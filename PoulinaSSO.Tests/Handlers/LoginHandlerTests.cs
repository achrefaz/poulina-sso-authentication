using FluentAssertions;
using Moq;
using Domain.Commands.Auth;
using Domain.Handlers.Auth;
using Domain.Interfaces;
using Domain.Models.Enums;
using PoulinaSSO.Tests.Helpers;
using Xunit;

namespace PoulinaSSO.Tests.Handlers;

/// <summary>
/// Tests unitaires pour LoginHandler (login direct sans OAuth2).
/// Scénarios : succès, MDP incorrect, compte bloqué/désactivé/verrouillé,
/// email non vérifié, lockout après 5 tentatives, MFA requis.
/// </summary>
public class LoginHandlerTests
{
    private readonly Mock<IAuthRepository> _repoMock;
    private readonly Mock<IPasswordHasher> _hasherMock;
    private readonly LoginHandler          _handler;

    public LoginHandlerTests()
    {
        _repoMock   = RepoMockHelper.Create();
        _hasherMock = new Mock<IPasswordHasher>();
        _handler    = new LoginHandler(_repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object);
    }

    private LoginCommand BuildCommand(string email = "user@test.com", string password = "Password123!")
        => new(new LoginRequest { Email = email, Password = password }, "127.0.0.1", "TestAgent/1.0");

    // ── Succès ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Login_Succes_RetourneAccessTokenEtRefreshToken()
    {
        // Arrange
        var user   = new UtilisateurBuilder().WithRole("RH").Build();
        var client = new ClientApplicationBuilder().Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetFirstClientAsync(default)).ReturnsAsync(client);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        // Act
        var result = await _handler.Handle(BuildCommand(), default);

        // Assert
        result.Success.Should().BeTrue();
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.RefreshToken.Should().NotBeNullOrEmpty();
        result.ErrorCode.Should().BeNull();
    }

    [Fact]
    public async Task Login_Succes_ReinitialiseTentativesEchouees()
    {
        // Arrange — utilisateur avec 3 tentatives échouées
        var user   = new UtilisateurBuilder().WithTentatives(3).WithRole("RH").Build();
        var client = new ClientApplicationBuilder().Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetFirstClientAsync(default)).ReturnsAsync(client);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        // Act
        await _handler.Handle(BuildCommand(), default);

        // Assert
        user.TentativesConnexionEchouees.Should().Be(0);
        user.DateVerrouillage.Should().BeNull();
    }

    // ── Champs manquants ──────────────────────────────────────────────────────

    [Theory]
    [InlineData("", "Password123!")]
    [InlineData("user@test.com", "")]
    [InlineData("", "")]
    public async Task Login_ChampsManquants_RetourneEchec(string email, string password)
    {
        var result = await _handler.Handle(BuildCommand(email, password), default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("requis");
    }

    // ── Email introuvable ─────────────────────────────────────────────────────

    [Fact]
    public async Task Login_EmailIntrouvable_RetourneMessageGenerique()
    {
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default))
                 .ReturnsAsync((Domain.Models.Utilisateur?)null);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        // Message générique — ne révèle pas si l'email existe
        result.Message.Should().Be("Email ou mot de passe incorrect.");
    }

    // ── Mot de passe incorrect ────────────────────────────────────────────────

    [Fact]
    public async Task Login_MdpIncorrect_IncrementeTentatives()
    {
        var user = new UtilisateurBuilder().Build();
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(false);

        await _handler.Handle(BuildCommand(), default);

        user.TentativesConnexionEchouees.Should().Be(1);
    }

    [Fact]
    public async Task Login_5MdpIncorrects_VerrouilleLCompte()
    {
        var user = new UtilisateurBuilder().WithTentatives(4).Build();
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(false);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        user.TentativesConnexionEchouees.Should().Be(5);
        user.DateVerrouillage.Should().NotBeNull();
        user.DateVerrouillage!.Value.Should().BeCloseTo(DateTime.UtcNow.AddMinutes(15), TimeSpan.FromSeconds(5));
    }

    // ── Compte bloqué ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Login_CompteBloque_RetourneErreurBLOCKED()
    {
        var user = new UtilisateurBuilder().WithStatut(StatutUtilisateur.BLOQUE).Build();
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("BLOCKED");
    }

    // ── Compte désactivé ──────────────────────────────────────────────────────

    [Fact]
    public async Task Login_CompteDesactive_RetourneErreurDISABLED()
    {
        var user = new UtilisateurBuilder().WithStatut(StatutUtilisateur.DESACTIVE).Build();
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("DISABLED");
    }

    // ── Compte verrouillé temporairement ─────────────────────────────────────

    [Fact]
    public async Task Login_CompteVerrouille_RetourneErreurLOCKED()
    {
        var user = new UtilisateurBuilder()
            .WithVerrouillage(DateTime.UtcNow.AddMinutes(10))
            .Build();
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("LOCKED");
    }

    [Fact]
    public async Task Login_VerrouillageExpire_AuthoriseLaConnexion()
    {
        // Verrouillage dans le passé → doit être ignoré
        var user   = new UtilisateurBuilder()
            .WithVerrouillage(DateTime.UtcNow.AddMinutes(-1))
            .WithRole("RH")
            .Build();
        var client = new ClientApplicationBuilder().Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetFirstClientAsync(default)).ReturnsAsync(client);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeTrue();
    }

    // ── Email non vérifié ─────────────────────────────────────────────────────

    [Fact]
    public async Task Login_EmailNonVerifie_RetourneErreurEMAIL_NOT_VERIFIED()
    {
        var user = new UtilisateurBuilder().WithEmailVerifie(false).Build();
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("EMAIL_NOT_VERIFIED");
    }

    // ── MFA requis ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Login_MfaActif_RetourneMfaPendingTokenEtCodeMFA_REQUIRED()
    {
        var secret = TotpHelper.GenerateSecret();
        var user   = new UtilisateurBuilder()
            .WithMfaTotp(secret)
            .WithRole("RH")
            .Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeTrue();
        result.ErrorCode.Should().Be("MFA_REQUIRED");
        result.AccessToken.Should().NotBeNullOrEmpty("le MfaPendingToken est retourné dans AccessToken");
        result.RefreshToken.Should().BeNullOrEmpty("pas encore de refresh token à ce stade");
    }

    // ── Aucun client configuré ────────────────────────────────────────────────
    
    [Fact]
    public async Task Login_AucunClientConfigure_RetourneEchec()
    {
        var user = new UtilisateurBuilder().WithRole("RH").Build();
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetFirstClientAsync(default))
                 .ReturnsAsync((Domain.Models.ClientApplication?)null);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("cliente");
    }
}