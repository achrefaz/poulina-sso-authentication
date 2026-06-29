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
/// Tests unitaires pour LoginDirectHandler (flow simplifié sans OAuth2).
/// Scénarios : succès, MDP incorrect, compte bloqué/désactivé/verrouillé,
/// email non vérifié, lockout après 5 tentatives, MFA requis,
/// changement de mot de passe obligatoire, aucun client configuré.
/// </summary>
public class LoginDirectHandlerTests
{
    private readonly Mock<IAuthRepository> _repoMock;
    private readonly Mock<IPasswordHasher> _hasherMock;
    private readonly LoginDirectHandler    _handler;

    public LoginDirectHandlerTests()
    {
        _repoMock   = RepoMockHelper.Create();
        _hasherMock = new Mock<IPasswordHasher>();
        _handler    = new LoginDirectHandler(_repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object);
    }

    private LoginDirectCommand BuildCommand(string email = "user@test.com", string password = "Password123!")
        => new(new LoginDirectRequest { Email = email, Password = password }, "127.0.0.1", "TestAgent/1.0");

    // ── Succès ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task LoginDirect_Succes_RetourneAccessTokenEtRefreshTokenEtRoles()
    {
        var user   = new UtilisateurBuilder().WithRole("RH_USER").Build();
        var client = new ClientApplicationBuilder().Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetFirstClientAsync(default)).ReturnsAsync(client);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeTrue();
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.RefreshToken.Should().NotBeNullOrEmpty();
        result.Roles.Should().Contain("RH_USER");
        result.ErrorCode.Should().BeNull();
        result.ExpiresIn.Should().Be(900);
    }

    [Fact]
    public async Task LoginDirect_Succes_ReinitialiseTentativesEchouees()
    {
        var user   = new UtilisateurBuilder().WithTentatives(3).WithRole("RH_USER").Build();
        var client = new ClientApplicationBuilder().Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetFirstClientAsync(default)).ReturnsAsync(client);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        await _handler.Handle(BuildCommand(), default);

        user.TentativesConnexionEchouees.Should().Be(0);
        user.DateVerrouillage.Should().BeNull();
    }

    // ── Champs manquants ──────────────────────────────────────────────────────

    [Theory]
    [InlineData("", "Password123!")]
    [InlineData("user@test.com", "")]
    [InlineData("", "")]
    public async Task LoginDirect_ChampsManquants_RetourneEchec(string email, string password)
    {
        var result = await _handler.Handle(BuildCommand(email, password), default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("requis");
    }

    // ── Email introuvable ─────────────────────────────────────────────────────

    [Fact]
    public async Task LoginDirect_EmailIntrouvable_RetourneMessageGenerique()
    {
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default))
                 .ReturnsAsync((Domain.Models.Utilisateur?)null);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        result.Message.Should().Be("Email ou mot de passe incorrect.");
    }

    // ── Mot de passe incorrect ────────────────────────────────────────────────

    [Fact]
    public async Task LoginDirect_MdpIncorrect_IncrementeTentatives()
    {
        var user = new UtilisateurBuilder().Build();
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(false);

        await _handler.Handle(BuildCommand(), default);

        user.TentativesConnexionEchouees.Should().Be(1);
    }

    [Fact]
    public async Task LoginDirect_5MdpIncorrects_VerrouilleLCompte()
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
    public async Task LoginDirect_CompteBloque_RetourneErreurBLOCKED()
    {
        var user = new UtilisateurBuilder().WithStatut(StatutUtilisateur.BLOQUE).Build();
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("BLOCKED");
    }

    // ── Compte désactivé ──────────────────────────────────────────────────────

    [Fact]
    public async Task LoginDirect_CompteDesactive_RetourneErreurDISABLED()
    {
        var user = new UtilisateurBuilder().WithStatut(StatutUtilisateur.DESACTIVE).Build();
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("DISABLED");
    }

    // ── Compte verrouillé temporairement ─────────────────────────────────────

    [Fact]
    public async Task LoginDirect_CompteVerrouille_RetourneErreurLOCKED()
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
    public async Task LoginDirect_VerrouillageExpire_AuthoriseLaConnexion()
    {
        var user   = new UtilisateurBuilder()
            .WithVerrouillage(DateTime.UtcNow.AddMinutes(-1))
            .WithRole("RH_USER")
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
    public async Task LoginDirect_EmailNonVerifie_RetourneErreurEMAIL_NOT_VERIFIED()
    {
        var user = new UtilisateurBuilder().WithEmailVerifie(false).Build();
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("EMAIL_NOT_VERIFIED");
        result.EmailVerified.Should().BeFalse();
    }

    // ── MFA requis ────────────────────────────────────────────────────────────

    [Fact]
    public async Task LoginDirect_MfaActif_RetourneMfaPendingToken()
    {
        var secret = TotpHelper.GenerateSecret();
        var user   = new UtilisateurBuilder()
            .WithMfaTotp(secret)
            .WithRole("RH_USER")
            .Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeTrue();
        result.MfaRequired.Should().BeTrue();
        result.MfaPendingToken.Should().NotBeNullOrEmpty();
        result.AccessToken.Should().BeNullOrEmpty("pas de vrai token avant validation TOTP");
        result.RefreshToken.Should().BeNullOrEmpty("pas de refresh token avant validation TOTP");
    }

    // ── Changement de mot de passe obligatoire ────────────────────────────────

    [Fact]
    public async Task LoginDirect_DoitChangerMotDePasse_RetournePasswordChangeRequired()
    {
        var user = new UtilisateurBuilder()
            .WithRole("RH_USER")
            .WithDoitChangerMotDePasse(true)
            .Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeTrue();
        result.PasswordChangeRequired.Should().BeTrue();
        result.AccessToken.Should().NotBeNullOrEmpty("token temporaire nécessaire pour changer le mot de passe");
        result.RefreshToken.Should().BeNullOrEmpty("pas de refresh token tant que le mot de passe n'est pas changé");
        result.Roles.Should().NotBeEmpty();
    }

    // ── Aucun client configuré ────────────────────────────────────────────────

    [Fact]
    public async Task LoginDirect_AucunClientConfigure_RetourneEchec()
    {
        var user = new UtilisateurBuilder().WithRole("RH_USER").Build();
        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetFirstClientAsync(default))
                 .ReturnsAsync((Domain.Models.ClientApplication?)null);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("cliente");
    }
}