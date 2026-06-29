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
/// Tests unitaires pour VerifyMfaLoginHandler (step 2 du login MFA).
/// Scénarios : code TOTP valide, code invalide, token MFA expiré,
/// utilisateur introuvable, compte inactif.
/// </summary>
public class MfaLoginHandlerTests
{
    private readonly Mock<IAuthRepository>  _repoMock;
    private readonly Mock<IPasswordHasher>  _hasherMock;
    private readonly VerifyMfaLoginHandler  _handler;

    public MfaLoginHandlerTests()
    {
        _repoMock   = RepoMockHelper.Create();
        _hasherMock = new Mock<IPasswordHasher>();
        _handler    = new VerifyMfaLoginHandler(
            _repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object);
    }

    private VerifyMfaLoginCommand BuildCommand(
        string  mfaPendingToken,
        string  code,
        string  ip        = "127.0.0.1",
        string  userAgent = "TestAgent/1.0")
        => new(mfaPendingToken, code, ip, userAgent);

    // ── Succès ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task VerifyMfaLogin_CodeValide_RetourneAccessTokenEtRoles()
    {
        var secret = TotpHelper.GenerateSecret();
        var user   = new UtilisateurBuilder()
            .WithMfaTotp(secret)
            .WithRole("RH_USER")
            .Build();
        var client = new ClientApplicationBuilder().Build();

        var pendingToken = MfaPendingTokenHelper.Generate(user.Id);
        var validCode    = TotpHelper.GenerateCurrentCode(secret);

        _repoMock.Setup(r => r.GetUtilisateurByIdAsync(user.Id, default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetFirstClientAsync(default)).ReturnsAsync(client);

        var result = await _handler.Handle(BuildCommand(pendingToken, validCode), default);

        result.Success.Should().BeTrue();
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.RefreshToken.Should().NotBeNullOrEmpty();
        result.Roles.Should().Contain("RH_USER");
        result.UserId.Should().Be(user.Id);
    }

    // ── Code TOTP invalide ────────────────────────────────────────────────────

    [Fact]
    public async Task VerifyMfaLogin_CodeInvalide_RetourneEchec()
    {
        var secret = TotpHelper.GenerateSecret();
        var user   = new UtilisateurBuilder().WithMfaTotp(secret).WithRole("RH_USER").Build();

        var pendingToken = MfaPendingTokenHelper.Generate(user.Id);
        var invalidCode  = TotpHelper.GenerateInvalidCode();

        _repoMock.Setup(r => r.GetUtilisateurByIdAsync(user.Id, default)).ReturnsAsync(user);

        var result = await _handler.Handle(BuildCommand(pendingToken, invalidCode), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_totp");
    }

    // ── Token MFA expiré ──────────────────────────────────────────────────────

    [Fact]
    public async Task VerifyMfaLogin_TokenExpire_RetourneEchec()
    {
        var expiredToken = MfaPendingTokenHelper.Generate(Guid.NewGuid(), expired: true);

        var result = await _handler.Handle(BuildCommand(expiredToken, "123456"), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_token");
    }

    // ── Token invalide (non MFA pending) ─────────────────────────────────────

    [Fact]
    public async Task VerifyMfaLogin_TokenInvalide_RetourneEchec()
    {
        var result = await _handler.Handle(BuildCommand("token_totalement_invalide", "123456"), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_token");
    }

    // ── Utilisateur introuvable ───────────────────────────────────────────────

    [Fact]
    public async Task VerifyMfaLogin_UtilisateurIntrouvable_RetourneEchec()
    {
        var userId       = Guid.NewGuid();
        var pendingToken = MfaPendingTokenHelper.Generate(userId);

        _repoMock.Setup(r => r.GetUtilisateurByIdAsync(userId, default))
                 .ReturnsAsync((Domain.Models.Utilisateur?)null);

        var result = await _handler.Handle(BuildCommand(pendingToken, "123456"), default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("introuvable");
    }

    // ── Compte bloqué / désactivé ─────────────────────────────────────────────

    [Theory]
    [InlineData(StatutUtilisateur.BLOQUE)]
    [InlineData(StatutUtilisateur.DESACTIVE)]
    public async Task VerifyMfaLogin_CompteInactif_RetourneEchec(StatutUtilisateur statut)
    {
        var secret = TotpHelper.GenerateSecret();
        var user   = new UtilisateurBuilder()
            .WithMfaTotp(secret)
            .WithStatut(statut)
            .Build();

        var pendingToken = MfaPendingTokenHelper.Generate(user.Id);
        var validCode    = TotpHelper.GenerateCurrentCode(secret);

        _repoMock.Setup(r => r.GetUtilisateurByIdAsync(user.Id, default)).ReturnsAsync(user);

        var result = await _handler.Handle(BuildCommand(pendingToken, validCode), default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("inactif");
    }

    // ── Aucun client configuré ────────────────────────────────────────────────

    [Fact]
    public async Task VerifyMfaLogin_AucunClientConfigure_RetourneEchec()
    {
        var secret = TotpHelper.GenerateSecret();
        var user   = new UtilisateurBuilder().WithMfaTotp(secret).WithRole("RH_USER").Build();

        var pendingToken = MfaPendingTokenHelper.Generate(user.Id);
        var validCode    = TotpHelper.GenerateCurrentCode(secret);

        _repoMock.Setup(r => r.GetUtilisateurByIdAsync(user.Id, default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetFirstClientAsync(default))
                 .ReturnsAsync((Domain.Models.ClientApplication?)null);

        var result = await _handler.Handle(BuildCommand(pendingToken, validCode), default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("cliente");
    }
}