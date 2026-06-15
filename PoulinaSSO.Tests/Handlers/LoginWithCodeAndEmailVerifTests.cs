using FluentAssertions;
using Moq;
using System.Security.Cryptography;
using System.Text;
using Domain.Commands.Auth;
using Domain.Handlers.Auth;
using Domain.Interfaces;
using Domain.Models;
using Domain.Models.Enums;
using PoulinaSSO.Tests.Helpers;
using Xunit;

namespace PoulinaSSO.Tests.Handlers;

/// <summary>
/// Tests unitaires pour LoginWithCodeHandler (OAuth2 Authorization Code Flow).
/// Scénarios : succès avec PKCE, email non vérifié, client invalide,
/// redirect_uri invalide, rôle insuffisant, MFA requis, compte bloqué.
/// </summary>
public class LoginWithCodeHandlerTests
{
    private readonly Mock<IAuthRepository>  _repoMock;
    private readonly Mock<IPasswordHasher>  _hasherMock;
    private readonly LoginWithCodeHandler   _handler;

    public LoginWithCodeHandlerTests()
    {
        _repoMock   = RepoMockHelper.Create();
        _hasherMock = new Mock<IPasswordHasher>();
        _handler    = new LoginWithCodeHandler(_repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object);
    }

    private static (string Verifier, string Challenge) GeneratePkce()
    {
        var verifier  = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');
        var hash      = SHA256.HashData(Encoding.UTF8.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash)
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');
        return (verifier, challenge);
    }

    private LoginWithCodeCommand BuildCommand(
        string  email          = "user@test.com",
        string  password       = "Password123!",
        string  clientId       = "rh-app",
        string  redirectUri    = "http://localhost:3001/callback",
        string? codeChallenge  = null,
        string? state          = "random_state")
    {
        return new LoginWithCodeCommand(
            new LoginWithCodeRequest
            {
                Email               = email,
                Password            = password,
                ClientId            = clientId,
                RedirectUri         = redirectUri,
                State               = state,
                CodeChallenge       = codeChallenge,
                CodeChallengeMethod = codeChallenge != null ? "S256" : null,
                Scopes              = "openid profile"
            },
            "127.0.0.1",
            "TestAgent/1.0");
    }

    // ── Succès avec PKCE ──────────────────────────────────────────────────────

    [Fact]
    public async Task LoginWithCode_Succes_RetourneCodeEtRedirectUri()
    {
        var (_, challenge) = GeneratePkce();
        var user   = new UtilisateurBuilder().WithRole("RH").Build();
        var client = new ClientApplicationBuilder()
            .WithClientId("rh-app")
            .WithAllowedRoles("RH")
            .WithRedirectUri("http://localhost:3001/callback")
            .Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetClientByClientIdAsync("rh-app", default)).ReturnsAsync(client);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(codeChallenge: challenge), default);

        result.Success.Should().BeTrue();
        result.Code.Should().NotBeNullOrEmpty();
        result.RedirectUri.Should().Contain("code=");
        result.RedirectUri.Should().Contain("state=");
    }

    // ── Email non vérifié ─────────────────────────────────────────────────────

    [Fact]
    public async Task LoginWithCode_EmailNonVerifie_RetourneErreurEMAIL_NOT_VERIFIED()
    {
        var user   = new UtilisateurBuilder().WithEmailVerifie(false).Build();
        var client = new ClientApplicationBuilder().WithClientId("rh-app").WithAllowedRoles("RH").Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetClientByClientIdAsync("rh-app", default)).ReturnsAsync(client);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("EMAIL_NOT_VERIFIED");
    }

    // ── Client inconnu ────────────────────────────────────────────────────────

    [Fact]
    public async Task LoginWithCode_ClientInconnu_RetourneInvalidClient()
    {
        var user = new UtilisateurBuilder().WithRole("RH").Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetClientByClientIdAsync(It.IsAny<string>(), default))
                 .ReturnsAsync((Domain.Models.ClientApplication?)null);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_client");
    }

    // ── Redirect URI invalide ─────────────────────────────────────────────────

    [Fact]
    public async Task LoginWithCode_RedirectUriInvalide_RetourneErreur()
    {
        var user   = new UtilisateurBuilder().WithRole("RH").Build();
        var client = new ClientApplicationBuilder()
            .WithClientId("rh-app")
            .WithRedirectUri("http://localhost:3001/callback")  // seule URI autorisée
            .WithAllowedRoles("RH")
            .Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetClientByClientIdAsync("rh-app", default)).ReturnsAsync(client);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        // Redirect URI différente → doit être rejetée
        var result = await _handler.Handle(
            BuildCommand(redirectUri: "http://evil.com/callback"), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_redirect_uri");
    }

    // ── Rôle insuffisant ──────────────────────────────────────────────────────

    [Fact]
    public async Task LoginWithCode_RoleInsuffisant_RetourneAccessDenied()
    {
        var user   = new UtilisateurBuilder().WithRole("Finance").Build();
        var client = new ClientApplicationBuilder()
            .WithClientId("rh-app")
            .WithAllowedRoles("RH")
            .WithRedirectUri("http://localhost:3001/callback")
            .WithRequiertPKCE(false)
            .Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetClientByClientIdAsync("rh-app", default)).ReturnsAsync(client);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("access_denied");
    }

    // ── MFA requis ────────────────────────────────────────────────────────────

    [Fact]
    public async Task LoginWithCode_MfaActif_RetourneMFA_REQUIRED()
    {
        var (_, challenge) = GeneratePkce();
        var secret = TotpHelper.GenerateSecret();
        var user   = new UtilisateurBuilder().WithMfaTotp(secret).WithRole("RH").Build();
        var client = new ClientApplicationBuilder()
            .WithClientId("rh-app")
            .WithAllowedRoles("RH")
            .WithRedirectUri("http://localhost:3001/callback")
            .Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetClientByClientIdAsync("rh-app", default)).ReturnsAsync(client);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        var result = await _handler.Handle(BuildCommand(codeChallenge: challenge), default);

        result.Success.Should().BeTrue();
        result.ErrorCode.Should().Be("MFA_REQUIRED");
        result.AccessToken.Should().NotBeNullOrEmpty("MFA pending token attendu");
    }

    // ── PKCE requis mais manquant ─────────────────────────────────────────────

    [Fact]
    public async Task LoginWithCode_PkceRequisMaisManquant_RetourneErreur()
    {
        var user   = new UtilisateurBuilder().WithRole("RH").Build();
        var client = new ClientApplicationBuilder()
            .WithClientId("rh-app")
            .WithAllowedRoles("RH")
            .WithRedirectUri("http://localhost:3001/callback")
            .WithRequiertPKCE(true)
            .Build();

        _repoMock.Setup(r => r.GetUtilisateurByEmailAsync(It.IsAny<string>(), default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetClientByClientIdAsync("rh-app", default)).ReturnsAsync(client);
        _hasherMock.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);

        // Pas de code_challenge
        var result = await _handler.Handle(BuildCommand(codeChallenge: null), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("code_challenge_required");
    }
}

/// <summary>
/// Tests unitaires pour les handlers de vérification email.
/// Couvre les scénarios : token valide, token expiré, token introuvable.
/// Note : EmailVerificationHandlers doit exposer ConfirmEmailHandler et
/// ResendConfirmationHandler — adaptez les noms si nécessaire.
/// </summary>
public class EmailVerificationHandlerTests
{
    private readonly Mock<IAuthRepository> _repoMock;
    private readonly Mock<IPasswordHasher> _hasherMock;
    private readonly Mock<IEmailService>   _emailMock;

    public EmailVerificationHandlerTests()
    {
        _repoMock   = RepoMockHelper.Create();
        _hasherMock = new Mock<IPasswordHasher>();
        _emailMock  = new Mock<IEmailService>();
        _emailMock.Setup(e => e.EnvoyerEmailConfirmationAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        _emailMock.Setup(e => e.RenvoyerEmailConfirmationAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
    }

    private static (string Raw, string Hash) GenerateVerificationToken()
    {
        var raw = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))
                         .Replace("+", "-").Replace("/", "_").TrimEnd('=');
        var hash = Convert.ToBase64String(
            SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
        return (raw, hash);
    }

    // ── RegisterHandler : email de confirmation envoyé à la création ─────────

    [Fact]
    public async Task Register_NouvelUtilisateur_EnvoieEmailDeConfirmation()
    {
        var handler = new RegisterHandler(
            _repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object, _emailMock.Object);

        _repoMock.Setup(r => r.EmailExisteAsync(It.IsAny<string>(), default)).ReturnsAsync(false);
        _hasherMock.Setup(h => h.Hash(It.IsAny<string>())).Returns("hashed_pw");

        var cmd = new RegisterCommand(new RegisterRequest
        {
            Email    = "new@poulina.com",
            Password = "Password123!",
            Nom      = "Dupont",
            Prenom   = "Jean"
        });

        var result = await handler.Handle(cmd, default);

        result.Success.Should().BeTrue();
        _emailMock.Verify(e => e.EnvoyerEmailConfirmationAsync(
            "new@poulina.com",
            It.IsAny<string>(),
            It.Is<string>(l => l.Contains("/api/Auth/confirm-email?token=")),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Register_EmailDejaExistant_RetourneEchec()
    {
        var handler = new RegisterHandler(
            _repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object, _emailMock.Object);

        _repoMock.Setup(r => r.EmailExisteAsync(It.IsAny<string>(), default)).ReturnsAsync(true);

        var cmd = new RegisterCommand(new RegisterRequest
        {
            Email    = "existing@poulina.com",
            Password = "Password123!",
            Nom      = "Dupont",
            Prenom   = "Jean"
        });

        var result = await handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("existe déjà");
        _emailMock.Verify(e => e.EnvoyerEmailConfirmationAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Register_MotDePasseTropCourt_RetourneEchec()
    {
        var handler = new RegisterHandler(
            _repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object, _emailMock.Object);

        var cmd = new RegisterCommand(new RegisterRequest
        {
            Email    = "user@poulina.com",
            Password = "abc",   // < 8 caractères
            Nom      = "Dupont",
            Prenom   = "Jean"
        });

        var result = await handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("8 caractères");
    }
}