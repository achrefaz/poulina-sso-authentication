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
/// Tests unitaires pour ExchangeCodeHandler (OAuth2 code → access token avec PKCE).
/// Scénarios : échange valide S256, code déjà utilisé, code expiré,
/// code verifier manquant, code verifier invalide, grant_type invalide,
/// mismatch client, rôle insuffisant.
/// </summary>
public class ExchangeCodeHandlerTests
{
    private readonly Mock<IAuthRepository> _repoMock;
    private readonly Mock<IPasswordHasher> _hasherMock;
    private readonly ExchangeCodeHandler   _handler;

    public ExchangeCodeHandlerTests()
    {
        _repoMock   = RepoMockHelper.Create();
        _hasherMock = new Mock<IPasswordHasher>();
        _handler    = new ExchangeCodeHandler(_repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object);
    }

    // ── Helpers PKCE ─────────────────────────────────────────────────────────

    private static (string Verifier, string Challenge) GeneratePkce()
    {
        // code_verifier : 43-128 caractères URL-safe
        var verifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');

        // code_challenge = BASE64URL(SHA256(verifier))
        var hash      = SHA256.HashData(Encoding.UTF8.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash)
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');

        return (verifier, challenge);
    }

    private AuthorizationCode BuildAuthCode(
        Domain.Models.Utilisateur user,
        Domain.Models.ClientApplication client,
        bool used          = false,
        int  expirationMin = 5,
        string? challenge  = null,
        string? method     = "S256")
    {
        return new AuthorizationCode
        {
            Id                  = Guid.NewGuid(),
            CodeHash            = "code_hash",
            UtilisateurId       = user.Id,
            ClientId            = client.Id,
            DateCreation        = DateTime.UtcNow,
            DateExpiration      = DateTime.UtcNow.AddMinutes(expirationMin),
            EstUtilise          = used,
            CodeChallenge       = challenge,
            CodeChallengeMethod = method,
            Scopes              = "openid profile",
            Utilisateur         = user,
            Client              = client
        };
    }

    // ── Échange valide avec PKCE S256 ─────────────────────────────────────────

    [Fact]
    public async Task Exchange_CodeValideAvecPKCE_RetourneTokens()
    {
        var (verifier, challenge) = GeneratePkce();
        var user   = new UtilisateurBuilder().WithRole("RH").Build();
        var client = new ClientApplicationBuilder().WithClientId("rh-app").Build();
        var code   = BuildAuthCode(user, client, challenge: challenge);
        var rawCode = "raw_code_value";

        _repoMock.Setup(r => r.GetAuthorizationCodeByHashAsync(It.IsAny<string>(), default)).ReturnsAsync(code);

        var cmd = new ExchangeCodeCommand(new TokenRequest
        {
            GrantType    = "authorization_code",
            Code         = rawCode,
            ClientId     = "rh-app",
            RedirectUri  = "http://localhost:3001/callback",
            CodeVerifier = verifier
        });

        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeTrue();
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.RefreshToken.Should().NotBeNullOrEmpty();
        result.TokenType.Should().Be("Bearer");
        result.ExpiresIn.Should().Be(900);
        code.EstUtilise.Should().BeTrue();
    }

    // ── Code déjà utilisé ────────────────────────────────────────────────────

    [Fact]
    public async Task Exchange_CodeDejaUtilise_RetourneInvalidGrant()
    {
        var (_, challenge) = GeneratePkce();
        var user   = new UtilisateurBuilder().WithRole("RH").Build();
        var client = new ClientApplicationBuilder().Build();
        var code   = BuildAuthCode(user, client, used: true, challenge: challenge);

        _repoMock.Setup(r => r.GetAuthorizationCodeByHashAsync(It.IsAny<string>(), default)).ReturnsAsync(code);

        var cmd = new ExchangeCodeCommand(new TokenRequest
        {
            GrantType   = "authorization_code",
            Code        = "any_code",
            ClientId    = "rh-app",
            RedirectUri = "http://localhost:3001/callback"
        });

        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_grant");
        result.ErrorDescription.Should().Contain("déjà utilisé");
    }

    // ── Code expiré ───────────────────────────────────────────────────────────

    [Fact]
    public async Task Exchange_CodeExpire_RetourneInvalidGrant()
    {
        var user   = new UtilisateurBuilder().WithRole("RH").Build();
        var client = new ClientApplicationBuilder().Build();
        var code   = BuildAuthCode(user, client, expirationMin: -1); // expiré

        _repoMock.Setup(r => r.GetAuthorizationCodeByHashAsync(It.IsAny<string>(), default)).ReturnsAsync(code);

        var cmd = new ExchangeCodeCommand(new TokenRequest
        {
            GrantType   = "authorization_code",
            Code        = "expired_code",
            ClientId    = "rh-app",
            RedirectUri = "http://localhost:3001/callback"
        });

        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_grant");
        result.ErrorDescription.Should().Contain("expiré");
    }

    // ── Code introuvable ──────────────────────────────────────────────────────

    [Fact]
    public async Task Exchange_CodeIntrouvable_RetourneInvalidGrant()
    {
        _repoMock.Setup(r => r.GetAuthorizationCodeByHashAsync(It.IsAny<string>(), default))
                 .ReturnsAsync((AuthorizationCode?)null);

        var cmd = new ExchangeCodeCommand(new TokenRequest
        {
            GrantType   = "authorization_code",
            Code        = "unknown_code",
            ClientId    = "rh-app",
            RedirectUri = "http://localhost:3001/callback"
        });

        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_grant");
    }

    // ── PKCE : code verifier manquant ────────────────────────────────────────

    [Fact]
    public async Task Exchange_PkceCodeVerifierManquant_RetourneInvalidGrant()
    {
        var (_, challenge) = GeneratePkce();
        var user   = new UtilisateurBuilder().WithRole("RH").Build();
        var client = new ClientApplicationBuilder().WithClientId("rh-app").Build();
        var code   = BuildAuthCode(user, client, challenge: challenge);

        _repoMock.Setup(r => r.GetAuthorizationCodeByHashAsync(It.IsAny<string>(), default)).ReturnsAsync(code);

        var cmd = new ExchangeCodeCommand(new TokenRequest
        {
            GrantType    = "authorization_code",
            Code         = "code",
            ClientId     = "rh-app",
            RedirectUri  = "http://localhost:3001/callback",
            CodeVerifier = null    // manquant
        });

        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_grant");
        result.ErrorDescription.Should().Contain("verifier");
    }

    // ── PKCE : code verifier invalide ────────────────────────────────────────

    [Fact]
    public async Task Exchange_PkceCodeVerifierInvalide_RetourneInvalidGrant()
    {
        var (_, challenge) = GeneratePkce();
        var user   = new UtilisateurBuilder().WithRole("RH").Build();
        var client = new ClientApplicationBuilder().WithClientId("rh-app").Build();
        var code   = BuildAuthCode(user, client, challenge: challenge);

        _repoMock.Setup(r => r.GetAuthorizationCodeByHashAsync(It.IsAny<string>(), default)).ReturnsAsync(code);

        var cmd = new ExchangeCodeCommand(new TokenRequest
        {
            GrantType    = "authorization_code",
            Code         = "code",
            ClientId     = "rh-app",
            RedirectUri  = "http://localhost:3001/callback",
            CodeVerifier = "WRONG_VERIFIER_VALUE"    // invalide
        });

        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_grant");
        result.ErrorDescription.Should().Contain("verifier invalide");
    }

    // ── grant_type invalide ───────────────────────────────────────────────────

    [Fact]
    public async Task Exchange_GrantTypeInvalide_RetourneUnsupportedGrantType()
    {
        var cmd = new ExchangeCodeCommand(new TokenRequest
        {
            GrantType   = "client_credentials",
            Code        = "code",
            ClientId    = "rh-app",
            RedirectUri = "http://localhost:3001/callback"
        });

        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("unsupported_grant_type");
    }

    // ── Mismatch client ───────────────────────────────────────────────────────

    [Fact]
    public async Task Exchange_ClientIdMismatch_RetourneInvalidClient()
    {
        var user   = new UtilisateurBuilder().WithRole("RH").Build();
        var client = new ClientApplicationBuilder().WithClientId("finance-app").Build(); // code émis pour finance-app
        var code   = BuildAuthCode(user, client);

        _repoMock.Setup(r => r.GetAuthorizationCodeByHashAsync(It.IsAny<string>(), default)).ReturnsAsync(code);

        var cmd = new ExchangeCodeCommand(new TokenRequest
        {
            GrantType   = "authorization_code",
            Code        = "code",
            ClientId    = "rh-app",    // mais rh-app demande l'échange
            RedirectUri = "http://localhost:3001/callback"
        });

        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_client");
    }

    // ── Rôle insuffisant ──────────────────────────────────────────────────────

    [Fact]
    public async Task Exchange_RoleInsuffisant_RetourneAccessDenied()
    {
        var user   = new UtilisateurBuilder().WithRole("Finance").Build(); // n'a pas le rôle RH
        var client = new ClientApplicationBuilder()
            .WithClientId("rh-app")
            .WithAllowedRoles("RH")
            .Build();
        var code   = BuildAuthCode(user, client); // pas de challenge pour simplifier

        _repoMock.Setup(r => r.GetAuthorizationCodeByHashAsync(It.IsAny<string>(), default)).ReturnsAsync(code);

        var cmd = new ExchangeCodeCommand(new TokenRequest
        {
            GrantType   = "authorization_code",
            Code        = "code",
            ClientId    = "rh-app",
            RedirectUri = "http://localhost:3001/callback"
        });

        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("access_denied");
    }
}

/// <summary>
/// Tests unitaires pour VerifyMfaLoginHandler.
/// Scénarios : code TOTP valide, code invalide, MFA pending token expiré,
/// token invalide (mauvaise signature), utilisateur introuvable.
/// </summary>
public class VerifyMfaLoginHandlerTests
{
    private readonly Mock<IAuthRepository>  _repoMock;
    private readonly Mock<IPasswordHasher>  _hasherMock;
    private readonly VerifyMfaLoginHandler  _handler;

    public VerifyMfaLoginHandlerTests()
    {
        _repoMock   = RepoMockHelper.Create();
        _hasherMock = new Mock<IPasswordHasher>();
        _handler    = new VerifyMfaLoginHandler(_repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object);
    }

    private VerifyMfaLoginCommand BuildCommand(Guid userId, string totpCode, bool expiredPendingToken = false)
    {
        var (verifier, challenge) = GeneratePkce();
        return new VerifyMfaLoginCommand(
            MfaPendingToken:     MfaPendingTokenHelper.Generate(userId, expired: expiredPendingToken),
            Code:                totpCode,
            IpAddress:           "127.0.0.1",
            UserAgent:           "TestAgent/1.0",
            ClientId:            "rh-app",
            RedirectUri:         "http://localhost:3001/callback",
            State:               "random_state",
            CodeChallenge:       challenge,
            CodeChallengeMethod: "S256",
            Scopes:              "openid profile"
        );
    }

    private static (string Verifier, string Challenge) GeneratePkce()
    {
        var verifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');
        var hash      = SHA256.HashData(Encoding.UTF8.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash)
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');
        return (verifier, challenge);
    }

    // ── Code TOTP valide ─────────────────────────────────────────────────────

    [Fact]
    public async Task VerifyMfa_CodeValide_RetourneAuthorizationCode()
    {
        var secret = TotpHelper.GenerateSecret();
        var userId = Guid.NewGuid();
        var user   = new UtilisateurBuilder().WithId(userId).WithMfaTotp(secret).WithRole("RH").Build();
        var client = new ClientApplicationBuilder().WithClientId("rh-app").Build();
        var code   = TotpHelper.GenerateCurrentCode(secret);

        _repoMock.Setup(r => r.GetUtilisateurByIdAsync(userId, default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetClientByClientIdAsync("rh-app", default)).ReturnsAsync(client);

        var result = await _handler.Handle(BuildCommand(userId, code), default);

        result.Success.Should().BeTrue();
        result.Code.Should().NotBeNullOrEmpty("un authorization code OAuth2 doit être retourné");
        result.RedirectUri.Should().Contain("code=");
    }

    // ── Code TOTP invalide ───────────────────────────────────────────────────

    [Fact]
    public async Task VerifyMfa_CodeTotpInvalide_RetourneErreurInvalidTotp()
    {
        var secret = TotpHelper.GenerateSecret();
        var userId = Guid.NewGuid();
        var user   = new UtilisateurBuilder().WithId(userId).WithMfaTotp(secret).Build();

        _repoMock.Setup(r => r.GetUtilisateurByIdAsync(userId, default)).ReturnsAsync(user);

        var result = await _handler.Handle(BuildCommand(userId, "000000"), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_totp");
    }

    // ── MFA pending token expiré ─────────────────────────────────────────────

    [Fact]
    public async Task VerifyMfa_TokenExpire_RetourneErreurInvalidToken()
    {
        var userId = Guid.NewGuid();
        var user   = new UtilisateurBuilder().WithId(userId).WithMfaTotp().Build();

        _repoMock.Setup(r => r.GetUtilisateurByIdAsync(userId, default)).ReturnsAsync(user);

        var result = await _handler.Handle(BuildCommand(userId, "123456", expiredPendingToken: true), default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_token");
    }

    // ── MFA pending token avec mauvaise signature ────────────────────────────

    [Fact]
    public async Task VerifyMfa_TokenSignatureInvalide_RetourneErreurInvalidToken()
    {
        var cmd = new VerifyMfaLoginCommand(
            MfaPendingToken:     "this.is.not.a.valid.jwt",
            Code:                "123456",
            IpAddress:           "127.0.0.1",
            UserAgent:           "TestAgent/1.0",
            ClientId:            "rh-app",
            RedirectUri:         "http://localhost:3001/callback",
            State:               null,
            CodeChallenge:       null,
            CodeChallengeMethod: null,
            Scopes:              null
        );

        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be("invalid_token");
    }

    // ── Utilisateur introuvable (token valide mais user supprimé) ────────────

    [Fact]
    public async Task VerifyMfa_UtilisateurIntrouvable_RetourneEchec()
    {
        var userId = Guid.NewGuid();
        _repoMock.Setup(r => r.GetUtilisateurByIdAsync(userId, default))
                 .ReturnsAsync((Domain.Models.Utilisateur?)null);

        var result = await _handler.Handle(BuildCommand(userId, "123456"), default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("introuvable");
    }

    // ── Compte bloqué après token MFA valide ────────────────────────────────

    [Fact]
    public async Task VerifyMfa_CompteBloque_RetourneEchec()
    {
        var secret = TotpHelper.GenerateSecret();
        var userId = Guid.NewGuid();
        var user   = new UtilisateurBuilder()
            .WithId(userId)
            .WithMfaTotp(secret)
            .WithStatut(StatutUtilisateur.BLOQUE)
            .Build();

        _repoMock.Setup(r => r.GetUtilisateurByIdAsync(userId, default)).ReturnsAsync(user);

        var code   = TotpHelper.GenerateCurrentCode(secret);
        var result = await _handler.Handle(BuildCommand(userId, code), default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("inactif");
    }

    // ── Client OAuth2 introuvable ────────────────────────────────────────────

    [Fact]
    public async Task VerifyMfa_ClientIntrouvable_RetourneEchec()
    {
        var secret = TotpHelper.GenerateSecret();
        var userId = Guid.NewGuid();
        var user   = new UtilisateurBuilder().WithId(userId).WithMfaTotp(secret).Build();
        var code   = TotpHelper.GenerateCurrentCode(secret);

        _repoMock.Setup(r => r.GetUtilisateurByIdAsync(userId, default)).ReturnsAsync(user);
        _repoMock.Setup(r => r.GetClientByClientIdAsync(It.IsAny<string>(), default))
                 .ReturnsAsync((Domain.Models.ClientApplication?)null);

        var result = await _handler.Handle(BuildCommand(userId, code), default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("Client");
    }
}