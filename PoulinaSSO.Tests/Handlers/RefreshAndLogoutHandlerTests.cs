using FluentAssertions;
using Moq;
using Domain.Commands.Auth;
using Domain.Handlers.Auth;
using Domain.Interfaces;
using Domain.Models;
using Domain.Models.Enums;
using PoulinaSSO.Tests.Helpers;
using Xunit;

namespace PoulinaSSO.Tests.Handlers;

/// <summary>
/// Tests unitaires pour RefreshTokenHandler.
/// Scénarios : token valide (rotation), token déjà utilisé, token expiré,
/// token introuvable, compte bloqué, rôle insuffisant pour le client cible.
/// </summary>
public class RefreshTokenHandlerTests
{
    private readonly Mock<IAuthRepository> _repoMock;
    private readonly Mock<IPasswordHasher> _hasherMock;
    private readonly RefreshTokenHandler   _handler;

    public RefreshTokenHandlerTests()
    {
        _repoMock   = RepoMockHelper.Create();
        _hasherMock = new Mock<IPasswordHasher>();
        _handler    = new RefreshTokenHandler(_repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object);
    }

    private static RefreshToken BuildRefreshToken(Domain.Models.Utilisateur user, bool used = false, int expirationDays = 7)
    {
        var client = new ClientApplicationBuilder().Build();
        return new RefreshToken
        {
            Id             = Guid.NewGuid(),
            UtilisateurId  = user.Id,
            ClientId       = client.Id,
            TokenHash      = "hashed",
            DateCreation   = DateTime.UtcNow,
            DateExpiration = DateTime.UtcNow.AddDays(expirationDays),
            EstUtilise     = used,
            Utilisateur    = user,
            Client         = client
        };
    }

    // ── Token valide → rotation ───────────────────────────────────────────────

    [Fact]
    public async Task Refresh_TokenValide_RetourneNouveauxTokens()
    {
        var user  = new UtilisateurBuilder().WithRole("RH").Build();
        var rt    = BuildRefreshToken(user);
        var rawToken = "raw_token_value";

        _repoMock.Setup(r => r.GetRefreshTokenByHashAsync(It.IsAny<string>(), default)).ReturnsAsync(rt);

        var cmd    = new RefreshTokenCommand(new RefreshRequest { RefreshToken = rawToken }, "127.0.0.1");
        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeTrue();
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.RefreshToken.Should().NotBeNullOrEmpty();
        rt.EstUtilise.Should().BeTrue("le token utilisé doit être marqué comme consommé");
    }

    // ── Token introuvable ─────────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_TokenIntrouvable_RetourneEchec()
    {
        _repoMock.Setup(r => r.GetRefreshTokenByHashAsync(It.IsAny<string>(), default))
                 .ReturnsAsync((RefreshToken?)null);

        var cmd    = new RefreshTokenCommand(new RefreshRequest { RefreshToken = "bad_token" }, "127.0.0.1");
        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("invalide");
    }

    // ── Token déjà utilisé (détection de réutilisation) ─────────────────────

    [Fact]
    public async Task Refresh_TokenDejaUtilise_RetourneEchec()
    {
        var user = new UtilisateurBuilder().WithRole("RH").Build();
        var rt   = BuildRefreshToken(user, used: true);

        _repoMock.Setup(r => r.GetRefreshTokenByHashAsync(It.IsAny<string>(), default)).ReturnsAsync(rt);

        var cmd    = new RefreshTokenCommand(new RefreshRequest { RefreshToken = "reused_token" }, "127.0.0.1");
        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("déjà utilisé");
    }

    // ── Token expiré ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_TokenExpire_RetourneEchec()
    {
        var user = new UtilisateurBuilder().WithRole("RH").Build();
        var rt   = BuildRefreshToken(user, expirationDays: -1); // expiré hier

        _repoMock.Setup(r => r.GetRefreshTokenByHashAsync(It.IsAny<string>(), default)).ReturnsAsync(rt);

        var cmd    = new RefreshTokenCommand(new RefreshRequest { RefreshToken = "expired_token" }, "127.0.0.1");
        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("expiré");
    }

    // ── Compte bloqué ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_CompteBloque_RetourneEchec()
    {
        var user = new UtilisateurBuilder().WithStatut(StatutUtilisateur.BLOQUE).WithRole("RH").Build();
        var rt   = BuildRefreshToken(user);

        _repoMock.Setup(r => r.GetRefreshTokenByHashAsync(It.IsAny<string>(), default)).ReturnsAsync(rt);

        var cmd    = new RefreshTokenCommand(new RefreshRequest { RefreshToken = "any_token" }, "127.0.0.1");
        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("inactif");
    }

    // ── Rôle insuffisant pour le client cible ────────────────────────────────

    [Fact]
    public async Task Refresh_RoleInsuffisant_RetourneAccesDenie()
    {
        // Utilisateur avec rôle "Finance" mais le client cible requiert "RH"
        var user       = new UtilisateurBuilder().WithRole("Finance").Build();
        var rt         = BuildRefreshToken(user);
        var rhClient   = new ClientApplicationBuilder().WithAllowedRoles("RH").Build();

        _repoMock.Setup(r => r.GetRefreshTokenByHashAsync(It.IsAny<string>(), default)).ReturnsAsync(rt);
        _repoMock.Setup(r => r.GetClientByClientIdAsync("rh-app", default)).ReturnsAsync(rhClient);

        var cmd = new RefreshTokenCommand(
            new RefreshRequest { RefreshToken = "token", ClientId = "rh-app" },
            "127.0.0.1");
        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("insuffisant");
    }

    // ── Refresh token vide ───────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_TokenVide_RetourneEchec()
    {
        var cmd    = new RefreshTokenCommand(new RefreshRequest { RefreshToken = "" }, "127.0.0.1");
        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("requis");
    }
}

/// <summary>
/// Tests unitaires pour LogoutHandler.
/// Scénarios : logout avec refresh token spécifique, logout global (révoque tout),
/// révocation du JWT via blacklist.
/// </summary>
public class LogoutHandlerTests
{
    private readonly Mock<IAuthRepository> _repoMock;
    private readonly Mock<IPasswordHasher> _hasherMock;
    private readonly LogoutHandler         _handler;

    public LogoutHandlerTests()
    {
        _repoMock   = RepoMockHelper.Create();
        _hasherMock = new Mock<IPasswordHasher>();
        _repoMock.Setup(r => r.RevokeJwtAsync(It.IsAny<string>(), It.IsAny<DateTime>(), It.IsAny<CancellationToken>()))
                 .Returns(Task.CompletedTask);
        _handler = new LogoutHandler(_repoMock.Object, FakeConfiguration.Build(), _hasherMock.Object);
    }

    // ── Logout avec refresh token spécifique ─────────────────────────────────

    [Fact]
    public async Task Logout_AvecRefreshTokenSpecifique_MarqueTokenUtilise()
    {
        var userId = Guid.NewGuid();
        var rt     = new RefreshToken
        {
            Id            = Guid.NewGuid(),
            UtilisateurId = userId,
            EstUtilise    = false,
            Utilisateur   = new UtilisateurBuilder().WithId(userId).Build(),
            Client        = new ClientApplicationBuilder().Build()
        };

        _repoMock.Setup(r => r.GetRefreshTokenByHashAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                 .ReturnsAsync(rt);

        var cmd = new LogoutCommand(
            new LogoutRequest { RefreshToken = "some_raw_token" },
            userId,
            Jti:             Guid.NewGuid().ToString(),
            TokenExpiration: DateTime.UtcNow.AddMinutes(10));

        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeTrue();
        rt.EstUtilise.Should().BeTrue();
        _repoMock.Verify(r => r.RevokeJwtAsync(It.IsAny<string>(), It.IsAny<DateTime>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── Logout global (sans refresh token) ───────────────────────────────────

    [Fact]
    public async Task Logout_SansRefreshToken_RevoqueToussLesTokensEtSessions()
    {
        var userId = Guid.NewGuid();
        var rt1    = new RefreshToken { Id = Guid.NewGuid(), UtilisateurId = userId, EstUtilise = false };
        var rt2    = new RefreshToken { Id = Guid.NewGuid(), UtilisateurId = userId, EstUtilise = false };
        var session = new Session { Id = Guid.NewGuid(), UtilisateurId = userId, Statut = StatutSession.ACTIVE };

        _repoMock.Setup(r => r.GetActiveRefreshTokensAsync(userId, default))
                 .ReturnsAsync(new List<RefreshToken> { rt1, rt2 });
        _repoMock.Setup(r => r.GetActiveSessionsAsync(userId, default))
                 .ReturnsAsync(new List<Session> { session });

        var cmd = new LogoutCommand(
            null,
            userId,
            Jti:             Guid.NewGuid().ToString(),
            TokenExpiration: DateTime.UtcNow.AddMinutes(10));

        var result = await _handler.Handle(cmd, default);

        result.Success.Should().BeTrue();
        rt1.EstUtilise.Should().BeTrue();
        rt2.EstUtilise.Should().BeTrue();
        session.Statut.Should().Be(StatutSession.REVOQUEE);
    }

    // ── JWT toujours blacklisté ───────────────────────────────────────────────

    [Fact]
    public async Task Logout_BlacklisteToujours_LeJtiDuJwt()
    {
        var userId = Guid.NewGuid();
        var jti    = Guid.NewGuid().ToString();
        var exp    = DateTime.UtcNow.AddMinutes(10);

        _repoMock.Setup(r => r.GetActiveRefreshTokensAsync(userId, default))
                 .ReturnsAsync(new List<RefreshToken>());
        _repoMock.Setup(r => r.GetActiveSessionsAsync(userId, default))
                 .ReturnsAsync(new List<Session>());

        await _handler.Handle(new LogoutCommand(null, userId, jti, exp), default);

        _repoMock.Verify(r => r.RevokeJwtAsync(jti, exp, It.IsAny<CancellationToken>()), Times.Once);
    }
}