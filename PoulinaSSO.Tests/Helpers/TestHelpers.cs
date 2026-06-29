using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Moq;
using OtpNet;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Domain.Interfaces;
using Domain.Models;
using Domain.Models.Enums;

namespace PoulinaSSO.Tests.Helpers;

/// <summary>
/// Fournit une IConfiguration en mémoire avec les settings JWT nécessaires aux handlers.
/// </summary>
public static class FakeConfiguration
{
    public const string SecretKey = "PoulinaSSO-SuperSecretKey-2024!@#$";
    public const string Issuer    = "https://localhost:7001";
    public const string Audience  = "https://localhost:7001";
    public const string BaseUrl   = "http://localhost:5095";

    public static IConfiguration Build() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["JwtSettings:SecretKey"]             = SecretKey,
                ["JwtSettings:Issuer"]                = Issuer,
                ["JwtSettings:Audience"]              = Audience,
                ["JwtSettings:ExpirationMinutes"]     = "15",
                ["JwtSettings:TokenLifetimeSecondes"] = "900",
                ["AppSettings:BaseUrl"]               = BaseUrl,
                ["Brevo:SmtpLogin"]                   = "test@smtp-brevo.com",
                ["Brevo:SmtpPassword"]                = "fake-password",
                ["Brevo:ExpéditeurEmail"]             = "noreply@test.com",
                ["Brevo:ExpéditeurNom"]               = "Test SSO",
            })
            .Build();
}

/// <summary>
/// Builder fluent pour créer des objets Utilisateur dans les tests.
/// </summary>
public class UtilisateurBuilder
{
    private readonly Utilisateur _u = new()
    {
        Id                          = Guid.NewGuid(),
        Email                       = "test@poulina.com",
        Nom                         = "Dupont",
        Prenom                      = "Jean",
        MotDePasseHash              = "hashed_password",
        Salt                        = string.Empty,
        Statut                      = StatutUtilisateur.ACTIF,
        EmailVerifie                = true,
        TypeMFA                     = TypeMFA.AUCUN,
        MFAValidee                  = false,
        TentativesConnexionEchouees = 0,
        DoitChangerMotDePasse       = false,
        DateCreation                = DateTime.UtcNow,
        UtilisateurRoles            = new List<UtilisateurRole>()
    };

    public UtilisateurBuilder WithId(Guid id)                 { _u.Id = id;                         return this; }
    public UtilisateurBuilder WithEmail(string email)         { _u.Email = email;                   return this; }
    public UtilisateurBuilder WithStatut(StatutUtilisateur s) { _u.Statut = s;                      return this; }
    public UtilisateurBuilder WithEmailVerifie(bool v)        { _u.EmailVerifie = v;                return this; }
    public UtilisateurBuilder WithPasswordHash(string h)      { _u.MotDePasseHash = h;              return this; }
    public UtilisateurBuilder WithVerrouillage(DateTime? d)   { _u.DateVerrouillage = d;            return this; }
    public UtilisateurBuilder WithTentatives(int n)           { _u.TentativesConnexionEchouees = n; return this; }

    // Deux noms acceptés pour éviter les cassures dans les tests existants
    public UtilisateurBuilder WithDoitChangerMdp(bool v)          { _u.DoitChangerMotDePasse = v; return this; }
    public UtilisateurBuilder WithDoitChangerMotDePasse(bool v)   { _u.DoitChangerMotDePasse = v; return this; }

    public UtilisateurBuilder WithRole(string roleName)
    {
        var role = new Role { Id = Guid.NewGuid(), Nom = roleName };
        _u.UtilisateurRoles.Add(new UtilisateurRole { Role = role, Actif = true });
        return this;
    }

    public UtilisateurBuilder WithMfaTotp(string? secret = null)
    {
        _u.TypeMFA    = TypeMFA.TOTP;
        _u.MFAValidee = true;
        _u.SecretMFA  = secret ?? TotpHelper.GenerateSecret();
        return this;
    }

    public UtilisateurBuilder WithEmailVerificationToken(string tokenHash, DateTime? expiration = null)
    {
        _u.EmailVerifie                = false;
        _u.TokenVerificationEmail      = tokenHash;
        _u.TokenVerificationExpiration = expiration ?? DateTime.UtcNow.AddHours(24);
        return this;
    }

    public Utilisateur Build() => _u;
}

/// <summary>
/// Builder fluent pour les clients OAuth2 / applications.
/// </summary>
public class ClientApplicationBuilder
{
    private readonly ClientApplication _c = new()
    {
        Id              = Guid.NewGuid(),
        ClientId        = "rh-app",
        Nom             = "RH Application",
        RedirectionUris = "http://localhost:3001/callback",
        AllowedRoles    = "RH_USER,RH_ADMIN",
        RequiertPKCE    = true,
        Actif           = true,
    };

    public ClientApplicationBuilder WithClientId(string id)     { _c.ClientId = id;         return this; }
    public ClientApplicationBuilder WithRedirectUri(string uri) { _c.RedirectionUris = uri; return this; }
    public ClientApplicationBuilder WithAllowedRoles(string r)  { _c.AllowedRoles = r;      return this; }
    public ClientApplicationBuilder WithRequiertPKCE(bool v)    { _c.RequiertPKCE = v;      return this; }
    public ClientApplication Build() => _c;
}

/// <summary>
/// Helpers pour générer des codes TOTP valides dans les tests.
/// </summary>
public static class TotpHelper
{
    public static string GenerateSecret()
    {
        var bytes = KeyGeneration.GenerateRandomKey(20);
        return Base32Encoding.ToString(bytes);
    }

    /// <summary>Génère un code TOTP valide pour le secret donné (fenêtre actuelle).</summary>
    public static string GenerateCurrentCode(string secret)
    {
        var bytes = Base32Encoding.ToBytes(secret);
        var totp  = new Totp(bytes, step: 30, totpSize: 6);
        return totp.ComputeTotp();
    }

    public static string GenerateInvalidCode() => "000000";
}

/// <summary>
/// Helpers pour générer des MFA pending tokens dans les tests.
/// </summary>
public static class MfaPendingTokenHelper
{
    public static string Generate(Guid userId, bool expired = false)
    {
        var key    = Encoding.UTF8.GetBytes(FakeConfiguration.SecretKey);
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new Claim(ClaimTypes.NameIdentifier,   userId.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("mfa_pending",               "true"),
        };

        var token = new JwtSecurityToken(
            issuer:             FakeConfiguration.Issuer,
            audience:           FakeConfiguration.Audience,
            claims:             claims,
            expires:            expired
                                    ? DateTime.UtcNow.AddMinutes(-1)
                                    : DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

/// <summary>
/// Helpers pour créer et configurer les Mocks de IAuthRepository.
/// </summary>
public static class RepoMockHelper
{
    public static Mock<IAuthRepository> Create()
    {
        var mock = new Mock<IAuthRepository>();
        mock.Setup(r => r.SaveChangesAsync(It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        mock.Setup(r => r.AddAuditLogAsync(It.IsAny<AuditLog>()))
            .Returns(Task.CompletedTask);
        mock.Setup(r => r.AddSessionAsync(It.IsAny<Session>()))
            .Returns(Task.CompletedTask);
        mock.Setup(r => r.AddRefreshTokenAsync(It.IsAny<RefreshToken>()))
            .Returns(Task.CompletedTask);
        mock.Setup(r => r.CleanExpiredRevokedTokensAsync(It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        return mock;
    }

    public static string HashToken(string raw)
    {
        using var sha = SHA256.Create();
        return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(raw)));
    }
}