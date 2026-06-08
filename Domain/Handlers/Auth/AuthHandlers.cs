using MediatR;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Domain.Commands.Auth;
using Domain.Interfaces;
using Domain.Models;
using Domain.Models.Enums;
using Domain.Queries.Auth;

namespace Domain.Handlers.Auth
{
    
    public abstract class AuthHandlerBase
    {
        protected readonly IAuthRepository _repo;
        protected readonly IConfiguration  _configuration;
        protected readonly IPasswordHasher _passwordHasher;

        protected AuthHandlerBase(
            IAuthRepository  repo,
            IConfiguration   configuration,
            IPasswordHasher  passwordHasher)
        {
            _repo           = repo;
            _configuration  = configuration;
            _passwordHasher = passwordHasher;
        }

        protected string GenerateJwtToken(Utilisateur user, List<string> roles, string? scopes = null)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey   = Encoding.UTF8.GetBytes(
                jwtSettings["SecretKey"] ?? "poulina-sso-super-secret-key-minimum-32-characters-2024");

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,        user.Id.ToString()),
                new Claim(ClaimTypes.NameIdentifier,          user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email,      user.Email),
                new Claim(JwtRegisteredClaimNames.GivenName,  user.Prenom ?? ""),
                new Claim(JwtRegisteredClaimNames.FamilyName, user.Nom    ?? ""),
                new Claim(JwtRegisteredClaimNames.Jti,        Guid.NewGuid().ToString())
            };

            foreach (var role in roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            if (!string.IsNullOrEmpty(scopes))
                claims.Add(new Claim("scope", scopes));

            if (user.DoitChangerMotDePasse)
                claims.Add(new Claim("pwd_change_required", "true"));

            var lifetimeSeconds = int.TryParse(jwtSettings["TokenLifetimeSecondes"], out var lt) ? lt : 900;

            var token = new JwtSecurityToken(
                issuer:             jwtSettings["Issuer"],
                audience:           jwtSettings["Audience"],
                claims:             claims,
                expires:            DateTime.UtcNow.AddSeconds(lifetimeSeconds),
                signingCredentials: new SigningCredentials(
                    new SymmetricSecurityKey(secretKey),
                    SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        protected async Task<string> CreateRefreshTokenAsync(Guid userId, Guid clientId, string ipAddress)
        {
            var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

            await _repo.AddRefreshTokenAsync(new RefreshToken
            {
                Id             = Guid.NewGuid(),
                UtilisateurId  = userId,
                ClientId       = clientId,
                TokenHash      = HashToken(rawToken),
                DateCreation   = DateTime.UtcNow,
                DateExpiration = DateTime.UtcNow.AddDays(7),
                EstUtilise     = false,
                IpAddress      = ipAddress
            });

            await _repo.SaveChangesAsync();
            return rawToken;
        }

        protected string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            return Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(token)));
        }

        protected async Task LogAuditAsync(
            Guid? userId, string action, string categorie, bool succes,
            string ipAddress, string userAgent, string? erreur = null)
        {
            await _repo.AddAuditLogAsync(new AuditLog
            {
                Id            = Guid.NewGuid(),
                UtilisateurId = userId,
                Action        = action,
                Categorie     = categorie,
                IpAddress     = ipAddress,
                UserAgent     = userAgent,
                DateHeure     = DateTime.UtcNow,
                Succes        = succes,
                MessageErreur = erreur
            });
            await _repo.SaveChangesAsync();
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // 1. RegisterHandler
    // ────────────────────────────────────────────────────────────────────────
    public class RegisterHandler : AuthHandlerBase, IRequestHandler<RegisterCommand, RegisterResult>
    {
        public RegisterHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<RegisterResult> Handle(RegisterCommand cmd, CancellationToken ct)
        {
            var req = cmd.Request;

            if (string.IsNullOrWhiteSpace(req.Email) ||
                string.IsNullOrWhiteSpace(req.Password) ||
                req.Password.Length < 8)
                return new RegisterResult { Success = false, Message = "Email et mot de passe (min 8 caractères) requis." };

            if (await _repo.EmailExisteAsync(req.Email, ct))
                return new RegisterResult { Success = false, Message = "Un utilisateur avec cet email existe déjà." };

            var user = new Utilisateur
            {
                Id                    = Guid.NewGuid(),
                Email                 = req.Email.Trim().ToLower(),
                Nom                   = req.Nom,
                Prenom                = req.Prenom,
                MotDePasseHash        = _passwordHasher.Hash(req.Password),
                Salt                  = string.Empty,
                Statut                = StatutUtilisateur.ACTIF,
                DateCreation          = DateTime.UtcNow,
                TypeMFA               = TypeMFA.AUCUN,
                DoitChangerMotDePasse = false
            };

            await _repo.AddUtilisateurAsync(user, ct);
            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(user.Id, "REGISTER", "AUTH", true, "", "", $"Nouvel utilisateur: {user.Email}");

            return new RegisterResult { Success = true, Message = "Utilisateur enregistré avec succès.", UserId = user.Id };
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // 2. LoginHandler
    // ────────────────────────────────────────────────────────────────────────
    public class LoginHandler : AuthHandlerBase, IRequestHandler<LoginCommand, LoginResult>
    {
        public LoginHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<LoginResult> Handle(LoginCommand cmd, CancellationToken ct)
        {
            var req = cmd.Request;

            if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
                return new LoginResult { Success = false, Message = "Email et mot de passe requis." };

            var user = await _repo.GetUtilisateurByEmailAsync(req.Email.Trim().ToLower(), ct);

            if (user == null)
            {
                await LogAuditAsync(null, "LOGIN_FAILED", "AUTH", false, cmd.IpAddress, cmd.UserAgent, "Email introuvable");
                return new LoginResult { Success = false, Message = "Email ou mot de passe incorrect." };
            }

            if (user.Statut == StatutUtilisateur.BLOQUE)
            {
                await LogAuditAsync(user.Id, "LOGIN_BLOCKED", "AUTH", false, cmd.IpAddress, cmd.UserAgent, user.RaisonBlocage);
                return new LoginResult { Success = false, ErrorCode = "BLOCKED", Message = "Compte bloqué. Contactez l'administrateur.", Raison = user.RaisonBlocage };
            }

            if (user.Statut == StatutUtilisateur.DESACTIVE)
            {
                await LogAuditAsync(user.Id, "LOGIN_DISABLED", "AUTH", false, cmd.IpAddress, cmd.UserAgent);
                return new LoginResult { Success = false, ErrorCode = "DISABLED", Message = "Votre compte est désactivé." };
            }

            if (user.DateVerrouillage.HasValue && user.DateVerrouillage > DateTime.UtcNow)
            {
                await LogAuditAsync(user.Id, "LOGIN_LOCKED", "AUTH", false, cmd.IpAddress, cmd.UserAgent);
                return new LoginResult { Success = false, ErrorCode = "LOCKED", Message = "Compte verrouillé temporairement. Réessayez dans 15 minutes." };
            }

            if (!_passwordHasher.Verify(req.Password, user.MotDePasseHash))
            {
                user.TentativesConnexionEchouees++;
                if (user.TentativesConnexionEchouees >= 5)
                    user.DateVerrouillage = DateTime.UtcNow.AddMinutes(15);

                await _repo.SaveChangesAsync(ct);
                await LogAuditAsync(user.Id, "LOGIN_FAILED", "AUTH", false, cmd.IpAddress, cmd.UserAgent, "Mot de passe incorrect");
                return new LoginResult { Success = false, Message = "Email ou mot de passe incorrect." };
            }

            user.TentativesConnexionEchouees = 0;
            user.DateVerrouillage            = null;
            user.DateDerniereConnexion       = DateTime.UtcNow;

            await _repo.AddSessionAsync(new Session
            {
                Id                   = Guid.NewGuid(),
                UtilisateurId        = user.Id,
                SessionId            = Guid.NewGuid().ToString(),
                IpAddress            = cmd.IpAddress,
                UserAgent            = cmd.UserAgent,
                DateCreation         = DateTime.UtcNow,
                DateDerniereActivite = DateTime.UtcNow,
                DateExpiration       = DateTime.UtcNow.AddHours(8),
                Statut               = StatutSession.ACTIVE,
                DeviceInfo           = "direct-login"
            });

            var defaultClient = await _repo.GetFirstClientAsync(ct);
            if (defaultClient == null)
                return new LoginResult { Success = false, Message = "Aucune application cliente configurée." };

            var roles        = user.UtilisateurRoles.Where(ur => ur.Actif).Select(ur => ur.Role.Nom).ToList();
            var accessToken  = GenerateJwtToken(user, roles);
            var refreshToken = await CreateRefreshTokenAsync(user.Id, defaultClient.Id, cmd.IpAddress);

            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(user.Id, "LOGIN_SUCCESS", "AUTH", true, cmd.IpAddress, cmd.UserAgent);

            return new LoginResult
            {
                Success               = true,
                AccessToken           = accessToken,
                RefreshToken          = refreshToken,
                DoitChangerMotDePasse = user.DoitChangerMotDePasse,
                UserId                = user.Id
            };
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // 3. LoginWithCodeHandler
    // ────────────────────────────────────────────────────────────────────────
    public class LoginWithCodeHandler : AuthHandlerBase, IRequestHandler<LoginWithCodeCommand, LoginWithCodeResult>
    {
        public LoginWithCodeHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<LoginWithCodeResult> Handle(LoginWithCodeCommand cmd, CancellationToken ct)
        {
            var req = cmd.Request;

            if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
                return new LoginWithCodeResult { Success = false, Message = "Email et mot de passe requis." };

            var user = await _repo.GetUtilisateurByEmailAsync(req.Email.Trim().ToLower(), ct);

            if (user == null)
            {
                await LogAuditAsync(null, "LOGIN_FAILED", "AUTH", false, cmd.IpAddress, cmd.UserAgent, "Email introuvable");
                return new LoginWithCodeResult { Success = false, Message = "Email ou mot de passe incorrect." };
            }

            if (user.Statut == StatutUtilisateur.BLOQUE)
            {
                await LogAuditAsync(user.Id, "LOGIN_BLOCKED", "AUTH", false, cmd.IpAddress, cmd.UserAgent, user.RaisonBlocage);
                return new LoginWithCodeResult { Success = false, ErrorCode = "BLOCKED", Message = "Compte bloqué." };
            }

            if (user.Statut == StatutUtilisateur.DESACTIVE)
            {
                await LogAuditAsync(user.Id, "LOGIN_DISABLED", "AUTH", false, cmd.IpAddress, cmd.UserAgent);
                return new LoginWithCodeResult { Success = false, ErrorCode = "DISABLED", Message = "Compte désactivé." };
            }

            if (user.DateVerrouillage.HasValue && user.DateVerrouillage > DateTime.UtcNow)
            {
                await LogAuditAsync(user.Id, "LOGIN_LOCKED", "AUTH", false, cmd.IpAddress, cmd.UserAgent);
                return new LoginWithCodeResult { Success = false, ErrorCode = "LOCKED", Message = "Compte verrouillé temporairement." };
            }

            if (!_passwordHasher.Verify(req.Password, user.MotDePasseHash))
            {
                user.TentativesConnexionEchouees++;
                if (user.TentativesConnexionEchouees >= 5)
                    user.DateVerrouillage = DateTime.UtcNow.AddMinutes(15);

                await _repo.SaveChangesAsync(ct);
                await LogAuditAsync(user.Id, "LOGIN_FAILED", "AUTH", false, cmd.IpAddress, cmd.UserAgent, "Mot de passe incorrect");
                return new LoginWithCodeResult { Success = false, Message = "Email ou mot de passe incorrect." };
            }

            var client = await _repo.GetClientByClientIdAsync(req.ClientId, ct);

            if (client == null)
            {
                await LogAuditAsync(user.Id, "LOGIN_FAILED", "AUTH", false, cmd.IpAddress, cmd.UserAgent, $"Client inconnu: {req.ClientId}");
                return new LoginWithCodeResult { Success = false, ErrorCode = "invalid_client", Message = "Client inconnu ou inactif." };
            }

            if (!client.RedirectionUris.Contains(req.RedirectUri))
            {
                await LogAuditAsync(user.Id, "LOGIN_FAILED", "AUTH", false, cmd.IpAddress, cmd.UserAgent, "redirect_uri invalide");
                return new LoginWithCodeResult { Success = false, ErrorCode = "invalid_redirect_uri", Message = "URI de redirection non autorisée." };
            }

            if (client.RequiertPKCE && string.IsNullOrEmpty(req.CodeChallenge))
                return new LoginWithCodeResult { Success = false, ErrorCode = "code_challenge_required", Message = "PKCE requis." };

            var allowedRoles = client.AllowedRoles.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(r => r.Trim()).ToList();
            var userRoles    = user.UtilisateurRoles.Where(ur => ur.Actif).Select(ur => ur.Role.Nom).ToList();

            if (!userRoles.Any(r => allowedRoles.Contains(r)))
            {
                await LogAuditAsync(user.Id, "ACCESS_DENIED", "AUTH", false, cmd.IpAddress, cmd.UserAgent,
                    $"Rôles user: [{string.Join(", ", userRoles)}]. Requis: [{string.Join(", ", allowedRoles)}]");
                return new LoginWithCodeResult { Success = false, ErrorCode = "access_denied", Message = $"Vous n'avez pas les droits d'accès à {client.Nom}." };
            }

            user.TentativesConnexionEchouees = 0;
            user.DateVerrouillage            = null;
            user.DateDerniereConnexion       = DateTime.UtcNow;

            await _repo.AddSessionAsync(new Session
            {
                Id                   = Guid.NewGuid(),
                UtilisateurId        = user.Id,
                SessionId            = Guid.NewGuid().ToString(),
                IpAddress            = cmd.IpAddress,
                UserAgent            = cmd.UserAgent,
                DateCreation         = DateTime.UtcNow,
                DateDerniereActivite = DateTime.UtcNow,
                DateExpiration       = DateTime.UtcNow.AddHours(8),
                Statut               = StatutSession.ACTIVE,
                DeviceInfo           = client.ClientId
            });

            
            var normalizedChallenge = req.CodeChallengeMethod?.ToUpper() switch
            {
                "S256"  => req.CodeChallenge,   
                "PLAIN" => req.CodeChallenge,   
                _       => req.CodeChallenge
            };

            var rawCode = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            await _repo.AddAuthorizationCodeAsync(new AuthorizationCode
            {
                Id                  = Guid.NewGuid(),
                CodeHash            = HashToken(rawCode),
                UtilisateurId       = user.Id,
                ClientId            = client.Id,
                DateCreation        = DateTime.UtcNow,
                DateExpiration      = DateTime.UtcNow.AddMinutes(5),
                EstUtilise          = false,
                CodeChallenge       = normalizedChallenge,
                CodeChallengeMethod = req.CodeChallengeMethod,
                Scopes              = req.Scopes
            });

            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(user.Id, "AUTH_CODE_ISSUED", "AUTH", true, cmd.IpAddress, cmd.UserAgent, $"Code émis pour {client.Nom}");

            return new LoginWithCodeResult
            {
                Success     = true,
                Code        = rawCode,
                RedirectUri = $"{req.RedirectUri}?code={rawCode}&state={req.State}"
            };
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // 4. RefreshTokenHandler
    // ────────────────────────────────────────────────────────────────────────
    public class RefreshTokenHandler : AuthHandlerBase, IRequestHandler<RefreshTokenCommand, RefreshResult>
    {
        public RefreshTokenHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<RefreshResult> Handle(RefreshTokenCommand cmd, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(cmd.Request.RefreshToken))
                return new RefreshResult { Success = false, Message = "Refresh token requis." };

            var tokenHash = HashToken(cmd.Request.RefreshToken);
            var entity    = await _repo.GetRefreshTokenByHashAsync(tokenHash, ct);

            if (entity == null)
                return new RefreshResult { Success = false, Message = "Refresh token invalide." };

            if (entity.EstUtilise)
            {
                await LogAuditAsync(entity.UtilisateurId, "REFRESH_TOKEN_REUSE", "AUTH", false, cmd.IpAddress, "", "Possible attaque");
                return new RefreshResult { Success = false, Message = "Refresh token déjà utilisé." };
            }

            if (entity.DateExpiration < DateTime.UtcNow)
                return new RefreshResult { Success = false, Message = "Refresh token expiré. Veuillez vous reconnecter." };

            var user = entity.Utilisateur;
            if (user.Statut == StatutUtilisateur.BLOQUE || user.Statut == StatutUtilisateur.DESACTIVE)
                return new RefreshResult { Success = false, Message = "Compte inactif." };

            entity.EstUtilise      = true;
            entity.DateRevoquation = DateTime.UtcNow;

            var roles        = user.UtilisateurRoles.Where(ur => ur.Actif).Select(ur => ur.Role.Nom).ToList();
            var accessToken  = GenerateJwtToken(user, roles);
            var refreshToken = await CreateRefreshTokenAsync(user.Id, entity.ClientId, cmd.IpAddress);

            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(user.Id, "TOKEN_REFRESHED", "AUTH", true, cmd.IpAddress, "");

            return new RefreshResult { Success = true, AccessToken = accessToken, RefreshToken = refreshToken };
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // 5. LogoutHandler
    // ────────────────────────────────────────────────────────────────────────
    public class LogoutHandler : AuthHandlerBase, IRequestHandler<LogoutCommand, LogoutResult>
    {
        public LogoutHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<LogoutResult> Handle(LogoutCommand cmd, CancellationToken ct)
        {
            // ── 1. Blacklister le JWT access token courant ────────────────────
            if (!string.IsNullOrEmpty(cmd.Jti))
                await _repo.RevokeJwtAsync(cmd.Jti, cmd.TokenExpiration, ct);

            // ── 2. Révoquer les Refresh Tokens ────────────────────────────────
            if (!string.IsNullOrEmpty(cmd.Request?.RefreshToken))
            {
                var tokenHash = HashToken(cmd.Request.RefreshToken);
                var rt = await _repo.GetRefreshTokenByHashAsync(tokenHash, ct);
                if (rt != null && rt.UtilisateurId == cmd.UserId)
                {
                    rt.EstUtilise      = true;
                    rt.DateRevoquation = DateTime.UtcNow;
                }
            }
            else
            {
                var allTokens = await _repo.GetActiveRefreshTokensAsync(cmd.UserId, ct);
                foreach (var rt in allTokens)
                {
                    rt.EstUtilise      = true;
                    rt.DateRevoquation = DateTime.UtcNow;
                }

                var sessions = await _repo.GetActiveSessionsAsync(cmd.UserId, ct);
                foreach (var s in sessions)
                    s.Statut = StatutSession.REVOQUEE;
            }

            // ── 3. Nettoyer les tokens expirés en base (maintenance) ──────────
            await _repo.CleanExpiredRevokedTokensAsync(ct);

            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(cmd.UserId, "LOGOUT", "AUTH", true, "", "");

            return new LogoutResult { Success = true, Message = "Déconnexion réussie." };
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // 6. GetUserInfoHandler (Query)
    // ────────────────────────────────────────────────────────────────────────
    public class GetUserInfoHandler : AuthHandlerBase, IRequestHandler<GetUserInfoQuery, UserInfoResult>
    {
        public GetUserInfoHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<UserInfoResult> Handle(GetUserInfoQuery query, CancellationToken ct)
        {
            var user = await _repo.GetUtilisateurByIdAsync(query.UserId, ct);

            if (user == null)
                return new UserInfoResult { Success = false };

            return new UserInfoResult
            {
                Success               = true,
                Sub                   = user.Id,
                Email                 = user.Email,
                Nom                   = user.Nom,
                Prenom                = user.Prenom,
                Statut                = user.Statut.ToString(),
                DoitChangerMotDePasse = user.DoitChangerMotDePasse,
                Roles                 = user.UtilisateurRoles.Select(ur => ur.Role.Nom).ToList()
            };
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // 7. AuthorizeHandler (Query — validation paramètres OAuth2 step 1)
    // ────────────────────────────────────────────────────────────────────────
    public class AuthorizeHandler : AuthHandlerBase, IRequestHandler<AuthorizeQuery, AuthorizeResult>
    {
        public AuthorizeHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<AuthorizeResult> Handle(AuthorizeQuery query, CancellationToken ct)
        {
            if (query.ResponseType != "code")
                return new AuthorizeResult { Success = false, ErrorMessage = "unsupported_response_type" };

            var client = await _repo.GetClientByClientIdAsync(query.ClientId, ct);

            if (client == null)
                return new AuthorizeResult { Success = false, ErrorMessage = "invalid_client" };

            if (!client.RedirectionUris.Contains(query.RedirectUri))
                return new AuthorizeResult { Success = false, ErrorMessage = "invalid_redirect_uri" };

            if (client.RequiertPKCE && string.IsNullOrEmpty(query.CodeChallenge))
                return new AuthorizeResult { Success = false, ErrorMessage = "code_challenge_required" };

            return new AuthorizeResult
            {
                Success  = true,
                LoginUrl = $"/login?client_id={query.ClientId}&redirect_uri={query.RedirectUri}&state={query.State}&scope={query.Scope}"
            };
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // 8. ExchangeCodeHandler (Command — code → access token)
    // ────────────────────────────────────────────────────────────────────────
    public class ExchangeCodeHandler : AuthHandlerBase, IRequestHandler<ExchangeCodeCommand, ExchangeCodeResult>
    {
        public ExchangeCodeHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<ExchangeCodeResult> Handle(ExchangeCodeCommand cmd, CancellationToken ct)
        {
            var req = cmd.Request;

            if (req.GrantType != "authorization_code")
                return new ExchangeCodeResult { Success = false, ErrorCode = "unsupported_grant_type" };

            var authCode = await _repo.GetAuthorizationCodeByHashAsync(HashToken(req.Code), ct);

            if (authCode == null)
                return new ExchangeCodeResult { Success = false, ErrorCode = "invalid_grant", ErrorDescription = "Code invalide." };
            if (authCode.EstUtilise)
                return new ExchangeCodeResult { Success = false, ErrorCode = "invalid_grant", ErrorDescription = "Code déjà utilisé." };
            if (authCode.DateExpiration < DateTime.UtcNow)
                return new ExchangeCodeResult { Success = false, ErrorCode = "invalid_grant", ErrorDescription = "Code expiré." };
            if (authCode.Client.ClientId != req.ClientId)
                return new ExchangeCodeResult { Success = false, ErrorCode = "invalid_client" };

            if (!string.IsNullOrEmpty(authCode.CodeChallenge))
            {
                if (string.IsNullOrEmpty(req.CodeVerifier))
                    return new ExchangeCodeResult { Success = false, ErrorCode = "invalid_grant", ErrorDescription = "Code verifier manquant." };

                bool pkceValide;

                if (authCode.CodeChallengeMethod?.ToUpper() == "S256")
                {
                    var verifierHash = Convert.ToBase64String(
                        SHA256.HashData(Encoding.UTF8.GetBytes(req.CodeVerifier)))
                        .Replace("+", "-")
                        .Replace("/", "_")
                        .TrimEnd('=');

                    pkceValide = verifierHash == authCode.CodeChallenge;
                }
                else
                {
                    pkceValide = req.CodeVerifier == authCode.CodeChallenge;
                }

                if (!pkceValide)
                    return new ExchangeCodeResult { Success = false, ErrorCode = "invalid_grant", ErrorDescription = "Code verifier invalide." };
            }

            authCode.EstUtilise = true;

            var user         = authCode.Utilisateur;
            var roles        = user.UtilisateurRoles.Where(ur => ur.Actif).Select(ur => ur.Role.Nom).ToList();
            var accessToken  = GenerateJwtToken(user, roles, authCode.Scopes);
            var refreshToken = await CreateRefreshTokenAsync(user.Id, authCode.ClientId, "");

            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(user.Id, "TOKEN_ISSUED", "AUTH", true, "", "", $"Token émis pour: {authCode.Client.Nom}");

            return new ExchangeCodeResult
            {
                Success      = true,
                AccessToken  = accessToken,
                RefreshToken = refreshToken,
                TokenType    = "Bearer",
                ExpiresIn    = 900,
                Scope        = authCode.Scopes
            };
        }
    }
}