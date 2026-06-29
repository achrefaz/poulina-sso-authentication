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
using OtpNet;

namespace Domain.Handlers.Auth
{
    // ── Classe de base partagée ───────────────────────────────────────────────

    public abstract class AuthHandlerBase
    {
        protected readonly IAuthRepository _repo;
        protected readonly IConfiguration  _configuration;
        protected readonly IPasswordHasher _passwordHasher;

        protected AuthHandlerBase(
            IAuthRepository repo,
            IConfiguration  configuration,
            IPasswordHasher passwordHasher)
        {
            _repo           = repo;
            _configuration  = configuration;
            _passwordHasher = passwordHasher;
        }

        protected (string Token, string Jti) GenerateJwtToken(
            Utilisateur user, List<string> roles, string? scopes = null)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey   = Encoding.UTF8.GetBytes(
                jwtSettings["SecretKey"] ?? "poulina-sso-super-secret-key-minimum-32-characters-2024");

            var jti = Guid.NewGuid().ToString();

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub,       user.Id.ToString()),
                new(ClaimTypes.NameIdentifier,          user.Id.ToString()),
                new(JwtRegisteredClaimNames.Email,      user.Email),
                new(JwtRegisteredClaimNames.GivenName,  user.Prenom ?? ""),
                new(JwtRegisteredClaimNames.FamilyName, user.Nom    ?? ""),
                new(JwtRegisteredClaimNames.Jti,        jti)
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
                    SecurityAlgorithms.HmacSha256));

            return (new JwtSecurityTokenHandler().WriteToken(token), jti);
        }

        protected string GenerateMfaPendingToken(Guid userId)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey   = Encoding.UTF8.GetBytes(
                jwtSettings["SecretKey"] ?? "poulina-sso-super-secret-key-minimum-32-characters-2024");

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new Claim(ClaimTypes.NameIdentifier,   userId.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("mfa_pending",               "true"),
            };

            var token = new JwtSecurityToken(
                issuer:             jwtSettings["Issuer"],
                audience:           jwtSettings["Audience"],
                claims:             claims,
                expires:            DateTime.UtcNow.AddMinutes(5),
                signingCredentials: new SigningCredentials(
                    new SymmetricSecurityKey(secretKey),
                    SecurityAlgorithms.HmacSha256));

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        protected Guid ValidateMfaPendingToken(string token)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var key         = Encoding.UTF8.GetBytes(
                jwtSettings["SecretKey"] ?? "poulina-sso-super-secret-key-minimum-32-characters-2024");

            var handler    = new JwtSecurityTokenHandler();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey         = new SymmetricSecurityKey(key),
                ValidateIssuer           = true,
                ValidIssuer              = jwtSettings["Issuer"],
                ValidateAudience         = true,
                ValidAudience            = jwtSettings["Audience"],
                ValidateLifetime         = true,
                ClockSkew                = TimeSpan.Zero
            };

            var principal = handler.ValidateToken(token, parameters, out _);
            var pending   = principal.FindFirst("mfa_pending")?.Value;

            if (pending != "true")
                throw new SecurityTokenException("Token invalide : pas un MFA pending token.");

            var sub = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                   ?? principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

            return Guid.Parse(sub!);
        }

        protected async Task<string> CreateRefreshTokenAsync(
            Guid userId, Guid clientId, string ipAddress, int lifetimeDays = 7)
        {
            var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

            await _repo.AddRefreshTokenAsync(new RefreshToken
            {
                Id             = Guid.NewGuid(),
                UtilisateurId  = userId,
                ClientId       = clientId,
                TokenHash      = HashToken(rawToken),
                DateCreation   = DateTime.UtcNow,
                DateExpiration = DateTime.UtcNow.AddDays(lifetimeDays),
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

        protected static bool ValidateTotp(string secret, string code)
        {
            if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(code))
                return false;
            try
            {
                var secretBytes = Base32Encoding.ToBytes(secret);
                var totp        = new Totp(secretBytes, step: 30, totpSize: 6);
                return totp.VerifyTotp(
                    code.Trim(),
                    out _,
                    new VerificationWindow(previous: 1, future: 1));
            }
            catch { return false; }
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

    // ── RegisterHandler ───────────────────────────────────────────────────────

    public class RegisterHandler : AuthHandlerBase, IRequestHandler<RegisterCommand, RegisterResult>
    {
        private readonly IEmailService _emailService;

        public RegisterHandler(
            IAuthRepository repo,
            IConfiguration  cfg,
            IPasswordHasher ph,
            IEmailService   emailService)
            : base(repo, cfg, ph)
        {
            _emailService = emailService;
        }

        public async Task<RegisterResult> Handle(RegisterCommand cmd, CancellationToken ct)
        {
            var req = cmd.Request;

            if (string.IsNullOrWhiteSpace(req.Email) ||
                string.IsNullOrWhiteSpace(req.Password) ||
                req.Password.Length < 8)
                return new RegisterResult { Success = false, Message = "Email et mot de passe (min 8 caractères) requis." };

            if (await _repo.EmailExisteAsync(req.Email, ct))
                return new RegisterResult { Success = false, Message = "Un utilisateur avec cet email existe déjà." };

            var (rawToken, tokenHash) = GenererTokenVerification();

            var user = new Utilisateur
            {
                Id                          = Guid.NewGuid(),
                Email                       = req.Email.Trim().ToLower(),
                Nom                         = req.Nom,
                Prenom                      = req.Prenom,
                MotDePasseHash              = _passwordHasher.Hash(req.Password),
                Salt                        = string.Empty,
                Statut                      = StatutUtilisateur.ACTIF,
                DateCreation                = DateTime.UtcNow,
                TypeMFA                     = TypeMFA.AUCUN,
                DoitChangerMotDePasse       = false,
                EmailVerifie                = false,
                TokenVerificationEmail      = tokenHash,
                TokenVerificationExpiration = DateTime.UtcNow.AddHours(24)
            };

            await _repo.AddUtilisateurAsync(user, ct);
            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(user.Id, "REGISTER", "AUTH", true, "", "", $"Nouvel utilisateur: {user.Email}");

            var baseUrl = _configuration["AppSettings:BaseUrl"] ?? "http://localhost:5095";
            var lien    = $"{baseUrl}/api/Auth/confirm-email?token={Uri.EscapeDataString(rawToken)}";

            await _emailService.EnvoyerEmailConfirmationAsync(
                user.Email,
                $"{user.Prenom} {user.Nom}",
                lien,
                ct);

            return new RegisterResult
            {
                Success = true,
                Message = "Compte créé avec succès. Vérifiez votre email pour activer votre compte.",
                UserId  = user.Id
            };
        }

        private static (string Raw, string Hash) GenererTokenVerification()
        {
            var raw  = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                             .Replace("+", "-").Replace("/", "_").TrimEnd('=');
            using var sha256 = SHA256.Create();
            var hash = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(raw)));
            return (raw, hash);
        }
    }

    // ── LoginDirectHandler ────────────────────────────────────────────────────

    public class LoginDirectHandler : AuthHandlerBase, IRequestHandler<LoginDirectCommand, LoginDirectResult>
    {
        public LoginDirectHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<LoginDirectResult> Handle(LoginDirectCommand cmd, CancellationToken ct)
        {
            var req = cmd.Request;

            if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
                return new LoginDirectResult { Success = false, Message = "Email et mot de passe requis." };

            var user = await _repo.GetUtilisateurByEmailAsync(req.Email.Trim().ToLower(), ct);

            if (user == null)
            {
                await LogAuditAsync(null, "LOGIN_FAILED", "AUTH", false, cmd.IpAddress, cmd.UserAgent, "Email introuvable");
                return new LoginDirectResult { Success = false, Message = "Email ou mot de passe incorrect." };
            }

            if (user.Statut == StatutUtilisateur.BLOQUE)
            {
                await LogAuditAsync(user.Id, "LOGIN_BLOCKED", "AUTH", false, cmd.IpAddress, cmd.UserAgent, user.RaisonBlocage);
                return new LoginDirectResult { Success = false, ErrorCode = "BLOCKED", Message = "Compte bloqué. Contactez l'administrateur.", Raison = user.RaisonBlocage };
            }

            if (user.Statut == StatutUtilisateur.DESACTIVE)
            {
                await LogAuditAsync(user.Id, "LOGIN_DISABLED", "AUTH", false, cmd.IpAddress, cmd.UserAgent);
                return new LoginDirectResult { Success = false, ErrorCode = "DISABLED", Message = "Votre compte est désactivé." };
            }

            if (!user.EmailVerifie)
            {
                await LogAuditAsync(user.Id, "LOGIN_EMAIL_NOT_VERIFIED", "AUTH", false, cmd.IpAddress, cmd.UserAgent);
                return new LoginDirectResult
                {
                    Success       = false,
                    ErrorCode     = "EMAIL_NOT_VERIFIED",
                    EmailVerified = false,
                    Message       = "Votre email n'est pas encore confirmé."
                };
            }

            if (user.DateVerrouillage.HasValue && user.DateVerrouillage > DateTime.UtcNow)
            {
                await LogAuditAsync(user.Id, "LOGIN_LOCKED", "AUTH", false, cmd.IpAddress, cmd.UserAgent);
                return new LoginDirectResult { Success = false, ErrorCode = "LOCKED", Message = "Compte verrouillé temporairement. Réessayez dans 15 minutes." };
            }

            if (!_passwordHasher.Verify(req.Password, user.MotDePasseHash))
            {
                user.TentativesConnexionEchouees++;
                if (user.TentativesConnexionEchouees >= 5)
                    user.DateVerrouillage = DateTime.UtcNow.AddMinutes(15);

                await _repo.SaveChangesAsync(ct);
                await LogAuditAsync(user.Id, "LOGIN_FAILED", "AUTH", false, cmd.IpAddress, cmd.UserAgent, "Mot de passe incorrect");
                return new LoginDirectResult { Success = false, Message = "Email ou mot de passe incorrect." };
            }

            user.TentativesConnexionEchouees = 0;
            user.DateVerrouillage            = null;

            // MFA requis
            if (user.TypeMFA == TypeMFA.TOTP && user.MFAValidee && !string.IsNullOrEmpty(user.SecretMFA))
            {
                var mfaPendingToken = GenerateMfaPendingToken(user.Id);
                await _repo.SaveChangesAsync(ct);
                await LogAuditAsync(user.Id, "LOGIN_MFA_REQUIRED", "AUTH", true, cmd.IpAddress, cmd.UserAgent);

                return new LoginDirectResult
                {
                    Success         = true,
                    MfaRequired     = true,
                    MfaPendingToken = mfaPendingToken,
                    Message         = "Code TOTP requis."
                };
            }

            // Changement de mot de passe obligatoire
            if (user.DoitChangerMotDePasse)
            {
                var roles          = user.UtilisateurRoles.Where(ur => ur.Actif).Select(ur => ur.Role.Nom).ToList();
                var (tempToken, _) = GenerateJwtToken(user, roles);

                await _repo.SaveChangesAsync(ct);
                await LogAuditAsync(user.Id, "LOGIN_PWD_CHANGE_REQUIRED", "AUTH", true, cmd.IpAddress, cmd.UserAgent);

                return new LoginDirectResult
                {
                    Success                = true,
                    PasswordChangeRequired = true,
                    AccessToken            = tempToken,
                    Roles                  = roles,
                    UserId                 = user.Id,
                    Message                = "Changement de mot de passe requis."
                };
            }

            // Login standard
            user.DateDerniereConnexion = DateTime.UtcNow;

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
                return new LoginDirectResult { Success = false, Message = "Aucune application cliente configurée." };

            var userRoles        = user.UtilisateurRoles.Where(ur => ur.Actif).Select(ur => ur.Role.Nom).ToList();
            var (accessToken, _) = GenerateJwtToken(user, userRoles);
            var refreshToken     = await CreateRefreshTokenAsync(user.Id, defaultClient.Id, cmd.IpAddress);

            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(user.Id, "LOGIN_SUCCESS", "AUTH", true, cmd.IpAddress, cmd.UserAgent);

            return new LoginDirectResult
            {
                Success       = true,
                AccessToken   = accessToken,
                RefreshToken  = refreshToken,
                ExpiresIn     = 900,
                Roles         = userRoles,
                EmailVerified = true,
                UserId        = user.Id
            };
        }
    }

    // ── RefreshTokenHandler ───────────────────────────────────────────────────

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

            // Vérification des rôles si un clientId est fourni
            var targetClientId = cmd.Request.ClientId;
            if (!string.IsNullOrEmpty(targetClientId))
            {
                var targetClient = await _repo.GetClientByClientIdAsync(targetClientId, ct);
                if (targetClient == null)
                    return new RefreshResult { Success = false, Message = "Client inconnu." };

                if (!string.IsNullOrEmpty(targetClient.AllowedRoles))
                {
                    var allowedRoles = targetClient.AllowedRoles
                        .Split(',', StringSplitOptions.RemoveEmptyEntries)
                        .Select(r => r.Trim())
                        .ToList();
                    var userRoles = user.UtilisateurRoles
                        .Where(ur => ur.Actif)
                        .Select(ur => ur.Role.Nom)
                        .ToList();

                    if (!userRoles.Any(r => allowedRoles.Contains(r)))
                    {
                        await LogAuditAsync(user.Id, "REFRESH_ACCESS_DENIED", "AUTH", false, cmd.IpAddress, "",
                            $"Rôle insuffisant pour {targetClient.Nom}. User: [{string.Join(", ", userRoles)}]");
                        return new RefreshResult { Success = false, Message = "Accès refusé : rôle insuffisant pour cette application." };
                    }
                }
            }

            entity.EstUtilise      = true;
            entity.DateRevoquation = DateTime.UtcNow;

            var roles            = user.UtilisateurRoles.Where(ur => ur.Actif).Select(ur => ur.Role.Nom).ToList();
            var (accessToken, _) = GenerateJwtToken(user, roles);
            var refreshToken     = await CreateRefreshTokenAsync(user.Id, entity.ClientId, cmd.IpAddress);

            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(user.Id, "TOKEN_REFRESHED", "AUTH", true, cmd.IpAddress, "");

            return new RefreshResult { Success = true, AccessToken = accessToken, RefreshToken = refreshToken };
        }
    }

    // ── LogoutHandler ─────────────────────────────────────────────────────────

    public class LogoutHandler : AuthHandlerBase, IRequestHandler<LogoutCommand, LogoutResult>
    {
        public LogoutHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<LogoutResult> Handle(LogoutCommand cmd, CancellationToken ct)
        {
            if (!string.IsNullOrEmpty(cmd.Jti))
                await _repo.RevokeJwtAsync(cmd.Jti, cmd.TokenExpiration, ct);

            if (!string.IsNullOrEmpty(cmd.Request?.RefreshToken))
            {
                var tokenHash = HashToken(cmd.Request.RefreshToken);
                var rt        = await _repo.GetRefreshTokenByHashAsync(tokenHash, ct);
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

            await _repo.CleanExpiredRevokedTokensAsync(ct);
            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(cmd.UserId, "LOGOUT", "AUTH", true, "", "");

            return new LogoutResult { Success = true, Message = "Déconnexion réussie." };
        }
    }

    // ── GetUserInfoHandler ────────────────────────────────────────────────────

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
                Roles                 = user.UtilisateurRoles.Select(ur => ur.Role.Nom).ToList(),
                MfaEnabled            = user.MFAValidee
            };
        }
    }

    // ── SetupMfaHandler ───────────────────────────────────────────────────────

    public class SetupMfaHandler : AuthHandlerBase, IRequestHandler<SetupMfaCommand, SetupMfaResult>
    {
        public SetupMfaHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<SetupMfaResult> Handle(SetupMfaCommand cmd, CancellationToken ct)
        {
            var user = await _repo.GetUtilisateurByIdAsync(cmd.UserId, ct);
            if (user is null)
                return new SetupMfaResult { Success = false, Message = "Utilisateur introuvable." };

            var secretBytes = KeyGeneration.GenerateRandomKey(20);
            var secret      = Base32Encoding.ToString(secretBytes);

            var issuer     = Uri.EscapeDataString("Poulina-SSO");
            var email      = Uri.EscapeDataString(user.Email);
            var otpAuthUri = $"otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";

            user.SecretMFA  = secret;
            user.TypeMFA    = TypeMFA.TOTP;
            user.MFAValidee = false;

            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(user.Id, "MFA_SETUP_INITIATED", "AUTH", true, "", "", "Setup TOTP initié");

            return new SetupMfaResult
            {
                Success      = true,
                OtpAuthUri   = otpAuthUri,
                QrCodeUrl    = otpAuthUri,
                ManualSecret = secret,
                Message      = "Scannez le QR code dans Google Authenticator ou Authy, puis confirmez avec /mfa/verify-setup."
            };
        }
    }

    // ── VerifyMfaSetupHandler ─────────────────────────────────────────────────

    public class VerifyMfaSetupHandler : AuthHandlerBase, IRequestHandler<VerifyMfaSetupCommand, VerifyMfaSetupResult>
    {
        public VerifyMfaSetupHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<VerifyMfaSetupResult> Handle(VerifyMfaSetupCommand cmd, CancellationToken ct)
        {
            var user = await _repo.GetUtilisateurByIdAsync(cmd.UserId, ct);
            if (user is null)
                return new VerifyMfaSetupResult { Success = false, Message = "Utilisateur introuvable." };

            if (string.IsNullOrEmpty(user.SecretMFA) || user.TypeMFA != TypeMFA.TOTP)
                return new VerifyMfaSetupResult { Success = false, Message = "Aucun setup MFA en cours. Appelez d'abord POST /mfa/setup." };

            if (user.MFAValidee)
                return new VerifyMfaSetupResult { Success = false, Message = "Le MFA est déjà activé." };

            if (!ValidateTotp(user.SecretMFA, cmd.Code))
                return new VerifyMfaSetupResult { Success = false, Message = "Code TOTP invalide. Vérifiez l'heure de votre appareil et réessayez." };

            user.MFAValidee = true;

            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(user.Id, "MFA_ACTIVATED", "AUTH", true, "", "", "MFA TOTP activé avec succès");

            return new VerifyMfaSetupResult
            {
                Success = true,
                Message = "MFA activé avec succès. Conservez votre code de secours."
            };
        }
    }

    // ── VerifyMfaLoginHandler ─────────────────────────────────────────────────

    public class VerifyMfaLoginHandler : AuthHandlerBase, IRequestHandler<VerifyMfaLoginCommand, VerifyMfaLoginResult>
    {
        public VerifyMfaLoginHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<VerifyMfaLoginResult> Handle(VerifyMfaLoginCommand cmd, CancellationToken ct)
        {
            Guid userId;
            try
            {
                userId = ValidateMfaPendingToken(cmd.MfaPendingToken);
            }
            catch (Exception)
            {
                return new VerifyMfaLoginResult
                {
                    Success   = false,
                    ErrorCode = "invalid_token",
                    Message   = "Token MFA invalide ou expiré. Veuillez vous reconnecter."
                };
            }

            var user = await _repo.GetUtilisateurByIdAsync(userId, ct);
            if (user is null || !user.MFAValidee || string.IsNullOrEmpty(user.SecretMFA))
                return new VerifyMfaLoginResult { Success = false, Message = "Utilisateur introuvable ou MFA non configuré." };

            if (user.Statut == StatutUtilisateur.BLOQUE || user.Statut == StatutUtilisateur.DESACTIVE)
                return new VerifyMfaLoginResult { Success = false, Message = "Compte inactif." };

            if (!ValidateTotp(user.SecretMFA, cmd.Code))
            {
                await LogAuditAsync(userId, "MFA_VERIFY_FAILED", "AUTH", false, cmd.IpAddress, cmd.UserAgent, "Code TOTP incorrect");
                await _repo.SaveChangesAsync(ct);
                return new VerifyMfaLoginResult
                {
                    Success   = false,
                    ErrorCode = "invalid_totp",
                    Message   = "Code TOTP invalide."
                };
            }

            user.DateDerniereConnexion       = DateTime.UtcNow;
            user.TentativesConnexionEchouees = 0;

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
                DeviceInfo           = "mfa-login"
            });

            var defaultClient = await _repo.GetFirstClientAsync(ct);
            if (defaultClient == null)
                return new VerifyMfaLoginResult { Success = false, Message = "Aucune application cliente configurée." };

            var roles            = user.UtilisateurRoles.Where(ur => ur.Actif).Select(ur => ur.Role.Nom).ToList();
            var (accessToken, _) = GenerateJwtToken(user, roles);
            var refreshToken     = await CreateRefreshTokenAsync(user.Id, defaultClient.Id, cmd.IpAddress);

            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(userId, "LOGIN_MFA_SUCCESS", "AUTH", true, cmd.IpAddress, cmd.UserAgent, "Connexion MFA réussie");

            return new VerifyMfaLoginResult
            {
                Success      = true,
                AccessToken  = accessToken,
                RefreshToken = refreshToken,
                Roles        = roles,
                UserId       = userId,
                Message      = "MFA validé."
            };
        }
    }

    // ── DisableMfaHandler ─────────────────────────────────────────────────────

    public class DisableMfaHandler : AuthHandlerBase, IRequestHandler<DisableMfaCommand, DisableMfaResult>
    {
        public DisableMfaHandler(IAuthRepository repo, IConfiguration cfg, IPasswordHasher ph)
            : base(repo, cfg, ph) { }

        public async Task<DisableMfaResult> Handle(DisableMfaCommand cmd, CancellationToken ct)
        {
            var user = await _repo.GetUtilisateurByIdAsync(cmd.UserId, ct);
            if (user is null)
                return new DisableMfaResult { Success = false, Message = "Utilisateur introuvable." };

            if (!user.MFAValidee || string.IsNullOrEmpty(user.SecretMFA))
                return new DisableMfaResult { Success = false, Message = "Le MFA n'est pas activé." };

            if (!ValidateTotp(user.SecretMFA, cmd.Code))
                return new DisableMfaResult { Success = false, Message = "Code TOTP invalide." };

            user.MFAValidee = false;
            user.SecretMFA  = null;
            user.TypeMFA    = TypeMFA.AUCUN;

            await _repo.SaveChangesAsync(ct);
            await LogAuditAsync(user.Id, "MFA_DISABLED", "AUTH", true, "", "", "MFA désactivé");

            return new DisableMfaResult { Success = true, Message = "MFA désactivé avec succès." };
        }
    }
}