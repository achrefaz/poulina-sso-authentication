using Domain.Commands.Auth;
using Domain.Interfaces;
using MediatR;
using System.Security.Cryptography;
using System.Text;

namespace Domain.Handlers.Auth
{
    public class ForgotPasswordHandler : IRequestHandler<ForgotPasswordCommand, ForgotPasswordResult>
    {
        private readonly IAuthRepository _repo;
        private readonly IEmailService   _emailService;
        private readonly Microsoft.Extensions.Configuration.IConfiguration _config;

        public ForgotPasswordHandler(
            IAuthRepository repo,
            IEmailService   emailService,
            Microsoft.Extensions.Configuration.IConfiguration config)
        {
            _repo         = repo;
            _emailService = emailService;
            _config       = config;
        }

        public async Task<ForgotPasswordResult> Handle(ForgotPasswordCommand cmd, CancellationToken ct)
        {
            const string genericMessage =
                "Si cet email existe, un lien de réinitialisation vient de vous être envoyé.";

            if (string.IsNullOrWhiteSpace(cmd.Request.Email))
                return new ForgotPasswordResult { Success = true, Message = genericMessage };

            var user = await _repo.GetUtilisateurByEmailAsync(cmd.Request.Email.Trim().ToLower(), ct);

            // Anti-énumération : toujours répondre pareil, que le compte existe ou non
            if (user is null)
                return new ForgotPasswordResult { Success = true, Message = genericMessage };

            var (rawToken, tokenHash) = GenererToken();

            user.TokenResetMotDePasse = tokenHash;
            user.TokenResetExpiration = DateTime.UtcNow.AddHours(1);

            var frontendUrl = _config["AppSettings:FrontendBaseUrl"]
                              ?? _config["AppSettings:BaseUrl"]
                              ?? "http://localhost:4200";
            var lien = $"{frontendUrl}/reset-password?token={Uri.EscapeDataString(rawToken)}";

            await _emailService.EnvoyerReinitialisationMotDePasseAsync(
                user.Email,
                $"{user.Prenom} {user.Nom}",
                lien,
                ct);

            await _repo.AddAuditLogAsync(new Domain.Models.AuditLog
            {
                Id            = Guid.NewGuid(),
                UtilisateurId = user.Id,
                Action        = "FORGOT_PASSWORD_REQUEST",
                Categorie     = "AUTH",
                DateHeure     = DateTime.UtcNow,
                Succes        = true
            });

            await _repo.SaveChangesAsync(ct);

            return new ForgotPasswordResult { Success = true, Message = genericMessage };
        }

        private static (string Raw, string Hash) GenererToken()
        {
            var raw  = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))
                              .Replace("+", "-").Replace("/", "_").TrimEnd('=');
            using var sha256 = SHA256.Create();
            var hash = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(raw)));
            return (raw, hash);
        }
    }

    public class ResetPasswordHandler : IRequestHandler<ResetPasswordCommand, ResetPasswordResult>
    {
        private readonly IAuthRepository _repo;
        private readonly IPasswordHasher _passwordHasher;

        public ResetPasswordHandler(IAuthRepository repo, IPasswordHasher passwordHasher)
        {
            _repo           = repo;
            _passwordHasher = passwordHasher;
        }

        public async Task<ResetPasswordResult> Handle(ResetPasswordCommand cmd, CancellationToken ct)
        {
            var req = cmd.Request;

            if (string.IsNullOrWhiteSpace(req.NouveauMotDePasse) || req.NouveauMotDePasse.Length < 8)
                return new ResetPasswordResult
                {
                    Success = false,
                    Message = "Le mot de passe doit contenir au moins 8 caractères."
                };

            if (string.IsNullOrWhiteSpace(req.Token))
                return new ResetPasswordResult
                {
                    Success   = false,
                    Message   = "Ce lien est invalide ou a déjà été utilisé.",
                    ErrorCode = "INVALID_TOKEN"
                };

            var tokenHash = HashToken(req.Token);
            var user      = await _repo.GetUtilisateurByTokenResetAsync(tokenHash, ct);

            if (user is null)
                return new ResetPasswordResult
                {
                    Success   = false,
                    Message   = "Ce lien est invalide ou a déjà été utilisé.",
                    ErrorCode = "INVALID_TOKEN"
                };

            if (user.TokenResetExpiration is null || user.TokenResetExpiration < DateTime.UtcNow)
                return new ResetPasswordResult
                {
                    Success   = false,
                    Message   = "Ce lien a expiré. Veuillez refaire une demande de réinitialisation.",
                    ErrorCode = "EXPIRED_TOKEN"
                };

            user.MotDePasseHash        = _passwordHasher.Hash(req.NouveauMotDePasse);
            user.TokenResetMotDePasse  = null;
            user.TokenResetExpiration  = null;
            user.DoitChangerMotDePasse = false;
            user.DateMiseAJour         = DateTime.UtcNow;

            // Révocation des refresh tokens actifs (mêmes garanties que ChangePassword)
            var refreshTokens = await _repo.GetActiveRefreshTokensAsync(user.Id, ct);
            foreach (var rt in refreshTokens)
            {
                rt.EstUtilise      = true;
                rt.DateRevoquation = DateTime.UtcNow;
            }

            await _repo.AddAuditLogAsync(new Domain.Models.AuditLog
            {
                Id            = Guid.NewGuid(),
                UtilisateurId = user.Id,
                Action        = "PASSWORD_RESET",
                Categorie     = "AUTH",
                DateHeure     = DateTime.UtcNow,
                Succes        = true
            });

            await _repo.SaveChangesAsync(ct);

            return new ResetPasswordResult
            {
                Success = true,
                Message = "Mot de passe réinitialisé avec succès. Vous pouvez vous reconnecter."
            };
        }

        private static string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            return Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(token)));
        }
    }
}