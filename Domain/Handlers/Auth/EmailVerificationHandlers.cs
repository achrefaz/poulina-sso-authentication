using Domain.Commands.Auth;
using Domain.Interfaces;
using MediatR;
using System.Security.Cryptography;
using System.Text;

namespace Domain.Handlers.Auth
{
    
    public class ConfirmEmailHandler : IRequestHandler<ConfirmEmailCommand, ConfirmEmailResult>
    {
        private readonly IAuthRepository _repo;

        public ConfirmEmailHandler(IAuthRepository repo)
        {
            _repo = repo;
        }

        public async Task<ConfirmEmailResult> Handle(ConfirmEmailCommand cmd, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(cmd.Token))
                return new ConfirmEmailResult { Success = false, Message = "Token manquant." };

            // Hasher le token reçu pour comparer avec ce qui est stocké en base
            var tokenHash = HashToken(cmd.Token);

            var user = await _repo.GetUtilisateurByTokenVerificationAsync(tokenHash, ct);

            if (user is null)
                return new ConfirmEmailResult
                {
                    Success = false,
                    Message = "Lien de confirmation invalide ou déjà utilisé."
                };

            if (user.EmailVerifie)
                return new ConfirmEmailResult
                {
                    Success = true,
                    Message = "Votre email est déjà confirmé. Vous pouvez vous connecter."
                };

            if (user.TokenVerificationExpiration < DateTime.UtcNow)
                return new ConfirmEmailResult
                {
                    Success = false,
                    Message = "Lien expiré. Veuillez demander un nouveau lien de confirmation."
                };

           
            user.EmailVerifie                 = true;
            user.TokenVerificationEmail       = null;   
            user.TokenVerificationExpiration  = null;

            await _repo.AddAuditLogAsync(new Domain.Models.AuditLog
            {
                Id            = Guid.NewGuid(),
                UtilisateurId = user.Id,
                Action        = "EMAIL_CONFIRMED",
                Categorie     = "AUTH",
                DateHeure     = DateTime.UtcNow,
                Succes        = true
            });

            await _repo.SaveChangesAsync(ct);

            return new ConfirmEmailResult
            {
                Success = true,
                Message = "Email confirmé avec succès. Vous pouvez maintenant vous connecter."
            };
        }

        private static string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            return Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(token)));
        }
    }

   
    public class RenvoyerConfirmationEmailHandler
        : IRequestHandler<RenvoyerConfirmationEmailCommand, RenvoyerConfirmationEmailResult>
    {
        private readonly IAuthRepository _repo;
        private readonly IEmailService   _emailService;
        private readonly Microsoft.Extensions.Configuration.IConfiguration _config;

        public RenvoyerConfirmationEmailHandler(
            IAuthRepository repo,
            IEmailService   emailService,
            Microsoft.Extensions.Configuration.IConfiguration config)
        {
            _repo         = repo;
            _emailService = emailService;
            _config       = config;
        }

        public async Task<RenvoyerConfirmationEmailResult> Handle(
            RenvoyerConfirmationEmailCommand cmd, CancellationToken ct)
        {
            var user = await _repo.GetUtilisateurByEmailAsync(cmd.Email.Trim().ToLower(), ct);

            
            if (user is null || user.EmailVerifie)
                return new RenvoyerConfirmationEmailResult
                {
                    Success = true,
                    Message = "Si cet email existe et n'est pas encore confirmé, un nouveau lien a été envoyé."
                };

            
            var (rawToken, tokenHash) = GenererToken();

            user.TokenVerificationEmail      = tokenHash;
            user.TokenVerificationExpiration = DateTime.UtcNow.AddHours(24);

            var baseUrl = _config["AppSettings:BaseUrl"] ?? "http://localhost:5095";
            var lien    = $"{baseUrl}/api/Auth/confirm-email?token={Uri.EscapeDataString(rawToken)}";

            await _emailService.RenvoyerEmailConfirmationAsync(
                user.Email,
                $"{user.Prenom} {user.Nom}",
                lien,
                ct);

            await _repo.SaveChangesAsync(ct);

            return new RenvoyerConfirmationEmailResult
            {
                Success = true,
                Message = "Si cet email existe et n'est pas encore confirmé, un nouveau lien a été envoyé."
            };
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
}