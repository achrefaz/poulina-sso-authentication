using Domain.Interfaces;
using Domain.Models;
using Domain.Models.Enums;
using Data.Context;
using Microsoft.EntityFrameworkCore;

namespace Data.Repositories
{
    public class AuthRepository : IAuthRepository
    {
        private readonly ApplicationDbContext _context;

        public AuthRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        // ── Utilisateurs ──────────────────────────────────────────────────────

        public Task<Utilisateur?> GetUtilisateurByEmailAsync(string email, CancellationToken ct = default)
            => _context.Utilisateurs
                .Include(u => u.UtilisateurRoles.Where(ur => ur.Actif))
                .ThenInclude(ur => ur.Role)
                .FirstOrDefaultAsync(u => u.Email == email, ct);

        public Task<Utilisateur?> GetUtilisateurByIdAsync(Guid id, CancellationToken ct = default)
            => _context.Utilisateurs
                .Include(u => u.UtilisateurRoles.Where(ur => ur.Actif))
                .ThenInclude(ur => ur.Role)
                .FirstOrDefaultAsync(u => u.Id == id, ct);

        public Task<bool> EmailExisteAsync(string email, CancellationToken ct = default)
            => _context.Utilisateurs.AnyAsync(u => u.Email == email, ct);

        public async Task AddUtilisateurAsync(Utilisateur user, CancellationToken ct = default)
            => await _context.Utilisateurs.AddAsync(user, ct);

        // ── Sessions & Tokens ─────────────────────────────────────────────────

        public async Task AddSessionAsync(Session session)
            => await _context.Sessions.AddAsync(session);

        public async Task AddRefreshTokenAsync(RefreshToken token)
            => await _context.RefreshTokens.AddAsync(token);

        public async Task AddAuthorizationCodeAsync(AuthorizationCode code)
            => await _context.AuthorizationCodes.AddAsync(code);

        public async Task AddAuditLogAsync(AuditLog log)
            => await _context.AuditLogs.AddAsync(log);

        // ── Clients ───────────────────────────────────────────────────────────

        public Task<ClientApplication?> GetClientByClientIdAsync(string clientId, CancellationToken ct = default)
            => _context.ClientsApplications
                .FirstOrDefaultAsync(c => c.ClientId == clientId && c.Actif, ct);

        public Task<ClientApplication?> GetFirstClientAsync(CancellationToken ct = default)
            => _context.ClientsApplications.FirstOrDefaultAsync(ct);

        // ── Refresh Tokens ────────────────────────────────────────────────────

        public Task<RefreshToken?> GetRefreshTokenByHashAsync(string hash, CancellationToken ct = default)
            => _context.RefreshTokens
                .Include(rt => rt.Utilisateur)
                    .ThenInclude(u => u.UtilisateurRoles.Where(ur => ur.Actif))
                    .ThenInclude(ur => ur.Role)
                .Include(rt => rt.Client)
                .FirstOrDefaultAsync(rt => rt.TokenHash == hash, ct);

        public Task<List<RefreshToken>> GetActiveRefreshTokensAsync(Guid userId, CancellationToken ct = default)
            => _context.RefreshTokens
                .Where(r => r.UtilisateurId == userId && !r.EstUtilise)
                .ToListAsync(ct);

        // ── Authorization Codes ───────────────────────────────────────────────

        public Task<AuthorizationCode?> GetAuthorizationCodeByHashAsync(string hash, CancellationToken ct = default)
            => _context.AuthorizationCodes
                .Include(ac => ac.Utilisateur)
                    .ThenInclude(u => u.UtilisateurRoles.Where(ur => ur.Actif))
                    .ThenInclude(ur => ur.Role)
                .Include(ac => ac.Client)
                .FirstOrDefaultAsync(ac => ac.CodeHash == hash, ct);

        // ── Sessions ──────────────────────────────────────────────────────────

        public Task<List<Session>> GetActiveSessionsAsync(Guid userId, CancellationToken ct = default)
            => _context.Sessions
                .Where(s => s.UtilisateurId == userId && s.Statut == StatutSession.ACTIVE)
                .ToListAsync(ct);

        // ── JWT Blacklist ─────────────────────────────────────────────────────

        public async Task RevokeJwtAsync(string jti, DateTime expiration, CancellationToken ct = default)
        {
            var alreadyRevoked = await _context.RevokedTokens
                .AnyAsync(t => t.Jti == jti, ct);

            if (!alreadyRevoked)
            {
                await _context.RevokedTokens.AddAsync(new RevokedToken
                {
                    Id             = Guid.NewGuid(),
                    Jti            = jti,
                    DateRevocation = DateTime.UtcNow,
                    DateExpiration = expiration
                }, ct);
            }
        }

        public Task<bool> IsJwtRevokedAsync(string jti, CancellationToken ct = default)
            => _context.RevokedTokens.AnyAsync(t => t.Jti == jti, ct);

        public async Task CleanExpiredRevokedTokensAsync(CancellationToken ct = default)
        {
            var expired = await _context.RevokedTokens
                .Where(t => t.DateExpiration < DateTime.UtcNow)
                .ToListAsync(ct);

            if (expired.Any())
                _context.RevokedTokens.RemoveRange(expired);
        }

        // ── Email Verification ────────────────────────────────────────────────

        public Task<Utilisateur?> GetUtilisateurByTokenVerificationAsync(
            string tokenHash, CancellationToken ct = default)
            => _context.Utilisateurs
                .FirstOrDefaultAsync(u => u.TokenVerificationEmail == tokenHash, ct);

        // ── Persistance ───────────────────────────────────────────────────────

        public Task SaveChangesAsync(CancellationToken ct = default)
            => _context.SaveChangesAsync(ct);
    }
}