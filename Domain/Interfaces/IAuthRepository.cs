using Domain.Models;

namespace Domain.Interfaces
{
    public interface IAuthRepository
    {
        //  Utilisateurs 
        Task<Utilisateur?> GetUtilisateurByEmailAsync(string email, CancellationToken ct = default);
        Task<Utilisateur?> GetUtilisateurByIdAsync(Guid id, CancellationToken ct = default);
        Task<bool> EmailExisteAsync(string email, CancellationToken ct = default);
        Task AddUtilisateurAsync(Utilisateur user, CancellationToken ct = default);

        //  Sessions & Tokens 
        Task AddSessionAsync(Session session);
        Task AddRefreshTokenAsync(RefreshToken token);
        Task AddAuthorizationCodeAsync(AuthorizationCode code);
        Task AddAuditLogAsync(AuditLog log);

        //  Clients 
        Task<ClientApplication?> GetClientByClientIdAsync(string clientId, CancellationToken ct = default);
        Task<ClientApplication?> GetFirstClientAsync(CancellationToken ct = default);

        //  Refresh Tokens 
        Task<RefreshToken?> GetRefreshTokenByHashAsync(string hash, CancellationToken ct = default);
        Task<List<RefreshToken>> GetActiveRefreshTokensAsync(Guid userId, CancellationToken ct = default);

        // Authorization Codes
        Task<AuthorizationCode?> GetAuthorizationCodeByHashAsync(string hash, CancellationToken ct = default);

        // Sessions 
        Task<List<Session>> GetActiveSessionsAsync(Guid userId, CancellationToken ct = default);

        //  JWT Blacklist
        Task RevokeJwtAsync(string jti, DateTime expiration, CancellationToken ct = default);
        Task<bool> IsJwtRevokedAsync(string jti, CancellationToken ct = default);
        Task CleanExpiredRevokedTokensAsync(CancellationToken ct = default);
        
        Task SaveChangesAsync(CancellationToken ct = default);
    }
}