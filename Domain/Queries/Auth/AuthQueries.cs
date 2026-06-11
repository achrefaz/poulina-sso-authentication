using MediatR;

namespace Domain.Queries.Auth
{
    // ── UserInfo (OpenID Connect) ─────────────────────────────────────────
    public record GetUserInfoQuery(Guid UserId) : IRequest<UserInfoResult>;

    public class UserInfoResult
    {
        public bool Success { get; set; }
        public Guid Sub { get; set; }
        public string? Email { get; set; }
        public string? Nom { get; set; }
        public string? Prenom { get; set; }
        public List<string> Roles { get; set; } = new();
        public string? Statut { get; set; }
        public bool DoitChangerMotDePasse { get; set; }
        public bool MfaEnabled { get; set; }
    }

    // ── Authorize step 1 (validation paramètres OAuth2) ───────────────────
    public record AuthorizeQuery(
        string ClientId,
        string RedirectUri,
        string ResponseType,
        string? Scope,
        string? State,
        string? CodeChallenge,
        string? CodeChallengeMethod
    ) : IRequest<AuthorizeResult>;

    public class AuthorizeResult
    {
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public string? LoginUrl { get; set; }
    }
}