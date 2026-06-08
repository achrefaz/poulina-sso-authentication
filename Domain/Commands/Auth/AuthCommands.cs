using MediatR;

namespace Domain.Commands.Auth
{
    // ── DTOs ──────────────────────────────────────────────────────────────────
    // Moved here from API.Controllers so Domain owns its own request contracts.

    public class RegisterRequest
    {
        public string Email    { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Nom      { get; set; } = string.Empty;
        public string Prenom   { get; set; } = string.Empty;
    }

    public class LoginRequest
    {
        public string Email    { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class LoginWithCodeRequest
    {
        public string  Email               { get; set; } = string.Empty;
        public string  Password            { get; set; } = string.Empty;
        public string  ClientId            { get; set; } = string.Empty;
        public string  RedirectUri         { get; set; } = string.Empty;
        public string? State               { get; set; }
        public string? CodeChallenge       { get; set; }
        public string? CodeChallengeMethod { get; set; }
        public string  Scopes              { get; set; } = string.Empty;
    }

    public class RefreshRequest
    {
        public string RefreshToken { get; set; } = string.Empty;
    }

    public class LogoutRequest
    {
        public string? RefreshToken { get; set; }
    }

    public class TokenRequest
    {
        public string  GrantType    { get; set; } = string.Empty;
        public string  Code         { get; set; } = string.Empty;
        public string  ClientId     { get; set; } = string.Empty;
        public string  RedirectUri  { get; set; } = string.Empty;
        public string? CodeVerifier { get; set; }
    }

    // ── 1. Register ───────────────────────────────────────────────────────────
    public record RegisterCommand(RegisterRequest Request) : IRequest<RegisterResult>;

    public class RegisterResult
    {
        public bool    Success { get; set; }
        public string? Message { get; set; }
        public Guid?   UserId  { get; set; }
    }

    // ── 2. Login direct ───────────────────────────────────────────────────────
    public record LoginCommand(
        LoginRequest Request,
        string IpAddress,
        string UserAgent
    ) : IRequest<LoginResult>;

    public class LoginResult
    {
        public bool    Success               { get; set; }
        public string? Message               { get; set; }
        public string? AccessToken           { get; set; }
        public string? RefreshToken          { get; set; }
        public bool    DoitChangerMotDePasse { get; set; }
        public string? ErrorCode             { get; set; }
        public string? Raison                { get; set; }
        public Guid?   UserId                { get; set; }
    }

    // ── 3. Login with code ────────────────────────────────────────────────────
    public record LoginWithCodeCommand(
        LoginWithCodeRequest Request,
        string IpAddress,
        string UserAgent
    ) : IRequest<LoginWithCodeResult>;

    public class LoginWithCodeResult
    {
        public bool    Success     { get; set; }
        public string? Message     { get; set; }
        public string? Code        { get; set; }
        public string? RedirectUri { get; set; }
        public string? ErrorCode   { get; set; }
    }

    // ── 4. Refresh Token ──────────────────────────────────────────────────────
    public record RefreshTokenCommand(
        RefreshRequest Request,
        string IpAddress
    ) : IRequest<RefreshResult>;

    public class RefreshResult
    {
        public bool    Success      { get; set; }
        public string? Message      { get; set; }
        public string? AccessToken  { get; set; }
        public string? RefreshToken { get; set; }
    }

    // ── 5. Logout ─────────────────────────────────────────────────────────────
    public record LogoutCommand(
        LogoutRequest? Request,
        Guid     UserId,
        string   Jti,
        DateTime TokenExpiration
    ) : IRequest<LogoutResult>;

    public class LogoutResult
    {
        public bool    Success { get; set; }
        public string? Message { get; set; }
    }

    // ── 6. Exchange code → token ──────────────────────────────────────────────
    public record ExchangeCodeCommand(TokenRequest Request) : IRequest<ExchangeCodeResult>;

    public class ExchangeCodeResult
    {
        public bool    Success          { get; set; }
        public string? ErrorCode        { get; set; }
        public string? ErrorDescription { get; set; }
        public string? AccessToken      { get; set; }
        public string? RefreshToken     { get; set; }
        public string? TokenType        { get; set; }
        public int?    ExpiresIn        { get; set; }
        public string? Scope            { get; set; }
    }
}