using MediatR;

namespace Domain.Commands.Auth
{
    // DTOs — Requêtes entrantes (owned by Domain, not by API layer)

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

    // ── DTOs MFA ──────────────────────────────────────────────────────────────

    public class MfaCodeRequest
    {
        public string Code { get; set; } = string.Empty;
    }

    public class MfaVerifyRequest
    {
        public string  MfaPendingToken     { get; set; } = string.Empty;
        public string  Code                { get; set; } = string.Empty;
        // Paramètres OAuth2 pour générer le code après validation TOTP
        public string  ClientId            { get; set; } = string.Empty;
        public string  RedirectUri         { get; set; } = string.Empty;
        public string? State               { get; set; }
        public string? CodeChallenge       { get; set; }
        public string? CodeChallengeMethod { get; set; }
        public string? Scopes              { get; set; }
    }

    // ── Resend confirmation email ─────────────────────────────────────────────
    public class ResendConfirmationRequest
    {
        public string Email { get; set; } = string.Empty;
    }

    // Register

    public record RegisterCommand(RegisterRequest Request) : IRequest<RegisterResult>;

    public class RegisterResult
    {
        public bool    Success { get; set; }
        public string? Message { get; set; }
        public Guid?   UserId  { get; set; }
    }

    // Login direct

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

    // Login with code (OAuth2 Authorization Code Flow)

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
        public string? AccessToken { get; set; }
    }

    // Refresh Token

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

    // Logout

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

    // Exchange code → token

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

    // MFA — Setup

    public record SetupMfaCommand(Guid UserId) : IRequest<SetupMfaResult>;

    public class SetupMfaResult
    {
        public bool    Success      { get; set; }
        public string? Message      { get; set; }
        public string? OtpAuthUri   { get; set; }
        public string? QrCodeUrl    { get; set; }
        public string? ManualSecret { get; set; }
    }

    // MFA — Verify Setup

    public record VerifyMfaSetupCommand(Guid UserId, string Code) : IRequest<VerifyMfaSetupResult>;

    public class VerifyMfaSetupResult
    {
        public bool    Success { get; set; }
        public string? Message { get; set; }
    }

    // MFA — Verify Login

    public record VerifyMfaLoginCommand(
        string  MfaPendingToken,
        string  Code,
        string  IpAddress,
        string  UserAgent,
        string  ClientId,
        string  RedirectUri,
        string? State,
        string? CodeChallenge,
        string? CodeChallengeMethod,
        string? Scopes
    ) : IRequest<VerifyMfaLoginResult>;

    public class VerifyMfaLoginResult
    {
        public bool    Success               { get; set; }
        public string? Message               { get; set; }
        public string? ErrorCode             { get; set; }
        public string? Code                  { get; set; }
        public string? RedirectUri           { get; set; }
        // Conservés pour compatibilité
        public string? AccessToken           { get; set; }
        public string? RefreshToken          { get; set; }
        public bool    DoitChangerMotDePasse { get; set; }
        public Guid?   UserId                { get; set; }
    }

    // MFA — Disable

    public record DisableMfaCommand(Guid UserId, string Code) : IRequest<DisableMfaResult>;

    public class DisableMfaResult
    {
        public bool    Success { get; set; }
        public string? Message { get; set; }
    }
}