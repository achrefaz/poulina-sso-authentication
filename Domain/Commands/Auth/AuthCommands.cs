using MediatR;

namespace Domain.Commands.Auth
{
    // ── DTOs entrants ─────────────────────────────────────────────────────

    public class RegisterRequest
    {
        public string Email    { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Nom      { get; set; } = string.Empty;
        public string Prenom   { get; set; } = string.Empty;
    }

    public class LoginDirectRequest
    {
        public string Email    { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class RefreshRequest
    {
        public string  RefreshToken { get; set; } = string.Empty;
        public string? ClientId     { get; set; }
    }

    public class LogoutRequest
    {
        public string? RefreshToken { get; set; }
    }

    // ── DTOs MFA ──────────────────────────────────────────────────────────

    public class MfaCodeRequest
    {
        public string Code { get; set; } = string.Empty;
    }

    public class MfaVerifyRequest
    {
        public string  MfaPendingToken { get; set; } = string.Empty;
        public string  Code            { get; set; } = string.Empty;
    }

    // ── Resend confirmation email ─────────────────────────────────────────

    public class ResendConfirmationRequest
    {
        public string Email { get; set; } = string.Empty;
    }

    // ── Register ──────────────────────────────────────────────────────────

    public record RegisterCommand(RegisterRequest Request) : IRequest<RegisterResult>;

    public class RegisterResult
    {
        public bool    Success { get; set; }
        public string? Message { get; set; }
        public Guid?   UserId  { get; set; }
    }

    // ── Login direct ──────────────────────────────────────────────────────

    public record LoginDirectCommand(
        LoginDirectRequest Request,
        string IpAddress,
        string UserAgent
    ) : IRequest<LoginDirectResult>;

    public class LoginDirectResult
    {
        public bool         Success                { get; set; }
        public string?      Message                { get; set; }
        public string?      ErrorCode              { get; set; }
        public string?      Raison                 { get; set; }
        public string?      AccessToken            { get; set; }
        public string?      RefreshToken           { get; set; }
        public int          ExpiresIn              { get; set; } = 900;
        public List<string> Roles                  { get; set; } = [];
        public bool         MfaRequired            { get; set; }
        public string?      MfaPendingToken        { get; set; }
        public bool         PasswordChangeRequired { get; set; }
        public bool         EmailVerified          { get; set; }
        public Guid?        UserId                 { get; set; }
    }

    // ── Refresh Token ─────────────────────────────────────────────────────

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

    // ── Logout ────────────────────────────────────────────────────────────

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

    // ── MFA Setup ────────────────────────────────────────────────────────

    public record SetupMfaCommand(Guid UserId) : IRequest<SetupMfaResult>;

    public class SetupMfaResult
    {
        public bool    Success      { get; set; }
        public string? Message      { get; set; }
        public string? OtpAuthUri   { get; set; }
        public string? QrCodeUrl    { get; set; }
        public string? ManualSecret { get; set; }
    }

    // ── MFA Verify Setup ─────────────────────────────────────────────────

    public record VerifyMfaSetupCommand(Guid UserId, string Code) : IRequest<VerifyMfaSetupResult>;

    public class VerifyMfaSetupResult
    {
        public bool    Success { get; set; }
        public string? Message { get; set; }
    }
    

    // ── MFA Verify Login ─────────────────────────────────────────────────

    public record VerifyMfaLoginCommand(
        string MfaPendingToken,
        string Code,
        string IpAddress,
        string UserAgent
    ) : IRequest<VerifyMfaLoginResult>;

    public class VerifyMfaLoginResult
    {
        public bool         Success      { get; set; }
        public string?      Message      { get; set; }
        public string?      ErrorCode    { get; set; }
        public string?      AccessToken  { get; set; }
        public string?      RefreshToken { get; set; }
        public List<string> Roles        { get; set; } = [];
        public Guid?        UserId       { get; set; }
    }

    // ── MFA Disable ──────────────────────────────────────────────────────

    public record DisableMfaCommand(Guid UserId, string Code) : IRequest<DisableMfaResult>;

    public class DisableMfaResult
    {
        public bool    Success { get; set; }
        public string? Message { get; set; }
    }
}