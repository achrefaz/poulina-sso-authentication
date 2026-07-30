using MediatR;

namespace Domain.Commands.Auth
{
    // ── DTOs entrants ─────────────────────────────────────────────────────

    public class ForgotPasswordRequest
    {
        public string Email { get; set; } = string.Empty;
    }

    public class ResetPasswordRequest
    {
        public string Token             { get; set; } = string.Empty;
        public string NouveauMotDePasse { get; set; } = string.Empty;
    }

    // ── Forgot Password ───────────────────────────────────────────────────

    public record ForgotPasswordCommand(ForgotPasswordRequest Request) : IRequest<ForgotPasswordResult>;

    public class ForgotPasswordResult
    {
        public bool    Success { get; set; } = true;
        public string? Message { get; set; }
    }

    // ── Reset Password ────────────────────────────────────────────────────

    public record ResetPasswordCommand(ResetPasswordRequest Request) : IRequest<ResetPasswordResult>;

    public class ResetPasswordResult
    {
        public bool    Success   { get; set; }
        public string? Message   { get; set; }
        public string? ErrorCode { get; set; } // "INVALID_TOKEN" | "EXPIRED_TOKEN"
    }
}