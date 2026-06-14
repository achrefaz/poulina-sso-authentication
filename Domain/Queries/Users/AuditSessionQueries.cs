using MediatR;

namespace Domain.Queries.Users
{
    // ── Audit Logs ────────────────────────────────────────────────────────────

    public record GetAuditLogsQuery(
        int    Page        = 1,
        int    PageSize    = 20,
        string? Action     = null,
        string? DateDebut  = null,
        string? DateFin    = null
    ) : IRequest<AuditLogsResult>;

    public class AuditLogsResult
    {
        public bool                Success    { get; set; }
        public List<AuditLogDto>   Items      { get; set; } = [];
        public int                 Total      { get; set; }
        public int                 Page       { get; set; }
        public int                 PageSize   { get; set; }
        public int                 TotalPages { get; set; }
    }

    public class AuditLogDto
    {
        public Guid      Id            { get; set; }
        public string?   Email         { get; set; }
        public string    Action        { get; set; } = string.Empty;
        public string    Categorie     { get; set; } = string.Empty;
        public string    IpAddress     { get; set; } = string.Empty;
        public DateTime  DateHeure     { get; set; }
        public bool      Succes        { get; set; }
        public string?   MessageErreur { get; set; }
    }

    // ── Sessions ──────────────────────────────────────────────────────────────

    public record GetSessionsQuery(
        int Page     = 1,
        int PageSize = 20
    ) : IRequest<SessionsResult>;

    public class SessionsResult
    {
        public bool               Success    { get; set; }
        public List<SessionDto>   Items      { get; set; } = [];
        public int                Total      { get; set; }
        public int                Page       { get; set; }
        public int                PageSize   { get; set; }
        public int                TotalPages { get; set; }
    }

    public class SessionDto
    {
        public Guid      Id                    { get; set; }
        public string    SessionId             { get; set; } = string.Empty;
        public string?   Email                 { get; set; }
        public string    IpAddress             { get; set; } = string.Empty;
        public string    UserAgent             { get; set; } = string.Empty;
        public DateTime  DateCreation          { get; set; }
        public DateTime  DateDerniereActivite  { get; set; }
        public string    Statut                { get; set; } = string.Empty;
    }
}

// ── Commande de révocation de session ────────────────────────────────────────

namespace Domain.Commands.Users
{
    public record RevokeSessionCommand(Guid SessionId) : IRequest<RevokeSessionResult>;

    public class RevokeSessionResult
    {
        public bool   Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}