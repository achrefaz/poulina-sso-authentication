using MediatR;
using Domain.Interfaces;
using Domain.Models.Enums;
using Domain.Queries.Users;
using Domain.Commands.Users;

namespace Domain.Handlers.Users
{
    // ── Handler : Audit Logs ──────────────────────────────────────────────────

    public class GetAuditLogsHandler : IRequestHandler<GetAuditLogsQuery, AuditLogsResult>
    {
        private readonly IAuthRepository _repo;

        public GetAuditLogsHandler(IAuthRepository repo)
        {
            _repo = repo;
        }

        public async Task<AuditLogsResult> Handle(GetAuditLogsQuery request, CancellationToken ct)
        {
            DateTime? dateDebut = null;
            DateTime? dateFin   = null;

            if (!string.IsNullOrEmpty(request.DateDebut) &&
                DateTime.TryParse(request.DateDebut, out var d1))
                dateDebut = d1;

            if (!string.IsNullOrEmpty(request.DateFin) &&
                DateTime.TryParse(request.DateFin, out var d2))
                dateFin = d2.AddDays(1);

            var (items, total) = await _repo.GetAuditLogsAsync(
                request.Page,
                request.PageSize,
                request.Action,
                dateDebut,
                dateFin,
                ct);

            return new AuditLogsResult
            {
                Success    = true,
                Items      = items,
                Total      = total,
                Page       = request.Page,
                PageSize   = request.PageSize,
                TotalPages = (int)Math.Ceiling((double)total / request.PageSize)
            };
        }
    }

    // ── Handler : Sessions actives ────────────────────────────────────────────

    public class GetSessionsHandler : IRequestHandler<GetSessionsQuery, SessionsResult>
    {
        private readonly IAuthRepository _repo;

        public GetSessionsHandler(IAuthRepository repo)
        {
            _repo = repo;
        }

        public async Task<SessionsResult> Handle(GetSessionsQuery request, CancellationToken ct)
        {
            var (items, total) = await _repo.GetAllSessionsPagedAsync(
                request.Page,
                request.PageSize,
                ct);

            return new SessionsResult
            {
                Success    = true,
                Items      = items,
                Total      = total,
                Page       = request.Page,
                PageSize   = request.PageSize,
                TotalPages = (int)Math.Ceiling((double)total / request.PageSize)
            };
        }
    }

    // ── Handler : Révoquer une session ────────────────────────────────────────

    public class RevokeSessionHandler : IRequestHandler<RevokeSessionCommand, RevokeSessionResult>
    {
        private readonly IAuthRepository _repo;

        public RevokeSessionHandler(IAuthRepository repo)
        {
            _repo = repo;
        }

        public async Task<RevokeSessionResult> Handle(RevokeSessionCommand request, CancellationToken ct)
        {
            var session = await _repo.GetSessionByIdAsync(request.SessionId, ct);

            if (session == null)
                return new RevokeSessionResult { Success = false, Message = "Session introuvable." };

            session.Statut = StatutSession.REVOQUEE;
            await _repo.SaveChangesAsync(ct);

            return new RevokeSessionResult { Success = true, Message = "Session révoquée avec succès." };
        }
    }
}