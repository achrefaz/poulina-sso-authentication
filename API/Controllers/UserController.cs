using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Data.Context;
using Domain.Interfaces;
using Domain.Models;
using Domain.Models.Enums;
using Infra.Security;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UserController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly IPasswordHasher      _passwordHasher;
    private readonly IEmailService        _emailService;
    private readonly IConfiguration       _configuration;

    public UserController(
        ApplicationDbContext context,
        IPasswordHasher      passwordHasher,
        IEmailService        emailService,
        IConfiguration       configuration)
    {
        _context        = context;
        _passwordHasher = passwordHasher;
        _emailService   = emailService;
        _configuration  = configuration;
    }

    // ── Profil ─────────────────────────────────────────────────────────────

    [HttpGet("profile")]
    public async Task<IActionResult> GetProfile()
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized(new { message = "Token invalide." });

        var user = await _context.Utilisateurs
            .Include(u => u.UtilisateurRoles.Where(ur => ur.Actif))
                .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Id == userId);

        if (user == null) return NotFound(new { message = "Utilisateur introuvable." });

        return Ok(new
        {
            user.Id,
            user.Email,
            user.Nom,
            user.Prenom,
            Statut = user.Statut.ToString(),
            user.DateCreation,
            user.DateDerniereConnexion,
            user.DateBlocage,
            user.RaisonBlocage,
            user.DoitChangerMotDePasse,
            user.EmailVerifie,
            Roles = user.UtilisateurRoles.Select(ur => ur.Role.Nom).ToList()
        });
    }

    // ── Changement de mot de passe ─────────────────────────────────────────

    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized(new { message = "Token invalide." });

        var user = await _context.Utilisateurs.FindAsync(userId);
        if (user == null) return NotFound(new { message = "Utilisateur introuvable." });

        if (!user.DoitChangerMotDePasse)
        {
            if (string.IsNullOrEmpty(request.AncienMotDePasse))
                return BadRequest(new { message = "L'ancien mot de passe est requis." });

            if (!_passwordHasher.Verify(request.AncienMotDePasse, user.MotDePasseHash))
            {
                await LogAudit(userId.Value, "CHANGE_PASSWORD_FAILED", "USER", false, "Ancien mot de passe incorrect");
                return Unauthorized(new { message = "Ancien mot de passe incorrect." });
            }
        }

        if (string.IsNullOrEmpty(request.NouveauMotDePasse) || request.NouveauMotDePasse.Length < 8)
            return BadRequest(new { message = "Le nouveau mot de passe doit contenir au moins 8 caractères." });

        if (request.NouveauMotDePasse != request.ConfirmationMotDePasse)
            return BadRequest(new { message = "Les mots de passe ne correspondent pas." });

        if (_passwordHasher.Verify(request.NouveauMotDePasse, user.MotDePasseHash))
            return BadRequest(new { message = "Le nouveau mot de passe doit être différent de l'ancien." });

        user.MotDePasseHash        = _passwordHasher.Hash(request.NouveauMotDePasse);
        user.DoitChangerMotDePasse = false;
        user.DateMiseAJour         = DateTime.UtcNow;

        var refreshTokens = await _context.RefreshTokens
            .Where(rt => rt.UtilisateurId == userId && !rt.EstUtilise
                         && rt.DateExpiration > DateTime.UtcNow)
            .ToListAsync();

        foreach (var rt in refreshTokens)
        {
            rt.EstUtilise      = true;
            rt.DateRevoquation = DateTime.UtcNow;
        }

        var sessions = await _context.Sessions
            .Where(s => s.UtilisateurId == userId && s.Statut == StatutSession.ACTIVE)
            .ToListAsync();

        foreach (var session in sessions)
            session.Statut = StatutSession.REVOQUEE;

        await _context.SaveChangesAsync();
        await LogAudit(userId.Value, "CHANGE_PASSWORD", "USER", true, "Mot de passe changé avec succès");

        return Ok(new { message = "Mot de passe changé avec succès. Veuillez vous reconnecter." });
    }

    // ── Admin : Créer utilisateur ──────────────────────────────────────────

    [HttpPost("admin/users")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        var adminId = GetCurrentUserId();
        if (adminId == null) return Unauthorized();

        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            return BadRequest(new { message = "Email et mot de passe requis." });

        if (request.Password.Length < 8)
            return BadRequest(new { message = "Le mot de passe doit contenir au moins 8 caractères." });

        var existingUser = await _context.Utilisateurs
            .FirstOrDefaultAsync(u => u.Email == request.Email.Trim().ToLower());

        if (existingUser != null)
            return BadRequest(new { message = "Un utilisateur avec cet email existe déjà." });

        var (rawToken, tokenHash) = GenererTokenVerification();

        // On conserve le mot de passe en clair AVANT le hachage pour l'envoyer par email.
        // Il n'est jamais persisté — uniquement utilisé dans cette portée locale.
        var motDePasseEnClair = request.Password;

        var user = new Utilisateur
        {
            Id                          = Guid.NewGuid(),
            Email                       = request.Email.Trim().ToLower(),
            Nom                         = request.Nom,
            Prenom                      = request.Prenom,
            MotDePasseHash              = _passwordHasher.Hash(motDePasseEnClair),
            Salt                        = string.Empty,
            Statut                      = StatutUtilisateur.ACTIF,
            DateCreation                = DateTime.UtcNow,
            TypeMFA                     = TypeMFA.AUCUN,
            DoitChangerMotDePasse       = true,
            EmailVerifie                = false,
            TokenVerificationEmail      = tokenHash,
            TokenVerificationExpiration = DateTime.UtcNow.AddHours(24)
        };

        _context.Utilisateurs.Add(user);

        if (request.RoleIds != null && request.RoleIds.Any())
        {
            foreach (var roleId in request.RoleIds)
            {
                var role = await _context.Roles.FindAsync(roleId);
                if (role != null && role.Actif)
                {
                    _context.UtilisateurRoles.Add(new UtilisateurRole
                    {
                        UtilisateurId   = user.Id,
                        RoleId          = roleId,
                        DateAssignation = DateTime.UtcNow,
                        AssignePar      = adminId.Value,
                        Actif           = true
                    });
                }
            }
        }

        await _context.SaveChangesAsync();
        await LogAudit(adminId.Value, "CREATE_USER", "ADMIN", true, $"Utilisateur créé: {user.Email}");

        var nomComplet = $"{user.Prenom} {user.Nom}".Trim();

        // Email 1 : credentials (email + mot de passe temporaire)
        await _emailService.EnvoyerCredentialsAsync(
            user.Email,
            nomComplet,
            motDePasseEnClair);

        // Email 2 : lien de confirmation pour activer le compte
        var baseUrl = _configuration["AppSettings:BaseUrl"] ?? "http://localhost:5095";
        var lien    = $"{baseUrl}/api/Auth/confirm-email?token={Uri.EscapeDataString(rawToken)}";

        await _emailService.EnvoyerEmailConfirmationAsync(
            user.Email,
            nomComplet,
            lien);

        return Ok(new
        {
            message = "Utilisateur créé avec succès. Les identifiants et le lien de confirmation ont été envoyés par email.",
            userId  = user.Id
        });
    }

    // ── Admin : Lister utilisateurs ────────────────────────────────────────

    [HttpGet("admin/users")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _context.Utilisateurs
            .Include(u => u.UtilisateurRoles.Where(ur => ur.Actif))
                .ThenInclude(ur => ur.Role)
            .Select(u => new
            {
                u.Id,
                u.Email,
                u.Nom,
                u.Prenom,
                Statut               = u.Statut.ToString(),
                u.DateCreation,
                u.DateDerniereConnexion,
                u.EmailVerifie,
                u.DoitChangerMotDePasse,
                Roles = u.UtilisateurRoles.Select(ur => ur.Role.Nom).ToList()
            })
            .ToListAsync();

        return Ok(users);
    }

    // ── Admin : Bloquer utilisateur ────────────────────────────────────────

    [HttpPatch("admin/users/{id}/bloquer")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> BloquerUtilisateur(Guid id, [FromBody] BloquerRequest request)
    {
        var adminId = GetCurrentUserId();
        if (adminId == null) return Unauthorized();

        var user = await _context.Utilisateurs.FindAsync(id);
        if (user == null) return NotFound(new { message = "Utilisateur introuvable." });

        user.Statut        = StatutUtilisateur.BLOQUE;
        user.DateBlocage   = DateTime.UtcNow;
        user.RaisonBlocage = request.Raison;
        user.DateMiseAJour = DateTime.UtcNow;

        await _context.SaveChangesAsync();
        await LogAudit(adminId.Value, "BLOCK_USER", "ADMIN", true,
            $"Utilisateur {user.Email} bloqué. Raison: {request.Raison}");

        return Ok(new { message = $"Utilisateur {user.Email} bloqué avec succès." });
    }

    // ── Admin : Débloquer utilisateur ──────────────────────────────────────

    [HttpPatch("admin/users/{id}/debloquer")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> DebloquerUtilisateur(Guid id)
    {
        var adminId = GetCurrentUserId();
        if (adminId == null) return Unauthorized();

        var user = await _context.Utilisateurs.FindAsync(id);
        if (user == null) return NotFound(new { message = "Utilisateur introuvable." });

        user.Statut                      = StatutUtilisateur.ACTIF;
        user.DateBlocage                 = null;
        user.RaisonBlocage               = null;
        user.TentativesConnexionEchouees = 0;
        user.DateVerrouillage            = null;
        user.DateMiseAJour               = DateTime.UtcNow;

        await _context.SaveChangesAsync();
        await LogAudit(adminId.Value, "UNBLOCK_USER", "ADMIN", true,
            $"Utilisateur {user.Email} débloqué.");

        return Ok(new { message = $"Utilisateur {user.Email} débloqué avec succès." });
    }

    // ── Admin : Supprimer utilisateur ──────────────────────────────────────

    [HttpDelete("admin/users/{id}")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> DeleteUser(Guid id)
    {
        var adminId = GetCurrentUserId();
        if (adminId == null) return Unauthorized();

        var user = await _context.Utilisateurs.FindAsync(id);
        if (user == null) return NotFound(new { message = "Utilisateur introuvable." });

        if (user.Id == adminId)
            return BadRequest(new { message = "Vous ne pouvez pas supprimer votre propre compte." });

        var email = user.Email;
        _context.Utilisateurs.Remove(user);

        await _context.SaveChangesAsync();
        await LogAudit(adminId.Value, "DELETE_USER", "ADMIN", true,
            $"Utilisateur {email} supprimé.");

        return Ok(new { message = $"Utilisateur {email} supprimé avec succès." });
    }

    // ── Admin : Rôles ──────────────────────────────────────────────────────

    [HttpGet("admin/roles")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> GetRoles()
    {
        var roles = await _context.Roles
            .Where(r => r.Actif)
            .Select(r => new { r.Id, r.Nom, r.Description })
            .ToListAsync();

        return Ok(roles);
    }

    [HttpPost("admin/roles")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
    {
        var adminId = GetCurrentUserId();
        if (adminId == null) return Unauthorized();

        if (string.IsNullOrWhiteSpace(request.Nom))
            return BadRequest(new { message = "Le nom du rôle est requis." });

        var exists = await _context.Roles.AnyAsync(r => r.Nom == request.Nom.ToUpper());
        if (exists)
            return BadRequest(new { message = "Ce rôle existe déjà." });

        var role = new Role
        {
            Id           = Guid.NewGuid(),
            Nom          = request.Nom.ToUpper(),
            Description  = request.Description,
            Actif        = true,
            DateCreation = DateTime.UtcNow
        };

        _context.Roles.Add(role);
        await _context.SaveChangesAsync();
        await LogAudit(adminId.Value, "CREATE_ROLE", "ADMIN", true, $"Rôle créé: {role.Nom}");

        return Ok(new { message = $"Rôle {role.Nom} créé avec succès.", roleId = role.Id });
    }

    [HttpPost("admin/users/{userId}/roles/{roleId}")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> AssignRole(Guid userId, Guid roleId)
    {
        var adminId = GetCurrentUserId();
        if (adminId == null) return Unauthorized();

        var user = await _context.Utilisateurs.FindAsync(userId);
        if (user == null) return NotFound(new { message = "Utilisateur introuvable." });

        var role = await _context.Roles.FindAsync(roleId);
        if (role == null || !role.Actif)
            return NotFound(new { message = "Rôle introuvable." });

        var existingRole = await _context.UtilisateurRoles
            .FirstOrDefaultAsync(ur => ur.UtilisateurId == userId && ur.RoleId == roleId);

        if (existingRole != null)
        {
            if (existingRole.Actif)
                return BadRequest(new { message = "L'utilisateur possède déjà ce rôle." });

            existingRole.Actif           = true;
            existingRole.DateAssignation = DateTime.UtcNow;
            existingRole.AssignePar      = adminId.Value;
        }
        else
        {
            _context.UtilisateurRoles.Add(new UtilisateurRole
            {
                UtilisateurId   = userId,
                RoleId          = roleId,
                DateAssignation = DateTime.UtcNow,
                AssignePar      = adminId.Value,
                Actif           = true
            });
        }

        await _context.SaveChangesAsync();
        await LogAudit(adminId.Value, "ASSIGN_ROLE", "ADMIN", true,
            $"Rôle {role.Nom} assigné à {user.Email}");

        return Ok(new { message = $"Rôle {role.Nom} assigné avec succès." });
    }

    [HttpDelete("admin/users/{userId}/roles/{roleId}")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> RevokeRole(Guid userId, Guid roleId)
    {
        var adminId = GetCurrentUserId();
        if (adminId == null) return Unauthorized();

        var utilisateurRole = await _context.UtilisateurRoles
            .Include(ur => ur.Utilisateur)
            .Include(ur => ur.Role)
            .FirstOrDefaultAsync(ur => ur.UtilisateurId == userId && ur.RoleId == roleId && ur.Actif);

        if (utilisateurRole == null)
            return NotFound(new { message = "Association utilisateur-rôle introuvable." });

        utilisateurRole.Actif = false;

        await _context.SaveChangesAsync();
        await LogAudit(adminId.Value, "REVOKE_ROLE", "ADMIN", true,
            $"Rôle {utilisateurRole.Role.Nom} révoqué pour {utilisateurRole.Utilisateur.Email}");

        return Ok(new { message = $"Rôle {utilisateurRole.Role.Nom} révoqué avec succès." });
    }

    // ── Admin : Clients ────────────────────────────────────────────────────

    [HttpGet("admin/clients")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> GetClients()
    {
        var clients = await _context.ClientsApplications
            .Where(c => c.Actif)
            .Select(c => new
            {
                c.Id,
                c.Nom,
                c.Description,
                c.ClientId,
                c.AllowedRoles,
                c.AllowedScopes,
                c.RedirectionUris,
                c.RequiertPKCE,
                c.TokenLifetimeSecondes,
                c.RefreshTokenLifetimeJours,
                c.DateCreation
            })
            .ToListAsync();

        return Ok(clients);
    }

    // ── Admin : Audit Logs ─────────────────────────────────────────────────

    [HttpGet("admin/audit-logs")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> GetAuditLogs(
        [FromQuery] int     page      = 1,
        [FromQuery] int     pageSize  = 20,
        [FromQuery] string? action    = null,
        [FromQuery] string? dateDebut = null,
        [FromQuery] string? dateFin   = null)
    {
        var query = _context.AuditLogs
            .Include(a => a.Utilisateur)
            .AsQueryable();

        if (!string.IsNullOrEmpty(action))
            query = query.Where(a => a.Action == action);

        if (!string.IsNullOrEmpty(dateDebut) && DateTime.TryParse(dateDebut, out var dDebut))
            query = query.Where(a => a.DateHeure >= dDebut);

        if (!string.IsNullOrEmpty(dateFin) && DateTime.TryParse(dateFin, out var dFin))
            query = query.Where(a => a.DateHeure < dFin.AddDays(1));

        var total = await query.CountAsync();

        var items = await query
            .OrderByDescending(a => a.DateHeure)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(a => new
            {
                a.Id,
                Email         = a.Utilisateur != null ? a.Utilisateur.Email : null,
                a.Action,
                a.Categorie,
                a.IpAddress,
                a.DateHeure,
                a.Succes,
                a.MessageErreur
            })
            .ToListAsync();

        return Ok(new
        {
            items,
            total,
            page,
            pageSize,
            totalPages = (int)Math.Ceiling((double)total / pageSize)
        });
    }

    // ── Admin : Sessions ───────────────────────────────────────────────────

    [HttpGet("admin/sessions")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> GetSessions(
        [FromQuery] int page     = 1,
        [FromQuery] int pageSize = 20)
    {
        var total = await _context.Sessions.CountAsync();

        var items = await _context.Sessions
            .Include(s => s.Utilisateur)
            .OrderByDescending(s => s.DateCreation)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(s => new
            {
                s.Id,
                s.SessionId,
                Email                = s.Utilisateur != null ? s.Utilisateur.Email : null,
                s.IpAddress,
                s.UserAgent,
                s.DateCreation,
                s.DateDerniereActivite,
                Statut = s.Statut.ToString()
            })
            .ToListAsync();

        return Ok(new
        {
            items,
            total,
            page,
            pageSize,
            totalPages = (int)Math.Ceiling((double)total / pageSize)
        });
    }

    [HttpPatch("admin/sessions/{id}/revoquer")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> RevoquerSession(Guid id)
    {
        var adminId = GetCurrentUserId();
        if (adminId == null) return Unauthorized();

        var session = await _context.Sessions
            .Include(s => s.Utilisateur)
            .FirstOrDefaultAsync(s => s.Id == id);

        if (session == null)
            return NotFound(new { message = "Session introuvable." });

        if (session.Statut != StatutSession.ACTIVE)
            return BadRequest(new { message = "Cette session n'est pas active." });

        session.Statut = StatutSession.REVOQUEE;

        await _context.SaveChangesAsync();
        await LogAudit(
            adminId.Value,
            "REVOKE_SESSION",
            "ADMIN",
            true,
            $"Session {session.SessionId} révoquée pour {session.Utilisateur?.Email}");

        return Ok(new { message = "Session révoquée avec succès." });
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private Guid? GetCurrentUserId()
    {
        var userIdString = User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(userIdString, out var userId) ? userId : null;
    }

    private async Task LogAudit(Guid userId, string action, string categorie, bool succes, string? details = null)
    {
        _context.AuditLogs.Add(new AuditLog
        {
            Id            = Guid.NewGuid(),
            UtilisateurId = userId,
            Action        = action,
            Categorie     = categorie,
            IpAddress     = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "",
            UserAgent     = Request.Headers["User-Agent"].ToString(),
            DateHeure     = DateTime.UtcNow,
            Succes        = succes,
            DetailsJson   = details
        });
        await _context.SaveChangesAsync();
    }

    private static (string Raw, string Hash) GenererTokenVerification()
    {
        var raw = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))
                         .Replace("+", "-").Replace("/", "_").TrimEnd('=');
        using var sha256 = SHA256.Create();
        var hash = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(raw)));
        return (raw, hash);
    }
}

// ── DTOs ───────────────────────────────────────────────────────────────────

public class CreateUserRequest
{
    public string       Email    { get; set; } = string.Empty;
    public string       Password { get; set; } = string.Empty;
    public string       Nom      { get; set; } = string.Empty;
    public string       Prenom   { get; set; } = string.Empty;
    public List<Guid>?  RoleIds  { get; set; }
}

public class BloquerRequest
{
    public string Raison { get; set; } = string.Empty;
}

public class CreateRoleRequest
{
    public string Nom         { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

public class ChangePasswordRequest
{
    public string? AncienMotDePasse       { get; set; }
    public string  NouveauMotDePasse      { get; set; } = string.Empty;
    public string  ConfirmationMotDePasse { get; set; } = string.Empty;
}