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

        // ── Générer le token de vérification email ────────────────────────
        var (rawToken, tokenHash) = GenererTokenVerification();

        var user = new Utilisateur
        {
            Id                          = Guid.NewGuid(),
            Email                       = request.Email.Trim().ToLower(),
            Nom                         = request.Nom,
            Prenom                      = request.Prenom,
            MotDePasseHash              = _passwordHasher.Hash(request.Password),
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

        // ── Envoyer l'email de confirmation ───────────────────────────────
        var baseUrl = _configuration["AppSettings:BaseUrl"] ?? "http://localhost:5095";
        var lien    = $"{baseUrl}/api/Auth/confirm-email?token={Uri.EscapeDataString(rawToken)}";

        await _emailService.EnvoyerEmailConfirmationAsync(
            user.Email,
            $"{user.Prenom} {user.Nom}",
            lien);

        return Ok(new
        {
            message = "Utilisateur créé avec succès. Un email de confirmation a été envoyé.",
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
                Statut = u.Statut.ToString(),
                u.DateCreation,
                u.DateDerniereConnexion,
                u.DateBlocage,
                u.RaisonBlocage,
                u.DoitChangerMotDePasse,
                u.EmailVerifie,
                Roles = u.UtilisateurRoles.Select(ur => new { ur.Role.Id, ur.Role.Nom }).ToList()
            })
            .ToListAsync();

        return Ok(users);
    }

    // ── Admin : Bloquer ────────────────────────────────────────────────────

    [HttpPatch("admin/users/{userId}/bloquer")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> BloquerUtilisateur(Guid userId, [FromBody] BloquerRequest request)
    {
        var adminId = GetCurrentUserId();
        if (adminId == null) return Unauthorized();

        if (adminId == userId)
            return BadRequest(new { message = "Vous ne pouvez pas bloquer votre propre compte." });

        var user = await _context.Utilisateurs.FindAsync(userId);
        if (user == null) return NotFound(new { message = "Utilisateur introuvable." });

        user.Statut        = StatutUtilisateur.BLOQUE;
        user.DateBlocage   = DateTime.UtcNow;
        user.RaisonBlocage = request.Raison;

        await _context.SaveChangesAsync();
        await LogAudit(adminId.Value, "BLOCK_USER", "ADMIN", true, $"Utilisateur {user.Email} bloqué: {request.Raison}");

        return Ok(new { message = $"Utilisateur {user.Email} bloqué avec succès." });
    }

    // ── Admin : Débloquer ──────────────────────────────────────────────────

    [HttpPatch("admin/users/{userId}/debloquer")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> DebloquerUtilisateur(Guid userId)
    {
        var adminId = GetCurrentUserId();
        if (adminId == null) return Unauthorized();

        var user = await _context.Utilisateurs.FindAsync(userId);
        if (user == null) return NotFound(new { message = "Utilisateur introuvable." });

        user.Statut        = StatutUtilisateur.ACTIF;
        user.DateBlocage   = null;
        user.RaisonBlocage = null;

        await _context.SaveChangesAsync();
        await LogAudit(adminId.Value, "UNBLOCK_USER", "ADMIN", true, $"Utilisateur {user.Email} débloqué");

        return Ok(new { message = $"Utilisateur {user.Email} débloqué avec succès." });
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

        var nomNormalise = request.Nom.Trim().ToUpper();

        var existing = await _context.Roles.FirstOrDefaultAsync(r => r.Nom == nomNormalise);
        if (existing != null)
            return BadRequest(new { message = "Un rôle avec ce nom existe déjà." });

        var role = new Role
        {
            Id           = Guid.NewGuid(),
            Nom          = nomNormalise,
            Description  = request.Description,
            Actif        = true,
            DateCreation = DateTime.UtcNow
        };

        _context.Roles.Add(role);
        await _context.SaveChangesAsync();
        await LogAudit(adminId.Value, "CREATE_ROLE", "ADMIN", true, $"Rôle créé: {role.Nom}");

        return Ok(new { message = "Rôle créé avec succès.", roleId = role.Id });
    }

    [HttpPost("admin/users/{userId}/roles/{roleId}")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> AssignerRole(Guid userId, Guid roleId)
    {
        var adminId = GetCurrentUserId();
        if (adminId == null) return Unauthorized();

        var user = await _context.Utilisateurs.FindAsync(userId);
        if (user == null)
        {
            await LogAudit(adminId.Value, "ASSIGN_ROLE_FAILED", "ADMIN", false, $"Utilisateur {userId} introuvable");
            return NotFound(new { message = "Utilisateur introuvable." });
        }

        var role = await _context.Roles.FindAsync(roleId);
        if (role == null || !role.Actif)
        {
            await LogAudit(adminId.Value, "ASSIGN_ROLE_FAILED", "ADMIN", false, $"Rôle {roleId} introuvable");
            return NotFound(new { message = "Rôle introuvable ou inactif." });
        }

        var existingRole = await _context.UtilisateurRoles
            .FirstOrDefaultAsync(ur => ur.UtilisateurId == userId && ur.RoleId == roleId);

        if (existingRole != null && existingRole.Actif)
            return BadRequest(new { message = "Ce rôle est déjà assigné à cet utilisateur." });

        if (existingRole != null)
        {
            existingRole.Actif           = true;
            existingRole.DateRevocation  = null;
            existingRole.RevoquePar      = null;
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
        await LogAudit(adminId.Value, "ASSIGN_ROLE", "ADMIN", true, $"Rôle {role.Nom} assigné à {user.Email}");

        return Ok(new { message = $"Rôle {role.Nom} assigné à {user.Email} avec succès." });
    }

    [HttpDelete("admin/users/{userId}/roles/{roleId}")]
    [Authorize(Roles = "ADMIN")]
    public async Task<IActionResult> RevoquerRole(Guid userId, Guid roleId)
    {
        var adminId = GetCurrentUserId();
        if (adminId == null) return Unauthorized();

        var utilisateurRole = await _context.UtilisateurRoles
            .Include(ur => ur.Role)
            .Include(ur => ur.Utilisateur)
            .FirstOrDefaultAsync(ur => ur.UtilisateurId == userId && ur.RoleId == roleId && ur.Actif);

        if (utilisateurRole == null)
        {
            await LogAudit(adminId.Value, "REVOKE_ROLE_FAILED", "ADMIN", false,
                $"Rôle {roleId} non assigné à l'utilisateur {userId}");
            return NotFound(new { message = "Ce rôle n'est pas assigné à cet utilisateur." });
        }

        utilisateurRole.Actif          = false;
        utilisateurRole.DateRevocation = DateTime.UtcNow;
        utilisateurRole.RevoquePar     = adminId.Value;

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