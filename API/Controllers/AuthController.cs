using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Domain.Commands.Auth;
using Domain.Queries.Auth;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IMediator _mediator;

    // Nom du cookie Refresh Token
    private const string RefreshTokenCookieName = "X-Refresh-Token";

    public AuthController(IMediator mediator)
    {
        _mediator = mediator;
    }

    // ── Helpers cookies ────────────────────────────────────────────────────

    private void SetRefreshTokenCookie(string refreshToken, int lifetimeDays = 7)
    {
        Response.Cookies.Append(RefreshTokenCookieName, refreshToken, new CookieOptions
        {
            HttpOnly  = true,                        // inaccessible par JavaScript
            Secure    = true,                        // HTTPS uniquement
            SameSite  = SameSiteMode.Strict,         // bloque les requêtes cross-site
            Expires   = DateTimeOffset.UtcNow.AddDays(lifetimeDays),
            Path      = "/api/Auth"                  // limité aux endpoints Auth uniquement
        });
    }

    private void DeleteRefreshTokenCookie()
    {
        Response.Cookies.Delete(RefreshTokenCookieName, new CookieOptions
        {
            HttpOnly = true,
            Secure   = true,
            SameSite = SameSiteMode.Strict,
            Path     = "/api/Auth"
        });
    }

    private string? GetRefreshTokenFromCookie()
        => Request.Cookies[RefreshTokenCookieName];

    // ── 1. Register ────────────────────────────────────────────────────────
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var result = await _mediator.Send(new RegisterCommand(request));
        return result.Success
            ? Ok(new { message = result.Message, userId = result.UserId })
            : BadRequest(new { message = result.Message });
    }

    // ── 2. Login direct ────────────────────────────────────────────────────
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var ip        = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
        var userAgent = Request.Headers["User-Agent"].ToString();

        var result = await _mediator.Send(new LoginCommand(request, ip, userAgent));

        if (!result.Success)
        {
            return result.ErrorCode switch
            {
                "BLOCKED"  => Unauthorized(new { message = result.Message, raison = result.Raison }),
                "DISABLED" => Unauthorized(new { message = result.Message }),
                "LOCKED"   => Unauthorized(new { message = result.Message }),
                _          => Unauthorized(new { message = result.Message })
            };
        }

        // Refresh Token → Cookie HttpOnly (jamais exposé dans le body)
        if (result.RefreshToken != null)
            SetRefreshTokenCookie(result.RefreshToken);

        var response = new Dictionary<string, object?>
        {
            ["accessToken"] = result.AccessToken,
            ["expiresIn"]   = 900,
            ["tokenType"]   = "Bearer",
            ["userId"]      = result.UserId
        };

        if (result.DoitChangerMotDePasse)
            response["passwordChangeRequired"] = true;

        return Ok(response);
    }

    // ── 3. Login with code (OAuth2 Authorization Code Flow) ────────────────
    [HttpPost("login-with-code")]
    public async Task<IActionResult> LoginWithCode([FromBody] LoginWithCodeRequest request)
    {
        var ip        = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
        var userAgent = Request.Headers["User-Agent"].ToString();

        var result = await _mediator.Send(new LoginWithCodeCommand(request, ip, userAgent));

        if (!result.Success)
        {
            return result.ErrorCode switch
            {
                "invalid_client"          => BadRequest(new { error = result.ErrorCode, message = result.Message }),
                "invalid_redirect_uri"    => BadRequest(new { error = result.ErrorCode, message = result.Message }),
                "code_challenge_required" => BadRequest(new { error = result.ErrorCode, message = result.Message }),
                "access_denied"           => StatusCode(403, new { error = result.ErrorCode, message = result.Message }),
                _                         => Unauthorized(new { message = result.Message })
            };
        }

        return Ok(new { authorizationCode = result.Code, redirectUri = result.RedirectUri });
    }

    // ── 4. Refresh Token ───────────────────────────────────────────────────
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh()
    {
        // Lire le refresh token depuis le cookie HttpOnly (pas depuis le body)
        var refreshTokenFromCookie = GetRefreshTokenFromCookie();

        if (string.IsNullOrEmpty(refreshTokenFromCookie))
            return Unauthorized(new { message = "Refresh token manquant." });

        var ip     = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
        var result = await _mediator.Send(
            new RefreshTokenCommand(
                new RefreshRequest { RefreshToken = refreshTokenFromCookie },
                ip));

        if (!result.Success)
        {
            DeleteRefreshTokenCookie();
            return Unauthorized(new { message = result.Message });
        }

        // Nouveau refresh token → Cookie HttpOnly
        if (result.RefreshToken != null)
            SetRefreshTokenCookie(result.RefreshToken);

        return Ok(new
        {
            accessToken = result.AccessToken,
            expiresIn   = 900,
            tokenType   = "Bearer"
        });
    }

    // ── 5. Logout ──────────────────────────────────────────────────────────
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var userIdStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdStr, out var userId))
            return Unauthorized();

        var jti        = User.FindFirstValue(JwtRegisteredClaimNames.Jti) ?? "";
        var expClaim   = User.FindFirstValue(JwtRegisteredClaimNames.Exp) ?? "0";
        var expiration = DateTimeOffset
            .FromUnixTimeSeconds(long.Parse(expClaim))
            .UtcDateTime;

        // Lire le refresh token depuis le cookie pour le révoquer
        var refreshTokenFromCookie = GetRefreshTokenFromCookie();

        var result = await _mediator.Send(new LogoutCommand(
            refreshTokenFromCookie != null
                ? new LogoutRequest { RefreshToken = refreshTokenFromCookie }
                : null,
            userId,
            jti,
            expiration));

        // Supprimer le cookie refresh token
        DeleteRefreshTokenCookie();

        return Ok(new { message = result.Message });
    }

    // ── 6. UserInfo (OpenID Connect) ───────────────────────────────────────
    [HttpGet("userinfo")]
    [Authorize]
    public async Task<IActionResult> UserInfo()
    {
        var userIdStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdStr, out var userId))
            return Unauthorized();

        var result = await _mediator.Send(new GetUserInfoQuery(userId));

        return result.Success
            ? Ok(new
            {
                sub                 = result.Sub.ToString(),
                email               = result.Email,
                given_name          = result.Prenom,
                family_name         = result.Nom,
                name                = $"{result.Prenom} {result.Nom}",
                roles               = result.Roles,
                statut              = result.Statut,
                email_verified      = true,
                pwd_change_required = result.DoitChangerMotDePasse
            })
            : NotFound(new { message = "Utilisateur introuvable." });
    }

    // ── 7. Authorize (OAuth2 step 1) ───────────────────────────────────────
    [HttpGet("authorize")]
    public async Task<IActionResult> Authorize(
        [FromQuery] string client_id,
        [FromQuery] string redirect_uri,
        [FromQuery] string response_type,
        [FromQuery] string scope,
        [FromQuery] string? state,
        [FromQuery] string? code_challenge,
        [FromQuery] string? code_challenge_method)
    {
        var result = await _mediator.Send(
            new AuthorizeQuery(client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method));

        return result.Success
            ? Ok(new { message = "Paramètres valides. Redirigez l'utilisateur vers la page de login.", loginUrl = result.LoginUrl })
            : BadRequest(new { error = result.ErrorMessage });
    }
    
    // ── 8. Token (exchange code → access token) ────────────────────────────
    [HttpPost("token")]
    public async Task<IActionResult> Token([FromBody] TokenRequest request)
    {
        var result = await _mediator.Send(new ExchangeCodeCommand(request));

        if (!result.Success)
            return BadRequest(new { error = result.ErrorCode, error_description = result.ErrorDescription });

        // Refresh Token → Cookie HttpOnly
        if (result.RefreshToken != null)
            SetRefreshTokenCookie(result.RefreshToken);

        return Ok(new
        {
            access_token = result.AccessToken,
            token_type   = result.TokenType,
            expires_in   = result.ExpiresIn,
            scope        = result.Scope
            // refresh_token supprimé du body — maintenant dans le cookie
        });
    }
}