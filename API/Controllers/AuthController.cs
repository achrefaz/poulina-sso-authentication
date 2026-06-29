using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Domain.Commands.Auth;
using Domain.Queries.Auth;
using Microsoft.AspNetCore.RateLimiting;
using QRCoder;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IMediator _mediator;
    private const string RefreshTokenCookieName = "X-Refresh-Token";

    public AuthController(IMediator mediator)
    {
        _mediator = mediator;
    }

    private void SetRefreshTokenCookie(string refreshToken, int lifetimeDays = 7)
    {
        Response.Cookies.Append(RefreshTokenCookieName, refreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure   = true,
            SameSite = SameSiteMode.Strict,
            Expires  = DateTimeOffset.UtcNow.AddDays(lifetimeDays),
            Path     = "/api/Auth"
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

    // Register

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var result = await _mediator.Send(new RegisterCommand(request));
        return result.Success
            ? Ok(new { message = result.Message, userId = result.UserId })
            : BadRequest(new { message = result.Message });
    }

    // Login direct

    [HttpPost("login-direct")]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> LoginDirect([FromBody] LoginDirectRequest request)
    {
        var ip        = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
        var userAgent = Request.Headers["User-Agent"].ToString();

        var result = await _mediator.Send(new LoginDirectCommand(request, ip, userAgent));

        if (!result.Success)
        {
            return result.ErrorCode switch
            {
                "BLOCKED"            => Unauthorized(new { message = result.Message, raison = result.Raison }),
                "DISABLED"           => Unauthorized(new { message = result.Message }),
                "LOCKED"             => Unauthorized(new { message = result.Message }),
                "EMAIL_NOT_VERIFIED" => Unauthorized(new { message = result.Message, errorCode = result.ErrorCode }),
                _                    => Unauthorized(new { message = result.Message })
            };
        }

        if (result.MfaRequired)
            return Ok(new { mfaRequired = true, mfaPendingToken = result.MfaPendingToken });

        if (result.PasswordChangeRequired)
            return Ok(new { passwordChangeRequired = true, accessToken = result.AccessToken, roles = result.Roles });

        if (result.RefreshToken != null)
            SetRefreshTokenCookie(result.RefreshToken);

        return Ok(new
        {
            accessToken = result.AccessToken,
            expiresIn   = result.ExpiresIn,
            tokenType   = "Bearer",
            roles       = result.Roles,
            userId      = result.UserId
        });
    }

    // Refresh Token

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest? body)
    {
        var refreshTokenFromCookie = GetRefreshTokenFromCookie();

        if (string.IsNullOrEmpty(refreshTokenFromCookie))
            return Unauthorized(new { message = "Refresh token manquant." });

        var ip     = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
        var result = await _mediator.Send(
            new RefreshTokenCommand(
                new RefreshRequest
                {
                    RefreshToken = refreshTokenFromCookie,
                    ClientId     = body?.ClientId
                },
                ip));

        if (!result.Success)
        {
            DeleteRefreshTokenCookie();
            return Unauthorized(new { message = result.Message });
        }

        if (result.RefreshToken != null)
            SetRefreshTokenCookie(result.RefreshToken);

        return Ok(new { accessToken = result.AccessToken, expiresIn = 900, tokenType = "Bearer" });
    }

    // Logout

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var userIdStr = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userIdStr, out var userId))
            return Unauthorized();

        var jti        = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value ?? "";
        var expClaim   = User.FindFirst(JwtRegisteredClaimNames.Exp)?.Value ?? "0";
        var expiration = DateTimeOffset.FromUnixTimeSeconds(long.Parse(expClaim)).UtcDateTime;

        var refreshTokenFromCookie = GetRefreshTokenFromCookie();

        var result = await _mediator.Send(new LogoutCommand(
            refreshTokenFromCookie != null
                ? new LogoutRequest { RefreshToken = refreshTokenFromCookie }
                : null,
            userId, jti, expiration));

        DeleteRefreshTokenCookie();
        return Ok(new { message = result.Message });
    }

    // UserInfo

    [HttpGet("userinfo")]
    [Authorize]
    public async Task<IActionResult> UserInfo()
    {
        var userIdStr = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
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
                pwd_change_required = result.DoitChangerMotDePasse,
                mfa_enabled         = result.MfaEnabled
            })
            : NotFound(new { message = "Utilisateur introuvable." });
    }

    // MFA Setup

    [HttpPost("mfa/setup")]
    [Authorize]
    public async Task<IActionResult> MfaSetup()
    {
        var userIdStr = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userIdStr, out var userId))
            return Unauthorized();

        var result = await _mediator.Send(new SetupMfaCommand(userId));

        if (!result.Success)
            return BadRequest(new { message = result.Message });

        string qrCodeBase64;
        try
        {
            using var qrGenerator = new QRCodeGenerator();
            using var qrData      = qrGenerator.CreateQrCode(result.OtpAuthUri!, QRCodeGenerator.ECCLevel.M);
            using var qrCode      = new PngByteQRCode(qrData);
            var pngBytes          = qrCode.GetGraphic(5);
            qrCodeBase64 = "data:image/png;base64," + Convert.ToBase64String(pngBytes);
        }
        catch
        {
            qrCodeBase64 = result.OtpAuthUri!;
        }

        return Ok(new
        {
            message      = result.Message,
            otpAuthUri   = result.OtpAuthUri,
            qrCodeBase64 = qrCodeBase64,
            manualSecret = result.ManualSecret
        });
    }

    // MFA Verify Setup

    [HttpPost("mfa/verify-setup")]
    [Authorize]
    public async Task<IActionResult> MfaVerifySetup([FromBody] MfaCodeRequest request)
    {
        var userIdStr = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userIdStr, out var userId))
            return Unauthorized();

        var result = await _mediator.Send(new VerifyMfaSetupCommand(userId, request.Code));

        return result.Success
            ? Ok(new { message = result.Message })
            : BadRequest(new { message = result.Message });
    }

    // MFA Verify Login

    [HttpPost("mfa/verify")]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> MfaVerify([FromBody] MfaVerifyRequest request)
    {
        if (string.IsNullOrEmpty(request.MfaPendingToken) || string.IsNullOrEmpty(request.Code))
            return BadRequest(new { message = "mfaPendingToken et code sont requis." });

        var ip        = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
        var userAgent = Request.Headers["User-Agent"].ToString();

        var result = await _mediator.Send(new VerifyMfaLoginCommand(
            request.MfaPendingToken,
            request.Code,
            ip,
            userAgent));

        if (!result.Success)
            return Unauthorized(new { message = result.Message });

        if (result.RefreshToken != null)
            SetRefreshTokenCookie(result.RefreshToken);

        return Ok(new
        {
            accessToken = result.AccessToken,
            expiresIn   = 900,
            tokenType   = "Bearer",
            roles       = result.Roles,
            userId      = result.UserId
        });
    }

    // MFA Disable

    [HttpPost("mfa/disable")]
    [Authorize]
    public async Task<IActionResult> MfaDisable([FromBody] MfaCodeRequest request)
    {
        var userIdStr = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userIdStr, out var userId))
            return Unauthorized();

        var result = await _mediator.Send(new DisableMfaCommand(userId, request.Code));

        return result.Success
            ? Ok(new { message = result.Message })
            : BadRequest(new { message = result.Message });
    }

    // Confirm Email

    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromQuery] string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return BadRequest(new { message = "Token manquant." });

        var result = await _mediator.Send(new ConfirmEmailCommand(token));

        return result.Success
            ? Ok(new { message = result.Message })
            : BadRequest(new { message = result.Message });
    }

    // Resend Confirmation Email

    [HttpPost("resend-confirmation")]
    public async Task<IActionResult> ResendConfirmation([FromBody] ResendConfirmationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email))
            return BadRequest(new { message = "Email requis." });

        var result = await _mediator.Send(new RenvoyerConfirmationEmailCommand(request.Email));
        return Ok(new { message = result.Message });
    }
}