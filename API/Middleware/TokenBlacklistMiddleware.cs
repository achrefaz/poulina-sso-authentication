using System.IdentityModel.Tokens.Jwt;
using Domain.Interfaces;

namespace API.Middleware
{
    public class TokenBlacklistMiddleware
    {
        private readonly RequestDelegate _next;

        public TokenBlacklistMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, IAuthRepository repo)
        {
            var authHeader = context.Request.Headers["Authorization"].ToString();

            if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
            {
                var token = authHeader.Replace("Bearer ", "").Trim();
                var handler = new JwtSecurityTokenHandler();

                if (handler.CanReadToken(token))
                {
                    try
                    {
                        var jwt = handler.ReadJwtToken(token);
                        var jti = jwt.Claims
                            .FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;

                        if (!string.IsNullOrEmpty(jti))
                        {
                            var isRevoked = await repo.IsJwtRevokedAsync(jti);

                            if (isRevoked)
                            {
                                context.Response.StatusCode  = 401;
                                context.Response.ContentType = "application/json";
                                await context.Response.WriteAsJsonAsync(
                                    new { message = "Token révoqué. Veuillez vous reconnecter." });
                                return;
                            }
                        }
                    }
                    catch
                    {
                    }
                }
            }

            await _next(context);
        }
    }
}