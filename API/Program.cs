using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Threading.RateLimiting;
using Data.Context;
using Data.Repositories;
using Domain.Interfaces;
using Infra.Security;
using Infra.Services;
using Domain.Handlers.Auth;
using API.Middleware;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ── DbContext ─────────────────────────────────────────────────────────────────
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// ── Repositories ──────────────────────────────────────────────────────────────
builder.Services.AddScoped<IAuthRepository, AuthRepository>();

// ── Infrastructure ────────────────────────────────────────────────────────────
builder.Services.AddScoped<IPasswordHasher, PasswordHasher>();

// ── Email Service (Brevo SMTP) ────────────────────────────────────────────────
builder.Services.AddScoped<IEmailService, BrevoEmailService>();

// ── MediatR ───────────────────────────────────────────────────────────────────
builder.Services.AddMediatR(cfg =>
    cfg.RegisterServicesFromAssembly(typeof(RegisterHandler).Assembly));

// ── CORS ──────────────────────────────────────────────────────────────────────
builder.Services.AddCors(options =>
{
    options.AddPolicy("SsoClients", policy =>
    {
        policy
            .WithOrigins(
                "http://localhost:4200",
                "http://localhost:3001",
                "http://localhost:3002",
                "http://localhost:3003")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

// ── Rate Limiting ─────────────────────────────────────────────────────────────
builder.Services.AddRateLimiter(options =>
{
    // 5 requêtes par minute par ip
    options.AddFixedWindowLimiter("login", o =>
    {
        o.PermitLimit          = 5;
        o.Window               = TimeSpan.FromMinutes(1);
        o.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        o.QueueLimit           = 0;
    });
    
    options.OnRejected = async (context, ct) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await context.HttpContext.Response.WriteAsJsonAsync(
            new { message = "Trop de tentatives. Réessayez dans une minute." }, ct);
    };
});

// ── JWT Authentication ────────────────────────────────────────────────────────
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey   = Encoding.UTF8.GetBytes(
    jwtSettings["SecretKey"] ?? "poulina-sso-super-secret-key-minimum-32-characters-2024");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme    = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken            = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey         = new SymmetricSecurityKey(secretKey),
        ValidateIssuer           = true,
        ValidIssuer              = jwtSettings["Issuer"],
        ValidateAudience         = true,
        ValidAudience            = jwtSettings["Audience"],
        ValidateLifetime         = true,
        ClockSkew                = TimeSpan.Zero
    };
});

var app = builder.Build();

// ── Migration automatique au démarrage ────────────────────────────────────────
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await db.Database.MigrateAsync();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// ── En-têtes de sécurité HTTP ─────────────────────────────────────────────────
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"]        = "DENY";
    context.Response.Headers["X-XSS-Protection"]       = "1; mode=block";
    context.Response.Headers["Referrer-Policy"]        = "strict-origin-when-cross-origin";
    context.Response.Headers["Permissions-Policy"]     = "geolocation=(), microphone=(), camera=()";
    await next();
});

app.UseCors("SsoClients");
app.UseRateLimiter();           
app.UseAuthentication();
app.UseMiddleware<TokenBlacklistMiddleware>();
app.UseAuthorization();
app.MapControllers();

app.Run();