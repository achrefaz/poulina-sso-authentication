using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Data.Context;
using Data.Repositories;
using Domain.Interfaces;
using Infra.Security;
using Infra.Services;
using Domain.Handlers.Auth;
using API.Middleware;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ── DbContext 
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// ── Repositories 
builder.Services.AddScoped<IAuthRepository, AuthRepository>();

// ── Infrastructure
builder.Services.AddScoped<IPasswordHasher, PasswordHasher>();

// ── Email Service (Brevo SMTP) 
builder.Services.AddScoped<IEmailService, BrevoEmailService>();

// ── MediatR 
builder.Services.AddMediatR(cfg =>
    cfg.RegisterServicesFromAssembly(typeof(RegisterHandler).Assembly));

// ── CORS 
builder.Services.AddCors(options =>
{
    options.AddPolicy("SsoClients", policy =>
    {
        policy
            .WithOrigins(
                "http://localhost:3001",
                "http://localhost:3002",
                "http://localhost:3003")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

// ── JWT Authentication
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

// ── Migration automatique au démarrage
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

app.UseHttpsRedirection();
app.UseCors("SsoClients");
app.UseAuthentication();
app.UseMiddleware<TokenBlacklistMiddleware>();
app.UseAuthorization();
app.MapControllers();

app.Run();