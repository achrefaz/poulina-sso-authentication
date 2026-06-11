using Domain.Models;
using Domain.Models.Enums;
using Microsoft.EntityFrameworkCore;

namespace Data.Context
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<Utilisateur>        Utilisateurs        { get; set; }
        public DbSet<ClientApplication>  ClientsApplications { get; set; }
        public DbSet<Session>            Sessions            { get; set; }
        public DbSet<RefreshToken>       RefreshTokens       { get; set; }
        public DbSet<AuthorizationCode>  AuthorizationCodes  { get; set; }
        public DbSet<AuditLog>           AuditLogs           { get; set; }
        public DbSet<Role>               Roles               { get; set; }
        public DbSet<UtilisateurRole>    UtilisateurRoles    { get; set; }
        public DbSet<RevokedToken>       RevokedTokens       { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // ── Utilisateur ───────────────────────────────────────────────────
            modelBuilder.Entity<Utilisateur>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.Email).IsUnique();
                entity.Property(e => e.Email).IsRequired().HasMaxLength(256);
                entity.Property(e => e.MotDePasseHash).IsRequired();
                entity.Property(e => e.Nom).HasMaxLength(100);
                entity.Property(e => e.Prenom).HasMaxLength(100);
                entity.Property(e => e.RaisonBlocage).HasMaxLength(500);
                entity.Property(e => e.Statut)
                      .HasConversion<string>()
                      .HasMaxLength(50);
                entity.Property(e => e.TypeMFA)
                      .HasConversion<string>()
                      .HasMaxLength(50);

                // ── Email Verification ────────────────────────────────────────
                entity.Property(e => e.EmailVerifie)
                      .HasDefaultValue(false);
                entity.Property(e => e.TokenVerificationEmail)
                      .HasMaxLength(512)
                      .IsRequired(false);
                entity.Property(e => e.TokenVerificationExpiration)
                      .IsRequired(false);
            });

            // ── Role ──────────────────────────────────────────────────────────
            modelBuilder.Entity<Role>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.Nom).IsUnique();
                entity.Property(e => e.Nom).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Description).HasMaxLength(500);
            });

            // ── UtilisateurRole ───────────────────────────────────────────────
            modelBuilder.Entity<UtilisateurRole>(entity =>
            {
                entity.HasKey(e => new { e.UtilisateurId, e.RoleId });
                entity.HasOne(e => e.Utilisateur)
                      .WithMany(u => u.UtilisateurRoles)
                      .HasForeignKey(e => e.UtilisateurId)
                      .OnDelete(DeleteBehavior.Cascade);
                entity.HasOne(e => e.Role)
                      .WithMany(r => r.UtilisateurRoles)
                      .HasForeignKey(e => e.RoleId)
                      .OnDelete(DeleteBehavior.Restrict);
            });

            // ── ClientApplication ─────────────────────────────────────────────
            modelBuilder.Entity<ClientApplication>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.ClientId).IsUnique();
                entity.Property(e => e.ClientId).IsRequired().HasMaxLength(100);
                entity.Property(e => e.ClientSecretHash).IsRequired();
                entity.Property(e => e.Nom).IsRequired().HasMaxLength(100);
                entity.Property(e => e.AllowedRoles).HasMaxLength(500);
            });

            // ── Session ───────────────────────────────────────────────────────
            modelBuilder.Entity<Session>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.SessionId).IsUnique();
                entity.Property(e => e.SessionId).IsRequired().HasMaxLength(256);
                entity.Property(e => e.Statut)
                      .HasConversion<string>()
                      .HasMaxLength(50);
                entity.HasOne(e => e.Utilisateur)
                      .WithMany(u => u.Sessions)
                      .HasForeignKey(e => e.UtilisateurId)
                      .OnDelete(DeleteBehavior.Cascade);
            });

            // ── RefreshToken ──────────────────────────────────────────────────
            modelBuilder.Entity<RefreshToken>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.TokenHash).IsUnique();
                entity.HasOne(e => e.Utilisateur)
                      .WithMany(u => u.RefreshTokens)
                      .HasForeignKey(e => e.UtilisateurId)
                      .OnDelete(DeleteBehavior.Cascade);
                entity.HasOne(e => e.Client)
                      .WithMany(c => c.RefreshTokens)
                      .HasForeignKey(e => e.ClientId)
                      .OnDelete(DeleteBehavior.Restrict);
            });

            // ── AuthorizationCode ─────────────────────────────────────────────
            modelBuilder.Entity<AuthorizationCode>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.CodeHash).IsUnique();
                entity.HasOne(e => e.Client)
                      .WithMany(c => c.AuthorizationCodes)
                      .HasForeignKey(e => e.ClientId)
                      .OnDelete(DeleteBehavior.Restrict);
            });

            // ── AuditLog ──────────────────────────────────────────────────────
            modelBuilder.Entity<AuditLog>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.DateHeure);
                entity.HasOne(e => e.Utilisateur)
                      .WithMany(u => u.AuditLogs)
                      .HasForeignKey(e => e.UtilisateurId)
                      .OnDelete(DeleteBehavior.SetNull);
            });

            // ── RevokedToken ──────────────────────────────────────────────────
            modelBuilder.Entity<RevokedToken>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.Jti).IsUnique();
                entity.Property(e => e.Jti).IsRequired().HasMaxLength(256);
            });

            // ── Seed : Rôles par défaut ───────────────────────────────────────
            modelBuilder.Entity<Role>().HasData(
                new Role
                {
                    Id           = Guid.Parse("00000000-0000-0000-0000-000000000001"),
                    Nom          = "ADMIN",
                    Description  = "Accès total à toutes les plateformes",
                    Actif        = true,
                    DateCreation = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                },
                new Role
                {
                    Id           = Guid.Parse("00000000-0000-0000-0000-000000000002"),
                    Nom          = "FINANCE_USER",
                    Description  = "Accès à l'application Finance",
                    Actif        = true,
                    DateCreation = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                },
                new Role
                {
                    Id           = Guid.Parse("00000000-0000-0000-0000-000000000003"),
                    Nom          = "RH_USER",
                    Description  = "Accès à l'application RH",
                    Actif        = true,
                    DateCreation = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                },
                new Role
                {
                    Id           = Guid.Parse("00000000-0000-0000-0000-000000000004"),
                    Nom          = "DASHBOARD_VIEWER",
                    Description  = "Accès au Dashboard en lecture",
                    Actif        = true,
                    DateCreation = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                }
            );

            // ── Seed : Clients par défaut ─────────────────────────────────────
            modelBuilder.Entity<ClientApplication>().HasData(
                new ClientApplication
                {
                    Id                        = Guid.Parse("11111111-1111-1111-1111-111111111111"),
                    Nom                       = "RH Application",
                    Description               = "Plateforme RH Poulina",
                    ClientId                  = "rh-client",
                    ClientSecretHash          = "rh-secret-hash",
                    RedirectionUris           = "http://localhost:3001/callback",
                    PostLogoutRedirectionUris = "http://localhost:3001",
                    AllowedScopes             = "openid profile email offline_access",
                    AllowedRoles              = "RH_USER,ADMIN",
                    Actif                     = true,
                    DateCreation              = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                    RequiertPKCE              = true,
                    TokenLifetimeSecondes     = 900,
                    RefreshTokenLifetimeJours = 7
                },
                new ClientApplication
                {
                    Id                        = Guid.Parse("22222222-2222-2222-2222-222222222222"),
                    Nom                       = "Finance Application",
                    Description               = "Plateforme Finance Poulina",
                    ClientId                  = "finance-client",
                    ClientSecretHash          = "finance-secret-hash",
                    RedirectionUris           = "http://localhost:3002/callback",
                    PostLogoutRedirectionUris = "http://localhost:3002",
                    AllowedScopes             = "openid profile email offline_access",
                    AllowedRoles              = "FINANCE_USER,ADMIN",
                    Actif                     = true,
                    DateCreation              = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                    RequiertPKCE              = true,
                    TokenLifetimeSecondes     = 900,
                    RefreshTokenLifetimeJours = 7
                },
                new ClientApplication
                {
                    Id                        = Guid.Parse("33333333-3333-3333-3333-333333333333"),
                    Nom                       = "Dashboard",
                    Description               = "Dashboard analytique Poulina",
                    ClientId                  = "dashboard-client",
                    ClientSecretHash          = "dashboard-secret-hash",
                    RedirectionUris           = "http://localhost:3003/callback",
                    PostLogoutRedirectionUris = "http://localhost:3003",
                    AllowedScopes             = "openid profile email offline_access",
                    AllowedRoles              = "DASHBOARD_VIEWER,ADMIN",
                    Actif                     = true,
                    DateCreation              = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                    RequiertPKCE              = true,
                    TokenLifetimeSecondes     = 900,
                    RefreshTokenLifetimeJours = 7
                }
            );
        }
    }
}