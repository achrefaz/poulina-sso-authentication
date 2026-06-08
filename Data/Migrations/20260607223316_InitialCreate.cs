using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ClientsApplications",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Nom = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ClientId = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    ClientSecretHash = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RedirectionUris = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PostLogoutRedirectionUris = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AllowedScopes = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AllowedRoles = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: false),
                    Actif = table.Column<bool>(type: "bit", nullable: false),
                    DateCreation = table.Column<DateTime>(type: "datetime2", nullable: false),
                    DateRotationSecret = table.Column<DateTime>(type: "datetime2", nullable: true),
                    RequiertPKCE = table.Column<bool>(type: "bit", nullable: false),
                    TokenLifetimeSecondes = table.Column<int>(type: "int", nullable: false),
                    RefreshTokenLifetimeJours = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientsApplications", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Roles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Nom = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: false),
                    Actif = table.Column<bool>(type: "bit", nullable: false),
                    DateCreation = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Roles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Utilisateurs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Email = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    MotDePasseHash = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Salt = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Nom = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Prenom = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Telephone = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    TypeMFA = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    SecretMFA = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    MFAValidee = table.Column<bool>(type: "bit", nullable: false),
                    Statut = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    DateCreation = table.Column<DateTime>(type: "datetime2", nullable: false),
                    DateDerniereConnexion = table.Column<DateTime>(type: "datetime2", nullable: true),
                    DateMiseAJour = table.Column<DateTime>(type: "datetime2", nullable: true),
                    TentativesConnexionEchouees = table.Column<int>(type: "int", nullable: false),
                    DateVerrouillage = table.Column<DateTime>(type: "datetime2", nullable: true),
                    DateBlocage = table.Column<DateTime>(type: "datetime2", nullable: true),
                    RaisonBlocage = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: true),
                    DoitChangerMotDePasse = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Utilisateurs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditLogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UtilisateurId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Action = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Categorie = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IpAddress = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    UserAgent = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DateHeure = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Succes = table.Column<bool>(type: "bit", nullable: false),
                    MessageErreur = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DetailsJson = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLogs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AuditLogs_Utilisateurs_UtilisateurId",
                        column: x => x.UtilisateurId,
                        principalTable: "Utilisateurs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "AuthorizationCodes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CodeHash = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    UtilisateurId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClientId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DateCreation = table.Column<DateTime>(type: "datetime2", nullable: false),
                    DateExpiration = table.Column<DateTime>(type: "datetime2", nullable: false),
                    EstUtilise = table.Column<bool>(type: "bit", nullable: false),
                    CodeChallenge = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CodeChallengeMethod = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Scopes = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthorizationCodes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AuthorizationCodes_ClientsApplications_ClientId",
                        column: x => x.ClientId,
                        principalTable: "ClientsApplications",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_AuthorizationCodes_Utilisateurs_UtilisateurId",
                        column: x => x.UtilisateurId,
                        principalTable: "Utilisateurs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RefreshTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UtilisateurId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClientId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TokenHash = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    DateCreation = table.Column<DateTime>(type: "datetime2", nullable: false),
                    DateExpiration = table.Column<DateTime>(type: "datetime2", nullable: false),
                    DateRevoquation = table.Column<DateTime>(type: "datetime2", nullable: true),
                    IpAddress = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    EstUtilise = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RefreshTokens_ClientsApplications_ClientId",
                        column: x => x.ClientId,
                        principalTable: "ClientsApplications",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_RefreshTokens_Utilisateurs_UtilisateurId",
                        column: x => x.UtilisateurId,
                        principalTable: "Utilisateurs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Sessions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UtilisateurId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SessionId = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    IpAddress = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    UserAgent = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DateCreation = table.Column<DateTime>(type: "datetime2", nullable: false),
                    DateDerniereActivite = table.Column<DateTime>(type: "datetime2", nullable: false),
                    DateExpiration = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Statut = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    DeviceInfo = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Sessions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Sessions_Utilisateurs_UtilisateurId",
                        column: x => x.UtilisateurId,
                        principalTable: "Utilisateurs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UtilisateurRoles",
                columns: table => new
                {
                    UtilisateurId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DateAssignation = table.Column<DateTime>(type: "datetime2", nullable: false),
                    AssignePar = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Actif = table.Column<bool>(type: "bit", nullable: false),
                    DateRevocation = table.Column<DateTime>(type: "datetime2", nullable: true),
                    RevoquePar = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UtilisateurRoles", x => new { x.UtilisateurId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_UtilisateurRoles_Roles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_UtilisateurRoles_Utilisateurs_UtilisateurId",
                        column: x => x.UtilisateurId,
                        principalTable: "Utilisateurs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "ClientsApplications",
                columns: new[] { "Id", "Actif", "AllowedRoles", "AllowedScopes", "ClientId", "ClientSecretHash", "DateCreation", "DateRotationSecret", "Description", "Nom", "PostLogoutRedirectionUris", "RedirectionUris", "RefreshTokenLifetimeJours", "RequiertPKCE", "TokenLifetimeSecondes" },
                values: new object[,]
                {
                    { new Guid("11111111-1111-1111-1111-111111111111"), true, "RH_USER,ADMIN", "openid profile email offline_access", "rh-client", "rh-secret-hash", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, "Plateforme RH Poulina", "RH Application", "http://localhost:3001", "http://localhost:3001/callback", 7, true, 900 },
                    { new Guid("22222222-2222-2222-2222-222222222222"), true, "FINANCE_USER,ADMIN", "openid profile email offline_access", "finance-client", "finance-secret-hash", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, "Plateforme Finance Poulina", "Finance Application", "http://localhost:3002", "http://localhost:3002/callback", 7, true, 900 },
                    { new Guid("33333333-3333-3333-3333-333333333333"), true, "DASHBOARD_VIEWER,ADMIN", "openid profile email offline_access", "dashboard-client", "dashboard-secret-hash", new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), null, "Dashboard analytique Poulina", "Dashboard", "http://localhost:3003", "http://localhost:3003/callback", 7, true, 900 }
                });

            migrationBuilder.InsertData(
                table: "Roles",
                columns: new[] { "Id", "Actif", "DateCreation", "Description", "Nom" },
                values: new object[,]
                {
                    { new Guid("00000000-0000-0000-0000-000000000001"), true, new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Accès total à toutes les plateformes", "ADMIN" },
                    { new Guid("00000000-0000-0000-0000-000000000002"), true, new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Accès à l'application Finance", "FINANCE_USER" },
                    { new Guid("00000000-0000-0000-0000-000000000003"), true, new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Accès à l'application RH", "RH_USER" },
                    { new Guid("00000000-0000-0000-0000-000000000004"), true, new DateTime(2025, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), "Accès au Dashboard en lecture", "DASHBOARD_VIEWER" }
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_DateHeure",
                table: "AuditLogs",
                column: "DateHeure");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_UtilisateurId",
                table: "AuditLogs",
                column: "UtilisateurId");

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationCodes_ClientId",
                table: "AuthorizationCodes",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationCodes_CodeHash",
                table: "AuthorizationCodes",
                column: "CodeHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationCodes_UtilisateurId",
                table: "AuthorizationCodes",
                column: "UtilisateurId");

            migrationBuilder.CreateIndex(
                name: "IX_ClientsApplications_ClientId",
                table: "ClientsApplications",
                column: "ClientId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_ClientId",
                table: "RefreshTokens",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_TokenHash",
                table: "RefreshTokens",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_UtilisateurId",
                table: "RefreshTokens",
                column: "UtilisateurId");

            migrationBuilder.CreateIndex(
                name: "IX_Roles_Nom",
                table: "Roles",
                column: "Nom",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Sessions_SessionId",
                table: "Sessions",
                column: "SessionId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Sessions_UtilisateurId",
                table: "Sessions",
                column: "UtilisateurId");

            migrationBuilder.CreateIndex(
                name: "IX_UtilisateurRoles_RoleId",
                table: "UtilisateurRoles",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "IX_Utilisateurs_Email",
                table: "Utilisateurs",
                column: "Email",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditLogs");

            migrationBuilder.DropTable(
                name: "AuthorizationCodes");

            migrationBuilder.DropTable(
                name: "RefreshTokens");

            migrationBuilder.DropTable(
                name: "Sessions");

            migrationBuilder.DropTable(
                name: "UtilisateurRoles");

            migrationBuilder.DropTable(
                name: "ClientsApplications");

            migrationBuilder.DropTable(
                name: "Roles");

            migrationBuilder.DropTable(
                name: "Utilisateurs");
        }
    }
}
