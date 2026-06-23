using Domain.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Mail;

namespace Infra.Services
{
    public class BrevoEmailService : IEmailService
    {
        private readonly IConfiguration             _config;
        private readonly ILogger<BrevoEmailService> _logger;

        public BrevoEmailService(
            IConfiguration             config,
            ILogger<BrevoEmailService> logger)
        {
            _config = config;
            _logger = logger;
        }

        // ── Envoi initial ─────────────────────────────────────────────────────

        public Task EnvoyerEmailConfirmationAsync(
            string destinataireEmail,
            string destinataireNom,
            string lienConfirmation,
            CancellationToken ct = default)
            => EnvoyerAsync(
                destinataireEmail,
                destinataireNom,
                sujet:    "Confirmez votre compte Poulina SSO",
                htmlBody: BuildHtmlConfirmation(destinataireNom, lienConfirmation),
                ct);

        // ── Renvoi ────────────────────────────────────────────────────────────

        public Task RenvoyerEmailConfirmationAsync(
            string destinataireEmail,
            string destinataireNom,
            string lienConfirmation,
            CancellationToken ct = default)
            => EnvoyerAsync(
                destinataireEmail,
                destinataireNom,
                sujet:    "Nouveau lien de confirmation — Poulina SSO",
                htmlBody: BuildHtmlRenouvellement(destinataireNom, lienConfirmation),
                ct);

        // ── Credentials initiaux ──────────────────────────────────────────────

        public Task EnvoyerCredentialsAsync(
            string destinataireEmail,
            string destinataireNom,
            string motDePasseTemporaire,
            CancellationToken ct = default)
            => EnvoyerAsync(
                destinataireEmail,
                destinataireNom,
                sujet:    "Vos accès Poulina SSO",
                htmlBody: BuildHtmlCredentials(destinataireNom, destinataireEmail, motDePasseTemporaire),
                ct);

        // ── Core SMTP ─────────────────────────────────────────────────────────

        private async Task EnvoyerAsync(
            string destinataireEmail,
            string destinataireNom,
            string sujet,
            string htmlBody,
            CancellationToken ct)
        {
            var smtpLogin    = _config["Brevo:SmtpLogin"]
                               ?? throw new InvalidOperationException("Brevo:SmtpLogin manquant.");
            var smtpPassword = _config["Brevo:SmtpPassword"]
                               ?? throw new InvalidOperationException("Brevo:SmtpPassword manquant.");
            var expedEmail   = _config["Brevo:ExpéditeurEmail"] ?? smtpLogin;
            var expedNom     = _config["Brevo:ExpéditeurNom"]   ?? "Poulina SSO";

            try
            {
                using var client = new SmtpClient("smtp-relay.brevo.com", 587)
                {
                    Credentials    = new NetworkCredential(smtpLogin, smtpPassword),
                    EnableSsl      = true,
                    DeliveryMethod = SmtpDeliveryMethod.Network
                };

                using var message = new MailMessage
                {
                    From       = new MailAddress(expedEmail, expedNom),
                    Subject    = sujet,
                    Body       = htmlBody,
                    IsBodyHtml = true
                };
                message.To.Add(new MailAddress(destinataireEmail, destinataireNom));

                await client.SendMailAsync(message, ct);

                _logger.LogInformation("Email envoyé à {Email} — sujet: {Sujet}",
                    destinataireEmail, sujet);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Impossible d'envoyer l'email à {Email}", destinataireEmail);
            }
        }

        // ── Templates HTML ────────────────────────────────────────────────────

        private static string BuildHtmlConfirmation(string nom, string lien) => $"""
            <!DOCTYPE html>
            <html lang="fr">
            <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
            <body style="margin:0;padding:0;background:#f4f6f8;font-family:Arial,sans-serif;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr><td align="center" style="padding:40px 20px;">
                  <table width="600" cellpadding="0" cellspacing="0"
                         style="background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
                    <tr>
                      <td style="background:#1a3a5c;padding:32px 40px;text-align:center;">
                        <h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:700;">Poulina SSO</h1>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:40px;">
                        <h2 style="margin:0 0 16px;color:#111827;font-size:20px;">Bonjour {nom},</h2>
                        <p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6;">
                          Votre compte Poulina SSO a été créé par un administrateur.<br>
                          Cliquez sur le bouton ci-dessous pour confirmer votre adresse email et activer votre compte.
                        </p>
                        <table cellpadding="0" cellspacing="0" width="100%">
                          <tr>
                            <td align="center" style="padding:8px 0 32px;">
                              <a href="{lien}"
                                 style="display:inline-block;background:#1a3a5c;color:#ffffff;
                                        text-decoration:none;padding:14px 32px;border-radius:6px;
                                        font-size:15px;font-weight:600;">
                                Confirmer mon email
                              </a>
                            </td>
                          </tr>
                        </table>
                        <p style="margin:0 0 8px;color:#6b7280;font-size:13px;">
                          Ce lien est valable <strong>24 heures</strong>.
                        </p>
                        <p style="margin:0;color:#6b7280;font-size:13px;">
                          <a href="{lien}" style="color:#1a3a5c;word-break:break-all;">{lien}</a>
                        </p>
                      </td>
                    </tr>
                    <tr>
                      <td style="background:#f9fafb;padding:20px 40px;text-align:center;border-top:1px solid #e5e7eb;">
                        <p style="margin:0;color:#9ca3af;font-size:12px;">
                          © 2025 Poulina Group — Système SSO
                        </p>
                      </td>
                    </tr>
                  </table>
                </td></tr>
              </table>
            </body>
            </html>
            """;

        private static string BuildHtmlRenouvellement(string nom, string lien) => $"""
            <!DOCTYPE html>
            <html lang="fr">
            <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
            <body style="margin:0;padding:0;background:#f4f6f8;font-family:Arial,sans-serif;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr><td align="center" style="padding:40px 20px;">
                  <table width="600" cellpadding="0" cellspacing="0"
                         style="background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
                    <tr>
                      <td style="background:#1a3a5c;padding:32px 40px;text-align:center;">
                        <h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:700;">Poulina SSO</h1>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:40px;">
                        <h2 style="margin:0 0 16px;color:#111827;font-size:20px;">Bonjour {nom},</h2>
                        <p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6;">
                          Vous avez demandé un nouveau lien de confirmation.<br>
                          Cliquez ci-dessous pour activer votre compte.
                        </p>
                        <table cellpadding="0" cellspacing="0" width="100%">
                          <tr>
                            <td align="center" style="padding:8px 0 32px;">
                              <a href="{lien}"
                                 style="display:inline-block;background:#1a3a5c;color:#ffffff;
                                        text-decoration:none;padding:14px 32px;border-radius:6px;
                                        font-size:15px;font-weight:600;">
                                Confirmer mon email
                              </a>
                            </td>
                          </tr>
                        </table>
                        <p style="margin:0;color:#6b7280;font-size:13px;">
                          <a href="{lien}" style="color:#1a3a5c;word-break:break-all;">{lien}</a>
                        </p>
                      </td>
                    </tr>
                    <tr>
                      <td style="background:#f9fafb;padding:20px 40px;text-align:center;border-top:1px solid #e5e7eb;">
                        <p style="margin:0;color:#9ca3af;font-size:12px;">
                          © 2025 Poulina Group — Système SSO
                        </p>
                      </td>
                    </tr>
                  </table>
                </td></tr>
              </table>
            </body>
            </html>
            """;

        private static string BuildHtmlCredentials(string nom, string email, string motDePasse) => $"""
            <!DOCTYPE html>
            <html lang="fr">
            <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
            <body style="margin:0;padding:0;background:#f4f6f8;font-family:Arial,sans-serif;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr><td align="center" style="padding:40px 20px;">
                  <table width="600" cellpadding="0" cellspacing="0"
                         style="background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
                    <tr>
                      <td style="background:#1a3a5c;padding:32px 40px;text-align:center;">
                        <h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:700;">Poulina SSO</h1>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:40px;">
                        <h2 style="margin:0 0 8px;color:#111827;font-size:20px;">Bonjour {nom},</h2>
                        <p style="margin:0 0 28px;color:#374151;font-size:15px;line-height:1.6;">
                          Un administrateur a créé votre compte sur la plateforme <strong>Poulina SSO</strong>.<br>
                          Voici vos identifiants de connexion temporaires :
                        </p>

                        <!-- Bloc credentials -->
                        <table cellpadding="0" cellspacing="0" width="100%"
                               style="background:#f0f4ff;border:1px solid #c7d7fd;border-radius:8px;margin-bottom:28px;">
                          <tr>
                            <td style="padding:24px 28px;">
                              <table cellpadding="0" cellspacing="0" width="100%">
                                <tr>
                                  <td style="padding:0 0 14px 0;">
                                    <span style="display:block;font-size:11px;font-weight:700;color:#6b7280;
                                                 text-transform:uppercase;letter-spacing:0.05em;margin-bottom:4px;">
                                      Adresse email
                                    </span>
                                    <span style="font-size:15px;color:#111827;font-weight:600;">
                                      {email}
                                    </span>
                                  </td>
                                </tr>
                                <tr>
                                  <td style="border-top:1px solid #dbeafe;padding:14px 0 0 0;">
                                    <span style="display:block;font-size:11px;font-weight:700;color:#6b7280;
                                                 text-transform:uppercase;letter-spacing:0.05em;margin-bottom:4px;">
                                      Mot de passe temporaire
                                    </span>
                                    <span style="font-size:15px;color:#111827;font-weight:600;
                                                 font-family:Courier New,Courier,monospace;
                                                 background:#ffffff;padding:4px 10px;border-radius:4px;
                                                 border:1px solid #c7d7fd;display:inline-block;">
                                      {motDePasse}
                                    </span>
                                  </td>
                                </tr>
                              </table>
                            </td>
                          </tr>
                        </table>

                        <!-- Avertissement changement de mot de passe -->
                        <table cellpadding="0" cellspacing="0" width="100%"
                               style="background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;margin-bottom:28px;">
                          <tr>
                            <td style="padding:16px 20px;">
                              <p style="margin:0;color:#92400e;font-size:13px;line-height:1.5;">
                                ⚠️ <strong>Important :</strong> Ce mot de passe est temporaire.
                                Vous devrez le modifier dès votre première connexion.
                              </p>
                            </td>
                          </tr>
                        </table>

                        <p style="margin:0 0 8px;color:#6b7280;font-size:13px;line-height:1.5;">
                          Un second email vous sera envoyé avec un lien pour confirmer votre adresse email
                          et activer votre compte.
                        </p>
                        <p style="margin:0;color:#6b7280;font-size:13px;">
                          Si vous n'êtes pas à l'origine de cette demande, contactez votre administrateur.
                        </p>
                      </td>
                    </tr>
                    <tr>
                      <td style="background:#f9fafb;padding:20px 40px;text-align:center;border-top:1px solid #e5e7eb;">
                        <p style="margin:0;color:#9ca3af;font-size:12px;">
                          © 2025 Poulina Group — Système SSO
                        </p>
                      </td>
                    </tr>
                  </table>
                </td></tr>
              </table>
            </body>
            </html>
            """;
    }
}