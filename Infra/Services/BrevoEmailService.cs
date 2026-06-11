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
                      <td style="background:#1a56db;padding:32px 40px;text-align:center;">
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
                                 style="display:inline-block;background:#1a56db;color:#ffffff;
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
                          <a href="{lien}" style="color:#1a56db;word-break:break-all;">{lien}</a>
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
                      <td style="background:#1a56db;padding:32px 40px;text-align:center;">
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
                                 style="display:inline-block;background:#1a56db;color:#ffffff;
                                        text-decoration:none;padding:14px 32px;border-radius:6px;
                                        font-size:15px;font-weight:600;">
                                Confirmer mon email
                              </a>
                            </td>
                          </tr>
                        </table>
                        <p style="margin:0;color:#6b7280;font-size:13px;">
                          <a href="{lien}" style="color:#1a56db;word-break:break-all;">{lien}</a>
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