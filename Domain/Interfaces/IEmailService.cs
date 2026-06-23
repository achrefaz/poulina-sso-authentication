namespace Domain.Interfaces
{
    public interface IEmailService
    {
        // Email de confirmation de compte 
        Task EnvoyerEmailConfirmationAsync(
            string destinataireEmail,
            string destinataireNom,
            string lienConfirmation,
            CancellationToken ct = default);

        // Renvoi d'un email de confirmation 
        Task RenvoyerEmailConfirmationAsync(
            string destinataireEmail,
            string destinataireNom,
            string lienConfirmation,
            CancellationToken ct = default);

        // Envoi des credentials initiaux (email + mot de passe temporaire) créés par un admin
        Task EnvoyerCredentialsAsync(
            string destinataireEmail,
            string destinataireNom,
            string motDePasseTemporaire,
            CancellationToken ct = default);
    }
}