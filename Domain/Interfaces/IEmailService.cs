namespace Domain.Interfaces
{
    
    public interface IEmailService
    {
        
        Task EnvoyerEmailConfirmationAsync(
            string destinataireEmail,
            string destinataireNom,
            string lienConfirmation,
            CancellationToken ct = default);
        
        // Renvoie un nouvel email de confirmation (si l'ancien token a expiré).
        Task RenvoyerEmailConfirmationAsync(
            string destinataireEmail,
            string destinataireNom,
            string lienConfirmation,
            CancellationToken ct = default);
    }
}