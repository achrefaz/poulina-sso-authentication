using System;

namespace Domain.Models
{
    public class RefreshToken
    {
        public Guid Id { get; set; }
        public Guid UtilisateurId { get; set; }
        public Guid ClientId { get; set; }
        public string TokenHash { get; set; } = string.Empty;
        public DateTime DateCreation { get; set; } = DateTime.UtcNow;
        public DateTime DateExpiration { get; set; }
        public DateTime? DateRevoquation { get; set; }
        public string? IpAddress { get; set; }
        public bool EstUtilise { get; set; }
        
        public virtual Utilisateur Utilisateur { get; set; } = null!;
        public virtual ClientApplication Client { get; set; } = null!;
    }
}