using System;

namespace Domain.Models
{
    public class AuthorizationCode
    {
        public Guid Id { get; set; }
        public string CodeHash { get; set; } = string.Empty;
        public Guid UtilisateurId { get; set; }
        public Guid ClientId { get; set; }
        public DateTime DateCreation { get; set; } = DateTime.UtcNow;
        public DateTime DateExpiration { get; set; }
        public bool EstUtilise { get; set; }
        public string? CodeChallenge { get; set; }
        public string? CodeChallengeMethod { get; set; }
        public string Scopes { get; set; } = string.Empty;
        
        public virtual Utilisateur Utilisateur { get; set; } = null!;
        public virtual ClientApplication Client { get; set; } = null!;
    }
}