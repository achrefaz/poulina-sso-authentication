using System;

namespace Domain.Models
{
    public class AuditLog
    {
        public Guid Id { get; set; }
        public Guid? UtilisateurId { get; set; }
        public string Action { get; set; } = string.Empty;
        public string Categorie { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;
        public DateTime DateHeure { get; set; } = DateTime.UtcNow;
        public bool Succes { get; set; }
        public string? MessageErreur { get; set; }
        public string? DetailsJson { get; set; }

        // Navigation property
        public virtual Utilisateur? Utilisateur { get; set; }
    }
}