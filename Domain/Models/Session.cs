using System;
using Domain.Models.Enums;

namespace Domain.Models
{
    public class Session
    {
        public Guid Id { get; set; }
        public Guid UtilisateurId { get; set; }
        public string SessionId { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;
        public DateTime DateCreation { get; set; } = DateTime.UtcNow;
        public DateTime DateDerniereActivite { get; set; } = DateTime.UtcNow;
        public DateTime? DateExpiration { get; set; }
        public StatutSession Statut { get; set; } = StatutSession.ACTIVE;
        public string? DeviceInfo { get; set; }
        
        public virtual Utilisateur Utilisateur { get; set; } = null!;
    }
}