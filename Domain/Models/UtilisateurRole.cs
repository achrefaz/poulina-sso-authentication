using System;

namespace Domain.Models
{
    public class UtilisateurRole
    {
        public Guid UtilisateurId { get; set; }
        public Guid RoleId { get; set; }
        public DateTime DateAssignation { get; set; } = DateTime.UtcNow;
        public Guid AssignePar { get; set; } 
        public bool Actif { get; set; } = true;
        public DateTime? DateRevocation { get; set; }
        public Guid? RevoquePar { get; set; } 
        
        public virtual Utilisateur Utilisateur { get; set; } = null!;
        public virtual Role Role { get; set; } = null!;
    }
}