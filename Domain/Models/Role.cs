using System;
using System.Collections.Generic;

namespace Domain.Models
{
    public class Role
    {
        public Guid Id { get; set; }
        public string Nom { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool Actif { get; set; } = true;
        public DateTime DateCreation { get; set; } = DateTime.UtcNow;
        
        public virtual ICollection<UtilisateurRole> UtilisateurRoles { get; set; } = new List<UtilisateurRole>();
    }
}