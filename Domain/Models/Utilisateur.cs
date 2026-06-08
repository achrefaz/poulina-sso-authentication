using Domain.Models.Enums;
using System;
using System.Collections.Generic;

namespace Domain.Models
{
    public class Utilisateur
    {
        public Guid Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public string MotDePasseHash { get; set; } = string.Empty;
        public string Salt { get; set; } = string.Empty;
        public string Nom { get; set; } = string.Empty;
        public string Prenom { get; set; } = string.Empty;
        public string? Telephone { get; set; }
        public TypeMFA TypeMFA { get; set; } = TypeMFA.AUCUN;
        public string? SecretMFA { get; set; }
        public bool MFAValidee { get; set; }
        public StatutUtilisateur Statut { get; set; } = StatutUtilisateur.ACTIF;
        public DateTime DateCreation { get; set; } = DateTime.UtcNow;
        public DateTime? DateDerniereConnexion { get; set; }
        public DateTime? DateMiseAJour { get; set; }
        public int TentativesConnexionEchouees { get; set; }
        public DateTime? DateVerrouillage { get; set; } 
        public DateTime? DateBlocage { get; set; }        
        public string? RaisonBlocage { get; set; }
        public bool DoitChangerMotDePasse { get; set; }
        
        public virtual ICollection<Session> Sessions { get; set; } = new List<Session>();
        public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
        public virtual ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
        public virtual ICollection<UtilisateurRole> UtilisateurRoles { get; set; } = new List<UtilisateurRole>();
    }
}