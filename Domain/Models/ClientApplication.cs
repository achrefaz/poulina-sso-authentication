namespace Domain.Models
{
    public class ClientApplication
    {
        public Guid     Id                        { get; set; }
        public string   Nom                       { get; set; } = string.Empty;
        public string   Description               { get; set; } = string.Empty;
        public string   ClientId                  { get; set; } = string.Empty;
        public string   ClientSecretHash          { get; set; } = string.Empty;
        public string   AllowedRoles              { get; set; } = string.Empty;
        public bool     Actif                     { get; set; } = true;
        public DateTime DateCreation              { get; set; } = DateTime.UtcNow;
        public DateTime? DateRotationSecret       { get; set; }
        public int      TokenLifetimeSecondes     { get; set; } = 900;
        public int      RefreshTokenLifetimeJours { get; set; } = 7;

        public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }
}