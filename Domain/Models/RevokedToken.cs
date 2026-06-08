namespace Domain.Models
{
    public class RevokedToken
    {
        public Guid     Id             { get; set; }
        public string   Jti            { get; set; } = string.Empty;
        public DateTime DateRevocation { get; set; } = DateTime.UtcNow;
        public DateTime DateExpiration { get; set; }
    }
}