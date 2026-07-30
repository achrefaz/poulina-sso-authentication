namespace Domain.Commands.Users
{
    public class CreateUserRequest
    {
        public string       Email    { get; set; } = string.Empty;
        public string       Password { get; set; } = string.Empty;
        public string       Nom      { get; set; } = string.Empty;
        public string       Prenom   { get; set; } = string.Empty;
        public List<Guid>?  RoleIds  { get; set; }
    }

    public class ChangePasswordRequest
    {
        public string? AncienMotDePasse       { get; set; }
        public string  NouveauMotDePasse      { get; set; } = string.Empty;
        public string  ConfirmationMotDePasse { get; set; } = string.Empty;
    }

    public class BloquerRequest
    {
        public string Raison { get; set; } = string.Empty;
    }

    public class CreateRoleRequest
    {
        public string Nom         { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }
}