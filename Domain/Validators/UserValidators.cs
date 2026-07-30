using Domain.Commands.Users;
using FluentValidation;

namespace Domain.Validators
{
    public class CreateUserRequestValidator : AbstractValidator<CreateUserRequest>
    {
        public CreateUserRequestValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("Email requis.")
                .EmailAddress().WithMessage("Format d'email invalide.")
                .Matches(@"^[^\s@]+@[^\s@]+\.[^\s@]+$").WithMessage("L'email doit inclure un domaine valide (ex: nom@domaine.com).")
                .MaximumLength(256).WithMessage("L'email ne doit pas dépasser 256 caractères.");

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("Mot de passe requis.")
                .MinimumLength(8).WithMessage("Le mot de passe doit contenir au moins 8 caractères.")
                .Matches("[A-Z]").WithMessage("Le mot de passe doit contenir au moins une majuscule.")
                .Matches("[a-z]").WithMessage("Le mot de passe doit contenir au moins une minuscule.")
                .Matches("[0-9]").WithMessage("Le mot de passe doit contenir au moins un chiffre.");

            RuleFor(x => x.Nom)
                .NotEmpty().WithMessage("Le nom est requis.")
                .MaximumLength(100).WithMessage("Le nom ne doit pas dépasser 100 caractères.")
                .Matches(@"^[a-zA-ZÀ-ÿ\s\-']+$").WithMessage("Le nom contient des caractères invalides.");

            RuleFor(x => x.Prenom)
                .NotEmpty().WithMessage("Le prénom est requis.")
                .MaximumLength(100).WithMessage("Le prénom ne doit pas dépasser 100 caractères.")
                .Matches(@"^[a-zA-ZÀ-ÿ\s\-']+$").WithMessage("Le prénom contient des caractères invalides.");
        }
    }

    public class ChangePasswordRequestValidator : AbstractValidator<ChangePasswordRequest>
    {
        public ChangePasswordRequestValidator()
        {
            RuleFor(x => x.NouveauMotDePasse)
                .NotEmpty().WithMessage("Le nouveau mot de passe est requis.")
                .MinimumLength(8).WithMessage("Le mot de passe doit contenir au moins 8 caractères.")
                .Matches("[A-Z]").WithMessage("Le mot de passe doit contenir au moins une majuscule.")
                .Matches("[a-z]").WithMessage("Le mot de passe doit contenir au moins une minuscule.")
                .Matches("[0-9]").WithMessage("Le mot de passe doit contenir au moins un chiffre.");

            RuleFor(x => x.ConfirmationMotDePasse)
                .Equal(x => x.NouveauMotDePasse).WithMessage("Les mots de passe ne correspondent pas.");
        }
    }
}