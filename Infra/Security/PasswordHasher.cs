using Domain.Interfaces;

namespace Infra.Security
{
    public class PasswordHasher : IPasswordHasher
    {
        private const int WorkFactor = 12;

        /// <summary>
        /// Hash un mot de passe avec BCrypt (génère son propre salt automatiquement)
        /// </summary>
        public string Hash(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);
        }

        /// <summary>
        /// Vérifie un mot de passe contre son hash BCrypt
        /// </summary>
        public bool Verify(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
    }
}