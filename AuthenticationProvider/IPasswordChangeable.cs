using Jellyfin.Data.Entities;

namespace JellyGuard.AuthenticationProvider
{
    /// <summary>
    /// Interface for password changeable authentication providers.
    /// </summary>
    public interface IPasswordChangeable
    {
        /// <summary>
        /// Changes the password for a given user.
        /// </summary>
        /// <param name="user">The user for whom to change the password.</param>
        /// <param name="newPassword">The new password.</param>
        /// <returns>A task.</returns>
        public Task ChangePassword(User user, string newPassword);

        /// <summary>
        /// Resets the password for a given user.
        /// </summary>
        /// <param name="user">The user for whom to reset the password.</param>
        /// <returns>A task.</returns>
        public Task ResetPassword(User user)
        {
            return ChangePassword(user, string.Empty);
        }
    }
}
