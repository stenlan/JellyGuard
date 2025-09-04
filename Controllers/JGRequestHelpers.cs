using Jellyfin.Api.Constants;
using Jellyfin.Api.Extensions;
using Jellyfin.Data.Entities;
using Jellyfin.Extensions;
using MediaBrowser.Controller.Net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JellyGuard.Controllers
{
    public class JGRequestHelpers
    {
        private static string? GetClaimValue(in ClaimsPrincipal user, string name)
        => user.Claims.FirstOrDefault(claim => claim.Type.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;

        /// <summary>
        /// Checks if the user can access a user.
        /// </summary>
        /// <param name="claimsPrincipal">The <see cref="ClaimsPrincipal"/> for the current request.</param>
        /// <param name="userId">The user id.</param>
        /// <returns>A <see cref="bool"/> whether the user can access the user.</returns>
        public static Guid GetUserId(ClaimsPrincipal claimsPrincipal, Guid? userId)
        {
            var claimValue = GetClaimValue(claimsPrincipal, InternalClaimTypes.UserId);

            var authenticatedUserId = string.IsNullOrEmpty(claimValue)
                ? default
                : Guid.Parse(claimValue);

            // UserId not provided, fall back to authenticated user id.
            if (userId.IsNullOrEmpty())
            {
                return authenticatedUserId;
            }

            // User must be administrator to access another user.
            var isAdministrator = claimsPrincipal.IsInRole(UserRoles.Administrator);
            if (!userId.Value.Equals(authenticatedUserId) && !isAdministrator)
            {
                throw new SecurityException("Forbidden");
            }

            return userId.Value;
        }

        /// <summary>
        /// Checks if the user can update an entry.
        /// </summary>
        /// <param name="claimsPrincipal">The <see cref="ClaimsPrincipal"/> for the current request.</param>
        /// <param name="user">The user id.</param>
        /// <param name="restrictUserPreferences">Whether to restrict the user preferences.</param>
        /// <returns>A <see cref="bool"/> whether the user can update the entry.</returns>
        internal static bool AssertCanUpdateUser(ClaimsPrincipal claimsPrincipal, User user, bool restrictUserPreferences)
        {
            var authenticatedUserId = claimsPrincipal.GetUserId();
            var isAdministrator = claimsPrincipal.IsInRole(UserRoles.Administrator);

            // If they're going to update the record of another user, they must be an administrator
            if (!user.Id.Equals(authenticatedUserId) && !isAdministrator)
            {
                return false;
            }

            // TODO the EnableUserPreferenceAccess policy does not seem to be used elsewhere
            if (!restrictUserPreferences || isAdministrator)
            {
                return true;
            }

            return user.EnableUserPreferenceAccess;
        }
    }
}
