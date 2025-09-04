using Jellyfin.Api.Controllers;
using Jellyfin.Api.Models.StartupDtos;
using JellyGuard.AuthenticationManager;
using JellyGuard.AuthenticationProvider;
using JellyGuard.DataHolders;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JellyGuard.Controllers
{
    public class JGStartupController(
        IUserManager userManager,
        UserAuthenticationManager userAuthenticationManager
    ) : ControllerBase
    {
        /// <summary>
        /// Sets the user name and password.
        /// </summary>
        /// <param name="startupUserDto">The DTO containing username and password.</param>
        /// <response code="204">Updated user name and password.</response>
        /// <returns>
        /// A <see cref="Task" /> that represents the asynchronous update operation.
        /// The task result contains a <see cref="NoContentResult"/> indicating success.
        /// </returns>
        [EndpointOverride<StartupController>(nameof(StartupController.UpdateStartupUser))]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        public async Task<ActionResult> UpdateStartupUser([FromBody] StartupUserDto startupUserDto)
        {
            var user = userManager.Users.First();
            if (string.IsNullOrWhiteSpace(startupUserDto.Password))
            {
                return BadRequest("Password must not be empty");
            }

            if (startupUserDto.Name is not null)
            {
                user.Username = startupUserDto.Name;
            }

            await userManager.UpdateUserAsync(user).ConfigureAwait(false);

            if (!string.IsNullOrEmpty(startupUserDto.Password))
            {
                var passwordProvider = await userAuthenticationManager.ResolveProvider<UsernamePasswordAuthData>().ConfigureAwait(false);

                if (passwordProvider is not IPasswordChangeable passwordChangeable)
                {
                    return BadRequest("You cannot change your password for this authentication provider.");
                }

                await passwordChangeable.ChangePassword(user, startupUserDto.Password).ConfigureAwait(false);
            }

            return NoContent();
        }
    }
}
