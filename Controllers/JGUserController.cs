using Emby.Server.Implementations.Session;
using Jellyfin.Api.Constants;
using Jellyfin.Api.Controllers;
using Jellyfin.Api.Extensions;
using Jellyfin.Api.Helpers;
using Jellyfin.Api.Models.UserDtos;
using JellyGuard.AuthenticationManager;
using JellyGuard.AuthenticationProvider;
using JellyGuard.DataHolders;
using JellyGuard.JGSessionManager;
using MediaBrowser.Common.Api;
using MediaBrowser.Common.Extensions;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Events.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Dto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations;

namespace JellyGuard.Controllers
{
    public class JGUserController(
        IUserManager userManager,
        IAuthorizationContext authContext,
        ILogger<JGUserController> logger,
        IEventManager eventManager,
        UserAuthenticationManager userAuthenticationManager,
        JellyGuardSessionManager jgSessionManager,
        ISessionManager sessionManager) : ControllerBase
    {
        /// <summary>
        /// Authenticates a user.
        /// </summary>
        /// <param name="userId">The user id.</param>
        /// <param name="pw">The password as plain text.</param>
        /// <response code="200">User authenticated.</response>
        /// <response code="403">Sha1-hashed password only is not allowed.</response>
        /// <response code="404">User not found.</response>
        /// <returns>A <see cref="Task"/> containing an <see cref="AuthenticationResult"/>.</returns>
        [EndpointOverride<UserController>(nameof(UserController.AuthenticateUser))]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ApiExplorerSettings(IgnoreApi = true)]
        [Obsolete("Authenticate with username instead")]
        public async Task<ActionResult<MediaBrowser.Controller.Authentication.AuthenticationResult>> AuthenticateUser(
            [FromRoute, Required] Guid userId,
            [FromQuery, Required] string pw)
        {
            var user = userManager.GetUserById(userId);

            if (user is null)
            {
                return NotFound("User not found");
            }

            JGAuthenticateUserByName request = new JGAuthenticateUserByName
            {
                Username = user.Username,
                Pw = pw
            };
            return await AuthenticateUserByName(request).ConfigureAwait(false);
        }

        /**
         *  Authentication flow should keep verification and logging elements from (not strictly ordered):
         *  
         *  The endpoint itself
         *  (SessionManager#AuthenticateNewSession)
         *  SessionManager#AuthenticateNewSessionInternal
         *  UserManager#AuthenticateUser
         *  (UserManager#AuthenticateLocalUser)
         *  (UserManager#AuthenticateWithProvider)
         *  DefaultAuthenticationProvider#Authenticate (or other IAuthenticationProvider/IRequiresResolvedUser # Authenticate)
         *  SessionManager#GetAuthorizationToken
         *  SessionManager#LogSessionActivity
         */

        /// <summary>
        /// Authenticates a user by name.
        /// </summary>
        /// <param name="request">The <see cref="AuthenticateUserByName"/> request.</param>
        /// <response code="200">User authenticated.</response>
        /// <returns>A <see cref="Task"/> containing an <see cref="AuthenticationRequest"/> with information about the new session.</returns>
        [EndpointOverride<UserController>(nameof(UserController.AuthenticateUserByName))]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<MediaBrowser.Controller.Authentication.AuthenticationResult>> AuthenticateUserByName([FromBody, Required] JGAuthenticateUserByName request)
        {
            var auth = await authContext.GetAuthorizationInfo(Request).ConfigureAwait(false);
            var remoteEndpoint = HttpContext.GetNormalizedRemoteIP().ToString();
            if (string.IsNullOrWhiteSpace(request.Username))
            {
                logger.LogInformation("Authentication request without username has been denied (IP: {IP}).", remoteEndpoint);
                throw new ArgumentNullException("request.Username");
            }

            var mfaAwareClient = HttpContext.Request.Headers.ContainsKey("X-MFA-Aware");

            try
            {
                var (provider, result) = await userAuthenticationManager.Authenticate(new UsernamePasswordAuthData(request.Username, request.Pw, request.TOTP), remoteEndpoint).ConfigureAwait(false);

                if (!result.Authenticated)
                {
                    if (result.ErrorCode == 1300) // arbitrarily chosen error code used to signal that the username and password were correct, but TOTP was not
                    {
                        throw new AuthenticationException("Incorrect or missing TOTP code.");
                    }

                    // MFA setup required. If client is MFA aware, send them the setup URI.
                    // If not, simply send an error message to avoid unnecessary leaking of secret, in case of
                    // clients that might display the raw error message on a screen, for example.
                    else if (result.ErrorCode == 1301)
                    {
                        throw new AuthenticationException((mfaAwareClient && result.ErrorData != null) ? result.ErrorData : "MFA setup required.");
                    }

                    await eventManager.PublishAsync(new AuthenticationRequestEventArgs(new AuthenticationRequest
                    {
                        App = auth.Client,
                        AppVersion = auth.Version,
                        DeviceId = auth.DeviceId,
                        DeviceName = auth.Device,
                        Password = request.Pw,
                        RemoteEndPoint = remoteEndpoint,
                        Username = request.Username
                    })).ConfigureAwait(false);
                    throw new AuthenticationException("Invalid username or password entered.");
                }

                return await jgSessionManager.CreateSession(
                    result.User,
                    auth.DeviceId,
                    auth.Client,
                    auth.Version,
                    auth.Device,
                    provider.GetType().FullName!,
                    remoteEndpoint).ConfigureAwait(false);
            }
            catch (SecurityException e)
            {
                // rethrow adding IP address to message
                throw new SecurityException($"[{remoteEndpoint}] {e.Message}", e);
            }
        }

        /// <summary>
        /// Enables or disables MFA for a user.
        /// </summary>
        /// <param name="userId">The user id.</param>
        /// <param name="request">The <see cref="SetUserMFADto"/> containing a boolean that indicates whether you want to disable or enable MFA for this user.</param>
        /// <response code="200">Success.</response>
        /// <response code="404">User not found.</response>
        /// <returns>A <see cref="OkResult"/> indicating success, a <see cref="NotFoundResult"/> if the user was not found,
        /// or a <see cref="BadRequestResult"/> if the default username/password authentication provider is not enabled and thus MFA
        /// cannot be enabled.</returns>
        [HttpPost("Users/MFA/{userId}")]
        [Authorize(Policy = Policies.RequiresElevation)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult> SetMFA([FromRoute, Required] Guid userId, [FromBody, Required] SetUserMFADto request)
        {
            var user = userManager.GetUserById(userId);
            if (user is null)
            {
                return NotFound();
            }

            var defaultProvider = await userAuthenticationManager.ResolveConcrete<JGDefaultAuthenticationProvider>().ConfigureAwait(false);

            if (defaultProvider is null)
            {
                return BadRequest("Default authentication provider is not enabled.");
            }

            await defaultProvider.SetMFA(user, request.Enable).ConfigureAwait(false);

            return Ok();
        }

        /// <summary>
        /// Updates a user's password.
        /// </summary>
        /// <param name="userId">The user id.</param>
        /// <param name="request">The <see cref="UpdateUserPassword"/> request.</param>
        /// <response code="204">Password successfully reset.</response>
        /// <response code="403">User is not allowed to update the password.</response>
        /// <response code="404">User not found.</response>
        /// <returns>A <see cref="NoContentResult"/> indicating success or a <see cref="ForbidResult"/> or a <see cref="NotFoundResult"/> on failure.</returns>
        [EndpointOverride<UserController>(nameof(UserController.UpdateUserPassword))]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult> UpdateUserPassword(
            [FromQuery] Guid? userId,
            [FromBody, Required] JGUpdateUserPassword request)
        {
            var requestUserId = userId ?? User.GetUserId();
            var user = userManager.GetUserById(requestUserId);
            if (user is null)
            {
                return NotFound();
            }

            if (!JGRequestHelpers.AssertCanUpdateUser(User, user, true))
            {
                return StatusCode(StatusCodes.Status403Forbidden, "User is not allowed to update the password.");
            }

            var passwordProvider = await userAuthenticationManager.ResolveProvider<UsernamePasswordAuthData>().ConfigureAwait(false);

            if (passwordProvider is not IPasswordChangeable passwordChangeable)
            {
                return StatusCode(StatusCodes.Status403Forbidden, "You cannot change your password for this authentication provider.");
            }

            if (request.ResetPassword)
            {
                await passwordChangeable.ResetPassword(user).ConfigureAwait(false);
            }
            else
            {
                if (!User.IsInRole(UserRoles.Administrator) || (userId.HasValue && User.GetUserId().Equals(userId.Value)))
                {
                    var authenticationRes = await passwordProvider.Authenticate(new UsernamePasswordAuthData(user.Username, request.CurrentPw ?? string.Empty, request.TOTP)).ConfigureAwait(false);

                    if (!authenticationRes.Authenticated)
                    {
                        if (authenticationRes.ErrorCode == 1300) // arbitrarily chosen error code used to signal that the username and password were correct, but TOTP was not
                        {
                            return StatusCode(StatusCodes.Status403Forbidden, "A TOTP code is required.");
                        }

                        return StatusCode(StatusCodes.Status403Forbidden, "Invalid user or password entered.");
                    }
                }

                await passwordChangeable.ChangePassword(user, request.NewPw ?? string.Empty).ConfigureAwait(false);

                var currentToken = User.GetToken();
                await sessionManager.RevokeUserTokens(user.Id, currentToken).ConfigureAwait(false);
            }

            return NoContent();
        }

        /// <summary>
        /// Updates a user's password.
        /// </summary>
        /// <param name="userId">The user id.</param>
        /// <param name="request">The <see cref="UpdateUserPassword"/> request.</param>
        /// <response code="204">Password successfully reset.</response>
        /// <response code="403">User is not allowed to update the password.</response>
        /// <response code="404">User not found.</response>
        /// <returns>A <see cref="NoContentResult"/> indicating success or a <see cref="ForbidResult"/> or a <see cref="NotFoundResult"/> on failure.</returns>
        [EndpointOverride<UserController>(nameof(UserController.UpdateUserPasswordLegacy))]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [Obsolete("Kept for backwards compatibility")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public Task<ActionResult> UpdateUserPasswordLegacy(
            [FromRoute, Required] Guid userId,
            [FromBody, Required] JGUpdateUserPassword request)
            => UpdateUserPassword(userId, request);

        /// <summary>
        /// Creates a user.
        /// </summary>
        /// <param name="request">The create user by name request body.</param>
        /// <response code="200">User created.</response>
        /// <returns>An <see cref="UserDto"/> of the new user.</returns>
        [EndpointOverride<UserController>(nameof(UserController.CreateUserByName))]
        [Authorize(Policy = Policies.RequiresElevation)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<UserDto>> CreateUserByName([FromBody, Required] CreateUserByName request)
        {
            var newUser = await userManager.CreateUserAsync(request.Name).ConfigureAwait(false);

            // no need to authenticate password for new user
            if (request.Password is not null)
            {
                var passwordProvider = await userAuthenticationManager.ResolveProvider<UsernamePasswordAuthData>().ConfigureAwait(false);

                if (passwordProvider is not IPasswordChangeable passwordChangeable)
                {
                    await userManager.DeleteUserAsync(newUser.Id).ConfigureAwait(false);
                    throw new InvalidOperationException("You cannot create a password for this authentication provider.");
                }

                await passwordChangeable.ChangePassword(newUser, request.Password).ConfigureAwait(false);
            }

            var result = userManager.GetUserDto(newUser, HttpContext.GetNormalizedRemoteIP().ToString());

            return result;
        }
    }
}
