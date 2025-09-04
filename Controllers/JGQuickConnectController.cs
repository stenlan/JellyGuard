using Emby.Server.Implementations.QuickConnect;
using ICU4N.Logging;
using Jellyfin.Api.Controllers;
using Jellyfin.Api.Helpers;
using Jellyfin.Api.Models.UserDtos;
using JellyGuard.AuthenticationManager;
using JellyGuard.AuthenticationProvider;
using JellyGuard.DataHolders;
using JellyGuard.JGSessionManager;
using MediaBrowser.Common.Extensions;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.QuickConnect;
using MediaBrowser.Model.QuickConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JellyGuard.Controllers
{
    public class JGQuickConnectController(
        IUserManager userManager,
        IAuthorizationContext authContext,
        ILogger<JGUserController> logger,
        IEventManager eventManager,
        UserAuthenticationManager userAuthenticationManager,
        JellyGuardSessionManager sessionManager) : ControllerBase
    {
        private Task<QuickConnectAuthenticationProvider?> GetQuickConnectProvider()
        {
            return userAuthenticationManager.ResolveConcrete<QuickConnectAuthenticationProvider>();
        }

        /// <summary>
        /// Gets the current quick connect state.
        /// </summary>
        /// <response code="200">Quick connect state returned.</response>
        /// <returns>Whether Quick Connect is enabled on the server or not.</returns>
        [EndpointOverride<QuickConnectController>(nameof(QuickConnectController.GetQuickConnectEnabled))]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<bool>> GetQuickConnectEnabled()
        {
            return await GetQuickConnectProvider().ConfigureAwait(false) != null;
        }

        /// <summary>
        /// Initiate a new quick connect request.
        /// </summary>
        /// <response code="200">Quick connect request successfully created.</response>
        /// <response code="401">Quick connect is not active on this server.</response>
        /// <returns>A <see cref="QuickConnectResult"/> with a secret and code for future use or an error message.</returns>
        [EndpointOverride<QuickConnectController>(nameof(QuickConnectController.InitiateQuickConnect))]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<JGQuickConnectResult>> InitiateQuickConnect()
        {
            var quickConnectProvider = await GetQuickConnectProvider().ConfigureAwait(false);

            if (quickConnectProvider is null)
            {
                return Unauthorized("Quick connect is disabled");
            }

            var auth = await authContext.GetAuthorizationInfo(Request).ConfigureAwait(false);
            ArgumentException.ThrowIfNullOrEmpty(auth.DeviceId);
            ArgumentException.ThrowIfNullOrEmpty(auth.Device);
            ArgumentException.ThrowIfNullOrEmpty(auth.Client);
            ArgumentException.ThrowIfNullOrEmpty(auth.Version);

            throw new NotImplementedException("This still needs to be fixed.");

            /*var res = new JGQuickConnectResult(
                TODO,
                TODO,
                    DateTime.UtcNow,
                    auth.DeviceId,
                    auth.Device,
                    auth.Client,
                    auth.Version);

            var monitorData = await quickConnectProvider.Initiate(res).ConfigureAwait(false);

            res.Secret = monitorData.MonitorKey;
            res.Code = monitorData.UpdateKey;

            return res;*/
        }

        /// <summary>
        /// Old version of <see cref="InitiateQuickConnect" /> using a GET method.
        /// Still available to avoid breaking compatibility.
        /// </summary>
        /// <returns>The result of <see cref="InitiateQuickConnect" />.</returns>
        [Obsolete("Use POST request instead")]
        [EndpointOverride<QuickConnectController>(nameof(QuickConnectController.InitiateQuickConnectLegacy))]
        [ApiExplorerSettings(IgnoreApi = true)]
        public Task<ActionResult<JGQuickConnectResult>> InitiateQuickConnectLegacy() => InitiateQuickConnect();

        /// <summary>
        /// Attempts to retrieve authentication information.
        /// </summary>
        /// <param name="secret">Secret previously returned from the Initiate endpoint.</param>
        /// <response code="200">Quick connect result returned.</response>
        /// <response code="404">Unknown quick connect secret.</response>
        /// <returns>An updated <see cref="QuickConnectResult"/>.</returns>
        [EndpointOverride<QuickConnectController>(nameof(QuickConnectController.GetQuickConnectState))]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<JGQuickConnectResult>> GetQuickConnectState([FromQuery, Required] string secret, [FromQuery] string? waitForUpdate = null)
        {
            ArgumentException.ThrowIfNullOrEmpty(secret);
            var quickConnectProvider = await GetQuickConnectProvider().ConfigureAwait(false);

            if (quickConnectProvider is null)
            {
                return Unauthorized("Quick connect is disabled");
            }

            var data = await quickConnectProvider.GetData(secret, waitForUpdate == "1").ConfigureAwait(false);

            if (data is null)
            {
                return NotFound("Unknown secret");
            }

            return data;
        }

        /// <summary>
        /// Authorizes a pending quick connect request.
        /// </summary>
        /// <param name="code">Quick connect code to authorize.</param>
        /// <param name="userId">The user the authorize. Access to the requested user is required.</param>
        /// <response code="200">Quick connect result authorized successfully.</response>
        /// <response code="403">Unknown user id.</response>
        /// <returns>Boolean indicating if the authorization was successful.</returns>
        [EndpointOverride<QuickConnectController>(nameof(QuickConnectController.AuthorizeQuickConnect))]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<ActionResult<bool>> AuthorizeQuickConnect([FromQuery, Required] string code, [FromQuery] Guid? userId = null)
        {
            userId = JGRequestHelpers.GetUserId(User, userId);

            ArgumentNullException.ThrowIfNullOrEmpty(code);
            if (!userId.HasValue)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            var quickConnectProvider = await GetQuickConnectProvider().ConfigureAwait(false);

            if (quickConnectProvider is null)
            {
                return Unauthorized("Quick connect is disabled");
            }

            try
            {
                var success = await quickConnectProvider.Authorize(code, userId.Value).ConfigureAwait(false);
                if (success)
                {
                    logger.LogDebug("Authorizing device with code {Code} to login as user {UserId}", code, userId);
                }

                return success;
            }
            catch (AuthenticationException)
            {
                return Unauthorized("Quick connect is disabled");
            }
        }

        /// <summary>
        /// Authenticates a user with quick connect.
        /// </summary>
        /// <param name="request">The <see cref="QuickConnectDto"/> request.</param>
        /// <response code="200">User authenticated.</response>
        /// <response code="400">Missing token.</response>
        /// <returns>A <see cref="Task"/> containing an <see cref="AuthenticationRequest"/> with information about the new session.</returns>
        [EndpointOverride<UserController>(nameof(UserController.AuthenticateWithQuickConnect))]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<MediaBrowser.Controller.Authentication.AuthenticationResult>> AuthenticateWithQuickConnect([FromBody, Required] QuickConnectDto request)
        {
            var remoteEndpoint = HttpContext.GetNormalizedRemoteIP().ToString();

            try
            {
                var (provider, result) = await userAuthenticationManager.Authenticate(new ExternallyTriggeredAuthenticationData(request.Secret), remoteEndpoint, "QuickConnect").ConfigureAwait(false);

                if (provider is not IKeyedMonitorable<QuickConnectResult> monitorable)
                {
                    return Unauthorized("Quick connect is disabled");
                }

                if (!result.Authenticated)
                {
                    return Unauthorized("Unknown secret");
                }

                var auth = await authContext.GetAuthorizationInfo(Request).ConfigureAwait(false);

                return await sessionManager.CreateSession(result.User, auth.DeviceId, auth.Client, auth.Version, auth.Device, provider.GetType().FullName, remoteEndpoint).ConfigureAwait(false);
            }
            catch (SecurityException e)
            {
                // rethrow adding IP address to message
                throw new SecurityException($"[{remoteEndpoint}] {e.Message}", e);
            }
        }
    }
}
