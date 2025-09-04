using Jellyfin.Api.Controllers;
using JellyGuard.AuthenticationManager;
using MediaBrowser.Common.Api;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Dto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JellyGuard.Controllers
{
    public class JGSessionController (
        UserAuthenticationManager userAuthenticationManager
    ) : ControllerBase
    {
        /// <summary>
        /// Get all auth providers.
        /// </summary>
        /// <response code="200">Auth providers retrieved.</response>
        /// <returns>An <see cref="IEnumerable{NameIdPair}"/> with the auth providers.</returns>
        [EndpointOverride<SessionController>(nameof(SessionController.GetAuthProviders))]
        [Authorize(Policy = Policies.RequiresElevation)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<IEnumerable<NameIdPair>>> GetAuthProviders()
        {
            return Ok(await userAuthenticationManager.GetAuthenticationProviders());
        }
    }
}
