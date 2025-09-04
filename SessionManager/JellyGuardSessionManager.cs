using Jellyfin.Data.Entities;
using JellyGuard.Proxies;
using MediaBrowser.Controller.Session;

namespace JellyGuard.JGSessionManager
{
    public class JellyGuardSessionManager
    {
        /// <summary>
        /// Creates a new session for a given user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="deviceId">The device id.</param>
        /// <param name="appName">Type of the client.</param>
        /// <param name="appVersion">The app version.</param>
        /// <param name="deviceName">Name of the device.</param>
        /// <param name="authenticationProviderId">The authentication provider used to authenticate this user.</param>
        /// <param name="remoteEndpoint">The remote endpoint.</param>
        /// <returns><see cref="Task"/>&lt;<see cref="global::MediaBrowser.Controller.Session.Session"/>&gt;.</returns>
        public Task<MediaBrowser.Controller.Authentication.AuthenticationResult> CreateSession(User user, string deviceId, string appName, string appVersion, string deviceName, string authenticationProviderId, string remoteEndpoint)
        {
            return SessionManagerProxy.SessionManager.AuthenticateDirect(new AuthenticationRequest
            {
                App = appName,
                AppVersion = appVersion,
                DeviceId = deviceId,
                DeviceName = deviceName,
                RemoteEndPoint = remoteEndpoint,
                Username = user.Username
            });
        }
    }
}
