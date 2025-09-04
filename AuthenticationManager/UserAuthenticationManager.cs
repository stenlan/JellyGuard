using Jellyfin.Data.Entities;
using Jellyfin.Data.Enums;
using Jellyfin.Data.Events.Users;
using Jellyfin.Server.Implementations;
using JellyGuard.AuthenticationProvider;
using JellyGuard.Database;
using JellyGuard.Database.Models;
using JellyGuard.DataHolders;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Model.Dto;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace JellyGuard.AuthenticationManager
{
    /// <summary>
    /// Handles authentication of users. If you simply want to add a new authentication provider,
    /// you probably want to implement <see cref="IAuthenticationProvider"/> or one of the helper
    /// classes <see cref="AbstractAuthenticationProvider{TResponseC2S, TGlobalData, TUserData}"/> or its inheritors./>.
    /// </summary>
    public class UserAuthenticationManager(
        IDbContextFactory<JellyfinDbContext> contextFactory,
        IUserManager userManager,
        ILogger<UserAuthenticationManager> logger,
        INetworkManager networkManager,
        IEventManager eventManager
        )
    {
        // Dictionary<TResponseC2S, Dictionary<AuthenticationType, IAuthenticationProvider<TResponseC2S>>>
        private readonly ConcurrentDictionary<Type, PayloadHandlerInfo> _providerMap = new();
        private readonly ConcurrentDictionary<Type, object> _providersByImpType = new();

        /// <summary>
        /// Registers a provider.
        /// </summary>
        /// <param name="providers">The providers.</param>
        /// <returns>A void Task.</returns>
        public async Task RegisterProviders(IEnumerable<object> providers)
        {
            var authenticationProviderTypeName = typeof(IAuthenticationProvider<>).Name;
            foreach (var provider in providers)
            {
                var providerType = provider.GetType();
                var interfaceType = providerType.GetInterface(authenticationProviderTypeName)
                    ?? throw new InvalidOperationException("[JellyGuard] Attempted to register an authentication provider that does not inherit from IAuthenticationProvider<T>.");

                var payloadHandlerInfo = _providerMap.GetOrAdd(interfaceType.GetGenericArguments()[0], new PayloadHandlerInfo() { All = new(), ByTypeFilter = new() });
                payloadHandlerInfo.All.Push(provider);

                string? authenticationType = (string?)interfaceType.GetProperty(nameof(JGDefaultAuthenticationProvider.AuthenticationType))!.GetValue(provider);
                if (authenticationType != null)
                {
                    payloadHandlerInfo.ByTypeFilter[authenticationType] = provider;
                }

                _providersByImpType[providerType] = provider;

                var dbContext = await contextFactory.CreateDbContextAsync().ConfigureAwait(false);
                var typeName = providerType.FullName!;
                var entryExists = false;
                await using (dbContext)
                {
                    var authProviderDatas = dbContext.AuthenticationProviderDatas();
                    entryExists = authProviderDatas.Any(provider => provider.AuthenticationProviderId == typeName);
                    if (!entryExists)
                    {
                        authProviderDatas.Add(new AuthenticationProviderData() { AuthenticationProviderId = typeName, IsEnabled = true });
                        await dbContext.SaveChangesAsync().ConfigureAwait(false);
                    }
                }

                logger.LogInformation("Registered authentiation provider {1}", (string)providerType.GetProperty(nameof(JGDefaultAuthenticationProvider.Name))!.GetValue(provider)!);
            }
        }

        /// <summary>
        /// Performs an authentication attempt, with optional payload data. Will use the last registered authentication provider that
        /// matches the <typeparamref name="TResponseC2S"/> and optional <paramref name="authenticationTypeFilter"/> filter.
        /// </summary>
        /// <param name="authenticationData">Authentication data.</param>
        /// <param name="remoteEndpoint">The remote endpoint, if known.</param>
        /// <param name="authenticationTypeFilter">An optional authentication type filter. Mainly useful when the payload data type alone is not enough to resolve an authentication provider, like with externally triggered authentication providers that don't take payload data at all.</param>
        /// <typeparam name="TResponseC2S">The payload data.</typeparam>
        /// <returns>A tuple containing the <see cref="IAuthenticationProvider{TResponseC2S}"/> that responded, and an optional User (if the authentication was successful).
        /// </returns>
        /// <exception cref="NotImplementedException">When there is no registered authentication provider for the given TResponseC2S.</exception>
        public async Task<(IAuthenticationProvider<TResponseC2S> Provider, AuthenticationResult Result)> Authenticate<TResponseC2S>(TResponseC2S authenticationData, string? remoteEndpoint, string? authenticationTypeFilter = null)
            where TResponseC2S : struct
        {
            var provider = await ResolveProvider<TResponseC2S>().ConfigureAwait(false)
                ?? throw new NotImplementedException("Attempted authentication using '" + typeof(TResponseC2S).Name + "', but found no registered provider that can handle it.");

            var authenticationResult = await provider.Authenticate(authenticationData).ConfigureAwait(false);

            if (authenticationResult.Authenticated)
            {
                var user = authenticationResult.User;
                if (user.HasPermission(PermissionKind.IsDisabled))
                {
                    logger.LogInformation(
                        "Authentication request for {UserName} has been denied because this account is currently disabled (IP: {IP}).",
                        user.Username,
                        remoteEndpoint);
                    throw new SecurityException(
                        $"The {user.Username} account is currently disabled. Please consult with your administrator.");
                }

                if (!user.HasPermission(PermissionKind.EnableRemoteAccess) &&
                    !(remoteEndpoint != null && networkManager.IsInLocalNetwork(remoteEndpoint)))
                {
                    logger.LogInformation(
                        "Authentication request for {UserName} forbidden: remote access disabled and user not in local network (IP: {IP}).",
                        user.Username,
                        remoteEndpoint);
                    throw new SecurityException("Forbidden.");
                }

                if (!user.IsParentalScheduleAllowed())
                {
                    logger.LogInformation(
                        "Authentication request for {UserName} is not allowed at this time due parental restrictions (IP: {IP}).",
                        user.Username,
                        remoteEndpoint);
                    throw new SecurityException("User is not allowed access at this time.");
                }

                user.LastActivityDate = user.LastLoginDate = DateTime.UtcNow;
                user.InvalidLoginAttemptCount = 0;
                await userManager.UpdateUserAsync(user).ConfigureAwait(false);
                logger.LogInformation("Authentication request for {UserName} has succeeded.", user.Username);
            }
            else if (authenticationResult.User is not null)
            {
                await IncrementInvalidLoginAttemptCount(authenticationResult.User).ConfigureAwait(false);
                logger.LogInformation(
                    "Authentication request for user {UserName} has been denied (IP: {IP}).",
                    authenticationResult.User.Username,
                    remoteEndpoint);
            }
            else
            {
                logger.LogInformation(
                    "Authentication request with data {Data} has been denied (IP: {IP}).",
                    authenticationData,
                    remoteEndpoint);
            }

            return (provider, authenticationResult);
        }

        private async Task IncrementInvalidLoginAttemptCount(User user)
        {
            user.InvalidLoginAttemptCount++;
            int? maxInvalidLogins = user.LoginAttemptsBeforeLockout;
            if (maxInvalidLogins.HasValue && user.InvalidLoginAttemptCount >= maxInvalidLogins)
            {
                user.SetPermission(PermissionKind.IsDisabled, true);
                await eventManager.PublishAsync(new UserLockedOutEventArgs(user)).ConfigureAwait(false);
                logger.LogWarning(
                    "Disabling user {Username} due to {Attempts} unsuccessful login attempts.",
                    user.Username,
                    user.InvalidLoginAttemptCount);
            }

            await userManager.UpdateUserAsync(user).ConfigureAwait(false);
        }

        /// <summary>
        /// Finds an _enabled_ authentication provider that matches the <typeparamref name="TResponseC2S"/> and optional <paramref name="authenticationTypeFilter"/> filter.
        /// </summary>
        /// <param name="authenticationTypeFilter">An optional authentication type filter. Mainly useful when the payload data type alone is not enough to resolve an authentication provider, like with externally triggered authentication providers that don't take payload data at all.</param>
        /// <typeparam name="TResponseC2S">The payload data.</typeparam>
        /// <returns>The last registered authentication provider that can handle <typeparamref name="TResponseC2S"/>.</returns>
        public async Task<IAuthenticationProvider<TResponseC2S>?> ResolveProvider<TResponseC2S>(string? authenticationTypeFilter = null)
            where TResponseC2S : struct
        {
            var payloadHandlerInfo = _providerMap[typeof(TResponseC2S)];
            if (payloadHandlerInfo is null)
            {
                return null;
            }

            IEnumerable<object?> providersRaw = authenticationTypeFilter == null ? payloadHandlerInfo.All : [payloadHandlerInfo.ByTypeFilter[authenticationTypeFilter]];

            foreach (var providerRaw in providersRaw)
            {
                if (providerRaw is null)
                {
                    continue;
                }

                IAuthenticationProvider<TResponseC2S> provider = (IAuthenticationProvider<TResponseC2S>)providerRaw;

                var dbContext = await contextFactory.CreateDbContextAsync().ConfigureAwait(false);
                AuthenticationProviderData? data;
                await using (dbContext.ConfigureAwait(false))
                {
                    data = dbContext.AuthenticationProviderDatas().First(dbProvider => dbProvider.AuthenticationProviderId == provider.GetType().FullName);
                }

                if (data?.IsEnabled != true)
                {
                    continue;
                }

                return provider;
            }

            return null;
        }

        /// <summary>
        /// Get the enabled authentication providers.
        /// </summary>
        /// <remarks>
        /// This API will change in the future to include more information and configuration options.
        /// It should be the basis for customisation done through the admin panel.
        /// Right now, only a global enable/disable is exposed, and some hardcoded actions for the default
        /// authentication provider are implemented.
        /// </remarks>
        /// <returns>The enabled authentication providers.</returns>
        public async Task<IEnumerable<NameIdPair>> GetAuthenticationProviders()
        {
            // TODO: revise. probably want to include legacy authentication providers too, for the time being
            // and maybe also disabled ones (depending on how API was used in the past) if this is going to be
            // used mainly for config pages and stuff, so that admins can enable/disable them through this API
            List<NameIdPair> providers = [];
            foreach (var entry in _providerMap.Values)
            {
                foreach (var providerRaw in entry.All)
                {
                    if (providerRaw is null)
                    {
                        continue;
                    }

                    var providerType = providerRaw.GetType();
                    var typeName = providerType.FullName!;

                    var dbContext = await contextFactory.CreateDbContextAsync().ConfigureAwait(false);
                    AuthenticationProviderData? data;
                    await using (dbContext.ConfigureAwait(false))
                    {
                        data = dbContext.AuthenticationProviderDatas().First(dbProvider => dbProvider.AuthenticationProviderId == typeName);
                    }

                    if (data?.IsEnabled != true)
                    {
                        continue;
                    }

                    providers.Add(new NameIdPair() { Id = typeName, Name = (string)providerType.GetProperty(nameof(JGDefaultAuthenticationProvider.Name))!.GetValue(providerRaw)! });
                }
            }

            return providers;
        }

        /// <summary>
        /// Resolves an authentication provider by its concrete implementation type, only if it is enabled.
        /// </summary>
        /// <typeparam name="T">The implementation type to resolve.</typeparam>
        /// <returns>The authentication provider, if found.</returns>
        public async Task<T?> ResolveConcrete<T>()
            where T : class
        {
            var providerType = typeof(T);
            var providerRaw = _providersByImpType[providerType];
            if (providerRaw is null)
            {
                return null;
            }

            var typeName = providerType.FullName!;
            var dbContext = await contextFactory.CreateDbContextAsync().ConfigureAwait(false);
            AuthenticationProviderData? data;
            await using (dbContext.ConfigureAwait(false))
            {
                data = dbContext.AuthenticationProviderDatas().First(dbProvider => dbProvider.AuthenticationProviderId == typeName);
            }

            if (data?.IsEnabled != true)
            {
                return null;
            }

            return providerRaw as T;
        }

        private record PayloadHandlerInfo
        {
            public required ConcurrentDictionary<string, object> ByTypeFilter { get; set; }

            public required ConcurrentStack<object> All { get; set; }
        }
    }
}
