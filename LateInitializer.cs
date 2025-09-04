
using Emby.Server.Implementations;
using Emby.Server.Implementations.Session;
using Jellyfin.Server.Implementations.Users;
using JellyGuard.AuthenticationManager;
using JellyGuard.AuthenticationProvider;
using JellyGuard.Proxies;
using MediaBrowser.Common;
using MediaBrowser.Controller.Providers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace JellyGuard
{
    // makes use of the fact that this is constructed by the application host after all plugins have finished initializing,
    // and is also just a marker interface (doesn't implement the generic variant), so there should be no runtime impact
    public class LateInitializer : IMetadataProvider
    {
        private readonly ILogger<LateInitializer> _logger;
        private readonly IApplicationHost _applicationHost;

        private Type[] _allConcreteTypes;
        private List<Type> _creatingInstances;
        private ConcurrentBag<IDisposable> _disposableParts;

        public LateInitializer(ILogger<LateInitializer> logger, IApplicationHost applicationHost, UserAuthenticationManager userAuthenticationManager) {
            _logger = logger;
            _applicationHost = applicationHost;

            var allConcreteTypesField = typeof(ApplicationHost).GetField("_allConcreteTypes", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                ?? throw new InvalidOperationException("[JellyGuard] Could not get concrete types from ApplicationHost");
            _allConcreteTypes = (Type[])allConcreteTypesField.GetValue(_applicationHost)!;

            var disposablePartsField = typeof(ApplicationHost).GetField("_disposableParts", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                ?? throw new InvalidOperationException("[JellyGuard] Could not get disposable parts from ApplicationHost");
            _disposableParts = (ConcurrentBag<IDisposable>)disposablePartsField.GetValue(_applicationHost)!;

            var _creatingInstancesField = typeof(ApplicationHost).GetField("_creatingInstances", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                ?? throw new InvalidOperationException("[JellyGuard] Could not get _creatingInstances from ApplicationHost");
            _creatingInstances = (List<Type>)_creatingInstancesField.GetValue(_applicationHost)!;

            logger.LogInformation("Registering authentication providers...");
            _ = userAuthenticationManager.RegisterProviders(GetAuthenticationProviderExports());

            SessionManagerProxy.SessionManager = (SessionManager) (CreateInstanceSafe(typeof(SessionManager))
                ?? throw new InvalidOperationException("[JellyGuard] Failed to supply SessionManager instance to proxy."));
            UserManagerProxy.UserManager = (UserManager) (CreateInstanceSafe(typeof(UserManager))
                ?? throw new InvalidOperationException("[JellyGuard] Failed to supply UserManager instance to proxy."));
        }

        private IReadOnlyCollection<object> GetAuthenticationProviderExports()
        {
            var authenticationProviderType = typeof(IAuthenticationProvider<>);
            var authenticationProviders = new List<object>();
            
            foreach (var type in _allConcreteTypes)
            {
                var interfaces = type.FindInterfaces(
                    (m, criteria) =>
                    {
                        if (m.IsGenericType && m.GetGenericTypeDefinition() == authenticationProviderType)
                        {
                            return true;
                        }

                        return false;
                    },
                    null);

                if (interfaces.Length > 0) // implements generic IAuthenticationProvider
                {
                    var instance = CreateInstanceSafe(type);
                    authenticationProviders.Add(instance);
                    if (instance is IDisposable disposable)
                    {
                        _disposableParts.Add(disposable);
                    }
                }
            }

            var defaultAssembly = typeof(AuthenticationProvider.JGDefaultAuthenticationProvider).Assembly;

            // Sort the authentication providers so that internal ones are first,
            // which allows external ones to override internal ones.
            // We don't sort others since plugin load order is non deterministic anyway.
            authenticationProviders.Sort((a, b) =>
            {
                var aDefault = a.GetType().Assembly == defaultAssembly;
                var bDefault = b.GetType().Assembly == defaultAssembly;

                if (aDefault == bDefault) // both internal or both external
                {
                    return 0;
                }

                return aDefault ? -1 : 1;
            });

            return authenticationProviders;
        }

        private object? CreateInstanceSafe(Type type)
        {
            try
            {
                _creatingInstances.Add(type);
                _logger.LogDebug("Creating instance of {Type}", type);
                return _applicationHost.ServiceProvider is null
                    ? Activator.CreateInstance(type)
                    : ActivatorUtilities.CreateInstance(_applicationHost.ServiceProvider, type);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating {Type}", type);
                // If this is a plugin fail it.
                return null;
            }
            finally
            {
                _creatingInstances.Remove(type);
            }
        }

        public string Name => string.Empty;
    }
}
