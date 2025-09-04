using Emby.Server.Implementations.Session;
using Jellyfin.Server.Implementations;
using Jellyfin.Server.Implementations.Users;
using JellyGuard.AuthenticationManager;
using JellyGuard.Database;
using JellyGuard.JGSessionManager;
using JellyGuard.Proxies;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Plugins;
using MediaBrowser.Controller.Session;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;

namespace JellyGuard
{
    public class PluginServiceRegistrator : IPluginServiceRegistrator
    {
        public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
        {
            // From ServiceCollectionExtensions, make sure to update upon jellyfin update
            serviceCollection.AddPooledDbContextFactory<JellyfinDbContext>((serviceProvider, opt) =>
            {
                opt.ReplaceService<IMigrationsAssembly, JGMigrationsAssembly>();
                opt.ReplaceService<IModelCustomizer, JGModelCustomizer>();

                var applicationPaths = serviceProvider.GetRequiredService<IApplicationPaths>();
                opt.UseSqlite($"Filename={Path.Combine(applicationPaths.DataPath, "jellyfin.db")}");
            });

            serviceCollection.AddSingleton<UserAuthenticationManager>();

            // proxy sessionmanager and usermanager so plugins don't accidentally bypass authentication by calling their functions somewhere
            // unfortunately this is needed because of the tight coupling in the authentication implementation
            var sessionManagerDesc = serviceCollection.FirstOrDefault(d => d.ImplementationType == typeof(SessionManager))
                ?? throw new InvalidOperationException("[JellyGuard] Failed to find session manager instance to proxy.");
            serviceCollection.Remove(sessionManagerDesc);

            var sessionManagerProxy = DispatchProxy.Create<ISessionManager, SessionManagerProxy>();
            serviceCollection.AddSingleton<ISessionManager>(sessionManagerProxy);

            var userManagerDesc = serviceCollection.FirstOrDefault(d => d.ImplementationType == typeof(UserManager))
                ?? throw new InvalidOperationException("[JellyGuard] Failed to find user manager instance to proxy.");
            serviceCollection.Remove(userManagerDesc);

            var userManagerProxy = DispatchProxy.Create<IUserManager, UserManagerProxy>();
            serviceCollection.AddSingleton<IUserManager>(userManagerProxy);

            // add JellyGuard session manager
            serviceCollection.AddSingleton<JellyGuardSessionManager>();
        }
    }
}
