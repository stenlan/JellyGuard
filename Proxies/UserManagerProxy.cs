using Emby.Server.Implementations.Session;
using Jellyfin.Server.Implementations.Users;
using System.Reflection;

namespace JellyGuard.Proxies
{
    internal class UserManagerProxy : DispatchProxy
    {
        internal static UserManager UserManager;
        private static string AuthenticateUser = nameof(UserManager.AuthenticateUser);
        private static string ChangePassword = nameof(UserManager.ChangePassword);
        private static string ResetPassword = nameof(UserManager.ResetPassword);

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            var methodName = targetMethod?.Name;
            if (methodName == AuthenticateUser || methodName == ChangePassword || methodName == ResetPassword)
            {
                throw new InvalidOperationException($"[JellyGuard] Banned method {methodName} invoked on UserManager. For authentication, please use the appropriate" +
                    $"UserAuthenticationManager or any IAuthenticationProvider<T> functions. To create a session, use JellyGuardSessionManager#CreateSession. " +
                    $"You can obtain a reference to most managers simply by adding it as a DI dependency.");
            }
            return targetMethod?.Invoke(UserManager, args);
        }
    }
}
