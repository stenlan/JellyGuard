using Emby.Server.Implementations.Session;
using System.Reflection;

namespace JellyGuard.Proxies
{
    internal class SessionManagerProxy : DispatchProxy
    {
        internal static SessionManager SessionManager { get; set; }
        private static string AuthenticateNewSession = nameof(SessionManager.AuthenticateNewSession);
        private static string AuthenticateDirect = nameof(SessionManager.AuthenticateDirect);

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            var methodName = targetMethod?.Name;
            if (methodName == AuthenticateNewSession || methodName == AuthenticateDirect)
            {
                throw new InvalidOperationException($"[JellyGuard] Banned method {methodName} invoked on SessionManager. For authentication, please use the appropriate" +
                    $" UserAuthenticationManager or any IAuthenticationProvider<T> functions. To create a session, use JellyGuardSessionManager#CreateSession. " +
                    $"You can obtain a reference to most managers simply by adding it as a DI dependency.");
            }
            return targetMethod?.Invoke(SessionManager, args);
        }
    }
}
