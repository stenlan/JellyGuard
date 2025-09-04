using JellyGuard.DataHolders;

namespace JellyGuard.AuthenticationProvider
{
    /// <summary>
    /// Interface for authentication providers. Custom authentication providers should generally inherit from
    /// <see cref="AbstractAuthenticationProvider{TResponseC2S, TGlobalData, TUserData}"/> or its subclasses instead, which contain a lot of convenience
    /// logic for authentication providers.
    /// </summary>
    /// <typeparam name="TResponseC2S">The payload data that authenticates a user. This type is used as a key for signalling if an authentication provider can handle a specific type of authentication data.</typeparam>
    /// <remarks>
    /// Besides being able to _handle_ a certain type of data, the data needs to come from somewhere. That is not the responsibility of an authentication provider. Jellyfin
    /// by default implements just 1 type of authentication, which is the classic password-based authentication, the payload for which gets passed in through the normal authentication
    /// flow. To support this, use <see cref="UsernamePasswordAuthData"/>. Other types will be implemented in the future.
    /// </remarks>
    public interface IAuthenticationProvider<TResponseC2S>
        where TResponseC2S : struct
    {
        /// <summary>
        /// Gets the display name of this authentication provider.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Gets an optional field that can be used for extra disambiguation between IAuthenticationProviders with the same TResponseC2S.
        /// </summary>
        string? AuthenticationType { get; }

        /// <summary>
        /// Attempts to authenticate a user.
        /// </summary>
        /// <param name="authenticationData">The authentication data.</param>
        /// <returns>An authentication result.</returns>
        Task<AuthenticationResult> Authenticate(TResponseC2S authenticationData);
    }
}
