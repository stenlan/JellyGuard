namespace JellyGuard.DataHolders
{
    /// <summary>
    /// Record to hold data for username/password-based authentication.
    /// </summary>
    public record struct UsernamePasswordAuthData(string? Username, string? Password, string? TOTP);
}
