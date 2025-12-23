namespace SecureNotes.Api.Common;

public static class RateLimits
{
    public const string AuthPolicy = "auth";

    /// <summary>
    /// Ten attempts a minute per address. Generous for a person who has forgotten
    /// which password they used, and useless for working through a password list.
    /// </summary>
    public const int AuthPermitsPerWindow = 10;

    public static readonly TimeSpan AuthWindow = TimeSpan.FromMinutes(1);
}
