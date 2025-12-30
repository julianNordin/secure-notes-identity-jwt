namespace SecureNotes.Api.Common;

/// <summary>
/// Where the refresh token lives: an httpOnly cookie, rather than the JSON body
/// and the browser's localStorage it rode in until Phase 18.
/// </summary>
/// <remarks>
/// Each flag below is doing a specific job, and an untested flag is an undone
/// feature - the integration tests assert all four off the Set-Cookie header.
/// </remarks>
public static class RefreshCookie
{
    public const string Name = "refresh_token";

    /// <summary>
    /// The only path with any use for it. A cookie scoped to <c>/</c> would ride
    /// along on every note request, which is a long-lived credential being handed
    /// out dozens of times a session for no reason at all.
    /// </summary>
    public const string Path = "/api/auth";

    public static CookieOptions Options(DateTimeOffset expiresAt) => new()
    {
        // The point of the whole refactor. Script cannot read an httpOnly cookie,
        // so an XSS that would previously have walked off with a refresh token out
        // of localStorage now gets nothing durable. It can still act as the user
        // while its page is open - that is not fixable from here - but it can no
        // longer take home a credential that outlives the tab it ran in.
        HttpOnly = true,

        // Never over plaintext. A refresh token is a long-lived credential and one
        // interception is a whole session, renewable.
        Secure = true,

        // Not attached to any cross-site request, so a form post or an image tag on
        // somebody else's site cannot make the browser spend this token. That is
        // CSRF defence bought with an attribute instead of a token in every form.
        SameSite = SameSiteMode.Strict,

        Path = Path,

        // Matches the row in the database rather than being guessed at, so the
        // browser never holds a cookie the server has already stopped honouring.
        Expires = expiresAt,

        // Exempt from cookie-consent suppression: without it there is no session.
        IsEssential = true,
    };

    /// <summary>The same cookie, expired. Deleting requires the same attributes.</summary>
    public static CookieOptions Expired() => Options(DateTimeOffset.UnixEpoch);
}
