using SecureNotes.Api.Common;

namespace SecureNotes.Api.Tests.TestHelpers;

/// <summary>
/// The refresh token is an httpOnly cookie now, so the tests have to speak cookies.
/// </summary>
/// <remarks>
/// Set explicitly rather than through HttpClient's CookieContainer, for two
/// reasons that both matter. The container will not send a Secure cookie over
/// http, and the test host is http. And half of these tests need to present one
/// *particular* token - a spent one, a live sibling, one belonging to another
/// device - which a container holding only the newest cookie cannot express. Doing
/// it by hand also keeps what is being sent visible in the test itself.
/// </remarks>
public static class RefreshCookies
{
    /// <summary>The whole Set-Cookie line for the refresh cookie, flags and all.</summary>
    public static string? SetCookieOn(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.FirstOrDefault(value =>
                value.StartsWith($"{RefreshCookie.Name}=", StringComparison.Ordinal))
            : null;

    /// <summary>The raw token out of a response, or null when it carries none.</summary>
    public static string? TokenOn(HttpResponseMessage response)
    {
        var cookie = SetCookieOn(response);
        if (cookie is null)
        {
            return null;
        }

        var value = cookie.Split(';')[0][(RefreshCookie.Name.Length + 1)..];

        // An empty value is the deletion the server sends when it refuses.
        return value.Length == 0 ? null : value;
    }

    /// <summary>Posts to an auth endpoint carrying the token the way a browser would.</summary>
    public static Task<HttpResponseMessage> PostAsync(
        HttpClient client, string path, string? refreshToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path);

        if (refreshToken is not null)
        {
            request.Headers.Add("Cookie", $"{RefreshCookie.Name}={refreshToken}");
        }

        return client.SendAsync(request);
    }

    public static Task<HttpResponseMessage> RefreshAsync(HttpClient client, string? refreshToken) =>
        PostAsync(client, "/api/auth/refresh", refreshToken);
}
