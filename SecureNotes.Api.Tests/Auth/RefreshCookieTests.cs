using System.Net;
using System.Net.Http.Json;
using SecureNotes.Api.Common;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests.Auth;

/// <summary>
/// Phase 18's refactor, asserted. The refresh token left the JSON body for an
/// httpOnly cookie, and the flags on that cookie *are* the feature - so an
/// untested flag is an undone feature, and each one gets its own line here.
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class RefreshCookieTests(NotesApiFactory factory) : ApiTestBase(factory)
{
    private async Task<HttpResponseMessage> LoginAsync(HttpClient client, AuthenticatedClient account)
    {
        var response = await client.PostAsJsonAsync(
            "/api/auth/login", new LoginRequest(account.Email, account.Password));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return response;
    }

    /// <summary>
    /// The headline claim of the refactor. Before Phase 18 the refresh token was a
    /// field in this body and went straight into localStorage, where any script on
    /// the origin could read it at leisure. It is not in the body at all now.
    /// </summary>
    [Fact]
    public async Task Login_DoesNotPutTheRefreshTokenInTheBody_WhenItSucceeds()
    {
        using var account = await Factory.RegisterAndLoginAsync();
        using var client = Factory.CreateClient();

        var response = await LoginAsync(client, account);

        var body = await response.Content.ReadAsStringAsync();
        var refreshToken = RefreshCookies.TokenOn(response);

        // Not vacuous: there has to be a real token in the cookie, and a real body
        // to look through, before "it is not in there" means anything at all.
        Assert.NotNull(refreshToken);
        Assert.Contains("access_token", body);

        Assert.DoesNotContain(refreshToken, body);
        Assert.DoesNotContain("refresh_token", body);
    }

    [Theory]
    [InlineData("httponly")]
    [InlineData("secure")]
    [InlineData("samesite=strict")]
    [InlineData("path=/api/auth")]
    public async Task Login_SetsTheRefreshCookieWithItsProtectiveFlags_WhenItSucceeds(string flag)
    {
        using var account = await Factory.RegisterAndLoginAsync();
        using var client = Factory.CreateClient();

        var setCookie = RefreshCookies.SetCookieOn(await LoginAsync(client, account));

        Assert.NotNull(setCookie);
        Assert.Contains(flag, setCookie, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The cookie must not outlive the row behind it, or the browser spends a
    /// credential the server has already stopped honouring on every refresh.
    /// </summary>
    [Fact]
    public async Task Login_GivesTheCookieAnExpiry_WhenItSucceeds()
    {
        using var account = await Factory.RegisterAndLoginAsync();
        using var client = Factory.CreateClient();

        var setCookie = RefreshCookies.SetCookieOn(await LoginAsync(client, account));

        Assert.Contains("expires=", setCookie!, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Reading it from the cookie and nowhere else is what makes httpOnly mean anything.</summary>
    [Fact]
    public async Task Refresh_Returns401_WhenNoCookieIsPresented()
    {
        using var client = Factory.CreateClient();

        var response = await RefreshCookies.RefreshAsync(client, refreshToken: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// A body carrying the token is not a second way in. If it were, httpOnly would
    /// be decorative - the XSS-readable path would still be open and the refactor
    /// would have changed nothing but the paperwork.
    /// </summary>
    [Fact]
    public async Task Refresh_Returns401_WhenTheTokenIsSentInTheBodyInsteadOfTheCookie()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        // A fresh client on purpose, carrying no cookies at all, so this request
        // provably contains the token in exactly one place. Reusing the signed-in
        // client would leave the result depending on whether its cookie container
        // decided to attach the cookie as well - which it does not, only because
        // the cookie is Secure and the test host is http. That is a true fact about
        // today's configuration and a terrible thing to rest an assertion on.
        using var client = Factory.CreateClient();

        var inTheBody = await client.PostAsJsonAsync(
            "/api/auth/refresh", new { refresh_token = account.RefreshToken });

        Assert.Equal(HttpStatusCode.Unauthorized, inTheBody.StatusCode);

        // The control, and it is what stops this being a test of a typo. The very
        // same token on the very same client is accepted the moment it arrives as
        // a cookie - so the 401 above is about where the token was, not about the
        // token being bad or the route being wrong.
        var inTheCookie = await RefreshCookies.RefreshAsync(client, account.RefreshToken);

        Assert.Equal(HttpStatusCode.OK, inTheCookie.StatusCode);
    }

    /// <summary>
    /// A browser holding a token the server will never honour again only fails
    /// more slowly, so a refusal takes the cookie away with it.
    /// </summary>
    [Fact]
    public async Task Refresh_ClearsTheCookie_WhenItRefuses()
    {
        using var client = Factory.CreateClient();

        var response = await RefreshCookies.RefreshAsync(client, "a token nobody ever issued");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.NotNull(RefreshCookies.SetCookieOn(response));
        Assert.Null(RefreshCookies.TokenOn(response));
    }

    [Fact]
    public async Task Logout_ClearsTheCookie_WhenItSucceeds()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var response = await RefreshCookies.PostAsync(
            account.Client, "/api/auth/logout", account.RefreshToken);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Null(RefreshCookies.TokenOn(response));
    }

    /// <summary>Everywhere includes here, and the cookie is part of here.</summary>
    [Fact]
    public async Task LogoutEverywhere_ClearsTheCookie_WhenItSucceeds()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var response = await RefreshCookies.PostAsync(
            account.Client, "/api/auth/logout-all", account.RefreshToken);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Null(RefreshCookies.TokenOn(response));
    }
}
