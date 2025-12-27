using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests.Auth;

/// <summary>
/// Ending sessions: one at a time, and everywhere at once.
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class SessionRevocationTests(NotesApiFactory factory) : ApiTestBase(factory)
{
    private async Task<TokenResponse> LoginAgainAsync(HttpClient client, AuthenticatedClient account)
    {
        var response = await client.PostAsJsonAsync(
            "/api/auth/login", new LoginRequest(account.Email, account.Password));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return (await response.Content.ReadFromJsonAsync<TokenResponse>())!;
    }

    [Fact]
    public async Task Logout_InvalidatesTheRefreshToken_WhenItIsPresented()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var logout = await account.Client.PostAsJsonAsync(
            "/api/auth/logout", new RefreshRequest(account.RefreshToken));
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var refresh = await account.Client.PostAsJsonAsync(
            "/api/auth/refresh", new RefreshRequest(account.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
    }

    /// <summary>
    /// Logout answers the same way whether or not the token was real. Reporting the
    /// difference would make it a token oracle, and no honest caller can use the
    /// answer - a client logging out does not care whether the server agreed.
    /// </summary>
    [Fact]
    public async Task Logout_Returns204_WhenTheTokenWasNeverIssued()
    {
        using var client = Factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/auth/logout", new RefreshRequest("a token nobody ever issued"));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    /// <summary>
    /// The thing a stateless JWT is famously unable to do. Rolling the security
    /// stamp kills an access token that has already been issued, on its very next
    /// request, rather than up to fifteen minutes later when it would have expired.
    /// </summary>
    [Fact]
    public async Task LogoutAll_Returns401ForAnotherDevicesLiveAccessToken_WhenItIsCalled()
    {
        using var laptop = await Factory.RegisterAndLoginAsync();
        using var phoneClient = Factory.CreateClient();

        var phone = await LoginAgainAsync(phoneClient, laptop);
        phoneClient.DefaultRequestHeaders.Authorization = new("Bearer", phone.AccessToken);

        // The phone's token is live and working before anything happens.
        Assert.Equal(HttpStatusCode.OK, (await phoneClient.GetAsync("/api/auth/me")).StatusCode);

        Assert.Equal(
            HttpStatusCode.NoContent,
            (await laptop.Client.PostAsync("/api/auth/logout-all", null)).StatusCode);

        // Same token, same request, one moment later.
        Assert.Equal(HttpStatusCode.Unauthorized, (await phoneClient.GetAsync("/api/auth/me")).StatusCode);
    }

    /// <summary>
    /// Logout-all needs both halves. Revoking refresh tokens alone would stop new
    /// access tokens being minted while leaving the ones already out there working,
    /// which would make it mean "log out everywhere within fifteen minutes".
    /// </summary>
    [Fact]
    public async Task LogoutAll_RevokesEveryRefreshTokenForTheAccount_WhenItIsCalled()
    {
        using var laptop = await Factory.RegisterAndLoginAsync();
        using var phoneClient = Factory.CreateClient();
        var phone = await LoginAgainAsync(phoneClient, laptop);

        await laptop.Client.PostAsync("/api/auth/logout-all", null);

        Assert.Equal(0, await Factory.WithDbAsync(db => db.RefreshTokens
            .CountAsync(t => t.UserId == laptop.UserId && t.RevokedAt == null)));

        var refresh = await phoneClient.PostAsJsonAsync(
            "/api/auth/refresh", new RefreshRequest(phone.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
    }

    /// <summary>
    /// Revocation is scoped to the account. One user signing out everywhere must not
    /// disturb anybody else, and a missing WHERE clause would look like working
    /// software right up until it did not.
    /// </summary>
    [Fact]
    public async Task LogoutAll_LeavesOtherAccountsAlone_WhenItIsCalled()
    {
        using var alice = await Factory.RegisterAndLoginAsync();
        using var bob = await Factory.RegisterAndLoginAsync();

        await alice.Client.PostAsync("/api/auth/logout-all", null);

        Assert.Equal(HttpStatusCode.OK, (await bob.Client.GetAsync("/api/auth/me")).StatusCode);

        var refresh = await bob.Client.PostAsJsonAsync(
            "/api/auth/refresh", new RefreshRequest(bob.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
    }

    /// <summary>
    /// The account behind a live token is deleted. The token is still perfectly
    /// signed and still inside its lifetime, and it is refused.
    /// </summary>
    /// <remarks>
    /// The same fail-closed path an infrastructure failure takes: SecurityStampCheck
    /// cannot produce a user, so it fails the token rather than letting the request
    /// through to find out what happens next. Worth pinning because the natural
    /// shape of a caching change - keep the stamp, skip the lookup - would turn this
    /// into a request that proceeds with a principal for an account that is gone.
    /// </remarks>
    [Fact]
    public async Task Me_Returns401RatherThan500_WhenTheAccountBehindTheTokenIsDeleted()
    {
        using var account = await Factory.RegisterAndLoginAsync();
        Assert.Equal(HttpStatusCode.OK, (await account.Client.GetAsync("/api/auth/me")).StatusCode);

        await Factory.WithDbAsync(db => db.Users.Where(u => u.Id == account.UserId).ExecuteDeleteAsync());

        var response = await account.Client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task LogoutAll_Returns401_WhenTheCallerIsAnonymous()
    {
        using var client = Factory.CreateClient();

        var response = await client.PostAsync("/api/auth/logout-all", null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
