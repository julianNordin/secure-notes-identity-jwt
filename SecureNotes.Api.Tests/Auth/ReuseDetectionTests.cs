using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests.Auth;

/// <summary>
/// A spent refresh token being presented is not a mistake, it is evidence that two
/// parties hold the same token. Nothing in the request distinguishes the thief from
/// the victim - same token, and an IP is neither trustworthy nor stable - so the
/// only safe move is to end the whole session and make someone log in again.
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class ReuseDetectionTests(NotesApiFactory factory) : ApiTestBase(factory)
{
    private static async Task<string> RotateAsync(HttpClient client, string refreshToken)
    {
        var response = await RefreshCookies.RefreshAsync(client, refreshToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return RefreshCookies.TokenOn(response)!;
    }

    /// <summary>
    /// The headline test. A chain of three, a replay of the first, and the third -
    /// live, held by the honest client, never presented to anyone - is dead too.
    /// Revoking only the replayed token would leave the thief's copy working.
    /// </summary>
    [Fact]
    public async Task Refresh_KillsALiveSiblingToken_WhenAnAlreadyRotatedTokenIsReplayed()
    {
        using var account = await Factory.RegisterAndLoginAsync();
        var stolen = account.RefreshToken;

        var second = await RotateAsync(account.Client, stolen);
        var live = await RotateAsync(account.Client, second);

        // The attacker presents the copy they took before the first rotation.
        var replay = await RefreshCookies.RefreshAsync(account.Client, stolen);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);

        // The honest client's token was never presented to anybody and is now dead.
        var afterwards = await RefreshCookies.RefreshAsync(account.Client, live);
        Assert.Equal(HttpStatusCode.Unauthorized, afterwards.StatusCode);

        var liveTokens = await Factory.WithDbAsync(db => db.RefreshTokens
            .CountAsync(t => t.UserId == account.UserId && t.RevokedAt == null));
        Assert.Equal(0, liveTokens);
    }

    /// <summary>
    /// The cost of the rule above, stated plainly: a real user can be logged out by
    /// an attacker replaying an old token. That is the right trade - the price is
    /// one login, and the alternative is leaving a session open that is known to
    /// have been copied.
    /// </summary>
    [Fact]
    public async Task Login_StillWorks_AfterAFamilyHasBeenRevoked()
    {
        using var account = await Factory.RegisterAndLoginAsync();
        var stolen = account.RefreshToken;
        await RotateAsync(account.Client, stolen);
        await RefreshCookies.RefreshAsync(account.Client, stolen);

        using var client = Factory.CreateClient();
        var response = await client.PostAsJsonAsync(
            "/api/auth/login", new LoginRequest(account.Email, account.Password));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// Revocation is scoped to the family, not the account. Signing in on a phone
    /// and a laptop makes two families; a replay against one must not sign the
    /// other one out, or every user with two devices would be logged out constantly.
    /// </summary>
    [Fact]
    public async Task Refresh_LeavesAnotherLoginUntouched_WhenOneFamilyIsRevoked()
    {
        using var laptop = await Factory.RegisterAndLoginAsync();

        using var phoneClient = Factory.CreateClient();
        var phoneLogin = await phoneClient.PostAsJsonAsync(
            "/api/auth/login", new LoginRequest(laptop.Email, laptop.Password));
        var phoneRefresh = RefreshCookies.TokenOn(phoneLogin)!;

        var families = await Factory.WithDbAsync(db => db.RefreshTokens
            .Where(t => t.UserId == laptop.UserId)
            .Select(t => t.FamilyId)
            .Distinct()
            .CountAsync());
        Assert.Equal(2, families);

        // Burn the laptop's family with a replay.
        var stolen = laptop.RefreshToken;
        await RotateAsync(laptop.Client, stolen);
        await RefreshCookies.RefreshAsync(laptop.Client, stolen);

        // The phone never presented anything twice and keeps working.
        var response = await RefreshCookies.RefreshAsync(phoneClient, phoneRefresh);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
