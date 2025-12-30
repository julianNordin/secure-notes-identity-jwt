using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests.Auth;

[Collection(ApiCollection.Name)]
public sealed class RefreshRotationTests(NotesApiFactory factory) : ApiTestBase(factory)
{
    /// <summary>The application stores this, never the token. Phase 07's whole point.</summary>
    private static string Hash(string raw) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));

    [Fact]
    public async Task Refresh_Returns200WithADifferentPair_WhenThePresentedTokenIsLive()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var response = await RefreshCookies.RefreshAsync(account.Client, account.RefreshToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var rotated = await response.Content.ReadFromJsonAsync<TokenResponse>();

        Assert.NotEqual(account.RefreshToken, RefreshCookies.TokenOn(response));
        Assert.NotEqual(account.AccessToken, rotated!.AccessToken);
    }

    /// <summary>
    /// The rotated access token has to actually work, or rotation would be handing
    /// out a credential that only looks like one.
    /// </summary>
    [Fact]
    public async Task Refresh_ReturnsAnAccessTokenThatReachesAProtectedRoute_WhenItRotates()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var rotated = await (await RefreshCookies.RefreshAsync(account.Client, account.RefreshToken))
            .Content.ReadFromJsonAsync<TokenResponse>();

        using var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", rotated!.AccessToken);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/auth/me")).StatusCode);
    }

    /// <summary>
    /// A token works exactly once. A copy taken in transit dies the moment the real
    /// client refreshes, so a silent theft becomes a race the attacker usually
    /// loses rather than an open session.
    /// </summary>
    [Fact]
    public async Task Refresh_Returns401_WhenThePresentedTokenHasAlreadyBeenRotated()
    {
        using var account = await Factory.RegisterAndLoginAsync();
        var spent = account.RefreshToken;

        await RefreshCookies.RefreshAsync(account.Client, spent);

        var replay = await RefreshCookies.RefreshAsync(account.Client, spent);

        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task Refresh_Returns401_WhenTheTokenWasNeverIssued()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var response = await RefreshCookies.RefreshAsync(account.Client, "a token nobody ever issued");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// Rotation keeps the family id and records the replacement, which is what lets
    /// Phase 08 walk a chain from any token in it to all the others.
    /// </summary>
    [Fact]
    public async Task Refresh_IssuesTheReplacementIntoTheSameFamily_WhenItRotates()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var rotated = await RefreshCookies.RefreshAsync(account.Client, account.RefreshToken);

        var rows = await Factory.WithDbAsync(db => db.RefreshTokens
            .Where(t => t.UserId == account.UserId)
            .OrderBy(t => t.CreatedAt)
            .ToListAsync());

        Assert.Equal(2, rows.Count);
        Assert.Equal(rows[0].FamilyId, rows[1].FamilyId);

        // The spent one is revoked and points at its replacement; the new one is live.
        Assert.NotNull(rows[0].RevokedAt);
        Assert.Equal(Hash(RefreshCookies.TokenOn(rotated)!), rows[0].ReplacedByTokenHash);
        Assert.Null(rows[1].RevokedAt);
    }

    /// <summary>
    /// What is stored is exactly SHA-256 of what the client was handed, and the
    /// token itself appears nowhere. A database dump full of raw refresh tokens is
    /// a room full of live sessions; this is the assertion that it is not one.
    /// </summary>
    [Fact]
    public async Task Refresh_StoresOnlyAHashOfTheToken_WhenOneIsIssued()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var stored = await Factory.WithDbAsync(db => db.RefreshTokens
            .Where(t => t.UserId == account.UserId)
            .Select(t => t.TokenHash)
            .ToListAsync());

        Assert.Equal([Hash(account.RefreshToken)], stored);
        Assert.DoesNotContain(account.RefreshToken, stored);
    }
}
