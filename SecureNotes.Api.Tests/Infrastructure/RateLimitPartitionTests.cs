using System.Net;
using System.Net.Http.Json;
using SecureNotes.Api.Common;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests.Infrastructure;

/// <summary>
/// Two halves of one claim: the harness gives each client a rate limit partition of
/// its own, and it does that without switching the limiter off.
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class RateLimitPartitionTests(NotesApiFactory factory) : ApiTestBase(factory)
{
    /// <summary>
    /// Six accounts is twelve requests to /api/auth against a limit of ten a
    /// minute. Before the harness gave each client its own address they shared one
    /// partition keyed "unknown", and this failed on the sixth registration.
    /// </summary>
    [Fact]
    public async Task RegisterAndLogin_AllSucceed_WhenEachAccountUsesItsOwnClient()
    {
        for (var i = 0; i < 6; i++)
        {
            using var account = await Factory.RegisterAndLoginAsync();
            Assert.NotEqual(Guid.Empty, account.UserId);
        }
    }

    /// <summary>
    /// One client is one address is one partition, so the limit still bites. This is
    /// the test that fails if anybody ever "fixes" the harness by raising the limit
    /// under test or turning the limiter off.
    /// </summary>
    [Fact]
    public async Task Login_Returns429WithRetryAfter_WhenOneClientExceedsTheWindow()
    {
        using var client = Factory.CreateClient();
        var wrong = new LoginRequest("nobody@securenotes.test", "not the right password");

        var responses = new List<HttpResponseMessage>();
        for (var i = 0; i < RateLimits.AuthPermitsPerWindow + 2; i++)
        {
            responses.Add(await client.PostAsJsonAsync("/api/auth/login", wrong));
        }

        // The permitted ones are refused for the ordinary reason - an unknown
        // address and a wrong password are the same 401 - and the rest are refused
        // for being too many.
        Assert.Equal(
            RateLimits.AuthPermitsPerWindow,
            responses.Count(r => r.StatusCode == HttpStatusCode.Unauthorized));
        Assert.Equal(2, responses.Count(r => r.StatusCode == HttpStatusCode.TooManyRequests));

        // Retry-After is the difference between a client that backs off and one that
        // guesses, so it is part of the feature rather than a nicety.
        var refused = responses.Last(r => r.StatusCode == HttpStatusCode.TooManyRequests);
        Assert.Equal(
            (int)RateLimits.AuthWindow.TotalSeconds,
            int.Parse(Assert.Single(refused.Headers.GetValues("Retry-After"))));

        foreach (var response in responses)
        {
            response.Dispose();
        }
    }
}
