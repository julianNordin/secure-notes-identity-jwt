using System.Net;
using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests.Authorization;

/// <summary>
/// Secure by default, asserted against an endpoint that says nothing about who may
/// call it. Every other test in this suite exercises an endpoint whose attributes
/// are correct; this is the one that would notice if the safety net under them were
/// removed.
/// </summary>
/// <remarks>
/// Not hypothetical. Phase 10's commit message described SetFallbackPolicy and its
/// diff never touched Program.cs, so for four phases the policy did not exist and
/// nothing failed - the verification quoted in that commit gave identical answers
/// either way. This test is the one that could not have.
/// </remarks>
[Collection(ApiCollection.Name)]
public sealed class FallbackPolicyTests(NotesApiFactory factory) : ApiTestBase(factory)
{
    [Fact]
    public async Task BareEndpoint_Returns401_WhenTheCallerIsAnonymousAndNothingSaysOtherwise()
    {
        using var client = Factory.CreateClient();

        var response = await client.GetAsync(DeliberatelyBareController.Route);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Bearer", response.Headers.WwwAuthenticate.ToString());
    }

    /// <summary>
    /// The other half, and the reason the first half is not just a broken route: the
    /// endpoint really is there and really does work for an authenticated caller.
    /// A 401 from a typo in the URL would look identical without this.
    /// </summary>
    [Fact]
    public async Task BareEndpoint_Returns200_WhenTheCallerIsAuthenticated()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var response = await account.Client.GetAsync(DeliberatelyBareController.Route);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
