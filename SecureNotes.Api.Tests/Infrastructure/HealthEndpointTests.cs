using System.Net;
using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests.Infrastructure;

[Collection(ApiCollection.Name)]
public sealed class HealthEndpointTests(NotesApiFactory factory) : ApiTestBase(factory)
{
    /// <summary>
    /// The first green test, and it proves more than the endpoint. Reaching 200
    /// here means the container started, the environment variables landed before
    /// the host read them, the migrations ran, and AddNpgSql could open a
    /// connection - the entire harness, asserted by one status code.
    /// </summary>
    [Fact]
    public async Task Get_Returns200Healthy_WhenTheDatabaseIsReachable()
    {
        using var client = Factory.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", await response.Content.ReadAsStringAsync());
    }

    /// <summary>
    /// Phase 10's fallback policy makes every endpoint require authentication, so
    /// /health only answers anonymously because it says AllowAnonymous. This is the
    /// test that fails if someone removes that.
    /// </summary>
    [Fact]
    public async Task Get_Returns200_WhenTheCallerIsAnonymous()
    {
        using var client = Factory.CreateClient();

        Assert.Null(client.DefaultRequestHeaders.Authorization);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);
    }
}
