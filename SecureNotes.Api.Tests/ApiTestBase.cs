using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests;

/// <summary>
/// Gives every test an empty, freshly seeded database. Derived classes still carry
/// [Collection(ApiCollection.Name)] themselves rather than inheriting it, because
/// xUnit resolves the collection from the concrete test class.
/// </summary>
public abstract class ApiTestBase(NotesApiFactory factory) : IAsyncLifetime
{
    protected NotesApiFactory Factory { get; } = factory;

    // Reset before each test, not after. Cleaning up afterwards leaves the last
    // test's rows behind for anyone who looks at the database, and does nothing at
    // all when a test fails hard enough to skip its own teardown - which is exactly
    // the run where the next test's mysterious failure would be blamed on itself.
    public Task InitializeAsync()
    {
        // Back to real time, so a test that wound the clock cannot change what
        // the next one sees.
        Factory.RebindClock(DateTimeOffset.UtcNow);

        return Factory.ResetDatabaseAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;
}
