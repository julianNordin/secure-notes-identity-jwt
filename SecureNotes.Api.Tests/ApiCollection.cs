using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests;

/// <summary>
/// Every test class joins this one collection. That is what makes the whole suite
/// share a single container and a single host - and, just as importantly, run its
/// tests one at a time. Isolation here means emptying the database between tests,
/// which is only coherent while no two tests are in flight at once.
/// </summary>
[CollectionDefinition(Name)]
public sealed class ApiCollection : ICollectionFixture<NotesApiFactory>
{
    public const string Name = "api";
}
