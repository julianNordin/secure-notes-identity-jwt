using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using SecureNotes.Api.Common;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests.Infrastructure;

/// <summary>
/// Proves the per-test reset, which every later phase quietly depends on.
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class DatabaseIsolationTests(NotesApiFactory factory) : ApiTestBase(factory)
{
    // Two tests doing the same thing, each asserting it is the only one to have done
    // it. In either order they can both pass only if the database was emptied
    // between them; if the reset ever stops working, whichever runs second fails and
    // says so in terms of what it found rather than as a puzzle somewhere else.
    [Fact]
    public Task CreateNote_LeavesOneNoteAndOneNewUser_WhenRunFirst() => AssertNothingLeakedAsync();

    [Fact]
    public Task CreateNote_LeavesOneNoteAndOneNewUser_WhenRunAfterATestThatDidTheSame() =>
        AssertNothingLeakedAsync();

    private async Task AssertNothingLeakedAsync()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var created = await account.Client.PostAsJsonAsync(
            "/api/notes", new CreateNoteRequest("The only note", "The only content"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        Assert.Equal(1, await Factory.WithDbAsync(db => db.Notes.CountAsync()));

        // The seed admin, plus the one account this test registered. A user left
        // behind by another test would show up right here.
        Assert.Equal(2, await Factory.WithDbAsync(db => db.Users.CountAsync()));
    }

    /// <summary>
    /// The reset truncates every table the migrations created, roles included, so it
    /// has to put them back. Without this the first test after a reset would meet an
    /// application in which no role exists, nobody can be an admin, and every
    /// authorization test fails for a reason that has nothing to do with
    /// authorization.
    /// </summary>
    [Fact]
    public async Task ResetDatabase_RestoresTheRolesAndTheSeedAdmin()
    {
        var roles = await Factory.WithDbAsync(db => db.Roles.Select(r => r.Name!).ToListAsync());
        Assert.Equal(Roles.All.Order(), roles.Order());

        using var admin = await Factory.LoginAsSeedAdminAsync();
        Assert.Equal(NotesApiFactory.AdminEmail, admin.Email);
    }

    /// <summary>
    /// The table list comes out of the catalogue rather than being written down, so
    /// a migration adding a table cannot leave it leaking rows between tests. This
    /// checks the query actually sees the schema it is meant to.
    /// </summary>
    [Fact]
    public async Task ResetDatabase_CoversEveryTableTheMigrationsCreated()
    {
        var tables = await Factory.WithDbAsync(db => db.Database
            .SqlQueryRaw<string>(
                @"SELECT table_name AS ""Value"" FROM information_schema.tables
                  WHERE table_schema = 'public' AND table_type = 'BASE TABLE'")
            .ToListAsync());

        // The seven Identity tables, Notes, RefreshTokens, and the migrations
        // history the reset deliberately leaves alone.
        Assert.Equal(10, tables.Count);
        Assert.Contains("__EFMigrationsHistory", tables);
        Assert.Contains("AspNetUsers", tables);
        Assert.Contains("RefreshTokens", tables);
        Assert.Contains("Notes", tables);
    }
}
