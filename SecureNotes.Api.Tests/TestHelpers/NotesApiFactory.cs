using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SecureNotes.Api.Data;
using Testcontainers.PostgreSql;

namespace SecureNotes.Api.Tests.TestHelpers;

/// <summary>
/// Boots the real application against a real Postgres in a throwaway container.
/// One container and one host for the whole suite; see ApiCollection for why that
/// is a fixture rather than a per-class field.
/// </summary>
public sealed class NotesApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    // The same image tag as docker-compose.yml. Testing against a different major
    // version than the one being developed against would make this suite answer
    // questions about a database nobody runs.
    //
    // Testcontainers 4.14 obsoleted both the parameterless constructor and
    // .WithImage() in favour of naming the image here, so that a builder cannot
    // exist in a state where the image is still the package default.
    private readonly PostgreSqlContainer _database =
        new PostgreSqlBuilder("postgres:17-alpine").Build();

    /// <summary>
    /// Long enough to satisfy JwtOptionsValidator and different from the
    /// placeholder it rejects. It is not a secret: it exists only inside a test
    /// process, and every token it signs dies with the container.
    /// </summary>
    public const string SigningKey = "integration-tests-only-signing-key-not-a-secret-0123456789";

    public const string AdminEmail = "seed-admin@securenotes.test";

    public const string AdminPassword = "seed admin password, tests only";

    private int _clients;

    /// <summary>
    /// The application's clock, under the test's control.
    /// </summary>
    /// <remarks>
    /// Frozen rather than ticking, and reset to the real time before each test by
    /// ApiTestBase. Winding it backwards before logging in is how an expired access
    /// token is produced without a suite that sleeps: TokenService stamps exp from
    /// this clock, while the JWT handler validates exp against the real one.
    ///
    /// It does not reach Identity's lockout. Neither UserManager nor SignInManager
    /// takes a TimeProvider in 9.0.1 - checked by reflection, both come back empty -
    /// so lockout windows are computed against DateTimeOffset.UtcNow directly and no
    /// amount of fake time will move them.
    /// </remarks>
    public RebindableClock Clock { get; } = new();

    /// <summary>Starts the application clock again from a chosen moment.</summary>
    public void RebindClock(DateTimeOffset now) => Clock.RebindTo(now);

    public async Task InitializeAsync()
    {
        await _database.StartAsync();

        // Environment variables, and set here rather than through
        // ConfigureAppConfiguration, because by the time that runs it is too late.
        // Program.cs reads ConnectionStrings:Default in its own top-level
        // statements, immediately after CreateBuilder returns; a WebApplicationBuilder
        // does not apply configuration deltas from the host builder until Build() is
        // called, which is afterwards. Environment variables are read by
        // CreateBuilder itself, so they are already there when that line runs.
        Environment.SetEnvironmentVariable("ConnectionStrings__Default", _database.GetConnectionString());
        Environment.SetEnvironmentVariable("Jwt__SigningKey", SigningKey);

        // The seed admin comes from the application's own DbInitializer rather than
        // being inserted by the tests. An admin created a different way than the
        // real one is an admin whose setup nothing verifies.
        Environment.SetEnvironmentVariable("Seed__AdminEmail", AdminEmail);
        Environment.SetEnvironmentVariable("Seed__AdminPassword", AdminPassword);

        // Touching Services builds the host, which runs DbInitializer.SeedAsync and
        // therefore the migrations. Doing it here rather than lazily on the first
        // request keeps container startup and schema creation inside fixture setup,
        // where a failure is reported as a failure to start rather than as every
        // test in the suite failing for its own mysterious reason.
        _ = Services;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Not Development: that would map Swagger and let the exception handler
        // return stack traces, so the suite would be exercising a pipeline no
        // deployment runs. Not Production either, so the distinction stays visible.
        builder.UseEnvironment("Testing");

        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<IStartupFilter, TestRemoteIpStartupFilter>();

            // Replace rather than add: Program.cs already registered
            // TimeProvider.System, and leaving both in place would work only because
            // the last registration wins, which is a rule nobody should have to know.
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(Clock);
        });
    }

    /// <summary>
    /// Hands every client its own remote address, so each lands in a rate limit
    /// partition of its own.
    /// </summary>
    /// <remarks>
    /// ConfigureClient rather than a helper method, because CreateClient() and
    /// CreateDefaultClient() both route through it. A test that calls the ordinary
    /// method still gets an isolated client, so there is nothing to remember and
    /// nothing to forget - and a test that did forget would fail or pass depending
    /// on what ran before it, which is the worst kind of failure to own.
    /// </remarks>
    protected override void ConfigureClient(HttpClient client)
    {
        base.ConfigureClient(client);

        var ordinal = Interlocked.Increment(ref _clients);
        var address = new IPAddress([10, (byte)(ordinal >> 16), (byte)(ordinal >> 8), (byte)ordinal]);

        client.DefaultRequestHeaders.Add(TestRemoteIpStartupFilter.HeaderName, address.ToString());
    }

    /// <summary>
    /// Runs a query against the same database the application is using.
    /// </summary>
    /// <remarks>
    /// Several of this project's claims are claims about rows rather than about
    /// status codes - that a replayed refresh token revoked its whole family, that
    /// deleting a user took their notes with them, that a refresh token is stored as
    /// a hash and never in the clear. None of those can be asserted through the API,
    /// because an API that reported them would be leaking them.
    /// </remarks>
    public async Task<T> WithDbAsync<T>(Func<AppDbContext, Task<T>> query)
    {
        using var scope = Services.CreateScope();
        return await query(scope.ServiceProvider.GetRequiredService<AppDbContext>());
    }

    /// <summary>
    /// Empties every table the migrations created, then re-seeds through the
    /// application's own DbInitializer. Called between tests by ApiTestBase.
    /// </summary>
    public async Task ResetDatabaseAsync()
    {
        using var scope = Services.CreateScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        // Read out of the catalogue rather than listed here. A hand-written list is
        // correct until the next migration adds a table, and then it is silently
        // wrong: the new table keeps its rows between tests, and the failure
        // surfaces somewhere else entirely as a test that only fails when it runs
        // after some other one.
        var tables = await database.Database
            .SqlQueryRaw<string>(
                @"SELECT quote_ident(table_name) AS ""Value""
                  FROM information_schema.tables
                  WHERE table_schema = 'public'
                    AND table_type = 'BASE TABLE'
                    AND table_name <> '__EFMigrationsHistory'")
            .ToListAsync();

        // One statement naming every table, because TRUNCATE takes an exclusive
        // lock on each one and doing them separately invites a deadlock. CASCADE
        // for the foreign key from Notes to AspNetUsers; RESTART IDENTITY so one
        // test's row count cannot reach the next test through a sequence.
        // EF1002 warns that this interpolates into SQL. It does, and it has to: a
        // table name cannot be a query parameter in any database, so the analyser's
        // suggested ExecuteSqlAsync is not available here. What makes it safe is
        // that the names never came from outside - Postgres produced them from its
        // own catalogue and quote_ident already escaped them.
#pragma warning disable EF1002
        await database.Database.ExecuteSqlRawAsync(
            $"TRUNCATE TABLE {string.Join(", ", tables)} RESTART IDENTITY CASCADE");
#pragma warning restore EF1002

        // Roles and the seed admin are part of a working system rather than test
        // fixtures, so they come back through the same path production uses. It
        // also means every test run exercises the seeding code.
        await DbInitializer.SeedAsync(Services);
    }

    // Explicit implementation: xUnit's IAsyncLifetime.DisposeAsync returns Task and
    // WebApplicationFactory's IAsyncDisposable.DisposeAsync returns ValueTask, and
    // two methods cannot differ by return type alone. InitializeAsync has no such
    // clash and stays public.
    async Task IAsyncLifetime.DisposeAsync()
    {
        await base.DisposeAsync();
        await _database.DisposeAsync();
    }
}
