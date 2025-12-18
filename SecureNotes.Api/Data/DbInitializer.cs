using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureNotes.Api.Common;
using SecureNotes.Api.Domain;

namespace SecureNotes.Api.Data;

public static class DbInitializer
{
    /// <summary>
    /// Applies migrations, ensures both roles exist, and creates the seed admin if
    /// one is configured. Idempotent: running it twice changes nothing.
    /// </summary>
    public static async Task SeedAsync(IServiceProvider services, CancellationToken cancellationToken = default)
    {
        using var scope = services.CreateScope();
        var provider = scope.ServiceProvider;

        var logger = provider.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(DbInitializer));

        // Migrating on startup is a convenience that suits a single-instance app
        // being developed. It is worth knowing what it costs: with several
        // instances they race, and a migration that fails leaves the app down
        // rather than merely un-migrated. A real deployment runs migrations as a
        // separate step before the new version starts.
        await provider.GetRequiredService<AppDbContext>().Database.MigrateAsync(cancellationToken);

        var roles = provider.GetRequiredService<RoleManager<AppRole>>();
        foreach (var name in Roles.All)
        {
            if (!await roles.RoleExistsAsync(name))
            {
                await roles.CreateAsync(new AppRole(name));
                logger.LogInformation("Created role {Role}.", name);
            }
        }

        var configuration = provider.GetRequiredService<IConfiguration>();
        var email = configuration["Seed:AdminEmail"];
        var password = configuration["Seed:AdminPassword"];

        // No credentials configured means no admin is created, and that is the
        // right default. A hardcoded fallback admin is how a development password
        // ends up live in production, and the account it creates is the first thing
        // anyone scanning the internet tries.
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            logger.LogInformation(
                "No Seed:AdminEmail and Seed:AdminPassword configured, so no admin account was " +
                "created. Set them with dotnet user-secrets to get one.");
            return;
        }

        var users = provider.GetRequiredService<UserManager<AppUser>>();
        var admin = await users.FindByEmailAsync(email);

        if (admin is null)
        {
            admin = new AppUser
            {
                UserName = email,
                Email = email,
                DisplayName = "Seed Admin",
                EmailConfirmed = true,
                CreatedAt = provider.GetRequiredService<TimeProvider>().GetUtcNow(),
            };

            var created = await users.CreateAsync(admin, password);
            if (!created.Succeeded)
            {
                logger.LogError(
                    "Could not create the seed admin: {Errors}",
                    string.Join("; ", created.Errors.Select(e => e.Description)));
                return;
            }

            logger.LogInformation("Created the seed admin {Email}.", email);
        }

        foreach (var role in Roles.All)
        {
            if (!await users.IsInRoleAsync(admin, role))
            {
                await users.AddToRoleAsync(admin, role);
            }
        }
    }
}
