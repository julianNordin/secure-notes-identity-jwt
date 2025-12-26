using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SecureNotes.Api.Domain;
using SecureNotes.Api.DTOs;

namespace SecureNotes.Api.Tests.TestHelpers;

public static class ApiFactoryExtensions
{
    /// <summary>Clears the configured twelve-character minimum.</summary>
    public const string DefaultPassword = "correct horse battery staple";

    /// <summary>
    /// Registers a fresh account through the real endpoint, optionally grants it a
    /// role or confirms its address, logs it in, and returns a client already
    /// carrying the bearer token.
    /// </summary>
    public static async Task<AuthenticatedClient> RegisterAndLoginAsync(
        this NotesApiFactory factory,
        string? role = null,
        bool confirmEmail = false,
        string password = DefaultPassword)
    {
        // A new address per call. Sharing one between tests would make them pass or
        // fail depending on which ran first, which is the failure mode the database
        // reset exists to prevent - reintroducing it in the helper would be a poor
        // trade for a shorter string.
        var email = $"user-{Guid.NewGuid():N}@securenotes.test";

        var client = factory.CreateClient();

        var registration = await client.PostAsJsonAsync(
            "/api/auth/register", new RegisterRequest(email, password, "Test User"));
        await EnsureStatusAsync(registration, HttpStatusCode.Accepted);

        var userId = await ApplyOutOfBandSetupAsync(factory, email, role, confirmEmail);

        return await SignInAsync(factory, client, userId, email, password);
    }

    /// <summary>
    /// Logs in the admin DbInitializer seeds, rather than making an admin by hand.
    /// </summary>
    public static async Task<AuthenticatedClient> LoginAsSeedAdminAsync(this NotesApiFactory factory)
    {
        var client = factory.CreateClient();

        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
        var admin = await users.FindByEmailAsync(NotesApiFactory.AdminEmail)
            ?? throw new InvalidOperationException(
                "DbInitializer did not seed an admin. Seed__AdminEmail and Seed__AdminPassword " +
                "are set in NotesApiFactory.InitializeAsync, and ResetDatabaseAsync re-seeds.");

        return await SignInAsync(
            factory, client, admin.Id, NotesApiFactory.AdminEmail, NotesApiFactory.AdminPassword);
    }

    private static async Task<AuthenticatedClient> SignInAsync(
        NotesApiFactory factory, HttpClient client, Guid userId, string email, string password)
    {
        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, password));
        await EnsureStatusAsync(response, HttpStatusCode.OK);

        var tokens = await response.Content.ReadFromJsonAsync<TokenResponse>()
            ?? throw new InvalidOperationException("Login succeeded and returned no token payload.");

        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        return new AuthenticatedClient(client, userId, email, password, tokens);
    }

    /// <summary>
    /// Grants a role and confirms an address through UserManager rather than over
    /// HTTP, and returns the new account's id.
    /// </summary>
    /// <remarks>
    /// Out of band on purpose. Registration answers 202 whether or not the address
    /// was new and deliberately reveals nothing else, so it cannot tell a test which
    /// user it just made. There is also no endpoint that grants a role, and there
    /// should not be one. Both still go through UserManager rather than raw SQL, so
    /// the normalised columns and the security stamp are maintained the same way the
    /// application maintains them.
    /// </remarks>
    private static async Task<Guid> ApplyOutOfBandSetupAsync(
        NotesApiFactory factory, string email, string? role, bool confirmEmail)
    {
        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();

        var user = await users.FindByEmailAsync(email)
            ?? throw new InvalidOperationException($"Registration did not create {email}.");

        if (confirmEmail)
        {
            // The real token round trip rather than setting the flag, so a change
            // that breaks confirmation breaks the tests that depend on it.
            var token = await users.GenerateEmailConfirmationTokenAsync(user);
            var confirmed = await users.ConfirmEmailAsync(user, token);
            if (!confirmed.Succeeded)
            {
                throw new InvalidOperationException(
                    $"Could not confirm {email}: {string.Join("; ", confirmed.Errors.Select(e => e.Description))}");
            }
        }

        if (role is not null && !await users.IsInRoleAsync(user, role))
        {
            await users.AddToRoleAsync(user, role);
        }

        return user.Id;
    }

    /// <summary>
    /// Fails with the status and the body when setup does not go as expected.
    /// </summary>
    /// <remarks>
    /// Worth the few lines. When setup breaks, the alternative is a
    /// NullReferenceException from deserialising a response that was never a token,
    /// several frames away from the request that actually failed.
    /// </remarks>
    private static async Task EnsureStatusAsync(HttpResponseMessage response, HttpStatusCode expected)
    {
        if (response.StatusCode == expected)
        {
            return;
        }

        throw new InvalidOperationException(
            $"{response.RequestMessage?.Method} {response.RequestMessage?.RequestUri} expected " +
            $"{(int)expected} and returned {(int)response.StatusCode}. Body: " +
            await response.Content.ReadAsStringAsync());
    }
}
