using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using SecureNotes.Api.Domain;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests.Auth;

/// <summary>
/// Lockout is what stops an online password guess from simply continuing. It works
/// only because login goes through SignInManager.CheckPasswordSignInAsync with
/// lockoutOnFailure: true - UserManager.CheckPasswordAsync never touches
/// AccessFailedCount, and an API built on it has a lockout policy configured and no
/// lockout at all.
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class LockoutTests(NotesApiFactory factory) : ApiTestBase(factory)
{
    private static async Task<HttpResponseMessage> AttemptAsync(
        HttpClient client, string email, string password) =>
        await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, password));

    private Task<AppUser> ReadUserAsync(Guid id) =>
        Factory.WithDbAsync(db => db.Users.AsNoTracking().SingleAsync(u => u.Id == id));

    [Fact]
    public async Task Login_CountsFailuresAndThenLocks_WhenThePasswordIsWrongFiveTimes()
    {
        using var account = await Factory.RegisterAndLoginAsync();
        using var client = Factory.CreateClient();

        for (var i = 0; i < 4; i++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized,
                (await AttemptAsync(client, account.Email, "wrong")).StatusCode);
        }

        var beforeLocking = await ReadUserAsync(account.UserId);
        Assert.Equal(4, beforeLocking.AccessFailedCount);
        Assert.Null(beforeLocking.LockoutEnd);

        await AttemptAsync(client, account.Email, "wrong");

        // Identity resets the counter to zero at the moment it sets LockoutEnd, so
        // the lock is the thing to assert here and the count is not.
        var locked = await ReadUserAsync(account.UserId);
        Assert.NotNull(locked.LockoutEnd);
        Assert.True(locked.LockoutEnd > DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// A locked account answers a correct password exactly the way it answers a
    /// wrong one. A distinct "your account is locked" status would confirm that the
    /// address has an account and that the password just tried was the right one -
    /// an oracle handed to the very attacker who caused the lock.
    /// </summary>
    [Fact]
    public async Task Login_ReturnsTheSameResponseAsAWrongPassword_WhenTheAccountIsLockedOut()
    {
        using var account = await Factory.RegisterAndLoginAsync();
        using var client = Factory.CreateClient();

        HttpResponseMessage? wrong = null;
        for (var i = 0; i < 5; i++)
        {
            wrong = await AttemptAsync(client, account.Email, "wrong");
        }

        var correct = await AttemptAsync(client, account.Email, account.Password);

        Assert.Equal(HttpStatusCode.Unauthorized, correct.StatusCode);
        Assert.Equal(wrong!.StatusCode, correct.StatusCode);

        var body = await correct.Content.ReadAsStringAsync();
        Assert.Contains("Invalid credentials.", body);
        Assert.Equal(await wrong.Content.ReadAsStringAsync(), body);
    }

    /// <summary>
    /// The lock is temporary, and this proves it releases rather than merely that it
    /// engaged - a lockout that never lifted would be a denial of service anybody
    /// could inflict on anybody else by guessing wrong five times.
    /// </summary>
    /// <remarks>
    /// The window is moved by rewinding LockoutEnd in the database rather than by a
    /// fake clock, because Identity 9.0.1 does not take one: neither UserManager nor
    /// SignInManager has a TimeProvider anywhere on it, so the fifteen minutes are
    /// measured against DateTimeOffset.UtcNow and nothing in this suite can move it.
    /// Sleeping through a real fifteen minutes is not a test anybody would run. What
    /// is asserted is therefore what this project owns - that login consults
    /// LockoutEnd and lets the account back in once it has passed - and not
    /// Identity's own arithmetic for choosing that value.
    /// </remarks>
    [Fact]
    public async Task Login_Returns200_WhenTheLockoutWindowHasPassed()
    {
        using var account = await Factory.RegisterAndLoginAsync();
        using var client = Factory.CreateClient();

        for (var i = 0; i < 5; i++)
        {
            await AttemptAsync(client, account.Email, "wrong");
        }

        Assert.Equal(HttpStatusCode.Unauthorized,
            (await AttemptAsync(client, account.Email, account.Password)).StatusCode);

        await Factory.WithDbAsync(db => db.Users
            .Where(u => u.Id == account.UserId)
            .ExecuteUpdateAsync(set => set.SetProperty(
                u => u.LockoutEnd, DateTimeOffset.UtcNow.AddMinutes(-1))));

        Assert.Equal(HttpStatusCode.OK,
            (await AttemptAsync(client, account.Email, account.Password)).StatusCode);
    }

    /// <summary>
    /// Lockout is per account. If it were not, one attacker guessing at one address
    /// could lock every user out of the system at once.
    /// </summary>
    [Fact]
    public async Task Login_LeavesOtherAccountsUnlocked_WhenOneIsLockedOut()
    {
        using var target = await Factory.RegisterAndLoginAsync();
        using var bystander = await Factory.RegisterAndLoginAsync();
        using var client = Factory.CreateClient();

        for (var i = 0; i < 5; i++)
        {
            await AttemptAsync(client, target.Email, "wrong");
        }

        using var other = Factory.CreateClient();
        Assert.Equal(HttpStatusCode.OK,
            (await AttemptAsync(other, bystander.Email, bystander.Password)).StatusCode);
    }
}
