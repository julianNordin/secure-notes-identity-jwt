using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests.Auth;

[Collection(ApiCollection.Name)]
public sealed class RegistrationTests(NotesApiFactory factory) : ApiTestBase(factory)
{
    private const string Password = "correct horse battery staple";

    [Fact]
    public async Task Register_Returns202_WhenTheAddressIsNew()
    {
        using var client = Factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/auth/register", new RegisterRequest("ada@securenotes.test", Password, "Ada"));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
    }

    /// <summary>
    /// The anti-enumeration guarantee from Phase 04, asserted rather than asserted
    /// about. A different status, or the same status with a different body, would
    /// turn this endpoint into a free directory of who has an account here.
    /// </summary>
    [Fact]
    public async Task Register_ReturnsAByteIdenticalResponse_WhenTheAddressIsAlreadyRegistered()
    {
        using var client = Factory.CreateClient();
        var request = new RegisterRequest("ada@securenotes.test", Password, "Ada");

        var first = await client.PostAsJsonAsync("/api/auth/register", request);
        var second = await client.PostAsJsonAsync("/api/auth/register", request);

        Assert.Equal(first.StatusCode, second.StatusCode);
        Assert.Equal(
            await first.Content.ReadAsStringAsync(),
            await second.Content.ReadAsStringAsync());
    }

    /// <summary>
    /// The other half of the same claim: hiding the duplicate from the caller must
    /// not mean accepting it. One address, one account.
    /// </summary>
    [Fact]
    public async Task Register_CreatesOneAccount_WhenTheSameAddressRegistersTwice()
    {
        using var client = Factory.CreateClient();
        var request = new RegisterRequest("ada@securenotes.test", Password, "Ada");

        await client.PostAsJsonAsync("/api/auth/register", request);
        await client.PostAsJsonAsync("/api/auth/register", request);

        var count = await Factory.WithDbAsync(db =>
            db.Users.CountAsync(u => u.NormalizedEmail == "ADA@SECURENOTES.TEST"));

        Assert.Equal(1, count);
    }

    // Validation failures are a different thing from account existence and stay
    // visible: the caller can act on "that is not an email address", and it reveals
    // nothing about who is registered.
    [Theory]
    [InlineData("ada@securenotes.test", "short", "a password under twelve characters")]
    [InlineData("not-an-email", "correct horse battery staple", "a malformed address")]
    [InlineData("", "correct horse battery staple", "an empty address")]
    public async Task Register_Returns400_When(string email, string password, string _)
    {
        using var client = Factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/auth/register", new RegisterRequest(email, password, "Ada"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// Two accounts, one password, two different hashes - which is what a per-user
    /// salt is for. Without one, a stolen table tells an attacker which accounts
    /// share a password, and one cracked hash unlocks all of them at once.
    /// </summary>
    [Fact]
    public async Task Register_StoresADifferentHashForEachAccount_WhenTwoAccountsShareAPassword()
    {
        using var client = Factory.CreateClient();
        await client.PostAsJsonAsync("/api/auth/register", new RegisterRequest("one@securenotes.test", Password, "One"));
        await client.PostAsJsonAsync("/api/auth/register", new RegisterRequest("two@securenotes.test", Password, "Two"));

        var hashes = await Factory.WithDbAsync(db => db.Users
            .Where(u => u.Email != NotesApiFactory.AdminEmail)
            .Select(u => u.PasswordHash!)
            .ToListAsync());

        Assert.Equal(2, hashes.Count);
        Assert.NotEqual(hashes[0], hashes[1]);
        Assert.All(hashes, hash => Assert.DoesNotContain(Password, hash));
    }
}
