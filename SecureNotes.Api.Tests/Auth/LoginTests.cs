using System.Net;
using System.Net.Http.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using SecureNotes.Api.Common;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Services;
using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests.Auth;

[Collection(ApiCollection.Name)]
public sealed class LoginTests(NotesApiFactory factory) : ApiTestBase(factory)
{
    [Fact]
    public async Task Login_Returns200WithATokenPair_WhenTheCredentialsAreCorrect()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        Assert.NotEmpty(account.AccessToken);
        Assert.NotEmpty(account.RefreshToken);
    }

    /// <summary>
    /// Register, log in, reach a protected route. Reaching /api/auth/me proves the
    /// token was signed by us, has not expired, carries the issuer and audience the
    /// handler expects, and produced a principal with a readable sub claim.
    /// </summary>
    [Fact]
    public async Task Me_Returns200WithTheAccount_WhenTheTokenFromLoginIsPresented()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var response = await account.Client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var me = await response.Content.ReadFromJsonAsync<MeResponse>();
        Assert.Equal(account.UserId, me!.Id);
        Assert.Equal(account.Email, me.Email);
        Assert.Equal([Roles.User], me.Roles);
    }

    /// <summary>
    /// A 401 rather than a 302 to a login page is the proof that AddIdentityCore
    /// kept the cookie schemes out of the default. The WWW-Authenticate header is
    /// what says so.
    /// </summary>
    [Fact]
    public async Task Me_Returns401WithABearerChallenge_WhenNoTokenIsPresented()
    {
        using var client = Factory.CreateClient();

        var response = await client.GetAsync("/api/auth/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Bearer", response.Headers.WwwAuthenticate.ToString());
    }

    /// <summary>
    /// The headline anti-enumeration assertion for login: a wrong password and an
    /// address that has never registered are indistinguishable, byte for byte.
    /// Anything less lets an anonymous caller sort a list of addresses into "banks
    /// here" and "does not".
    /// </summary>
    [Fact]
    public async Task Login_ReturnsAByteIdenticalResponse_WhenThePasswordIsWrongAndWhenTheAddressIsUnknown()
    {
        using var account = await Factory.RegisterAndLoginAsync();
        using var client = Factory.CreateClient();

        var wrongPassword = await client.PostAsJsonAsync(
            "/api/auth/login", new LoginRequest(account.Email, "definitely not the password"));

        var unknownAddress = await client.PostAsJsonAsync(
            "/api/auth/login", new LoginRequest("nobody@securenotes.test", "definitely not the password"));

        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(wrongPassword.StatusCode, unknownAddress.StatusCode);

        var wrongPasswordBody = await wrongPassword.Content.ReadAsStringAsync();

        // Not vacuous: two empty bodies would also be equal, so the body has to be
        // shown to say something before its sameness means anything.
        Assert.Contains("Invalid credentials.", wrongPasswordBody);
        Assert.Equal(wrongPasswordBody, await unknownAddress.Content.ReadAsStringAsync());
    }

    /// <summary>
    /// Pins the claim set the rest of the system reads. sub is the owner id every
    /// authorization decision hangs off, sstamp is what makes revocation possible,
    /// and both policy inputs ride in the token rather than costing a query.
    /// </summary>
    [Fact]
    public async Task Login_IssuesATokenCarryingTheClaimsTheApplicationReads_WhenTheCredentialsAreCorrect()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var token = new JsonWebToken(account.AccessToken);

        Assert.Equal("HS256", token.Alg);
        Assert.Equal(account.UserId.ToString(), token.Subject);
        Assert.Equal(account.Email, token.GetClaim(JwtRegisteredClaimNames.Email).Value);
        Assert.Equal(Roles.User, token.GetClaim(TokenService.RoleClaim).Value);
        Assert.Equal("false", token.GetClaim(TokenService.EmailVerifiedClaim).Value);
        Assert.NotEmpty(token.GetClaim(TokenService.SecurityStampClaim).Value);

        // Fifteen minutes, and short on purpose: an access token cannot be recalled,
        // so its lifetime is the window a stolen one is worth having.
        Assert.Equal(15, (token.ValidTo - token.ValidFrom).TotalMinutes, 1);
    }
}
