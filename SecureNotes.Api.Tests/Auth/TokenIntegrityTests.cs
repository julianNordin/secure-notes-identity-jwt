using System.Net;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SecureNotes.Api.Services;
using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests.Auth;

/// <summary>
/// Everything the JwtBearer configuration in Program.cs claims to reject, rejected.
/// Each test changes exactly one thing about a token that otherwise works.
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class TokenIntegrityTests(NotesApiFactory factory) : ApiTestBase(factory)
{
    private static async Task<HttpStatusCode> CallMeAsync(NotesApiFactory factory, string token)
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", token);

        return (await client.GetAsync("/api/auth/me")).StatusCode;
    }

    /// <summary>Rebuilds a token from an issued one, varying one thing.</summary>
    private static string Mint(string issued, string key, Action<SecurityTokenDescriptor> vary)
    {
        var original = new JsonWebToken(issued);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = original.Issuer,
            Audience = original.Audiences.Single(),
            IssuedAt = DateTime.UtcNow,
            NotBefore = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddMinutes(15),
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = original.Subject,
                [JwtRegisteredClaimNames.Email] = original.GetClaim(JwtRegisteredClaimNames.Email).Value,
                [TokenService.SecurityStampClaim] = original.GetClaim(TokenService.SecurityStampClaim).Value,
                [TokenService.RoleClaim] = new[] { original.GetClaim(TokenService.RoleClaim).Value },
            },
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), SecurityAlgorithms.HmacSha256),
        };

        vary(descriptor);
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    /// <summary>
    /// The control, and the reason the rest of this class means anything. A token
    /// this helper mints with nothing varied is accepted, so a 401 in the tests
    /// below is caused by the one thing they changed and not by a broken helper.
    /// </summary>
    [Fact]
    public async Task Me_Returns200_WhenTheTestMintsATokenWithNothingVaried()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var token = Mint(account.AccessToken, NotesApiFactory.SigningKey, _ => { });

        Assert.Equal(HttpStatusCode.OK, await CallMeAsync(Factory, token));
    }

    /// <summary>
    /// The privilege escalation an unsigned or badly validated JWT would allow:
    /// take a real token, rewrite the role claim to Admin, keep the signature.
    /// </summary>
    [Fact]
    public async Task Me_Returns401_WhenThePayloadIsEditedAndTheSignatureKept()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var parts = account.AccessToken.Split('.');
        var payload = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(parts[1]));
        var escalated = payload.Replace("[\"User\"]", "[\"Admin\"]");
        Assert.NotEqual(payload, escalated);

        parts[1] = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(escalated));
        var forged = string.Join('.', parts);

        Assert.Equal(HttpStatusCode.Unauthorized, await CallMeAsync(Factory, forged));
    }

    /// <summary>
    /// A well-formed token signed by somebody else. This is the one that matters if
    /// a signing key ever leaks into a repository.
    /// </summary>
    [Fact]
    public async Task Me_Returns401_WhenTheTokenIsSignedWithAnAttackersKey()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var token = Mint(account.AccessToken, "an attackers key, also at least thirty-two bytes", _ => { });

        Assert.Equal(HttpStatusCode.Unauthorized, await CallMeAsync(Factory, token));
    }

    /// <summary>
    /// alg:none is the classic. ValidAlgorithms is an explicit allow-list of one,
    /// which is what makes this unreachable rather than merely unlikely - the token
    /// is refused on its header, before its signature is even considered.
    /// </summary>
    [Fact]
    public async Task Me_Returns401_WhenTheTokenClaimsAlgNone()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var header = WebEncoders.Base64UrlEncode(
            Encoding.UTF8.GetBytes("{\"alg\":\"none\",\"typ\":\"JWT\"}"));
        var payload = account.AccessToken.Split('.')[1];

        Assert.Equal(HttpStatusCode.Unauthorized, await CallMeAsync(Factory, $"{header}.{payload}."));
    }

    [Fact]
    public async Task Me_Returns401_WhenTheSignatureIsStripped()
    {
        using var account = await Factory.RegisterAndLoginAsync();
        var parts = account.AccessToken.Split('.');

        Assert.Equal(HttpStatusCode.Unauthorized, await CallMeAsync(Factory, $"{parts[0]}.{parts[1]}."));
    }

    [Fact]
    public async Task Me_Returns401_WhenTheIssuerIsNotOurs()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var token = Mint(account.AccessToken, NotesApiFactory.SigningKey, d => d.Issuer = "https://evil.example");

        Assert.Equal(HttpStatusCode.Unauthorized, await CallMeAsync(Factory, token));
    }

    /// <summary>
    /// A token minted for a different audience is a token meant for a different
    /// service, and accepting one is how a token stolen from somewhere else works
    /// here too.
    /// </summary>
    [Fact]
    public async Task Me_Returns401_WhenTheAudienceIsNotOurs()
    {
        using var account = await Factory.RegisterAndLoginAsync();

        var token = Mint(account.AccessToken, NotesApiFactory.SigningKey, d => d.Audience = "some-other-service");

        Assert.Equal(HttpStatusCode.Unauthorized, await CallMeAsync(Factory, token));
    }

    /// <summary>
    /// Expiry, without a suite that sleeps. The clock is wound back twenty minutes
    /// before logging in, so TokenService stamps exp fifteen minutes after that -
    /// five minutes ago in real terms - while the handler validates against the real
    /// clock with ClockSkew set to zero. A five-minute default skew would have let
    /// this pass, which is why the default is not left in place.
    /// </summary>
    [Fact]
    public async Task Me_Returns401_WhenTheAccessTokenHasExpired()
    {
        Factory.RebindClock(DateTimeOffset.UtcNow.AddMinutes(-20));

        using var account = await Factory.RegisterAndLoginAsync();

        var token = new JsonWebToken(account.AccessToken);
        Assert.True(token.ValidTo < DateTime.UtcNow, "the minted token should already be expired");

        Assert.Equal(HttpStatusCode.Unauthorized, await CallMeAsync(Factory, account.AccessToken));
    }
}
