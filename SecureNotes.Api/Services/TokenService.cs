using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SecureNotes.Api.Common;
using SecureNotes.Api.Domain;

namespace SecureNotes.Api.Services;

public sealed record AccessToken(string Value, DateTimeOffset ExpiresAt);

public interface ITokenService
{
    AccessToken CreateAccessToken(AppUser user, IReadOnlyCollection<string> roles);
}

public sealed class TokenService(IOptions<JwtOptions> options, TimeProvider clock) : ITokenService
{
    /// <summary>Identity's security stamp, carried so Phase 08 can revoke live tokens.</summary>
    public const string SecurityStampClaim = "sstamp";

    /// <summary>
    /// The short name, not ClaimTypes.Role's WS-Federation URI. Both work as long as
    /// TokenValidationParameters.RoleClaimType agrees; the short one keeps the token
    /// smaller, and a token travels on every single request.
    /// </summary>
    public const string RoleClaim = "role";

    /// <summary>Whether the address on file has been confirmed. Read by the CanWriteNotes policy.</summary>
    public const string EmailVerifiedClaim = "email_verified";

    /// <summary>Account creation time, unix seconds. Read by the CanWriteNotes policy.</summary>
    public const string CreatedAtClaim = "created_at";

    private readonly JwtOptions _options = options.Value;

    public AccessToken CreateAccessToken(AppUser user, IReadOnlyCollection<string> roles)
    {
        var now = clock.GetUtcNow();
        var expires = now.AddMinutes(_options.AccessTokenMinutes);

        // SecurityTokenDescriptor.Claims takes a raw dictionary, which is written to
        // the token verbatim. The alternative, Subject = new ClaimsIdentity(...),
        // runs the outbound claim type map and would silently rewrite "sub" into a
        // WS-Federation URI on the way out.
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Sub] = user.Id.ToString(),
            [JwtRegisteredClaimNames.Email] = user.Email ?? string.Empty,

            // A unique id for this token. Phase 08 needs a handle it can name in a
            // log line when it revokes something.
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),

            // Identity rolls the security stamp on password change and on
            // logout-all. Carrying it here is what lets Phase 08 invalidate an
            // access token that has already been issued - the thing a stateless
            // token is famously unable to do.
            [SecurityStampClaim] = user.SecurityStamp ?? string.Empty,

            [RoleClaim] = roles.ToArray(),

            // Both of these are inputs to an authorization policy, so they ride in
            // the token rather than being looked up per request. They can only go
            // stale for as long as an access token lives, which is fifteen minutes,
            // and confirming an address is not urgent enough to pay a database read
            // on every request the way the security stamp does.
            [EmailVerifiedClaim] = user.EmailConfirmed ? "true" : "false",
            [CreatedAtClaim] = user.CreatedAt.ToUnixTimeSeconds().ToString(),
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            Claims = claims,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey)),
                SecurityAlgorithms.HmacSha256),
        };

        return new AccessToken(new JsonWebTokenHandler().CreateToken(descriptor), expires);
    }
}
