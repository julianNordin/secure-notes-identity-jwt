using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.JsonWebTokens;
using SecureNotes.Api.Domain;
using SecureNotes.Api.Services;

namespace SecureNotes.Api.Common;

/// <summary>
/// Rejects an access token whose security stamp no longer matches the account.
/// </summary>
/// <remarks>
/// <para>
/// A signed JWT is valid until it expires and there is no way to recall one. That
/// is the whole reason the access token lifetime is fifteen minutes. This closes
/// the gap for the cases that actually matter: Identity rolls the security stamp
/// on password change, and logout-all rolls it deliberately, so every token issued
/// before that moment stops working on its next request rather than up to fifteen
/// minutes later.
/// </para>
/// <para>
/// The cost is one indexed read per authenticated request. That is a real price
/// and it is worth naming: it trades the main advantage of stateless tokens for
/// the ability to revoke them. For this API, where a compromised session is the
/// threat the whole project is about, that is the right way round.
/// </para>
/// </remarks>
public static class SecurityStampCheck
{
    public static async Task ValidateAsync(TokenValidatedContext context)
    {
        var principal = context.Principal;

        var presented = principal?.FindFirst(TokenService.SecurityStampClaim)?.Value;
        var subject = principal?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

        if (presented is null || subject is null)
        {
            // A signature-valid token missing either claim was minted by something
            // that is not this application's TokenService.
            context.Fail("The token is missing the claims this application issues.");
            return;
        }

        var users = context.HttpContext.RequestServices.GetRequiredService<UserManager<AppUser>>();
        var user = await users.FindByIdAsync(subject);

        if (user is null)
        {
            // The account was deleted while a token was still live.
            context.Fail("The account this token identifies no longer exists.");
            return;
        }

        // Ordinal, not culture-aware. This is an opaque identifier, and a
        // culture-sensitive comparison on one is a bug waiting for a locale change.
        if (!string.Equals(user.SecurityStamp, presented, StringComparison.Ordinal))
        {
            context.Fail("The security stamp on this token no longer matches the account.");
        }
    }
}
