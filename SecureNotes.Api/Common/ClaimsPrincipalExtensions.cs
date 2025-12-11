using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;

namespace SecureNotes.Api.Common;

public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// The caller's user id, read from the <c>sub</c> claim.
    /// </summary>
    /// <remarks>
    /// Reads <c>sub</c> and nothing else, deliberately. This only works because
    /// JwtBearerOptions.MapInboundClaims is false; left at its default of true the
    /// handler rewrites <c>sub</c> to the WS-Federation nameidentifier URI and this
    /// lookup returns null. A fallback to ClaimTypes.NameIdentifier would paper over
    /// that misconfiguration instead of surfacing it, and every authorization
    /// decision in this project is downstream of this one value.
    /// </remarks>
    public static Guid GetUserId(this ClaimsPrincipal principal)
    {
        var raw = principal.FindFirstValue(JwtRegisteredClaimNames.Sub);

        if (!Guid.TryParse(raw, out var id))
        {
            throw new InvalidOperationException(
                "The authenticated principal has no parseable 'sub' claim. Check that " +
                "JwtBearerOptions.MapInboundClaims is false and that TokenService still " +
                "writes the user id to 'sub'.");
        }

        return id;
    }
}
