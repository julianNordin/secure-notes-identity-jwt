using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace SecureNotes.Api.Common;

/// <summary>
/// Encodes and decodes Identity's confirmation and reset tokens for transport.
/// </summary>
/// <remarks>
/// Identity's tokens are protected binary rendered as base64, which contains
/// <c>+</c> and <c>/</c> and trailing <c>=</c>. Put one in a URL unchanged and
/// <c>+</c> is decoded as a space on the way back, so the token arrives subtly
/// corrupted and Identity rejects it as invalid. The symptom is a confirmation link
/// that fails for no visible reason while the token in the log looks right, and it
/// is worth encoding even for tokens sent in a JSON body, because the link in the
/// email is the case that matters and one codec is easier to trust than two rules.
/// </remarks>
public static class IdentityTokenCodec
{
    public static string Encode(string token) =>
        WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

    /// <summary>Returns null if the value is not decodable, which callers treat as an invalid token.</summary>
    public static string? Decode(string encoded)
    {
        try
        {
            return Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(encoded));
        }
        catch (FormatException)
        {
            // Garbage in, "invalid token" out. A 500 here would turn a malformed
            // link into an error report, and would tell a prober that their input
            // reached something interesting.
            return null;
        }
    }
}
