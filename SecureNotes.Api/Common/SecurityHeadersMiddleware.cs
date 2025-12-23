namespace SecureNotes.Api.Common;

/// <summary>
/// Adds the response headers a browser needs in order to defend itself.
/// </summary>
/// <remarks>
/// Cheap, and each one closes a specific hole. They are set before the response
/// starts rather than after, because once the first byte is written the headers
/// have already gone.
/// </remarks>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    public Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;

        // Stops a browser guessing that a JSON response it was told is JSON might
        // really be HTML or script. Content sniffing is how a stored note full of
        // markup becomes a stored XSS.
        headers["X-Content-Type-Options"] = "nosniff";

        // This API is never legitimately framed, and refusing outright removes
        // clickjacking without needing to reason about which parent is acceptable.
        headers["X-Frame-Options"] = "DENY";

        // A URL here can carry a password reset token. Without this, that token
        // travels in the Referer header to whatever the page links to next.
        headers["Referrer-Policy"] = "no-referrer";

        // The API returns JSON, so the only page a browser renders from this origin
        // is Swagger. default-src 'self' plus the two relaxations Swagger UI needs
        // for its inline initialiser and its inline styles. Not a policy worth
        // copying to an app that serves real HTML - it is as narrow as this one can be.
        headers["Content-Security-Policy"] =
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

        return next(context);
    }
}
