namespace SecureNotes.Api.Common;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    /// <summary>The value shipped in .env.example. Treated as "unset".</summary>
    public const string PlaceholderKey = "replace-me-with-at-least-32-bytes-of-random-data";

    /// <summary>
    /// HS256 is HMAC-SHA256, whose block size is 256 bits. A key shorter than that
    /// is stretched to fit, so a short key does not fail loudly - it just quietly
    /// provides less security than the algorithm's name implies.
    /// </summary>
    public const int MinimumKeyBytes = 32;

    public string Issuer { get; init; } = "secure-notes";

    public string Audience { get; init; } = "secure-notes";

    /// <summary>
    /// Never read from a tracked file. `dotnet user-secrets` in development,
    /// Jwt__SigningKey in the environment everywhere else.
    /// </summary>
    public string SigningKey { get; init; } = string.Empty;

    /// <summary>
    /// Short on purpose. An access token cannot be recalled once issued, so its
    /// lifetime is the window an attacker gets with a stolen one. Phase 07's
    /// refresh tokens are what make a short window tolerable to use.
    /// </summary>
    public int AccessTokenMinutes { get; init; } = 15;
}
