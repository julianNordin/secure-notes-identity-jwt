namespace SecureNotes.Api.Domain;

/// <summary>
/// A long-lived credential that can be exchanged for a new access token.
/// </summary>
/// <remarks>
/// One row per issued token, kept after revocation rather than deleted, because
/// the history is what makes it possible to notice a stolen token being replayed.
/// </remarks>
public class RefreshToken
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public required string Token { get; set; }

    /// <summary>
    /// Every token descended from one login shares a family id. Rotation issues a
    /// new token into the same family, so a whole login session can be revoked in
    /// one statement.
    /// </summary>
    public Guid FamilyId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Null while the token is live. Set on rotation, logout or revocation.</summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>The token issued in this one's place, so the chain can be walked.</summary>
    public string? ReplacedByToken { get; set; }

    /// <summary>Recorded for the audit trail, never for authorization decisions.</summary>
    public string? CreatedByIp { get; set; }

    public AppUser? User { get; set; }

    public bool IsActive(DateTimeOffset now) => RevokedAt is null && ExpiresAt > now;
}
