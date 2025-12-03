namespace SecureNotes.Api.Domain;

/// <summary>
/// A note belonging to exactly one user.
/// </summary>
/// <remarks>
/// The domain is deliberately thin. This project is about who is allowed to touch
/// a note, not about what a note is, and anything richer here would compete for
/// attention with the authorization code that is the point.
/// </remarks>
public class Note
{
    public Guid Id { get; set; }

    public required string Title { get; set; }

    public required string Content { get; set; }

    /// <summary>
    /// The owning user.
    /// </summary>
    /// <remarks>
    /// A bare Guid rather than a navigation property, because there is no user
    /// table to point at yet. ASP.NET Core Identity arrives in Phase 03 and the
    /// real foreign key is added there.
    /// </remarks>
    public Guid OwnerId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}
