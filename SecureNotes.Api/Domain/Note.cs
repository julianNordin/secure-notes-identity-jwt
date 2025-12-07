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
    /// A real foreign key to AspNetUsers, cascading on delete. There is no
    /// navigation property back to the user: nothing in this project loads a note
    /// in order to reach its owner, and an unused navigation is one more way for
    /// a serialiser to wander into data the caller was never authorised to see.
    /// </remarks>
    public Guid OwnerId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}
