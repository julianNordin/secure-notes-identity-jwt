namespace SecureNotes.Api.DTOs;

/// <summary>
/// A note as an admin sees it: the same fields as a normal note response, plus
/// who owns it.
/// </summary>
/// <remarks>
/// A separate record rather than an owner field on NoteResponse that happens to be
/// null for everyone else. If one type served both, the only thing keeping owner
/// identities out of ordinary responses would be remembering to null the field,
/// and that is a guarantee nobody can audit.
/// </remarks>
public record AdminNoteResponse(
    Guid Id,
    string Title,
    string Content,
    Guid OwnerId,
    string OwnerEmail,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public record AdminUserResponse(
    Guid Id,
    string Email,
    string? DisplayName,
    bool EmailConfirmed,
    bool LockedOut,
    DateTimeOffset CreatedAt,
    IReadOnlyCollection<string> Roles);
