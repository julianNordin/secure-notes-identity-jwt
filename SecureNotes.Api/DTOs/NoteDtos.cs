namespace SecureNotes.Api.DTOs;

public record NoteResponse(
    Guid Id,
    string Title,
    string Content,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public record CreateNoteRequest(string Title, string Content);

public record UpdateNoteRequest(string Title, string Content);

/// <summary>
/// A page of results.
/// </summary>
/// <remarks>
/// A wrapper rather than a bare array, because a bare array leaves the client no
/// way to know whether it has seen everything, and no way to ask for the rest.
/// </remarks>
public record PagedResponse<T>(
    IReadOnlyCollection<T> Items,
    int Page,
    int PageSize,
    int TotalCount,
    int TotalPages);
