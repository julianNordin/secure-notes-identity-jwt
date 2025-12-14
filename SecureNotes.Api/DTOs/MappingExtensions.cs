using SecureNotes.Api.Domain;

namespace SecureNotes.Api.DTOs;

/// <summary>
/// Hand-written mapping, deliberately. A mapping library would save a few lines
/// and cost the guarantee that matters most here: that OwnerId cannot reach a
/// response by accident, because nothing in this file puts it there.
/// </summary>
public static class MappingExtensions
{
    public static NoteResponse ToResponse(this Note note) =>
        new(note.Id, note.Title, note.Content, note.CreatedAt, note.UpdatedAt);
}
