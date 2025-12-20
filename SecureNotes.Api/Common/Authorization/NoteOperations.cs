using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace SecureNotes.Api.Common.Authorization;

/// <summary>
/// The things one can do to a note, as authorization requirements.
/// </summary>
/// <remarks>
/// Separate operations rather than a single "may touch this note", because the
/// answer genuinely differs: an admin may read any note, and may not edit or delete
/// one. Collapsing them into one requirement would force that distinction to be
/// re-litigated at every call site.
/// </remarks>
public static class NoteOperations
{
    public static readonly OperationAuthorizationRequirement Read = new() { Name = nameof(Read) };

    public static readonly OperationAuthorizationRequirement Update = new() { Name = nameof(Update) };

    public static readonly OperationAuthorizationRequirement Delete = new() { Name = nameof(Delete) };
}
