using Microsoft.AspNetCore.Identity;

namespace SecureNotes.Api.Domain;

/// <summary>
/// The application's user.
/// </summary>
/// <remarks>
/// <para>
/// Identity's <see cref="IdentityUser{TKey}"/> is generic over the key type. Guid
/// is used here rather than the default string because a user id ends up in the
/// <c>sub</c> claim of every access token, and a sequential or guessable id there
/// tells an attacker how many users exist and lets them enumerate them.
/// </para>
/// <para>
/// Nothing sensitive is added to this type. Identity already stores the password
/// hash, the security stamp, the lockout counters and the confirmation flags, and
/// re-implementing any of those is how projects end up with two sources of truth.
/// </para>
/// </remarks>
public class AppUser : IdentityUser<Guid>
{
    public string? DisplayName { get; set; }

    /// <summary>
    /// When the account was created. Read by the MinimumAccountAge policy in Phase 10.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    public ICollection<Note> Notes { get; set; } = [];
}
