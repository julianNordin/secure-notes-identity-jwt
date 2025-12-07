using Microsoft.AspNetCore.Identity;

namespace SecureNotes.Api.Domain;

/// <summary>
/// An application role. Two exist: Admin and User, seeded in Phase 09.
/// </summary>
/// <remarks>
/// This type adds nothing to <see cref="IdentityRole{TKey}"/> today. It exists so
/// that the key type is Guid like everything else, and so that there is somewhere
/// to put a description or a display name later without a migration that changes
/// a framework table's identity.
/// </remarks>
public class AppRole : IdentityRole<Guid>
{
    public AppRole()
    {
    }

    public AppRole(string roleName) : base(roleName)
    {
    }
}
