namespace SecureNotes.Api.Common;

/// <summary>
/// The two roles this application has.
/// </summary>
/// <remarks>
/// Constants rather than string literals scattered through attributes, because a
/// typo in [Authorize(Roles = "Admn")] does not fail to compile, does not fail to
/// start, and does not fail any test that only checks a non-admin is refused. It
/// fails open, silently, for exactly the people it was meant to stop.
/// </remarks>
public static class Roles
{
    public const string Admin = "Admin";

    public const string User = "User";

    public static readonly string[] All = [Admin, User];
}
