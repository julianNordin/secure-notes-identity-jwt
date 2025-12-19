namespace SecureNotes.Api.Common.Authorization;

public static class Policies
{
    /// <summary>Membership of the Admin role, expressed as a policy.</summary>
    /// <remarks>
    /// The same rule as [Authorize(Roles = "Admin")], written the other way so the
    /// two forms sit side by side and can be compared. A role is just a claim with
    /// an attribute that knows its name; the moment a rule needs to say anything
    /// other than "is a member of", the attribute has run out of road and a policy
    /// has not.
    /// </remarks>
    public const string RequireAdmin = "RequireAdmin";

    /// <summary>Confirmed email, or an account still inside the grace period.</summary>
    public const string CanWriteNotes = "CanWriteNotes";

    /// <summary>How long a new account may write before confirming its address.</summary>
    public static readonly TimeSpan ConfirmationGrace = TimeSpan.FromDays(7);
}
