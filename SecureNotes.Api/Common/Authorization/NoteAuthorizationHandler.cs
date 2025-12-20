using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.IdentityModel.JsonWebTokens;
using SecureNotes.Api.Domain;

namespace SecureNotes.Api.Common.Authorization;

/// <summary>
/// Decides whether a caller may perform an operation on one specific note.
/// </summary>
/// <remarks>
/// <para>
/// This is the difference between authorization that knows about roles and
/// authorization that knows about things. No policy or attribute can answer "may
/// this caller edit note 47", because the answer depends on the note. The rule
/// lives here, once, and the endpoints ask rather than remember.
/// </para>
/// <para>
/// Admins may read any note and may not edit or delete one. That is a deliberate
/// asymmetry: an administrator needs to be able to see what is in the system to
/// support it and moderate it, and being able to see it is not a reason to be able
/// to silently rewrite it. Widening this later is one line; explaining an edit
/// nobody made is not.
/// </para>
/// </remarks>
public sealed class NoteAuthorizationHandler
    : AuthorizationHandler<OperationAuthorizationRequirement, Note>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        Note resource)
    {
        var subject = context.User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

        if (Guid.TryParse(subject, out var callerId) && callerId == resource.OwnerId)
        {
            // The owner may do anything to their own note.
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        if (requirement.Name == NoteOperations.Read.Name && context.User.IsInRole(Roles.Admin))
        {
            context.Succeed(requirement);
        }

        // No Fail() call. Fail is a veto that no other handler can undo, and this
        // handler only knows that it cannot personally approve the request.
        return Task.CompletedTask;
    }
}
