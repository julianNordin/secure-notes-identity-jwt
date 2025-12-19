using Microsoft.AspNetCore.Authorization;
using SecureNotes.Api.Services;

namespace SecureNotes.Api.Common.Authorization;

/// <summary>
/// The caller may write if their email is confirmed, or if their account is still
/// inside the grace period.
/// </summary>
/// <remarks>
/// A real product rule rather than a demonstration. Demanding confirmation before
/// anyone can do anything makes a broken confirmation email a total outage; never
/// demanding it means the address on file is decorative and password reset has
/// nothing trustworthy to send to. The grace period is the compromise: new
/// accounts work immediately, and the rule bites once there has been ample
/// opportunity to confirm.
/// </remarks>
public sealed class EmailConfirmationRequirement(TimeSpan grace) : IAuthorizationRequirement
{
    public TimeSpan Grace { get; } = grace;
}

/// <remarks>
/// Takes TimeProvider by constructor injection rather than reading
/// DateTimeOffset.UtcNow, so Phase 16 can test the boundary with a FakeTimeProvider
/// instead of waiting a week.
/// </remarks>
public sealed class EmailConfirmationHandler(TimeProvider clock)
    : AuthorizationHandler<EmailConfirmationRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, EmailConfirmationRequirement requirement)
    {
        if (context.User.FindFirst(TokenService.EmailVerifiedClaim)?.Value == "true")
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        var createdAt = context.User.FindFirst(TokenService.CreatedAtClaim)?.Value;

        // No parseable created_at means the token was not minted by this
        // application's TokenService. Say nothing and let the requirement fail: a
        // handler that guesses in the caller's favour is one that can be talked out
        // of its own rule.
        if (!long.TryParse(createdAt, out var unixSeconds))
        {
            return Task.CompletedTask;
        }

        if (clock.GetUtcNow() - DateTimeOffset.FromUnixTimeSeconds(unixSeconds) <= requirement.Grace)
        {
            context.Succeed(requirement);
        }

        // Not calling Fail(). Succeed and Fail are not opposites: Fail is a veto no
        // other handler can undo, and this handler only knows that it personally
        // cannot approve the request. Simply not succeeding leaves the decision to
        // the rest of the pipeline, which is what a handler should do.
        return Task.CompletedTask;
    }
}
