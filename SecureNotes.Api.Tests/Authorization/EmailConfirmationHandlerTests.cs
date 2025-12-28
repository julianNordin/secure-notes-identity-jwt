using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Time.Testing;
using SecureNotes.Api.Common.Authorization;
using SecureNotes.Api.Services;

namespace SecureNotes.Api.Tests.Authorization;

/// <summary>
/// The other fast tier handler, and the one the TimeProvider argument was actually
/// for. The rule it enforces - a confirmed address, or an account young enough not
/// to have been asked yet - has its boundary a week out, and the only reason this
/// file runs in milliseconds rather than taking seven days is that the handler
/// takes its clock by injection instead of reading DateTimeOffset.UtcNow.
/// </summary>
/// <remarks>
/// No host, no container, no HTTP. The requirement is built here exactly as
/// Program.cs builds it and the handler is a plain new, so a failure here names the
/// rule rather than the pipeline around it.
/// </remarks>
public sealed class EmailConfirmationHandlerTests
{
    // Whole seconds, deliberately. created_at rides in the token as unix seconds,
    // so a start instant carrying milliseconds would be rounded on the way through
    // the claim and leave every boundary assertion below off by a fraction.
    private static readonly DateTimeOffset CreatedAt = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // The grace Program.cs wires into the policy, not a number invented here, so
    // this file tests the rule the application actually enforces.
    private static readonly EmailConfirmationRequirement Requirement = new(Policies.ConfirmationGrace);

    private static ClaimsPrincipal Caller(bool? emailVerified, string? createdAt)
    {
        var claims = new List<Claim>();

        if (emailVerified is not null)
        {
            claims.Add(new Claim(
                TokenService.EmailVerifiedClaim, emailVerified.Value ? "true" : "false"));
        }

        if (createdAt is not null)
        {
            claims.Add(new Claim(TokenService.CreatedAtClaim, createdAt));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));
    }

    private static ClaimsPrincipal Unconfirmed(DateTimeOffset createdAt) =>
        Caller(emailVerified: false, createdAt.ToUnixTimeSeconds().ToString());

    private static async Task<AuthorizationHandlerContext> DecideAsync(
        ClaimsPrincipal caller, DateTimeOffset now)
    {
        var context = new AuthorizationHandlerContext([Requirement], caller, resource: null);
        await new EmailConfirmationHandler(new FakeTimeProvider(now)).HandleAsync(context);

        return context;
    }

    /// <summary>
    /// A confirmed address is enough on its own. The handler returns before it ever
    /// looks at created_at, which is why an account ten years old still writes.
    /// </summary>
    [Fact]
    public async Task Handler_Succeeds_WhenTheEmailIsConfirmed()
    {
        var caller = Caller(emailVerified: true, CreatedAt.ToUnixTimeSeconds().ToString());

        var context = await DecideAsync(caller, CreatedAt.AddYears(10));

        Assert.True(context.HasSucceeded);
    }

    /// <summary>
    /// The other half of the compromise: a brand new account writes immediately,
    /// so a confirmation email that never arrives is not a total outage on day one.
    /// </summary>
    [Fact]
    public async Task Handler_Succeeds_WhenTheAccountIsUnconfirmedAndInsideTheGrace()
    {
        var context = await DecideAsync(Unconfirmed(CreatedAt), CreatedAt.AddDays(1));

        Assert.True(context.HasSucceeded);
    }

    /// <summary>
    /// The boundary is inclusive - the comparison is &lt;=, not &lt; - and these two
    /// tests are the only thing holding it there. One tick apart, because a day
    /// apart would pass just as happily against a rule that was a day out.
    /// </summary>
    [Fact]
    public async Task Handler_Succeeds_WhenTheAccountIsExactlyAtTheEdgeOfTheGrace()
    {
        var edge = CreatedAt + Policies.ConfirmationGrace;

        var context = await DecideAsync(Unconfirmed(CreatedAt), edge);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task Handler_DoesNotSucceed_WhenTheAccountIsOneTickPastTheGrace()
    {
        var justPast = CreatedAt + Policies.ConfirmationGrace + TimeSpan.FromTicks(1);

        var context = await DecideAsync(Unconfirmed(CreatedAt), justPast);

        Assert.False(context.HasSucceeded);
    }

    /// <summary>
    /// No created_at means the token was not minted by this application's
    /// TokenService, so there is no age to measure and nothing to be lenient about.
    /// A handler that guesses in the caller's favour is one that can be talked out
    /// of its own rule.
    /// </summary>
    [Fact]
    public async Task Handler_DoesNotSucceed_WhenThereIsNoCreatedAtClaim()
    {
        var context = await DecideAsync(
            Caller(emailVerified: false, createdAt: null), CreatedAt);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task Handler_DoesNotSucceed_WhenTheCreatedAtClaimIsNotANumber()
    {
        var context = await DecideAsync(
            Caller(emailVerified: false, "the first of January"), CreatedAt);

        Assert.False(context.HasSucceeded);
    }

    /// <summary>
    /// An absent claim is not a confirmed address. Worth pinning separately from
    /// the explicit "false" above, because the two arrive by different routes - a
    /// token minted before the claim existed carries no email_verified at all - and
    /// a check written as "not false" would let every one of those through forever.
    /// </summary>
    [Fact]
    public async Task Handler_DoesNotSucceed_WhenTheEmailVerifiedClaimIsMissingAndTheGraceHasPassed()
    {
        var caller = Caller(emailVerified: null, CreatedAt.ToUnixTimeSeconds().ToString());

        var context = await DecideAsync(caller, CreatedAt.AddDays(30));

        Assert.False(context.HasSucceeded);
    }

    /// <summary>
    /// Refusing is not vetoing - the same rule NoteAuthorizationHandler follows, and
    /// worth asserting on both handlers because it is invisible either way today.
    /// Fail() cannot be undone by any other handler, and this one only knows it
    /// cannot personally approve the request. Calling Fail() here would behave
    /// identically until the first day a second handler had something to say.
    /// </summary>
    [Fact]
    public async Task Handler_DoesNotVeto_WhenItRefuses()
    {
        var context = await DecideAsync(
            Unconfirmed(CreatedAt), CreatedAt + Policies.ConfirmationGrace + TimeSpan.FromDays(1));

        Assert.False(context.HasSucceeded);
        Assert.False(context.HasFailed);
    }
}
