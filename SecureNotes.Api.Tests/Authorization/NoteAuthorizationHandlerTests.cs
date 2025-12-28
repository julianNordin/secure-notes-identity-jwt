using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.IdentityModel.JsonWebTokens;
using SecureNotes.Api.Common;
using SecureNotes.Api.Common.Authorization;
using SecureNotes.Api.Domain;
using SecureNotes.Api.Services;

namespace SecureNotes.Api.Tests.Authorization;

/// <summary>
/// The fast tier. No host, no container, no HTTP - which is the entire point of
/// putting the rule in a handler instead of an if statement inside a controller.
/// </summary>
public sealed class NoteAuthorizationHandlerTests
{
    private static readonly Guid OwnerId = Guid.CreateVersion7();

    private static readonly Note Note = new()
    {
        Id = Guid.CreateVersion7(),
        OwnerId = OwnerId,
        Title = "A note",
        Content = "Some content",
    };

    private static ClaimsPrincipal Caller(Guid id, params string[] roles)
    {
        var claims = new List<Claim> { new(JwtRegisteredClaimNames.Sub, id.ToString()) };
        claims.AddRange(roles.Select(role => new Claim(TokenService.RoleClaim, role)));

        // The role claim type has to match what the token carries, or IsInRole
        // silently answers false for somebody who visibly holds the role.
        return new ClaimsPrincipal(new ClaimsIdentity(
            claims, "Test", JwtRegisteredClaimNames.Sub, TokenService.RoleClaim));
    }

    private static async Task<AuthorizationHandlerContext> DecideAsync(
        ClaimsPrincipal caller, OperationAuthorizationRequirement operation)
    {
        var context = new AuthorizationHandlerContext([operation], caller, Note);
        await new NoteAuthorizationHandler().HandleAsync(context);

        return context;
    }

    [Theory]
    [InlineData(nameof(NoteOperations.Read))]
    [InlineData(nameof(NoteOperations.Update))]
    [InlineData(nameof(NoteOperations.Delete))]
    public async Task Handler_Succeeds_WhenTheCallerOwnsTheNote(string operation)
    {
        var context = await DecideAsync(Caller(OwnerId), OperationFor(operation));

        Assert.True(context.HasSucceeded);
    }

    [Theory]
    [InlineData(nameof(NoteOperations.Read))]
    [InlineData(nameof(NoteOperations.Update))]
    [InlineData(nameof(NoteOperations.Delete))]
    public async Task Handler_DoesNotSucceed_WhenTheCallerIsAStranger(string operation)
    {
        var context = await DecideAsync(Caller(Guid.CreateVersion7()), OperationFor(operation));

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task Handler_Succeeds_WhenAnAdminReadsSomebodyElsesNote()
    {
        var context = await DecideAsync(
            Caller(Guid.CreateVersion7(), Roles.Admin), NoteOperations.Read);

        Assert.True(context.HasSucceeded);
    }

    /// <summary>
    /// The deliberate asymmetry, at the level where it is actually decided. An admin
    /// needs to see what is in the system to support it; being able to see something
    /// is not a reason to be able to rewrite it silently.
    /// </summary>
    [Theory]
    [InlineData(nameof(NoteOperations.Update))]
    [InlineData(nameof(NoteOperations.Delete))]
    public async Task Handler_DoesNotSucceed_WhenAnAdminTriesToChangeSomebodyElsesNote(string operation)
    {
        var context = await DecideAsync(
            Caller(Guid.CreateVersion7(), Roles.Admin), OperationFor(operation));

        Assert.False(context.HasSucceeded);
    }

    /// <summary>
    /// Refusing is not the same as vetoing. Fail() cannot be undone by any other
    /// handler, and this one only knows it cannot personally approve the request -
    /// so it stays silent and leaves the decision to the rest of the pipeline.
    /// Calling Fail() here would work today and quietly break the first time a
    /// second handler had something to say.
    /// </summary>
    [Fact]
    public async Task Handler_DoesNotVeto_WhenItRefuses()
    {
        var context = await DecideAsync(Caller(Guid.CreateVersion7()), NoteOperations.Update);

        Assert.False(context.HasSucceeded);
        Assert.False(context.HasFailed);
    }

    /// <summary>A token with no usable sub is not somebody. It is nobody.</summary>
    [Fact]
    public async Task Handler_DoesNotSucceed_WhenTheSubjectClaimIsNotAGuid()
    {
        var caller = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(JwtRegisteredClaimNames.Sub, "not-a-guid")], "Test"));

        var context = new AuthorizationHandlerContext([NoteOperations.Read], caller, Note);
        await new NoteAuthorizationHandler().HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    private static OperationAuthorizationRequirement OperationFor(string name) => name switch
    {
        nameof(NoteOperations.Read) => NoteOperations.Read,
        nameof(NoteOperations.Update) => NoteOperations.Update,
        nameof(NoteOperations.Delete) => NoteOperations.Delete,
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };
}
