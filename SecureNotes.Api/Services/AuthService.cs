using Microsoft.AspNetCore.Identity;
using SecureNotes.Api.Domain;
using SecureNotes.Api.DTOs;

namespace SecureNotes.Api.Services;

public enum RegistrationOutcome
{
    Created,
    AlreadyRegistered,
    Rejected,
}

public sealed record RegistrationResult(RegistrationOutcome Outcome, IdentityResult? Failure = null);

public interface IAuthService
{
    Task<RegistrationResult> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken);

    /// <summary>Returns null for every kind of failed login, on purpose.</summary>
    Task<TokenResponse?> LoginAsync(LoginRequest request, string? ip, CancellationToken cancellationToken);

    /// <summary>Rotates a refresh token. Null if it is unknown, expired or already spent.</summary>
    Task<TokenResponse?> RefreshAsync(string presented, string? ip, CancellationToken cancellationToken);

    /// <summary>Revokes the presented refresh token. Idempotent and always silent.</summary>
    Task LogoutAsync(string presented, CancellationToken cancellationToken);
}

public sealed class AuthService(
    UserManager<AppUser> users,
    SignInManager<AppUser> signIn,
    ITokenService tokens,
    IRefreshTokenService refreshTokens,
    TimeProvider clock,
    ILogger<AuthService> logger) : IAuthService
{
    public async Task<RegistrationResult> RegisterAsync(
        RegisterRequest request, CancellationToken cancellationToken)
    {
        var existing = await users.FindByEmailAsync(request.Email);
        if (existing is not null)
        {
            // Hash the submitted password and throw the result away. The caller must
            // not be able to tell a taken address from a free one, and the status
            // code is only half of that: a real registration spends 100,000 PBKDF2
            // iterations, so returning early here would make response time the
            // oracle that the status code no longer is.
            users.PasswordHasher.HashPassword(existing, request.Password);

            // Phase 12 turns this into an actual email to the address on file -
            // "someone tried to register with your address" - which is where the
            // information belongs, because only the real owner can read it.
            logger.LogInformation(
                "Registration attempted for an address that already has an account: {UserId}",
                existing.Id);

            return new RegistrationResult(RegistrationOutcome.AlreadyRegistered);
        }

        var user = new AppUser
        {
            // Email doubles as the username. Identity requires a UserName and this
            // API has no separate concept of one, so keeping them equal avoids a
            // second uniqueness rule that could disagree with the first.
            UserName = request.Email,
            Email = request.Email,
            DisplayName = request.DisplayName,
            CreatedAt = clock.GetUtcNow(),
        };

        // CreateAsync hashes the password. Nothing in this project ever sees, logs
        // or stores the plaintext, and there is no code path that could.
        var result = await users.CreateAsync(user, request.Password);

        if (result.Succeeded)
        {
            return new RegistrationResult(RegistrationOutcome.Created);
        }

        // The lookup above and this insert are not atomic, so two simultaneous
        // registrations for the same address both pass the check and one loses on
        // the unique index. That loser must get the same answer as the winner.
        if (result.Errors.Any(e => e.Code is "DuplicateUserName" or "DuplicateEmail"))
        {
            return new RegistrationResult(RegistrationOutcome.AlreadyRegistered);
        }

        return new RegistrationResult(RegistrationOutcome.Rejected, result);
    }

    public async Task<TokenResponse?> LoginAsync(
        LoginRequest request, string? ip, CancellationToken cancellationToken)
    {
        var user = await users.FindByEmailAsync(request.Email);

        if (user is null)
        {
            // Same trick as registration: burn the hashing work a real login would
            // spend, so response time does not reveal whether the address exists.
            users.PasswordHasher.HashPassword(new AppUser { UserName = request.Email }, request.Password);
            logger.LogInformation("Login attempted for an address with no account.");
            return null;
        }

        var result = await signIn.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

        if (!result.Succeeded)
        {
            // Locked out, wrong password and not-allowed all leave by this door.
            // A distinct "your account is locked" response would confirm the address
            // has an account here, which is what the uniform answer exists to hide.
            logger.LogInformation(
                "Failed login for {UserId}. LockedOut={LockedOut} NotAllowed={NotAllowed}",
                user.Id, result.IsLockedOut, result.IsNotAllowed);
            return null;
        }

        // A fresh login starts a new family. Nothing links this session to a previous
        // one, so revoking an old session cannot touch this one.
        var refresh = await refreshTokens.IssueAsync(user, familyId: null, ip, cancellationToken);

        return await BuildResponseAsync(user, refresh);
    }

    public async Task<TokenResponse?> RefreshAsync(
        string presented, string? ip, CancellationToken cancellationToken)
    {
        var stored = await refreshTokens.FindAsync(presented, cancellationToken);

        if (stored?.User is null)
        {
            logger.LogInformation("Refresh presented a token that is not in the store.");
            return null;
        }

        if (!stored.IsActive(clock.GetUtcNow()))
        {
            // Expired, or already spent. Phase 08 makes the already-spent case mean
            // something far stronger than a plain refusal.
            logger.LogInformation(
                "Refresh presented an inactive token for {UserId} in family {FamilyId}.",
                stored.UserId, stored.FamilyId);
            return null;
        }

        // Rotation. The presented token is spent the moment it is accepted and its
        // replacement is issued into the same family, so one token is usable exactly
        // once and a copy taken in transit dies as soon as the real client refreshes.
        var replacement = await refreshTokens.IssueAsync(stored.User, stored.FamilyId, ip, cancellationToken);
        await refreshTokens.RevokeAsync(stored, replacement, cancellationToken);

        return await BuildResponseAsync(stored.User, replacement);
    }

    public async Task LogoutAsync(string presented, CancellationToken cancellationToken)
    {
        var stored = await refreshTokens.FindAsync(presented, cancellationToken);

        // Silent either way. A logout that reported whether the token was real would
        // be a way to test tokens, and no caller can do anything with the answer.
        if (stored is not null && stored.IsActive(clock.GetUtcNow()))
        {
            await refreshTokens.RevokeAsync(stored, replacedBy: null, cancellationToken);
        }
    }

    private async Task<TokenResponse> BuildResponseAsync(AppUser user, string refreshToken)
    {
        var roles = (await users.GetRolesAsync(user)).ToArray();
        var access = tokens.CreateAccessToken(user, roles);

        return new TokenResponse(
            access.Value,
            "Bearer",
            (int)Math.Round((access.ExpiresAt - clock.GetUtcNow()).TotalSeconds),
            refreshToken);
    }
}
