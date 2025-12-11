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
    Task<TokenResponse?> LoginAsync(LoginRequest request, CancellationToken cancellationToken);
}

public sealed class AuthService(
    UserManager<AppUser> users,
    SignInManager<AppUser> signIn,
    ITokenService tokens,
    TimeProvider clock,
    ILogger<AuthService> logger) : IAuthService
{
    public async Task<TokenResponse?> LoginAsync(
        LoginRequest request, CancellationToken cancellationToken)
    {
        var user = await users.FindByEmailAsync(request.Email);

        if (user is null)
        {
            // Same trick as registration: burn the hashing work a real login would
            // spend, so that response time does not reveal whether the address
            // exists. Returning early here would undo the uniform 401 below.
            users.PasswordHasher.HashPassword(new AppUser { UserName = request.Email }, request.Password);
            logger.LogInformation("Login attempted for an address with no account.");
            return null;
        }

        // CheckPasswordSignInAsync rather than UserManager.CheckPasswordAsync,
        // purely for lockoutOnFailure. UserManager's version verifies the password
        // and does not touch AccessFailedCount, so an API built on it has a lockout
        // policy configured and no lockout. It also does not issue a cookie, which
        // is what makes it the right one for a bearer-token API.
        var result = await signIn.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

        if (!result.Succeeded)
        {
            // Locked out, wrong password and not-allowed all leave by this door.
            // A distinct "your account is locked" response would confirm the
            // address has an account here, which is the thing the uniform answer
            // exists to hide. The real owner finds out by email in Phase 12.
            logger.LogInformation(
                "Failed login for {UserId}. LockedOut={LockedOut} NotAllowed={NotAllowed}",
                user.Id, result.IsLockedOut, result.IsNotAllowed);
            return null;
        }

        var roles = (await users.GetRolesAsync(user)).ToArray();
        var token = tokens.CreateAccessToken(user, roles);

        return new TokenResponse(
            token.Value,
            "Bearer",
            (int)Math.Round((token.ExpiresAt - clock.GetUtcNow()).TotalSeconds));
    }

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
}
