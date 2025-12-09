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
}

public sealed class AuthService(
    UserManager<AppUser> users,
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
}
