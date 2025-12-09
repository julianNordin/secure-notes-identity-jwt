using Microsoft.AspNetCore.Identity;
using SecureNotes.Api.Domain;
using SecureNotes.Api.DTOs;

namespace SecureNotes.Api.Services;

public interface IAuthService
{
    Task<IdentityResult> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken);
}

public sealed class AuthService(UserManager<AppUser> users, TimeProvider clock) : IAuthService
{
    public async Task<IdentityResult> RegisterAsync(
        RegisterRequest request, CancellationToken cancellationToken)
    {
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
        return await users.CreateAsync(user, request.Password);
    }
}
