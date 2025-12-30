using Microsoft.AspNetCore.Identity;
using SecureNotes.Api.Common;
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
    Task<IssuedSession?> LoginAsync(LoginRequest request, string? ip, CancellationToken cancellationToken);

    /// <summary>Rotates a refresh token. Null if it is unknown, expired or already spent.</summary>
    Task<IssuedSession?> RefreshAsync(string presented, string? ip, CancellationToken cancellationToken);

    /// <summary>Revokes the presented refresh token. Idempotent and always silent.</summary>
    Task LogoutAsync(string presented, CancellationToken cancellationToken);

    /// <summary>Ends every session the user has anywhere, including live access tokens.</summary>
    Task LogoutEverywhereAsync(Guid userId, CancellationToken cancellationToken);

    Task SendConfirmationAsync(AppUser user, CancellationToken cancellationToken);

    Task<bool> ConfirmEmailAsync(Guid userId, string encodedToken, CancellationToken cancellationToken);

    /// <summary>Silent whether or not the address has an account.</summary>
    Task SendPasswordResetAsync(string emailAddress, CancellationToken cancellationToken);

    Task<IdentityResult> ResetPasswordAsync(
        Guid userId, string encodedToken, string newPassword, CancellationToken cancellationToken);

    Task<IdentityResult> ChangePasswordAsync(
        Guid userId, string current, string replacement, CancellationToken cancellationToken);
}

public sealed class AuthService(
    UserManager<AppUser> users,
    SignInManager<AppUser> signIn,
    ITokenService tokens,
    IEmailSender email,
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

            await email.SendAsync(
                existing.Email!,
                "Someone tried to register with your address",
                "Your SecureNotes account already exists. If this was you, sign in or reset your " +
                "password. If it was not, no action is needed - no account was created.",
                cancellationToken);

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
            // Every account gets the User role. Roles are additive here, so the
            // absence of a role would be indistinguishable from a role that failed
            // to apply, and a policy asking "is this caller a User" would answer no
            // for everyone. Admin is only ever granted deliberately.
            await users.AddToRoleAsync(user, Roles.User);
            await SendConfirmationAsync(user, cancellationToken);

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

    public async Task<IssuedSession?> LoginAsync(
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
        var issued = await refreshTokens.IssueAsync(user, familyId: null, ip, cancellationToken);

        return await BuildResponseAsync(user, issued);
    }

    public async Task<IssuedSession?> RefreshAsync(
        string presented, string? ip, CancellationToken cancellationToken)
    {
        var stored = await refreshTokens.FindAsync(presented, cancellationToken);

        if (stored?.User is null)
        {
            logger.LogInformation("Refresh presented a token that is not in the store.");
            return null;
        }

        if (stored.RevokedAt is not null)
        {
            // This token was already spent. Rotation means the legitimate client no
            // longer has it, so two parties held the same token and one of them is
            // not the user. There is no way to tell which of them is presenting it
            // now, so the only safe move is to end the session for both: revoke
            // every live token descended from that login and make them authenticate
            // again with something this attacker does not have.
            var killed = await refreshTokens.RevokeFamilyAsync(stored.FamilyId, cancellationToken);

            logger.LogWarning(
                "Refresh token reuse detected for {UserId}. Family {FamilyId} revoked, " +
                "{Killed} live token(s) killed. A spent token was presented, which means it " +
                "was held by more than one party.",
                stored.UserId, stored.FamilyId, killed);

            return null;
        }

        if (!stored.IsActive(clock.GetUtcNow()))
        {
            // Simply expired. Nothing suspicious: the user was away too long.
            logger.LogInformation(
                "Refresh presented an expired token for {UserId}.", stored.UserId);
            return null;
        }

        // Rotation. The presented token is spent the moment it is accepted and its
        // replacement is issued into the same family, so one token is usable exactly
        // once and a copy taken in transit dies as soon as the real client refreshes.
        var replacement = await refreshTokens.IssueAsync(stored.User, stored.FamilyId, ip, cancellationToken);
        await refreshTokens.RevokeAsync(stored, replacement.Token, cancellationToken);

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

    public async Task LogoutEverywhereAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());

        if (user is null)
        {
            return;
        }

        // Both halves are needed and neither is enough alone. Revoking the refresh
        // tokens stops new access tokens being minted; rolling the security stamp
        // kills the access tokens already out there, which would otherwise keep
        // working until they expired. Without the second, "log out everywhere"
        // would mean "log out everywhere in up to fifteen minutes".
        var killed = await refreshTokens.RevokeAllForUserAsync(userId, cancellationToken);
        await users.UpdateSecurityStampAsync(user);

        logger.LogInformation(
            "Logged {UserId} out everywhere: {Killed} refresh token(s) revoked, security stamp rolled.",
            userId, killed);
    }

    private async Task<IssuedSession> BuildResponseAsync(AppUser user, IssuedRefreshToken refresh)
    {
        var roles = (await users.GetRolesAsync(user)).ToArray();
        var access = tokens.CreateAccessToken(user, roles);

        var body = new TokenResponse(
            access.Value,
            "Bearer",
            (int)Math.Round((access.ExpiresAt - clock.GetUtcNow()).TotalSeconds));

        return new IssuedSession(body, refresh.Token, refresh.ExpiresAt);
    }

    public async Task SendConfirmationAsync(AppUser user, CancellationToken cancellationToken)
    {
        if (user.EmailConfirmed)
        {
            return;
        }

        var token = IdentityTokenCodec.Encode(await users.GenerateEmailConfirmationTokenAsync(user));

        await email.SendAsync(
            user.Email!,
            "Confirm your SecureNotes address",
            $"Confirm with userId={user.Id} and token={token}",
            cancellationToken);
    }

    public async Task<bool> ConfirmEmailAsync(
        Guid userId, string encodedToken, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        var token = IdentityTokenCodec.Decode(encodedToken);

        if (user is null || token is null)
        {
            return false;
        }

        var result = await users.ConfirmEmailAsync(user, token);

        if (!result.Succeeded)
        {
            logger.LogInformation("Email confirmation failed for {UserId}.", userId);
        }

        return result.Succeeded;
    }

    public async Task SendPasswordResetAsync(string emailAddress, CancellationToken cancellationToken)
    {
        var user = await users.FindByEmailAsync(emailAddress);

        // No account, nothing sent, and the caller is told the same thing either
        // way. This endpoint is anonymous, so any difference in its answer is a
        // free directory of who banks here.
        if (user is null)
        {
            logger.LogInformation("Password reset requested for an address with no account.");
            return;
        }

        var token = IdentityTokenCodec.Encode(await users.GeneratePasswordResetTokenAsync(user));

        await email.SendAsync(
            user.Email!,
            "Reset your SecureNotes password",
            $"Reset with userId={user.Id} and token={token}. If this was not you, ignore it.",
            cancellationToken);
    }

    public async Task<IdentityResult> ResetPasswordAsync(
        Guid userId, string encodedToken, string newPassword, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());
        var token = IdentityTokenCodec.Decode(encodedToken);

        if (user is null || token is null)
        {
            // Deliberately the same failure a wrong token produces, so a bad user id
            // cannot be used to find out which ids exist.
            return IdentityResult.Failed(new IdentityError
            {
                Code = "InvalidToken",
                Description = "The reset link is invalid or has expired.",
            });
        }

        var result = await users.ResetPasswordAsync(user, token, newPassword);

        if (result.Succeeded)
        {
            // ResetPasswordAsync rolls the security stamp, which the Phase 08 check
            // turns into an immediate logout everywhere. Revoke the refresh tokens
            // too: whoever forced this reset must not keep a way back in.
            await refreshTokens.RevokeAllForUserAsync(user.Id, cancellationToken);
            logger.LogInformation("Password reset completed for {UserId}, all sessions ended.", user.Id);
        }

        return result;
    }

    public async Task<IdentityResult> ChangePasswordAsync(
        Guid userId, string current, string replacement, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId.ToString());

        if (user is null)
        {
            return IdentityResult.Failed(new IdentityError
            {
                Code = "NotFound",
                Description = "The account no longer exists.",
            });
        }

        var result = await users.ChangePasswordAsync(user, current, replacement);

        if (result.Succeeded)
        {
            await refreshTokens.RevokeAllForUserAsync(user.Id, cancellationToken);

            await email.SendAsync(
                user.Email!,
                "Your SecureNotes password changed",
                "If this was not you, reset your password immediately.",
                cancellationToken);

            logger.LogInformation("Password changed for {UserId}, all sessions ended.", user.Id);
        }

        return result;
    }
}
