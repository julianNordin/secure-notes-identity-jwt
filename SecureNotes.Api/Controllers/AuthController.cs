using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SecureNotes.Api.Domain;
using SecureNotes.Api.Common;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Services;

namespace SecureNotes.Api.Controllers;

[ApiController]
[Route("api/auth")]
[EnableRateLimiting(RateLimits.AuthPolicy)]
/// <remarks>
/// The fallback policy makes every endpoint require an authenticated caller, so the
/// four endpoints below have to opt out explicitly. Three of them could not work any
/// other way - you cannot log in if logging in requires being logged in - and logout
/// is anonymous because the refresh token it revokes is itself the credential, and
/// demanding a live access token as well would mean an expired session could never
/// be cleaned up.
/// </remarks>
public sealed class AuthController(IAuthService auth, UserManager<AppUser> users) : ControllerBase
{
    /// <summary>
    /// Creates a new account.
    /// </summary>
    /// <remarks>
    /// Answers 202 whether or not the address was already registered. The two cases
    /// are deliberately indistinguishable: any endpoint that tells an anonymous
    /// caller whether a given address has an account is a way to test a list of
    /// addresses against this service, which is the first step of a credential
    /// stuffing run and is worth something to a phisher on its own.
    /// </remarks>
    [HttpPost("register")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register(
        RegisterRequest request, CancellationToken cancellationToken)
    {
        var result = await auth.RegisterAsync(request, cancellationToken);

        return result.Outcome switch
        {
            // A malformed request is safe to report precisely - it says nothing
            // about who does or does not have an account here.
            RegistrationOutcome.Rejected => BadRequest(result.Failure!.ToValidationProblem()),
            _ => Accepted(),
        };
    }

    /// <summary>
    /// Exchanges an email and password for an access token.
    /// </summary>
    /// <remarks>
    /// This is the OAuth2 <c>password</c> grant of RFC 6749 section 4.3, and the
    /// response is the RFC's section 5.1 token response. Every failure - unknown
    /// address, wrong password, locked out - returns the same 401 with the same
    /// body, because anything else lets an anonymous caller sort a list of email
    /// addresses into "has an account here" and "does not".
    /// </remarks>
    [HttpPost("login")]
    [AllowAnonymous]
    [ProducesResponseType<TokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken cancellationToken)
    {
        var token = await auth.LoginAsync(
            request, HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken);

        if (token is null)
        {
            return Unauthorized(new ProblemDetails
            {
                Title = "Invalid credentials.",
                Status = StatusCodes.Status401Unauthorized,
            });
        }

        return Ok(token);
    }

    /// <summary>
    /// Returns the caller's own account, as the server sees it.
    /// </summary>
    /// <remarks>
    /// The smoke test for the whole authentication pipeline: reaching this at all
    /// proves the token was signed by us, has not expired, carries the issuer and
    /// audience we expect, and produced a principal with a readable sub claim.
    /// </remarks>
    [HttpGet("me")]
    [Authorize]
    [ProducesResponseType<MeResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Me()
    {
        var user = await users.FindByIdAsync(User.GetUserId().ToString());

        // The token was valid but the account behind it is gone - deleted while a
        // token was still live. Not 404: the caller asked about themselves, and
        // the honest answer is that this credential no longer identifies anyone.
        if (user is null)
        {
            return Unauthorized();
        }

        var roles = (await users.GetRolesAsync(user)).ToArray();
        return Ok(new MeResponse(user.Id, user.Email!, user.DisplayName, roles));
    }

    /// <summary>
    /// Exchanges a refresh token for a new access token and a new refresh token.
    /// </summary>
    /// <remarks>
    /// The OAuth2 <c>refresh_token</c> grant, RFC 6749 section 6, with rotation.
    /// The presented token is spent by this call and will not work again, so a copy
    /// captured in transit stops being useful the moment the real client refreshes.
    /// </remarks>
    [HttpPost("refresh")]
    [AllowAnonymous]
    [ProducesResponseType<TokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Refresh(RefreshRequest request, CancellationToken cancellationToken)
    {
        var token = await auth.RefreshAsync(
            request.RefreshToken, HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken);

        if (token is null)
        {
            return Unauthorized(new ProblemDetails
            {
                Title = "Invalid refresh token.",
                Status = StatusCodes.Status401Unauthorized,
            });
        }

        return Ok(token);
    }

    /// <summary>
    /// Revokes the presented refresh token.
    /// </summary>
    /// <remarks>
    /// Always 204, whether or not the token was real. Reporting the difference
    /// would turn logout into a way to test tokens, and no honest caller can do
    /// anything with the answer. The access token already issued is untouched and
    /// stays valid until it expires - Phase 08 adds the mechanism that fixes that.
    /// </remarks>
    [HttpPost("logout")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Logout(RefreshRequest request, CancellationToken cancellationToken)
    {
        await auth.LogoutAsync(request.RefreshToken, cancellationToken);

        return NoContent();
    }

    /// <summary>
    /// Ends every session this account has, on every device.
    /// </summary>
    /// <remarks>
    /// Revokes all of the user's refresh tokens and rolls their security stamp.
    /// The second part is what makes it immediate: without it, access tokens
    /// already issued would keep working until they expired, and "log out
    /// everywhere" would quietly mean "log out everywhere within fifteen minutes".
    /// The token used to make this call is invalidated too, which is correct -
    /// everywhere includes here.
    /// </remarks>
    [HttpPost("logout-all")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> LogoutEverywhere(CancellationToken cancellationToken)
    {
        await auth.LogoutEverywhereAsync(User.GetUserId(), cancellationToken);

        return NoContent();
    }

    /// <summary>Confirms an email address using the token from the confirmation email.</summary>
    [HttpPost("confirm-email")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ConfirmEmail(
        ConfirmEmailRequest request, CancellationToken cancellationToken)
    {
        var confirmed = await auth.ConfirmEmailAsync(request.UserId, request.Token, cancellationToken);

        if (!confirmed)
        {
            return BadRequest(new ProblemDetails
            {
                Title = "The confirmation link is invalid or has expired.",
                Status = StatusCodes.Status400BadRequest,
            });
        }

        return NoContent();
    }

    /// <summary>Sends the confirmation email again.</summary>
    /// <remarks>Always 202, so it cannot be used to test whether an address is registered.</remarks>
    [HttpPost("resend-confirmation")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    public async Task<IActionResult> ResendConfirmation(
        EmailOnlyRequest request, CancellationToken cancellationToken)
    {
        var user = await users.FindByEmailAsync(request.Email);

        if (user is not null)
        {
            await auth.SendConfirmationAsync(user, cancellationToken);
        }

        return Accepted();
    }

    /// <summary>Starts a password reset.</summary>
    /// <remarks>
    /// Always 202. This endpoint is anonymous, so any difference between "sent" and
    /// "no such account" would be a free directory of who has an account here.
    /// </remarks>
    [HttpPost("forgot-password")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    public async Task<IActionResult> ForgotPassword(
        EmailOnlyRequest request, CancellationToken cancellationToken)
    {
        await auth.SendPasswordResetAsync(request.Email, cancellationToken);

        return Accepted();
    }

    /// <summary>Completes a password reset using the token from the email.</summary>
    [HttpPost("reset-password")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ResetPassword(
        ResetPasswordRequest request, CancellationToken cancellationToken)
    {
        var result = await auth.ResetPasswordAsync(
            request.UserId, request.Token, request.NewPassword, cancellationToken);

        return result.Succeeded ? NoContent() : BadRequest(result.ToValidationProblem());
    }

    /// <summary>Changes the caller's own password.</summary>
    /// <remarks>
    /// Succeeding here ends every other session immediately: Identity rolls the
    /// security stamp, which the Phase 08 check enforces on the next request, and
    /// the refresh tokens are revoked as well. Changing a password because it may
    /// have been exposed would be pointless if the exposed session stayed live.
    /// </remarks>
    [HttpPost("change-password")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> ChangePassword(
        ChangePasswordRequest request, CancellationToken cancellationToken)
    {
        var result = await auth.ChangePasswordAsync(
            User.GetUserId(), request.CurrentPassword, request.NewPassword, cancellationToken);

        return result.Succeeded ? NoContent() : BadRequest(result.ToValidationProblem());
    }
}
