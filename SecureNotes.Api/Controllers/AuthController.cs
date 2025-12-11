using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SecureNotes.Api.Domain;
using SecureNotes.Api.Common;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Services;

namespace SecureNotes.Api.Controllers;

[ApiController]
[Route("api/auth")]
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
    [ProducesResponseType<TokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken cancellationToken)
    {
        var token = await auth.LoginAsync(request, cancellationToken);

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
}
