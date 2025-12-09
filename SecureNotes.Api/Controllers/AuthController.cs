using Microsoft.AspNetCore.Mvc;
using SecureNotes.Api.Common;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Services;

namespace SecureNotes.Api.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController(IAuthService auth) : ControllerBase
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
}
