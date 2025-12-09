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
    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Register(
        RegisterRequest request, CancellationToken cancellationToken)
    {
        var result = await auth.RegisterAsync(request, cancellationToken);

        if (result.Succeeded)
        {
            return StatusCode(StatusCodes.Status201Created);
        }

        if (result.Errors.Any(e => e.Code is "DuplicateUserName" or "DuplicateEmail"))
        {
            return Conflict(new ProblemDetails
            {
                Title = "That email address is already registered.",
                Status = StatusCodes.Status409Conflict,
            });
        }

        return BadRequest(result.ToValidationProblem());
    }
}
