using Microsoft.AspNetCore.Mvc;

namespace SecureNotes.Api.Tests.TestHelpers;

/// <summary>
/// An endpoint with no [Authorize] and no [AllowAnonymous], on purpose.
/// </summary>
/// <remarks>
/// This is the controller somebody adds in a hurry. Nothing about it says who may
/// call it, which is exactly the mistake Phase 10's fallback policy exists to catch:
/// without the policy it is public to anyone who finds the URL and nothing anywhere
/// reports that, because the symptom of the mistake is that everything works.
///
/// It lives in the test assembly and is reachable only because NotesApiFactory adds
/// that assembly as an MVC application part, so no deployed application contains it.
/// </remarks>
[ApiController]
[Route("api/test/bare")]
public sealed class DeliberatelyBareController : ControllerBase
{
    public const string Route = "/api/test/bare";

    [HttpGet]
    public IActionResult Get() => Ok("reached");
}
