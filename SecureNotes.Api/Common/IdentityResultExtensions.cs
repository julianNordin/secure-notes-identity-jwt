using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace SecureNotes.Api.Common;

public static class IdentityResultExtensions
{
    /// <summary>
    /// Turns Identity's flat error list into a field-keyed RFC 9457 problem, so a
    /// failed registration reads the same way to a client as a failed validation.
    /// </summary>
    public static ValidationProblemDetails ToValidationProblem(this IdentityResult result)
    {
        var errors = result.Errors
            .GroupBy(FieldFor)
            .ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray());

        return new ValidationProblemDetails(errors)
        {
            Type = "https://tools.ietf.org/html/rfc9110#section-15.5.1",
            Title = "One or more validation errors occurred.",
            Status = StatusCodes.Status400BadRequest,
        };
    }

    // Identity reports errors as flat codes with no notion of which field they
    // belong to. Mapping them back is guesswork by prefix, but it is guesswork
    // done once here rather than in every caller.
    private static string FieldFor(IdentityError error) => error.Code switch
    {
        not null when error.Code.StartsWith("Password", StringComparison.Ordinal) => "password",
        "DuplicateEmail" or "InvalidEmail" or "DuplicateUserName" or "InvalidUserName" => "email",
        _ => string.Empty,
    };
}
