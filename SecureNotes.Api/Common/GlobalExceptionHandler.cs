using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace SecureNotes.Api.Common;

/// <summary>
/// Turns an unhandled exception into an RFC 9457 problem document.
/// </summary>
/// <remarks>
/// The default developer exception page is genuinely useful and must never be
/// reachable in production: a stack trace names your file paths, your package
/// versions and often your connection string, which is a free map of the system for
/// anyone who can provoke a 500. Detail is filled in only in Development, and the
/// full exception always goes to the log, where the operator can see it and the
/// caller cannot.
/// </remarks>
public sealed class GlobalExceptionHandler(
    IProblemDetailsService problemDetails,
    IHostEnvironment environment,
    ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext context, Exception exception, CancellationToken cancellationToken)
    {
        logger.LogError(
            exception, "Unhandled exception for {Method} {Path}",
            context.Request.Method, context.Request.Path);

        context.Response.StatusCode = StatusCodes.Status500InternalServerError;

        return await problemDetails.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = context,
            Exception = exception,
            ProblemDetails = new ProblemDetails
            {
                Type = "https://tools.ietf.org/html/rfc9110#section-15.6.1",
                Title = "An unexpected error occurred.",
                Status = StatusCodes.Status500InternalServerError,
                Detail = environment.IsDevelopment() ? exception.ToString() : null,
            },
        });
    }
}
