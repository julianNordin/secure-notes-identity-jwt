using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace SecureNotes.Api.Common;

/// <summary>
/// Runs the registered FluentValidation validator for every action argument that
/// has one, and short-circuits with an RFC 9457 validation problem if it fails.
/// </summary>
/// <remarks>
/// This exists because FluentValidation.AspNetCore's automatic MVC integration is
/// deprecated. One filter, registered once, is the whole mechanism - so when a
/// request is not being validated, there is exactly one place to look.
/// </remarks>
public sealed class ValidationFilter(IServiceProvider services) : IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        foreach (var argument in context.ActionArguments.Values)
        {
            if (argument is null)
            {
                continue;
            }

            // The validator is resolved by the argument's runtime type, so adding a
            // validator for a new DTO is enough to have it enforced - there is no
            // second registration step to forget.
            if (services.GetService(typeof(IValidator<>).MakeGenericType(argument.GetType()))
                is not IValidator validator)
            {
                continue;
            }

            var result = await validator.ValidateAsync(
                new ValidationContext<object>(argument), context.HttpContext.RequestAborted);

            if (result.IsValid)
            {
                continue;
            }

            var errors = result.Errors
                .GroupBy(e => e.PropertyName)
                .ToDictionary(g => g.Key, g => g.Select(e => e.ErrorMessage).ToArray());

            context.Result = new BadRequestObjectResult(new ValidationProblemDetails(errors)
            {
                Type = "https://tools.ietf.org/html/rfc9110#section-15.5.1",
                Title = "One or more validation errors occurred.",
                Status = StatusCodes.Status400BadRequest,
            });

            return;
        }

        await next();
    }
}
