using System.Text;
using Microsoft.Extensions.Options;

namespace SecureNotes.Api.Common;

/// <summary>
/// Refuses to let the application start on a signing key that is missing, too
/// short, or still the placeholder.
/// </summary>
/// <remarks>
/// Paired with ValidateOnStart, this turns a silent security failure into a
/// startup crash. Without it, a deployment that forgot to set Jwt__SigningKey
/// starts happily and signs every token with an empty string, and nothing looks
/// wrong until someone works out they can mint their own admin token.
/// </remarks>
public sealed class JwtOptionsValidator : IValidateOptions<JwtOptions>
{
    public ValidateOptionsResult Validate(string? name, JwtOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.SigningKey))
        {
            failures.Add(
                "Jwt:SigningKey is not set. In development run " +
                "`dotnet user-secrets set \"Jwt:SigningKey\" \"<random>\"` from SecureNotes.Api/. " +
                "Elsewhere set the Jwt__SigningKey environment variable.");
        }
        else if (options.SigningKey == JwtOptions.PlaceholderKey)
        {
            failures.Add(
                "Jwt:SigningKey is still the placeholder from .env.example. A key that is " +
                "published in the repository is not a key.");
        }
        else
        {
            var bytes = Encoding.UTF8.GetByteCount(options.SigningKey);
            if (bytes < JwtOptions.MinimumKeyBytes)
            {
                failures.Add(
                    $"Jwt:SigningKey is {bytes} bytes. HS256 needs at least " +
                    $"{JwtOptions.MinimumKeyBytes}, because a shorter key is silently stretched " +
                    "rather than rejected.");
            }
        }

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            failures.Add("Jwt:Issuer must be set, because token validation checks it.");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            failures.Add("Jwt:Audience must be set, because token validation checks it.");
        }

        if (options.AccessTokenMinutes is < 1 or > 60)
        {
            failures.Add(
                $"Jwt:AccessTokenMinutes is {options.AccessTokenMinutes}. An access token cannot " +
                "be revoked, so anything beyond an hour is a stolen-token window nobody can close.");
        }

        if (options.RefreshTokenDays is < 1 or > 90)
        {
            failures.Add(
                $"Jwt:RefreshTokenDays is {options.RefreshTokenDays}. Beyond ninety days a stolen " +
                "token outlives any plausible chance of the theft being noticed.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
