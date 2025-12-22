using System.Text.Json.Serialization;

namespace SecureNotes.Api.DTOs;

public record RegisterRequest(string Email, string Password, string? DisplayName);

public record LoginRequest(string Email, string Password);

/// <summary>
/// The token response, deliberately shaped like RFC 6749 section 5.1.
/// </summary>
/// <remarks>
/// This endpoint is the OAuth2 <c>password</c> grant in all but name, and Phase 07
/// adds the <c>refresh_token</c> grant beside it. Using the RFC's field names rather
/// than inventing camel-cased ones means any OAuth2-aware client already knows how
/// to read it, and makes the resemblance a documented fact rather than a claim.
/// </remarks>
public record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] int ExpiresIn,
    [property: JsonPropertyName("refresh_token")] string RefreshToken);

/// <summary>The OAuth2 <c>refresh_token</c> grant, RFC 6749 section 6.</summary>
public record RefreshRequest(
    [property: JsonPropertyName("refresh_token")] string RefreshToken);

public record MeResponse(Guid Id, string Email, string? DisplayName, IReadOnlyCollection<string> Roles);

public record ConfirmEmailRequest(Guid UserId, string Token);

public record EmailOnlyRequest(string Email);

public record ResetPasswordRequest(Guid UserId, string Token, string NewPassword);

public record ChangePasswordRequest(string CurrentPassword, string NewPassword);
