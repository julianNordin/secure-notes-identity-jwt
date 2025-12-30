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
    [property: JsonPropertyName("expires_in")] int ExpiresIn);

/// <summary>
/// What a successful login or refresh actually produces: the token response that
/// goes in the body, and the refresh token that does not.
/// </summary>
/// <remarks>
/// A separate type rather than a [JsonIgnore] on TokenResponse, for the same
/// reason AdminNoteResponse is its own record in Phase 09. If the refresh token
/// were a field on the wire shape, the only thing keeping the most sensitive
/// credential in the system out of a JSON body would be remembering an attribute,
/// and nobody can audit "we remembered". Here it cannot be serialised by
/// accident, because it is not on the thing that gets serialised.
/// </remarks>
public record IssuedSession(
    TokenResponse Tokens, string RefreshToken, DateTimeOffset RefreshExpiresAt);

public record MeResponse(Guid Id, string Email, string? DisplayName, IReadOnlyCollection<string> Roles);

public record ConfirmEmailRequest(Guid UserId, string Token);

public record EmailOnlyRequest(string Email);

public record ResetPasswordRequest(Guid UserId, string Token, string NewPassword);

public record ChangePasswordRequest(string CurrentPassword, string NewPassword);
