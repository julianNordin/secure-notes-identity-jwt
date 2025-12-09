namespace SecureNotes.Api.DTOs;

public record RegisterRequest(string Email, string Password, string? DisplayName);
