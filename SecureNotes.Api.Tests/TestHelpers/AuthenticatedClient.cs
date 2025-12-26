using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SecureNotes.Api.Domain;
using SecureNotes.Api.DTOs;

namespace SecureNotes.Api.Tests.TestHelpers;

/// <summary>
/// A registered account, its identifiers, its live tokens, and an HttpClient that
/// already carries the bearer header.
/// </summary>
/// <remarks>
/// Deliberately hands back more than the HttpClient. Phase 15 needs the refresh
/// token to rotate and replay it and the raw access token to tamper with it; Phase
/// 16 needs the user id to assert that one account cannot reach another's note. A
/// helper that returned only a ready-made client would have every one of those
/// tests reaching around it to get the rest, which is how a helper stops being one.
/// </remarks>
public sealed class AuthenticatedClient(
    HttpClient client,
    Guid userId,
    string email,
    string password,
    TokenResponse tokens) : IDisposable
{
    public HttpClient Client { get; } = client;

    public Guid UserId { get; } = userId;

    public string Email { get; } = email;

    public string Password { get; } = password;

    public string AccessToken { get; } = tokens.AccessToken;

    public string RefreshToken { get; } = tokens.RefreshToken;

    public void Dispose() => Client.Dispose();
}
