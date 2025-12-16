using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureNotes.Api.Common;
using SecureNotes.Api.Data;
using SecureNotes.Api.Domain;

namespace SecureNotes.Api.Services;

public interface IRefreshTokenService
{
    /// <summary>Issues a new token, into <paramref name="familyId"/> if rotating.</summary>
    Task<string> IssueAsync(AppUser user, Guid? familyId, string? ip, CancellationToken cancellationToken);

    /// <summary>Looks a presented token up. Returns the row whether or not it is still active.</summary>
    Task<RefreshToken?> FindAsync(string presented, CancellationToken cancellationToken);

    Task RevokeAsync(RefreshToken token, string? replacedBy, CancellationToken cancellationToken);
}

public sealed class RefreshTokenService(
    AppDbContext db,
    IOptions<JwtOptions> options,
    TimeProvider clock) : IRefreshTokenService
{
    /// <summary>
    /// 256 bits from a cryptographic RNG.
    /// </summary>
    /// <remarks>
    /// Not a Guid. A Guid looks random and is not: v4 carries only 122 bits, and
    /// nothing guarantees Guid.NewGuid is seeded from a CSPRNG on every platform.
    /// This value is a bearer credential - whoever holds it is the user - so it
    /// gets the same treatment as a key.
    /// </remarks>
    public const int TokenBytes = 32;

    private readonly JwtOptions _options = options.Value;

    public async Task<string> IssueAsync(
        AppUser user, Guid? familyId, string? ip, CancellationToken cancellationToken)
    {
        var raw = Base64UrlEncode(RandomNumberGenerator.GetBytes(TokenBytes));
        var now = clock.GetUtcNow();

        db.RefreshTokens.Add(new RefreshToken
        {
            Id = Guid.CreateVersion7(),
            UserId = user.Id,
            Token = raw,
            FamilyId = familyId ?? Guid.CreateVersion7(),
            CreatedAt = now,
            ExpiresAt = now.AddDays(_options.RefreshTokenDays),
            CreatedByIp = ip,
        });

        await db.SaveChangesAsync(cancellationToken);

        return raw;
    }

    public Task<RefreshToken?> FindAsync(string presented, CancellationToken cancellationToken) =>
        db.RefreshTokens
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.Token == presented, cancellationToken);

    public async Task RevokeAsync(RefreshToken token, string? replacedBy, CancellationToken cancellationToken)
    {
        token.RevokedAt = clock.GetUtcNow();
        token.ReplacedByToken = replacedBy;

        await db.SaveChangesAsync(cancellationToken);
    }

    // Base64 with the URL-unsafe characters swapped and the padding dropped, so the
    // token survives a cookie, a query string and a JSON body unchanged.
    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
