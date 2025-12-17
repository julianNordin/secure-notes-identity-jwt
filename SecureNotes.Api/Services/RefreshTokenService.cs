using System.Security.Cryptography;
using System.Text;
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

    /// <summary>Revokes every live token in a family. Returns how many were killed.</summary>
    Task<int> RevokeFamilyAsync(Guid familyId, CancellationToken cancellationToken);

    /// <summary>Revokes every live token belonging to one user.</summary>
    Task<int> RevokeAllForUserAsync(Guid userId, CancellationToken cancellationToken);
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

    /// <summary>
    /// How long a dead token is kept before it is swept.
    /// </summary>
    /// <remarks>
    /// Not zero, because reuse detection needs the revoked row to still be there -
    /// deleting a spent token immediately would turn a replay into "unknown token"
    /// and lose the one signal worth having.
    /// </remarks>
    public static readonly TimeSpan DeadTokenRetention = TimeSpan.FromDays(30);

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
            TokenHash = Hash(raw),
            FamilyId = familyId ?? Guid.CreateVersion7(),
            CreatedAt = now,
            ExpiresAt = now.AddDays(_options.RefreshTokenDays),
            CreatedByIp = ip,
        });

        await db.SaveChangesAsync(cancellationToken);

        // Sweep this user's long-dead rows, here rather than in a background
        // service. Cleanup happens where the growth happens, the work is bounded to
        // one user and one index, and there is no hosted service lifetime to reason
        // about or to disable when the integration tests spin up a host.
        var cutoff = now - DeadTokenRetention;
        await db.RefreshTokens
            .Where(t => t.UserId == user.Id && t.ExpiresAt < cutoff)
            .ExecuteDeleteAsync(cancellationToken);

        return raw;
    }

    public Task<RefreshToken?> FindAsync(string presented, CancellationToken cancellationToken)
    {
        // Look up by hash. Nothing needs a constant-time comparison here and adding
        // one would be theatre: the match is an index lookup on a 256-bit value, so
        // there is no secret to leak a byte at a time and no near-miss to learn from.
        var hash = Hash(presented);

        return db.RefreshTokens
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.TokenHash == hash, cancellationToken);
    }

    public async Task RevokeAsync(RefreshToken token, string? replacedBy, CancellationToken cancellationToken)
    {
        token.RevokedAt = clock.GetUtcNow();
        token.ReplacedByTokenHash = replacedBy is null ? null : Hash(replacedBy);

        await db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// A single SHA-256, not a password hash.
    /// </summary>
    /// <remarks>
    /// PBKDF2 is slow on purpose because a password is low-entropy and guessable.
    /// This token is 256 bits from a CSPRNG, so brute force is not on the table and
    /// a slow hash would only mean burning 100ms of server time on every refresh.
    /// </remarks>
    private static string Hash(string raw) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));

    public Task<int> RevokeFamilyAsync(Guid familyId, CancellationToken cancellationToken) =>
        db.RefreshTokens
            .Where(t => t.FamilyId == familyId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, clock.GetUtcNow()), cancellationToken);

    public Task<int> RevokeAllForUserAsync(Guid userId, CancellationToken cancellationToken) =>
        db.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, clock.GetUtcNow()), cancellationToken);

    // Base64 with the URL-unsafe characters swapped and the padding dropped, so the
    // token survives a cookie, a query string and a JSON body unchanged.
    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
