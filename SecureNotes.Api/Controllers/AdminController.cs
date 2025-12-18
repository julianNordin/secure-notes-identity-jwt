using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureNotes.Api.Common;
using SecureNotes.Api.Data;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Services;

namespace SecureNotes.Api.Controllers;

/// <summary>
/// Endpoints only an administrator may reach.
/// </summary>
/// <remarks>
/// [Authorize(Roles = ...)] sits on the controller rather than on each action, so a
/// new admin action is protected because of where it lives rather than because
/// somebody remembered an attribute.
/// </remarks>
[ApiController]
[Authorize(Roles = Roles.Admin)]
[Route("api/admin")]
public sealed class AdminController(AppDbContext db, TimeProvider clock) : ControllerBase
{
    /// <summary>
    /// Every note in the system, whoever owns it.
    /// </summary>
    [HttpGet("notes")]
    [ProducesResponseType<PagedResponse<AdminNoteResponse>>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> AllNotes(
        [FromQuery] string? search,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        CancellationToken cancellationToken = default)
    {
        page = Math.Max(page, 1);
        pageSize = Math.Clamp(pageSize, 1, NoteService.MaxPageSize);

        // Deliberately no owner filter - that is the entire difference between this
        // endpoint and GET /api/notes, and the reason it needs its own route and
        // its own role check rather than a flag on the normal one.
        var query = db.Notes.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var pattern = $"%{search.Trim()}%";
            query = query.Where(n =>
                EF.Functions.ILike(n.Title, pattern) || EF.Functions.ILike(n.Content, pattern));
        }

        var total = await query.CountAsync(cancellationToken);

        var items = await query
            .OrderByDescending(n => n.UpdatedAt)
            .ThenBy(n => n.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Join(db.Users, n => n.OwnerId, u => u.Id, (n, u) => new AdminNoteResponse(
                n.Id, n.Title, n.Content, n.OwnerId, u.Email!, n.CreatedAt, n.UpdatedAt))
            .ToListAsync(cancellationToken);

        return Ok(new PagedResponse<AdminNoteResponse>(
            items, page, pageSize, total, (int)Math.Ceiling(total / (double)pageSize)));
    }

    /// <summary>
    /// Every account, with its roles and lockout state.
    /// </summary>
    /// <remarks>
    /// Returns no password hashes and no security stamps. An admin has no use for
    /// either, and an endpoint that hands them out turns one compromised admin
    /// session into an offline attack on every password in the system.
    /// </remarks>
    [HttpGet("users")]
    [ProducesResponseType<PagedResponse<AdminUserResponse>>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> AllUsers(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        CancellationToken cancellationToken = default)
    {
        page = Math.Max(page, 1);
        pageSize = Math.Clamp(pageSize, 1, NoteService.MaxPageSize);

        var now = clock.GetUtcNow();
        var total = await db.Users.CountAsync(cancellationToken);

        var items = await db.Users
            .AsNoTracking()
            .OrderBy(u => u.CreatedAt)
            .ThenBy(u => u.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(u => new AdminUserResponse(
                u.Id,
                u.Email!,
                u.DisplayName,
                u.EmailConfirmed,
                u.LockoutEnd != null && u.LockoutEnd > now,
                u.CreatedAt,
                db.UserRoles.Where(ur => ur.UserId == u.Id)
                    .Join(db.Roles, ur => ur.RoleId, r => r.Id, (ur, r) => r.Name!)
                    .ToList()))
            .ToListAsync(cancellationToken);

        return Ok(new PagedResponse<AdminUserResponse>(
            items, page, pageSize, total, (int)Math.Ceiling(total / (double)pageSize)));
    }
}
