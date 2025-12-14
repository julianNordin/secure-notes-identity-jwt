using Microsoft.EntityFrameworkCore;
using SecureNotes.Api.Data;
using SecureNotes.Api.Domain;
using SecureNotes.Api.DTOs;

namespace SecureNotes.Api.Services;

public interface INoteService
{
    Task<PagedResponse<NoteResponse>> ListForOwnerAsync(
        Guid ownerId, string? search, int page, int pageSize, CancellationToken cancellationToken);

    /// <summary>
    /// Loads a note by id with no ownership filter. The caller decides who may see it.
    /// </summary>
    Task<Note?> FindAsync(Guid id, CancellationToken cancellationToken);

    Task<Note> CreateAsync(Guid ownerId, CreateNoteRequest request, CancellationToken cancellationToken);

    Task UpdateAsync(Note note, UpdateNoteRequest request, CancellationToken cancellationToken);

    Task DeleteAsync(Note note, CancellationToken cancellationToken);
}

public sealed class NoteService(AppDbContext db, TimeProvider clock) : INoteService
{
    public const int MaxPageSize = 100;

    public async Task<PagedResponse<NoteResponse>> ListForOwnerAsync(
        Guid ownerId, string? search, int page, int pageSize, CancellationToken cancellationToken)
    {
        page = Math.Max(page, 1);

        // Capped, not just defaulted. Without a ceiling, ?pageSize=1000000 is a
        // request to serialise the entire table into one response, which is a
        // denial of service that costs the caller one HTTP request.
        pageSize = Math.Clamp(pageSize, 1, MaxPageSize);

        // The ownership filter lives in the SQL. Loading every note and filtering
        // in memory would work and would mean the database hands this process rows
        // it has no business holding, one connection-log leak away from being a
        // real disclosure.
        var query = db.Notes.AsNoTracking().Where(n => n.OwnerId == ownerId);

        if (!string.IsNullOrWhiteSpace(search))
        {
            var pattern = $"%{search.Trim()}%";
            query = query.Where(n =>
                EF.Functions.ILike(n.Title, pattern) || EF.Functions.ILike(n.Content, pattern));
        }

        var total = await query.CountAsync(cancellationToken);

        var items = await query
            // Without a total ordering the database may return rows in any order,
            // so the same note can appear on two pages while another appears on none.
            .OrderByDescending(n => n.UpdatedAt)
            .ThenBy(n => n.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(n => new NoteResponse(n.Id, n.Title, n.Content, n.CreatedAt, n.UpdatedAt))
            .ToListAsync(cancellationToken);

        return new PagedResponse<NoteResponse>(
            items, page, pageSize, total, (int)Math.Ceiling(total / (double)pageSize));
    }

    public Task<Note?> FindAsync(Guid id, CancellationToken cancellationToken) =>
        db.Notes.FirstOrDefaultAsync(n => n.Id == id, cancellationToken);

    public async Task<Note> CreateAsync(
        Guid ownerId, CreateNoteRequest request, CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();

        var note = new Note
        {
            Id = Guid.CreateVersion7(),
            Title = request.Title,
            Content = request.Content,
            // Taken from the authenticated principal, never from the request body.
            // A body-supplied owner is an authorization bypass with extra steps.
            OwnerId = ownerId,
            CreatedAt = now,
            UpdatedAt = now,
        };

        db.Notes.Add(note);
        await db.SaveChangesAsync(cancellationToken);

        return note;
    }

    public async Task UpdateAsync(Note note, UpdateNoteRequest request, CancellationToken cancellationToken)
    {
        note.Title = request.Title;
        note.Content = request.Content;
        note.UpdatedAt = clock.GetUtcNow();

        // OwnerId is deliberately not assignable here. A note cannot change hands.
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task DeleteAsync(Note note, CancellationToken cancellationToken)
    {
        db.Notes.Remove(note);
        await db.SaveChangesAsync(cancellationToken);
    }
}
