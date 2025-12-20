using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using SecureNotes.Api.Common;
using SecureNotes.Api.Common.Authorization;
using SecureNotes.Api.Domain;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Services;

namespace SecureNotes.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/notes")]
public sealed class NotesController(
    INoteService notes,
    IAuthorizationService authorization) : ControllerBase
{
    /// <summary>
    /// Lists the caller's own notes, newest first.
    /// </summary>
    [HttpGet]
    [ProducesResponseType<PagedResponse<NoteResponse>>(StatusCodes.Status200OK)]
    public async Task<IActionResult> List(
        [FromQuery] string? search,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        CancellationToken cancellationToken = default)
    {
        var result = await notes.ListForOwnerAsync(
            User.GetUserId(), search, page, pageSize, cancellationToken);

        return Ok(result);
    }

    /// <summary>
    /// Returns one of the caller's notes.
    /// </summary>
    /// <remarks>
    /// A note that exists but belongs to somebody else answers 404, not 403.
    /// 403 would confirm the note exists, which hands an attacker a way to probe
    /// for valid ids and count another user's notes. The caller cannot act on the
    /// distinction anyway: from where they stand, a note they may not have and a
    /// note that is not there are the same thing.
    /// </remarks>
    [HttpGet("{id:guid}")]
    [ProducesResponseType<NoteResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Get(Guid id, CancellationToken cancellationToken)
    {
        var note = await notes.FindAsync(id, cancellationToken);
        if (note is null)
        {
            return NotFound();
        }

        if (await AuthorizeAsync(note, NoteOperations.Read) is { } refusal)
        {
            return refusal;
        }

        return Ok(note.ToResponse());
    }

    /// <summary>
    /// Creates a note owned by the caller.
    /// </summary>
    [HttpPost]
    [Authorize(Policy = Policies.CanWriteNotes)]
    [ProducesResponseType<NoteResponse>(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> Create(CreateNoteRequest request, CancellationToken cancellationToken)
    {
        var note = await notes.CreateAsync(User.GetUserId(), request, cancellationToken);

        return CreatedAtAction(nameof(Get), new { id = note.Id }, note.ToResponse());
    }

    /// <summary>
    /// Replaces the title and content of one of the caller's notes.
    /// </summary>
    [HttpPut("{id:guid}")]
    [Authorize(Policy = Policies.CanWriteNotes)]
    [ProducesResponseType<NoteResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Update(
        Guid id, UpdateNoteRequest request, CancellationToken cancellationToken)
    {
        var note = await notes.FindAsync(id, cancellationToken);
        if (note is null)
        {
            return NotFound();
        }

        if (await AuthorizeAsync(note, NoteOperations.Update) is { } refusal)
        {
            return refusal;
        }

        await notes.UpdateAsync(note, request, cancellationToken);

        return Ok(note.ToResponse());
    }

    /// <summary>
    /// Deletes one of the caller's notes.
    /// </summary>
    [HttpDelete("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete(Guid id, CancellationToken cancellationToken)
    {
        var note = await notes.FindAsync(id, cancellationToken);
        if (note is null)
        {
            return NotFound();
        }

        if (await AuthorizeAsync(note, NoteOperations.Delete) is { } refusal)
        {
            return refusal;
        }

        await notes.DeleteAsync(note, cancellationToken);

        return NoContent();
    }

    /// <summary>
    /// Returns the response to send instead, or null if the caller may proceed.
    /// </summary>
    /// <remarks>
    /// Two checks, because the two refusals mean different things. A caller who may
    /// not even read the note gets 404: for them the note's existence is itself the
    /// secret, and 403 would confirm it. A caller who may read it but not perform
    /// this operation gets 403, because they can already see the note - an admin
    /// looking at it through GET can hardly be misled by being told plainly that
    /// they may not edit it. Answering 404 there would be dishonest to no purpose.
    /// </remarks>
    private async Task<IActionResult?> AuthorizeAsync(
        Note note, OperationAuthorizationRequirement operation)
    {
        if (!(await authorization.AuthorizeAsync(User, note, NoteOperations.Read)).Succeeded)
        {
            return NotFound();
        }

        if (!(await authorization.AuthorizeAsync(User, note, operation)).Succeeded)
        {
            return Forbid();
        }

        return null;
    }
}
