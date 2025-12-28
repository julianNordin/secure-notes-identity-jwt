using System.Net;
using System.Net.Http.Json;
using SecureNotes.Api.DTOs;
using SecureNotes.Api.Tests.TestHelpers;

namespace SecureNotes.Api.Tests.Authorization;

public enum Actor { Anonymous, Owner, OtherUser, Admin }

public enum Operation { Read, Update, Delete, List, AdminList }

/// <summary>
/// Twenty cells: four callers against five operations. The table is the artefact -
/// it makes all three authorization styles legible at a glance, and any change to
/// any of them shows up here as a changed number rather than as a paragraph.
/// </summary>
[Collection(ApiCollection.Name)]
public sealed class AuthorizationMatrixTests(NotesApiFactory factory) : ApiTestBase(factory)
{
    // Anonymous. Nothing is reachable: the notes controller carries [Authorize],
    // the admin controller a policy, and Phase 10's fallback policy would close
    // anything that forgot both.
    [Theory]
    [InlineData(Actor.Anonymous, Operation.Read, HttpStatusCode.Unauthorized)]
    [InlineData(Actor.Anonymous, Operation.Update, HttpStatusCode.Unauthorized)]
    [InlineData(Actor.Anonymous, Operation.Delete, HttpStatusCode.Unauthorized)]
    [InlineData(Actor.Anonymous, Operation.List, HttpStatusCode.Unauthorized)]
    [InlineData(Actor.Anonymous, Operation.AdminList, HttpStatusCode.Unauthorized)]

    // The owner. Everything on their own note, and 403 on the admin route - they
    // know it exists, so hiding it would be dishonest to no purpose.
    [InlineData(Actor.Owner, Operation.Read, HttpStatusCode.OK)]
    [InlineData(Actor.Owner, Operation.Update, HttpStatusCode.OK)]
    [InlineData(Actor.Owner, Operation.Delete, HttpStatusCode.NoContent)]
    [InlineData(Actor.Owner, Operation.List, HttpStatusCode.OK)]
    [InlineData(Actor.Owner, Operation.AdminList, HttpStatusCode.Forbidden)]

    // Another user. 404 on every single-note operation, never 403: here the note's
    // existence is itself the secret. Their own list still works and is empty.
    [InlineData(Actor.OtherUser, Operation.Read, HttpStatusCode.NotFound)]
    [InlineData(Actor.OtherUser, Operation.Update, HttpStatusCode.NotFound)]
    [InlineData(Actor.OtherUser, Operation.Delete, HttpStatusCode.NotFound)]
    [InlineData(Actor.OtherUser, Operation.List, HttpStatusCode.OK)]
    [InlineData(Actor.OtherUser, Operation.AdminList, HttpStatusCode.Forbidden)]

    // The admin, and the deliberate asymmetry from Phase 11: may read any note,
    // may not rewrite or delete one. Seeing something is not a reason to be able to
    // change it silently, and widening this later is one line.
    [InlineData(Actor.Admin, Operation.Read, HttpStatusCode.OK)]
    [InlineData(Actor.Admin, Operation.Update, HttpStatusCode.Forbidden)]
    [InlineData(Actor.Admin, Operation.Delete, HttpStatusCode.Forbidden)]
    [InlineData(Actor.Admin, Operation.List, HttpStatusCode.OK)]
    [InlineData(Actor.Admin, Operation.AdminList, HttpStatusCode.OK)]
    public async Task Endpoint_AnswersTheMatrix_ForEachCallerAndOperation(
        Actor actor, Operation operation, HttpStatusCode expected)
    {
        using var owner = await Factory.RegisterAndLoginAsync();
        using var other = await Factory.RegisterAndLoginAsync();
        using var admin = await Factory.LoginAsSeedAdminAsync();
        using var anonymous = Factory.CreateClient();

        var note = await CreateNoteAsync(owner);

        var client = actor switch
        {
            Actor.Anonymous => anonymous,
            Actor.Owner => owner.Client,
            Actor.OtherUser => other.Client,
            Actor.Admin => admin.Client,
            _ => throw new ArgumentOutOfRangeException(nameof(actor)),
        };

        var response = await SendAsync(client, operation, note.Id);

        Assert.Equal(expected, response.StatusCode);
    }

    private static async Task<NoteResponse> CreateNoteAsync(AuthenticatedClient owner)
    {
        var response = await owner.Client.PostAsJsonAsync(
            "/api/notes", new CreateNoteRequest("The owner's note", "Owned content"));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        return (await response.Content.ReadFromJsonAsync<NoteResponse>())!;
    }

    private static Task<HttpResponseMessage> SendAsync(HttpClient client, Operation operation, Guid id) =>
        operation switch
        {
            Operation.Read => client.GetAsync($"/api/notes/{id}"),
            Operation.Update => client.PutAsJsonAsync(
                $"/api/notes/{id}", new UpdateNoteRequest("Edited", "Edited content")),
            Operation.Delete => client.DeleteAsync($"/api/notes/{id}"),
            Operation.List => client.GetAsync("/api/notes"),
            Operation.AdminList => client.GetAsync("/api/admin/notes"),
            _ => throw new ArgumentOutOfRangeException(nameof(operation)),
        };
}
