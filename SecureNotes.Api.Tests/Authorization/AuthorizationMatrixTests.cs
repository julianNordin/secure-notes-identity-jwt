using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
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

    /// <summary>
    /// The claim the matrix cannot make on its own. The table proves that another
    /// user's note answers 404; it does not prove that this is the *same* 404 an id
    /// which never existed produces. If the two differed by so much as a word the
    /// pair would be an oracle - ask for an id, and the shape of the refusal tells
    /// you whether there is a real note behind it you are not allowed to see. That
    /// is exactly the question 404 was chosen in order not to answer, so the
    /// sameness is the feature and the matrix cell is only half of it.
    /// </summary>
    /// <remarks>
    /// Written first as a raw byte comparison, which cannot pass: ProblemDetails
    /// carries a per-request traceId, so no two responses of any kind are ever
    /// byte-identical. The third request is the control that establishes this - two
    /// refusals that are both saying nothing still differ - which is what makes
    /// normalising the traceId away honest rather than convenient.
    /// </remarks>
    [Theory]
    [InlineData(Operation.Read)]
    [InlineData(Operation.Update)]
    [InlineData(Operation.Delete)]
    public async Task Endpoint_RefusesSomebodyElsesNoteExactlyAsItRefusesAnIdThatNeverExisted(
        Operation operation)
    {
        using var owner = await Factory.RegisterAndLoginAsync();
        using var other = await Factory.RegisterAndLoginAsync();

        var note = await CreateNoteAsync(owner);

        var hidden = await SendAsync(other.Client, operation, note.Id);
        var absent = await SendAsync(other.Client, operation, Guid.CreateVersion7());
        var absentAgain = await SendAsync(other.Client, operation, Guid.CreateVersion7());

        Assert.Equal(HttpStatusCode.NotFound, hidden.StatusCode);
        Assert.Equal(hidden.StatusCode, absent.StatusCode);
        Assert.Equal(hidden.Content.Headers.ContentType, absent.Content.Headers.ContentType);

        var hiddenBody = Anonymised(await hidden.Content.ReadAsStringAsync());
        var absentBody = await absent.Content.ReadAsStringAsync();
        var absentAgainBody = await absentAgain.Content.ReadAsStringAsync();

        // The control. Two ids that both never existed cannot be telling the caller
        // anything different, and their raw bodies still differ - so a raw
        // comparison proves nothing either way. What survives normalisation is the
        // only part that could carry a signal, and it also shows the requested id
        // is not echoed back.
        Assert.NotEqual(absentBody, absentAgainBody);
        Assert.Equal(Anonymised(absentBody), Anonymised(absentAgainBody));

        // Not vacuous: the body has to be shown to say something before its
        // sameness means anything. Two empty strings are also equal.
        Assert.Contains("\"status\":404", hiddenBody);
        Assert.Equal(Anonymised(absentBody), hiddenBody);
    }

    /// <summary>
    /// Blanks the one field that differs on every response the application has ever
    /// produced - the per-request correlation id - and leaves every other byte where
    /// it is, so an extra field, a reordering or a stray space all still count as a
    /// difference worth failing over.
    /// </summary>
    private static string Anonymised(string body) =>
        Regex.Replace(body, "\"traceId\":\"[^\"]*\"", "\"traceId\":\"<per-request>\"");

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
