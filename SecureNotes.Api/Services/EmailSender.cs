namespace SecureNotes.Api.Services;

public interface IEmailSender
{
    Task SendAsync(string to, string subject, string body, CancellationToken cancellationToken);
}

/// <summary>
/// Writes the message to the log instead of sending it.
/// </summary>
/// <remarks>
/// <para>
/// No SMTP, no API key, no network, nothing to leak - and the confirmation and
/// reset tokens are copy-pasteable out of the console, which is what makes the
/// whole flow testable by hand and in Phase 15.
/// </para>
/// <para>
/// The interface is the point rather than this implementation. Everything that
/// needs to reach a user reaches it through one method, so swapping in a real
/// provider is one registration and touches nothing that decides *what* to send.
/// </para>
/// </remarks>
public sealed class LoggingEmailSender(ILogger<LoggingEmailSender> logger) : IEmailSender
{
    public Task SendAsync(string to, string subject, string body, CancellationToken cancellationToken)
    {
        // Deliberately one entry rather than a structured payload per field: this is
        // meant to be read by a person during development, not queried.
        logger.LogInformation(
            "EMAIL to {Recipient}\n  Subject: {Subject}\n  {Body}", to, subject, body);

        return Task.CompletedTask;
    }
}
