using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

namespace SecureNotes.Api.Tests.TestHelpers;

/// <summary>
/// Gives each test client a remote IP address of its own.
/// </summary>
/// <remarks>
/// TestServer never sets Connection.RemoteIpAddress, so it is null for every
/// request. Phase 13's limiter partitions on exactly that, and a null address
/// falls back to the literal string "unknown" - which means the entire test
/// process shares one bucket of ten requests per minute, and the suite starts
/// answering 429 to its own setup on the sixth account it registers.
///
/// The alternatives were to raise the limit under test or to switch the limiter
/// off, and both delete the coverage rather than fix the harness: Phase 13's
/// middleware ordering is a security property, and a limiter that is disabled
/// while being tested is a limiter nobody has tested. This supplies the one thing
/// a real network stack would have provided, leaving the limiter fully configured
/// and fully exercised - and it makes the limit itself testable, since many
/// requests from one client still share one address and still get cut off.
///
/// It is only ever registered by NotesApiFactory, so no deployed pipeline contains
/// it and no request from outside can reach it. Trusting a client-supplied header
/// for a rate limit partition would be a real vulnerability in production, which
/// is precisely why this lives in the test assembly and not behind a flag in the
/// application.
/// </remarks>
public sealed class TestRemoteIpStartupFilter : IStartupFilter
{
    public const string HeaderName = "X-Test-Remote-Ip";

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) =>
        app =>
        {
            // Added before next(app), which puts it ahead of everything Program.cs
            // registers - including UseRateLimiter, which has to see the address.
            app.Use(async (context, continuePipeline) =>
            {
                if (context.Request.Headers.TryGetValue(HeaderName, out var header)
                    && IPAddress.TryParse(header.ToString(), out var address))
                {
                    context.Connection.RemoteIpAddress = address;
                }

                await continuePipeline(context);
            });

            next(app);
        };
}

