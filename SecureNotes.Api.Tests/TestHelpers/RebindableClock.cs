using Microsoft.Extensions.Time.Testing;

namespace SecureNotes.Api.Tests.TestHelpers;

/// <summary>
/// A TimeProvider whose underlying fake clock can be replaced.
/// </summary>
/// <remarks>
/// One host serves the whole suite, so whatever is registered as TimeProvider is
/// registered once and cannot be swapped per test. FakeTimeProvider on its own is
/// not enough to work with, because SetUtcNow refuses to move backwards -
/// "Cannot go back in time." - and winding the clock back is exactly what produces
/// an already-expired access token without sleeping.
///
/// So the singleton is this, and the fake behind it is replaced instead of rewound.
/// Forward travel still goes through FakeTimeProvider.Advance, which is what the
/// grace-period and handler tests want.
/// </remarks>
public sealed class RebindableClock : TimeProvider
{
    public FakeTimeProvider Fake { get; private set; } = new(DateTimeOffset.UtcNow);

    public void RebindTo(DateTimeOffset now) => Fake = new FakeTimeProvider(now);

    public override DateTimeOffset GetUtcNow() => Fake.GetUtcNow();
}
