using FluentValidation;

namespace SecureNotes.Api.DTOs;

public sealed class RefreshRequestValidator : AbstractValidator<RefreshRequest>
{
    public RefreshRequestValidator()
    {
        // Bounded, so an unbounded string never reaches the database lookup. Real
        // tokens are a fixed 43 characters; anything much longer is noise.
        RuleFor(r => r.RefreshToken).NotEmpty().MaximumLength(128);
    }
}
