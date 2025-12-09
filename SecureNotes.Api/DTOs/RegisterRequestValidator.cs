using FluentValidation;

namespace SecureNotes.Api.DTOs;

public sealed class RegisterRequestValidator : AbstractValidator<RegisterRequest>
{
    public RegisterRequestValidator()
    {
        RuleFor(r => r.Email)
            .NotEmpty()
            .EmailAddress()
            .MaximumLength(256);

        RuleFor(r => r.Password)
            .NotEmpty()
            // Mirrors Identity's own RequiredLength of 12. Identity would reject a
            // shorter password anyway, but rejecting it here means the caller gets
            // a field-keyed validation error instead of an Identity error code.
            .MinimumLength(12)
            // An upper bound is a security control, not tidiness. Password hashing
            // is deliberately expensive, so an unbounded password field lets one
            // request burn arbitrary CPU: a ten megabyte password is a denial of
            // service aimed straight at the PBKDF2 loop.
            .MaximumLength(256);

        RuleFor(r => r.DisplayName)
            .MaximumLength(100);
    }
}
