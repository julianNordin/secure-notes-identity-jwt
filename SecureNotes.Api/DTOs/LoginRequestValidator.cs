using FluentValidation;

namespace SecureNotes.Api.DTOs;

public sealed class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(r => r.Email).NotEmpty().MaximumLength(256);

        // Deliberately no minimum length and no format rule. Login validates
        // credentials, it does not re-state the registration policy: telling a
        // caller their password is "too short to be one of ours" narrows a guess,
        // and the password rules may change while old passwords stay valid.
        RuleFor(r => r.Password).NotEmpty().MaximumLength(256);
    }
}
