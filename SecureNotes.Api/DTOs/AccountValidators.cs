using FluentValidation;

namespace SecureNotes.Api.DTOs;

public sealed class ConfirmEmailRequestValidator : AbstractValidator<ConfirmEmailRequest>
{
    public ConfirmEmailRequestValidator()
    {
        RuleFor(r => r.UserId).NotEmpty();
        RuleFor(r => r.Token).NotEmpty().MaximumLength(2048);
    }
}

public sealed class EmailOnlyRequestValidator : AbstractValidator<EmailOnlyRequest>
{
    public EmailOnlyRequestValidator()
    {
        RuleFor(r => r.Email).NotEmpty().EmailAddress().MaximumLength(256);
    }
}

public sealed class ResetPasswordRequestValidator : AbstractValidator<ResetPasswordRequest>
{
    public ResetPasswordRequestValidator()
    {
        RuleFor(r => r.UserId).NotEmpty();
        RuleFor(r => r.Token).NotEmpty().MaximumLength(2048);
        RuleFor(r => r.NewPassword).NotEmpty().MinimumLength(12).MaximumLength(256);
    }
}

public sealed class ChangePasswordRequestValidator : AbstractValidator<ChangePasswordRequest>
{
    public ChangePasswordRequestValidator()
    {
        RuleFor(r => r.CurrentPassword).NotEmpty().MaximumLength(256);
        RuleFor(r => r.NewPassword).NotEmpty().MinimumLength(12).MaximumLength(256);

        // Not a security control, just an unhelpful no-op worth catching early.
        RuleFor(r => r.NewPassword).NotEqual(r => r.CurrentPassword)
            .WithMessage("The new password must be different from the current one.");
    }
}
