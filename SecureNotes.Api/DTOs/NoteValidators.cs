using FluentValidation;

namespace SecureNotes.Api.DTOs;

public sealed class CreateNoteRequestValidator : AbstractValidator<CreateNoteRequest>
{
    public CreateNoteRequestValidator()
    {
        RuleFor(r => r.Title).NotEmpty().MaximumLength(200);

        // Matches the column. Without it the database raises a truncation error that
        // surfaces as a 500, which is a server error for what is really bad input.
        RuleFor(r => r.Content).NotNull().MaximumLength(20_000);
    }
}

public sealed class UpdateNoteRequestValidator : AbstractValidator<UpdateNoteRequest>
{
    public UpdateNoteRequestValidator()
    {
        RuleFor(r => r.Title).NotEmpty().MaximumLength(200);
        RuleFor(r => r.Content).NotNull().MaximumLength(20_000);
    }
}
