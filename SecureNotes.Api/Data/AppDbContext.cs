using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureNotes.Api.Domain;

namespace SecureNotes.Api.Data;

/// <remarks>
/// All three type arguments are given on purpose. The one-argument overload,
/// <c>IdentityDbContext&lt;AppUser&gt;</c>, silently keeps Identity's default string
/// key for roles and every join table, which does not compile against an AppUser
/// keyed on Guid and, when it does compile, produces a schema with mismatched key
/// types across the Identity tables.
/// </remarks>
public class AppDbContext(DbContextOptions<AppDbContext> options)
    : IdentityDbContext<AppUser, AppRole, Guid>(options)
{
    public DbSet<Note> Notes => Set<Note>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        // This call has to come first. IdentityDbContext maps its seven tables
        // inside OnModelCreating, so skipping it - or calling it after the local
        // configuration - yields a migration containing only Notes, with no
        // AspNetUsers for the foreign key below to point at.
        base.OnModelCreating(builder);

        builder.Entity<Note>(note =>
        {
            note.Property(n => n.Title).HasMaxLength(200);
            note.Property(n => n.Content).HasMaxLength(20_000);

            // Every list query in this project filters by owner, because that is
            // what "users see only their own notes" means at the database level.
            // Without this index the central operation of the API is a sequential
            // scan over a table that only ever grows.
            note.HasIndex(n => n.OwnerId);

            // Cascade: deleting an account deletes the notes it owned. The
            // alternative leaves rows whose OwnerId points at nothing, which is
            // the shape of an accidental data leak the first time a query forgets
            // to join. There is nothing here worth keeping after the owner is gone.
            note.HasOne<AppUser>()
                .WithMany(u => u.Notes)
                .HasForeignKey(n => n.OwnerId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
