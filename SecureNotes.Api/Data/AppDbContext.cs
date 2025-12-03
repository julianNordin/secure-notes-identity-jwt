using Microsoft.EntityFrameworkCore;
using SecureNotes.Api.Domain;

namespace SecureNotes.Api.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<Note> Notes => Set<Note>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<Note>(note =>
        {
            note.Property(n => n.Title).HasMaxLength(200);
            note.Property(n => n.Content).HasMaxLength(20_000);

            // Every list query in this project filters by owner, because that is
            // what "users see only their own notes" means at the database level.
            // Without this index that filter is a sequential scan over a table
            // that only ever grows.
            note.HasIndex(n => n.OwnerId);
        });
    }
}
