using Microsoft.EntityFrameworkCore;
using SecureNotes.Api.Data;

var builder = WebApplication.CreateBuilder(args);

// Fail at startup with something a human can act on, rather than at the first
// request with a connection error that reads like the database is down.
var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException(
        "No connection string named 'Default' was found. Set ConnectionStrings:Default in " +
        "appsettings.Development.json, or ConnectionStrings__Default in the environment. " +
        "`docker compose up -d db` starts the database it expects.");

builder.Services.AddDbContext<AppDbContext>(options => options.UseNpgsql(connectionString));

builder.Services.AddControllers();

var app = builder.Build();

app.MapControllers();

app.Run();
