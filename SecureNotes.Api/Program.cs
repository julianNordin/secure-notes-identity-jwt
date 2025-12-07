using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureNotes.Api.Data;
using SecureNotes.Api.Domain;

var builder = WebApplication.CreateBuilder(args);

// Fail at startup with something a human can act on, rather than at the first
// request with a connection error that reads like the database is down.
var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException(
        "No connection string named 'Default' was found. Set ConnectionStrings:Default in " +
        "appsettings.Development.json, or ConnectionStrings__Default in the environment. " +
        "`docker compose up -d db` starts the database it expects.");

builder.Services.AddDbContext<AppDbContext>(options => options.UseNpgsql(connectionString));

// AddIdentityCore, not AddIdentity. AddIdentity additionally registers the three
// Identity cookie schemes and makes IdentityConstants.ApplicationScheme the
// default authentication scheme. This API authenticates with bearer tokens, and
// with the cookie scheme in front, a request carrying no token gets a 302 to
// /Account/Login instead of a 401 - and then a 404, because no such page is
// registered. The symptom reads like a routing bug and is nothing of the kind.
builder.Services
    .AddIdentityCore<AppUser>(options =>
    {
        // Length is the only password rule that reliably buys entropy. Character
        // class requirements mostly produce Password1! and a sticky note, and
        // NIST SP 800-63B stopped recommending them for that reason.
        options.Password.RequiredLength = 12;
        options.Password.RequireDigit = false;
        options.Password.RequireLowercase = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireNonAlphanumeric = false;

        // Two accounts sharing an email would make "log in with your email"
        // ambiguous, and the login lookup below assumes it is not.
        options.User.RequireUniqueEmail = true;

        // Applied by SignInManager.CheckPasswordSignInAsync(lockoutOnFailure: true)
        // in Phase 05, and proven end to end in Phase 12.
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.Lockout.AllowedForNewUsers = true;
    })
    .AddRoles<AppRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddSignInManager();

// AddDefaultTokenProviders() is deliberately NOT here. It registers
// DataProtectorTokenProvider, which needs IDataProtectionProvider, which
// AddIdentityCore does not bring with it - so registering it now fails DI
// validation at startup. Nothing needs those providers until email confirmation
// and password reset in Phase 12, and data protection key persistence is a
// decision that belongs in that phase rather than smuggled in here.

builder.Services.AddControllers();

var app = builder.Build();

app.MapControllers();

app.Run();
