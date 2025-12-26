using System.Text;
using System.Threading.RateLimiting;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.OpenApi;
using Microsoft.IdentityModel.Tokens;
using SecureNotes.Api.Common;
using SecureNotes.Api.Common.Authorization;
using SecureNotes.Api.Data;
using SecureNotes.Api.Domain;
using SecureNotes.Api.Services;

var builder = WebApplication.CreateBuilder(args);

// Fail at startup with something a human can act on, rather than at the first
// request with a connection error that reads like the database is down.
var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException(
        "No connection string named 'Default' was found. Set ConnectionStrings:Default in " +
        "appsettings.Development.json, or ConnectionStrings__Default in the environment. " +
        "`docker compose up -d db` starts the database it expects.");

// ValidateOnStart turns a silent security failure into a startup crash. Without
// it a deployment that forgot Jwt__SigningKey boots happily, signs every token
// with an empty string, and looks fine until someone mints their own admin token.
builder.Services.AddOptions<JwtOptions>()
    .Bind(builder.Configuration.GetSection(JwtOptions.SectionName))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<JwtOptions>, JwtOptionsValidator>();

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
    .AddSignInManager()

    // Deferred here from Phase 03, where it broke startup: DataProtectorTokenProvider
    // needs IDataProtectionProvider, which AddIdentityCore does not register. The
    // AddDataProtection call below is what makes this work, and it belongs in the
    // phase that actually needs email confirmation and password reset tokens.
    .AddDefaultTokenProviders();

// Identity's confirmation and reset tokens are encrypted with these keys, so where
// they live decides how long a token stays valid. The default on Windows is a
// per-user folder, which survives a restart. In a container with no persistent
// volume the keys are regenerated on every start, and every outstanding reset link
// stops working - a bug that looks like "tokens randomly invalid" and is really
// "the keyring was thrown away".
builder.Services.AddDataProtection();


// Injected rather than reached for statically, so Phases 10, 15 and 16 can put a
// FakeTimeProvider in its place and test lockout windows and token expiry without
// a test suite that sleeps.
builder.Services.AddSingleton(TimeProvider.System);

builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<INoteService, NoteService>();
builder.Services.AddScoped<IRefreshTokenService, RefreshTokenService>();
builder.Services.AddScoped<IEmailSender, LoggingEmailSender>();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer();

// Configured through IOptions<JwtOptions> rather than reading configuration
// directly, so the validator above has already run by the time the signing key is
// used here. Reading the raw config would build a zero-length key on a
// misconfigured deployment and throw something unhelpful before the validator got
// its chance to say what was actually wrong.
builder.Services
    .AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IOptions<JwtOptions>>((bearer, jwtOptions) =>
    {
        var jwt = jwtOptions.Value;

        // Off. Left at its default of true, the handler rewrites `sub` to
        // http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier, and
        // User.FindFirst("sub") returns null with no error anywhere - which takes an
        // afternoon to find, because the token visibly contains the claim.
        bearer.MapInboundClaims = false;

        // Signature and expiry are not enough on their own. A JWT cannot be
        // recalled, so this checks the account's security stamp on every request
        // and rejects tokens issued before a password change or a logout-all.
        bearer.Events = new JwtBearerEvents
        {
            OnTokenValidated = SecurityStampCheck.ValidateAsync,
        };

        // Every flag is written out even where it matches the default. These are the
        // security properties of the whole API; inheriting them silently means nobody
        // can review them, and a future package update could change one.
        bearer.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwt.Issuer,

            ValidateAudience = true,
            ValidAudience = jwt.Audience,

            ValidateLifetime = true,

            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey)),

            // An explicit allow-list of one. This is what makes algorithm confusion
            // and `"alg":"none"` unreachable rather than merely unlikely: a token
            // whose header names anything else is rejected before its signature is
            // even considered.
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],

            // The default is five minutes, which means an "expired" token keeps
            // working for another five. That default exists for clock drift between
            // separate machines, and this process both signs and validates.
            ClockSkew = TimeSpan.Zero,

            NameClaimType = JwtRegisteredClaimNames.Sub,
            RoleClaimType = TokenService.RoleClaim,
        };
    });

builder.Services.AddSingleton<IAuthorizationHandler, EmailConfirmationHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, NoteAuthorizationHandler>();

builder.Services
    .AddAuthorizationBuilder()

    // Secure by default. The point of a fallback policy is the failure mode it
    // creates: without one, forgetting [Authorize] on a new endpoint publishes it
    // to anyone who finds the URL, and nothing anywhere complains - the symptom of
    // the mistake is that everything works. With one, the same forgetting returns
    // 401 and gets noticed in minutes. It also inverts who has to be careful: the
    // endpoints that are deliberately public now have to say so, and that list is
    // short enough to read in one screen and audit.
    .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())

    // The same rule as [Authorize(Roles = "Admin")], written the other way round so
    // the two forms can be compared. A role is a claim with an attribute that knows
    // its name; the moment a rule says anything other than "is a member of", the
    // attribute has run out of road and a policy has not.
    .AddPolicy(Policies.RequireAdmin, policy => policy.RequireRole(Roles.Admin))

    .AddPolicy(Policies.CanWriteNotes, policy =>
        policy.AddRequirements(new EmailConfirmationRequirement(Policies.ConfirmationGrace)))
;

// Keyed by client IP so one noisy source cannot lock everyone else out, and
// applied only to /api/auth. The rest of the API needs a valid token to reach
// at all, which is its own limit; these endpoints are the ones an anonymous
// caller can hammer, and they are where credential stuffing lands.
builder.Services.AddRateLimiter(limiter =>
{
    limiter.AddPolicy(RateLimits.AuthPolicy, context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = RateLimits.AuthPermitsPerWindow,
                Window = RateLimits.AuthWindow,

                // No queue. Queueing a rejected login means holding a connection
                // open on behalf of whoever is attacking you, which turns a rate
                // limit into a resource the attacker gets to consume.
                QueueLimit = 0,
            }));

    limiter.OnRejected = async (context, cancellationToken) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;

        // Without Retry-After a well-behaved client has no idea whether to come
        // back in a second or an hour, so it guesses, and usually guesses wrong.
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            context.HttpContext.Response.Headers.RetryAfter =
                ((int)retryAfter.TotalSeconds).ToString();
        }

        await context.HttpContext.Response.WriteAsJsonAsync(
            new ProblemDetails
            {
                Type = "https://tools.ietf.org/html/rfc9110#section-15.5.29",
                Title = "Too many requests.",
                Status = StatusCodes.Status429TooManyRequests,
                Detail = "Too many attempts from this address. Try again shortly.",
            },
            cancellationToken);
    };
});

// AddProblemDetails is what makes IProblemDetailsService available and gives the
// framework's own 4xx responses the same RFC 9457 shape the handlers produce, so a
// client has one error format to parse rather than two.
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

builder.Services.AddHealthChecks().AddNpgSql(connectionString, name: "postgres");

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(swagger =>
{
    swagger.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "SecureNotes",
        Version = "v1",
        Description =
            "A personal notes API where authentication is the feature. /api/auth/login is the " +
            "OAuth2 password grant and /api/auth/refresh the refresh_token grant.",
    });

    // The XML the csproj is already generating. Without this the endpoint summaries
    // written on the controllers exist only in the source.
    swagger.IncludeXmlComments(Path.Combine(
        AppContext.BaseDirectory,
        $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml"));

    // Type=Http with Scheme=bearer, not ApiKey-in-header. The difference is real:
    // this way the UI adds "Bearer " itself, so pasting a raw token works instead
    // of silently producing an unparseable header.
    swagger.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Paste the access_token from POST /api/auth/login. No \"Bearer\" prefix.",
    });

    // Microsoft.OpenApi 2.x, which Swashbuckle 10 depends on, replaced the old
    // "an OpenApiSecurityScheme carrying a Reference" shape with a dedicated
    // reference type. The 3.x recipe every tutorial still shows does not compile.
    swagger.AddSecurityRequirement(document => new OpenApiSecurityRequirement
    {
        [new OpenApiSecuritySchemeReference("Bearer", document)] = [],
    });
});

builder.Services.AddValidatorsFromAssemblyContaining<Program>();

// One globally registered filter is the entire validation mechanism, so when a
// request is not being validated there is exactly one place to look.
builder.Services.AddControllers(options => options.Filters.Add<ValidationFilter>());

var app = builder.Build();

await DbInitializer.SeedAsync(app.Services);

// First in the pipeline, so a 500 anywhere below still comes back as a problem
// document rather than an empty response or a stack trace.
app.UseExceptionHandler();

app.UseMiddleware<SecurityHeadersMiddleware>();

// Before authentication, deliberately. An unauthenticated flood is exactly what
// this exists to stop, and a limiter placed after the authentication middleware
// only ever sees the requests that already got through.
app.UseRateLimiter();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Order is the feature. UseAuthentication turns the Authorization header into a
// ClaimsPrincipal; UseAuthorization decides what that principal may do. Reversed,
// or with the first one missing, authorization runs against an anonymous principal
// and every [Authorize] endpoint answers 401 no matter how good the token is.
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// AllowAnonymous explicitly: the fallback policy from Phase 10 covers endpoints,
// and this is one. Swagger got away without it only because it is middleware that
// runs before the endpoint pipeline.
app.MapHealthChecks("/health").AllowAnonymous();

app.Run();
