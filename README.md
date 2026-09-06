# secure-notes-identity-jwt

[![CI](https://github.com/julianNordin/secure-notes-identity-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/julianNordin/secure-notes-identity-jwt/actions/workflows/ci.yml)
[![.NET](https://img.shields.io/badge/.NET-9.0-512BD4)](https://dotnet.microsoft.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17-4169E1)](https://www.postgresql.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB)](https://react.dev/)
[![Tests](https://img.shields.io/badge/tests-103%20passing-2ea44f)](#testing)

A personal notes API where **authentication is the feature**. Users see only their own notes,
admins see all of them, and the notes themselves are deliberately boring so that the interesting
part — ASP.NET Core Identity, JWT access tokens, rotating refresh tokens with reuse detection, and
three distinct styles of authorization — is what a reader's attention lands on.

**Status:** ✅ Complete — all 18 phases. See [Roadmap](#roadmap) below.

## Why this project

Most JWT tutorials stop at "here is a token, here is `[Authorize]`". That leaves out everything
that makes auth hard: what happens when a refresh token is stolen, how you revoke a token that is
by definition not revocable, why a `403` can be an information leak, and how you prove any of it
with tests. This project is built around those questions.

A few of the answers it commits to, each of which has a test that fails when it is undone:

- A note belonging to somebody else returns **`404`, never `403`** — and byte-identically to a note
  that never existed, because otherwise the pair is an oracle for finding valid ids.
- Registering an address that is already taken returns the **same `202`** as registering a new one.
  The "you already have an account" message goes to the email itself, where only its owner reads it.
- A replayed refresh token **revokes the entire token family**, logging out the legitimate user too.
  That is the correct trade, and it is uncomfortable enough to be worth stating out loud.
- Every endpoint is protected **by default** by a fallback policy, so forgetting `[Authorize]` fails
  closed rather than open.

## Tech stack

| Layer | Choice |
|---|---|
| API | ASP.NET Core 9, controllers |
| Identity | ASP.NET Core Identity (`AddIdentityCore`), PBKDF2-HMAC-SHA512, 100k iterations |
| Tokens | JWT bearer (HS256) access tokens, rotating refresh tokens with family reuse detection |
| Data | EF Core 9, PostgreSQL 17 |
| Hardening | Rate limiting, RFC 9457 problem details, security headers, health checks |
| Tests | xUnit, `WebApplicationFactory`, Testcontainers — 103 tests against real Postgres |
| Client | React 19, TypeScript, Vite |

## The token lifecycle

The centre of the project. Two credentials with deliberately different properties:

```
  POST /api/auth/login
    │
    ├──►  access token    JWT, HS256, 15 minutes.  Response body.
    │                     Held in memory by the client and never in storage.
    │
    └──►  refresh token   32 CSPRNG bytes, 14 days.  httpOnly + Secure +
                          SameSite=Strict cookie, scoped to /api/auth.
                          Stored server-side as SHA-256 only - never in the clear.

  ...fifteen minutes pass, the access token expires...

  POST /api/auth/refresh          family f
    │                             ┌───────────────────────────────┐
    ├──►  new access token        │  RT1  ──►  RT2  ──►  RT3      │
    └──►  new refresh token RT2   │ spent     spent      live     │
          RT1 is spent forever    └───────────────────────────────┘
          (rotation: a token works exactly once, so a copy taken in
           transit dies the moment the real client next refreshes)

  someone replays RT1
    │
    ├──►  401
    └──►  the WHOLE of family f is revoked - RT3 dies too, and the real user
          is logged out of that device.

          A spent token being presented means two parties held a copy, and
          nothing in the request distinguishes them: same token, and an IP is
          neither trustworthy nor stable. The cost is one login. The
          alternative is leaving a known-compromised session open.

  meanwhile, revoking an access token that is by definition not revocable:

  POST /api/auth/logout-all  ──►  refresh tokens revoked  (no new access tokens)
                             └─►  security stamp rolled   (live ones die at once)

          The stamp rides in the token and is checked on every request, which
          costs one indexed read and buys back revocation. Without the second
          half, "log out everywhere" would quietly mean "within fifteen minutes".
```

## Threat model

What this defends against, and — more usefully — what it does not.

**Defended**

| Threat | Defence |
|---|---|
| Password database dump | PBKDF2-HMAC-SHA512, 100k iterations, per-user salt. Swapping in Argon2id is one DI registration. |
| Refresh token database dump | Only SHA-256 hashes are stored. A dump is not a room full of live sessions. |
| Stolen refresh token | Rotation makes it single-use; replay revokes the whole family and logs everyone out. |
| Stolen access token | 15-minute lifetime, and a security-stamp check that revokes it immediately on password change or logout-all. |
| XSS reading the refresh token | It is an httpOnly cookie. Script cannot read it — this is what Phase 18 bought. |
| CSRF | `SameSite=Strict` on the refresh cookie; the access token rides in a header no cross-site form can set. |
| Account enumeration | Register, login, forgot-password and reset all answer identically whether or not the address exists. |
| Resource enumeration | Another user's note is `404`, byte-identical to one that never existed. |
| Credential stuffing | 10 requests/minute per IP on `/api/auth`, plus Identity lockout at 5 failures for 15 minutes. |
| Algorithm confusion / `alg:none` | An explicit `ValidAlgorithms` allow-list of exactly `HS256`. |
| Forgetting `[Authorize]` | A fallback policy protects every endpoint unless it says `[AllowAnonymous]`. |

**Not defended, and deliberately so**

- **XSS in general.** An httpOnly cookie stops a script *taking the refresh token home*. It does not
  stop that script making requests as the user while its page is open. The access token is in
  memory, which is where any script on the origin can reach it too. Content-Security-Policy is set,
  but the real defence against XSS is not shipping XSS.
- **A compromised server.** The signing key signs tokens; anyone holding it mints them. This is why
  the key never touches a tracked file, and why the app refuses to boot on a weak or placeholder one.
- **Anything at the transport layer.** The dev setup is HTTP on localhost. `Secure` cookies and HSTS
  assume TLS in front, and nothing here terminates it.
- **A malicious admin.** An admin can read every note by design. The one deliberate limit is that
  they may **not** edit or delete one — seeing something is not a reason to be able to rewrite it
  silently — but this is not a defence against an admin who wants to read your notes.
- **Denial of service beyond the auth endpoints.** Rate limiting covers `/api/auth`, which is what an
  anonymous caller can hammer. Everything else needs a valid token, which is its own limit, and a
  determined authenticated user can still be expensive.
- **Timing side channels.** Registration hashes-and-discards on the duplicate path so both branches
  do comparable work, but the honest claim is that the difference is smaller than network jitter —
  not that it is constant time.

## Getting started

**Prerequisites:** .NET 9 SDK, Docker (for the database), Node 20+ (for the client).

```bash
docker compose up -d db

# The signing key never lives in a tracked file. The app refuses to boot without
# one, on anything shorter than 32 bytes, or on the .env.example placeholder.
cd SecureNotes.Api
dotnet user-secrets set "Jwt:SigningKey" "$(openssl rand -base64 48)"
cd ..

dotnet run --project SecureNotes.Api      # http://localhost:5080, Swagger at /swagger
```

The client is optional and lives in `client/`:

```bash
cd client
npm ci
npm run dev                               # http://localhost:5173
```

Optionally seed a development admin, whose credentials come from configuration and never
from a literal in the source:

```bash
cd SecureNotes.Api
dotnet user-secrets set "Seed:AdminEmail" "admin@securenotes.local"
dotnet user-secrets set "Seed:AdminPassword" "$(openssl rand -base64 24)"
```

## Endpoints

Anonymous endpoints are marked; everything else needs a bearer token, because the
fallback policy protects anything that does not say otherwise.

| Method | Route | Auth | Notes |
|---|---|---|---|
| `POST` | `/api/auth/register` | anonymous | Always `202`, new address or not |
| `POST` | `/api/auth/login` | anonymous | `200` + refresh cookie. Every failure is the same `401` |
| `POST` | `/api/auth/refresh` | cookie | Rotates. Replay revokes the family |
| `POST` | `/api/auth/logout` | cookie | Always `204` |
| `POST` | `/api/auth/logout-all` | bearer | Revokes every token and rolls the security stamp |
| `GET` | `/api/auth/me` | bearer | The caller's own account |
| `POST` | `/api/auth/confirm-email` | anonymous | Idempotent, not single-use |
| `POST` | `/api/auth/resend-confirmation` | anonymous | Always `202` |
| `POST` | `/api/auth/forgot-password` | anonymous | Always `202`, address or not |
| `POST` | `/api/auth/reset-password` | anonymous | Ends every session, including the caller's |
| `POST` | `/api/auth/change-password` | bearer | Ends every session, including the caller's |
| `GET` | `/api/notes` | bearer | Paged, `?search=`, owner-filtered in SQL |
| `POST` | `/api/notes` | bearer | Policy `CanWriteNotes`: confirmed email **or** inside the grace period |
| `GET` `DELETE` | `/api/notes/{id}` | bearer | Resource-based; another user's note is `404` |
| `PUT` | `/api/notes/{id}` | bearer | Resource-based **and** `CanWriteNotes` |
| `GET` | `/api/admin/notes` | `Admin` | Every note, with owner email |
| `GET` | `/api/admin/users` | `Admin` | No password hashes, no security stamps |
| `GET` | `/health` | anonymous | `503` when the database is down |

## A walkthrough with curl

```bash
# Registering a new address and registering one that already exists are
# indistinguishable - both 202, same body. Run it twice and compare.
curl -i -X POST localhost:5080/api/auth/register \
     -H 'Content-Type: application/json' \
     -d '{"email":"ada@example.com","password":"correct horse battery staple","displayName":"Ada"}'

# Login. The access token comes back in the body; the refresh token does not -
# it is a Set-Cookie the page's own script could never read.
curl -i -X POST localhost:5080/api/auth/login -c jar.txt \
     -H 'Content-Type: application/json' \
     -d '{"email":"ada@example.com","password":"correct horse battery staple"}'
# Set-Cookie: refresh_token=...; path=/api/auth; secure; samesite=strict; httponly

A=<the access_token from above>

curl -i  localhost:5080/api/notes                                 # 401, no token
curl -s  localhost:5080/api/notes -H "Authorization: Bearer $A"   # 200
curl -i  localhost:5080/api/notes/$SOMEONE_ELSES -H "Authorization: Bearer $A"  # 404, never 403
curl -i  localhost:5080/api/notes/$NEVER_EXISTED -H "Authorization: Bearer $A"  # the same 404
curl -i  localhost:5080/api/admin/notes -H "Authorization: Bearer $A"           # 403 - route is no secret
curl -i  localhost:5080/api/notes -H "Authorization: Bearer ${A}x"              # 401, tampered

# Rotation, then the interesting part.
curl -i -X POST localhost:5080/api/auth/refresh -b jar.txt -c jar2.txt   # 200, rotated pair
curl -i -X POST localhost:5080/api/auth/refresh -b jar.txt               # 401, replay detected
curl -i -X POST localhost:5080/api/auth/refresh -b jar2.txt              # 401, family revoked
# The third one is the point: jar2 held a live token that was never presented
# twice by anyone, and the replay took it down as collateral.

# Rate limiting, on the endpoints an anonymous caller can hammer.
for i in $(seq 1 15); do curl -s -o /dev/null -w '%{http_code} ' \
  -X POST localhost:5080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"wrong"}'; done
# 401 x10 then 429 x5, with Retry-After: 60

curl -s localhost:5080/health                                            # Healthy
```

## OAuth2, named rather than outsourced

There is no external identity provider here, and nothing that needs the internet. What there is,
is the OAuth2 model applied honestly and labelled:

| RFC 6749 | Here |
|---|---|
| §4.3 `password` grant | `POST /api/auth/login` |
| §6 `refresh_token` grant | `POST /api/auth/refresh` |
| §5.1 token response | `access_token`, `token_type`, `expires_in` — the RFC's field names, not invented camel-case |
| Scopes | Role claims, checked by policy |
| [OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics) §4.14 | Refresh token rotation with reuse detection — the recommendation for public clients, implemented rather than cited |

Swagger declares a `Bearer` security scheme and describes the grant mapping in its document
description. It deliberately does **not** declare an OAuth2 flow: Swagger UI's password flow posts
`grant_type=password` as form data, and this API's `/api/auth/login` takes JSON. Declaring the flow
would light up an Authorize button that produces a request the server rejects — a scheme that
claims a capability the code does not have, which is worse than not claiming it. The mapping above
is the honest version of the same statement.

## Three styles of authorization, side by side

The API uses all three deliberately, because the interesting thing is where each one runs out of
road.

| Style | Example | When it is the right tool |
|---|---|---|
| **Role** | `[Authorize(Roles = "Admin")]` | "Is the caller a member of X." Nothing more. |
| **Policy** | `[Authorize(Policy = "CanWriteNotes")]` | Any rule about the caller that is not membership — here, a confirmed email **or** an account inside a seven-day grace period. |
| **Resource** | `IAuthorizationService.AuthorizeAsync(User, note, NoteOperations.Update)` | Any rule about the caller **and a specific object**. Ownership cannot be expressed in an attribute, because the attribute cannot see the note. |

A role is just a claim with an attribute that knows its name. The moment a rule says anything other
than "is a member of", the attribute has run out of road and a policy has not.

Resource handlers are for the single-item path only. The list endpoint keeps a `WHERE` clause,
because authorizing ten thousand rows one at a time is not a design, it is a load test.

### The authorization matrix

Twenty cells, asserted by one table-driven test — the artefact that makes all three styles legible
at a glance:

| | read | update | delete | list | admin-list |
|---|---|---|---|---|---|
| **anonymous** | 401 | 401 | 401 | 401 | 401 |
| **owner** | 200 | 200 | 204 | 200 | 403 |
| **other user** | **404** | **404** | **404** | 200 | 403 |
| **admin** | **200** | **403** | **403** | 200 | 200 |

Both refusal codes appear, and the difference is the whole point. Another user's note is **`404`**
because there the note's *existence* is the secret. A non-admin on `/api/admin/notes` is **`403`**
because they already know the route exists, and hiding it would be dishonest to no purpose.

The admin row is a deliberate asymmetry: an admin may read any note and may **not** rewrite or
delete one. Widening that later is one line; explaining an edit nobody made is not.

## Testing

```bash
docker compose up -d db     # not required - the tests start their own container
dotnet test                 # 103 tests, ~40s cold
```

Three tiers, fastest first:

| Tier | What it proves | Cost |
|---|---|---|
| Handler unit tests | The authorization rules themselves, with a `FakeTimeProvider` and no host at all | 8 tests in ~190ms |
| Auth flow integration | Registration, login, rotation, reuse detection, revocation, token forgery, lockout, cookie flags | real Postgres |
| Authorization matrix | The twenty cells above, the fallback policy, and `404` indistinguishability | real Postgres |

Every test runs against **real PostgreSQL** through Testcontainers — never an in-memory provider.
Half of what this project asserts is about unique indexes, cascade deletes and Identity's own
schema, none of which behave the same on a fake.

A note on method: several of these tests were **deliberately made to fail** before being believed —
by removing the fallback policy, flipping the grace-period comparison from `<=` to `<`, dropping
each cookie flag in turn, and putting the refresh token back in the login body. A test that has
never been seen to fail is not yet a test. One of those runs found a flawed *test* rather than
flawed code, which is the argument for doing it.

## Project structure

```
SecureNotes.Api/
  Common/            JwtOptions + startup validation, ClaimsPrincipalExtensions,
                     RefreshCookie, GlobalExceptionHandler, SecurityHeadersMiddleware
    Authorization/   NoteOperations, NoteAuthorizationHandler,
                     EmailConfirmationRequirement + handler, Policies
  Controllers/       AuthController, NotesController, AdminController
  Data/              AppDbContext, DbInitializer, Migrations/
  Domain/            Note, AppUser, AppRole, RefreshToken
  DTOs/              Requests, responses, FluentValidation validators
  Services/          AuthService, TokenService, RefreshTokenService,
                     NoteService, LoggingEmailSender
SecureNotes.Api.Tests/
  TestHelpers/       NotesApiFactory, AuthenticatedClient, RefreshCookies,
                     RebindableClock, DeliberatelyBareController
  Auth/              Registration, login, rotation, reuse, revocation,
                     token integrity, lockout, refresh cookie
  Authorization/     The matrix, fallback policy, both handlers
client/
  src/lib/           apiClient.ts - the token store and single-flight refresh
  src/context/       AuthProvider, useAuth
  src/pages/         Login, Register, Notes
```

## Roadmap

- [x] **01** · Solution scaffold, repo hygiene & Compose Postgres
- [x] **02** · Notes domain, EF Core & first migration
- [x] **03** · ASP.NET Core Identity: users, roles, schema
- [x] **04** · Registration & password hashing
- [x] **05** · Login & JWT access tokens
- [x] **06** · Owner-scoped Notes API
- [x] **07** · Refresh tokens: issue, rotate, revoke
- [x] **08** · Reuse detection & security-stamp invalidation
- [x] **09** · Role-based authorization
- [x] **10** · Policy-based authorization & secure-by-default
- [x] **11** · Resource-based authorization
- [x] **12** · Account lifecycle: lockout, email confirmation, password reset
- [x] **13** · Hardening: rate limiting, ProblemDetails, headers, health
- [x] **14** · Integration test harness: WebApplicationFactory + Testcontainers
- [x] **15** · Integration tests: authentication flows
- [x] **16** · Integration tests: the authorization matrix
- [x] **17** · React login client
- [x] **18** · The httpOnly cookie refactor, CI, README, `v1.0`

## License

Personal learning/portfolio project — no license specified yet.
