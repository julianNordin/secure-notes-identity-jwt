# secure-notes-identity-jwt

[![.NET](https://img.shields.io/badge/.NET-9.0-512BD4)](https://dotnet.microsoft.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17-4169E1)](https://www.postgresql.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB)](https://react.dev/)

A personal notes API where **authentication is the feature**. Users see only their own notes,
admins see all of them, and the notes themselves are deliberately boring so that the interesting
part — ASP.NET Core Identity, JWT access tokens, rotating refresh tokens with reuse detection, and
three distinct styles of authorization — is what a reader's attention lands on.

**Status:** 🚧 In progress — Phase 09 of 18 complete. See [Roadmap](#roadmap) below.

## Why this project

Most JWT tutorials stop at "here is a token, here is `[Authorize]`". That leaves out everything
that makes auth hard: what happens when a refresh token is stolen, how you revoke a token that is
by definition not revocable, why a `403` can be an information leak, and how you prove any of it
with tests. This project is built around those questions.

## Tech stack

| Layer | Choice |
|---|---|
| API | ASP.NET Core 9, controllers |
| Identity | ASP.NET Core Identity, PBKDF2 password hashing |
| Tokens | JWT bearer (HS256) access tokens, rotating refresh tokens |
| Data | EF Core 9, PostgreSQL 17 |
| Tests | xUnit, `WebApplicationFactory`, Testcontainers |
| Client | React 19, TypeScript, Vite |

## Getting started

**Prerequisites:** .NET 9 SDK, Docker (for the database), Node 20+ (for the client).

```bash
docker compose up -d db
dotnet run --project SecureNotes.Api      # http://localhost:5080
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
- [ ] **10** · Policy-based authorization & secure-by-default
- [ ] **11** · Resource-based authorization
- [ ] **12** · Account lifecycle: lockout, email confirmation, password reset
- [ ] **13** · Hardening: rate limiting, ProblemDetails, headers, health
- [ ] **14** · Integration test harness: WebApplicationFactory + Testcontainers
- [ ] **15** · Integration tests: authentication flows
- [ ] **16** · Integration tests: the authorization matrix
- [ ] **17** · React login client
- [ ] **18** · The httpOnly cookie refactor, CI, README, `v1.0`

## License

Personal learning/portfolio project — no license specified yet.
