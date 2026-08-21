# Downstream durable backend integration checklist

This checklist is for consumers that persist CapAuth authorization state
(revocations, replay reservations, principal snapshots, issuer policy) in
their own PostgreSQL database. CapAuth provides the capability token model,
verification, and contracts. The consumer owns the schema, the roles, the
grants, and the migrations. Every pitfall below was discovered by a red
gate in the first reference consumer, not by documentation.

## 1. Provision roles before migrations

Migration runner roles are deliberately least-privilege and cannot create
roles (`NOCREATEROLE`). Any role your migrations `GRANT` to must be created
by an administrator provisioning step that runs before the migration runner.

- Create grantee roles idempotently in a provisioning script, never inside a
  digest-pinned migration.
- Use the same least-privilege attribute profile as the migrator:
  `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS
  NOREPLICATION`.
- Reject role-graph membership and object ownership for runtime roles at
  provision time, and read the profile back after creating it. Fail closed
  on any drift.
- Document every role class (migrator, per-principal runtime logins, shared
  function grantees) and how they relate. An undocumented grantee inside a
  security migration is a finding, not a detail.

## 2. Re-apply privilege hardening after any function re-creation

PostgreSQL grants `EXECUTE` on new functions to `PUBLIC` by default. The
durable CapAuth functions are `SECURITY DEFINER`, so a missed revoke is a
real privilege leak, not hygiene.

- Every `CREATE FUNCTION` for a CapAuth backend function must be followed,
  in the same migration, by `REVOKE ALL ON FUNCTION <signature> FROM
  PUBLIC` and the explicit `GRANT EXECUTE ... TO <role>`.
- `DROP FUNCTION` plus `CREATE FUNCTION` discards all previous revokes and
  grants. `CREATE OR REPLACE FUNCTION` preserves them. Prefer `CREATE OR
  REPLACE`; if a signature change forces `DROP` plus `CREATE`, re-apply
  every privilege statement from the original migration.
- Down migrations that drop and restore a function must restore its
  privilege state as well, or the restored object silently changes the
  security posture.
- Add a lint rule over your migration set so this class is caught by
  tooling. The reference consumer lints that every definer function carries
  its `REVOKE FROM PUBLIC` and that re-created functions re-apply prior
  grants.

## 3. Verify grants by readback, not by construction

Do not trust that the provisioning script produced the intended privilege
set. Read the effective privileges back and compare against an exact
allowlist.

- `has_function_privilege` and `information_schema.role_table_grants`
  include privileges inherited through `PUBLIC`. That is the point: the
  readback must see what a role can actually do.
- Fail provisioning when the readback differs from the allowlist in either
  direction (missing or extra privileges).
- Repeat the role drift check at application startup; RLS cannot contain a
  login once an administrator grants it `BYPASSRLS`, so role governance is a
  standing deployment trust boundary.

## 4. Test against a real database

Fake executors cannot observe default `PUBLIC` grants, trigger behavior, or
RLS interaction. The exact surface that is the production prerequisite is
the one that must have real-database integration coverage.

- Run the full migration set against a disposable PostgreSQL (for example a
  digest-pinned container with tmpfs storage) in CI.
- Exercise the definer functions through the same provisioning path
  production uses, including concurrent replay-reservation attempts.
- Verify the complete down/up cycle: after a rollback, functions, triggers,
  and privilege state must match the pre-migration baseline.

## Ownership summary

| Artifact | Owner |
|----------|-------|
| Token model, verification, capability contracts | CapAuth library |
| Schema, tables, definer functions, triggers | Consumer migrations |
| Roles and their least-privilege profiles | Consumer provisioning |
| Grants and PUBLIC revokes | Consumer migrations, verified by readback |
| Migration lint and integration qualification | Consumer CI |
