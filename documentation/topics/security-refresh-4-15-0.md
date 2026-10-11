<!--
SPDX-FileCopyrightText: 2026 Vintrepid

SPDX-License-Identifier: MIT
-->

# Stable v4.15.0 security refresh

This fork integrates the complete official `v4.15.0` maintenance release, commit
`d6b2be35cf8f0b8ab84e7a934cfb0d91de0a3c17`, from
[`team-alembic/ash_authentication`](https://github.com/team-alembic/ash_authentication/releases/tag/v4.15.0).
It retains the history of both existing consumer revisions, `f39c0ad` and
`42d1af7`; it does not relabel an older implementation as a patched version.

## Revoked sessions

[CVE-2026-86533 / GHSA-w374-hvrx-66hg](https://github.com/team-alembic/ash_authentication/security/advisories/GHSA-w374-hvrx-66hg)
affects the session reader when `session_identifier :jti` is used without
requiring token presence. The upstream native reader now consults the JTI
revocation store before resolving the subject. The Plug helper and token-read
security leaves match the official release exactly. Independent native tests
re-read captured sessions after logout for both stored and unstored tokens.

The Phoenix LiveView reader is an independent implementation. Hosts using it
also require `ash_authentication_phoenix >= 2.17.4`; updating this core fork
alone is not sufficient. See
[the Phoenix advisory](https://github.com/team-alembic/ash_authentication_phoenix/security/advisories/GHSA-m6x4-4gvp-xwjr).

## Existing fork guarantees

Upstream's conditional native upsert replaces the old row-lock backport.
Single-use revocation is decided by the database write, including for read
actions that have no surrounding transaction. The complete upstream suite
includes real separate-connection concurrency scenarios for magic-link read
and registration actions and password sign-in tokens, with token storage both
enabled and disabled. This is a token-consumption guarantee, not exactly-once
delivery or execution of arbitrary external effects.

The earlier fork's explicit `store_all_tokens?` option remains compatible on
`revoke/3` and `revoke_jti/4`: either boolean selects exclusive consumption using
the upstream primitive. An explicit `single_use?` option takes precedence.
Calls without either option retain upstream's idempotent logout semantics.
New integrations should use `single_use?` to express intent rather than token
storage configuration.

Existing insert-only revocation DSL action names remain available for host
configuration compatibility; internal authentication flows no longer depend on
them. Password reset and confirmation preserve their transactional rollback
behavior on revocation failure, and magic-link token-generation errors remain
returned errors rather than pattern-match crashes.

The unchanged strict style check required private helper factoring. Branches,
caller scopes, callback timing, error shapes and constant-time API-key work are
preserved; no style or security check is suppressed. Every security helper body
is inside an attested owning source file, and the session security leaves remain
exactly equal to the official release.

## Verification and source attestation

`security_attestation.json` records official tag provenance, SHA-256 security
source anchors, owning native regression paths and verification results. A
consumer must independently anchor that document to its reviewed immutable Git
revision, actual fetched checkout and loaded app version. A version string or
Hex audit of a Git override is not source verification.

This fork also requires the dependency floors Ash `3.34.6`, Decimal `3.1.2` and
Spark `2.7.6`. The native Hex audit remains unexcluded. No provider,
production-account or application data is included or changed by this refresh.

The complete native `mix check --no-retry` pipeline runs on the repository's
declared Elixir `1.18.3` / OTP `27` toolchain. The complete behavioral suite also
runs on Elixir `1.20.4` / OTP `29`. The latter deprecates upstream's default
protocol argument on `Strategy.action/3`, and Ash intentionally removes its old
`Ash.Resource.record/0` alias on OTP 29. Preserving the protocol avoids breaking
custom host implementations; those upstream compatibility warnings are not
silently suppressed or represented as a passing 1.20 compiler/type gate.

Tests can use `ASH_AUTHENTICATION_TEST_PORT` to select an isolated local
PostgreSQL test server; the upstream default remains `5432`. This affects only
the test repository configuration, not host applications.
