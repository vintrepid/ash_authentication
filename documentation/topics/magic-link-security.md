<!--
SPDX-FileCopyrightText: 2026 Vintrepid

SPDX-License-Identifier: MIT
-->

# Magic link security review and hardening plan

This note records the security review that led to the
`security/magic-link-hardening-v4` branch. It covers Ash Authentication's
responsibilities, the obligations of Phoenix integrations and applications,
and the work needed before an email link should be treated as sufficient for a
privileged account.

## Bottom line

Ash Authentication v4.14.1 has a sound signed-token foundation, a ten-minute
default magic-link lifetime, optional user interaction, and a single-use option
that defaults to true. However, v4.14.1's token revocation used an upsert after
verification. Concurrent requests could both verify before either revocation
committed, so "single use" was not an atomic guarantee.

This branch backports the atomic revocation design from upstream PR
[#1153](https://github.com/team-alembic/ash_authentication/pull/1153) to the
v4.14.1 line. Upstream already fixed the issue on its v5 development branch,
but the fix is not present in the v4.14.1 release used by Calvin.

The backport is necessary, but it is not the complete security boundary. An
application can still expose a valid token through rendered-email storage,
logs, analytics, overly broad mail-preview access, browser referrers, or weak
session configuration. Those controls do not belong in this core library.

## Threat model

The reviewed flow must account for:

- accidental GET requests from email scanners and previewers;
- replay of one link by two concurrent requests;
- token disclosure through logs, audit records, exception reporting, or stored
  rendered email;
- token disclosure through URL history or referrer headers;
- repeated link requests used for inbox flooding or account enumeration;
- compromise of the user's email account;
- a valid low-assurance sign-in being used to perform a privileged action.

Magic links are bearer credentials. Anyone who obtains a live link can use it
unless the application adds a second control. The implementation must therefore
minimize where the raw token exists and limit what a resulting session may do.

## Existing protections

The v4 magic-link strategy already provides useful controls:

- JWTs are signed with the application's configured signing secret.
- The default link lifetime is ten minutes.
- `single_use_token?` defaults to `true`.
- `require_interaction? true` changes consumption from an automatic GET to an
  explicit interaction, protecting links from email scanners.
- `store_all_tokens? true` with
  `require_token_presence_for_authentication? true` makes the token resource an
  allow-list for active session tokens.
- Invalid signatures, expiration, action mismatches, subject mismatches, and
  revoked JTIs are rejected during verification.

Applications should explicitly enable `require_interaction?`; v4 retains a
false default for compatibility. They should also enable
`return_error_on_invalid_magic_link_token?` so a failed exchange is recorded as
a failure rather than a successful empty result.

## Atomic single-use backport

### Previous behavior

Verification checked that a JTI was not revoked. Revocation then used an
upsert. If two requests verified at the same time, both could reach the user
action before one revocation became visible. Because an upsert tolerates a
duplicate primary key, both callers could appear to consume the same token.

### New behavior

Internal authentication flows now tell the token resource whether the issued
token was stored:

- For stored tokens, the existing JTI row is selected with a row lock. The
  first request changes its purpose to `"revocation"`; later requests receive
  an invalid-token error.
- For unstored tokens, revocation uses an insert-only action. The JTI primary
  key lets exactly one insert win; a duplicate is translated to an
  `InvalidToken` revocation error.
- The registration-enabled magic-link flow consumes the token in a
  `before_action` hook so a losing request aborts and rolls back its user upsert.
- Password reset, confirmation, sign-in-token, remember-me, and logout helpers
  use the same atomic primitive because they shared the same race.

No schema migration is required. The token resource's existing JTI primary key
provides the uniqueness boundary. Two non-upsert revocation actions are added
by the resource transformer.

For compatibility, a direct external call to `TokenResource.revoke/2` without
the `store_all_tokens?` option retains the legacy behavior. Security-sensitive
callers should pass the option or use a higher-level authentication flow that
does so.

## Responsibility split

| Control | Owner | Status or recommendation |
| --- | --- | --- |
| Signed JWT, expiration, action and subject validation | Ash Authentication | Existing |
| Atomic single-use consumption | Ash Authentication | Backported on this branch |
| Require a human interaction before consumption | Core strategy plus Phoenix route | Configure `require_interaction? true` |
| Do not persist or log raw links | Application sender, mailer, audit system | Store a redacted body or metadata only |
| Restrict mail-preview and auth-event access | Application authorization | Admin-only, least privilege |
| `Referrer-Policy: no-referrer` on exchange page | Phoenix/application | Add at the response boundary |
| Secure cookie, HTTPS redirect, HSTS | Phoenix/application deployment | Enforce in production |
| Request and exchange rate limits | Application/API edge | Limit by normalized identity and client address |
| Device or initiating-browser binding | Core plus Phoenix/application | Design as an opt-in follow-up |
| Step-up authentication for privileged actions | Application policy | Require a stronger factor or recent re-authentication |
| Email authentication (SPF, DKIM, DMARC) | Sending domain | Monitor and move DMARC toward enforcement |

## Token handling rules for integrations

1. Put the raw token only in the delivered message and the exchange request.
2. Never store a fully rendered authentication email containing a live URL.
   Persist a redacted rendering or delivery metadata instead.
3. Mark token parameters and arguments sensitive so framework inspection and
   error output redact them.
4. Avoid putting tokens in analytics events, exception metadata, or structured
   request logs.
5. Use an interaction page that does not consume the token on GET and sends
   `Referrer-Policy: no-referrer`.
6. After a successful exchange, redirect to a clean URL that contains no token.
7. Keep the lifetime short. Ten minutes is appropriate for the reviewed use
   case.

## Email compromise and privileged users

No magic-link implementation can remain secure after the destination mailbox
is compromised: the mailbox contains the bearer credential. Short expiration,
single use, and revocation reduce the window but do not change that fact.

For administrators or other high-impact roles, use the email link to establish
an initial session and require step-up authentication before sensitive actions.
Possible step-up factors include WebAuthn/passkeys, TOTP, or a recently entered
password. Record the authentication method and time in session metadata so
application policies can enforce this consistently.

## Device binding follow-up

An opt-in device-binding design could associate a link request with a
high-entropy nonce stored in an HttpOnly, SameSite cookie and require the same
nonce during exchange. This reduces the value of a forwarded or intercepted
link, but it also prevents cross-device flows and can lock out users whose mail
client opens links outside the initiating browser.

This belongs in a separate design because it spans token claims/storage,
Phoenix request handling, and user-experience policy. It should not be enabled
by default without an explicit fallback decision.

## Standards and references

- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [MojoAuth magic-link security review](https://mojoauth.com/blog/are-magic-links-secure-technical-deep-dive)
- [Upstream atomic revocation PR #1153](https://github.com/team-alembic/ash_authentication/pull/1153)

The MojoAuth article says NIST does not ban email-based authentication. Current
NIST SP 800-63B is stricter: email shall not be used as an out-of-band
authentication channel. Applications with an assurance or compliance target
must use the NIST text as the authority and should treat email links as a
convenience mechanism, not a phishing-resistant authenticator.

## Verification performed for this branch

The backport compiles on the v4.14.1 dependency line. Focused tests cover:

- first-winner-only revocation for stored and unstored tokens;
- magic-link registration rollback after a previously consumed token;
- password-reset and confirmation rollback when revocation loses;
- the affected plug/logout behavior.

The focused run completed with 71 passing tests, including two doctests.
