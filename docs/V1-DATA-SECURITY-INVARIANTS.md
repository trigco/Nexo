# Nexo v1 — Data, Credentials and Provisioning Invariants

This document is a mandatory implementation contract for the migration from the legacy `panel.py` model.

## Credential containment

The legacy database stores SSH passwords in `users.password`, and the legacy public serializer includes that field. This is a critical finding.

Required migration:
1. Stop returning SSH passwords from any list/detail/dashboard API.
2. Stop rendering or copying passwords from user detail views.
3. Introduce a one-time credential delivery flow at creation/reset. Return the new password once in the create/reset response only; never persist it in plaintext.
4. For existing users, do not pretend the old password can be converted into a verifier while preserving the customer's password. Use an explicit reset workflow and communicate that reset to the administrator.
5. Migrate legacy `password` values to an encrypted temporary delivery vault only if there is a documented short expiry and encryption key custody; otherwise clear the column after an administrator-approved reset campaign.
6. Add migration metadata and a report of users requiring credential reset. Do not log the legacy values.
7. Change schema to `password_hash` only for panel-managed authentication secrets. Linux account passwords should not be queryable from panel storage.
8. Ensure Xray Trojan credentials are generated, shown once and not echoed through general user serialization. Prefer UUID-backed protocols where possible.

## Provisioning state machine

User provisioning must not be a single DB insert followed by several best-effort shell calls.

States:
- pending
- provisioning
- active
- degraded
- failed
- suspending
- suspended
- revoking
- revoked

Each protocol has its own sub-state and external reference (Linux UID/account, Xray client email/UUID, OpenVPN certificate serial). Keep a provisioning operation record with request ID, start/end timestamps, adapter results and safe error code.

Create flow:
1. Validate user input, package snapshot, protocol support and capacity.
2. Insert user as pending in a transaction.
3. Insert provisioning operation and protocol subrecords.
4. Execute typed agent operations idempotently.
5. Verify the external resource exists and matches expected policy.
6. Commit user active only after all required protocols are active.
7. On partial failure, either compensate created resources in reverse order or mark degraded with actionable repair state. Never return a generic successful active user.

Delete/revoke flow:
1. Mark revoking and deny new sessions first.
2. Revoke/disable each protocol resource.
3. Verify revocation.
4. Mark revoked and preserve audit/usage history.
5. Purge personal data only according to an explicit retention policy.

Manual suspension is a separate reason from automatic quota/expiry. Automatic enforcement must never clear a manual suspension.

## Traffic accounting invariants

- Every sample records source, protocol, interval and monotonic cumulative counter.
- A counter decrease is not automatically zero or a negative delta; classify reset/restart and persist a new baseline.
- Samples are idempotent by source/reference/window.
- Aggregate user usage only once per source sample.
- Never combine inbound totals and per-user totals unless they are distinct dimensions.
- Expose whether usage is exact, estimated, unsupported or stale.
- Quota reset records an audit event and a new accounting epoch.

## Device limits

An IP is not a hardware identity. A connection address can change; multiple devices can share NAT; one device can have multiple addresses. The system must not claim HWID enforcement for protocols that do not supply a stable authenticated device identifier. For those protocols, show the actual supported policy (concurrent sessions or distinct source IPs) and label it accurately.

## Inbound/outbound configuration publication

- Validate protocol/transport/security combinations before persistence.
- Verify port is in range and unoccupied by an unrelated listener.
- Generate candidate configuration from typed records; never concatenate shell or raw JSON user strings into commands.
- Ensure API inbound and routing tag references remain intact.
- Run the installed Xray binary's config test against a temporary file.
- Atomically publish candidate and save last-known-good.
- Restart/reload and check service plus listener health.
- Roll back on failure, return failed state and preserve diagnostic reference.
- Store generated config hash and Xray version used for validation.

## OpenVPN lifecycle

- Use per-client certificates and serial identity.
- Revocation publishes a CRL and verifies it is loaded by the running server.
- Include the expected CA, client cert, key, remote endpoint and protocol in each profile.
- Do not return another user's private key or profile.
- Verify server reachability and service state after config changes.
