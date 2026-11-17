# Nexo Professional v1 — Architecture

## Goal

Turn Nexo from a compact single-file VPS panel into a maintainable, auditable VPS administration platform while retaining the existing Ubuntu 24.04 installation and data model during migration.

The existing implementation is a Python standard-library application with SQLite, one HTTP handler, an inline HTML application, and shell/systemd orchestration. It already supports SSH accounts, Xray inbounds/users, OpenVPN profiles, WS/stunnel, service actions, and quota enforcement. This document defines the v1 target and migration contract; it does not claim that every planned module is already implemented.

## V1 boundaries

### Control plane
- Authentication: persistent sessions, secure cookie policy, login throttling, CSRF token validation, session revocation, password rotation, audit events.
- RBAC: owner, administrator, operator, read-only support. Every mutation is authorized server-side.
- Server inventory: one or more VPS records, agent heartbeat, capabilities, health, version, resource telemetry.
- User lifecycle: create, edit, renew, suspend, resume, revoke, bulk actions, package assignment, protocol entitlements, quota, expiry, IP/device policy, notes and audit history.
- Packages: named reusable plans with quota, validity, connection/device ceilings, enabled protocols, and optional inbound restrictions.
- Traffic: normalized per-user/per-protocol counters, usage snapshots, reset events, quota enforcement state, and reconciliation.
- Network: inbound definitions, outbound definitions, routing rules and Xray config validation/publish/rollback.
- Services: typed service registry, installed/running/failed/unknown states, safe allowlisted actions and action audit.
- OpenVPN: server configuration health, client certificate lifecycle, revocation and downloadable profile generation.
- SSH: Linux account lifecycle, access policy, safe password/key handling, online sessions and traffic accounting.
- Branding: logo/name/theme/contact details and public client-facing metadata; no secrets in branding settings.
- Operations: structured logs, diagnostics bundle, backups, restore verification, migrations and health checks.

### Agent/control-plane split

The control plane owns users, policy, plans, inventory, RBAC and audit. A privileged node agent performs narrowly-scoped host operations. Do not expose arbitrary shell execution to the web process or browser.

Recommended v1 deployment shape:
1. Web/API process runs unprivileged.
2. Node agent runs as a dedicated systemd service with a restricted Unix socket.
3. API authenticates and authorizes each request, validates a typed operation, then calls the local agent.
4. Agent supports only explicit operations (create/disable/delete SSH account, validate/publish Xray config, manage OpenVPN cert, read metrics, service allowlist).
5. Every agent request has a request ID, actor, operation, validated arguments, timeout and result record.
6. No general-purpose command endpoint, arbitrary service unit, shell string, or user-controlled executable path.

## Module layout

```text
nexo/
  apps/
    api/                 # HTTP routes, middleware, OpenAPI
    web/                 # responsive administration SPA
    agent/               # privileged local node agent
  packages/
    domain/              # entities, policies, validation
    application/         # use cases and transactions
    infrastructure/      # SQLite/Postgres, systemd, Xray, OpenVPN adapters
    contracts/           # API and agent schemas
  migrations/
  deploy/
    systemd/
    nginx/
    scripts/
  tests/
    unit/
    integration/
    migration/
    security/
  docs/
```

The initial upgrade may remain Python-based to avoid unnecessary stack churn. Separate modules and contracts first; change framework/runtime only when test coverage and operational value justify it.

## Data model

Core records:
- admins(id, username, password_hash, role, enabled, created_at, last_login_at)
- sessions(id_hash, admin_id, csrf_hash, created_at, expires_at, revoked_at, last_seen_at)
- servers(id, name, host, agent_version, status, last_heartbeat_at, capabilities_json)
- users(id, server_id, username, status, package_id, created_at, expires_at, note, ...)
- packages(id, name, quota_bytes, validity_days, ip_limit, device_limit, protocols_json, inbound_ids_json, enabled)
- user_protocols(user_id, protocol, external_ref, state)
- inbounds(id, server_id, tag, remark, protocol, listen, port, network, security, settings_json, enabled)
- outbounds(id, server_id, tag, protocol, settings_json, enabled)
- routing_rules(id, server_id, priority, rule_json, enabled)
- traffic_samples(id, user_id, protocol, upload_bytes, download_bytes, sampled_at, source)
- usage_state(user_id, period_start, used_bytes, quota_bytes, last_reconciled_at)
- service_state(server_id, service_id, installed, active, health, checked_at, details_json)
- certificates(id, user_id, kind, serial, issued_at, expires_at, revoked_at)
- audit_events(id, actor_id, server_id, action, target_type, target_id, request_id, outcome, details_json, created_at)
- settings(key, value, updated_at)

The current SQLite tables are the migration source of truth. Preserve user IDs, usernames, traffic totals, protocol selections, UUIDs, inbounds, settings and admin identity/password hash. Migrations must be additive, transactional and repeatable. Backups must be taken and verified before schema changes.

## API contract (v1)

All routes are versioned under `/api/v1`. All responses use a consistent envelope and request ID.

- `GET /health/live`, `GET /health/ready`
- `POST /auth/login`, `POST /auth/logout`, `GET /auth/session`, `POST /auth/password`
- `GET/POST /servers`, `GET/PATCH /servers/{id}`
- `GET/POST /users`, `GET/PATCH/DELETE /users/{id}`
- `POST /users/{id}/renew`, `POST /users/{id}/suspend`, `POST /users/{id}/resume`
- `GET/POST /packages`, `GET/PATCH/DELETE /packages/{id}`
- `GET/POST /inbounds`, `GET/PATCH/DELETE /inbounds/{id}`
- `GET/POST /outbounds`, `GET/PATCH/DELETE /outbounds/{id}`
- `GET/POST /routing-rules`, `PATCH/DELETE /routing-rules/{id}`
- `GET /traffic/summary`, `GET /traffic/users/{id}`, `POST /traffic/users/{id}/reset`
- `GET /services`, `POST /services/{id}/actions` (body action enum; strict allowlist)
- `GET/POST /openvpn/clients`, `POST /openvpn/clients/{id}/revoke`
- `GET /audit-events`, `GET/PATCH /settings/branding`

All write routes require authenticated session, CSRF validation, role authorization, schema validation, audit record and a safe idempotency policy where retries are possible.

## Security baseline

- HTTPS only; use a real certificate via reverse proxy or ACME. Do not expose the panel over plain HTTP.
- Secure, HttpOnly, SameSite=Strict session cookie; rotate session after authentication and privilege changes.
- Store only a keyed hash of opaque session tokens in persistent storage.
- CSRF token bound to session and validated on every state-changing request; validate Origin/Host.
- Login throttling by account and source address with progressive backoff; generic login failure responses.
- Parameterized SQL only; strict request body size/type bounds.
- No secrets in logs, HTML, API responses, installer output beyond one-time initial credentials.
- Never store or render user SSH passwords after creation. Prefer SSH public keys where practical.
- Validate all ports, protocol enums, paths, hostnames, UUIDs, dates, quota bounds and inbound references.
- Service control is allowlisted. No arbitrary systemd unit names or shell strings.
- Xray config generated in memory, validated with Xray test mode, atomically written, then restarted. Retain last-known-good config and roll back on failed health check.
- Restrict Xray stats API to loopback.
- Firewall changes are deterministic and idempotent. Do not flush unrelated firewall chains.
- Agent socket permissions and peer identity are enforced; web process is not root.
- Audit sensitive user, account, network and service mutations.

## User and bandwidth semantics

- One explicit canonical user status: active, suspended, expired, quota_exhausted, revoked.
- Manual suspension must never be silently undone by quota enforcement.
- Quota enforcement must be protocol-aware and use monotonic counter deltas, reset/restart detection and persisted reconciliation offsets.
- Do not present device/HWID limiting as enforced unless a protocol can reliably supply a stable device identity. SSH/Xray/OpenVPN IP observations are not equivalent to hardware IDs.
- Inbound assignment must be explicit and validated. Empty assignment semantics must be clearly labelled (all matching inbounds or none), never ambiguous.
- Package changes are versioned and the applied policy snapshot is stored on each user so later package edits do not unexpectedly alter existing customers.

## UI / UX

Responsive desktop and mobile administration:
- Overview: health, CPU/RAM/disk, live RX/TX, user counts, online clients, traffic, service health, inbound/outbound summaries, recent audit events.
- Users: searchable/filterable table, details drawer, plan, protocol, quota/expiry, online presence, safe bulk operations.
- Packages: plan builder and assignment.
- Network: inbound, outbound and routing-rule workspaces with config preview and validation.
- Services: installed/active/health states, logs/diagnostics and safe lifecycle actions.
- OpenVPN: client issuance, profile download and revocation.
- Branding/settings: identity, domain, certificate and backup/restore.
- Every destructive action requires confirmation; every mutation has visible progress and result. No fake loading or optimistic success for privileged operations.
- Use accessible contrast, keyboard support, clear empty/error/loading states and touch-friendly controls.

## Release gates

A release is not "ready" until all are true:
1. Unit and integration tests pass in mock mode.
2. Existing database migration test passes against a copy of a real v0 database.
3. Installer is idempotent and has rollback/backup.
4. Fresh Ubuntu 24.04 install tested on a disposable VPS.
5. Existing VPS upgrade tested from a restorable snapshot.
6. SSH access is preserved during installation; no firewall flush or uncontrolled sshd rewrite.
7. Xray config passes the installed binary's `run -test`; restart health is verified and rollback tested.
8. OpenVPN server starts and a generated client profile imports and connects.
9. Quota, expiry, manual suspension, renewal and reset cases are tested across enabled protocols.
10. Session persistence, CSRF, login rate limits, role enforcement and audit events are tested.
11. All service states come from actual systemd/binary health, not mocked defaults.
12. No secrets, default passwords or private keys are committed.

## VPS smoke-test

After install:
- `systemctl --failed`
- `systemctl status nexo-api nexo-agent xray openvpn-server@server ssh`
- `curl -fsS https://127.0.0.1:<panel-port>/health/ready`
- `xray run -test -config /usr/local/etc/xray/config.json`
- `ss -lntup`
- `journalctl -u nexo-api -u nexo-agent --since -10m`
- Login, create disposable SSH and VLESS users, verify links and connections, verify usage, suspend/renew/delete, revoke an OpenVPN profile, and confirm audit records.
