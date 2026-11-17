# Nexo v1 Implementation Plan

## Delivery sequence

### Phase 0 — Baseline and safety
- Pin current main commit and archive installer, panel source and SQLite database.
- Run syntax checks and PANEL_MOCK smoke tests.
- Document current ports, units, firewall rules, config and certificates.
- Provide upgrade dry-run and backup/restore commands.
- Never run the installer against the user's live VPS as part of source-code work.

### Phase 1 — Security and persistence
- Persistent hashed session tokens and revocation.
- CSRF and Origin validation, login throttling, secure cookie settings.
- RBAC and audit trail.
- Request IDs, bounded JSON bodies and consistent API errors.
- Fix SQLite connection lifecycle, foreign keys, WAL, busy timeout and transactional write patterns.

### Phase 2 — Domain modularization
- Extract user, package, inbound, outbound, traffic, service and certificate use cases.
- Add schema migrations and repository interfaces.
- Preserve existing API routes during transition through compatibility adapters.
- Add contract and migration tests.

### Phase 3 — User and package management
- Package CRUD and immutable applied package snapshots.
- Protocol-specific provisioning adapters.
- Bulk operations with per-item result records.
- Clear status reasons and separate manual suspension from automatic quota/expiry lock.
- Device limit only when the client protocol provides verifiable stable identity; otherwise mark unsupported.

### Phase 4 — Network workspace
- Inbounds, outbounds, routing rules and DNS settings.
- Generated Xray config preview, validation, atomic publish, health verification and rollback.
- Explicit outbound tags and routing priorities.
- Port collision checks across managed listeners.

### Phase 5 — Services and OpenVPN
- Safe service allowlist and proper installed/active/failed states.
- OpenVPN profile generation, per-client cert issuance/revocation and status telemetry.
- SSH account/key management with preservation of existing host access.
- Diagnostics and log tailing with sensitive-data redaction.

### Phase 6 — Frontend replacement
- Modern information architecture, responsive navigation, desktop work tables and mobile detail sheets.
- Dedicated screens for overview, users, packages, online, network, services, OpenVPN, audit and settings.
- Loading/error/empty/success states tied to actual API responses.
- Avoid inline UI/logic coupling; use typed API client and reusable components.

### Phase 7 — Release hardening
- Disposable VPS integration, install/upgrade/rollback tests.
- Test resource footprint on small VPS.
- Backup rotation and restore drill.
- Versioned release bundle and checksums.
- Publish v1.0 only after the release gates in V1-ARCHITECTURE.md pass.

## Known findings from the inspected code

- UI and backend are embedded in `panel.py`; there is no module separation.
- HTTP API is implemented with `BaseHTTPRequestHandler`.
- Sessions are stored in process memory and disappear on restart.
- Session cookie uses HttpOnly and SameSite=Lax but is not marked Secure in the shown login handler.
- No CSRF token or login throttling is visible in the inspected route code.
- Services are controlled through an allowlist, but the custom panel process itself is managed as root by the current installer.
- User rows retain SSH passwords in clear text in SQLite, and public user serialization exposes password. This must be removed through a migration and credential rotation workflow.
- Device/HWID fields exist, but the inspected enforcer applies SSH session/IP and Xray IP filtering; that is not reliable hardware identity enforcement.
- Current SSH per-user iptables accounting chain has a single OUTPUT jump to per-user chains. This design needs packet-path validation before traffic totals are trusted.
- Current OpenVPN setup uses one shared server and generated client certificates; verify revocation, client isolation, status accounting and profile correctness on a real host.
- Inbound TLS uses self-signed certificates by default. Production TLS requires explicit hostname/certificate validation and renewal.
- Dashboard polling is frequent; ensure metrics sampling does not block request handling or overload small VPS instances.

## Current status

This branch contains the target architecture and delivery gates. It is not a v1 executable release yet. The repository has not been modified on main, no VPS deployment has been performed, and a VPS install test is still required.


## Implemented in the current feature branch (not yet a release)

- Persistent opaque session records stored as SHA-256 hashes, revocation, CSRF token validation, same-origin write checks, secure cookie attributes and login throttling.
- Request JSON body size/type bounds and baseline response security headers.
- SSH-only credential storage removal and one-time create/reset delivery. Existing legacy plaintext SSH credentials are not yet migrated/cleared automatically; an explicit customer reset campaign is still needed.
- Packages: CRUD, user assignment and immutable applied policy snapshots.
- Audit event persistence and an audit-log UI.
- SSH upload/download accounting via per-UID conntrack marks; real VPS packet-path validation remains a release gate.
- Xray user traffic aggregation covers VLESS, VMess, Trojan and Shadowsocks.
- Strict inbound reference validation and occupied-port checks.
- User provisioning compensation and safer revoke-before-delete sequencing.
- OpenVPN profile entitlement checks and surfaced Easy-RSA command failures.
- Installer pre-upgrade backup, preservation of existing admin credentials, TLS certificates and SSH policy files.
- Installer/source synchronization CI tests.

Still not implemented: multi-admin RBAC, privileged agent separation, a full outbound/routing workspace, OpenVPN live-session disconnect on quota lock, encrypted secret vault for Trojan/Shadowsocks, certificate ACME lifecycle, full migration of legacy cleartext credentials, and a disposable-VPS end-to-end release test.


- OpenVPN users now receive unique certificate common names; disabled/expired/quota-exhausted names are atomically published to a fail-closed client-connect hook. Existing active sessions are not yet killed at quota lock, and per-protocol removal remains blocked until a complete revoke workflow is implemented.
