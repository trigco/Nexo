# Protocol repair work — 2026-11-17

## Implemented in this branch

### SSH over WebSocket
- Replaced the previous "send HTTP headers to sshd and raw-pipe everything" behavior with an RFC 6455 binary WebSocket bridge.
- Validates the HTTP GET upgrade, Upgrade/Connection headers, version 13 and the 16-byte WebSocket key.
- Decodes masked client frames, supports extended payload lengths, fragmented binary messages, ping/pong and close frames.
- Encodes SSH responses as unmasked server-to-client binary WebSocket frames.
- Rejects malformed/unmasked client frames, unsupported text messages, oversized frames and invalid control frames.
- Added the required Sec-WebSocket-Key and Sec-WebSocket-Version headers to the generated SSH WS payload.
- Updated the installer's embedded wsproxy source. Updating only the standalone wsproxy.py was insufficient because install.sh writes its own embedded copy.

### Xray and inbound safety
- Xray config writes now validate a temporary candidate with `xray run -test -config` before replacing the live config.
- Config publication is atomic. If the service fails after publication, the last-known-good config is restored and Xray is restarted again.
- Inbound create/update/delete operations restore their database state if the Xray configuration publish fails.
- Reality key generation and TLS certificate generation now check command results rather than silently accepting missing key/cert files.
- Rejects `xtls-rprx-vision` unless the inbound is VLESS over TCP with REALITY.

### Regression checks
- Added WebSocket handshake, RFC accept hash, frame decoding/encoding and invalid-upgrade tests.
- Added VLESS TCP RAW config/link and invalid flow-combination tests.
- Added GitHub Actions compile + unittest workflow.

## Verification

GitHub Actions run for commit `251f1d0fe2eca3bcad3c05c37ed98e7696e49b5e` completed successfully:
- Python compilation: passed
- Protocol regression tests: passed

Workflow: https://github.com/trigco/Nexo/actions

## Still required before production

These checks are not simulated by the unit tests and have not been performed on a VPS:
- Test a real SSH WebSocket client through port 80 and verify binary frame interoperability.
- Test Xray startup and actual VLESS TCP client connections against the installed Xray core version.
- Verify TLS certificate provisioning with a trusted domain certificate (the existing self-signed default is not production-trusted).
- Test WSS/stunnel, firewall/security-group rules, OpenVPN client connection/revocation, traffic counters and quota enforcement.
- Complete the broader v1 RBAC, package, outbound/routing, audit and UI implementation.

Do not treat this branch as a finished v1 release or deploy it over the only production VPS without a snapshot and rollback path.


## Follow-up hardening added

- Replaced volatile in-memory sessions with hashed, persistent SQLite session records; logout revokes sessions.
- Added CSRF double-submit token validation, same-origin checks for browser writes, secure HttpOnly session cookies, request body limits, security headers and login throttling.
- Removed SSH-only passwords from persistent user rows and public user serializers. Initial/reset SSH credentials are delivered once to the administrator. Trojan/Shadowsocks credentials remain in the restricted local database because Xray needs their protocol secrets to rebuild the configuration; encrypt-at-rest vault migration is still required.
- Added package CRUD and immutable applied package snapshots, including package assignment from the user editor.
- Added audit events and an audit-log screen for authentication, user, package, inbound, service and settings actions.
- Corrected SSH bandwidth accounting to count upload and conntrack-marked reply/download bytes separately without adding the mark-setting rule to the usage total.
- Expanded Xray per-user accounting to Trojan and Shadowsocks in addition to VLESS and VMess.
- Rejected invalid inbound references rather than silently treating them as “all matching inbounds”.
- Added listener collision detection before creating or moving an inbound.
- Added compensating cleanup for partially provisioned users and changed deletion order so Xray revocation happens before the user row is removed.
- OpenVPN profile downloads now require an active user with OpenVPN entitlement; Easy-RSA failures are surfaced instead of silently ignored.
- Removed unsupported per-user DNSTT provisioning and disabled misleading HWID enforcement controls.
- Installer now backs up existing panel/Xray/OpenVPN/SSH/service configuration and firewall state, preserves existing admin credentials on upgrades, and preserves existing TLS certificates and SSH policy files.
- Added installer-source synchronization checks so embedded panel/proxy copies cannot silently drift from the standalone sources.

## Latest verification scope

GitHub Actions currently checks Python compilation, shell syntax, protocol/unit tests, persistence/security tests, package snapshot tests and installer source synchronization. A green CI run does **not** replace a disposable Ubuntu VPS integration test. Real protocol handshakes, Xray core version compatibility, OpenVPN client connect/revoke behavior and upgrade rollback still require VPS validation.


### OpenVPN admission hardening

- OpenVPN certificates now use unique per-issuance common names, so deleting and recreating a panel username does not reuse a revoked Easy-RSA identity.
- The panel atomically publishes a root-owned, world-readable list of disabled/expired/quota-exhausted OpenVPN common names.
- Installer configures a fail-closed `client-connect` hook that rejects listed identities on new connections.
- Existing live OpenVPN sessions are **not yet forcibly disconnected** at quota/suspension time; this remains a release gate. The admission hook prevents reconnect after policy lock.
- Protocol removal in the user editor is blocked until a complete per-protocol revoke workflow is available. Deleting a user performs the current full revoke path.


### Settings integrity

- Hostnames, IPs, URL paths, ports, brand text and Telegram links are validated before persistence.
- Service ports that are not yet reconfigured by Nexo are now read-only in the UI and rejected by the API if changed; this prevents the panel from generating client links to ports the daemon is not actually listening on.
- Panel port remains editable but explicitly requires a service restart before taking effect.


## Follow-up fixes — 2026-11-17

- Xray candidate configuration files are assigned `root:xray` ownership and mode `0640` before atomic publication; rollback candidates receive the same attributes. This prevents a generated config from reverting to `root:root` mode and becoming unreadable to the Xray service account.
- SSH-only account creation, editing, renewal and deletion no longer require an Xray configuration rebuild. Xray sync remains mandatory for users with Xray-backed protocols.
- Service actions now verify the resulting systemd active/inactive state before the API reports success. A timeout includes recent unit journal output, and the UI reports the verified state rather than saying only that the action was sent.
- DNSTT installer now uses UDP/5300 behind an inbound UDP/53 redirect to avoid binding conflicts with systemd-resolved's loopback stub; build and key-generation failures are visible and incomplete installs are not enabled.
- Added regression tests for SSH-only edit/delete and protocol-aware provisioning, plus service state verification.

## Remaining protocol release gates

- DNSTT installer now exposes source/build/key-generation errors instead of suppressing them. Its service listens on UDP/5300 and installs an idempotent PREROUTING redirect for external UDP/53 traffic, leaving the local systemd-resolved loopback stub untouched. The service still forwards to SSH port 22 only; there is no shared SSH/VLESS protocol multiplexer yet. DNSTT shared-domain operation therefore remains incomplete and must not be represented as VLESS-ready.
- OpenVPN disabled-user admission is fail-closed for new connections. Existing connected clients are not yet actively disconnected when quota/expiry/suspension is reached.
- The branch has not been verified against a disposable Ubuntu 24.04 VPS after these latest changes. CI and live protocol tests must pass before production deployment.
