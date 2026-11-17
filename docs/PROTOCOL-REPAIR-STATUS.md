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
