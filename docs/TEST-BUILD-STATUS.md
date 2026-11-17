# Nexo Web Panel Test Build

This branch is a test-only build lane. It does not deploy to a VPS or change the production `main` branch.

## CI checks

- Bash syntax validation for `install.sh`
- Python compilation for `panel.py` and `wsproxy.py`
- All unit/regression tests under `tests/`
- Test bundle packaging with source, installer, README, docs, and build metadata

The GitHub Actions artifact is named `nexo-web-panel-test` and is retained for 14 days.

## Release blockers

- Shared DNSTT SSH/VLESS protocol multiplexing is not implemented. Current DNSTT service forwarding is SSH-only; it must not be advertised as VLESS-ready.
- OpenVPN sessions already connected when a user is suspended, expired, or over quota are not yet forcibly disconnected.
- Disposable Ubuntu 24.04 VPS smoke tests remain required for real SSH WebSocket interoperability, Xray version/config compatibility, trusted TLS, OpenVPN connect/revoke and traffic/quota enforcement, plus backup/restore and upgrade rollback.

A passing CI build is a test artifact, not a production-ready installer. Never install it over the only production VPS without a restorable snapshot and separate console access.
