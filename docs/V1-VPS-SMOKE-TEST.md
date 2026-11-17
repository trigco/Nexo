# Nexo v1 — VPS Smoke Test

This is a validation checklist, not an unattended installer. Run first on a disposable Ubuntu 24.04 VPS or a restorable snapshot. Never run destructive checks on the only live SSH connection.

## Before changing a VPS

1. Confirm console / rescue access with the VPS provider.
2. Keep a second SSH session open.
3. Record `ip -br addr`, `ip route`, `ss -lntup`, `systemctl --failed`, `iptables-save` and `nft list ruleset`.
4. Back up `/etc/mpanel`, `/usr/local/etc/xray`, `/etc/openvpn`, relevant systemd units, SSH configuration and firewall rules.
5. Verify the backup can be read and has restrictive permissions.
6. Record current public host, panel URL, ports, active services and admin access.

## Read-only baseline

```bash
sudo systemctl --failed
sudo systemctl status ssh --no-pager
sudo systemctl status mpanel wsproxy stunnel-ssh xray openvpn-server@server dnstt --no-pager
sudo ss -lntup
sudo iptables-save
sudo nft list ruleset
sudo du -sh /etc/mpanel /usr/local/etc/xray /etc/openvpn 2>/dev/null
```

## Post-install / post-upgrade health

Adapt service names to the released build; v1 is expected to use `nexo-api` and `nexo-agent`.

```bash
sudo systemctl --failed
sudo systemctl status nexo-api nexo-agent ssh xray openvpn-server@server --no-pager
sudo ss -lntup
sudo journalctl -u nexo-api -u nexo-agent --since '-10 min' --no-pager
sudo xray run -test -config /usr/local/etc/xray/config.json
```

Readiness endpoint must not disclose secrets, filesystem paths or configuration content.

## Functional validation

- Login; confirm session survives API worker restart, logout revokes it, and CSRF/Origin checks reject invalid writes.
- Create a package; verify limits and supported protocols.
- Create a test user with SSH and VLESS entitlements. Confirm generated credentials/links work and that returned API payloads never include stored SSH passwords.
- Confirm manual suspension remains in effect after an accounting/enforcement pass.
- Test quota reached, expiry, renewal with and without usage reset, and deletion cleanup.
- Create Xray inbound; inspect generated config, run Xray test mode, publish, check service health, and verify rollback by injecting an invalid candidate config on the disposable host only.
- Create an outbound and route a test inbound to it; validate tag references and rule priority.
- Issue an OpenVPN certificate; import the downloaded profile, establish connection, revoke certificate, and confirm reconnect is rejected.
- Stop/restart only disposable test services through the panel and verify truthful status and audit event.
- Check audit records for every privileged action; inspect logs for passwords, private keys and session tokens (none should appear).

## Rollback

Do not delete the previous config or database until the new build passes health and protocol tests. If health checks fail:
1. Stop the new API/agent services.
2. Restore the pre-upgrade database and configuration backups.
3. Restore prior systemd units and firewall state.
4. Restart the original service stack.
5. Confirm SSH login from a separate client before closing the maintenance session.

A failed smoke test blocks v1 release. Never report a deployment as complete based only on successful file transfer or installer exit status.
