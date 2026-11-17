# Nexo

A premium, 3x-ui style management panel for a multi-protocol VPS — one auto-installer, one web portal, zero pip dependencies (pure Python 3 standard library).

## Features

- **Dashboard** — live CPU / RAM / disk gauges with sparklines, 3x-ui style network speed chart, system info, service states, inbound summary
- **Users** — per-user traffic quota (GB) + expiry with a 1-minute enforcer, manual-vs-automatic lock state, renew, block/unlock, IP limits and online client tracking
- **Packages** — reusable protocol/quota/validity/IP-limit plans with immutable per-user applied snapshots
- **Audit log** — records authentication, user, package, inbound, service and settings changes
- **SSH** — Direct, WebSocket (:80), WSS/TLS via stunnel (:443), Cloudflare WebSocket + ready-to-copy payloads, branded login banner and per-user quota message
- **V2Ray (Xray)** — VLESS / VMess / Trojan / Shadowsocks, transports RAW(TCP) / WS / gRPC / HTTPUpgrade / XHTTP / mKCP, security None / TLS / Reality, per-inbound client caps, per-user inbound assignment, share links with one-tap copy, config validation and rollback
- **OpenVPN** — EC certificates, per-user .ovpn download
- **DNSTT** — DNS tunnel server management (needs inbound UDP 53 open on the VPS firewall)
- **Services page** — start / stop / restart SSH, WebSocket proxy, stunnel, Xray, OpenVPN, DNSTT; shows *Not installed* vs *Stopped* honestly

## Test install (Ubuntu 24.04 only)

This branch is a **test build**, not a production release. Use only a fresh disposable VPS or a restorable snapshot with provider-console access. The installer changes SSH settings, restarts SSH, installs/enables services and creates iptables accounting/NAT rules. Keep a second SSH session open.

```bash
curl -fsSL https://raw.githubusercontent.com/trigco/Nexo/test/web-panel-release/install.sh -o install-nexo-test.sh
less install-nexo-test.sh
sudo bash install-nexo-test.sh
```

Type `INSTALL NEXO TEST` at the confirmation prompt. The script refuses non-Ubuntu-24.04 hosts. Do not use the `main` branch installer for this test build.

Default panel: `https://SERVER_IP:8443` (self-signed certificate warning expected). On a first install, credentials are saved to `/root/mpanel-admin.txt` with mode 0600.

Before installation, allow these inbound ports in the VPS provider firewall/security group as needed:

| Port | Protocol | Purpose |
|---|---|---|
| 22 | TCP | SSH administration |
| 80 | TCP | SSH WebSocket |
| 443 | TCP | SSH TLS/stunnel |
| 8443 | TCP | Nexo panel |
| 33500 | UDP | OpenVPN |
| 53 | UDP | DNSTT only; currently SSH-forwarding only |

Do not open ports you do not intend to test. The DNSTT service is not a shared SSH/VLESS multiplexer. OpenVPN existing sessions are not yet forcibly disconnected when a user reaches quota or expiry. A green CI run is not a substitute for the VPS smoke-test checklist in `docs/V1-VPS-SMOKE-TEST.md`.


## Files

| File | What it is |
|---|---|
| `install.sh` | One-shot installer (embeds the panel + WS proxy) |
| `panel.py` | The whole panel: backend API + single-page UI, SQLite storage |
| `wsproxy.py` | WebSocket/raw relay that fronts sshd on port 80 |

## License

MIT
