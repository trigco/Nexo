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

## Install

On a fresh **Ubuntu 24.04** VPS, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/trigco/Nexo/main/install.sh -o install.sh
bash install.sh
```

On a fresh install the installer prints the initial admin credentials and saves them to `/root/mpanel-admin.txt`. On upgrades it preserves the existing admin password and does not rotate credentials. Before changing services it creates a root-only backup under `/var/backups/nexo/`. Do not treat the installer as a substitute for a tested VPS snapshot and restore drill.

Default ports: panel `8443` (HTTPS, self-signed), SSH `22`, WS proxy `80`, stunnel `443`, OpenVPN `33500/udp`.

> Note: some cloud trial firewalls block inbound ports (e.g. UDP 53 for DNSTT, or 8443). If the panel does not open from the internet, check your provider's firewall first — the service itself logs `Nexo listening on https://0.0.0.0:8443` when it is up. Current device/HWID enforcement is intentionally disabled because these protocols do not provide a reliable stable hardware identity.

## Files

| File | What it is |
|---|---|
| `install.sh` | One-shot installer (embeds the panel + WS proxy) |
| `panel.py` | The whole panel: backend API + single-page UI, SQLite storage |
| `wsproxy.py` | WebSocket/raw relay that fronts sshd on port 80 |

## License

MIT
