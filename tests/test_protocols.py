import base64
import http.client
import json
import os
import socket
import sys
import tempfile
import time
import threading
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)
os.environ.setdefault("PANEL_MOCK", "1")
os.environ.setdefault("PANEL_HOME", tempfile.mkdtemp(prefix="nexo-test-"))

import wsproxy
import panel


def masked_frame(payload, opcode=2, fin=True, mask=b"abcd"):
    payload = bytes(payload)
    first = (0x80 if fin else 0) | opcode
    n = len(payload)
    if n < 126:
        header = bytes((first, 0x80 | n))
    elif n <= 65535:
        header = bytes((first, 0x80 | 126, n >> 8, n & 255))
    else:
        header = bytes((first, 0x80 | 127)) + n.to_bytes(8, "big")
    return header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


class WebSocketTests(unittest.TestCase):
    def test_rfc_accept_vector(self):
        self.assertEqual(
            wsproxy.websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        )

    def test_masked_frame_decode(self):
        left, right = socket.socketpair()
        try:
            left.sendall(masked_frame(b"SSH-2.0-test"))
            self.assertEqual(wsproxy.recv_frame(right), (True, 2, b"SSH-2.0-test"))
        finally:
            left.close()
            right.close()

    def test_extended_length_frame(self):
        payload = b"x" * 2048
        left, right = socket.socketpair()
        try:
            left.sendall(masked_frame(payload))
            self.assertEqual(wsproxy.recv_frame(right), (True, 2, payload))
        finally:
            left.close()
            right.close()

    def test_ssh_upstream_eof_sends_close_and_unblocks_client(self):
        client, proxy_client = socket.socketpair()
        upstream_peer, upstream = socket.socketpair()
        thread = threading.Thread(
            target=wsproxy.ssh_to_websocket,
            args=(upstream, proxy_client, threading.Lock()),
        )
        thread.start()
        upstream_peer.close()
        first, second = client.recv(2)
        self.assertEqual(first, 0x88)
        self.assertEqual(second, 2)
        self.assertEqual(client.recv(2), b"\x03\xe8")
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        client.close()
        proxy_client.close()
        upstream.close()

    def test_server_frame_is_binary_and_unmasked(self):
        left, right = socket.socketpair()
        try:
            wsproxy.send_frame(left, b"SSH reply")
            first, second = right.recv(2)
            self.assertEqual(first, 0x82)
            self.assertEqual(second & 0x80, 0)
            self.assertEqual(right.recv(second & 0x7f), b"SSH reply")
        finally:
            left.close()
            right.close()

    def test_handshake(self):
        client, server = socket.socketpair()
        errors = []

        def accept():
            try:
                wsproxy.perform_handshake(server)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=accept)
        thread.start()
        client.sendall(
            b"GET /ssh HTTP/1.1\r\nHost: example.test\r\n"
            b"Upgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n"
            b"Sec-WebSocket-Version: 13\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        response = client.recv(1024)
        thread.join(timeout=2)
        self.assertFalse(errors)
        self.assertIn(b"101 Switching Protocols", response)
        self.assertIn(b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", response)
        client.close()
        server.close()


    def test_fragmented_binary_message_is_forwarded_as_one_ssh_stream(self):
        client, proxy_client = socket.socketpair()
        upstream_peer, upstream = socket.socketpair()
        errors = []

        def relay():
            try:
                wsproxy.websocket_to_ssh(proxy_client, upstream, threading.Lock())
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=relay)
        thread.start()
        client.sendall(masked_frame(b"SSH-2.0-", fin=False))
        client.sendall(masked_frame(b"OpenSSH-test", opcode=0, fin=True, mask=b"efgh"))
        client.sendall(masked_frame(b"", opcode=8, fin=True))
        received = upstream_peer.recv(128)
        thread.join(timeout=2)
        self.assertFalse(errors)
        self.assertEqual(received, b"SSH-2.0-OpenSSH-test")
        client.close()
        proxy_client.close()
        upstream_peer.close()
        upstream.close()

    def test_rejects_missing_upgrade(self):
        client, server = socket.socketpair()
        errors = []

        def accept():
            try:
                wsproxy.perform_handshake(server)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=accept)
        thread.start()
        client.sendall(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        thread.join(timeout=2)
        self.assertTrue(errors)
        self.assertIsInstance(errors[0], wsproxy.ProtocolError)
        client.close()
        server.close()


class XrayInboundTests(unittest.TestCase):
    def test_vless_tcp_raw_stream_config(self):
        inbound = {
            "id": 12, "remark": "VLESS TCP", "protocol": "vless",
            "port": 23456, "network": "tcp", "path": "/ray",
            "security": "none", "enabled": 1, "stream_json": "{}",
            "max_clients": 0,
        }
        user = {
            "id": 4, "username": "testuser", "uuid": "12345678-1234-4234-8234-123456789abc",
            "protocols": "vless", "enabled": 1, "inbound_ids": "",
        }
        generated = panel._inbound_json(inbound, [user])
        self.assertEqual(generated["protocol"], "vless")
        self.assertEqual(generated["streamSettings"]["network"], "tcp")
        self.assertEqual(generated["streamSettings"]["security"], "none")
        self.assertEqual(generated["streamSettings"]["tcpSettings"]["header"]["type"], "none")
        self.assertNotIn("wsSettings", generated["streamSettings"])
        self.assertEqual(generated["settings"]["clients"][0]["id"], user["uuid"])
        self.assertEqual(generated["settings"]["decryption"], "none")

    def test_tcp_link_declares_tcp_transport(self):
        inbound = {
            "id": 12, "remark": "VLESS TCP", "protocol": "vless",
            "port": 23456, "network": "tcp", "path": "/ray",
            "security": "none", "stream_json": "{}",
        }
        user = {
            "id": 4, "username": "testuser", "uuid": "12345678-1234-4234-8234-123456789abc",
            "protocols": "vless", "inbound_ids": "",
        }
        link = panel.inbound_link(inbound, user, {"server_host": "198.51.100.20"})
        self.assertIn("type=tcp", link)
        self.assertIn("security=none", link)
        self.assertIn(":23456?", link)

    def test_vision_flow_rejected_for_non_reality_tcp(self):
        with self.assertRaises(ValueError):
            panel._validate_inbound({
                "protocol": "vless", "network": "ws", "security": "none",
                "port": 23456, "flow": "xtls-rprx-vision",
            })


class PersistenceAndSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nexo-security-test-")
        panel.BASE = self.tmp.name
        panel.DB_PATH = os.path.join(self.tmp.name, "panel.db")
        panel.MOCK = True
        panel.init_db()
        conn = panel.db()
        conn.execute("UPDATE admin SET password_hash=? WHERE id=1",
                     (panel.hash_password("correct-horse-battery"),))
        conn.commit()
        conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def start_test_server(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), panel.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_login_sets_persistent_session_and_csrf_is_required(self):
        server, thread = self.start_test_server()
        port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        body = json.dumps({"username": "admin", "password": "correct-horse-battery"})
        conn.request("POST", "/api/login", body=body,
                     headers={"Content-Type": "application/json",
                              "Origin": f"http://127.0.0.1:{port}"})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        response.read()
        cookies = [v for k, v in response.getheaders() if k.lower() == "set-cookie"]
        session_cookie = next(v.split(";", 1)[0] for v in cookies
                              if v.startswith("mpanel_session="))
        csrf_cookie = next(v.split(";", 1)[0] for v in cookies
                           if v.startswith("mpanel_csrf="))
        csrf = csrf_cookie.split("=", 1)[1]

        conn.close()
        denied_conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        denied_conn.request("POST", "/api/settings", body="{}",
                            headers={"Content-Type": "application/json",
                                     "Cookie": session_cookie + "; " + csrf_cookie,
                                     "Origin": f"http://127.0.0.1:{port}"})
        denied = denied_conn.getresponse()
        self.assertEqual(denied.status, 403)
        denied.read()
        denied_conn.close()

        allowed_conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        allowed_conn.request("POST", "/api/settings", body="{}",
                             headers={"Content-Type": "application/json",
                                      "Cookie": session_cookie + "; " + csrf_cookie,
                                      "X-CSRF-Token": csrf,
                                      "Origin": f"http://127.0.0.1:{port}"})
        allowed = allowed_conn.getresponse()
        self.assertEqual(allowed.status, 200)
        allowed.read()
        allowed_conn.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

        # A new application process using the same SQLite file must accept
        # the still-valid opaque session cookie.
        server2, thread2 = self.start_test_server()
        port2 = server2.server_address[1]
        conn2 = http.client.HTTPConnection("127.0.0.1", port2, timeout=3)
        conn2.request("GET", "/api/me", headers={"Cookie": session_cookie})
        resumed = conn2.getresponse()
        self.assertEqual(resumed.status, 200)
        self.assertTrue(json.loads(resumed.read())["logged_in"])
        conn2.close()
        server2.shutdown()
        server2.server_close()
        thread2.join(timeout=2)

    def test_ssh_only_password_is_not_persisted_or_serialized(self):
        created = panel.create_user({
            "username": "alice", "protocols": ["ssh"],
            "password": "one-time-secret-123", "days": 30,
        })
        self.assertEqual(created["credential_once"], "one-time-secret-123")
        self.assertNotIn("password", created)
        rows = panel.list_users_as_rows()
        self.assertEqual(rows[0]["password"], "")
        listed = panel.user_public(rows[0], panel.get_settings())
        self.assertNotIn("password", listed)
        self.assertNotIn("credential_once", listed)

    def test_invalid_inbound_assignment_is_rejected_not_treated_as_all(self):
        with self.assertRaises(ValueError):
            panel.clean_inbound_ids({"inbound_ids": [999999]})

    def test_openvpn_certificate_identity_is_unique_and_revoked_on_delete(self):
        created = panel.create_user({
            "username": "vpnuser", "protocols": ["ovpn"], "days": 30,
        })
        conn = panel.db()
        row = conn.execute("SELECT * FROM users WHERE id=?", (created["id"],)).fetchone()
        conn.close()
        cert_name = row["ovpn_cert_name"]
        self.assertTrue(cert_name.startswith("vpnuser-"))
        with patch.object(panel, "ovpn_revoke_user") as revoke:
            panel.delete_user(created["id"])
            revoke.assert_called_once_with(cert_name)

    def test_disabled_openvpn_user_is_added_to_connection_deny_list(self):
        created = panel.create_user({
            "username": "blockedvpn", "protocols": ["ovpn"],
        })
        panel.update_user(created["id"], {"enabled": False})
        denied = panel.ovpn_denied_names()
        cert_name = next(row["ovpn_cert_name"] for row in panel.list_users_as_rows()
                         if row["id"] == created["id"])
        self.assertIn(cert_name, denied)

    def test_protocol_removal_is_rejected_until_revoke_flow_exists(self):
        created = panel.create_user({
            "username": "keepuser", "protocols": ["ssh"],
            "password": "initial-secret-123",
        })
        with self.assertRaisesRegex(ValueError, "Protocol removal"):
            panel.update_user(created["id"], {"protocols": ["vless"]})

    def test_settings_validation_rejects_invalid_ports_hosts_and_paths(self):
        valid = panel.validate_settings({
            "panel_port": 8443, "server_host": "vpn.example.com",
            "xray_path": "/edge/ws", "telegram": "https://t.me/nexo_channel",
        })
        self.assertEqual(valid["panel_port"], "8443")
        self.assertEqual(valid["server_host"], "vpn.example.com")
        with self.assertRaises(ValueError):
            panel.validate_settings({"panel_port": 70000})
        with self.assertRaises(ValueError):
            panel.validate_settings({"server_host": "good.example;touch /tmp/pwn"})
        with self.assertRaises(ValueError):
            panel.validate_settings({"xray_path": "/ok\\r\\nInjected: yes"})
        with self.assertRaises(ValueError):
            panel.validate_settings({"unknown": "value"})

    def test_user_input_rejects_unknown_protocol_and_negative_quota(self):
        with self.assertRaises(ValueError):
            panel.create_user({"username": "badproto", "protocols": ["ssh", "madeup"]})
        with self.assertRaises(ValueError):
            panel.create_user({"username": "badquota", "protocols": ["ssh"],
                               "quota_gb": -1})


    def test_manual_lock_is_not_undone_by_quota_enforcer(self):
        conn = panel.db()
        conn.execute(
            "INSERT INTO users (username, password, protocols, uuid, quota_bytes, "
            "used_bytes, expire_date, enabled, created_at, auto_locked) "
            "VALUES (?, '', 'ssh', '', 0, 0, '', 0, '', 0)",
            ("manual-lock",),
        )
        conn.commit()
        conn.close()
        panel.enforce()
        conn = panel.db()
        row = conn.execute("SELECT enabled, auto_locked FROM users WHERE username=?",
                           ("manual-lock",)).fetchone()
        conn.close()
        self.assertEqual(row["enabled"], 0)
        self.assertEqual(row["auto_locked"], 0)

    def test_package_assignment_snapshots_policy_and_blocks_assigned_delete(self):
        package_id = panel.create_package({
            "name": "Starter 30D", "quota_gb": 25, "validity_days": 30,
            "ip_limit": 1, "protocols": ["ssh", "vless"], "inbound_ids": [],
        })
        created = panel.create_user({
            "username": "packageuser", "package_id": package_id,
            "password": "initial-secret-123",
        })
        self.assertEqual(created["package_id"], package_id)
        self.assertEqual(created["package_snapshot"]["name"], "Starter 30D")
        self.assertEqual(created["quota_gb"], 25)
        self.assertEqual(created["protocols"], ["ssh", "vless"])
        with self.assertRaises(ValueError):
            panel.delete_package(package_id)

        panel.update_package(package_id, {
            "quota_gb": 40, "validity_days": 60,
        })
        conn = panel.db()
        row = conn.execute("SELECT quota_bytes, package_snapshot_json FROM users "
                           "WHERE username='packageuser'").fetchone()
        conn.close()
        self.assertEqual(row["quota_bytes"], 25 * panel.GB)
        self.assertEqual(json.loads(row["package_snapshot_json"])["quota_bytes"],
                         25 * panel.GB)

    def test_sessions_are_persisted_as_hashes(self):
        token = "raw-session-token"
        csrf = "raw-csrf-token"
        now = int(time.time())
        conn = panel.db()
        conn.execute(
            "INSERT INTO sessions (token_hash, csrf_hash, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (panel.token_hash(token), panel.token_hash(csrf), now, now + 600),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM sessions").fetchone()
        conn.close()
        self.assertNotIn(token, dict(row).values())
        self.assertNotIn(csrf, dict(row).values())
        self.assertEqual(row["token_hash"], panel.token_hash(token))




if __name__ == "__main__":
    unittest.main()
