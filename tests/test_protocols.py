import base64
import os
import socket
import sys
import tempfile
import time
import threading
import unittest

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
