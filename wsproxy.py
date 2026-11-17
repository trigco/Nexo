#!/usr/bin/env python3
"""RFC 6455 WebSocket-to-SSH byte-stream bridge.

The client-to-server WebSocket frames are decoded (including masking and
fragmentation) before their binary payload is sent to sshd. SSH bytes read
from sshd are returned as unmasked binary WebSocket frames. Control frames
(ping/pong/close) are handled locally.

This is intentionally a narrow bridge: it does not accept arbitrary HTTP
methods, proxy arbitrary paths, or forward HTTP headers to the SSH daemon.
"""
import base64
import hashlib
import os
import socket
import struct
import sys
import threading

LISTEN_HOST = os.environ.get("WSPROXY_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("WSPROXY_PORT", sys.argv[1] if __name__ == "__main__" and len(sys.argv) > 1 else 80))
UPSTREAM_HOST = os.environ.get("WSPROXY_UPSTREAM_HOST", "127.0.0.1")
UPSTREAM_PORT = int(os.environ.get("WSPROXY_UPSTREAM_PORT", "22"))
MAX_HEADER = 16384
MAX_FRAME = 1024 * 1024
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class ProtocolError(Exception):
    pass


def websocket_accept(key):
    try:
        decoded = base64.b64decode(key.encode("ascii"), validate=True)
    except Exception as exc:
        raise ProtocolError("invalid Sec-WebSocket-Key") from exc
    if len(decoded) != 16:
        raise ProtocolError("invalid Sec-WebSocket-Key length")
    digest = hashlib.sha1((key + GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def _read_headers(sock):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("client closed during HTTP handshake")
        data.extend(chunk)
        if len(data) > MAX_HEADER:
            raise ProtocolError("HTTP headers too large")
    head, _, remainder = bytes(data).partition(b"\r\n\r\n")
    try:
        lines = head.decode("iso-8859-1").split("\r\n")
    except UnicodeDecodeError as exc:
        raise ProtocolError("invalid HTTP headers") from exc
    if not lines or len(lines[0].split()) != 3:
        raise ProtocolError("invalid HTTP request line")
    method, path, version = lines[0].split()
    if method != "GET" or not version.startswith("HTTP/1."):
        raise ProtocolError("WebSocket requires an HTTP GET")
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            raise ProtocolError("malformed HTTP header")
        name, value = line.split(":", 1)
        name = name.strip().lower()
        headers.setdefault(name, []).append(value.strip())
    return path, headers, remainder


def perform_handshake(client):
    path, headers, remainder = _read_headers(client)
    upgrade = ",".join(headers.get("upgrade", [])).lower()
    connection = ",".join(headers.get("connection", [])).lower()
    version = headers.get("sec-websocket-version", [""])[-1]
    key = headers.get("sec-websocket-key", [""])[-1]
    if upgrade != "websocket" or "upgrade" not in [x.strip() for x in connection.split(",")]:
        raise ProtocolError("missing WebSocket Upgrade headers")
    if version != "13":
        client.sendall(b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        raise ProtocolError("unsupported WebSocket version")
    accept = websocket_accept(key)
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
    )
    client.sendall(response.encode("ascii"))
    return path, remainder


def _recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF in WebSocket frame")
        data.extend(chunk)
    return bytes(data)


def recv_frame(sock):
    first, second = _recv_exact(sock, 2)
    fin = bool(first & 0x80)
    if first & 0x70:
        raise ProtocolError("RSV bits require an unnegotiated extension")
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    if not masked:
        raise ProtocolError("client WebSocket frames must be masked")
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(sock, 8))[0]
        if length >> 63:
            raise ProtocolError("invalid WebSocket payload length")
    if length > MAX_FRAME:
        raise ProtocolError("WebSocket frame exceeds configured limit")
    if opcode >= 8 and (not fin or length > 125):
        raise ProtocolError("invalid WebSocket control frame")
    mask = _recv_exact(sock, 4)
    payload = bytearray(_recv_exact(sock, length))
    for i in range(length):
        payload[i] ^= mask[i & 3]
    return fin, opcode, bytes(payload)


def send_frame(sock, payload, opcode=2, lock=None):
    payload = bytes(payload)
    if len(payload) > MAX_FRAME:
        raise ProtocolError("outgoing WebSocket frame too large")
    length = len(payload)
    if length < 126:
        header = bytes((0x80 | opcode, length))
    elif length <= 65535:
        header = bytes((0x80 | opcode, 126)) + struct.pack("!H", length)
    else:
        header = bytes((0x80 | opcode, 127)) + struct.pack("!Q", length)
    packet = header + payload
    if lock:
        with lock:
            sock.sendall(packet)
    else:
        sock.sendall(packet)


def websocket_to_ssh(client, upstream, send_lock, initial=b""):
    """Decode client frames and write their payload as an SSH byte stream."""
    pending = bytearray(initial)
    fragmented = bytearray()
    fragment_opcode = None
    while True:
        if pending:
            # The handshake reader returns bytes after CRLFCRLF. Feed them
            # through a tiny buffered socket adapter to avoid losing bytes.
            fin, opcode, payload = _parse_buffered_frame(client, pending)
        else:
            fin, opcode, payload = recv_frame(client)
        if opcode == 8:
            try:
                send_frame(client, payload[:125], opcode=8, lock=send_lock)
            except OSError:
                pass
            break
        if opcode == 9:
            send_frame(client, payload, opcode=10, lock=send_lock)
            continue
        if opcode == 10:
            continue
        if opcode in (1, 2):
            if fragment_opcode is not None:
                raise ProtocolError("new data frame before fragmented message completed")
            if fin:
                if opcode != 2:
                    raise ProtocolError("SSH tunnel requires binary WebSocket messages")
                if payload:
                    upstream.sendall(payload)
            else:
                if opcode != 2:
                    raise ProtocolError("SSH tunnel requires binary WebSocket messages")
                fragment_opcode = opcode
                fragmented.extend(payload)
        elif opcode == 0:
            if fragment_opcode is None:
                raise ProtocolError("unexpected continuation frame")
            fragmented.extend(payload)
            if len(fragmented) > MAX_FRAME:
                raise ProtocolError("fragmented message too large")
            if fin:
                upstream.sendall(fragmented)
                fragmented.clear()
                fragment_opcode = None
        else:
            raise ProtocolError("unsupported WebSocket opcode")


def _parse_buffered_frame(sock, pending):
    # Parse a complete frame already read along with the HTTP headers.
    if len(pending) < 2:
        pending.extend(_recv_exact(sock, 2 - len(pending)))
    first, second = pending[0], pending[1]
    fin, opcode = bool(first & 0x80), first & 0x0F
    if first & 0x70 or not (second & 0x80):
        raise ProtocolError("invalid client frame")
    length = second & 0x7F
    offset = 2
    if length == 126:
        while len(pending) < 4:
            pending.extend(_recv_exact(sock, 4 - len(pending)))
        length = struct.unpack("!H", pending[2:4])[0]
        offset = 4
    elif length == 127:
        while len(pending) < 10:
            pending.extend(_recv_exact(sock, 10 - len(pending)))
        length = struct.unpack("!Q", pending[2:10])[0]
        offset = 10
    if length > MAX_FRAME:
        raise ProtocolError("WebSocket frame exceeds configured limit")
    while len(pending) < offset + 4 + length:
        pending.extend(_recv_exact(sock, offset + 4 + length - len(pending)))
    mask = pending[offset:offset + 4]
    payload = bytearray(pending[offset + 4:offset + 4 + length])
    del pending[:offset + 4 + length]
    for i in range(length):
        payload[i] ^= mask[i & 3]
    return fin, opcode, bytes(payload)


def ssh_to_websocket(upstream, client, send_lock):
    while True:
        data = upstream.recv(65536)
        if not data:
            break
        send_frame(client, data, opcode=2, lock=send_lock)


def handle(client):
    upstream = None
    try:
        client.settimeout(15)
        # Verify sshd is reachable before returning 101 to the client.
        upstream = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=10)
        upstream.settimeout(None)
        _, remainder = perform_handshake(client)
        client.settimeout(None)
        send_lock = threading.Lock()
        down = threading.Thread(
            target=ssh_to_websocket, args=(upstream, client, send_lock), daemon=True
        )
        down.start()
        websocket_to_ssh(client, upstream, send_lock, remainder)
    except (OSError, ProtocolError, ValueError) as exc:
        print(f"wsproxy connection closed: {exc}", flush=True)
    finally:
        for sock in (upstream, client):
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(128)
    print(
        f"wsproxy listening on {LISTEN_HOST}:{LISTEN_PORT} -> "
        f"{UPSTREAM_HOST}:{UPSTREAM_PORT}", flush=True
    )
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
