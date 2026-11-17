#!/usr/bin/env python3
"""WebSocket-to-SSH relay.

Listens on a TCP port (default 80). If the client sends an HTTP request with
a Sec-WebSocket-Key header, it answers 101 Switching Protocols and then
pipes bytes both ways to sshd. Anything else (for example a raw SSH client
behind stunnel, which sends its version string first) is piped raw from the
first byte. This dual behaviour is what lets one port serve both plain
WebSocket tunnel apps and stunnel-wrapped direct SSH.

Note: the first chunk is consumed with a normal recv (never MSG_PEEK), so
every byte is forwarded to sshd exactly once and in order.
"""
import socket
import sys
import threading

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
UPSTREAM = ("127.0.0.1", 22)
HTTP_PREFIXES = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ")


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client):
    try:
        client.settimeout(15)
        data = client.recv(65536)
        if not data:
            client.close()
            return
        upstream = socket.create_connection(UPSTREAM, timeout=10)
        leftover = data
        if data.startswith(HTTP_PREFIXES):
            # Collect the full HTTP header block before deciding.
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = client.recv(65536)
                if not chunk:
                    break
                data += chunk
            head, sep, rest = data.partition(b"\r\n\r\n")
            key = None
            if sep:
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"sec-websocket-key:"):
                        key = line.split(b":", 1)[1].strip()
                        break
            if key:
                import base64
                import hashlib

                accept = base64.b64encode(
                    hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
                ).decode()
                client.sendall(
                    (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                    ).encode()
                )
                leftover = rest
            else:
                leftover = data
        client.settimeout(None)
        if leftover:
            upstream.sendall(leftover)
        t = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
        t.start()
        pipe(upstream, client)
    except OSError:
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(128)
    print(f"wsproxy listening on :{LISTEN_PORT} -> {UPSTREAM[0]}:{UPSTREAM[1]}", flush=True)
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
