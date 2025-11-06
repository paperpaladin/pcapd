"""Generate loopback traffic for the live corpus. Run inside the namespace
that t/live.sh creates; it has no privileges of its own."""
import socket
import sys
import threading
import time

PORT = 9099


def serve(family, handler, port=PORT):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", port))
    s.listen(1)
    t = threading.Thread(target=lambda: handler(s), daemon=True)
    t.start()
    return s, t


def echo(family, payload):
    def handler(s):
        c, _ = s.accept()
        buf = b""
        while len(buf) < len(payload):
            d = c.recv(65536)
            if not d:
                break
            buf += d
        c.sendall(buf[::-1])
        c.close()

    s, t = serve(family, handler)
    c = socket.socket(family, socket.SOCK_STREAM)
    c.connect(("::1" if family == socket.AF_INET6 else "127.0.0.1", PORT))
    c.sendall(payload)
    got = b""
    while len(got) < len(payload):
        d = c.recv(65536)
        if not d:
            break
        got += d
    c.close()
    t.join(2)
    s.close()
    assert got == payload[::-1], (len(got), len(payload))


def udp(family, n, size):
    host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((host, PORT))
    c = socket.socket(family, socket.SOCK_DGRAM)
    for i in range(n):
        c.sendto(bytes([i & 0xFF]) * size, (host, PORT))
        d, addr = s.recvfrom(70000)
        s.sendto(d[:16], addr)
        c.recv(70000)
    c.close()
    s.close()


def rst(family):
    # Connect to a port nothing is listening on: the kernel answers with RST.
    host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
    c = socket.socket(family, socket.SOCK_STREAM)
    c.settimeout(2)
    try:
        c.connect((host, PORT + 1))
    except OSError:
        pass
    c.close()
    # And a connection that is reset after data, using SO_LINGER 0.
    def handler(s):
        conn, _ = s.accept()
        conn.recv(100)
        time.sleep(0.1)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        conn.close()

    s, t = serve(family, handler)
    c = socket.socket(family, socket.SOCK_STREAM)
    c.connect((host, PORT))
    c.sendall(b"knock")
    time.sleep(0.3)
    try:
        c.recv(100)
    except OSError:
        pass
    c.close()
    t.join(2)
    s.close()


MODES = {
    "echo4": lambda: echo(socket.AF_INET, b"hello there, this is the client speaking" * 3),
    "bulk4": lambda: echo(socket.AF_INET, bytes(range(256)) * 900),
    "udp4": lambda: udp(socket.AF_INET, 6, 100),
    "rst4": lambda: rst(socket.AF_INET),
    "echo6": lambda: echo(socket.AF_INET6, b"six six six" * 11),
    "udp6": lambda: udp(socket.AF_INET6, 4, 120),
    "bigudp4": lambda: udp(socket.AF_INET, 2, 3500),
    "bigudp6": lambda: udp(socket.AF_INET6, 2, 3500),
}

if __name__ == "__main__":
    MODES[sys.argv[1]]()
