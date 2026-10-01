#!/usr/bin/env python3
"""Small local RFB operator for an already authenticated private slot3 worker.

Run inside the worker container. Text for `type` is read from stdin, so account
passwords and one-time codes never appear in command arguments or shell logs.
"""

import argparse
import base64
import hashlib
import hmac
import struct
import socket
import sys
import time
import zlib


KEYS = {"Return": 0xFF0D, "Tab": 0xFF09, "BackSpace": 0xFF08,
        "Escape": 0xFF1B, "Control_L": 0xFFE3, "Shift_L": 0xFFE1,
        "Home": 0xFF50, "End": 0xFF57, "space": 0x20}


def recvall(sock, length):
    out = bytearray()
    while len(out) < length:
        part = sock.recv(length - len(out))
        if not part:
            raise RuntimeError("RFB socket closed")
        out.extend(part)
    return bytes(out)


class RFB:
    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", 5900), timeout=15)
        self.sock.settimeout(20)
        version = recvall(self.sock, 12)
        if not version.startswith(b"RFB 003."):
            raise RuntimeError("unsupported RFB version")
        self.sock.sendall(b"RFB 003.008\n")
        count = recvall(self.sock, 1)[0]
        types = recvall(self.sock, count)
        if 1 not in types:
            raise RuntimeError("private VNC does not offer no-auth after container boundary")
        self.sock.sendall(b"\x01")
        if struct.unpack(">I", recvall(self.sock, 4))[0] != 0:
            raise RuntimeError("RFB security handshake failed")
        self.sock.sendall(b"\x01")
        header = recvall(self.sock, 24)
        self.width, self.height = struct.unpack(">HH", header[:4])
        name_length = struct.unpack(">I", header[20:24])[0]
        recvall(self.sock, name_length)
        # Request 32-bit little-endian true color, RGB in byte positions 2/1/0.
        pixel = struct.pack(">BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
        self.sock.sendall(b"\x00\x00\x00\x00" + pixel)
        self.sock.sendall(struct.pack(">BBHi", 2, 0, 1, 0))

    def key(self, symbol, down=True):
        keysym = KEYS.get(symbol, ord(symbol) if len(symbol) == 1 else None)
        if keysym is None:
            raise ValueError(f"unknown key {symbol!r}")
        self.sock.sendall(struct.pack(">BBxxI", 4, int(down), keysym))

    def press(self, symbol):
        self.key(symbol, True)
        self.key(symbol, False)

    def type(self, value):
        for ch in value:
            self.press(ch)
            time.sleep(0.012)

    def click(self, x, y):
        for mask in (1, 0):
            self.sock.sendall(struct.pack(">BBHH", 5, mask, x, y))

    def scroll(self, x, y, steps):
        mask = 16 if steps > 0 else 8
        for _ in range(abs(steps)):
            self.sock.sendall(struct.pack(">BBHH", 5, mask, x, y))
            self.sock.sendall(struct.pack(">BBHH", 5, 0, x, y))

    def drag(self, x1, y1, x2, y2):
        self.sock.sendall(struct.pack(">BBHH", 5, 1, x1, y1))
        for step in range(1, 11):
            x = x1 + (x2 - x1) * step // 10
            y = y1 + (y2 - y1) * step // 10
            self.sock.sendall(struct.pack(">BBHH", 5, 1, x, y))
            time.sleep(0.04)
        self.sock.sendall(struct.pack(">BBHH", 5, 0, x2, y2))

    def screenshot(self):
        self.sock.sendall(struct.pack(">BBHHHH", 3, 0, 0, 0, self.width, self.height))
        while True:
            kind = recvall(self.sock, 1)[0]
            if kind == 0:
                recvall(self.sock, 1)
                rects = struct.unpack(">H", recvall(self.sock, 2))[0]
                framebuffer = bytearray(self.width * self.height * 4)
                for _ in range(rects):
                    x, y, w, h, encoding = struct.unpack(">HHHHi", recvall(self.sock, 12))
                    if encoding != 0:
                        raise RuntimeError(f"unexpected RFB encoding {encoding}")
                    for row in range(h):
                        raw = recvall(self.sock, w * 4)
                        start = ((y + row) * self.width + x) * 4
                        framebuffer[start:start + w * 4] = raw
                return self._png(framebuffer)
            if kind == 2:
                continue
            if kind == 3:
                recvall(self.sock, 3)
                recvall(self.sock, struct.unpack(">I", recvall(self.sock, 4))[0])
                continue
            raise RuntimeError(f"unexpected RFB message {kind}")

    def _png(self, bgra):
        rows = bytearray()
        for y in range(self.height):
            rows.append(0)
            start = y * self.width * 4
            row = bgra[start:start + self.width * 4]
            for i in range(0, len(row), 4):
                rows.extend((row[i + 2], row[i + 1], row[i]))

        def chunk(kind, data):
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

        return (b"\x89PNG\r\n\x1a\n"
                + chunk(b"IHDR", struct.pack(">IIBBBBB", self.width, self.height, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(bytes(rows), 6))
                + chunk(b"IEND", b""))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("screenshot", "click", "scroll", "drag", "key", "type", "navigate", "totp"))
    parser.add_argument("args", nargs="*")
    args = parser.parse_args()
    client = RFB()
    try:
        if args.action == "screenshot":
            sys.stdout.buffer.write(client.screenshot())
        elif args.action == "click":
            client.click(int(args.args[0]), int(args.args[1]))
        elif args.action == "scroll":
            client.scroll(int(args.args[0]), int(args.args[1]), int(args.args[2]))
        elif args.action == "drag":
            client.drag(*(int(item) for item in args.args[:4]))
        elif args.action == "key":
            client.press(args.args[0])
        elif args.action == "type":
            client.type(sys.stdin.read().rstrip("\n"))
        elif args.action == "totp":
            secret = "".join(sys.stdin.read().split()).upper().rstrip("=")
            seed = base64.b32decode(secret + "=" * (-len(secret) % 8))
            while 30 - (int(time.time()) % 30) < 12:
                time.sleep(1)
            counter = int(time.time()) // 30
            digest = hmac.new(seed, counter.to_bytes(8, "big"), hashlib.sha1).digest()
            offset = digest[-1] & 15
            number = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
            client.type(f"{number % 1000000:06d}")
        elif args.action == "navigate":
            client.key("Control_L", True)
            client.press("l")
            client.key("Control_L", False)
            client.type(sys.stdin.read().rstrip("\n"))
            client.press("Return")
    finally:
        client.sock.close()


if __name__ == "__main__":
    main()
