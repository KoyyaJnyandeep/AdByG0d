from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable


_PATCHED = False


def _rol(value: int, bits: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


class _MD4:
    block_size = 64
    digest_size = 16

    def __init__(self, data: bytes = b""):
        self._count = 0
        self._buf = b""
        self._state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        if data:
            self.update(data)

    def update(self, data: bytes):
        data = bytes(data)
        self._count += len(data)
        data = self._buf + data
        blocks_len = len(data) & ~0x3F
        for offset in range(0, blocks_len, 64):
            self._process(data[offset:offset + 64])
        self._buf = data[blocks_len:]
        return self

    def copy(self):
        other = _MD4()
        other._count = self._count
        other._buf = self._buf
        other._state = self._state[:]
        return other

    def digest(self) -> bytes:
        clone = self.copy()
        bit_len = clone._count * 8
        pad_len = 56 - ((clone._count + 1) % 64)
        if pad_len < 0:
            pad_len += 64
        clone.update(b"\x80" + (b"\x00" * pad_len) + struct.pack("<Q", bit_len))
        return struct.pack("<4I", *clone._state)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def _process(self, block: bytes) -> None:
        x = list(struct.unpack("<16I", block))
        a, b, c, d = self._state

        def f(x_: int, y: int, z: int) -> int:
            return (x_ & y) | (~x_ & z)

        def g(x_: int, y: int, z: int) -> int:
            return (x_ & y) | (x_ & z) | (y & z)

        def h(x_: int, y: int, z: int) -> int:
            return x_ ^ y ^ z

        for i in range(0, 16, 4):
            a = _rol(a + f(b, c, d) + x[i], 3)
            d = _rol(d + f(a, b, c) + x[i + 1], 7)
            c = _rol(c + f(d, a, b) + x[i + 2], 11)
            b = _rol(b + f(c, d, a) + x[i + 3], 19)

        for i in (0, 1, 2, 3):
            a = _rol(a + g(b, c, d) + x[i] + 0x5A827999, 3)
            d = _rol(d + g(a, b, c) + x[i + 4] + 0x5A827999, 5)
            c = _rol(c + g(d, a, b) + x[i + 8] + 0x5A827999, 9)
            b = _rol(b + g(c, d, a) + x[i + 12] + 0x5A827999, 13)

        for i in (0, 2, 1, 3):
            a = _rol(a + h(b, c, d) + x[i] + 0x6ED9EBA1, 3)
            d = _rol(d + h(a, b, c) + x[i + 8] + 0x6ED9EBA1, 9)
            c = _rol(c + h(d, a, b) + x[i + 4] + 0x6ED9EBA1, 11)
            b = _rol(b + h(c, d, a) + x[i + 12] + 0x6ED9EBA1, 15)

        self._state = [
            (self._state[0] + a) & 0xFFFFFFFF,
            (self._state[1] + b) & 0xFFFFFFFF,
            (self._state[2] + c) & 0xFFFFFFFF,
            (self._state[3] + d) & 0xFFFFFFFF,
        ]


def _md4_hash(data: bytes = b""):
    return _MD4(data)


def ensure_hashlib_md4() -> None:
    """Register an MD4 fallback for NTLM on OpenSSL builds that disable MD4."""
    global _PATCHED
    if _PATCHED:
        return

    try:
        hashlib.new("md4", b"")
        _PATCHED = True
        return
    except (ValueError, TypeError):
        pass

    original_new: Callable[..., object] = hashlib.new

    def new(name: str, data: bytes = b"", **kwargs):
        if name.lower() == "md4":
            return _md4_hash(data)
        return original_new(name, data, **kwargs)

    hashlib.new = new  # type: ignore[assignment]
    _PATCHED = True
