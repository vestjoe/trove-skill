"""The NT hash of a password, so a plaintext and a dumped hash of it are known to be one secret."""

from __future__ import annotations

import functools
import hashlib
import struct

_R1, _R2, _R3 = (3, 7, 11, 19), (3, 5, 9, 13), (3, 9, 11, 15)
_K2 = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
_K3 = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
_MASK = 0xFFFFFFFF


def _rotl(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & _MASK


def md4(data: bytes) -> bytes:
    """RFC 1320 MD4; hashlib only has it when OpenSSL's legacy provider is loaded."""
    bits = len(data) * 8
    data += b"\x80" + b"\0" * ((55 - len(data)) % 64) + struct.pack("<Q", bits)
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    for at in range(0, len(data), 64):
        x = struct.unpack("<16I", data[at:at + 64])
        a, b, c, d = state
        for i in range(16):
            a, b, c, d = d, _rotl((a + ((b & c) | (~b & d)) + x[i]) & _MASK, _R1[i % 4]), b, c
        for i in range(16):
            a, b, c, d = d, _rotl((a + ((b & c) | (b & d) | (c & d)) + x[_K2[i]] + 0x5A827999) & _MASK,
                                  _R2[i % 4]), b, c
        for i in range(16):
            a, b, c, d = d, _rotl((a + (b ^ c ^ d) + x[_K3[i]] + 0x6ED9EBA1) & _MASK, _R3[i % 4]), b, c
        state = [(s + v) & _MASK for s, v in zip(state, (a, b, c, d))]
    return struct.pack("<4I", *state)


def nt_hash(password: str) -> str:
    """Lower-case hex NT hash: MD4 of the UTF-16LE password."""
    return md4(password.encode("utf-16-le")).hex()


@functools.lru_cache(maxsize=1024)
def dcc2(nt: str, user: str, iterations: int) -> str:
    """Lower-case hex DCC2 (mscash2) of an NT hash for a user name, as a cached logon stores it."""
    salt = user.lower().encode("utf-16-le")
    return hashlib.pbkdf2_hmac("sha1", md4(bytes.fromhex(nt) + salt), salt, iterations, 16).hex()
