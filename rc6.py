import struct
import math

w = 32
r = 20
mod = 2 ** 32
P32 = 0xB7E15163
Q32 = 0x9E3779B9


def rol(x, y):
    return ((x << (y & 31)) | (x >> (32 - (y & 31)))) & 0xFFFFFFFF


def ror(x, y):
    return ((x >> (y & 31)) | (x << (32 - (y & 31)))) & 0xFFFFFFFF


class RC6:
    def __init__(self, key: bytes):
        self._key_schedule(key)

    def _key_schedule(self, key: bytes):
        c = len(key) // 4
        L = list(struct.unpack("<" + "I" * c, key))

        t = 2 * r + 4
        self.S = [0] * t
        self.S[0] = P32
        for i in range(1, t):
            self.S[i] = (self.S[i - 1] + Q32) % mod

        A = B = i = j = 0
        for _ in range(3 * max(c, t)):
            A = self.S[i] = rol((self.S[i] + A + B) % mod, 3)
            B = L[j] = rol((L[j] + A + B) % mod, (A + B))
            i = (i + 1) % t
            j = (j + 1) % c

    def encrypt_block(self, block: bytes) -> bytes:
        A, B, C, D = struct.unpack("<4I", block)

        B = (B + self.S[0]) % mod
        D = (D + self.S[1]) % mod

        for i in range(1, r + 1):
            t = rol(B * (2 * B + 1) % mod, 5)
            u = rol(D * (2 * D + 1) % mod, 5)
            A = (rol(A ^ t, u) + self.S[2 * i]) % mod
            C = (rol(C ^ u, t) + self.S[2 * i + 1]) % mod
            A, B, C, D = B, C, D, A

        A = (A + self.S[2 * r + 2]) % mod
        C = (C + self.S[2 * r + 3]) % mod

        return struct.pack("<4I", A, B, C, D)

    def decrypt_block(self, block: bytes) -> bytes:
        A, B, C, D = struct.unpack("<4I", block)

        C = (C - self.S[2 * r + 3]) % mod
        A = (A - self.S[2 * r + 2]) % mod

        for i in range(r, 0, -1):
            A, B, C, D = D, A, B, C
            u = rol(D * (2 * D + 1) % mod, 5)
            t = rol(B * (2 * B + 1) % mod, 5)
            C = ror((C - self.S[2 * i + 1]) % mod, t) ^ u
            A = ror((A - self.S[2 * i]) % mod, u) ^ t

        D = (D - self.S[1]) % mod
        B = (B - self.S[0]) % mod

        return struct.pack("<4I", A, B, C, D)