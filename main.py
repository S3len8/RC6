import struct
import os

# =========================
# ПАРАМЕТРИ RC6
# =========================
W = 32
R = 20
MOD = 2 ** W
LOG_W = 5

P32 = 0xB7E15163
Q32 = 0x9E3779B9


# =========================
# ДОПОМІЖНІ ФУНКЦІЇ
# =========================
def rotl(x, n):
    n %= W
    return ((x << n) | (x >> (W - n))) & 0xFFFFFFFF


def rotr(x, n):
    n %= W
    return ((x >> n) | (x << (W - n))) & 0xFFFFFFFF


def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]


# =========================
# KEY SCHEDULE
# =========================
def key_schedule(key: bytes):
    b = len(key)
    c = max(1, (b + 3) // 4)

    L = [0] * c
    for i in range(b):
        L[i // 4] |= key[i] << (8 * (i % 4))

    t = 2 * R + 4
    S = [0] * t
    S[0] = P32
    for i in range(1, t):
        S[i] = (S[i - 1] + Q32) % MOD

    A = B = i = j = 0
    v = 3 * max(c, t)

    for _ in range(v):
        A = S[i] = rotl((S[i] + A + B) % MOD, 3)
        B = L[j] = rotl((L[j] + A + B) % MOD, (A + B))
        i = (i + 1) % t
        j = (j + 1) % c

    return S


# =========================
# ШИФРУВАННЯ БЛОКУ
# =========================
def encrypt_block(block: bytes, S):
    A, B, C, D = struct.unpack("<4I", block)

    B = (B + S[0]) % MOD
    D = (D + S[1]) % MOD

    for i in range(1, R + 1):
        t = rotl((B * (2 * B + 1)) % MOD, LOG_W)
        u = rotl((D * (2 * D + 1)) % MOD, LOG_W)

        A = (rotl(A ^ t, u) + S[2 * i]) % MOD
        C = (rotl(C ^ u, t) + S[2 * i + 1]) % MOD

        A, B, C, D = B, C, D, A

    A = (A + S[2 * R + 2]) % MOD
    C = (C + S[2 * R + 3]) % MOD

    return struct.pack("<4I", A, B, C, D)


# =========================
# ДЕШИФРУВАННЯ БЛОКУ
# =========================
def decrypt_block(block: bytes, S):
    A, B, C, D = struct.unpack("<4I", block)

    C = (C - S[2 * R + 3]) % MOD
    A = (A - S[2 * R + 2]) % MOD

    for i in range(R, 0, -1):
        A, B, C, D = D, A, B, C

        t = rotl((B * (2 * B + 1)) % MOD, LOG_W)
        u = rotl((D * (2 * D + 1)) % MOD, LOG_W)

        C = rotr((C - S[2 * i + 1]) % MOD, t) ^ u
        A = rotr((A - S[2 * i]) % MOD, u) ^ t

    D = (D - S[1]) % MOD
    B = (B - S[0]) % MOD

    return struct.pack("<4I", A, B, C, D)


# =========================
# CBC MODE
# =========================
def encrypt_file(input_path, output_path, key: bytes):
    S = key_schedule(key)

    with open(input_path, "rb") as f:
        data = f.read()

    data = pad(data)

    iv = os.urandom(16)
    prev_block = iv
    ciphertext = iv

    for i in range(0, len(data), 16):
        block = data[i:i+16]

        # XOR з попереднім блоком (CBC)
        block = bytes(a ^ b for a, b in zip(block, prev_block))

        encrypted_block = encrypt_block(block, S)
        ciphertext += encrypted_block
        prev_block = encrypted_block

    with open(output_path, "wb") as f:
        f.write(ciphertext)

    print("Файл зашифровано!")


def decrypt_file(input_path, output_path, key: bytes):
    S = key_schedule(key)

    with open(input_path, "rb") as f:
        data = f.read()

    iv = data[:16]
    data = data[16:]

    prev_block = iv
    plaintext = b""

    for i in range(0, len(data), 16):
        block = data[i:i+16]
        decrypted_block = decrypt_block(block, S)

        # XOR після дешифрування
        decrypted_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))

        plaintext += decrypted_block
        prev_block = block

    plaintext = unpad(plaintext)

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print("Файл дешифровано!")


# =========================
# ПРИКЛАД
# =========================
if __name__ == "__main__":
    key = b"ExampleSecretKey123"

    encrypt_file("input.txt", "encrypted.rc6", key)
    decrypt_file("encrypted.rc6", "decrypted.txt", key)