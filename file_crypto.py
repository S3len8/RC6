import os
import time
import base64
from rc6 import RC6
from utils import pad, unpad

# Магічна сигнатура — перевіряє правильність ключа при розшифруванні
MAGIC = b"RC6SIGN\x00"  # 8 байт


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _cbc_encrypt(cipher, raw_data, progress_callback=None):
    """CBC шифрування сирих байт, повертає iv + ciphertext."""
    iv = os.urandom(16)
    data = pad(MAGIC + raw_data)
    total_blocks = len(data) // 16
    encrypted = b""
    prev = iv
    start = time.time()

    for i in range(0, len(data), 16):
        block = xor_bytes(data[i:i + 16], prev)
        enc_block = cipher.encrypt_block(block)
        encrypted += enc_block
        prev = enc_block
        if progress_callback:
            progress_callback((i // 16 + 1) / total_blocks * 100)

    return iv + encrypted, time.time() - start, len(data)


def _cbc_decrypt(cipher, blob, progress_callback=None):
    """CBC розшифровання blob (iv + ciphertext). Повертає початкові байти."""
    iv = blob[:16]
    ciphertext = blob[16:]
    total_blocks = len(ciphertext) // 16
    decrypted = b""
    prev = iv
    start = time.time()

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec_block = xor_bytes(cipher.decrypt_block(block), prev)
        decrypted += dec_block
        prev = block
        if progress_callback:
            progress_callback((i // 16 + 1) / total_blocks * 100)

    try:
        decrypted = unpad(decrypted)
    except Exception:
        raise ValueError("Неправильний ключ чи дані неправильні.")

    if not decrypted.startswith(MAGIC):
        raise ValueError("Неправильний ключ — дані не можуть бути розшифровані.")

    elapsed = time.time() - start
    return decrypted[len(MAGIC):], elapsed, len(ciphertext)


# ── FILE ───────────────────────────────────────────────────────────────────────

def encrypt_file(input_path, output_path, key, progress_callback=None):
    cipher = RC6(key)
    with open(input_path, "rb") as f:
        raw = f.read()
    blob, elapsed, size = _cbc_encrypt(cipher, raw, progress_callback)
    with open(output_path, "wb") as f:
        f.write(blob)
    return elapsed, size


def decrypt_file(input_path, output_path, key, progress_callback=None):
    cipher = RC6(key)
    with open(input_path, "rb") as f:
        blob = f.read()
    data, elapsed, size = _cbc_decrypt(cipher, blob, progress_callback)
    with open(output_path, "wb") as f:
        f.write(data)
    return elapsed, size


# ── TEXT ───────────────────────────────────────────────────────────────────────

def encrypt_text(plaintext: str, key: bytes, progress_callback=None) -> str:
    """Шифрує строки, повертає Base64-строку."""
    cipher = RC6(key)
    raw = plaintext.encode("utf-8")
    blob, elapsed, size = _cbc_encrypt(cipher, raw, progress_callback)
    return base64.b64encode(blob).decode("ascii"), elapsed, size


def decrypt_text(b64_ciphertext: str, key: bytes, progress_callback=None) -> str:
    """Розшифровує Base64-строку, повертає початковий текст."""
    cipher = RC6(key)
    try:
        blob = base64.b64decode(b64_ciphertext.strip())
    except Exception:
        raise ValueError("Неправильний формат — очікується зашифрований Base64-текст.")
    data, elapsed, size = _cbc_decrypt(cipher, blob, progress_callback)
    return data.decode("utf-8"), elapsed, size