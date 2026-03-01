import os
import time
from rc6 import RC6
from utils import pad, unpad


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_file(input_path, output_path, key, progress_callback=None):
    cipher = RC6(key)
    iv = os.urandom(16)

    with open(input_path, "rb") as f:
        data = pad(f.read())

    total_blocks = len(data) // 16
    encrypted = b""
    prev = iv

    start_time = time.time()

    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        block = xor_bytes(block, prev)
        enc_block = cipher.encrypt_block(block)
        encrypted += enc_block
        prev = enc_block

        if progress_callback:
            progress_callback((i // 16 + 1) / total_blocks * 100)

    end_time = time.time()
    elapsed = end_time - start_time

    with open(output_path, "wb") as f:
        f.write(iv + encrypted)

    return elapsed, len(data)


def decrypt_file(input_path, output_path, key, progress_callback=None):
    cipher = RC6(key)

    with open(input_path, "rb") as f:
        data = f.read()

    iv = data[:16]
    ciphertext = data[16:]

    total_blocks = len(ciphertext) // 16
    decrypted = b""
    prev = iv

    start_time = time.time()

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec_block = cipher.decrypt_block(block)
        dec_block = xor_bytes(dec_block, prev)
        decrypted += dec_block
        prev = block

        if progress_callback:
            progress_callback((i // 16 + 1) / total_blocks * 100)

    decrypted = unpad(decrypted)

    end_time = time.time()
    elapsed = end_time - start_time

    with open(output_path, "wb") as f:
        f.write(decrypted)

    return elapsed, len(ciphertext)