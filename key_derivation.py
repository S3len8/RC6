import hashlib


def derive_key(password: str, key_size: int) -> bytes:
    if key_size not in (16, 24, 32):
        raise ValueError("Key size must be 16, 24 or 32 bytes")

    hash_bytes = hashlib.sha256(password.encode()).digest()
    return hash_bytes[:key_size]