def pad(data: bytes, block_size: int = 16) -> bytes:
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)


def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    return data[:-padding_len]