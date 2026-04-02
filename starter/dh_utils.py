import hashlib


def public_component(g: int, private_value: int, p: int) -> int:
    """Compute public value: g^private mod p."""
    # TODO(student): implement with modular exponentiation.
    return pow(g, private_value, p)


def shared_secret(peer_public: int, private_value: int, p: int) -> int:
    """Compute shared secret: peer_public^private mod p."""
    # TODO(student): implement modular exponentiation.
    return pow(peer_public, private_value, p)


def derive_key_material(shared_k: int, length: int = 32) -> bytes:
    """
    - convert integer K to bytes
    - SHA-256 digest
    - return `length` bytes (truncate/repeat)
    """

    k_bytes_len = max(1, (shared_k.bit_length() + 7) // 8)
    k_bytes = shared_k.to_bytes(k_bytes_len, "big")
    digest = hashlib.sha256(k_bytes).digest()

    if length <= len(digest):
        return digest[:length]

    # Repeat digest stream if longer output requested.
    repeats = (length + len(digest) - 1) // len(digest)
    return (digest * repeats)[:length]


def xor_bytes(data: bytes, key_stream: bytes) -> bytes:
    """XOR helper for teaching demo."""
    return bytes([b ^ key_stream[i % len(key_stream)] for i, b in enumerate(data)])
