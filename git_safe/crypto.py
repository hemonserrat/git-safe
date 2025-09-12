"""
Cryptographic operations for git-safe
"""

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .constants import BLOCK_SIZE, CTR_NONCE_LEN, HMAC_CHECK_LEN


def ctr_decrypt(aes_key: bytes, nonce: bytes, data: bytes) -> bytes:
    """
    Decrypt data using AES-256 in CTR mode.

    Args:
        aes_key: 32-byte AES key
        nonce: nonce of any length (will be padded/truncated to fit)
        data: Data to decrypt

    Returns:
        Decrypted data
    """
    # Create cipher in ECB mode for manual CTR implementation
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())  # nosec B305
    encryptor = cipher.encryptor()

    out = bytearray()

    for off in range(0, len(data), BLOCK_SIZE):
        block = data[off : off + BLOCK_SIZE]
        # Create counter by combining nonce and block counter
        counter_bytes = nonce + struct.pack(">I", off // BLOCK_SIZE)

        # Pad or truncate to exactly BLOCK_SIZE (16 bytes) for ECB mode
        if len(counter_bytes) < BLOCK_SIZE:
            # Pad with zeros
            ctr = counter_bytes + b"\x00" * (BLOCK_SIZE - len(counter_bytes))
        else:
            # Truncate to block size
            ctr = counter_bytes[:BLOCK_SIZE]

        stream = encryptor.update(ctr)
        out.extend(b ^ s for b, s in zip(block, stream, strict=False))

    # Finalize the encryptor (required by cryptography library)
    encryptor.finalize()
    return bytes(out)


def ctr_encrypt(aes_key: bytes, nonce: bytes, data: bytes) -> bytes:
    """
    Encrypt data using AES-256 in CTR mode.
    CTR mode encryption and decryption are the same operation.

    Args:
        aes_key: 32-byte AES key
        nonce: 12-byte nonce
        data: Data to encrypt

    Returns:
        Encrypted data
    """
    return ctr_decrypt(aes_key, nonce, data)


def generate_nonce(data: bytes) -> bytes:
    """
    Generate a nonce for encryption based on data hash and random bytes.

    Args:
        data: Input data to hash

    Returns:
        12-byte nonce
    """
    h = hashlib.sha256(data, usedforsecurity=False).digest()
    return h[:HMAC_CHECK_LEN] + os.urandom(CTR_NONCE_LEN - HMAC_CHECK_LEN)


def verify_hmac(hmac_key: bytes, data: bytes, expected_hmac: bytes) -> bool:
    """
    Verify HMAC-SHA256 of data.

    Args:
        hmac_key: HMAC key
        data: Data to verify
        expected_hmac: Expected HMAC value (first 12 bytes)

    Returns:
        True if HMAC is valid
    """
    computed_hmac = hmac.new(hmac_key, data, hashlib.sha256).digest()[:HMAC_CHECK_LEN]
    return hmac.compare_digest(computed_hmac, expected_hmac)


def compute_hmac(hmac_key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256 of data.

    Args:
        hmac_key: HMAC key
        data: Data to compute HMAC for

    Returns:
        First 12 bytes of HMAC-SHA256
    """
    return hmac.new(hmac_key, data, hashlib.sha256).digest()[:HMAC_CHECK_LEN]
