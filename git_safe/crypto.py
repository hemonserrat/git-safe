"""
Cryptographic operations for git-safe
"""

import hashlib
import hmac
import os

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
    if not data:
        return b""

    # Prepare the initial counter value by combining nonce with counter
    # Pad or truncate nonce to fit in the counter space
    if len(nonce) < BLOCK_SIZE:
        # Pad with zeros, leaving space for counter at the end
        counter_prefix = nonce + b"\x00" * (BLOCK_SIZE - 4 - len(nonce))
        initial_counter = counter_prefix + b"\x00\x00\x00\x00"  # 32-bit counter starts at 0
    else:
        # Truncate nonce and reserve last 4 bytes for counter
        counter_prefix = nonce[: BLOCK_SIZE - 4]
        initial_counter = counter_prefix + b"\x00\x00\x00\x00"

    # Use proper CTR mode from cryptography library
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(initial_counter), backend=default_backend())
    decryptor = cipher.decryptor()

    result = decryptor.update(data) + decryptor.finalize()
    return result


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
