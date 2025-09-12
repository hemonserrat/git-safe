"""
Keyfile management for git-safe
"""

import os
import struct
from pathlib import Path

import gnupg

from .constants import AES_KEY_LEN, HMAC_KEY_LEN, KEYFILE_AES_KEY_ID, KEYFILE_HMAC_KEY_ID, KEYFILE_MAGIC


class KeyfileError(Exception):
    """Exception raised for keyfile-related errors"""

    pass


def generate_keys() -> tuple[bytes, bytes]:
    """
    Generate new AES and HMAC keys.

    Returns:
        Tuple of (aes_key, hmac_key)
    """
    aes_key = os.urandom(AES_KEY_LEN)
    hmac_key = os.urandom(HMAC_KEY_LEN)
    return aes_key, hmac_key


def create_keyfile_data(aes_key: bytes, hmac_key: bytes) -> bytes:
    """
    Create keyfile binary data from keys.

    Args:
        aes_key: 32-byte AES key
        hmac_key: 64-byte HMAC key

    Returns:
        Binary keyfile data
    """
    data = bytearray(KEYFILE_MAGIC)

    # Add AES key blob
    data.extend(struct.pack(">II", KEYFILE_AES_KEY_ID, len(aes_key)))
    data.extend(aes_key)

    # Add HMAC key blob
    data.extend(struct.pack(">II", KEYFILE_HMAC_KEY_ID, len(hmac_key)))
    data.extend(hmac_key)

    return bytes(data)


def load_keyfile(path: Path) -> tuple[bytes, bytes]:
    """
    Load keys from a keyfile.

    Args:
        path: Path to keyfile

    Returns:
        Tuple of (aes_key, hmac_key)

    Raises:
        KeyfileError: If keyfile is invalid or missing keys
    """
    try:
        data = path.read_bytes()
    except OSError as e:
        raise KeyfileError(f"Cannot read keyfile {path}: {e}") from e

    if not data.startswith(KEYFILE_MAGIC):
        raise KeyfileError("Invalid keyfile: missing magic header")

    blob = data[len(KEYFILE_MAGIC) :]
    aes_key = hmac_key = None

    while blob:
        if len(blob) < 8:
            raise KeyfileError("Invalid keyfile: truncated blob header")

        id_, length = struct.unpack(">II", blob[:8])

        if len(blob) < 8 + length:
            raise KeyfileError("Invalid keyfile: truncated blob data")

        val = blob[8 : 8 + length]
        blob = blob[8 + length :]

        if id_ == KEYFILE_AES_KEY_ID:
            aes_key = val
        elif id_ == KEYFILE_HMAC_KEY_ID:
            hmac_key = val

    if not aes_key or not hmac_key:
        raise KeyfileError("Missing keys in keyfile")

    if len(aes_key) != AES_KEY_LEN:
        raise KeyfileError(f"Invalid AES key length: {len(aes_key)}")

    if len(hmac_key) != HMAC_KEY_LEN:
        raise KeyfileError(f"Invalid HMAC key length: {len(hmac_key)}")

    return aes_key, hmac_key


def save_keyfile(path: Path, aes_key: bytes, hmac_key: bytes) -> None:
    """
    Save keys to a keyfile.

    Args:
        path: Path to save keyfile
        aes_key: 32-byte AES key
        hmac_key: 64-byte HMAC key

    Raises:
        KeyfileError: If unable to save keyfile
    """
    try:
        keyfile_data = create_keyfile_data(aes_key, hmac_key)
        # Ensure parent directory exists
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(keyfile_data)
        # Set restrictive permissions
        path.chmod(0o600)
    except OSError as e:
        raise KeyfileError(f"Cannot save keyfile {path}: {e}") from e


def export_key_gpg(keyfile_path: Path, gpg_recipient: str, output_path: Path | None = None) -> Path:
    """
    Export keyfile encrypted with GPG.

    Args:
        keyfile_path: Path to existing keyfile
        gpg_recipient: GPG key ID or email to encrypt for
        output_path: Optional output path (defaults to keyfile_path.gpg)

    Returns:
        Path to encrypted keyfile

    Raises:
        KeyfileError: If GPG encryption fails
    """
    if output_path is None:
        output_path = keyfile_path.with_suffix(keyfile_path.suffix + ".gpg")

    try:
        gpg = gnupg.GPG()

        # Read keyfile data
        keyfile_data = keyfile_path.read_bytes()

        # Encrypt with GPG
        encrypted_data = gpg.encrypt(keyfile_data, gpg_recipient, armor=False)

        if not encrypted_data.ok:
            raise KeyfileError(f"GPG encryption failed: {encrypted_data.status}")

        # Write encrypted keyfile
        output_path.write_bytes(encrypted_data.data)
        output_path.chmod(0o600)

        return output_path

    except Exception as e:
        raise KeyfileError(f"Failed to export GPG keyfile: {e}") from e


def import_key_gpg(encrypted_keyfile_path: Path, output_path: Path | None = None) -> Path:
    """
    Import keyfile decrypted from GPG.

    Args:
        encrypted_keyfile_path: Path to GPG-encrypted keyfile
        output_path: Optional output path (defaults to removing .gpg extension)

    Returns:
        Path to decrypted keyfile

    Raises:
        KeyfileError: If GPG decryption fails
    """
    if output_path is None:
        if encrypted_keyfile_path.suffix == ".gpg":
            output_path = encrypted_keyfile_path.with_suffix("")
        else:
            output_path = encrypted_keyfile_path.with_suffix(".key")

    try:
        gpg = gnupg.GPG()

        # Read encrypted keyfile data
        encrypted_data = encrypted_keyfile_path.read_bytes()

        # Decrypt with GPG
        decrypted_data = gpg.decrypt(encrypted_data)

        if not decrypted_data.ok:
            raise KeyfileError(f"GPG decryption failed: {decrypted_data.status}")

        # Verify it's a valid keyfile
        if not decrypted_data.data.startswith(KEYFILE_MAGIC):
            raise KeyfileError("Decrypted data is not a valid keyfile")

        # Write decrypted keyfile
        output_path.write_bytes(decrypted_data.data)
        output_path.chmod(0o600)

        return output_path

    except Exception as e:
        raise KeyfileError(f"Failed to import GPG keyfile: {e}") from e


def generate_keyfile(path: Path) -> tuple[bytes, bytes]:
    """
    Generate a new keyfile with random keys.

    Args:
        path: Path to save new keyfile

    Returns:
        Tuple of (aes_key, hmac_key)

    Raises:
        KeyfileError: If unable to generate or save keyfile
    """
    aes_key, hmac_key = generate_keys()
    save_keyfile(path, aes_key, hmac_key)
    return aes_key, hmac_key
