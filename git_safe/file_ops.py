"""
File operations for git-safe encryption/decryption
"""

from pathlib import Path

from .constants import CTR_NONCE_LEN, HMAC_CHECK_LEN, MAGIC
from .crypto import compute_hmac, ctr_decrypt, ctr_encrypt, generate_nonce, verify_hmac


class FileOperationError(Exception):
    """Exception raised for file operation errors"""

    pass


def encrypt_file(file_path: Path, aes_key: bytes, hmac_key: bytes, backup: bool = True) -> None:
    """
    Encrypt a file in place.

    Args:
        file_path: Path to file to encrypt
        aes_key: 32-byte AES key
        hmac_key: 64-byte HMAC key
        backup: Whether to create a backup before encryption

    Raises:
        FileOperationError: If encryption fails
    """
    try:
        # Read original file data
        original_data = file_path.read_bytes()

        # Create backup if requested
        if backup:
            backup_path = file_path.with_suffix(file_path.suffix + ".backup")
            backup_path.write_bytes(original_data)

        # Generate nonce based on file content
        nonce = generate_nonce(original_data)

        # Encrypt the data
        encrypted_data = ctr_encrypt(aes_key, nonce, original_data)

        # Compute HMAC of the original data
        hmac_value = compute_hmac(hmac_key, original_data)

        # Create the final encrypted file format: MAGIC + nonce + hmac + encrypted_data
        output_data = MAGIC + nonce + hmac_value + encrypted_data

        # Write encrypted file
        file_path.write_bytes(output_data)

        print(f"[encrypted] {file_path}")

    except OSError as e:
        raise FileOperationError(f"Failed to encrypt {file_path}: {e}") from e
    except Exception as e:
        raise FileOperationError(f"Encryption error for {file_path}: {e}") from e


def decrypt_file(
    file_path: Path, aes_key: bytes, hmac_key: bytes, output_path: Path | None = None, verify_only: bool = False
) -> bool:
    """
    Decrypt a file, always overwriting the original file in-place.

    Args:
        file_path: Path to encrypted file
        aes_key: 32-byte AES key
        hmac_key: 64-byte HMAC key
        output_path: (ignored, always writes in-place)
        verify_only: If True, only verify HMAC without writing output

    Returns:
        True if decryption successful, False otherwise

    Raises:
        FileOperationError: If decryption fails
    """
    try:
        # Read encrypted file data
        encrypted_data = file_path.read_bytes()

        # Check for magic header
        if not encrypted_data.startswith(MAGIC):
            return False

        # Extract components
        body = encrypted_data[len(MAGIC) :]
        if len(body) < CTR_NONCE_LEN + HMAC_CHECK_LEN:
            print(f"[INVALID] {file_path}: file too short")
            return False

        nonce = body[:CTR_NONCE_LEN]
        stored_hmac = body[CTR_NONCE_LEN : CTR_NONCE_LEN + HMAC_CHECK_LEN]
        ciphertext = body[CTR_NONCE_LEN + HMAC_CHECK_LEN :]

        # Decrypt the data
        plaintext = ctr_decrypt(aes_key, nonce, ciphertext)

        # Verify HMAC
        if not verify_hmac(hmac_key, plaintext, stored_hmac):
            print(f"[HMAC FAIL] {file_path}")
            return False

        if verify_only:
            print(f"[verified] {file_path}")
            return True

        # Write decrypted file
        if output_path is not None:
            output_path.write_bytes(plaintext)
            print(f"[decrypted] {file_path} -> {output_path}")
        else:
            file_path.write_bytes(plaintext)
            print(f"[decrypted] {file_path} (in-place)")

        return True

    except OSError as e:
        raise FileOperationError(f"Failed to decrypt {file_path}: {e}") from e
    except Exception as e:
        raise FileOperationError(f"Decryption error for {file_path}: {e}") from e


def is_encrypted_file(file_path: Path) -> bool:
    """
    Check if a file is encrypted with git-safe.

    Args:
        file_path: Path to file to check

    Returns:
        True if file is encrypted with git-safe
    """
    try:
        if not file_path.is_file():
            return False

        # Read just enough bytes to check magic header
        with file_path.open("rb") as f:
            header = f.read(len(MAGIC))
            return header == MAGIC
    except OSError:
        return False


def find_encrypted_files(root_path: Path) -> list[Path]:
    """
    Find all encrypted files in a directory tree.

    Args:
        root_path: Root directory to search

    Returns:
        List of encrypted file paths
    """
    encrypted_files = []

    for file_path in root_path.rglob("*"):
        if file_path.is_file() and is_encrypted_file(file_path):
            encrypted_files.append(file_path)

    return encrypted_files


def clean_backups(root_path: Path, pattern: str = "*.backup") -> int:
    """
    Remove backup files created during encryption.

    Args:
        root_path: Root directory to search
        pattern: Glob pattern for backup files

    Returns:
        Number of backup files removed
    """
    count = 0

    for backup_file in root_path.rglob(pattern):
        if backup_file.is_file():
            try:
                backup_file.unlink()
                count += 1
                print(f"[removed backup] {backup_file}")
            except OSError as e:
                print(f"[warning] Could not remove backup {backup_file}: {e}")

    return count


def verify_file_integrity(file_path: Path, aes_key: bytes, hmac_key: bytes) -> bool:
    """
    Verify the integrity of an encrypted file without decrypting it.

    Args:
        file_path: Path to encrypted file
        aes_key: 32-byte AES key
        hmac_key: 64-byte HMAC key

    Returns:
        True if file integrity is valid
    """
    return decrypt_file(file_path, aes_key, hmac_key, verify_only=True)
