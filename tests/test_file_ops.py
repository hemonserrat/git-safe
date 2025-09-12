"""
Tests for git_safe.file_ops module
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from git_safe.constants import CTR_NONCE_LEN, MAGIC
from git_safe.file_ops import (
    FileOperationError,
    clean_backups,
    decrypt_file,
    encrypt_file,
    find_encrypted_files,
    is_encrypted_file,
    verify_file_integrity,
)


class TestFileEncryption:
    """Test file encryption operations"""

    @pytest.fixture
    def sample_keys(self):
        """Generate sample keys for testing"""
        aes_key = b"A" * 32  # 32-byte AES key
        hmac_key = b"H" * 64  # 64-byte HMAC key
        return aes_key, hmac_key

    @pytest.fixture
    def sample_file(self):
        """Create a sample file for testing"""
        content = b"This is test file content for encryption testing."

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        yield tmp_path, content

        if tmp_path.exists():
            tmp_path.unlink()

        # Clean up backup file if it exists
        backup_path = tmp_path.with_suffix(tmp_path.suffix + ".backup")
        if backup_path.exists():
            backup_path.unlink()

    def test_encrypt_file_success(self, sample_keys, sample_file):
        """Test successful file encryption"""
        aes_key, hmac_key = sample_keys
        file_path, original_content = sample_file

        # Encrypt the file
        encrypt_file(file_path, aes_key, hmac_key)

        # Verify file was encrypted
        encrypted_content = file_path.read_bytes()
        assert encrypted_content.startswith(MAGIC)
        assert encrypted_content != original_content
        assert len(encrypted_content) > len(MAGIC) + CTR_NONCE_LEN

        # Verify backup was created
        backup_path = file_path.with_suffix(file_path.suffix + ".backup")
        assert backup_path.exists()
        assert backup_path.read_bytes() == original_content

    def test_encrypt_file_no_backup(self, sample_keys, sample_file):
        """Test file encryption without backup"""
        aes_key, hmac_key = sample_keys
        file_path, original_content = sample_file

        # Encrypt without backup
        encrypt_file(file_path, aes_key, hmac_key, backup=False)

        # Verify file was encrypted
        encrypted_content = file_path.read_bytes()
        assert encrypted_content.startswith(MAGIC)

        # Verify no backup was created
        backup_path = file_path.with_suffix(file_path.suffix + ".backup")
        assert not backup_path.exists()

    def test_encrypt_file_empty_file(self, sample_keys):
        """Test encryption of empty file"""
        aes_key, hmac_key = sample_keys

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            # File is empty
            assert tmp_path.read_bytes() == b""

            encrypt_file(tmp_path, aes_key, hmac_key)

            # Should still have magic header and nonce
            encrypted_content = tmp_path.read_bytes()
            assert encrypted_content.startswith(MAGIC)
            assert len(encrypted_content) >= len(MAGIC) + CTR_NONCE_LEN
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
            backup_path = tmp_path.with_suffix(tmp_path.suffix + ".backup")
            if backup_path.exists():
                backup_path.unlink()

    def test_encrypt_file_large_file(self, sample_keys):
        """Test encryption of large file"""
        aes_key, hmac_key = sample_keys
        large_content = b"A" * 10000  # 10KB file

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(large_content)
            tmp_path = Path(tmp.name)

        try:
            encrypt_file(tmp_path, aes_key, hmac_key)

            encrypted_content = tmp_path.read_bytes()
            assert encrypted_content.startswith(MAGIC)
            assert len(encrypted_content) > len(large_content)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
            backup_path = tmp_path.with_suffix(tmp_path.suffix + ".backup")
            if backup_path.exists():
                backup_path.unlink()

    @patch("pathlib.Path.read_bytes")
    def test_encrypt_file_read_error(self, mock_read, sample_keys):
        """Test encryption with file read error"""
        mock_read.side_effect = OSError("Permission denied")

        aes_key, hmac_key = sample_keys
        test_path = Path("/tmp/test_file")

        with pytest.raises(FileOperationError, match="Failed to encrypt"):
            encrypt_file(test_path, aes_key, hmac_key)

    @patch("pathlib.Path.write_bytes")
    def test_encrypt_file_write_error(self, mock_write, sample_keys, sample_file):
        """Test encryption with file write error"""
        # Let read succeed but write fail
        mock_write.side_effect = OSError("Permission denied")

        aes_key, hmac_key = sample_keys
        file_path, _ = sample_file

        with pytest.raises(FileOperationError, match="Failed to encrypt"):
            encrypt_file(file_path, aes_key, hmac_key)


class TestFileDecryption:
    """Test file decryption operations"""

    @pytest.fixture
    def sample_keys(self):
        """Generate sample keys for testing"""
        aes_key = b"A" * 32
        hmac_key = b"H" * 64
        return aes_key, hmac_key

    @pytest.fixture
    def encrypted_file(self, sample_keys):
        """Create an encrypted file for testing"""
        aes_key, hmac_key = sample_keys
        original_content = b"This is test content for decryption testing."

        with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp:
            tmp_path = Path(tmp.name)

        # Create the file with original content first
        tmp_path.write_bytes(original_content)

        # Encrypt it
        encrypt_file(tmp_path, aes_key, hmac_key, backup=False)

        yield tmp_path, original_content

        if tmp_path.exists():
            tmp_path.unlink()

        # Clean up potential decrypted file
        decrypted_path = tmp_path.with_suffix("")
        if decrypted_path.exists():
            decrypted_path.unlink()

    def test_decrypt_file_success(self, sample_keys, encrypted_file):
        """Test successful file decryption"""
        aes_key, hmac_key = sample_keys
        encrypted_path, original_content = encrypted_file

        # Decrypt the file (in-place)
        result = decrypt_file(encrypted_path, aes_key, hmac_key)

        assert result is True

        # Check decrypted file was restored in-place
        assert encrypted_path.read_bytes() == original_content

    def test_decrypt_file_custom_output(self, sample_keys, encrypted_file):
        """Test decryption with custom output path"""
        aes_key, hmac_key = sample_keys
        encrypted_path, original_content = encrypted_file

        custom_output = encrypted_path.parent / "custom_output.txt"

        try:
            result = decrypt_file(encrypted_path, aes_key, hmac_key, output_path=custom_output)

            assert result is True
            assert custom_output.exists()
            assert custom_output.read_bytes() == original_content
        finally:
            if custom_output.exists():
                custom_output.unlink()

    def test_decrypt_file_verify_only(self, sample_keys, encrypted_file):
        """Test decryption in verify-only mode"""
        aes_key, hmac_key = sample_keys
        encrypted_path, original_content = encrypted_file

        result = decrypt_file(encrypted_path, aes_key, hmac_key, verify_only=True)

        assert result is True

        # No output file should be created
        decrypted_path = encrypted_path.with_suffix("")
        assert not decrypted_path.exists()

    def test_decrypt_file_not_encrypted(self, sample_keys):
        """Test decryption of non-encrypted file"""
        aes_key, hmac_key = sample_keys

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"This is not an encrypted file")
            tmp_path = Path(tmp.name)

        try:
            result = decrypt_file(tmp_path, aes_key, hmac_key)
            assert result is False
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_decrypt_file_truncated(self, sample_keys):
        """Test decryption of truncated encrypted file"""
        aes_key, hmac_key = sample_keys

        # Create file with magic but too short for nonce
        truncated_content = MAGIC + b"short"

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(truncated_content)
            tmp_path = Path(tmp.name)

        try:
            result = decrypt_file(tmp_path, aes_key, hmac_key)
            assert result is False
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_decrypt_file_wrong_key(self, encrypted_file):
        """Test decryption with wrong key"""
        wrong_aes_key = b"B" * 32
        wrong_hmac_key = b"I" * 64
        encrypted_path, _ = encrypted_file

        result = decrypt_file(encrypted_path, wrong_aes_key, wrong_hmac_key)
        assert result is False

    def test_decrypt_file_corrupted_hmac(self, sample_keys, encrypted_file):
        """Test decryption with corrupted HMAC"""
        aes_key, hmac_key = sample_keys
        encrypted_path, _ = encrypted_file

        # Corrupt the file by modifying the nonce (which contains HMAC check)
        encrypted_content = encrypted_path.read_bytes()
        corrupted_content = bytearray(encrypted_content)
        # Modify the nonce part (after magic header)
        corrupted_content[len(MAGIC)] = (corrupted_content[len(MAGIC)] + 1) % 256
        encrypted_path.write_bytes(bytes(corrupted_content))

        result = decrypt_file(encrypted_path, aes_key, hmac_key)
        assert result is False

    def test_decrypt_file_no_suffix_handling(self, sample_keys):
        """Test decryption output path handling for files without recognized suffix"""
        aes_key, hmac_key = sample_keys
        original_content = b"Test content"

        with tempfile.NamedTemporaryFile(delete=False, suffix=".unknown") as tmp:
            tmp_path = Path(tmp.name)

        # Create and encrypt the file
        tmp_path.write_bytes(original_content)
        encrypt_file(tmp_path, aes_key, hmac_key, backup=False)

        try:
            result = decrypt_file(tmp_path, aes_key, hmac_key)
            assert result is True

            # Should restore the file in-place
            assert tmp_path.read_bytes() == original_content
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    @patch("pathlib.Path.read_bytes")
    def test_decrypt_file_read_error(self, mock_read, sample_keys):
        """Test decryption with file read error"""
        mock_read.side_effect = OSError("Permission denied")

        aes_key, hmac_key = sample_keys
        test_path = Path("/tmp/test_file")

        with pytest.raises(FileOperationError, match="Failed to decrypt"):
            decrypt_file(test_path, aes_key, hmac_key)


class TestFileDetection:
    """Test encrypted file detection"""

    def test_is_encrypted_file_true(self):
        """Test detection of encrypted file"""
        encrypted_content = MAGIC + b"some encrypted content"

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(encrypted_content)
            tmp_path = Path(tmp.name)

        try:
            assert is_encrypted_file(tmp_path) is True
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_is_encrypted_file_false(self):
        """Test detection of non-encrypted file"""
        regular_content = b"This is regular file content"

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(regular_content)
            tmp_path = Path(tmp.name)

        try:
            assert is_encrypted_file(tmp_path) is False
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_is_encrypted_file_nonexistent(self):
        """Test detection of non-existent file"""
        non_existent = Path("/non/existent/file")
        assert is_encrypted_file(non_existent) is False

    def test_is_encrypted_file_directory(self):
        """Test detection on directory"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            assert is_encrypted_file(tmp_path) is False

    def test_is_encrypted_file_empty(self):
        """Test detection of empty file"""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            # File is empty
            assert is_encrypted_file(tmp_path) is False
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_is_encrypted_file_partial_magic(self):
        """Test detection of file with partial magic header"""
        partial_magic = MAGIC[:5]  # Only part of magic header

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(partial_magic)
            tmp_path = Path(tmp.name)

        try:
            assert is_encrypted_file(tmp_path) is False
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    @patch("pathlib.Path.open")
    def test_is_encrypted_file_read_error(self, mock_open):
        """Test detection with file read error"""
        mock_open.side_effect = OSError("Permission denied")

        test_path = Path("/tmp/test_file")
        assert is_encrypted_file(test_path) is False


class TestFindEncryptedFiles:
    """Test finding encrypted files"""

    @pytest.fixture
    def temp_directory_with_files(self):
        """Create temporary directory with mixed files"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Create regular files
            (tmp_path / "regular1.txt").write_bytes(b"regular content 1")
            (tmp_path / "regular2.txt").write_bytes(b"regular content 2")

            # Create encrypted files
            (tmp_path / "encrypted1.enc").write_bytes(MAGIC + b"encrypted content 1")
            (tmp_path / "encrypted2.enc").write_bytes(MAGIC + b"encrypted content 2")

            # Create subdirectory with files
            (tmp_path / "subdir").mkdir()
            (tmp_path / "subdir" / "regular3.txt").write_bytes(b"regular content 3")
            (tmp_path / "subdir" / "encrypted3.enc").write_bytes(MAGIC + b"encrypted content 3")

            yield tmp_path

    def test_find_encrypted_files_success(self, temp_directory_with_files):
        """Test finding encrypted files in directory tree"""
        root_path = temp_directory_with_files

        encrypted_files = find_encrypted_files(root_path)
        encrypted_names = [f.name for f in encrypted_files]

        assert len(encrypted_files) == 3
        assert "encrypted1.enc" in encrypted_names
        assert "encrypted2.enc" in encrypted_names
        assert "encrypted3.enc" in encrypted_names
        assert "regular1.txt" not in encrypted_names

    def test_find_encrypted_files_empty_directory(self):
        """Test finding encrypted files in empty directory"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            encrypted_files = find_encrypted_files(tmp_path)
            assert len(encrypted_files) == 0

    def test_find_encrypted_files_no_encrypted(self):
        """Test finding encrypted files when none exist"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Create only regular files
            (tmp_path / "regular1.txt").write_bytes(b"regular content 1")
            (tmp_path / "regular2.txt").write_bytes(b"regular content 2")

            encrypted_files = find_encrypted_files(tmp_path)
            assert len(encrypted_files) == 0


class TestCleanBackups:
    """Test backup file cleanup"""

    @pytest.fixture
    def temp_directory_with_backups(self):
        """Create temporary directory with backup files"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Create regular files
            (tmp_path / "file1.txt").write_bytes(b"content 1")
            (tmp_path / "file2.txt").write_bytes(b"content 2")

            # Create backup files
            (tmp_path / "file1.txt.backup").write_bytes(b"backup content 1")
            (tmp_path / "file2.txt.backup").write_bytes(b"backup content 2")
            (tmp_path / "file3.secret.backup").write_bytes(b"backup content 3")

            # Create subdirectory with backups
            (tmp_path / "subdir").mkdir()
            (tmp_path / "subdir" / "file4.key.backup").write_bytes(b"backup content 4")

            yield tmp_path

    def test_clean_backups_success(self, temp_directory_with_backups):
        """Test successful backup cleanup"""
        root_path = temp_directory_with_backups

        # Verify backups exist before cleanup
        assert (root_path / "file1.txt.backup").exists()
        assert (root_path / "file2.txt.backup").exists()
        assert (root_path / "file3.secret.backup").exists()
        assert (root_path / "subdir" / "file4.key.backup").exists()

        count = clean_backups(root_path)

        assert count == 4

        # Verify backups were removed
        assert not (root_path / "file1.txt.backup").exists()
        assert not (root_path / "file2.txt.backup").exists()
        assert not (root_path / "file3.secret.backup").exists()
        assert not (root_path / "subdir" / "file4.key.backup").exists()

        # Verify regular files still exist
        assert (root_path / "file1.txt").exists()
        assert (root_path / "file2.txt").exists()

    def test_clean_backups_custom_pattern(self, temp_directory_with_backups):
        """Test backup cleanup with custom pattern"""
        root_path = temp_directory_with_backups

        # Create files with different backup extension
        (root_path / "file5.txt.bak").write_bytes(b"backup content 5")

        count = clean_backups(root_path, pattern="*.bak")

        assert count == 1
        assert not (root_path / "file5.txt.bak").exists()

        # Original .backup files should still exist
        assert (root_path / "file1.txt.backup").exists()

    def test_clean_backups_no_backups(self):
        """Test backup cleanup when no backups exist"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Create only regular files
            (tmp_path / "file1.txt").write_bytes(b"content 1")
            (tmp_path / "file2.txt").write_bytes(b"content 2")

            count = clean_backups(tmp_path)
            assert count == 0

    @patch("pathlib.Path.unlink")
    def test_clean_backups_removal_error(self, mock_unlink, temp_directory_with_backups):
        """Test backup cleanup with removal error"""
        mock_unlink.side_effect = OSError("Permission denied")

        root_path = temp_directory_with_backups

        # Should not raise exception, just print warning
        count = clean_backups(root_path)
        assert count == 0  # No files successfully removed


class TestVerifyFileIntegrity:
    """Test file integrity verification"""

    @pytest.fixture
    def sample_keys(self):
        """Generate sample keys for testing"""
        aes_key = b"A" * 32
        hmac_key = b"H" * 64
        return aes_key, hmac_key

    def test_verify_file_integrity_valid(self, sample_keys):
        """Test verification of valid encrypted file"""
        aes_key, hmac_key = sample_keys
        original_content = b"Test content for integrity verification"

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(original_content)
            tmp_path = Path(tmp.name)

        try:
            # Encrypt the file
            encrypt_file(tmp_path, aes_key, hmac_key, backup=False)

            # Verify integrity
            result = verify_file_integrity(tmp_path, aes_key, hmac_key)
            assert result is True
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_verify_file_integrity_invalid(self, sample_keys):
        """Test verification of invalid encrypted file"""
        aes_key, hmac_key = sample_keys

        # Create fake encrypted file with wrong HMAC
        fake_encrypted = MAGIC + b"\x00" * CTR_NONCE_LEN + b"fake encrypted content"

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(fake_encrypted)
            tmp_path = Path(tmp.name)

        try:
            result = verify_file_integrity(tmp_path, aes_key, hmac_key)
            assert result is False
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_verify_file_integrity_not_encrypted(self, sample_keys):
        """Test verification of non-encrypted file"""
        aes_key, hmac_key = sample_keys

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"This is not an encrypted file")
            tmp_path = Path(tmp.name)

        try:
            result = verify_file_integrity(tmp_path, aes_key, hmac_key)
            assert result is False
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
