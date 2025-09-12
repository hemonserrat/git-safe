"""
Tests for git_safe.keyfile module
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from git_safe.constants import AES_KEY_LEN, HMAC_KEY_LEN, KEYFILE_AES_KEY_ID, KEYFILE_HMAC_KEY_ID, KEYFILE_MAGIC
from git_safe.keyfile import (
    KeyfileError,
    create_keyfile_data,
    export_key_gpg,
    generate_keyfile,
    generate_keys,
    import_key_gpg,
    load_keyfile,
    save_keyfile,
)


class TestKeyfileOperations:
    """Test keyfile operations"""

    def test_generate_keys(self):
        """Test key generation"""
        aes_key, hmac_key = generate_keys()

        assert len(aes_key) == AES_KEY_LEN
        assert len(hmac_key) == HMAC_KEY_LEN
        assert isinstance(aes_key, bytes)
        assert isinstance(hmac_key, bytes)

        # Generate again to ensure randomness
        aes_key2, hmac_key2 = generate_keys()
        assert aes_key != aes_key2
        assert hmac_key != hmac_key2

    def test_create_keyfile_data(self):
        """Test keyfile data creation"""
        aes_key = b"A" * AES_KEY_LEN
        hmac_key = b"H" * HMAC_KEY_LEN

        keyfile_data = create_keyfile_data(aes_key, hmac_key)

        # Check magic header
        assert keyfile_data.startswith(KEYFILE_MAGIC)

        # Check structure
        assert len(keyfile_data) > len(KEYFILE_MAGIC)

        # Should contain both keys
        assert aes_key in keyfile_data
        assert hmac_key in keyfile_data

    def test_create_keyfile_data_structure(self):
        """Test keyfile data structure in detail"""
        aes_key = b"A" * AES_KEY_LEN
        hmac_key = b"H" * HMAC_KEY_LEN

        keyfile_data = create_keyfile_data(aes_key, hmac_key)

        # Parse the structure
        offset = len(KEYFILE_MAGIC)

        # First blob (AES key)
        import struct

        blob_id, blob_len = struct.unpack(">II", keyfile_data[offset : offset + 8])
        assert blob_id == KEYFILE_AES_KEY_ID
        assert blob_len == len(aes_key)

        blob_data = keyfile_data[offset + 8 : offset + 8 + blob_len]
        assert blob_data == aes_key

        # Second blob (HMAC key)
        offset += 8 + blob_len
        blob_id, blob_len = struct.unpack(">II", keyfile_data[offset : offset + 8])
        assert blob_id == KEYFILE_HMAC_KEY_ID
        assert blob_len == len(hmac_key)

        blob_data = keyfile_data[offset + 8 : offset + 8 + blob_len]
        assert blob_data == hmac_key

    def test_load_keyfile_success(self):
        """Test successful keyfile loading"""
        aes_key = b"A" * AES_KEY_LEN
        hmac_key = b"H" * HMAC_KEY_LEN
        keyfile_data = create_keyfile_data(aes_key, hmac_key)

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(keyfile_data)
            tmp_path = Path(tmp.name)

        try:
            loaded_aes, loaded_hmac = load_keyfile(tmp_path)
            assert loaded_aes == aes_key
            assert loaded_hmac == hmac_key
        finally:
            tmp_path.unlink()

    def test_load_keyfile_missing_file(self):
        """Test loading non-existent keyfile"""
        non_existent = Path("/non/existent/keyfile")

        with pytest.raises(KeyfileError, match="Cannot read keyfile"):
            load_keyfile(non_existent)

    def test_load_keyfile_invalid_magic(self):
        """Test loading keyfile with invalid magic header"""
        invalid_data = b"INVALID" + b"A" * 100

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(invalid_data)
            tmp_path = Path(tmp.name)

        try:
            with pytest.raises(KeyfileError, match="Invalid keyfile: missing magic header"):
                load_keyfile(tmp_path)
        finally:
            tmp_path.unlink()

    def test_load_keyfile_truncated_blob_header(self):
        """Test loading keyfile with truncated blob header"""
        truncated_data = KEYFILE_MAGIC + b"ABC"  # Less than 8 bytes for header

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(truncated_data)
            tmp_path = Path(tmp.name)

        try:
            with pytest.raises(KeyfileError, match="truncated blob header"):
                load_keyfile(tmp_path)
        finally:
            tmp_path.unlink()

    def test_load_keyfile_truncated_blob_data(self):
        """Test loading keyfile with truncated blob data"""
        import struct

        # Create header claiming more data than available
        bad_data = KEYFILE_MAGIC + struct.pack(">II", KEYFILE_AES_KEY_ID, 100) + b"short"

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(bad_data)
            tmp_path = Path(tmp.name)

        try:
            with pytest.raises(KeyfileError, match="truncated blob data"):
                load_keyfile(tmp_path)
        finally:
            tmp_path.unlink()

    def test_load_keyfile_missing_keys(self):
        """Test loading keyfile missing required keys"""
        import struct

        # Create keyfile with unknown blob ID
        bad_data = KEYFILE_MAGIC + struct.pack(">II", 999, 4) + b"test"

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(bad_data)
            tmp_path = Path(tmp.name)

        try:
            with pytest.raises(KeyfileError, match="Missing keys in keyfile"):
                load_keyfile(tmp_path)
        finally:
            tmp_path.unlink()

    def test_load_keyfile_invalid_aes_key_length(self):
        """Test loading keyfile with invalid AES key length"""
        import struct

        bad_aes_key = b"A" * 16  # Wrong length
        hmac_key = b"H" * HMAC_KEY_LEN

        bad_data = KEYFILE_MAGIC
        bad_data += struct.pack(">II", KEYFILE_AES_KEY_ID, len(bad_aes_key)) + bad_aes_key
        bad_data += struct.pack(">II", KEYFILE_HMAC_KEY_ID, len(hmac_key)) + hmac_key

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(bad_data)
            tmp_path = Path(tmp.name)

        try:
            with pytest.raises(KeyfileError, match="Invalid AES key length"):
                load_keyfile(tmp_path)
        finally:
            tmp_path.unlink()

    def test_load_keyfile_invalid_hmac_key_length(self):
        """Test loading keyfile with invalid HMAC key length"""
        import struct

        aes_key = b"A" * AES_KEY_LEN
        bad_hmac_key = b"H" * 32  # Wrong length

        bad_data = KEYFILE_MAGIC
        bad_data += struct.pack(">II", KEYFILE_AES_KEY_ID, len(aes_key)) + aes_key
        bad_data += struct.pack(">II", KEYFILE_HMAC_KEY_ID, len(bad_hmac_key)) + bad_hmac_key

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(bad_data)
            tmp_path = Path(tmp.name)

        try:
            with pytest.raises(KeyfileError, match="Invalid HMAC key length"):
                load_keyfile(tmp_path)
        finally:
            tmp_path.unlink()

    def test_save_keyfile_success(self):
        """Test successful keyfile saving"""
        aes_key = b"A" * AES_KEY_LEN
        hmac_key = b"H" * HMAC_KEY_LEN

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            save_keyfile(tmp_path, aes_key, hmac_key)

            # Verify file was created and has correct permissions
            assert tmp_path.exists()
            assert oct(tmp_path.stat().st_mode)[-3:] == "600"

            # Verify content by loading it back
            loaded_aes, loaded_hmac = load_keyfile(tmp_path)
            assert loaded_aes == aes_key
            assert loaded_hmac == hmac_key
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    @patch("pathlib.Path.write_bytes")
    def test_save_keyfile_write_error(self, mock_write):
        """Test keyfile save with write error"""
        mock_write.side_effect = OSError("Permission denied")

        aes_key = b"A" * AES_KEY_LEN
        hmac_key = b"H" * HMAC_KEY_LEN
        tmp_path = Path("/tmp/test_keyfile")

        with pytest.raises(KeyfileError, match="Cannot save keyfile"):
            save_keyfile(tmp_path, aes_key, hmac_key)

    def test_generate_keyfile(self):
        """Test keyfile generation"""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            aes_key, hmac_key = generate_keyfile(tmp_path)

            # Verify keys are correct length
            assert len(aes_key) == AES_KEY_LEN
            assert len(hmac_key) == HMAC_KEY_LEN

            # Verify file was created
            assert tmp_path.exists()

            # Verify we can load the same keys back
            loaded_aes, loaded_hmac = load_keyfile(tmp_path)
            assert loaded_aes == aes_key
            assert loaded_hmac == hmac_key
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


class TestGPGOperations:
    """Test GPG-related keyfile operations"""

    @pytest.fixture
    def sample_keyfile(self):
        """Create a sample keyfile for testing"""
        aes_key = b"A" * AES_KEY_LEN
        hmac_key = b"H" * HMAC_KEY_LEN
        keyfile_data = create_keyfile_data(aes_key, hmac_key)

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(keyfile_data)
            tmp_path = Path(tmp.name)

        yield tmp_path, aes_key, hmac_key

        if tmp_path.exists():
            tmp_path.unlink()

    @patch("git_safe.keyfile.gnupg.GPG")
    def test_export_key_gpg_success(self, mock_gpg_class, sample_keyfile):
        """Test successful GPG export"""
        keyfile_path, aes_key, hmac_key = sample_keyfile

        # Mock GPG operations
        mock_gpg = MagicMock()
        mock_gpg_class.return_value = mock_gpg

        mock_encrypted = MagicMock()
        mock_encrypted.ok = True
        mock_encrypted.data = b"encrypted_keyfile_data"
        mock_gpg.encrypt.return_value = mock_encrypted

        # Test export
        recipient = "test@example.com"
        result_path = export_key_gpg(keyfile_path, recipient)

        # Verify GPG was called correctly
        mock_gpg.encrypt.assert_called_once()
        args, kwargs = mock_gpg.encrypt.call_args
        assert recipient in args
        assert kwargs.get("armor") is False

        # Verify output file
        expected_path = keyfile_path.with_suffix(keyfile_path.suffix + ".gpg")
        assert result_path == expected_path
        assert result_path.exists()

        # Clean up
        if result_path.exists():
            result_path.unlink()

    @patch("git_safe.keyfile.gnupg.GPG")
    def test_export_key_gpg_custom_output(self, mock_gpg_class, sample_keyfile):
        """Test GPG export with custom output path"""
        keyfile_path, aes_key, hmac_key = sample_keyfile

        mock_gpg = MagicMock()
        mock_gpg_class.return_value = mock_gpg

        mock_encrypted = MagicMock()
        mock_encrypted.ok = True
        mock_encrypted.data = b"encrypted_keyfile_data"
        mock_gpg.encrypt.return_value = mock_encrypted

        custom_output = keyfile_path.parent / "custom.gpg"
        result_path = export_key_gpg(keyfile_path, "test@example.com", custom_output)

        assert result_path == custom_output
        assert result_path.exists()

        # Clean up
        if result_path.exists():
            result_path.unlink()

    @patch("git_safe.keyfile.gnupg.GPG")
    def test_export_key_gpg_encryption_failure(self, mock_gpg_class, sample_keyfile):
        """Test GPG export with encryption failure"""
        keyfile_path, aes_key, hmac_key = sample_keyfile

        mock_gpg = MagicMock()
        mock_gpg_class.return_value = mock_gpg

        mock_encrypted = MagicMock()
        mock_encrypted.ok = False
        mock_encrypted.status = "encryption failed"
        mock_gpg.encrypt.return_value = mock_encrypted

        with pytest.raises(KeyfileError, match="GPG encryption failed"):
            export_key_gpg(keyfile_path, "test@example.com")

    @patch("git_safe.keyfile.gnupg.GPG")
    def test_export_key_gpg_exception(self, mock_gpg_class, sample_keyfile):
        """Test GPG export with general exception"""
        keyfile_path, aes_key, hmac_key = sample_keyfile

        mock_gpg_class.side_effect = Exception("GPG not available")

        with pytest.raises(KeyfileError, match="Failed to export GPG keyfile"):
            export_key_gpg(keyfile_path, "test@example.com")

    @patch("git_safe.keyfile.gnupg.GPG")
    def test_import_key_gpg_success(self, mock_gpg_class):
        """Test successful GPG import"""
        # Create mock encrypted keyfile
        encrypted_data = b"encrypted_keyfile_data"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".gpg") as tmp:
            tmp.write(encrypted_data)
            encrypted_path = Path(tmp.name)

        try:
            # Mock GPG operations
            mock_gpg = MagicMock()
            mock_gpg_class.return_value = mock_gpg

            # Create valid keyfile data for decryption result
            aes_key = b"A" * AES_KEY_LEN
            hmac_key = b"H" * HMAC_KEY_LEN
            keyfile_data = create_keyfile_data(aes_key, hmac_key)

            mock_decrypted = MagicMock()
            mock_decrypted.ok = True
            mock_decrypted.data = keyfile_data
            mock_gpg.decrypt.return_value = mock_decrypted

            # Test import
            result_path = import_key_gpg(encrypted_path)

            # Verify GPG was called correctly
            mock_gpg.decrypt.assert_called_once_with(encrypted_data)

            # Verify output file
            expected_path = encrypted_path.with_suffix("")
            assert result_path == expected_path
            assert result_path.exists()

            # Verify we can load the keyfile
            loaded_aes, loaded_hmac = load_keyfile(result_path)
            assert loaded_aes == aes_key
            assert loaded_hmac == hmac_key

            # Clean up
            if result_path.exists():
                result_path.unlink()
        finally:
            if encrypted_path.exists():
                encrypted_path.unlink()

    @patch("git_safe.keyfile.gnupg.GPG")
    def test_import_key_gpg_custom_output(self, mock_gpg_class):
        """Test GPG import with custom output path"""
        encrypted_data = b"encrypted_keyfile_data"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(encrypted_data)
            encrypted_path = Path(tmp.name)

        try:
            mock_gpg = MagicMock()
            mock_gpg_class.return_value = mock_gpg

            aes_key = b"A" * AES_KEY_LEN
            hmac_key = b"H" * HMAC_KEY_LEN
            keyfile_data = create_keyfile_data(aes_key, hmac_key)

            mock_decrypted = MagicMock()
            mock_decrypted.ok = True
            mock_decrypted.data = keyfile_data
            mock_gpg.decrypt.return_value = mock_decrypted

            custom_output = encrypted_path.parent / "custom.key"
            result_path = import_key_gpg(encrypted_path, custom_output)

            assert result_path == custom_output
            assert result_path.exists()

            # Clean up
            if result_path.exists():
                result_path.unlink()
        finally:
            if encrypted_path.exists():
                encrypted_path.unlink()

    @patch("git_safe.keyfile.gnupg.GPG")
    def test_import_key_gpg_decryption_failure(self, mock_gpg_class):
        """Test GPG import with decryption failure"""
        encrypted_data = b"encrypted_keyfile_data"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(encrypted_data)
            encrypted_path = Path(tmp.name)

        try:
            mock_gpg = MagicMock()
            mock_gpg_class.return_value = mock_gpg

            mock_decrypted = MagicMock()
            mock_decrypted.ok = False
            mock_decrypted.status = "decryption failed"
            mock_gpg.decrypt.return_value = mock_decrypted

            with pytest.raises(KeyfileError, match="GPG decryption failed"):
                import_key_gpg(encrypted_path)
        finally:
            if encrypted_path.exists():
                encrypted_path.unlink()

    @patch("git_safe.keyfile.gnupg.GPG")
    def test_import_key_gpg_invalid_keyfile(self, mock_gpg_class):
        """Test GPG import with invalid decrypted data"""
        encrypted_data = b"encrypted_keyfile_data"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(encrypted_data)
            encrypted_path = Path(tmp.name)

        try:
            mock_gpg = MagicMock()
            mock_gpg_class.return_value = mock_gpg

            mock_decrypted = MagicMock()
            mock_decrypted.ok = True
            mock_decrypted.data = b"invalid_keyfile_data"  # No magic header
            mock_gpg.decrypt.return_value = mock_decrypted

            with pytest.raises(KeyfileError, match="not a valid keyfile"):
                import_key_gpg(encrypted_path)
        finally:
            if encrypted_path.exists():
                encrypted_path.unlink()

    @patch("git_safe.keyfile.gnupg.GPG")
    def test_import_key_gpg_exception(self, mock_gpg_class):
        """Test GPG import with general exception"""
        encrypted_data = b"encrypted_keyfile_data"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(encrypted_data)
            encrypted_path = Path(tmp.name)

        try:
            mock_gpg_class.side_effect = Exception("GPG not available")

            with pytest.raises(KeyfileError, match="Failed to import GPG keyfile"):
                import_key_gpg(encrypted_path)
        finally:
            if encrypted_path.exists():
                encrypted_path.unlink()
