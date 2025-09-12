"""
Integration tests for git-safe
Tests the complete workflow from keyfile generation to encryption/decryption
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from git_safe.cli import main
from git_safe.file_ops import decrypt_file, encrypt_file, is_encrypted_file
from git_safe.keyfile import generate_keyfile, load_keyfile
from git_safe.patterns import parse_gitattributes


@pytest.mark.integration
class TestCompleteWorkflow:
    """Test complete git-safe workflow"""

    @pytest.fixture
    def temp_project(self):
        """Create a temporary project directory with files"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            project_path = Path(tmp_dir)

            # Create project files
            (project_path / "README.md").write_text("# Test Project")
            (project_path / "config.json").write_text('{"debug": true}')
            (project_path / "secrets.txt").write_text("secret data")
            (project_path / "passwords.txt").write_text("admin:password123")

            # Create subdirectory
            (project_path / "config").mkdir()
            (project_path / "config" / "dev.env").write_text("API_KEY=secret123")
            (project_path / "config" / "prod.env").write_text("API_KEY=prod456")

            # Create .gitattributes
            gitattributes_content = """
secrets.txt filter=git-safe
passwords.txt filter=git-safe
config/*.env filter=git-safe
            """.strip()
            (project_path / ".gitattributes").write_text(gitattributes_content)

            yield project_path

    def test_keyfile_generation_and_loading(self, temp_project):
        """Test keyfile generation and loading"""
        keyfile_path = temp_project / ".git-safe/.git-safe-key"

        # Generate keyfile
        aes_key, hmac_key = generate_keyfile(keyfile_path)

        assert keyfile_path.exists()
        assert len(aes_key) == 32
        assert len(hmac_key) == 64

        # Load keyfile
        loaded_aes, loaded_hmac = load_keyfile(keyfile_path)

        assert loaded_aes == aes_key
        assert loaded_hmac == hmac_key

    def test_pattern_matching_workflow(self, temp_project):
        """Test pattern matching from .gitattributes"""
        os.chdir(temp_project)

        pathspec = parse_gitattributes()

        # Test pattern matching
        assert pathspec.match_file("secrets.txt")
        assert pathspec.match_file("passwords.txt")
        assert pathspec.match_file("config/dev.env")
        assert pathspec.match_file("config/prod.env")
        assert not pathspec.match_file("README.md")
        assert not pathspec.match_file("config.json")

    def test_encryption_decryption_workflow(self, temp_project):
        """Test complete encryption/decryption workflow"""
        os.chdir(temp_project)

        # Generate keyfile
        keyfile_path = temp_project / ".git-safe/.git-safe-key"
        aes_key, hmac_key = generate_keyfile(keyfile_path)

        # Test files to encrypt
        test_files = [temp_project / "secrets.txt", temp_project / "passwords.txt", temp_project / "config" / "dev.env"]

        original_contents = {}

        # Store original contents
        for file_path in test_files:
            original_contents[file_path] = file_path.read_bytes()

        # Encrypt files
        for file_path in test_files:
            encrypt_file(file_path, aes_key, hmac_key, backup=True)

            # Verify file is encrypted
            assert is_encrypted_file(file_path)

            # Verify backup exists
            backup_path = file_path.with_suffix(file_path.suffix + ".backup")
            assert backup_path.exists()
            assert backup_path.read_bytes() == original_contents[file_path]

        # Decrypt files
        for file_path in test_files:
            # Create output path for decryption
            decrypted_path = file_path.with_suffix(".decrypted")

            result = decrypt_file(file_path, aes_key, hmac_key, output_path=decrypted_path)
            assert result is True

            # Verify decrypted content matches original
            assert decrypted_path.exists()
            assert decrypted_path.read_bytes() == original_contents[file_path]

            # Clean up
            decrypted_path.unlink()

    def test_file_integrity_verification(self, temp_project):
        """Test file integrity verification"""
        os.chdir(temp_project)

        # Generate keyfile
        keyfile_path = temp_project / ".git-safe/.git-safe-key"
        aes_key, hmac_key = generate_keyfile(keyfile_path)

        # Create and encrypt a test file
        test_file = temp_project / "test_integrity.txt"
        test_content = b"Content for integrity testing"
        test_file.write_bytes(test_content)

        encrypt_file(test_file, aes_key, hmac_key, backup=False)

        # Verify integrity (should pass)
        result = decrypt_file(test_file, aes_key, hmac_key, verify_only=True)
        assert result is True

        # Corrupt the file
        encrypted_content = test_file.read_bytes()
        corrupted_content = bytearray(encrypted_content)
        corrupted_content[-1] = (corrupted_content[-1] + 1) % 256  # Modify last byte
        test_file.write_bytes(bytes(corrupted_content))

        # Verify integrity (should fail)
        result = decrypt_file(test_file, aes_key, hmac_key, verify_only=True)
        assert result is False

    def test_wrong_key_handling(self, temp_project):
        """Test behavior with wrong encryption keys"""
        os.chdir(temp_project)

        # Generate two different keyfiles
        keyfile1_path = temp_project / "key1.key"
        keyfile2_path = temp_project / "key2.key"

        aes_key1, hmac_key1 = generate_keyfile(keyfile1_path)
        aes_key2, hmac_key2 = generate_keyfile(keyfile2_path)

        # Create and encrypt file with first key
        test_file = temp_project / "test_wrong_key.txt"
        test_content = b"Content encrypted with key1"
        test_file.write_bytes(test_content)

        encrypt_file(test_file, aes_key1, hmac_key1, backup=False)

        # Try to decrypt with second key (should fail)
        result = decrypt_file(test_file, aes_key2, hmac_key2, verify_only=True)
        assert result is False

        # Decrypt with correct key (should succeed)
        result = decrypt_file(test_file, aes_key1, hmac_key1, verify_only=True)
        assert result is True


@pytest.mark.integration
class TestCLIIntegration:
    """Test CLI integration"""

    @pytest.fixture
    def temp_project(self):
        """Create a temporary project directory"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            project_path = Path(tmp_dir)

            # Create test files
            (project_path / "secret.txt").write_text("secret content")
            (project_path / "regular.txt").write_text("regular content")

            # Create .gitattributes
            (project_path / ".gitattributes").write_text("secret.txt filter=git-safe")

            # Change to project directory
            try:
                original_cwd = os.getcwd()
            except FileNotFoundError:
                # If current directory doesn't exist, use a safe default
                original_cwd = str(Path.home())

            os.chdir(project_path)

            yield project_path

            # Restore original directory
            try:
                os.chdir(original_cwd)
            except (FileNotFoundError, OSError):
                # If original directory no longer exists, go to home
                os.chdir(Path.home())

    @patch("sys.argv")
    def test_cli_init_command(self, mock_argv, temp_project):
        """Test CLI init command"""
        mock_argv.__getitem__.side_effect = lambda i: ["git-safe", "init"][i]
        mock_argv.__len__.return_value = 2

        result = main()

        assert result == 0
        assert (temp_project / ".git-safe/.git-safe-key").exists()

    @patch("sys.argv")
    def test_cli_encrypt_decrypt_workflow(self, mock_argv, temp_project):
        """Test CLI encrypt and decrypt workflow"""
        keyfile_path = temp_project / ".git-safe/.git-safe-key"

        # First, initialize keyfile
        mock_argv.__getitem__.side_effect = lambda i: ["git-safe", "init"][i]
        mock_argv.__len__.return_value = 2

        result = main()
        assert result == 0
        assert keyfile_path.exists()

        # Store original content
        secret_file = temp_project / "secret.txt"
        original_content = secret_file.read_text()

        # Encrypt files
        mock_argv.__getitem__.side_effect = lambda i: ["git-safe", "encrypt"][i]
        mock_argv.__len__.return_value = 2

        result = main()
        assert result == 0

        # Verify file is encrypted
        assert is_encrypted_file(secret_file)

        # Decrypt files
        mock_argv.__getitem__.side_effect = lambda i: ["git-safe", "decrypt", "--all"][i]
        mock_argv.__len__.return_value = 3

        result = main()
        assert result == 0

        # Check if decrypted file was created
        # After decryption, the original file should be restored in-place
        secret_file = temp_project / "secret.txt"
        assert secret_file.read_text() == original_content

    @patch("sys.argv")
    def test_cli_status_command(self, mock_argv, temp_project):
        """Test CLI status command"""
        # Initialize and encrypt first
        keyfile_path = temp_project / ".git-safe/.git-safe-key"

        # Init
        mock_argv.__getitem__.side_effect = lambda i: ["git-safe", "init"][i]
        mock_argv.__len__.return_value = 2
        main()

        # Encrypt
        mock_argv.__getitem__.side_effect = lambda i: ["git-safe", "encrypt"][i]
        mock_argv.__len__.return_value = 2
        main()

        # Status
        mock_argv.__getitem__.side_effect = lambda i: ["git-safe", "status", "--keyfile", str(keyfile_path)][i]
        mock_argv.__len__.return_value = 4

        result = main()
        assert result == 0

    @patch("sys.argv")
    def test_cli_clean_command(self, mock_argv, temp_project):
        """Test CLI clean command"""
        # Create some backup files
        (temp_project / "file1.backup").write_text("backup1")
        (temp_project / "file2.backup").write_text("backup2")

        mock_argv.__getitem__.side_effect = lambda i: ["git-safe", "clean"][i]
        mock_argv.__len__.return_value = 2

        result = main()
        assert result == 0

        # Verify backup files were removed
        assert not (temp_project / "file1.backup").exists()
        assert not (temp_project / "file2.backup").exists()


@pytest.mark.integration
@pytest.mark.slow
class TestLargeFileHandling:
    """Test handling of large files"""

    def test_large_file_encryption_decryption(self, temp_dir):
        """Test encryption/decryption of large files"""
        from git_safe.keyfile import generate_keys

        # Generate keys
        aes_key, hmac_key = generate_keys()

        # Create a large file (1MB)
        large_file = temp_dir / "large_file.bin"
        large_content = os.urandom(1024 * 1024)  # 1MB of random data
        large_file.write_bytes(large_content)

        # Encrypt
        encrypt_file(large_file, aes_key, hmac_key, backup=False)

        # Verify it's encrypted
        assert is_encrypted_file(large_file)

        # Decrypt
        decrypted_file = temp_dir / "large_file_decrypted.bin"
        result = decrypt_file(large_file, aes_key, hmac_key, output_path=decrypted_file)

        assert result is True
        assert decrypted_file.exists()
        assert decrypted_file.read_bytes() == large_content

    def test_many_small_files(self, temp_dir):
        """Test encryption/decryption of many small files"""
        from git_safe.keyfile import generate_keys

        # Generate keys
        aes_key, hmac_key = generate_keys()

        # Create many small files
        num_files = 100
        files_and_content = {}

        for i in range(num_files):
            file_path = temp_dir / f"small_file_{i:03d}.txt"
            content = f"Content of file {i}".encode()
            file_path.write_bytes(content)
            files_and_content[file_path] = content

        # Encrypt all files
        for file_path in files_and_content.keys():
            encrypt_file(file_path, aes_key, hmac_key, backup=False)
            assert is_encrypted_file(file_path)

        # Decrypt all files
        for file_path, original_content in files_and_content.items():
            decrypted_path = file_path.with_suffix(".decrypted")
            result = decrypt_file(file_path, aes_key, hmac_key, output_path=decrypted_path)

            assert result is True
            assert decrypted_path.read_bytes() == original_content

            # Clean up
            decrypted_path.unlink()


@pytest.mark.integration
class TestErrorRecovery:
    """Test error recovery scenarios"""

    def test_partial_encryption_recovery(self, temp_dir):
        """Test recovery from partial encryption failure"""
        from git_safe.file_ops import FileOperationError
        from git_safe.keyfile import generate_keys

        # Generate keys
        aes_key, hmac_key = generate_keys()

        # Create test files
        files = []
        for i in range(3):
            file_path = temp_dir / f"test_file_{i}.txt"
            file_path.write_text(f"Content {i}")
            files.append(file_path)

        # Encrypt first file successfully
        encrypt_file(files[0], aes_key, hmac_key, backup=True)
        assert is_encrypted_file(files[0])

        # Verify backup exists
        backup_path = files[0].with_suffix(files[0].suffix + ".backup")
        assert backup_path.exists()

        # Simulate failure on second file by making it read-only
        files[1].chmod(0o000)  # No permissions

        try:
            with pytest.raises(FileOperationError):
                encrypt_file(files[1], aes_key, hmac_key, backup=True)
        finally:
            # Restore permissions for cleanup
            files[1].chmod(0o644)

        # Third file should still be encryptable
        encrypt_file(files[2], aes_key, hmac_key, backup=True)
        assert is_encrypted_file(files[2])

    def test_corrupted_keyfile_handling(self, temp_dir):
        """Test handling of corrupted keyfiles"""
        from git_safe.keyfile import KeyfileError, load_keyfile

        # Create corrupted keyfile
        corrupted_keyfile = temp_dir / "corrupted.key"
        corrupted_keyfile.write_bytes(b"This is not a valid keyfile")

        with pytest.raises(KeyfileError, match="Invalid keyfile"):
            load_keyfile(corrupted_keyfile)

    def test_missing_gitattributes_handling(self, temp_dir):
        """Test handling when .gitattributes is missing"""
        os.chdir(temp_dir)

        # No .gitattributes file exists
        pathspec = parse_gitattributes()

        # Should return empty pathspec
        assert len(pathspec.patterns) == 0

        # Should not match any files
        test_file = temp_dir / "test.secret"
        test_file.write_text("secret")

        assert not pathspec.match_file("test.secret")
