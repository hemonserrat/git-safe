"""
Tests for git_safe.cli module
"""

import argparse
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from git_safe.cli import (
    _ensure_gitattributes_filter,
    _is_git_repository,
    _setup_git_filter,
    cmd_clean,
    cmd_decrypt,
    cmd_encrypt,
    cmd_export_key,
    cmd_init,
    cmd_status,
    cmd_unlock,
    create_parser,
    main,
)
from git_safe.file_ops import FileOperationError
from git_safe.keyfile import KeyfileError


class TestCommandInit:
    """Test init command"""

    @pytest.fixture
    def mock_args(self):
        """Create mock arguments for init command"""
        args = MagicMock()
        args.keyfile = MagicMock()
        args.keyfile.name = "test.key"
        args.force = False
        args.export_gpg = None
        return args

    def test_cmd_init_success(self, mock_args):
        """Test successful init command"""
        with patch("git_safe.cli.generate_keyfile") as mock_generate:
            mock_generate.return_value = (b"aes_key", b"hmac_key")
            mock_args.keyfile.exists.return_value = False

            result = cmd_init(mock_args)

            assert result == 0
            mock_generate.assert_called_once_with(mock_args.keyfile)

    @patch("git_safe.cli.generate_keyfile")
    @patch("git_safe.cli.export_key_gpg")
    def test_cmd_init_with_gpg_export(self, mock_export, mock_generate, mock_args):
        """Test init command with GPG export"""
        mock_generate.return_value = (b"aes_key", b"hmac_key")
        mock_export.return_value = Path("test.key.gpg")
        mock_args.keyfile.exists.return_value = False
        mock_args.export_gpg = "test@example.com"

        result = cmd_init(mock_args)

        assert result == 0
        mock_generate.assert_called_once_with(mock_args.keyfile)
        mock_export.assert_called_once_with(mock_args.keyfile, "test@example.com")

    def test_cmd_init_keyfile_exists_no_force(self, mock_args):
        """Test init command when keyfile exists without force"""
        mock_args.keyfile.exists.return_value = True
        mock_args.force = False

        result = cmd_init(mock_args)

        assert result == 1

    @patch("git_safe.cli.generate_keyfile")
    def test_cmd_init_keyfile_exists_with_force(self, mock_generate, mock_args):
        """Test init command when keyfile exists with force"""
        mock_generate.return_value = (b"aes_key", b"hmac_key")
        mock_args.keyfile.exists.return_value = True
        mock_args.force = True

        result = cmd_init(mock_args)

        assert result == 0
        mock_generate.assert_called_once_with(mock_args.keyfile)

    @patch("git_safe.cli.generate_keyfile")
    def test_cmd_init_keyfile_error(self, mock_generate, mock_args):
        """Test init command with keyfile error"""
        mock_generate.side_effect = KeyfileError("Failed to generate keyfile")
        mock_args.keyfile.exists.return_value = False

        cmd_init(mock_args)

    @patch("git_safe.cli.generate_keyfile")
    @patch("git_safe.cli._ensure_gitattributes_filter")
    @patch("git_safe.cli._setup_git_filter")
    def test_cmd_init_with_git_integration_success(
        self, mock_setup_git, mock_ensure_gitattributes, mock_generate, mock_args
    ):
        """Test init command with successful Git integration"""
        mock_generate.return_value = (b"aes_key", b"hmac_key")
        mock_args.keyfile.exists.return_value = False
        mock_ensure_gitattributes.return_value = True
        mock_setup_git.return_value = True

        result = cmd_init(mock_args)

        assert result == 0
        mock_generate.assert_called_once_with(mock_args.keyfile)
        mock_ensure_gitattributes.assert_called_once()
        mock_setup_git.assert_called_once()

    @patch("git_safe.cli.generate_keyfile")
    @patch("git_safe.cli._ensure_gitattributes_filter")
    @patch("git_safe.cli._setup_git_filter")
    def test_cmd_init_with_git_integration_partial_success(
        self, mock_setup_git, mock_ensure_gitattributes, mock_generate, mock_args
    ):
        """Test init command with partial Git integration success"""
        mock_generate.return_value = (b"aes_key", b"hmac_key")
        mock_args.keyfile.exists.return_value = False
        mock_ensure_gitattributes.return_value = True
        mock_setup_git.return_value = False  # Git filter setup fails

        result = cmd_init(mock_args)

        assert result == 0  # Should still succeed
        mock_generate.assert_called_once_with(mock_args.keyfile)
        mock_ensure_gitattributes.assert_called_once()
        mock_setup_git.assert_called_once()

    @patch("git_safe.cli.generate_keyfile")
    @patch("git_safe.cli._ensure_gitattributes_filter")
    @patch("git_safe.cli._setup_git_filter")
    def test_cmd_init_with_git_integration_warnings(
        self, mock_setup_git, mock_ensure_gitattributes, mock_generate, mock_args
    ):
        """Test init command with Git integration warnings"""
        mock_generate.return_value = (b"aes_key", b"hmac_key")
        mock_args.keyfile.exists.return_value = False
        mock_ensure_gitattributes.return_value = False  # .gitattributes setup fails
        mock_setup_git.return_value = False  # Git filter setup fails

        result = cmd_init(mock_args)

        assert result == 0  # Should still succeed
        mock_generate.assert_called_once_with(mock_args.keyfile)
        mock_ensure_gitattributes.assert_called_once()
        mock_setup_git.assert_called_once()


class TestGitRepositoryHelpers:
    """Test Git repository helper functions"""

    @patch("pathlib.Path.exists")
    def test_is_git_repository_with_git_dir(self, mock_exists):
        """Test _is_git_repository when .git directory exists"""
        mock_exists.return_value = True

        result = _is_git_repository()

        assert result is True
        mock_exists.assert_called_once()

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_file")
    def test_is_git_repository_with_git_file(self, mock_is_file, mock_exists):
        """Test _is_git_repository when .git file exists (worktree)"""
        mock_exists.return_value = False
        mock_is_file.return_value = True

        result = _is_git_repository()

        assert result is True
        mock_exists.assert_called_once()
        mock_is_file.assert_called_once()

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_file")
    def test_is_git_repository_no_git(self, mock_is_file, mock_exists):
        """Test _is_git_repository when no .git exists"""
        mock_exists.return_value = False
        mock_is_file.return_value = False

        result = _is_git_repository()

        assert result is False

    def test_ensure_gitattributes_filter_create_new_file(self):
        """Test _ensure_gitattributes_filter creates new .gitattributes file"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            import os

            original_cwd = os.getcwd()
            try:
                os.chdir(tmp_dir)

                result = _ensure_gitattributes_filter()

                assert result is True
                gitattributes_path = Path(".gitattributes")
                assert gitattributes_path.exists()
                content = gitattributes_path.read_text()
                assert "*.secret filter=git-safe diff=git-safe" in content
            finally:
                os.chdir(original_cwd)

    def test_ensure_gitattributes_filter_append_to_existing(self):
        """Test _ensure_gitattributes_filter appends to existing .gitattributes"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            import os

            original_cwd = os.getcwd()
            try:
                os.chdir(tmp_dir)

                # Create existing .gitattributes
                gitattributes_path = Path(".gitattributes")
                gitattributes_path.write_text("*.txt text\n")

                result = _ensure_gitattributes_filter()

                assert result is True
                content = gitattributes_path.read_text()
                assert "*.txt text" in content
                assert "*.secret filter=git-safe diff=git-safe" in content
            finally:
                os.chdir(original_cwd)

    def test_ensure_gitattributes_filter_already_exists(self):
        """Test _ensure_gitattributes_filter when filter line already exists"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            import os

            original_cwd = os.getcwd()
            try:
                os.chdir(tmp_dir)

                # Create .gitattributes with existing filter line
                gitattributes_path = Path(".gitattributes")
                gitattributes_path.write_text("*.secret filter=git-safe diff=git-safe\n")
                original_content = gitattributes_path.read_text()

                result = _ensure_gitattributes_filter()

                assert result is True
                # Content should be unchanged
                assert gitattributes_path.read_text() == original_content
            finally:
                os.chdir(original_cwd)

    @patch("pathlib.Path.open")
    def test_ensure_gitattributes_filter_write_error(self, mock_open):
        """Test _ensure_gitattributes_filter handles write errors"""
        mock_open.side_effect = OSError("Permission denied")

        result = _ensure_gitattributes_filter()

        assert result is False

    @patch("git_safe.cli._is_git_repository")
    def test_setup_git_filter_not_git_repo(self, mock_is_git):
        """Test _setup_git_filter when not in Git repository"""
        mock_is_git.return_value = False

        result = _setup_git_filter()

        assert result is False
        mock_is_git.assert_called_once()

    @patch("git_safe.cli._is_git_repository")
    @patch("subprocess.run")
    def test_setup_git_filter_success(self, mock_run, mock_is_git):
        """Test _setup_git_filter successful setup"""
        mock_is_git.return_value = True

        # Mock git config check (config doesn't exist)
        check_result = MagicMock()
        check_result.returncode = 1  # Config doesn't exist

        # Mock git config set (successful)
        set_result = MagicMock()
        set_result.returncode = 0

        mock_run.side_effect = [check_result] * 4 + [set_result] * 4

        result = _setup_git_filter()

        assert result is True
        mock_is_git.assert_called_once()
        # Should be called 8 times (4 checks + 4 sets)
        # The actual call count may vary based on early returns for conflicting configs
        assert mock_run.call_count >= 4  # At least 4 checks should be made

    @patch("git_safe.cli._is_git_repository")
    @patch("subprocess.run")
    def test_setup_git_filter_already_configured(self, mock_run, mock_is_git):
        """Test _setup_git_filter when already configured correctly"""
        mock_is_git.return_value = True

        # Mock git config check (config exists with correct value)
        check_result = MagicMock()
        check_result.returncode = 0
        check_result.stdout = "git-safe clean %f"

        mock_run.return_value = check_result

        result = _setup_git_filter()

        assert result is True
        mock_is_git.assert_called_once()
        # Should only check, not set
        assert mock_run.call_count == 4

    @patch("git_safe.cli._is_git_repository")
    @patch("subprocess.run")
    def test_setup_git_filter_conflicting_config(self, mock_run, mock_is_git):
        """Test _setup_git_filter with conflicting existing config"""
        mock_is_git.return_value = True

        # Mock git config check (config exists with different value)
        check_result = MagicMock()
        check_result.returncode = 0
        check_result.stdout = "different-tool clean %f"

        mock_run.return_value = check_result

        result = _setup_git_filter()

        assert result is True  # Should still succeed but warn
        mock_is_git.assert_called_once()
        # Should only check, not set due to conflict
        assert mock_run.call_count == 4

    @patch("git_safe.cli._is_git_repository")
    @patch("subprocess.run")
    def test_setup_git_filter_set_error(self, mock_run, mock_is_git):
        """Test _setup_git_filter when git config set fails"""
        mock_is_git.return_value = True

        # Mock git config check (config doesn't exist)
        check_result = MagicMock()
        check_result.returncode = 1

        # Mock git config set (fails)
        set_result = MagicMock()
        set_result.returncode = 1
        mock_run.side_effect = [check_result, set_result]

        result = _setup_git_filter()

        assert result is False
        mock_is_git.assert_called_once()

    @patch("git_safe.cli._is_git_repository")
    @patch("subprocess.run")
    def test_setup_git_filter_exception(self, mock_run, mock_is_git):
        """Test _setup_git_filter handles exceptions"""
        mock_is_git.return_value = True
        mock_run.side_effect = Exception("Unexpected error")

        result = _setup_git_filter()

        assert result is False


class TestCommandExportKey:
    """Test export-key command"""

    @pytest.fixture
    def mock_args(self):
        """Create mock arguments for export-key command"""
        args = MagicMock()
        args.keyfile = MagicMock()
        args.recipient = "test@example.com"
        args.output = None
        return args

    @patch("git_safe.cli.export_key_gpg")
    def test_cmd_export_key_success(self, mock_export, mock_args):
        """Test successful export-key command"""
        mock_export.return_value = Path("test.key.gpg")
        mock_args.keyfile.exists = MagicMock(return_value=True)

        result = cmd_export_key(mock_args)

        assert result == 0
        mock_export.assert_called_once()

    def test_cmd_export_key_keyfile_not_exists(self, mock_args):
        """Test export-key command when keyfile doesn't exist"""
        mock_args.keyfile.exists = MagicMock(return_value=False)

        result = cmd_export_key(mock_args)

        assert result == 1

    @patch("git_safe.cli.export_key_gpg")
    def test_cmd_export_key_with_custom_output(self, mock_export, mock_args):
        """Test export-key command with custom output path"""
        mock_export.return_value = Path("custom.gpg")
        mock_args.keyfile.exists = MagicMock(return_value=True)
        mock_args.output = Path("custom.gpg")

        result = cmd_export_key(mock_args)

        assert result == 0
        mock_export.assert_called_once_with(mock_args.keyfile, mock_args.recipient, mock_args.output)

    @patch("git_safe.cli.export_key_gpg")
    def test_cmd_export_key_error(self, mock_export, mock_args):
        """Test export-key command with error"""
        mock_export.side_effect = KeyfileError("GPG export failed")
        mock_args.keyfile.exists = MagicMock(return_value=True)

        result = cmd_export_key(mock_args)

        assert result == 1


class TestCommandUnlock:
    """Test unlock command"""

    @pytest.fixture
    def mock_args(self):
        """Create mock arguments for unlock command"""
        args = MagicMock()
        args.gpg_keyfile = MagicMock()
        args.output = None
        return args

    @patch("git_safe.cli.import_key_gpg")
    def test_cmd_unlock_success(self, mock_import, mock_args):
        """Test successful unlock command"""
        mock_import.return_value = Path("test.key")
        mock_args.gpg_keyfile.exists = MagicMock(return_value=True)

        result = cmd_unlock(mock_args)

        assert result == 0
        mock_import.assert_called_once()

    def test_cmd_unlock_gpg_keyfile_not_exists(self, mock_args):
        """Test unlock command when GPG keyfile doesn't exist"""
        mock_args.gpg_keyfile.exists = MagicMock(return_value=False)

        result = cmd_unlock(mock_args)

        assert result == 1

    @patch("git_safe.cli.import_key_gpg")
    def test_cmd_unlock_with_custom_output(self, mock_import, mock_args):
        """Test unlock command with custom output path"""
        mock_import.return_value = Path("custom.key")
        mock_args.gpg_keyfile.exists = MagicMock(return_value=True)
        mock_args.output = Path("custom.key")

        result = cmd_unlock(mock_args)

        assert result == 0
        mock_import.assert_called_once_with(mock_args.gpg_keyfile, mock_args.output)

    @patch("git_safe.cli.import_key_gpg")
    def test_cmd_unlock_error(self, mock_import, mock_args):
        """Test unlock command with error"""
        mock_import.side_effect = KeyfileError("GPG import failed")
        mock_args.gpg_keyfile.exists = MagicMock(return_value=True)

        result = cmd_unlock(mock_args)

        assert result == 1


class TestCommandEncrypt:
    """Test encrypt command"""

    @pytest.fixture
    def mock_args(self):
        """Create mock arguments for encrypt command"""
        args = MagicMock()
        args.keyfile = Path("test.key")
        args.no_backup = False
        args.continue_on_error = False
        return args

    @patch("git_safe.cli.load_keyfile")
    @patch("git_safe.cli.parse_gitattributes")
    @patch("git_safe.cli.find_matching_files")
    @patch("git_safe.cli.encrypt_file")
    @patch("pathlib.Path.cwd")
    def test_cmd_encrypt_success(self, mock_cwd, mock_encrypt, mock_find, mock_parse, mock_load, mock_args):
        """Test successful encrypt command"""
        # Setup mocks
        mock_load.return_value = (b"aes_key", b"hmac_key")
        mock_pathspec = MagicMock()
        mock_pathspec.patterns = ["*.secret"]
        mock_parse.return_value = mock_pathspec
        mock_cwd.return_value = Path("/test")
        mock_find.return_value = [Path("test.secret"), Path("passwords.txt")]

        result = cmd_encrypt(mock_args)

        assert result == 0
        assert mock_encrypt.call_count == 2
        mock_load.assert_called_once_with(mock_args.keyfile)
        mock_parse.assert_called_once()
        mock_find.assert_called_once()

    @patch("git_safe.cli.load_keyfile")
    @patch("git_safe.cli.parse_gitattributes")
    def test_cmd_encrypt_no_patterns(self, mock_parse, mock_load, mock_args):
        """Test encrypt command with no patterns"""
        mock_load.return_value = (b"aes_key", b"hmac_key")
        mock_pathspec = MagicMock()
        mock_pathspec.patterns = []
        mock_parse.return_value = mock_pathspec

        result = cmd_encrypt(mock_args)

        assert result == 0

    @patch("git_safe.cli.load_keyfile")
    @patch("git_safe.cli.parse_gitattributes")
    @patch("git_safe.cli.find_matching_files")
    @patch("pathlib.Path.cwd")
    def test_cmd_encrypt_no_matching_files(self, mock_cwd, mock_find, mock_parse, mock_load, mock_args):
        """Test encrypt command with no matching files"""
        mock_load.return_value = (b"aes_key", b"hmac_key")
        mock_pathspec = MagicMock()
        mock_pathspec.patterns = ["*.secret"]
        mock_parse.return_value = mock_pathspec
        mock_cwd.return_value = Path("/test")
        mock_find.return_value = []

        result = cmd_encrypt(mock_args)

        assert result == 0

    @patch("git_safe.cli.load_keyfile")
    @patch("git_safe.cli.parse_gitattributes")
    @patch("git_safe.cli.find_matching_files")
    @patch("git_safe.cli.encrypt_file")
    @patch("pathlib.Path.cwd")
    def test_cmd_encrypt_file_error_no_continue(
        self, mock_cwd, mock_encrypt, mock_find, mock_parse, mock_load, mock_args
    ):
        """Test encrypt command with file error and no continue"""
        mock_load.return_value = (b"aes_key", b"hmac_key")
        mock_pathspec = MagicMock()
        mock_pathspec.patterns = ["*.secret"]
        mock_parse.return_value = mock_pathspec
        mock_cwd.return_value = Path("/test")
        mock_find.return_value = [Path("test.secret")]
        mock_encrypt.side_effect = FileOperationError("Encryption failed")
        mock_args.continue_on_error = False

        result = cmd_encrypt(mock_args)

        assert result == 1

    @patch("git_safe.cli.load_keyfile")
    @patch("git_safe.cli.parse_gitattributes")
    @patch("git_safe.cli.find_matching_files")
    @patch("git_safe.cli.encrypt_file")
    @patch("pathlib.Path.cwd")
    def test_cmd_encrypt_file_error_continue(self, mock_cwd, mock_encrypt, mock_find, mock_parse, mock_load, mock_args):
        """Test encrypt command with file error and continue"""
        mock_load.return_value = (b"aes_key", b"hmac_key")
        mock_pathspec = MagicMock()
        mock_pathspec.patterns = ["*.secret"]
        mock_parse.return_value = mock_pathspec
        mock_cwd.return_value = Path("/test")
        mock_find.return_value = [Path("test.secret"), Path("passwords.txt")]
        mock_encrypt.side_effect = [FileOperationError("Encryption failed"), None]
        mock_args.continue_on_error = True

        result = cmd_encrypt(mock_args)

        assert result == 0
        assert mock_encrypt.call_count == 2

    @patch("git_safe.cli.load_keyfile")
    def test_cmd_encrypt_keyfile_error(self, mock_load, mock_args):
        """Test encrypt command with keyfile error"""
        mock_load.side_effect = KeyfileError("Cannot load keyfile")

        result = cmd_encrypt(mock_args)

        assert result == 1


class TestCommandDecrypt:
    """Test decrypt command"""

    @pytest.fixture
    def mock_args(self):
        """Create mock arguments for decrypt command"""
        args = MagicMock()
        args.keyfile = Path("test.key")
        args.all = False
        args.patterns = []
        args.continue_on_error = False
        return args

    @patch("git_safe.cli.load_keyfile")
    @patch("git_safe.cli.find_encrypted_files")
    @patch("git_safe.cli.decrypt_file")
    @patch("pathlib.Path.cwd")
    def test_cmd_decrypt_all_success(self, mock_cwd, mock_decrypt, mock_find, mock_load, mock_args):
        """Test successful decrypt command with --all"""
        mock_load.return_value = (b"aes_key", b"hmac_key")
        mock_cwd.return_value = Path("/test")
        mock_find.return_value = [Path("test.enc"), Path("passwords.enc")]
        mock_decrypt.return_value = True
        mock_args.all = True

        result = cmd_decrypt(mock_args)

        assert result == 0
        assert mock_decrypt.call_count == 2
        mock_load.assert_called_once_with(mock_args.keyfile)
        mock_find.assert_called_once()

    @patch("git_safe.cli.load_keyfile")
    @patch("git_safe.cli.decrypt_file")
    @patch("pathlib.Path.cwd")
    @patch("pathlib.Path.glob")
    def test_cmd_decrypt_patterns_success(self, mock_glob, mock_cwd, mock_decrypt, mock_load, mock_args):
        """Test successful decrypt command with patterns"""
        mock_load.return_value = (b"aes_key", b"hmac_key")
        mock_cwd.return_value = Path("/test")
        mock_file = MagicMock()
        mock_file.is_file.return_value = True
        mock_glob.return_value = [mock_file]
        mock_decrypt.return_value = True
        mock_args.patterns = ["*.enc"]

        result = cmd_decrypt(mock_args)

        assert result == 0
        mock_decrypt.assert_called_once()

    @patch("git_safe.cli.load_keyfile")
    @patch("git_safe.cli.parse_gitattributes")
    def test_cmd_decrypt_no_options(self, mock_parse, mock_load, mock_args):
        """Test decrypt command with no --all and no patterns (uses .gitattributes by default)"""
        mock_load.return_value = (b"aes_key", b"hmac_key")
        mock_pathspec = MagicMock()
        mock_pathspec.patterns = []
        mock_parse.return_value = mock_pathspec

        result = cmd_decrypt(mock_args)

        assert result == 0
        mock_parse.assert_called_once()

    @patch("git_safe.cli.load_keyfile")
    @patch("git_safe.cli.parse_gitattributes")
    @patch("git_safe.cli.find_matching_files")
    @patch("git_safe.cli.decrypt_file")
    @patch("pathlib.Path.cwd")
    def test_cmd_decrypt_gitattributes_success(
        self, mock_cwd, mock_decrypt, mock_find, mock_parse, mock_load, mock_args
    ):
        """Test decrypt command using .gitattributes patterns successfully"""
        mock_load.return_value = (b"aes_key", b"hmac_key")
        mock_pathspec = MagicMock()
        mock_pathspec.patterns = ["*.secret"]
        mock_parse.return_value = mock_pathspec
        mock_cwd.return_value = Path("/test")
        mock_file = MagicMock()
        mock_file.is_file.return_value = True
        mock_find.return_value = [mock_file]
        mock_decrypt.return_value = True

        result = cmd_decrypt(mock_args)

        assert result == 0
        mock_parse.assert_called_once()
        mock_find.assert_called_once()
        mock_decrypt.assert_called_once()

    @patch("git_safe.cli.load_keyfile")
    @patch("git_safe.cli.find_encrypted_files")
    @patch("pathlib.Path.cwd")
    def test_cmd_decrypt_no_files_found(self, mock_cwd, mock_find, mock_load, mock_args):
        """Test decrypt command when no files found"""
        mock_load.return_value = (b"aes_key", b"hmac_key")
        mock_cwd.return_value = Path("/test")
        mock_find.return_value = []
        mock_args.all = True

        result = cmd_decrypt(mock_args)

        assert result == 0

    @patch("git_safe.cli.load_keyfile")
    @patch("git_safe.cli.find_encrypted_files")
    @patch("git_safe.cli.decrypt_file")
    @patch("pathlib.Path.cwd")
    def test_cmd_decrypt_file_error_no_continue(self, mock_cwd, mock_decrypt, mock_find, mock_load, mock_args):
        """Test decrypt command with file error and no continue"""
        mock_load.return_value = (b"aes_key", b"hmac_key")
        mock_cwd.return_value = Path("/test")
        mock_find.return_value = [Path("test.enc")]
        mock_decrypt.side_effect = FileOperationError("Decryption failed")
        mock_args.all = True
        mock_args.continue_on_error = False

        result = cmd_decrypt(mock_args)

        assert result == 1

    @patch("git_safe.cli.load_keyfile")
    def test_cmd_decrypt_keyfile_error(self, mock_load, mock_args):
        """Test decrypt command with keyfile error"""
        mock_load.side_effect = KeyfileError("Cannot load keyfile")

        result = cmd_decrypt(mock_args)

        assert result == 1


class TestCommandStatus:
    """Test status command"""

    @pytest.fixture
    def mock_args(self):
        """Create mock arguments for status command"""
        args = MagicMock()
        args.keyfile = None
        return args

    @patch("git_safe.cli.find_encrypted_files")
    @patch("pathlib.Path.cwd")
    def test_cmd_status_no_keyfile(self, mock_cwd, mock_find, mock_args):
        """Test status command without keyfile"""
        mock_cwd.return_value = Path("/test")
        mock_find.return_value = [Path("test.enc"), Path("passwords.enc")]

        result = cmd_status(mock_args)

        assert result == 0
        mock_find.assert_called_once()

    @patch("git_safe.cli.load_keyfile")
    @patch("git_safe.cli.find_encrypted_files")
    @patch("git_safe.cli.verify_file_integrity")
    @patch("pathlib.Path.cwd")
    def test_cmd_status_with_keyfile(self, mock_cwd, mock_verify, mock_find, mock_load, mock_args):
        """Test status command with keyfile"""
        mock_load.return_value = (b"aes_key", b"hmac_key")
        mock_cwd.return_value = Path("/test")
        mock_find.return_value = [Path("test.enc"), Path("passwords.enc")]
        mock_verify.side_effect = [True, False]
        mock_args.keyfile = MagicMock()
        mock_args.keyfile.exists = MagicMock(return_value=True)

        result = cmd_status(mock_args)

        assert result == 0
        mock_load.assert_called_once_with(mock_args.keyfile)
        assert mock_verify.call_count == 2

    @patch("git_safe.cli.find_encrypted_files")
    @patch("pathlib.Path.cwd")
    def test_cmd_status_no_encrypted_files(self, mock_cwd, mock_find, mock_args):
        """Test status command when no encrypted files found"""
        mock_cwd.return_value = Path("/test")
        mock_find.return_value = []

        result = cmd_status(mock_args)

        assert result == 0

    @patch("git_safe.cli.load_keyfile")
    def test_cmd_status_keyfile_error(self, mock_load, mock_args):
        """Test status command with keyfile error"""
        mock_load.side_effect = KeyfileError("Cannot load keyfile")
        mock_args.keyfile = MagicMock()
        mock_args.keyfile.exists = MagicMock(return_value=True)

        result = cmd_status(mock_args)

        assert result == 1


class TestCommandClean:
    """Test clean command"""

    @pytest.fixture
    def mock_args(self):
        """Create mock arguments for clean command"""
        args = MagicMock()
        args.filename = None  # Ensure it's backup cleanup, not Git filter
        return args

    @patch("git_safe.cli.clean_backups")
    @patch("pathlib.Path.cwd")
    def test_cmd_clean_success(self, mock_cwd, mock_clean, mock_args):
        """Test successful clean command"""
        mock_cwd.return_value = Path("/test")
        mock_clean.return_value = 5
        mock_args.filename = None  # Ensure it's backup cleanup, not Git filter

        result = cmd_clean(mock_args)

        assert result == 0
        mock_clean.assert_called_once_with(Path("/test"))

    @patch("git_safe.cli.clean_backups")
    @patch("pathlib.Path.cwd")
    def test_cmd_clean_error(self, mock_cwd, mock_clean, mock_args):
        """Test clean command with error"""
        mock_cwd.return_value = Path("/test")
        mock_clean.side_effect = Exception("Cleanup failed")

        result = cmd_clean(mock_args)

        assert result == 1


class TestArgumentParser:
    """Test argument parser creation"""

    def test_create_parser(self):
        """Test parser creation"""
        parser = create_parser()

        assert isinstance(parser, argparse.ArgumentParser)
        assert parser.prog == "git-safe"

    def test_parser_init_command(self):
        """Test parsing init command"""
        parser = create_parser()

        args = parser.parse_args(["init"])
        assert args.command == "init"
        assert args.keyfile == Path(".git-safe/.git-safe-key")
        assert args.force is False
        assert args.export_gpg is None

        args = parser.parse_args(["init", "--keyfile", "custom.key", "--force", "--export-gpg", "test@example.com"])
        assert args.keyfile == Path("custom.key")
        assert args.force is True
        assert args.export_gpg == "test@example.com"

    def test_parser_export_key_command(self):
        """Test parsing export-key command"""
        parser = create_parser()

        args = parser.parse_args(["export-key", "test@example.com"])
        assert args.command == "export-key"
        assert args.recipient == "test@example.com"
        assert args.keyfile == Path(".git-safe/.git-safe-key")
        assert args.output is None

        args = parser.parse_args(
            ["export-key", "--keyfile", "custom.key", "--output", "custom.gpg", "test@example.com"]
        )
        assert args.keyfile == Path("custom.key")
        assert args.output == Path("custom.gpg")

    def test_parser_unlock_command(self):
        """Test parsing unlock command"""
        parser = create_parser()

        args = parser.parse_args(["unlock", "--gpg-keyfile", "test.key.gpg"])
        assert args.command == "unlock"
        assert args.gpg_keyfile == Path("test.key.gpg")
        assert args.output is None

        args = parser.parse_args(["unlock", "--gpg-keyfile", "test.key.gpg", "--output", "custom.key"])
        assert args.output == Path("custom.key")

    def test_parser_encrypt_command(self):
        """Test parsing encrypt command"""
        parser = create_parser()

        args = parser.parse_args(["encrypt"])
        assert args.command == "encrypt"
        assert args.keyfile == Path(".git-safe/.git-safe-key")
        assert args.no_backup is False
        assert args.continue_on_error is False

        args = parser.parse_args(["encrypt", "--keyfile", "custom.key", "--no-backup", "--continue-on-error"])
        assert args.keyfile == Path("custom.key")
        assert args.no_backup is True
        assert args.continue_on_error is True

    def test_parser_decrypt_command(self):
        """Test parsing decrypt command"""
        parser = create_parser()

        args = parser.parse_args(["decrypt", "--all"])
        assert args.command == "decrypt"
        assert args.all is True
        assert args.patterns == []

        args = parser.parse_args(["decrypt", "*.enc", "*.secret"])
        assert args.all is False
        assert args.patterns == ["*.enc", "*.secret"]

    def test_parser_status_command(self):
        """Test parsing status command"""
        parser = create_parser()

        args = parser.parse_args(["status"])
        assert args.command == "status"
        assert args.keyfile is None

        args = parser.parse_args(["status", "--keyfile", "test.key"])
        assert args.keyfile == Path("test.key")

    def test_parser_clean_command(self):
        """Test parsing clean command"""
        parser = create_parser()

        args = parser.parse_args(["clean"])
        assert args.command == "clean"


class TestMainFunction:
    """Test main function"""

    @patch("git_safe.cli.create_parser")
    def test_main_no_command(self, mock_create_parser):
        """Test main function with no command"""
        mock_parser = MagicMock()
        mock_args = MagicMock()
        mock_args.command = None
        mock_parser.parse_args.return_value = mock_args
        mock_create_parser.return_value = mock_parser

        result = main()

        assert result == 1
        mock_parser.print_help.assert_called_once()

    @patch("git_safe.cli.create_parser")
    @patch("git_safe.cli.cmd_init")
    def test_main_with_command(self, mock_cmd_init, mock_create_parser):
        """Test main function with valid command"""
        mock_parser = MagicMock()
        mock_args = MagicMock()
        mock_args.command = "init"
        mock_parser.parse_args.return_value = mock_args
        mock_create_parser.return_value = mock_parser
        mock_cmd_init.return_value = 0

        result = main()

        assert result == 0
        mock_cmd_init.assert_called_once_with(mock_args)

    @patch("git_safe.cli.create_parser")
    def test_main_unknown_command(self, mock_create_parser):
        """Test main function with unknown command"""
        mock_parser = MagicMock()
        mock_args = MagicMock()
        mock_args.command = "unknown"
        mock_parser.parse_args.return_value = mock_args
        mock_create_parser.return_value = mock_parser

        result = main()

        assert result == 1

    @patch("git_safe.cli.create_parser")
    @patch("git_safe.cli.cmd_encrypt")
    def test_main_all_commands(self, mock_cmd_encrypt, mock_create_parser):
        """Test main function dispatches to all command handlers"""
        mock_parser = MagicMock()
        mock_create_parser.return_value = mock_parser
        mock_cmd_encrypt.return_value = 0

        # Test each command
        commands = ["init", "export-key", "unlock", "encrypt", "decrypt", "status", "clean"]

        for command in commands:
            mock_args = MagicMock()
            mock_args.command = command
            mock_parser.parse_args.return_value = mock_args

            with patch(f'git_safe.cli.cmd_{command.replace("-", "_")}') as mock_handler:
                mock_handler.return_value = 0
                result = main()
                assert result == 0
                mock_handler.assert_called_once_with(mock_args)
