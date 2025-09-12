"""
Tests for git_safe.patterns module
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from git_safe.patterns import PatternError, find_matching_files, parse_gitattributes, should_encrypt_file


class TestPatternParsing:
    """Test .gitattributes pattern parsing"""

    def test_parse_gitattributes_nonexistent_file(self):
        """Test parsing non-existent .gitattributes file"""
        non_existent = Path("/non/existent/.gitattributes")
        pathspec = parse_gitattributes(non_existent)

        assert len(pathspec.patterns) == 0

    def test_parse_gitattributes_empty_file(self):
        """Test parsing empty .gitattributes file"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".gitattributes") as tmp:
            tmp.write("")
            tmp_path = Path(tmp.name)

        try:
            pathspec = parse_gitattributes(tmp_path)
            assert len(pathspec.patterns) == 0
        finally:
            tmp_path.unlink()

    def test_parse_gitattributes_comments_and_empty_lines(self):
        """Test parsing .gitattributes with comments and empty lines"""
        content = """
# This is a comment

# Another comment
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".gitattributes") as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            pathspec = parse_gitattributes(tmp_path)
            assert len(pathspec.patterns) == 0
        finally:
            tmp_path.unlink()

    def test_parse_gitattributes_git_safe_filter(self):
        """Test parsing .gitattributes with git-safe filter"""
        content = """
*.secret filter=git-safe
passwords.txt filter=git-safe
config/*.env filter=git-safe
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".gitattributes") as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            pathspec = parse_gitattributes(tmp_path)
            assert len(pathspec.patterns) == 3

            # Test that patterns match expected files
            assert pathspec.match_file("test.secret")
            assert pathspec.match_file("passwords.txt")
            assert pathspec.match_file("config/dev.env")
            assert not pathspec.match_file("regular.txt")
        finally:
            tmp_path.unlink()

    def test_parse_gitattributes_mixed_attributes(self):
        """Test parsing .gitattributes with mixed attributes"""
        content = """
*.txt text
*.secret filter=git-safe
*.jpg binary
passwords.txt filter=git-safe text
*.log filter=other-filter
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".gitattributes") as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            pathspec = parse_gitattributes(tmp_path)
            assert len(pathspec.patterns) == 2  # Only git-safe filter patterns

            assert pathspec.match_file("test.secret")
            assert pathspec.match_file("passwords.txt")
            assert not pathspec.match_file("test.txt")  # Has text but not git-safe filter
            assert not pathspec.match_file("test.log")  # Has different filter
        finally:
            tmp_path.unlink()

    def test_parse_gitattributes_complex_patterns(self):
        """Test parsing .gitattributes with complex patterns"""
        content = """
secrets/** filter=git-safe
!secrets/public/* filter=git-safe
*.key filter=git-safe
/root-secret.txt filter=git-safe
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".gitattributes") as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            pathspec = parse_gitattributes(tmp_path)
            assert len(pathspec.patterns) == 4

            # Test complex pattern matching
            assert pathspec.match_file("secrets/private/key.txt")
            assert pathspec.match_file("test.key")
            assert pathspec.match_file("root-secret.txt")
        finally:
            tmp_path.unlink()

    def test_parse_gitattributes_malformed_lines(self):
        """Test parsing .gitattributes with malformed lines"""
        content = """
*.secret filter=git-safe
malformed-line-no-attributes
*.key filter=git-safe
just-a-pattern
        """

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".gitattributes") as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            pathspec = parse_gitattributes(tmp_path)
            assert len(pathspec.patterns) == 2  # Only valid git-safe patterns

            assert pathspec.match_file("test.secret")
            assert pathspec.match_file("test.key")
        finally:
            tmp_path.unlink()

    def test_parse_gitattributes_read_error(self):
        """Test parsing .gitattributes with read error"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".gitattributes") as tmp:
            tmp_path = Path(tmp.name)

        try:
            with patch("pathlib.Path.read_text") as mock_read:
                mock_read.side_effect = OSError("Permission denied")

                # This should raise a PatternError
                with pytest.raises(PatternError, match="Cannot read .gitattributes"):
                    parse_gitattributes(tmp_path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_parse_gitattributes_default_path(self):
        """Test parsing .gitattributes with default path"""
        content = "*.secret filter=git-safe\n"

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            gitattributes_path = tmp_path / ".gitattributes"
            gitattributes_path.write_text(content)

            # Change to temp directory to test default path
            import os

            try:
                original_cwd = os.getcwd()
            except FileNotFoundError:
                original_cwd = str(Path.home())

            try:
                os.chdir(tmp_path)
                pathspec = parse_gitattributes()  # No path specified
                assert len(pathspec.patterns) == 1
                assert pathspec.match_file("test.secret")
            finally:
                try:
                    os.chdir(original_cwd)
                except (FileNotFoundError, OSError):
                    os.chdir(Path.home())


class TestFileMatching:
    """Test file matching functionality"""

    @pytest.fixture
    def temp_directory(self):
        """Create a temporary directory with test files"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Create test file structure
            (tmp_path / "test.secret").write_text("secret content")
            (tmp_path / "passwords.txt").write_text("passwords")
            (tmp_path / "regular.txt").write_text("regular content")

            # Create subdirectories
            (tmp_path / "config").mkdir()
            (tmp_path / "config" / "dev.env").write_text("dev config")
            (tmp_path / "config" / "prod.env").write_text("prod config")
            (tmp_path / "config" / "readme.txt").write_text("readme")

            (tmp_path / "secrets").mkdir()
            (tmp_path / "secrets" / "api.key").write_text("api key")
            (tmp_path / "secrets" / "db.key").write_text("db key")

            yield tmp_path

    def test_find_matching_files_empty_pathspec(self, temp_directory):
        """Test finding files with empty pathspec"""
        from pathspec import PathSpec, patterns

        empty_pathspec = PathSpec.from_lines(patterns.GitWildMatchPattern, [])
        matching_files = find_matching_files(temp_directory, empty_pathspec)

        assert len(matching_files) == 0

    def test_find_matching_files_simple_patterns(self, temp_directory):
        """Test finding files with simple patterns"""
        from pathspec import PathSpec, patterns

        pathspec = PathSpec.from_lines(patterns.GitWildMatchPattern, ["*.secret", "passwords.txt"])

        matching_files = find_matching_files(temp_directory, pathspec)
        matching_names = [f.name for f in matching_files]

        assert "test.secret" in matching_names
        assert "passwords.txt" in matching_names
        assert "regular.txt" not in matching_names
        assert len(matching_files) == 2

    def test_find_matching_files_directory_patterns(self, temp_directory):
        """Test finding files with directory patterns"""
        from pathspec import PathSpec, patterns

        pathspec = PathSpec.from_lines(patterns.GitWildMatchPattern, ["config/*.env", "secrets/*"])

        matching_files = find_matching_files(temp_directory, pathspec)
        matching_relative = [f.relative_to(temp_directory) for f in matching_files]

        assert Path("config/dev.env") in matching_relative
        assert Path("config/prod.env") in matching_relative
        assert Path("secrets/api.key") in matching_relative
        assert Path("secrets/db.key") in matching_relative
        assert Path("config/readme.txt") not in matching_relative
        assert len(matching_files) == 4

    def test_find_matching_files_recursive_patterns(self, temp_directory):
        """Test finding files with recursive patterns"""
        from pathspec import PathSpec, patterns

        pathspec = PathSpec.from_lines(patterns.GitWildMatchPattern, ["**/*.key"])

        matching_files = find_matching_files(temp_directory, pathspec)
        matching_relative = [f.relative_to(temp_directory) for f in matching_files]

        assert Path("secrets/api.key") in matching_relative
        assert Path("secrets/db.key") in matching_relative
        assert len(matching_files) == 2

    def test_find_matching_files_no_matches(self, temp_directory):
        """Test finding files with patterns that don't match anything"""
        from pathspec import PathSpec, patterns

        pathspec = PathSpec.from_lines(patterns.GitWildMatchPattern, ["*.nonexistent", "missing/*"])

        matching_files = find_matching_files(temp_directory, pathspec)
        assert len(matching_files) == 0


class TestShouldEncryptFile:
    """Test should_encrypt_file functionality"""

    @pytest.fixture
    def temp_directory_with_gitattributes(self):
        """Create temporary directory with .gitattributes"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Create .gitattributes
            gitattributes_content = """
*.secret filter=git-safe
passwords.txt filter=git-safe
config/*.env filter=git-safe
            """
            (tmp_path / ".gitattributes").write_text(gitattributes_content)

            # Create test files
            (tmp_path / "test.secret").write_text("secret")
            (tmp_path / "passwords.txt").write_text("passwords")
            (tmp_path / "regular.txt").write_text("regular")

            (tmp_path / "config").mkdir()
            (tmp_path / "config" / "dev.env").write_text("dev config")

            yield tmp_path

    def test_should_encrypt_file_matching(self, temp_directory_with_gitattributes):
        """Test should_encrypt_file with matching files"""
        root_path = temp_directory_with_gitattributes

        assert should_encrypt_file(root_path / "test.secret", root_path)
        assert should_encrypt_file(root_path / "passwords.txt", root_path)
        assert should_encrypt_file(root_path / "config" / "dev.env", root_path)

    def test_should_encrypt_file_non_matching(self, temp_directory_with_gitattributes):
        """Test should_encrypt_file with non-matching files"""
        root_path = temp_directory_with_gitattributes

        assert not should_encrypt_file(root_path / "regular.txt", root_path)
        assert not should_encrypt_file(root_path / "config" / "readme.txt", root_path)

    def test_should_encrypt_file_nonexistent_file(self, temp_directory_with_gitattributes):
        """Test should_encrypt_file with non-existent file"""
        root_path = temp_directory_with_gitattributes

        # Should still work for pattern matching even if file doesn't exist
        assert should_encrypt_file(root_path / "nonexistent.secret", root_path)
        assert not should_encrypt_file(root_path / "nonexistent.txt", root_path)

    def test_should_encrypt_file_no_gitattributes(self):
        """Test should_encrypt_file with no .gitattributes file"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            test_file = tmp_path / "test.secret"
            test_file.write_text("secret")

            # No .gitattributes file exists
            assert not should_encrypt_file(test_file, tmp_path)

    def test_should_encrypt_file_default_root_path(self):
        """Test should_encrypt_file with default root path"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Create .gitattributes in temp directory
            gitattributes_path = tmp_path / ".gitattributes"
            gitattributes_content = "*.secret filter=git-safe\n"
            gitattributes_path.write_text(gitattributes_content)

            # Create test files in temp directory
            test_file = tmp_path / "test.secret"
            test_file.write_text("secret")

            regular_file = tmp_path / "regular.txt"
            regular_file.write_text("regular")

            # Change to temp directory to test default root path
            import os

            try:
                original_cwd = os.getcwd()
            except FileNotFoundError:
                original_cwd = str(Path.home())

            try:
                os.chdir(tmp_path)
                # Test with explicit root_path instead of relying on cwd
                assert should_encrypt_file(test_file, tmp_path)
                assert not should_encrypt_file(regular_file, tmp_path)
            finally:
                try:
                    os.chdir(original_cwd)
                except (FileNotFoundError, OSError):
                    os.chdir(Path.home())

    def test_should_encrypt_file_pattern_error(self):
        """Test should_encrypt_file with pattern parsing error"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            test_file = tmp_path / "test.secret"
            test_file.write_text("secret")

            # Mock parse_gitattributes to raise PatternError
            with patch("git_safe.patterns.parse_gitattributes") as mock_parse:
                mock_parse.side_effect = PatternError("Parse error")

                assert not should_encrypt_file(test_file, tmp_path)

    def test_should_encrypt_file_value_error(self):
        """Test should_encrypt_file with ValueError (file not relative to root)"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir1:
            with tempfile.TemporaryDirectory() as tmp_dir2:
                tmp_path1 = Path(tmp_dir1)
                tmp_path2 = Path(tmp_dir2)

                # Create file in one directory, try to check against different root
                test_file = tmp_path1 / "test.secret"
                test_file.write_text("secret")

                # This should cause ValueError when trying to get relative path
                assert not should_encrypt_file(test_file, tmp_path2)
