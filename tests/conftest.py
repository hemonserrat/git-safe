"""
Pytest configuration and shared fixtures for git-safe tests
"""

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)


@pytest.fixture
def sample_aes_key():
    """Sample AES key for testing"""
    return b"A" * 32


@pytest.fixture
def sample_hmac_key():
    """Sample HMAC key for testing"""
    return b"H" * 64


@pytest.fixture
def sample_keys(sample_aes_key, sample_hmac_key):
    """Sample key pair for testing"""
    return sample_aes_key, sample_hmac_key


@pytest.fixture
def sample_data():
    """Sample data for testing"""
    return b"This is sample test data for encryption and decryption testing."


@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Automatically clean up test files after each test"""
    yield

    # Clean up any test files that might have been created
    test_files = [".gitattributes", ".git-safe-key", "test.secret", "passwords.txt", "regular.txt"]

    for filename in test_files:
        path = Path(filename)
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass  # Ignore cleanup errors


@pytest.fixture
def mock_gitattributes_content():
    """Sample .gitattributes content for testing"""
    return """
# Git-safe patterns
*.secret filter=git-safe
passwords.txt filter=git-safe
config/*.env filter=git-safe

# Other attributes
*.txt text
*.jpg binary
    """.strip()
