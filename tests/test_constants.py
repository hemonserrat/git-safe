"""
Tests for git_safe.constants module
"""

from git_safe.constants import (
    AES_KEY_LEN,
    BLOCK_SIZE,
    CTR_NONCE_LEN,
    HMAC_CHECK_LEN,
    HMAC_KEY_LEN,
    KEYFILE_AES_KEY_ID,
    KEYFILE_HMAC_KEY_ID,
    KEYFILE_MAGIC,
    MAGIC,
)


class TestConstants:
    """Test constants are properly defined"""

    def test_magic_constants(self):
        """Test magic header constants"""
        assert MAGIC == b"\x00GITSAFE\x00\x00"
        assert KEYFILE_MAGIC == b"\x00GITSAFEKEY\x00\x00"
        assert len(MAGIC) == 10
        assert len(KEYFILE_MAGIC) == 13

    def test_key_lengths(self):
        """Test key length constants"""
        assert AES_KEY_LEN == 32  # 256 bits
        assert HMAC_KEY_LEN == 64  # 512 bits

    def test_crypto_constants(self):
        """Test cryptographic constants"""
        assert HMAC_CHECK_LEN == 12
        assert CTR_NONCE_LEN == 12
        assert BLOCK_SIZE == 16  # AES block size

    def test_keyfile_blob_ids(self):
        """Test keyfile blob ID constants"""
        assert KEYFILE_AES_KEY_ID == 3
        assert KEYFILE_HMAC_KEY_ID == 5
        # Ensure they're different
        assert KEYFILE_AES_KEY_ID != KEYFILE_HMAC_KEY_ID

    def test_constants_are_immutable(self):
        """Test that constants are the expected types"""
        assert isinstance(MAGIC, bytes)
        assert isinstance(KEYFILE_MAGIC, bytes)
        assert isinstance(AES_KEY_LEN, int)
        assert isinstance(HMAC_KEY_LEN, int)
        assert isinstance(HMAC_CHECK_LEN, int)
        assert isinstance(CTR_NONCE_LEN, int)
        assert isinstance(BLOCK_SIZE, int)
        assert isinstance(KEYFILE_AES_KEY_ID, int)
        assert isinstance(KEYFILE_HMAC_KEY_ID, int)
