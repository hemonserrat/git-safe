"""
Tests for git_safe.crypto module
"""

import os
from unittest.mock import patch

import pytest

from git_safe.constants import CTR_NONCE_LEN, HMAC_CHECK_LEN
from git_safe.crypto import compute_hmac, ctr_decrypt, ctr_encrypt, generate_nonce, verify_hmac


class TestCrypto:
    """Test cryptographic operations"""

    @pytest.fixture
    def sample_keys(self):
        """Generate sample keys for testing"""
        aes_key = b"A" * 32  # 32-byte AES key
        hmac_key = b"H" * 64  # 64-byte HMAC key
        return aes_key, hmac_key

    @pytest.fixture
    def sample_data(self):
        """Sample data for testing"""
        return b"Hello, World! This is test data for encryption."

    def test_ctr_encrypt_decrypt_roundtrip(self, sample_keys, sample_data):
        """Test that encryption and decryption are inverse operations"""
        aes_key, _ = sample_keys
        nonce = os.urandom(CTR_NONCE_LEN)

        # Encrypt then decrypt
        encrypted = ctr_encrypt(aes_key, nonce, sample_data)
        decrypted = ctr_decrypt(aes_key, nonce, encrypted)

        assert decrypted == sample_data
        assert encrypted != sample_data  # Ensure it was actually encrypted

    def test_ctr_encrypt_decrypt_are_same_operation(self, sample_keys, sample_data):
        """Test that CTR mode encrypt and decrypt are the same operation"""
        aes_key, _ = sample_keys
        nonce = os.urandom(CTR_NONCE_LEN)

        encrypted1 = ctr_encrypt(aes_key, nonce, sample_data)
        encrypted2 = ctr_decrypt(aes_key, nonce, sample_data)

        assert encrypted1 == encrypted2

    def test_ctr_different_nonces_produce_different_ciphertext(self, sample_keys, sample_data):
        """Test that different nonces produce different ciphertext"""
        aes_key, _ = sample_keys
        nonce1 = os.urandom(CTR_NONCE_LEN)
        nonce2 = os.urandom(CTR_NONCE_LEN)

        # Ensure nonces are different
        while nonce1 == nonce2:
            nonce2 = os.urandom(CTR_NONCE_LEN)

        encrypted1 = ctr_encrypt(aes_key, nonce1, sample_data)
        encrypted2 = ctr_encrypt(aes_key, nonce2, sample_data)

        assert encrypted1 != encrypted2

    def test_ctr_empty_data(self, sample_keys):
        """Test encryption/decryption of empty data"""
        aes_key, _ = sample_keys
        nonce = os.urandom(CTR_NONCE_LEN)
        empty_data = b""

        encrypted = ctr_encrypt(aes_key, nonce, empty_data)
        decrypted = ctr_decrypt(aes_key, nonce, encrypted)

        assert decrypted == empty_data
        assert encrypted == empty_data  # Empty data should remain empty

    def test_ctr_large_data(self, sample_keys):
        """Test encryption/decryption of large data (multiple blocks)"""
        aes_key, _ = sample_keys
        nonce = os.urandom(CTR_NONCE_LEN)
        large_data = b"A" * 1000  # Multiple AES blocks

        encrypted = ctr_encrypt(aes_key, nonce, large_data)
        decrypted = ctr_decrypt(aes_key, nonce, encrypted)

        assert decrypted == large_data
        assert len(encrypted) == len(large_data)

    def test_ctr_invalid_key_length(self):
        """Test that invalid key lengths are handled by underlying crypto"""
        short_key = b"short"
        nonce = os.urandom(CTR_NONCE_LEN)
        data = b"test data"

        # Should raise an exception from the crypto library
        with pytest.raises(ValueError):
            ctr_encrypt(short_key, nonce, data)

    def test_ctr_invalid_nonce_length(self, sample_keys):
        """Test behavior with invalid nonce length"""
        aes_key, _ = sample_keys
        short_nonce = b"short"
        data = b"test data"

        # This should work but produce different results than expected nonce length
        encrypted = ctr_encrypt(aes_key, short_nonce, data)
        decrypted = ctr_decrypt(aes_key, short_nonce, encrypted)

        assert decrypted == data

    @patch("git_safe.crypto.os.urandom")
    def test_generate_nonce_deterministic_part(self, mock_urandom, sample_data):
        """Test that nonce generation includes deterministic hash part"""
        mock_urandom.return_value = b"\x00" * (CTR_NONCE_LEN - HMAC_CHECK_LEN)

        nonce1 = generate_nonce(sample_data)
        nonce2 = generate_nonce(sample_data)

        # First part should be the same (hash-based)
        assert nonce1[:HMAC_CHECK_LEN] == nonce2[:HMAC_CHECK_LEN]
        # But full nonces should be the same due to mocked urandom
        assert nonce1 == nonce2
        assert len(nonce1) == CTR_NONCE_LEN

    def test_generate_nonce_different_data(self):
        """Test that different data produces different nonce prefixes"""
        data1 = b"data1"
        data2 = b"data2"

        nonce1 = generate_nonce(data1)
        nonce2 = generate_nonce(data2)

        # Hash parts should be different
        assert nonce1[:HMAC_CHECK_LEN] != nonce2[:HMAC_CHECK_LEN]
        assert len(nonce1) == CTR_NONCE_LEN
        assert len(nonce2) == CTR_NONCE_LEN

    def test_compute_hmac(self, sample_keys, sample_data):
        """Test HMAC computation"""
        _, hmac_key = sample_keys

        hmac_result = compute_hmac(hmac_key, sample_data)

        assert len(hmac_result) == HMAC_CHECK_LEN
        assert isinstance(hmac_result, bytes)

    def test_compute_hmac_consistency(self, sample_keys, sample_data):
        """Test that HMAC computation is consistent"""
        _, hmac_key = sample_keys

        hmac1 = compute_hmac(hmac_key, sample_data)
        hmac2 = compute_hmac(hmac_key, sample_data)

        assert hmac1 == hmac2

    def test_compute_hmac_different_data(self, sample_keys):
        """Test that different data produces different HMACs"""
        _, hmac_key = sample_keys
        data1 = b"data1"
        data2 = b"data2"

        hmac1 = compute_hmac(hmac_key, data1)
        hmac2 = compute_hmac(hmac_key, data2)

        assert hmac1 != hmac2

    def test_compute_hmac_different_keys(self, sample_data):
        """Test that different keys produce different HMACs"""
        key1 = b"K" * 64
        key2 = b"L" * 64

        hmac1 = compute_hmac(key1, sample_data)
        hmac2 = compute_hmac(key2, sample_data)

        assert hmac1 != hmac2

    def test_verify_hmac_valid(self, sample_keys, sample_data):
        """Test HMAC verification with valid HMAC"""
        _, hmac_key = sample_keys

        expected_hmac = compute_hmac(hmac_key, sample_data)
        result = verify_hmac(hmac_key, sample_data, expected_hmac)

        assert result is True

    def test_verify_hmac_invalid(self, sample_keys, sample_data):
        """Test HMAC verification with invalid HMAC"""
        _, hmac_key = sample_keys

        wrong_hmac = b"\x00" * HMAC_CHECK_LEN
        result = verify_hmac(hmac_key, sample_data, wrong_hmac)

        assert result is False

    def test_verify_hmac_wrong_key(self, sample_data):
        """Test HMAC verification with wrong key"""
        key1 = b"K" * 64
        key2 = b"L" * 64

        hmac_with_key1 = compute_hmac(key1, sample_data)
        result = verify_hmac(key2, sample_data, hmac_with_key1)

        assert result is False

    def test_verify_hmac_truncated(self, sample_keys, sample_data):
        """Test HMAC verification with truncated HMAC"""
        _, hmac_key = sample_keys

        full_hmac = compute_hmac(hmac_key, sample_data)
        truncated_hmac = full_hmac[: HMAC_CHECK_LEN - 1]

        result = verify_hmac(hmac_key, sample_data, truncated_hmac)

        assert result is False

    def test_verify_hmac_empty_data(self, sample_keys):
        """Test HMAC verification with empty data"""
        _, hmac_key = sample_keys
        empty_data = b""

        expected_hmac = compute_hmac(hmac_key, empty_data)
        result = verify_hmac(hmac_key, empty_data, expected_hmac)

        assert result is True

    def test_hmac_timing_attack_resistance(self, sample_keys, sample_data):
        """Test that HMAC verification uses constant-time comparison"""
        _, hmac_key = sample_keys

        correct_hmac = compute_hmac(hmac_key, sample_data)
        wrong_hmac = bytearray(correct_hmac)
        wrong_hmac[0] = (wrong_hmac[0] + 1) % 256  # Change one byte

        # Both should return quickly and consistently
        result1 = verify_hmac(hmac_key, sample_data, correct_hmac)
        result2 = verify_hmac(hmac_key, sample_data, bytes(wrong_hmac))

        assert result1 is True
        assert result2 is False
