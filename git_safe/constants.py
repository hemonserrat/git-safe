"""
Constants used throughout git-safe
"""

# Magic headers
MAGIC = b"\x00GITSAFE\x00\x00"
KEYFILE_MAGIC = b"\x00GITSAFEKEY\x00\x00"

# Key lengths
AES_KEY_LEN = 32
HMAC_KEY_LEN = 64

# Other constants
HMAC_CHECK_LEN = 12
CTR_NONCE_LEN = 12
BLOCK_SIZE = 16

# Keyfile blob IDs
KEYFILE_AES_KEY_ID = 3
KEYFILE_HMAC_KEY_ID = 5
# Exit codes for CLI and scripts
EXIT_SUCCESS = 0
EXIT_ERROR = 1
