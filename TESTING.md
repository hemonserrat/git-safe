# Testing Guide for git-safe

This document describes the comprehensive test suite for git-safe and how to run the tests.

## Test Structure

The test suite is organized into several categories:

### Unit Tests
- **`test_constants.py`** - Tests for constants and configuration values
- **`test_crypto.py`** - Tests for cryptographic operations (AES-CTR, HMAC)
- **`test_keyfile.py`** - Tests for keyfile generation, loading, and GPG operations
- **`test_patterns.py`** - Tests for .gitattributes pattern matching
- **`test_file_ops.py`** - Tests for file encryption/decryption operations
- **`test_cli.py`** - Tests for command-line interface

### Integration Tests
- **`test_integration.py`** - End-to-end workflow tests

### Test Configuration
- **`conftest.py`** - Shared fixtures and test configuration
- **`pytest.ini`** - Pytest configuration
- **`requirements-test.txt`** - Testing dependencies

## Test Coverage

The test suite provides comprehensive coverage of:

### Cryptographic Operations (test_crypto.py)
- ✅ AES-256-CTR encryption/decryption
- ✅ HMAC-SHA256 computation and verification
- ✅ Nonce generation
- ✅ Round-trip encryption/decryption
- ✅ Error handling for invalid keys/data
- ✅ Edge cases (empty data, large data)

### Keyfile Management (test_keyfile.py)
- ✅ Key generation (AES + HMAC)
- ✅ Keyfile creation and parsing
- ✅ Binary format validation
- ✅ GPG encryption/decryption of keyfiles
- ✅ Error handling for corrupted keyfiles
- ✅ File permissions and security

### Pattern Matching (test_patterns.py)
- ✅ .gitattributes parsing
- ✅ Git wildcard pattern matching
- ✅ File discovery and filtering
- ✅ Complex pattern scenarios
- ✅ Error handling for malformed files

### File Operations (test_file_ops.py)
- ✅ File encryption with magic headers
- ✅ File decryption and verification
- ✅ Backup file creation
- ✅ Encrypted file detection
- ✅ Integrity verification
- ✅ Batch operations
- ✅ Error recovery

### Command Line Interface (test_cli.py)
- ✅ All CLI commands (init, encrypt, decrypt, etc.)
- ✅ Argument parsing
- ✅ Error handling and exit codes
- ✅ Command dispatch
- ✅ Integration with core modules

### Integration Tests (test_integration.py)
- ✅ Complete workflow scenarios
- ✅ CLI integration testing
- ✅ Large file handling
- ✅ Error recovery scenarios
- ✅ Multi-file operations

## Running Tests

### Prerequisites

Install testing dependencies:
```bash
pip install -r requirements-test.txt
```

### Quick Test Commands

```bash
# Run all tests
python run_tests.py

# Run only fast unit tests
python run_tests.py --type fast

# Run with coverage report
python run_tests.py --type coverage

# Run specific module tests
python run_tests.py --module crypto
python run_tests.py --module keyfile
```

### Direct Pytest Commands

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_crypto.py

# Run specific test class
pytest tests/test_crypto.py::TestCrypto

# Run specific test method
pytest tests/test_crypto.py::TestCrypto::test_ctr_encrypt_decrypt_roundtrip

# Run tests with coverage
pytest --cov=git_safe --cov-report=term-missing

# Run only unit tests (exclude integration)
pytest -m "not integration"

# Run only integration tests
pytest -m integration

# Run only fast tests (exclude slow)
pytest -m "not slow"
```

### Test Categories

Tests are marked with pytest markers:

- `@pytest.mark.unit` - Unit tests (default)
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.slow` - Slow-running tests

## Test Coverage Goals

The test suite aims for:
- **>85% code coverage** overall
- **>90% coverage** for core cryptographic functions
- **>80% coverage** for CLI and file operations
- **100% coverage** for constants and utilities

Current coverage can be viewed by running:
```bash
python run_tests.py --type coverage
```

This generates an HTML coverage report in `htmlcov/index.html`.

## Writing New Tests

### Test Organization

Follow these conventions:
- One test file per module (`test_<module>.py`)
- Group related tests in classes (`TestClassName`)
- Use descriptive test method names (`test_what_it_does_when_condition`)

### Fixtures

Common fixtures are available in `conftest.py`:
- `temp_dir` - Temporary directory for file operations
- `sample_keys` - Sample AES/HMAC keys for testing
- `sample_data` - Sample data for encryption tests

### Example Test

```python
def test_encrypt_decrypt_roundtrip(self, sample_keys, sample_data):
    """Test that encryption and decryption are inverse operations"""
    aes_key, hmac_key = sample_keys

    # Encrypt
    nonce = generate_nonce(sample_data)
    encrypted = ctr_encrypt(aes_key, nonce, sample_data)

    # Decrypt
    decrypted = ctr_decrypt(aes_key, nonce, encrypted)

    # Verify
    assert decrypted == sample_data
    assert encrypted != sample_data  # Ensure it was actually encrypted
```

### Mocking Guidelines

Use `unittest.mock` for external dependencies:
- Mock file system operations when testing error conditions
- Mock GPG operations to avoid requiring GPG setup
- Mock random number generation for deterministic tests

### Test Data

- Use temporary directories for file operations
- Clean up test files automatically (handled by fixtures)
- Use deterministic test data when possible
- Test edge cases (empty files, large files, invalid data)

## Continuous Integration

The test suite is designed to run in CI environments:

```bash
# Install dependencies
pip install -r requirements-test.txt

# Run tests with coverage
pytest --cov=git_safe --cov-report=xml --cov-fail-under=85

# Run tests in parallel (if pytest-xdist is installed)
pytest -n auto
```

## Performance Testing

Some tests are marked as `@pytest.mark.slow` for performance testing:
- Large file encryption/decryption
- Many small files processing
- Memory usage validation

Run performance tests separately:
```bash
pytest -m slow
```

## Security Testing

The test suite includes security-focused tests:
- Cryptographic correctness
- Key generation randomness
- HMAC timing attack resistance
- File permission validation
- Error message information leakage

## Debugging Tests

For debugging failing tests:

```bash
# Run with detailed output
pytest -vvv --tb=long

# Run specific test with debugging
pytest tests/test_crypto.py::test_specific_function -vvv --pdb

# Show local variables in tracebacks
pytest --tb=long --showlocals
```

## Test Maintenance

Regular maintenance tasks:
1. Update test dependencies in `requirements-test.txt`
2. Review and update test coverage goals
3. Add tests for new features
4. Remove or update tests for deprecated functionality
5. Monitor test execution time and optimize slow tests

## Troubleshooting

### Common Issues

**Import Errors**
```bash
# Ensure git_safe is in Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

**Permission Errors**
```bash
# Some tests create files with specific permissions
# Ensure test cleanup runs properly
```

**GPG Tests Failing**
```bash
# GPG tests are mocked by default
# Real GPG tests require GPG installation and configuration
```

### Getting Help

If tests are failing:
1. Check the test output for specific error messages
2. Run individual test files to isolate issues
3. Use verbose mode (`-v`) for more details
4. Check that all dependencies are installed
5. Ensure you're running tests from the project root directory
