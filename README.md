# git-safe

[![CI](https://github.com/hemonserrat/git-safe/workflows/CI/badge.svg)](https://github.com/hemonserrat/git-safe/actions/workflows/ci.yml)
[![Security Scan](https://github.com/hemonserrat/git-safe/workflows/Security%20Scan/badge.svg)](https://github.com/hemonserrat/git-safe/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/hemonserrat/git-safe/branch/main/graph/badge.svg)](https://codecov.io/gh/hemonserrat/git-safe)
[![PyPI version](https://badge.fury.io/py/gitsafe-cli.svg)](https://badge.fury.io/py/gitsafe-cli)
[![Python versions](https://img.shields.io/pypi/pyversions/gitsafe-cli.svg)](https://pypi.org/project/gitsafe-cli/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

A Python CLI tool providing file encryption with .gitattributes-style pattern matching and both symmetric and GPG-encrypted keyfile modes.

Effortless file encryption for your git repos—pattern-matched, secure, and keyfile-flexible.

> **🔒 Secure by Design**: Built with modern cryptographic standards and comprehensive security scanning

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#gitattributes-configuration)
- [Examples](#examples)
- [Architecture](#architecture)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Quick Start

```bash
# Install from PyPI
pip install gitsafe-cli

# Or install from source
git clone https://github.com/hemonserrat/git-safe.git
cd git-safe
pip install -e .

# Initialize encryption for your repository (automatically sets up .gitattributes and Git filters)
git-safe init

# That's it! Files matching *.secret are now automatically encrypted/decrypted transparently
echo "my secret" > config.secret
git add config.secret    # Automatically encrypted when committed
git commit -m "Add secret config"
# File remains readable in your working directory, encrypted in Git history
```

## Features

- **Transparent Operation**: Files are automatically encrypted/decrypted through Git filters - no manual intervention needed
- **Pattern Matching**: Uses `.gitattributes`-style patterns for selecting files to encrypt
- **Dual Encryption Modes**:
  - Symmetric encryption (AES-256 CTR + HMAC-SHA256)
  - GPG-encrypted keyfile export/import (like git-crypt's `export-key`)
- **Modular Architecture**: Clean separation of concerns with dedicated modules
- **Enhanced CLI**: Multiple commands for different operations
- **File Integrity**: HMAC verification for encrypted files
- **Backup Support**: Optional backup creation during manual encryption

## Installation

### From PyPI (Recommended)

```bash
pip install gitsafe-cli
```

### From Source

```bash
git clone https://github.com/hemonserrat/git-safe.git
cd git-safe
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/hemonserrat/git-safe.git
cd git-safe
pip install -e ".[dev,security]"
```

### System Requirements

- Python 3.8 or higher
- GPG (for keyfile sharing functionality)
  - **Ubuntu/Debian**: `sudo apt-get install gnupg`
  - **macOS**: `brew install gnupg`
  - **Windows**: Install [Gpg4win](https://www.gpg4win.org/)

## Usage

### Initialize a new keyfile

```bash
git-safe init [--keyfile PATH] [--force] [--export-gpg RECIPIENT]
```

The `init` command performs the following setup automatically:

1. **Creates keyfile**: By default at `.git-safe/.git-safe-key` (creates `.git-safe` directory if needed)
2. **Sets up .gitattributes**: Adds `*.secret filter=git-safe diff=git-safe` if not already present
3. **Configures Git filters**: Sets up local Git configuration for automatic encryption/decryption:
   - `filter.git-safe.clean` - Encrypts files on commit
   - `filter.git-safe.smudge` - Decrypts files on checkout
   - `filter.git-safe.required` - Makes the filter required
   - `diff.git-safe.textconv` - Enables readable diffs

**Note**: Git filter setup is skipped if not in a Git repository, with a warning message.

> **🔐 CRITICAL SECURITY WARNING**
>
> **The `.git-safe` directory contains your encryption keys and MUST be kept secure:**
> - **Add `.git-safe/` to your `.gitignore`** - Never commit keyfiles to your repository
> - **Backup your keyfiles securely** - If lost, encrypted files cannot be recovered
> - **Use GPG export for team sharing** - Share keys securely with `git-safe export-key`
>
> **Without the keyfile, your encrypted data is permanently inaccessible!**

### Transparent Operation

After initialization, git-safe works transparently through Git filters:

```bash
# Files matching *.secret are automatically encrypted/decrypted
echo "database_password=secret123" > config.secret
git add config.secret     # Automatically encrypted when staged
git commit -m "Add config" # Stored encrypted in Git history
cat config.secret         # Still readable in working directory

# No manual encrypt/decrypt needed - it's all automatic!
```

### Export keyfile with GPG encryption

```bash
git-safe export-key RECIPIENT [--keyfile PATH] [--output PATH]
```

### Import GPG-encrypted keyfile

```bash
git-safe unlock [--gpg-keyfile PATH] [--output PATH]
```
- By default, the unlock command will look for `.git-safe/.git-safe-key.gpg` if `--gpg-keyfile` is not specified.

### Manual Operations (Optional)

The following commands are **optional** - Git filters handle encryption/decryption automatically:

#### Encrypt files manually

```bash
git-safe encrypt [--keyfile PATH] [--no-backup] [--continue-on-error]
```

#### Decrypt files manually

```bash
git-safe decrypt [--keyfile PATH] [--all] [--continue-on-error] [PATTERNS...]
```
- Decrypted files will always overwrite the original encrypted files in-place, preserving their names and extensions.

#### Show status of encrypted files

```bash
git-safe status [--keyfile PATH]
```

#### Clean backup files

```bash
git-safe clean
```

## .gitattributes Configuration

The `git-safe init` command automatically adds the default pattern `*.secret filter=git-safe diff=git-safe` to your `.gitattributes` file.

You can add additional patterns to specify which files should be encrypted:

```
secrets.txt filter=git-safe
*.key filter=git-safe
config/*.secret filter=git-safe
```

**Note**: The `diff=git-safe` attribute enables readable diffs for encrypted files when the Git filter is properly configured.

## Architecture

The tool is organized into several modules:

- **`constants.py`**: Magic headers and cryptographic constants
- **`crypto.py`**: Low-level cryptographic operations (AES-CTR, HMAC)
- **`keyfile.py`**: Keyfile generation, loading, and GPG export/import
- **`patterns.py`**: .gitattributes parsing and pattern matching
- **`file_ops.py`**: File encryption, decryption, and management
- **`cli.py`**: Command-line interface and argument parsing

## File Format

Encrypted files use the format:
```
MAGIC (9 bytes) + NONCE (12 bytes) + ENCRYPTED_DATA
```

Keyfiles use the format:
```
KEYFILE_MAGIC (12 bytes) + KEY_BLOBS
```

Where each key blob is:
```
ID (4 bytes) + LENGTH (4 bytes) + DATA (LENGTH bytes)
```

## Security

### Encryption Details
- Uses AES-256 in CTR mode for encryption
- HMAC-SHA256 for integrity verification
- Secure random nonce generation
- GPG integration for keyfile sharing
- Restrictive file permissions (0600) for keyfiles

### Keyfile Management (CRITICAL)

> **⚠️ WARNING: Keyfile loss means permanent data loss!**

**Essential Security Practices:**

1. **Never commit keyfiles to Git:**
   ```bash
   echo ".git-safe/" >> .gitignore
   git add .gitignore
   git commit -m "Ignore git-safe keyfiles"
   ```

2. **Backup keyfiles securely:**
   - Store copies in secure, encrypted locations
   - Use multiple backup locations (local + cloud)
   - Test backup restoration regularly

3. **Team collaboration:**
   ```bash
   # Export for team members
   git-safe export-key teammate@company.com

   # Team member imports
   git-safe unlock --gpg-keyfile shared-key.gpg
   ```

4. **Key rotation:**
   - Regularly rotate keyfiles for long-term projects
   - Use `--force` flag to overwrite existing keyfiles
   - Re-encrypt all files after key rotation

**Recovery Scenarios:**
- ✅ **Keyfile backed up**: Restore from backup, continue working
- ❌ **Keyfile lost, no backup**: Encrypted files are **permanently unrecoverable**
- ✅ **Team member has keyfile**: Export/import via GPG

## Compatibility

This tool is designed to be compatible with git-crypt's file format and workflow, while providing additional features and a more Pythonic implementation.

## Legacy Interface

The original `git-safe.py` script is maintained for backward compatibility and now uses the new modular architecture internally.

## Examples

1. **Complete setup with transparent encryption:**
```bash
# Initialize keyfile (automatically sets up .gitattributes and Git filters)
git-safe init

# Add .git-safe to .gitignore (IMPORTANT!)
echo ".git-safe/" >> .gitignore

# Create secret files - they work transparently
echo "database_password=secret123" > config.secret
echo "api_key=abc123xyz" > api.secret

# Normal Git workflow - encryption happens automatically
git add .
git commit -m "Add configuration files"

# Files are encrypted in Git, readable in working directory
git show HEAD:config.secret  # Shows encrypted binary data
cat config.secret            # Shows readable plaintext
```

2. **Share keyfile with team member:**
```bash
# Export keyfile for GPG recipient
git-safe export-key alice@example.com

# Team member imports the keyfile
git-safe unlock
# By default, this will look for .git-safe/.git-safe-key.gpg
```

3. **Manual operations (if needed):**
```bash
# Manually encrypt files (usually not needed)
git-safe encrypt

# Manually decrypt files (usually not needed)
git-safe decrypt --all

# Check status of encrypted files
git-safe status
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/hemonserrat/git-safe.git
cd git-safe
pip install -e ".[dev,security]"
pre-commit install  # Optional: for automated code formatting
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=git_safe --cov-report=html

# Run security tests
bandit -r git_safe/
safety check
```

## Troubleshooting

### Common Issues

**GPG not found**: Ensure GPG is installed and available in your PATH.
```bash
gpg --version  # Should show GPG version
```

**Permission denied**: Keyfiles are created with restrictive permissions (0600). Ensure you have proper file system permissions.

**Import errors**: If you encounter import errors, try reinstalling:
```bash
pip uninstall gitsafe-cli
pip install gitsafe-cli
```

### Keyfile Issues

**"No keyfile found" error**:
```bash
# Check if keyfile exists
ls -la .git-safe/.git-safe-key

# If missing, restore from backup or re-initialize
git-safe init --force
```

**Git filter errors**:
```bash
# Check Git filter configuration
git config --local --list | grep git-safe

# Re-run init to fix configuration
git-safe init --force
```

**Files not encrypting automatically**:
```bash
# Check .gitattributes
cat .gitattributes

# Verify file matches pattern
echo "test.secret" | git check-attr --all --stdin
```

**Encrypted files show as binary in diffs**:
```bash
# Check diff filter configuration
git config --local diff.git-safe.textconv

# Should show: git-safe diff
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by [git-crypt](https://www.agwa.name/projects/git-crypt/) by Andrew Ayer
- Built with modern Python cryptographic libraries
- Thanks to all contributors who have helped improve this project

## Dependencies

- [cryptography](https://cryptography.io/) - Modern cryptographic operations
- [python-gnupg](https://gnupg.readthedocs.io/) - GPG integration
- [pathspec](https://python-path-specification.readthedocs.io/) - .gitattributes pattern matching
