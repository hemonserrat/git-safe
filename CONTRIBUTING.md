# Contributing to git-safe

Thank you for your interest in contributing to git-safe! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Style](#code-style)
- [Security Considerations](#security-considerations)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow:

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming environment for all contributors
- Report any unacceptable behavior to the project maintainers

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- GPG (for testing GPG functionality)

### Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/hemonserrat/git-safe.git
   cd git-safe
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install development dependencies:**
   ```bash
   pip install -e ".[dev,security]"
   ```

4. **Install pre-commit hooks (optional but recommended):**
   ```bash
   pre-commit install
   ```

5. **Verify your setup:**
   ```bash
   pytest
   git-safe --help
   ```

## Making Changes

### Branch Naming

Use descriptive branch names:
- `feature/add-new-encryption-mode`
- `fix/keyfile-permission-issue`
- `docs/update-installation-guide`
- `refactor/improve-error-handling`

### Commit Messages

Follow conventional commit format:
```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(crypto): add support for AES-GCM encryption
fix(keyfile): handle permission errors gracefully
docs(readme): update installation instructions
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=git_safe --cov-report=html

# Run specific test file
pytest tests/test_crypto.py

# Run tests with verbose output
pytest -v
```

### Test Categories

1. **Unit Tests**: Test individual functions and classes
2. **Integration Tests**: Test component interactions
3. **Security Tests**: Verify cryptographic operations
4. **CLI Tests**: Test command-line interface

### Writing Tests

- Place tests in the `tests/` directory
- Name test files as `test_*.py`
- Use descriptive test function names
- Include both positive and negative test cases
- Test edge cases and error conditions

Example test structure:
```python
def test_encrypt_file_success():
    """Test successful file encryption."""
    # Arrange
    # Act
    # Assert

def test_encrypt_file_invalid_key():
    """Test encryption with invalid key raises appropriate error."""
    # Test error conditions
```

## Code Style

### Formatting and Linting

We use several tools to maintain code quality:

```bash
# Format code
black .

# Sort imports
isort .

# Lint code
ruff check .

# Type checking (optional)
mypy git_safe/
```

### Style Guidelines

- Follow PEP 8 with 120 character line limit
- Use double quotes for strings
- Add type hints for new code (when practical)
- Write docstrings for public functions and classes
- Keep functions focused and reasonably sized (< 50 lines)

### Documentation

- Update docstrings when changing function signatures
- Add comments for complex cryptographic operations
- Update README.md for user-facing changes
- Include examples in docstrings when helpful

## Security Considerations

Since git-safe is a cryptographic tool, security is paramount:

### Security Review Process

1. **Cryptographic Changes**: All changes to cryptographic code require extra scrutiny
2. **Dependency Updates**: Security-related dependencies need careful review
3. **Input Validation**: Always validate user inputs, especially file paths
4. **Error Handling**: Avoid leaking sensitive information in error messages

### Security Testing

```bash
# Run security linting
bandit -r git_safe/

# Check for known vulnerabilities
safety check
```

### Reporting Security Issues

Please report security vulnerabilities privately to the maintainers rather than opening public issues.

## Submitting Changes

### Pull Request Process

1. **Create a feature branch** from `main`
2. **Make your changes** following the guidelines above
3. **Add or update tests** for your changes
4. **Update documentation** if needed
5. **Run the full test suite** and ensure it passes
6. **Submit a pull request** with a clear description

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] Added tests for new functionality
- [ ] Updated documentation

## Security Checklist (if applicable)
- [ ] No sensitive data in logs
- [ ] Input validation added
- [ ] Cryptographic operations reviewed
```

### Review Process

1. **Automated Checks**: CI/CD pipeline runs tests and security scans
2. **Code Review**: Maintainers review code for quality and security
3. **Testing**: Changes are tested in different environments
4. **Approval**: At least one maintainer approval required
5. **Merge**: Changes are merged into main branch

## Release Process

Releases follow semantic versioning (SemVer):

- **Major** (X.0.0): Breaking changes
- **Minor** (0.X.0): New features, backward compatible
- **Patch** (0.0.X): Bug fixes, backward compatible

### Release Steps

1. Update version in `pyproject.toml` and `setup.py`
2. Update `CHANGELOG.md`
3. Create and push a version tag: `git tag v1.0.0`
4. GitHub Actions automatically creates release and publishes to PyPI

## Development Tips

### Debugging

```bash
# Use Python debugger
python -m pdb -m git_safe.cli encrypt
```

### Testing GPG Functionality

```bash
# Generate test GPG key
gpg --batch --generate-key <<EOF
Key-Type: RSA
Key-Length: 2048
Name-Real: Test User
Name-Email: test@example.com
Expire-Date: 1y
%no-protection
%commit
EOF
```

### Performance Testing

```bash
# Profile code execution
python -m cProfile -o profile.stats -m git_safe.cli encrypt
python -c "import pstats; pstats.Stats('profile.stats').sort_stats('cumulative').print_stats(10)"
```

## Getting Help

- **Documentation**: Check the README.md and code comments
- **Issues**: Search existing GitHub issues
- **Discussions**: Use GitHub Discussions for questions
- **Contact**: Reach out to maintainers for complex issues

## Recognition

Contributors are recognized in:
- GitHub contributors list
- Release notes for significant contributions
- Special thanks in documentation updates

Thank you for contributing to git-safe! 🔒
