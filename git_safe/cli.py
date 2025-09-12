"""
Command-line interface for git-safe
"""

import argparse
import subprocess
import sys
from pathlib import Path

from git_safe.constants import EXIT_ERROR, EXIT_SUCCESS

from .file_ops import (
    FileOperationError,
    clean_backups,
    decrypt_file,
    encrypt_file,
    find_encrypted_files,
    verify_file_integrity,
)
from .keyfile import (
    KeyfileError,
    export_key_gpg,
    generate_keyfile,
    import_key_gpg,
    load_keyfile,
)
from .patterns import PatternError, find_matching_files, parse_gitattributes

# Command constants
INIT_CMD = "init"
EXPORT_KEY_CMD = "export-key"
UNLOCK_CMD = "unlock"
ENCRYPT_CMD = "encrypt"
DECRYPT_CMD = "decrypt"
STATUS_CMD = "status"
CLEAN_CMD = "clean"
SMUDGE_CMD = "smudge"
DIFF_CMD = "diff"

# Default keyfile path
DEFAULT_KEYFILE = ".git-safe/.git-safe-key"
# Git filter configuration
GITATTRIBUTES_FILTER_LINE = "*.secret filter=git-safe diff=git-safe"


def _is_git_repository() -> bool:
    """Check if current directory is a Git repository."""
    return Path(".git").exists() or Path(".git").is_file()


def _ensure_gitattributes_filter() -> bool:
    """
    Ensure .gitattributes contains the git-safe filter line.

    Returns:
        True if the line was added or already exists, False on error.
    """
    gitattributes_path = Path(".gitattributes")

    try:
        # Read existing content if file exists
        existing_content = ""
        if gitattributes_path.exists():
            existing_content = gitattributes_path.read_text()

            # Check if filter line already exists
            if GITATTRIBUTES_FILTER_LINE in existing_content:
                print("✓ .gitattributes already contains git-safe filter")
                return True

        # Append the filter line
        with gitattributes_path.open("a") as f:
            if existing_content and not existing_content.endswith("\n"):
                f.write("\n")
            f.write(f"{GITATTRIBUTES_FILTER_LINE}\n")

        if gitattributes_path.stat().st_size == len(GITATTRIBUTES_FILTER_LINE) + 1:
            print("✓ Created .gitattributes with git-safe filter")
        else:
            print("✓ Added git-safe filter to .gitattributes")
        return True

    except OSError as e:
        print(f"Warning: Could not update .gitattributes: {e}")
        return False


def _setup_git_filter() -> bool:
    """
    Set up Git filter configuration for git-safe.

    Returns:
        True if setup was successful, False otherwise.
    """
    if not _is_git_repository():
        print("Warning: Not in a Git repository - skipping Git filter setup")
        return False

    try:
        # Get the git-safe executable path
        git_safe_cmd = "git-safe"

        # Configuration to set
        configs = [
            ("filter.git-safe.clean", f"{git_safe_cmd} clean %f"),
            ("filter.git-safe.smudge", f"{git_safe_cmd} smudge %f"),
            ("filter.git-safe.required", "true"),
            ("diff.git-safe.textconv", f"{git_safe_cmd} diff"),
        ]

        for config_key, config_value in configs:
            try:
                # Check if config already exists
                result = subprocess.run(
                    ["git", "config", "--local", config_key], capture_output=True, text=True, check=False
                )

                if result.returncode == 0:
                    existing_value = result.stdout.strip()
                    if existing_value == config_value:
                        print(f"✓ Git config {config_key} already set correctly")
                        continue
                    else:
                        print(f"Warning: Git config {config_key} exists with different value: {existing_value}")
                        print(f"         Expected: {config_value}")
                        continue

                # Set the configuration
                subprocess.run(["git", "config", "--local", config_key, config_value], check=True, capture_output=True)
                print(f"✓ Set Git config {config_key}")

            except subprocess.CalledProcessError as e:
                print(f"Warning: Failed to set Git config {config_key}: {e}")
                return False

        return True

    except Exception as e:
        print(f"Warning: Failed to setup Git filter: {e}")
        return False


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize a new git-safe keyfile and set up Git repository integration."""
    try:
        # Ensure parent directory exists
        args.keyfile.parent.mkdir(parents=True, exist_ok=True)

        if args.keyfile.exists() and not args.force:
            print(f"Error: Keyfile {args.keyfile} already exists. Use --force to overwrite.")
            return EXIT_ERROR

        aes_key, hmac_key = generate_keyfile(args.keyfile)
        print(f"Generated new keyfile: {args.keyfile}")

        if args.export_gpg:
            gpg_keyfile = export_key_gpg(args.keyfile, args.export_gpg)
            print(f"Exported GPG-encrypted keyfile: {gpg_keyfile}")

        # Set up Git repository integration
        print("\nSetting up Git repository integration...")

        # Ensure .gitattributes contains the filter line
        gitattributes_success = _ensure_gitattributes_filter()

        # Set up Git filter configuration
        git_filter_success = _setup_git_filter()

        if gitattributes_success and git_filter_success:
            print("✓ Git repository integration completed successfully")
        elif gitattributes_success:
            print("✓ .gitattributes setup completed (Git filter setup skipped)")
        else:
            print("⚠ Git repository integration completed with warnings")

        return EXIT_SUCCESS

    except KeyfileError as e:
        print(f"Error: {e}")
        return EXIT_ERROR


def cmd_export_key(args: argparse.Namespace) -> int:
    """Export keyfile encrypted with GPG."""
    try:
        if not args.keyfile.exists():
            print(f"Error: Keyfile {args.keyfile} does not exist")
            return EXIT_ERROR

        output_path = args.output or args.keyfile.with_suffix(args.keyfile.suffix + ".gpg")
        gpg_keyfile = export_key_gpg(args.keyfile, args.recipient, output_path)
        print(f"Exported GPG-encrypted keyfile: {gpg_keyfile}")

        return EXIT_SUCCESS

    except KeyfileError as e:
        print(f"Error: {e}")
        return EXIT_ERROR


def cmd_unlock(args: argparse.Namespace) -> int:
    """Unlock (import) GPG-encrypted keyfile."""
    try:
        gpg_keyfile = args.gpg_keyfile
        if not gpg_keyfile.exists():
            print(f"Error: GPG keyfile {gpg_keyfile} does not exist")
            return EXIT_ERROR

        output_path = args.output or gpg_keyfile.with_suffix("")
        keyfile_path = import_key_gpg(gpg_keyfile, output_path)
        print(f"Imported keyfile: {keyfile_path}")

        return EXIT_SUCCESS

    except KeyfileError as e:
        print(f"Error: {e}")
        return EXIT_ERROR


def cmd_encrypt(args: argparse.Namespace) -> int:
    """Encrypt files based on .gitattributes patterns."""
    try:
        # Load keyfile
        aes_key, hmac_key = load_keyfile(args.keyfile)

        # Parse patterns from .gitattributes
        pathspec = parse_gitattributes()

        if not pathspec.patterns:
            print("Warning: No patterns found in .gitattributes with filter=git-safe")
            return EXIT_SUCCESS

        # Find matching files
        root_path = Path.cwd()
        matching_files = find_matching_files(root_path, pathspec)

        if not matching_files:
            print("No files match the patterns in .gitattributes")
            return EXIT_SUCCESS

        # Encrypt files
        encrypted_count = 0
        for file_path in matching_files:
            try:
                encrypt_file(file_path, aes_key, hmac_key, backup=not args.no_backup)
                encrypted_count += 1
            except FileOperationError as e:
                print(f"Error: {e}")
                if not args.continue_on_error:
                    return EXIT_ERROR

        print(f"Encrypted {encrypted_count} files")
        return EXIT_SUCCESS

    except (KeyfileError, PatternError, FileOperationError) as e:
        print(f"Error: {e}")
        return EXIT_ERROR


def cmd_decrypt(args: argparse.Namespace) -> int:
    """Decrypt files."""
    try:
        # Load keyfile
        aes_key, hmac_key = load_keyfile(args.keyfile)

        # Find files to decrypt
        files_to_decrypt = []

        if args.all:
            # Find all encrypted files
            files_to_decrypt = find_encrypted_files(Path.cwd())
        elif args.patterns:
            # Find files matching patterns
            for pattern in args.patterns:
                for file_path in Path.cwd().glob(pattern):
                    if file_path.is_file():
                        files_to_decrypt.append(file_path)
        else:
            # Default: use .gitattributes patterns
            pathspec = parse_gitattributes()

            if not pathspec.patterns:
                print("Warning: No patterns found in .gitattributes with filter=git-safe")
                return EXIT_SUCCESS

            # Find matching files
            root_path = Path.cwd()
            matching_files = find_matching_files(root_path, pathspec)

            if not matching_files:
                print("No files match the patterns in .gitattributes")
                return EXIT_SUCCESS

            # Filter to only encrypted files
            for file_path in matching_files:
                if file_path.is_file():
                    files_to_decrypt.append(file_path)

        if not files_to_decrypt:
            print("No encrypted files found")
            return EXIT_SUCCESS

        # Decrypt files
        decrypted_count = 0
        for file_path in files_to_decrypt:
            try:
                if decrypt_file(file_path, aes_key, hmac_key):
                    decrypted_count += 1
            except FileOperationError as e:
                print(f"Error: {e}")
                if not args.continue_on_error:
                    return EXIT_ERROR

        print(f"Decrypted {decrypted_count} files")
        return EXIT_SUCCESS

    except (KeyfileError, PatternError, FileOperationError) as e:
        print(f"Error: {e}")
        return EXIT_ERROR


def cmd_status(args: argparse.Namespace) -> int:
    """Show status of encrypted files."""
    try:
        # Load keyfile if provided
        aes_key = hmac_key = None
        if args.keyfile and args.keyfile.exists():
            aes_key, hmac_key = load_keyfile(args.keyfile)

        # Find encrypted files
        encrypted_files = find_encrypted_files(Path.cwd())

        if not encrypted_files:
            print("No encrypted files found")
            return EXIT_SUCCESS

        print(f"Found {len(encrypted_files)} encrypted files:")

        for file_path in encrypted_files:
            status = "encrypted"
            if aes_key and hmac_key:
                if verify_file_integrity(file_path, aes_key, hmac_key):
                    status = "encrypted (verified)"
                else:
                    status = "encrypted (INVALID)"

            print(f"  {file_path} [{status}]")

        return EXIT_SUCCESS

    except (KeyfileError, FileOperationError) as e:
        print(f"Error: {e}")
        return EXIT_ERROR


def cmd_clean(args: argparse.Namespace) -> int:
    """Clean backup files or handle Git filter clean operation."""
    # Check if this is a Git filter clean operation (has filename argument)
    if hasattr(args, "filename") and args.filename:
        return _git_filter_clean(args.filename)

    # Otherwise, it's the backup cleanup operation
    try:
        count = clean_backups(Path.cwd())
        print(f"Removed {count} backup files")
        return EXIT_SUCCESS

    except Exception as e:
        print(f"Error: {e}")
        return EXIT_ERROR


def cmd_smudge(args: argparse.Namespace) -> int:
    """Handle Git filter smudge operation (decrypt on checkout)."""
    return _git_filter_smudge(args.filename)


def cmd_diff(args: argparse.Namespace) -> int:
    """Handle Git filter diff operation (provide readable diff)."""
    return _git_filter_diff(args.filename)


def _git_filter_clean(filename: str) -> int:
    """
    Git filter clean operation: encrypt file content from stdin to stdout.
    This is called by Git when committing files.
    """
    try:
        # Load keyfile
        keyfile_path = Path(DEFAULT_KEYFILE)
        if not keyfile_path.exists():
            # Try to find keyfile in parent directories
            current = Path.cwd()
            while current != current.parent:
                keyfile_path = current / ".git-safe" / ".git-safe-key"
                if keyfile_path.exists():
                    break
                current = current.parent
            else:
                print("Error: No keyfile found", file=sys.stderr)
                return EXIT_ERROR

        aes_key, hmac_key = load_keyfile(keyfile_path)

        # Read from stdin
        input_data = sys.stdin.buffer.read()

        # Generate nonce and encrypt
        from .crypto import compute_hmac, ctr_encrypt, generate_nonce

        nonce = generate_nonce(input_data)
        encrypted_data = ctr_encrypt(aes_key, nonce, input_data)
        hmac_value = compute_hmac(hmac_key, input_data)

        # Write encrypted format to stdout
        from .constants import MAGIC

        output_data = MAGIC + nonce + hmac_value + encrypted_data
        sys.stdout.buffer.write(output_data)

        return EXIT_SUCCESS

    except Exception as e:
        print(f"Error in git filter clean: {e}", file=sys.stderr)
        return EXIT_ERROR


def _git_filter_smudge(filename: str) -> int:
    """
    Git filter smudge operation: decrypt file content from stdin to stdout.
    This is called by Git when checking out files.
    """
    try:
        # Load keyfile
        keyfile_path = Path(DEFAULT_KEYFILE)
        if not keyfile_path.exists():
            # Try to find keyfile in parent directories
            current = Path.cwd()
            while current != current.parent:
                keyfile_path = current / ".git-safe" / ".git-safe-key"
                if keyfile_path.exists():
                    break
                current = current.parent
            else:
                # If no keyfile found, pass through unchanged
                input_data = sys.stdin.buffer.read()
                sys.stdout.buffer.write(input_data)
                return EXIT_SUCCESS

        aes_key, hmac_key = load_keyfile(keyfile_path)

        # Read from stdin
        input_data = sys.stdin.buffer.read()

        # Check if it's encrypted
        from .constants import CTR_NONCE_LEN, HMAC_CHECK_LEN, MAGIC

        if not input_data.startswith(MAGIC):
            # Not encrypted, pass through unchanged
            sys.stdout.buffer.write(input_data)
            return EXIT_SUCCESS

        # Decrypt the data
        body = input_data[len(MAGIC) :]
        if len(body) < CTR_NONCE_LEN + HMAC_CHECK_LEN:
            # Invalid format, pass through unchanged
            sys.stdout.buffer.write(input_data)
            return EXIT_SUCCESS

        nonce = body[:CTR_NONCE_LEN]
        stored_hmac = body[CTR_NONCE_LEN : CTR_NONCE_LEN + HMAC_CHECK_LEN]
        ciphertext = body[CTR_NONCE_LEN + HMAC_CHECK_LEN :]

        # Decrypt and verify
        from .crypto import ctr_decrypt, verify_hmac

        plaintext = ctr_decrypt(aes_key, nonce, ciphertext)

        if not verify_hmac(hmac_key, plaintext, stored_hmac):
            print(f"Warning: HMAC verification failed for {filename}", file=sys.stderr)
            # Still output the decrypted content

        sys.stdout.buffer.write(plaintext)
        return EXIT_SUCCESS

    except Exception as e:
        print(f"Error in git filter smudge: {e}", file=sys.stderr)
        # On error, pass through unchanged
        try:
            input_data = sys.stdin.buffer.read()
            sys.stdout.buffer.write(input_data)
        except Exception:
            pass
        return EXIT_ERROR


def _git_filter_diff(filename: str) -> int:
    """
    Git filter diff operation: provide readable content for diffs.
    This is called by Git when showing diffs.
    """
    try:
        # Load keyfile
        keyfile_path = Path(DEFAULT_KEYFILE)
        if not keyfile_path.exists():
            # Try to find keyfile in parent directories
            current = Path.cwd()
            while current != current.parent:
                keyfile_path = current / ".git-safe" / ".git-safe-key"
                if keyfile_path.exists():
                    break
                current = current.parent
            else:
                # If no keyfile, show placeholder
                print("[git-safe encrypted file - no keyfile available]")
                return EXIT_SUCCESS

        aes_key, hmac_key = load_keyfile(keyfile_path)

        # Read the file directly (diff textconv gets filename as argument)
        file_path = Path(filename)
        if not file_path.exists():
            print("[git-safe encrypted file - file not found]")
            return EXIT_SUCCESS

        input_data = file_path.read_bytes()

        # Check if it's encrypted
        from .constants import CTR_NONCE_LEN, HMAC_CHECK_LEN, MAGIC

        if not input_data.startswith(MAGIC):
            # Not encrypted, show as-is
            sys.stdout.buffer.write(input_data)
            return EXIT_SUCCESS

        # Decrypt the data
        body = input_data[len(MAGIC) :]
        if len(body) < CTR_NONCE_LEN + HMAC_CHECK_LEN:
            print("[git-safe encrypted file - invalid format]")
            return EXIT_SUCCESS

        nonce = body[:CTR_NONCE_LEN]
        stored_hmac = body[CTR_NONCE_LEN : CTR_NONCE_LEN + HMAC_CHECK_LEN]
        ciphertext = body[CTR_NONCE_LEN + HMAC_CHECK_LEN :]

        # Decrypt and verify
        from .crypto import ctr_decrypt, verify_hmac

        plaintext = ctr_decrypt(aes_key, nonce, ciphertext)

        if not verify_hmac(hmac_key, plaintext, stored_hmac):
            print("[git-safe encrypted file - HMAC verification failed]")
            return EXIT_SUCCESS

        sys.stdout.buffer.write(plaintext)
        return EXIT_SUCCESS

    except Exception as e:
        print(f"[git-safe encrypted file - error: {e}]")
        return EXIT_SUCCESS


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="git-safe",
        description="Effortless file encryption for your git repos—pattern-matched, secure, and keyfile-flexible.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init command
    init_parser = subparsers.add_parser(INIT_CMD, help="Initialize a new keyfile")
    init_parser.add_argument(
        "--keyfile",
        type=Path,
        default=Path(DEFAULT_KEYFILE),
        help=f"Path to keyfile (default: {DEFAULT_KEYFILE}). Will create .git-safe directory if needed.",
    )
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing keyfile")
    init_parser.add_argument(
        "--export-gpg", metavar="RECIPIENT", help="Also export keyfile encrypted for GPG recipient"
    )

    # export-key command
    export_parser = subparsers.add_parser(EXPORT_KEY_CMD, help="Export keyfile encrypted with GPG")
    export_parser.add_argument(
        "--keyfile", type=Path, default=Path(DEFAULT_KEYFILE), help=f"Path to keyfile (default: {DEFAULT_KEYFILE})"
    )
    export_parser.add_argument("recipient", help="GPG key ID or email to encrypt for")
    export_parser.add_argument("--output", type=Path, help="Output path for encrypted keyfile")

    # unlock command (import GPG keyfile)
    unlock_parser = subparsers.add_parser(UNLOCK_CMD, help="Import GPG-encrypted keyfile")
    unlock_parser.add_argument(
        "--gpg-keyfile",
        type=Path,
        default=Path(".git-safe/.git-safe-key.gpg"),
        help="Path to GPG-encrypted keyfile (default: .git-safe/.git-safe-key.gpg)",
    )
    unlock_parser.add_argument("--output", type=Path, help="Output path for decrypted keyfile")

    # encrypt command
    encrypt_parser = subparsers.add_parser(ENCRYPT_CMD, help="Encrypt files based on .gitattributes")
    encrypt_parser.add_argument(
        "--keyfile", type=Path, default=Path(DEFAULT_KEYFILE), help=f"Path to keyfile (default: {DEFAULT_KEYFILE})"
    )
    encrypt_parser.add_argument("--no-backup", action="store_true", help="Do not create backup files")
    encrypt_parser.add_argument(
        "--continue-on-error", action="store_true", help="Continue processing files even if some fail"
    )

    # decrypt command
    decrypt_parser = subparsers.add_parser(DECRYPT_CMD, help="Decrypt files (uses .gitattributes patterns by default)")
    decrypt_parser.add_argument(
        "--keyfile", type=Path, default=Path(DEFAULT_KEYFILE), help=f"Path to keyfile (default: {DEFAULT_KEYFILE})"
    )
    decrypt_parser.add_argument("--all", action="store_true", help="Decrypt all encrypted files")
    decrypt_parser.add_argument(
        "--continue-on-error", action="store_true", help="Continue processing files even if some fail"
    )
    decrypt_parser.add_argument("patterns", nargs="*", help="File patterns to decrypt (overrides .gitattributes)")

    # status command
    status_parser = subparsers.add_parser(STATUS_CMD, help="Show status of encrypted files")
    status_parser.add_argument("--keyfile", type=Path, help="Path to keyfile for verification")

    # clean command
    clean_parser = subparsers.add_parser(CLEAN_CMD, help="Remove backup files or Git filter clean")
    clean_parser.add_argument("filename", nargs="?", help="Filename for Git filter operation")

    # smudge command (Git filter)
    smudge_parser = subparsers.add_parser(SMUDGE_CMD, help="Git filter smudge operation")
    smudge_parser.add_argument("filename", help="Filename for Git filter operation")

    # diff command (Git filter)
    diff_parser = subparsers.add_parser(DIFF_CMD, help="Git filter diff operation")
    diff_parser.add_argument("filename", help="Filename for Git filter operation")

    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return EXIT_ERROR

    # Dispatch to command handlers
    command_handlers = {
        INIT_CMD: cmd_init,
        EXPORT_KEY_CMD: cmd_export_key,
        UNLOCK_CMD: cmd_unlock,
        ENCRYPT_CMD: cmd_encrypt,
        DECRYPT_CMD: cmd_decrypt,
        STATUS_CMD: cmd_status,
        CLEAN_CMD: cmd_clean,
        SMUDGE_CMD: cmd_smudge,
        DIFF_CMD: cmd_diff,
    }

    handler = command_handlers.get(args.command)
    if handler:
        return handler(args)
    else:
        print(f"Unknown command: {args.command}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
