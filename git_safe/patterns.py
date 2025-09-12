"""
Pattern matching for git-safe using .gitattributes
"""

from pathlib import Path

from pathspec import PathSpec, patterns


class PatternError(Exception):
    """Exception raised for pattern-related errors"""

    pass


def parse_gitattributes(gitattributes_path: Path | None = None) -> PathSpec:
    """
    Parse .gitattributes file and extract patterns for git-safe filter.

    Args:
        gitattributes_path: Path to .gitattributes file (defaults to ./.gitattributes)

    Returns:
        PathSpec object for matching files

    Raises:
        PatternError: If .gitattributes cannot be read
    """
    if gitattributes_path is None:
        gitattributes_path = Path(".gitattributes")

    if not gitattributes_path.exists():
        return PathSpec.from_lines(patterns.GitWildMatchPattern, [])

    try:
        lines = gitattributes_path.read_text().splitlines()
    except OSError as e:
        raise PatternError(f"Cannot read .gitattributes: {e}") from e

    patterns_list = []

    for _line_num, line in enumerate(lines, 1):
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        parts = line.split()

        # Look for lines with git-safe filter
        if len(parts) >= 2:
            pattern = parts[0]
            attributes = parts[1:]

            # Check if any attribute is filter=git-safe
            for attr in attributes:
                if attr == "filter=git-safe":
                    patterns_list.append(pattern)
                    break

    return PathSpec.from_lines(patterns.GitWildMatchPattern, patterns_list)


def find_matching_files(root_path: Path, pathspec: PathSpec) -> list[Path]:
    """
    Find all files matching the pathspec patterns.

    Args:
        root_path: Root directory to search
        pathspec: PathSpec object with patterns

    Returns:
        List of matching file paths
    """
    matching_files = []

    for file_path in root_path.rglob("*"):
        if file_path.is_file():
            relative_path = file_path.relative_to(root_path)
            if pathspec.match_file(str(relative_path)):
                matching_files.append(file_path)

    return matching_files


def should_encrypt_file(file_path: Path, root_path: Path | None = None) -> bool:
    """
    Check if a file should be encrypted based on .gitattributes patterns.

    Args:
        file_path: Path to file to check
        root_path: Root directory (defaults to current directory)

    Returns:
        True if file should be encrypted
    """
    if root_path is None:
        root_path = Path.cwd()

    try:
        pathspec = parse_gitattributes(root_path / ".gitattributes")
        relative_path = file_path.relative_to(root_path)
        return pathspec.match_file(str(relative_path))
    except (PatternError, ValueError):
        return False
