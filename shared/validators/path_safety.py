from __future__ import annotations

from pathlib import Path


def _absolute_path(path: Path) -> Path:
    """Normalise paths to an absolute form without requiring them to exist."""
    return path if path.is_absolute() else Path.cwd() / path


def path_uses_symlink(path: Path, *, repo_root: Path | None = None) -> bool:
    """Return True when a path uses a symlink within the relevant trust boundary."""
    absolute_path = _absolute_path(path)

    if repo_root is None:
        try:
            return absolute_path.is_symlink()
        except OSError:
            return True

    absolute_repo_root = _absolute_path(repo_root)
    if not absolute_path.is_relative_to(absolute_repo_root):
        try:
            return absolute_path.is_symlink()
        except OSError:
            return True

    current = absolute_path
    while True:
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True

        if current == absolute_repo_root:
            return False

        parent = current.parent
        if parent == current:
            return False
        current = parent


def validate_local_file(
    path: Path,
    *,
    repo_root: Path | None = None,
    label: str = "file",
) -> str | None:
    """Return a human-readable safety error for unsafe local file paths."""
    if path_uses_symlink(path, repo_root=repo_root):
        return f"Refusing to read symlinked {label}: {path}"

    if repo_root is None:
        return None

    try:
        resolved_repo_root = _absolute_path(repo_root).resolve(strict=True)
    except OSError as exc:
        return f"Cannot resolve repository root for {label}: {exc}"

    try:
        resolved_path = _absolute_path(path).resolve(strict=True)
    except OSError:
        return None

    try:
        resolved_path.relative_to(resolved_repo_root)
    except ValueError:
        return (
            f"Refusing to read {label} outside repository root: "
            f"{path} -> {resolved_path}"
        )

    return None
