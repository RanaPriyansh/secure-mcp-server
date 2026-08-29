"""Secure filesystem operations with path allowlist."""

import os
from pathlib import Path
from secure_mcp_server.config import Config


class FilesystemError(Exception):
    """Raised when filesystem operation fails or is blocked."""
    pass


def _resolve_and_validate_path(path: str, config: Config) -> Path:
    """
    Resolve path and validate it's within allowed paths.
    
    Args:
        path: Path to validate
        config: Server configuration
    
    Returns:
        Path: Resolved absolute path
    
    Raises:
        FilesystemError: If path is invalid or not allowed
    """
    if not config.allowed_paths:
        raise FilesystemError("No allowed paths configured")
    
    if ".." in path:
        raise FilesystemError("Path traversal detected in path")
    
    try:
        resolved = Path(path).resolve()
    except (OSError, RuntimeError) as e:
        raise FilesystemError(f"Invalid path: {e}")
    
    for allowed in config.allowed_paths:
        allowed_path = Path(allowed).resolve()
        try:
            resolved.relative_to(allowed_path)
            return resolved
        except ValueError:
            continue
    
    raise FilesystemError(f"Path {path} is not within allowed paths")


def read_file(path: str, config: Config) -> str:
    """
    Read file contents with security checks.
    
    Args:
        path: File path to read
        config: Server configuration
    
    Returns:
        str: File contents
    
    Raises:
        FilesystemError: If file cannot be read or access is denied
    """
    resolved_path = _resolve_and_validate_path(path, config)
    
    if not resolved_path.exists():
        raise FilesystemError(f"File {path} not found")
    
    if not resolved_path.is_file():
        raise FilesystemError(f"Path {path} is not a file")
    
    file_size = resolved_path.stat().st_size
    if file_size > config.max_file_size_bytes:
        raise FilesystemError(
            f"File size {file_size} exceeds maximum {config.max_file_size_bytes}"
        )
    
    try:
        return resolved_path.read_text()
    except (OSError, UnicodeDecodeError) as e:
        raise FilesystemError(f"Failed to read file: {e}")


def list_directory(path: str, config: Config) -> list[str]:
    """
    List directory contents with security checks.
    
    Args:
        path: Directory path to list
        config: Server configuration
    
    Returns:
        list[str]: List of entry names in the directory
    
    Raises:
        FilesystemError: If directory cannot be listed or access is denied
    """
    resolved_path = _resolve_and_validate_path(path, config)
    
    if not resolved_path.exists():
        raise FilesystemError(f"Directory {path} not found")
    
    if not resolved_path.is_dir():
        raise FilesystemError(f"Path {path} is not a directory")
    
    try:
        return [entry.name for entry in resolved_path.iterdir()]
    except OSError as e:
        raise FilesystemError(f"Failed to list directory: {e}")
