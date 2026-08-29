import os
import pytest
import tempfile
from pathlib import Path
from secure_mcp_server.filesystem_tool import read_file, list_directory, FilesystemError
from secure_mcp_server.config import Config


@pytest.fixture
def test_dir():
    """Create temporary test directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.txt"
        test_file.write_text("Hello, World!")
        
        subdir = Path(tmpdir) / "subdir"
        subdir.mkdir()
        (subdir / "nested.txt").write_text("Nested content")
        
        yield tmpdir


@pytest.fixture
def test_config(test_dir):
    """Provide test configuration with allowed path."""
    return Config(
        bearer_token="test-token",
        allowed_paths=[test_dir],
        allowed_domains=[],
        max_file_size_bytes=1024,
        rate_limit_requests=10,
        rate_limit_period_seconds=60.0,
    )


def test_read_file_success(test_config, test_dir):
    """Read file within allowed path."""
    content = read_file(f"{test_dir}/test.txt", test_config)
    assert content == "Hello, World!"


def test_read_file_blocks_path_traversal(test_config, test_dir):
    """Path traversal attempts are blocked."""
    with pytest.raises(FilesystemError, match="Path traversal"):
        read_file(f"{test_dir}/../etc/passwd", test_config)


def test_read_file_blocks_symlink_escape(test_config, test_dir):
    """Symlinks that escape allowed paths are blocked."""
    link_path = Path(test_dir) / "escape_link"
    try:
        link_path.symlink_to("/etc/passwd")
    except OSError:
        pytest.skip("Cannot create symlink")
    
    with pytest.raises(FilesystemError, match="not within allowed"):
        read_file(str(link_path), test_config)


def test_read_file_blocks_disallowed_path(test_config):
    """Files outside allowed paths are blocked."""
    with pytest.raises(FilesystemError, match="not within allowed"):
        read_file("/etc/passwd", test_config)


def test_read_file_blocks_large_file(test_config, test_dir):
    """Large files exceeding size limit are blocked."""
    large_file = Path(test_dir) / "large.txt"
    large_file.write_text("x" * 2000)
    
    with pytest.raises(FilesystemError, match="exceeds maximum"):
        read_file(str(large_file), test_config)


def test_read_file_not_found(test_config, test_dir):
    """Non-existent file raises appropriate error."""
    with pytest.raises(FilesystemError, match="not found"):
        read_file(f"{test_dir}/nonexistent.txt", test_config)


def test_list_directory_success(test_config, test_dir):
    """List directory within allowed path."""
    entries = list_directory(test_dir, test_config)
    assert "test.txt" in entries
    assert "subdir" in entries


def test_list_directory_blocks_path_traversal(test_config, test_dir):
    """Path traversal in directory listing is blocked."""
    with pytest.raises(FilesystemError, match="Path traversal"):
        list_directory(f"{test_dir}/../etc", test_config)


def test_list_directory_blocks_disallowed_path(test_config):
    """Directories outside allowed paths are blocked."""
    with pytest.raises(FilesystemError, match="not within allowed"):
        list_directory("/etc", test_config)


def test_read_file_empty_allowed_paths():
    """Empty allowed_paths blocks all file access."""
    config = Config(
        bearer_token="test-token",
        allowed_paths=[],
        allowed_domains=[],
        max_file_size_bytes=1024,
        rate_limit_requests=10,
        rate_limit_period_seconds=60.0,
    )
    
    with pytest.raises(FilesystemError, match="No allowed paths"):
        read_file("/tmp/test.txt", config)
