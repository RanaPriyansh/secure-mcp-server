import pytest
import tempfile
from pathlib import Path
from secure_mcp_server.server import create_server
from secure_mcp_server.config import Config


@pytest.fixture
def test_config(tmp_path):
    """Provide test configuration."""
    return Config(
        bearer_token="test-secret-token",
        allowed_paths=[str(tmp_path)],
        allowed_domains=["example.com"],
        max_file_size_bytes=1024,
        rate_limit_requests=10,
        rate_limit_period_seconds=60.0,
    )


def test_server_creation(test_config):
    """Server can be created with valid config."""
    server = create_server(test_config)
    assert server is not None


def test_server_lists_tools(test_config):
    """Server lists expected tools."""
    server = create_server(test_config)
    
    tools = server.get_tools()
    
    tool_names = [tool.name for tool in tools]
    assert "read_file" in tool_names
    assert "list_directory" in tool_names
    assert "fetch_url" in tool_names
    assert len(tools) == 3


def test_server_enforces_rate_limiting(test_config, tmp_path):
    """Server enforces rate limiting per session."""
    config = Config(
        bearer_token="test-secret-token",
        allowed_paths=[str(tmp_path)],
        allowed_domains=["example.com"],
        max_file_size_bytes=1024,
        rate_limit_requests=2,
        rate_limit_period_seconds=60.0,
    )
    server = create_server(config)
    
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    
    server.call_tool("read_file", {"path": str(test_file)})
    server.call_tool("read_file", {"path": str(test_file)})
    
    with pytest.raises(Exception, match="Rate limit"):
        server.call_tool("read_file", {"path": str(test_file)})
