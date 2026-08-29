import os
import pytest
from secure_mcp_server.config import get_config, Config


def test_config_fails_without_bearer_token():
    """Config must fail-closed when MCP_BEARER_TOKEN is missing."""
    env = os.environ.copy()
    if "MCP_BEARER_TOKEN" in env:
        del os.environ["MCP_BEARER_TOKEN"]
    
    with pytest.raises(ValueError, match="MCP_BEARER_TOKEN"):
        get_config()
    
    os.environ.clear()
    os.environ.update(env)


def test_config_loads_with_bearer_token(monkeypatch):
    """Config loads successfully when MCP_BEARER_TOKEN is set."""
    monkeypatch.setenv("MCP_BEARER_TOKEN", "test-token-123")
    
    config = get_config()
    
    assert isinstance(config, Config)
    assert config.bearer_token == "test-token-123"
    assert config.max_file_size_bytes > 0
    assert config.rate_limit_requests > 0
    assert config.rate_limit_period_seconds > 0


def test_config_has_default_values(monkeypatch):
    """Config provides sensible defaults."""
    monkeypatch.setenv("MCP_BEARER_TOKEN", "test-token")
    
    config = get_config()
    
    assert config.allowed_paths == []
    assert config.allowed_domains == []
    assert config.max_file_size_bytes == 10_485_760  # 10 MB
    assert config.rate_limit_requests == 10
    assert config.rate_limit_period_seconds == 60.0


def test_config_respects_environment_overrides(monkeypatch):
    """Config respects environment variable overrides."""
    monkeypatch.setenv("MCP_BEARER_TOKEN", "test-token")
    monkeypatch.setenv("MCP_ALLOWED_PATHS", "/tmp:/var/log")
    monkeypatch.setenv("MCP_ALLOWED_DOMAINS", "example.com:api.github.com")
    monkeypatch.setenv("MCP_MAX_FILE_SIZE_BYTES", "5242880")
    monkeypatch.setenv("MCP_RATE_LIMIT_REQUESTS", "20")
    monkeypatch.setenv("MCP_RATE_LIMIT_PERIOD_SECONDS", "30.0")
    
    config = get_config()
    
    assert config.allowed_paths == ["/tmp", "/var/log"]
    assert config.allowed_domains == ["example.com", "api.github.com"]
    assert config.max_file_size_bytes == 5_242_880
    assert config.rate_limit_requests == 20
    assert config.rate_limit_period_seconds == 30.0
