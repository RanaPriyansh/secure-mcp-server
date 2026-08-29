import pytest
from secure_mcp_server.auth import verify_bearer_token, AuthenticationError
from secure_mcp_server.config import Config


@pytest.fixture
def test_config():
    """Provide test configuration."""
    return Config(
        bearer_token="test-secret-token",
        allowed_paths=[],
        allowed_domains=[],
        max_file_size_bytes=10485760,
        rate_limit_requests=10,
        rate_limit_period_seconds=60.0,
    )


def test_verify_bearer_token_success(test_config):
    """Valid bearer token passes verification."""
    result = verify_bearer_token("Bearer test-secret-token", test_config)
    assert result is True


def test_verify_bearer_token_missing_header(test_config):
    """Missing authorization header raises AuthenticationError."""
    with pytest.raises(AuthenticationError, match="Missing authorization header"):
        verify_bearer_token("", test_config)


def test_verify_bearer_token_invalid_format(test_config):
    """Invalid header format raises AuthenticationError."""
    with pytest.raises(AuthenticationError, match="Invalid authorization header format"):
        verify_bearer_token("InvalidFormat token", test_config)


def test_verify_bearer_token_wrong_token(test_config):
    """Wrong token raises AuthenticationError."""
    with pytest.raises(AuthenticationError, match="Invalid bearer token"):
        verify_bearer_token("Bearer wrong-token", test_config)


def test_verify_bearer_token_case_sensitive(test_config):
    """Bearer token is case-sensitive."""
    with pytest.raises(AuthenticationError, match="Invalid bearer token"):
        verify_bearer_token("Bearer TEST-SECRET-TOKEN", test_config)


def test_verify_bearer_token_no_bearer_prefix(test_config):
    """Token without 'Bearer ' prefix is rejected."""
    with pytest.raises(AuthenticationError, match="Invalid authorization header format"):
        verify_bearer_token("test-secret-token", test_config)
