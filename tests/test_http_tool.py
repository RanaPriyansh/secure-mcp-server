import pytest
import httpx
from unittest.mock import Mock, patch
from secure_mcp_server.http_tool import fetch_url, HTTPError
from secure_mcp_server.config import Config


@pytest.fixture
def test_config():
    """Provide test configuration with allowed domains."""
    return Config(
        bearer_token="test-token",
        allowed_paths=[],
        allowed_domains=["example.com", "api.github.com"],
        max_file_size_bytes=10485760,
        rate_limit_requests=10,
        rate_limit_period_seconds=60.0,
    )


def test_fetch_url_blocks_disallowed_domain(test_config):
    """URLs with disallowed domains are blocked."""
    with pytest.raises(HTTPError, match="not in allowed domains"):
        fetch_url("https://evil.com/data", test_config)


def test_fetch_url_blocks_ip_address(test_config):
    """Direct IP addresses are blocked."""
    with pytest.raises(HTTPError, match="not in allowed domains"):
        fetch_url("https://192.168.1.1/data", test_config)


def test_fetch_url_requires_https(test_config):
    """Non-HTTPS URLs are blocked."""
    with pytest.raises(HTTPError, match="Only HTTPS"):
        fetch_url("http://example.com/data", test_config)


def test_fetch_url_empty_allowed_domains():
    """Empty allowed_domains blocks all requests."""
    config = Config(
        bearer_token="test-token",
        allowed_paths=[],
        allowed_domains=[],
        max_file_size_bytes=10485760,
        rate_limit_requests=10,
        rate_limit_period_seconds=60.0,
    )
    
    with pytest.raises(HTTPError, match="No allowed domains"):
        fetch_url("https://example.com/data", config)


@patch("httpx.get")
def test_fetch_url_success(mock_get, test_config):
    """Successful fetch from allowed domain."""
    mock_response = Mock()
    mock_response.text = "response content"
    mock_response.raise_for_status = Mock()
    mock_get.return_value = mock_response
    
    result = fetch_url("https://example.com/api/data", test_config)
    
    assert result == "response content"
    mock_get.assert_called_once()


@patch("httpx.get")
def test_fetch_url_handles_http_error(mock_get, test_config):
    """HTTP errors are handled appropriately."""
    mock_get.side_effect = httpx.HTTPStatusError(
        "404", request=Mock(), response=Mock()
    )
    
    with pytest.raises(HTTPError, match="HTTP request failed"):
        fetch_url("https://example.com/notfound", test_config)


@patch("httpx.get")
def test_fetch_url_handles_network_error(mock_get, test_config):
    """Network errors are handled appropriately."""
    mock_get.side_effect = httpx.RequestError("Connection failed", request=Mock())
    
    with pytest.raises(HTTPError, match="HTTP request failed"):
        fetch_url("https://example.com/data", test_config)


def test_fetch_url_validates_subdomain(test_config):
    """Subdomains of allowed domains are not automatically allowed."""
    with pytest.raises(HTTPError, match="not in allowed domains"):
        fetch_url("https://sub.example.com/data", test_config)


def test_fetch_url_exact_domain_match(test_config):
    """Domain matching is exact."""
    result = None
    with patch("httpx.get") as mock_get:
        mock_response = Mock()
        mock_response.text = "data"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        result = fetch_url("https://example.com/test", test_config)
    
    assert result == "data"
