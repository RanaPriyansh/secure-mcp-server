import pytest
import time
from secure_mcp_server.rate_limit import RateLimiter, RateLimitError
from secure_mcp_server.config import Config


@pytest.fixture
def test_config():
    """Provide test configuration with tight rate limits."""
    return Config(
        bearer_token="test-token",
        allowed_paths=[],
        allowed_domains=[],
        max_file_size_bytes=10485760,
        rate_limit_requests=3,
        rate_limit_period_seconds=1.0,
    )


def test_rate_limiter_allows_within_limit(test_config):
    """Requests within rate limit are allowed."""
    limiter = RateLimiter(test_config)
    session_id = "session-1"
    
    limiter.check_rate_limit(session_id)
    limiter.check_rate_limit(session_id)
    limiter.check_rate_limit(session_id)


def test_rate_limiter_blocks_over_limit(test_config):
    """Requests over rate limit raise RateLimitError."""
    limiter = RateLimiter(test_config)
    session_id = "session-1"
    
    limiter.check_rate_limit(session_id)
    limiter.check_rate_limit(session_id)
    limiter.check_rate_limit(session_id)
    
    with pytest.raises(RateLimitError, match="Rate limit exceeded"):
        limiter.check_rate_limit(session_id)


def test_rate_limiter_refills_over_time(test_config):
    """Token bucket refills over time."""
    limiter = RateLimiter(test_config)
    session_id = "session-1"
    
    limiter.check_rate_limit(session_id)
    limiter.check_rate_limit(session_id)
    limiter.check_rate_limit(session_id)
    
    time.sleep(0.4)
    limiter.check_rate_limit(session_id)


def test_rate_limiter_independent_sessions(test_config):
    """Different sessions have independent rate limits."""
    limiter = RateLimiter(test_config)
    
    limiter.check_rate_limit("session-1")
    limiter.check_rate_limit("session-1")
    limiter.check_rate_limit("session-1")
    
    limiter.check_rate_limit("session-2")
    limiter.check_rate_limit("session-2")
    limiter.check_rate_limit("session-2")


def test_rate_limiter_partial_refill(test_config):
    """Partial refill allows partial requests."""
    limiter = RateLimiter(test_config)
    session_id = "session-1"
    
    limiter.check_rate_limit(session_id)
    limiter.check_rate_limit(session_id)
    limiter.check_rate_limit(session_id)
    
    with pytest.raises(RateLimitError):
        limiter.check_rate_limit(session_id)
    
    time.sleep(0.4)
    limiter.check_rate_limit(session_id)
    
    with pytest.raises(RateLimitError):
        limiter.check_rate_limit(session_id)
