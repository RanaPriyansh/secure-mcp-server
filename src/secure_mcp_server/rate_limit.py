"""Token bucket rate limiting."""

import time
from threading import Lock
from typing import Dict
from secure_mcp_server.config import Config


class RateLimitError(Exception):
    """Raised when rate limit is exceeded."""
    pass


class TokenBucket:
    """Token bucket for rate limiting."""
    
    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.
        
        Args:
            capacity: Maximum number of tokens
            refill_rate: Tokens added per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self.lock = Lock()
    
    def consume(self) -> bool:
        """
        Try to consume one token.
        
        Returns:
            bool: True if token was consumed, False if bucket is empty
        """
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            
            self.tokens = min(
                self.capacity,
                self.tokens + elapsed * self.refill_rate
            )
            self.last_refill = now
            
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            
            return False


class RateLimiter:
    """Per-session rate limiter using token buckets."""
    
    def __init__(self, config: Config):
        """
        Initialize rate limiter.
        
        Args:
            config: Server configuration
        """
        self.config = config
        self.buckets: Dict[str, TokenBucket] = {}
        self.lock = Lock()
    
    def check_rate_limit(self, session_id: str) -> None:
        """
        Check rate limit for a session.
        
        Args:
            session_id: Unique session identifier
        
        Raises:
            RateLimitError: If rate limit is exceeded
        """
        with self.lock:
            if session_id not in self.buckets:
                refill_rate = (
                    self.config.rate_limit_requests / 
                    self.config.rate_limit_period_seconds
                )
                self.buckets[session_id] = TokenBucket(
                    capacity=self.config.rate_limit_requests,
                    refill_rate=refill_rate
                )
        
        bucket = self.buckets[session_id]
        if not bucket.consume():
            raise RateLimitError("Rate limit exceeded")
