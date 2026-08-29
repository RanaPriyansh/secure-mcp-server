"""Configuration management for secure MCP server."""

import os
from dataclasses import dataclass


@dataclass
class Config:
    """Server configuration."""
    bearer_token: str
    allowed_paths: list[str]
    allowed_domains: list[str]
    max_file_size_bytes: int
    rate_limit_requests: int
    rate_limit_period_seconds: float


def get_config() -> Config:
    """
    Load configuration from environment variables.
    
    Raises:
        ValueError: If MCP_BEARER_TOKEN is not set (fail-closed).
    
    Returns:
        Config: Server configuration.
    """
    bearer_token = os.getenv("MCP_BEARER_TOKEN")
    if not bearer_token:
        raise ValueError("MCP_BEARER_TOKEN environment variable is required")
    
    allowed_paths_str = os.getenv("MCP_ALLOWED_PATHS", "")
    allowed_paths = [p.strip() for p in allowed_paths_str.split(":") if p.strip()]
    
    allowed_domains_str = os.getenv("MCP_ALLOWED_DOMAINS", "")
    allowed_domains = [d.strip() for d in allowed_domains_str.split(":") if d.strip()]
    
    max_file_size_bytes = int(os.getenv("MCP_MAX_FILE_SIZE_BYTES", "10485760"))
    rate_limit_requests = int(os.getenv("MCP_RATE_LIMIT_REQUESTS", "10"))
    rate_limit_period_seconds = float(os.getenv("MCP_RATE_LIMIT_PERIOD_SECONDS", "60.0"))
    
    return Config(
        bearer_token=bearer_token,
        allowed_paths=allowed_paths,
        allowed_domains=allowed_domains,
        max_file_size_bytes=max_file_size_bytes,
        rate_limit_requests=rate_limit_requests,
        rate_limit_period_seconds=rate_limit_period_seconds,
    )
