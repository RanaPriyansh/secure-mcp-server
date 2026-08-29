"""Secure HTTP operations with domain allowlist."""

from urllib.parse import urlparse
import httpx
from secure_mcp_server.config import Config


class HTTPError(Exception):
    """Raised when HTTP operation fails or is blocked."""
    pass


def fetch_url(url: str, config: Config) -> str:
    """
    Fetch URL contents with security checks.
    
    Args:
        url: URL to fetch
        config: Server configuration
    
    Returns:
        str: Response content
    
    Raises:
        HTTPError: If fetch fails or is blocked
    """
    if not config.allowed_domains:
        raise HTTPError("No allowed domains configured")
    
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise HTTPError(f"Invalid URL: {e}")
    
    if parsed.scheme != "https":
        raise HTTPError("Only HTTPS URLs are allowed")
    
    domain = parsed.netloc.lower()
    if ":" in domain:
        domain = domain.split(":")[0]
    
    if domain not in config.allowed_domains:
        raise HTTPError(f"Domain {domain} is not in allowed domains")
    
    try:
        response = httpx.get(url, timeout=30.0, follow_redirects=False)
        response.raise_for_status()
        return response.text
    except (httpx.HTTPStatusError, httpx.RequestError) as e:
        raise HTTPError(f"HTTP request failed: {e}")
