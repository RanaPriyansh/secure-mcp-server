"""Bearer token authentication."""

from secure_mcp_server.config import Config


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


def verify_bearer_token(authorization_header: str, config: Config) -> bool:
    """
    Verify bearer token from authorization header.
    
    Args:
        authorization_header: Authorization header value (e.g., "Bearer token123")
        config: Server configuration containing the expected bearer token
    
    Returns:
        bool: True if token is valid
    
    Raises:
        AuthenticationError: If authentication fails
    """
    if not authorization_header:
        raise AuthenticationError("Missing authorization header")
    
    parts = authorization_header.split(" ", 1)
    if len(parts) != 2 or parts[0] != "Bearer":
        raise AuthenticationError("Invalid authorization header format")
    
    token = parts[1]
    if token != config.bearer_token:
        raise AuthenticationError("Invalid bearer token")
    
    return True
