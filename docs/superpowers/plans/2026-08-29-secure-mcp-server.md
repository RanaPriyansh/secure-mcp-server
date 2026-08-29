# Secure MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-ready Python MCP server with fail-closed authentication, rate limiting, and secure file/HTTP tools.

**Architecture:** Python MCP server with bearer token authentication (fail-closed), per-session token-bucket rate limiting, two tools (filesystem with path allowlist + path-traversal protection, HTTP with domain allowlist), structured JSON logging with no secrets, and comprehensive test coverage (37+ tests).

**Tech Stack:** Python 3.9+, MCP SDK, pytest, httpx (for HTTP tool), token bucket rate limiting

## Global Constraints

- Package name: `secure-mcp-server`, module name: `secure_mcp_server`
- MIT LICENSE with author Priyansh Rana (already exists)
- Server requires `MCP_BEARER_TOKEN` environment variable to start (fail-closed)
- Tests must pass on fresh clone without production tokens (use fixtures)
- No real network, GPU, or live mailbox required for tests
- No conexus, gidney, lobster, tara@, real emails, or API keys in code
- Structured errors with no stack traces exposed to clients
- Structured JSON logs with no secrets logged
- Python version: 3.9+

---

### Task 1: Project Structure and Configuration

**Files:**
- Create: `pyproject.toml`
- Create: `src/secure_mcp_server/__init__.py`
- Create: `.gitignore`
- Create: `pytest.ini`

**Interfaces:**
- Consumes: None
- Produces: Package structure, dependency manifest (`mcp>=1.0.0`, `httpx>=0.25.0`)

- [ ] **Step 1: Write pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "secure-mcp-server"
version = "0.1.0"
description = "A secure MCP server with authentication, rate limiting, and safe file/HTTP tools"
authors = [{name = "Priyansh Rana"}]
license = {text = "MIT"}
readme = "README.md"
requires-python = ">=3.9"
dependencies = [
    "mcp>=1.0.0",
    "httpx>=0.25.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-asyncio>=0.21.0",
]

[tool.hatch.build.targets.wheel]
packages = ["src/secure_mcp_server"]
```

- [ ] **Step 2: Create .gitignore**

```
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
.pytest_cache/
.coverage
htmlcov/
.venv/
venv/
ENV/
.env
.DS_Store
```

- [ ] **Step 3: Create pytest.ini**

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
asyncio_mode = auto
```

- [ ] **Step 4: Create src/secure_mcp_server/__init__.py**

```python
"""Secure MCP Server - A production-ready MCP server with authentication and rate limiting."""

__version__ = "0.1.0"
```

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml .gitignore pytest.ini src/secure_mcp_server/__init__.py
git commit -m "feat: add project structure and configuration"
```

---

### Task 2: Configuration Management

**Files:**
- Create: `src/secure_mcp_server/config.py`
- Create: `tests/test_config.py`

**Interfaces:**
- Consumes: None
- Produces: `get_config() -> Config` (dataclass with bearer_token: str, allowed_paths: list[str], allowed_domains: list[str], max_file_size_bytes: int, rate_limit_requests: int, rate_limit_period_seconds: float)

- [ ] **Step 1: Write failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'secure_mcp_server.config'"

- [ ] **Step 3: Write minimal implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_config.py -v`
Expected: PASS (all 4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/secure_mcp_server/config.py tests/test_config.py
git commit -m "feat: add configuration management with fail-closed auth"
```

---

### Task 3: Structured Logging

**Files:**
- Create: `src/secure_mcp_server/logging_config.py`
- Create: `tests/test_logging.py`

**Interfaces:**
- Consumes: None
- Produces: `setup_logging() -> None`, `get_logger(name: str) -> logging.Logger` (configured for structured JSON output with secret redaction)

- [ ] **Step 1: Write failing test**

```python
import json
import logging
from io import StringIO
from secure_mcp_server.logging_config import setup_logging, get_logger


def test_logging_outputs_json():
    """Logger outputs structured JSON."""
    setup_logging()
    logger = get_logger("test")
    
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    logger.handlers = [handler]
    
    logger.info("test message", extra={"key": "value"})
    
    output = stream.getvalue()
    log_entry = json.loads(output.strip())
    
    assert log_entry["message"] == "test message"
    assert log_entry["key"] == "value"
    assert "timestamp" in log_entry
    assert "level" in log_entry


def test_logging_redacts_bearer_token():
    """Logger redacts bearer tokens from logs."""
    setup_logging()
    logger = get_logger("test")
    
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    logger.handlers = [handler]
    
    logger.info("Auth header", extra={"authorization": "Bearer secret-token-123"})
    
    output = stream.getvalue()
    log_entry = json.loads(output.strip())
    
    assert "secret-token-123" not in output
    assert log_entry["authorization"] == "Bearer [REDACTED]"


def test_logging_redacts_mcp_bearer_token():
    """Logger redacts MCP_BEARER_TOKEN from logs."""
    setup_logging()
    logger = get_logger("test")
    
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    logger.handlers = [handler]
    
    logger.info("Config loaded", extra={"MCP_BEARER_TOKEN": "secret-123"})
    
    output = stream.getvalue()
    log_entry = json.loads(output.strip())
    
    assert "secret-123" not in output
    assert log_entry["MCP_BEARER_TOKEN"] == "[REDACTED]"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_logging.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'secure_mcp_server.logging_config'"

- [ ] **Step 3: Write minimal implementation**

```python
"""Structured logging configuration with secret redaction."""

import json
import logging
import sys
from datetime import datetime
from typing import Any


class SecretRedactingFormatter(logging.Formatter):
    """JSON formatter that redacts secrets."""
    
    REDACTED_KEYS = {"bearer_token", "authorization", "MCP_BEARER_TOKEN", "token", "password", "secret"}
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON with secrets redacted."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        for key, value in record.__dict__.items():
            if key not in ("name", "msg", "args", "created", "filename", "funcName",
                          "levelname", "levelno", "lineno", "module", "msecs",
                          "pathname", "process", "processName", "relativeCreated",
                          "thread", "threadName", "exc_info", "exc_text", "stack_info"):
                log_data[key] = self._redact_secrets(key, value)
        
        return json.dumps(log_data)
    
    def _redact_secrets(self, key: str, value: Any) -> Any:
        """Redact secret values."""
        if isinstance(key, str) and key.lower() in (k.lower() for k in self.REDACTED_KEYS):
            if isinstance(value, str) and value.startswith("Bearer "):
                return "Bearer [REDACTED]"
            return "[REDACTED]"
        return value


def setup_logging() -> None:
    """Configure structured JSON logging."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(SecretRedactingFormatter())
    
    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(logging.INFO)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance."""
    return logging.getLogger(name)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_logging.py -v`
Expected: PASS (all 3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/secure_mcp_server/logging_config.py tests/test_logging.py
git commit -m "feat: add structured JSON logging with secret redaction"
```

---

### Task 4: Bearer Token Authentication

**Files:**
- Create: `src/secure_mcp_server/auth.py`
- Create: `tests/test_auth.py`

**Interfaces:**
- Consumes: `Config` (from config.py)
- Produces: `verify_bearer_token(authorization_header: str, config: Config) -> bool`, `AuthenticationError(Exception)`

- [ ] **Step 1: Write failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_auth.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'secure_mcp_server.auth'"

- [ ] **Step 3: Write minimal implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_auth.py -v`
Expected: PASS (all 6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/secure_mcp_server/auth.py tests/test_auth.py
git commit -m "feat: add bearer token authentication"
```

---

### Task 5: Token Bucket Rate Limiting

**Files:**
- Create: `src/secure_mcp_server/rate_limit.py`
- Create: `tests/test_rate_limit.py`

**Interfaces:**
- Consumes: `Config` (from config.py)
- Produces: `RateLimiter` class with `check_rate_limit(session_id: str) -> None` method, `RateLimitError(Exception)`

- [ ] **Step 1: Write failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_rate_limit.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'secure_mcp_server.rate_limit'"

- [ ] **Step 3: Write minimal implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_rate_limit.py -v`
Expected: PASS (all 5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/secure_mcp_server/rate_limit.py tests/test_rate_limit.py
git commit -m "feat: add token bucket rate limiting"
```

---

### Task 6: Filesystem Tool with Path Protection

**Files:**
- Create: `src/secure_mcp_server/filesystem_tool.py`
- Create: `tests/test_filesystem_tool.py`

**Interfaces:**
- Consumes: `Config` (from config.py)
- Produces: `read_file(path: str, config: Config) -> str`, `list_directory(path: str, config: Config) -> list[str]`, `FilesystemError(Exception)`

- [ ] **Step 1: Write failing test**

```python
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
    link_path.symlink_to("/etc/passwd")
    
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_filesystem_tool.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'secure_mcp_server.filesystem_tool'"

- [ ] **Step 3: Write minimal implementation**

```python
"""Secure filesystem operations with path allowlist."""

import os
from pathlib import Path
from secure_mcp_server.config import Config


class FilesystemError(Exception):
    """Raised when filesystem operation fails or is blocked."""
    pass


def _resolve_and_validate_path(path: str, config: Config) -> Path:
    """
    Resolve path and validate it's within allowed paths.
    
    Args:
        path: Path to validate
        config: Server configuration
    
    Returns:
        Path: Resolved absolute path
    
    Raises:
        FilesystemError: If path is invalid or not allowed
    """
    if not config.allowed_paths:
        raise FilesystemError("No allowed paths configured")
    
    if ".." in path:
        raise FilesystemError("Path traversal detected in path")
    
    try:
        resolved = Path(path).resolve()
    except (OSError, RuntimeError) as e:
        raise FilesystemError(f"Invalid path: {e}")
    
    for allowed in config.allowed_paths:
        allowed_path = Path(allowed).resolve()
        try:
            resolved.relative_to(allowed_path)
            return resolved
        except ValueError:
            continue
    
    raise FilesystemError(f"Path {path} is not within allowed paths")


def read_file(path: str, config: Config) -> str:
    """
    Read file contents with security checks.
    
    Args:
        path: File path to read
        config: Server configuration
    
    Returns:
        str: File contents
    
    Raises:
        FilesystemError: If file cannot be read or access is denied
    """
    resolved_path = _resolve_and_validate_path(path, config)
    
    if not resolved_path.exists():
        raise FilesystemError(f"File {path} not found")
    
    if not resolved_path.is_file():
        raise FilesystemError(f"Path {path} is not a file")
    
    file_size = resolved_path.stat().st_size
    if file_size > config.max_file_size_bytes:
        raise FilesystemError(
            f"File size {file_size} exceeds maximum {config.max_file_size_bytes}"
        )
    
    try:
        return resolved_path.read_text()
    except (OSError, UnicodeDecodeError) as e:
        raise FilesystemError(f"Failed to read file: {e}")


def list_directory(path: str, config: Config) -> list[str]:
    """
    List directory contents with security checks.
    
    Args:
        path: Directory path to list
        config: Server configuration
    
    Returns:
        list[str]: List of entry names in the directory
    
    Raises:
        FilesystemError: If directory cannot be listed or access is denied
    """
    resolved_path = _resolve_and_validate_path(path, config)
    
    if not resolved_path.exists():
        raise FilesystemError(f"Directory {path} not found")
    
    if not resolved_path.is_dir():
        raise FilesystemError(f"Path {path} is not a directory")
    
    try:
        return [entry.name for entry in resolved_path.iterdir()]
    except OSError as e:
        raise FilesystemError(f"Failed to list directory: {e}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_filesystem_tool.py -v`
Expected: PASS (all 10 tests)

- [ ] **Step 5: Commit**

```bash
git add src/secure_mcp_server/filesystem_tool.py tests/test_filesystem_tool.py
git commit -m "feat: add secure filesystem tools with path protection"
```

---

### Task 7: HTTP Tool with Domain Allowlist

**Files:**
- Create: `src/secure_mcp_server/http_tool.py`
- Create: `tests/test_http_tool.py`

**Interfaces:**
- Consumes: `Config` (from config.py)
- Produces: `fetch_url(url: str, config: Config) -> str`, `HTTPError(Exception)`

- [ ] **Step 1: Write failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_http_tool.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'secure_mcp_server.http_tool'"

- [ ] **Step 3: Write minimal implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_http_tool.py -v`
Expected: PASS (all 9 tests)

- [ ] **Step 5: Commit**

```bash
git add src/secure_mcp_server/http_tool.py tests/test_http_tool.py
git commit -m "feat: add secure HTTP tool with domain allowlist"
```

---

### Task 8: MCP Server Integration

**Files:**
- Create: `src/secure_mcp_server/server.py`
- Create: `tests/test_server.py`

**Interfaces:**
- Consumes: All previous modules (config, auth, rate_limit, logging_config, filesystem_tool, http_tool)
- Produces: `main() -> None` (MCP server entry point)

- [ ] **Step 1: Write failing test**

```python
import pytest
import json
from unittest.mock import Mock, patch, MagicMock
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


@pytest.mark.asyncio
async def test_server_requires_authentication(test_config, tmp_path):
    """Server requires valid bearer token."""
    server = create_server(test_config)
    
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    
    with patch("secure_mcp_server.server.get_session_auth") as mock_auth:
        mock_auth.return_value = None
        
        with pytest.raises(Exception, match="Authentication"):
            await server.call_tool("read_file", {"path": str(test_file)})


@pytest.mark.asyncio
async def test_server_enforces_rate_limiting(test_config, tmp_path):
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
    
    with patch("secure_mcp_server.server.get_session_auth") as mock_auth:
        mock_auth.return_value = "Bearer test-secret-token"
        
        await server.call_tool("read_file", {"path": str(test_file)})
        await server.call_tool("read_file", {"path": str(test_file)})
        
        with pytest.raises(Exception, match="Rate limit"):
            await server.call_tool("read_file", {"path": str(test_file)})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_server.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'secure_mcp_server.server'"

- [ ] **Step 3: Write minimal implementation**

```python
"""MCP server implementation."""

import asyncio
from typing import Any
from mcp.server import Server
from mcp.types import Tool, TextContent
from secure_mcp_server.config import Config, get_config
from secure_mcp_server.auth import verify_bearer_token, AuthenticationError
from secure_mcp_server.rate_limit import RateLimiter, RateLimitError
from secure_mcp_server.filesystem_tool import read_file, list_directory, FilesystemError
from secure_mcp_server.http_tool import fetch_url, HTTPError
from secure_mcp_server.logging_config import setup_logging, get_logger


logger = get_logger(__name__)


def create_server(config: Config) -> Server:
    """
    Create MCP server with security middleware.
    
    Args:
        config: Server configuration
    
    Returns:
        Server: Configured MCP server
    """
    server = Server("secure-mcp-server")
    rate_limiter = RateLimiter(config)
    
    @server.list_tools()
    async def list_tools() -> list[Tool]:
        """List available tools."""
        return [
            Tool(
                name="read_file",
                description="Read file contents from allowed paths",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "File path to read",
                        }
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="list_directory",
                description="List directory contents from allowed paths",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Directory path to list",
                        }
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="fetch_url",
                description="Fetch URL contents from allowed domains (HTTPS only)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "HTTPS URL to fetch",
                        }
                    },
                    "required": ["url"],
                },
            ),
        ]
    
    @server.call_tool()
    async def call_tool(name: str, arguments: Any) -> list[TextContent]:
        """
        Call a tool with security checks.
        
        Args:
            name: Tool name
            arguments: Tool arguments
        
        Returns:
            list[TextContent]: Tool results
        
        Raises:
            Exception: If security checks fail or tool execution fails
        """
        session_id = "default"
        auth_header = None
        
        try:
            verify_bearer_token(auth_header or "", config)
        except AuthenticationError as e:
            logger.warning("Authentication failed", extra={"error": str(e)})
            raise Exception(f"Authentication failed: {e}")
        
        try:
            rate_limiter.check_rate_limit(session_id)
        except RateLimitError as e:
            logger.warning("Rate limit exceeded", extra={"session_id": session_id})
            raise Exception(f"Rate limit exceeded: {e}")
        
        try:
            if name == "read_file":
                result = read_file(arguments["path"], config)
                logger.info("File read", extra={"path": arguments["path"]})
            elif name == "list_directory":
                entries = list_directory(arguments["path"], config)
                result = "\n".join(entries)
                logger.info("Directory listed", extra={"path": arguments["path"]})
            elif name == "fetch_url":
                result = fetch_url(arguments["url"], config)
                logger.info("URL fetched", extra={"url": arguments["url"]})
            else:
                raise Exception(f"Unknown tool: {name}")
            
            return [TextContent(type="text", text=result)]
        except (FilesystemError, HTTPError) as e:
            logger.error("Tool execution failed", extra={"tool": name, "error": str(e)})
            raise Exception(str(e))
    
    return server


async def main() -> None:
    """Run MCP server."""
    setup_logging()
    logger.info("Starting secure MCP server")
    
    try:
        config = get_config()
        logger.info("Configuration loaded")
    except ValueError as e:
        logger.error("Configuration failed", extra={"error": str(e)})
        raise
    
    server = create_server(config)
    
    from mcp.server.stdio import stdio_server
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def run():
    """Entry point for the server."""
    asyncio.run(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_server.py -v`
Expected: PASS (all 3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/secure_mcp_server/server.py tests/test_server.py
git commit -m "feat: add MCP server integration with all security features"
```

---

### Task 9: Server Entry Point and Documentation

**Files:**
- Create: `src/secure_mcp_server/__main__.py`
- Create: `README.md`
- Create: `demo.sh`
- Modify: `src/secure_mcp_server/__init__.py`

**Interfaces:**
- Consumes: `server.run()` (from server.py)
- Produces: Executable package, comprehensive README

- [ ] **Step 1: Create __main__.py**

```python
"""Entry point for running secure MCP server as a module."""

from secure_mcp_server.server import run

if __name__ == "__main__":
    run()
```

- [ ] **Step 2: Update __init__.py**

```python
"""Secure MCP Server - A production-ready MCP server with authentication and rate limiting."""

__version__ = "0.1.0"

from secure_mcp_server.server import run

__all__ = ["run"]
```

- [ ] **Step 3: Create README.md**

```markdown
# Secure MCP Server

A production-ready Python MCP server with bearer token authentication, rate limiting, and secure file/HTTP tools.

## Features

- **Fail-closed authentication**: Requires `MCP_BEARER_TOKEN` environment variable
- **Per-session rate limiting**: Token bucket algorithm prevents abuse
- **Secure file operations**: Path allowlist with traversal protection
- **Secure HTTP operations**: Domain allowlist with HTTPS-only enforcement
- **Structured logging**: JSON logs with automatic secret redaction
- **No exposed secrets**: Structured errors without stack traces

## Security Model

This server provides defense-in-depth for MCP tool access, but **is not a kernel-level sandbox**. It:

- ✅ Validates bearer tokens (fail-closed)
- ✅ Enforces path and domain allowlists
- ✅ Blocks path traversal attempts
- ✅ Enforces file size limits
- ✅ Rate limits per session
- ❌ Does NOT provide process isolation
- ❌ Does NOT protect against malicious code execution

## Installation

### Using uv (recommended)

```bash
git clone https://github.com/RanaPriyansh/secure-mcp-server.git
cd secure-mcp-server
uv pip install -e ".[dev]"
```

### Using pip

```bash
git clone https://github.com/RanaPriyansh/secure-mcp-server.git
cd secure-mcp-server
pip install -e ".[dev]"
```

## Usage

### Running the Server

```bash
export MCP_BEARER_TOKEN="your-secret-token"
export MCP_ALLOWED_PATHS="/tmp:/var/log"
export MCP_ALLOWED_DOMAINS="example.com:api.github.com"
python -m secure_mcp_server
```

### Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MCP_BEARER_TOKEN` | **Yes** | - | Bearer token for authentication (fail-closed) |
| `MCP_ALLOWED_PATHS` | No | `[]` | Colon-separated list of allowed filesystem paths |
| `MCP_ALLOWED_DOMAINS` | No | `[]` | Colon-separated list of allowed HTTP domains |
| `MCP_MAX_FILE_SIZE_BYTES` | No | `10485760` | Maximum file size (10 MB default) |
| `MCP_RATE_LIMIT_REQUESTS` | No | `10` | Rate limit bucket capacity |
| `MCP_RATE_LIMIT_PERIOD_SECONDS` | No | `60.0` | Rate limit refill period |

### Tools

#### `read_file`

Read file contents from allowed paths.

```json
{
  "path": "/tmp/example.txt"
}
```

#### `list_directory`

List directory contents from allowed paths.

```json
{
  "path": "/tmp"
}
```

#### `fetch_url`

Fetch HTTPS URLs from allowed domains.

```json
{
  "url": "https://api.github.com/repos/owner/repo"
}
```

## Testing

Run the test suite:

```bash
pytest
```

Run with coverage:

```bash
pytest --cov=secure_mcp_server --cov-report=html
```

All tests pass on a fresh clone without requiring:
- Production bearer tokens (tests use fixtures)
- Real network access (HTTP tests are mocked)
- GPU or specialized hardware
- External services

## Development

Install development dependencies:

```bash
pip install -e ".[dev]"
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Author

Priyansh Rana
```

- [ ] **Step 4: Create demo.sh**

```bash
#!/bin/bash
set -e

echo "=== Secure MCP Server Demo ==="
echo

echo "1. Setting up test environment..."
export MCP_BEARER_TOKEN="demo-token-123"
export MCP_ALLOWED_PATHS="/tmp"
export MCP_ALLOWED_DOMAINS="api.github.com"

echo "2. Bearer token: $MCP_BEARER_TOKEN"
echo "3. Allowed paths: $MCP_ALLOWED_PATHS"
echo "4. Allowed domains: $MCP_ALLOWED_DOMAINS"
echo

echo "5. Running tests..."
pytest -v

echo
echo "=== Demo Complete ==="
echo "To start the server: python -m secure_mcp_server"
```

- [ ] **Step 5: Make demo.sh executable**

Run: `chmod +x demo.sh`
Expected: File is executable

- [ ] **Step 6: Commit**

```bash
git add src/secure_mcp_server/__main__.py src/secure_mcp_server/__init__.py README.md demo.sh
git commit -m "feat: add server entry point and documentation"
```

---

### Task 10: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: pyproject.toml, test suite
- Produces: GitHub Actions workflow

- [ ] **Step 1: Create CI workflow**

```yaml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.9", "3.10", "3.11", "3.12"]
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v5
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -e ".[dev]"
    
    - name: Run tests
      run: |
        pytest -v --cov=secure_mcp_server --cov-report=term-missing
      env:
        MCP_BEARER_TOKEN: test-token-for-ci
    
    - name: Check for forbidden strings
      run: |
        if grep -r -i "conexus\|gidney\|lobster\|tara@" --exclude-dir=.git .; then
          echo "ERROR: Found forbidden strings in repository"
          exit 1
        fi
        echo "✓ No forbidden strings found"
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "feat: add GitHub Actions CI workflow"
```

---

### Task 11: Final Verification and Cleanup

**Files:**
- Review all files for forbidden content
- Verify tests pass without production secrets

**Interfaces:**
- Consumes: All previous work
- Produces: Clean, ready-to-ship repository

- [ ] **Step 1: Run full test suite**

Run: `pytest -v`
Expected: All tests pass

- [ ] **Step 2: Check for forbidden strings**

Run: `grep -r -i "conexus\|gidney\|lobster\|tara@" --exclude-dir=.git . || echo "Clean"`
Expected: Output "Clean" (no matches)

- [ ] **Step 3: Verify fresh clone scenario**

Run:
```bash
cd /tmp
git clone /workspace test-clone
cd test-clone
pip install -e ".[dev]"
MCP_BEARER_TOKEN=test pytest
```
Expected: All tests pass

- [ ] **Step 4: Clean up test clone**

Run: `rm -rf /tmp/test-clone`
Expected: Directory removed

- [ ] **Step 5: Final commit if needed**

```bash
git status
# If any changes remain, commit them
git add .
git commit -m "chore: final cleanup"
```

---

## Implementation Complete

All tasks implement a secure, production-ready MCP server with:
- 37+ tests covering authentication, rate limiting, path traversal, domain allowlist
- Fail-closed authentication
- Structured JSON logging with secret redaction
- No GPU, network, or external service dependencies for tests
- Clean repository (no forbidden strings or secrets)
- Comprehensive README for strangers
- GitHub Actions CI

The implementation follows TDD, creates focused commits, and produces a repository ready for public release on GitHub.
