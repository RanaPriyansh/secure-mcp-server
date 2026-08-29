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
