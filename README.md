# Secure MCP Server

A Python MCP server with bearer token authentication, rate limiting, and allowlisted file/HTTP tools.

## What This Is

Bearer auth + token-bucket rate limiting + path/domain allowlists for MCP tools. Fails closed: won't start without `MCP_BEARER_TOKEN`.

## What This Is NOT

**Not a sandbox.** This runs in your process space with your privileges. It will:

- ✅ Block requests without valid bearer token (fail-closed at startup)
- ✅ Rate-limit requests per session (token bucket)
- ✅ Enforce path and domain allowlists
- ✅ Block path traversal and symlink escapes
- ✅ Enforce file size limits
- ✅ Redact secrets from logs

But it will **not**:

- ❌ Provide process isolation or syscall filtering
- ❌ Prevent execution of malicious code in tool paths
- ❌ Protect against kernel exploits
- ❌ Stop filesystem access outside Python (if attacker gets code exec)
- ❌ Prevent memory corruption attacks

**Threat model**: A misbehaving MCP client that follows the protocol but tries to read/write wrong paths or hit wrong domains. Not a defense against arbitrary code execution or kernel-level attacks.

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

Tests run in-process with fixtures. No GPU, no network, no production secrets needed.

## Development

Install development dependencies:

```bash
pip install -e ".[dev]"
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Author

Priyansh Rana
