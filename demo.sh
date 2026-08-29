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
python3 -m pytest -v

echo
echo "=== Demo Complete ==="
echo "To start the server: python -m secure_mcp_server"
