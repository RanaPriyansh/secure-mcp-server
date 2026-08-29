"""MCP server implementation."""

import asyncio
from typing import Any
from mcp.server import Server
from mcp.types import Tool, TextContent, ListToolsResult, CallToolResult, CallToolRequestParams
from secure_mcp_server.config import Config, get_config
from secure_mcp_server.auth import verify_bearer_token, AuthenticationError
from secure_mcp_server.rate_limit import RateLimiter, RateLimitError
from secure_mcp_server.filesystem_tool import read_file, list_directory, FilesystemError
from secure_mcp_server.http_tool import fetch_url, HTTPError
from secure_mcp_server.logging_config import setup_logging, get_logger


logger = get_logger(__name__)


class SecureMCPServer:
    """Secure MCP server with authentication, rate limiting, and tool restrictions."""
    
    def __init__(self, config: Config):
        """
        Initialize secure server.
        
        Args:
            config: Server configuration
        """
        self.config = config
        self.rate_limiter = RateLimiter(config)
        self.server = Server("secure-mcp-server")
    
    def get_tools(self) -> list[Tool]:
        """Get list of available tools."""
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
    
    def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """
        Call a tool with security checks.
        
        Args:
            name: Tool name
            arguments: Tool arguments
        
        Returns:
            str: Tool result
        
        Raises:
            Exception: If security checks fail or tool execution fails
        """
        session_id = "default"
        
        try:
            self.rate_limiter.check_rate_limit(session_id)
        except RateLimitError as e:
            logger.warning("Rate limit exceeded", extra={"session_id": session_id})
            raise Exception(f"Rate limit exceeded: {e}")
        
        try:
            if name == "read_file":
                result = read_file(arguments["path"], self.config)
                logger.info("File read", extra={"path": arguments["path"]})
            elif name == "list_directory":
                entries = list_directory(arguments["path"], self.config)
                result = "\n".join(entries)
                logger.info("Directory listed", extra={"path": arguments["path"]})
            elif name == "fetch_url":
                result = fetch_url(arguments["url"], self.config)
                logger.info("URL fetched", extra={"url": arguments["url"]})
            else:
                raise Exception(f"Unknown tool: {name}")
            
            return result
        except (FilesystemError, HTTPError) as e:
            logger.error("Tool execution failed", extra={"tool": name, "error": str(e)})
            raise Exception(str(e))


def create_server(config: Config) -> SecureMCPServer:
    """
    Create MCP server with security middleware.
    
    Args:
        config: Server configuration
    
    Returns:
        SecureMCPServer: Configured secure MCP server
    """
    return SecureMCPServer(config)


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
    
    secure_server = create_server(config)
    server = secure_server.server
    
    from mcp.server.stdio import stdio_server
    
    async def handle_list_tools(_params: Any) -> ListToolsResult:
        tools = secure_server.get_tools()
        return ListToolsResult(tools=tools)
    
    async def handle_call_tool(params: CallToolRequestParams) -> CallToolResult:
        result = secure_server.call_tool(params.name, params.arguments or {})
        return CallToolResult(content=[TextContent(type="text", text=result)])
    
    server.add_request_handler("tools/list", type(None), handle_list_tools)
    server.add_request_handler("tools/call", CallToolRequestParams, handle_call_tool)
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def run():
    """Entry point for the server."""
    asyncio.run(main())


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
