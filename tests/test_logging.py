import json
import logging
from io import StringIO
from secure_mcp_server.logging_config import setup_logging, get_logger, SecretRedactingFormatter


def test_logging_outputs_json():
    """Logger outputs structured JSON."""
    logger = get_logger("test")
    
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SecretRedactingFormatter())
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    
    logger.info("test message", extra={"key": "value"})
    
    output = stream.getvalue()
    log_entry = json.loads(output.strip())
    
    assert log_entry["message"] == "test message"
    assert log_entry["key"] == "value"
    assert "timestamp" in log_entry
    assert "level" in log_entry


def test_logging_redacts_bearer_token():
    """Logger redacts bearer tokens from logs."""
    logger = get_logger("test")
    
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SecretRedactingFormatter())
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    
    logger.info("Auth header", extra={"authorization": "Bearer secret-token-123"})
    
    output = stream.getvalue()
    log_entry = json.loads(output.strip())
    
    assert "secret-token-123" not in output
    assert log_entry["authorization"] == "Bearer [REDACTED]"


def test_logging_redacts_mcp_bearer_token():
    """Logger redacts MCP_BEARER_TOKEN from logs."""
    logger = get_logger("test")
    
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SecretRedactingFormatter())
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    
    logger.info("Config loaded", extra={"MCP_BEARER_TOKEN": "secret-123"})
    
    output = stream.getvalue()
    log_entry = json.loads(output.strip())
    
    assert "secret-123" not in output
    assert log_entry["MCP_BEARER_TOKEN"] == "[REDACTED]"
