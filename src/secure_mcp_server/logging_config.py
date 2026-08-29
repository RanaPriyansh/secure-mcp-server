"""Structured logging configuration with secret redaction."""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class SecretRedactingFormatter(logging.Formatter):
    """JSON formatter that redacts secrets."""
    
    REDACTED_KEYS = {"bearer_token", "authorization", "MCP_BEARER_TOKEN", "token", "password", "secret"}
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON with secrets redacted."""
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
