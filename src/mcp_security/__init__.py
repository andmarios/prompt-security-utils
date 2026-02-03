"""MCP Security Utilities - Prompt injection protection for MCP skills."""

from mcp_security.wrapping import (
    wrap_untrusted_content,
    WrappedContent,
    CONTENT_START_MARKER,
    CONTENT_END_MARKER,
)
from mcp_security.detection import (
    detect_suspicious_content,
    DetectionResult,
    SUSPICIOUS_PATTERNS,
    Severity,
)
from mcp_security.screening import (
    screen_content,
    screen_content_haiku,
    screen_content_local,
    ScreenResult,
)
from mcp_security.config import (
    SecurityConfig,
    load_config,
    save_config,
)
from mcp_security.cache import (
    ScreeningCache,
    get_cache,
)
from mcp_security.output import (
    output_external_content,
    wrap_field,
    wrap_fields,
)

__all__ = [
    # Wrapping
    "wrap_untrusted_content",
    "WrappedContent",
    "CONTENT_START_MARKER",
    "CONTENT_END_MARKER",
    # Detection
    "detect_suspicious_content",
    "DetectionResult",
    "SUSPICIOUS_PATTERNS",
    "Severity",
    # Screening
    "screen_content",
    "screen_content_haiku",
    "screen_content_local",
    "ScreenResult",
    # Config
    "SecurityConfig",
    "load_config",
    "save_config",
    # Cache
    "ScreeningCache",
    "get_cache",
    # Output
    "output_external_content",
    "wrap_field",
    "wrap_fields",
]

__version__ = "0.1.0"
