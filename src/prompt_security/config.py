"""Security configuration management."""

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, ClassVar


@dataclass
class SecurityConfig:
    """Security configuration with all settings."""

    CONFIG_PATH: ClassVar[Path] = Path.home() / ".claude" / ".mcp-security" / "config.json"

    # === LLM Screening Settings ===
    llm_screen_enabled: bool = False  # Disabled by default (opt-in)
    use_local_llm: bool = False       # Use Haiku by default
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:1b"
    screen_timeout: float = 5.0       # Seconds

    # === Detection Settings ===
    detection_enabled: bool = True    # Always on by default
    custom_patterns: list[list[str]] = field(default_factory=list)
    # Format: [["regex", "category", "severity"], ...]

    # === Allowlists (known-safe document IDs) ===
    allowlisted_documents: list[str] = field(default_factory=list)
    allowlisted_emails: list[str] = field(default_factory=list)
    allowlisted_tickets: list[str] = field(default_factory=list)

    # === Per-Service Toggle ===
    # If a service is listed here, security wrapping is DISABLED for it
    disabled_services: list[str] = field(default_factory=list)

    # === Per-Operation Toggle ===
    # Format: {"service.operation": false} to disable specific operations
    # e.g., {"gmail.read": false} disables wrapping for gmail.read only
    disabled_operations: dict[str, bool] = field(default_factory=dict)

    # === Caching Settings ===
    cache_enabled: bool = True
    cache_ttl_seconds: int = 900  # 15 minutes
    cache_max_size: int = 1000    # Max entries

    @classmethod
    def load(cls) -> "SecurityConfig":
        """Load configuration from file or create default."""
        if cls.CONFIG_PATH.exists():
            try:
                with open(cls.CONFIG_PATH) as f:
                    data = json.load(f)
                    return cls(**data)
            except (json.JSONDecodeError, TypeError):
                # Invalid config, return default
                return cls()
        return cls()

    def save(self) -> None:
        """Save configuration to file."""
        self.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(self.CONFIG_PATH, "w") as f:
            json.dump(asdict(self), f, indent=2)

    def is_service_enabled(self, service: str) -> bool:
        """Check if security is enabled for a service."""
        return service not in self.disabled_services

    def is_operation_enabled(self, operation: str) -> bool:
        """Check if security is enabled for an operation (e.g., 'gmail.read')."""
        # Check if explicitly disabled
        if operation in self.disabled_operations:
            return self.disabled_operations[operation]
        # Check if service is disabled
        service = operation.split(".")[0] if "." in operation else operation
        return self.is_service_enabled(service)

    def is_allowlisted(self, source_type: str, source_id: str) -> bool:
        """Check if a source is in the allowlist."""
        if source_type in ("email", "message"):
            return source_id in self.allowlisted_emails
        elif source_type in ("document", "docs", "spreadsheet", "sheets", "slides"):
            return source_id in self.allowlisted_documents
        elif source_type in ("ticket", "zendesk"):
            return source_id in self.allowlisted_tickets
        return False

    def get_custom_patterns(self) -> list[tuple[str, str, str]]:
        """Get custom patterns as list of tuples."""
        return [tuple(p) for p in self.custom_patterns if len(p) == 3]


def load_config() -> SecurityConfig:
    """Load security configuration (convenience function)."""
    return SecurityConfig.load()


def save_config(config: SecurityConfig) -> None:
    """Save security configuration (convenience function)."""
    config.save()
