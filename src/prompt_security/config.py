"""Security configuration management."""

import json
from dataclasses import dataclass, field, fields, asdict
from pathlib import Path
from typing import ClassVar


@dataclass
class SecurityConfig:
    """Security configuration with generic security settings.

    Service-specific settings (allowlists, disabled operations) belong in the
    consuming services (e.g., google-workspace, zendesk-skill).
    """

    CONFIG_PATH: ClassVar[Path] = Path.home() / ".claude" / ".prompt-security" / "config.json"

    # === Content Markers ===
    # IMPORTANT: Change these from defaults to prevent marker injection attacks
    # Use unique, secret values that attackers cannot guess
    content_start_marker: str = "<<<EXTERNAL_CONTENT>>>"
    content_end_marker: str = "<<<END_EXTERNAL_CONTENT>>>"

    # === LLM Screening Settings ===
    llm_screen_enabled: bool = False  # Disabled by default (opt-in)
    llm_screen_chunked: bool = True   # Use chunked screening for large content
    llm_screen_max_chunks: int = 10   # Max chunks to screen (0 = unlimited)
    use_local_llm: bool = False       # Use Haiku by default
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:1b"
    screen_timeout: float = 5.0       # Seconds

    # === Detection Settings ===
    detection_enabled: bool = True    # Always on by default
    custom_patterns: list[list[str]] = field(default_factory=list)
    # Format: [["regex", "category", "severity"], ...]

    # === Semantic Similarity Settings ===
    semantic_enabled: bool = True           # Enabled by default
    semantic_model: str = "BAAI/bge-small-en-v1.5"  # fastembed transformer model
    semantic_threshold: float = 0.72        # Global floor (per-pattern can be stricter)
    semantic_top_k: int = 3                 # Number of nearest neighbors to check
    semantic_custom_patterns_path: str = "" # Additional pattern bank (JSON)

    # === Caching Settings ===
    cache_enabled: bool = True
    cache_ttl_seconds: int = 900  # 15 minutes
    cache_max_size: int = 1000    # Max entries

    @classmethod
    def load(cls) -> "SecurityConfig":
        """Load configuration from file or create default.

        Unknown fields in the config file are ignored to allow graceful migration.
        """
        if cls.CONFIG_PATH.exists():
            try:
                with open(cls.CONFIG_PATH) as f:
                    data = json.load(f)
                    # Filter to only known fields
                    valid_fields = {f.name for f in fields(cls)}
                    filtered_data = {k: v for k, v in data.items() if k in valid_fields}
                    return cls(**filtered_data)
            except (json.JSONDecodeError, TypeError):
                # Invalid config, return default
                return cls()
        return cls()

    def save(self) -> None:
        """Save configuration to file."""
        self.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(self.CONFIG_PATH, "w") as f:
            json.dump(asdict(self), f, indent=2)

    def get_custom_patterns(self) -> list[tuple[str, str, str]]:
        """Get custom patterns as list of tuples."""
        return [tuple(p) for p in self.custom_patterns if len(p) == 3]


def load_config() -> SecurityConfig:
    """Load security configuration (convenience function)."""
    return SecurityConfig.load()


def save_config(config: SecurityConfig) -> None:
    """Save security configuration (convenience function)."""
    config.save()
