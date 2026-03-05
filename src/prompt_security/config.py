"""Security configuration management."""

import json
import secrets
from dataclasses import dataclass, field, fields, asdict
from pathlib import Path
from typing import ClassVar

# Base marker templates — the {id} is replaced with a random hex string
_MARKER_START_TEMPLATE = "<<<EXTERNAL_CONTENT_{id}>>>"
_MARKER_END_TEMPLATE = "<<<END_EXTERNAL_CONTENT_{id}>>>"

# Fallback markers used when SecurityConfig() is constructed directly
# without going through load(). Prefer load() for randomized markers.
_FALLBACK_START_MARKER = "<<<EXTERNAL_CONTENT>>>"
_FALLBACK_END_MARKER = "<<<END_EXTERNAL_CONTENT>>>"


def _generate_marker_id() -> str:
    """Generate a random hex string for marker uniqueness."""
    return secrets.token_hex(8)


def generate_markers(marker_id: str | None = None) -> tuple[str, str]:
    """Generate a pair of unique content markers.

    Args:
        marker_id: Optional fixed ID. If None, a random one is generated.

    Returns:
        Tuple of (start_marker, end_marker).
    """
    mid = marker_id or _generate_marker_id()
    return (
        _MARKER_START_TEMPLATE.format(id=mid),
        _MARKER_END_TEMPLATE.format(id=mid),
    )


@dataclass
class SecurityConfig:
    """Security configuration with generic security settings.

    Service-specific settings (allowlists, disabled operations) belong in the
    consuming services (e.g., google-workspace, zendesk-skill).
    """

    CONFIG_PATH: ClassVar[Path] = Path.home() / ".config" / "prompt-security-utils" / "config.json"
    _LEGACY_CONFIG_PATH: ClassVar[Path] = Path.home() / ".claude" / ".prompt-security" / "config.json"

    # === Content Markers ===
    # Randomized automatically on first load(). Clients can override these.
    content_start_marker: str = _FALLBACK_START_MARKER
    content_end_marker: str = _FALLBACK_END_MARKER

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
        # Migrate from old location if needed
        if cls._LEGACY_CONFIG_PATH.exists() and not cls.CONFIG_PATH.exists():
            import shutil
            import sys
            try:
                cls.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(cls._LEGACY_CONFIG_PATH, cls.CONFIG_PATH)
                print(
                    f"[prompt-security-utils] Migrated config from "
                    f"{cls._LEGACY_CONFIG_PATH} to {cls.CONFIG_PATH}",
                    file=sys.stderr,
                )
            except OSError as e:
                print(
                    f"[prompt-security-utils] Warning: failed to migrate config: {e}",
                    file=sys.stderr,
                )

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

        # No config file exists — create one with randomized markers
        start, end = generate_markers()
        config = cls(content_start_marker=start, content_end_marker=end)
        try:
            config.save()
        except OSError as e:
            import sys
            print(
                f"[prompt-security-utils] Warning: could not save initial config: {e}",
                file=sys.stderr,
            )
        return config

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
