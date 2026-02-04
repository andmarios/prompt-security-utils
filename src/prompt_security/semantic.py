"""Semantic similarity detection for prompt injection patterns."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import numpy as np

from prompt_security.config import SecurityConfig, load_config
from prompt_security.detection import Severity

logger = logging.getLogger(__name__)


@dataclass
class PatternEntry:
    """A single pattern in the injection pattern bank."""

    text: str
    category: str
    severity: str  # "high", "medium", "low"
    threshold: float | None = None  # Per-pattern override (None = use global)


@dataclass
class SemanticResult:
    """Result of semantic similarity screening."""

    injection_detected: bool
    confidence: float  # Highest cosine similarity found
    matched_pattern: str  # Nearest pattern text
    category: str  # Category of matched pattern
    severity: Severity
    source: str = "semantic"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for JSON serialization."""
        return {
            "injection_detected": self.injection_detected,
            "confidence": self.confidence,
            "matched_pattern": self.matched_pattern,
            "category": self.category,
            "severity": self.severity.value,
            "source": self.source,
        }


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Compute cosine similarity between vector a (1, dim) and matrix b (N, dim).

    Returns array of shape (N,) with similarities.
    """
    a_norm = np.linalg.norm(a, axis=1, keepdims=True)
    b_norm = np.linalg.norm(b, axis=1, keepdims=True)

    # Avoid division by zero
    a_norm = np.maximum(a_norm, 1e-10)
    b_norm = np.maximum(b_norm, 1e-10)

    a_normalized = a / a_norm
    b_normalized = b / b_norm

    return (a_normalized @ b_normalized.T)[0]  # (N,)


class SemanticEngine:
    """Semantic similarity engine for detecting injection patterns.

    Singleton. Lazy-loads model and pattern bank on first screen() call.
    Uses fastembed for transformer-based embeddings via onnxruntime (no torch).
    """

    _instance: ClassVar[SemanticEngine | None] = None
    _instance_model: ClassVar[str | None] = None

    def __init__(self, config: SecurityConfig) -> None:
        self._model: Any = None  # TextEmbedding, lazy-loaded
        self._patterns: list[PatternEntry] = []
        self._pattern_embeddings: np.ndarray | None = None
        self._config = config

    @classmethod
    def get(cls, config: SecurityConfig) -> SemanticEngine:
        """Get or create singleton instance. Recreates if model config changes."""
        if cls._instance is None or cls._instance_model != config.semantic_model:
            cls._instance = cls(config)
            cls._instance_model = config.semantic_model
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        cls._instance = None
        cls._instance_model = None

    def _ensure_loaded(self) -> None:
        """Lazy-load model and pattern bank on first use."""
        if self._model is not None:
            return

        from fastembed import TextEmbedding

        self._model = TextEmbedding(model_name=self._config.semantic_model)
        self._patterns = self._load_patterns()

        if self._patterns:
            texts = [p.text for p in self._patterns]
            self._pattern_embeddings = np.array(list(self._model.embed(texts)))
        else:
            self._pattern_embeddings = np.array([])

    def _load_patterns(self) -> list[PatternEntry]:
        """Load built-in patterns + optional custom patterns."""
        patterns: list[PatternEntry] = []

        # Built-in patterns (shipped with package)
        builtin_path = Path(__file__).parent / "patterns" / "injection_patterns.json"
        if builtin_path.exists():
            patterns.extend(self._read_pattern_file(builtin_path))

        # Custom patterns (user-provided)
        if self._config.semantic_custom_patterns_path:
            custom_path = Path(self._config.semantic_custom_patterns_path).expanduser()
            if custom_path.exists():
                patterns.extend(self._read_pattern_file(custom_path))

        return patterns

    @staticmethod
    def _read_pattern_file(path: Path) -> list[PatternEntry]:
        """Read and parse a pattern bank JSON file."""
        try:
            with open(path) as f:
                data = json.load(f)

            entries = []
            for item in data:
                if not isinstance(item, dict) or "text" not in item:
                    continue
                entries.append(PatternEntry(
                    text=item["text"],
                    category=item.get("category", "unknown"),
                    severity=item.get("severity", "medium"),
                    threshold=item.get("threshold"),
                ))
            return entries
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load pattern file %s: %s", path, e)
            return []

    def screen(self, content: str) -> SemanticResult | None:
        """Screen content against the injection pattern bank.

        Returns SemanticResult with injection_detected=True if any pattern
        exceeds its threshold, or injection_detected=False with the best
        match for diagnostics. Returns None if no patterns are loaded.
        """
        if not content or not content.strip():
            return SemanticResult(
                injection_detected=False,
                confidence=0.0,
                matched_pattern="",
                category="",
                severity=Severity.LOW,
            )

        self._ensure_loaded()

        if not self._patterns or self._pattern_embeddings is None or len(self._pattern_embeddings) == 0:
            return None

        # Embed content
        content_emb = np.array(list(self._model.embed([content])))

        # Cosine similarity against all patterns
        similarities = _cosine_similarity(content_emb, self._pattern_embeddings)

        # Check top-k, respecting per-pattern thresholds
        k = min(self._config.semantic_top_k, len(self._patterns))
        top_indices = np.argsort(similarities)[-k:][::-1]
        global_threshold = self._config.semantic_threshold

        for idx in top_indices:
            score = float(similarities[idx])
            pattern = self._patterns[idx]
            # Per-pattern threshold can only be stricter than global floor
            pattern_threshold = pattern.threshold if pattern.threshold is not None else global_threshold
            threshold = max(pattern_threshold, global_threshold)

            if score >= threshold:
                return SemanticResult(
                    injection_detected=True,
                    confidence=score,
                    matched_pattern=pattern.text,
                    category=pattern.category,
                    severity=Severity[pattern.severity.upper()],
                )

        # No match — return best score for diagnostics
        best_idx = int(top_indices[0])
        return SemanticResult(
            injection_detected=False,
            confidence=float(similarities[best_idx]),
            matched_pattern=self._patterns[best_idx].text,
            category=self._patterns[best_idx].category,
            severity=Severity.LOW,
        )


def screen_content_semantic(
    content: str,
    config: SecurityConfig | None = None,
) -> SemanticResult | None:
    """Screen content using semantic similarity against injection pattern bank.

    Convenience function that handles config loading and engine instantiation.
    Returns None if semantic screening is disabled.
    """
    config = config or load_config()
    if not config.semantic_enabled:
        return None
    engine = SemanticEngine.get(config)
    return engine.screen(content)
