"""LRU cache for LLM screening results."""

import hashlib
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any


@dataclass
class CacheEntry:
    """Single cache entry with expiration."""
    result: dict[str, Any]
    created_at: float

    def is_expired(self, ttl_seconds: int) -> bool:
        """Check if entry has expired."""
        return time.time() - self.created_at > ttl_seconds


class ScreeningCache:
    """Thread-safe LRU cache for screening results."""

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 900):
        """
        Initialize cache.

        Args:
            max_size: Maximum number of entries
            ttl_seconds: Time-to-live for entries (default 15 minutes)
        """
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._lock = threading.Lock()

    def _content_hash(self, content: str) -> str:
        """Generate hash key for content."""
        return hashlib.sha256(content.encode()).hexdigest()[:32]

    def get(self, content: str) -> dict[str, Any] | None:
        """
        Get cached result for content.

        Returns:
            Cached result dict or None if not found/expired
        """
        key = self._content_hash(content)

        with self._lock:
            if key not in self._cache:
                return None

            entry = self._cache[key]

            # Check expiration
            if entry.is_expired(self._ttl_seconds):
                del self._cache[key]
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            return entry.result

    def set(self, content: str, result: dict[str, Any]) -> None:
        """
        Cache a screening result.

        Args:
            content: The content that was screened
            result: The screening result to cache
        """
        key = self._content_hash(content)

        with self._lock:
            # Remove oldest entries if at capacity
            while len(self._cache) >= self._max_size:
                self._cache.popitem(last=False)

            self._cache[key] = CacheEntry(
                result=result,
                created_at=time.time(),
            )

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        """Return number of cached entries."""
        with self._lock:
            return len(self._cache)


# Global cache instance
_cache: ScreeningCache | None = None


def get_cache(max_size: int = 1000, ttl_seconds: int = 900) -> ScreeningCache:
    """
    Get or create the global cache instance.

    Args:
        max_size: Maximum entries (only used on first call)
        ttl_seconds: TTL in seconds (only used on first call)

    Returns:
        Global ScreeningCache instance
    """
    global _cache
    if _cache is None:
        _cache = ScreeningCache(max_size=max_size, ttl_seconds=ttl_seconds)
    return _cache
