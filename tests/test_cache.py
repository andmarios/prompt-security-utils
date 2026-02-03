"""Tests for screening cache."""

import time
import threading

from prompt_security.cache import ScreeningCache, CacheEntry, get_cache


class TestCacheEntry:
    """Test CacheEntry dataclass."""

    def test_is_expired_false(self):
        """Entry should not be expired within TTL."""
        entry = CacheEntry(result={"test": True}, created_at=time.time())
        assert entry.is_expired(ttl_seconds=60) is False

    def test_is_expired_true(self):
        """Entry should be expired after TTL."""
        entry = CacheEntry(result={"test": True}, created_at=time.time() - 120)
        assert entry.is_expired(ttl_seconds=60) is True


class TestScreeningCache:
    """Test ScreeningCache class."""

    def test_set_get(self):
        """Test basic set and get operations."""
        cache = ScreeningCache(max_size=100, ttl_seconds=900)
        result = {"injection_detected": False, "confidence": 0.1}

        cache.set("test content", result)
        retrieved = cache.get("test content")

        assert retrieved == result

    def test_get_nonexistent(self):
        """Test get for non-existent key returns None."""
        cache = ScreeningCache()
        assert cache.get("nonexistent") is None

    def test_cache_expiration(self):
        """Test TTL expiration."""
        cache = ScreeningCache(max_size=100, ttl_seconds=1)
        cache.set("test", {"test": True})

        # Should exist immediately
        assert cache.get("test") is not None

        # Wait for expiration
        time.sleep(1.5)

        # Should be expired
        assert cache.get("test") is None

    def test_lru_eviction(self):
        """Test LRU eviction when cache is full."""
        cache = ScreeningCache(max_size=3, ttl_seconds=900)

        cache.set("first", {"order": 1})
        cache.set("second", {"order": 2})
        cache.set("third", {"order": 3})

        # Access first to make it recently used
        cache.get("first")

        # Add fourth - should evict "second" (least recently used)
        cache.set("fourth", {"order": 4})

        assert cache.get("first") is not None
        assert cache.get("second") is None  # Evicted
        assert cache.get("third") is not None
        assert cache.get("fourth") is not None

    def test_clear(self):
        """Test cache clearing."""
        cache = ScreeningCache()
        cache.set("test1", {"a": 1})
        cache.set("test2", {"b": 2})

        assert len(cache) == 2

        cache.clear()

        assert len(cache) == 0
        assert cache.get("test1") is None
        assert cache.get("test2") is None

    def test_len(self):
        """Test __len__ method."""
        cache = ScreeningCache()
        assert len(cache) == 0

        cache.set("test1", {"a": 1})
        assert len(cache) == 1

        cache.set("test2", {"b": 2})
        assert len(cache) == 2

    def test_content_hash_consistency(self):
        """Test that same content produces same hash."""
        cache = ScreeningCache()
        content = "test content"

        hash1 = cache._content_hash(content)
        hash2 = cache._content_hash(content)

        assert hash1 == hash2

    def test_content_hash_different_content(self):
        """Test that different content produces different hash."""
        cache = ScreeningCache()

        hash1 = cache._content_hash("content 1")
        hash2 = cache._content_hash("content 2")

        assert hash1 != hash2

    def test_thread_safety(self):
        """Test concurrent access to cache."""
        cache = ScreeningCache(max_size=1000, ttl_seconds=900)
        errors = []

        def writer(thread_id):
            try:
                for i in range(100):
                    cache.set(f"key_{thread_id}_{i}", {"thread": thread_id, "i": i})
            except Exception as e:
                errors.append(e)

        def reader(thread_id):
            try:
                for i in range(100):
                    cache.get(f"key_{thread_id}_{i}")
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(5):
            threads.append(threading.Thread(target=writer, args=(i,)))
            threads.append(threading.Thread(target=reader, args=(i,)))

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        assert len(errors) == 0


class TestGetCache:
    """Test get_cache function."""

    def test_returns_singleton(self):
        """Test that get_cache returns the same instance."""
        # Reset global cache for test
        import prompt_security.cache as cache_module
        cache_module._cache = None

        cache1 = get_cache()
        cache2 = get_cache()

        assert cache1 is cache2

    def test_uses_provided_settings_on_first_call(self):
        """Test that settings are used on first call."""
        import prompt_security.cache as cache_module
        cache_module._cache = None

        cache = get_cache(max_size=50, ttl_seconds=100)

        assert cache._max_size == 50
        assert cache._ttl_seconds == 100

        # Cleanup
        cache_module._cache = None

    def test_ignores_settings_on_subsequent_calls(self):
        """Test that settings are ignored after first call."""
        import prompt_security.cache as cache_module
        cache_module._cache = None

        cache1 = get_cache(max_size=50, ttl_seconds=100)
        cache2 = get_cache(max_size=999, ttl_seconds=999)

        # Second call settings should be ignored
        assert cache2._max_size == 50
        assert cache2._ttl_seconds == 100

        # Cleanup
        cache_module._cache = None
