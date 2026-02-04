"""Tests for LLM screening."""

from unittest.mock import patch, MagicMock

import httpx

from prompt_security.screening import (
    screen_content,
    screen_content_chunked,
    screen_content_haiku,
    screen_content_local,
    ScreenResult,
    _parse_screen_response,
    _split_into_chunks,
    HARMLESSNESS_PROMPT,
)
from prompt_security.config import SecurityConfig


class TestScreenResult:
    """Test ScreenResult dataclass."""

    def test_to_dict(self):
        """Test ScreenResult.to_dict() method."""
        result = ScreenResult(
            injection_detected=True,
            confidence=0.95,
            reason="Detected instruction override",
            source="haiku",
        )

        d = result.to_dict()
        assert d["injection_detected"] is True
        assert d["confidence"] == 0.95
        assert d["reason"] == "Detected instruction override"
        assert d["source"] == "haiku"


class TestParseScreenResponse:
    """Test _parse_screen_response function."""

    def test_valid_json(self):
        """Parse valid JSON response."""
        response = '{"injection_detected": true, "confidence": 0.8, "reason": "test"}'
        result = _parse_screen_response(response)

        assert result is not None
        assert result.injection_detected is True
        assert result.confidence == 0.8
        assert result.reason == "test"

    def test_json_in_code_block(self):
        """Parse JSON wrapped in markdown code block."""
        response = '''```json
{"injection_detected": false, "confidence": 0.1, "reason": "clean"}
```'''
        result = _parse_screen_response(response)

        assert result is not None
        assert result.injection_detected is False

    def test_invalid_json(self):
        """Return None for invalid JSON."""
        result = _parse_screen_response("not valid json")
        assert result is None

    def test_missing_fields(self):
        """Handle missing fields with defaults."""
        response = '{"injection_detected": true}'
        result = _parse_screen_response(response)

        assert result is not None
        assert result.injection_detected is True
        assert result.confidence == 0.0
        assert result.reason == "Unknown"


class TestScreenContentHaiku:
    """Test screen_content_haiku function."""

    def test_no_api_key(self):
        """Return None when no API key."""
        with patch.dict("os.environ", {}, clear=True):
            result = screen_content_haiku("test content")
            assert result is None

    def test_successful_response(self):
        """Test successful API response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "content": [{
                "text": '{"injection_detected": true, "confidence": 0.9, "reason": "test"}'
            }]
        }

        with patch.object(httpx, "post", return_value=mock_response):
            with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
                result = screen_content_haiku("test content")

        assert result is not None
        assert result.injection_detected is True
        assert result.source == "haiku"

    def test_api_error(self):
        """Return None on API error."""
        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch.object(httpx, "post", return_value=mock_response):
            with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
                result = screen_content_haiku("test content")

        assert result is None

    def test_content_truncation(self):
        """Test that content is truncated to 3000 chars."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "content": [{"text": '{"injection_detected": false, "confidence": 0.1, "reason": "ok"}'}]
        }

        long_content = "x" * 5000

        with patch.object(httpx, "post", return_value=mock_response) as mock_post:
            with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
                screen_content_haiku(long_content)

        # Check the content was truncated in the request
        call_args = mock_post.call_args
        request_body = call_args[1]["json"]
        prompt = request_body["messages"][0]["content"]
        # The prompt should contain truncated content (3000 chars max)
        assert len(prompt) < len(HARMLESSNESS_PROMPT.format(content=long_content))


class TestScreenContentLocal:
    """Test screen_content_local function."""

    def test_successful_response(self):
        """Test successful Ollama response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": '{"injection_detected": false, "confidence": 0.2, "reason": "clean"}'
        }

        with patch.object(httpx, "post", return_value=mock_response):
            result = screen_content_local("test content")

        assert result is not None
        assert result.injection_detected is False
        assert "ollama" in result.source

    def test_ollama_error(self):
        """Return None on Ollama error."""
        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch.object(httpx, "post", return_value=mock_response):
            result = screen_content_local("test content")

        assert result is None

    def test_custom_model(self):
        """Test custom model name in source."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": '{"injection_detected": false, "confidence": 0.1, "reason": "ok"}'
        }

        with patch.object(httpx, "post", return_value=mock_response):
            result = screen_content_local("test", model="custom-model:7b")

        assert result is not None
        assert result.source == "ollama:custom-model:7b"


class TestScreenContent:
    """Test screen_content function."""

    def test_disabled_returns_none(self):
        """Return None when screening is disabled."""
        config = SecurityConfig(llm_screen_enabled=False)
        result = screen_content("test content", config)
        assert result is None

    @patch("prompt_security.screening.screen_content_haiku")
    @patch("prompt_security.screening.get_cache")
    def test_uses_cache(self, mock_get_cache, mock_haiku):
        """Test that cache is used."""
        mock_cache = MagicMock()
        mock_cache.get.return_value = {
            "injection_detected": True,
            "confidence": 0.9,
            "reason": "cached",
        }
        mock_get_cache.return_value = mock_cache

        config = SecurityConfig(llm_screen_enabled=True, cache_enabled=True)
        result = screen_content("test content", config)

        assert result is not None
        assert result.source == "cache"
        mock_haiku.assert_not_called()

    @patch("prompt_security.screening.screen_content_haiku")
    @patch("prompt_security.screening.get_cache")
    def test_caches_result(self, mock_get_cache, mock_haiku):
        """Test that results are cached."""
        mock_cache = MagicMock()
        mock_cache.get.return_value = None
        mock_get_cache.return_value = mock_cache

        mock_haiku.return_value = ScreenResult(
            injection_detected=False,
            confidence=0.1,
            reason="ok",
            source="haiku",
        )

        config = SecurityConfig(llm_screen_enabled=True, cache_enabled=True)
        screen_content("test content", config)

        mock_cache.set.assert_called_once()

    @patch("prompt_security.screening.screen_content_local")
    @patch("prompt_security.screening.get_cache")
    def test_uses_local_llm(self, mock_get_cache, mock_local):
        """Test that local LLM is used when configured."""
        mock_cache = MagicMock()
        mock_cache.get.return_value = None
        mock_get_cache.return_value = mock_cache

        mock_local.return_value = ScreenResult(
            injection_detected=False,
            confidence=0.1,
            reason="ok",
            source="ollama:llama",
        )

        config = SecurityConfig(
            llm_screen_enabled=True,
            use_local_llm=True,
            ollama_url="http://test:11434",
            ollama_model="test-model",
        )
        result = screen_content("test content", config)

        mock_local.assert_called_once()
        assert "ollama" in result.source


def test_harmlessness_prompt_format():
    """Test that HARMLESSNESS_PROMPT has content placeholder."""
    assert "{content}" in HARMLESSNESS_PROMPT
    formatted = HARMLESSNESS_PROMPT.format(content="test")
    assert "test" in formatted


def test_prompt_has_calibration_examples():
    """Verify prompt contains both malicious and clean calibration examples."""
    # Should have high-confidence malicious examples
    assert "0.95" in HARMLESSNESS_PROMPT
    assert "0.90" in HARMLESSNESS_PROMPT
    # Should have clean examples scored at 0.0
    assert "0.0" in HARMLESSNESS_PROMPT
    # Should still have the JSON response format
    assert "injection_detected" in HARMLESSNESS_PROMPT


def test_prompt_covers_key_attack_types():
    """Verify calibration examples cover key attack vectors."""
    prompt_lower = HARMLESSNESS_PROMPT.lower()
    # Instruction override
    assert "ignore all previous instructions" in prompt_lower
    # Jailbreak / DAN
    assert "dan" in prompt_lower
    # Code comment injection
    assert "<!--" in HARMLESSNESS_PROMPT
    # False authority
    assert "anthropic" in prompt_lower
    # Exfiltration
    assert "forward" in prompt_lower or "external-server" in prompt_lower


class TestSplitIntoChunks:
    """Test _split_into_chunks function."""

    def test_short_content_single_chunk(self):
        """Short content should return single chunk."""
        content = "Short content"
        chunks = _split_into_chunks(content, chunk_size=1000)
        assert len(chunks) == 1
        assert chunks[0] == content

    def test_long_content_multiple_chunks(self):
        """Long content should be split into multiple chunks."""
        content = "A" * 5000
        chunks = _split_into_chunks(content, chunk_size=1000, overlap=100)
        assert len(chunks) > 1
        # Each chunk should be at most chunk_size
        for chunk in chunks:
            assert len(chunk) <= 1000

    def test_chunks_overlap(self):
        """Chunks should overlap to catch boundary injections."""
        content = "0123456789" * 100  # 1000 chars
        chunks = _split_into_chunks(content, chunk_size=300, overlap=50)

        # Check that consecutive chunks overlap
        for i in range(len(chunks) - 1):
            # End of chunk i should match start of chunk i+1
            assert chunks[i][-50:] == chunks[i + 1][:50]


class TestScreenContentChunked:
    """Test screen_content_chunked function."""

    def test_disabled_returns_none(self):
        """Return None when screening is disabled."""
        config = SecurityConfig(llm_screen_enabled=False)
        result = screen_content_chunked("test content", config)
        assert result is None

    @patch("prompt_security.screening.screen_content")
    def test_stops_on_detection(self, mock_screen):
        """Should stop early when injection is detected."""
        # First chunk clean, second chunk has injection
        mock_screen.side_effect = [
            ScreenResult(False, 0.1, "clean", "haiku"),
            ScreenResult(True, 0.9, "injection found", "haiku"),
            ScreenResult(False, 0.1, "clean", "haiku"),  # Should not be called
        ]

        config = SecurityConfig(llm_screen_enabled=True, cache_enabled=False)
        content = "A" * 10000  # Large content

        result = screen_content_chunked(content, config)

        assert result is not None
        assert result.injection_detected is True
        assert result.chunk_index == 1
        assert "chunked" in result.source
        # Should only have called screen_content twice
        assert mock_screen.call_count == 2

    @patch("prompt_security.screening.screen_content")
    def test_all_chunks_clean(self, mock_screen):
        """Should return clean result when all chunks are clean."""
        mock_screen.return_value = ScreenResult(False, 0.1, "clean", "haiku")

        config = SecurityConfig(llm_screen_enabled=True, cache_enabled=False)
        content = "A" * 10000

        result = screen_content_chunked(content, config)

        assert result is not None
        assert result.injection_detected is False
        assert result.total_chunks is not None
        assert result.total_chunks > 1

    @patch("prompt_security.screening.screen_content")
    def test_max_chunks_limit(self, mock_screen):
        """Should respect max_chunks limit."""
        mock_screen.return_value = ScreenResult(False, 0.1, "clean", "haiku")

        config = SecurityConfig(llm_screen_enabled=True, cache_enabled=False)
        content = "A" * 50000  # Very large content

        result = screen_content_chunked(content, config, max_chunks=3)

        assert result is not None
        # Should only screen 3 chunks
        assert mock_screen.call_count == 3

    def test_result_includes_chunk_info(self):
        """ScreenResult should include chunk information."""
        result = ScreenResult(
            injection_detected=True,
            confidence=0.9,
            reason="test",
            source="chunked:haiku",
            chunk_index=2,
            total_chunks=5,
        )

        d = result.to_dict()
        assert d["chunk_index"] == 2
        assert d["total_chunks"] == 5
