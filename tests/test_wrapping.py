"""Tests for content wrapping."""

from prompt_security.wrapping import (
    wrap_untrusted_content,
    WrappedContent,
)


def test_wrap_untrusted_content_includes_markers():
    """Verify all required fields are present."""
    result = wrap_untrusted_content("Hello world", "email", "msg123")

    assert "trust_level" in result
    assert "source_type" in result
    assert "source_id" in result
    assert "warning" in result
    assert "content_start_marker" in result
    assert "data" in result
    assert "content_end_marker" in result


def test_wrap_untrusted_content_preserves_content():
    """Verify data field contains original content."""
    content = "Test email body with special chars: <>&\n\t"
    result = wrap_untrusted_content(content, "email", "msg123")

    assert result["data"] == content


def test_wrap_untrusted_content_sets_external_trust_level():
    """Verify trust level is always 'external'."""
    result = wrap_untrusted_content("test", "document", "doc123")
    assert result["trust_level"] == "external"


def test_wrap_untrusted_content_sets_source_type():
    """Verify source type is preserved."""
    for source_type in ["email", "document", "spreadsheet", "slide", "ticket"]:
        result = wrap_untrusted_content("test", source_type, "id123")
        assert result["source_type"] == source_type


def test_wrap_untrusted_content_sets_source_id():
    """Verify source ID is preserved."""
    result = wrap_untrusted_content("test", "email", "unique-id-123")
    assert result["source_id"] == "unique-id-123"


def test_markers_are_random_per_call():
    """Verify each call generates fresh random markers."""
    r1 = wrap_untrusted_content("test", "email", "msg1")
    r2 = wrap_untrusted_content("test", "email", "msg2")

    assert r1["content_start_marker"] != r2["content_start_marker"]
    assert r1["content_end_marker"] != r2["content_end_marker"]


def test_start_and_end_markers_are_different():
    """Verify start and end markers use different random IDs."""
    result = wrap_untrusted_content("test", "email", "msg123")

    assert result["content_start_marker"] != result["content_end_marker"]
    # They should have different hex IDs (not just different prefixes)
    start_id = result["content_start_marker"].replace("<<<EXTERNAL_CONTENT_", "").replace(">>>", "")
    end_id = result["content_end_marker"].replace("<<<END_EXTERNAL_CONTENT_", "").replace(">>>", "")
    assert start_id != end_id


def test_markers_follow_template_pattern():
    """Verify markers follow the expected template."""
    result = wrap_untrusted_content("test", "email", "msg123")

    assert result["content_start_marker"].startswith("<<<EXTERNAL_CONTENT_")
    assert result["content_start_marker"].endswith(">>>")
    assert result["content_end_marker"].startswith("<<<END_EXTERNAL_CONTENT_")
    assert result["content_end_marker"].endswith(">>>")


def test_wrapped_content_dataclass():
    """Test WrappedContent dataclass."""
    wrapped = WrappedContent(
        trust_level="external",
        source_type="email",
        source_id="msg123",
        warning="test warning",
        content_start_marker="<<<START>>>",
        data="test data",
        content_end_marker="<<<END>>>",
    )

    assert wrapped.trust_level == "external"
    assert wrapped.data == "test data"


def test_wrapped_content_to_dict():
    """Test WrappedContent.to_dict() method."""
    wrapped = WrappedContent(
        trust_level="external",
        source_type="email",
        source_id="msg123",
        warning="test warning",
        content_start_marker="<<<START>>>",
        data="test data",
        content_end_marker="<<<END>>>",
    )

    result = wrapped.to_dict()
    assert isinstance(result, dict)
    assert result["trust_level"] == "external"
    assert result["data"] == "test data"


def test_wrap_untrusted_content_with_empty_content():
    """Verify empty content is handled."""
    result = wrap_untrusted_content("", "email", "msg123")
    assert result["data"] == ""


def test_wrap_untrusted_content_with_unicode():
    """Verify unicode content is preserved."""
    content = "Hello 世界 🌍 Привет"
    result = wrap_untrusted_content(content, "email", "msg123")
    assert result["data"] == content


def test_wrap_untrusted_content_warning_message():
    """Verify warning message is informative."""
    result = wrap_untrusted_content("test", "email", "msg123")
    warning = result["warning"]

    assert "EXTERNAL" in warning.upper()
    assert "data" in warning.lower() or "DATA" in warning
