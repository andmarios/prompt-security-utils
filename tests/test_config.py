"""Tests for configuration management."""

import json
from unittest.mock import patch

import pytest
from prompt_security.config import (
    SecurityConfig,
    load_config,
    save_config,
    generate_markers,
    _FALLBACK_START_MARKER,
    _FALLBACK_END_MARKER,
)


@pytest.fixture
def temp_config_path(tmp_path):
    """Create temporary config path with no legacy path."""
    config_path = tmp_path / ".config" / "prompt-security-utils" / "config.json"
    legacy_path = tmp_path / ".claude" / ".prompt-security" / "config.json"
    with (
        patch.object(SecurityConfig, "CONFIG_PATH", config_path),
        patch.object(SecurityConfig, "_LEGACY_CONFIG_PATH", legacy_path),
    ):
        yield config_path


def test_config_default_values():
    """Test default configuration values."""
    config = SecurityConfig()

    assert config.llm_screen_enabled is False
    assert config.use_local_llm is False
    assert config.detection_enabled is True
    assert config.cache_enabled is True
    assert config.custom_patterns == []


def test_config_load_creates_randomized_markers(temp_config_path):
    """Test that first load creates config with randomized markers."""
    config = SecurityConfig.load()

    # Markers should NOT be the fallback hardcoded values
    assert config.content_start_marker != _FALLBACK_START_MARKER
    assert config.content_end_marker != _FALLBACK_END_MARKER

    # Markers should follow the template pattern
    assert config.content_start_marker.startswith("<<<EXTERNAL_CONTENT_")
    assert config.content_start_marker.endswith(">>>")
    assert config.content_end_marker.startswith("<<<END_EXTERNAL_CONTENT_")
    assert config.content_end_marker.endswith(">>>")

    # Config file should have been auto-saved
    assert temp_config_path.exists()


def test_config_load_persists_markers(temp_config_path):
    """Test that randomized markers persist across loads."""
    first = SecurityConfig.load()
    second = SecurityConfig.load()

    assert first.content_start_marker == second.content_start_marker
    assert first.content_end_marker == second.content_end_marker


def test_config_load_unique_across_installs(temp_config_path):
    """Test that different installs get different markers."""
    first = SecurityConfig.load()

    # Delete config to simulate a fresh install
    temp_config_path.unlink()

    second = SecurityConfig.load()

    assert first.content_start_marker != second.content_start_marker
    assert first.content_end_marker != second.content_end_marker


def test_config_save_load_roundtrip(temp_config_path):
    """Test saving and loading config preserves values."""
    original = SecurityConfig(
        llm_screen_enabled=True,
        use_local_llm=True,
        detection_enabled=False,
        custom_patterns=[["test_pattern", "test_category", "high"]],
    )

    original.save()

    loaded = SecurityConfig.load()

    assert loaded.llm_screen_enabled == original.llm_screen_enabled
    assert loaded.use_local_llm == original.use_local_llm
    assert loaded.detection_enabled == original.detection_enabled
    assert loaded.custom_patterns == original.custom_patterns


def test_config_invalid_json(temp_config_path):
    """Test handling of invalid JSON config file."""
    temp_config_path.parent.mkdir(parents=True, exist_ok=True)
    temp_config_path.write_text("invalid json {{{")

    config = SecurityConfig.load()
    # Should return default config
    assert config.detection_enabled is True


def test_config_ignores_unknown_fields(temp_config_path):
    """Test that unknown fields in config file are ignored gracefully."""
    # Write config with fields that no longer exist (from old service-specific config)
    temp_config_path.parent.mkdir(parents=True, exist_ok=True)
    old_config = {
        "detection_enabled": False,
        "allowlisted_documents": ["doc1"],  # No longer in config
        "disabled_services": ["gmail"],  # No longer in config
    }
    temp_config_path.write_text(json.dumps(old_config))

    config = SecurityConfig.load()

    # Known field should be loaded
    assert config.detection_enabled is False
    # Unknown fields should be ignored (not cause errors)
    assert not hasattr(config, "allowlisted_documents") or config.__dict__.get("allowlisted_documents") is None


def test_get_custom_patterns():
    """Test custom patterns extraction."""
    config = SecurityConfig(
        custom_patterns=[
            ["pattern1", "cat1", "high"],
            ["pattern2", "cat2", "medium"],
            ["invalid", "only_two"],  # Should be skipped
            ["also", "invalid", "has", "four"],  # Should be skipped
        ]
    )

    patterns = config.get_custom_patterns()

    assert len(patterns) == 2
    assert ("pattern1", "cat1", "high") in patterns
    assert ("pattern2", "cat2", "medium") in patterns


def test_load_config_convenience():
    """Test load_config convenience function."""
    with patch.object(SecurityConfig, "load") as mock_load:
        mock_load.return_value = SecurityConfig()
        config = load_config()
        mock_load.assert_called_once()


def test_save_config_convenience():
    """Test save_config convenience function."""
    config = SecurityConfig()
    with patch.object(config, "save") as mock_save:
        save_config(config)
        mock_save.assert_called_once()


def test_config_creates_parent_dirs(temp_config_path):
    """Test that save creates parent directories."""
    config = SecurityConfig()
    config.save()

    assert temp_config_path.parent.exists()
    assert temp_config_path.exists()


def test_generate_markers_random():
    """Test that generate_markers produces unique pairs."""
    a_start, a_end = generate_markers()
    b_start, b_end = generate_markers()

    assert a_start != b_start
    assert a_end != b_end
    # Start and end in a pair share the same ID
    assert a_start.replace("EXTERNAL_CONTENT_", "") == a_end.replace("END_EXTERNAL_CONTENT_", "")


def test_generate_markers_fixed_id():
    """Test that generate_markers accepts a fixed ID."""
    start, end = generate_markers(marker_id="test123")

    assert start == "<<<EXTERNAL_CONTENT_test123>>>"
    assert end == "<<<END_EXTERNAL_CONTENT_test123>>>"


def test_client_custom_markers_preserved(temp_config_path):
    """Test that client-set custom markers survive save/load."""
    config = SecurityConfig(
        content_start_marker="<<<MY_APP_START>>>",
        content_end_marker="<<<MY_APP_END>>>",
    )
    config.save()

    loaded = SecurityConfig.load()
    assert loaded.content_start_marker == "<<<MY_APP_START>>>"
    assert loaded.content_end_marker == "<<<MY_APP_END>>>"
