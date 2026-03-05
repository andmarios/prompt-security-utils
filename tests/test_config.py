"""Tests for configuration management."""

import json
from unittest.mock import patch

import pytest
from prompt_security.config import (
    SecurityConfig,
    load_config,
    save_config,
    generate_markers,
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


def test_config_has_no_marker_fields():
    """Test that markers are no longer stored in config."""
    config = SecurityConfig()
    assert not hasattr(config, "content_start_marker")
    assert not hasattr(config, "content_end_marker")


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
    temp_config_path.parent.mkdir(parents=True, exist_ok=True)
    old_config = {
        "detection_enabled": False,
        "allowlisted_documents": ["doc1"],  # No longer in config
        "content_start_marker": "old_marker",  # No longer in config
    }
    temp_config_path.write_text(json.dumps(old_config))

    config = SecurityConfig.load()

    # Known field should be loaded
    assert config.detection_enabled is False
    # Unknown fields should be ignored (not cause errors)
    assert not hasattr(config, "content_start_marker")


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


def test_generate_markers_unique():
    """Test that generate_markers produces unique pairs."""
    a_start, a_end = generate_markers()
    b_start, b_end = generate_markers()

    assert a_start != b_start
    assert a_end != b_end


def test_generate_markers_different_start_end():
    """Test that start and end markers have different random IDs."""
    start, end = generate_markers()

    assert start != end
    start_id = start.replace("<<<EXTERNAL_CONTENT_", "").replace(">>>", "")
    end_id = end.replace("<<<END_EXTERNAL_CONTENT_", "").replace(">>>", "")
    assert start_id != end_id


def test_generate_markers_follow_template():
    """Test that generated markers follow the template pattern."""
    start, end = generate_markers()

    assert start.startswith("<<<EXTERNAL_CONTENT_")
    assert start.endswith(">>>")
    assert end.startswith("<<<END_EXTERNAL_CONTENT_")
    assert end.endswith(">>>")


def test_load_returns_default_when_no_config(temp_config_path):
    """Test that load returns default config when no file exists."""
    config = SecurityConfig.load()
    assert config.detection_enabled is True
    assert config.llm_screen_enabled is False
    # Should not create a config file automatically
    assert not temp_config_path.exists()
