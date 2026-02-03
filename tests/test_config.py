"""Tests for configuration management."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from prompt_security.config import SecurityConfig, load_config, save_config


@pytest.fixture
def temp_config_path(tmp_path):
    """Create temporary config path."""
    config_path = tmp_path / ".claude" / ".mcp-security" / "config.json"
    with patch.object(SecurityConfig, "CONFIG_PATH", config_path):
        yield config_path


def test_config_default_values():
    """Test default configuration values."""
    config = SecurityConfig()

    assert config.llm_screen_enabled is False
    assert config.use_local_llm is False
    assert config.detection_enabled is True
    assert config.cache_enabled is True
    assert config.custom_patterns == []
    assert config.allowlisted_documents == []
    assert config.allowlisted_emails == []
    assert config.disabled_services == []


def test_config_load_default(temp_config_path):
    """Test loading default config when file doesn't exist."""
    config = SecurityConfig.load()
    assert config.detection_enabled is True


def test_config_save_load_roundtrip(temp_config_path):
    """Test saving and loading config preserves values."""
    original = SecurityConfig(
        llm_screen_enabled=True,
        use_local_llm=True,
        detection_enabled=False,
        custom_patterns=[["test_pattern", "test_category", "high"]],
        allowlisted_documents=["doc1", "doc2"],
        allowlisted_emails=["msg1"],
        disabled_services=["gmail"],
        disabled_operations={"docs.read": False},
    )

    original.save()

    loaded = SecurityConfig.load()

    assert loaded.llm_screen_enabled == original.llm_screen_enabled
    assert loaded.use_local_llm == original.use_local_llm
    assert loaded.detection_enabled == original.detection_enabled
    assert loaded.custom_patterns == original.custom_patterns
    assert loaded.allowlisted_documents == original.allowlisted_documents
    assert loaded.allowlisted_emails == original.allowlisted_emails
    assert loaded.disabled_services == original.disabled_services
    assert loaded.disabled_operations == original.disabled_operations


def test_config_invalid_json(temp_config_path):
    """Test handling of invalid JSON config file."""
    temp_config_path.parent.mkdir(parents=True, exist_ok=True)
    temp_config_path.write_text("invalid json {{{")

    config = SecurityConfig.load()
    # Should return default config
    assert config.detection_enabled is True


def test_is_service_enabled():
    """Test per-service toggle."""
    config = SecurityConfig(disabled_services=["gmail", "calendar"])

    assert config.is_service_enabled("docs") is True
    assert config.is_service_enabled("sheets") is True
    assert config.is_service_enabled("gmail") is False
    assert config.is_service_enabled("calendar") is False


def test_is_operation_enabled():
    """Test per-operation toggle."""
    config = SecurityConfig(
        disabled_services=["gmail"],
        disabled_operations={"docs.read": False, "sheets.read": True},
    )

    # Explicitly disabled
    assert config.is_operation_enabled("docs.read") is False

    # Explicitly enabled
    assert config.is_operation_enabled("sheets.read") is True

    # Service disabled
    assert config.is_operation_enabled("gmail.list") is False

    # Default (enabled)
    assert config.is_operation_enabled("slides.read") is True


def test_is_allowlisted_email():
    """Test email allowlist checking."""
    config = SecurityConfig(allowlisted_emails=["msg123", "msg456"])

    assert config.is_allowlisted("email", "msg123") is True
    assert config.is_allowlisted("message", "msg456") is True
    assert config.is_allowlisted("email", "msg999") is False


def test_is_allowlisted_document():
    """Test document allowlist checking."""
    config = SecurityConfig(allowlisted_documents=["doc123", "doc456"])

    assert config.is_allowlisted("document", "doc123") is True
    assert config.is_allowlisted("docs", "doc456") is True
    assert config.is_allowlisted("spreadsheet", "doc123") is True
    assert config.is_allowlisted("sheets", "doc456") is True
    assert config.is_allowlisted("slides", "doc123") is True
    assert config.is_allowlisted("document", "doc999") is False


def test_is_allowlisted_ticket():
    """Test ticket allowlist checking."""
    config = SecurityConfig(allowlisted_tickets=["ticket123"])

    assert config.is_allowlisted("ticket", "ticket123") is True
    assert config.is_allowlisted("zendesk", "ticket123") is True
    assert config.is_allowlisted("ticket", "ticket999") is False


def test_is_allowlisted_unknown_type():
    """Test unknown source type returns False."""
    config = SecurityConfig(
        allowlisted_emails=["id1"],
        allowlisted_documents=["id2"],
        allowlisted_tickets=["id3"],
    )

    assert config.is_allowlisted("unknown_type", "id1") is False


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
