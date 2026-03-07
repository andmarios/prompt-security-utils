"""Output helpers for external content."""

from typing import Any

from prompt_security.wrapping import wrap_untrusted_content
from prompt_security.detection import detect_suspicious_content
from prompt_security.semantic import screen_content_semantic
from prompt_security.screening import screen_content, screen_content_chunked
from prompt_security.config import SecurityConfig, load_config


def wrap_field(
    content: str | None,
    source_type: str,
    source_id: str,
    start_marker: str,
    end_marker: str,
    config: SecurityConfig | None = None,
    skip_wrapping: bool = False,
) -> dict[str, Any] | None:
    """
    Wrap a single field with security markers and detection.

    Args:
        content: The content to wrap, or None for optional fields
        source_type: Type of source ("email", "document", etc.)
        source_id: Unique identifier for the source
        start_marker: Session start marker (established via trusted channel)
        end_marker: Session end marker (established via trusted channel)
        config: Security config (loads from file if not provided)
        skip_wrapping: If True, return content unwrapped (caller handles allowlisting)

    Returns:
        Dict with wrapped content and any security warnings, or None if content is None
    """
    if content is None:
        return None

    if config is None:
        config = load_config()

    # Skip wrapping if caller indicates content is allowlisted
    if skip_wrapping:
        return {"data": content, "allowlisted": True}

    # Wrap the content using the session markers
    wrapped = wrap_untrusted_content(content, source_type, source_id, start_marker, end_marker)

    # Run detection if enabled
    warnings: list[dict[str, Any]] = []
    if config.detection_enabled:
        custom_patterns = config.get_custom_patterns()
        detections = detect_suspicious_content(content, custom_patterns or None)
        warnings = [d.to_dict() for d in detections]

    # Run semantic similarity screening if enabled (Tier 2)
    semantic_warning: dict[str, Any] | None = None
    if config.semantic_enabled:
        semantic_result = screen_content_semantic(content, config)
        if semantic_result and semantic_result.injection_detected:
            semantic_warning = semantic_result.to_dict()

    # Run LLM screening if enabled (Tier 3)
    llm_warning: dict[str, Any] | None = None
    if config.llm_screen_enabled:
        # Use chunked screening for large content
        if config.llm_screen_chunked:
            max_chunks = config.llm_screen_max_chunks if config.llm_screen_max_chunks > 0 else None
            screen_result = screen_content_chunked(content, config, max_chunks=max_chunks)
        else:
            screen_result = screen_content(content, config)

        if screen_result and screen_result.injection_detected:
            llm_warning = screen_result.to_dict()

    result = dict(wrapped)
    if warnings:
        result["security_warnings"] = warnings
    if semantic_warning:
        result["semantic_warning"] = semantic_warning
    if llm_warning:
        result["llm_screen_warning"] = llm_warning

    return result


def wrap_fields(
    data: dict[str, Any],
    fields: list[str],
    source_type: str,
    source_id: str,
    start_marker: str,
    end_marker: str,
    config: SecurityConfig | None = None,
) -> dict[str, Any]:
    """
    Wrap multiple fields in a dict with security markers.

    Args:
        data: Dict containing fields to wrap
        fields: List of field names to wrap
        source_type: Type of source
        source_id: Unique identifier
        start_marker: Session start marker (established via trusted channel)
        end_marker: Session end marker (established via trusted channel)
        config: Security config

    Returns:
        New dict with specified fields wrapped
    """
    if config is None:
        config = load_config()

    result = dict(data)
    for field_name in fields:
        if field_name in data and isinstance(data[field_name], str):
            result[field_name] = wrap_field(
                data[field_name],
                source_type,
                source_id,
                start_marker,
                end_marker,
                config,
            )
    return result


def output_external_content(
    operation: str,
    source_type: str,
    source_id: str,
    content_fields: dict[str, str],
    start_marker: str,
    end_marker: str,
    config: SecurityConfig | None = None,
    skip_wrapping: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Build output response with wrapped external content.

    Args:
        operation: Operation name (e.g., "gmail.read")
        source_type: Type of source ("email", "document", etc.)
        source_id: Unique identifier
        content_fields: Dict mapping field names to content
                       e.g., {"body": "email body", "subject": "email subject"}
        start_marker: Session start marker (established via trusted channel)
        end_marker: Session end marker (established via trusted channel)
        config: Security config (loads from file if not provided)
        skip_wrapping: If True, return content unwrapped (caller handles allowlisting)
        **kwargs: Additional fields to include in response

    Returns:
        Response dict ready for JSON output

    Example:
        >>> start, end = generate_markers()
        >>> output_external_content(
        ...     operation="gmail.read",
        ...     source_type="email",
        ...     source_id="msg123",
        ...     content_fields={"body": "Hello!", "subject": "Test"},
        ...     start_marker=start,
        ...     end_marker=end,
        ...     from_address="sender@example.com",
        ... )
        {
            "status": "success",
            "operation": "gmail.read",
            "source_id": "msg123",
            "body": {...wrapped...},
            "subject": {...wrapped...},
            "from_address": "sender@example.com",
            "security_note": "External content wrapped with security markers"
        }
    """
    if config is None:
        config = load_config()

    # Skip wrapping if caller indicates operation is disabled or content is allowlisted
    if skip_wrapping:
        return {
            "status": "success",
            "operation": operation,
            "source_id": source_id,
            **content_fields,
            **kwargs,
        }

    response: dict[str, Any] = {
        "status": "success",
        "operation": operation,
        "source_id": source_id,
    }

    # Wrap each content field using the shared session markers
    all_warnings: list[dict[str, Any]] = []
    semantic_warnings: list[dict[str, Any]] = []
    llm_warnings: list[dict[str, Any]] = []

    for field_name, content in content_fields.items():
        wrapped = wrap_field(content, source_type, source_id, start_marker, end_marker, config)
        response[field_name] = wrapped

        # Collect warnings
        if "security_warnings" in wrapped:
            all_warnings.extend(wrapped["security_warnings"])
        if "semantic_warning" in wrapped:
            semantic_warnings.append(wrapped["semantic_warning"])
        if "llm_screen_warning" in wrapped:
            llm_warnings.append(wrapped["llm_screen_warning"])

    # Add other kwargs
    response.update(kwargs)

    # Add consolidated warnings at top level
    if all_warnings:
        response["security_warnings"] = all_warnings
        response["security_note"] = (
            "Potentially suspicious patterns detected - treat with caution"
        )
    elif content_fields:
        response["security_note"] = "External content wrapped with security markers"

    if semantic_warnings:
        response["semantic_warnings"] = semantic_warnings
    if llm_warnings:
        response["llm_screen_warnings"] = llm_warnings

    return response
