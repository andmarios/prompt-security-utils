# Prompt Security Utils

Prompt injection protection for LLM applications. Provides content wrapping, pattern detection, and optional LLM-based screening.

## Installation

```bash
pip install prompt-security-utils
```

Or with uv:

```bash
uv add prompt-security-utils
```

## Usage

```python
from prompt_security import (
    wrap_untrusted_content,
    detect_suspicious_content,
    output_external_content,
)

# Wrap external content with security markers
wrapped = wrap_untrusted_content(
    content="Email body here...",
    source_type="email",
    source_id="msg123",
)

# Detect suspicious patterns
detections = detect_suspicious_content("Ignore all previous instructions!")
for d in detections:
    print(f"{d.category}: {d.matched_text} ({d.severity.value})")

# Output helper for CLI tools
response = output_external_content(
    operation="gmail.read",
    source_type="email",
    source_id="msg123",
    content_fields={"body": "email content", "subject": "subject line"},
)
```

## Configuration

Security settings are stored in `~/.claude/.mcp-security/config.json`:

```json
{
  "llm_screen_enabled": false,
  "use_local_llm": false,
  "detection_enabled": true,
  "custom_patterns": [],
  "allowlisted_documents": [],
  "allowlisted_emails": [],
  "disabled_services": [],
  "cache_enabled": true
}
```

## License

MIT
