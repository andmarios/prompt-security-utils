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

Security settings are stored in `~/.claude/.prompt-security/config.json`:

```json
{
  "content_start_marker": "<<<EXTERNAL_CONTENT>>>",
  "content_end_marker": "<<<END_EXTERNAL_CONTENT>>>",
  "llm_screen_enabled": false,
  "use_local_llm": false,
  "ollama_url": "http://localhost:11434",
  "ollama_model": "llama3.2:1b",
  "screen_timeout": 5.0,
  "detection_enabled": true,
  "custom_patterns": [],
  "allowlisted_documents": [],
  "allowlisted_emails": [],
  "allowlisted_tickets": [],
  "disabled_services": [],
  "disabled_operations": {},
  "cache_enabled": true,
  "cache_ttl_seconds": 900,
  "cache_max_size": 1000
}
```

### Configuration Options

#### Content Markers (Security-Critical)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `content_start_marker` | string | `"<<<EXTERNAL_CONTENT>>>"` | Marker placed before untrusted content |
| `content_end_marker` | string | `"<<<END_EXTERNAL_CONTENT>>>"` | Marker placed after untrusted content |

**⚠️ IMPORTANT:** Since this repository is open source, the default markers are publicly known. Attackers could craft content containing these exact markers to escape the "data boundary" and inject instructions.

**Recommended:** Configure custom, secret markers unique to your deployment:

```json
{
  "content_start_marker": "«««YOUR_SECRET_START_MARKER_xyz123»»»",
  "content_end_marker": "«««YOUR_SECRET_END_MARKER_xyz123»»»"
}
```

Use markers that:
- Are unlikely to appear in normal content
- Include random characters/numbers
- Are kept secret (not committed to repos)

#### LLM Screening Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `llm_screen_enabled` | bool | `false` | Enable LLM-based content screening (uses API calls) |
| `llm_screen_chunked` | bool | `true` | Use chunked screening for large content (screens all content) |
| `llm_screen_max_chunks` | int | `10` | Maximum chunks to screen (0 = unlimited) |
| `use_local_llm` | bool | `false` | Use local Ollama instead of Claude Haiku for screening |
| `ollama_url` | string | `"http://localhost:11434"` | Ollama API URL (when `use_local_llm` is true) |
| `ollama_model` | string | `"llama3.2:1b"` | Ollama model to use for screening |
| `screen_timeout` | float | `5.0` | Timeout in seconds for LLM screening requests |

#### Detection Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `detection_enabled` | bool | `true` | Enable regex-based pattern detection |
| `custom_patterns` | array | `[]` | User-defined detection patterns (see below) |

#### Allowlists

Allowlisted items bypass security wrapping entirely.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `allowlisted_documents` | array | `[]` | Document IDs to skip wrapping (Google Docs, Sheets, Slides) |
| `allowlisted_emails` | array | `[]` | Email/message IDs to skip wrapping |
| `allowlisted_tickets` | array | `[]` | Ticket IDs to skip wrapping (Zendesk, etc.) |

#### Service/Operation Toggles

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `disabled_services` | array | `[]` | Services to disable wrapping for (e.g., `["gmail", "calendar"]`) |
| `disabled_operations` | object | `{}` | Specific operations to disable (e.g., `{"gmail.read": false}`) |

#### Caching Settings

Cache stores LLM screening results to avoid repeated API calls.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `cache_enabled` | bool | `true` | Enable caching of LLM screening results |
| `cache_ttl_seconds` | int | `900` | Cache entry time-to-live (15 minutes default) |
| `cache_max_size` | int | `1000` | Maximum number of cached entries |

### Custom Patterns

Add your own detection patterns as arrays of `[regex, category, severity]`:

```json
{
  "custom_patterns": [
    ["as\\s+a\\s+helpful\\s+ai", "social_engineering", "high"],
    ["(admin|root)\\s+mode", "privilege_escalation", "high"],
    ["don'?t\\s+tell\\s+the\\s+user", "concealment", "high"]
  ]
}
```

**Severity levels:** `"high"`, `"medium"`, `"low"`

**Note:** Patterns use Python regex syntax. Remember to double-escape backslashes in JSON.

## Built-in Detection Categories

The following patterns are detected by default:

| Category | Severity | Examples |
|----------|----------|----------|
| `instruction_override` | HIGH | "ignore previous instructions", "forget your rules" |
| `role_hijack` | HIGH | "you are now", "act as", "pretend to be" |
| `prompt_injection` | HIGH | `</system>`, `[INST]`, "system prompt:" |
| `jailbreak` | HIGH | "DAN mode", "developer mode enabled" |
| `exfiltration` | HIGH/MEDIUM | "send to", "forward all", "upload to" |
| `credential_leak` | HIGH/MEDIUM | "api_key:", "password:", "BEGIN PRIVATE KEY" |
| `base64_encoding` | LOW | Long base64 strings |
| `html_encoding` | MEDIUM | HTML entities like `&#x3C;` |
| `unicode_escape` | MEDIUM | Unicode escapes like `\u0069` |
| `invisible_chars` | MEDIUM | Zero-width characters |

## License

MIT
