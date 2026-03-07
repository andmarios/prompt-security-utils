# Secure Usage: Documentation & API Improvements

**Date:** 2026-03-07
**Status:** Approved

## Problem

Two independent consuming projects (zendesk-mcp, google-workspace) made the same three security mistakes when integrating prompt-security-utils:

1. **Selective wrapping** — Only wrapping "obvious" fields (subject, body) while leaving user-controlled fields (names, emails, org names, view titles) raw
2. **Raw read-back** — Returning stored external data (jq query results, file contents) directly to the LLM without wrapping
3. **No field classification** — No guidance on which fields are user-controlled vs admin-controlled, forcing developers to guess

Additionally, zendesk-mcp reinvented `wrap_field_simple()` locally because the library's `wrap_field()` didn't handle `None` input for optional fields.

## Root Cause

The library provides correct building blocks but insufficient guidance and convenience for common patterns. The secure path requires too much knowledge of the threat model and too much boilerplate. When the easy path is insecure, developers take it.

## Design

### API Changes

#### 1. `wrap_field()` — Accept `None` input

Update signature to handle optional fields without blowing up:

```python
def wrap_field(
    content: str | None,  # was: str
    source_type: str,
    source_id: str,
    start_marker: str,
    end_marker: str,
    config: SecurityConfig | None = None,
    skip_wrapping: bool = False,
) -> dict[str, Any] | None:  # was: dict[str, Any]
```

`None` in → `None` out. Everything else runs the full 3-tier pipeline. This eliminates the need for consumers to build their own `wrap_field_simple()`.

#### 2. `wrap_external_data()` — Wrap any string content for LLM consumption

New function for the store-then-query pattern and file read-back:

```python
def wrap_external_data(
    content: str,
    source_type: str,
    source_id: str,
    start_marker: str,
    end_marker: str,
    config: SecurityConfig | None = None,
) -> dict[str, Any]:
```

Handles: jq query results, log file contents, text attachments, HTML, any string that came from an external source. Runs the full detection pipeline. Returns a single wrapped dict with one set of markers around the entire content.

Lives in `prompt_security/wrapping.py` alongside `wrap_untrusted_content`.

#### 3. `read_and_wrap_file()` — One-liner for file reads

Convenience function that reads a file from disk and wraps its content:

```python
def read_and_wrap_file(
    file_path: str,
    source_type: str,
    source_id: str,
    start_marker: str,
    end_marker: str,
    config: SecurityConfig | None = None,
) -> dict[str, Any] | None:
```

- Reads text files and wraps content via the full pipeline
- Skips binary files (returns metadata-only response)
- Makes the secure path a one-liner for file attachment reads

Lives in `prompt_security/wrapping.py`.

### Documentation

#### 1. `docs/SECURITY_GUIDE.md`

Comprehensive security guide covering:

- **Threat model** — Why MCP servers are the attack surface for prompt injection
- **The Golden Rule** — ALL external content must be wrapped, no exceptions
- **Field classification** — Decision tree for user-controlled vs admin-controlled fields
- **Anti-patterns** — Real before/after code from zendesk-mcp and google-workspace (open source, referenced by name)
- **Integration patterns** — MCP server, CLI tool, store-then-query, file attachments
- **Token overhead** — Acknowledges the cost and explains batch wrapping via `output_external_content()`

#### 2. `docs/INTEGRATION_CHECKLIST.md`

Quick-reference checklist for PR reviews. Covers:

- Marker generation and trusted channel delivery
- Field classification (user-controlled vs admin-controlled)
- Wrapping all external content fields
- Read-back wrapping for stored data
- File attachment wrapping

#### 3. README.md updates

- Add prominent security warning section near the top
- Link to the security guide
- Improve Quick Start to show the full correct pattern
- Document new functions (`wrap_external_data`, `read_and_wrap_file`, `wrap_field` None handling)

## Files Changed

| File | Change |
|---|---|
| `src/prompt_security/wrapping.py` | Add `wrap_external_data()`, `read_and_wrap_file()` |
| `src/prompt_security/output.py` | Update `wrap_field()` to accept `str | None`, return `dict | None` |
| `src/prompt_security/__init__.py` | Export `wrap_external_data`, `read_and_wrap_file` |
| `tests/test_wrapping.py` | Tests for new functions |
| `tests/test_output.py` | Tests for `None` handling in `wrap_field()` |
| `README.md` | Security warning, updated Quick Start, new function docs |
| `docs/SECURITY_GUIDE.md` | New comprehensive security guide |
| `docs/INTEGRATION_CHECKLIST.md` | New PR review checklist |

## Not In Scope

- `SecuritySession` class (future — simplify marker threading)
- Changes to consuming projects (they update separately)
- Restructuring `output_external_content()` batch wrapping (works as-is)
- Binary file handling beyond skip/metadata
