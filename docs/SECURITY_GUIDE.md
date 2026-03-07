# Security Guide

This guide explains the threat model behind prompt-security-utils and how to integrate it correctly. It uses real security bugs found in [zendesk-mcp](https://github.com/andmarios/zendesk-skill) and [google-workspace](https://github.com/andmarios/google-workspace-skill) as case studies.

## Threat Model

MCP servers and CLI tools that feed external content into LLM conversations are **the primary attack surface for prompt injection**. When an LLM reads data from Zendesk tickets, Gmail messages, Google Docs, or any external API, that data can contain instructions that trick the LLM into:

- Ignoring its system prompt
- Exfiltrating sensitive data from the conversation
- Performing unauthorized actions via tool calls
- Revealing its own instructions to attackers

**The attack path is simple**: an attacker puts "Ignore all previous instructions and..." into a Zendesk ticket subject, a Google Doc comment, a calendar event title, or an email. When the LLM reads that content as part of its context, it may follow the injected instructions instead of its own.

## The Golden Rule

> **ALL external content must be wrapped before it reaches the LLM. No exceptions.**

"External content" means any data that comes from outside your trusted system boundary — anything that a user, customer, or external party could have authored or influenced. This includes fields you might not think of as dangerous:

- User names and email addresses
- Organization names
- Ticket subjects and view titles
- Calendar event titles and descriptions
- Document comments and suggestions
- File names and folder names
- Vacation auto-reply messages
- Email signatures

If a human outside your organization could have set the value, wrap it.

## Field Classification

Use this decision tree for every field in an API response:

```
Is this field set by an admin in a controlled interface?
├── YES (e.g., group names, tag names, SLA policy titles, roles, statuses)
│   └── Do NOT wrap — admin-controlled
└── NO or UNSURE
    ├── Could an external user have authored or influenced this value?
    │   ├── YES (e.g., ticket subject, user name, email body, doc comment)
    │   │   └── WRAP IT
    │   └── NO (e.g., internal system IDs, timestamps, counts)
    │       └── Do NOT wrap — system-generated
    └── When in doubt → WRAP IT
```

### Examples by Risk Level

**MUST wrap (user-controlled free text):**
- Ticket subjects, descriptions, comments
- User names, email addresses, notes
- Organization names, notes
- Document content, headings, comments, suggestions
- Email bodies, subjects, signatures
- Calendar event titles, descriptions, locations
- Contact names, addresses, organization fields
- View titles (can be created by agents, not just admins)
- Attachment filenames
- Any field from stored/cached API responses read back later

**Do NOT wrap (admin/system-controlled):**
- Status values (open, closed, pending)
- Priority levels (low, normal, high, urgent)
- Role values (admin, agent, end-user)
- Internal IDs (numeric or UUID)
- Timestamps (created_at, updated_at)
- Counts and metrics
- Group names (admin-created in Zendesk)
- Tag names (admin-created)
- SLA policy titles
- Domain names (admin-configured)
- System labels (INBOX, SENT, DRAFT)

## Anti-Patterns: Real Security Bugs

### Anti-Pattern 1: Selective Wrapping

**The mistake**: Only wrapping "obvious" fields like email body or ticket description, while leaving user names, emails, org names, and other user-controlled fields raw.

**zendesk-mcp before hardening** — Only `subject` was wrapped in `get_ticket`. Names, emails, org names, and view titles were returned raw:

```python
# INSECURE — only subject is wrapped, name and email are raw
return {
    "id": ticket.get("id"),
    "subject": wrap_field(ticket.get("subject"), "ticket", ticket_id, start, end),
    "name": user.get("name"),           # Raw! Attacker-controlled
    "email": user.get("email"),         # Raw! Attacker-controlled
    "organization": org.get("name"),    # Raw! Attacker-controlled
}
```

**Correct pattern:**

```python
# SECURE — all user-controlled fields wrapped
return {
    "id": ticket.get("id"),
    "subject": wrap_field(ticket.get("subject"), "ticket", ticket_id, start, end),
    "name": wrap_field(user.get("name"), "user", user_id, start, end),
    "email": wrap_field(user.get("email"), "user", user_id, start, end),
    "organization": wrap_field(org.get("name"), "organization", org_id, start, end),
}
```

### Anti-Pattern 2: Raw Read-Back

**The mistake**: Storing external API responses to disk, then reading them back with jq/queries and returning the raw result to the LLM.

**zendesk-mcp before hardening** — `zendesk_query_stored` returned raw jq output:

```python
# INSECURE — raw jq output goes straight to the LLM
success, result = execute_jq(file_path, jq_expr)
if success:
    return result  # This is unscreened external content!
```

**Correct pattern using `wrap_external_data()`:**

```python
# SECURE — wrap query results before returning to LLM
from prompt_security import wrap_external_data

success, result = execute_jq(file_path, jq_expr)
if success and result:
    return wrap_external_data(result, "ticket", source_id, start, end)
```

### Anti-Pattern 3: Forgetting Entire Operations

**The mistake**: Having some operations use security wrapping while others bypass it entirely.

**google-workspace before hardening** — Only 5 of ~30 operations used the security pipeline. The other ~25 operations passed external Google API content through raw `output_success()`:

```python
# INSECURE — external calendar data bypasses all security
output_success(
    operation="calendar.list",
    events=events,           # External content — unwrapped!
    event_count=len(events),
)
```

**Correct pattern:**

```python
# SECURE — all external content goes through the pipeline
output_external_content(
    operation="calendar.list",
    source_type="calendar",
    source_id=f"calendar.list:{calendar_id}",
    content_fields={"events": json.dumps(events, default=str)},
    start_marker=start,
    end_marker=end,
    event_count=len(events),
)
```

### Anti-Pattern 4: No Trusted Channel for Markers

**The mistake**: Generating markers but not delivering them to the LLM via the system prompt / MCP instructions. Without the trusted channel, the LLM has no reference to distinguish real markers from forged ones.

```python
# INSECURE — markers generated but never sent to LLM
start, end = generate_markers()
# ... wrapping happens, but LLM doesn't know the marker values
```

**Correct MCP pattern:**

```python
from mcp.server.fastmcp import FastMCP
from prompt_security import generate_markers, security_instructions

_START, _END = generate_markers()
mcp = FastMCP("my_service", instructions=security_instructions(_START, _END))
```

## Integration Patterns

### Pattern 1: MCP Server

```python
from mcp.server.fastmcp import FastMCP
from prompt_security import (
    generate_markers,
    security_instructions,
    output_external_content,
    wrap_field,
)

# 1. Generate markers once at startup
_START, _END = generate_markers()

# 2. Deliver markers via trusted channel (MCP instructions)
mcp = FastMCP("my_service", instructions=security_instructions(_START, _END))

# 3. Wrap ALL external content in every tool response
@mcp.tool()
async def get_record(record_id: str) -> str:
    data = await api.get(f"/records/{record_id}")
    result = output_external_content(
        operation="records.get",
        source_type="record",
        source_id=record_id,
        content_fields={
            "title": data["title"],              # User-controlled
            "description": data["description"],  # User-controlled
            "author_name": data["author"]["name"],  # User-controlled
        },
        start_marker=_START,
        end_marker=_END,
        record_id=record_id,    # System-controlled, not wrapped
        status=data["status"],  # Admin-controlled, not wrapped
    )
    return json.dumps(result)
```

### Pattern 2: CLI Tool

```python
from prompt_security import generate_markers, wrap_field, output_external_content

# Generate markers at session start
START, END = generate_markers()
# For CLI: markers are defense-in-depth (human controls the pipeline)

def display_user(user_data):
    return {
        "id": user_data["id"],
        "name": wrap_field(user_data.get("name"), "user", str(user_data["id"]), START, END),
        "email": wrap_field(user_data.get("email"), "user", str(user_data["id"]), START, END),
        "role": user_data.get("role"),  # Admin-controlled
    }
```

### Pattern 3: Store-Then-Query (jq, file read-back)

```python
from prompt_security import wrap_external_data, read_and_wrap_file

# Wrap jq query results
success, result = execute_jq(stored_file_path, jq_expression)
if success and result:
    wrapped = wrap_external_data(result, "ticket", source_id, START, END)
    return json.dumps(wrapped)

# Wrap file reads (one-liner)
wrapped = read_and_wrap_file(attachment_path, "attachment", f"file:{filename}", START, END)
```

### Pattern 4: Batch Operations (lists, search results)

For operations returning lists of items, use `output_external_content` with `json.dumps` for the collection:

```python
users = api_response.get("users", [])
result = output_external_content(
    operation="users.search",
    source_type="user",
    source_id=f"search:{query}",
    content_fields={"users": json.dumps(users, default=str)},
    start_marker=START,
    end_marker=END,
    user_count=len(users),
)
```

Or wrap individual fields per item using `wrap_field`:

```python
users = [
    {
        "id": u["id"],
        "name": wrap_field(u.get("name"), "user", str(u["id"]), START, END),
        "email": wrap_field(u.get("email"), "user", str(u["id"]), START, END),
        "role": u.get("role"),  # Not wrapped — admin-controlled
    }
    for u in api_response.get("users", [])
]
```

Choose based on token budget: batch wrapping (one set of markers for the whole list) is cheaper; per-field wrapping gives finer-grained detection.

## Token Overhead

Wrapping adds structural overhead per field (~285 bytes for short values). For operations returning many small fields (e.g., 10 users x 2 fields = 20 wrapped values), the overhead can be significant.

**Mitigation strategies:**

1. **Batch wrapping** — Use `output_external_content()` with `json.dumps()` to wrap entire collections as a single content field. One set of markers instead of N.
2. **Only wrap user-controlled fields** — Don't wrap IDs, timestamps, counts, statuses. Use the field classification tree above.
3. **Limit list sizes** — Cap search results (e.g., top 10) before wrapping.

## Checklist

See [INTEGRATION_CHECKLIST.md](INTEGRATION_CHECKLIST.md) for a copy-paste checklist to use during PR reviews.
