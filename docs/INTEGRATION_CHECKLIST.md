# Integration Checklist

Use this checklist when integrating prompt-security-utils into a new service or reviewing PRs that handle external content. Every item must be satisfied.

## Setup

- [ ] `generate_markers()` called once at startup/session start
- [ ] Markers delivered to LLM via trusted channel:
  - MCP server: `FastMCP("name", instructions=security_instructions(start, end))`
  - CLI tool: markers used as defense-in-depth
- [ ] `SecurityConfig` loaded (or defaults used)

## Field Classification

For every field in every API response that reaches the LLM:

- [ ] Classified each field as user-controlled or admin/system-controlled
- [ ] Documented the classification (comment or design doc)
- [ ] User-controlled fields: wrapped with `wrap_field()` or included in `output_external_content(content_fields=...)`
- [ ] Admin/system fields: passed as `**kwargs` or plain values (not in `content_fields`)

### Common fields people forget to wrap

- [ ] User names and display names
- [ ] Email addresses
- [ ] Organization/company names
- [ ] View/filter titles
- [ ] File/attachment names
- [ ] Calendar event titles and locations
- [ ] Comment and note bodies
- [ ] Auto-reply subjects and bodies
- [ ] Signature blocks

## Read-Back / Query Paths

- [ ] Every path that reads stored data and returns it to the LLM uses `wrap_external_data()` or `read_and_wrap_file()`
- [ ] jq query results are wrapped before returning
- [ ] File attachments read from disk are wrapped before returning
- [ ] Error messages from queries are NOT wrapped (they're our own text)

## Operations Audit

- [ ] Listed ALL operations/tools that return data to the LLM
- [ ] Every operation that returns external content uses wrapping
- [ ] Write operations (create, update, delete) confirmed to NOT need wrapping (outbound, not inbound)
- [ ] Verified no `output_success()` or plain `return` with external content

## Testing

- [ ] Test that wrapped fields have `trust_level: "external"`
- [ ] Test that admin-controlled fields are NOT wrapped
- [ ] Test that suspicious content produces `security_warnings`
- [ ] Test that None/empty content is handled gracefully
- [ ] Test read-back/query paths return wrapped output
