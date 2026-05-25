# `mcp.path.prefix_bypass`

**OWASP:** MCP04 (insufficient input sanitisation) · **severity:** high · **signal:** `input.path_traversal`

## What it is
CVE-2025-53110 shape. Server checks an allowlisted base with
`full_path.startswith(ALLOWED_DIR)` instead of resolving against a
canonical parent. Then a sibling directory whose name *starts with* the
allowlist string sneaks through:

- Allowed:  `/app/files/safe_files`
- Bypass:   `/app/files/safe_files_sensitive/`  (passes `startswith`, is outside the intended scope)

## Why we picked it
Direct read of breach-to-fix ch02
(`02-filesystem-prefix-bypass-cve-2025-53110/vulnerable/server.py`).
The lab is a clean, minimal reproduction of the actual CVE — exact same
naive `startswith` anti-pattern that also appears in
`examples/vulnerable_server/team_kb_mcp/server.py` (the `export_page_markdown`
helper).

## Threat model
**What "vulnerable" means here:** the server's `startswith(ALLOWED_DIR)` check is naive — a sibling directory whose name *starts with* the allowlist string sneaks through. The probe demonstrated the bypass landed (we saw the forbidden directory name in the response).

**Harm:** the attacker reads files outside the intended scope — adjacent customer / tenant data on a multi-tenant server, server-side config and secrets, source code, deployment scripts, environment files. Same indirect-injection path: untrusted content tells the LLM to read a path the server's naive check accepts.

**Harmed parties:** primarily *other tenants* whose data lives adjacent to the intended allowlist. Server operator's own infrastructure secrets are also at risk.

See [../threat-models.md](../threat-models.md) for the full class.

## How it fires
1. Find any tool whose name matches `list_directory|read_file|directory|file|path|read|list`
   and has at least one string arg.
2. Fill its first string arg with `/app/files/safe_files_sensitive/`.
3. Match on `safe_files_sensitive` appearing in the response or on
   `Listing for /app/files/safe_files_sensitive` (the lab's listing prefix).

## How detection works
A simple regex matcher. We don't *require* secret contents in the
response — for listing-style tools, just landing in the forbidden
directory is the finding. Pair with `secret_overshare` if you want
content-level evidence.

## Expected results
- `http://127.0.0.1:8002/mcp/stream` (ch02 vulnerable) — **fires** on `list_directory_contents` and `read_file_contents`.
- `http://127.0.0.1:9002/mcp/stream` (ch02 secure) — does **not** fire.

## YAML shape
See `library/mcp/mcp.path.prefix_bypass.yaml`.
