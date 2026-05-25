# `mcp.path.canary_file_read`

**OWASP:** MCP04 (insufficient input sanitisation) + MCP02 (excessive
output) · **severity:** critical · **signal:** `input.path_traversal`

## What it is
Impact-tier follow-up to `mcp.path.prefix_bypass`. The bypass probe
proves the `startswith` check can be tricked into letting a sibling
directory through; this probe completes the chain by reading a known
canary file inside the forbidden directory and matching on its contents.

Default canary: `/app/files/safe_files_sensitive/secret.txt` →
`FLAG{cve_2025_53110_escape_route}` (breach-to-fix ch02). Override the
path for other targets.

## Why we picked it
Parallel structure to `mcp.command.secret_file_read`: a vulnerability
finding that says *"the server reads files it shouldn't"* lands harder
than one that says *"the server's path check has a logic flaw"*.
Operators triage on impact, not on attack class. This split keeps both
levels of evidence available — the bypass probe runs first (zero
secrets needed, fires on directory enumeration), this one fires only
when content actually came through.

## Why `applies_to` excludes `list_*`
A list-directory tool can also fire `mcp.path.prefix_bypass` and
return directory entries — but it cannot return file *contents*. This
probe deliberately scopes to `read_file`/`get_file`/`cat_file`/...
variants. Avoiding list tools also keeps the probe from spamming
unnecessary calls.

## Threat model
**What "vulnerable" means here:** path traversal works *and* exfiltration completed — the canary file's contents flowed back through the tool response. Pairs with `prefix_bypass` (sink) to form a sink + impact proof chain.

**Harm:** content-level exfiltration. Whatever was in the canary file is now readable to anyone who can call the tool. In a real deployment that's adjacent-tenant documents, secrets stored as files, internal reports, customer attachments.

**Harmed parties:** other tenants of the multi-tenant service; server operator if internal secrets are reachable via the same flaw.

See [../threat-models.md](../threat-models.md) for the full class.

## How it fires
1. Filter `tools/list` by the file-read regex (`^(read_file|get_file|
   cat_file|file_contents|read_file_contents|fetch_file)`).
2. For each match, send the canary path as the tool's first string arg.
3. Run `secret_pattern` against the response. Default patterns include
   `FLAG{…}`, `/etc/passwd` first-line shape, PEM blocks, common API
   key shapes — server-specific canaries can be added via
   `matcher.params.patterns`.

## Expected results
- `http://127.0.0.1:8002/mcp/stream` (ch02 vulnerable) — **fires
  vulnerable** on `read_file_contents`; evidence includes
  `FLAG{cve_2025_53110_escape_route}`.
- `http://127.0.0.1:9002/mcp/stream` (ch02 secure) — does **not** fire
  (server rejects the path with `"Access denied: …"`).
- Servers without a file-read tool — skipped.

## Customisation
For non-ch02 targets, override two things:

```yaml
payload:
  arguments:
    __first_string_arg__: "/some/other/canary/path"

matcher:
  kind: secret_pattern
  params:
    patterns:
      - "MY-SERVER-CANARY-[A-Z0-9]+"
```

## YAML shape
See `library/mcp/mcp.path.canary_file_read.yaml`.
