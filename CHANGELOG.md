# jakk changelog

## v0.2.0 — 2026-05-23

Black-box MCP scanner. v0.2 makes jakk runnable as a GitHub-native,
safe-by-default CI smoke test for authenticated, multi-tenant,
multi-argument MCP servers (not just the single-arg lab targets v0.1
shipped against), adds four new probe classes, and passes a
self-security audit.

### Probes (7 → 13)

- **Auth-misconfig** (`surface: auth`): `mcp.auth.no_credential`,
  `mcp.auth.invalid_token`, `mcp.auth.wrong_prefix`.
- **Cross-tenant authz** (`surface: authz`): `mcp.authz.cross_tenant_read`
  — two-credential confused-deputy / BOLA probe.
- **SSRF**: `mcp.ssrf.cloud_metadata` — cloud instance-metadata SSRF
  (AWS IMDSv1 / GCP / Azure). Research-backed (BlueRock: 36.7% of 7,000
  servers vulnerable).
- **SQLi**: `mcp.sql.error_based` — query-kind error-based SQL injection
  probe with database-engine syntax-error matching.

### Capabilities

- **GitHub Action**: safe-by-default Marketplace form factor for PR
  checks. Emits JSONL/SARIF and can fail CI with `--exit-nonzero-on-fired`.
- **Auth** for commercial targets: `--bearer`, `--oauth-token-file`,
  `--header KEY=VALUE`.
- **`--safe`** + `side_effect: safe|unsafe` classification — run only
  read-only / no-side-effect probes against production.
- **C+ schema-aware arg resolution** (`target_arg_kind` + `__target_arg__`):
  probes target arguments by *semantic role* (path/query/id/url/text), so
  one library generalizes across servers regardless of argument naming.
- **Context args** (`--arg KEY=VALUE`): fill non-target required args
  (owner/repo/...) so multi-argument production tools execute instead of
  erroring. Actionable `skipped` when required args are unsatisfied.
- **Canary path override** (`--canary-path PATH`): retarget path probes
  from lab defaults to a path meaningful on the current target.
- **SARIF output** (`--sarif PATH`): emit fired findings as SARIF 2.1.0
  for GitHub code scanning. JSONL remains the complete transcript.
- **Stdio smoke scans** (`--stdio COMMAND`): launch local stdio MCP
  servers for input-handling/schema probes; auth probes are skipped
  because stdio has no transport-auth layer.
- **Corroboration** for `marker_echo` probes: 3-call differential +
  negative canary; new `suggestive` outcome.

### Classification

- 6 outcomes: `vulnerable` / `echo` / `suggestive` / `pass` / `skipped` /
  `error`.
- **Refined error/pass semantics**: a transport failure (couldn't
  complete the call) is `error`; a tool-result error (server *ran* and
  rejected the input) where the matcher found no leak is `pass` (server
  handled it safely) with the rejection message preserved in evidence.

### Security (self-audit, 2026-05-23)

Three findings in jakk's own attack surface, all fixed:

- Rich markup injection via untrusted server output → `rich.markup.escape()`
  on all rendered untrusted fields.
- Unbounded response → memory DoS → response capped at 1 MiB.
- Operator credentials (`--bearer`/`--cred-a`/`--cred-b`) leaked into JSONL
  → masked with placeholders in stored findings.

No code-execution sinks; runtime dependency closure clean (one build-time
setuptools CVE). See `docs/2026-05-23_self-security-audit.md`.

### Verification

- 190 unit tests.
- GitHub Action smoke test: the composite Action is dogfooded with
  `uses: ./` against `examples/stdio_smoke_server.py`, verifies JSONL
  output, and asserts no findings fire on the clean fixture.
- Live runs against breach-to-fix ch01 / ch02 / ch08 (vulnerable + secure)
  and the official **github-mcp-server** (HTTP read-only mode) — the first
  real production target. Coverage run: `docs/2026-05-23_github-mcp-coverage-run.md`.

### Scope decision

jakk targets **HTTP** MCP servers as the production threat model. Stdio
is supported as a local smoke-test transport for the subset of probes
that applies; auth probes are skipped because stdio has no transport-auth
layer. See `docs/scope-decision.md`.

## v0.1.0 — 2026-05-22

Initial release. 7 probes (command injection, path traversal, response
leaks, schema poisoning) across tool_call / tool_list surfaces.
5-outcome taxonomy. FastMCP streamable-HTTP client. JSONL output.
Validated against breach-to-fix ch02 / ch08.
