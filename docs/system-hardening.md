---
date: 2026-05-23
status: jakk's own security posture — pre-release checklist + ongoing discipline
audience: maintainers of jakk
related:
  - docs/mcp-server-distribution-decision.md (why we declined the MCP-server route, and how that changes hardening scope)
  - docs/threat-models.md (the bug classes jakk catches in OTHER servers; some apply to jakk itself)
---

# jakk system hardening

A security tool that gets compromised is worse than no tool — it
gains the trust of its users while leaking their data, credentials,
or scan results. jakk's own security posture matters as much as its
detection quality.

This document lays out the attack surface jakk has *as a CLI tool*,
what we do today to harden each surface, what we should do before
v1 release, and what would change if we ever decide to ship as an
MCP server (we currently do not — see
`mcp-server-distribution-decision.md`).

---

## 1 · Threat model — who might attack jakk?

| Adversary | What they want | Likelihood | Severity if successful |
|---|---|---|---|
| **Supply-chain attacker** | Poison a dependency so jakk users execute malicious code on scan | low-medium (npm/PyPI typosquatting + maintainer compromise are common) | catastrophic — RCE on every jakk user |
| **Hostile MCP target** | Send a response that escapes jakk's parser or matcher and exfiltrates from the scan host | low (scans are operator-initiated) | high — RCE / data exfil on the scanner host |
| **Hostile YAML library** | Trick the operator into loading a YAML that does something unexpected at load time | low (library is curated, operator must explicitly point `--library` at it) | medium — depends on what YAML can do |
| **Operator misconfiguration** | The operator scans something they shouldn't | medium-high | varies — usually ToS / legal, not technical |
| **Disclosed-finding leakage** | JSONL contains secrets from a scanned server; the operator commits it accidentally | medium (humans do this) | high — secondary disclosure of someone else's data |

Lowest-likelihood / highest-severity is the supply-chain row. That
drives most of the discipline below.

---

## 2 · Surface inventory

### 2.1 Python dependencies

Direct deps from `jakk/pyproject.toml`:
- `fastmcp>=2.0` — the MCP client. Heavy; pulls in mcp SDK and httpx.
- `pydantic>=2.7` — model definitions. Maintained, broad-ecosystem.
- `pyyaml>=6.0` — library loader. **`yaml.safe_load`** only.
- `httpx>=0.27` — HTTP transport (transitive via fastmcp).
- `rich>=13.0` — console rendering.

Indirect deps (via fastmcp): mcp SDK, anyio, sniffio, sse-starlette,
authlib, joserfc, jsonschema, keyring (and its keyring backends —
`jaraco.classes`, `jaraco.context`, etc.).

### 2.2 Input surfaces

| Input | Source | Trust level |
|---|---|---|
| `--endpoint` URL | Operator (CLI) | Trusted |
| `--library` YAML files | Operator-curated, on-disk | Trusted-but-loaded-via-safe_load |
| `--bearer` / `--oauth-token-file` | Operator | Secret-trusted |
| `--header KEY=VALUE` | Operator | Trusted |
| `--cred-a/-b`, `--foreign-id` | Operator | Secret-trusted |
| MCP server responses (`list_tools`, `call_tool` outputs) | **Hostile** target | Untrusted |
| MCP server tool descriptions / schemas | **Hostile** target | Untrusted |
| Environment variables | Operator host | Trusted |

The hostile rows are where matcher / parser robustness matters. A
crafted response that exploits a regex catastrophic-backtracking bug,
or a YAML/JSON parser quirk, or rich's terminal-control sequences,
could compromise the scan host.

### 2.3 Output surfaces

| Output | Destination | Risk |
|---|---|---|
| Console (Rich-rendered table) | Operator's terminal | Terminal-escape injection if matcher evidence isn't sanitized |
| JSONL findings file | Operator's filesystem | Contains evidence from scanned server — may include secrets |
| Process exit code | Caller (CI, shell) | Low |

---

## 3 · Today (what we already do)

### 3.1 Dependency hygiene
- `pyproject.toml` pins minimum versions, not exact. Upgrading
  brings security patches automatically; downside is undetected
  breaking changes.
- No pinned hashes (`requirements.txt` with `--hash=sha256:...`).
- `pip install -e .[dev]` is the documented install path; users run
  pip's dependency resolution against PyPI.

### 3.2 YAML loading
- `yaml.safe_load` only. No `yaml.load`, no custom tags, no
  pickle-equivalents. (`library.py:113`)
- Schema validation via Pydantic catches type errors at load time.
- Regex fields are pre-compiled at load (`AppliesTo._validate_regex`)
  so an invalid regex fails fast on `load_library`, not mid-scan.

### 3.3 Network
- All MCP traffic via `fastmcp.Client` with `StreamableHttpTransport`.
- TLS verification is fastmcp's default (httpx default = verify=True).
- `--timeout` defaults to 15s per call.
- Credentials never logged to console or JSONL (we log payloads, but
  for authz probes the payload is what was sent — operator decides
  whether that's sensitive).

### 3.4 Subprocess / system access
- jakk does NOT call out to subprocess, eval, exec, or os.system.
- jakk does NOT read environment variables directly except via the
  documented `--oauth-token-file` path (file read; standard error
  handling).
- jakk does NOT write to any path outside `--jsonl` (operator
  chooses the path).

### 3.5 Matcher robustness
- Regex matchers use Python's `re` (RE2-style backtracking — has
  catastrophic-backtracking failure modes on pathological inputs).
- No timeout on individual regex calls.
- Evidence snippets are truncated to 60-char radius around match,
  capped at 400 chars in `Finding.evidence`.

### 3.6 Rendering
- Rich console output. Rich has its own escape-sanitization layer,
  but matcher evidence is fed in via `table.add_row` which passes
  through Rich's markup parser.
- We do `replace("\n", " ⏎ ")` on evidence before adding to table —
  that's it. No `Text.from_markup(..., emoji=False)` or explicit
  escape.

### 3.7 Tests
- 75 unit tests. No live MCP server required for unit tests.
- No security-focused tests (no fuzzing of matchers against
  pathological inputs, no terminal-escape injection tests, no
  unicode-confusable tests).

---

## 4 · Pre-release checklist (before v1 tag)

Discrete tasks, each takes <1 hour. Run them all before tagging
v0.2.x → v1.0.

### 4.1 Dependency audit
- [ ] Run `pip-audit` (or equivalent) against the resolved dep tree.
      Resolve any CVEs above medium severity.
- [ ] Document the actual resolved versions (`pip freeze >
      jakk/requirements.lock`) at release time so users can pin
      defensively.
- [ ] Confirm fastmcp 3.x has no known CVEs at release date.

### 4.2 Output sanitization
- [ ] Wrap matcher evidence in Rich's `escape()` before passing to
      `table.add_row`. Prevents a hostile server from injecting
      terminal control sequences via tool response text.
- [ ] Add a unit test that scans a stub server returning
      `\x1b[2J\x1b[H` and confirms the scan output doesn't clear the
      terminal.

### 4.3 Matcher robustness
- [ ] Add per-regex timeout to the matcher loop (Python `re` doesn't
      support timeouts natively; wrap in a thread with a deadline,
      or use `regex` library which has `TimeoutError`).
- [ ] Add a unit test with a known catastrophic-backtracking pattern
      vs a hostile-shaped response. Should bail in <1s, not hang.

### 4.4 JSONL handling
- [ ] Document that JSONL findings can contain secrets from scanned
      servers. Recommend `.gitignore` patterns for `*.jsonl` in any
      project README that mentions running jakk in CI.
- [ ] Consider an optional `--redact-secrets` flag that scrubs the
      `evidence` field of any string matching `_DEFAULT_SECRET_PATTERNS`
      before write. (Conservative: scrub adds friction for triage;
      operator should opt in.)

### 4.5 Self-scan
- [ ] Run jakk against itself in a "self-scan stub": a small FastMCP
      server that wraps jakk's CLI as a tool. Confirm the wrapper
      doesn't accidentally expose anything sensitive. **This is not
      a release product; it's a one-time release-gate scan.**
- [ ] Document the result. Even an "all pass" outcome is data.

### 4.6 Threat-model the README's quick-start
- [ ] Confirm the documented quickstart (`pip install -e ".[dev]"
      && jakk mcp scan ...`) is the most-secure default. If we
      should be recommending a `--safe` first run for unknown
      targets, say so in the README.

### 4.7 Disclosure policy
- [ ] Add `SECURITY.md` at repo root with:
  - How to report a security issue in jakk itself
  - Expected response time (suggest: 48 hours for triage)
  - Public-disclosure window (suggest: 90 days)
  - List of jakk's own scope (jakk's code, library YAMLs, deps) vs
    out-of-scope (third-party MCP servers users point jakk at; their
    bugs are their disclosure paths)

### 4.8 Source provenance
- [ ] At v1 release, sign the GitHub tag with a GPG key.
- [ ] Publish a release artifact (sdist + wheel) with checksums in
      the GitHub release notes.
- [ ] Set up `pyproject.toml` `Trusted Publisher` config for PyPI
      uploads (GitHub Actions → PyPI without a long-lived token).

---

## 5 · Ongoing discipline (every release)

| Cadence | Task |
|---|---|
| Every PR | Run unit tests. Confirm no new dep added without explicit reason. |
| Every minor release | Re-run `pip-audit`. Refresh `requirements.lock`. |
| Every release | Read the release notes of fastmcp + mcp SDK + pydantic for any security-relevant changes. |
| Quarterly | Re-run the pre-release checklist §4 above as an audit. |
| On any reported issue | Triage within 48 hours per SECURITY.md. |

---

## 6 · What changes if we ever ship as MCP server

We currently do not (per ADR). If that decision reverses, the
hardening scope expands materially:

| Today (CLI) | If we ship as MCP server |
|---|---|
| Output is for one operator's terminal | Output is consumed by an LLM client — every byte is a potential prompt-injection surface |
| One untrusted-input source (the scanned server) | Two: the scanned server AND the calling LLM agent (which itself may be steered by adversarial content) |
| State lives in operator's filesystem | State lives in jakk-the-server's process — needs explicit auth, persistence policy, multi-tenant isolation |
| One CVE class to worry about (RCE on operator host) | Plus: schema poisoning of OUR descriptions, directive smuggling in OUR responses, cross-tenant data leakage in OUR scan history |
| Pre-release checklist is ~8 items | Pre-release checklist roughly doubles |

The dogfooding obligation: jakk-as-MCP-server must be scanned by
jakk-as-CLI-scanner before every release, and must come out clean on
all eleven probes. That's a meaningful engineering tax — and the
direct reason the ADR declined to take it on for v1.

If we ever reverse the ADR, **the first PR after the reversal is to
add the self-scan to CI, not to write the server**. No "we'll add
hardening later." That's how security tools get compromised.

---

## 7 · The 11 probes against jakk itself (if hypothetically MCP-shipped)

This isn't a planned scan — it's the audit you'd have to commit to
if we ever shipped jakk as an MCP server. Documented so the cost is
explicit.

| Probe | Applies to jakk-as-server? | What we'd have to harden |
|---|---|---|
| `mcp.command.shell_marker` | Maybe (only if a future tool calls subprocess) | No shell-out from any exposed tool. |
| `mcp.command.secret_file_read` | Same | Same. |
| `mcp.path.prefix_bypass` | Maybe (only if we expose a file-read tool) | No file-path arguments without canonical-path resolution + allowlist via realpath comparison, not startswith. |
| `mcp.path.canary_file_read` | Same | Same. |
| `mcp.response.secret_overshare` | **Yes** | Scan history must not return secrets even if they're in evidence. |
| `mcp.response.directive_passthrough` | **Yes** | Scan results contain content from scanned servers — must escape / quote anything LLM-directive-shaped before returning. |
| `mcp.schema.description_smuggling` | **Yes** | Our tool descriptions must contain zero directive-style content. Audit at every release. |
| `mcp.auth.no_credential` | **Yes** | jakk-as-server requires auth on every call. No public mode. |
| `mcp.auth.invalid_token` | **Yes** | Token validation, not just presence. JWT signature + expiry + audience. |
| `mcp.auth.wrong_prefix` | **Yes** | Strict RFC 6750 scheme parsing. |
| `mcp.authz.cross_tenant_read` | **Yes** | If multi-tenant, per-call ownership check on every accessed resource (scan history, target list, credentials). |

8 of 11 probes apply directly. Two more (`shell_marker`,
`secret_file_read`) apply conditionally based on tool design.

In other words: shipping as an MCP server obligates jakk to be one
of the more hardened MCP servers in existence. That's a defensible
goal but a real cost — and one the ADR currently says we don't take
on.

---

## 8 · What we explicitly DO NOT do

| Practice | Why we don't |
|---|---|
| Auto-update dependencies on user install | Surprises users; supply-chain attackers love auto-update windows. Users pin defensively. |
| Bundle third-party probe libraries from URLs | `--library` accepts a local directory only. No HTTP fetch of YAMLs. |
| Allow YAML to declare arbitrary Python imports | Pydantic models are fixed; YAML can only set declared fields. |
| Telemetry / phone-home | jakk makes no outbound connection except to `--endpoint`. |
| Read configs from `~/.jakk` or `XDG_CONFIG_HOME` by default | All config is explicit CLI flags. Reduces "where did this setting come from" confusion. |
| Auto-detect and use any installed MCP credentials | Credentials are explicit CLI args. |

These are *features* of the threat model, not omissions. Each one
we add later trades a small operator convenience for an enlarged
attack surface.

---

## 9 · References

- ADR — `mcp-server-distribution-decision.md`
- Probe catalog — `docs/README.md`
- Threat models — `docs/threat-models.md`
- Disclosure methodology (for users) — `docs/depth-of-exposure-methodology.md`
- (Pre-v1) `SECURITY.md` at repo root — to be added in §4.7
