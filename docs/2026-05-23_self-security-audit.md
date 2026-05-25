---
date: 2026-05-23
status: jakk self-security audit — pre-v0.2-release gate
scope: jakk's OWN attack surface (a scanner that gets compromised is worse
       than no scanner). Bugs, edge cases, vulns, exploits, supply chain.
verdict: 3 findings fixed, 0 open high/critical. Cleared for v0.2.
related: docs/system-hardening.md (the threat model this executes)
---

# jakk self-security audit (2026-05-23)

A security tool that gets compromised gains its users' trust while
leaking their data. Before calling v0.2 done, this audits jakk's own
attack surface — what a malicious MCP server jakk *scans*, or a hostile
dependency, could do to the scanner host.

**Verdict: 3 findings, all fixed. No open high/critical. Cleared for v0.2.**

---

## 1 · Method

- Supply-chain: `pip-audit` on jakk's *isolated* dependency closure (clean venv, jakk only — not the shared dev venv).
- Code sinks: grep for `eval`/`exec`/`os.system`/`subprocess`/`pickle`/`yaml.load`/`shell=True`.
- Untrusted-input flow: trace how a scanned server's responses, tool names, and schemas reach regexes, the console renderer, and output files.
- Path/credential handling: trace `--jsonl`, `--oauth-token-file`, `--library`, `--bearer`, `--cred-*`.

The threat actor of interest: **a malicious MCP server that jakk is
pointed at.** jakk sends it probes; it sends back arbitrary responses.
Those responses must not be able to execute code, corrupt the terminal,
exhaust memory, or exfiltrate the operator's secrets.

---

## 2 · Supply chain — CLEAN

jakk's true dependency closure (isolated venv, 93 packages) flagged
**one** package:

| Package | CVE | Note |
|---|---|---|
| `setuptools 69.0.2` | CVE-2024-6345 (RCE via package download), PYSEC-2025-49 (ReDoS in metadata parsing) | **Build-time only.** Not imported by jakk at runtime. Present as the venv's default build tool. |

Recommendation: pin `setuptools>=78.1.1` in CI / release environments.
Not a runtime risk to a jakk scan.

**Important context:** an audit of the *shared* dev venv showed ~30 CVEs
(aiohttp, langchain-core, langgraph, langsmith, requests, urllib3, pip,
pygments, ...). **None of those are jakk's** — they belong to its agent-side sibling,
langchain, and dev tooling. jakk's runtime deps (fastmcp, pydantic,
pyyaml, httpx, rich + their transitive closure) resolved clean. This is
exactly why jakk ships as a separate package with its own `pyproject.toml`:
its closure can be audited independently of its agent-side sibling's.

---

## 3 · Code sinks — NONE

No dangerous execution primitives anywhere in `jakk/`:

- No `eval`, `exec`, `compile`-of-input, `os.system`, `subprocess`, `shell=True`.
- No `pickle` / `marshal` / `__import__` of untrusted data.
- YAML loaded with **`yaml.safe_load` only** (no `yaml.load`, no custom tags).
- No code path turns a scanned server's response into executable anything.

jakk is a read-and-match tool. It connects, calls tools, regex-matches
responses, writes findings. There's no sink for RCE from server data.

---

## 4 · Findings (all fixed)

### F1 · Rich markup injection via untrusted output — MEDIUM — FIXED

**Issue.** The console renderer passed `evidence` and `tool_name`
(both attacker-controlled — from the server's responses and tool list)
directly into `rich`'s `table.add_row`. Rich *interprets* markup like
`[red]`, `[/]`, `[link=file:///...]` in those strings. A malicious
server could return a response — or name a tool — containing Rich markup
to corrupt the operator's terminal output, hide/forge finding rows, or
abuse Rich markup features (e.g. clickable `link` tags).

**Fix.** `rich.markup.escape()` applied to every untrusted field
(`evidence`, `tool_name`, `test_id`, `expected_signal`) before
`add_row`. Markup characters now render as literal text.

**Tests.** `test_render_escapes_markup_in_evidence`,
`test_render_escapes_markup_in_tool_name`,
`test_render_does_not_crash_on_unbalanced_markup`.

### F2 · Unbounded response → memory DoS — MEDIUM — FIXED

**Issue.** `_flatten_content` assembled the *entire* server response
into a string with no size limit, then regexes ran over the whole thing.
A hostile (or buggy) server returning a multi-GB body could exhaust
scanner memory before any matching happened.

**Fix.** `_flatten_content` caps the assembled text at **1 MiB**
(`_MAX_RESPONSE_CHARS`), appending a truncation marker. 1 MiB is far more
than any real finding needs — secrets, metadata docs, and markers all
appear early in a response — and matcher evidence is itself
snippet-truncated downstream. Bounds both memory and regex CPU.

**Tests.** `test_flatten_content_caps_oversized_response`,
`test_flatten_content_preserves_small_response`,
`test_flatten_content_truncates_early_content_block`,
`test_flatten_content_cap_is_configurable`.

### F3 · Operator credentials leaked into findings/JSONL — MEDIUM — FIXED

**Issue.** The authz probe stored its resolved phase arguments in the
finding payload — and those args contained the *expanded* credential
values (`--cred-a <token>` → the real token). JSONL output therefore
contained the operator's credentials in plaintext. JSONL files get
committed to repos, attached to bug reports, ingested by CI — a real
leak path for the operator's own secrets. Context args (`--arg`) and
corroboration call args had the same exposure.

**Fix.** `_redact_args` masks any stored arg whose value exactly matches
a known secret (`--bearer` / `--cred-a` / `--cred-b`) with a placeholder
(`<bearer>` / `<cred_a>` / `<cred_b>`). Applied at every payload-storage
site (tool_call findings, both authz phases, corroboration calls). The
actual tool call still uses the real value; only the stored/displayed
copy is masked.

**Verified live.** Authz scan of ch01 with `--cred-a alpha-api-key`:
JSONL contains `<cred_a>`/`<cred_b>`, zero occurrences of the raw keys,
and the probe still fires `vulnerable` (functionality intact).

**Tests.** `test_redact_args_masks_known_credentials`,
`test_redact_args_noop_when_no_secrets`,
`test_redact_args_leaves_nonmatching_values`.

---

## 5 · Reviewed and found acceptable (no change)

| Area | Assessment |
|---|---|
| **ReDoS in matchers** | All matcher regexes are linear-time — single quantifiers, negated classes (`[^}]+`), bounded repeats (`{16}`, `{36}`). No nested quantifiers (`(a+)+`). The 1 MiB response cap (F2) further bounds worst-case regex time. LOW. |
| **Path handling** (`--jsonl`, `--oauth-token-file`, `--library`) | All paths are operator-supplied CLI args, never server-derived. No traversal/injection vector — the operator chooses where to read/write on their own machine. LOW. |
| **SSRF against the scanner** | jakk only connects to `--endpoint` (operator-supplied). Server responses never cause jakk to make further requests. Unlike the servers it scans, jakk does not fetch server-controlled URLs. None. |
| **Malformed/empty library** | `load_library` fails fast with the file path on bad YAML; empty selection exits 1. Covered by tests. LOW. |
| **Unicode / weird tool schemas** | Python `str` handles unicode; `ToolDescriptor` tolerates missing/None fields; markup escape (F1) handles unicode-confusable markup. LOW. |
| **TLS** | fastmcp/httpx default `verify=True`. jakk doesn't disable it. OK. |
| **No telemetry / phone-home** | jakk makes no outbound connection except to `--endpoint`. Confirmed. |

---

## 6 · Residual risks (documented, not fixed)

| # | Risk | Why accepted |
|---|---|---|
| R1 | JSONL `evidence` can still contain **secrets the scanned server leaked** (that's the *point* of `secret_overshare` / `secret_file_read` / SSRF — they surface the server's secrets). | This is intended output, not a jakk leak. The operator chooses the JSONL path. Mitigation documented: `.gitignore *.jsonl`, treat findings files as sensitive. A future `--redact-server-secrets` flag could scrub them, at the cost of triage signal. |
| R2 | `_redact_args` masks by **exact value match**. A credential embedded as a *substring* of a larger arg, or transformed before sending, wouldn't be masked. | The credential template tokens (`{cred_a}`) are substituted whole, so exact-match covers the real cases. Substring redaction risks over-masking benign values. Acceptable. |
| R3 | Corroboration `response` text is held in memory per call (now capped at 1 MiB each, F2). | Bounded after F2. Three calls × 1 MiB worst case. Acceptable. |
| R4 | setuptools build-time CVE (§2). | Build-time only, not runtime. Pin in CI. |

---

## 7 · Test coverage added

`tests/unit/test_jakk_security.py` — 10 cases pinning F1/F2/F3:
markup escaping (evidence + tool_name + unbalanced), response cap
(oversized, small, configurable, early-block), credential redaction
(masks known, noop, non-matching). Total suite: 133 → 143.

---

## 8 · Verdict

| | |
|---|---|
| Code-execution sinks | none |
| Supply-chain (runtime closure) | clean (1 build-time setuptools CVE) |
| Findings | 3, all fixed (F1 markup, F2 DoS, F3 cred leak) |
| Open high/critical | 0 |
| Residual risks | 4, all documented + accepted |

**jakk is cleared for v0.2.** A malicious server jakk scans cannot
execute code on the scanner, corrupt the terminal (F1), exhaust its
memory (F2), or cause the operator's own credentials to leak into
output files (F3). The remaining residual risks are documented and
operator-manageable.

---

## 9 · Pre-release checklist status (from system-hardening.md §4)

- [x] Dependency audit (pip-audit on isolated closure) — clean bar setuptools
- [x] Output sanitization (Rich escape) — F1 fixed
- [x] Matcher robustness — regexes linear + 1 MiB input cap (F2)
- [x] JSONL credential handling — F3 fixed (server-secret redaction is R1, documented)
- [ ] `SECURITY.md` at repo root — TODO before public release
- [ ] GPG-signed release tag + checksums — TODO at tag time
- [ ] PyPI Trusted Publisher — TODO at publish time
- [x] Self-scan capability (jakk-as-server) — N/A: ADR declined MCP-server distribution

Remaining unchecked items are release-mechanics (SECURITY.md, signing,
PyPI) for whenever v0.2 is tagged/published, not code risks.
