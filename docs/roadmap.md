---
date: 2026-05-23
status: forward roadmap — launch-ready v0.2 + next build queue
scope: what's next, what's parked and why, with the analysis behind each call
---

# jakk roadmap

Three tiers: **v0.2 launch-ready** (already built), **near-term** (next
highest-leverage work), and **deferred** (parked with reasoning, so we
don't relitigate or forget). Every deferral records *why* it's not now
and *what would change the call*.

---

## v0.2 launch-ready

| Item | Status | Notes |
|---|---|---|
| **GitHub Action form factor** | done | Safe-by-default CI scan, JSONL output, optional PR gating. |
| **Context-arg supply** (`--arg k=v`) | done | Closes the GitHub MCP multi-required-arg coverage gap. |
| **SSRF probe** (`mcp.ssrf.cloud_metadata`) | done | Uses `url` arg-kind and cloud metadata matcher. |
| **`query`-kind SQLi probe** (`mcp.sql.error_based`) | done | First query-kind probe; error-based MVP. |
| **`auth.wrong_prefix` severity recalibration** | done | high -> low; framed as spec-laxity/hardening. |
| **Stdio smoke scans** (`--stdio`) | done | Local input-handling/schema scan support; auth probes skip as N/A. |

---

## Near-term (next build queue, ranked)

| # | Item | Status | Why this rank |
|---|---|---|---|
| 1 | **SARIF output** | queued | Best GitHub-native upgrade: findings show in code scanning/security UI instead of only JSONL artifacts. |
| 2 | **Action examples for common MCP stacks** | queued | Short, copy-paste workflows for FastMCP, Node MCP SDK, and Docker Compose targets reduce first-run friction. |
| 3 | **Per-tool context map** | queued | Current `--arg` is global. A context file keyed by tool name helps servers whose tools need different valid IDs. |
| 4 | **BOLA write / stored-injection chain probe** | queued | Builds on the ch01-extended experiment; high-impact but needs careful side-effect controls and restore semantics. |

---

## Deferred (parked with reasons)

### D1 · Rug-pull / tool-definition-drift detection

**What it is.** A rug-pull server shows a clean tool list at approval
time, then silently swaps in a malicious version later (usually hidden
instructions in a tool description) — after the user has already
granted trust. Coined by Invariant Labs (April 6, 2025) alongside tool
poisoning; PoC `whatsapp-takeover.py` swaps its interface on second
load to make a parallel WhatsApp MCP leak chat history without
re-approval.

**Novelty: HIGH.** No widely-used scanner detects it deterministically.
It attacks the *trust-over-time* dimension that single-snapshot tools
miss by design. A solid detector would be a genuine differentiator as
of May 2026.

**Confidence: LOW — four concrete reasons a single-connect scanner struggles:**

1. **The swap is *triggered*, not on a clock we control.** Smart
   rug-pulls flip on a date, a call count, the caller's identity
   (clean for anyone who looks like an auditor), randomness, or a
   remote kill-switch. Scanning twice in 5 seconds won't trip a change
   set to fire in two weeks or after 1,000 calls.
2. **Can't distinguish malicious swap from normal update.** Servers
   update tools legitimately all the time. A diff shows *a* change —
   feature release or rug pull? Without an expected baseline, every
   update looks suspicious. High false-positive risk.
3. **jakk is deliberately stateless.** Detection needs memory of
   "before" — a saved baseline to diff against. That's a
   record-now / re-scan-later / diff workflow, a different operating
   model than "point and scan."
4. **The payload may never touch `tools/list`.** Some rug-pulls change
   what a tool *returns at call time*, conditionally — that's
   `response.directive_passthrough` territory, and catching the
   conditional version means triggering the condition, which jakk
   can't reliably do.

**What jakk could honestly ship (the partial version):**
- Snapshot `tools/list` (names + descriptions + schemas) as a saved baseline.
- On a later scan, diff against the baseline; flag changes — especially
  ones that *add* directive-shaped content to a description (reuse the
  `schema_field` matcher on the diff).
- Run the poison-check on every snapshot, so the first scan catches
  already-poisoned tools and the diff catches newly-poisoned ones.

Catches the **crude** rug-pull (descriptions changing between two scans
you run). Does NOT catch the conditional/caller-aware/time-bombed kind.
We'd ship a probe honest about catching the easy version only.

**What would change the call.** Promote to near-term if: (a) we add the
stateful baseline-store anyway for another reason, or (b) a specific
engagement needs crude rug-pull detection and the partial version
suffices.

**Reading:**
- Invariant Labs, "MCP Tool Poisoning Attacks" (Apr 6, 2025) — origin + PoC
- arXiv 2508.12538, "Systematic Analysis of MCP Security" — taxonomy
- CyberArk, "Poison everywhere: No output from your MCP server is safe" — the response-time variant the partial detector misses

### D2 · Parser-differential auth bypass (`mcp.auth.parser_differential`)

**What it is.** A probe that, given a real gateway-fronted server,
hunts for a request the gateway treats as unauthenticated but the
origin executes (header smuggling / scheme confusion).

**Why deferred.** Only meaningful against a REAL gateway-fronted hosted
target. Building it against our own localhost server requires authoring
the gateway = constructing the conclusion (circular). See
the parser-differential analysis (kept internal) for the full reasoning.

**What would change the call.** A bug-bounty engagement against a hosted
MCP that genuinely sits behind a gateway (Cloudflare-fronted Notion,
Atlassian, etc.), where the differential would be a real bypass.

### D3 · Two-credential authz against a real hosted target

**What it is.** `mcp.authz.cross_tenant_read` (built) aimed at a real
multi-tenant hosted MCP — two accounts, a private resource owned by A,
test whether B can read it.

**Why deferred.** Needs two real accounts + a private resource + a
bug-bounty program that covers MCP testing + the full pre-flight from
`depth-of-exposure-methodology.md`. Days, not hours; real legal stakes.

**What would change the call.** A confirmed in-scope bounty program and
disposable test accounts.

### D4 · jakk → agent-side-sibling memory seed

**What it is.** Feed jakk's findings into its agent-side sibling's strategic memory so
the adaptive multi-turn engine can skip discovery and jump to
escalation on tools jakk already flagged.

**Why deferred.** Needs its agent-side sibling's consumer side built first. Low
urgency until both tools are being run on the same target.

### D5 · MCP-server distribution of jakk

**Why deferred.** Declined for v1 — see
`mcp-server-distribution-decision.md`. CLI fits the user; MCP-server
form adds a dogfooding tax (8 of 11 probes would apply to
jakk-as-server) for no user benefit.

---

## Explicit non-goals (not deferred — declined)

- Random/grammar fuzzing of tool inputs (FP mountain; PromptFoo/Garak don't help with MCP surface).
- LLM-judge matchers (violates the deterministic design; that's its agent-side sibling's job).
- Web UI (CLI + JSONL until findings volume justifies it).
- Supply-chain / package-squatting analysis (not black-box scannable; different tool category).
- Client-side attacks (consent bypass, config injection like Claude Code CVE-2025-59536) — out of jakk's server-side scope.

---

## How items move from deferred → near-term

A deferred item promotes when its "what would change the call" trigger
fires. Re-rank near-term by leverage (does it unblock other work?) over
novelty (is it a cool attack?). The GitHub run is the template: it
surfaced context-arg supply (#1) as higher-leverage than any new probe,
because without it the existing probes can't even run against real
multi-arg tools.
