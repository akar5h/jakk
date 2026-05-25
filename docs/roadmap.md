---
date: 2026-05-23
status: forward roadmap — near-term build queue + deferred-with-reasons
scope: what's next, what's parked and why, with the analysis behind each call
---

# jakk roadmap

Two tiers: **near-term** (actively queued for v0.3) and **deferred**
(parked with the reasoning, so we don't relitigate or forget). Every
deferral records *why* it's not now and *what would change the call*.

---

## Near-term (v0.3 build queue, ranked)

| # | Item | Status | Why this rank |
|---|---|---|---|
| 1 | **Context-arg supply** — fill non-target required args (`owner`, `repo`) with valid values via `--arg k=v` or a context file | queued | Biggest coverage blocker. Until fixed, jakk can't probe ANY multi-arg production tool — it errors on `get_file_contents` before testing. Surfaced by the GitHub run. |
| 2 | **SSRF probe** (`mcp.ssrf.cloud_metadata`) | **in progress** | Research-backed: 36.7% of 7,000 scanned servers vulnerable (BlueRock); real AWS IAM key retrieval via cloud metadata. Uses the dormant `url` arg-kind. Deterministic, HTTP-scoped, jakk-shaped. |
| 3 | **`query`-kind probe** | queued | GitHub exposes 5 `search_*` tools with `query` args no probe targets. Query-syntax injection + over-broad result leakage. The `query` arg-kind already exists in the registry. |
| 4 | **`auth.wrong_prefix` severity recalibration** | ✅ done | high → low; reworded as spec-laxity not bypass. |

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

### D6 · stdio transport

**Why deferred — effectively permanently.** jakk targets HTTP
production servers; stdio is single-user local-dev where the auth +
authz probes don't apply. See `scope-decision.md`. Escape hatch:
stdio-default servers that also ship HTTP mode get run in HTTP mode.

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
