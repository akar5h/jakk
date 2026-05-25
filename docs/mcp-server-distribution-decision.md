---
date: 2026-05-23
status: Architecture Decision Record (ADR)
decision: jakk will NOT ship as an MCP server for v1.
                  Distribution mechanism is CLI (PyPI + GitHub).
revisit: v2 (post-launch) — only if the dogfooding cost is genuinely
                  paid down and a real user need surfaces.
---

# ADR — Should jakk ship as an MCP server?

## Context

A pattern circulating in the offensive-MCP space is to ship security
tooling *as* an MCP server. Other LLM clients can then install the
tool from a registry and invoke it inline ("Claude, scan this server
for vulnerabilities"). The framing — "MCP-on-MCP", "MCP scanning MCP"
— is sticky and gets traction on social media.

This ADR records the decision *not* to do that for jakk v1, and the
reasons.

---

## The framing question

Two ways to consume jakk:

| Mode | Consumer | Interface | Distribution |
|---|---|---|---|
| **A. CLI tool** (what jakk is today) | Human security engineer | `jakk mcp scan ...` | PyPI / GitHub |
| **B. MCP server** (the alternative pitch) | LLM agent | `tools/call jakk_scan(...)` | MCP server registry |

Both *can* exist. The question is which is the primary distribution
and which (if any) is a secondary convenience.

---

## Arguments for Mode B (the MCP-server pitch)

1. **Adoption / stars.** Anyone running Claude Desktop, Cursor,
   Cline, or another MCP-aware client can install jakk from a
   registry and use it without touching a terminal. Lower friction
   for casual users. Higher star count.
2. **Composition.** Agents can call jakk inside a security-engineering
   workflow ("scan this server, then summarize the findings, then
   open a Jira ticket"). Demo-ready story.
3. **MCP-on-MCP framing.** Self-referential, sticky on Twitter / HN,
   matches the moment.

---

## Arguments against Mode B

### 1. The actual user is not an LLM

Security engineers, AppSec teams, and bug-bounty hunters live in a
terminal. They want:
- JSONL output piped into `jq` and downstream tooling
- A scan-then-grep-then-diff workflow
- Reproducible commands they can paste into a runbook
- CI integration via exit codes

An LLM-mediated interface puts a layer of natural-language paraphrase
between the operator and the scan output. That's friction, not
convenience, for the audience that *should* care.

### 2. The composition story is overstated

The "agent calls jakk during a workflow" story sounds compelling
until you ask which workflow. Concrete cases:

- "Scan this server before deploying" → CI does this via the CLI. No
  agent needed.
- "I'm chatting with my agent and want to test a hypothesis" → fine,
  but a terminal one-liner is faster than dictating tool args.
- "Run jakk continuously and alert me" → a cron + Slack webhook is
  simpler than an MCP-server-plus-agent loop.

The only case where Mode B genuinely wins is "I don't know how to use
a terminal." That's not the user we should optimize for if the
product is supposed to be a credible security tool.

### 3. The dogfooding cost is real, not theoretical

If jakk ships as an MCP server, jakk's tool descriptions, schemas,
and responses *become things attackers can manipulate*. Specifically:

| jakk's own probe class | Applies to jakk-as-MCP-server? |
|---|---|
| `schema.description_smuggling` | Yes. Our tool descriptions are now an injection surface against LLM clients consuming us. |
| `response.directive_passthrough` | Yes. Our scan-result text could contain attacker-controlled content (echoed evidence) that the consuming LLM treats as authoritative. |
| `response.secret_overshare` | Yes. We must scrub our own JSONL output for secret-shaped strings before returning it. |
| `command.shell_marker` / `secret_file_read` | Yes if our scanner calls subprocesses. (It doesn't currently — but adding any system tooling becomes a sink.) |
| `auth.*` | Yes. If jakk-as-MCP-server is reachable on a network, it must enforce its own auth. |
| `authz.cross_tenant_read` | Yes if jakk-as-MCP-server holds per-tenant state (saved scans, credentials, target lists). |

In other words: shipping as MCP means *applying jakk's own scan
classes to itself, hardening accordingly, and re-scanning on every
release*. That's a meaningful engineering tax for an audience that
doesn't need it.

### 4. "MCP-on-MCP" is aesthetic, not technical

The framing is sticky because it sounds clever, not because it serves
the user. Naming an architecture choice because it tweets well is the
opposite of the engineering culture we want around a security tool.

### 5. The better positioning is honest about layers

jakk attacks the **server**. The interesting "MCP attacking" target is
the **LLM agent that consumes MCP** — that's its agent-side sibling's job, and its agent-side sibling
is fundamentally multi-turn LLM-driven. So:

- jakk = server-side half of MCP security testing (the infrastructure)
- its agent-side sibling = agent-side half (the LLM behavior under indirect injection)

That two-part decomposition is the durable, honest positioning. "MCP-
on-MCP" muddles it.

### 6. Time-to-launch

Wrapping jakk as an MCP server adds:
- Server skeleton (FastMCP-based)
- Tool descriptions written for LLM consumption (different audience than CLI help text)
- Auth layer for the server itself
- Persistent state for scan history (or explicit statelessness)
- Documentation for installation in N different MCP-aware clients
- Dogfooding the above per release

Order of magnitude: 1-2 weeks of engineering plus ongoing maintenance.
For v1 with a 4-day target, this is straightforwardly out of scope.

---

## Decision

**For v1: jakk ships as a CLI tool only.** PyPI distribution. GitHub
repo. README + docs. No MCP-server wrapping.

**For v2 / post-launch:** Reconsider only if all three hold:
1. Real users (with names and email addresses) request the MCP-server
   variant for a workflow that can't be served by the CLI.
2. The dogfooding cost is paid down — specifically, a documented
   self-scan pre-release process exists and runs clean.
3. A clear positioning emerges that doesn't muddle the
   "server-side vs agent-side" split with its agent-side sibling.

If those don't hold, v2 also stays CLI-only.

---

## Implications for what we DON'T build

| Component | Status |
|---|---|
| `jakk/server.py` (FastMCP server wrapper) | Don't build. |
| Tool descriptions for LLM consumption | Don't write. |
| MCP-server registry submission | Don't pursue. |
| Persistent scan-history database | Don't build. |
| Multi-user / multi-tenant scan service | Don't build. |
| Agent-callable JSON output format (separate from JSONL) | Don't build. |
| LLM-friendly help text (parallel to CLI `--help`) | Don't write. |

These are all real costs we *avoid* by deciding now rather than
post-launch.

---

## Implications for what we DO need

Even staying CLI-only, the v1 launch should:

1. **Read the dogfooding doc** (`system-hardening.md`) before any
   release. CLI tools have their own attack surface (dependencies,
   config files, env vars); we should not be hand-wavy about ours
   just because we declined the MCP-server route.
2. **Frame jakk's positioning** (in the README) without using the
   "MCP-on-MCP" phrase. Lead with "black-box scanner for MCP
   servers" — clear, accurate, unambiguous.
3. **Acknowledge the MCP-server option exists, and why we declined**
   in launch-prep FAQ (Q5) and any external Q&A. Treat it as an
   informed choice, not an oversight.

---

## What would change this decision?

Signals that would prompt revisiting:

- ≥5 unsolicited GitHub issues requesting MCP-server distribution from
  identifiable security-engineering personas (not "would be cool if").
- A vendor or platform partner specifically asks for MCP-server
  variant for an integration we want.
- The its agent-side sibling side of the split lands MCP-server distribution and
  proves the audience exists.
- A new MCP feature (e.g. attestation, signed servers) materially
  reduces the dogfooding cost.

Absent those, the answer remains no.

---

## References

- Launch prep FAQ Q5 — public-facing version of this decision
- System hardening doc — what the dogfooding cost would look like in practice
- Positioning doc — the "server-side vs agent-side" split with its agent-side sibling
- v0.2 discovery §3 — "Decisions and why" table; this ADR extends one of those rows
