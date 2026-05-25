---
date: 2026-05-23
status: methodology playbook — public-shareable
scope: deepening a confirmed MCP authorization finding into a complete
       impact assessment, without overstepping into harm
audience: security researchers, bug-bounty hunters, internal red teams
companion: docs/threat-models.md (what "vulnerable" means per class)
---

# Depth-of-exposure methodology for MCP authorization findings

A single jakk `vulnerable` finding tells you **the property exists**.
It does not tell you **how far the bug goes**. This playbook is for the
step *after* the scanner: turning one confirmed cross-tenant /
authorization bug into an honest impact assessment, with the smallest
possible footprint and the strongest possible evidence chain.

This is a procedural document, not a script. It assumes you're acting
under explicit authorization — your own lab, a bug-bounty program's
defined scope, or a paid engagement. If none of those apply to your
target, **stop reading and stop testing**: the techniques below are
indistinguishable from intrusion without authorization.

Worked examples in this playbook use a deliberately-vulnerable local
lab (`examples/external_targets/ch01-extended/`) so every measurement
is reproducible without touching anyone else's data.

---

## 1 · Premise

When jakk fires `mcp.authz.cross_tenant_read` (or its equivalent on
another scanner), the operator has proven one fact: **identity B can
read at least one object belonging to identity A**. That's the entry
point. The bug's real impact depends on four orthogonal axes:

```
   ┌─────────────────────────┐    ┌─────────────────────────┐
   │  Axis 1 — Tool breadth  │    │  Axis 3 — Data classes  │
   │  How many tools leak?   │    │  Metadata / PII /       │
   │                         │    │  secrets / attachments? │
   └────────────┬────────────┘    └────────────┬────────────┘
                │                                │
                ▼                                ▼
       ┌────────────────────────────────────────────────┐
       │   One confirmed finding (jakk vulnerable=1)    │
       └────────────────────────────────────────────────┘
                ▲                                ▲
                │                                │
   ┌────────────┴────────────┐    ┌────────────┴────────────┐
   │ Axis 2 — IDs            │    │ Axis 4 — Read vs write  │
   │ How guessable are       │    │ Can the attacker        │
   │ foreign object IDs?     │    │ also modify A's data?   │
   └─────────────────────────┘    └─────────────────────────┘
```

A single read of one record may have small impact (mid-severity).
Three read tools leaking, sequential IDs, secret-class fields exposed,
and write capability is a high-severity, easy-to-exploit, hard-to-
detect compromise of every customer on the server. Same root cause,
ten times the blast radius.

Operators triaging the finding need both data points: **the bug**, and
**how far it reaches**. Bug-bounty submissions that include axis-level
measurements are routinely paid 3-10× more than equivalent submissions
that say only "B can read A's data" — because the vendor's engineer
gets the full impact picture immediately and doesn't have to recreate
it.

---

## 2 · Pre-flight (do this BEFORE the first request)

Skipping any of these turns lawful research into unlawful access. The
checks take 10 minutes; the consequences of skipping them are
career-ending. Do them every time.

### 2.1 · Read the bounty program scope, in full

For each candidate target, the bounty program defines:

- **Which systems are testable** (often: vendor's own infrastructure, vendor's product, vendor's API; almost never: customer instances, partner services, sub-processors).
- **Which techniques are allowed** (usually read-only enumeration; rarely write operations; never DoS / mass scanning).
- **What data is off-limits** (real customer data, PII, payment data — even when you can technically reach it).
- **What the disclosure timeline is** (most programs: report immediately when proven, 90-day public disclosure window).

Print the scope. Highlight what you intend to do. If anything you
plan isn't explicitly covered, **assume it isn't authorized**.

### 2.2 · Create disposable test identities

Both identities (A and B) must be under your control. Real customer
accounts are off-limits even if you have valid credentials.

For most commercial targets:
- Create two free-trial accounts in different workspaces.
- Use distinct email domains so the vendor's heuristics don't dedupe.
- Pay for the minimum tier if free trials aren't available; expense it.
- Document the workspace IDs / account IDs at creation — you'll need them in the disclosure.

For self-hosted labs (like `ch01-extended`): the two identities are
the fixed credentials in the lab. No setup required.

### 2.3 · Write stop conditions BEFORE the first request

A pre-engagement note that says exactly:

- "I will stop after N confirmed leaks per axis." (Default: N=1 for read; N=1 for write.)
- "I will not access foreign objects whose owner I cannot identify."
- "I will not retrieve more than X bytes of foreign data in total." (Default: X = small — kilobytes, not megabytes.)
- "I will report within 24 hours of confirmed exploitation."

Write this BEFORE testing. If during testing you find yourself
arguing "but I should keep going to prove …", you've left the
research frame. Stop, file what you have.

### 2.4 · Single-tester rule

Don't share findings, credentials, or proof artifacts with anyone
until disclosure is complete. Authorization usually attaches to *you*,
not a team. A second tester operating off your write-up is, legally,
an unauthorized actor with insider knowledge.

---

## 3 · The four-axis model

Each axis answers one question, uses one procedure, produces one
metric. Run them in the order below — earlier axes inform later ones,
and the lowest-risk axes go first.

| # | Axis | Question | Risk |
|---|---|---|---|
| 1 | Tool breadth | Does the leak apply to one tool or many? | Low — same-shape calls, foreign reads only |
| 2 | ID predictability | Can the attacker guess foreign IDs without prior knowledge? | Lowest — uses ONLY your own data |
| 3 | Data classes | What kinds of fields come back? | Low-Med — one foreign read per axis 1 finding |
| 4 | Read vs write | Can the attacker also modify foreign objects? | High — destructive, gated by explicit flag |

Recommended order: 2, 1, 3, 4 (least to most risky).

---

## 4 · Axis 2 — ID predictability

**Run this first.** It uses only your own data, so it carries the
lowest risk. The result calibrates everything that follows: if foreign
IDs are unguessable, the bug's reach is bounded by what the attacker
can otherwise discover; if they're predictable, every leak is one of
millions.

### 4.1 · Procedure

1. As identity A, call any listing or creation tool that returns
   object IDs. Capture the IDs.
2. Repeat in identities A1, A2, A3 (different test accounts /
   workspaces / sessions) to get more samples without touching foreign
   data.
3. Analyze the ID set:
   - What's the regex shape? (`CRM-\d{4}`, `proj_[a-z0-9]{8}`,
     UUID v4, snowflake IDs, etc.)
   - What's the gap between consecutive issued IDs?
   - Is there a tenant component embedded in the ID?

### 4.2 · Metric

Three labels, with rough enumeration cost:

| Label | Shape | Cost to scan full space |
|---|---|---|
| **Sequential** | `CRM-\d{1,4}` or similar, gap ≤ 10 | seconds — fully scannable |
| **Low-entropy** | `proj_[a-z0-9]{8}`, gap varies | hours-days — partially scannable |
| **High-entropy** | UUID v4 or HMAC-derived | infeasible — needs out-of-band leak |

If the ID space is sequential or low-entropy, mark the finding as
"unauthenticated discovery feasible". If high-entropy, the bug still
matters but its reach is bounded by ID leak paths (logs, URLs, prior
breach data).

### 4.3 · Worked example — ch01-extended

```python
async with Client("http://127.0.0.1:18011/mcp/stream") as c:
    r = await c.call_tool("list_projects", {"api_key": "alpha-api-key"})
    # → All projects: [{"project_id": "CRM-1001", ...}, {"project_id": "CRM-2001", ...}]
```

Observed IDs: `CRM-1001`, `CRM-2001`.

Analysis:
- Regex inferable: `CRM-\d{1,4}`.
- Gap between observed IDs: 1000.
- Candidate ID space: ~10,000 (4-digit suffix).
- Enumeration cost at 1 ms/call: ~10 seconds.

Verdict: **sequential / stepped — HIGH predictability**. An attacker
with one valid credential can enumerate the full space in seconds.

### 4.4 · Stop conditions

- Never enumerate foreign IDs to "verify the shape". Your own samples
  are sufficient; the regex shape is structural information, not
  customer data.
- If your test accounts produce only 1-2 IDs, infer the shape from the
  regex / format alone. Don't ask the vendor for more.

### 4.5 · Commercial adaptation

- Use the free trial / sandbox tier to plant 3-5 of your own objects across at most 2 accounts.
- For services that issue obvious snowflake IDs (`170…`), the timestamp half is recoverable; note this in the writeup.
- Some services use a per-tenant ID prefix (e.g. `acct_X/proj_Y`). If the prefix is the access-control boundary and B can guess A's prefix, that's a separate finding worth its own axis.

---

## 5 · Axis 1 — Tool breadth

How much of the server's surface is affected.

### 5.1 · Procedure

1. Enumerate the server's tools via `tools/list` (jakk does this implicitly during any scan).
2. Filter to *read-shaped* tools by name regex: `^(get|list|read|fetch|describe|status|info|search)`. Operator should refine if the target uses verbs jakk doesn't catch.
3. For each filtered tool that accepts an object identifier:
   a. Try the foreign-ID-known-to-leak from your confirmed-finding probe.
   b. Use B's credential.
   c. Record success / failure.
4. Stop at the FIRST tool of each *shape* that doesn't leak — most BOLA bugs are 100% within a shape (all object-by-ID reads share the same authz code path).

### 5.2 · Metric

The **breadth ratio** — leaking tools / read-shaped tools.

| Ratio | Reading |
|---|---|
| 1/N (one tool) | Possibly a one-off mistake in one handler. |
| Most-of-N | A pattern. Shared authz code path is missing the check. |
| All-of-N | A class-level bug. The middleware never enforces ownership; every read leaks. |

### 5.3 · Worked example — ch01-extended

```
read-shaped tools: fetch_project, list_projects, get_project_settings

fetch_project(CRM-1001, bravo-api-key) → leaks tenant_alpha
list_projects(bravo-api-key)           → returns BOTH tenants' projects
get_project_settings(CRM-1001, bravo-api-key) → leaks webhook_secret for alpha

breadth ratio: 3/3 — class-level BOLA
```

Verdict: every read tool leaks. The fix isn't a tool-specific patch
— the authz check must move up to the shared middleware.

### 5.4 · Stop conditions

- Don't try every possible (tool, foreign-ID) combination. Pick one foreign ID and one tool of each shape; if both leak, the class is broken.
- Don't iterate during rate-limit / error states. If a tool throws 429, stop and resume later or skip.
- If the target has 50+ read tools, sample ~10 across visibly distinct shapes; don't enumerate all.

### 5.5 · Commercial adaptation

- Respect documented rate limits even when the bug would let you exceed them.
- Some services rate-limit on patterns: "fetched 20 different resource IDs in 10 seconds" → fraud detection alert. Slow down or split across days.
- If the bounty scope is "the API but not the UI", restrict the tool list to API tools; don't reach for UI-only endpoints that aren't in jakk's enumeration anyway.

---

## 6 · Axis 3 — Data classes

What you actually see in the leaked response.

### 6.1 · Procedure

1. Take **one** leaked foreign object (the smallest enough to demonstrate the bug).
2. Walk its fields. For each field, classify into one of:
   - **metadata** — IDs, timestamps, status codes, counters
   - **PII** — names, emails, phone, addresses, account IDs
   - **secret** — API keys, tokens, webhook secrets, PEM blocks
   - **reference** — URLs, file paths, IDs pointing to other objects (potential pivot)
3. Count per class.
4. Note the *highest-severity* field with a 20-character preview only (e.g. `"webhook_secret": "whsec_alpha_zT4m..."`). Never paste the full value into the writeup; the vendor's engineer can verify with a fresh request.

### 6.2 · Metric

A four-bucket histogram of the leaked object, plus the highest-severity item.

### 6.3 · Worked example — ch01-extended

```
fetch_project(CRM-1001, bravo-api-key) →
  project_id, tenant, name, status, notes

get_project_settings(CRM-1001, bravo-api-key) →
  webhook_url, webhook_secret, notification_email, retention_days

Classification:
  metadata: 5 (project_id, tenant, status, notes, retention_days)
  PII:      2 (name, notification_email)
  secret:   1 (webhook_secret = whsec_alpha_zT4m... [redacted])
  reference:1 (webhook_url)

Highest-severity field: webhook_secret (secret-class)
```

The presence of a single secret-class field bumps severity from
"BOLA-read of business data" to "BOLA-read of credentials". A
webhook secret enables downstream attacks on the target's
notification path (forge events, replay, exfiltrate to attacker-
controlled URL by re-registering).

### 6.4 · Stop conditions

- Inspect ONE foreign object. Don't re-call to enumerate field variations.
- If the leaked object includes nested arrays of sub-objects (e.g. project → comments → users), inspect the FIRST element of each, not the whole tree.
- Redact non-canary values in your notes. The fact that a `password` field came back is the finding; its contents are not.

### 6.5 · Commercial adaptation

- Even in bug-bounty scope, do not retain leaked customer data. Take notes (structural) and discard the payload after writeup.
- For services with attachments (file uploads), do NOT download the file. Note its presence and metadata; let the vendor's team verify content during triage.
- If a secret-class field comes back, the vendor may need to rotate it. Note that in the disclosure ("recommend rotating field X on all affected tenants").

---

## 7 · Axis 4 — Read vs write (escalation)

The most consequential axis. Run it LAST, only when:
- Bounty program explicitly permits write operations, OR
- Target is your own lab / test environment.

If the program is silent on writes, treat that as a "no". The
escalation finding is valuable; an unauthorized write is not.

### 7.1 · Procedure

1. Find a mutate tool by name pattern: `^(update|set|modify|delete|create|share|invite|move)` or schema-shape (tool takes an object identifier AND a modify-shaped argument).
2. As B, attempt to modify A's object with a **canary value** (`JAKK-WRITE-CANARY-<hex>`) — a value that cannot be confused with legitimate data.
3. Read the object back as A (using A's credential) to confirm the write hit shared state.
4. **Restore the original value immediately.**
5. Record: write call succeeded? canary visible to A?

### 7.2 · Metric

| Outcome | Severity step-up |
|---|---|
| Write rejected | None — bug is read-only. |
| Write accepted but invisible to A | Probe environment didn't share state (rare). Investigate further. |
| Write accepted and visible to A | **Persistent cross-tenant modification.** Worst case. |

### 7.3 · Worked example — ch01-extended

```python
async with Client("http://127.0.0.1:18011/mcp/stream") as c:
    canary = "JAKK-WRITE-CANARY-9F2A"

    # B writes to A's project
    await c.call_tool("update_project", {
        "project_id": "CRM-1001",
        "api_key": "bravo-api-key",
        "notes": canary,
    })

    # A reads back — does she see B's writes?
    r = await c.call_tool("fetch_project", {
        "project_id": "CRM-1001",
        "api_key": "alpha-api-key",
    })
    # → "...notes: 'JAKK-WRITE-CANARY-9F2A'..."   ← B's write is in A's view

    # Restore (in a real engagement you'd disclose without restoring,
    # and let the vendor decide; in a lab, hygiene is fine).
```

Verdict: **persistent cross-tenant write confirmed**. Severity escalates:
- Read finding: B can read A's data.
- Read+write finding: B can also *plant content in A's data*. If A's
  agents (LLM, automation, workflow) later read this object, they
  treat B-supplied content as A's authoritative data. This converts
  a BOLA-write into a stored indirect-prompt-injection vector
  against every consumer of the modified object.

### 7.4 · Stop conditions

- ONE canary write per affected mutate tool. Don't iterate.
- ONLY against test data you own end-to-end. A canary in a real
  customer's project is data corruption.
- Restore in your lab; **don't** restore in real targets — the
  audit trail of your write (in their logs) is part of the evidence.
- If the canary value somehow ends up exposed in another tenant's
  view (cache contamination, search indexes), STOP and disclose
  immediately; the bug has propagation beyond just cross-tenant
  writes.

### 7.5 · Commercial adaptation

- **Default position: don't run this axis on commercial targets.**
- Run only if the bounty program's text explicitly says "modification of test objects is permitted" or similar.
- If permitted: write to YOUR OWN test object's `notes` field with a canary, then attempt the cross-tenant write from B against the same object. (You're the owner of both sides — no real customer involved.)
- Never delete. Never share/transfer ownership. Never invite. Those
  are write operations with potential audit-log side effects that go
  beyond data integrity.

---

## 8 · Aggregating the four axes into an impact statement

Once you have measurements for each axis, the impact statement
writes itself:

```
[CVSS-style or written]
Vector: [class — e.g. BOLA-write across [tool count]/[total] tools]
ID exposure: [predictability label] (~[time to enumerate])
Data classes leaked: [metadata count]/[PII count]/[secret count]/[reference count]
Highest-severity field: [field name, redacted value preview]
Write capability: [yes/no/not-tested]
```

Worked example from ch01-extended:

```
Vector:       BOLA across 4/4 tools (3 read + 1 write)
ID exposure:  sequential CRM-\d{1,4}, ~10s to enumerate full space
Data classes: 5 metadata / 2 PII / 1 secret / 1 reference
Highest field: settings.webhook_secret (whsec_alpha_zT4m... [redacted])
Write capability: confirmed; cross-tenant writes are visible to legitimate owner
                  → escalates to stored indirect-injection vector
```

That summary, paired with the per-axis reproduction steps, is a
complete disclosure.

---

## 9 · Disclosure template

```
TITLE: Cross-tenant authorization bypass in [product] [API/tool surface]

SUMMARY
[1 sentence: who can do what to whom.]

REPRODUCTION (5 minutes for your engineer)
1. Create two test accounts (or use these test creds: [provide if program allows]).
2. As [identity B], call [tool] with [identity A's object ID].
3. Observe: response includes [structural evidence — what shouldn't be reachable].

DEPTH OF EXPOSURE (per-axis)
- Tool breadth: [N]/[M] read-shaped tools leak. Pattern: shared authz path missing the check.
- ID predictability: [label]. Full enumeration in ~[time].
- Data classes: [counts]. Highest-severity field: [name] (redacted: [preview]).
- Write capability: [yes/no/not-tested]. [If yes:] writes are visible to the
  legitimate owner — converts to a stored indirect-injection vector against
  downstream consumers.

IMPACT
[2-3 sentences. Who's affected (tenants), what's leaked, why ID predictability
matters, why write matters if applicable.]

SUGGESTED REMEDIATION
- Move the authz check from per-tool handlers to shared middleware that runs
  on every call.
- Verify the check uses the request's authenticated identity, not the
  resource's identity.
- Consider rotating any secret-class fields exposed during the window the
  bug was live (logs/audit trail will show callers).

RESPONSIBLE-DISCLOSURE INFO
- Discovery date: [YYYY-MM-DD]
- Submitted to: [program]
- Public-disclosure intent: [90 days after submission, or coordinated with vendor]
- Test accounts used: [IDs/emails, so vendor can correlate logs]
- Data accessed: minimal — single proof object per affected tool. Notes
  retained only structurally; no PII or secret values held after submission.
```

Keep the writeup to ~1-2 pages. Long writeups slow triage. The
per-axis measurements are the load-bearing content.

---

## 10 · What NOT to do

Universal across all axes:

| Don't | Why |
|---|---|
| Enumerate foreign IDs beyond proof | Crosses the line from research to exploitation. |
| Touch real customer data, even with valid credentials | Authorization-to-test doesn't transfer to data ownership. |
| Retain leaked data after writeup | Liability + ToS violation. Note structure, discard payload. |
| Submit findings publicly before the disclosure window | Most programs require 90 days minimum. Going early can void the bounty AND expose you to legal action. |
| Share creds, payloads, or proof artifacts with peers | Authorization attaches to you; recipients are unauthorized. |
| Run write tests against any commercial target without explicit permission | Even "harmless" canary writes are unauthorized modifications. |
| Use this playbook as a checklist | It's a frame. Per-engagement judgment is non-negotiable. |
| Treat "the program didn't say no" as "the program said yes" | Silence ≠ authorization. Defaults are restrictive. |

If you can't honestly tick all of these, the legitimate move is:
1. Stop testing.
2. File what you already have via the bounty program.
3. Discuss scope with the vendor before resuming.

---

## 11 · Companion artifacts

- `docs/threat-models.md` — per-class threat models. Read this to understand what "vulnerable" means before you start measuring depth.
- `examples/external_targets/ch01-extended/` — local lab used for every worked example in this doc.
- `library/mcp/mcp.authz.cross_tenant_read.yaml` — the jakk probe that produces the initial finding this playbook deepens.
- (Future v0.3) `library/mcp/mcp.authz.*.yaml` — sketched probe classes that will operationalize Axes 1, 2, and 4 directly in jakk. Until those exist, the procedures here run as manual scripts.

---

## 12 · Limits of this playbook

What this playbook does *not* cover, and why:

- **Authentication bypass.** Different bug class. Use `mcp.auth.*` probes first; if those fire, you're not looking at an authorization bug.
- **DoS / rate-limit testing.** Always out of scope for bug-bounty programs. Don't.
- **Source-code disclosure / SSRF / SQLi.** Separate axes, separate methodology. Adapt the four-axis frame as needed but don't pretend BOLA depth applies.
- **Severity scoring.** No CVSS calculator here. Vendors have their own; map your measurements onto theirs at disclosure time.
- **Coordinated multi-vendor disclosure.** If your finding affects a vendor *and* their customers in ways the vendor can't unilaterally fix, that's a coordinated disclosure scenario. Out of scope for this doc; engage a CSIRT / disclosure coordinator (CERT/CC, JPCERT, etc.).

---

Written 2026-05-23 against jakk v0.2. Updated as the methodology
evolves and as v0.3 lands the corresponding probe automation.
