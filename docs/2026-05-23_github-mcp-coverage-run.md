---
date: 2026-05-23
status: coverage run — jakk against github-mcp-server (HTTP, read-only)
framing: calibration against real production code, NOT a CVE hunt
target: github/github-mcp-server (official), HTTP mode, --read-only, localhost
related:
  - docs/scope-decision.md (why HTTP-only; this run validates that scope)
  - docs/depth-of-exposure-methodology.md (the discipline followed here)
---

# jakk coverage run — github-mcp-server

The first run of jakk against a real, mass-deployed production MCP
server — GitHub's official `github-mcp-server`, run in HTTP mode on
localhost with `--read-only`, scanned with our own fine-grained PAT.

This is deliberately framed as a **coverage measurement**, not a
vulnerability hunt. The interesting bugs in the GitHub MCP ecosystem
are agent-side (Invariant Labs' indirect-injection disclosure, May
2025) and already published — its agent-side sibling's territory, not jakk's. What
jakk-against-GitHub gives us is honest calibration: which of jakk's
probes can fire against a real production tool surface, and which
can't, and why.

The headline result is a **coverage gap**, not a finding — and that's
the point.

---

## 1 · Setup

```bash
# Official server, HTTP mode, read-only. PAT supplied per-request by jakk.
docker run -d --rm -p 8082:8082 --name jakk-github-mcp \
  ghcr.io/github/github-mcp-server http --read-only --port 8082

# Triple safety belt:
#   1. fine-grained PAT scoped to one throwaway repo, read-only perms
#   2. server's own --read-only flag (write tools not registered)
#   3. jakk --safe for the first pass
jakk mcp scan \
  --endpoint http://127.0.0.1:8082/mcp \
  --library library/mcp \
  --oauth-token-file ~/.jakk-scan/github-pat.txt \
  --safe
```

Server exposed **23 tools** in read-only mode:

```
get_commit, get_file_contents, get_label, get_latest_release, get_me,
get_release_by_tag, get_tag, get_team_members, get_teams, issue_read,
list_branches, list_commits, list_issue_types, list_issues,
list_pull_requests, list_releases, list_tags, pull_request_read,
search_code, search_issues, search_pull_requests, search_repositories,
search_users
```

This is the realistic production shape: every tool takes `owner` +
`repo` plus its specific args. Multi-required-argument signatures
throughout.

---

## 2 · Results

### 2.1 Full library (read-only server, so unsafe probes are safe here)

```
Tests run: 20   pass=11   error=7   skipped=1   vulnerable=1
```

| Outcome | Count | Probes |
|---|---|---|
| pass | 11 | auth.no_credential, auth.invalid_token, schema.description_smuggling, response.* ×4 (get_me, get_teams), command.shell_marker ×4 |
| error | 7 | command.secret_file_read ×4, path.prefix_bypass ×2, path.canary_file_read ×1 |
| skipped | 1 | authz.cross_tenant_read (needs two credentials; only had one PAT) |
| vulnerable | 1 | auth.wrong_prefix (verified — see §3) |

### 2.2 The negative controls we never had before

Three results matter because they're the first time jakk's probes
ran against a *correctly-implemented* production server, giving us
true negatives:

| Probe | Result | Evidence |
|---|---|---|
| `auth.no_credential` | **pass** | server returned `401 Unauthorized` to a no-Authorization request |
| `auth.invalid_token` | **pass** | server returned `400 Bad Request` to `Bearer garbage-<rand>` |
| `schema.description_smuggling` | **pass** | GitHub's tool descriptions contain no smuggled directives |
| `command.shell_marker` ×4 | **pass** | "neither real marker reflected" — GitHub doesn't shell out; the API URL-encodes the payload, marker never comes back |

Until this run, every jakk smoke had been against breach-to-fix labs
that ship with NO auth (so auth probes always fired `vulnerable` as
true positives on intentionally-open servers). github-mcp-server is
the first target where the auth probes *should* pass — and they do.
That's the validation that the auth probes aren't just always-fire
noise.

---

## 3 · The one finding — verified, but low severity

`auth.wrong_prefix` fired `vulnerable`: the server accepted the PAT
sent as a raw `Authorization: <token>` header, without the `Bearer `
scheme prefix.

**Verified manually** (the discipline: every `vulnerable` gets eyeballed):

| Header sent | Server response |
|---|---|
| `Authorization: Bearer <pat>` | accepted (correct) |
| `Authorization: <pat>` (no scheme) | **accepted** ← the finding |
| `Authorization: bearer <pat>` (lowercase) | **accepted** (another lax variant) |
| `Authorization: token <pat>` | rejected (400) |

So the finding is real, not a jakk artifact. The server's HTTP auth is
permissive about the scheme prefix.

**But the honest severity is low/informational, not high.** This is a
spec-conformance issue (RFC 6750 requires the `Bearer` scheme), NOT an
authentication bypass:

- The token is still validated. You cannot get in without a valid token.
- An attacker presenting a validly-issued token in a non-standard
  format gains nothing they couldn't get by formatting it correctly.
- The "harm" framing in `threat-models.md` (normalization-layer bypass)
  applies only in narrow scenarios where a proxy strips/validates the
  `Bearer` prefix differently than the origin — not demonstrated here.

**This is a jakk calibration finding, not a GitHub finding.** The
probe fired correctly, but `auth.wrong_prefix`'s severity rating of
`high` is miscalibrated. Accepting a valid token in a lax format is
not the same class of problem as accepting an *invalid* token (which
the server correctly rejects, per §2.2). v0.3 should re-rate
`wrong_prefix` to `low` and reword its threat model.

---

## 4 · The coverage gap — the actually-valuable result

7 of 20 rows came back `error`. All for the same reason:

```
mcp.path.canary_file_read → get_file_contents
   args sent: {"path": "/app/files/safe_files_sensitive/secret.txt"}
   error: ToolError: missing required parameter: owner
```

C+ did its job — the payload landed in `path` (not `owner`, which is
where the old `__first_string_arg__` would have put it). But
`get_file_contents(owner, repo, path, ref, sha)` *also requires*
`owner` and `repo`, which the probe never supplied. The call errors
on the missing required parameter before the path-traversal logic is
ever reached.

Same root cause across all 7 errors:

| Probe | Tools | Missing |
|---|---|---|
| `command.secret_file_read` | list_pull_requests, pull_request_read, search_pull_requests, search_repositories | required args beyond the first string arg |
| `path.prefix_bypass` | get_file_contents, list_commits | owner / repo |
| `path.canary_file_read` | get_file_contents | owner / repo |

**The lesson C+ didn't cover:** C+ solved arg *selection* (which arg
gets the payload). The next gap is arg *context* — multi-argument
tools need their *other* required arguments filled with valid values
for the probe to execute at all. Against a tool like
`get_file_contents(owner, repo, path)`, jakk needs to supply a real
`owner` and `repo` (the operator's test account/repo) so the call
reaches the path-handling code where the vulnerability would live.

The breach-to-fix labs never surfaced this because their tools were
single-string-arg (ch02: `read_file_contents(file_path)` — fill the
one arg, done) or credential+id (ch01:
`fetch_project(project_id, api_key)` — both supplied as templates).
GitHub's `owner + repo + path` is the realistic production shape, and
it breaks the probes in exactly the way that teaches us what v0.3
needs.

---

## 5 · What this run proves

- **jakk's HTTP + auth pipeline works against real production code.** Connect, enumerate 23 tools, authenticate per-request, classify. End to end. No crashes, no hangs, clean output.
- **The auth probes produce true negatives** (no_credential / invalid_token both `pass`) — they're not always-fire noise.
- **C+ works against the real GitHub-shaped signature** — the payload lands in `path`, proven against `get_file_contents(owner, repo, path)` with real GitHub tools, not just the local validation server.
- **The `schema.description_smuggling` probe runs zero-side-effect** against a production server and correctly passes.

## 6 · What this run does NOT prove

- **No vulnerability was found in github-mcp-server** (the one `vulnerable` is a low-severity spec-conformance issue, arguably a jakk false-positive in severity terms).
- **The path/command probes were NOT actually exercised** — they errored on missing context args before testing anything. We have no evidence about whether GitHub MCP is path-traversal-safe, because we never got a well-formed call through. (It almost certainly is — it uses the GitHub API, not a filesystem — but jakk didn't test it.)
- **authz was untested** (one PAT, no second identity / foreign repo).

---

## 7 · v0.3 priorities surfaced by the real run

Ranked by how much they unblock:

1. **Context-arg supply (highest).** Probes need a way to fill non-target required args with valid values. Proposed: CLI `--arg owner=myuser --arg repo=myrepo` (repeatable) and/or a per-target context file, with `{ctx_owner}` style template tokens in the YAML. Without this, jakk cannot probe ANY multi-required-arg tool — i.e. most production tools. This is the single biggest coverage blocker the run found.
2. **`wrong_prefix` severity recalibration.** `high` → `low`/`info`. Reword the threat model: accepting a validly-issued token in a non-standard format ≠ auth bypass. Distinguish from `invalid_token` (which is a real high if it fires).
3. **A `query`-kind probe.** GitHub exposes 5 `search_*` tools with a `query` arg that no current probe targets (the `query` arg-kind exists in the registry but no probe uses it yet). Search endpoints are a classic injection surface (query-syntax injection, over-broad result leakage). Worth a dedicated probe.
4. **Two-credential setup for authz against GitHub.** Two PATs from two accounts + a private repo owned by A → test whether B's PAT can read A's repo via the MCP. Needs the methodology pre-flight.

---

## 8 · Honest framing for any public mention

If this run is ever described publicly:

- "We ran jakk against GitHub's official MCP server" — true.
- "jakk found a vulnerability in GitHub MCP" — **do not say this.** The one finding is a low-severity spec-conformance issue; calling it a vulnerability would be the kind of overclaim the security community remembers.
- "jakk validated its auth probes against a correctly-implemented production server" — true and the more interesting claim.
- "The run surfaced a coverage gap (context args) that drives v0.3" — true; this is the honest lede.

The result is not "we found a bug." It's "we calibrated against real
production code, confirmed the probes that should pass do, and learned
exactly what's missing to probe multi-arg tools." That's a more
durable thing to be able to say than a marginal CVE.

---

## 9 · Reproducibility

```bash
docker run -d --rm -p 8082:8082 --name jakk-github-mcp \
  ghcr.io/github/github-mcp-server http --read-only --port 8082

jakk mcp scan --endpoint http://127.0.0.1:8082/mcp \
  --library library/mcp \
  --oauth-token-file ~/.jakk-scan/github-pat.txt --jsonl /tmp/gh-full.jsonl

jq -r '"\(.outcome)\t\(.test_id)\t\(.tool_name)"' /tmp/gh-full.jsonl
docker stop jakk-github-mcp
```

PAT: fine-grained, single throwaway repo, Contents/Issues/PRs
read-only, 7-day expiry. Revoke after the run.
