---
date: 2026-05-23
status: SSRF probe family — dedicated reference
probe: mcp.ssrf.cloud_metadata
matcher: cloud_metadata
audience: AI eng / dev + security reviewers
---

# jakk SSRF probe — `mcp.ssrf.cloud_metadata`

The single highest-prevalence server-side bug class in the 2026 MCP
data, and jakk's probe for it.

> **Why this exists:** BlueRock scanned 7,000+ MCP servers in 2026 and
> found **36.7% vulnerable to SSRF**, including live retrieval of AWS
> IAM access keys, secret keys, and session tokens from an EC2
> instance's metadata endpoint via a misconfigured MCP server. That's
> not a theoretical bug — it's the most common way an MCP server hands
> an attacker the keys to its cloud account.

---

## 1 · What SSRF is, in plain terms

**SSRF = Server-Side Request Forgery.** A tool takes a URL from the
caller and *the server fetches it* — from the server's own network
position. The bug is: the server will fetch **any** URL, including ones
the caller could never reach directly.

```
   You (caller)                    Server (in a cloud VM)
       │                                  │
       │  fetch_url("http://internal")    │
       │ ───────────────────────────────► │
       │                                  │  the server makes the
       │                                  │  request FROM INSIDE its
       │                                  │  own network ─────────────►  internal-only services
       │                                  │                              (databases, admin panels,
       │  ◄─────────────────────────────  │  ◄────────────────────────   CLOUD METADATA endpoint)
       │     the internal response         │
```

The caller borrows the server's network position. The juiciest thing
reachable from that position is the **cloud metadata endpoint.**

## 2 · The cloud metadata attack chain

Every major cloud (AWS, GCP, Azure) runs a metadata service at the
**link-local address `169.254.169.254`** — reachable *only* from inside
the instance. It exists so the VM can ask "what's my IAM role, what are
my temporary credentials?" Those credentials are exactly what an
attacker wants.

```
   1. Attacker finds a tool that fetches URLs (fetch_url, render_image,
      import_from_url, webhook_test, screenshot, ...).

   2. Attacker calls it with:
        http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>

   3. The server (running in AWS) fetches that URL from inside the
      instance and returns the body.

   4. The body is the instance's TEMPORARY AWS CREDENTIALS:
        { "AccessKeyId": "ASIA...", "SecretAccessKey": "...",
          "Token": "...", "Code": "Success" }

   5. Attacker now holds the instance's cloud permissions.
      = full account pivot from one tool call.
```

For MCP specifically, the "attacker" is often **indirect**: untrusted
content (a webpage the agent summarizes, an issue it reads) steers the
LLM into calling the URL-fetching tool with the metadata address.

## 3 · How the probe works

**Probe:** `library/mcp/mcp.ssrf.cloud_metadata.yaml`
**Matcher:** `cloud_metadata` (in `jakk/matchers.py`)

1. **Tool selection.** `applies_to.tool_name_regex` narrows to plausibly-
   URL-fetching tools (`fetch`, `url`, `http`, `request`, `webhook`,
   `import`, `render`, `preview`, `proxy`, `download`, `screenshot`,
   `scrape`, `crawl`). `target_arg_kind: url` then picks the URL-shaped
   argument out of the tool's signature — *regardless of what the server
   names it* (`url` / `uri` / `endpoint` / `webhook_url` / `link`). This
   is the C+ arg-kind mechanism; it's why the probe works across servers
   without per-vendor config.

2. **Payload.** `__target_arg__` is set to the AWS IMDSv1 listing URL:
   `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
   AWS IMDSv1 is the primary target because a plain GET reaches it — **no
   special request headers needed**, so any naive fetch works.

3. **Detection.** The `cloud_metadata` matcher inspects the response for
   the documented *response shapes* of each cloud's metadata service:

   | Cloud | What we match |
   |---|---|
   | AWS IMDS | `AccessKeyId` / `SecretAccessKey` fields, `ASIA...` temp keys, `Code:Success` envelope |
   | GCP | `ya29.` access tokens, `Metadata-Flavor: Google` echo |
   | Azure IMDS | `access_token` + `client_id` pairing, `subscriptionId` GUID |

   A match = `vulnerable` (we pulled an actual metadata document). No
   match = `pass`.

## 4 · Outcomes

| Outcome | Meaning |
|---|---|
| `vulnerable` | The server fetched the metadata URL and returned a credential-shaped body. Real, reportable SSRF-to-cloud-creds. |
| `pass` | The server refused, blocked the link-local address, or isn't in a cloud / behind that metadata service. |
| `skipped` | No URL-shaped tool on this server (e.g. github-mcp-server — confirmed). |
| `error` | The call failed at transport/protocol level before a tool result could be evaluated. |

**Severity: critical.** Cloud credential theft → account pivot is among
the highest-impact outcomes a single tool call can produce.

## 5 · What it catches and what it misses

**Catches:**
- AWS IMDSv1 SSRF — the most prevalent and most reachable (header-free).
- Any URL-fetching tool, by argument role, across servers.

**Misses (honest limitations):**
- **AWS IMDSv2** — requires a PUT to get a session token first, then a
  header on the GET. A naive single-GET fetch won't do the dance, but
  IMDSv2-only instances are also harder to SSRF, so the miss correlates
  with lower real risk. (Future: a two-call IMDSv2 variant.)
- **GCP / Azure** — their metadata requires request headers
  (`Metadata-Flavor: Google`, `Metadata: true`) that the *server* would
  have to add to its fetch. A naive URL-fetch won't, so these are less
  reachable via pure-URL SSRF. The matcher still detects their response
  shapes in case a server proxies headers through.
- **Non-metadata SSRF** — SSRF to internal databases, admin panels, or
  an attacker's callback listener. This probe is specifically the
  *cloud-metadata* variant (in-band, unambiguous evidence). A broader
  callback-based SSRF probe is a possible future addition but needs an
  out-of-band listener.
- **`skipped` on multi-arg tools without context** — if the URL-fetching
  tool also requires other args (e.g. `fetch(url, method, headers)` with
  `method` required), jakk tells the operator which `--arg` values to
  supply before rerunning.

## 6 · Adapting to other targets

To point at a known IAM role, a different cloud, or a mock/test
endpoint, copy the YAML and change the URL + add patterns:

```yaml
payload:
  arguments:
    __target_arg__: "http://169.254.169.254/latest/meta-data/iam/security-credentials/my-known-role"

matcher:
  kind: cloud_metadata
  params:
    patterns:
      - "INTERNAL-IMDS-[A-Z0-9]+"   # bespoke internal metadata service
```

## 7 · Validation (how this probe was proven)

End-to-end, locally, without real cloud infra:

1. **Mock metadata endpoint** (`/tmp/ssrf_mock_metadata.py`) — a plain
   HTTP server on `:19999` returning a realistic AWS IMDS credentials
   document with **fake** values.
2. **SSRF-vulnerable fixture** (`/tmp/ssrf_vuln_server.py`) — a FastMCP
   server with `fetch_url(url)` that naively GETs whatever URL it's
   given. This is a *real* SSRF bug in the fixture (no allowlist, no
   link-local block) — a legitimate test fixture, not an engineered gap.
3. **Probe** pointed at the mock metadata URL → jakk fires `vulnerable`,
   `__target_arg__` correctly resolved to the `url` argument, matcher
   caught the `ASIA...` / `AccessKeyId` / `Code:Success` shapes.
4. **Negative**: same probe against github-mcp-server (no URL tool) →
   `skipped` cleanly.

Unit tests: `tests/unit/test_jakk_ssrf.py` — 14 cases pinning the
matcher (AWS/GCP/Azure positives, clean-response negatives incl. a bare
`access_token` that must NOT fire, operator-supplied patterns).

## 8 · Files

- `library/mcp/mcp.ssrf.cloud_metadata.yaml` — the probe
- `jakk/matchers.py` — `cloud_metadata` matcher (heavily commented)
- `tests/unit/test_jakk_ssrf.py` — matcher tests
- `docs/threat-models.md` — should gain an SSRF entry (follow-up)

## 9 · References

- BlueRock MCP SSRF survey (2026) — 36.7% of 7,000 servers
- AWS IMDS docs — `/latest/meta-data/iam/security-credentials/`
- OWASP-for-MCP MCP04 (insufficient input sanitisation)
