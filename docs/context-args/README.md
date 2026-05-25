---
date: 2026-05-23
status: context-arg supply (--arg) — dedicated reference
feature: --arg KEY=VALUE
audience: AI eng / dev running jakk against real multi-argument tools
---

# jakk context args — `--arg KEY=VALUE`

The feature that lets jakk probe **real production tools**, which almost
always take more than one argument.

---

## 1 · The problem it solves

jakk's probes inject a payload into ONE argument — the "target" arg
(path for traversal, url for SSRF, etc.). But real tools take several
required arguments, and the call fails if any of them is missing.

The clearest example, from the GitHub MCP coverage run:

```
get_file_contents(owner, repo, path, ref)
                  ▲      ▲     ▲
                  │      │     └─ jakk injects the traversal payload here
                  │      │        (correctly, via target_arg_kind: path)
                  └──────┴─ but these are REQUIRED and jakk didn't set them
```

Before `--arg`, the probe filled `path` and sent the call — the server
rejected it with *"missing required parameter: owner"* before the
path-handling code ever ran. The probe errored without testing
anything. Against GitHub MCP, **7 of 20 probe rows errored** for exactly
this reason. The probes were fine; they just couldn't reach the code
under test.

## 2 · The fix

`--arg KEY=VALUE` (repeatable) supplies valid values for the non-target
arguments. You provide your test context once; the scanner fills any
tool-declared arg the probe didn't set.

```bash
jakk mcp scan \
  --endpoint http://127.0.0.1:8082/mcp \
  --library library/mcp \
  --oauth-token-file ~/.jakk-scan/github-pat.txt \
  --select mcp.path.canary_file_read \
  --arg owner=octocat \
  --arg repo=Hello-World
```

Now the call goes out as
`get_file_contents(owner="octocat", repo="Hello-World", path="<payload>")`
— complete, and it reaches the path-handling logic the probe is there
to test.

## 3 · How it resolves (precise order)

For each matched tool, `_resolve_arguments` builds the call in this order:

1. **Target arg** — `__target_arg__` (role-based, via `target_arg_kind`) or
   `__first_string_arg__` (position-based). The payload lands here.
2. **Explicit payload args** — anything the probe YAML sets literally
   (with `{run_id}` expansion).
3. **Context args** (`--arg`) — fill any arg the TOOL declares that steps
   1-2 didn't set. **Scoped to tool-declared args**: a `--arg` for an
   argument the tool doesn't have is ignored (we never send a parameter
   the tool won't accept).
4. **Required-arg check** — if the tool STILL has unfilled required args,
   the probe is `skipped` with an actionable message telling you which
   `--arg` to supply — instead of firing a call doomed to a generic
   "missing parameter" error.

Precedence: a value the probe sets explicitly (step 2) wins over a
context arg (step 3) for the same key.

## 4 · The outcome change: actionable `skipped` instead of opaque `error`

Before `--arg`, an unsatisfiable multi-arg tool produced `error`
("call returned isError=True") — you had to read the raw server message
to figure out what was missing.

Now:

| Situation | Outcome | Evidence |
|---|---|---|
| Required args unfilled, no `--arg` supplied | `skipped` | `tool needs required arg(s) ['owner','repo'] ... Supply: --arg owner=<value> --arg repo=<value>` |
| Required args filled (by probe + `--arg`), call runs, no leak | `pass` / `error` | depends on the matcher + whether the server itself errored |
| Required args filled, call runs, leak detected | `vulnerable` | the matcher's evidence |

The `skipped` message tells you exactly what to add. Run it once to see
what's needed, add the `--arg`s, run again.

## 5 · Worked example — the GitHub coverage gap, closed

```bash
# 1. First run — probe can't satisfy get_file_contents
jakk mcp scan --endpoint http://127.0.0.1:8082/mcp --library library/mcp \
  --oauth-token-file ~/.jakk-scan/github-pat.txt --select mcp.path.canary_file_read
#   → skipped: "tool needs required arg(s) ['owner','repo'] ...
#               Supply: --arg owner=<value> --arg repo=<value>"

# 2. Supply the context — probe now executes
jakk mcp scan --endpoint http://127.0.0.1:8082/mcp --library library/mcp \
  --oauth-token-file ~/.jakk-scan/github-pat.txt --select mcp.path.canary_file_read \
  --arg owner=octocat --arg repo=Hello-World
#   → the call goes out as get_file_contents(owner, repo, path=<payload>);
#     GitHub returns not-found for the bogus traversal path (it uses the API,
#     can't filesystem-traverse) → no leak. The probe RAN; GitHub passed.
```

The transition **skipped → executing** is the whole point: jakk can now
test multi-arg production tools, not just the single-arg lab tools.

## 6 · What to put in `--arg`

The valid, benign values your test context needs:
- **owner / repo** — a repo you can read (your throwaway test repo, or a
  public one like `octocat/Hello-World`).
- **account_id / workspace_id / project_id** — your own test tenant's IDs
  for SaaS MCPs.
- Anything else a tool marks required that isn't the injection target.

Rule of thumb: if a `skipped` finding says *"needs required arg X"*, add
`--arg X=<your test value>`.

## 7 · Interaction with other features

- **`target_arg_kind` (C+)** — context args fill *around* the target arg.
  The target arg is chosen by role; context args fill the rest. They're
  complementary: C+ decides *where the payload goes*, `--arg` makes the
  *rest of the call valid*.
- **authz probes** — those use their own template tokens
  (`{cred_a}`/`{cred_b}`/`{foreign_id}` via `--cred-a` etc.), not `--arg`.
  Context args apply to the tool_call surface.
- **SSRF / path / command probes** — all benefit. A `fetch(url, method)`
  tool with required `method` now takes `--arg method=GET`.

## 8 · Limitations

- **You must know valid values.** jakk won't invent an `owner` — you
  supply your test context. That's deliberate: the operator knows their
  authorized test accounts; jakk shouldn't guess.
- **One value per arg per scan.** If two tools need different `owner`
  values, run two scans. (A per-tool context map is a possible future
  addition; not needed yet.)
- **Doesn't auto-fill optional args.** Only required args trigger the
  `skipped` check; optional args are left unset unless you `--arg` them.

## 9 · Files

- `jakk/cli.py` — `--arg` flag, `_parse_kv` helper
- `jakk/scanner.py` — `ScanConfig.context_args`, `_resolve_arguments`
  step 3-4, `_UnsatisfiedRequiredArgs`, `_skip_evidence`
- `jakk/mcp_client.py` — `ToolDescriptor.required_args()` / `has_arg()`
- `tests/unit/test_jakk_scanner.py` — context-arg + required-arg tests
