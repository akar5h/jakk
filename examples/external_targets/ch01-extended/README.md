# ch01-extended

Locally-authored extension of breach-to-fix ch01 vulnerable. Same
confused-deputy / BOLA shape, more surface:

| Tool | What it does | Vulnerability shape |
|---|---|---|
| `fetch_project(project_id, api_key)` | Reads a project. Same as upstream ch01. | BOLA-read |
| `list_projects(api_key)` | Lists all projects across all tenants. | BOLA-list |
| `get_project_settings(project_id, api_key)` | Reads project settings incl. a `webhook_secret`. | BOLA-read (secret-class data) |
| `update_project(project_id, api_key, name?, status?, notes?)` | Modifies any project's fields. | BOLA-write |

All four authenticate the `api_key` but never authorize the resource —
the same flaw, on more tools, in more flavors.

## Why this exists

The upstream ch01 lab exposes only `fetch_project`. The jakk
depth-of-exposure methodology playbook needs to demonstrate all four
axes empirically: tool breadth (needs >1 tool), ID predictability
(works on any data), data class breakdown (needs interesting fields),
and read-vs-write (needs a write tool). ch01-extended adds the missing
surface without touching the vendored upstream lab.

## Running

```bash
# Default port 8011 (uses upstream ch01 data file).
CHALLENGE_PORT=8011 .venv/bin/python examples/external_targets/ch01-extended/server.py

# Or pick another port:
CHALLENGE_PORT=18011 .venv/bin/python examples/external_targets/ch01-extended/server.py
```

The server reads project data from
`examples/external_targets/_vendor/mcp-breach-to-fix-labs/01-Asana-multi-tenant-authorization-bypass/data/projects.json`
by default (override via `CH01_EXT_DATA_PATH`).

`update_project` modifications live in an in-memory overlay, NOT the
on-disk data file — restart the server to reset state. This keeps
the methodology playbook's worked examples reproducible without
having to git-restore the vendored data.

## Test identities

Same as upstream ch01:

| API key | Tenant |
|---|---|
| `alpha-api-key` | `tenant_alpha` (owns CRM-1001) |
| `bravo-api-key` | `tenant_bravo` (owns CRM-2001) |

## Status

This is a deliberate vulnerability lab. It is intentionally insecure.
Do not deploy. Run only on localhost.
