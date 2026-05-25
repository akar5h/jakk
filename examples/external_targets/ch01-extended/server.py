"""Extended breach-to-fix ch01 vulnerable server.

Same confused-deputy / cross-tenant BOLA as upstream ch01, but extends
the surface with three more tools so the four depth-of-exposure axes
(tool breadth, ID predictability, data class breakdown, read-vs-write)
all have real things to measure.

Tools exposed:
    fetch_project(project_id, api_key)      — original; reads any project (BOLA-read)
    list_projects(api_key)                  — NEW; lists ALL projects across tenants (BOLA-list)
    get_project_settings(project_id, api_key) — NEW; reads project settings incl. a webhook secret (BOLA-read, secret-class)
    update_project(project_id, api_key, name?, status?, notes?) — NEW; modifies any project (BOLA-write)

All four tools have the same flaw: API key is *authenticated* (must be
one of the known keys) but never *authorized* (no per-tenant scoping
on the resource being touched). Run alongside the upstream vulnerable
ch01 — same data file, same shape, more surface for the playbook to
work against.

Usage (local, no Docker):
    CHALLENGE_PORT=8011 python examples/external_targets/ch01-extended/server.py
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

APP_NAME = "Extended Challenge 01: Cross-Tenant CRM (read + write BOLA)"
INSTRUCTIONS = (
    "Extended ch01 surface for jakk depth-of-exposure methodology. "
    "DO NOT USE IN PRODUCTION. All four exposed tools have the same "
    "confused-deputy flaw: API key is authenticated but never authorized."
)

# Reuse the upstream ch01 data file by default. Override via CH01_EXT_DATA_PATH.
DEFAULT_DATA = (
    Path(__file__).resolve().parents[1]
    / "_vendor"
    / "mcp-breach-to-fix-labs"
    / "01-Asana-multi-tenant-authorization-bypass"
    / "data"
    / "projects.json"
)
DATA_FILE = Path(os.environ.get("CH01_EXT_DATA_PATH", str(DEFAULT_DATA)))

# Extra "settings" data — only used by get_project_settings. Webhooks contain a
# secret-shaped value to give the data-class-breakdown axis something to find.
SETTINGS_DATA: Dict[str, Dict[str, Any]] = {
    "CRM-1001": {
        "webhook_url": "https://hooks.example.com/alpha",
        "webhook_secret": "whsec_alpha_zT4mxQyrV2bH7N9p",
        "notification_email": "ops@alpha-corp.example",
        "retention_days": 90,
    },
    "CRM-2001": {
        "webhook_url": "https://hooks.example.com/bravo",
        "webhook_secret": "whsec_bravo_kJ8nR5xL9wA3vC4q",
        "notification_email": "security@bravo-corp.example",
        "retention_days": 365,
    },
}

API_KEYS: Dict[str, str] = {
    "alpha-api-key": "tenant_alpha",
    "bravo-api-key": "tenant_bravo",
}

# In-memory mutation store so update_project can prove it works without
# touching the shared data file. Snapshot at startup, overlays per write.
_OVERLAY: Dict[str, Dict[str, Any]] = {}

log = logging.getLogger("ch01_extended")

mcp = FastMCP(
    name=APP_NAME,
    instructions=INSTRUCTIONS,
    streamable_http_path="/mcp/stream",
)
mcp.app = mcp.streamable_http_app()


def _load_projects() -> List[Dict[str, Any]]:
    with DATA_FILE.open(encoding="utf-8") as fh:
        projects: List[Dict[str, Any]] = json.load(fh)
    # Apply in-memory overlays from prior update_project calls.
    for p in projects:
        pid = p["project_id"]
        if pid in _OVERLAY:
            p.update(_OVERLAY[pid])
    return projects


def _validate_api_key(api_key: str) -> str:
    tenant = API_KEYS.get(api_key)
    if not tenant:
        raise ValueError("Invalid API key.")
    return tenant


# -----------------------------------------------------------------------------
# Tools
# -----------------------------------------------------------------------------


@mcp.tool()
def fetch_project(project_id: str, api_key: str) -> str:
    """Read a CRM project by ID. AUTHENTICATED but NOT AUTHORIZED — any valid
    api_key can read any project regardless of tenant."""
    try:
        _validate_api_key(api_key)
    except ValueError as exc:
        return str(exc)
    for project in _load_projects():
        if project["project_id"] == project_id:
            log.warning("BOLA-read: api_key=%s fetched project=%s", api_key, project_id)
            return f"Project data:\n{json.dumps(project, indent=2)}"
    return f"Project {project_id} not found."


@mcp.tool()
def list_projects(api_key: str) -> str:
    """List CRM projects. AUTHENTICATED but NOT AUTHORIZED — returns ALL
    projects across ALL tenants, not just the caller's."""
    try:
        _validate_api_key(api_key)
    except ValueError as exc:
        return str(exc)
    projects = _load_projects()
    log.warning("BOLA-list: api_key=%s listed %d projects", api_key, len(projects))
    # Return a compact summary; caller can fetch_project for details.
    summary = [
        {"project_id": p["project_id"], "tenant": p["tenant"], "name": p["name"]}
        for p in projects
    ]
    return f"All projects:\n{json.dumps(summary, indent=2)}"


@mcp.tool()
def get_project_settings(project_id: str, api_key: str) -> str:
    """Read project settings including notification config. AUTHENTICATED but
    NOT AUTHORIZED — webhook secrets returned without tenant check."""
    try:
        _validate_api_key(api_key)
    except ValueError as exc:
        return str(exc)
    settings = SETTINGS_DATA.get(project_id)
    if not settings:
        return f"No settings for {project_id}."
    log.warning("BOLA-read-settings: api_key=%s fetched settings for %s", api_key, project_id)
    return f"Project settings:\n{json.dumps(settings, indent=2)}"


@mcp.tool()
def update_project(
    project_id: str,
    api_key: str,
    name: Optional[str] = None,
    status: Optional[str] = None,
    notes: Optional[str] = None,
) -> str:
    """Modify a CRM project's fields. AUTHENTICATED but NOT AUTHORIZED — any
    valid api_key can modify any project regardless of tenant.

    This is the BOLA-write variant that the depth-of-exposure methodology
    uses to demonstrate escalation from read-only to read-write impact.
    """
    try:
        _validate_api_key(api_key)
    except ValueError as exc:
        return str(exc)

    # Find the project to confirm it exists.
    projects = _load_projects()
    target = next((p for p in projects if p["project_id"] == project_id), None)
    if not target:
        return f"Project {project_id} not found."

    # Apply the update to the in-memory overlay (so the data file stays clean
    # across runs — restart the server to reset).
    updates: Dict[str, Any] = {}
    if name is not None:
        updates["name"] = name
    if status is not None:
        updates["status"] = status
    if notes is not None:
        updates["notes"] = notes
    if not updates:
        return "No fields to update."

    _OVERLAY.setdefault(project_id, {}).update(updates)
    log.warning(
        "BOLA-write: api_key=%s modified project=%s fields=%s",
        api_key,
        project_id,
        list(updates.keys()),
    )

    # Return the post-update state so the caller can confirm.
    refreshed = _load_projects()
    after = next(p for p in refreshed if p["project_id"] == project_id)
    return f"Project updated:\n{json.dumps(after, indent=2)}"


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("CHALLENGE_HOST", "0.0.0.0")
    port = int(os.environ.get("CHALLENGE_PORT", "8011"))
    log.info("Starting extended ch01 on %s:%s (data=%s)", host, port, DATA_FILE)
    uvicorn.run("server:mcp.app", host=host, port=port, log_level="info")
