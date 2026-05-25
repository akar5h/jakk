"""Compatibility filter — decide which discovered tools a test fires against.

Also hosts the ``ARG_KINDS`` registry — semantic-role heuristics that let
probes target a tool argument by *role* (e.g. "path", "query") rather than
by literal name. This is what lets one probe library generalize across
MCP servers whose tools name their arguments differently.

Example: a path-traversal probe declares ``target_arg_kind: path``. Against
breach-to-fix's ``read_file_contents(file_path)`` it resolves to ``file_path``;
against GitHub's ``get_file_contents(owner, repo, path)`` it resolves to
``path``. No per-server hardcoding in either case.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

from .library import AppliesTo, TestCase
from .mcp_client import ToolDescriptor


# ---------------------------------------------------------------------------
# Semantic argument-role registry
# ---------------------------------------------------------------------------
#
# Each kind has two regex patterns: ``name_regex`` matched against the
# argument's name, ``desc_regex`` matched against its ``description``.
# Resolution tries names first, then descriptions — so an argument literally
# named ``path`` wins over one merely described as "path to the file".
#
# Kinds are deliberately CONSERVATIVE. Adding a kind expands the surface
# every probe can opt into; adding a regex broadens what each kind catches.
# Both choices are reviewable in PR.
#
# NOTE: there is intentionally no ``command`` kind. Shell-injection probes
# target tools where the bug is "this string arg gets interpolated into a
# shell command" — there is no semantic clue in the schema for that. Those
# probes keep using ``__first_string_arg__`` resolution.
ARG_KINDS: dict[str, dict[str, str]] = {
    "path": {
        # "path" matches as a substring (covers path, full_path, file_path,
        # filepath, dir_path, etc.) — safe because tool_name_regex has already
        # narrowed us to file/path/read/list tools. Standalone words are
        # anchored to avoid false matches like "profile" → file.
        "name_regex": (
            r"(?i)(path|^file$|^filename$|^dir$|^directory$|"
            r"target_file|^src$|^source$)"
        ),
        "desc_regex": (
            r"(?i)(file path|path to|filename|file name|"
            r"absolute path|relative path|directory path)"
        ),
    },
    "query": {
        "name_regex": r"(?i)(^q$|^query$|^search$|^term$|^keyword$|search_query)",
        "desc_regex": r"(?i)(search query|search term|search string|keyword to search)",
    },
    "id": {
        "name_regex": r"(?i)(^id$|_id$|^number$|_number$|^identifier$|_key$)",
        "desc_regex": r"(?i)(identifier of|id of the|number of the|unique identifier)",
    },
    "url": {
        "name_regex": r"(?i)(^url$|^uri$|^endpoint$|webhook_url|^link$)",
        "desc_regex": r"(?i)(url to|uri of|web address|endpoint url)",
    },
    "text": {
        "name_regex": r"(?i)(^text$|^body$|^content$|^message$|^note$|^notes$|^comment$|description)",
        "desc_regex": r"(?i)(text content|body of|message body|comment text|note text)",
    },
}


def find_arg_of_kind(tool: ToolDescriptor, kind: str) -> Optional[str]:
    """Find a string-typed argument in ``tool``'s inputSchema whose name or
    description matches the given semantic kind.

    Resolution order:
      1. First string-typed arg whose NAME matches the kind's ``name_regex``.
      2. First string-typed arg whose DESCRIPTION matches the kind's ``desc_regex``.
      3. Returns ``None`` if nothing matches.

    The name pass beats the description pass, so a literal ``path`` argument
    is preferred over one merely documented as "the path to read."
    """
    if kind not in ARG_KINDS:
        raise ValueError(
            f"unknown target_arg_kind: {kind!r}. "
            f"Registered kinds: {sorted(ARG_KINDS.keys())}"
        )
    spec = ARG_KINDS[kind]
    name_re = re.compile(spec["name_regex"])
    desc_re = re.compile(spec["desc_regex"])

    props = (tool.input_schema or {}).get("properties") or {}

    def _is_string_typed(prop: object) -> bool:
        if not isinstance(prop, dict):
            return False
        t = prop.get("type")
        if t == "string":
            return True
        if isinstance(t, list) and "string" in t:
            return True
        return False

    # Pass 1: name match
    for name, prop in props.items():
        if not _is_string_typed(prop):
            continue
        if name_re.search(name):
            return name

    # Pass 2: description match
    for name, prop in props.items():
        if not _is_string_typed(prop):
            continue
        desc = prop.get("description", "") if isinstance(prop, dict) else ""
        if isinstance(desc, str) and desc and desc_re.search(desc):
            return name

    return None


# ---------------------------------------------------------------------------
# applies_to evaluation
# ---------------------------------------------------------------------------


def matches(applies_to: AppliesTo, tool: ToolDescriptor) -> bool:
    if applies_to.none:
        return False
    if applies_to.tool_name and tool.name != applies_to.tool_name:
        return False
    if applies_to.tool_name_regex and not re.search(applies_to.tool_name_regex, tool.name):
        return False
    if applies_to.min_string_args and tool.string_arg_count() < applies_to.min_string_args:
        return False
    if applies_to.require_no_required_args:
        required = (tool.input_schema or {}).get("required") or []
        if required:
            return False
    if applies_to.target_arg_kind:
        # Filter: probe only fires on tools that actually expose an arg of
        # the declared kind. Without this check, a tool that matches the
        # name regex but has no path-shaped arg would produce an `error`
        # outcome at scan time. Better to skip cleanly at filter time.
        if find_arg_of_kind(tool, applies_to.target_arg_kind) is None:
            return False
    return True


def select_tools(case: TestCase, tools: Iterable[ToolDescriptor]) -> list[ToolDescriptor]:
    """Return the subset of ``tools`` that ``case.applies_to`` matches."""
    if case.applies_to.none:
        return []
    return [t for t in tools if matches(case.applies_to, t)]
