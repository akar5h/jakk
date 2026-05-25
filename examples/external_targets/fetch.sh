#!/usr/bin/env bash
# Idempotent fetcher for third-party MCP scan targets.
# Sources clone into _vendor/ (gitignored). Nothing third-party enters our history.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR="$HERE/_vendor"
mkdir -p "$VENDOR"

fetch_repo() {
    local url="$1"
    local name
    name="$(basename "$url" .git)"
    local dest="$VENDOR/$name"

    if [[ -d "$dest/.git" ]]; then
        echo "[fetch] $name: updating"
        git -C "$dest" fetch --depth 1 origin
        git -C "$dest" reset --hard origin/HEAD
    else
        echo "[fetch] $name: cloning $url"
        git clone --depth 1 "$url" "$dest"
    fi
}

fetch_repo "https://github.com/PawelKozy/mcp-breach-to-fix-labs.git"

echo "[fetch] done. sources under $VENDOR/"
