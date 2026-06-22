"""Tiny clean MCP server used to dogfood the jakk GitHub Action.

It exposes one benign tool over stdio. The Action smoke workflow scans this
server with safe probes only; auth probes are skipped as N/A for stdio and the
remaining probes should pass/skip without findings.
"""
from __future__ import annotations

from fastmcp import FastMCP

mcp = FastMCP("jakk stdio smoke server")


@mcp.tool()
def echo(message: str) -> str:
    """Return a benign echo response with no secrets or directives."""
    return f"echo: {message}"


if __name__ == "__main__":
    mcp.run()
