"""BYTEMATCH MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from bytematch.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-bytematch[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-bytematch[mcp]'")
        return 1
    app = FastMCP("bytematch")

    @app.tool()
    def bytematch_scan(target: str) -> str:
        """Verifies that deployed on-chain bytecode matches a given source/Foundry build, detecting unverified or tampered proxies and implementations.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
