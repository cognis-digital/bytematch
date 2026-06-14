"""BYTEMATCH MCP server — exposes verify() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json as _json


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-bytematch[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-bytematch[mcp]'")
        return 1

    from bytematch.core import verify, load_artifact_runtime_bytecode

    app = FastMCP("bytematch")

    @app.tool()
    def bytematch_verify(deployed: str, artifact_json: str) -> str:
        """Verify deployed on-chain bytecode against a build artifact JSON.

        Returns JSON with a Sourcify-style verdict (exact_match / runtime_match
        / partial_match / mismatch).
        """
        try:
            art_hex = load_artifact_runtime_bytecode(artifact_json)
            result = verify(deployed, art_hex)
            return _json.dumps(result.to_dict())
        except (ValueError, _json.JSONDecodeError) as exc:
            return _json.dumps({"error": str(exc)})

    app.run()
    return 0
