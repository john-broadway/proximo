"""Entry point for ``python -m proximo``: the MCP door over stdio, the same as the ``proximo``
console script. Stdio, on demand, no daemon: wire either into your MCP client."""
from proximo.core.doors.mcp import main

if __name__ == "__main__":
    raise SystemExit(main())
