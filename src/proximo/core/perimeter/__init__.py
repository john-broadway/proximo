"""The perimeter: what every network door of the core mounts, once.

`guard` (the Host allowlist, the cross-origin guard, the bearer check, the badge camera, the
refusal auditor and `serve`), `rest` (the OpenAPI face), `mcp_http` (the SDK's streamable-HTTP
transport behind the guard), `a2a` (the agent card, its signing, the JSON-RPC executor) and
`badge` (the caller badge the camera reads). A perimeter module carries requests to the dispatch,
instance, recorder and tool list its door hands it; it has no caller of its own and names no
0.44 module (`tests/test_gate_mutations_inventory.py` holds the core to that). Moved under the
core 2026-10-17, the second step of the seam move the flip reads.
"""
