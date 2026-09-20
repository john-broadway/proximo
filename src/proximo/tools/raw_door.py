"""The raw GET door as a tool: one name, four planes, every published read.

Its own toolset (`raw`), reachable in every mode by name through proximo_read / proximo_call
(they dispatch from the full catalog), and deliberately NOT resident in the lean facade: the
facade is a token budget, and a door most requests never open must not tax every request. Validation, gate refusal
and the envelope are `proximo.rawdoor` (pure); this module supplies the backend and the ledger.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

import proximo.server as _proximo_server
from proximo import rawdoor
from proximo.backends import ProximoError
from proximo.server import _audited, tool


def _getter(plane: str):
    """The plane's `_get`, shaped to `(path, params) -> data`. A plane this Proximo has not
    configured raises the backend's RuntimeError at construction; that is a clean refusal here."""
    try:
        if plane == "pve":
            _, api, _, _ = _proximo_server._svc()
            return lambda path, params: api._get(rawdoor.with_query(path, params))
        backend = {"pbs": _proximo_server._pbs, "pmg": _proximo_server._pmg, "pdm": _proximo_server._pdm}[plane]()[1]
    except ProximoError:
        raise
    except RuntimeError as e:
        raise ProximoError(f"{plane} is not configured on this Proximo ({e})") from e
    return lambda path, params: backend._get(path, params)


@tool()
def proximo_api_get(
    plane: Annotated[str, Field(description="Which API tree: 'pve', 'pbs', 'pmg' or 'pdm'.")],
    path: Annotated[
        str,
        Field(
            description="Absolute API path with real values in it, e.g. the guest status path for one VMID. No query string."
        ),
    ],
    params: Annotated[dict | None, Field(description="Flat query parameters (string/number/bool values).")] = None,
) -> dict[str, Any]:
    """READ-ONLY: run any GET the plane publishes, by path, and return the vendor's data
    labelled raw.

    The floor under the curated tools: when no tool covers a read, this does, with the same
    ledger entry every read gets. The path must match a GET in the vendored API tree (write
    paths, tunnels and unknown paths are refused with the nearest published reads named), and
    reads a curated tool already gates (qemu-agent, byte streams) are refused with that tool
    named. Bodies over PROXIMO_RAW_MAX_BYTES come back labelled truncated with their size.
    """
    published = rawdoor.validate(plane, path)
    path = rawdoor.canonical(path)
    query = rawdoor.check_params(params)
    get = _getter(plane)
    return _audited(
        "proximo_api_get",
        f"{plane}:{path}",
        lambda: rawdoor.envelope(plane, path, published, get(path, query)),
        detail={"published": published, "params": sorted(query)},
    )
