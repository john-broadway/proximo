"""Hardware Mappings plane — PVE cluster PCI and USB device mappings.

Covers Plane F (PLAN + PROVE; MEDIUM risk — config is re-creatable after delete,
but VMs referencing a deleted mapping lose the device path and may fail to start):
  - PVE hardware list (physical devices on a node)    (/nodes/{node}/hardware/{pci|usb})
  - PCI cluster mappings                              (/cluster/mapping/pci)
  - USB cluster mappings                              (/cluster/mapping/usb)

VERIFIED live shapes: None — all endpoint shapes carry "Smoke-confirm:" comments.

Security posture:
  - All path components validated with \\Z-anchored regexes (trailing-newline bypass rejected).
  - Hardware type validated against a closed frozenset {pci, usb} (no arbitrary string into URL path).
  - No snapshot primitive on this plane — plans declare re-creatable, NEVER imply undo.
  - RISK_MEDIUM: VMs referencing a deleted mapping lose their device path and may fail to start;
    config is re-addable but restoring a passthrough link to a running VM requires restart.
"""

from __future__ import annotations

import re

from .backends import ProximoError
from .planning import RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# Mapping ID: path segment in /cluster/mapping/{pci,usb}/{id}
# Pattern mirrors the backup-job-id format used elsewhere in PVE config.
# Smoke-confirm: exact accepted charset against a live PVE instance.
_MAPPING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")

# Node name: path segment in /nodes/{node}/hardware/{type}
# Smoke-confirm: exact accepted charset against a live PVE instance.
_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

# Hardware type — closed set; no arbitrary string into URL path.
_VALID_HW_TYPES = frozenset({"pci", "usb"})

# Free-text body fields (description, map) are forwarded to PVE verbatim. Reject control chars/
# newlines so a mapping create/update can't smuggle one into the config write. Mirrors the
# _check_freetext guard in the firewall/access planes; the value is form-encoded (no URL-path
# injection), so this is body hygiene, applied here for parity with the sibling planes.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _check_mapping_freetext(kw: dict) -> None:
    # `map` is often a repeated per-node LIST, so scan list elements too — not just str values.
    for field in ("description", "map"):
        v = kw.get(field)
        parts = v if isinstance(v, (list, tuple)) else [v]
        for part in parts:
            if isinstance(part, str) and _CONTROL_RE.search(part):
                raise ProximoError(
                    f"invalid {field}: control characters and newlines are not allowed"
                )


def _check_mapping_id(mapping_id: str) -> str:
    # Do NOT strip — stripping defeats \\Z trailing-newline protection.
    s = str(mapping_id)
    if not _MAPPING_ID_RE.match(s):
        raise ProximoError(
            f"invalid mapping ID: {mapping_id!r} "
            "(must start with alnum, then alnum/_/-, <=64 chars, no slash)"
        )
    return s


def _check_node(node: str) -> str:
    s = str(node)
    if not _NODE_RE.match(s):
        raise ProximoError(
            f"invalid node name: {node!r} "
            "(must start with alnum, then alnum/._/-, <=64 chars)"
        )
    return s


def _check_hw_type(hw_type: str) -> str:
    if hw_type not in _VALID_HW_TYPES:
        raise ProximoError(
            f"invalid hardware type: {hw_type!r} "
            f"(expected one of {sorted(_VALID_HW_TYPES)})"
        )
    return hw_type


# ---------------------------------------------------------------------------
# Hardware list (read-only: discovers physical PCI/USB devices on a node)
# ---------------------------------------------------------------------------

def hardware_list(api, node: str, hw_type: str = "pci") -> dict:
    """List physical PCI or USB devices on a PVE node.

    GET /nodes/{node}/hardware/{pci|usb}
    Smoke-confirm: exact response field names (vendor, class, iommugroup, etc.).
    """
    _check_node(node)
    _check_hw_type(hw_type)
    return {"devices": api._get(f"/nodes/{node}/hardware/{hw_type}") or []}


# ---------------------------------------------------------------------------
# PCI mapping operations
# ---------------------------------------------------------------------------

def mapping_pci_get(api, mapping_id: str) -> dict:
    """Get one PCI cluster mapping config.

    GET /cluster/mapping/pci/{id}
    Smoke-confirm: exact response shape (map array, description, ...).
    """
    _check_mapping_id(mapping_id)
    return api._get(f"/cluster/mapping/pci/{mapping_id}") or {}


def mapping_pci_list(api) -> list[dict]:
    """List all PCI cluster mappings (read). GET /cluster/mapping/pci."""
    return api._get("/cluster/mapping/pci") or []


def mapping_usb_list(api) -> list[dict]:
    """List all USB cluster mappings (read). GET /cluster/mapping/usb."""
    return api._get("/cluster/mapping/usb") or []


def mapping_pci_create(api, mapping_id: str, **kw) -> None:
    """Create a PCI cluster mapping.

    POST /cluster/mapping/pci
    Body: {id, map?, description?, ...}
    Smoke-confirm: id in body vs path + exact accepted body fields.
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_mapping_id(mapping_id)
    _check_mapping_freetext(kw)
    data = {"id": mapping_id, **kw}
    # MUTATION — confirm-gated + audited at the server layer.
    api._post("/cluster/mapping/pci", {k: v for k, v in data.items() if v is not None})


def mapping_pci_update(api, mapping_id: str, **kw) -> None:
    """Update a PCI cluster mapping.

    PUT /cluster/mapping/pci/{id}
    Body: {map?, description?, digest?, ...}
    Smoke-confirm: exact accepted body fields.
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_mapping_id(mapping_id)
    _check_mapping_freetext(kw)
    # MUTATION — confirm-gated + audited at the server layer.
    api._put(f"/cluster/mapping/pci/{mapping_id}", {k: v for k, v in kw.items() if v is not None})


def mapping_pci_delete(api, mapping_id: str) -> None:
    """Delete a PCI cluster mapping.

    DELETE /cluster/mapping/pci/{id}
    Smoke-confirm: response shape (null or empty).
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_mapping_id(mapping_id)
    # MUTATION — confirm-gated + audited at the server layer.
    api._delete(f"/cluster/mapping/pci/{mapping_id}")


# ---------------------------------------------------------------------------
# USB mapping operations
# ---------------------------------------------------------------------------

def mapping_usb_get(api, mapping_id: str) -> dict:
    """Get one USB cluster mapping config.

    GET /cluster/mapping/usb/{id}
    Smoke-confirm: exact response shape (map array, description, ...).
    """
    _check_mapping_id(mapping_id)
    return api._get(f"/cluster/mapping/usb/{mapping_id}") or {}


def mapping_usb_create(api, mapping_id: str, **kw) -> None:
    """Create a USB cluster mapping.

    POST /cluster/mapping/usb
    Body: {id, map?, description?, ...}
    Smoke-confirm: id in body vs path + exact accepted body fields.
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_mapping_id(mapping_id)
    _check_mapping_freetext(kw)
    data = {"id": mapping_id, **kw}
    # MUTATION — confirm-gated + audited at the server layer.
    api._post("/cluster/mapping/usb", {k: v for k, v in data.items() if v is not None})


def mapping_usb_update(api, mapping_id: str, **kw) -> None:
    """Update a USB cluster mapping.

    PUT /cluster/mapping/usb/{id}
    Body: {map?, description?, digest?, ...}
    Smoke-confirm: exact accepted body fields.
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_mapping_id(mapping_id)
    _check_mapping_freetext(kw)
    # MUTATION — confirm-gated + audited at the server layer.
    api._put(f"/cluster/mapping/usb/{mapping_id}", {k: v for k, v in kw.items() if v is not None})


def mapping_usb_delete(api, mapping_id: str) -> None:
    """Delete a USB cluster mapping.

    DELETE /cluster/mapping/usb/{id}
    Smoke-confirm: response shape (null or empty).
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_mapping_id(mapping_id)
    # MUTATION — confirm-gated + audited at the server layer.
    api._delete(f"/cluster/mapping/usb/{mapping_id}")


# ---------------------------------------------------------------------------
# Plan factories — PCI mappings
# ---------------------------------------------------------------------------

def plan_mapping_pci_create(mapping_id: str, **kw) -> Plan:
    """Plan a PCI mapping creation (additive, MEDIUM risk — needs node-hw setup)."""
    _check_mapping_id(mapping_id)
    return Plan(
        action="pve_mapping_pci_create",
        target=f"cluster/mapping/pci/{mapping_id}",
        change=f"create PCI cluster mapping {mapping_id!r}: {kw}",
        current={},
        blast_radius=["adds a new PCI passthrough mapping (no existing data affected)"],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "PCI passthrough mappings require matching IOMMU/VFIO configuration on nodes",
            "incorrect map entries may prevent VMs from starting",
        ],
        note=(
            "Additive config. Delete with pve_mapping_pci_delete to remove. "
            "Smoke-confirm: exact POST body shape (id in body vs path) against a live PVE instance."
        ),
    )


def plan_mapping_pci_update(api, mapping_id: str, **kw) -> Plan:
    """Plan a PCI mapping update. Reads current config for honesty."""
    _check_mapping_id(mapping_id)
    current = mapping_pci_get(api, mapping_id)
    return Plan(
        action="pve_mapping_pci_update",
        target=f"cluster/mapping/pci/{mapping_id}",
        change=f"update PCI cluster mapping {mapping_id!r}: {kw}",
        current=current,
        blast_radius=[
            "changes device path for VMs referencing this mapping",
            "running VMs with this mapping may need restart to pick up new device path",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "modifies passthrough map entries — can break running VMs that hold this mapping",
        ],
        note=(
            "No snapshot primitive on this plane. Current config captured above — "
            "re-apply it manually to revert."
        ),
    )


def plan_mapping_pci_delete(api, mapping_id: str) -> Plan:
    """Plan a PCI mapping deletion. Reads current config for honesty."""
    _check_mapping_id(mapping_id)
    current = mapping_pci_get(api, mapping_id)
    return Plan(
        action="pve_mapping_pci_delete",
        target=f"cluster/mapping/pci/{mapping_id}",
        change=f"delete PCI cluster mapping {mapping_id!r}",
        current=current,
        blast_radius=[
            "VMs referencing this mapping lose the device path",
            "affected VMs may fail to start or lose PCI passthrough device",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "config delete — re-addable, but VMs using this mapping break until remapped",
        ],
        note=(
            "No UNDO primitive on this plane. Current config captured above — "
            "re-create with pve_mapping_pci_create to restore the mapping. "
            "VMs must be reconfigured if the mapping ID changes."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — USB mappings
# ---------------------------------------------------------------------------

def plan_mapping_usb_create(mapping_id: str, **kw) -> Plan:
    """Plan a USB mapping creation (additive, MEDIUM risk)."""
    _check_mapping_id(mapping_id)
    return Plan(
        action="pve_mapping_usb_create",
        target=f"cluster/mapping/usb/{mapping_id}",
        change=f"create USB cluster mapping {mapping_id!r}: {kw}",
        current={},
        blast_radius=["adds a new USB passthrough mapping (no existing data affected)"],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "USB passthrough mappings require matching USB device IDs across nodes",
            "incorrect map entries may prevent VMs from acquiring the USB device",
        ],
        note=(
            "Additive config. Delete with pve_mapping_usb_delete to remove. "
            "Smoke-confirm: exact POST body shape (id in body vs path) against a live PVE instance."
        ),
    )


def plan_mapping_usb_update(api, mapping_id: str, **kw) -> Plan:
    """Plan a USB mapping update. Reads current config for honesty."""
    _check_mapping_id(mapping_id)
    current = mapping_usb_get(api, mapping_id)
    return Plan(
        action="pve_mapping_usb_update",
        target=f"cluster/mapping/usb/{mapping_id}",
        change=f"update USB cluster mapping {mapping_id!r}: {kw}",
        current=current,
        blast_radius=[
            "changes USB device path for VMs referencing this mapping",
            "running VMs with this mapping may lose USB passthrough until restarted",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "modifies passthrough map entries — can break running VMs that hold this mapping",
        ],
        note=(
            "No snapshot primitive on this plane. Current config captured above — "
            "re-apply it manually to revert."
        ),
    )


def plan_mapping_usb_delete(api, mapping_id: str) -> Plan:
    """Plan a USB mapping deletion. Reads current config for honesty."""
    _check_mapping_id(mapping_id)
    current = mapping_usb_get(api, mapping_id)
    return Plan(
        action="pve_mapping_usb_delete",
        target=f"cluster/mapping/usb/{mapping_id}",
        change=f"delete USB cluster mapping {mapping_id!r}",
        current=current,
        blast_radius=[
            "VMs referencing this mapping lose the USB device path",
            "affected VMs may fail to start or lose USB passthrough",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "config delete — re-addable, but VMs using this mapping break until remapped",
        ],
        note=(
            "No UNDO primitive on this plane. Current config captured above — "
            "re-create with pve_mapping_usb_create to restore the mapping. "
            "VMs must be reconfigured if the mapping ID changes."
        ),
    )
