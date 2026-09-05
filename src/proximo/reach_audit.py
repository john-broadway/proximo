"""`proximo reach-audit` — the reach-privilege decision packet for the mirror (grant model, gap 2).

The mirror derives shell reach from the served token's own Proxmox-side permission map, keyed
on a REACH PRIVILEGE the operator chooses. Choosing it is the one thing the mirror adds to the
world, and it must be chosen from evidence: PVE has custom roles but no custom privileges, so
whatever privilege carries the reach ALIASES with every existing and future grant of it. This
verb prints that evidence, live, per candidate:

- the STANDING hazard: which roles carry the candidate (a grant of any of them to the SERVED
  principal — the token or, for privsep tokens, its user — silently extends shell reach);
- TODAY'S exposure: which principals hold those roles, on which paths (`/` flagged in
  pve_overbroad_grants' vocabulary);
- the DERIVED preview: which guests the SERVED token would reach under that privilege — asked of
  PVE per guest path, because the full permission map returns only ACL-anchored paths (a
  pool-member guest has no `/vms/<id>` key there; the explicit per-path query resolves
  propagation server-side, deeper NoAccess included — probed live 2026-08-26) — compared
  against the current env allowlist as +added/-removed.

Print-only; read-only API calls; the CLI prints the query-count header and FLUSHES it before
the sweep runs (no silent floods on a large estate — scope with --ctids; the first lens round
caught the count line merely leading the OUTPUT while temporally following the flood). The
output names WHOSE map was derived (the token id, never the secret — token_id_of REFUSES a
file that does not match the PVE token shape rather than printing unknown content): on an
arm-pattern estate the CLI's token and the armed token differ, and an audit that doesn't say
which one it read would misinform the choice.
"""
from __future__ import annotations

import os
from typing import Any

from .access import access_acl_list, access_roles_list
from .config import parse_allowlist

# Plausible reach privileges, swept when no --priv is given. Deliberately a visible tuple, not magic —
# edit here as candidates emerge. The custom-role lane (a dedicated role carrying one of
# these on scoped paths) is what the aliasing table exists to inform.
CANDIDATES = ("VM.Console", "VM.GuestAgent.Unrestricted", "VM.PowerMgmt")

# The choice has TWO axes and aliasing is only one of them. The other is SEMANTIC FIT: the
# mirror reads the reach privilege as "may run shell commands as root in this guest", so a candidate
# must MEAN that in stock PVE, or the mirror grants more than the platform means by the grant
# (caught 2026-08-26: VM.Console gates a console ATTACH — the guest still asks for a login —
# while pct exec is passwordless root; mirroring Console would silently upgrade every
# console-grant into a root shell). Stated per candidate so the packet informs both axes.
CANDIDATE_SEMANTICS: dict[str, str] = {
    "VM.Console": ("gates console ATTACH — a login prompt, NOT execution; keying the mirror "
                   "on it grants MORE than PVE means by the grant"),
    "VM.GuestAgent.Unrestricted": ("PVE's own privilege for root-level command execution "
                                   "inside guests (agent exec) — the semantic match for the "
                                   "shell channel"),
    "VM.PowerMgmt": ("gates power-state changes — no execution semantics; keying the mirror "
                     "on it reads power rights as shell rights"),
}

_ROOT_REASON = "ACL at '/' affects EVERY resource on the cluster — widest possible scope"


def alias_report(api: Any, priv: str) -> dict[str, Any]:
    """Both aliasing layers for one candidate privilege, separated on purpose."""
    roles = sorted(r["roleid"] for r in access_roles_list(api)
                   if priv in str(r.get("privs", "")).split(","))
    grants = [a for a in access_acl_list(api) if a.get("roleid") in roles]
    root_grants = [{**g, "reasons": [_ROOT_REASON]} for g in grants if g.get("path") == "/"]
    return {"roles": roles, "grants": grants, "root_grants": root_grants}


def derived_reach(api: Any, ctids: list[str], priv: str) -> dict[str, bool]:
    """Would the SERVED token hold `priv` on each guest? One per-path query per guest — PVE
    resolves propagation (and deeper NoAccess revocation) server-side; the full map cannot
    answer this (anchored paths only)."""
    out: dict[str, bool] = {}
    for ctid in ctids:
        path = f"/vms/{ctid}"
        m = api.access_permissions(path=path) or {}
        out[ctid] = bool((m.get(path) or {}).get(priv))
    return out


def token_id_of(token_path: str) -> str:
    """The token's ID (public — it appears in every ACL entry), never its secret: the file
    carries 'user@realm!name=secret'; everything from the first '=' on stays behind.

    FAIL-CLOSED on shape: a file without '=' or whose id part does not look like an authid
    (user@realm!name) is REFUSED without printing ANY of its content — the estate's own PBS/PDM
    token files use 'id:secret' (colon), one --token-path slip away, and a splitter that fails
    open would print the whole secret (lens finding, 2026-08-26)."""
    with open(token_path, encoding="utf-8") as f:
        content = f.read().strip()
    tid = content.split("=", 1)[0].strip()
    if "=" not in content or "@" not in tid or "!" not in tid or "\n" in tid:
        raise ValueError(
            f"{token_path} does not look like a PVE token file (USER@REALM!NAME=SECRET) — "
            "refusing to read an id from it. PBS/PDM token files (id:secret) are a different "
            "shape; this audit reads the PVE map only.")
    return tid


def _api_and_token(token_path: str | None = None):
    """Build the API backend the audit reads through (extracted for the CLI test seam).
    A --token-path override is scoped to the config build — never left in the process env."""
    from .backends import ApiBackend
    from .config import ProximoConfig
    prev = os.environ.get("PROXIMO_TOKEN_PATH")
    if token_path:
        os.environ["PROXIMO_TOKEN_PATH"] = token_path
    try:
        cfg = ProximoConfig.from_env()
    finally:
        if token_path:
            if prev is None:
                os.environ.pop("PROXIMO_TOKEN_PATH", None)
            else:
                os.environ["PROXIMO_TOKEN_PATH"] = prev
    return ApiBackend(cfg), token_id_of(cfg.token_path)


def _ctid_key(c: str):
    """Numeric-aware sort that cannot crash: isdigit() is True for '\u00b2' while int() raises
    (lens finding) — try/except is the only honest test."""
    try:
        return (0, int(c))
    except ValueError:
        return (1, c)


def render_header(ctids: list[str], privs: list[str], token_id: str) -> str:
    """Printed and FLUSHED by the CLI before any sweep query runs — the count must precede
    the flood it warns about, not merely lead the output string."""
    n_queries = len(ctids) * len(privs)
    n_meta = 2 * len(privs)  # roles + ACL reads per candidate
    return (
        "proximo reach-audit — reach-privilege candidate evidence for the mirror\n"
        f"derived for the SERVED token: {token_id}\n"
        f"{len(ctids)} guest(s) x {len(privs)} candidate(s) = {n_queries} per-path "
        f"permission queries (+{n_meta} roles/ACL reads)\n\n")


def _current_allowlist() -> set[str]:
    # Through config's parser, not a second copy of it: this read is the allowlist the gates
    # enforce, and a private re-split here is exactly the drift the one-parser rule exists to
    # prevent (claims lens, 2026-09-04 — it was byte-equivalent, and that is luck, not a design).
    return set(parse_allowlist(os.environ.get("PROXIMO_CT_ALLOWLIST", "")))


def render(api: Any, ctids: list[str], privs: list[str], *, token_id: str) -> str:
    """Header + body in one string (test/API convenience); the CLI prints render_header FIRST,
    then this body, so the count genuinely precedes the sweep."""
    return render_header(ctids, privs, token_id) + render_body(api, ctids, privs)


def render_body(api: Any, ctids: list[str], privs: list[str]) -> str:
    lines: list[str] = []
    ctids = list(dict.fromkeys(ctids))  # dedupe, order kept — '101,101' must not lie as 1/2
    current = _current_allowlist()
    for priv in privs:
        rep = alias_report(api, priv)
        lines.append(f"== {priv} " + "=" * max(1, 55 - len(priv)))
        lines.append("  semantics: " + CANDIDATE_SEMANTICS.get(
            priv, "not in the swept set — check what this privilege gates in stock PVE "
                  "before keying the mirror on it"))
        lines.append(f"  roles carrying it (STANDING hazard — granting any of these to the "
                     f"served principal extends reach): {', '.join(rep['roles']) or 'none'}")
        for g in rep["grants"]:
            lines.append(f"     {g.get('type', '?')} {g.get('ugid')} holds "
                         f"{g.get('roleid')} on {g.get('path')}")
        for r in rep["root_grants"]:
            lines.append(f"  !! {r.get('ugid')}: {r['reasons'][0]}")
        reach = derived_reach(api, ctids, priv)
        allowed = sorted((c for c, ok in reach.items() if ok), key=_ctid_key)
        lines.append(f"  derived reach: {', '.join(allowed) or 'NO guests'} "
                     f"({len(allowed)}/{len(ctids)})")
        added = [c for c in allowed if c not in current]
        removed = sorted((c for c in current if c in reach and not reach[c]), key=_ctid_key)
        if added:
            lines.append(f"  vs current allowlist (audited guests only): +{' +'.join(added)}")
        if removed:
            lines.append(f"  vs current allowlist (audited guests only): -{' -'.join(removed)}")
        if not added and not removed:
            lines.append("  vs current allowlist: identical (on the audited guests)")
        lines.append("")
    lines.append("The reach-privilege choice is the operator's; the mirror builds behind it. Two honest")
    lines.append("lanes: a de facto BUILT-IN privilege keeps the vocabulary stock PVE at the cost")
    lines.append("of the aliasing above (and it must MEAN execution — read each semantics line);")
    lines.append("a CUSTOM ROLE carrying one privilege decouples AI shell reach from human role")
    lines.append("grants (the privilege itself still aliases wherever built-in roles carry it —")
    lines.append("Administrator at minimum). This table is the evidence for either choice.")
    return "\n".join(lines) + "\n"
