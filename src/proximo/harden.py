"""`proximo harden` — walk the operator through erecting the pillars only their hand can raise.

The trust spine ships four pillars standing (PLAN / PROVE / UNDO / DIAGNOSE). The pillars that
bind the AGENT rather than trusting it — CONSENT, CONTAIN, the off-box PROVE anchor, and the
ARM pattern — are opt-in BY NECESSITY: a pillar Proximo raised for you would be a pillar the
agent could lower for itself. Necessity is not an excuse for them going unerected: security
that lives only in a documentation chapter is prose. This verb makes the strong posture the
EASY posture — it reads which stations stand, and for each empty one prints the exact
operator-shell steps (YOUR terminal, never the agent's) plus a verify line.

Print-only, like `mint`: it never creates a directory, never writes an env file, never touches
the operator's ground — describing the ground is the agent's job, standing on it is yours.

Disclosure rule (same as doctor's spine block): configured stations report yes, NEVER where —
a hijacked session must not learn the path to the operator's switch.

Presence, not validity (same shallow check as doctor's _socket): a garbled sink name or a
wrong dir reads "standing" here and fails LOUD at server startup or at the refusing gate —
nothing fails open, but this verb proves configuration exists, not that it works. The verify
line on each station is where working gets proven.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Station:
    name: str
    configured: bool
    why: str            # one line: what this station buys, honestly scoped
    recipe: str         # numbered operator-shell steps (printed only while empty)
    verify: str         # one command whose output proves the station stands


def _set(var: str) -> bool:
    return bool(os.environ.get(var, "").strip())


def posture() -> list[Station]:
    anchor = os.environ.get("PROXIMO_AUDIT_ANCHOR_SINK", "").strip().lower()
    return [
        Station(
            "CONSENT", _set("PROXIMO_CONSENT_DIR"),
            "every mutation needs a grant file only your hand can drop — the second party "
            "the platform never had",
            "1. The directory needs BOTH properties: the SERVER's uid can write it (consuming\n"
            "   a grant is a delete — a dir the server cannot write bricks every approval\n"
            "   fail-closed), and the AGENT's other channels cannot. In practice that is the\n"
            "   split deployment: run the server under its own uid and give only that uid\n"
            "   (plus your hand) write on the dir. Co-located same-uid setups make this\n"
            "   pillar cosmetic - config warns about exactly that when the var is set.\n"
            "2. Set PROXIMO_CONSENT_DIR to the directory (and optionally\n"
            "   PROXIMO_CONSENT_TTL_SECONDS) in the server's env, then restart the server.\n"
            "3. To approve one plan: drop the grant file its refusal names into the dir.",
            "proximo doctor  ->  spine.yours_to_erect.CONSENT.configured: true",
        ),
        Station(
            "CONTAIN", _set("PROXIMO_CONTAIN_TRIP_PATH"),
            "a kill-switch file: touching it halts every mutation mid-incident, no restart, "
            "and no tool can clear it",
            "1. On YOUR terminal, choose a path OUTSIDE the agent's write reach, e.g.:\n"
            "     /etc/proximo/contain.trip   (do NOT create the file — its ABSENCE is 'run')\n"
            "2. Set PROXIMO_CONTAIN_TRIP_PATH to that path in the server's env; restart.\n"
            "3. In an incident: touch the file. Every mutation refuses until YOU remove it.",
            "proximo doctor  ->  spine.yours_to_erect.CONTAIN.configured: true",
        ),
        Station(
            "PROVE-ANCHOR", anchor not in ("", "none"),
            "the ledger head pinned off-box — a truncated or rewritten chain is caught even "
            "if this whole box is compromised",
            "1. Pick a sink less compromisable than this box. Two families, honestly\n"
            "   different: FETCHABLE pins (=file + PROXIMO_AUDIT_ANCHOR_FILE_PATH on\n"
            "   root-retained ground, or =http + PROXIMO_AUDIT_ANCHOR_URL on another host)\n"
            "   seed the expected head at config load, and a CLEAN audit_verify re-pins it\n"
            "   (a moved head is never re-pinned over). WRITE-ONLY witnesses (=syslog +\n"
            "   PROXIMO_AUDIT_ANCHOR_SYSLOG_ADDRESS, or =journal) append every clean head\n"
            "   to your collector's trail but pin nothing back - detection there is your\n"
            "   collector's retention, not an automatic startup check.\n"
            "2. Set the sink vars in the server's env; restart.",
            "call the audit_verify TOOL from your client -> ok: true (fetchable sinks: "
            "against the anchored head; write-only sinks: the clean head lands on your "
            "collector's trail)",
        ),
        Station(
            "MIRROR", _set("PROXIMO_REACH_PRIVILEGE"),
            "shell reach into guests obeys the served token's own PVE permission map — the "
            "one channel the platform cannot scope, governed in the platform's own "
            "vocabulary. (Allowlist-only estates are a documented correct posture; this "
            "station staying empty there is honest, and --check does not gate on it.)",
            "1. Choose the reach privilege from evidence: `proximo reach-audit` prints what\n"
            "   each candidate aliases with on YOUR cluster and what it means in stock PVE.\n"
            "   A one-privilege custom role (`pveum role add`) keeps the aliasing table\n"
            "   empty and decouples AI reach from human grants.\n"
            "2. Grant it where you mean the reach to be, from YOUR shell:\n"
            "     pveum acl modify /vms/<id> --tokens <served-token> --roles <role>\n"
            "3. Set PROXIMO_REACH_PRIVILEGE to the privilege name in the server's env;\n"
            "   restart. Unset = dormant (allowlist-only reach, zero behavior change).\n"
            "4. Once the mirror alone is trusted, the allowlist may widen to '*' — the\n"
            "   token's own map is then the whole boundary.",
            "proximo doctor  ->  config.reach_grant.mirror.state: enforcing (and a guest "
            "the token holds no grant on refuses ct_logs with blocked:mirror)",
        ),
        Station(
            "ARM", _set("PROXIMO_ARM_SOURCE"),
            "writes served only while YOUR hand armed the box — disarmed, the server holds a "
            "read-only token and exec refuses. (Mint-and-revoke deployments — no standing "
            "write token at rest — are equally strong, differently shaped; this station "
            "correctly stays empty there and --check does not gate on it.)",
            "1. Mint both runbooks: `proximo mint` (read-only) and `proximo mint --write`.\n"
            "2. Keep the write token at an operator-run path; set PROXIMO_ARM_SOURCE to it\n"
            "   and PROXIMO_READONLY_SOURCE to the read-only token's path.\n"
            "3. Arm with `proximo arm` from YOUR shell before write work; `proximo disarm`\n"
            "   after. Optional lease: PROXIMO_ARM_TTL auto-expires a forgotten arm.",
            "proximo doctor  ->  the served token reports the read-only capability set "
            "while disarmed",
        ),
    ]


_FURTHER = (
    ("SCOPE", "PROXIMO_SCOPE_PATH", "arm-time target provenance gate"),
    ("LEASE", "PROXIMO_ARM_TTL", "an arm that expires instead of lingering"),
    ("TAINT", "PROXIMO_TAINT_FORBID", "adversarial-content tracking that forbids cross-domain "
     "actions after untrusted reads"),
    ("ENVELOPE", "PROXIMO_FORBID / PROXIMO_RATE_MAX", "per-surface forbid list + rate ceiling"),
)

# --check gates on the stations with no legitimate empty shape. ARM is reported but NOT
# gated: a mint-and-revoke deployment (no standing write token at rest) is a documented
# CORRECT posture whose ARM station stays empty forever — cron teeth must not bite it.
# MIRROR is reported but NOT gated for the same reason: an allowlist-only estate is a
# documented correct posture, and dormant-unset is the mirror's own contract.
_CHECK_GATED = ("CONSENT", "CONTAIN", "PROVE-ANCHOR")


def check_exit(stations: list[Station]) -> int:
    """--check: 0 when every gated station stands, else 1 (cron/CI teeth)."""
    return 0 if all(s.configured for s in stations if s.name in _CHECK_GATED) else 1


def render(stations: list[Station]) -> str:
    lines = ["proximo harden — the pillars only your hand can raise", ""]
    empty = [s for s in stations if not s.configured]
    for s in stations:
        if s.configured:
            lines.append(f"  [standing] {s.name} — {s.why}")
        else:
            lines.append(f"  [ EMPTY  ] {s.name} — {s.why}")
    lines.append("")
    if not empty:
        lines.append("All four stand. The strong posture is your posture.")
    else:
        lines.append("Erect the empty stations from YOUR shell — never the agent's. Their")
        lines.append("state must live outside the agent's write reach, or the pillar is a")
        lines.append("boundary within the agent's own trust domain (SECURITY.md, 'The")
        lines.append("two-deployment trust model').")
        for s in empty:
            lines.append("")
            lines.append(f"-- {s.name} " + "-" * max(1, 60 - len(s.name)))
            lines.append(s.recipe)
            lines.append(f"   verify: {s.verify}")
        lines.append("")
        lines.append("Further rails (opt-in, one env each): " +
                     "; ".join(f"{n} ({env}) — {why}" for n, env, why in _FURTHER))
    return "\n".join(lines) + "\n"
