"""The receipt — the inverse of telemetry, for Proximo.

`proximo doctor` already asks a live cluster real questions. What did not exist was a way for the
answer to travel. This turns a doctor report into one pasteable artifact, names where it can go, and
then STOPS. **Nothing here transmits.** `render` is a pure function; whether the text ever leaves the
operator's machine is their decision, made by hand, after reading it.

That is enforced structurally rather than promised: this module imports no network client and no
subprocess, and `render` takes no api/transport handle. There are tests pinning both. A comment
saying "we don't phone home" is worth nothing; an absent import is worth something.

WHY PROXIMO NEEDS THIS MORE THAN PACIOLI DOES. Proximo is pulled ~3,700 times a month and has
essentially never received a bug report. The people who use it are silent by disposition, and the
only public conversation about it is a forum thread that stopped being about the software. So every
signal available is a vanity counter. A refusal that fires on a stranger's cluster is invisible here,
and that is the actual gap — not features.

REDACTION IS THE PRECONDITION, AND IT IS HARDER HERE. A Proxmox doctor report is *made of* the things
an operator must not publish: node names, cluster name, IP addresses, storage identifiers, realms,
usernames and API token IDs. A receipt that carries them turns a helpful act into a disclosure of the
operator's whole topology. So redaction walks the entire structure — dict keys and values, lists,
nested — before anything is rendered, and the fingerprint is computed on the REDACTED text so that
the same defect on two different clusters produces the same fingerprint rather than leaking which
cluster it was.

WHAT IS DELIBERATELY KEPT. Versions, counts, booleans, privilege NAMES, and refusal reasons. Those
are the diagnosis. An artifact redacted into uselessness helps nobody and wastes the goodwill of the
person who sent it.
"""
from __future__ import annotations

import hashlib
import re

__all__ = ["redact", "redact_structure", "fingerprint", "render", "compile_denylist", "WHERE"]


def compile_denylist(tokens: list[str]) -> re.Pattern[str] | None:
    """Compile an operator-supplied list of BARE estate tokens (node/cluster names a regex can't
    tell from an English word) into a redaction pattern, or None if empty.

    Kept PURE (``re`` only, no ``os``/file/env) so this module keeps its structural 'no I/O, no side
    channel' guarantee (see the module docstring and test_receipt's import pin): the CALLER reads the
    file/env — it already has ``os`` — and passes the tokens here. A literal, operator-supplied list
    redacts only real estate names, so there is no over-redaction the way a generic bare-word rule
    would gut the receipt. Case-insensitive, word-bounded; longest-first so a token that is a prefix
    of another can't be half-matched."""
    cleaned = sorted({t.strip() for t in tokens if t.strip()}, key=len, reverse=True)
    if not cleaned:
        return None
    alts = "|".join(re.escape(t) for t in cleaned)
    return re.compile(rf"\b(?:{alts})\b", re.IGNORECASE)

# The destination is part of the artifact. An emitter with nowhere to send its output is a dead end
# with good formatting, not a loop — which is exactly what the first version of Pacioli's was.
WHERE = "https://github.com/john-broadway/proximo/issues/new?template=receipt.yml"

# Order matters: most specific first, so a token id is not half-eaten by the user rule and an email
# is not shredded into a hostname. Every rule leaves a MARKER — a silently deleted value reads as
# "there was nothing here", which is its own small untruth.
_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    # A PVE API token id: user@realm!tokenname — and the secret uuid if one ever appears.
    (re.compile(r"\b[\w.\-]+@(?:pam|pve|ad|ldap|openid|[\w\-]+)![\w.\-]+"), "[redacted-token-id]"),
    # A long hex/uuid run is a secret, a fingerprint or a key. Highest cost, lowest diagnostic value.
    (re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b"), "[redacted-uuid]"),
    (re.compile(r"\b[0-9a-fA-F]{24,}\b"), "[redacted-secret]"),
    # Certificate fingerprints: colon-separated hex pairs.
    (re.compile(r"\b(?:[0-9a-fA-F]{2}:){7,}[0-9a-fA-F]{2}\b"), "[redacted-fingerprint]"),
    (re.compile(r"\b[\w.+\-]+@(?:pam|pve|ad|ldap|openid)\b"), "[redacted-user]"),
    (re.compile(r"\b[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+"), "[redacted-user]"),
    # A filesystem path. Absolute paths name the operator's directory layout, and config paths
    # routinely embed a hostname or hardware model in the filename — a real receipt on 2026-07-28
    # carried a CA-bundle path doing exactly that. Before the address rules, because a path can
    # contain dots that look like a hostname.
    (re.compile(r"(?<![\w.])/(?:etc|root|home|var|opt|srv|mnt|usr|tmp)(?:/[\w.@%+\-]+)+"),
     "[redacted-path]"),
    # The WHOLE url, before the address rules — otherwise the address rule rewrites its host first
    # and this rule then matches only a fragment, producing mangled output.
    (re.compile(r"\bhttps?://[^\s,;)\]'\"]+"), "[redacted-url]"),
    # IPv6 before IPv4 so a mapped address is not half-matched.
    (re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b"), "[redacted-ip]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"), "[redacted-ip]"),
    (re.compile(r"\b(?:[\w\-]+\.)+(?:com|net|org|io|dev|lan|local|internal|example|home|arpa)\b"),
     "[redacted-host]"),
)

# Keys whose VALUE is a bare identifier naming the operator's estate. These carry no diagnostic
# weight on their own — "node is called pve01" tells a maintainer nothing — but together they map a
# stranger's infrastructure. Redacted by KEY, because the value is often a plain word no regex can
# distinguish from an ordinary noun.
_IDENTIFYING_KEYS = frozenset({
    "node", "nodes", "nodename", "cluster", "clustername", "cluster_name",
    "storage", "storages", "vmid", "vmids", "hostname", "host", "target", "targets",
    "user", "userid", "username", "tokenid", "token", "realm", "pool", "pools",
    "ip", "address", "endpoint", "url", "base_url", "fqdn", "mac", "bridge", "iface",
    "ca_bundle", "token_path", "path", "audit_log", "ledger", "config_path", "keyfile",
})


def redact(text: object, deny: re.Pattern[str] | None = None) -> str:
    """Strip an operator's estate out of one string, leaving a marker in its place.

    ``deny`` (from compile_denylist) additionally strips operator-listed bare estate names the
    regex rules can't see — a node named ``pve01`` matches no pattern."""
    out = str(text)
    for pattern, marker in _RULES:
        out = pattern.sub(marker, out)
    if deny is not None:
        out = deny.sub("[redacted-id]", out)
    return out


def redact_structure(obj: object, _key: str | None = None,
                     deny: re.Pattern[str] | None = None) -> object:
    """Walk a doctor report and redact it whole.

    Two passes at once, and both are needed: string VALUES go through the regex rules, and values
    under an identifying KEY are replaced outright regardless of shape. A node named `pve01` matches
    no pattern; a node named `mail` matches an English word. Only the key knows what it is. An
    optional ``deny`` (compile_denylist) catches a bare estate name embedded in a free-text value.
    """
    if isinstance(obj, dict):
        return {k: redact_structure(v, _key=str(k).lower(), deny=deny) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_structure(v, _key=_key, deny=deny) for v in obj]
    if isinstance(obj, bool) or obj is None:
        return obj
    if isinstance(obj, (int, float)):
        # Counts and versions are the diagnosis. A VMID is an identifier, not a count.
        return "[redacted-id]" if _key in _IDENTIFYING_KEYS else obj
    if _key in _IDENTIFYING_KEYS:
        return "[redacted-id]"
    return redact(obj, deny=deny)


def fingerprint(report: object, deny: re.Pattern[str] | None = None) -> str:
    """A short stable id, computed on the REDACTED structure.

    Same defect on two different clusters => same fingerprint. That is the whole point: two
    operators can discover they are hitting the same thing without either revealing whose cluster
    it was. A ``deny`` denylist makes it MORE stable — two clusters whose only difference was their
    node names now fingerprint identically once each redacts its own names.
    """
    import json
    payload = json.dumps(redact_structure(report, deny=deny), sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _lines(obj: object, indent: int = 0) -> list[str]:
    pad = "  " * indent
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                out.append(f"{pad}{k}:")
                out.extend(_lines(v, indent + 1))
            else:
                out.append(f"{pad}{k}: {v}")
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, (dict, list)):
                out.extend(_lines(v, indent + 1))
            else:
                out.append(f"{pad}- {v}")
    else:
        out.append(f"{pad}{obj}")
    return out


def render(report: object, *, version: str, generated_at: str,
           deny: re.Pattern[str] | None = None) -> str:
    """Render a doctor report into the pasteable artifact. Pure: no I/O, no clock, no api handle.

    `version` and `generated_at` are passed IN rather than read here, so the same report always
    renders identically and the caller owns every fact the receipt asserts. `deny` (compile_denylist)
    is likewise passed in — the caller reads the operator's node-name list, keeping this module I/O-free.
    """
    safe = redact_structure(report, deny=deny)
    fp = fingerprint(report, deny=deny)

    head = [
        "proximo receipt",
        f"  version      {version}",
        f"  generated    {generated_at}",
        f"  fingerprint  {fp}",
        "",
        "Node and cluster names, addresses, storage and pool identifiers, users, realms and API",
        "token ids were removed before this text was written. Nothing was transmitted: the operator",
        "ran a local, read-only check and chose to share the result. The fingerprint is computed on",
        "the redacted text, so an identical defect on a different cluster produces an identical",
        "fingerprint.",
        "",
    ]
    foot = [
        "",
        "-" * 78,
        "Where this can go, if you want it to:",
        f"  {WHERE}",
        "Paste it whole. Read it first — it is your cluster and your call, and we would rather you",
        "checked than took our word for the redaction.",
    ]
    return "\n".join(head + _lines(safe) + foot).rstrip() + "\n"
