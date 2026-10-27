"""RECEIPT: a doctor report becomes ONE pasteable, estate-free artifact, and nothing is sent.

`proximo-core doctor --receipt` (parity: 0.44's `proximo doctor --receipt`; capability
`shareable-doctor-receipt`). The doctor asks a live estate real questions; what did not exist was a
way for the answer to travel. This turns that report into one text with a fingerprint, names where
it can go, and STOPS. **Nothing here transmits**: `render` is a pure function of the report in
hand, it takes no handle to any plane, and whether the text ever leaves the operator's machine is
their decision, made by hand, after reading it. The module imports only `hashlib`, `json`, `re`
and `typing`; `tests/test_core_receipt.py` reads its import statements.

BUILT BY ALLOWLIST, NOT BY REDACTION. The first receipt scrubbed the report with patterns, and an
independent lens walked estate names straight through it: a registry target's name inside a TOML
error, the CONTAIN trip file's prose, the operator's log name inside a sealed-archive name. Patterns
cannot find a name that has no shape, and a PUBLIC artifact cannot lean on them. So the receipt is
built the other way round. `SCHEMA` states, per key the doctor writes, the one kind of value that
may appear: a boolean, a count, a strict version, a word from a fixed vocabulary, an environment
variable's name. Anything the schema does not name is dropped; every free-text string (an error, a
reason, a file name, a flag sentence) becomes `[text]`. A flag is rendered by its CODE only (the
fixed head of its sentence picks the code; whatever the doctor interpolated into it is never
read). A string no field of the schema allows cannot arrive, whatever it looks like.

The pattern scrub (`redact`) stays as the SECOND line, over every string the schema let through
and over the header, and `--deny NAME` (`compile_denylist`) as a third: a name boundary treats
`-`, `.` and `_` as separators, so denying `acme` also removes `acme-prod`.

The fingerprint hashes only the defect's SHAPE: the set of flag codes and each pillar's standing.
The same defect on two estates has one fingerprint; counts, versions and names do not move it.

KEPT, because it is the diagnosis: versions, counts, booleans, pillar states, plane reach status,
flag codes, the names of environment variables the doctor says are missing.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

#: The destination is part of the artifact. An emitter with nowhere to send its output is a dead
#: end with good formatting. The template ships in `.github/ISSUE_TEMPLATE/` (a test holds it).
WHERE = "https://github.com/john-broadway/proximo/issues/new?template=receipt.yml"

TEXT = "[text]"
INVALID = "[invalid]"
_MARK = "[redacted-id]"

# ---- the allowlist -------------------------------------------------------------------------------
# A validator takes the report's value and returns what may be shown. It never returns the input
# for a string unless the string is in a vocabulary or matches a strict shape.

PRODUCTS = frozenset({"pve", "pbs", "pmg", "pdm"})
PILLARS = frozenset({"PLAN", "CONSENT", "PROVE", "UNDO", "DIAGNOSE", "CONTAIN"})
LANES = frozenset({"agent", "shell", "node", "download"})            # spine._LANES, held to it by a test
_MODES = frozenset({"keyed", "unkeyed", "mixed", "empty", "unreadable"})
_ERRORS = frozenset({"refused", "cut", "not a record", "HTTPStatusError", "ConnectError", "ConnectTimeout",
                     "ReadTimeout", "WriteTimeout", "PoolTimeout", "TimeoutException", "ReadError",
                     "RemoteProtocolError", "TransportError", "TooManyRedirects", "DecodeError",
                     "RuntimeError", "ProximoError", "OSError", "PermissionError", "FileNotFoundError",
                     "ValueError", "KeyError", "JSONDecodeError", "UnicodeDecodeError", "SSLError"})
_TLS = frozenset({"pin mismatch", "certificate not verified"})
_SHAPES = frozenset({"dict", "list", "str", "int", "float", "bool", "NoneType"})
#: The vendors' real shapes: major.minor, major.minor.patch, either with a -N release; a 1-2 digit
#: major, so an address prefix (192.168.1, 172.16.1) is not a version. `10.` is also refused: it is
#: the private range's first octet and a Proxmox major 10 reads as text until the vendor ships one.
_VERSION = re.compile(r"(?!10\.)\d{1,2}\.\d{1,2}(?:\.\d{1,2}(?:-\d{1,3})?|-\d{1,3})?")
_CLOCK = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")      # the door's own clock, not report data
_ENVNAME = re.compile(r"PROXIMO_[A-Z0-9_]{1,60}")
_ENVPAIR = re.compile(rf"{_ENVNAME.pattern}(?: \(or {_ENVNAME.pattern}\))?")


def _bool(v: object) -> object:
    return v if isinstance(v, bool) or v is None else INVALID


def _int(v: object) -> object:
    return v if v is None or (isinstance(v, (int, float)) and not isinstance(v, bool)) else INVALID


def _word(vocab: frozenset[str]) -> Any:
    return lambda v: v if isinstance(v, str) and v in vocab else TEXT


def _text(v: object) -> object:
    return None if v in (None, "", [], {}) else TEXT


def _present(v: object) -> object:
    return "present" if v else None


def _count(v: object) -> object:
    return len(v) if isinstance(v, (list, tuple)) else INVALID


def _version_or_error(v: object) -> object:
    if isinstance(v, str):
        return v if _VERSION.fullmatch(v) else TEXT
    return _apply(_ERROR, v)


def _env_names(v: object) -> object:
    if not isinstance(v, list):
        return INVALID
    return [n if isinstance(n, str) and _ENVPAIR.fullmatch(n) else TEXT for n in v]


def _chain(v: object) -> object:
    if v == "ok":
        return "ok"
    if isinstance(v, str):
        for head in ("broken", "unjudgeable"):
            if v.startswith(head):
                return head
    return TEXT


def _allowlist_size(v: object) -> object:
    return v if v == "*" or (isinstance(v, int) and not isinstance(v, bool)) or v is None else TEXT


_ERROR: dict[str, Any] = {"error": _word(_ERRORS), "status": _int, "tls": _word(_TLS), "verify_code": _int,
                          "bytes": _int, "cap": _int, "shape": _word(_SHAPES), "reason": _text}

# A dict is an object (listed keys only); ("map", vocab, sub) is a table keyed by a vocabulary.
SCHEMA: dict[str, Any] = {
    "doctor": _word(frozenset({"proximo-core"})),
    "record": {"refused": _text, "rows": _int, "mutations": _int, "tiered": _int, "held": _int, "creates": _int,
               "untrusted": _int},
    "planes": ("map", PRODUCTS, {
        "configured": _bool, "missing": _env_names, "error": _text, "verify_tls": _bool,
        "fingerprint_pinned": _bool, "tls_strict": _bool,
        "arm": {"enforced": _bool, "armed": _bool, "reason": _text},
        "reach": {"version": _version_or_error,
                  "permissions": {"paths": _int, "skipped": _text, **_ERROR}}}),
    "targets": {"configured": _bool, "count": _int, "error": _text},
    "ledger": {"keyed": _bool, "mode": _word(_MODES), "key_readable": _bool, "rows": _int, "chain": _chain,
               "in_flight": _int, "sealed_archive": _present},
    "pillars": ("map", PILLARS, {
        "standing": _bool, "ttl_seconds": _int, "advisory": _bool, "creates_judged": _int,
        "lanes": ("map", LANES, {"open": _bool, "allowlist": _allowlist_size}),
        "ssh_target_configured": _bool,
        "trip": {"configured": _bool, "tripped": _bool, "reason": _text},
        "rate": {"max": _int, "window": _int}, "forbid": _int,
        "taint": {"track": _bool, "forbid": _bool, "require_consent": _bool, "fence": _bool}}),
    "retired": _count,
    "flags": None,                       # rendered by code, below
    "complete": _bool,
}

#: The fixed head of each flag sentence the doctor writes (core/doctor.py), in order, and the code it
#: gets. Only the head is matched; what follows was interpolated by the doctor and is never read.
_P = r"(pve|pbs|pmg|pdm)"
_FLAGS: tuple[tuple[re.Pattern[str], str], ...] = tuple((re.compile(p), c) for p, c in (
    (r"the record is refused", "record-refused"),
    (rf"{_P}: tls_strict=false", "tls-relaxed:{1}"),
    (rf"{_P}: no reach: GET /version failed", "no-reach:{1}"),
    (rf"{_P}: the credential reaches the box but GET /access/permissions", "permissions-unread:{1}"),
    (r"the target registry is set and unreadable", "registry-unreadable"),
    (r"the ledger cannot be read", "ledger-unreadable"),
    (r"the audit key cannot be read", "audit-key-unreadable"),
    (r"a sealed rotation archive sits beside the ledger", "sealed-archive"),
    (r"the ledger is configured keyed and no key is readable", "audit-key-missing"),
    (r"the ledger's chain is", "chain-broken"),
    (r"\d+ mutation\(s\) in flight", "mutations-in-flight"),
    (r"CONSENT is advisory", "consent-advisory"),
    (r"CONSENT is inert", "consent-inert"),
    (r"UNDO is off", "undo-off"),
    (r"the (agent|shell|node) lane's allowlist is garbled", "lane-allowlist-garbled:{1}"),
    (r"CONTAIN has no trip path", "contain-no-trip-path"),
    (r"CONTAIN is tripped", "contain-tripped"),
    (r"CONTAIN: no rate cap", "contain-no-rate-cap"),
    (r"a retired switch is set", "retired-switch-set"),
    (r"PROXIMO_SURFACES is set", "surfaces-set"),
    (r"no plane is configured", "no-plane-configured"),
))


def flag_code(sentence: object) -> str:
    """One flag sentence to its code, or `unrecognised`. Never returns any of the sentence's tail."""
    if isinstance(sentence, str):
        for pattern, code in _FLAGS:
            if m := pattern.match(sentence):
                return code.replace("{1}", m.group(1)) if m.groups() else code
    return "unrecognised"


def _apply(schema: Any, value: Any) -> Any:
    if callable(schema):
        return schema(value)
    if isinstance(schema, tuple):                       # ("map", vocab, sub)
        _, vocab, sub = schema
        if not isinstance(value, dict):
            return INVALID
        return {k: _apply(sub, v) for k, v in value.items() if isinstance(k, str) and k in vocab}
    if not isinstance(value, dict):
        return INVALID
    return {k: _apply(s, value[k]) for k, s in schema.items() if k in value and s is not None}


def allowed(report: object) -> dict[str, Any]:
    """The doctor's report cut down to what the schema lets through, with flags as codes."""
    safe = _apply(SCHEMA, report) if isinstance(report, dict) else {}
    flags = report.get("flags") if isinstance(report, dict) else None
    if isinstance(flags, list):
        safe["flags"] = [flag_code(f) for f in flags]
    return safe


# ---- the second line: patterns over whatever got through -----------------------------------------

_TOKEN_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"[\w.\-]+@[\w\-]+![\w.\-]+"), "[redacted-token-id]"),
    (re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b"), "[redacted-uuid]"),
    (re.compile(r"\b(?:[0-9a-fA-F]{2}:){7,}[0-9a-fA-F]{2}\b"), "[redacted-fingerprint]"),
    (re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)*"), "[redacted-user]"),
    (re.compile(r"https?://\S*"), "[redacted-url]"),
    (re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b"), "[redacted-ip]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"), "[redacted-ip]"),
)
_MAX_TOKEN = 200                                    # a longer run is a blob, and the rules stay linear on it
_PATHY = re.compile(r"[\\/]")
_WORDY = re.compile(r"[A-Za-z0-9_.\-]+")
_SECRET = re.compile(r"[A-Za-z0-9+/_\-]{32,}={0,2}")


def _host_like(tok: str) -> bool:
    """A dotted name whose last label is alphabetic, 2 to 63 chars: any TLD, no list to age."""
    labels = tok.rstrip(".").split(".")
    return len(labels) >= 2 and all(labels) and labels[-1].isalpha() and 2 <= len(labels[-1]) <= 63


def _scrub_token(tok: str) -> str:
    if len(tok) > _MAX_TOKEN:
        return "[redacted-secret]"
    if tok.startswith("[redacted-") or tok == TEXT or tok == INVALID:
        return tok
    for pattern, marker in _TOKEN_RULES:
        tok = pattern.sub(marker, tok)
    # a path, in any spelling: a slash or a backslash anywhere joins a non-separator character
    tok = re.sub(r"[^\s,;()'\"<>=\[\]]*[\\/][^\s,;()'\"<>=\[\]]*",
                 lambda m: "[redacted-path]" if re.search(r"[^\\/]", m.group(0)) else m.group(0), tok)
    tok = _SECRET.sub(lambda m: m.group(0) if _ENVNAME.fullmatch(m.group(0)) else "[redacted-secret]", tok)
    return _WORDY.sub(lambda m: "[redacted-host]" if _host_like(m.group(0)) else m.group(0), tok)


def compile_denylist(tokens: list[str]) -> re.Pattern[str] | None:
    """The operator's own bare names (a guest called `web1`) as one pattern, or None.

    Case insensitive; `-`, `.` and `_` are separators, so `acme` also removes `acme-prod`, while
    `acme` inside `acmetool` stays (a letter or digit on either side is the same word)."""
    cleaned = sorted({t.strip() for t in tokens if t and t.strip()}, key=len, reverse=True)
    if not cleaned:
        return None
    return re.compile(rf"(?<![A-Za-z0-9])(?:{'|'.join(re.escape(t) for t in cleaned)})(?![A-Za-z0-9])", re.IGNORECASE)


def redact(text: object, deny: re.Pattern[str] | None = None) -> str:
    """Strip an estate out of one string, leaving a marker in its place. Linear in the input."""
    out = re.sub(r"\S+", lambda m: _scrub_token(m.group(0)), str(text))
    return deny.sub(_MARK, out) if deny is not None else out


def _second_line(obj: Any, deny: re.Pattern[str] | None) -> Any:
    if isinstance(obj, dict):
        return {redact(k, deny): _second_line(v, deny) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_second_line(v, deny) for v in obj]
    return redact(obj, deny) if isinstance(obj, str) else obj


def redact_structure(report: object, deny: re.Pattern[str] | None = None) -> dict[str, Any]:
    """The report as the receipt shows it: allowlisted, then scrubbed."""
    return _second_line(allowed(report), deny)


def shape(report: object) -> dict[str, Any]:
    """What the fingerprint hashes: the defect's shape. Not a count, a version or a name."""
    safe = allowed(report)
    got = safe.get("pillars")
    pillars: dict[str, Any] = got if isinstance(got, dict) else {}
    return {"flags": sorted(set(safe.get("flags") or [])),
            "pillars": {k: v.get("standing") for k, v in sorted(pillars.items()) if isinstance(v, dict)}}


def fingerprint(report: object, deny: re.Pattern[str] | None = None) -> str:  # noqa: ARG001 -- kept for callers
    """A short stable id of the defect's shape: same defect on two estates, same fingerprint."""
    return hashlib.sha256(json.dumps(shape(report), sort_keys=True).encode("utf-8")).hexdigest()[:12]


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
        out.extend(f"{pad}- {v}" for v in obj)
    else:
        out.append(f"{pad}{obj}")
    return out


def render(report: object, *, version: str, generated_at: str, deny: re.Pattern[str] | None = None) -> str:
    """The pasteable artifact. Pure: no I/O, no clock, no handle to any plane. `version` and
    `generated_at` come IN, so the same report renders identically."""
    head = [
        "proximo receipt",
        f"  version      {version if _VERSION.fullmatch(version) else redact(version, deny)}",
        f"  generated    {generated_at if _CLOCK.fullmatch(generated_at) else redact(generated_at, deny)}",
        f"  fingerprint  {fingerprint(report)}",
        "",
        "This text is built from an allowlist: only booleans, counts, versions, fixed words and flag",
        "codes appear. Every name, address, path, user, token id and every free-text message from the",
        "check was left out, shown as [text] where one existed. Nothing was transmitted: the operator",
        "ran a local check and chose to share the result. The fingerprint hashes the defect's shape",
        "alone (flag codes and pillar states), so one defect on two estates has one fingerprint.",
        "",
    ]
    foot = [
        "",
        "-" * 78,
        "Where this can go, if you want it to:",
        f"  {WHERE}",
        "Paste it whole. Read it first: it is your estate and your call, and we would rather you",
        "checked than took our word for it.",
    ]
    return "\n".join(head + _lines(redact_structure(report, deny)) + foot).rstrip() + "\n"
