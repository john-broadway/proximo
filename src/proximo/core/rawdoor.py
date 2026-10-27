"""The raw GET door — every published read on every plane, reachable by path.

The 2026-08-12 ruling: the estate layer computes with provenance, and the raw API stays
reachable underneath it. The curated tools are the thin hops; this is the floor under them.
Three laws keep it a door and not a hole:

  1. A path must name a read the vendor publishes. It is matched against the vendored tree
     (`proximo.apitree`) with GET as the only method BEFORE the wire is touched; a write-only
     path, a console or migration tunnel, or a path nobody publishes is refused with the
     nearest published reads named.
  2. It never launders a gate. Where a curated tool already stands guard over a read (the
     qemu-agent family behind PROXIMO_ENABLE_AGENT and its allowlist; the byte streams that
     the file-restore tools land on disk under a cap), the door refuses and names the tool.
     Where a curated read stripped a credential (a remote's password, an ACME plugin's DNS
     keys), `records/secrets.toml` withholds the same field here and the envelope says so.
  3. It never invents. The result is the vendor's `data` in a labelled envelope
     (`derived: false`, the published path it matched); a body over the byte cap is reported
     as truncated with its size, never handed back as a silent prefix.

Pure: no backend, no ledger. `proximo.tools.raw_door` supplies both.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import math
import os
import re
import unicodedata
from typing import Any, NamedTuple
from urllib.parse import unquote, urlencode

from proximo.core import apitree
from proximo.core.errors import ProximoError

# THE ANSWER CAP, in the unit the window is spent in. A 4K window holds the six tools (942 tokens as the
# wire sends them), a find (up to ~450), a plan (up to ~850 with its arguments whole) and the model's
# own thousand; what is left for ONE read is DEFAULT_MAX_TOKENS of the conservative estimate below, which
# is at most that many real Qwen3 tokens on every pinned sample (dense ones included) and about 60
# percent of that on ordinary rows. THE BYTE CAP BINDS ON ORDINARY ROWS: 1.125 KiB is the cut for lean rows
# (their estimate would let 1.2 KiB through), so the token cap is what binds on dense text (a byte is a
# token there) and the byte cap on plain text, and an unsampled text that tokenizes at one token a byte
# cannot cost more than 1,152 tokens. An operator's PROXIMO_RAW_MAX_BYTES stands alone. It was 6 KiB,
# said to be 1.5K tokens; measured, 6 KiB was 2,400 tokens of lean rows and 3,300 of raw rows, and 5,400
# of CIDRs.
DEFAULT_MAX_BYTES = 1152
DEFAULT_MAX_TOKENS = 750

#: THE TOKEN ESTIMATE: a weight per byte by class, summed and rounded up with 5 percent over. Measured
#: 2026-10-25 with llama.cpp's `llama-tokenize` on the Qwen3-1.7B vocabulary, compact JSON, seventeen
#: fixed samples (tests/test_door_fixes.py pins every one with its count): that tokenizer takes each
#: digit as a token, a '.' or ',' after a digit as a token (a list of numbers is a token a byte), a
#: capital letter as nearly one, and merges lowercase words and JSON punctuation. Weights were fitted so
#: that the estimate, margin included, is AT OR ABOVE the tokenizer's count on all seventeen: the dense
#: ones (base64, hashes, task ids, CIDRs, URL-encoded text, one-letter keys, fingerprints, ANSI logs,
#: arrays of numbers) as well as rows, and as low as that allows. It reads 1.0 to 1.2 times over on the
#: dense samples and 1.3 to 2.3 times over on ordinary rows, schema and prose. It is NOT a bound for
#: text nobody sampled: a different vocabulary, or text built to split into single bytes, moves it.
#: Non-ASCII bytes are counted whole, which is over for CJK and Cyrillic (they merge) and means an
#: estate named in CJK gets about a third of the budget the same answer in ASCII gets.
TOKEN_WEIGHTS = {"digit": 1.0, "upper": 1.5, "lower": 0.55, "number_punct": 0.9, "other": 0.55}
TOKEN_MARGIN = 1.05
_DIGITS, _UPPER, _LOWER = b"0123456789", bytes(range(65, 91)), bytes(range(97, 123))
_NUMBER_PUNCT = re.compile(rb"(?<=[0-9])[.,]")


def estimate_tokens(text: str) -> int:
    """What `text` costs a small model's window (see TOKEN_WEIGHTS). Stdlib only: the shell door
    imports this module."""
    raw = text.encode()
    d = len(raw) - len(raw.translate(None, _DIGITS))
    u = len(raw) - len(raw.translate(None, _UPPER))
    lo = len(raw) - len(raw.translate(None, _LOWER))
    p = len(_NUMBER_PUNCT.findall(raw))
    w = TOKEN_WEIGHTS
    return math.ceil(TOKEN_MARGIN * (w["digit"] * d + w["upper"] * u + w["lower"] * lo
                                     + w["number_punct"] * p + w["other"] * (len(raw) - d - u - lo - p)))


_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_BAD_SEGMENT = re.compile(r"[\s?#]|[\x00-\x1f\x7f]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# The guest-agent subtree: ONE definition, referenced by _GATED here and by the opt-in gate in
# `proximo.core.spine` (spine imports this constant, so the prefix is not retyped). Unlike the
# download/quarantine gates below, this is an OPT-IN gate: the engine serves these addresses when
# PROXIMO_ENABLE_AGENT is set and the VMID is on PROXIMO_AGENT_ALLOWLIST (spine.agent_refusal);
# the gate string is the raw door's pointer and the table's "this row is governed by the opt-in".
AGENT_PREFIX = "/nodes/{node}/qemu/{vmid}/agent"

# Published prefixes a curated tool gates; the door points at the tool instead of opening them.
# Keyed by plane; the value is the tool family and the gate it enforces.
_GATED: dict[str, tuple[tuple[str, str], ...]] = {
    "pve": (
        (
            # The raw GET door still points here; the engine serves this subtree through the
            # opt-in (spine.agent_refusal), so the operator sees the opt-in sentence, not this.
            # The string is unchanged from the committed vendor stage, which stays byte-built.
            AGENT_PREFIX,
            "pve_agent_* (PROXIMO_ENABLE_AGENT and PROXIMO_AGENT_ALLOWLIST gate every guest-agent read)",
        ),
        (
            "/nodes/{node}/storage/{storage}/file-restore/download",
            "pve_file_restore_download (bytes land on disk under a cap, never in a response)",
        ),
    ),
    "pbs": (
        ("/admin/datastore/{store}/pxar-file-download", "pbs_file_download (bytes land on disk under a cap)"),
        (
            "/admin/datastore/{store}/download",
            "a byte stream no curated tool serves yet; pbs_file_download lands pxar-file-download on disk",
        ),
        (
            "/admin/datastore/{store}/download-decoded",
            "a byte stream no curated tool serves yet; pbs_file_download lands pxar-file-download on disk",
        ),
    ),
    "pmg": (("/quarantine/download", "pmg_quarantine_* (a mail body is a stream, not a JSON read)"),),
    "pdm": (),
}
#: THE DOWNLOAD LANE: the gated paths that answer bytes, not JSON. The raw GET door still refuses
#: them (it answers JSON); the engine serves them through `proximo.core.download` once the
#: operator opens the lane (PROXIMO_ENABLE_DOWNLOAD), landing the bytes on disk under a cap.
STREAMS: frozenset[tuple[str, str]] = frozenset(
    (product, path) for product, entries in _GATED.items() for path, _tool in entries if path != AGENT_PREFIX)


def is_stream(product: str, path: str) -> bool:
    return (product, path) in STREAMS


MAX_PARAM_CHARS = 4096


def _gated(published: str, prefix: str) -> bool:
    """`prefix` names a published path or a subtree of it: equal, or a child by whole segment."""
    return published == prefix or published.startswith(prefix + "/")


def reject_malformed(path: str, *, allow_placeholders: bool = False) -> None:
    """Refuse a path whose spelling could make the governed string differ from the sent one.

    EXTRACTED so there is exactly ONE copy. `proximo.core.engine` governs a normalized path and
    sends an unnormalized one; without this check an adversarial lens showed `//nodes/backup` on
    pbs governed as `GET /nodes/{node}` while httpx collapses it to `/backup` -- an EXCLUDED
    protocol tunnel. Anything that a URL library may re-interpret (`//`, `..`, `?`, `#`,
    whitespace, control characters) must die here, at the spelling, before the address is
    matched and long before a credential is read.

    `allow_placeholders` lets a governance LOOKUP accept the published template spelling
    (`/nodes/{node}/status`), which a plan may legitimately ask about. It never permits one at
    the wire: `execute` refuses a path that still carries placeholders.

    A value that carries a slash (a CIDR, a volume id) rides its segment as `%2F`, so the gate
    judges the DECODED spelling too, for what breaks the door's invariants: a control character
    (a lens sent `192.0.2.0%0A%2F24`, whose `%0A` decoded into the newline that separates the
    forbid haystack's fields and split the operator's entry in two; THIS check is what kills it),
    an empty or `..` segment, and any `%` that survives one decode (`%252F`, `%zz`: what the
    vendor would make of a second decode is not ours to guess). Not a space, `#` or `?` inside a
    value: the wire gets the encoded bytes, a file name may carry them, and a lens found the
    wider rule refusing `Windows 11 Pro.iso`.
    """
    decoded = unquote(path)
    bad = (
        not path.startswith("/")
        or "//" in path
        or "//" in decoded
        or _BAD_SEGMENT.search(path)
        or _CONTROL.search(decoded)
        or ".." in decoded.split("/")
        or "%" in decoded
        or (not allow_placeholders and ("{" in path or "}" in path))
    )
    if bad:
        raise ProximoError(
            f"malformed path {quote(path)}: an absolute API path"
            + ("" if allow_placeholders else " with real values in it (no `{placeholders}`)")
            + ", no query string, no empty or '..' segments and no whitespace; inside a value "
              "a '/' is %2F, a control character is refused however it is spelled, and a '%' "
              "must not survive one decode (query parameters go in `args`)"
        )


def validate(plane: str, path: str) -> str:
    """The published form of `path` if it is a GET the plane publishes and no curated tool
    gates; a ProximoError that says why otherwise. Runs before any backend is built."""
    if plane not in apitree.PRODUCTS:
        raise ProximoError(f"unknown plane {plane!r}: one of {', '.join(apitree.PRODUCTS)}")
    reject_malformed(path)
    published = apitree.find(plane, path, "GET")
    if published is None:
        near = apitree.nearest(plane, path, "GET")
        hint = f" Published GET paths nearby: {', '.join(near)}." if near else ""
        raise ProximoError(f"{plane} publishes no GET at {quote(path)} "
                           f"(a write-only path, a tunnel, or nothing).{hint}")
    for prefix, tool in _GATED[plane]:
        if _gated(published, prefix):
            raise ProximoError(f"{path!r} is gated by a curated tool; use {tool}. The raw door does not open a gate.")
    return published


def check_params(params: dict | None) -> dict:
    """Flat string/number/bool query parameters, bools in the 1/0 form Proxmox accepts."""
    out: dict = {}
    for key, value in (params or {}).items():
        if not isinstance(key, str) or not _KEY.match(key):
            raise ProximoError(f"args: key {key!r} is not a plain query name")
        if isinstance(value, bool):
            out[key] = 1 if value else 0
        elif isinstance(value, str) and len(value) > MAX_PARAM_CHARS:
            raise ProximoError(f"args: {key!r} is longer than {MAX_PARAM_CHARS} characters")
        elif isinstance(value, (str, int, float)):
            out[key] = value
        else:
            raise ProximoError(f"args: {key!r} must be a string, number or bool, not {type(value).__name__}")
    return out


def canonical(path: str) -> str:
    """One spelling per resource for the ledger target: no trailing slash."""
    return path.rstrip("/") or "/"


def with_query(path: str, params: dict) -> str:
    """For a backend whose `_get` takes no params argument: the query rides the path."""
    return f"{path}?{urlencode(params)}" if params else path


def _env_number(name: str) -> tuple[int | None, str | None]:
    """(the value, None) for a positive whole number; (None, the problem) for junk; (None, None)
    for unset. Junk FAILS CLOSED: the caller keeps the default cap and the problem is named
    (`cap_problems`, doctor, the note on a cut answer), never read as 'the operator chose a cap'."""
    raw = os.environ.get(name, "")
    if not raw.strip():
        return None, None
    try:
        value = int(raw.strip())
    except ValueError:
        value = 0
    if value < 1:
        return None, f"{name}={raw[:20]!r} is not a positive whole number; the default cap stands"
    return value, None


def cap_problems() -> list[str]:
    """Each cap variable that is set to junk, in words; empty when every one is unset or sane."""
    return [p for p in (_env_number("PROXIMO_RAW_MAX_BYTES")[1], _env_number("PROXIMO_RAW_MAX_TOKENS")[1]) if p]


def max_bytes() -> int:
    value, _ = _env_number("PROXIMO_RAW_MAX_BYTES")
    return DEFAULT_MAX_BYTES if value is None else value


class Cap(NamedTuple):
    """What one answer may weigh: compact bytes, and estimated tokens (None = no token cap)."""
    bytes: int
    tokens: int | None

    def minus(self, nbytes: int, ntokens: int, floor: int = 256) -> Cap:
        """What is left after `nbytes`/`ntokens` are spent elsewhere in the same answer, never less
        than a sliver (a header larger than the cap is the header's problem, not a reason to send nothing)."""
        return Cap(max(self.bytes - nbytes, min(floor, self.bytes)),
                   None if self.tokens is None else max(self.tokens - ntokens, min(floor * 100 // 256, self.tokens)))


def answer_cap() -> Cap:
    """The cap on what a MODEL is handed, from the environment or the defaults."""
    return Cap(max_bytes(), max_tokens())


#: What the door's own evaluation may read: diagnose runs a battery of governed reads and keeps only
#: its verdicts, so the model never sees those bytes and the 4K window is not what bounds them. The
#: old 6 KiB default stands (an operator's PROXIMO_RAW_MAX_BYTES still wins), with no token cap.
EVALUATION_MAX_BYTES = 6 * 1024


def evaluation_cap() -> Cap:
    value, _ = _env_number("PROXIMO_RAW_MAX_BYTES")
    return Cap(EVALUATION_MAX_BYTES if value is None else value, None)


#: A PLAN carries the authored verdict whole (the tier's sentence, the reason, the notes a condition
#: raises: 300 to 600 bytes each), so it gets 1.75 KiB of bytes and more tokens than a read; what is left
#: beside those goes to the echoed arguments and the diff, as many entries as fit.
PLAN_MAX_BYTES = 1792
PLAN_MAX_TOKENS = 1250


def plan_cap() -> Cap:
    """1.75 KiB and 1,250 estimated tokens (measured: the worst realistic plans are 1.6 to 1.8 KB and 520 to
    700 real tokens, because the estimate reads authored English about 2 times over)."""
    value, _ = _env_number("PROXIMO_RAW_MAX_BYTES")
    tokens, _ = _env_number("PROXIMO_RAW_MAX_TOKENS")
    return Cap(PLAN_MAX_BYTES if value is None else value,
               tokens if tokens is not None else None if value is not None else PLAN_MAX_TOKENS)


#: A COMPOSED answer (a diagnosis: several reads, each reduced to its verdict) is the whole answer to
#: the question, so it gets twice the bytes; the token cap is the same, and an operator's number wins.
COMPOSED_MAX_BYTES = 4 * 1024
COMPOSED_MAX_TOKENS = 2000


def composed_cap() -> Cap:
    """Twice the bytes and a third more tokens than a read: a diagnosis is the whole answer, with no
    find, plan or read beside it in the window (the six tools, 903 tokens, and 2,000 leave 1,097)."""
    value, _ = _env_number("PROXIMO_RAW_MAX_BYTES")
    tokens, _ = _env_number("PROXIMO_RAW_MAX_TOKENS")
    return Cap(COMPOSED_MAX_BYTES if value is None else value,
               tokens if tokens is not None else None if value is not None else COMPOSED_MAX_TOKENS)


def max_tokens() -> int | None:
    """The token cap. None only when the operator chose a VALID byte cap (PROXIMO_RAW_MAX_BYTES, no
    PROXIMO_RAW_MAX_TOKENS): their number then stands alone. Junk in either variable never stands
    the token cap down."""
    value, _ = _env_number("PROXIMO_RAW_MAX_TOKENS")
    if value is not None:
        return value
    if _env_number("PROXIMO_RAW_MAX_BYTES")[0] is not None:
        return None
    return DEFAULT_MAX_TOKENS


def _compact(data: object) -> str:
    """The door's own serialization: compact JSON, as every door sends it."""
    return json.dumps(data, default=str, separators=(",", ":"))


def _size(data: object) -> int:
    return len(_compact(data).encode())


def fits(nbytes: int, text_for_tokens: str | None = None, *, tokens: int | None = None,
         cap: Cap | None = None) -> bool:
    """Whether an answer of `nbytes` compact bytes (and, when a token cap is on, `tokens`
    estimated tokens, or the estimate of `text_for_tokens`) is under every cap that applies."""
    cap = cap or answer_cap()
    if nbytes > cap.bytes:
        return False
    if cap.tokens is None:
        return True
    if tokens is None:
        tokens = estimate_tokens(text_for_tokens or "")
    return tokens <= cap.tokens


def describe(value: object) -> str | object:
    """What a model needs to know about a value it cannot have whole: a small scalar as itself, the
    rest by kind and size ("list of 400", "text, 5000 chars", "object, 12 keys"). Never a prefix."""
    if isinstance(value, list):
        return f"list of {len(value)}"
    if isinstance(value, dict):
        return f"object, {len(value)} keys"
    if isinstance(value, str) and len(value) > 40:
        return f"text, {len(value)} chars"
    return value


# ---- THE ONE RULE FOR ANYTHING ECHOED BACK ----------------------------------------------------------
# Input the model sent (a path, a method, an id, the arguments of a call) and live state the door read
# back (a guest's config, a `from` value) come back to the model in refusals, headers, plans and diffs.
# Every one of those goes through `echo`: the first characters, then the length and the first 12 hex of
# the SHA-256 of the whole, in the value itself: "abc... (500 chars, sha256:0123456789ab)". The model
# that sent the value can match it; nothing copies a clipped value back believing it whole; the full
# value still binds the consent id and reaches the vendor unchanged (only the DISPLAY is clipped).
# Input that is absurd is refused up front by `check_input`, never echoed.

ECHO_LIMIT = 80
MAX_INPUT = {"path": 512, "method": 16, "id": 128, "name": 128, "words": 512}


#: characters shown as escapes in anything echoed: by Unicode CATEGORY, not a hand list. Cf (format: bidi
#: marks and overrides, zero-width joiners and spaces, the soft hyphen, the word joiner, the BOM, the tag
#: block U+E0000-E007F that hides text from a person), Zl and Zp (line and paragraph separators), Cs (a lone
#: surrogate) and Cc (control characters, an ANSI escape among them) except the newline and the tab.
_ESCAPED = frozenset({"Cf", "Zl", "Zp", "Cs", "Cc"})


def fingerprint(text: str) -> str:
    """The first 12 hex of the SHA-256 of `text`. A lone surrogate (which `str.encode` refuses) is
    hashed as its backslash escape, so the fingerprint never raises on what a caller typed."""
    return hashlib.sha256(text.encode("utf-8", "backslashreplace")).hexdigest()[:12]


def _hidden(ch: str) -> bool:
    return ch not in "\n\t" and unicodedata.category(ch) in _ESCAPED


def _plain(text: str) -> str:
    """`text` with every character a person cannot see, or that can reorder what they see, shown as
    its escape (`\\u202e`, `\\x1b`)."""
    if text.isascii() and text.isprintable():
        return text
    return "".join(_escape(ch) if _hidden(ch) else ch for ch in text)


def _escape(ch: str) -> str:
    n = ord(ch)
    return f"\\x{n:02x}" if n <= 0xFF else f"\\u{n:04x}" if n <= 0xFFFF else f"\\U{n:08x}"


def plain_deep(value: Any) -> Any:
    """`_plain` through every string (keys too) of a list or a dict."""
    if isinstance(value, str):
        return _plain(value)
    if isinstance(value, list):
        return [plain_deep(x) for x in value]
    if isinstance(value, dict):
        return {_plain(k) if isinstance(k, str) else k: plain_deep(x) for k, x in value.items()}
    return value


def _shown(text: str) -> list[str]:
    """`text` as the units a person reads: each character, or its escape (`_plain`), whole."""
    if text.isascii() and text.isprintable():
        return list(text)
    return [_escape(ch) if _hidden(ch) else ch for ch in text]


def _mark(text: str) -> str:
    return f"... ({len(text)} chars, sha256:{fingerprint(text)})"


def echo(text: str, limit: int = ECHO_LIMIT) -> str:
    """`text` as it is when short; else its first characters and a mark that carries the length and a
    fingerprint of the whole, so a clip is never mistaken for the value. Bidi, zero-width and control
    characters are escaped FIRST and the cut counts what is shown, escapes included (`limit` characters
    of display at most), and never splits an escape; a lone surrogate cannot raise."""
    units = _shown(text)
    if sum(len(u) for u in units) <= limit:
        return "".join(units)
    kept, used = [], 0
    for u in units:
        if used + len(u) > limit:
            break
        kept.append(u)
        used += len(u)
    return "".join(kept) + _mark(text)


def echo_bytes(text: str, max_bytes: int) -> str:
    """`echo` bounded in ENCODED BYTES, mark included: the whole result is at most `max_bytes` UTF-8
    bytes whatever the characters (an escape is ten bytes for one character, a CJK one three)."""
    units = _shown(text)
    whole = "".join(units)
    if len(whole.encode()) <= max_bytes:
        return whole
    mark = _mark(text)
    budget = max_bytes - len(mark.encode())
    kept, used = [], 0
    for u in units:
        size = len(u.encode())
        if used + size > budget:
            break
        kept.append(u)
        used += size
    return "".join(kept) + mark


def echo_value(value: Any, limit: int = ECHO_LIMIT) -> Any:
    """A value for display: a string through `echo`; a number, a bool or None as it is; a container
    as its compact JSON through `echo` when that is long (a short one stays a container)."""
    if isinstance(value, str):
        return echo(value, limit)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = _compact(value)
    return plain_deep(value) if len(text) <= limit else echo(text, limit)


def echo_map(values: dict[Any, Any], entries: int, limit: int = 32) -> tuple[dict[str, Any], int]:
    """At most `entries` entries of a caller's or a record's map, keys and values through `echo`, and
    how many were left out. Display only: a display never feeds a decision."""
    shown = {echo(str(k), 40): echo_value(v, limit) for k, v in list(values.items())[:entries]}
    return shown, max(len(values) - entries, 0)


#: THE OPERATOR'S VIEW. The token cap protects what a MODEL is handed; the operator at a terminal
#: (`proximo-core ... --plan`, no model in the loop) reads a plan or a restore with every argument and
#: every value whole. The shell door sets this for a plan; the MCP, REST and A2A doors never do.
OPERATOR_VIEW: contextvars.ContextVar[bool] = contextvars.ContextVar("proximo_operator_view", default=False)


def operator_view() -> bool:
    return OPERATOR_VIEW.get()


def check_input(kind: str, text: str) -> None:
    """Refuse an input of an absurd length, in a short sentence that names the length and never the
    text: a 60 KB method must not come back as a 60 KB refusal."""
    limit = MAX_INPUT[kind]
    if isinstance(text, str) and len(text) > limit:
        raise ProximoError(f"the {kind} is {len(text)} characters; the longest this door takes is {limit}")


def quote(text: str, limit: int = ECHO_LIMIT) -> str:
    """`echo` as a repr: what a model typed, quoted, bounded."""
    return repr(text) if len(text) <= limit else repr(echo(text, limit))


def shorten(text: str, limit: int = ECHO_LIMIT) -> str:
    """`echo`, for a refusal that prints the text unquoted."""
    return echo(text, limit)


def first_sentence(text: str, limit: int = 160) -> str:
    """The first sentence of an authored line (its attribution tail dropped), cut to `limit` with an ellipsis.
    A model-facing plan carries this; the whole sentence is the operator's (`--plan`)."""
    head = text.split(" [Claude,", 1)[0]
    first = head.split(". ", 1)[0].rstrip(".")
    return first if len(first) <= limit else first[:limit - 1].rstrip() + "\u2026"


def _cost(obj: object) -> tuple[int, int]:
    body = _compact(obj)
    return len(body.encode()), estimate_tokens(body)


#: bytes and tokens kept back from every answer for the notes a door adds beside it (`asked`, `read_only`,
#: `cap_problem`)
NOTE_ROOM = (120, 45)


def spent(header: dict[str, Any]) -> tuple[int, int]:
    """What the rest of an answer costs before its data goes in: the header, and the room kept back for
    the notes a door adds beside it. A FENCED answer is not guessed here: `engine._envelope` measures it
    as it will be sent and shrinks the data's share until the whole fits."""
    nbytes, ntokens = _cost(header)
    return nbytes + NOTE_ROOM[0], ntokens + NOTE_ROOM[1]


def _note() -> str:
    problems = cap_problems()
    return ("over the answer cap" + (f"; {'; '.join(problems)}" if problems else "")) if problems else ""


def bounded(data: object, cap: Cap | None = None) -> dict | None:
    """None when `data` fits the cap; else what stands in for it, and THAT fits the cap too (its
    own keys are measured). ONE copy, both doors: a body over the cap is reported, never handed back
    as a silent prefix and never whole. A LIST is cut by rows, with `total` and `returned` beside
    the rows that fit, so the count survives the cut. An OBJECT is DESCRIBED, never cut: its keys with
    kinds and sizes, as many as fit, and `keys_total` for the rest; a model handed the first 2 KB of a
    JSON document has a document that does not parse. Anything else is described by kind and size.
    Every cut carries a `next` that says how to narrow. The cap is bytes AND estimated tokens (the
    token cap keeps dense text, where a byte is a token, inside a 4K window), measured on the
    compact JSON the door sends."""
    cap = cap or answer_cap()
    body = _compact(data)
    size = len(body.encode())
    if fits(size, body, cap=cap):
        return None
    note = _note()
    head: dict[str, Any] = {"truncated": True, "bytes": size, "cap": cap.bytes, **({"note": note} if note else {})}
    if isinstance(data, list):
        head.update(total=len(data), returned=len(data), data=[],
                    next=f"{len(data)} of {len(data)} rows: fields= or args narrows, or a concrete path")
        room = cap.minus(*_cost(head), 64)
        kept, used, spent = [], 2, 2            # the brackets
        for item in data:
            text = _compact(item)
            piece = len(text.encode()) + (1 if kept else 0)    # "," between rows
            cost = estimate_tokens(text) + (1 if kept else 0)
            if used + piece > room.bytes or (room.tokens is not None and spent + cost > room.tokens):
                break
            kept.append(item)
            used, spent = used + piece, spent + cost
        head.update(returned=len(kept), data=kept,
                    next=head["next"].replace(f"{len(data)} of {len(data)}", f"{len(kept)} of {len(data)}", 1))
        return head
    if isinstance(data, dict):
        head.update(keys_total=len(data), keys_returned=0, keys={},
                    next="too big: read a child path or narrow with args")
        room = cap.minus(*_cost(head), 64)
        keys, used, spent = {}, 2, 2
        for k, v in data.items():
            name = k if len(k) <= 40 else k[:37] + "..."
            text = _compact({name: describe(v)})
            piece = len(text.encode()) - 1          # the entry, less the braces
            cost = estimate_tokens(text) - 1
            if used + piece > room.bytes or (room.tokens is not None and spent + cost > room.tokens):
                break
            keys[name] = describe(v)
            used, spent = used + piece, spent + cost
        head.update(keys=keys, keys_returned=len(keys))
        return head
    head.update(kind=str(describe(data)) if isinstance(data, str) else type(data).__name__,
                next="too big: narrow with args or a child path")
    return head


# fit_answer is below; its helpers come first.
#: Keys no cap may shrink, whatever the answer: the verdict and what governs it. A shrink that cut
#: one would be a safety regression, so an answer whose protected keys alone are over the cap is
#: left over the cap rather than cut.
PROTECTED = frozenset({
    "address", "plane", "access", "tier", "tier_authored", "tier_raised", "tier_may_rise", "why", "untrusted",
    "channel", "allowed", "reason", "needs", "arguments", "notes", "consent_id", "consent", "grant_path",
    "also", "risk_hint", "safety_net", "default_node", "consult", "download", "change", "noop", "derived",
    "matched_path", "called_path", "subject", "flags", "incomplete", "shell", "note",
    "intent", "task", "withheld", "error", "fenced", "truncated", "trimmed", "next", "id", "captured",
    "arguments_more", "change_more", "change_untrusted", "restores", "skipped", "differs_unwritten", "removes",
    "snapshot", "cap_problem", "read_only", "not_shown_whole", "operator_view", "arguments_unpublished_more",
    "restored", "deleted", "attempted", "skipped_more", "unknown_parameters",
    "parameters_more", "required_missing", "also_refused", "undo_notes"})


_TRIM_NEXT = "trimmed: ask a part by its own address, or narrow with args or fields="


def _clip(value: Any, limit: int = 160) -> tuple[Any, int]:
    """Every long string inside `value` cut to `limit` characters WITH the mark `echo` puts on a clip
    (its length and a fingerprint, in the value itself), and how many were cut: a failed task's status
    text is a paragraph, and the paragraph is what makes a ten-row list a thousand tokens."""
    if isinstance(value, str):
        return (value, 0) if len(value) <= limit else (echo(value, limit), 1)
    if isinstance(value, list):
        parts = [_clip(x, limit) for x in value]
        return [p[0] for p in parts], sum(p[1] for p in parts)
    if isinstance(value, dict):
        parts = {k: _clip(x, limit) for k, x in value.items()}
        return {k: p[0] for k, p in parts.items()}, sum(p[1] for p in parts.values())
    return value, 0


def _halve(value: Any) -> Any:
    """Half of a list or an object (the leading half); anything else as it is. Never a string: a
    half string is a corrupt value, and a long one is clipped WITH its mark by `_clip`."""
    if isinstance(value, list) and len(value) > 1:
        return value[:(len(value) + 1) // 2]
    if isinstance(value, dict) and len(value) > 1:
        return dict(list(value.items())[:(len(value) + 1) // 2])
    return value


def _size_of(value: Any) -> int:
    return _cost(value)[0]


def _say(kept: dict[str, tuple[int, int]], clipped: dict[str, int]) -> dict[str, str]:
    """`trimmed`: for each path, how many rows are kept of how many and how many strings were clipped."""
    return {name: ", ".join(part for part in (
        f"{kept[name][0]} of {kept[name][1]}" if name in kept else "",
        f"{clipped[name]} long string(s) clipped" if clipped.get(name) else "") if part)
        for name in (*kept, *(n for n in clipped if n not in kept))}


def _candidates(out: dict[str, Any], protect: frozenset[str],
                descend: tuple[str, ...]) -> list[tuple[int, tuple[str, ...]]]:
    """The parts of `out` a trim may shrink, with their sizes: each unprotected key, and the unprotected
    keys of each section of a `descend` key."""
    found: list[tuple[int, tuple[str, ...]]] = []
    for k, v in out.items():
        if k in protect:
            continue
        if k in descend and isinstance(v, dict):
            for sk, sv in v.items():
                if isinstance(sv, dict):
                    found += [(_size_of(x), (k, sk, ik)) for ik, x in sv.items() if ik not in protect]
                elif sk not in protect:
                    found.append((_size_of(sv), (k, sk)))
        else:
            found.append((_size_of(v), (k,)))
    return [c for c in found if c[0] > 60]


def note_problems(answer: dict[str, Any]) -> dict[str, Any]:
    """Name a junk cap variable on an answer that was cut under the default cap (`cap_problem`), so
    an operator who typed `6k` is told on the answer a model reads, not only in doctor."""
    if problems := cap_problems():
        answer["cap_problem"] = "; ".join(problems)
    return answer


def fit_answer(answer: dict[str, Any], *, descend: tuple[str, ...] = (), protect: frozenset[str] = PROTECTED,
               cap: Cap | None = None, next_text: str = _TRIM_NEXT) -> dict[str, Any]:
    """THE LAST GUARD for a composed answer (a plan, a diagnosis): while it is over the cap, long
    strings are clipped WITH the mark `echo` puts on a clip, then the largest key that is not
    protected is halved (a list keeps its leading half, an object its leading keys), again and again,
    and the answer says what it did (`trimmed`: path -> how many were kept of how many, how many
    strings were clipped) and how to ask for the rest (`next`). A list stays a list and an object an
    object, so a consumer of the shape still reads it. Keys named in `descend` are dicts of sections
    whose own keys are trimmed one by one (a diagnosis's battery). PROTECTED MEANS NEVER DROPPED, not
    that a value may be unbounded: a protected key is never touched here because its builder bounded it
    (`echo_map`); an answer whose protected keys alone are over the cap is left over it, not cut."""
    cap = cap or answer_cap()
    out = dict(answer)
    kept: dict[str, tuple[int, int]] = {}       # path -> (rows now, rows first)
    clipped: dict[str, int] = {}                # path -> strings clipped

    def say() -> dict[str, str]:
        return _say(kept, clipped)

    def over() -> bool:
        plain = _compact(out)
        if fits(len(plain.encode()), plain, cap=cap) and not kept and not clipped:
            return False
        body = _compact({**out, "trimmed": say() or {"x": "1 of 2"}, "next": out.get("next", next_text)})
        return not fits(len(body.encode()), body, cap=cap)

    def candidates() -> list[tuple[int, tuple[str, ...]]]:
        return _candidates(out, protect, descend)

    def get(path: tuple[str, ...]) -> Any:
        node: Any = out
        for part in path:
            node = node[part]
        return node

    def put(path: tuple[str, ...], value: Any) -> None:
        node: Any = out
        for part in path[:-1]:
            node[part] = dict(node[part])
            node = node[part]
        node[path[-1]] = value

    if over():
        for _size, path in candidates():           # first the long strings, everywhere, marked
            value, count = _clip(get(path))
            if count:
                put(path, value)
                clipped["/".join(path)] = count
    for _ in range(200):
        if not over():
            break
        options = [c for c in sorted(candidates(), reverse=True) if _halve(get(c[1])) is not get(c[1])]
        if not options:
            break
        path = options[0][1]
        before = get(path)
        put(path, _halve(before))
        name = "/".join(path)
        kept[name] = (len(get(path)), kept[name][1] if name in kept else len(before))
    if kept or clipped:
        out["trimmed"] = say()
        out.setdefault("next", next_text)
        note_problems(out)
    return out


# ---- THE EXIT: one hard ceiling on every answer a model is handed ----------------------------------------
# Everything above makes an answer small on purpose. This is the guarantee that does not depend on any of it:
# the answer is measured as the compact JSON bytes it leaves the door in (after fit, fencing and headers), and
# one over its kind's ceiling is REPLACED by a fixed-shape answer of a few hundred bytes. Nothing is exempt,
# protected keys included. The worst case in real tokens is the ceiling itself at one token a byte (dense
# text, measured); at the measured 2.5 to 4 bytes a token it is a third of that.

CEILINGS = {"read": 1152, "plan": 2048, "composed": 3072, "refusal": 512}

#: answers whose null, false or empty values say nothing a model acts on
_NOISE = frozenset({"untrusted", "derived", "channel", "tier", "needs", "withheld", "tier_authored", "tier_raised",
                    "noop", "truncated", "summarized", "consent", "also", "grant_path", "unpublished", "next"})
#: what an over-cap answer keeps of the real one: the verdict and the identifiers a caller acts on
_KEEP = ("address", "plane", "allowed", "needs", "tier", "consent_id", "status", "intent", "ok", "incomplete",
         "restores", "called_path", "total", "returned")


def kind_of(name: str, answer: dict[str, Any]) -> str:
    """Which ceiling an answer is held to: a diagnosis is `composed`; a plan or a call (whose dry run is a
    plan, and whose run answers an envelope) is `plan`; everything else is `read`."""
    if "battery" in answer:
        return "composed"
    return "plan" if name in ("proximo_plan", "proximo_call") else "read"


def terse(answer: dict[str, Any]) -> dict[str, Any]:
    """The answer without the keys whose value is nothing (a null tier, a false `untrusted`, an empty
    `withheld`) and without `matched_path` when it only repeats `called_path`. Data, a verdict, a next path."""
    out = {k: v for k, v in answer.items() if not (k in _NOISE and v in (None, False, "", [], {}))}
    if out.get("matched_path") == out.get("called_path"):
        out.pop("matched_path", None)
    return out


def _sent(answer: object) -> int:
    return len(json.dumps(answer, separators=(",", ":"), ensure_ascii=False, default=str).encode())


def over_cap(name: str, answer: dict[str, Any], size: int, ceiling: int) -> dict[str, Any]:
    """The fixed-shape replacement: the verdict and identifiers, counts of what was left out, one fixed line."""
    out: dict[str, Any] = {"over_cap": True, "bytes": size, "cap": ceiling}
    for key in _KEEP:
        if key in answer and isinstance(answer[key], (str, int, float, bool)) and answer[key] is not None:
            out[key] = echo(answer[key], 80) if isinstance(answer[key], str) else answer[key]
    if isinstance(answer.get("reason"), str):
        out["reason"] = echo(answer["reason"], 100)
    undo = answer.get("undo")
    if isinstance(undo, dict) and isinstance(undo.get("id"), str):
        out["undo"] = echo(undo["id"], 24)
    task = answer.get("task")
    if isinstance(task, dict):
        out["task"] = {k: echo(str(task[k]), 40) for k in ("status", "exitstatus") if k in task}
    counts = {k: len(v) for k, v in answer.items() if isinstance(v, (list, dict)) and v and k not in ("undo", "task")}
    if counts:
        out["counts"] = dict(list(counts.items())[:8])
    out["next"] = _operator_line(name, answer)
    if _sent(out) <= ceiling:
        return out
    return _minimal(name, answer, size, ceiling)


def _operator_line(name: str, answer: dict[str, Any]) -> str:
    cid = answer.get("consent_id")
    if isinstance(cid, str):
        return f"the full plan is for the operator: proximo-core consent show {echo(cid, 80)}"
    if kind_of(name, answer) == "plan":
        return "the full plan is for the operator: proximo-core <plane> <METHOD> <path> --plan"
    return "narrow: args, fields=, a concrete path"


def _minimal(name: str, answer: dict[str, Any], size: int, ceiling: int) -> dict[str, Any]:
    """THE FLOOR UNDER THE OVER-CAP SHAPE: when even that is over (kept values that escape ten bytes a
    character), only the verdict, `needs`, the consent id and the operator's line, each short and fixed in
    kind, and the consent id dropped too (its line generic) if a ceiling is smaller than that."""
    out: dict[str, Any] = {"over_cap": True, "bytes": size, "cap": ceiling}
    if isinstance(answer.get("allowed"), bool):
        out["allowed"] = answer["allowed"]
    if isinstance(answer.get("needs"), str):
        out["needs"] = echo_bytes(answer["needs"], 24)
    cid = answer.get("consent_id")
    if isinstance(cid, str) and _sent({**out, "consent_id": echo_bytes(cid, 80)}) + 200 <= ceiling:
        out["consent_id"] = echo_bytes(cid, 80)
        out["next"] = f"the full plan is for the operator: proximo-core consent show {out['consent_id']}"
    else:
        out["next"] = _operator_line(name, {k: v for k, v in answer.items() if k != "consent_id"})
    return out


def finish(name: str, answer: dict[str, Any]) -> dict[str, Any]:
    """`answer` as the door lets it leave: terse, and under its ceiling or replaced (see above)."""
    tidy = terse(answer)
    ceiling = CEILINGS[kind_of(name, answer)]
    size = _sent(tidy)
    return tidy if size <= ceiling else over_cap(name, tidy, size, ceiling)


def refusal_text(text: str) -> str:
    """A refusal's words, bounded: caller text in them is clipped by its builder, and this is the exit's net:
    escaped, then cut so the WHOLE of it, mark included, is at most the refusal ceiling in bytes."""
    return echo_bytes(text, CEILINGS["refusal"])
