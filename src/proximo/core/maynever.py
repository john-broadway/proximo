"""THE MAY/NEVER MAP, step 2: the vendor's own rule, read against what the token holds.

Each api-viewer publishes, per call, the rule its door checks before the handler runs (carried
verbatim in `proximo.json.gz`, column `permissions`; step 1). This module answers one call, on one
concrete path, for one token, with one of five answers:

- MAY: the vendor's door lets this token through (the rule is met, or it admits every user).
- NEVER: the rule is not met; `why` names the missing grant ("VM.Audit on /vms/100"), or says the
  vendor published no rule (PVE then admits only root@pam itself; an API token is never root@pam).
- FILTERED: a read every user may call whose vendor words open as a cut list ("Only list entries
  where you have ...", `_CUT_LIST`); the words ride in `why`. Words that state a requirement
  ("Requires ...", "You need ...") are not a cut list: they are WORDS (lens 1 on 21eefb7: 22 reads
  that 403 were called filtered).
- WORDS: the rule is the vendor's to judge in a form this map does not evaluate (a prose condition,
  a `user: world` login door, a head such as `userid-param` or `perm-modify`, a `require_param`
  option, a placeholder no value fills, a value the vendor's door would not read as a path, a row on
  Proximo's own ssh lane, a product not evaluated yet, a rule the grammar does not know). Never
  rounded to MAY: "in words" is an answer, not a yes.
- UNKNOWN: what the token holds could not be read. Never rounded to either side.

THE MAP GOVERNS NOTHING. A NEVER still sends: the vendor's 403 is the lock, and this module imports
no gate (`tests/test_maynever.py` holds it to that). It informs a plan; it never refuses one.

WHAT A TOKEN HOLDS AT A PATH IS THE VENDOR'S ANSWER, not ours: `GET /access/permissions` with that
`path` runs PVE's own ACL walk (propagation, a deeper ACL that takes a grant away). The whole map,
read once and walked by ancestor, says "held" at `/pool/x` from a propagating `/` while a deeper ACL
on `/pool/x` takes it away (measured on the lab: `/` holds Pool.Audit, the lab pool does not, and
the vendor answers 403). So `at(path)` is one per-path read.

PVE's door (`check_api2_permissions`, the order this module follows): `user: all` admits every
authenticated caller BEFORE any `check` runs; `user: world` admits a caller with no login (the
login doors), so for a token it is WORDS; else the `check` decides; no rule admits only root@pam.
`or`/`and` are four-valued here (MAY, UNKNOWN, WORDS, NEVER): `and` is NEVER if any part is, else
UNKNOWN if any part is, else WORDS if any is, else MAY. `or` the vendor reads LEFT TO RIGHT
(`exec_api2_perm_check`), each part asked with noerr, and stops at the first that passes; but some parts
refuse outright even so (`userid-group`'s groups check, `verify_username`, an `and` that asks its own
parts without noerr, a `perm` with no path), ending the `or` before a later part runs (lenses 5, 6;
`_may_refuse`). So `or` is MAY at the first MAY up to and including the first such part; at such a part
the walk stops: if the part is NEVER it raises and the `or` is NEVER, else what follows counts as itself
if it is WORDS or UNKNOWN, as WORDS if it is MAY, and not at all if it is NEVER; the parts kept are then
UNKNOWN if any is, else WORDS, else NEVER. A path is filled as the vendor's `template_replace` would (a
falsy value is `-` there: unfilled here; a literal chunk of exactly `0` it drops: WORDS here). A path
with a character outside `[A-Za-z0-9._/-]` (in the rule's own text or in a value) is no path this map
answers for; the vendor's `normalize_path` refuses outside a letter, a digit, `.`, `-`, `_` and `/` only
(perl's `$` also lets one trailing newline through), and reads a path that collapses to `0` as `/`
(WORDS here), so this is stricter on purpose (in a VALUE, also an empty, `.` or `..` segment; the rule's
own text is asked as written, as the vendor asks it): over-cautious WORDS, never a guess.
PBS and PDM (proxmox-router's `Permission`): a `check` is {path, privs, partial}: the path's parts
joined and filled as PVE's template is; `partial` false needs every privilege at that path, true any one;
an `or` is each part asked on its own (no part refuses outright: Rust returns), a `userParam` part is the
vendor's self rule (MAY when the named argument is the served credential's own user, NEVER when it is
another, UNKNOWN when who is served could not be read, WORDS when the argument is not given); an `and`
needs every part. What the token holds comes from the caller's own `GET /access/permissions`, which these
products answer as the tree of ACL nodes the caller holds anything on (`list_permissions` drops a node
whose privileges are none, a NoAccess fence among them), each with its privileges and a propagate flag: a
path listed holds its privileges; a path not listed is UNKNOWN here, because the vendor's own walk
(`AclTree::roles`: a NoAccess node that the tree cannot show overrides a parent's grant; a node holding
only non-propagating roles does not stop the parent's propagation below it) is not inferred from the
tree (lens on 325b37e); an empty tree is the vendor saying the caller holds nothing anywhere, known. The
self rule compares what the vendor compares: the WHOLE auth id (`proxmox-auth-api` sets it to the token id
for a token, `user@realm!name`, and to the user for a ticket), so a token never passes `userParam` and a
ticket does for its own user. A rule of none is `Permission::Superuser` on PBS/PDM and root-only on PMG
and PVE: MAY for the user root@pam itself (a root ticket, PMG's root credential), NEVER for any token. A
rule slot the row's own path does not bind (two rows: `POST /nodes/{node}/network` on PBS and PDM carry
`{iface}` in the body) the vendor fills from the routed path only, so it is false for every caller but
root: NEVER here. PMG's rule is a list of roles the user must hold one of; the served user's role is not
read here yet, so a PMG check answers WORDS naming the roles, never a guess.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from proximo.core import apitree, rawdoor

MAY, NEVER, FILTERED, WORDS, UNKNOWN = "may", "never", "filtered", "in words", "unknown"
ANSWERS = (MAY, NEVER, FILTERED, WORDS, UNKNOWN)

#: what one echoed piece costs at most, as UTF-8 bytes, mark included (a filled path or a privilege
#: name is the caller's or the vendor's bytes), and what a whole `why` costs, the vendor's words in it
PIECE_BYTES, WHY_BYTES = 64, 480

#: how the vendor's words open when they describe a list cut to the caller's grants (measured on the
#: PVE api-viewer 2026-11-02). A wording not here is WORDS: a vendor rewording moves toward "in words"
_CUT_LIST = ("Only list ", "Only lists ", "Only returns ", "Will only return ", "The returned list is restricted",
             "List all pools where you have", "List task associated with the current user",
             "Custom models are filtered")

_SLOT = re.compile(r"\{([^{}]+)\}")
_SEGMENT = re.compile(r"[A-Za-z0-9._-]+", re.ASCII)

_USER = re.compile(r"[^\s!=:@]+@[^\s!=:@]+")                   # user@realm
_TOKEN_ID = re.compile(r"[^\s!=:@]+@[^\s!=:@]+![^\s!=:@]+")    # user@realm!name, the vendor's auth id

#: privileges held at one path (the vendor's names), or None when they could not be read
At = Callable[[str], "frozenset[str] | None"]


@dataclass(frozen=True)
class Answer:
    verdict: str
    why: str = ""


def _e(text: Any) -> str:
    return rawdoor.echo_bytes(str(text), PIECE_BYTES)


def answer(rule: Any, product: str, method: str, fill: Mapping[str, Any], at: At, *, wire: str,
           who: str | None = None, path_slots: frozenset[str] | None = None) -> Answer:
    """One call's answer. `rule` is the row's `permissions` column, `fill` the values for the
    rule's placeholders (the called path's and the call's arguments), `at` the token's holdings,
    `wire` the row's, required (Proximo's own ssh lane answers to no vendor rule, lens 2: a default of
    http read those rows as "root@pam only"), `who` the served credential's own user id (`user@realm`),
    for the vendor's self rule, or None when it could not be read; `path_slots` the placeholders the ROW's
    own path binds (PBS/PDM fill a rule's slot from the routed path only), or None to skip that check."""
    try:            # lens 8: each value read ONCE (a mapping that answers twice answered two paths)
        fill = dict(fill) if isinstance(fill, Mapping) else {}      # lens 5: no mapping, no values
    except Exception:  # noqa: BLE001 -- a mapping that raises on a read has no values
        fill = {}
    try:
        a = _answer(rule, product, method, fill, at, wire, who, path_slots)
    except RecursionError:      # lens 8: the grammar caps depth, not width; never raised
        a = Answer(WORDS, "a rule too wide for the map to walk")
    return Answer(a.verdict, rawdoor.echo_bytes(a.why, WHY_BYTES) if a.why else "")


def _answer(rule: Any, product: str, method: str, fill: Mapping[str, Any], at: At, wire: str,
            who: str | None = None, path_slots: frozenset[str] | None = None) -> Answer:
    if wire != "http":
        return Answer(WORDS, "Proximo's own lane, not the vendor's door: its allowlist decides")
    if problem := apitree.rule_problem(rule, product):      # public: a malformed rule is said, never raised
        return Answer(WORDS, f"a rule the map cannot read: {problem}")
    if rule is None:
        if who == "root@pam":           # the user itself (a root ticket, PMG's root credential): never a token
            return Answer(MAY, "the vendor publishes no rule and admits root@pam itself, which is served")
        return Answer(NEVER, "the vendor publishes no rule: only root@pam itself, never an API token")
    words = rule.get("description")
    if rule.get("user") == "world":
        return Answer(WORDS, "the vendor's login door: open to a caller before login, not to a token's rule")
    if rule.get("user") == "all":
        if not words:
            return Answer(MAY)
        cut = product == "pve" and method == "GET" and words.startswith(_CUT_LIST)  # PVE's wording, measured
        return Answer(FILTERED if cut else WORDS, f"the vendor says: {words}")
    if product == "pve":        # the grammar leaves a check here: description alone is refused
        got = _check(rule["check"], fill, at)
    elif product == "pmg":
        got = _roles(rule["check"])
    else:
        got = _rust(rule, fill, at, who, path_slots)
    if got.verdict == MAY and words:
        return Answer(WORDS, f"the check is met, and the vendor adds: {words}")
    return got


def _check(c: list[Any], fill: Mapping[str, Any], at: At) -> Answer:
    head, rest = c[0], c[1:]
    if head == "or":
        parts: list[Answer] = []
        for i, x in enumerate(rest):
            part = _check(x, fill, at)
            if part.verdict == MAY:
                return Answer(MAY)
            parts.append(part)
            if _may_refuse(x) and part.verdict == NEVER:    # lens 6: a NEVER here is an `and` (or an
                break                           # `or` down to one) that RAISES: nothing after it is reached
            if _may_refuse(x):                  # lens 5: the vendor may never reach what follows
                after = rest[i + 1:]
                later = _check(after[0] if len(after) == 1 else ["or", *after], fill, at) if after else None
                if later is not None and later.verdict == MAY:      # never lifted past the part above
                    parts.append(Answer(WORDS, "a later part counts only if the vendor's own rule before "
                                                "it does not refuse outright"))
                elif later is not None and later.verdict != NEVER:
                    parts.append(later)
                break
        return _joined(head, parts)
    if head == "and":
        return _joined(head, [_check(x, fill, at) for x in rest])
    if head == "perm":
        template, privs, tail = rest[0], rest[1], rest[2:]
        if tail[:1] == ["require_param"]:
            return Answer(WORDS, f"the vendor also requires the parameter {_e(tail[1])}")
        path = _filled(template, fill)
        if isinstance(path, Answer):
            return path
        held = at(path)
        if held is None:
            return Answer(UNKNOWN, f"what this token holds on {_e(path)} could not be read")
        want = list(dict.fromkeys(privs))          # the vendor may name one twice
        if tail == ["any", 1]:
            if held & set(want):
                return Answer(MAY)
            return Answer(NEVER, f"one of {', '.join(_e(p) for p in want)} on {_e(path)}")
        missing = [p for p in want if p not in held]
        if not missing:
            return Answer(MAY)
        return Answer(NEVER, f"{', '.join(_e(p) for p in missing)} on {_e(path)}")
    return Answer(WORDS, f"the vendor checks {_e(head)} by a rule of its own")


def _joined(head: str, parts: list[Answer]) -> Answer:
    of = {p.verdict for p in parts}
    order = (NEVER, UNKNOWN, WORDS, MAY) if head == "and" else (MAY, UNKNOWN, WORDS, NEVER)
    verdict = next(v for v in order if v in of)
    if verdict == MAY:
        return Answer(MAY)
    joiner = "; and " if head == "and" else "; or "
    return Answer(verdict, joiner.join(p.why for p in parts if p.verdict == verdict))


def _rust(rule: Mapping[str, Any], fill: Mapping[str, Any], at: At, who: str | None,
          path_slots: frozenset[str] | None) -> Answer:
    """PBS and PDM: {check}, or an `or` of {check} / {userParam}, or an `and` of {check} (the grammar
    `apitree.rule_problem` admits). Every part is asked on its own: the vendor's `or` returns, never raises."""
    if "check" in rule:
        return _privilege(rule["check"], fill, at, path_slots)
    head = "or" if "or" in rule else "and"
    parts = [_self(part["userParam"], fill, who) if "userParam" in part
             else _privilege(part["check"], fill, at, path_slots) for part in rule[head]]
    return _joined(head, parts)


def _privilege(c: Mapping[str, Any], fill: Mapping[str, Any], at: At,
               path_slots: frozenset[str] | None) -> Answer:
    """`Permission::Privilege(path, privs, partial)`: the path's parts joined, filled like PVE's template;
    `partial` true is any one of the privileges, false is all of them (the missing ones named). A slot the
    row's own path does not bind the vendor fills from the routed path only (`uri_param`, before the body
    is read): absent there, the check is false for every caller but root."""
    template = "/" + "/".join(c["path"])
    if path_slots is not None:
        if foreign := [n for n in _SLOT.findall(template) if n not in path_slots]:
            return Answer(NEVER, "the vendor fills " + ", ".join("{" + _e(n) + "}" for n in foreign)
                          + " from the request path only, and this address carries it elsewhere: "
                            "refused for every caller but root@pam")
    path = _filled(template, fill)
    if isinstance(path, Answer):
        return path
    held = at(path)
    if held is None:
        return Answer(UNKNOWN, f"what this token holds on {_e(path)} could not be read")
    want = list(dict.fromkeys(c["privs"]))          # the vendor may name one twice
    if c["partial"]:
        if held & set(want):
            return Answer(MAY)
        return Answer(NEVER, f"one of {', '.join(_e(p) for p in want)} on {_e(path)}")
    missing = [p for p in want if p not in held]
    if not missing:
        return Answer(MAY)
    return Answer(NEVER, f"{', '.join(_e(p) for p in missing)} on {_e(path)}")


def _self(name: str, fill: Mapping[str, Any], who: str | None) -> Answer:
    """`Permission::UserParam(name)`: the vendor admits the caller when that argument equals its WHOLE auth
    id: the user for a ticket, the token id (`user@realm!name`) for a token, which no user id equals."""
    v = fill.get(name)
    if _unfilled(v) or type(v) not in (str, int):
        return Answer(WORDS, f"depends on {{{_e(name)}}}: the vendor admits the user itself; give it")
    if who is None:
        return Answer(UNKNOWN, "who the served credential is could not be read")
    if str(v) == who:
        return Answer(MAY)
    if "!" in who:
        return Answer(NEVER, f"the served credential is a token, {_e(who.split('!', 1)[0])}'s, and the vendor "
                             "compares the token id, never its user")
    return Answer(NEVER, f"{{{_e(name)}}} is {_e(v)}, not the caller's own user")


def _roles(roles: list[Any]) -> Answer:
    """PMG: the user must hold one of these roles. The served user's role is not read here yet."""
    return Answer(WORDS, "the vendor admits the role " + " or ".join(_e(r) for r in roles)
                  + "; which role the served user holds is not read here")


def _may_refuse(c: list[Any]) -> bool:
    """Can this part, asked inside an `or` (noerr), still refuse the whole call (`exec_api2_perm_check`)?
    A `perm` with a path answers 0, but a falsy one (`""`, `"0"`) dies "missing parameters" first
    (lens 6). `perm-modify` answers 0 (no path: 0; else `check_any` with noerr). An `or` of parts
    that answer 0 answers 0. Anything else may raise: an `and` asks its parts without noerr, the
    userid tests call `verify_username` and `raise_perm_exc` (lens 5). NOT SEEN HERE: a privilege
    name the cluster does not know dies in `verify_privname` even under noerr; the vendor's own
    rules name only its own privileges, so that is a map built for another version (the map's
    node-built step) or a tampered table."""
    if c[0] == "perm":
        return c[1] in ("", "0")
    if c[0] == "perm-modify":
        return False
    if c[0] == "or":
        return any(_may_refuse(x) for x in c[1:])
    return True


def _filled(template: str, fill: Mapping[str, Any]) -> str | Answer:
    """The rule's path with every placeholder filled, or WORDS: a placeholder no value fills makes
    the answer depend on the object (`/vms/{vmid}`), and a parent's grant is no answer for a child a
    deeper ACL can take it from. A falsy value the vendor fills as `-`, so it is unfilled here too
    (lens 1: {vmid: 0} was asked at /vms/0). A value outside `[A-Za-z0-9._-]` segments, or the rule's
    own text outside `[A-Za-z0-9._/-]`, is no path either (stricter than the vendor's `normalize_path`,
    see the module note)."""
    names = _SLOT.findall(template)
    if not template or template == "0":         # lens 5/6: the vendor dies "missing parameters" on it
        return Answer(WORDS, "the rule's path is not one the vendor's door reads")
    if "0" in _SLOT.split(template)[::2]:       # lens 7: `$res .= $1 if $1` drops a literal "0" there
        return Answer(WORDS, "the rule's path is not one the vendor's door reads")
    if not re.fullmatch(r"[A-Za-z0-9._/-]*", _SLOT.sub("", template), re.ASCII):    # lens 2: the text, too
        return Answer(WORDS, "the rule's path is not one the vendor's door reads")
    if unbound := [n for n in names if _unfilled(fill.get(n))]:
        return Answer(WORDS, "depends on " + ", ".join("{" + _e(n) + "}" for n in unbound) + ": give it")
    texts: dict[str, str] = {}
    for n in names:
        v = fill[n]
        try:
            text = str(v) if type(v) in (str, int) else None     # lens 5: no subclass, its text is its own
        except ValueError:          # an int past the interpreter's digit limit (lens 2): said, never raised
            text = None
        if text is None or len(text) > 1024 or \
                not all(_SEGMENT.fullmatch(seg) and seg not in (".", "..") for seg in text.strip("/").split("/")):
            return Answer(WORDS, f"{{{_e(n)}}} is not a path the vendor's door reads")
        texts[n] = text                     # the text checked is the text filled (lens 3)
    raw = _SLOT.sub(lambda m: texts[m.group(1)], template)
    path = "/" + "/".join(s for s in raw.split("/") if s)         # empty segments drop
    if path != _normalized(raw):    # lens 8: "0/" is "/" to the vendor; any path it reads otherwise
        return Answer(WORDS, "the vendor reads this path as another")
    return path


def _normalized(raw: str) -> str | None:
    """The vendor's `normalize_path` (AccessControl.pm), with perl's truth ("" and "0" are false), but
    not its character check (this module's own is stricter). The map asks only a path equal to it."""
    if raw in ("", "0"):
        return None
    path = re.sub(r"/+", "/", raw)
    if path.endswith("/"):
        path = path[:-1]
    if path in ("", "0"):
        path = "/"
    return path if path.startswith("/") else "/" + path


def _unfilled(v: Any) -> bool:
    """The vendor's `$data->{x} || '-'`, judged without asking an unknown value its truth (lens 5)."""
    return v is None or v is False or (type(v) in (str, int) and (not v or v == "0"))


def _tree(data: Any) -> dict[str, frozenset[str]] | None:
    """PBS/PDM's `GET /access/permissions` for the caller: {path: {privilege: propagate}}, every value a
    bool: what each listed node holds. `{}` is the vendor's answer for a caller with no grant anywhere.
    Anything else is not that answer: None."""
    if not isinstance(data, dict):
        return None
    nodes: dict[str, frozenset[str]] = {}
    for path, held in data.items():
        if not (isinstance(path, str) and path.startswith("/") and isinstance(held, dict)):
            return None
        if not all(isinstance(k, str) and k and type(v) is bool for k, v in held.items()):
            return None
        nodes[path] = frozenset(held)
    return nodes


class Holdings:
    """`at(path)` for one served token: one `GET /access/permissions?path=` per path, through the
    engine (receipted, bounded, like every read). THE BYTES ASKED ABOUT ARE THE BYTES SENT: the token
    file is read once, the answer is keyed on those bytes' digest, and the read sends exactly them from a
    private copy (the wire re-reads its token file per request, so hashing the file before and after
    could not prove which bytes went: an arm and a disarm inside one read cached the write token's
    holdings under the read token's key, lens 2). An answer is reused for `max_age` seconds from the
    moment its read STARTED, for those bytes only, and one token's answers are kept at a time. An ACL
    change leaves the token's bytes alone, so the age is the bound on a stale answer: build one per
    question (a plan) and it never matters. A failed read is never reused as an answer, and after one, this
    Holdings asks nothing more (lens 3s1: a box that is down cost one timeout per path, the same path twice):
    one question, one failure, every later path unknown."""

    def __init__(self, cfg: Any, ledger_cfg: Any = None, read: Callable[[str | None, bytes], Any] | None = None,
                 max_age: float = 60.0, clock: Callable[[], float] = time.monotonic) -> None:
        self._cfg, self._lcfg = cfg, ledger_cfg
        self._read = read or self._vendor
        self._max_age, self._clock = max_age, clock
        self._seen: dict[tuple[str, str], tuple[float, frozenset[str]]] = {}
        self._trees: dict[str, tuple[float, dict[str, frozenset[str]] | None]] = {}
        self._failed = False                    # a read raised: nothing more is asked of this box
        self._product = getattr(cfg, "product", "pve") or "pve"

    @property
    def user(self) -> str | None:
        """The served credential's auth id AS THE VENDOR COMPARES IT: a token line's `user@realm!name` (the
        token id: `proxmox-auth-api` sets the auth id to it), a ticket's user (`user@realm`, its second field),
        a PMG credential file's first line, or PMG's configured username in password mode (the file is the
        password). None when the file is unreadable or not one of those."""
        if self._product == "pmg" and not getattr(self._cfg, "credential", False):
            name = getattr(self._cfg, "username", None)
            return name if isinstance(name, str) and "@" in name else None
        token = self._token()
        if token is None:
            return None
        text = token.decode("utf-8", "replace").strip().lstrip("\ufeff")
        if text.startswith("{"):
            try:
                ticket = json.loads(text).get("ticket")
            except (ValueError, AttributeError):
                return None
            parts = ticket.split(":") if isinstance(ticket, str) else []
            return parts[1] if len(parts) >= 4 and _USER.fullmatch(parts[1]) else None
        head = text.split("\n", 1)[0]
        if self._product == "pmg":
            return head if _USER.fullmatch(head) else None
        head = head.split("=", 1)[0].split(":", 1)[0]       # PVE's `=`, PBS/PDM's `:` before the secret
        return head if _TOKEN_ID.fullmatch(head) else None

    def _token(self) -> bytes | None:
        try:
            with open(self._cfg.token_path, "rb") as f:
                token = f.read()
        except (OSError, AttributeError, TypeError, ValueError):     # ValueError: a NUL in the path (lens 2)
            return None
        return token if token.strip() else None     # an empty file is no credential: nothing staged, nothing sent

    def _vendor(self, path: str | None, token: bytes) -> Any:
        import dataclasses  # noqa: PLC0415
        import os  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        from proximo.core import engine  # noqa: PLC0415  (lazy: the evaluator itself needs no engine)
        # 0600, this process's own, BESIDE the served token (as `arm` stages): a SIGKILL mid-read leaves the
        # copy where the token already lives (lens 3). A read-only token dir (the shipped unit's
        # ProtectSystem=strict over /etc/proximo, a secret mount) falls back to the process's temp dir,
        # which the shipped units make private (lens 4; outside one it is the shared TMPDIR, the copy still
        # 0600); no place at all raises, and the caller answers unknown.
        # The secret is written inside the try; only an interrupt between mkstemp's return and the try
        # can leave a file, and that file is empty.
        beside = os.path.dirname(os.path.abspath(self._cfg.token_path))
        try:
            fd, staged = tempfile.mkstemp(prefix=".proximo-map-", dir=beside)
        except OSError:
            fd, staged = tempfile.mkstemp(prefix=".proximo-map-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(token)
            row = engine.resolve(self._product, "GET", "/access/permissions")
            args = {"path": path} if self._product == "pve" else {}     # PBS/PDM: the caller's whole tree
            env = engine.execute(row, args, cfg=dataclasses.replace(self._cfg, token_path=staged),
                                 path="/access/permissions", ledger_cfg=self._lcfg, fields="all", evaluating=True)
        finally:
            os.unlink(staged)
        if not isinstance(env, dict) or env.get("truncated"):      # a cut tree is not the tree
            return None
        return env.get("data")

    def at(self, path: str) -> frozenset[str] | None:
        if type(path) is not str:               # lens 5: a list raised unhashable in the cache key
            return None
        if self._failed:
            return None
        token = self._token()
        if token is None:
            return None
        key = hashlib.sha256(token).hexdigest()
        if self._product in ("pbs", "pdm"):
            return self._from_tree(key, token, path)
        if self._product != "pve":
            return None                         # PMG publishes no per-path holdings: nothing is asked
        hit = self._seen.get((key, path))
        if hit is not None and self._clock() - hit[0] < self._max_age:
            return hit[1]
        started = self._clock()                     # lens 2: the age counts from the read's start
        held = self._ask(path, token)
        if held is None:
            return None
        self._seen = {k: v for k, v in self._seen.items() if k[0] == key}   # one token's answers at a time
        self._seen[(key, path)] = (started, held)
        return held

    def _from_tree(self, key: str, token: bytes, path: str) -> frozenset[str] | None:
        """PBS/PDM: one read of the caller's own tree per token, reused for `max_age` (an answer that is not
        the tree is remembered as unknown for as long, never re-read per path). A listed node holds what it
        lists; an unlisted path is unknown (the vendor's walk is not inferred); an empty tree holds nothing."""
        hit = self._trees.get(key)
        if hit is None or self._clock() - hit[0] >= self._max_age:
            started = self._clock()
            try:
                data = self._read(None, token)
            except Exception:  # noqa: BLE001 -- the vendor's or the spine's refusal: not read, never held
                self._failed = True
                return None
            self._trees = {key: (started, _tree(data))}      # one token's tree at a time
            hit = self._trees[key]
        nodes = hit[1]
        if nodes is None:
            return None
        if path in nodes:
            return nodes[path]
        return frozenset() if not nodes else None

    def _ask(self, path: str, token: bytes) -> frozenset[str] | None:
        try:
            data = self._read(path, token)
        except Exception:  # noqa: BLE001 -- the vendor's or the spine's refusal: not read, never held
            self._failed = True
            return None
        # The vendor answers {path: {privilege: propagate}} for the path asked (measured: a path with no
        # ACL of its own carries what it inherits). Anything else (another key, a non-flag value, a cut
        # or fenced answer) is not that answer: unknown, never "holds nothing".
        if not (isinstance(data, dict) and set(data) == {path} and isinstance(data[path], dict)):
            return None
        held = data[path]
        if not all(isinstance(k, str) and type(v) is int and v in (0, 1) for k, v in held.items()):
            return None
        return frozenset(held)
