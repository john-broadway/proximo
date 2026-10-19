"""MINT -- the runbook for the two credentials Proximo serves: a read token, and a write token
the VENDOR scopes and expires.

The core keeps no scope file and no arm TTL (2026-10-05): a write token whose ACL names the
guests it may touch IS the scope, and its own `expire` IS the lease, both enforced server-side
where no bug of ours can widen them. `mint` prints the vendor's own commands that make such a
token. It makes NO API call, holds NO credential and writes NOTHING: minting a credential is the
operator's act, run on the vendor's host, and the token secret goes from the vendor straight into
a 600 file. One secret does cross a command line, and the recipe says so: PMG's `pmgsh` takes
the service password only as an argument (PDM's bootstrap sends root's password on stdin).
Re-minting ROTATES: a past mint's token of the same name is deleted first, so tomorrow's 8h token
is not refused as "already exists".

    proximo-core mint pve                                  # the read token
    proximo-core mint pve --write --scope /vms/101         # a write token for one guest, 8h
    proximo-core mint pbs --write --scope /datastore/main --expire 2d

Per-product credential shapes (the =/:/password trap):
    PVE  token file  USER@REALM!NAME=SECRET   Authorization: PVEAPIToken={file}
    PBS  token file  USER@REALM!NAME:SECRET   Authorization: PBSAPIToken={file}
    PDM  token file  USER@REALM!NAME:SECRET   Authorization: PDMAPIToken {file}
    PMG  password    the password, one line   ticket auth (PMG has no API tokens)

The grant gotcha, learned against live hosts: a PVE `--privsep 1` token, every PBS token and
every PDM token is privilege-SEPARATED, so effective permissions are user ∩ token and the grant
names BOTH (PBS has no privsep toggle, which is not the same as no intersection: a token-only
grant there read "permission check failed", 2026-06-15). PMG has no tokens and no ACL paths: its
roles are global, so a PMG credential cannot be scoped, only expired.
"""
from __future__ import annotations

import re
from typing import TypedDict


class Step(TypedDict):
    key: str            # create, write, grant, wire, verify (the stable --json contract)
    title: str
    commands: list[str]  # copy-pasteable; an entry may be a multi-line block
    notes: list[str]


class Recipe(TypedDict):
    product: str
    user: str
    token_name: str
    token_file: str
    write: bool
    scope: list[str]
    expire: str
    steps: list[Step]


PRODUCTS: tuple[str, ...] = ("pve", "pbs", "pmg", "pdm")
#: A write credential lives for one working session unless the operator says otherwise.
WRITE_EXPIRE_DEFAULT = "8h"

_READ_ROLE = {"pve": "PVEAuditor", "pbs": "Audit", "pdm": "Auditor", "pmg": "audit"}
_WRITE_ROLE = {"pve": "PVEVMAdmin", "pbs": "DatastoreAdmin", "pdm": "Administrator", "pmg": "admin"}
_PREFIX = {"pve": "", "pbs": "PBS_", "pmg": "PMG_", "pdm": "PDM_"}
_PORT = {"pve": 8006, "pbs": 8007, "pmg": 8006, "pdm": 8443}
_UNITS = {"m": 60, "h": 3600, "d": 86400}
# Everything the operator types is PRINTED INTO A SHELL COMMAND, so each is held to a shape a
# shell cannot misread: the vendor's own ACL-path syntax, a userid, a token name, a plain path.
_SCOPE = re.compile(r"/|(?:/[A-Za-z0-9_][A-Za-z0-9._-]*)+")
_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*@[A-Za-z0-9_][A-Za-z0-9._-]*")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9._-]*")
# The token file: `$HOME/...` or an absolute path of plain segments (no `.`/`..`, no leading
# `-`: `chmod 600 -rf` reads a flag). The recipe writes it with `>` AS ROOT, so the system's own
# trees are refused by name below (`--token-file /etc/shadow` truncated it; lens 2026-10-06).
_SEG = r"(?!\.\.?(?:/|$))[A-Za-z0-9_.][A-Za-z0-9_.-]*"
_FILE = re.compile(rf"\$HOME(?:/{_SEG})+|/{_SEG}(?:/{_SEG})*")
_SYSTEM_DIRS = frozenset({"bin", "boot", "dev", "etc", "lib", "lib32", "lib64", "proc", "run", "sbin", "sys", "usr",
                          "var"})
_DIR = "$HOME/.config/proximo"
_SEPARATOR_HINT = "Minted by hand and seeing 401? Check the separator: PVE '=', PBS/PDM ':'."


def _step(key: str, title: str, commands: list[str], notes: list[str]) -> Step:
    return {"key": key, "title": title, "commands": commands, "notes": notes}


def expire_seconds(expire: str) -> int:
    """`never` -> 0 (the vendor's own "no expiration"), `<n>m|h|d` -> seconds. Anything else is
    a ValueError: a lifetime we cannot read must not become a token that never expires."""
    if expire == "never":
        return 0
    m = re.fullmatch(r"([1-9][0-9]*)([mhd])", expire)
    if not m:
        raise ValueError(f"--expire {expire!r}: use <n>m, <n>h or <n>d (e.g. 8h), or `never`")
    return int(m.group(1)) * _UNITS[m.group(2)]


def _epoch(seconds: int) -> str:
    """The expiry as the shell computes it WHEN THE COMMAND RUNS, never a stamp baked in at
    print time: a runbook read tomorrow must still mint an 8h token, not a dead one."""
    return "0" if seconds == 0 else f"$(( $(date +%s) + {seconds} ))"


def _open(file: str) -> list[str]:
    """Before a secret is written: its directory exists (the vendor's create succeeds even when
    the redirect fails, and the secret it printed once is gone), and the umask makes it 600.
    `mkdir -p -m`, not `install -d -m`: install RE-MODES a directory that already exists, and
    `--token-file /tmp/x.token` as root turned /tmp from 1777 to 700 (lens, 2026-10-06)."""
    return [f'mkdir -p -m 700 "$(dirname {file})"', "OLD_UMASK=$(umask); umask 177"]


def _close(file: str) -> list[str]:
    """After: an empty file means the create failed (a 401, a typo) and must not be wired."""
    return [f"test -s {file} || echo 'mint: {file} is EMPTY: the secret was not captured; fix "
            "the error above and run this step again' >&2", 'umask "$OLD_UMASK"']


def _wire(product: str, token_file: str, write: bool, extra: list[str]) -> Step:
    p = f"PROXIMO_{_PREFIX[product]}"
    secret = "CREDENTIAL_PATH" if product == "pmg" else "TOKEN_PATH"
    if write:
        commands = [f"export {p}ARM_SOURCE={token_file}"]
        notes = ["This is the ARM source: arming serves these bytes; disarming serves the read "
                 "credential again. The vendor ends its life at `expire` whatever we do."]
    else:
        served = f"{_DIR}/{product}.served"
        commands = [f"install -m 600 {token_file} {served}",
                    f"export {p}READONLY_SOURCE={token_file}",
                    f"export {p}{secret}={served}"]
        notes = ["The SERVED file is what Proximo reads; arm swaps its bytes for the write "
                 "credential and disarm swaps them back."]
    base = "PROXIMO_API_BASE_URL" if product == "pve" else f"PROXIMO_{_PREFIX[product]}BASE_URL"
    commands += [f"export {base}=https://<{product}-host>:{_PORT[product]}"
                 + ("" if product == "pdm" else "/api2/json")]
    notes.append("Created on the vendor's host: if Proximo runs elsewhere, move the 600 file over "
                 "scp to the same path there, never through a chat or a transcript.")
    return _step("wire", "point Proximo at it", commands + extra, notes)


def _verify(product: str, authid: str, write: bool) -> Step:
    when = "after `arm` (the write credential is served only while armed)" if write else "now"
    commands = [f"proximo-core {product} GET /version"]
    notes = [f"Run {when}. Proximo reads the file itself: the token never lands in a command "
             "line where `ps` could show it."]
    if product != "pmg":
        arg = "userid" if product == "pve" else "auth-id"
        # QUOTED: an interactive bash reads `!write` in an auth-id as history expansion.
        commands.append(f"proximo-core {product} GET /access/permissions '{arg}={authid}'")
        notes.append("The vendor's own answer to what this token can do, path by path. "
                     "If it shows more than the scope you meant, fix the grant, not Proximo.")
        if product == "pbs":
            notes.append("PBS applies an ACL change a few seconds late (live, PBS 4.2: 403 at once, "
                         "200 six seconds on): if verify shows less than you granted, run it again.")
    return _step("verify", "ask the vendor what the credential can do", commands, notes)


def _pve(user: str, name: str, file: str, write: bool, scope: list[str], ttl: int) -> list[Step]:
    authid = f"{user}!{name}"
    role = _WRITE_ROLE["pve"] if write else _READ_ROLE["pve"]
    create = "\n".join([
        f"pvesh get /access/users/{user} >/dev/null 2>&1 || "
        f"pveum user add {user} --comment 'Proximo (least-privilege)'",
        f"pvesh delete /access/users/{user}/token/{name} 2>/dev/null || true  # rotate",
        *_open(file),
        f"pvesh create /access/users/{user}/token/{name} --privsep 1 --expire {_epoch(ttl)} "
        "--output-format json \\",
        "  | python3 -c 'import json,sys; v=json.load(sys.stdin)[\"value\"]; "
        f"print(\"{authid}=\" + v, end=\"\")' \\",
        f"  > {file}",
        *_close(file),
    ])
    grants = [line for path in scope for line in (
        f"pveum acl modify {path} --tokens '{authid}' --roles {role}",
        f"pveum acl modify {path} --users '{user}' --roles {role}")]
    return [
        _step("create", "mint the token on the PVE host (as root)", [create], [
            "pvesh + JSON is the robust capture: `pveum user token add` prints the secret "
            "ONCE to a table and it is gone. The secret goes straight into the file.",
        ]),
        _step("write", "the token file (what Proximo reads)", [f"chmod 600 {file}"],
              [f"Exactly one line: {authid}=SECRET. PVE uses '='.", _SEPARATOR_HINT]),
        _step("grant", f"grant {role} on {', '.join(scope)} to the token AND the user", grants, [
            "A --privsep 1 token's permissions are the INTERSECTION of the user's ACL and the "
            "token's: grant both, or a new user (no ACL) leaves the token able to do nothing.",
        ]),
        _wire("pve", file, write, []),
        _verify("pve", authid, write),
    ]


def _pbs(user: str, name: str, file: str, write: bool, scope: list[str], ttl: int) -> list[Step]:
    authid = f"{user}!{name}"
    role = _WRITE_ROLE["pbs"] if write else _READ_ROLE["pbs"]
    create = "\n".join([
        "proxmox-backup-manager user list --output-format json | python3 -c 'import json,sys; "
        f"sys.exit(not any(u[\"userid\"] == \"{user}\" for u in json.load(sys.stdin)))' || "
        f"proxmox-backup-manager user create {user}",
        f"proxmox-backup-manager user delete-token {user} {name} 2>/dev/null || true  # rotate",
        *_open(file),
        # NO --output-format: generate-token refuses it ("schema does not allow additional
        # properties") and answers `Result: {json}` (live, PBS 4.2, 2026-10-06).
        f"proxmox-backup-manager user generate-token {user} {name} --expire {_epoch(ttl)} \\",
        "  | python3 -c 'import json,sys; t=sys.stdin.read(); v=json.loads(t[t.index(\"{\"):])[\"value\"]; "
        f"print(\"{authid}:\" + v, end=\"\")' \\",
        f"  > {file}",
        *_close(file),
    ])
    return [
        _step("create", "mint the token on the PBS host (as root)", [create], [
            "The secret goes straight into the file; it is never echoed.",
            "generate-token takes --expire and answers `Result: {json}`; delete-token rotates "
            "(both live on PBS 4.2, 2026-10-06).",
        ]),
        _step("write", "the token file (what Proximo reads)", [f"chmod 600 {file}"],
              [f"Exactly one line: {authid}:SECRET. PBS uses ':', not '='.", _SEPARATOR_HINT]),
        _step("grant", f"grant {role} on {', '.join(scope)} to the token AND the user",
              [f"proxmox-backup-manager acl update {path} {role} --auth-id '{who}'"
               for path in scope for who in (authid, user)],
              ["A PBS token's permissions are user ∩ token, like PVE's: PBS has no privsep TOGGLE, "
               "not no intersection. A token-only grant reads \"permission check failed\" "
               "(live, 2026-06-15)."]),
        _wire("pbs", file, write, []),
        _verify("pbs", authid, write),
    ]


def _pdm(user: str, name: str, file: str, write: bool, scope: list[str], ttl: int) -> list[Step]:
    authid = f"{user}!{name}"
    role = _WRITE_ROLE["pdm"] if write else _READ_ROLE["pdm"]
    # ON THE PDM HOST, over loopback: root's password goes to a certificate nobody checked
    # (`-k`) only when that is this machine's own listener, never across a network.
    api = "https://localhost:8443/api2/json"
    jar = '-b "$JAR"'
    csrf = '-H "CSRFPreventionToken: $CSRF"'
    create = "\n".join([
        # The jar holds a root@pam ticket: a PRIVATE file made under the umask, never a fixed
        # name in shared /tmp that another user could pre-create or point a symlink through.
        *_open(file),
        "JAR=$(mktemp)",
        # FROM THE TERMINAL: pasted or fed to `bash -s`, a bare `read` takes the NEXT LINE of the
        # recipe as root's password and the shell then chokes on it.
        "read -rsp 'PDM root password (one bootstrap call, never stored): ' PDM_PASS </dev/tty && echo",
        # STDIN, not argv: `printf` is a builtin, so the password is never a process argument.
        f"CSRF=$(printf %s \"$PDM_PASS\" | curl -sk -c \"$JAR\" -X POST {api}/access/ticket \\",
        "  --data-urlencode 'username=root@pam' --data-urlencode 'password@-' \\",
        "  | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"data\"][\"CSRFPreventionToken\"])')",
        "unset PDM_PASS",
        f"curl -sk {jar} {csrf} -X POST {api}/access/users --data-urlencode 'userid={user}'"
        "  # an existing user answers an error and changes nothing",
        f"curl -sk {jar} {csrf} -X DELETE {api}/access/users/{user}/token/{name} >/dev/null  # rotate",
        f"curl -sk {jar} {csrf} -X POST {api}/access/users/{user}/token/{name} \\",
        f"  --data-urlencode \"expire={_epoch(ttl)}\" \\",
        "  | python3 -c 'import json,sys; v=json.load(sys.stdin)[\"data\"][\"value\"]; "
        f"print(\"{authid}:\" + v, end=\"\")' \\",
        f"  > {file}",
        *_close(file),
    ])
    grant = "\n".join([
        *(f"curl -sk {jar} {csrf} -X PUT {api}/access/acl --data-urlencode 'auth-id={who}' "
          f"--data-urlencode 'path={path}' --data-urlencode 'role={role}' --data-urlencode 'propagate=true'"
          for path in scope for who in (authid, user)),
        'rm -f "$JAR"; unset CSRF JAR',
    ])
    return [
        _step("create", "mint the token over REST, on the PDM host (PDM has no CLI verb for tokens)", [create], [
            "PDM returns the ticket as an HttpOnly cookie, hence the jar; it is removed after "
            "the grant. The token secret goes straight into the file.",
        ]),
        _step("write", "the token file (what Proximo reads)", [f"chmod 600 {file}"],
              [f"Exactly one line: {authid}:SECRET. PDM uses ':'; its header is space-separated.",
               _SEPARATOR_HINT]),
        _step("grant", f"grant {role} on {', '.join(scope)} to the token AND the user", [grant], [
            "PDM tokens are always privilege-separated: effective permissions are user ∩ token.",
            "PDM does not publish its ACL path vocabulary in its API schema: the path is passed "
            "as you gave it. Check it against PDM's documentation, then against verify.",
        ]),
        _wire("pdm", file, write, []),
        _verify("pdm", authid, write),
    ]


def _pmg(user: str, name: str, file: str, write: bool, scope: list[str], ttl: int) -> list[Step]:
    # PMG has no API tokens: the credential is a USER, so read and write are two users, and the
    # file carries the user beside the password (credential mode) so arming swaps BOTH. In
    # password mode the username comes from config and arm could not switch users at all.
    role = _WRITE_ROLE["pmg"] if write else _READ_ROLE["pmg"]
    create = "\n".join([
        "# on the PMG host: the credential file, two lines: the user, then a fresh password",
        *_open(file),
        f"{{ echo '{user}'; openssl rand -base64 30; }} > {file}",
        *_close(file),
        f"pmgsh delete /access/users/{user} 2>/dev/null || true  # rotate",
        # --enable 1: PMG publishes `enable` with default 0, so a user created without it is born
        # disabled and every login answers 401 (live, PMG 9.1, 2026-10-06).
        f"pmgsh create /access/users --userid {user} --role {role} --enable 1 --expire {_epoch(ttl)} "
        f"--password \"$(sed -n 2p {file})\"",
    ])
    return [
        _step("create", "create a dedicated PMG service user (PMG has no API tokens)", [create], [
            "`pmgsh` takes the password only as an argument, so it is in the process list for "
            "the moment the command runs: run it where no one else lists processes.",
        ]),
        _step("write", "the credential file (what Proximo reads)", [f"chmod 600 {file}"],
              [f"Exactly two lines: {user}, then its password. Wired as PROXIMO_PMG_CREDENTIAL_PATH."]),
        _step("grant", f"the {role} role is the user's own", [f"pmgsh set /access/users/{user} --role {role}"], [
            "PMG roles are global: audit is read-only, admin is full control. There is no path "
            "to scope a PMG credential to; its expiry is the only bound.",
        ]),
        _wire("pmg", file, write, []),
        _verify("pmg", user, write),
    ]


_BUILDERS = {"pve": _pve, "pbs": _pbs, "pdm": _pdm, "pmg": _pmg}


def build_recipe(product: str = "pve", user: str | None = None, token_name: str | None = None,
                 token_file: str | None = None, write: bool = False,
                 scope: list[str] | tuple[str, ...] = (), expire: str | None = None) -> Recipe:
    """The five steps for one credential. Pure: no I/O, no env, no host.

    A WRITE credential must name its scope (`/` or `/vms` say "everything" out loud) and gets a
    finite lifetime unless `expire="never"` is asked for by name. PMG refuses a scope: it has
    none to give."""
    if product not in PRODUCTS:
        raise ValueError(f"unknown product {product!r}: valid are {', '.join(PRODUCTS)}")
    scope = list(scope)
    if product == "pmg" and scope:
        raise ValueError("pmg has no ACL paths: its roles are global, so a PMG credential cannot "
                         "be scoped, only expired (--expire)")
    if write and product != "pmg" and not scope:
        raise ValueError("--write needs --scope: the token's ACL is the only bound on what it may "
                         "touch. e.g. --scope /vms/101, --scope /pool/<name>, or --scope /vms for "
                         "every guest")
    for path in scope:
        if not _SCOPE.fullmatch(path):
            raise ValueError(f"--scope {path!r} is not an ACL path: `/`, or segments like /vms/101, "
                             "/pool/lab, /datastore/main (letters, digits, . _ -)")
    expire = expire or (WRITE_EXPIRE_DEFAULT if write else "never")
    ttl = expire_seconds(expire)
    name = token_name or ("write" if write else "read")
    # PMG's read and write credentials are two USERS; elsewhere one user holds two tokens.
    user = user or (f"proximo-{name}@pmg" if product == "pmg" else f"proximo@{product}")
    file = token_file or f"{_DIR}/{product}-{name}.{'credential' if product == 'pmg' else 'token'}"
    for flag, value, shape in (("--user", user, _USER), ("--token-name", name, _NAME), ("--token-file", file, _FILE)):
        if not shape.fullmatch(value):
            raise ValueError(f"{flag} {value!r}: it is printed into a shell command, so it may hold only "
                             "letters, digits and . _ - (a user also one @; a file is $HOME/... or an "
                             "absolute path of such segments)")
    segments = file.split("/")[1:]
    if file.startswith("/") and (len(segments) == 1 or segments[0].lower() in _SYSTEM_DIRS):
        # `>` runs as root: /etc/shadow, /vmlinuz (a symlink into /boot). $HOME/etc is the operator's own.
        raise ValueError(f"--token-file {file!r} lives under a system directory or at the root of the filesystem; "
                         "the recipe writes it with `>` as root, so it goes under $HOME or a data directory of yours")
    if ".ssh" in segments:
        raise ValueError(f"--token-file {file!r} is under a .ssh directory; the recipe writes it with `>` as root")
    scope = scope or ([] if product == "pmg" else ["/"])
    steps = _BUILDERS[product](user, name, file, write, scope, ttl)
    return {"product": product, "user": user, "token_name": name, "token_file": file,
            "write": write, "scope": scope, "expire": expire, "steps": steps}


def render_text(recipe: Recipe) -> str:
    """The numbered, copy-pasteable runbook (the CLI default)."""
    mode = "write" if recipe["write"] else "read"
    lines = [f"proximo mint: {recipe['product']} {mode} credential, "
             f"scope {', '.join(recipe['scope']) or 'none (PMG roles are global)'}, "
             f"expire {recipe['expire']}",
             f"# user={recipe['user']}  token={recipe['token_name']}  file={recipe['token_file']}", ""]
    total = len(recipe["steps"])
    for i, step in enumerate(recipe["steps"], 1):
        lines.append(f"[{i}/{total}] {step['key']}: {step['title']}")
        for command in step["commands"]:
            lines.extend(f"    {line}" for line in command.split("\n"))
        lines.extend(f"  note: {note}" for note in step["notes"])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def add_mint_options(parser) -> None:
    """The flags both doors take (`proximo-core mint <plane>` and 0.44's `proximo mint`)."""
    parser.add_argument("--write", action="store_true",
                        help="the write credential: needs --scope, expires in "
                             f"{WRITE_EXPIRE_DEFAULT} unless --expire says otherwise")
    parser.add_argument("--scope", action="append", default=[], metavar="PATH",
                        help="an ACL path the token is granted on (repeatable): /vms/101, "
                             "/pool/<name>, /datastore/<store>; not on pmg")
    parser.add_argument("--expire", default=None,
                        help=f"lifetime: <n>m, <n>h or <n>d, or `never` (write default "
                             f"{WRITE_EXPIRE_DEFAULT}, read default never)")
    parser.add_argument("--user", default=None, help="service user (default: proximo@<product>)")
    parser.add_argument("--token-name", default=None, help="token name (default: read or write)")
    parser.add_argument("--token-file", default=None,
                        help="credential file: $HOME/... or an absolute path outside the system's own "
                             "trees (default: $HOME/.config/proximo/<product>-<name>.token, pmg: .credential)")
    parser.add_argument("--json", action="store_true", help="the recipe as JSON")


def recipe_from_args(args) -> Recipe:
    return build_recipe(product=args.product, user=args.user, token_name=args.token_name,
                        token_file=args.token_file, write=args.write, scope=args.scope,
                        expire=args.expire)
