"""MINT: the runbook for a read credential and a write credential the VENDOR scopes and expires.

The core keeps no scope file and no arm TTL (2026-10-05); the token's ACL and its own `expire`
are the bounds. These tests hold the recipe to the vendor: every API path it prints is one the
vendor publishes, every grant lands on the scope asked for, the expiry is computed when the
command runs, and nothing a shell would misread rides in an unquoted argument.
"""
from __future__ import annotations

import json
import re

import pytest

from proximo.core import engine, mint
from proximo.core.doors import cli

ALL = mint.PRODUCTS
SCOPED = ("pve", "pbs", "pdm")


def _recipe(product, **kw):
    if kw.get("write") and product != "pmg":
        kw.setdefault("scope", ["/vms/101"])
    return mint.build_recipe(product, **kw)


def _text(recipe):
    return "\n".join(c for s in recipe["steps"] for c in s["commands"])


def _step(recipe, key):
    return next(s for s in recipe["steps"] if s["key"] == key)


# --- the vendor's own addresses ----------------------------------------------------------------

_API = [
    (re.compile(r"\bpvesh (create|set|get|delete) (/\S+)"), "pve"),
    (re.compile(r"\bpmgsh (create|set|get|delete) (/\S+)"), "pmg"),
]
_VERB = {"create": "POST", "set": "PUT", "get": "GET", "delete": "DELETE"}


def _printed_addresses(product, text):
    out = []
    for rx, plane in _API:
        out += [(plane, _VERB[v], p) for v, p in rx.findall(text)]
    out += [(product, m, p) for m, p in re.findall(r"-X (GET|POST|PUT|DELETE) \S+/api2/json(/\S+)", text)]
    out += [(pl, "GET", p) for pl, p in re.findall(r"proximo-core (\w+) GET (/\S+)", text)]
    return out


@pytest.mark.parametrize("write", [False, True])
@pytest.mark.parametrize("product", ALL)
def test_every_api_path_a_recipe_prints_is_one_the_vendor_publishes(product, write):
    """0.44's PMG recipe printed `pmgsh create /config/users`, which PMG does not publish (its
    users live at /access/users): an invented address in a runbook is a step that fails on the
    operator's box. Every printed address resolves in the vendor's own table."""
    addresses = _printed_addresses(product, _text(_recipe(product, write=write)))
    assert addresses
    for plane, method, path in addresses:
        assert engine.resolve(plane, method, path.rstrip("\\")).method == method, (plane, method, path)


# --- write needs a scope; the scope is what is granted -----------------------------------------

@pytest.mark.parametrize("product", SCOPED)
def test_a_write_credential_must_name_its_scope(product):
    with pytest.raises(ValueError, match="--write needs --scope"):
        mint.build_recipe(product, write=True)


@pytest.mark.parametrize("product", SCOPED)
def test_every_scope_is_granted_and_nothing_else(product):
    r = mint.build_recipe(product, write=True, scope=["/vms/101", "/pool/lab"])
    grant = "\n".join(_step(r, "grant")["commands"])
    for path in ("/vms/101", "/pool/lab"):
        assert path in grant
    granted = set(re.findall(r"acl (?:modify|update) (\S+)", grant)) | set(re.findall(r"'path=(\S+?)'", grant))
    assert granted == {"/vms/101", "/pool/lab"}


@pytest.mark.parametrize("product,both", [("pve", True), ("pdm", True), ("pbs", True)])
def test_privsep_planes_grant_the_token_and_the_user(product, both):
    """Every token plane is user ∩ token. PBS has no privsep TOGGLE, which 0.44's recipe (and
    this test, until the lens) read as no intersection: on a live PBS a token-only grant answered
    "permission check failed" (2026-06-15)."""
    r = mint.build_recipe(product, write=True, scope=["/vms/101"])
    grant = "\n".join(_step(r, "grant")["commands"])
    user, authid = r["user"], f"{r['user']}!{r['token_name']}"
    assert authid in grant
    assert (f"'{user}'" in grant or f"auth-id={user}'" in grant) is both


def test_a_pmg_user_is_created_enabled():
    """PMG publishes `enable` with default 0: without --enable 1 the user is born disabled and every
    login answers 401 (live, PMG 9.1, 2026-10-06). PVE, PBS and PDM default to enabled."""
    for write in (False, True):
        create = _step(mint.build_recipe("pmg", write=write), "create")["commands"][0]
        assert re.search(r"pmgsh create /access/users .*--enable 1", create)


def test_pmg_refuses_a_scope_and_says_why():
    with pytest.raises(ValueError, match="pmg has no ACL paths"):
        mint.build_recipe("pmg", write=True, scope=["/"])


@pytest.mark.parametrize("bad", ["vms/101", "/vms/101; rm -rf /", "/vms/$(id)", "/vms 101", "",
                                 "/vms//101", "/vms/101/", "/vms:101", "/a@b"])
def test_a_scope_a_shell_would_read_is_refused(bad):
    with pytest.raises(ValueError, match="not an ACL path"):
        mint.build_recipe("pve", write=True, scope=[bad])


# --- expire: finite by default for write, computed when the command runs ------------------------

@pytest.mark.parametrize("product", ALL)
def test_a_write_credential_expires_by_default_computed_at_run_time(product):
    r = _recipe(product, write=True)
    assert r["expire"] == mint.WRITE_EXPIRE_DEFAULT
    create = "\n".join(_step(r, "create")["commands"])
    assert "$(( $(date +%s) + 28800 ))" in create
    assert not re.search(r"expire\S*\s*=?\s*\"?1[0-9]{9}", create)     # no epoch baked at print time


@pytest.mark.parametrize("product", ALL)
def test_never_is_the_vendors_zero_and_only_when_asked(product):
    r = _recipe(product, write=True, expire="never")
    create = "\n".join(_step(r, "create")["commands"])
    assert re.search(r"expire[ =]0\b", create)
    assert mint.build_recipe(product)["expire"] == "never"            # read: no expiry unless asked


@pytest.mark.parametrize("bad", ["8", "0h", "8w", "-1h", "soon", ""])
def test_an_unreadable_lifetime_is_refused_not_turned_into_forever(bad):
    with pytest.raises(ValueError, match="--expire"):
        mint.expire_seconds(bad)


def test_lifetimes():
    assert [mint.expire_seconds(x) for x in ("30m", "8h", "2d", "never")] == [1800, 28800, 172800, 0]


# --- two credentials, two files, the arm pair -------------------------------------------------

@pytest.mark.parametrize("product", ALL)
def test_read_and_write_are_two_files_wired_as_the_arm_pair(product):
    read, write = mint.build_recipe(product), _recipe(product, write=True)
    assert read["token_file"] != write["token_file"]
    pre = "PROXIMO_" if product == "pve" else f"PROXIMO_{product.upper()}_"
    assert f"export {pre}READONLY_SOURCE={read['token_file']}" in _text(read)
    assert f"export {pre}ARM_SOURCE={write['token_file']}" in _text(write)


def test_pmg_read_and_write_are_two_users_in_credential_files():
    """PMG has no tokens: the credential is a user, and arm can switch users only when the file
    carries the user (credential mode); password mode takes the user from config."""
    read, write = mint.build_recipe("pmg"), mint.build_recipe("pmg", write=True)
    assert read["user"] != write["user"]
    assert "PROXIMO_PMG_CREDENTIAL_PATH" in _text(read) and "PASSWORD_PATH" not in _text(read) + _text(write)
    assert f"echo '{write['user']}'" in _text(write)


@pytest.mark.parametrize("product", ALL)
def test_the_base_url_is_the_name_the_wire_reads(product, monkeypatch):
    from proximo.core import wire
    line = next(c for c in _step(mint.build_recipe(product), "wire")["commands"] if "BASE_URL=" in c)
    name, _, value = line.removeprefix("export ").partition("=")
    monkeypatch.setenv(name, value)
    assert wire.env_base_url(product) == value


# --- no secret through a command line; nothing a shell misreads ---------------------------------

@pytest.mark.parametrize("product", ALL)
def test_verify_reads_the_file_itself(product):
    v = "\n".join(_step(_recipe(product, write=True), "verify")["commands"])
    assert v.startswith(f"proximo-core {product} GET /version")
    assert "cat " not in v and "curl" not in v


def _bangs_bash_expands(line: str) -> list[int]:
    """Offsets of every `!` an interactive bash would history-expand: outside quotes, or inside
    DOUBLE quotes. Only single quotes (and a backslash outside them) make it literal."""
    out, quote, i = [], None, 0
    while i < len(line):
        ch = line[i]
        if quote == "'":
            quote = None if ch == "'" else quote
        elif ch == "\\":
            i += 1
        elif ch in "'\"" and quote is None:
            quote = ch
        elif ch == '"' and quote == '"':
            quote = None
        elif ch == "!":
            out.append(i)
        i += 1
    return out


def test_the_bang_scanner_sees_what_bash_sees():
    assert _bangs_bash_expands("echo a!b") == [6]
    assert _bangs_bash_expands('echo "a!b"') == [7]
    assert _bangs_bash_expands("echo 'a!b'") == []
    assert _bangs_bash_expands("python3 -c 'print(\"a!b\")'") == []


@pytest.mark.parametrize("product", SCOPED)
def test_no_auth_id_bang_is_left_where_bash_expands_it(product):
    """Interactive bash expands `!write` as history: an auth-id outside single quotes is a broken
    command (the verify line shipped unquoted until the first read of the output)."""
    for line in _text(_recipe(product, write=True)).split("\n"):
        assert _bangs_bash_expands(line) == [], line


@pytest.mark.parametrize("product", ALL)
def test_the_secret_lands_in_a_600_file_never_on_stdout(product):
    r = _recipe(product, write=True)
    assert "umask 177" in _text(r) and f"chmod 600 {r['token_file']}" in _text(r)
    assert "SECRET" not in _text(r)          # the placeholder lives in notes, never in a command


def test_pdm_bootstrap_keeps_root_out_of_argv_and_out_of_shared_tmp():
    """The jar holds a root@pam ticket and the password is root's: a fixed /tmp name can be
    pre-created or symlinked by another user, and a password in curl's argv is in `ps`."""
    create = "\n".join(_step(_recipe("pdm", write=True), "create")["commands"])
    assert "/tmp/" not in create  # noqa: S108 -- asserts the path is ABSENT
    lines = create.split("\n")
    first = {k: next(i for i, x in enumerate(lines) if k in x) for k in ("umask 177", "mktemp")}
    assert first["umask 177"] < first["mktemp"]
    assert "password@-" in create and "password=$PDM_PASS" not in create
    assert 'printf %s "$PDM_PASS" | curl' in create


@pytest.mark.parametrize("product", ALL)
def test_no_recipe_names_a_fixed_file_in_shared_tmp(product):
    assert "/tmp/" not in _text(_recipe(product, write=True)) + _text(mint.build_recipe(product))  # noqa: S108 -- asserts the path is ABSENT


@pytest.mark.parametrize("product,sep", [("pve", "="), ("pbs", ":"), ("pdm", ":")])
def test_the_token_file_separator_is_the_vendors(product, sep):
    r = _recipe(product, write=True)
    assert f'print("{r["user"]}!{r["token_name"]}{sep}" + v' in _text(r)


# --- the doors -------------------------------------------------------------------------------

def test_the_core_door_prints_the_runbook(capsys):
    assert cli.main(["mint", "pve", "--write", "--scope", "/vms/101"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("proximo mint: pve write credential, scope /vms/101, expire 8h")
    assert "[5/5] verify" in out


def test_the_core_door_refuses_a_write_without_scope_as_usage(capsys):
    assert cli.main(["mint", "pbs", "--write"]) == cli.EXIT_USAGE
    assert "--write needs --scope" in capsys.readouterr().err


def test_the_core_door_json_is_only_json(capsys):
    assert cli.main(["mint", "pdm", "--write", "--scope", "/", "--json"]) == cli.EXIT_OK
    r = json.loads(capsys.readouterr().out)
    assert r["write"] is True and r["scope"] == ["/"] and r["expire"] == "8h"
    assert [s["key"] for s in r["steps"]] == ["create", "write", "grant", "wire", "verify"]


@pytest.mark.parametrize("flag,value", [
    ("user", "a@pbs;touch /tmp/PWNED;#"), ("user", "root"), ("user", "a b@pve"),
    ("token_name", "$(id>&2)"), ("token_name", "w'x"), ("token_name", "1abc"),
    ("token_file", "/tmp/f;id"),  # noqa: S108 -- a hostile input the recipe must refuse
    ("token_file", "~/x.token"), ("token_file", "a b"),
])
def test_every_typed_value_is_held_to_a_shape_a_shell_cannot_misread(flag, value):
    """Only --scope was checked; --user, --token-name and --token-file rode into `pvesh`,
    `generate-token`, a `python3 -c '...'` string and a redirect unvalidated (lens 2026-10-05)."""
    with pytest.raises(ValueError, match="printed into a shell command"):
        mint.build_recipe("pbs", write=True, scope=["/datastore/x"], **{flag: value})


@pytest.mark.parametrize("product", ["pve", "pbs"])
def test_the_user_step_is_a_no_op_when_the_user_exists(product):
    """The read recipe and then the write recipe share one user: the second `user add` failed
    "already exists" and a script stopped there (live, pve-test4, 2026-10-06)."""
    first = _step(_recipe(product, write=True), "create")["commands"][0].split("\n")[0]
    assert " || " in first and re.search(r"pveum user add|user create", first.split(" || ")[-1])


@pytest.mark.parametrize("product", ALL)
def test_a_re_mint_rotates_the_past_credential_of_the_same_name(product):
    """The vendor keeps an expired token (or user): tomorrow's 8h mint of `write` was refused as
    "already exists". The create step deletes the old one first, then creates."""
    create = _step(_recipe(product, write=True), "create")["commands"][0].split("\n")
    rotate = next(i for i, x in enumerate(create) if "# rotate" in x)
    make = next(i for i, x in enumerate(create)
                if re.search(r"pvesh create|generate-token|-X POST \S+/token/|pmgsh create", x))
    assert rotate < make, create


def _bash(script: str, **kw):
    """One printed line, run as the operator would run it. A fresh session: the subprocess inherits
    no controlling terminal, so a `</dev/tty` fails at once instead of waiting on a keyboard."""
    import subprocess
    return subprocess.run(["bash", "-s"], input=script, capture_output=True, text=True,  # noqa: S603, S607
                          timeout=20, start_new_session=True, **kw)


def _mkdir_line(product):
    r = _recipe(product, write=True)
    create = _step(r, "create")["commands"][0].split("\n")
    write = next(i for i, x in enumerate(create) if x.rstrip().endswith(f"> {r['token_file']}"))
    return create, write, next(x for x in create[:write] if "700" in x)


@pytest.mark.parametrize("product", ALL)
def test_the_secret_has_a_directory_a_umask_and_an_emptiness_check(product):
    """The vendor's create succeeds even when the redirect fails (no ~/.config/proximo on a fresh
    host), and the secret it printed once is gone. A failed create leaves an empty 600 file."""
    r = _recipe(product, write=True)
    create, write, _ = _mkdir_line(product)
    assert any("umask 177" in x for x in create[:write])
    assert any(f"test -s {r['token_file']}" in x for x in create[write:])
    assert create[-1] == 'umask "$OLD_UMASK"' or any('umask "$OLD_UMASK"' in x for x in create[write:])


@pytest.mark.parametrize("product", ALL)
def test_the_secrets_directory_is_made_when_missing_and_left_alone_when_present(product, tmp_path):
    """DRIVEN: the printed line, run with $HOME in a scratch dir. `install -d -m 700 "$(dirname F)"`
    RE-MODES a directory that already exists: `--token-file /tmp/x.token` as root turned /tmp from
    1777 to 700 and broke the box (lens, 2026-10-06). Made when missing, 0700; present, untouched."""
    import os
    _, _, line = _mkdir_line(product)
    env = {**os.environ, "HOME": str(tmp_path)}
    shared = tmp_path / ".config" / "proximo"
    shared.mkdir(parents=True)
    shared.chmod(0o1777)
    assert _bash(line, env=env).returncode == 0
    assert oct(shared.stat().st_mode & 0o7777) == oct(0o1777), line
    shared.rmdir()
    assert _bash(line, env=env).returncode == 0
    assert oct(shared.stat().st_mode & 0o7777) == oct(0o700), line


def test_the_pdm_password_prompt_reads_the_terminal_not_the_scripts_stdin():
    """DRIVEN: the recipe is pasted, or fed to `bash -s`; a bare `read` then takes its answer from
    the SCRIPT (the next line becomes root's password, and then a syntax error). Fed as a script
    with a sentinel line after it, the prompt must leave that line to bash: here there is no
    terminal, so the read fails at once and the sentinel still runs."""
    create = _step(_recipe("pdm", write=True), "create")["commands"][0].split("\n")
    prompt = next(x for x in create if "PDM_PASS" in x and "read " in x)
    out = _bash(prompt + "\necho SENTINEL-$((40+2))\n")
    assert "SENTINEL-42" in out.stdout, (out.stdout, out.stderr)


@pytest.mark.parametrize("listed,rc", [(True, 0), (False, 1)])
def test_the_pbs_user_check_exits_zero_only_when_the_user_is_listed(listed, rc):
    """DRIVEN, not grepped (lens, 2026-10-06: a grep let `u["user"]` and an inverted exit live):
    the printed `python3 -c` is fed a user list with and without the user. The list shape is the
    vendor's published one for GET /access/users, an array of objects keyed `userid`; the CLI's
    JSON output has not been captured live."""
    import subprocess
    import sys
    r = _recipe("pbs", write=True)
    first = _step(r, "create")["commands"][0].split("\n")[0].split(" || ")[0]
    snippet = re.search(r"python3 -c '([^']*)'", first).group(1)
    users = [{"userid": "root@pam", "enable": True}]
    if listed:
        users.append({"userid": r["user"], "enable": True, "comment": "Proximo"})
    out = subprocess.run([sys.executable, "-c", snippet], input=json.dumps(users),  # noqa: S603
                         capture_output=True, text=True)
    assert out.returncode == rc, out.stderr


def test_pdm_root_password_goes_only_to_this_hosts_own_listener():
    """`-k` skips the certificate: root's password may go only to loopback, never a network."""
    create = _step(_recipe("pdm", write=True), "create")["commands"][0]
    assert "https://localhost:8443/api2/json/access/ticket" in create and "<pdm-host>" not in create


@pytest.mark.parametrize("product", ALL)
def test_paths_are_home_relative_so_an_env_file_reads_them(product):
    """`~` stays literal in a sourced env file and the wire does not expand it."""
    assert "~" not in _text(_recipe(product, write=True)) + _text(mint.build_recipe(product))


# --- the capture, driven on the vendor's real output -----------------------------------------

_VENDOR_OUTPUT = {
    # PBS's generate-token takes no --output-format and answers `Result: {json}` (live, 4.2).
    "pbs": 'Result: {\n  "tokenid": "proximo@pbs!write",\n  "value": "S3CR3T"\n}\n',
    "pve": '{"full-tokenid": "proximo@pve!write", "info": {"privsep": "1"}, "value": "S3CR3T"}',
    "pdm": '{"data": {"tokenid": "proximo@pdm!write", "value": "S3CR3T"}}',
}


@pytest.mark.parametrize("product,sep", [("pve", "="), ("pbs", ":"), ("pdm", ":")])
def test_the_printed_capture_writes_the_token_line_from_the_vendors_real_output(product, sep):
    """Driven, not grepped: the `python3 -c` the recipe prints, fed what the vendor prints. The
    PBS one was written for `--output-format json`, which generate-token refuses; it got nothing
    and the token file was empty (live, 2026-10-06)."""
    import subprocess
    import sys
    r = _recipe(product, write=True)
    create = _step(r, "create")["commands"][0]
    made = create[re.search(r"pvesh create|generate-token|-X POST \S+/token/", create).start():]
    assert "--output-format" not in made.split("\n")[0] or product == "pve"
    snippet = re.search(r"python3 -c '([^']*)'", made).group(1)
    out = subprocess.run([sys.executable, "-c", snippet], input=_VENDOR_OUTPUT[product],  # noqa: S603
                         capture_output=True, text=True, check=True).stdout
    assert out == f"{r['user']}!{r['token_name']}{sep}S3CR3T"


# --- the token file: a place root's `>` may write ----------------------------------------------

@pytest.mark.parametrize("value", [
    "/etc/shadow",            # the lens's own example: root's `> /etc/shadow` truncates it
    "/proc/1/mem", "/usr/bin/env", "/var/lib/proximo/x.token", "/dev/sda", "/boot/x.token",
    "/ETC/x.token",           # a case-insensitive filesystem reads it as /etc
    "/vmlinuz", "/initrd.img", "/x.token",   # a file at the root: Debian's kernel symlinks live there
])
def test_a_token_file_under_a_system_directory_is_refused(value):
    """`_FILE` admitted any absolute path, so `--token-file /etc/shadow` printed a recipe whose
    `> /etc/shadow` runs as root and truncates it (lens 2026-10-06, MINOR, named since on every
    wrap). The file goes under $HOME or a data directory; the system's own trees are refused."""
    with pytest.raises(ValueError, match="system directory"):
        mint.build_recipe("pve", write=True, scope=["/"], token_file=value)


@pytest.mark.parametrize("value", [
    "-rf",                    # a flag, not a file: `chmod 600 -rf` reads it as an option
    "$HOMEevil/x.token",      # `$HOME` glued to a name is another variable
    "$HOME",                  # the directory itself, not a file in it
    "a/b.token",              # relative: the recipe runs in a cwd nobody chose
    "/a/../etc/x.token",      # a dot-dot segment walks out of the directory named
    "/a/./x.token", "/a/-x.token",
])
def test_a_token_file_is_home_relative_or_absolute_with_plain_segments(value):
    """The shape, not the place: relative, a dot-dot or dot segment, a flag, a glued `$HOME`."""
    with pytest.raises(ValueError, match="printed into a shell command"):
        mint.build_recipe("pve", write=True, scope=["/"], token_file=value)


@pytest.mark.parametrize("value", [
    "$HOME/.config/proximo/pve-write.token", "$HOME/etc/x.token", "$HOME/var/pve.token",
    "/srv/proximo/x.token", "/opt/proximo-2.token", "/home/ops/.proximo/pbs.token",
])
def test_a_plain_token_file_is_accepted_as_typed(value):
    """`$HOME/etc` is the operator's own directory: the system-tree rule reads absolute paths only
    (lens 2026-10-16: the first cut took index 1 of `$HOME/etc/x` too and refused it)."""
    assert mint.build_recipe("pve", write=True, scope=["/"], token_file=value)["token_file"] == value


@pytest.mark.parametrize("value", ["/home/ops/.ssh/authorized_keys", "$HOME/.ssh/x.token", "/srv/a/.ssh/b"])
def test_a_token_file_under_a_ssh_directory_is_refused(value):
    """`> ~/.ssh/authorized_keys` as root is a lockout, not a token (lens 2026-10-16)."""
    with pytest.raises(ValueError, match=r"\.ssh"):
        mint.build_recipe("pve", write=True, scope=["/"], token_file=value)
