"""Proximo configuration.

Loaded from the environment. The PVE token is referenced by *path*, never inlined —
Proximo reads it at call time and never logs it, so the credential stays
"run-but-not-read" (the operator's secrets vault is never echoed).
"""

from __future__ import annotations

import os
import re
import sys
import warnings
from dataclasses import dataclass

from ._secretfile import refuse_exposed_secret
from .audit import looks_like_head
from .audit_anchor import AnchorError, AnchorSink, build_anchor_sink

# Charset for PROXIMO_SSH_TARGET: hostname, SSH alias, or user@host.
# Must start with alphanumeric to block option-injection (e.g. -oProxyCommand=...).
# Empty string is allowed separately (local/on-host mode via is_local).
_SSH_TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]*\Z")

# PROXIMO_VERIFY_TLS — full falsy/truthy sets (matching audit_keyed's pattern).
# Unrecognized values keep TLS on (safe default) and emit a diagnostic warning.
_VTLS_FALSY = frozenset({"0", "false", "off", "no"})
_VTLS_TRUTHY = frozenset({"1", "true", "on", "yes"})
_TRUTHY = frozenset({"1", "true", "yes", "on"})  # generic bool-env values
_FALSY = frozenset({"0", "false", "off", "no"})  # generic opt-OUT set (same words as audit_keyed)

_DEFAULT_ENV_FILE = "~/.config/proximo/proximo.env"


def wants_help(argv: list[str]) -> bool:
    """True if -h/--help appears in argv. Stdlib-only so a face shim can call it BEFORE probing an
    optional extra — `proximo-http --help` must print usage and exit, never bind a socket."""
    return any(a in ("-h", "--help") for a in argv)


def print_face_usage(command: str, face_prefix: str, default_port: int, extra: str) -> None:
    """Print usage for a network-face console script (to stdout) — the `--help` a server-shim owes.

    Deliberately stdlib-only and importing nothing from the optional extra, so it runs on a wheel
    that has no starlette/uvicorn installed.
    """
    face = face_prefix.replace("_", "-")
    print(
        f"{command} — Proximo {face} face (server).\n\n"
        f"Runs a server on foreground; it takes NO configuration flags (only -h/--help). Everything\n"
        f"is set via PROXIMO_* environment variables:\n"
        f"  PROXIMO_{face_prefix}_HOST           bind host (default 127.0.0.1)\n"
        f"  PROXIMO_{face_prefix}_PORT           bind port (default {default_port})\n"
        f"  PROXIMO_{face_prefix}_TOKEN_FILE     bearer-token file (REQUIRED for a non-local bind)\n"
        f"  PROXIMO_{face_prefix}_ALLOWED_HOSTS  comma-separated Host allowlist\n"
        f"  ...plus the core PROXIMO_API_BASE_URL / PROXIMO_NODE / PROXIMO_TOKEN_PATH and the\n"
        f"     trust-spine vars (see packaging/proximo.env.example).\n\n"
        f'Install this face:  pip install "proximo-proxmox[{extra}]"'
    )


# Secret-file permission floor — shared with the PBS/PMG/PDM loaders and the network
# faces so every secret Proximo reads by path gets the same READ-side guard.
_refuse_exposed_secret = refuse_exposed_secret


def load_env_file() -> list[str]:
    """Source a ``proximo.env`` file into ``os.environ`` for the STDIO launch, then return the keys
    it set. Call this ONCE at process entry, before any ``ProximoConfig.from_env()``.

    Why this exists: daemon mode gets ``proximo.env`` via systemd's ``EnvironmentFile``, but a stdio
    MCP server only sees the client's inline ``mcpServers.env`` block — so a ``PROXIMO_*`` var set in
    the documented ``~/.config/proximo/proximo.env`` is silently ignored. That is a footgun, and
    fail-DANGEROUS for a security gate like ``PROXIMO_CONSENT_DIR`` (silently inert => mutations
    proceed ungated while the operator believes they need sign-off). See docs/known-issues.md.

    Non-breaking by construction: fills ONLY ``PROXIMO_*`` keys that are NOT already in ``os.environ``,
    so the real/inline env ALWAYS wins (an inline-config deployment is unaffected); only our namespace
    is touched (never PATH etc.); a missing file is a silent no-op (most deployments). What it DID load
    is printed to stderr so activation is legible, never silent. Path override: ``PROXIMO_ENV_FILE``."""
    path = os.environ.get("PROXIMO_ENV_FILE") or os.path.expanduser(_DEFAULT_ENV_FILE)
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except (FileNotFoundError, NotADirectoryError, IsADirectoryError):
        return []  # no file (or a bad path) => no-op; env-only deployments are unchanged
    except OSError as e:
        print(f"proximo: could not read env file {path!r}: {e}", file=sys.stderr)
        return []

    loaded: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]  # strip matching surrounding quotes
        if not key.startswith("PROXIMO_"):
            continue          # only our namespace — never let the file inject PATH/LD_*/etc.
        if key in os.environ:
            continue          # real/inline env always wins (no surprise for inline configs)
        os.environ[key] = val
        loaded.append(key)

    if loaded:
        print(f"proximo: loaded {len(loaded)} setting(s) from {path}: {', '.join(sorted(loaded))}",
              file=sys.stderr)
    return loaded


@dataclass(frozen=True)
class ProximoConfig:
    # --- Management half (Proxmox REST API) ---
    api_base_url: str          # e.g. "https://pve.example.lan:8006/api2/json"
    node: str                  # default node name, e.g. "pve"
    token_path: str            # file containing: USER@REALM!TOKENID=SECRET  (run-but-not-read)

    # --- Exec half (ssh -> pct) ---
    ssh_target: str = "pve"    # ssh host alias; or "local"/"localhost"/"" to run ON the host (direct pct)

    # --- Safety ---
    ct_allowlist: frozenset[str] = frozenset()  # empty=DENY all (fail-closed); "*"=allow all; else exact CTIDs
    enable_agent: bool = False  # OFF by default (API-only, safe). True enables qemu-agent ops on VMs.
    agent_allowlist: frozenset[str] = frozenset()  # empty=DENY all; "*"=allow all; else exact VMIDs
    audit_log_path: str = os.path.expanduser("~/.local/state/proximo/audit.log")
    verify_tls: bool = True
    ca_bundle: str | None = None  # path to the internal/Caddy CA bundle; preferred over disabling TLS verify
    fingerprint: str | None = None  # PROXIMO_FINGERPRINT — WIRE-ENFORCED exact-cert SHA-256 pin (self-signed PVE)
    enable_exec: bool = False  # OFF by default (API-only, safe). True enables ssh->pct exec (root-grant tradeoff).
    audit_key_path: str | None = None  # opt-in: path to an HMAC key file → keyed (tamper-resistant) PROVE ledger
    audit_keyed: bool = True  # PROXIMO_AUDIT_KEYED — keyed (HMAC) PROVE by default; "off"/"0"/"false"/"no" disables
    redact_ledger: bool = True  # PROXIMO_LEDGER_REDACT — fingerprint ct_psql SQL / ct_exec argv
    # by default; "0"/"false"/"off"/"no" records the full body instead
    expected_head: str | None = None  # PROXIMO_AUDIT_EXPECTED_HEAD — off-box-pinned head() for tail-attack detection
    anchor_sink: AnchorSink | None = None  # PROXIMO_AUDIT_ANCHOR_* — off-box head-pinning sink (None=off)

    @classmethod
    def from_env(cls) -> ProximoConfig:
        # Collect ALL missing required keys up front, never just the first: three sequential
        # dict subscripts inside one try only ever surfaced the first miss, forcing an operator
        # through a fix-one/rerun/hit-the-next cycle three times over (verdict 1.15). One pass,
        # one RuntimeError, every missing var named — same message shape when only one is
        # missing, so an existing narrow catcher on the single-var text is unaffected.
        _required = ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH")
        missing = [k for k in _required if k not in os.environ]
        if missing:  # fail loud, never guess
            raise RuntimeError(f"Missing required Proximo env var: {', '.join(missing)}")
        api_base_url = os.environ["PROXIMO_API_BASE_URL"]
        node = os.environ["PROXIMO_NODE"]
        token_path = os.environ["PROXIMO_TOKEN_PATH"]
        return cls._build(
            api_base_url=api_base_url,
            node=node,
            token_path=token_path,
            ssh_target=os.environ.get("PROXIMO_SSH_TARGET", "pve"),
            ct_allow_raw=os.environ.get("PROXIMO_CT_ALLOWLIST", ""),
            agent_allow_raw=os.environ.get("PROXIMO_AGENT_ALLOWLIST", ""),
            vtls_raw=os.environ.get("PROXIMO_VERIFY_TLS", "true"),
            ca_bundle=os.environ.get("PROXIMO_CA_BUNDLE") or None,
            fingerprint=os.environ.get("PROXIMO_FINGERPRINT") or None,
            enable_exec=os.environ.get("PROXIMO_ENABLE_EXEC", "false").lower() in ("1", "true", "yes", "on"),
            enable_agent=os.environ.get("PROXIMO_ENABLE_AGENT", "false").lower() in ("1", "true", "yes", "on"),
            audit_key_path=os.environ.get("PROXIMO_AUDIT_KEY_PATH") or None,
            audit_keyed_raw=os.environ.get("PROXIMO_AUDIT_KEYED", "true"),
            redact_ledger=os.environ.get("PROXIMO_LEDGER_REDACT", "true").strip().lower() not in _FALSY,
            expected_head_raw=os.environ.get("PROXIMO_AUDIT_EXPECTED_HEAD") or "",
            audit_log_path=os.environ.get("PROXIMO_AUDIT_LOG", cls.audit_log_path),
            anchor_sink_raw=os.environ.get("PROXIMO_AUDIT_ANCHOR_SINK", "none"),
            anchor_file_path=os.environ.get("PROXIMO_AUDIT_ANCHOR_FILE_PATH") or None,
        )

    @classmethod
    def from_env_ledger(cls) -> ProximoConfig:
        """Config carrying ONLY the instance PROVE-ledger settings, read from env.

        The PROVE ledger is ONE instance-wide chain and open_ledger() reads only the audit_*
        fields — never the PVE API triple. So this must NOT require PROXIMO_API_BASE_URL/NODE/
        TOKEN_PATH: a pure-targets deployment (PROXIMO_TARGETS set, no single-target env) still
        stands up its ledger. Before this, _instance_ledger() built from_env(), so
        `proximo doctor --target X` died with "Missing required Proximo env var:
        PROXIMO_API_BASE_URL" — the flagship diagnostic couldn't run in the flagship config.
        The API triple is defaulted to empty here (unused by the ledger; this config is never
        turned into a backend)."""
        return cls._build(
            api_base_url="", node="", token_path="",   # unused by the ledger
            ssh_target="pve", ct_allow_raw="", agent_allow_raw="",
            vtls_raw="true", ca_bundle=None, fingerprint=None,
            enable_exec=False, enable_agent=False,
            audit_key_path=os.environ.get("PROXIMO_AUDIT_KEY_PATH") or None,
            audit_keyed_raw=os.environ.get("PROXIMO_AUDIT_KEYED", "true"),
            redact_ledger=os.environ.get("PROXIMO_LEDGER_REDACT", "true").strip().lower() not in _FALSY,
            expected_head_raw=os.environ.get("PROXIMO_AUDIT_EXPECTED_HEAD") or "",
            audit_log_path=os.environ.get("PROXIMO_AUDIT_LOG", cls.audit_log_path),
            anchor_sink_raw=os.environ.get("PROXIMO_AUDIT_ANCHOR_SINK", "none"),
            anchor_file_path=os.environ.get("PROXIMO_AUDIT_ANCHOR_FILE_PATH") or None,
        )

    @classmethod
    def from_target(cls, fields: dict) -> ProximoConfig:
        """Build a config for a named registry remote (see proximo.targets).

        Same validation, defaults, and fail-closed warnings as from_env — they share _build.
        Secrets stay by reference (token_path), never inlined in the registry.
        """
        try:
            api_base_url = fields["base_url"]
            node = fields["node"]
            token_path = fields["token_path"]
        except KeyError as e:  # fail loud, never guess
            raise RuntimeError(f"target missing required field: {e.args[0]}") from e

        def _csv(key: str) -> str:
            # Accept a TOML list OR a comma string for allowlists; _build splits on commas.
            v = fields.get(key, "")
            return ",".join(str(x) for x in v) if isinstance(v, list) else str(v)

        return cls._build(
            api_base_url=api_base_url,
            node=node,
            token_path=token_path,
            ssh_target=fields.get("ssh_target", "pve"),
            ct_allow_raw=_csv("ct_allowlist"),
            agent_allow_raw=_csv("agent_allowlist"),
            vtls_raw=str(fields.get("verify_tls", "true")),
            ca_bundle=fields.get("ca_bundle") or None,
            fingerprint=fields.get("fingerprint") or None,
            enable_exec=bool(fields.get("enable_exec", False)),
            enable_agent=bool(fields.get("enable_agent", False)),
            audit_key_path=fields.get("audit_key_path") or None,
            audit_keyed_raw=str(fields.get("audit_keyed", "true")),
            # Ledger redaction is consumed per-target (exec tools read cfg.redact_ledger), but it is
            # an instance-wide intent: inherit the env PROXIMO_LEDGER_REDACT as the default so a
            # targets-mode operator's `export PROXIMO_LEDGER_REDACT=1` actually applies. An explicit
            # per-target `redact_ledger` still wins (a target may opt out of a redaction env turned on).
            redact_ledger=bool(fields.get(
                "redact_ledger",
                os.environ.get("PROXIMO_LEDGER_REDACT", "true").strip().lower() not in _FALSY)),
            expected_head_raw=str(fields.get("audit_expected_head") or ""),
            audit_log_path=fields.get("audit_log", cls.audit_log_path),
            anchor_sink_raw=str(fields.get("audit_anchor_sink", "none")),
            anchor_file_path=(str(fields["audit_anchor_file_path"])
                              if fields.get("audit_anchor_file_path") else None),
        )

    @classmethod
    def _build(
        cls,
        *,
        api_base_url: str,
        node: str,
        token_path: str,
        ssh_target: str,
        ct_allow_raw: str,
        agent_allow_raw: str,
        vtls_raw: str,
        ca_bundle: str | None,
        fingerprint: str | None,
        enable_exec: bool,
        enable_agent: bool,
        audit_key_path: str | None,
        audit_keyed_raw: str,
        redact_ledger: bool,
        expected_head_raw: str,
        audit_log_path: str,
        anchor_sink_raw: str = "none",
        anchor_file_path: str | None = None,
    ) -> ProximoConfig:
        """Shared validation/normalization/warnings for from_env and from_target.

        Both heads extract their required fields, then converge here so an env-configured box
        and a registry target get IDENTICAL fail-closed treatment.
        """
        ct_allowlist = frozenset(c.strip() for c in ct_allow_raw.strip().split(",") if c.strip())
        agent_allowlist = frozenset(c.strip() for c in agent_allow_raw.strip().split(",") if c.strip())

        _vtls_raw = vtls_raw.strip().lower()
        verify_tls = _vtls_raw not in _VTLS_FALSY
        audit_keyed = audit_keyed_raw.strip().lower() not in ("0", "false", "off", "no")

        # Normalize the pin before validating: a head() hexdigest is case-insensitive, and a copy-paste
        # from the migration warning often carries a trailing newline / surrounding spaces. Without this,
        # an uppercased/whitespaced pin raises here — and since _svc() runs from_env() for EVERY tool,
        # that bricks all of them, not just audit_verify. Genuinely-malformed values still raise.
        expected_head = expected_head_raw.strip().lower() or None
        if expected_head is not None and not looks_like_head(expected_head):
            raise RuntimeError(
                "PROXIMO_AUDIT_EXPECTED_HEAD must be a 64-char hex head() value "
                "(a sha256/hmac-sha256 hexdigest); got a malformed value"
            )

        # Secret-file permission floor: token + audit key must be owner-only (see the helper).
        _refuse_exposed_secret(token_path, "PVE token file")
        _refuse_exposed_secret(audit_key_path or "", "audit HMAC key file")

        # Validate the ssh target charset: empty string is the on-host sentinel (is_local);
        # any non-empty value must be a safe hostname/alias/user@host — a leading '-' would be
        # parsed by ssh as an option flag, enabling option-injection (e.g. -oProxyCommand=...).
        if ssh_target and not _SSH_TARGET_RE.match(ssh_target):
            raise RuntimeError(
                f"PROXIMO_SSH_TARGET must be a hostname or SSH alias "
                f"(characters: A-Z a-z 0-9 . _ @ -); got: {ssh_target!r}"
            )

        # Honest warnings (no phantom comments): least-privilege and TLS are load-bearing.
        if "*" in ct_allowlist:
            warnings.warn(
                "PROXIMO_CT_ALLOWLIST='*' — Proximo can reach ALL containers (least-privilege disabled).",
                stacklevel=2,
            )
        if _vtls_raw not in _VTLS_FALSY | _VTLS_TRUTHY:
            warnings.warn(
                f"PROXIMO_VERIFY_TLS={_vtls_raw!r} is not a recognized boolean value; "
                "TLS verification stays ON. Use 'false', '0', 'no', or 'off' to disable.",
                stacklevel=2,
            )
        if not verify_tls and not ca_bundle:
            # ApiBackend refuses to construct when verify_tls=False and no ca_bundle is set —
            # this warning fires immediately before that hard failure so operators can act.
            warnings.warn(
                "PROXIMO_VERIFY_TLS=false with no CA bundle — the backend will refuse to "
                "start (fail-closed). Set PROXIMO_CA_BUNDLE to a PEM CA file or use "
                "PROXIMO_VERIFY_TLS=true.",
                stacklevel=2,
            )
        if enable_exec:
            warnings.warn(
                "PROXIMO_ENABLE_EXEC is on — ssh->pct in-container exec enabled. This grants near-root on the "
                "PVE host; scope the ssh user and set a CTID allowlist.",
                stacklevel=2,
            )
        if enable_agent:
            warnings.warn(
                "PROXIMO_ENABLE_AGENT is on — qemu-agent ops enabled. Set a VMID allowlist "
                "(PROXIMO_AGENT_ALLOWLIST) to restrict which guests can be reached.",
                stacklevel=2,
            )
        if enable_agent and "*" in agent_allowlist:
            warnings.warn(
                "PROXIMO_AGENT_ALLOWLIST='*' — qemu-agent can reach ALL VMs (least-privilege disabled).",
                stacklevel=2,
            )
        if not audit_keyed:
            warnings.warn(
                "PROXIMO_AUDIT_KEYED is off — the PROVE ledger is running unkeyed (bare "
                "SHA-256, not HMAC-SHA256). Anyone with write access to the log file can "
                "forge entries without detection. Set PROXIMO_AUDIT_KEYED=true (the default) "
                "to restore HMAC-SHA256 tamper-evidence.",
                stacklevel=2,
            )
        if not redact_ledger:
            warnings.warn(
                "PROXIMO_LEDGER_REDACT is turned OFF — ct_exec/ct_psql/pve_agent_exec will "
                "record the full command/SQL body (which can carry secrets, e.g. a password "
                "on the argv) into the PROVE ledger, a durable file. Redaction (a sha256 "
                "fingerprint + kind + length) is the DEFAULT; unset this to restore it.",
                stacklevel=2,
            )
        # Independent CONSENT (PROXIMO_CONSENT_DIR). Read from the process env directly: CONSENT is
        # enforced env-side in consent.py (not per-target), so the precondition is about the process
        # and applies whether config came from_env or from_target. This IS the load-bearing honesty
        # note consent.py's docstring promises — the whole guarantee reduces to the boundary it names,
        # so fire it loudly whenever the gate is active.
        if os.environ.get("PROXIMO_CONSENT_DIR"):
            warnings.warn(
                "PROXIMO_CONSENT_DIR is set — Independent CONSENT is ACTIVE: every mutation now "
                "requires a single-use, out-of-band grant for its exact plan. This only closes the "
                "self-approval gap if the agent's OWN shell/user CANNOT write into that directory — "
                "if it can, the agent mints its own grant and the gate is cosmetic. Put the grant "
                "directory somewhere the agent cannot reach (a separate UID, or media/a host it lacks).",
                stacklevel=2,
            )
            if redact_ledger:
                # Symmetric to the redaction-OFF warning above: with redaction ON (the default) the
                # ledger `change` an approver sees is a sha256 fingerprint, NOT the command/SQL, so a
                # consent given off the ledger alone is blind. Point them at the leak-free channel.
                warnings.warn(
                    "CONSENT is active AND PROXIMO_LEDGER_REDACT is ON (the default): the ledger "
                    "'change' is a sha256 fingerprint, not the command/SQL. Approve ct_exec/ct_psql "
                    "from the dry-run plan's 'operator_cleartext' field (the un-redacted command, "
                    "preview-only — never written to the durable ledger), NOT from the redacted hash.",
                    stacklevel=2,
                )

        # Off-box PROVE anchor (PROXIMO_AUDIT_ANCHOR_*). build_anchor_sink raises RuntimeError on a
        # misconfigured sink (unknown type / file sink with no path). When a sink IS configured, fetch
        # its last pinned head so tail-attack detection turns on automatically:
        #   - FAIL-CLOSED: an unreachable/corrupt sink (AnchorError) => refuse to start. A configured
        #     anchor that can't be reached means the PROVE guarantee is silently gone — fail loud.
        #   - No manual pin + a sink head => auto-pin expected_head to it.
        #   - Manual pin that DIFFERS from the sink head => warn (drift), honor the manual pin (the
        #     sink is advisory; the operator has explicit control).
        #   - Sink reachable but empty (None) => first run; leave expected_head as-is.
        anchor_sink = build_anchor_sink(anchor_sink_raw, anchor_file_path)
        if anchor_sink is not None:
            try:
                pinned = anchor_sink.last_head()
            except AnchorError as e:
                raise RuntimeError(
                    f"PROXIMO_AUDIT_ANCHOR_SINK is configured but the off-box anchor is "
                    f"unreachable: {e}. Refusing to start without the PROVE tail-attack anchor "
                    f"(fail-closed). Fix the sink, or set PROXIMO_AUDIT_ANCHOR_SINK=none to run "
                    f"without it."
                ) from e
            if pinned is not None:
                if expected_head is None:
                    expected_head = pinned
                elif expected_head != pinned:
                    warnings.warn(
                        "PROXIMO_AUDIT_EXPECTED_HEAD is set manually AND differs from the off-box "
                        f"anchor's last pinned head ({pinned[:12]}...). Honoring the MANUAL pin; the "
                        "anchor value is advisory. If you rotated/upgraded, re-pin the manual value "
                        "or clear it to let the anchor pin automatically.",
                        stacklevel=2,
                    )

        return cls(
            api_base_url=api_base_url.rstrip("/"),
            node=node,
            token_path=token_path,
            ssh_target=ssh_target,
            ct_allowlist=ct_allowlist,
            audit_log_path=audit_log_path,
            verify_tls=verify_tls,
            ca_bundle=ca_bundle,
            fingerprint=fingerprint,
            enable_exec=enable_exec,
            audit_key_path=audit_key_path,
            audit_keyed=audit_keyed,
            redact_ledger=redact_ledger,
            expected_head=expected_head,
            anchor_sink=anchor_sink,
            enable_agent=enable_agent,
            agent_allowlist=agent_allowlist,
        )

    def ct_permitted(self, ctid: str) -> bool:
        """Least-privilege gate — fails CLOSED.

        Empty allowlist => deny everything (you must opt in).
        "*" => allow all CTIDs (warned about at load time).
        Otherwise => exact CTID match only.
        """
        if not self.ct_allowlist:
            return False
        if "*" in self.ct_allowlist:
            return True
        return str(ctid) in self.ct_allowlist

    def agent_permitted(self, vmid: str) -> bool:
        """Least-privilege gate for qemu-agent ops — fails CLOSED.

        Empty allowlist => deny everything (you must opt in).
        "*" => allow all VMIDs (warned about at load time).
        Otherwise => exact VMID match only.
        """
        if not self.agent_allowlist:
            return False
        if "*" in self.agent_allowlist:
            return True
        return str(vmid) in self.agent_allowlist

    @property
    def is_local(self) -> bool:
        """True when Proximo runs ON the PVE host itself.

        On-host: call `pct`/`pvesh` directly — no ssh hop, no quote layer.
        Off-host (default): reach the node via API token + ssh -> pct.
        Set ssh_target to "local"/"localhost"/"" for on-host mode.
        """
        return self.ssh_target.strip().lower() in ("", "local", "localhost")
