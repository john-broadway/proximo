"""The wire: one client for four planes, built from each plane's own config.

The four Proxmox products speak one REST shape (`{"data": ...}` bodies under `/api2/json`) with
FOUR ways of proving who is asking and TWO ways of encoding a body. That is the whole difference
between them, so it is data here, not four classes:

    pve   Authorization: PVEAPIToken=USER@REALM!ID=SECRET     form body, booleans as 1/0
    pbs   Authorization: PBSAPIToken=USER@REALM!ID:SECRET     form body, booleans as 1/0
    pdm   Authorization: PDMAPIToken ID:SECRET  (a SPACE)     JSON body, real booleans
    pmg   a ticket from POST /access/ticket, sent as the PMGAuthCookie cookie, plus the
          CSRFPreventionToken header on every mutation; on 401 the ticket is dropped and the
          login runs ONCE more                                 form body, booleans as 1/0

Everything else is shared and fail-closed: a secret is read from a file at call time and
registered with the output scrubber the moment it is read; a fingerprint pin replaces CA
validation with an exact-certificate match; and a client is REFUSED over a channel that
verifies nothing, because a read-only token is still a credential.

Env names are the estate's existing ones, so a box configured for the MCP door is configured
for this door with nothing added: PROXIMO_API_BASE_URL / PROXIMO_TOKEN_PATH for pve and
PROXIMO_<PLANE>_BASE_URL / _TOKEN_PATH (_PASSWORD_PATH and _USERNAME for pmg) for the rest,
each with _VERIFY_TLS, _CA_BUNDLE and _FINGERPRINT.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import httpx

from .errors import ProximoError, fingerprint_refused
from .secretfile import read_secret, refuse_exposed_secret, register_secret
from .tls import fingerprint_pinned_context, httpx_verify, parse_verify_tls

PRODUCTS = ("pve", "pbs", "pmg", "pdm")

#: Per-plane facts the vendor fixed and this module carries as data.
#:   prefix   the env-name infix ("" for pve, whose names predate the other planes)
#:   auth     "token" (a header built from the secret file) or "ticket" (pmg's login flow)
#:   header   the Authorization value with {t} for the token line; SPACE for pdm, "=" elsewhere
#:   body     "form" (1/0 booleans, the PVE family) or "json" (pdm's typed API wants real bools)
#:   timeout  seconds; pve's 30 is what every curated pve tool has always run under
_SPEC: dict[str, dict[str, Any]] = {
    "pve": {"prefix": "", "auth": "token", "header": "PVEAPIToken={t}", "body": "form", "timeout": 30},
    "pbs": {"prefix": "PBS_", "auth": "token", "header": "PBSAPIToken={t}", "body": "form", "timeout": 60},
    "pmg": {"prefix": "PMG_", "auth": "ticket", "header": "", "body": "form", "timeout": 60},
    "pdm": {"prefix": "PDM_", "auth": "token", "header": "PDMAPIToken {t}", "body": "json", "timeout": 60},
}


@dataclass(frozen=True)
class Plane:
    """One plane's connection settings. Secrets by PATH, read at call time, never held.

    `token_path`, `arm_source` and `readonly_source` are the names `arm.arm_state` reads, so a
    Plane answers the arm question directly: for pve they come from the estate's arm pair; for
    the other planes they are what their registry entry says, and silence there reads as NOT
    armed (arming is per target, never inherited from the pve box).
    """

    product: str
    base_url: str
    token_path: str                 # the token file; for pmg the CREDENTIAL file or the PASSWORD file
    username: str = "root@pam"      # pmg password mode only: who logs in
    verify_tls: bool = True
    ca_bundle: str | None = None
    fingerprint: str | None = None  # WIRE-ENFORCED exact-cert SHA-256 pin
    tls_strict: bool = True         # False relaxes ONLY a CA bundle's X509 strictness (PVE's root, #90)
    arm_source: str | None = None
    readonly_source: str | None = None
    # The per-target ENVELOPE, carried on the Plane so the core never reads a registry: a
    # target's `forbid` is a surface-specific ADDITION to the PROXIMO_FORBID floor, its
    # `rate_max`/`rate_window` compete with the env cap and the TIGHTEST wins (the 0.44 rules).
    name: str | None = None         # the registry name, for the receipt's `remote`
    forbid: tuple[str, ...] = ()
    rate_max: int | None = None
    rate_window: int | None = None
    # pmg only: `token_path` is a CREDENTIAL file, two lines `user@realm` then the password. The
    # identity rides in the file like a pve/pbs/pdm token's does, so swapping the file swaps WHO
    # logs in, and pmg has an arm pair. In password mode (a password file + a username from env)
    # a swap changes only the password, and arm.py refuses every pmg mutation.
    credential: bool = False
    # PVE node name to plain SSH destination, copied from the target registry and never shared mutable.
    nodes: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_env(cls, product: str) -> Plane:
        spec = _spec(product)
        p = f"PROXIMO_{spec['prefix']}"
        base_var = f"{p}BASE_URL" if product != "pve" else "PROXIMO_API_BASE_URL"
        cred = product == "pmg" and bool(os.environ.get(f"{p}CREDENTIAL_PATH"))
        if cred and os.environ.get(f"{p}PASSWORD_PATH"):
            raise RuntimeError(f"set {p}CREDENTIAL_PATH or {p}PASSWORD_PATH, not both: "
                               "they name two ways to log in and only one can be the one armed")
        secret_var = f"{p}CREDENTIAL_PATH" if cred else f"{p}PASSWORD_PATH" if product == "pmg" else f"{p}TOKEN_PATH"
        missing = [v for v in (base_var, secret_var) if not os.environ.get(v)]
        if missing:  # fail loud, never guess -- and name EVERY missing var, not the first
            if product == "pmg" and secret_var in missing:
                missing[missing.index(secret_var)] = f"{p}CREDENTIAL_PATH (or {p}PASSWORD_PATH)"
            raise RuntimeError(f"Missing required {product} env var: {', '.join(missing)}")
        what = _secret_what(product, cred)
        # The permission floor is checked at config load, as every plane's loader always has.
        refuse_exposed_secret(os.environ[secret_var], what)
        return cls(
            product=product,
            base_url=os.environ[base_var],
            token_path=os.environ[secret_var],
            username=os.environ.get(f"{p}USERNAME", "root@pam"),
            verify_tls=parse_verify_tls(os.environ.get(f"{p}VERIFY_TLS", "true")),
            ca_bundle=os.environ.get(f"{p}CA_BUNDLE") or None,
            fingerprint=os.environ.get(f"{p}FINGERPRINT") or None,
            tls_strict=parse_verify_tls(os.environ.get(f"{p}TLS_STRICT", "true")),
            # EACH PLANE ITS OWN PAIR. pve keeps PROXIMO_ARM_SOURCE; pbs and pdm read
            # PROXIMO_PBS_ARM_SOURCE / PROXIMO_PDM_ARM_SOURCE (and _READONLY_SOURCE), because
            # their token file carries its identity and a swap really changes who is asking.
            # pmg reads its pair only in CREDENTIAL mode, where the file carries the user too;
            # in password mode a swap cannot turn a read-only user into a write one (arm.py
            # says so in the refusal).
            arm_source=os.environ.get(_pair_var(product, "ARM_SOURCE")) or None if _pairs(product, cred) else None,
            readonly_source=(os.environ.get(_pair_var(product, "READONLY_SOURCE")) or None
                             if _pairs(product, cred) else None),
            credential=cred,
        )


def _pairs(product: str, credential: bool) -> bool:
    """Whether a plane reads an arm pair: every plane whose secret file names who is asking."""
    return product != "pmg" or credential


def _secret_what(product: str, credential: bool) -> str:
    if product != "pmg":
        return f"{product.upper()} token file"
    return "PMG credential file" if credential else "PMG password file"


def _pair_var(product: str, what: str) -> str:
    """The env name of a plane's arm pair: PROXIMO_ARM_SOURCE for pve (unchanged), else
    PROXIMO_<PLANE>_ARM_SOURCE."""
    return f"PROXIMO_{_spec(product)['prefix']}{what}"


def env_arm_view(product: str) -> SimpleNamespace:
    """The env box's ARM question for one plane, from env names alone: reads no secret and never
    raises, so a refusal never depends on a configured estate. The doors pass no config for the
    env box, and `arm_state(None)` grades the PVE pair; before this, PVE armed read as every
    plane armed (2026-09-28)."""
    cred = product == "pmg" and bool(os.environ.get("PROXIMO_PMG_CREDENTIAL_PATH"))
    pairs = _pairs(product, cred)
    # the SAME conflict from_env refuses, graded here too: a plan that reads armed for a box
    # execute cannot build is a plan that lies (lens 2026-09-28)
    conflict = ("PROXIMO_PMG_CREDENTIAL_PATH and PROXIMO_PMG_PASSWORD_PATH are both set: one way to "
                "log in, not two" if cred and os.environ.get("PROXIMO_PMG_PASSWORD_PATH") else None)
    return SimpleNamespace(
        product=product, name=None, base_url=env_base_url(product) or "",
        token_path=env_token_path(product) or "", credential=cred, conflict=conflict,
        arm_source=os.environ.get(_pair_var(product, "ARM_SOURCE")) or None if pairs else None,
        readonly_source=os.environ.get(_pair_var(product, "READONLY_SOURCE")) or None if pairs else None)


def env_base_url(product: str) -> str | None:
    """The plane's base URL from env, or None. A plain read: no secret is touched, nothing raises,
    so the spine can name the box for a rate budget before any config is built."""
    spec = _spec(product)
    return os.environ.get("PROXIMO_API_BASE_URL" if product == "pve" else f"PROXIMO_{spec['prefix']}BASE_URL") or None


def env_token_path(product: str) -> str | None:
    """The plane's served secret file path from env (pmg: the credential file, else the password
    file), or None. A plain read."""
    spec = _spec(product)
    p = f"PROXIMO_{spec['prefix']}"
    if product == "pmg":
        return os.environ.get(f"{p}CREDENTIAL_PATH") or os.environ.get(f"{p}PASSWORD_PATH") or None
    return os.environ.get(f"{p}TOKEN_PATH") or None


def _csv(value: Any) -> tuple[str, ...]:
    """A registry list field as a tuple: a comma string, a list of strings, or nothing."""
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(s.strip().lower() for s in value.split(",") if s.strip())
    if isinstance(value, list) and all(isinstance(i, str) for i in value):
        return tuple(s.strip().lower() for s in value if s.strip())
    raise ProximoError(f"a registry forbid must be a comma string or a list of strings, not {value!r}")


def plane_from_target(product: str, name: str, fields: dict[str, Any]) -> Plane:
    """One registry entry (PROXIMO_TARGETS, already resolved to `fields` and checked for its
    `kind`) as the Plane the engine governs and dials. Same names the backends read: base_url,
    token_path (pmg: credential_path, or password_path + username), verify_tls, ca_bundle,
    fingerprint, arm_source, readonly_source; plus the envelope. A missing base_url or secret
    path fails loud."""
    cred = product == "pmg" and bool(fields.get("credential_path"))
    nodes: tuple[tuple[str, str], ...] = ()
    if "nodes" in fields:
        if product != "pve":
            raise ProximoError(f"target {name!r}: nodes is supported only for pve targets")
        raw_nodes = fields["nodes"]
        if not isinstance(raw_nodes, dict):
            raise ProximoError(f"target {name!r}: nodes must be a table of node to SSH destination mappings")
        from proximo.core import shell
        checked: list[tuple[str, str]] = []
        for node, destination in raw_nodes.items():
            if not isinstance(node, str) or not shell.valid_node(node):
                raise ProximoError(f"target {name!r}: nodes keys must be valid PVE node names")
            if not isinstance(destination, str) or not shell.valid_destination(destination):
                raise ProximoError(f"target {name!r}: nodes values must be safe SSH destinations")
            checked.append((node, destination))
        nodes = tuple(checked)
    if cred and fields.get("password_path"):
        raise ProximoError(f"target {name!r} sets credential_path and password_path: one way to log in")
    secret_key = "credential_path" if cred else "password_path" if product == "pmg" else "token_path"
    missing = [k for k in ("base_url", secret_key) if not fields.get(k)]
    if missing:
        raise ProximoError(f"target {name!r} lacks {', '.join(missing)}")
    what = _secret_what(product, cred)
    refuse_exposed_secret(fields[secret_key], what)
    rate_max, rate_window = fields.get("rate_max"), fields.get("rate_window")
    for label, v in (("rate_max", rate_max), ("rate_window", rate_window)):
        if v is not None and (isinstance(v, bool) or not isinstance(v, int)):
            raise ProximoError(f"target {name!r}: {label} must be an integer, not {v!r}")
    return Plane(
        product=product,
        base_url=str(fields["base_url"]),
        token_path=str(fields[secret_key]),
        username=str(fields.get("username", "root@pam")),
        verify_tls=parse_verify_tls(str(fields.get("verify_tls", "true"))),
        ca_bundle=fields.get("ca_bundle") or None,
        fingerprint=fields.get("fingerprint") or None,
        tls_strict=parse_verify_tls(str(fields.get("tls_strict", "true"))),
        arm_source=fields.get("arm_source") or None,
        readonly_source=fields.get("readonly_source") or None,
        name=name,
        forbid=_csv(fields.get("forbid")),
        rate_max=rate_max,
        rate_window=rate_window,
        credential=cred,
        nodes=nodes,
    )


def _spec(product: str) -> dict[str, Any]:
    try:
        return _SPEC[product]
    except KeyError:
        raise ProximoError(f"unknown plane {product!r}; known planes: {', '.join(PRODUCTS)}") from None


def _base_url(product: str, url: str) -> str:
    """pdm is commonly configured as bare host:port; the API root is appended if absent."""
    url = url.rstrip("/")
    if product == "pdm" and not url.endswith("/api2/json"):
        url += "/api2/json"
    return url


def pmg_login(cfg: Plane) -> tuple[str, str]:
    """Who logs in to pmg, and with what. CREDENTIAL mode: the file's first line is `user@realm`,
    the rest the password, so the identity is exactly what the arm compared. Password mode: the
    username from config. A malformed credential file refuses by its shape, never its content."""
    if not cfg.credential:
        return cfg.username, read_secret(cfg.token_path, "PMG password file")
    user, _, password = read_secret(cfg.token_path, "PMG credential file").partition("\n")
    user, password = user.strip().lstrip("\ufeff"), password.strip()   # a BOM is not part of a name
    if "@" not in user or not password or "\n" in password:
        raise ProximoError("PMG credential file must hold two lines: user@realm, then the password")
    register_secret(password)
    return user, password


def _form(d: dict[str, Any]) -> dict[str, Any]:
    """The PVE family's type-checker wants booleans as 1/0 and rejects 'true'/'false'.
    None is DROPPED, not sent: an unset optional must be omitted, never serialized as "None"."""
    return {k: (1 if v is True else 0 if v is False else v) for k, v in d.items() if v is not None}


class Client:
    """`call(method, path, params) -> data`, one convention over four planes."""

    def __init__(self, cfg: Plane):
        self.cfg = cfg
        self.spec = _spec(cfg.product)
        self._ticket: str | None = None
        self._csrf: str | None = None
        self._lock = threading.Lock()
        # Normalised HERE, at the one place the URL is used, so a Plane built by hand and one built
        # from env dial the same root (PdmConfig normalised only in its loaders, never its constructor).
        self._client = httpx.Client(base_url=_base_url(cfg.product, cfg.base_url), verify=_verify(cfg),
                                    timeout=self.spec["timeout"])

    # --- proving who is asking -------------------------------------------------------------------

    def _headers(self, mutation: bool) -> dict[str, str]:
        if self.spec["auth"] == "token":
            # Read at call time; never logged; registered with the scrubber on first read.
            token = read_secret(self.cfg.token_path, f"{self.cfg.product.upper()} token file")
            return {"Authorization": self.spec["header"].format(t=token)}
        self._ensure_ticket()
        headers = {"Cookie": f"PMGAuthCookie={self._ticket}"}
        if mutation:
            headers["CSRFPreventionToken"] = self._csrf or ""
        return headers

    def _login(self) -> None:
        """pmg: POST /access/ticket. The password lives in the local scope of this call only."""
        username, password = pmg_login(self.cfg)
        r = self._client.post("/access/ticket", data={"username": username, "password": password})
        r.raise_for_status()
        data = r.json()["data"]
        self._ticket, self._csrf = data["ticket"], data["CSRFPreventionToken"]
        register_secret(self._ticket)  # session secrets the vendor handed us: never in an error either
        register_secret(self._csrf)

    def _ensure_ticket(self) -> None:
        # Double-checked so two threads that both see no ticket do not each log in.
        if self._ticket is None:
            with self._lock:
                if self._ticket is None:
                    self._login()

    def _relogin(self) -> None:
        with self._lock:
            self._ticket = self._csrf = None
            self._login()

    # --- the call --------------------------------------------------------------------------------

    def call(self, method: str, path: str, params: dict[str, Any] | None = None) -> Any:
        params = dict(params or {})
        mutation = method != "GET"
        r = self._send(method, path, params, self._headers(mutation))
        if r.status_code == 401 and self.spec["auth"] == "ticket":
            # An expired ticket, not a refusal: drop it, log in ONCE more, and retry ONCE.
            self._relogin()
            r = self._send(method, path, params, self._headers(mutation))
        r.raise_for_status()
        return r.json().get("data")

    def _send(self, method: str, path: str, params: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
        if method in ("GET", "DELETE"):
            # The query, for every plane. pve's curated tools folded it into the path; the wire
            # bytes are the same and one spelling here is one place to get it right.
            return self._client.request(method, path, headers=headers, params=_form(params))
        if method not in ("POST", "PUT"):
            raise ProximoError(f"{method} is not a method this wire sends")
        if self.spec["body"] == "json":
            return self._client.request(method, path, headers=headers, json=params)
        return self._client.request(method, path, headers=headers, data=_form(params))


def _verify(cfg: Plane) -> Any:
    """The TLS decision, fail-closed. A pin beats a bundle beats the system store; NOTHING is refused."""
    if not cfg.tls_strict and (cfg.fingerprint or not cfg.ca_bundle):
        # The relaxation is for a CA bundle and nothing else: a pin replaces chain checks and the
        # system store is no internal CA. Said here, never ignored, so nobody believes it applied.
        p = "PROXIMO_" + _spec(cfg.product)["prefix"]
        raise ProximoError(f"{p}TLS_STRICT=false (tls_strict) relaxes a CA bundle's X509 strictness and nothing "
                           f"else: set {p}CA_BUNDLE to the CA and no {p}FINGERPRINT, or unset it")
    if cfg.fingerprint:
        # WIRE-ENFORCED pin: exact-cert SHA-256 replaces CA/hostname validation, checked before
        # the credential is sent. A garbled pin refuses loudly here, never degrades into "no pin".
        try:
            return fingerprint_pinned_context(cfg.fingerprint)
        except ValueError as e:
            raise fingerprint_refused(cfg.product.upper(), e) from e
    verify: bool | str = cfg.ca_bundle if cfg.ca_bundle else cfg.verify_tls
    if verify is False:
        p = "PROXIMO_" + _spec(cfg.product)["prefix"]
        raise ProximoError(
            f"refusing to send the {cfg.product.upper()} credential over unverified TLS: set "
            f"{p}FINGERPRINT to the server cert's SHA-256 (strongest for a self-signed host), "
            f"{p}CA_BUNDLE to its CA, or {p}VERIFY_TLS=true. A read-only token is still a "
            f"credential -- it must not cross an unverified channel."
        )
    return httpx_verify(verify, strict=cfg.tls_strict) if isinstance(verify, str) else verify


def client(product: str, cfg: Plane | None = None) -> Client:
    """The plane's client, from THE CALLER'S config or, failing that, the environment.

    Building from env when a cfg was passed meant govern, the ledger and the pre-flight used one
    config while the client holding the socket and the token used another. And a cfg for a
    DIFFERENT plane is refused: a lens handed a pve Plane to a pbs row and the call was governed
    as pbs, dialled at the pve host with the pve token, and receipted as pbs. The product the
    caller resolved against and the product the config dials must be one product.
    """
    if cfg is not None and cfg.product != product:
        raise ProximoError(f"the address is {product} but the config given is for {cfg.product}")
    return Client(cfg or Plane.from_env(product))
