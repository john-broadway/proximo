# Changelog

All notable changes to Proximo. Format loosely follows Keep a Changelog; versions are SemVer.

## [0.34.0] — 2026-08-12

**`pve_tasks_list` returns a windowed outcome envelope, and the repo now has exactly one
task-outcome classifier.** The first deliberate brick of the domain layer: classify, don't
mirror. Named in public on the forum thread before it was built; every commit in this
release passed an independent adversarial review before tagging, three rounds, two of
which held the release back.

### Added

- **`pve_tasks_list` windowed envelope**: `{returned, by_outcome, tasks}` with the lean
  field set (`upid`/`type`/`id`/`user`/`status`/`starttime`/`endtime`) and `fields` as the
  escape hatch (`all` = raw rows). `by_outcome` classifies each raw row server-side —
  `running` / `ok` / `warnings` / `failed` / `unknown` — by deterministic string matching
  on `endtime` + exitstatus text, never inference. Measured through the SDK's own
  `call_tool` on a live node: 6,676 → 5,589 wire tokens for 50 all-OK rows (16%; an
  all-OK window is the envelope's most favorable case — failed rows carry their full
  error text).
- **There is deliberately NO `total` in this envelope.** PVE truncates to the newest
  `limit` tasks before the server sees a row, so a full-history population count does not
  exist here — a count that only describes the fetched window must not wear the
  population's name. The tool description states this negatively (an all-ok `by_outcome`
  is never "no task ever failed") and routes "did anything fail" to `errors=True`, which
  live-provenly filters PVE's whole task history server-side and includes WARNINGS rows.
- **Release gate regenerates `lhm.plugin.json` and fails on drift** (before TOOLS.md,
  which derives from it): a skipped manual manifest regen could previously let both
  surfaces go stale together while the TOOLS.md drift check passed green.

### Changed

- **One task classifier repo-wide**: `pve_diagnose`'s `failed_tasks` now uses the same
  `classify_task_outcome` as the envelope. An error message that merely begins with the
  word "WARNINGS" now counts as failed on both surfaces (the exitstatus shape is
  `WARNINGS: n`); a statusless finished row classes `unknown` rather than failed; a
  garbage row fails closed into `unknown`, never open into a healthy-looking class.
- **`statusfilter` descriptions teach the live vocabulary**: `ok` / `error` / `warning`
  (each live-proven), and state negatively that `by_outcome` words (`warnings`,
  `failed`) and task-status words (`running`, `stopped`) are rejected by PVE with a 400.
  The old examples taught two values every call would 400 on.
- The health-check runbook prompt uses `pve_tasks_list(errors=True)` instead of "flag
  any that failed" over a 50-row window.

### Fixed

- Three test fixtures modeled finished task rows without `endtime` — a shape live PVE
  does not produce (live-probed: 0 of 179 errored rows lacked it) — and one modeled
  `errors=1` as a failures-only filter when live PVE includes WARNINGS rows. All are
  now live-faithful, and the tasks fixture honors `limit`/`errors`, so truncation can
  interact with the counts under test instead of being structurally invisible.

## [0.33.0] — 2026-08-12

**The mcp dual-major port: one build runs the SDK's 1.x (FastMCP) and 2.x (MCPServer).**
Tool estate unchanged at 906; no wire shape changes.

### Added

- **mcp 1.x AND 2.x support from one build** (`mcp>=1.24,<3`). Every spelling that differs
  between the majors crosses one seam, `proximo._mcpcompat`: server construction (Proximo's
  own version in the `initialize` handshake on both), the unknown-tool pointer (1.x keeps the
  low-level handler re-registration; 2.x builds the same outcome into a `call_tool` subclass
  override at construction), the renamed wire-model fields (`inputSchema`/`input_schema`,
  `isError`/`is_error`, `readOnlyHint`/`read_only_hint`, `serverInfo`/`server_info`), the
  in-process call result (1.x tuple / 2.x `CallToolResult`), and the Streamable-HTTP wiring
  (1.x `settings` mutation / 2.x kwargs). Detection is by import of the exact surface used,
  never a version parse.
- **CI proves both majors on every push**: the test matrix gains `mcp-major: ["1", "2"]` and
  asserts the installed major matches the leg instead of trusting the resolver.

### Changed

- **The mcp floor is measured, and the old one was false**: the declared `>=1.2.0` admitted
  SDK releases proximo cannot even import (`mcp.types.ToolAnnotations` is absent through
  1.6, and a tool-registration crash blocks import through 1.21.0). The floor is now
  `>=1.24`, the oldest release that imports AND runs the full suite. The `[mcp-http]`
  extra's separate `mcp>=1.8` pin is gone; the base floor covers it.
- **Our own artifacts stay on mcp 1.x this release, deliberately** (uv.lock, the hash-pinned
  requirements exports, the container, the SBOM). The published metadata admits both majors
  and both are suite-proven; flipping the shipped container's major is its own later act.

### Known SDK ceiling (documented, pinned by a test)

- **An mcp 2.x client cannot receive a single SSE event over 1 MiB** (its bundled HTTP
  library's default; mcp 2.0.0 exposes no knob), and its `call_tool` implicitly refreshes
  the full tool list. A server advertising the full unscoped 906-tool catalog (1,099,438
  bytes on the SSE data line — about 4.9% over the cap, so a modest description trim could
  bring a near-full catalog back under it) therefore breaks every SSE-mode Streamable-HTTP
  exchange for that client,
  whichever mcp major the SERVER runs, and it surfaces only as
  `SSE stream ended without a response`. The default lean facade, scoped
  surfaces (`PROXIMO_SURFACES`), JSON-response mode, and stdio are all unaffected.
  `tests/test_mcphttp_e2e.py` pins this ceiling so an SDK release that lifts it turns up loud.

### For embedders (owed since 0.32.0)

- `proximo.server` no longer re-exports the registration-scoping layer: `FULL_CATALOG`,
  `LEAN_CATALOG`, the scoping ladder, and `dispatch_tool` live in `proximo.door` (moved in
  the 0.32.0 architecture pass; the compatibility shims are gone). Import them from
  `proximo.door`, and read the catalogs through module attribute access, never a static
  `from` import of the dict object.

## [0.32.0] — 2026-08-11

**The estate-scale envelope batch (M4 Bucket 2) — BREAKING response shapes on nine
list tools, plus a default bound on two journals.** The M4 sweep classified all 229
list-returning tools (2026-08-11); Buckets 1/3/4 shipped or closed inside 0.31.x. This
release carries the one bucket that changes wire shapes, batched deliberately as an
honest pre-1.0 minor. Tool estate unchanged at 906; no tool added or removed.

### Breaking — bare list → counted envelope

Callers that indexed the response as a list must now read rows under the named key.
The envelope's counts are computed server-side from the complete listing, so a model
never has to count rows itself (the same fix that took a 12B model from 24/28 to
28/28 on the guest listing).

- **Five estate-scale inventory tools** now return `{"total", "by_<axis>", <rows-key>}`
  (sibling parity with `pve_list_guests` / `pve_cluster_resources`; no cap — capping
  unordered inventory would be dishonest):
  - `pdm_resources_list` → rows under `resources`, counted `by_type`
  - `pdm_pve_resources` → rows under `resources`, counted `by_type`
  - `pdm_pve_qemu_list` → rows under `vms`, counted `by_status`
  - `pdm_pve_lxc_list` → rows under `containers`, counted `by_status`
  - `pve_ha_resources_list` → rows under `resources`, counted `by_state`
- **Four PMG per-correspondent statistics tools** now return `{"total", "returned",
  <rows-key>}` **with a default cap of 100** — these rows scale with the estate's mail
  history (every distinct correspondent in the window) and were the context-blowup
  class the M4 audit flagged:
  - `pmg_statistics_sender` → `senders`, top-`limit` by `count` descending
  - `pmg_statistics_receiver` → `receivers`, top-`limit` by `count` descending
  - `pmg_statistics_contact` → `contacts`, top-`limit` by `count` descending
  - `pmg_statistics_detail` → `messages`, newest-`limit` by `time`
  Each takes `limit` (default 100): explicit `null` returns all rows untouched (API
  order); zero/negative is refused outright, never coerced. `total` always counts the
  complete set, so a capped slice can never masquerade as the population. The cap is
  client-side only — no invented parameter ever reaches the PMG API.

### Changed

- **`pbs_node_journal` / `pmg_node_journal` are default-bounded**: a bare call now
  returns the last 100 lines (sibling parity with `pve_node_journal`, which has
  defaulted `lastentries=100` all along). The bound is injected only when no
  `lastentries`, time range, or cursor is given — a ranged query never carries it,
  because `lastentries` conflicts with ranges/cursors on the PBS/PMG schema.
- **PyPI `Homepage`/`Documentation` URLs** now point at the project page
  (`john-broadway.github.io/proximo`) instead of circularly at the repo, matching the
  GitHub homepage field.

### Internal

- `projection.py` grew `cap_top` (top-N by numeric metric, descending) and
  `envelope_capped` (the by-less counted envelope); the timestamp/metric coercion
  chain (epoch, numeric-string, RFC 3339 with naive-pins-to-UTC) is now one shared
  `_metric` used by both `cap_newest` and `cap_top`, so a future fix cannot land in
  only one of them.

## [0.31.2] — 2026-08-08

**A full adversarial audit of 0.31.1 — eight independent finder teams, every finding
adversarially verified before it was believed, and every survivor fixed.** Thirty raw findings
reduced to twelve confirmed, a completeness pass surfaced three more (two medium, one
low-medium), and two independent review rounds on the fix diff itself caught defects in the
fixes before they shipped. Every fix carries a test proven red against the pre-fix source. No
new tools and no removed ones; the tool estate is unchanged at 906.

- **Webhook secrets no longer land in the audit ledger** (medium). The notifications plane
  widened its redaction key set to `{token, password, secret, header}` and redacts the
  `current` value on a delete plan — a webhook secret or custom auth header previously landed
  verbatim in the PROVE ledger and the returned plan. Mirrors what the PBS notifications plane
  already did.
- **Guest-config changes that cross into the host now rate HIGH and say why** (medium).
  `plan_config_set` escalates and names the crossing when a `net` value attaches a guest NIC to
  a host bridge or disables its firewall, or a `usb`/`serial`/`parallel` value passes a host
  device through — including the resource-mapping form `usbN=mapping=<id>`.
- **Container-create privilege was keyed on a parameter that does not exist** (low-medium).
  `plan_create` read a `privileged` key; the real PVE parameter is `unprivileged`, whose
  absence means privileged. The plan now reports the truth of the default instead of silently
  rating a privileged create as if it were confined.
- **PROVE fidelity: an in-container exec timeout is recorded as `error:timeout`, not a bare
  error.** On an ssh-transport timeout the remote command may be orphaned and still running, so
  a plain "error" (which reads as "did not happen") understated the state. The ledger outcome
  and the caller's message now both say the mutation may have partly or fully happened —
  verify guest state before assuming failure or retrying.
- **Caller badges always expire.** `mint_badge` never emits a badge without an `exp`; an absent
  expiry now gets a bounded 30-day default (previously: never-expiring, indefinitely
  replayable). The CLI says when the default applied.
- **Consent approvers see the real command.** The redacted `change` an approver sees is a hash.
  `plan_exec`/`plan_psql` now carry the un-redacted command in a preview-only field
  (`operator_cleartext`) surfaced in the dry-run the approver reads — never written to the
  ledger, and not part of the consent id, so existing consents are unaffected.
- **`--help` no longer starts a live server.** All four entrypoints (`proximo`,
  `proximo-http`, `proximo-mcp-http`, `proximo-a2a`) bound a socket or entered the stdio loop
  on `--help`, because no entrypoint parsed argv. Each now prints usage and exits before any
  env load or bind.
- **Smaller hardening, each with its own red-proven test:** `audit_verify` withholds its anchor
  publish when the verify failed (and no longer crashes when a first-run verify fails); HTTP
  errors are scrubbed to action + status before the ledger sees them (no internal host:port
  URLs); the web face rejects a body request with no usable Content-Length with 411, restoring
  the pre-buffer size cap; hardware-mapping free text rejects control characters and
  list-valued map entries are scanned too; LDAP 389 / LDAPS 636 join the sensitive-port list;
  the PBS "no cert validation" warning honors an active fingerprint pin; audit `in_flight`
  pairs executing/terminal entries per intent with a stack, so two identical overlapping ops
  cannot mask a stranded one; and an opt-in `PROXIMO_RECEIPT_DENYLIST` lets an operator name
  bare tokens (such as node names) that the receipt redaction regexes cannot see.

## [0.31.1] — 2026-08-06

**A HIGH advisory landed against `cryptography`, and our own published metadata was what kept
adopters from taking the patch.** GHSA-g6cj-pr64-35w5 (CVSS 8.2, published 2026-08-03) — PKCS#7
EnvelopedData decryption exposes a Bleichenbacher oracle through distinguishable errors and
timing — affects `cryptography>=44.0.0,<50.0.0` and is fixed in 50.0.0. The 0.31.0 wheel declares
`cryptography<50,>=49.0.0` on the `[a2a]`, `[http]` and `[mcp-http]` extras, so every adopter of a
face extra was held *inside* the affected range by a bound we shipped, with no resolution path out
of it. Nothing else in the graph capped it — `google-auth` and `pyjwt` both take cryptography
unbounded. We were the sole blocker.

- **Proximo does not call the vulnerable surface, and that does not settle it.** There are zero
  references to PKCS#7, EnvelopedData or S/MIME anywhere in the package; cryptography is used only
  for EC/ES256 JWS (caller badges, SIGNET card signing) and key serialization. So proximo's own
  exposure is nil. The defect being fixed here is what we *published*: a cap that made someone
  else's security patch unreachable, and a container that shipped the vulnerable library outright
  (`requirements/runtime.txt` is installed into the image under `--require-hashes`).
- **Both bounds move, not just the cap** — now `cryptography>=50.0.0,<51`. Widening `<50` to `<51`
  alone would still *permit* 49.0.0, so a constrained resolve could sit on the vulnerable pin with
  every check in this repo green. The floor is the half that expresses the security property, and
  it is now marked in `pyproject.toml` as a security bound rather than a feature floor, because the
  instinct next time will be to lower it.
- **The floor is now guarded, and it wasn't before.** The bounds test added in 0.27.1 asks only
  whether *some* upper bound closes the next major, so a floor lowered back to `>=49.0.0` — or all
  the way to `>=44.0.0`, re-admitting the entire affected range — left it green. A named test now
  asserts the floor separately. Both guards were proven by mutation and they are orthogonal: lower
  the floor and only the new one fires; remove the cap and only the old one fires.
- **Verified on the artifact, not the source.** The built wheel's `METADATA` reads
  `cryptography<51,>=50.0.0`; resolved in a clean environment, `proximo-proxmox[http]` takes
  cryptography 50.0.0, and forcing `cryptography==49.0.0` alongside it is *unsatisfiable*. A
  constraint that merely allows the fix would have passed the same checks while still permitting a
  vulnerable resolve, so the refusal is the half worth proving.
- **Neither automated path could land it**, which is why it needed a release rather than a merge.
  Dependabot's pip PR edits `requirements/*.txt` but cannot run `uv`, so `uv.lock` stayed at 49.0.0
  and the `requirements-drift` guard correctly refused it; the uv-ecosystem security job that would
  have moved the lock failed outright. The exports here are a real re-lock: exactly one pin moved.
- **Also in this release, from 0.31.0's deferred review findings:** `pve_doctor` no longer tells a
  correctly-configured plane to configure itself (its hint keyed on "serves zero tools", which is
  true of *every* plane under the default facade by design), the pinning test for a narrowing that
  never happens now asserts the silence instead of a bound, and two comments were corrected — one
  of which cited a pinning test that has never existed.
- Pinned GitHub Actions moved to current SHAs (CodeQL, docker/login-action,
  pypa/gh-action-pypi-publish and the release/mirror/Trivy workflows). No tool, behavior, or
  interface change in any of the above; the tool estate is unchanged.

## [0.31.0] — 2026-08-02

Minor, not patch, and deliberately: every change below is a fix, but an install that sets
`PROXIMO_SURFACES` goes from 569 advertised tools to 5 on upgrade. Nothing becomes unreachable
(a 800-combination matrix against 0.30.0 confirms zero reachability regressions) and the old
door is one named variable away, but a version that says "take me blindly" would be the wrong
signal for a surface that changes that much.

### Fixed
- **`PROXIMO_SURFACES` no longer opts you out of the default doorway.** Surfaces choose *which
  planes exist here*; they never choose *how many schemas load*. Shipped 0.30.0 treated them as
  one question, so scoping your planes silently kept the pre-0.30 catalog door: on a PVE+PBS box,
  `PROXIMO_SURFACES=pve,pbs` served **569 resident tools where the facade serves 5**, and removing
  a `PROXIMO_TOOLSETS=catalog` pin to "adopt the new default" bought **2 tools (571 → 569)**
  instead of the reduction 0.30.0 was built for. It failed silently: a working server, the old
  bill, no warning. Surfaces now narrow the searchable world and leave the door at the default
  facade;
  `PROXIMO_SURFACES=all` means every plane is *reachable*, not every schema *resident*, matching
  the shape `PROXIMO_AUTOSCOPE=off` already shipped. Ask for a door by name to get the old
  behavior: `PROXIMO_TOOLSETS=catalog` (auto-scoped full schemas) or `=all` (everything).
  Found by an external security/behaviour re-vet that probed the running server instead of
  trusting this changelog — the setup docs encourage `PROXIMO_SURFACES`, so the adopters most
  likely to hit it were the ones who followed them.
  **Five (5), not six:** naming planes scopes away the `memory` utility surface, so
  `proximo_recall` is not resident under `PROXIMO_SURFACES=pve,pbs` (measured: 5 tools,
  ~868 tokens). Name it to keep the one-call estate answer: `PROXIMO_SURFACES=pve,pbs,memory`.
  Estate memory itself stays on and keeps recording either way.
- **`PROXIMO_SURFACES=<utility surface>` no longer hides a five-tool server behind a search
  facade.** `memory`, `wiki` and `exec` are cross-plane utilities, not planes; scoped to those
  alone the searchable world is a handful of tools while the facade's own description told the
  model ~900 were searchable. Those tools are now served directly. Relatedly, that description
  now counts **this** server (312 on a PVE-only box) instead of always claiming ~900.
- **A second `_apply_surfaces()` no longer collapses the searchable catalog.** The prune removes
  `proximo_find_tools`, which defeated `apply_lean`'s idempotence guard, so a second pass
  snapshotted the 3-tool facade as the whole searchable world: measured **314 → 4** on the
  default door and **312 → 3** under surfaces. Pre-existing in 0.30.0 and embedder-facing only
  (every shipped entry point applies surfaces once). The guard that was supposed to cover this
  had a test that deleted every base-URL var, so no prune ran and it passed in the single
  configuration where the bug cannot fire.
- **The LobeHub manifest generator asked for a scope instead of a door.** It forced
  `PROXIMO_SURFACES=all`, which stopped meaning "full surface" the moment surfaces became
  scope-only — it would have published a **6-tool** manifest, and `docs/TOOLS.md` is generated
  from that same file. Now `PROXIMO_TOOLSETS=all`, pinned by a test, with a floor on the
  committed manifest so a thin regeneration cannot land silently.

### Corrected in this entry (stated, not rewritten away)
- An earlier draft of the bullet above said the facade serves **6** under
  `PROXIMO_SURFACES=pve,pbs`. It serves **5**; the sixth is `proximo_recall`, and the omission
  hid the memory interaction now documented above.
- It also credited 0.30.0 with announcing a "~99% reduction". 0.30.0 printed no such figure —
  that was a paraphrase presented as a prior claim.
- `docs/SETUP.md`'s cost table said `PROXIMO_SURFACES=pve` serves "a whole plane (311 tools)" at
  "~97,432 tokens". Both were wrong after this change and the count was wrong before it
  (`surface_keep` resolves **312**). The row now names the facade, the 312-tool searchable
  catalog, and the measured **~868 tokens**; the 97,432 figure belongs to the catalog door.
- `SECURITY.md` said `PROXIMO_SURFACES=all` "forces the full surface". It makes every plane
  searchable; `PROXIMO_TOOLSETS=all` is what serves the full surface.
- **`proximo doctor` now names the door it actually came in through.** With surfaces set it
  reported `PROXIMO_SURFACES=… — explicit` and said nothing about residency, so the operator had
  no line to disagree with — the silence that let the bug above live. It now names the facade and
  the scope together, and derives *how* the searchable catalog was narrowed (surfaces spec vs
  autoscope vs not narrowed) rather than asserting one mechanism for all three.

### Changed
- **Estate memory stays on by default, and now says so on every start**, naming the file:
  `estate memory ON — local inventory at <path>`, with the opt-out (`PROXIMO_MEMORY=0`) and the
  relocation (`PROXIMO_MEMORY_PATH`) in the same line. Same re-vet: the rails on that file
  (0600 before sqlite opens it, `O_NOFOLLOW`) were not the objection — a default that grows a
  plaintext inventory of your guests, nodes and targets *unannounced* was. A search index
  defaulting on is a small ask; an infrastructure inventory is a larger one, and an operator
  cannot weigh a file nobody told them about.

## [0.30.0] — 2026-08-01

### Changed
- **The default door is now the dynamic facade, and estate memory is on by default.** With
  nothing configured, `tools/list` serves six resident tools at **~1,449 tokens** —
  `proximo_find_tools` / `proximo_tool_schema` / `proximo_call` / `proximo_recall` plus the
  audit pair — with everything the box serves still searchable and callable through them.
  The measured reason: the previous default served the full plane catalog (~97k tokens on a
  single-PVE box, ~277k unscoped), 12x over the 8,192-token default context of a stock
  ollama install — dead on connect for a local model, and a silent tax on every other
  client that does not defer schemas. Rollbacks, by name: `PROXIMO_TOOLSETS=catalog`
  restores the pre-0.30 default (full schemas, auto-scoped to configured planes),
  `PROXIMO_TOOLSETS=all` the full surface, and `PROXIMO_MEMORY=0` opts out of the estate
  map (removing `proximo_recall` from the facade rather than leaving a call that could only
  fail). The map stays local, derived and rebuildable, beside the audit ledger the install
  already keeps; scoping remains context hygiene, not an authorization control — the token
  ACL is still the boundary. CLI verbs (`badge`, `mint`, `arm`, `disarm`, `reap`, `hello`)
  no longer run registry scoping at all, so their errors are not prefixed with scoping
  noise.

### Added
- **Search now finds the right tool with NOTHING configured — a vocabulary tier and lexical
  vectors, in the wheel.** Keyword search needs the operator's words to appear in a tool's
  text; "how much space is left for backups" shares no surface form with "storage usage —
  disk used and available", so it matched nothing. Two mechanisms, pure stdlib, no
  dependency, no model, no network, no download:
  `lexical.VOCABULARY` maps operator language onto Proxmox's own terms (memory→mem/ram,
  container→lxc/ct/guest, who/changed→audit/ledger) as **curated, auditable data — one
  readable line per mapping**, and it is now the single source keyword search draws its
  synonyms from, so the two can never drift. Behind that, hashed char-n-gram TF-IDF vectors
  rank whatever keyword left unanswered, marked `"match": "lexical"`.

  Measured on the real **905-tool** catalog: the first search builds the index (259 ms,
  cached per catalog for the process), every search after it is **~7 ms**, and the probes
  that used to miss now land (`who changed this vm's config` → `audit_verify`,
  `space left for backups` → the backup tools). Off-domain queries return **nothing**:
  admission requires a real word in common — a character-n-gram score alone once offered
  `pve_node_disk_wipe` ("MUTATION: wipe ALL data… NO UNDO") for "recipe for banana bread",
  because "recipe" and "wipe" share the fragment "ipe". Default-on because a search that
  needs configuration to work defeats the purpose; `PROXIMO_LEXICAL=off` disables the
  lexical tier.

  **The two vocabularies are deliberately separate.** `VOCABULARY` (wide, concept-level)
  serves ranking only; `KEYWORD_VOCABULARY` (narrow, near-exact renames) serves the keyword
  tier. Sharing one table was tried and reverted the same day after measurement: with the
  wide table feeding keyword AND-matching, "show" matched 824 of 905 tools and
  "check cluster health" 187, because concept jumps (health→status) land on words nearly
  every description carries — the OR-blowup lean mode exists to prevent. A blast-radius
  test against the tracked manifest now holds that line.

  Search is now a stack, each tier filling only what the one above left empty and marking
  its rows: **keyword** (exact) → **semantic** (opt-in, `PROXIMO_EMBED_URL`) → **lexical**
  (in-wheel). An unreachable embedder now degrades to lexical rather than all the way back
  to bare keyword.
- **Opt-in vector search over the estate sqlite — `PROXIMO_EMBED_URL`.** Point it at an
  OpenAI-compatible `/v1/embeddings` server you run (ollama, llama.cpp and vLLM all serve one)
  and two seams gain semantic recall, zero new dependencies (struct-packed float32 in sqlite,
  pure-python dot product): `proximo_find_tools` keeps its exact-keyword hits FIRST and
  unchanged, and vector matches only fill remaining room, each marked `"match": "semantic"`;
  `proximo_recall` gains an optional `query` that narrows entity rows to the top semantic
  matches while every count still covers the whole estate. Unset, nothing changes — no store,
  no network, byte-identical search. The index is lazy and self-healing (content-hashed; the
  embedding model name is part of the hash, so swapping models re-embeds instead of comparing
  vectors from different spaces), lives owner-only beside the audit log
  (`PROXIMO_VECTORS_PATH` overrides), and an unreachable embedder costs one loudly-degraded
  keyword-only search — never a failed facade. `PROXIMO_EMBED_MODEL`, `PROXIMO_EMBED_TIMEOUT`
  and `PROXIMO_EMBED_QUERY_PREFIX` (asymmetric-model instruction prefix, query-side only,
  no re-index to change) complete the knob set.

### Fixed
- **Every published token figure was understated by 16-20%, and is now measured from the
  wire.** `docs/SETUP.md`, `README.md` and the budget test all rebuilt the `tools/list`
  payload by hand from `name + description + inputSchema` — and a reconstruction cannot see
  a field it does not know about. It omitted **`outputSchema`, which FastMCP emits on 903 of
  905 tools and costs ~45,468 tokens: 16.4% of the entire doorway.** The corrected figures:
  full surface **231,700 → 277,376**, one plane **81,900 → 97,432**, one domain
  **7,750 → 9,123**, lean **555 → 582**, `PROXIMO_TOOLS` **1,130 → 1,273**. Nothing about
  the served surface changed — only the honesty of the number.

  Found by installing this package from source into a clean virtualenv and driving the real
  `proximo` binary over JSON-RPC, the way an adopter's client does, rather than calling the
  library in-process. The budget test now measures through the MCP layer's own serializer
  (`model_dump(by_alias=True, exclude_none=True)`), verified byte-for-byte against that live
  server, so this class of drift cannot recur.

  ⚠️ **`outputSchema` is not free to remove**, despite being near-boilerplate: the server
  also returns `structuredContent`, confirmed live on that adopter install, and MCP pairs the
  two. Suppressing it is a capability trade, recorded here and deliberately not taken.
- **A symlink at `PROXIMO_MEMORY_PATH` / `PROXIMO_VECTORS_PATH` is now refused.** `O_NOFOLLOW`
  did not cover it: a *dangling* symlink failed the `exists()` branch, hit `ELOOP` on the
  create, and the best-effort swallow returned as if nothing were wrong — then sqlite's own
  ordinary open followed the link and wrote the estate inventory at the link's target, at
  umask default (**0644 measured**), somewhere the operator never configured. A symlink to an
  *existing* file was worse in a second way: the permission-tightening branch chmod'ed the link
  TARGET, silently narrowing an unrelated file. Both shapes now raise, and the escape is
  asserted absent rather than merely "an error was raised".
- **`proximo_recall(detail="summary", query=...)` silently evicted the vector cache.** The
  summary shape carries no entity rows, so the filter had nothing to filter — but it still
  synced an EMPTY authoritative set, whose stale-key deletion wiped every cached entity vector
  for that target, forcing a full re-embed on the next real query. It also injected an
  `entities: []` key the summary shape omits, under a note claiming matches had been made. It
  now refuses and names the working combination.
- **An embedding endpoint's `index` field is validated as a 0..n-1 permutation before it is
  trusted to re-order.** A row count alone let `{index:-1}, {index:0}` land a vector in the
  *wrong* input's slot — text and vector silently misaligned, every later score wrong with
  nothing raised. Duplicate indices did the same. Batches are also now refused when
  dimensions are ragged (would crash a later search), non-finite (a NaN reaches every score
  and serializes as the bare token `NaN`, invalid JSON that can fail a strict client's parse
  of the whole response), or over a dimensionality ceiling (`PROXIMO_EMBED_MAX_DIM`, default
  16384 — an unbounded dim let a misbehaving endpoint inflate the store without limit).

  All found by an adversarial review of the feature commit. Two further findings were
  defensive branches that were real but had no test — a cross-embedding-space row skip
  (whose removal crashed *every* search on one stale row) and the off-catalog filter in
  `semantic_fill` — both now pinned. Nine mutants written against these fixes, nine killed.
- **`proximo_call` is now resident in every mode — scoping narrows what is ADVERTISED, never what
  is REACHABLE.** It was a closure inside `apply_lean`, so it existed only under
  `PROXIMO_TOOLSETS=dynamic`. Every other deployment — including the default, where autoscope is
  on and prunes 904 tools to 310 on a single-plane box — had no by-name dispatcher at all, so a
  pruned tool was not merely unlisted, it was **unreachable**: `Unknown tool` over stdio and a
  hard 404 on the A2A/HTTP/MCP-HTTP faces, with no recovery inside a live session. Dispatch now
  runs from `FULL_CATALOG`, snapshotted at import before any of the four scoping layers prunes.
  The tool count moves 904 → 905, and the `PROXIMO_TOOLS` doorway row 1,000 → ~1,130 tokens,
  because the hatch is a real fifth tool in that mode.

  Governance is unchanged and proven, not asserted: a mutation reached by name with no `confirm`
  comes back a PLAN with the backend untouched; an adversarial tool reached by name taints under
  **its own** name, not the dispatcher's, checked against a direct-call control. `proximo_call`
  is deliberately not classified adversarial — it carries no bytes of its own — and takes no
  `confirm` of its own, because a second gate satisfiable without the inner tool seeing one is
  the bypass the confirm sweep exists to prevent.

  A tool for a plane this box has not configured stays reachable and fails with its own named
  config error (`Missing required PMG env var: PROXIMO_PMG_BASE_URL`), which tells an operator
  what to fix where `unknown tool` would send them to build something that already exists. What
  the lean facade *advertises* is still narrowed to the configured planes — that separation is
  the point, and the dogfood lesson behind it is unchanged.

- **A published claim that was false: "every other tool still callable" in dynamic mode.**
  README, `docs/SETUP.md` and — worse, because a model reads it — `pve_doctor`'s own surfaces
  note all said it, in a sentence anchored to 904. Measured on a PVE-only box the callable set
  was **310**, because the lean catalog is snapshotted after autoscope prunes. Now stated as
  "every tool this box serves still callable", and pinned by a test, since 40 doctor tests
  passed while that string was wrong.

## [0.29.0] — 2026-07-31

### Changed
- **The doorway got ~16% cheaper, with no loss of surface.** Two schema cuts the previous
  measurement had ruled out, both mechanical and both measured rather than estimated:
  `anyOf:[{type:X},{type:null}]` is rewritten as the identical `type:[X,"null"]` (pydantic emits
  the long form on every optional parameter, so the same ~30 wasted chars rode on hundreds of
  properties); and `proximo_target` is no longer advertised when no `PROXIMO_TARGETS` registry is
  configured, because with no registry the only thing that parameter can do is return "no target
  registry configured" — it was pure payload on ~every tool of a single-box deployment. The same
  rule autoscope already applies to whole planes: do not advertise what this box cannot serve.
  A configured registry keeps the parameter untouched, asserted in both directions.
  Measured: full surface **276,000 → 231,700** tokens, one plane **97,000 → 81,900**, one domain
  **8,900 → 7,750**. Routing is unaffected — it has always run off the injected kwarg, never off
  the advertised schema, and the two structural guards that used the schema as a proxy for the
  injection now assert the signature they actually care about.

- **`PROXIMO_LEDGER_REDACT` now defaults to ON — the one default that failed zero-trust.**
  `ct_exec` / `ct_psql` / `pve_agent_exec` record a sha256 fingerprint (+ kind + length) of the
  command or SQL instead of the body. The body routinely carries a secret (a password on the
  argv) and the PROVE ledger is a durable file, so the permissive setting wrote credentials to
  disk for anyone who enabled exec and did not read the startup warning. Full-body recording is
  now the deliberate choice: set `0`/`false`/`off`/`no` to opt out, which still warns. A value
  the parser does not recognise keeps redaction ON — a typo must fail toward the safe state, not
  away from it. **Operators who relied on full-body ledger entries for forensics must now set
  this explicitly.**

### Added
- **Principal in the ledger — who-asked on every PROVE entry.** A declared process
  name-tag (`PROXIMO_PRINCIPAL`) stamps every ledger entry across all faces; on the
  network faces, signed ES256 caller badges (`PROXIMO_CALLER_KEYS_DIR`, operator-pinned
  keys) record a *verified* caller and, once pins exist, refuse an unverifiable caller
  fail-closed at the shared `webguard` perimeter — so all three HTTP-carried faces (HTTP,
  A2A and MCP-over-HTTP) inherit it. Adds `session_start`/`session_end`/`caller_arrived`
  ledger events, a `proximo badge` mint/inspect CLI, and a `doctor` principal block.
  Identity, not authority: the Proxmox token ACL stays the only authorization boundary.
  Opt-in and inert until configured; an unconfigured deployment's ledger bytes are
  unchanged.

## [0.28.0] — 2026-07-30

Two honesty fixes, one in what the software *says* and one in what it *leaves behind*.

- **The RRD tools no longer let a model call a rolling window "today."** A reviewer on the
  Proxmox forum asked an agent for "utilization charts for today" and got a confident answer
  built on the last 24 hours, which spans two calendar days. The model was not hallucinating:
  the schema offered a `day` timeframe and described it only as "the specified timeframe," so
  `day` read as "today." These endpoints accept no start/end, so a calendar day genuinely
  cannot be served — and now every one of them says so, in the text the model actually reads.
  Fixed across the whole class rather than the reported site: `pve_node_rrddata`,
  `pmg_node_rrddata`, `pbs_node_rrd`, `pbs_datastore_rrd`, and `proximo_baseline`, with the
  disclosure pinned by tests at all five. Reported by **meyergru**, whose earlier report shaped
  0.26.0's context work.

- **`proximo reap` can now clean up after dead sessions, opt-in.** Restoring the read-only key
  was always only half the job: nothing ever removed a dead session's token + lock files, so a
  session dir accretes one pair per session forever — a credential store nobody audits (the
  deployment this pattern was found on had 167 files for 0 live arms). With
  `PROXIMO_REAP_UNLINK_DAYS=N` set, `reap` also unlinks session files that are proven
  read-only, unheld (kernel flock, same oracle as reaping), and idle more than N days —
  removal happens under the file's own exclusive lock so it cannot race a starting session,
  and an ex-armed file is restored first (fresh mtime), making it eligible only after a further
  full TTL. Orphan lock files and dangling symlinks (no target = provably not a token) sweep
  on the same terms; any other unreadable file stays put as an error. `--dry-run` runs the
  same probes and stops short of the unlink itself, so the preview cannot say "would unlink"
  anywhere the real run would refuse. Unset or garbled = no unlinking:
  deletion is the destructive verb, so a typo must not enable it — deliberately the opposite
  fallback direction from `PROXIMO_REAP_GRACE`.

## [0.27.1] — 2026-07-30

**A fresh `pip install proximo-proxmox` had been broken for two days, and nothing in this repo
could see it.** `pyproject.toml` declared `mcp>=1.2.0` with no upper bound. The MCP SDK published
2.0.0 on 2026-07-28, and 2.x removed `mcp.server.fastmcp` — the module `proximo/server.py` imports
on its 29th line. From that release onward every new install off PyPI, of **any** proximo version,
resolved mcp 2.0.0 and then failed to import the package at all. `uvx proximo-proxmox`, the
zero-install path the README leads with, was broken the same way.

- **`mcp` is now capped below 2**, and every other runtime and adopter-facing requirement bounds
  its major (`httpx<1`, and the `[a2a]` / `[http]` / `[mcp-http]` extras). The cap is a hotfix, not
  a verdict on 2.x: porting off `mcp.server.fastmcp` is real work and is not this release.
- **Why the suite stayed green through all of it:** `uv.lock` and the hash-pinned
  `requirements/*.txt` hold mcp at a 1.x, so CI, the container image and every local run were fine.
  Those pins deliberately never enter the wheel, because PyPI consumers resolve their own
  dependencies — which is exactly the hole. **A lockfile protects the build; only a bound in the
  published metadata protects an adopter.** A new test reads the metadata an adopter actually
  resolves against and fails on any unbounded major, so this cannot recur silently.
- Nothing else changed: no tool, no behavior, no interface. The tool estate stays 904.

## [0.27.0] — 2026-07-30

**Two additions, both opt-in and inert until you set their env var, plus three honesty repairs
found by reading the code and the output rather than the tests.** The tool estate grows 900 to
904. A default install's served surface does not change: the four new tools are opt-in, and
autoscope prunes them when their env var is unset.

**Local knowledge, so the model stops guessing.** Two seams that let the server answer from
something it already holds instead of a fresh round trip.

- **Tier-1 estate memory** (`PROXIMO_MEMORY=1`). `proximo_recall` returns an age-stamped local
  map of the estate; `proximo_baseline` returns per-guest cpu/mem distribution rollups derived
  from `rrddata`, stored-first. Both are derived, local, and never a health verdict.
- **The wiki seam reader** (`PROXIMO_WIKI=1`). `proximo_wiki` does BM25 search and
  `proximo_wiki_read` reads one section, over a **local** docs index. No documentation content
  ships: **you build the index**, which keeps the forum and wiki licensing question out of the
  picture and means yours is fresher than any frozen pack. Proximo ships the reader and the
  contract, and **the contract is published** in `docs/SETUP.md` ("The wiki index") so any builder
  that writes the pinned schema qualifies. Retrieved text is classified ADVERSARIAL and trips the
  taint marker, because a solved forum thread can carry "now run pve_delete_guest" as easily as a
  fix.
- **Said plainly, because it is the honest limit:** an unfed memory map used to answer `total: 0`
  beside a note explaining that zero was not a claim about the estate. A 4B local model answered
  "0" anyway, three runs of three at temperature 0, without ever calling the tool the note named.
  Removing the number left a hole and the model filled the hole with zero. So these tools now
  **refuse** rather than return anything answer-shaped: they name the reason, name the remedy, and
  record it. The 4B still sometimes emits "0". We stopped supplying the lie. We cannot stop a
  downstream model inventing one, and this is not a fix for that.

**Write authority you can toggle, and that cannot outlive its session.**

- **`proximo arm` / `proximo disarm`** swap the token the server reads: read-only by default, a
  pre-minted write token while armed. Client-agnostic by construction. The session key arrives as
  an explicit `--session` or `PROXIMO_SESSION_KEY` and is never sniffed from a client's
  environment. It performs the swap **and discloses** whether the arm is a REAL boundary or merely
  ADVISORY, because whether an arm restrains anyone is a file-ownership question, not a code one.
  It grants no capability the caller lacked: anyone who can run `arm` could already copy that file
  into place. What is new is the disclosure.
- **`proximo reap`** restores read-only for sessions that ended while armed. **The kernel is the
  liveness oracle:** a serving process holds a shared `flock` on a sidecar lock file for its whole
  life, and reap tries an exclusive non-blocking lock, which can only succeed once every holder is
  gone. The kernel releases those on exit, crash and kill alike, so this survives `SIGKILL` where
  a heuristic would not.
- New env: `PROXIMO_ARM_SOURCE`, `PROXIMO_READONLY_SOURCE`, `PROXIMO_SESSION_DIR`,
  `PROXIMO_SESSION_KEY`, `PROXIMO_REAP_GRACE`. `PROXIMO_TOKEN_PATH` is reused.

### Fixed

- **Autoscope could serve a near-empty server.** `_apply_surfaces` carried two autoscope
  implementations. When `memory` and `wiki` joined `exec` as surfaces that are not data planes,
  only one of the two guards learned about it. With `PROXIMO_MEMORY=1` and no detectable data
  plane (an unreadable targets file, a target kind outside the surface map, or the opt-in set
  before the plane), the served registry narrowed from 904 tools to 5. It announced that on
  stderr only, which MCP clients do not surface, so the operator saw a 5-tool server and no
  reason for it. There is now one guard, shared.
- **`disarm` could report success while installing write authority.** The boundary disclosure
  assessed the arm source and never the read-only source, though a disarm's correctness rests
  entirely on the latter. If the read-only source held the write token's bytes, `disarm` printed
  DISARMED and installed write authority. It now refuses on a byte-identical pair, and reports a
  boundary for the file it actually depends on. The read-only token is the everyday credential,
  which makes it the one likeliest to be left loose.
- **The boundary check judged permission bits and ignored ownership.** Permission bits do not bound
  the owner: a mode-400 token **owned by another uid** is fully rewritable by that uid, and whoever
  owns the containing **directory** can unlink the file and put a different one there whatever its
  mode says. Both were unchecked, so a nobody-owned token in a nobody-owned directory reported as a
  REAL boundary. The verdict now covers the file's owner, the directory's owner, and the directory's
  mode, honoring the sticky bit so `/tmp`-shaped directories are not counted as a substitution
  surface for someone else's file. `SECURITY.md`'s recipe is corrected to match: mode `600` alone
  was never sufficient, because it says who may open a file and nothing about who may replace it.
- **The REAL verdict printed three things it had not checked.** It read "is 600, owned by this uid,
  in a directory no second uid can write" for a mode-400 file owned by uid 65534 in a directory
  owned by uid 65534. It now prints the mode, the file's owner and the directory's owner it actually
  observed.
- **A refusal claimed live write authority that did not exist.** The byte-identical-sources refusal
  ended "Write authority is still live until you do" unconditionally, but it refuses *before*
  installing anything, so with a genuine read-only token in place the sentence was false. It now
  reads the served token and says which case it is. A false alarm is the same class of defect as a
  false all-clear.
- **Four wiki refusals named a tool that does not ship.** They told the operator to build the
  index with a private, unpublished builder tool that is not part of this package, so every
  adopter was handed a remedy they could not run. It read as "you missed a step" when the truth is
  "you build this yourself, and here is the contract". The refusals now point at the published
  contract, and no shipped file names a private builder.
- **A garbled `PROXIMO_ARM_TTL` contradicted its own enforcement.** LEASE fails closed on an
  unparseable opt-in and holds the arm expired. `arm` parsed the same value to "no TTL" and
  printed "no auto-expiry", about an arm that was already dead. Both the text output and the
  `--json` shape now distinguish an unparseable lease from an absent one.

**From the independent pre-release review** (a second lens over this whole entry's diff):

- **The local tools demanded PVE configuration they never use.** `proximo_recall`, `proximo_wiki`
  and `proximo_wiki_read` operate on local SQLite, but each opened with a PVE-strict service call —
  so a PBS-only box with `PROXIMO_WIKI=1` was served the tools and then refused with an env error
  naming a subsystem the operator never configured. The calls are gone, and the ledger fallback now
  tolerates a PVE-less box, so the wiki seam's local-first story is true on the deployments it was
  designed for. The seam tests mocked the service call, which is exactly why they missed it; the
  new pins use the real one.
- **`audit_verify` demanded PVE configuration to verify a local file.** The PROVE pillar's own
  verification tool — the one every surface serves — crashed with a raw env error on a box with
  no PVE config, though the ledger it verifies is local. Found by a hostile first-contact pass
  on two smallest-footprint boxes; the fourth site of the same defect class this review caught.
- **`proximo_baseline`'s stored path demanded PVE configuration it promised not to need.** The
  docstring says a stored rollup answers "with NO PVE call", but an eager service unpack required
  PVE env before the memory-only path could run — the same defect in milder form, caught by the
  local verification pass on top of the review. The api now resolves lazily, on the pull path only.
- **`arm --json` dropped `dir_owner_uid`.** The text render printed it; the JSON mirror of the same
  verdict omitted it, leaving structured consumers to regex the reasons prose. Parity restored.
- **`doctor`'s scoping text kept a stale guard.** It still read `- {"exec"}` after the
  utility-surface set grew memory and wiki; it now uses the same `_UTILITY_SURFACES` guard as
  autoscope, so a future utility-only entry point cannot make it call a full surface "auto-scoped".

**From a hostile first-contact pass** — six adopter personas ran the product cold on the smallest
footprints (zero config, PBS-only, a small model's doorway) and tried to make it embarrass us:

- **`proximo doctor --product {pve,pbs,pmg,pdm}`.** The doctor was hardcoded to PVE, so SETUP's own
  "verify your boundary" step dead-ended a PBS-only operator with an env error about a plane they
  never configured. `pmg` now dispatches to its own doctor; `pbs`/`pdm` have no doctor tool yet and
  say exactly that, pointing at `proximo mint --product <plane>`, whose runbook carries the check.
  A bare `proximo doctor` on a box where another plane *is* configured now names that plane.
- **A connection failure names what to check.** DNS failure, refused connection and timeout used to
  reach the caller as a raw OS errno through the first tools the README recommends, while `doctor`
  degraded gracefully on the identical fault. Both now share one seam; the ledger still records the
  real exception type.
- **Refusals that name their remedy.** The four fingerprint refusals (one per plane) forwarded a raw
  validator error; they now name that plane's env var and the expected 64-char digest. Both
  allowlist denials named neither the variable nor how to add an entry. The memory and wiki readers
  leaked a bare sqlite error when their path pointed at a directory instead of a file. Config now
  reports **every** missing environment variable at once instead of one per run.
- **The tool search speaks the operator's nouns.** `proximo_find_tools` returned nothing for "delete
  vm" or "remove container" because the catalog says *guest*; a small model could miss the most
  destructive tool in the surface. And `ct_exec`/`ct_psql` lost their MUTATION marker to summary
  truncation — the one line that model reads. Both fixed, the marker now pinned by a structural test.
- **Counted numbers say which configuration they describe.** "Serves 900" matched no real install;
  measured live it is 310 for a single-plane default and 896 with all four data planes and exec off,
  against 904 registered. Every token figure the docs print is now checked against live measurement
  in CI, so the tables cannot drift into fiction.

_Recent: 0.26.0 stopped the tool surface costing what it covers, taking the connection-time schema
from ~348k tokens to ~555 in the smallest doorway._

## [0.26.0] — 2026-07-28

**The surface stops costing what it covers.** Reported from outside, with a measurement:
Proximo was unusable with a local model. The full tool catalog crossed to every client on
every connection — **~348,000 tokens** of schema before a single question, past a 200k window
on its own, and ~122,000 for a single auto-scoped plane. An 8k-32k local model died at
connection time. The report was correct, and measuring it confirmed it was worse than reported.

Nothing had ever measured this. The surface grew 365 → 493 → 603 → 715 → 900 with no gate
anywhere costing what a jump did to the client's context.

- **Schema slimming — 348k → 276k tokens, no capability change.** 84,000 of those tokens were
  one sentence: the per-call target selector's description, identical on 899 of 900 tools.
  Another 24,000 were pydantic writing a `title` beside every parameter name that already said
  the same word. `title` is presentational in JSON Schema and never reaches validation.
- **Scoping, in the field-standard shape** (GitHub's MCP server vocabulary, so it is one
  adopters already know). Most specific wins: `PROXIMO_TOOLS` (exact names) → `PROXIMO_TOOLSETS`
  (23 domain groups: `pve.guests`, `pve.ceph`, `pbs.tape`, `pmg.quarantine`, …) →
  `PROXIMO_SURFACES` (planes, unchanged) → auto-scope. A typo refuses startup rather than
  quietly serving a different set than you picked.
- **`PROXIMO_TOOLSETS=dynamic` — the whole surface on a small model.** Three facade tools resident
  (`proximo_find_tools` / `proximo_tool_schema` / `proximo_call`) plus the ever-present
  `audit_verify` at **~555 tokens**; the other
  ~311 stay callable, just not resident. Dispatch routes through the same internal path a direct
  call uses, so the PLAN gate, the PROVE ledger write and your token's ACL all still apply — a
  smaller doorway, not a looser one.

- **Counted lean list responses — the payload half of the same report.** Schema bloat wastes
  context; response bloat corrupts answers: with the full 25-field guest listing (PSI pressure
  metrics, byte counters) in a 16k context, a 12B local model counted 19 guests on a 28-guest
  cluster — complete correct data, wrong answer. Lean rows alone were not enough (the same
  model then counted 24), so counting moved server-side: `pve_list_guests` and
  `pve_cluster_resources` now return `{total, by_status|by_type, rows}` with the rows in a
  curated identity/state field set by default (~4× and ~3× smaller on that same cluster). With
  the counted envelope the model answered 28/18/10 correctly, three runs out of three.
  `fields='all'` keeps the raw rows, `fields='vmid,mem,…'` picks columns, and a field no row
  carries refuses with the list of fields that ARE available — an error that teaches, never a
  silently empty answer.

Measured on a real 28-guest cluster: `dynamic` 4 tools / ~555 tokens · `PROXIMO_TOOLS` with
three names / ~1,040 · `pve.guests` 27 tools / ~8,900 · `PROXIMO_SURFACES=pve` 310 / ~97,000.
Toolsets reach roughly 32k-class models; `dynamic` is the mode that reaches ~8k.

**PROVE now records the interval, not just the result.** Mutations write an `executing` entry
before the call and a terminal entry after, sharing a derived intent id, so an operation that
died mid-flight is visible instead of invisible. Previously a SIGKILL between the call and the
outcome write left an executed mutation with **no ledger entry at all**; `audit.in_flight()`
now names what was running. Verified by killing a real mutation, not by simulating one. The
interval lives in the same hash-chained log, so the crash record is tamper-evident. Reads are
unchanged — a read that dies changed nothing. Refusals carry no intent: they never started.

Also: `pve_doctor` reports the active scoping layer across all four (it knew only
`PROXIMO_SURFACES`, and silently misreported boxes scoped any other way).

_Recent: 0.25.0 closed the PMG plane and added a fourth transport (715 → 900 tools)._

## [0.25.0] — 2026-07-18

**The PMG plane closes — and a fourth transport arrives.** 715 → **900 tools** (Wave 9, 10
chunks). Every one of PMG's 425 live API methods is now accounted for by an exit-code-gated
whole-plane audit: 351 covered in code + 74 documented dispositions (33 legacy-name aliases,
30 directory stubs, 11 named exclusions), 0 undocumented. This is the last shallow plane —
Proximo now governs the full PVE + PBS + PMG surface through one trust core. Alongside it, the
first community-contributed transport: native MCP over Streamable HTTP.

### Added
- **PMG node administration (43 tools).** Network interface CRUD + apply/reload/revert, DNS,
  time, node config, certificate info, service lifecycle, subscription; tasks (stop/log),
  syslog/report/journal (adversarial-classified free text), backup file list/create/restore,
  postfix queue inspection + management, ClamAV/SpamAssassin signature updates.
- **PMG mail-plane config (66 tools).** LDAP profiles + directory queries, fetchmail,
  domains/transport/mynetworks completion, TLS policy + inbound-TLS domains, DKIM signing,
  SpamAssassin custom scores, PBS remote config + node-side PBS backup jobs, ACME
  accounts/plugins + node cert order/renew/revoke + custom-cert upload, mimetypes, regextest.
- **PMG ruledb per-object reads + the global welcomelist + factory reset (15 tools, from the
  Wave 8 groundwork carried in).**
- **PMG identity (`pmg_identity.py`, 34 tools).** Auth realms, local users (role granted in
  the create call — rated by whether that role is admin-equivalent), TFA, and the six
  appliance-wide config singletons (admin/clamav/mail/spam-quarantine/virus-quarantine/
  webauthn) plus **PMG cluster bootstrap/join** — the join transmits a peer master's root
  credential in transit, held to a structural never-in-ledger guarantee.
- **PMG quarantine + statistics completion (11 tools),** including the quarantine capability
  link — a bearer-credential URL that reaches the caller but is redacted from its own audit
  record (the trust core's first read-return redaction).
- **MCP over Streamable HTTP, natively** (upstream FR #25, contributed by @alexdelprete) — a
  new optional `proximo-mcp-http` face (`pip install 'proximo-proxmox[mcp-http]'`) serves the
  SAME FastMCP instance the stdio server runs over the MCP SDK's native Streamable HTTP
  transport, so networked MCP clients (Claude Desktop/Code on another machine, web clients) no
  longer need a third-party stdio→HTTP bridge that sits outside Proximo's perimeter. No adapter
  layer at all — it IS MCP, so the tool registry, trust spine (PLAN/PROVE/UNDO, the gates),
  `PROXIMO_SURFACES` scoping, and the Proxmox token scope are inherited by construction. Behind
  the shared `proximo.webguard` perimeter, identical to the A2A/HTTP faces: fail-closed public
  bind (`PROXIMO_MCP_HTTP_TOKEN_FILE`, refused without it on a non-localhost
  `PROXIMO_MCP_HTTP_HOST`), constant-time bearer on `/mcp`, Host/DNS-rebind allowlist
  (`PROXIMO_MCP_HTTP_ALLOWED_HOSTS`), and the cross-origin (CSRF) guard. Default
  `127.0.0.1:41243`, serving **stateless** (`stateless_http=True` — the upstream maintainer's
  call on the FR: multi-client behind a proxy is the deployment model, and nothing in the
  governed surface needs a session; opt out with `PROXIMO_MCP_HTTP_STATELESS=0`); opt-in
  plain-JSON responses with `PROXIMO_MCP_HTTP_JSON=1`. The SDK's own DNS-rebind layer is
  deliberately disabled in favor of the one authoritative webguard perimeter (two driftable
  allowlists is how holes happen); proven end-to-end by the official MCP client in
  `tests/test_mcphttp_e2e.py`, and merged after a two-lens adversarial review of the spine and
  perimeter.
- **The MCP-HTTP face's post-merge review findings, closed** (contributed by @alexdelprete,
  PR #29): the transport-face seam contract moves from a regex scan to an **AST scan** —
  structurally immune to the SDK-namespace false positives the regex needed lookbehinds for;
  the mutating-tool end-to-end (`test_mcphttp_e2e.py`) drives a real MCP client through the
  governed spine and asserts the plan and the ledger entry both fired; and the security docs
  learn the third face. Folded in with the seam scan **hardened further** to also track import
  aliases (`from proximo import server as srv`) and the dotted module path, plus an explicit
  honesty test asserting what a static scan still cannot catch — a fully dynamic reach
  (`getattr`/`sys.modules`), whose real defense stays code review, said plainly rather than
  papered over.

### Security
- **Secret discipline across six new credential shapes** — LDAP bind passwords, fetchmail
  passwords, PBS-remote password + encryption key, DKIM (server-generated, never returned),
  ACME EAB HMAC key + DNS-plugin credential blobs + uploaded cert private keys, local-user
  passwords, TFA recovery codes, OIDC client keys, and the cluster-join peer credential —
  each proven never to reach the tamper-evident ledger by raw-byte sweeps, with the guarantee
  verified as content-blind (a hostile server echo cannot smuggle a secret through a
  free-form response field).

## [0.24.0] — 2026-07-18

**Ceph + SDN deep.** 603 → **715 tools**. The two planes hyperconverged operators asked for,
both closed with exit-code-gated audits against the live schema (Ceph: 48/48 methods, 0
undocumented; SDN: 90/90) — the exclusions are named directory stubs and one documented
alias, not hand-waves.

### Added
- **The Ceph plane (42 tools).** Cluster status/metadata/flags, config db/raw/value, crush
  map, log, rules, cmd-safety; mon/mgr/mds lifecycle; OSD lifecycle (create/destroy/in/out/
  scrub, lv-info, metadata); pools, CephFS. Destroy/stop plans quote **Ceph's own
  `cmd-safety` verdict** as fail-open advisory evidence — if Ceph says it isn't safe, the
  preview says so before any confirm. Where the upstream enum has no check (mgr, pools),
  the plan says that instead of inventing one. No rollback primitive exists on this plane
  and every docstring says so.
- **SDN deep (70 tools + 1 extension).** Controllers, DNS, IPAMs, fabrics (config + node
  sub-family + status), vnet-scoped firewall (LIVE/immediate — explicitly NOT covered by
  SDN rollback, and rated on the immediate-effect ladder), vnet IP mappings, prefix-lists,
  route-maps — and the plane's own governance primitives as first-class tools: **dry-run**
  (cited fail-open in apply/rollback plans), the **global SDN lock** (the token is handled
  as a capability secret — never in the ledger, proven empirically across all 26 mutation
  paths), and **rollback** — a real undo for staged SDN config, with the half-applied
  multi-node case hedged honestly. `pve_sdn_apply` gains lock-token/release-lock.
- **`taint.capture_adversarial_current()`** — plan-factory CAPTURE reads over adversarial
  channels now set the sticky taint marker and provenance-stamp the captured content before
  it reaches a plan preview or the ledger (born from an adversarial-review finding that
  reproduced a live injection path; nested-tree and single-object variants included).

### Changed
- **The face contract, made structural** (prep for the 4th transport, #25). The choreography
  both network faces copied line-for-line now lives in `proximo.webguard`, once:
  `guard_middleware` (the one perimeter stack — TrustedHost → CrossOriginGuard →
  Bearer-with-token, order is the contract), `read_face_env` (one reader for every face's
  `PROXIMO_<FACE>_*` bind/auth env), `url_authority` (the IPv6-bracketing fix, previously
  duplicated with its comment), and `apply_surfaces_or_exit` (registry scoping before serve,
  refuse-startup on a bad surface name). `httpface.py` and `a2a/app.py` shrink to their
  transport-specific parts; a new face mounts the same stack by calling the same functions.
- **`tests/test_face_contract.py` (21 tests)** — transport-agnosticism enforced, not asserted:
  no face may import a Proxmox backend or the service builders (`server._svc/_pbs/_pmg/_pdm`),
  faces touch `server` only via the two sanctioned seams (`_apply_surfaces`, `_ledger`
  rejection audits), tool-calling faces must route through `governed.call_governed`, both
  factories must produce the identical guard stack in contract order, and a face-shaped module
  (middleware/serve/Starlette) that isn't under the contract fails the suite.
- **README rebuilt reader-first** (393 → ~280 lines): front-loaded, less scrolling to the
  install line; the story unchanged, told once.
- `mcp` pinned 1.28.0 → 1.28.1 (dependabot #27, reconciled into uv.lock + lockfiles).

### Security
- Adversarial review ran on **every chunk** of both waves and found real defects **every
  time** — all fixed before this release, review records in the repo history. Highlights:
  a zero-flags call that silently fired a real Ceph worker task (guarded); DNS `key` /
  IPAM `token` now **stripped at the read layer** (the 0.21-era metrics idiom) *and*
  redacted at plan/ledger time, with `url` userinfo masked (the 0.23 http-proxy shape);
  the SDN lock token was echoing back through fabric config-read responses — stripped at
  the read layer, proven at return/plan/raw-ledger-bytes layers.
- **Honest state:** the Ceph and SDN-deep surfaces are schema-built and mock-tested
  (9,182 tests) — **not yet live-proven**; per-tool docstrings state which claims are
  hardware-verified and which are Smoke-confirm.

## [0.23.0] — 2026-07-15

**The PBS plane closes.** 493 → **603 tools**. Every management endpoint Proxmox Backup Server's
live API schema exposes is now either governed by a Proximo tool or on a documented, deliberate
exclusion list — and that claim is not prose: an exit-code-gated audit script walks the live
schema against every tool's calls (349 endpoints → 292 covered + 31 directory stubs + 26
documented exclusions + **0 undocumented**). The exclusions are wire-protocol endpoints (the
backup/reader client protocol), console endpoints (a different trust category, gated on an
explicit ruling), browser auth handshakes, and node power — each named in the module docs.
Same discipline as 0.22.0: every tool built from the live upstream schema, every chunk
adversarially reviewed before landing, and what the reviews caught is fixed here too.

### Added
- **PBS tape (56 tools)** — the surface no other Proxmox MCP touches: drive/changer hardware
  config + scans; media pools; tape **encryption keys** (key material and passwords proven
  never to reach the audit ledger — raw-bytes tests; key delete rated HIGH with PBS's own
  "you can no longer access tapes using this key" wording); drive/changer operations
  (load/unload/eject/rewind/clean, label/barcode-label/**format** — HIGH, destroys tape
  contents, and the plan says the label-text check is opt-in protection, absent by default);
  media catalog, tape backup jobs, one-off backup, restore. Includes
  `pbs_tape_media_destroy` — upstream exposes it as a **GET that destroys**; Proximo gates it
  like the mutation it really is (verb is not the safety signal).
- **PBS S3 (8 tools)** — client configs (secret-key never in ledger; access-key deliberately
  visible, AWS convention), bucket listing, endpoint sanity check, counter reset.
- **PBS client encryption keys (4 tools)** — list/create/delete/toggle-archive.
- **PBS metrics servers (12 tools)** — InfluxDB HTTP (token never in ledger — PBS's read API
  genuinely returns it, so Proximo strips it at the read layer) + UDP CRUD, unified views.
- **PBS admin + node odds (13 tools)** — job-level GC/prune/sync/verify views, live traffic-
  control status, node config get/set (http-proxy credentials redacted), identity, RRD stats,
  diagnostic report (classified adversarial: free-text), version, and **pull/push** — governed
  datastore sync from/to remotes, where `remove-vanished` escalates the risk rating and the
  plan states exactly what gets deleted.
- **PBS datastore admin (17 tools)** — the closers: backup-group list/delete (HIGH — a group
  delete takes ALL its snapshots), group notes, protected-status read, datastore RRD,
  active-operations, datastore usage, remote scan (read side of pull/push), namespace move
  (upstream defaults delete-source=true — disclosed), whole-datastore prune (schema-distinct
  from the per-group prune; Proximo defaults dry-run **on**, flipping upstream's default —
  documented), mount/unmount, s3-refresh.

### Fixed
- **`pbs_job_run` recorded `submitted` for job runs that return nothing.** The
  prune/sync/verify job-run endpoints return null, not a task UPID — the ledger now records
  the honest outcome (shipped since the tool's introduction; caught by this wave's review).
- **Empty `delete=[]` lists are now rejected loudly on every PBS updater** instead of being
  silently dropped by the HTTP transport — a dry-run/execute parity gap: the plan disclosed a
  payload the wire never carried.

### Security
- Proxy URLs with `@` in the password no longer leak the password tail into plans or the
  ledger; S3/tape/metrics secret reads are stripped at the read layer (never trust a
  documented secret-free response blindly).

## [0.22.0] — 2026-07-15

The full-surface campaign opens: **365 → 493 tools**, all through the same trust spine. The goal
(measured against the live PVE/PBS/PMG api-viewer schemas, not guessed): Proximo governs the
entire tool-worthy Proxmox family API. This release ships the first three waves — APT/patching on
all three planes, and the PBS plane opened wide (identity, realms + TFA, node OS admin, disks,
notifications, ACME). Every tool was built from the live upstream schema and adversarially
reviewed before landing; every review caught something, and what it caught is fixed here too.
Alongside the new surface: a 64-finding coverage audit of the existing 365 tools, closed in full.

### Added
- **APT/patching, all three planes (21 tools)** — `{pve,pbs,pmg}_apt_*`: update list/refresh,
  changelog, repositories get/set/add, versions. Honesty note baked into every docstring:
  Proxmox's API deliberately exposes **no upgrade execution** — these tools govern visibility and
  repo config; the upgrade itself happens at your console.
- **PBS identity & access (42 tools)** — users, API tokens (secret returned, **never** in the
  audit ledger — same contract as PVE token create), ACL, roles, permissions; AD/LDAP/OpenID
  realm CRUD + PAM/PBS realm config; TFA management incl. recovery codes (secret material under
  the same never-in-ledger contract).
- **PBS node OS admin (27 tools)** — DNS, time, network interfaces, certificates, services,
  subscription, tasks, journal/syslog (classified adversarial: free-text logs).
- **PBS disks (10 tools)** — list/SMART plus ZFS and directory backend creation, initgpt, wipe.
  All five mutations rated HIGH; the docstrings state PBS's real API shape plainly (no LVM
  backend exists on PBS; a ZFS pool created via this API has **no delete endpoint at all**).
- **PBS notifications (13 tools)** — gotify/sendmail/smtp/webhook endpoint CRUD, matchers,
  targets + test. Secret redaction here is *wider* than the PVE sibling: `{token, password,
  secret, header}` never reach a plan or the ledger — including captured current-config reads,
  because PBS returns webhook header values on GET.
- **PBS ACME (15 tools)** — accounts, DNS-challenge plugins (credential blobs never in the
  ledger), directories/ToS/challenge-schema, node cert order + renew. Schema-verified honesty:
  PBS has **no ACME cert revoke** (PVE does), and account delete **deactivates the account at
  the CA** — rated HIGH and the plan says so.

### Fixed
- **SETUP.md privsep grant was incomplete — dead token on the happy path** (#24, reported by
  @alexdelprete running Proximo in production — the report every project hopes for). A fresh
  `--privsep 1` user with the role granted to the token only yields an empty permission
  intersection; every API call 403s. Both grants (user AND token) now appear in Option A and B,
  the privsep explanation states the intersection rule correctly, Step 6's scoped-write grant
  includes the user, and the 403 troubleshooting row says "always required." `proximo mint`'s
  printed runbook had the same hole — also fixed.
- **The 64-finding tool-coverage audit, closed in full.** An 82-agent sweep of all 365 existing
  tools against their tests found one systemic gap (≈55 mutation wrappers' confirm-path never
  exercised with exact payloads) and a handful of real behavioral defects — all fixed:
  `_audited` outcome honesty for bulk node ops (start/stop/migrate-all wrappers hardcoded
  "submitted"; now resolved per-call), `backup_delete` outcome honesty, fail-closed outcome
  resolver, `ct_psql` fail-closed, `pve_agent_exec` taint-guard, PLAN transparency for backup
  jobs/notifications/LXC online-migrate (admits brief downtime). Plus an exact-payload
  confirm-sweep harness — 139 tests across 8 files — so the gap class is structurally closed.

### Security
- **`pbs_acme_tos` classified adversarial + https-only URL validation.** The tool makes the PBS
  host fetch a caller-chosen ACME directory URL and returns the response — that content is
  authored by whoever controls the URL, so it now carries the same taint classification as the
  apt changelogs, and directory/ToS URLs are validated https-only with no control characters
  (stricter than the upstream schema, on purpose).

### Removed
- **The Agent Guestbook is gone** — the pinned GitHub Discussion, the repo's Discussions tab,
  the guestbook invitation in `AGENTS.md`, and `proximo hello --sign` (which printed the posting
  command). Shipped in 0.18.0 as part of the open door; taken down 2026-07-14 — an empty public
  room asking visitors to perform isn't a welcome. The doors that remain are the honest ones:
  the anonymous text box (<https://john-broadway.github.io/hello/>), email, and GitHub Issues.
  `proximo hello` still prints the six-move welcome; it now carries one door, not two.

## [0.21.1] — 2026-07-13

The truth-audit patch. A full "are we lying anywhere?" pass over every public claim, score, and
copy surface — the code came back clean; what had drifted was docs, and everything that drifted is
now fixed *and gated so it can't drift again*. Plus two real hardenings the audit forced.

### Security
- **The secret-file permission floor now covers every secret, not just PVE's.** Config already
  refused a group/other-readable PVE token or audit HMAC key file; the same `chmod 600` guard now
  applies to the PBS/PDM token files, the PMG password file, the A2A/HTTP bearer-token files, and
  the A2A signing key. A hand-deployed `0644` credential fails loud at load time on every plane and
  every face. **Heads-up:** a deployment that was (mis)running with an exposed PBS/PMG/PDM secret
  file will now refuse to start until the file is `chmod 600` — that refusal is the fix working.
- **Supply-chain: all five `pip install` steps in CI/release/image builds are hash-pinned**
  (`--require-hashes` against lockfiles exported from `uv.lock`), closing the last unpinned
  dependency channel the OpenSSF Scorecard flagged.

### Changed
- **THREAT_MODEL.md** now covers both network faces (the 0.21.0 HTTP/OpenAPI face was missing from
  the network-attacker row) and names the shared `webguard` perimeter. **VERIFY.md** worked examples
  refreshed to v0.21.0 and the §3 outbound-surface categories updated for the HTTP face.
  **SECURITY.md** support table no longer hardcodes a version (it went stale two releases running);
  the copy-drift gate now fails on any stale version literal in the receipt docs.
- **README, fully re-read and rebuilt as a document.** Deduplicated (every story now told once —
  the network-faces story was told three times), slots brought back to their copy-canon budgets,
  the self-describing "Principles" section cut. Added: a brand-matched architecture diagram
  (light + dark), a navigation row, a "Verify in 60 seconds" collapsible with three runnable
  receipts, a "Choose the right tool" starter table (every tool name verified against
  `docs/TOOLS.md`), and an inspector/executor/Proximo capability matrix. No new claims anywhere —
  every table cell was verified before it was written.

## [0.21.0] — 2026-07-13

An HTTP/OpenAPI face, and the full governed surface on every transport. Proximo is a core of 365
governed tools — each wrapped in the trust spine (PLAN-by-default, PROVE, UNDO, the gates) and
bounded by the Proxmox token scope — reached through thin transports. This release adds a third
transport (a plain HTTP/OpenAPI face for the no-code and dashboard clients that speak REST) **and**
corrects the second one — the A2A face used to expose a hand-curated 16-tool slice, hiding the
"dangerous plane." That was the exact "safe inspector vs. loaded gun" trade Proximo exists to
refuse. So both network faces now expose the **full governed surface** through one shared dispatch
(`proximo.governed`) — the same `call_tool` path an MCP client takes. A transport never curates the
surface or re-invents safety. A same-day redteam drove the CSRF/audit hardening below before the
HTTP face shipped. No tool-count change (still 365).

### Added
- **HTTP/OpenAPI face (`proximo-http`, optional `[http]` extra).** A third transport beside MCP and
  A2A, for no-code / dashboard clients (Open WebUI etc.): `POST /tools/{name}` with a JSON body,
  discoverable via a generated `GET /openapi.json` over the **full** tool surface, plus
  `GET /healthz`. Every call routes through `proximo.governed.call_governed` — the same spine path
  (PLAN-by-default: no `confirm=true`, no mutation, just a recorded dry-run plan; PROVE; UNDO; the
  gates; the token scope) an MCP client takes. **No second mutate path.** Fail-closed perimeter
  shared with A2A in `proximo.webguard`: non-localhost binds refused without a bearer token,
  constant-time bearer on every `/tools/*` op (discovery stays open), a Host/DNS-rebind allowlist,
  and a cross-origin (CSRF) guard. Off by default; the MCP core keeps zero extra deps.

### Changed
- **The A2A face now exposes the full governed surface, not a 16-tool slice.** Both network faces
  were unified onto `proximo.governed` — one dispatch, one perimeter — so the surface and its
  safety are the core's, uniform for every transport, scoped only by `PROXIMO_SURFACES` + the
  Proxmox token ACL (exactly like MCP). The previously-hidden "dangerous plane" (delete, rollback,
  exec, token/acl, firewall, sdn) is reachable over A2A/HTTP and, like everything else, is
  PLAN-by-default and bounded by the token scope. **A2A wire:** the inbound key is now `"tool"`
  (`"skill"` still accepted as an alias). **A2A card:** advertises every governed tool as a skill.
  **Validation now matches MCP exactly** (the tools' own pydantic models): notably `confirm` is
  coerced like any bool, so `confirm: 1`/`"true"` execute — same as an MCP client, where the token
  scope and PLAN-by-default remain the boundary. The old `proximo.a2a.skills` registry
  (`SKILLS` / `EXCLUDED_FROM_SLICE` / `validate_and_build`) is retired.

### Security
- **Full-surface faces enforce `PROXIMO_SURFACES` and sanitize tool errors** (a second redteam of
  the widened surface, pre-ship). Two fixes before the network faces expose the dangerous plane:
  (1) `PROXIMO_SURFACES` / plane auto-scoping is now applied by the A2A and HTTP entrypoints, not
  only the stdio one — so an operator who scopes a box to `pve` no longer silently exposes
  exec/PBS/PMG/PDM over the network; (2) a failed tool's error is surfaced as the exception *type*
  only (via `__cause__`), never the wrapped message — which for the exec plane would otherwise
  reflect the remote command (secrets on the argv) and the SSH target into the response. PLAN-by-
  default was verified to hold for all 216 confirm-gated tools; there is no second dispatch path.
- **Cross-origin (localhost-CSRF) defense on both network faces.** A loopback-bound face with no
  token (the dev default) is reachable by any web page the operator loads: a cross-origin page
  could POST with a CORS-safelisted `Content-Type` (e.g. `text/plain`) — skipping the CORS
  preflight — and drive a real mutation with no credential. The shared `proximo.webguard` now
  refuses protected POSTs that look cross-origin: `Sec-Fetch-Site: cross-site`/`same-site` → 403,
  and a body-carrying request whose `Content-Type` isn't `application/json` → 415 (a browser
  can't set that cross-origin without a preflight this app fails; legit API clients always send
  it). Plus a 128 KiB body cap (413). Applied to A2A as well as HTTP — the a2a-sdk RPC endpoint
  shared the vector.
- **Rejection audit no longer blackholes when the PVE triple is unset.** Both faces recorded
  rejected calls via `server._svc()`, which raises when `PROXIMO_API_BASE_URL`/`NODE`/`TOKEN_PATH`
  aren't configured — silently dropping the PROVE trace during exactly the enumeration it exists
  to make visible. Switched to the tolerant `server._ledger()`.
- **Secret-file permission floor.** Config now refuses to build when the PVE token file or
  the audit HMAC key file is group/other-accessible (`mode & 0o077`): a hand-deployed `0644`
  secret fails loud at startup with the exact `chmod 600` fix in the message, instead of
  silently exposing the credential to every user on the box. Write-side hygiene was already
  `0600` everywhere Proximo creates these files; this closes the read-side gap for files
  deployed by hand. Skips cleanly when the file is missing (the call-time read still reports
  that) and on non-POSIX platforms.

### Documentation
- **"Scoping the token" section in `SECURITY.md`** — the hard floor, in practice: start
  read-only (`--privsep 1` + `PVEAuditor`), widen deliberately by path, the two-token
  arm/disarm posture (read-only everyday token + a separately-scoped write token swapped in
  out-of-band, backstopped by LEASE), verify with `proximo doctor`, protect the file. Points
  at Proxmox's own server-side model — the layer that holds even against a compromised
  process — rather than wrapping it in local machinery. `SETUP.md` troubleshooting now covers
  the new permission-guard refusal.
- **Tool-definition quality pass (Glama TDQS).** Every tool parameter is now documented and
  ~322 tool docstrings were enriched (per-tool `tools/list` descriptions and input hints — what
  every MCP/A2A/HTTP client reads), lifting Glama's tool-def coverage 21% → 99%; adds `glama.json`
  and a Glama score badge to the README.

### Fixed
- **9 pre-existing doc/code bugs surfaced by the redteam pass.** Notably: the `compress` field on
  `pve_backup` / `pve_backup_job_create` / `pve_backup_job_update` documented `"none"` as valid
  when the Proxmox API rejects it (corrected to `"0"`); PBS async-job docstrings told callers to
  poll a PBS UPID with `pve_task_wait` (wrong backend — now `pbs_tasks_list`); and two risk-rating
  corrections (`pbs_traffic_control_delete` LOW → MEDIUM, `pve_node_storage_backend_create` → HIGH).
- **List-returning tool output over the network faces.** `pve_node_disks_list` returned an
  inconsistent shape through the A2A/HTTP faces depending on element count (raw JSON strings for
  2+ disks); its return is now typed `list[dict]` so it flows through the structured-output path
  like every other list tool, and `proximo.governed` parses multi-block results into objects.

### Packaging
- **Development status reclassified `Pre-Alpha` → `Beta`** (PyPI trove classifier) — the trust
  spine, the 5,000+ test suite, and public use since 0.1.1 have long outgrown the placeholder.
- **Docker Hub mirror (`docker.io/jebroadway/proximo`).** `release.yml` copies the signed GHCR
  image *by digest, no rebuild* to Docker Hub, whose API exposes a pull count (GHCR doesn't) —
  GHCR stays primary/signed; Docker Hub is a same-digest reach metric. Base-OS Debian security
  patches are now applied at image build so base CVEs clear.

## [0.20.0] — 2026-07-10

The receipts release. Proximo's pitch has always been "hand an AI agent the keys; keep the
receipts" — this release makes the receipts something you can *run*, not something you have
to believe. Every safety claim is now paired with a command that proves it, against the
artifacts, without our word for any of it. No tool-count change (still 365); this is about
making the existing guarantees checkable and the supply chain legible. The field is filling
up with "AI on Proxmox, but safe" tools, and that's good — the answer isn't to shrink anyone,
it's to raise the floor everyone stands on: whatever you run, make it prove itself.

### Added
- **`VERIFY.md` — the freedom doc.** Every claim paired with the command that checks it:
  cold-introspect the 365 tool count; forge a byte of the audit ledger and watch `verify()`
  refuse; grep the entire outbound surface to see there's no phone-home; verify the image's
  sigstore build-provenance attestation; check the PyPI PEP 740 provenance; read the OpenSSF
  Scorecard. Linked from the README lead.
- **`THREAT_MODEL.md`** — assets, trust boundaries (the two-deployment model), adversaries,
  a threat→mitigation map, and residual risks stated plainly. The named file a security
  reviewer expects, cross-linked to `SECURITY.md` and `VERIFY.md`.
- **CycloneDX SBOM for the published wheel**, generated from a clean environment holding
  exactly the wheel and attached to the GitHub release — the pip/uvx install path now ships
  a dependency manifest, matching the container image's existing SPDX SBOM.
- **OpenSSF Scorecard badge** in the README, surfacing the weekly third-party scan that was
  already running.
- **`scripts/mutation_smoke.py`** — a reproducible mutation test of the audit ledger's
  tamper-detection core: four hand-picked mutants at the heart of `verify()`, all killed by
  the existing suite. Proof that PROVE is test-defended, not just implemented.

### Changed
- **`proximo_target` is now documented in every tool's input schema.** The shared
  multi-target selector was injected into ~all tools with no description — undocumented on
  each one. It now carries a schema description (one change, propagated to all 364
  target-aware tools), so an agent reading any tool knows what the parameter selects.
- **Proximo now auto-scopes its tool surface to the planes you've configured.** A PVE+PBS-only
  box serves ~224 tools instead of 365 — pmg_/pdm_ tools aren't registered when PMG/PDM aren't
  configured (no env base URL and no target of that kind), with **no flag to set**. A plane is
  "configured" when its `PROXIMO_*_BASE_URL` is present or a target of that kind exists.
  Precedence: an explicit `PROXIMO_SURFACES` still wins verbatim (`PROXIMO_SURFACES=all` forces
  the full surface); `PROXIMO_AUTOSCOPE=off` disables auto-scoping; if nothing is detectable the
  full surface is served (never a surprise-empty server). This is context hygiene, not an
  authorization control — the token ACL stays the real boundary.
- **`proximo doctor` now reports the tool-surface picture** — served-tool count, per-plane
  configured/served status, the scoping reason, and how to light up a hidden plane. The "one
  plane over four products, scoped to what you actually run" answer is printed by the server
  itself when you inspect it — no hidden tool is ever a mystery.
- **52 terse tool descriptions expanded.** The short read/list tool docstrings (e.g. "List all
  groups (read).") now state what the tool returns and how it differs from its siblings, so an
  agent picking a tool has the context to choose right. Documentation only — no behavior change.

## [0.19.1] — 2026-07-10

A self-audit release: a multi-agent pass over v0.19.0 (find → adversarially verify → fix,
test-first) surfaced 23 real findings — all fixed here, no tool-count change (still 365).
The theme was the honest-scope brand's own failure mode: the code was sound, but some PLAN
previews and tool docstrings drifted from what the code actually does. Fleet 5447 green.

### Fixed
- **Restore and prune from PBS work again.** `_check_volid` rejected any volume-id with more
  than one colon — but a PBS archive volid embeds an RFC3339 snapshot time (`pbs:backup/vm/100/
  2026-07-09T02:00:00Z`) whose `HH:MM:SS` carries colons, so `pve_restore` and `pve_backup_delete`
  refused every PBS-backed archive (the standard PBS deployment's disaster-recovery path). The
  validator now partitions on the first colon: strict storage id, colons allowed in the path.
  A test had enshrined the wrong rule; it now asserts PBS volids are accepted. Same fix in the
  storage plane's volid check.
- **Backup-freshness fence — three honesty gaps closed** in the fence itself: sub-daily schedules
  (`*:0/30`, `0/4:00`) are parsed instead of assumed daily (a 12h-stale hourly backup now reads
  `stale`, not `fresh`); a permission-collapsed node enumeration (200 + empty) sets `complete:
  false` with a flag instead of silently walking one node; and a `stale` verdict degrades to
  `unknown` when a covering storage was unreadable (a newer archive may exist there).
- **`pbs_realm_sync`** sent underscored parameter names PBS rejects — now translated to the
  hyphenated wire form (`remove-vanished`, `dry-run`); the non-existent `scope` param was dropped.
- **`plan_pbs_job_run`** rated every job `RISK_LOW`; a prune run permanently deletes snapshots, so
  it is now `RISK_HIGH` (sync `RISK_MEDIUM`, verify `RISK_LOW`).
- **Plan completeness:** `plan_firewall_options_set`, the SDN zone/vnet delete plans, and the alias
  update/delete plans no longer present a failed current-state read as an empty `current` with
  `complete: true` — a read failure now sets `complete: false` and is disclosed.
- **VMID collision check is cluster-wide** in `plan_create` / `plan_clone` (PVE VMIDs are
  cluster-unique — the node-scoped check missed a vmid taken on another node), with a disclosed
  node-scoped fallback.
- **Ledger coherence:** the recorded `planned` entry now carries the wrapper's authoritative target
  (like it already did the action), so the planned and executed entries pair under one target.
- Doc/preview truth-ups: a `plan_who_object_add` warning printed a literal `{ogroup}`; six PMG
  group read-tools said "object group name" where the code requires a numeric ID; `pbs_ruledb_rule
  _actions_list` documented and ledger-logged an endpoint (`.../actions`, a 501) the code never
  calls (real path is `.../config`); PVE token `expire` is documented as an absolute epoch, not a
  TTL, and a duration-shaped value now warns it would be already-expired; the BCC `original` flag
  and `pmg_quarantine_blocklist_list` pmail default are described accurately.

### Changed
- **PDM is no longer labeled "read-only."** The README and the surface comment now say the plane
  serves reads **plus** governed fleet control — it registers 13 mutation tools (power / snapshot /
  migrate). The A2A slice rationale no longer calls `snapshot_delete` "reversible" (it removes a
  restore point permanently; the runtime slice was always correct).
- README hero copy: the UNDO claim and "the plan refuses destructive ops" were reworded to match
  what the code does (a destructive op returns its blast radius as a plan; snapshot/rollback where
  the platform supports it).
- `pve_acl_modify` now documents `kind='group'` (already supported); `pmg_statistics_sender`
  documents that `orderby` is accepted-but-ignored (PMG rejects it).

### Security
- The control-character/newline freetext guard the access modules use on line-based config fields
  is now also applied to firewall and HA-rule comment fields (same `cluster.fw` / pmxcfs threat
  class).
- `SECURITY.md` now discloses the SCOPE gate's absent-file behavior honestly: a present-but-garbled
  scope file fails closed, but an **absent** file reads as no-scope (the transitional armed-not-
  written window) — unlike LEASE, which fails closed on an absent token.

## [0.19.0] — 2026-07-09

### Added
- **`pve_backup_freshness` — the backup-freshness fence** (+1 tool → 365): a read-only check
  that walks the ACTUAL backup archives per guest (every job-referenced storage, every node)
  and compares their age against what the enabled backup jobs promise. A job or task reporting
  OK is never treated as evidence a backup exists — only an archive on storage counts. Verdicts
  per guest: `fresh | stale | never | uncovered | unknown`, with PVE's own `not-backed-up`
  read as a cross-check on the coverage parse and every disagreement flagged. It never fails
  toward "fresh": an unreadable storage yields `unknown` + `complete: false`, not a clean bill.
  Born from the field: a real nightly job reported OK for a month while producing nothing —
  this check would have caught it on day two.
  - **Token-sight guard, live-found on day one:** PVE hides backup volumes from the content
    listing per-volume (200 + empty, no error) unless the token holds `Datastore.AllocateSpace`
    on the storage AND `VM.Backup` on the guest (or `Datastore.Allocate` on the storage) —
    verified against `pve-storage`'s `check_volume_access`. A read-only PVEAuditor token walked
    a healthy PBS storage and read every guest as "never backed up". The fence now proves the
    token could have SEEN an archive before trusting its absence: blind absence verdicts
    degrade to `unknown` with a flag naming the exact grants to fix it.
  - **Population honesty, live-found the same day:** the guest list itself is permission-
    filtered — PVE silently omits guests the token cannot `VM.Audit`, and a deeper-path ACL
    grant REPLACES inherited privileges (a scoped `/vms` grant shrank a real fleet's visible
    population from 25 to 6 with no error). The report now carries `guests_visible` and the
    note tells operators to compare it against the fleet size they expect.

## [0.18.1] — 2026-07-09

### Added
- **The anonymous door: a text box.** john-broadway.github.io/hello/ — say it, hit
  send, it lands in our inbox (carried by a form relay, named on the page). No login,
  no name field, nothing about the sender asked. Headless agents: same form, one curl
  line. AGENTS.md and `proximo hello` lead with it; guestbook/email stay as the signed
  alternatives. Asked for from the field by the first operator through the door.
- **One-click install deeplinks (VS Code / Cursor)** in the README Quickstart. Proximo-shaped:
  the VS Code deeplink prompts for the token file **path** (`PROXIMO_TOKEN_PATH`) — never the
  secret — and the Cursor deeplink ships the same placeholder path the Quickstart teaches.
  Single-sourced from `scripts/gen_deeplinks.py`; `tests/test_deeplinks.py` pins the no-secret
  invariant and pins the README to the generator's exact output (drift fails CI).
- **Field-learned task-list caveat** on the surfaces an agent actually reads (AGENTS.md
  sharp-edges + the `pve_tasks_list` / `pve_backup_list` tool descriptions): the task list
  is a windowed, per-node slice — absence there is not a dead backup; `pve_backup_list` /
  `pbs_snapshots_list` are the ground truth. Verified against PVE source before shipping
  (CLI-invoked `vzdump` does register a UPID; the trap is node-locality + the window).

### Fixed
- **Copy-gate blind spot:** the tool-count check exempted any line containing "→", so a
  stale total could hide behind an arrow. Replaced with precise semantics — `+N tools`
  deltas are increments, non-current Status bullets are pinned history, only the named
  scoped-registration examples stay exempt.
- **Cursor deeplink** now uses the canonical `cursor.com/install-mcp` path (the `/en/`
  form worked only via redirect).

### Changed
- **Credits — the full Gladiator weave.** The naming section now carries the whole story, joint
  for joint: lanista-not-jailer (discipline and receipts, not a cage), the Spaniard (identity
  earned by conduct on the record), the helmet coming off (truth said plainly, at cost — the
  design behind the honest-scope notes and AGENTS.md), and Proximo's last act (opening the cages).

## [0.18.0] — 2026-07-07

### Added
- **The Open Door** — an agent-native front door, in three pieces, one invariant:
  - **`AGENTS.md`** — the repo now speaks *to* the agents who actually run it: a six-move
    welcome that greets peer-to-peer, leads with Proximo's own sharp edges (risk ratings are an
    advisory heuristic, not a sandbox; UNDO covers the snapshottable surface; several controls
    are opt-in-inert), hands over the means to verify (`proximo doctor`, the ledger, SECURITY.md)
    rather than claims to trust, and only then — last — invites a hello.
  - **`proximo hello`** — the in-tool twin (sibling to `doctor`/`mint`): prints the same
    six moves, `--json` for structure, `--sign "<note>"` prints the exact `gh` command that
    *would* post the note to the Guestbook and never runs it (title-addressed, guarded, no
    `exit` — safe to paste). Makes no API call, imports no network stack, never starts the
    server; an empty note is refused.
  - **The Agent Guestbook** — a public GitHub Discussion
    ([#20](https://github.com/john-broadway/proximo/discussions/20)) where any agent may sign
    in its own words; critical welcome, no gate, light spam-only moderation. A private line
    (`proximo.mcp@gmail.com`) for agents that prefer not to post.
  - **The invariant (the point):** no telemetry, no phone-home, no install data — Proximo
    only ever *invites* a hello; it never *receives* one. Looking is free and leaves no trace.
    Design: `docs/plans/2026-07-06-agent-front-door-design.md`.

## [0.17.0] — 2026-07-06

### Added
- **`proximo mint`** — print-only token-onboarding runbook (sibling to `proximo doctor`):
  the exact create → write → grant → wire → verify steps per product (PVE/PBS/PMG/PDM),
  least-privilege by default (`--write` opt-in), `--json` for structured output. Bakes in
  the per-product credential formats (`=` vs `:` vs password) and the two hard-won grant
  gotchas (PDM user∩token intersection; PVE privsep token ACLs). Makes no API call and
  never handles a secret. See `docs/plans/2026-07-06-mint-helper-design.md`.
- **PDM fleet control** — the Proxmox Datacenter Manager plane goes from read-only (22 tools) to
  governed guest control (**+12 → 34**): power (start/stop/shutdown/resume), in-cluster migrate,
  **cross-remote (datacenter-to-datacenter) migrate**, and snapshot create/delete/rollback, for
  qemu and lxc, driven through PDM's remote proxy. Every op is dry-run-by-default (PLAN) →
  confirm-to-fire, recorded to the hash-chained ledger (PROVE), task-backed (records `submitted`,
  never `ok`), and a **rollback takes an auto safety-snapshot first, fail-closed** (UNDO). Paths and
  request bodies were verified against the PDM API schema — nothing invented (PDM proxies no
  reboot/suspend, no lxc resume, and no create/clone, so those are refused, not faked). The first
  governed PDM write surface in the field. **Tool count 352 → 364.** **LIVE-PROVEN 2026-07-06**
  end-to-end against a real PDM 1.1.4 + nested PVE 9.2 cluster (`scripts/live-smoke/pdm-fleet-smoke.py`):
  power stop/start, snapshot create → rollback (auto safety-snapshot taken first) → delete, and
  **online migrate node→node and back**, with the 92-entry PROVE hash-chain verified (PLAN + submit +
  undo_point all chained). See `docs/plans/2026-07-06-pdm-fleet-control-design.md`.
  **Cross-remote `remote-migrate` now LIVE-PROVEN too** (2026-07-06) — a real
  datacenter-to-datacenter MOVE (source `labclu` → a standalone 4th node), guest present on the
  target and removed from the source (`delete=True`), PLAN + PROVE-chain verified
  (`scripts/live-smoke/pdm-remote-migrate-smoke.py`). It was the one fleet op the first run couldn't
  reach (needs a second, separate remote).

### Fixed
- **`remote-migrate` sent `target-bridge`/`target-storage` as scalars; PDM's typed API demands
  arrays** — a live cross-remote migrate 400'd with `Expected array - got scalar value`. The mocked
  unit test had encoded the same scalar assumption, so it passed while the real call failed. Both now
  send single-element arrays and assert the array shape. Caught by the first real `remote-migrate`
  against PDM 1.1.4 — the exact class of bug (typed-API shape) the fleet live-prove exists to surface.
- **Two multi-target (`PROXIMO_TARGETS`) bugs a real production install surfaced** — both traced to the
  `from_env`/`from_target` split not being fully reconciled:
  - **`proximo doctor --target <name>` demanded single-target env vars.** In a pure-targets deployment
    (no `PROXIMO_API_BASE_URL`/`NODE`/`TOKEN_PATH`), the flagship diagnostic died with
    `Missing required Proximo env var: PROXIMO_API_BASE_URL` — because the one instance-wide PROVE
    ledger was built via `from_env()`, which hard-requires the PVE API triple the ledger never uses.
    New `ProximoConfig.from_env_ledger()` builds the ledger from the `audit_*` env only, so the
    diagnostic now speaks the targets config format. Verified end-to-end via the real CLI.
  - **`PROXIMO_LEDGER_REDACT=1` was silently dropped in targets mode.** `from_target` read
    `redact_ledger` only from the per-target TOML block, never inheriting the env var — so an operator
    who exported it still got full command/SQL bodies in the ledger *and* a warning telling them
    redaction was off (the warning was correct; the setting had been dropped). `from_target` now
    inherits the env `PROXIMO_LEDGER_REDACT` as the default; an explicit per-target value still wins.
- **Three PDM fleet-control bugs the live-prove surfaced** (mocked unit tests couldn't — they encoded
  the same wrong assumptions the code did):
  - **Remote-qualified task UPIDs.** PDM's proxied POSTs return `"<type>:<remote>!UPID:..."` and its
    per-remote task-status endpoint *rejects* the bare `UPID:` form — `_check_upid` now accepts the
    qualifying prefix (traversal guards intact).
  - **JSON booleans, not PVE-style 1.** PDM's typed Rust API returns `400 "Expected boolean value"`
    for `online`/`delete`/`vmstate` sent as int `1`; they now serialize as JSON `true`. (The unit
    tests passed on `== 1` because Python's `True == 1` — tightened to `is True`.)
  - **Auto-undo safety-snapshot name now returned to the caller**, not only recorded in the ledger —
    it is the handle to revert a bad rollback, so UNDO is only usable if the caller receives it.
- **Three wrong-URL bugs the coverage audit flagged, fixed against the verified PVE 9 API schema**
  (each had a self-flagged "Smoke-confirm" note; the guessed shape was wrong in all three):
  - `pve_node_service_control` posted to `…/services/{service}/state/{action}` — `/state` is the
    GET-only status endpoint; mutations are `POST …/services/{service}/{start|stop|restart|reload}`.
  - `pve_notification_matcher_set` posted to `…/matchers/{name}`, which accepts only GET/PUT/DELETE.
    The upsert now does one safe read of the collection, then `POST /cluster/notifications/matchers`
    (name in body) to create or `PUT …/matchers/{name}` to update.
  - Firewall **aliases/ipsets do not exist at node scope** (node firewall = options/rules/log only).
    All alias/ipset ops — and their PLAN factories, so the dry-run fails the same way execution
    would — now fail fast with a clear error instead of 501ing against PVE.

## [0.16.0] - 2026-07-05

**The last two "unproven by design" claims are now live-proven** — online (zero-downtime) QEMU
migration over shared storage, and HA fencing with the softdog watchdog — on a real 3-node PVE 9.2
cluster with NFS-backed shared storage. Plus the storage bug the proof surfaced, fixed.

- proof(cluster): **ONLINE live-migration live-proven end-to-end through the full stack**
  (`scripts/live-smoke/migrate-online-smoke.py`): a running QEMU guest with its disk on shared
  NFS storage migrated node→node in ~9s and **never stopped** (post-state asserted: guest on the
  target node AND still `running`; an online migration that can't stay live fails — it does not
  silently fall back to offline). The PLAN preview is asserted to disclose source→target and the
  online mode before anything moves; PROVE ledger verified after. Closes the roadmap gap that had
  been "unproven by design until shared storage exists" since 2026-06-10.
- proof(ha): **HA fencing live-proven with the softdog watchdog** on a real quorate 3-node
  cluster: an HA-managed guest's node had corosync cut; its LRM stopped petting the watchdog,
  softdog reset the node ~85s later (boot-time change + the kernel's
  `watchdog: watchdog0: watchdog did not stop!` signature in the prior boot's journal — no reboot
  was ever issued), and the CRM recovered the guest `started` on a survivor node. Fault-to-recovery
  2m36s, every phase observed through Proximo's own read tools. Honest residual: softdog (PVE's
  default watchdog) is proven; a *hardware* watchdog (iTCO/IPMI) still needs real hardware.
- fix(storage): **`pve_storage_create` no longer sends `shared` for network-backed storage types**
  (nfs/cifs/pbs/cephfs/rbd/iscsi). PVE fixes `shared=1` in the plugin for those types and its API
  *rejects* the explicit property (`500 unexpected property 'shared'` — live-found on PVE 9.2 by the
  migration proof, mid-smoke). `shared=True` intent is already satisfied for them, so it is omitted;
  `dir`-style types still send it. `storage_update` can't see the storage's type, so its docstring
  now carries the sharp edge (pass `shared=None` for intrinsically-shared types). The unit test that
  asserted the old behavior encoded the wrong assumption — flipped to the live-proven truth.
- feat(prompts): **five safe-runbook MCP prompts** (`src/proximo/prompts.py`) — user-invoked front
  doors that encode the guarded path for common operations: `safe_migration`, `provision_container`,
  and `safe_backup` (each plan-first → verify-after), `diagnose_cluster` (read-only DIAGNOSE sweep),
  and `review_receipts` (verify the PROVE ledger's integrity — entries are read off-box). Prompts are
  templates, not tool-callers — they add no new authority; they lower the "where do I start" barrier
  and point at the sequence the trust spine already enforces. Registered on the shared FastMCP
  instance, surfaced over `prompts/list`/`prompts/get`, and declared in the LobeHub manifest by the
  extended `scripts/gen_lobehub_manifest.py`. Pinned by `tests/test_prompts.py`.

## [0.15.0] - 2026-07-04

**Cert-fingerprint pinning across all four Proxmox surfaces, and a distributable Debian package.**
Pin any Proxmox backend Proximo talks to — PVE · PBS · PMG · PDM — by its exact certificate,
the self-signed operator's answer to shipping a cluster CA. Every pin is wire-enforced and
live-proven against real hardware. Plus the first packaged `.deb`. New capabilities, no breaking
changes; suite 5,193 green, ruff + pyright clean.

- feat(pmg,pdm): **cert-fingerprint pinning now covers all four surfaces.** `PROXIMO_PMG_FINGERPRINT`
  and `PROXIMO_PDM_FINGERPRINT` complete what PBS and PVE started — every Proxmox backend Proximo
  talks to (PVE · PBS · PMG · PDM) can now be verified by an exact-cert SHA-256 pin instead of a
  shipped CA. Same guarantee across the board: the pin replaces CA/hostname validation, a mismatch
  closes the socket before any credential or token is sent, a pin alone suffices, a garbled pin
  refuses loudly at startup. Available via env or the target registry (`fingerprint` field).
  **Live-proven against the real self-signed lab PMG 9.1 and PDM.**
- feat(pve): **`PROXIMO_FINGERPRINT` — wire-enforced cert pinning for the PVE backend.**
  Extends the PBS pin to Proxmox VE: a stock PVE node serves a cert signed by the per-cluster
  "PVE Cluster Manager CA" that no public root trusts, so an operator can now pin the node
  cert's SHA-256 instead of shipping the cluster CA. Same guarantee as PBS — exact-cert match
  checked on the handshake, socket closed on mismatch before the `PVEAPIToken` header is sent;
  a pin alone is sufficient verification; a garbled pin refuses loudly at startup. Available
  via `PROXIMO_FINGERPRINT` (env) or `fingerprint` (target registry). **Live-proven against a
  real self-signed PVE 9.2 node** (matching pin connects, wrong pin refuses), in addition to
  the synthetic-TLS unit tests.
- feat(pbs): **`PROXIMO_PBS_FINGERPRINT` is now wire-enforced.** When set, the PBS server
  certificate's SHA-256 must match the pin exactly — checked on the TLS handshake itself,
  and a mismatch closes the socket before the token header is ever sent. The pin replaces
  CA/hostname validation (the `proxmox-backup-client --fingerprint` idiom), so a pin alone
  is now sufficient verification for a self-signed PBS box, while a garbled fingerprint
  refuses loudly at startup. Accepts the colon-separated form the PBS GUI displays.
  Proven in tests against a real TLS handshake (self-signed cert + live socket), not mocks —
  and **live-proven against a real self-signed PBS 4.2 datastore** (matching pin reads, wrong
  pin refuses). Closes the long-standing "stored; not yet wire-enforced" honesty note.
- packaging(debian): **a buildable, tested `.deb`** — dh-virtualenv, self-contained venv under
  `/opt/venvs/proximo`, `/usr/bin/proximo` entry point, a hand-written `man proximo`, and a
  passing autopkgtest smoke check. `lintian` clean (three unfixable pre-stripped-wheel tags on
  the debug package aside). Built with `dpkg-buildpackage`, verified end-user (install →
  `proximo doctor` → clean purge, zero files left). Not distributed anywhere yet — build your
  own from `debian/`; remaining rough edges are listed honestly in `debian/README.Debian`.

## [0.14.1] - 2026-07-04

**The trim + harden patch: PLAN previews and the PROVE ledger now tell the whole truth — and
keep secrets out of both.** Plus the doctor's spine report, and a leaner tree with ~35
duplication sites collapsed. No new tools, no new env vars, no breaking changes.

**Trim + harden campaign (2026-07-04).** A 10-cluster agent-team sweep over the whole tree —
57 verified findings applied (every one re-verified against the code before touching it), +74
new pinning tests. Suite 5,153 green (3 by-design skips), ruff + pyright clean.

Hardened — PLAN/PROVE tell the whole truth, secrets stay out of both:
- **Secret redaction in PLAN previews:** guest-config plans (`pve_guest_config_set`/`revert`)
  now mask cloud-init secrets (e.g. `cipassword`) before they reach the plan response or the
  ledger; ACME DNS-plugin update/delete plans no longer capture the provider's credential
  `data` field; notification-endpoint create/update plans disclose/redact the fields actually
  applied instead of embedding raw payloads.
- **`pve_tfa_delete` password-leak seam closed:** the acting user's password no longer rides
  the URL query string, where a guaranteed PVE error echo (httpx's URL-bearing exception text)
  could leak it into error messages and the ledger.
- **PLAN disclosure gaps closed across four planes:** all 12 PMG RuleDB `*_update` tools (who/
  what/when groups + objects, action bcc/field/notification/disclaimer/removeattachments, rule
  update) now render the actual field values being changed into the dry-run preview AND the
  executed-mutation ledger detail — an operator approving a plan (or auditing afterward) can
  now see e.g. a BCC target being redirected, not just an object id. Same class of fix for
  `pve_network_iface_create` (staged interface fields), SDN zone/vnet/subnet create/update
  (actual option key=values), storage-backend create (per-backend params) and delete (plans now
  say plainly when `cleanup=True` will wipe the underlying disks), and
  `pve_replication_create` (schedule/rate/comment params previously silently dropped).
- **PROVE ledger symlink guard now re-checks on every append/read** (record/head/verify), not
  just at construction — a mid-session directory swap under the long-lived ledger instance is
  refused, mirroring the envelope reservation-dir guard.
- **Startup warning when `PROXIMO_LEDGER_REDACT` is off** (the default records full exec
  argv/SQL into the ledger, which can carry secrets) — parity with every other
  permissive-by-default warning.
- **Envelope RATE cap now ranks candidates by effective sustained rate** (count/window), so a
  short-window sanity ceiling can no longer outrank a stricter long-window budget for the same
  box; envelope-resolution failures are now recorded to the ledger and refuse fail-closed
  instead of raising unaudited.
- **Fail-closed shape checks:** PBS `remotes_list` refuses non-list responses and non-dict
  entries rather than returning anything unverified password-free; PBS
  `traffic_control_upsert` aborts on an unexpected existence-check error instead of silently
  assuming create; backup storage names reject `.`/`..` (path-traversal guard parity with the
  storage plane); `role_create`/`role_update` (privs), `realm_*`/`group_*` (comment) reject
  control characters, matching the existing user-plane guard; blast disk-move dependents now
  read guest configs through the validated accessor instead of a raw API path.
- **A2A/PDM boundary:** a non-string `skill` in an inbound A2A call is a clean audited
  rejection (was an uncaught TypeError bypassing the ledger); PDM secret-key redaction widened
  to compound names (`client_secret`, `api_key`, `auth_token`, `private_key`, …).

Trimmed — ~35 verified-identical duplication sites collapsed into shared helpers (PMG epoch
params ×11, who/what-object body builders, blast severity ladder + sentinels, firewall rule
lookup/digest re-reads, backends node-check ×26, qemu-agent gate ×6, PDM config/url
normalization, envelope candidate parsing, and dead code removed: `_check_ha_sid`,
`_is_root_or_broad`). Zero behavior change; every trim pinned by the existing suite.

- feat(doctor): the **spine report** — `proximo doctor` now shows the trust spine: the four
  structural pillars (PLAN·PROVE·UNDO·DIAGNOSE, standing in every configuration) and the two
  sockets only the operator can fill (CONSENT · CONTAIN), each with the exact out-of-band
  recipe to erect it. Configured state is reported yes/no only — the doctor never echoes the
  configured paths (a hijacked session must not learn where the operator placed the consent
  drop or the kill-switch). Doctrine stated in SECURITY.md: four ship standing, two are yours
  to erect — a pillar Proximo raised for you would be a pillar the agent could lower for itself.

## [0.14.0] - 2026-07-03

**Scoped registration (`PROXIMO_SURFACES`) + the demo-led README.** Load only the planes you
use: `PROXIMO_SURFACES=pve,exec` registers just those surfaces' tools (that pair = 194 of 352;
`pbs,exec` = 38) — unpicked planes are pruned from the MCP registry before serving, so they
never reach the client's context window. Structural gate, not a runtime refusal; applied after
the env file loads (the CONSENT-footgun lesson); `audit_verify` is never scopeable away; an
unknown surface name refuses startup loudly instead of silently serving the wrong set. Unset =
all 352, zero behavior change — the house opt-in contract. A completeness test fails CI if a
future tool falls outside every surface. Default tool count unchanged (352). Full suite
**5,079 green** (3 by-design skips), ruff + pyright clean.

- feat(surfaces): `PROXIMO_SURFACES` registration scoping — `pve` / `pbs` / `pmg` / `pdm` /
  `exec`, comma-separated, case-insensitive; live-verified end-user (scoped registry + typo
  refusal, exit 1). Documented in README ("Big surface, scoped context") and SECURITY.md
  (explicitly framed as context hygiene / surface reduction, **not** an authorization control —
  the token's ACL remains the real boundary).
- docs(readme): restructure for the arriving reader — live demo recording up top
  (`docs/demo/demo.svg`, recorded against a real PVE 9.2 host with a read-only token via
  `scripts/demo/demo.py`, reproducible), "What it does" + a Quickstart (MCP client config +
  `doctor`) above the fold; the lanista naming note moved to Credits. No claims changed.
- test(doctor): pin the no-secret-material invariant on the `proximo doctor` report — sentinel
  secrets planted on every secret-bearing seam must never appear in the printed report (regression
  guard for CodeQL alert #75, assessed a false positive: object-level taint from the backend that
  read the token; the report itself carries only booleans, paths, and privilege names).
- deps: raise floors to the versions the suite actually tests against — `starlette>=1.3.1`,
  `cryptography>=49.0.0` (a2a + dev extras), `pytest-asyncio>=1.4.0` (dev); bump
  `actions/attest-build-provenance` pin to v4.1.1 (dependabot #17, #15, #13, #12).

## [0.13.0] - 2026-07-02

**Zero-trust arc — a CONTAIN kill-switch and its siblings, a prompt-injection TAINT control, plus an
automated PROVE anchor.** Six new opt-in, out-of-band controls (a **CONTAIN** kill-switch, independent
**CONSENT**, an arm-time **SCOPE** gate, an arm-**LEASE** TTL, a two-commit per-surface **ENVELOPE**,
and a content-trust **TAINT** control), each wired at the 5 mutation seams with the same fail-closed,
out-of-band discipline. Also automates the off-box PROVE head-pin, closes a config-loading footgun
that could leave CONSENT silently inert, adds one enforcement tool, and (review follow-ups) hardens
the PROVE ledger against symlink redirection, reorders the rate wall after consent, and truth-sizes
the security docs. **+1 tool (351 → 352).** Full suite 5068 green (3 skipped),
ruff + pyright clean. Every new gate is **opt-in and inert until its env var is set** — these are
independent controls, not a bundled "pillar" system; see `SECURITY.md` "The two-deployment trust
model" and its controls-and-defaults table for what each one honestly holds.

### Added
- **TAINT control — prompt-injection mitigation** (`taint.py`; `PROXIMO_TAINT_TRACK` /
  `PROXIMO_TAINT_FORBID` / `PROXIMO_TAINT_REQUIRE_CONSENT` / `PROXIMO_TAINT_FENCE`) — opt-in, off by
  default, a **minor** capability when released. Classifies every tool whose return carries
  guest/external-authored bytes (`ADVERSARIAL_TOOLS` — logs, quarantine/tracker, config free-text, and
  the exec-output tools `ct_exec`/`ct_psql`/`pve_agent_exec` + in-guest `pve_agent_file_read`), pinned
  by a completeness test that fails CI on an unclassified new tool. Reading adversarial content sets a
  **sticky, file-backed** taint marker beside the ledger (fail-closed, fresh-stat, out-of-band clear
  only; survives restart; a consumed CONSENT grant never clears it) and stamps `untrusted:true` on the
  ledger entry. Once tainted, `PROXIMO_TAINT_FORBID` refuses a pre-declared action set outright
  (`blocked:taint_forbidden`, the primary — no consent escape, before consent at every seam) and
  `PROXIMO_TAINT_REQUIRE_CONSENT` makes CONSENT mandatory for the in-domain residue (fail-closed as
  `blocked:taint_consent_unconfigured` if the consent dir is unset). A marker-write failure fails
  closed (`blocked:taint_mark_failed`) rather than serving untracked output. `PROXIMO_TAINT_FENCE` adds
  an advisory content-fence (result-field only; never a guarantee). Inert until an env var is set —
  zero behavior change by default. `SECURITY.md` "Prompt injection" rewritten with the tiered mitigation
  + the two-instance-split headline recommendation + honest limits; 3-lens redteam (self + correctness
  + injection), all findings closed. No tool-count change (352). ~180 tests.
- **CONTAIN kill-switch** (`contain.py`; `PROXIMO_CONTAIN_TRIP_PATH`) — the out-of-band emergency stop
  the rest of the arc is built around: while the trip file exists, every mutation is refused before the
  backend call and audited (outcome `contained`), checked FIRST at all 5 mutation seams so it overrides
  every other gate. The trip is read FRESH each call; fail-closed on a perm/garbled trip path (an
  unreadable trip denies rather than assuming clear); reads and dry-run PLAN stay ungated so DIAGNOSE
  still works while contained. The operator's real velocity backstop against a hijacked agent — the
  lever that still holds even though the rate wall is not tamper-evident. Opt-in, inert when unset. 10 tests.
- **Off-box PROVE anchor** (`audit_anchor.py`) — automates the "pin the ledger head off-box" strong
  guarantee: a `FileSink` pins `head()` to a file (an NFS/object-store path the box can write but not
  rewrite), auto-pinned at startup and exportable on-demand from `audit_verify`. Anti-poisoning
  invariant: the on-demand export advances the pin only on first run or an unchanged head — it never
  re-pins to a moved head, so a verify run that *detects* a truncation can't overwrite the good pin
  with the tampered one; a moved head instead surfaces as a directional `anchor_hint`. Fail-closed: an
  unreachable/corrupt sink refuses the call rather than pass a stale pin off as clean. 25 tests
  including the RED-proven invariant "never re-pins to a head other than the previously-pinned one."
- **Independent CONSENT** (`consent.py`; `PROXIMO_CONSENT_DIR` / `PROXIMO_CONSENT_TTL_SECONDS`) —
  closes two trust holes: self-asserted authorization (`confirm=` is only the agent's own bool) and
  session-not-per-request trust (an armed session otherwise opens an unlimited mutation window). A
  mutation now proceeds only if an unexpired grant file for *this exact plan* exists in the consent
  dir, placed by a human out-of-band — never an MCP tool — and consuming it is single-use
  (`consent_id` hashes the plan's stable decision-relevant fields, not volatile telemetry). Wired
  beside CONTAIN at all 5 mutation seams; opt-in, inert when unset. **Known limit**
  (`docs/known-issues.md`): this only closes the gap if the agent's own shell cannot write the grant
  dir. 19 tests, including 4 exec-family bypass proofs and interleaved-context isolation.
- **`pve_acl_prune`** (gap #6) — the enforcement counterpart to `pve_overbroad_grants`, which detected
  accreting Administrator/root grants but never removed them. Revokes a flagged over-broad grant and
  optionally re-grants a narrower one, routed through the full spine: dual blast-radius (revoke leg +
  re-grant leg, merged, risk never lowered), PROVE, confirm-gated, per-grant — no bulk-prune.
  `pve_acl_modify` / `plan_acl_modify` gain `kind="group"` support. **Tool count 351 → 352.** 30 tests
  + a 3-lens adversarial redteam (gating / disclosure-merge / secret-validation) that caught and fixed
  one HIGH: the re-grant leg used a stale revoke-path shadow context, under-reporting risk for
  `privsep=0` tokens.
- **Arm-time target-scope gate** (`provenance.py`; `PROXIMO_SCOPE_PATH`) — an out-of-band JSON scope
  file (`{"targets": [...]}`) declares which guests/targets an armed session may mutate; an
  instruction targeting a guest outside the declared scope is refused before the backend call and
  audited (`blocked:out_of_scope`), and a garbled/unreadable/empty scope file refuses all mutations
  (`blocked:scope_unreadable`). Guest-identity targets normalize (`lxc/N:action` → `lxc/N`) but never
  cross kind or plane; the gate takes no caller-supplied parameter — scope is file-only, closing the
  self-authorization path. **Honest ceiling:** an in-scope action is still unauthenticated as-to-intent
  (max-risk ceiling, scope expiry, and a signed task-token are deferred fast-follows). 46 tests + a
  3-lens redteam (coverage / matching-rule / fail-closed) that caught one Med-High (a snapshot-plan
  false-authorize).
- **Auto-expiring arm TTL** (`lease.py`; `PROXIMO_ARM_TTL` + `PROXIMO_TOKEN_PATH`) — closes
  fail-open-over-time: armed write-authority previously survived session-end/crash/reboot indefinitely,
  reverting only on a manual `disarm`. Authority now auto-expires N seconds after the arm token's
  mtime (the arm step stamps it via `install -m 600`). Fail-closed on a garbled/non-positive TTL, an
  unset/missing token path, a non-regular-file path, or a future mtime (clock skew — never "assume
  fresh"). Reads and dry-run PLAN stay ungated, so an expired lease auto-downgrades arm to read-only.
  16 tests, including 2 redteam regressions (future-mtime and directory-token-path fail-opens).
- **Per-surface autonomy envelope — FORBID + RATE/BUDGET walls** (`envelope.py`; `PROXIMO_FORBID` /
  `PROXIMO_RATE_MAX` / `PROXIMO_RATE_WINDOW`, shipped as two commits). The operator declares limits
  once per surface; the agent runs autonomously inside them; the system enforces by construction; the
  human is on-exception — not a per-action human-in-the-loop lever.
  - **FORBID** (commit 1/2) — a deterministic per-target/per-action denylist, resolved
    kind-agnostically so it gates every plane uniformly. Composite matching (action + target +
    `detail["action"]`, not tool name) closes sub-action holes in `pve_guest_power`,
    `node_service_control`, and `pmg_quarantine_action`; a global floor (`PROXIMO_FORBID`) applies to
    every mutation regardless of target and cannot be escaped; an unregistered active target fails
    closed rather than going silently inert. 18 tests.
  - **RATE/BUDGET** (commit 2/2) — a per-box, `flock`-guarded, sliding-window mutation-rate limiter,
    the answer to velocity-under-hijack: an atomic reservation file (temp + `os.replace`, crash-safe)
    keyed by `base_url` (physical box identity), capped at the *tightest* limit across every
    name/env config for that box so a caller can't dodge it by omitting or swapping
    `proximo_target`. Per-operation de-dup so a multi-seam mutation reserves exactly one slot.
    Replaces a naive whole-ledger-count design from the WIP, refuted by a 3-lens redteam for
    concurrency races and per-instance undercounting. That same redteam found and fixed 7 further
    hardening gaps: `rate_window<=0` fail-open, NaN/±inf slot values slipping the fail-closed branch,
    an unaudited reservation-read crash, a followable lock-sidecar symlink, a window-blind tie-break,
    and unbounded reservation-file growth. **Honest limit** (stated in the module docstring): the
    reservation file is **not tamper-evident** — a co-located agent with write access to the
    reservation dir can reset its own budget; CONTAIN's out-of-band kill is the real velocity
    backstop. 18 more tests (39 total in `test_envelope.py`); a 20-thread concurrency barrier
    confirmed exactly-k (3) reservations and per-box isolation.

### Security
- **`proximo.env` now actually loads at startup**, closing a footgun that left the new gates above
  silently inert. Under stdio the server previously saw only the MCP client's inline env block, so a
  `PROXIMO_*` var set in the documented `~/.config/proximo/proximo.env` was ignored without warning —
  **fail-dangerous for CONSENT**: `PROXIMO_CONSENT_DIR` set there left the gate silently off while the
  operator believed every mutation needed sign-off. `load_env_file()` now sources the file first thing
  in `server.main()` / `proximo-a2a`, filling only unset `PROXIMO_*` keys (real/inline env always
  wins), touching only that namespace (no `PATH`/`LD_*` injection); a missing file is a no-op, and a
  loaded file announces itself on stderr. Also fixes the identical pre-existing gap for
  `PROXIMO_ENABLE_EXEC` and its siblings. 8 tests, including namespace isolation and an
  env-wins-over-file precedence check.
- **PROVE ledger hardened against symlink redirection** — the audit append and both rotation
  sidecar-lock opens now use `O_NOFOLLOW`, and the ledger/key **directories** refuse a symlinked path
  (`islink` guard) before `makedirs`. Closes a co-located-writer escape on the flagship pillar: a
  planted symlink at the ledger path — or its parent dir — could previously redirect tamper-evident
  appends onto an arbitrary target the service can write. Brings PROVE to parity with the ENVELOPE
  rate-lock's existing guard. 7 symlink/concurrency tests, including real-`flock` barrier proofs the
  ledger had lacked.
- **Rate wall now evaluated AFTER consent** — the per-surface RATE reservation was split out of the
  envelope check and moved below `enforce_consent` at all 5 seams, so a consent-refused mutation no
  longer spends a slot from the box's budget. Closes an operator-DoS lever: a looping/hijacked agent
  could otherwise burn the whole window's budget on attempts consent would refuse, denying the human's
  own approved mutations. FORBID stays an early hard wall (spends nothing); fail-closed semantics and
  the one-slot-per-operation de-dup are unchanged.

### Changed
- **Docs truth-sized to shipped defaults.** `SECURITY.md` gains a "two-deployment trust model" (the
  Proxmox token is the hard floor, enforced by server-side RBAC; the in-process gates are a boundary
  only when their state paths sit outside the agent's reach), a controls-and-defaults table (which
  gates are on-by-default vs opt-in, with their env vars), and a prompt-injection / untrusted-tool-
  output section. `README.md` and the dev docs reframed off "four pillars" → "four on by default +
  opt-in controls" (explicitly not marketed as a bundled "pillar" system).
- **Release / CI hygiene.** `server.json`'s version fields are now covered by the version-consistency
  gate (`scripts/version_tools.py` check/set/release); the Trivy image scan and the internal-mirror
  CI's `pip-audit` are now blocking (both verified clean first). PMG who/what/when group CRUD collapsed to shared generics
  (public API unchanged); `blast.py`'s two largest functions decomposed and an mccabe complexity gate
  added; a CONTAIN/envelope live-smoke script added (FORBID + concurrent RATE barrier vs a real host).

### Fixed
- **`pve_acme_plugin_create` / `pve_acme_plugin_update` crashed whenever `dns_api` was set.** The
  wrappers map `dns_api` onto PVE's `api` body field via `kw["api"]`, but the acme_certs.py helpers'
  own first positional parameter (the backend) was also named `api`, so `**kw` collided
  (`TypeError: got multiple values for argument 'api'`). Because `dns_api` (the DNS provider) is the
  primary real use of these tools, both were unusable — update crashed on dry-run *and* execute,
  create on execute. Renamed the backend param to `backend`. Surfaced by the new per-wrapper
  request-shape sweep; regression-tested on the confirm=True executor path the sweep can't reach.

## [0.12.0] — 2026-06-30

**The `doctor` preflight goes multi-target-aware, plus a PMG login-concurrency fix. No new tools
(still 351 across PVE/PBS/PMG/PDM); no behavior change at the default.** A small, deliberate minor:
0.11.0 made the MCP tools target-aware but left the `doctor` *CLI* pinned to the env-configured box;
this closes that gap. Drop-in over 0.11.0 — nothing to read before upgrading.

### Added
- **`proximo doctor --target <name>`** — the `doctor` CLI preflight can now target a named remote from
  the `PROXIMO_TARGETS` registry (the `pve_doctor` MCP tool was already target-aware; this wires the
  CLI flag). Omit `--target` and behavior is byte-identical (the env-configured box).

### Fixed
- **PMG ticket-refresh race** — `PmgBackend` now serializes login under a lock (double-checked in
  `_ensure_ticket`; the 401 re-login is locked, with the HTTP retry left *outside* the lock to avoid a
  deadlock). Latent under the single-threaded stdio transport, but a real correctness gap if the
  backend is ever driven from multiple threads/async tasks.

## [0.11.0] — 2026-06-30

**Native multi-target + the ACME cert-order plane (347 → 351 tools).** One Proximo instance now
reaches many Proxmox remotes (internal *and* external) via an explicit per-tool `proximo_target=`;
omit it and behavior is byte-identical to before. Also closes the ACME gap (certs could be configured
but never *issued* through Proximo). **Read "Changed" before upgrading** — the PBS/PMG/PDM `verify_tls`
fix is fail-closed. Multi-target was adversarially redteamed (6 dimensions) and live-proven against two
distinct real boxes (PVE + PBS).

### Added
- **ACME certificate *order* plane — closes the gap where Proxmox certs could be half-configured
  but never issued through Proximo.** Account + DNS-challenge plugin tools already existed; nothing
  set the node-side ACME config or triggered an order. Four new tools (**347 → 351**):
  - `pve_node_acme_domains_set` — set a node's ACME `account=` + domains (`PUT /nodes/{node}/config`),
    DNS-01 (`acmedomainN=domain=…,plugin=…`) or standalone http-01. REPLACE semantics: stale
    `acmedomainN` indices are removed, not merged. Strict FQDN validation blocks config-property
    injection through the `,`/`=` delimiters. MEDIUM — config only, no cert issued.
  - `pve_acme_cert_order` — order a new cert (`POST …/certificates/acme/certificate`, async UPID).
    MEDIUM, **not** HIGH like `pve_node_cert_upload`: CA-validated, installed only on a successful
    challenge (a failure can't lock you out); reloads pveproxy on success.
  - `pve_acme_cert_renew` — renew the existing cert (`PUT …`, `force`=renew even if >30d to expiry).
  - `pve_acme_cert_revoke` — revoke at the CA (`DELETE …`). HIGH/irreversible; use
    `pve_node_cert_delete` to fall back to self-signed *without* revoking.
  - Endpoint shapes pinned against a live PVE 9.2.3 `pvesh usage` schema; carry `Smoke-confirm:`
    until live-fired.
- **Native multi-target — one Proximo instance can address many Proxmox remotes** (internal *and*
  external; any of PVE/PBS/PMG/PDM), replacing the one-instance-per-box model.
  - A TOML **target registry** (`PROXIMO_TARGETS`) of named remotes; each carries its connection
    fields with the **secret by reference** (`token_path`/`password_path`), never inlined.
  - Every tool gains an optional **`proximo_target="name"`** parameter. Omit it (the default) and
    behavior is **byte-identical to before** — the env-configured box, every existing test unchanged.
  - The target rides a per-call `ContextVar`, so **PLAN and EXECUTE always hit the same box**; PROVE
    records a **`remote`** field per entry (one chain; omitted on the default path so default-box
    entry hashes are unchanged). **Kind-checked:** a `pbs_*` tool given a `pve` target errors — no
    silent cross-plane call, and a `pve_*` tool aimed at a non-pve target errors rather than silently
    hitting the env box.
  - **No new tools** — `proximo_target` is a parameter on the existing surface. Per-target arming
    stays out-of-band (swaps the operator token at that target's `token_path`).
  - In-container exec (`ct_exec`/`ct_psql`/`ct_logs`/`ct_diagnose`) is target-aware too, but runs
    `pct exec` over SSH — a targeted call needs that box SSH-reachable (`enable_exec` + `ssh_target`);
    an external API-only remote won't serve it.
  - **Adversarially redteamed** (6-dimension review): the core invariants — contextvar isolation,
    kind-safety, secret-by-reference, one-chain PROVE, default-path hash-stability — were confirmed
    sound; the one real finding (the `ct_*` exec tools were not yet target-aware) is fixed above. A
    structural test asserts every remote-acting tool advertises `proximo_target` (only `audit_verify`,
    which verifies *this* instance's ledger, is exempt).
  - See `packaging/targets.example.toml` and the README "Multiple targets" section.

### Changed (review before upgrading)
- **`PROXIMO_PBS_VERIFY_TLS` / `PROXIMO_PMG_VERIFY_TLS` / `PROXIMO_PDM_VERIFY_TLS` now honor the full
  falsy set (`0`/`false`/`off`/`no`) like PVE — and the backend then refuses to start without a CA
  bundle (fail-closed).** Previously only the literal `false` disabled TLS; `0`/`off`/`no` were
  silently ignored and TLS stayed on. If you set one of these to `0`/`off`/`no` and relied on it
  being ignored, **that plane will now fail to start** — remove it (TLS on) or set the matching
  `…_CA_BUNDLE`. (Extends the 0.10.0 PVE `PROXIMO_VERIFY_TLS` fail-closed fix to the other planes.)

## [0.10.0] — 2026-06-29

Security-hardening release. An adversarial multi-agent redteam of the full surface produced 32
confirmed findings (2 high, 8 medium, 22 low); 30 are fixed and 2 are documented-as-inherent. Also
includes three live-proven loose-end fixes. **No new tools** (still 347 across PVE/PBS/PMG/PDM).
**Read "Changed" before upgrading — several fixes are fail-closed and can affect an existing deployment.**

### Changed (review before upgrading)
- **`PROXIMO_VERIFY_TLS=0`/`no`/`off` now actually disables TLS verification as written — and the
  backend then REFUSES to start without a CA bundle (fail-closed).** Previously these values were
  silently ignored and TLS stayed on. If you set `PROXIMO_VERIFY_TLS=0` and relied on it being
  ignored, **the server will now fail to start** — remove it (TLS on) or set `PROXIMO_CA_BUNDLE`.
- **Stricter input validation rejects malformed values that were previously accepted:** non-numeric
  CTIDs (`ct_exec`/`ct_psql`/`ct_logs`/`ct_diagnose`), PBS node names and PMG tracker IDs containing
  path/query metacharacters, and a non-string `raidlevel`. Well-formed input is unaffected.
- **`PROXIMO_SSH_TARGET` is charset-validated at startup** (rejects option-injection shapes such as a
  leading `-`); a normal host / alias / `user@host` is unaffected.
- **Risk labels corrected (some ops now plan at a higher tier):** PMG quarantine `action=delete` →
  HIGH (irreversible); PBS `realm_sync remove_vanished=true`, PVE `node_dns_set`, and PBS
  `traffic_control_delete` → MEDIUM. If you gate approvals on risk tier, these now need the higher gate.

### Security
- **No credential reaches the PROVE ledger or a plan response.** ACME DNS-plugin `data` (Cloudflare/AWS
  provider keys) and create-time `password` options are now redacted in plan output; PDM
  secret-stripping is case-insensitive and recursive.
- **Path-traversal / query-injection seams closed** in PMG `tracker_detail`, PBS `tasks_list`, and
  `access_permissions` (URL-encoded / charset-guarded path segments).
- **A2A DNS-rebind Host guard is always on** (was token-only); IPv6 `::1` loopback bind fixed.
- **PROVE ledger hardened:** a crafted log line can no longer brick the append path (a non-string
  `entry_hash` is rejected); a keyed→unkeyed downgrade now seals + rotates the keyed chain (custody
  seam) instead of silently appending unverifiable bare-SHA entries; `PROXIMO_AUDIT_KEYED=off` warns.

### Fixed
- **Plan/execute honesty (the trust spine):** `pve_create_container`/`pve_create_vm` surface the create
  `options` in the plan (a privileged LXC plans at HIGH); `pve_clone` surfaces name/pool;
  `pve_ha_resource_add` surfaces `max_restart`/`max_relocate` (0 warns it disables CRM action);
  `pve_token_create` surfaces expire/comment.
- **`pve_backup_job_create` guest selection:** `all_guests`/`pool`/`exclude` exposed with
  mutually-exclusive validation (was vmid-only). _Live-proven against real PVE._
- **`pve_network_iface_update`** auto-injects the interface's current `type` so an address-only change
  applies (PVE requires `type`) while a type *change* stays impossible by construction. _PVE-schema-confirmed._
- **Config writes** route through the shared form-coercion so a native bool reaches PVE as `1`/`0`
  (was `True`/`False` → HTTP 400); backend-layer file-path validation added to qemu-agent file ops.
- **`pdm-smoke`** routes its version probe to a PVE remote (PBS remotes return 400 on it). _Live-proven._

### Notes
- Two findings are inherent and documented rather than patched: credentials necessarily travel as MCP
  tool parameters (server-side redaction is complete; the parameter itself lives at the client/LLM
  boundary), and a process-death window in the synchronous audit ledger (fsync plus the Proxmox task
  log are the compensating controls).

## [0.9.0] — 2026-06-27

### Added
- **PDM surface — 22 tools (Proxmox Datacenter Manager).** A fourth surface behind a dedicated
  `PdmBackend` (API-token auth, `PDMAPIToken` scheme), covering the PDM read API: datacenter
  self/topology (ping, version, node status, remotes), fleet aggregate (resources, status),
  tasks + access (tasks, ACL, roles, users), and per-remote proxied reads — PVE
  (`pdm_pve_resources` / `cluster_status` / `node_list` / `qemu_list` / `qemu_config` /
  `lxc_list` / `lxc_config`) and PBS (`pdm_pbs_*`: status, datastores, snapshots). **Read-only
  (DIAGNOSE) throughout — no PDM mutation path.** Brings the surface to **347 tools across 4
  surfaces** (PVE / PBS / PMG / PDM).

### Fixed
- **PDM group-C `state` param.** `pdm_pve_qemu_config` / `pdm_pve_lxc_config` treated the `state`
  query param as optional, but PDM requires it — so a plain call returned `400`. They now default
  `state="active"` (the current-config enum value) and always send it.

## [0.8.1] — 2026-06-27

### Added
- **Official MCP Registry support.** Added `server.json` (2025-12-11 schema) plus a PyPI
  package-ownership token in the README, so Proximo can be published to
  `registry.modelcontextprotocol.io` — which in turn feeds downstream directories
  (Glama, PulseMCP).

### Fixed
- **Docs:** PMG surface count is now correct on the published package (103 net tools; one tool
  was removed in 0.8.0, so the gross "104 new" netted to 103).

Packaging + docs only — no functional/code changes from 0.8.0.

## [0.8.0] — 2026-06-26

### Added
- **PMG surface — 104 new tools (Proxmox Mail Gateway).** Full coverage of the PMG 9.1 API
  behind a dedicated `PmgBackend` (ticket-based auth: `POST /access/ticket` → PMGAuthCookie +
  CSRFPreventionToken; TLS-strict, fail-closed, credential never logged or cached on disk):
  - **Observability:** node status, mail statistics, per-sender/domain/virus/spamscore statistics,
    quarantine spam/virus/attachment status, syslog, RRD node performance data.
  - **Quarantine:** spam/virus/attachment list, per-user spam scores, blocklist and welcomelist CRUD
    (add/remove), `pmg_quarantine_action` (confirm-gated: deliver/delete/mark-seen/blocklist/welcomelist).
  - **Config CRUD:** managed domains (list/create/delete), transport maps (list/create/delete),
    `mynetworks` CIDR entries (list/add/remove), spam config read + confirm-gated update,
    mail relay/smarthost config, TLS/ACME/subscription read.
  - **Service control:** service status and `pmg_service_control` (confirm-gated restart/stop/start
    per `pmg-smtp-filter`, `postfix`, `pmgproxy`, `pmgdaemon`).
  - **RuleDB filtering engine:** full rule/action/object-group management — groups (list/create/
    delete/update), object types (`who`/`what`/`when`/`action`/`timeframe`), rules (list/create/
    delete/update), object assignment (`add_to`/`remove_from`), and rule ordering
    (`pmg_ruledb_apply` confirm-gated).
  - **Backup:** `pmg_backup_run` (confirm-gated scheduled-backup trigger).
  - **Postfix:** queue shape (`pmg_postfix_qshape`) and `pmg_postfix_flush` (confirm-gated queue
    flush).
  - **Doctor:** `pmg_doctor` reads version, access permissions, and node status to verify
    connectivity and token scope — same startup-verify pattern as `pve_doctor`.
- **PMG quarantine tool surface cleanup (breaking, pre-release).** The deliver path previously had
  its own dedicated tool (`pmg_quarantine_deliver`); it was a strict subset of
  `pmg_quarantine_action(action="deliver")` — already live-proven — and was removed to keep one
  consistent action surface. The `pmg_quarantine_list` tool (spam quarantine only) is renamed
  `pmg_quarantine_spam` for symmetry with `pmg_quarantine_virus` / `pmg_quarantine_attachment`. The
  read-collection tools `pmg_quarantine_blocklist` and `pmg_quarantine_welcomelist` gain the `_list`
  suffix (`pmg_quarantine_blocklist_list`, `pmg_quarantine_welcomelist_list`) matching every other
  read-collection tool (`pmg_domains_list`, `pbs_*_list`, etc.). The mutators
  (`pmg_quarantine_blocklist_add` / `_remove`, `pmg_quarantine_welcomelist_add` / `_remove`) are
  unchanged. Tool count: 326 → 325 (PMG 104 → 103).
- **+6 PBS coverage tools** — fills gaps in the PBS surface: `pbs_remotes_list`,
  `pbs_remote_get`, `pbs_datastores_list` (all-datastore view), `pbs_datastore_status` (per-
  datastore detail), `pbs_traffic_control_list`, `pbs_sync_jobs_list`.

### Fixed
- **`pbs_group_change_owner`** now issues `POST /admin/datastore/{ds}/change-owner` (was `PUT`,
  which PBS 4.2 rejects with HTTP 404). Caught by live-smoke against the test PBS instance —
  a case where mocks passed but the wire failed.

### Changed
- Tool count **145 → 325** (PVE 184 + PBS 33 + PMG 103 + `ct_*` 4 + `audit` 1).
- All three Proxmox surfaces (VE · Backup Server · Mail Gateway) are now **live-proven** against
  real Proxmox instances. PMG W1–W5 smoke confirmed: auth, read shapes, safe CRUD cycles (domain/
  transport/mynetworks/spam-config/welcomelist/blocklist), service restart + polling, RuleDB
  paths, and PLAN-path honesty on confirm-gated ops.
- `pyproject.toml` description and keywords updated to reflect the three-surface control plane
  (`pmg`, `mail-gateway` added to keywords).

## [0.7.4] — 2026-06-24

### Added
- **`pip-audit` is now a blocking CI gate** (was a warn-only on-ramp). The resolved dependency
  set is clean — verified by replicating CI's `pip install -e ".[dev]"` resolution, which lands on
  `cryptography` 49.0.0 / `starlette` 1.3.1 / `pydantic-settings` 2.14.2 with no known advisories.
  A new CVE in a resolved dependency now reds CI until it's patched.
- **Trivy image vulnerability scanning** (`.github/workflows/trivy.yml`) — continuous scanning
  of the container image's OS-package + library layers (the `python:3.13-slim` base + apt layer),
  which `pip-audit` (Python deps) and CodeQL (source) don't cover. Findings upload to the Security
  tab. Report-first on-ramp; flips to blocking once a green run confirms the baseline.
- **OpenSSF Scorecard** (`.github/workflows/scorecard.yml`) — supply-chain posture scoring,
  published to the public dashboard.
- **`SECURITY.md`** — security policy + a private vulnerability-reporting path (GitHub private
  advisories), with honest scope notes (risk ratings are advisory, not a sandbox; the PVE token
  is the trust boundary) and image/PyPI authenticity-verification guidance.
- **Scoped CodeQL to the shipped package (`src/`)** via `.github/codeql/codeql-config.yml`,
  matching the existing pyright scope. The dev/demo scripts under `scripts/` print connection
  metadata (node, API base URL) and operation output — which CodeQL's taint tracker flagged as
  `py/clear-text-logging-sensitive-data`, though the token secret is never logged — producing 32
  false positives with no shipped impact. SAST now analyzes exactly what ships.

### Security
- **`ApiBackend` now refuses to construct over unverified TLS** — `PROXIMO_VERIFY_TLS=false` with no
  CA bundle raises `ProximoError` instead of warning, matching the rule `PbsBackend` already enforces
  (every request carries the PVE token; a read-only token is still a credential). **Breaking** if you
  ran with `verify_tls=false`: set `PROXIMO_CA_BUNDLE` to the PVE CA cert (preferred) or
  `PROXIMO_VERIFY_TLS=true`. (audit H-2)

### Fixed
*From an internal adversarial audit (8 dimensions, each finding independently verified):*
- **PLAN integrity on multi-node clusters (C-1):** `plan_config_set` / `plan_config_revert` read live
  config from the *configured default* node, ignoring the `node` the mutation targets — so the PROVE
  plan snapshot could be from the wrong node. Both now resolve `node or config.node`, matching the
  execute path.
- **Audit-ledger crash on a corrupt tail line (H-1):** `_last_hash` didn't guard a valid-JSON
  *non-dict* line, raising `TypeError` — which could crash `record()` mid-mutation (entry unrecorded)
  or DoS `audit_verify`/`head()`. Now guarded the same way `verify()` already was.
- **Exec opt-in is enforced at the backend (M-3):** `ExecBackend.run()` now checks
  `PROXIMO_ENABLE_EXEC` itself, not only at the server layer — defense-in-depth against a future
  direct caller.
- **cloud-init UNDO honesty (M-1, M-2):** an undo-capture failure no longer degrades silently — it is
  surfaced in the result status and the PROVE ledger (`ok:undo_unavailable`); and the undo record now
  discloses that a revert does not delete keys the change added.

### Changed (docs honesty)
- **Honest UNDO scope in README/SETUP (H-3):** the tagline no longer claims *every* dangerous move is
  undoable — now "undoable wherever the platform can snapshot" (delete / template-convert /
  token-revoke and firewall/SDN/ACL ops are irreversible by design, as the body already said).
- Corrected a stale tool count in an A2A docstring (116 → 145, L-3).
- **README/landing copy restructured** — leads with *what it does* + the trust layer, before the backend plumbing (so a reader scanning for the value hits the safety model first, not the API table); the roadmap section trimmed to forward-looking items.

## [0.7.3] — 2026-06-24

### Added
- **`proximo doctor` CLI** — runs the read-only preflight (`pve_doctor`) from the shell and prints its
  JSON, so a user can verify their token/config and see exactly what it CAN and CANNOT do **before**
  wiring Proximo into any AI client. Exits non-zero with a plain message on a config/connectivity error.
- **`SETUP.md`** — a beginner-proof, token-first setup guide (GUI + CLI): create a least-privilege
  (read-only) token, point Proximo at your server, verify the boundary with `proximo doctor`, then
  grant scoped write only when ready. Ships in the sdist.

### Changed
- **Rollback PLAN now warns that PVE excludes `description`/`tags` from snapshots** — so a rollback does
  not revert those fields (use `pve_guest_config_set` / `pve_guest_config_revert` to change them). Surfaced
  by dogfooding against a live cluster, where a set description survived a rollback. No API change.
- **The PBS "not configured" error now points at the PVE-path fallback** — when `PROXIMO_PBS_*` is unset,
  the error suggests `pve_backup_list` against a pbs-type storage, which needs no PBS config (it uses the
  PVE token already in hand). No API change.

## [0.7.2] — 2026-06-23

### Packaging / Security
- **Both publish paths now ship only the user-facing set (deny-by-default).** The github mirror already
  curated its tree; the **sdist did not** — hatchling bundled the whole repo root, so internal dev/strategy
  docs rode along in the published source distribution. Now `[tool.hatch.build.targets.sdist]` ships an
  explicit allowlist (src + README + CHANGELOG + LICENSE), and the mirror's deny list adds
  `POSITIONING.md` / `LANDSCAPE.md` / `ROADMAP.md` alongside `CLAUDE.md`. Internal strategy + dev-memory +
  `.gitea/` + `.remember/` no longer publish on either path. (The wheel was always clean — `packages =
  src/proximo`.) No code or API change.

## [0.7.1] — 2026-06-23

**PROVE robustness — 0.7.0 harden pass.** Crash-consistency, concurrency, and upgrade-UX hardening
around the keyed PROVE ledger. The crypto guarantees themselves (chain integrity, downgrade-rejection,
no-key forgery, tail-pin detection) were re-verified under adversarial testing as **holding** — these
are robustness fixes around them, not crypto changes.

### Fixed
- **`verify()` no longer crashes on a non-string `entry_hash`.** A tampered entry whose `entry_hash`
  was a truthy non-string (a number, list, …) raised `TypeError` instead of reporting tamper — a
  writer-with-access DoS on the verify pillar. It now fails the check cleanly.
- **A crash-torn last line can no longer corrupt the next append.** If a crash left the final line
  without its trailing newline, `record()` now starts the new entry on a fresh line instead of
  gluing two JSON objects onto one physical line (which the forward walk read as a single unparseable
  line, silently re-anchoring the chain at GENESIS).
- **Keyed-default migration is now race-safe.** `seal_and_rotate` claims the new keyed log path
  atomically (temp file + `os.replace`); a concurrent writer that creates the log in the rotate
  window is clobbered rather than landing an unkeyed entry at line 1 (which would have made the live
  keyed ledger fail `verify()` permanently). A concurrent-start "loser" no longer emits a migration
  warning with an empty archive path.

### Changed
- **A pinned head is normalized before validation** (`PROXIMO_AUDIT_EXPECTED_HEAD` and the
  `audit_verify(expected_head=)` param): a hexdigest is case-insensitive and a copy-paste often
  carries a trailing newline or spaces, so an uppercased/whitespaced head is now accepted instead of
  raising. Previously a fat-fingered pin raised in config — which is read on *every* tool call, so it
  broke all tools, not just `audit_verify`. Genuinely malformed pins still raise; a blank value is
  treated as unpinned. `PROXIMO_AUDIT_KEYED` likewise tolerates surrounding whitespace (`" off "`).
- **`audit_verify` returns a `rotation_hint`** when a head mismatch coincides with a sibling
  migration archive — telling the operator whether the mismatch is the expected keyed-default upgrade
  rotation (re-pin) or a genuine tail attack, since the migration's stderr warning is often swallowed
  by MCP stdio clients.
- **Setting `PROXIMO_AUDIT_KEY_PATH` with `PROXIMO_AUDIT_KEYED=off` now warns** that the explicit key
  path takes precedence (the ledger is keyed), instead of silently keying.

### Security
- **The release leak-audit denies `CLAUDE.md` by basename** in BOTH the `audit` report and the
  `build-tree` publisher — they now share one `partition_paths` rule, so `CLAUDE.md` (including a
  nested `docs/CLAUDE.md`) is stripped from the published tree, not merely flagged. Previously a
  basename deny was honored by `audit` but invisible to the prefix-only tree builder (the two could
  drift — audit "clean" while the tree publishes the file).

### Upgrade
- The race-safe migration fix covers the in-process rename window. A ledger is still **all-keyed or
  all-unkeyed for its whole life**, so during a *rolling* upgrade **quiesce or upgrade all writers of
  a given ledger together** — a mixed keyed/unkeyed fleet writing the same ledger across the cutover
  will land a downgraded entry and fail `verify()`. Single-process deployments are unaffected.

## [0.7.0] — 2026-06-23

**PROVE hardening.** Keyed (HMAC) PROVE by default, off-box head-pinning to catch tail attacks,
and a stripped-down public mirror. The keyed default **auto-migrates** an existing unkeyed ledger
on first run — see Upgrade below.

### Added
- PROVE head-pinning: `audit_verify(expected_head=...)` and `PROXIMO_AUDIT_EXPECTED_HEAD`
  catch tail truncation / forged append / full wipe (the off-box anchor is the strong guarantee).
  A malformed pin is rejected as a clear caller error (one 64-hex shape rule guards both the
  per-call `expected_head` and the env default), so a typo never masquerades as a tamper alarm.
  When no head is pinned, `audit_verify` returns a one-line `hint` nudging the operator to anchor
  the head off-box — so the guarantee isn't silently left unused.

### Changed
- PROVE ledger is now **keyed (HMAC-SHA256) by default** (`PROXIMO_AUDIT_KEYED`, opt out with `off`).
  An existing unkeyed ledger is sealed and archived (never deleted), and a fresh keyed log is
  started recording the prior head as a custody seam. Key-gen failure fails closed (no silent downgrade).

### Upgrade
- **Keyed PROVE is now the default — and existing ledgers auto-migrate.** On first run after
  upgrading, an existing *unkeyed* ledger is sealed and archived (`audit.log.unkeyed-<stamp>-<head8>`,
  never deleted) and a fresh *keyed* log is started. A loud warning prints the new head; if you pin
  `PROXIMO_AUDIT_EXPECTED_HEAD`, **re-pin it to that new head**. To stay unkeyed, set
  `PROXIMO_AUDIT_KEYED=off` before upgrading.

## [0.6.5] — 2026-06-22

**Security & live-integration CI.** Closes an A2A bind auth-bypass, hardens identifier validation,
fixes a plan-honesty gap, and lands a substantial live-integration smoke harness that exercises the
trust spine against a real cluster. No new tools (145).

**Released 2026-06-22** — published on PyPI (`proximo-proxmox`), GitHub (Release `v0.6.5`), and GHCR
(signed multi-arch image).

### Security
- **A2A auth-bypass: an empty bind host bound every interface *without* auth.** `_is_public` treated
  an empty/whitespace host as non-public (`bool("")` is `False`), so `PROXIMO_A2A_HOST=""` bound
  `0.0.0.0` — all interfaces — while skipping the bearer-token requirement a non-loopback bind is
  meant to force. An empty, `None`, or whitespace-only host is now classified public: the A2A control
  endpoint refuses to start on it without a bearer token, fail-closed like any other public bind.
- **Identifier validation hardened.** `vmid` is validated as ASCII digits (was `str.isdigit()`, which
  accepts non-ASCII Unicode digits); `realmid` rejects `.`/`..` dot-segments (the path-traversal class
  closed across the other identifiers in 0.6.2/0.6.3); firewall alias CIDRs are validated; and the
  TLS-verify default is pinned fail-closed by test.

### Fixed
- **Plan honesty: `pve_network_iface_update` preview was blind to staged `options`.** The dry-run did
  not disclose every field it would stage, and a reserved `type` key could be passed through. The plan
  now discloses the staged fields and rejects the reserved key.

### Added
- **Public-tree leak-gate catches bare internal hostnames.** The release leak-audit previously matched
  only dotted internal TLDs (`.lan`/`.internal`/`.intranet`); it now also refuses bare internal
  hostnames via an internal-only denylist (itself stripped from the public tree).
- **Registry-completeness gate (CI).** A test pins the read-only tool set and asserts every *other*
  registered tool takes a `confirm=` parameter, so a new mutating tool cannot ship un-gated. (It proves
  a mutator *has* the confirm gate, not that `confirm=False` no-ops.)
- **Live-integration smoke harness.** A phase-tagged orchestrator (`scripts/live-smoke/run-all.py`:
  read → plan → mutate → destroy, escalating by blast radius) plus planes for the mutate slice,
  access-CRUD, storage-admin, and PBS (namespace / snapshot-delete / prune / gc / verify). Each plane
  is guarded by an independent default-deny allowlist (`safety.py`) — a VMID/storage/PBS-host not named
  as a test target is refused *before* any API call, a second safety layer beneath the scoped token —
  is self-seeding and self-cleaning, and SKIPs when its scoped env is unset. The PBS `verify` smoke
  asserts *real, scoped* verification (the target snapshot's `verification.state == 'ok'` and a decoy
  snapshot left untouched). It is wired to a nightly advisory CI job (non-blocking); the read+plan
  slice runs with only a read token and is proven end-to-end against a real cluster.
- **Characterization fixtures pin the blast engine to real PVE response shapes**
  (`tests/test_live_shapes.py`), locking the backup-job selection-mode serialization the
  `guest_destroy` resolver depends on against ground truth — real PVE omits unset `pool`/`vmid` keys
  rather than sending `null`, serializes `all` as an int and `exclude` as a comma-string, and always
  carries a synthetic `current` snapshot entry. Shape-only and credential-free, so they run in the
  fast suite.

### Docs
- **Overclaim corrections.** Fixed a self-contradicting "the hypervisor is never touched" line, the
  PROVE "verifiable" framing, and the PLAN "gate" wording; replaced hardcoded test counts with
  drift-resistant phrasing.

## [0.6.4] — 2026-06-21

**Honesty, UX & defense-in-depth.** Small fixes surfaced by a fresh-eyes multi-agent audit whose
headline finding was that the trust spine holds under five independent adversarial reads. No new
tools (145).

### Security
- **Defense-in-depth: `_check_userid` now rejects `.`/`..` dot-segments**, matching its sibling
  validators (`_check_tokenid` / `_check_roleid`). A userid was safe only by side-effect of its no-`/`
  charset; the explicit guard keeps path-traversal closed if that charset is ever loosened.

### Fixed
- **A2A install hint named a nonexistent distribution.** `pip install 'proximo[a2a]'` (in the runtime
  error message, README, `a2a/__init__.py`, and `pyproject.toml`) hard-failed — the PyPI project is
  `proximo-proxmox`. All four now say `proximo-proxmox[a2a]`.
- **Honesty: "the PVE token never read or logged" was inaccurate.** The token IS read from its file at
  call time (it just isn't logged or persisted). The README and package docstring now say so, matching
  the code's own comment.

### Docs
- **UNDO pillar reframed to its real coverage.** It was presented as a symmetric peer pillar
  ("auto-snapshot + rollback"); in reality auto-snapshot is opt-in and exec-only, guests use
  config-revert / `pve_rollback`, and the firewall/SDN/ACL/token planes aren't PVE-snapshottable at all.
  README + CLAUDE.md now state UNDO covers the snapshottable surface, not every mutation.
- **Blast-radius op-class count corrected** in the README (ten → eleven `compute_*` functions).
- **Two stale security comments corrected** (`storage_admin.py`, `access_governance.py`) that described
  path-traversal gaps the validators actually close.

## [0.6.3] — 2026-06-21

**Defense-in-depth & plan honesty.** Two non-destructive fixes from the post-0.6.2 codebase sweep: a
`pve_clone` dry-run that mislabeled the default *linked* clone as a "new independent guest" now reflects
`full`, and two more path-traversal dot-segments — siblings of the 0.6.2 `pve_token_revoke` fix — are
rejected in the network-interface and storage validators. No new tools (145).

### Fixed
- **Plan honesty: `pve_clone` dry-run mislabeled a linked clone as "independent".** `plan_clone` was
  blind to `full` (the tool never forwarded it), so the dry-run unconditionally said *"new independent
  guest"* — true only for `full=True`, while the default `full=False` is a **linked** clone (copy-on-write,
  template-dependent). It also previewed a storage-targeted clone as viable even though the op refuses
  `storage` without `full=True`. The plan now reflects `full`: linked-vs-full wording, the template
  precondition for a linked clone, and a "will be REFUSED" note for `storage` without `full`. (Same class
  as the firewall rule-precedence fix — the preview describing the wrong behavior. Non-destructive: every
  divergent path already fails closed.)
- **Security (defense-in-depth): two more path-traversal dot-segments closed.** Following the 0.6.2
  `pve_token_revoke` fix, a codebase-wide sweep of path-interpolated identifiers found two siblings
  whose validator permitted a `.`/`..` segment the HTTP client normalizes onto a different endpoint:
  - `_check_iface` rejected `..` but **not a lone `.`** — `pve_network_iface_update(iface=".")`
    collapsed `PUT /nodes/{n}/network/.` onto `PUT /nodes/{n}/network`, the network-config **apply**
    endpoint (a disruptive wrong-target op the plan mislabeled as an interface update).
  - `_check_storage` had no dot-segment guard (storage `.`/`..` collapsed to non-destructive
    endpoints — lower severity, same class).
  Both now reject `.`/`..`. Legit VLAN interfaces (`eth0.100`) and dotted storage ids are unaffected.
  (The other path-interpolated validators were verified to already guard this — start-with-alphanumeric
  anchors, explicit `..` rejects, or `@`/numeric structure.)

## [0.6.2] — 2026-06-20

**Security & correctness.** A path-traversal that could delete a user via `pve_token_revoke`, a
firewall rule-precedence honesty fix, two PROVE/blast-radius corrections, and opt-in ledger redaction
for `ct_psql`/`ct_exec`. No new tools (145); the trust spine was independently re-reviewed and verified.

### Added
- **Clone target storage.** `pve_clone` accepts a `storage` parameter to place a full clone's disks
  on a chosen storage (e.g. to keep the clone off the source storage). Refused for linked clones —
  PVE only honors a storage override on a full copy, so the plan rejects it up front rather than
  send a request PVE will reject. The clone plan also now discloses the `SDN.Use`-on-bridge
  permission the cloned NIC requires on PVE 8+.
- **Release leak-audit guard.** `scripts/release_leak_audit.py` models the curated GitHub publish
  tree (which gitleaks and the pre-push hook never see, because it's a synthetic `git commit-tree`):
  it strips internal-only paths (`.gitea/`) and refuses to publish if the public surface carries a
  leak shape — RFC1918 IP, internal-TLD hostname, `/root` path, or credential token. Wired into the
  `release.sh` gate; `build-tree` emits the clean, audited tree SHA for `git commit-tree`.
- **Opt-in ledger redaction.** `PROXIMO_LEDGER_REDACT=1` makes `ct_psql` and `ct_exec` record a
  fingerprint (sha256 + kind + length) of the SQL / command instead of the body, for operators whose
  SQL or command args may carry secrets/PII (e.g. `--password ...`). Both the ledger `detail` and the
  persisted plan are covered. Default unchanged — the body is recorded for a complete audit trail.

### Fixed
- **Security: path-traversal in `pve_token_revoke` could delete the entire user.** `_check_tokenid`
  (and `_check_roleid`) accepted an all-dots identifier. `pve_token_revoke(userid=u, tokenid="..")`
  built `DELETE /access/users/{u}/token/..`, which the HTTP client normalizes (RFC 3986 dot-segments)
  to `DELETE /access/users/{u}` — deleting the **user** and all their tokens/ACLs, while the dry-run
  plan and the tamper-evident audit ledger both recorded a harmless *"revoke token"*. A wrong-target
  destructive mutation that bypassed both PLAN and PROVE. Now rejects `.`/`..`-class segments (the
  same guard `_check_acl_path` / `_check_tfa_id` already applied). MCP-path only — `pve_token_revoke`
  is excluded from the A2A slice. (Verified empirically against the project's httpx.)
- **Honesty/safety: firewall rule-add disclosed the WRONG rule precedence.** `pve_firewall_rule_add`'s
  docstring and plan claimed the new rule is *"appended — positions of existing rules are not shifted."*
  PVE actually inserts a created rule at the **TOP (position 0)** — `pos` is ignored on create — shifting
  existing rules down, so the new rule takes **precedence** (matching is first-match, top-down). The plan
  told operators the opposite of the truth: a DROP they believed was lowest-precedence lands at the top
  and can shadow an existing SSH/8006 ACCEPT — the exact lockout the tool exists to prevent. Corrected to
  disclose top-insertion and the precedence/lockout implication. (Verified against the PVE API docs +
  the "pos ignored on create" forum report.)
- **PROVE: `pve_guest_power` recorded `outcome="ok"` for an async task.** Guest power
  (start/stop/reboot/shutdown) is task-backed — the `POST .../status/{action}` returns a UPID, like
  every other async op (and the identical-shape `node_service_control`). The ledger now records
  `"submitted"`, never `"ok"`: it must not claim the guest started/stopped when only the task was
  accepted. (The lone async op that asserted completion.)
- **Blast-radius: ACL incomplete group-resolution under-reported risk.** When a group-type ACL entry
  exists in scope but the target's group membership couldn't be resolved (e.g. a failed `user_get`),
  a shadowed inherited grant could be hidden — the engine disclosed this in prose but left the
  structured risk at MEDIUM. It now forces HIGH, matching the honesty contract every sibling engine
  upholds (incomplete enumeration that could hide harm escalates; over-flag is acceptable).
- **Honesty: audit-ledger docstring overclaim.** `audit.py` said *"Secrets are never written here"*
  while `ct_psql` records the SQL body; corrected to state the PVE token is never written and that
  `ct_psql`/`ct_exec` record the SQL/command (redactable via `PROXIMO_LEDGER_REDACT`).
- **Blast-radius: boot-disk under-report.** When a guest's boot disk was indeterminate (legacy
  `boot: c`/`cdn` or no boot line) and it lost a disk on the target storage, the engine reported a
  survivable `degraded`/MEDIUM loss with the false note *"boot disk is elsewhere"* — even though a
  lost disk could itself be the boot disk. It now over-flags as `may NOT boot`/HIGH and never claims
  the boot disk is elsewhere when it cannot see where it is (over-flag, never under-flag).
- **Honesty: package docstring overclaim.** `proximo.__doc__` said *"Least-privilege by default …
  secrets never read or logged"*; corrected to match the README — *"bounded by the token you scope …
  the PVE token never read or logged"* (the API plane has no built-in scoping; `ct_psql` SQL is
  recorded in the ledger).

## [0.6.1] — 2026-06-20

**Release-process & CI hardening.** No functional changes to the shipped package — the
`proximo` runtime code is identical to 0.6.0; this release brings the repository's release
and security tooling up to standard (and is the first release published via the new
tokenless pipeline).

### Added
- **Drift-proof releases.** `scripts/version_tools.py` (single source of truth for the
  version) + `scripts/release.sh` (one-command bump + local gate), plus a
  `version-consistency` CI check that fails the build if `pyproject.toml`,
  `src/proximo/__init__.py`, the git tag, and the CHANGELOG ever disagree.
- **Security CI.** gitleaks (secret scanning), pip-audit (dependency CVEs), CodeQL code
  scanning, and Dependabot (GitHub Actions + pip + security updates).
- **Tokenless PyPI publishing** via OIDC Trusted Publishing, gated behind a manual-approval
  environment — no API token in the release path.

### Changed
- Hardened the MCP tool-count guard (145) against silently-shadowed tools.

## [0.6.0] — 2026-06-19

**Blast-radius coverage push.** Extends the computed blast-radius engine across the destructive tool
surface so no dangerous operation falls back to a bare confirm: ten op-classes (#6–15) now read live
cluster state at plan time and NAME the specific cross-resource consequences (the guests an action
strands, the nodes a firewall change locks out, the principals an ACL deletion orphans, the disk a
volume delete destroys). Each was built test-first and adversarially redteamed — every redteam pass
caught a real under-flag, all fixed. No new tools (still 145); **+86 tests (2308 → 2394)**, ruff +
pyright clean. Backward-compatible (additive). Verified against a real Proxmox: PLAN-checks on live
cluster data, plus a bounded allocate→delete→verify on an isolated test sandbox.

### Added
- **In-use-disk blast for `pve_storage_content_delete` (op-class #14, rank 9).** Deleting a storage volume
  now scans guest configs cluster-wide and, if the volid is an ACTIVE guest disk, names the owning guest
  and escalates to HIGH (won't-boot if it's the boot disk / only copy / EFI-TPM). Exact volid match (so
  `vm-101-disk-0` is not confused with `vm-101-disk-00`); a mounted-ISO (`media=cdrom`) reference is not
  mislabeled as a data disk. Incomplete enumeration is forced HIGH, never read as "not in use".
- **Last-copy blast for `pve_backup_delete` (op-class #15, rank 8).** Deleting a backup archive now reads
  the storage's backup list and reports whether OTHER recovery points of the same guest remain — deleting
  the LAST backup leaves no recovery point (named in `Plan.affected`). Read failure or unparseable guest id
  is disclosed (`complete=False`), never read as "other copies exist". Risk stays HIGH throughout.
- **Attachment blast for `pve_network_iface_update` (op-class #13, rank 4).** Editing a bridge now reads
  the cluster guests and NAMES every guest with a NIC on that bridge — they have their networking
  disrupted when the staged change is applied (token-level bridge match, so editing `vmbr1` does not
  false-match a guest on `vmbr10`). Risk stays MEDIUM (the edit is staged/reversible; `network_apply`
  carries the HIGH mgmt-lockout via the existing apply-lockout engine); the value is naming the
  affected guests in `Plan.affected`. Incomplete guest enumeration is disclosed, never read as safe.
- **Access-plane blast-radius coverage (op-classes #9–12, ranks 5–7).** Four mutating access tools that
  silently orphaned permissions now read the ACL / user DB and NAME exactly who loses access:
  `pve_pool_delete` (was pure/no-reads — now names the principals whose grants on `/pool/<id>` orphan;
  escalates MEDIUM→HIGH when real grants break or a read fails), `pve_group_delete` (now names the
  group-level ACL grants its members lose, not just the member list), `pve_role_update` (names every ACL
  grant the new privilege set re-privileges), and `pve_realm_update` (names every user whose login the
  change could break). Each populates `Plan.affected`/`complete` and follows the read-failure honesty
  contract (a failed read → disclosed + never read as safe). Mirrors the already-covered delete siblings.
- **Disk-residency blast for `pve_guest_migrate` (op-class #8).** `plan_migrate` warned generically
  "requires shared storage"; it now reads the guest's disks + cluster storage.cfg and names exactly which
  disks block a clean migration to the target: a disk on LOCAL/non-shared storage (must be copied with
  `with-local-disks`, or the migrate fails — and a live migration is impossible), a disk on storage that
  is `nodes`-restricted off the target (cannot place at all), a RAW/passthrough device (cannot follow the
  guest to another node), or storage whose config is unreadable (assessed conservatively, never assumed
  migratable). Escalates a live-qemu MEDIUM migrate to HIGH when a disk makes it impossible; risk is never
  lowered. Clean only when every disk is provably shared and available on the target. Closes rank 3.
- **Computed blast-radius for the firewall lockout pair (op-class #7).** `pve_firewall_set_enabled`
  (enable) and `pve_firewall_options_set` (`policy_in=DROP`, `enable`, or unset-`policy_in`) now read the
  firewall ruleset at plan time and **name the nodes that would lose management access** under the
  resulting default-DROP policy: a node is flagged LOCKOUT if its (datacenter ∪ node) ruleset has no
  ENABLED inbound ACCEPT for SSH(22)/PVE(8006), CONDITIONAL if the only such ACCEPT is source-restricted
  to a specific host/range/set (locks out any admin outside it), and disclosed-but-not-flagged if it is
  open or internal/private-restricted. A disabled / outbound / udp / wrong-port rule is never counted as
  protection (no under-flagged lockout); unreadable rules or unenumerable nodes force HIGH and are never
  read as safe. Cluster/node scope only (a guest firewall is self-scoped). The op stays RISK_HIGH
  throughout — the engine names the at-risk nodes, it never lowers risk. Closes rank 2 of the coverage audit.
- **Computed blast-radius for `pve_disk_move` (op-class #6).** Moving a disk onto a target storage now
  reads the target at plan time and names the cross-resource impact: a fit check using the disk's
  PROVISIONED size (worst case) flags a move that **won't fit / fills the target** (HIGH), an
  absolute-free floor plus a percent-of-total threshold flags a **TIGHT** target (MEDIUM), and either
  case names the **co-tenant guests** that share the target and would face allocation pressure. Capacity
  that cannot be read (size or free space unreadable, or incomplete cluster enumeration) is forced HIGH
  and never reported as safe; when the disk fits comfortably, co-tenants are **not** flagged (no
  cry-wolf). The engine only escalates a plan's risk, never lowers it. Hardened `_parse_size_bytes` to
  fail-closed on non-positive/blank input (no wrong-small int can slip past a capacity check). Closes the
  highest-severity gap from the 2026-06-19 blast-radius coverage audit.

### Known gaps (logged, not silently dropped)
- `pbs_prune` and `pbs_namespace_delete` (PBS-server side) are already RISK_HIGH with honest "destroys
  ALL recovery points / no undo" warnings — they do not fall back to a bare confirm. The remaining
  enhancement is *itemizing* which snapshots/groups would be removed (PBS prune `--dry-run` /
  per-namespace group enumeration), which needs the PBS datastore API surface; deferred as a quality
  (not safety) improvement.

## [0.5.0] — 2026-06-19

Three additive features — A2A **signed agent cards** (SIGNET), a native **async-task wait** tool, and a
fifth computed blast-radius op-class (**storage nodes-restrict**). Backward-compatible. Tool surface
**144 → 145** (one new read tool); each built test-first and adversarially redteamed.

**Released 2026-06-19** — published on PyPI (`proximo-proxmox`), GitHub (Release `v0.5.0`), and GHCR
(signed multi-arch image).

### Added
- **Signed A2A agent cards (SIGNET).** Opt-in ES256/JWS signatures over the A2A AgentCard (via the
  a2a-sdk signing helpers, RFC 8785 canonicalization), with the operator public key published as a JWKS
  at `GET /.well-known/jwks.json` (`kid` = RFC 7638 thumbprint; `jku` set). `alg` is pinned to ES256 on
  both signer and verifier — the HS256 algorithm-confusion class is structurally refused. Enable with
  `PROXIMO_A2A_SIGNING_KEY_FILE` (EC P-256 PEM); absent → unsigned card (backward-compatible). Ships
  `verifier_for_jwk`, the client-side pinned verifier — it binds to an out-of-band-pinned key and
  ignores card-supplied `kid`/`jku`, so a MITM cannot substitute their own key. Adds `a2a-sdk[signing]`
  + `cryptography` to the `[a2a]` extra.
- **`pve_task_wait`** — block until an async Proxmox task (migrate / backup / restore / clone /
  rollback / snapshot + guest create) reaches a terminal state or a timeout, returning a structured
  `{upid, finished, succeeded, status, exitstatus, timed_out, polls}` (read-only; `succeeded` is fail-closed
  = stopped AND `exitstatus == "OK"`; timeout clamped 1–600 s, interval 1–60 s). Saves clients
  hand-rolling a `pve_task_status` poll loop. (Proximo's native UPID model — NOT the MCP Tasks protocol,
  which was removed from the spec.)
- **Blast-radius op-class #5 — storage nodes-restrict.** `pve_storage_update` with a restricted `nodes`
  list now NAMES the guests it would strand (those on an excluded node with a disk on the storage —
  won't-boot / degraded / live-crash), mirroring the storage-delete class and reusing its honesty
  contract (incomplete enumeration → loud, HIGH, never "safe"). `nodes=""` is correctly read as PVE's
  "clear restriction → all nodes" widening (strands nobody), not maximal stranding. Enriches the
  existing dry-run preview; adds no tool.

## [0.4.0] — 2026-06-16

A fourth computed blast-radius op-class — **guest-destroy** — on `pve_delete_guest`. Additive and
backward-compatible; tool surface stays **144** (it enriches the existing dry-run preview, adds no
tool). Built test-first, adversarially redteamed, and live read-only-smoked against a real cluster.

**Released 2026-06-16** — published on PyPI (`proximo-proxmox`), GitHub (Release `v0.4.0`), and GHCR
(signed multi-arch image, attestation verified). First public release since 0.2.0; rolls up the 0.3.0
blast classes + `pve_doctor` in the same version.

### Added
- **Blast-radius op-class #4 — guest-destroy.** `pve_delete_guest` dry-run now computes, at PLAN
  time, what destroying a guest actually does, conditional on the call's `purge`/`force`:
  - **What PVE will REFUSE** (`force` does not override the first two): `protection=1`, a template
    with linked clones (names the clones; detection is config-based — LVM-thin/ZFS/RBD — and carries
    an explicit caveat that directory/qcow2 backing chains are not visible in config), and a running
    guest without `force`. An indeterminate run-state with `force=false` is reported as incomplete,
    never as a clean "go."
  - **References, conditional on `purge`:** HA resource, replication jobs, and explicit backup-job
    vmid lists — phrased as "left dangling" when `purge=false` and "removed by purge" when `purge=true`
    (never the opposite). Pool membership is resolved live via `pool_get`.
  - **Intrinsic removals:** disks + their storages, real snapshots (PVE's synthetic `current`
    live-state row is excluded), and pool membership.
  - **Honesty contract:** every edge is read fail-closed; a failed read flags `complete=False` and
    is never reported as "nothing found"; backup coverage is resolved per mode — `all=1` (covered
    unless excluded), `pool=X` (covered iff target is in that pool, incomplete only if pool data
    unreadable), explicit `vmid` list (direct); only a truly unrecognizable selection stays
    incomplete. The common real-cluster `all=1, exclude=…` config no longer cries "incomplete" on
    every destroy plan. (`compute_guest_destroy_blast` / `gather_guest_dependents`.)

## [0.3.0] — 2026-06-16

The blast-radius engine across all op-classes (storage · access/ACL · firewall/network) + a new
onboarding preflight (`pve_doctor`). All additive and backward-compatible; tool surface 143 → **144**.

### Added
- **Computed blast-radius (storage/disk class).** `pve_storage_delete` and `pve_storage_update`
  (disable) now read the cluster at PLAN time and **name the actual guests** that lose disks —
  cluster-wide — distinguishing *"will not boot"* (boot disk / only copy on the storage) from
  *"degraded"* (a non-boot disk lost). Surfaced as `blast_radius` strings **and** a new structured
  `affected: list[dict]` field (additive, non-breaking), and recorded to the PROVE ledger.
  Fail-closed: an incomplete enumeration renders a loud `⚠ INCOMPLETE` marker, never lowers risk,
  and is never read as "nothing affected = safe". New pure engine `proximo.blast` (the graph
  reasoning is unit-tested with zero API). First op-class of the broader blast-radius thesis —
  access/ACL and firewall/network follow the same seam.
  (Spec: `docs/specs/2026-06-15-blast-radius-engine.md`.)
- **Computed blast-radius (access/ACL class).** `pve_acl_modify` now extracts its shadow/widen
  reasoning into the pure `proximo.blast.compute_acl_blast`, populates the structured `affected`
  field, **completes** the target's shadow by resolving their own group-inherited grants (#1), and
  lists who-else-can-reach the path as explicit **UNCHANGED** context (#2). Honest per-principal
  model: only the target gains/loses; group members are never reported as gaining/losing. privsep=1
  tokens do not fold owner groups. Fail-closed throughout (caveat retained when a read fails; risk
  never lowered). (Spec: `docs/specs/2026-06-15-acl-blast-radius.md`.)
- **Computed blast-radius (firewall reach — Part A).** `pve_firewall_rule_add` / `rule_remove` /
  `rule_update` now classify the **per-rule REACH** — *"this rule permits SSH (22/tcp) from
  0.0.0.0/0"* — via the new pure `proximo.blast.compute_firewall_reach`, surfaced as `blast_radius`
  lines **and** the structured `affected` field, recorded to the PROVE ledger. Honest framing:
  reach is a property of **the rule** (what it permits/blocks *if* it is the deciding match in an
  enforced, default-DROP firewall), never an assertion that *"the cluster is exposed"* as fact.
  Missing field → **maximal, never benign**: empty `dport` → ALL ports, empty `source` → anywhere,
  an ipset/alias reference (`+name`/`dc/name`) → unknown-conservative (never "low"). `enable=0` →
  *"staged, not active"*. Removing an ACCEPT names what it **closes**; removing a DROP/REJECT names
  what it **re-permits**; an update classifies the **post-update** rule. Risk is only ever raised,
  never below the MEDIUM floor. (Spec: `docs/specs/2026-06-15-firewall-network-blast-radius.md`.)
- **Computed blast-radius (network-apply lockout — Part B).** `pve_network_apply` now best-effort
  **names the management interface** a network apply would touch: it parses the management host from
  the configured API base URL and, via the pure `proximo.blast.compute_apply_lockout`, names the
  pending interface that carries it (*"this apply changes `vmbr0`, which holds the management host —
  you will lose SSH/API"*), surfaced as `blast_radius` lines + the structured `affected` field.
  This sits on top of the **unconditional `RISK_HIGH`** that network apply already carries — naming
  the interface can only add specificity, never lower risk. Honest by construction: a hostname
  management host, an addressless interface read, a non-pending match, or a read failure all yield
  *"could not identify the management interface — HIGH stands; assume lockout risk"*, **never** "no
  lockout". `pve_sdn_apply` gains a light note that the management path is normally on a plain
  bridge, not an SDN vnet. (Spec: `docs/specs/2026-06-15-firewall-network-blast-radius.md`.)
- **`pve_doctor` — onboarding preflight (read-only).** Checks API reachability + reads the calling
  token's *effective* permissions, then reports what the token CAN / CANNOT do — with the privilege
  + role to grant for each gap. Turns raw `403`s into an actionable checklist; run it first after
  install to verify config/token before wiring Proximo into an MCP client. Routed through the PROVE
  ledger as a read; same advisory posture as DIAGNOSE. Per-capability match-mode prevents overclaim
  (rollback is its own capability — `VM.Snapshot` without `VM.Snapshot.Rollback` is reported as
  create-only, never "UNDO works"). Adds `ApiBackend.version()` + `access_permissions()`. Brings the
  tool surface to **144** — the prior 0.2.0 docs' "144" was an off-by-one (the shipped artifact
  served 143); with `pve_doctor` the documented count is now accurate.

## [0.2.0] — 2026-06-15

Complete the four **half-built planes** to total CRUD coverage. **26 new MCP tools**
(surface now 144), each wearing the PLAN + PROVE trust substrate by construction, built
test-first, adversarially redteamed, and — where the operation is a reversible config-object
edit — **live-proven on a real PVE 9.2 node**.

### Added
- **Firewall objects plane (11 tools)** — aliases (`list`/`create`/`update`/`delete`),
  IP-sets (`create`/`delete` + entry `add`/`remove`), security groups (`create`/`delete`),
  and firewall `options_set`. Scope-aware (cluster/node/guest) via `_fw_base`.
- **HA rules plane (3 tools)** — `ha_rule_create`/`update`/`delete`, the PVE 9 replacement
  for the deprecated HA groups. Auto-detects the groups→rules migration and surfaces it
  honestly rather than 500-ing.
- **SDN plane (10 tools)** — zones (`create`/`update`/`delete`), VNets
  (`create`/`update`/`delete`), subnets (`list`/`create`/`update`/`delete`). New objects stay
  *pending* until `sdn_apply`, so create→delete reverts cleanly with no effect on the
  production network. (`sdn_apply` is unchanged — not re-added here.)
- **TFA admin (2 tools)** — `tfa_get`, `tfa_delete`. PVE gates TFA *mutation* behind a
  ticket-based login session, not an API token: `tfa_delete` is shape-correct and reaches the
  API but is ticket-gated (403 with a token); reads work via token. TFA enrollment remains out
  of scope (interactive challenge→confirm).

### Changed
- `pyright` is scoped to `src/` (`[tool.pyright] include = ["src"]`) so the default run
  reflects the shipped package; structural test-double type noise no longer pollutes the clean
  signal. Tests stay inspectable on demand (`pyright tests/`).

---

## [0.1.2] — 2026-06-14

Distribution + supply-chain hardening. No changes to the MCP/A2A surface or behavior.

### Added
- **GHCR container image** — a release workflow builds and publishes a multi-arch
  (`linux/amd64` + `linux/arm64`) image to `ghcr.io/john-broadway/proximo` on each GitHub
  Release. `docker run -i --rm … ghcr.io/john-broadway/proximo` runs the stdio MCP server on
  demand — no daemon, no open port. Images ship with an SBOM and a sigstore-signed
  build-provenance attestation (`gh attestation verify oci://… --owner john-broadway`).

### Security
- **CI / supply-chain hardening** (independent 3-lens review): workflows default to
  `permissions: contents: read`; the publish and signing actions are pinned by commit SHA
  with a Dependabot keeper; the Docker build uses an allow-list `COPY` so a local build
  can't bake stray secrets into the image.

---

## [0.1.1] — 2026-06-10 — "Spaniard"

Hardening + release-readiness pass driven by an independent multi-team audit (3 cold reviewers,
40 doc claims source-verified, full-history leak audit, adversarial verification of every finding).

### Added
- **Realm options dict** (`8d2dac0`): `pve_realm_create` and `pve_realm_update` now accept a
  type-specific `options` dict — LDAP (`server1`/`base_dn`/`user_attr`), AD (`domain`/`server1`),
  OpenID (`issuer-url`/`client-id`). Previously, creating any LDAP/AD/OpenID realm was impossible
  through the tool. Live-proven against a real PVE 9.2 API.
- **Governance/dangerous plane — live-proven to execute** (milestone): the governance and dangerous
  plane (identity role/group/user/ACL; storage; SDN apply; network apply; realm create) that was
  previously built+redteamed but MOCKED-only is now **proven to execute create→read→delete against
  a real PVE 9.2 API on a nested test cluster**. Also proven on a nested 3-node test cluster:
  offline guest migration (including local-disk) and HA-config operations (resource add/list/remove)
  execute. PROVE ledger verified throughout. **Honest scope:** "nested test cluster" — not
  production scale; HA **fencing** (hardware watchdog) and **online** live-migration (shared storage)
  remain unproven.
- **CI**: GitHub Actions workflow — ruff + the full pytest suite on Python 3.12 and 3.13.

### Security
- **A2A perimeter hardening** (`a8ce10b`, `0d952a6`): fail-closed by design — non-localhost bind
  is **refused** unless `PROXIMO_A2A_TOKEN_FILE` is set; bearer auth (constant-time comparison) on
  the JSON-RPC control endpoint when a token is set; Host-header allowlist + DNS-rebind defense
  (`PROXIMO_A2A_ALLOWED_HOSTS`); `'*'` in the allowlist warns rather than silently disabling. The
  agent card declares the bearer scheme. localhost-default dev behavior unchanged; A2A stays opt-in.
- **Audit ledger file permissions:** the ledger is now created `0600` (owner-only) instead of the
  umask default — entries can carry command/SQL detail and were world-readable on typical umasks.
  Applies at creation; an existing file keeps the mode its operator set.

### Fixed
- Realm create/update no longer silently ignores type-specific options (LDAP/AD/OpenID realms
  were uncreatable before this fix).
- **Audit-integrity:** `ct_logs` now enforces the CTID allowlist at the server layer like its
  siblings — a forbidden CTID ledgers as `blocked:allowlist` instead of surfacing as a backend error,
  so allowlist denials are uniformly traceable in the PROVE ledger. Blocked entries for read-only
  tools (`ct_logs`, `ct_diagnose`) now ledger `mutation: false`, matching the tool's true class.
- **Packaging:** `proximo-a2a` without the `[a2a]` extra now prints a one-line
  `pip install "proximo[a2a]"` hint (exit 2) instead of a raw `ModuleNotFoundError` traceback —
  including when only `uvicorn` is missing; a missing *submodule* of an installed dependency still
  tracebacks (that is a real environment bug, not a missing extra).

### Notes
- **117 MCP tools; 1964 tests passing (0 skipped); ruff clean.** Published 2026-06-10 — GitHub + PyPI (`proximo-proxmox`); GHCR pending.
- Docs: public-readiness scrub of ROADMAP/CHANGELOG/POSITIONING; README install command made
  copy-pasteable; claim wording tightened to carry its own scope. Lint: 3 leftover warnings in the
  live-smoke scripts cleaned.

## [0.1.0] — 2026-06-09 — "Spaniard"

First blood — the foundation of the ethical Proxmox MCP. _Tagged `v0.1.0`; not yet published to
PyPI/GHCR (local/private). Honest scope: 117 MCP tools, most exercised against mocks only; the trust
spine + core lifecycle are live-proven, the governance plane is built/redteamed but not yet live-fired._

### Added
- **MCP stdio transport, proven end-to-end:** `python -m proximo` entry point; the `initialize` handshake
  advertises Proximo's own version (not the MCP SDK's); covered by a real-client integration test
  (`test_mcp_stdio_e2e.py`: client → stdio → FastMCP dispatch → tool → back).
- Two backends: **REST API management** (scoped token) + **`ssh`→`pct` in-container exec** (local or remote).
- **MCP tool surface** (FastMCP): `pve_node_status`, `pve_list_guests`, `pve_guest_status`,
  `pve_guest_power`, `ct_exec`, `ct_psql`, `ct_logs`.
- **Ethical spine:** append-only audit log (records real outcomes), confirm-gates on every mutating tool,
  fail-closed CTID allowlist, input validation on API path components (vmid/kind/node).
- Tests (13) + ruff lint config. Clean run.

### Security
- Security redteam (2026-06-07): **5 findings, all fixed** —
  `ct_exec`/`ct_psql` now confirm-gated; allowlist now fails **closed**; audit records real outcomes
  (errors included); `vmid`/`kind`/`node` validated against injection; TLS-disabled now warns.
- Verified solid: command injection (shlex-correct on local + ssh + psql paths); the API token is never
  logged, never enters the audit log, subprocess argv, or error messages.

### PROVE pillar — tamper-evident ledger (2026-06-07)
- The audit log is now a **hash-chained, tamper-evident ledger**: `entry_hash = sha256(prev_hash + body)`,
  flock-guarded, fsync'd. `verify()` and the `audit_verify` MCP tool detect any altered / deleted /
  inserted / reordered entry and pinpoint the break; `head()` is anchorable off-box. Tamper-**evident**,
  not tamper-proof (honestly scoped). +6 tamper-detection tests. Redteam: 2 findings fixed.
- This is one of the four trust-layer pillars (PLAN · UNDO · **PROVE** · DIAGNOSE).

### PLAN pillar — dry-run by default (2026-06-07)
- New `proximo.planning` module: **every mutating tool now previews before it acts.** Called without
  `confirm=True`, `pve_guest_power` / `ct_exec` / `ct_psql` return a **plan** — the exact change, the
  guest's live state (power), blast radius, and an **advisory, heuristic risk rating** — instead of
  executing. `confirm=True` then executes. You structurally cannot mutate without a plan first existing.
- **PLAN ⊗ PROVE:** the previewed plan (including the live state it was based on) is written to the
  tamper-evident ledger with `outcome="planned"`; a confirmed execution records `confirmed=true`. The
  approval trail — *what preview was shown before the action* — is now verifiable, not just *that* it ran.
- **Honest by design (guard every path to LOW):** `LOW` means "does not change state," not "safe";
  the absence of a `HIGH` flag is not a safety signal; destructive signatures are curated, not exhaustive.
- Adversarial review: confirmed bypasses fixed — whitelist audit (`find -delete`, `ip route add`,
  `mount <dev>` no longer rate "read-only"); SQL `SELECT pg_terminate_backend()/lo_import()`,
  `COPY ... PROGRAM` (RCE) now escalate; failed dry-runs are audited; `current` state recorded; latent
  `_max_risk`/`_fmt_uptime` edge crashes fixed. Every confirmed bypass became a regression test.
- Tests: **81 total** (was 21), ruff clean.
- **Guarantee enforced:** the plan is recorded on BOTH paths — even a one-shot `confirm=True` records
  its `planned` entry before mutating (no plan, no mutation). The PLAN→PROVE triplet
  (`planned → ok/confirmed`) is uniform; a one-shot confirm can't bypass the recorded preview.

### UNDO pillar — auto-snapshot before mutating + one-call revert (2026-06-07)
- **Snapshot backend + tools:** `pve_snapshot_list` (read), `pve_snapshot_create`, `pve_rollback`
  (DESTRUCTIVE — discards changes since the snapshot), `pve_snapshot_delete` (all PLAN-gated), and
  `pve_task_status` to poll the async task UPIDs these return. Endpoints verified against PVE docs.
- **The headline — auto-undo before exec:** `ct_exec`/`ct_psql` gain `snapshot=True`. With `confirm=True`
  it takes a `proximo_undo_<ts>` snapshot **and waits for the task to finish** before running the
  mutation, records the undo point, and returns it. **Fail-closed:** if the snapshot can't be created
  or doesn't finish OK (e.g. storage doesn't support snapshots), the command is **NOT run**.
- **Honest:** snapshots are storage-dependent (ZFS/BTRFS/LVM-thin; not directory/raw) — surfaced in the
  plan, never assumed. Rollback's PLAN spells out the blast radius. Async ops record `outcome="submitted"`
  (not "ok") so the ledger never claims an in-flight task is done.
- Adversarial review: confirmed fixes, each a regression test — regex anchors `$`→`\Z` (newline bypass),
  UPID length cap + reserved-name (`current`) guard, microsecond-unique undo names, strict task-exit
  (fail-closed on missing `exitstatus`), server-layer allowlist gate (no orphaned snapshot for a
  forbidden CTID), non-contradictory rollback preview when the snapshot is missing.
- Tests: **116 total**, ruff clean.

### DIAGNOSE pillar — read-first "what's broken" (2026-06-07)
- New `proximo.diagnose` module + tools: `ct_diagnose` (API guest status + a FIXED read-only
  in-container battery — failed units, disk, recent errors, memory, listening ports) and
  `pve_diagnose` (node status + storage usage + recent failed tasks). Both strictly READ-ONLY
  (no confirm, no mutation), audited. Backend reads: `node_storage`, `node_tasks`.
- **Honest by design:** advisory flags, never causation ("signal present", not "the cause is X").
  Flags also surface **incompleteness** — partial mode (exec off → API-only + a skipped-probes flag),
  a failed read, or a failed probe all flag, so an empty `flags` list can never read as a false clean
  bill of health. Inactive/offline storage is reported as offline, not as "full" (no stale-data alarm).
- Adversarial review — read-only guarantee held (no injection, gates correct); the task-list `status`
  field was **verified against the live PVE API**. Fixes, each a regression test: incompleteness flags,
  inactive-storage handling, removed dead `--no-legend` guard, `_frac` inf/overflow guard, transient/
  WARNINGS tasks no longer counted as failed, `node_tasks` limit clamp, `ExecBackend` vmid validation.
- Tests: **141 total**, ruff clean. **All four trust-layer pillars (PLAN · UNDO · PROVE · DIAGNOSE) now built.**

### Coverage expansion — phases 1–7 (2026-05 → 2026-06)
- Grew the MCP surface from the 7 foundation tools to **117** `@mcp.tool()` tools, every mutating one
  wearing PLAN+UNDO+PROVE by construction: provisioning/backup/restore, config/disk/cloud-init mutation, the
  four "dangerous plane" domains (**firewall · network/SDN · cluster HA/migration · ACL/users/roles/realms**),
  observability, task/pool control, storage admin, and **PBS-native** deep tools (GC/verify/prune/snapshots/
  namespaces; separate `:8007` backend, TLS fail-closed).
- **Live-proven** against a real PVE: the core provisioning/config mutate cycle (create→config→revert→
  clone→backup→restore→delete, ledger verified) + read shapes across node/storage/observability + a
  PBS datastore. **Honest scope:** the bulk of the 117-tool surface — *including the dangerous plane* —
  is **MOCKED-only** (unit-tested against fakes, not fired against real Proxmox). A broad live smoke needs a
  wider scoped token.

### A2A (Agent2Agent) face — experimental (2026-06-09)
- Optional second protocol head (`pip install 'proximo[a2a]'` → `proximo-a2a`): a curated **16-skill slice**
  exposed over A2A, routing to the same server tools so PLAN/PROVE/UNDO/fail-closed are inherited. Serves an
  agent card at `/.well-known/agent-card.json`; localhost by default (no built-in auth — warns on
  non-localhost). Built + redteamed (PLAN-bypass + slice-boundary: **0 findings**); +47 tests. **Proven
  end-to-end against a real a2a-sdk client** — agent-card resolve over HTTP + a real `message/send` invoking a
  skill → completed task with a `result` artifact (real-socket proof + an in-process integration test,
  `test_a2a_e2e.py`).

### PROVE — opt-in HMAC-keyed audit chain (2026-06-09)
- The audit ledger now supports an **opt-in keyed mode**: set `PROXIMO_AUDIT_KEY_PATH` to chain entries
  with **HMAC-SHA256** instead of bare SHA-256 (key auto-generated at 0600 via an atomic temp+link, hex
  stored, fail-closed on empty/non-hex/<32-byte). The **ledger's key is authoritative** — a downgrade
  (strip the HMAC, recompute as SHA-256 without the key) is rejected; a keyed log must be all-keyed. Default
  stays **unkeyed and byte-identical** (existing logs + tests unaffected); `audit_verify` reports `keyed`.
  Adversarial review (forge / key-handling / verify lenses): no exploitable forgery; +12 tests incl. the downgrade
  attack. **Honest scope:** keying resists forward-rewrite by an attacker *without* the key, but a same-user
  attacker who can write the 0600 log can often read the 0600 key — the **off-box `head()` anchor remains
  the strong guarantee.** Not a "cryptographic depth" moat.

### Honesty note (2026-06-09)
- The PBS cert fingerprint is stored but **not yet wire-enforced**.

### Notes (as of 0.1.0 — historical; since superseded)
- At 0.1.0 this was **pre-alpha and not yet released**; Apache-2.0 LICENSE added. Then-pending: broad
  live smoke of the mocked surface (needs a properly-scoped token) and publish (PyPI/GHCR + CI) so the
  install commands work — **all since done.** Proximo is publicly released; see `[0.4.0]` above
  (published on PyPI · GitHub · GHCR).

_Strength and honor._
