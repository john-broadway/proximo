# Changelog

All notable changes to Proximo. Format loosely follows Keep a Changelog; versions are SemVer.

## [0.50.0] — 2026-10-27

**The estate memory is back.** Capability `estate-memory`, cut in 0.45 and restored in the core's idiom (`proximo.core.memory`). One SQLite file, `memory.db`, sits beside the ledger. It is created 0600 and opened read-write, never creating, after the file and its sidecars are checked; a symlink, a hard link, a file another user owns, one group or other can read, or an empty file memory did not create is refused, never quietly tightened. `PROXIMO_MEMORY_PATH` moves the file, under the same rules. It holds the estate graph: guests, nodes, storage, pools, backup jobs, bridges, backup volumes and ACL grants, with first and last seen and status changes, and the edges between them (`runs_on`, `disk_on`, `nic_on`, `in_pool`, `backup_of`, `covered_by`, `granted_on`). The edges come from the estate model's own constructors and relations (`estate.RELATIONS`, `Estate.edges`, which also gains `GET /access/acl`), so a terminal answer and a consult agree by construction. Names, tags and ids are indexed with FTS5; a sqlite built without FTS5 searches the same columns with LIKE, and doctor's new `memory` section flags that as advice. It is fed by reads that already happened, at the store's hook: the withheld answer of every read of a source the estate reads, a guest's config and pending included. A memory failure never fails the read, `PROXIMO_STORE=off` does not switch it off, and `PROXIMO_MEMORY=off` creates nothing. A read the engine makes for its own judgement keeps nothing, through a `judging` flag on the hook; a read asked with a field subset, or the door's own look at a plan's target, feeds what it lists and retires nothing, because the hook is handed how the read was asked (`fields`, `evaluating`). Nothing here dials. Four verbs join the shell door, with no model and no network beyond the vendor. `proximo-core learn` is the one deliberate pass: cluster resources, the token's permission map, storage, backup jobs, pools, ACLs, each node's network and each guest's pending config (the consult's own read), every read through the engine and receipted, under a budget of 256 reads, and it says `complete: false` and why when a read is refused, fails, is not kept, runs over the budget, or when the token's map does not show `VM.Audit` reaching every guest. `where 105` answers the kind, node, status and the concrete published paths, such as `GET /nodes/pve1/lxc/105/status/current`; every path it can print is checked against the table. `uses local` lists the guests with a disk or a NIC on it, by slot, and is incomplete while any guest's config is not in memory or anything was evicted since those configs were kept. `changed 24h` lists what was added, what is gone and whose status changed; gone means every whole read that had listed it (cluster resources, the storage definitions, pools, backup jobs, ACLs, a node's network, a storage's content) has since read whole without it, dated by the read that dropped it last rather than by when it was last seen, so a nightly `learn` and a morning `changed 24h` agree; a node-scoped list never makes anything gone, and what the first read of a kind found is not counted as added. Every answer says `source: memory`, `as_of` and `age_seconds`. A thing memory has not seen is "not in memory (learned N minutes ago, or never)", and an empty memory answers with no count at all, the 0.44 lesson for a small model that reads the number and not the prose. Taint survives storage: a row from an untrusted address keeps the mark and the address in the file, and an answer built from it marks the session as the read did, refuses when the marker cannot be written, and is fenced under `PROXIMO_TAINT_FENCE`. Rows are kept per plane and box, so a registry target never mixes with the env box. The file is bounded: names and tags are cut to 120 characters and an id longer than that is not kept at all (counted), a read of more than 20,000 rows is not kept, a box holds at most 50,000 entities and 200,000 edges with the oldest seen dropped first and counted, and each answer fits 4 KB, a cut list saying how much it shows and a path never cut. Measured on a 100-guest file with the connection held (a long-lived door holds one per thread): medians of about 0.2 ms for `where`, 0.4 ms for `uses` and 0.2 ms for `changed`; a fresh connection, which the shell door opens once per process, adds about 0.7 ms, so a first answer takes about 0.9 to 1.2 ms. Deleting the file loses convenience, never proof: the ledger never reads it. Not restored: 0.44's baselines and diagnose journal. The MCP find answering concrete paths from memory comes next, through `memory.resolve`.

**The one-line description says what Proximo is.** The governed client for Proxmox, of which MCP is one door; on PyPI, the MCP registry, LobeHub, the Debian package and the LXC listing it read "the Proxmox MCP you can hand the keys", a frame that was never the product (John, 2026-10-28: "we are not a Proxmox MCP server").

**CI action bumped.** docker/login-action 4.7.0, pinned by the SHA of its release (Dependabot #112). Two PyPI-install steps now say in place why they are unpinned.

**The public commit names its authors.** The curated release commit ends with a `Co-authored-by` trailer for every author and co-author of the release range other than the owner, so an outside contributor's work reaches the contributors graph under their name. 0.49.1 shipped RavenLiao's #107 without that; his PR is now merged on GitHub as his.

## [0.49.1] — 2026-10-27

**Shell calls across a cluster, and the operator's wait.** A patch: one new registry table and one new variable, both off until set; nothing an existing setup sends changes.

**Route PVE shell rows by target and node.** From RavenLiao, PR #107 (the node-routing half of #98). A named PVE target may map concrete path node names to
OpenSSH destinations. The existing five SSH rows use that mapping for plan checks, execution and
diagnosis; missing routes refuse before consent, rate reservation and snapshots. The default box
continues to use `PROXIMO_SSH_TARGET`, and the remote hostname guard still runs before `pct`.

**The shell wait is the operator's.** `PROXIMO_SHELL_TIMEOUT` sets how long one shell call waits for its command, in whole seconds from 1 to 600; unset is the 60 it always was. Any other value refuses every shell call before anything dials, names the variable and never echoes the value, and `proximo doctor` reports the effective wait (`shell_timeout`) or flags it garbled. No argument a model sends moves it. Issue #106.

**CI actions bumped.** setup-python 7.1.0, setup-uv 10.3.2, codeql-action 4.39.1 and pypi-publish at the head of `release/v1`, each pinned by the SHA of its release (Dependabot #105).

**A shell path's vmid is ASCII digits.** `\d` also read Arabic-Indic and full-width digits as a container id; pct reads only ASCII, so nothing ran, and now the address is refused as not a shell address.

**4,186 tests.**

## [0.49.0] — 2026-10-27

**A small model can drive the doors.** A lab run put a 1.7B model on the MCP door and it failed at the door, not the estate; then the owner ruled that the door, not the model, carries the token budget, and that an answer is data, a verdict and the next concrete path, in as few words as it can be. All of it is inside door contract 3.

THE EXIT. Every answer a model is handed, on MCP, REST and A2A (plan, read, find, recall, diagnose, undo, audit, refusal), is measured as its final serialized bytes, after the builders, the fence and the header, at one place (`mcpcompat.seal_result`). Over its kind's ceiling it is REPLACED by a fixed-shape answer of a few hundred bytes: the verdict and `needs`, the `consent_id`, what ran (`undo`, `task`, `intent`) for an executed mutation, counts of what was left out, and one fixed line ("the full plan is for the operator: proximo-core consent show <id>"). Nothing is exempt: a protected key cannot overflow it. Ceilings: reads, finds and audit 1,152 bytes; plans, calls and an undo's plan 2,048; a diagnosis 3,072; a refusal 512. A property test drives seeded hostile input (many long arguments, 2,000 unpublished names, dense digits, CJK, bidi, huge vendor records, 60 audit rows, 120 offline storages) through every tool, fenced and not, and asserts the bytes at the exit. The worst case in real tokens is the ceiling at one token a byte, which dense text reaches (1,152 for a read, 2,048 for a plan, 3,072 for a diagnosis, 512 for a refusal); at the measured 2.5 to 4 bytes a token it is a third of that. Measured worst answers (Qwen3 tokenizer, llama.cpp): plan 614, call 618, read 552, find 304, audit_entries 338, audit_verify 98, against the six tools at 942, so tools plus one worst answer of each kind (a call's dry run is a plan) is about 2,850; counting a call beside a plan it is about 3,470. A typical read of a 37-guest estate went from 992 to 928 bytes, a typical qemu create plan from 1,416 to 1,112, a find from 1,090 to 1,085, a small read from 216 to 144; the refusal for an unarmed call is 125.

TERSE. An answer drops the keys whose value is nothing (a null tier, a false `untrusted`, an empty `withheld`, a `matched_path` that only repeats `called_path`); a find offers only addresses this door will serve (not held, gated or excluded); `audit_entries` no longer says where the ledger file is; a plan's `why` is the tier's first sentence (the whole sentence is the operator's `--plan`); prose in `next` and the notes is cut to a clause.

A MODEL'S PLAN DOES NOT ECHO ITS OWN ARGUMENTS. A mutation plan carries the verdict and `needs`, the `consent_id`, every argument NAME (up to 48, then `arguments_more`), a value of up to 48 characters, and for a longer one `[N chars sha256:<12 hex>]` in place, listed in `not_shown_whole`, with `operator_view` naming the command. The operator's whole view is `proximo-core consent show <consent_id>`: a refused mutation now records what it proposed (its arguments as typed JSON, secrets fingerprinted, the box, the id) on its ledger row, and `consent show` prints them whole, RECOMPUTES the id from what it shows and refuses a row that does not reproduce it (the ledger is same-uid writable); where a secret stands as a fingerprint it says the id cannot be recomputed. `proximo-core ... --plan` still prints a plan uncapped. A plan writes nothing; a refusal row is the record, so `consent show` answers after the call is attempted.

WHICH ARGUMENTS ARE SECRETS IS AN AUTHORED JUDGEMENT. The name rule (`password`, `secret`, `key`, `token` ...) hid values that are not secrets: `tokens` on an ACL entry (which token got the role), `sshkeys`, `root-ssh-keys`, `authorized-tokens`, `keys` on a mail-gateway user, booleans like `delete-token`, and `limit-passive-requests` (`pass` inside `passive`). `records/secrets.toml` carries a `public` list per address with a why for each; the build refuses a line that does nothing; `pass` is matched as a word; the rule is ASCII only; and a test pins the list of 33 names the door still fingerprints, in the model's plan, the operator's view and the receipt alike, so a new hide is a visible decision.

ONE RULE FOR ANYTHING ECHOED BACK. What the model sent (a path, a method, an id, an argument) and live state read back come back through `rawdoor.echo`: the first characters, then `(N chars, sha256:<12 hex>)`. A refusal echoes at most 80 characters of what was typed, an undeclared argument is one fixed sentence and at most three names, an unknown tool is cut, an absurd path (over 512), method (over 16), id or name (over 128) is refused before it is echoed, and `called_path` in a header is clipped to 160. `echo` escapes by Unicode category, not a list: format characters (bidi, zero-width, the soft hyphen, the word joiner, the BOM, the tag block), line and paragraph separators, lone surrogates and control characters, inside lists and objects too, and it cannot raise. The display never touches the consent id or what is sent to the vendor.

THE CAPS BELOW THE EXIT make answers small on purpose: by bytes AND estimated tokens, reads 1.125 KiB and 750 tokens (it was 6 KiB, said to be 1.5K tokens and measured at 2,400 for lean rows, 3,300 for raw rows and 5,400 for CIDRs), plans 1.75 KiB, a diagnosis 4 KiB; `PROXIMO_RAW_MAX_BYTES` alone stands alone, `PROXIMO_RAW_MAX_TOKENS` sets the other, junk in either keeps the defaults and names itself (`cap_problem`, doctor). `rawdoor.estimate_tokens` weighs each byte by class and was fitted to seventeen fixed samples tokenized with llama.cpp on the Qwen3 vocabulary, at or above the count on every one; text nobody sampled can be denser, and it is for one tokenizer. A diagnosis groups six or more flags of one shape into one line, clips long strings with the echo mark, halves lists and objects and never a string. Over the cap a list read answers with counts per state, per type when every row has one (`by_type`: how many containers are running and which are stopped), and a `next` that never suggests what was just asked. A fenced summary is one wrapper. Diagnose, doctor, a plan's twin read and an undo's record read for their own verdict under a 6 KiB evaluation cap, because the model sees only what they report.

`proximo_read` takes words the way `proximo_plan` does, refuses words that ask for a mutation unless a published GET carries that verb in its own name (and says `read_only` when it reaches one), and records the words typed on the receipt; `args` is the one argument name (`params` is still accepted on read, deprecated). The MCP doors and the shell door answer compact JSON; the six tools are 942 Qwen3 tokens as the wire sends them (they were 1,144).

**Five small behaviours come back.** Restored from 0.44 in the core's idiom, each on its row in `records/capabilities.toml` with proofs the capability gate runs.

- A rollback takes a safety snapshot first, through the datacenter manager or direct on the node (capability `pdm-rollback-safety-snapshot`). A rollback discards everything since the snapshot and Proxmox publishes no read of the guest to capture, so the only net is another snapshot. `records/undo.toml` gains `[net]`: four lines, one per rollback, each with its why; the build derives the snapshot and the rollback from the address, so a line cannot name a net the address does not support. The snapshot is a governed mutation of its own through `execute` (armed, tiered, receipted, waited, riding the rollback's consent), and a snapshot that does not land refuses the rollback before it is dialled, naming the snapshot to the caller. It is on by default and only the operator turns it off, with `PROXIMO_UNDO=off`, which the plan and the receipt say; no argument can skip it. It is storage-aware, judged as PVE judges it. Before taking it the engine reads, through `execute`, whether the target snapshot exists (a rollback to a missing one takes nothing and is refused, before the grant is spent) and the volumes involved. The rollback is blocked only by the TARGET SNAPSHOT's own drives (pve-guest-common checks no unused volume and no vmstate): on ZFS (also ZFS over iSCSI), or on a directory, NFS, CIFS, GlusterFS, CephFS or thick LVM storage with `snapshot-as-volume-chain`, a newer snapshot refuses it, so no safety snapshot is taken. RBD cannot carry that setting and never blocks. Separately, the safety snapshot snapshots the CURRENT config's drives and dies on a raw image on a directory, so where that is so no snapshot is possible, and none is tried. In both cases the plan and the receipt say plainly why, by storage type, and advise a backup. The datacenter manager never shows the chain setting, so those types read as unsettled there. An unreadable or unsettled storage takes the net, the fail-closed side. The plan also says when the target could not be confirmed. The consent id binds what the plan said about the net, so a grant approved on "a snapshot is taken" does not run a rollback whose storage has since moved. The net's reads (the snapshot list, the guest's config, the target snapshot's config, the storage definitions, the run state) are receipted, withheld and bounded like any read but do NOT mark the session tainted: taint protects the model from text a guest wrote, and the caller is only ever handed a closed vocabulary built from them (storage types, taken, skipped or off, a fixed set of sentences), so a rollback under `PROXIMO_TAINT_FORBID` runs on a clean session; a session something else already tainted is still refused, before any write. Nothing is spent before a call can refuse, with the exceptions said plainly: everything that can refuse (the walls, the net's reads, the safety snapshot's own walls, the consent look, the taint marker of an untrusted mutation, and the read-back UNDO takes of the record) runs before anything is spent; then the grant's marker is taken, the rate slots are reserved, and the receipt of the spend is written, and a refusal at any of those gives back what the earlier ones took. After the spend only three things can still refuse: the ledger itself becoming unwritable (which refuses every mutation by design); a safety snapshot that was sent but did not land, where the approval stays spent because something was sent under it, the rollback's own rate slot is given back because it was never dialled, and the refusal names the snapshot and says it may have landed; and a wall that appears between the check of the snapshot's own governance and its execution, where the approval is spent and the refusal says nothing was sent. A rollback and its snapshot cost two slots taken together, and so does a shell command that asks for `snapshot=true`; a cap that cannot give two refuses with the grant unspent. The plan shows a wall that only the net's snapshot meets. A bind mount, device mount or passthrough disk means no safety snapshot is possible (PVE cannot snapshot such a guest), and the PVE config read for it asks `current=1`, the main section PVE itself snapshots, not the pending one. `undo <id>` rolls the guest back to the safety snapshot and starts it only if it was running when the net was taken (an unread state starts nothing, and the plan says so), and it does so once, however the capture's id is spelled (the ledger records the resolved hash): a second `undo` of it is refused, unless the first attempt provably did not land (the request never reached the vendor, the vendor answered with an error status, or its task finished with an error); an attempt whose end is not known counts as landed, a timeout or a reset after the request went out included, and the refusal says what to read. A rollback made directly to a capture's safety snapshot closes the capture as an `undo` does, found by the snapshot's unique name and the guest, through whichever plane or node path it was made, and an error row now names the capture it belongs to, so an unrelated failure at the same path never reopens one that may have landed. Two undos of one capture racing take a per-capture lock beside the ledger (bounded wait, a symlinked directory refused) across the check and the rollback; an undo of another capture waits for nothing. The unknown-outcome refusal says what an operator can really do (read the task, then roll back to the safety snapshot directly). The fenced keywords of `execute` (the net's own read and its prepaid snapshot) accept only private sentinel objects, never a flag or anything a door, a record or an argument can spell; that is the fence, against caller data, and not a wall against Python running in the same process. A check pins that only the engine names the sentinels and that no other module reads their module's namespace dynamically. The reservation file keeps each slot with the window it was taken under and is bounded only against runaway growth, so a caller with a short window or a tight cap cannot forget the slots a longer-window or looser caller holds. Refusals of the once-guard and of the undo lock leave a receipt, and a lock directory that others can write to, or that another user owns, is refused. The net's reads keep nothing in the store, a storage type that is not text reads as unsettled instead of crashing, and the snapshot task's exit status is never copied into a refusal.
- An empty Ceph flags call is refused (capability `ceph-zero-flags-guard`). `PUT /cluster/ceph/flags` publishes eleven optional flags and requires none, so the vendor accepted a call that named none and started a worker task that changed nothing. `records/args.toml` is new: `[one_of]` says a call must name at least one of a list of parameters, with its why. Presence, not truth: `noout=0` clears a flag and is a real change; a value the wire drops (`[]`) names nothing. The plan says no with no credential, and the call is refused before the wire with a receipt.
- A rollback plan says the description and tags are not reverted (capability `rollback-keeps-description-and-tags`). Proxmox does not snapshot them, so a description set after the snapshot survives the rollback (0.7.3 found it on a live cluster). It is a note in `records/notes.toml` on the four rollback addresses, and the note language gains one thing: `always = true`, written out in place of a condition, for a note that is on for every call to one address; an empty condition is still refused.
- An exec or psql plan carries an advisory reading of the command or SQL (capability `command-risk-hint`). `risk_hint` says read, write or destructive, with a closed list of reasons; it never changes the tier or the verdict. "Read" is an allowlist: a known command by bare name or from a standard system directory with only options known to be read-only (exact spellings), or a SELECT, VALUES, TABLE, SHOW or EXPLAIN without ANALYZE that has no INTO and calls only functions known to be read-only. Everything else is a write or worse, unreadable input is a write, and input over a cap reads as a write that says it is too long to read. 0.44 read `date -s`, `ip a a`, `journalctl --vacuum-time`, a program named `/tmp/ls`, `SELECT nextval('s')` and `SELECT '--'; <a drop>` as reads; none does now. The hint is a word and labels, never a token of the command, and the executing receipt carries the same, so the fingerprinted command stays out of the ledger.
- `PROXIMO_NODE` fills `{node}` again (capability `default-node`). A call that leaves the published `{node}` in a `/nodes/{node}/...` path is filled from it on the env box's own PVE (never `/cluster/config/nodes/{node}`, where it names the node being added or removed), and the plan and the receipt say so. A registry target and PBS, PMG and PDM are never filled, a node the caller names is never overridden, and a value that is not a node name refuses. Unset or blank, nothing changes.

**A PDM array is an array again.** The shell door has only strings, so `target-bridge=vmbr0:vmbr0` on a PDM remote-migrate reached PDM as a scalar and PDM answered 400 "Expected array - got scalar value", the bug the first real remote-migrate found on 0.44 and the 0.45 cut lost. `coerce_args` now sends a single value for a PDM `array` parameter as a one-element list; the form planes are left alone. Found by writing the capability's first proof (`pdm-typed-arrays`, unproven until today).

**The reach grant is on the ledger.** The opt-in lanes (container shell, guest agent, node shell, download) are the perimeter for the one channel a Proxmox ACL cannot scope (ssh to `pct exec`), and a widening between two restarts left no trace. Restored from 0.44 in the core's idiom (capability `reach-grant-observable`). At every door's start (stdio, MCP over HTTP, REST, A2A; the `proximo-core` shell door before a call that can mutate) the grant is compared with the last `core.reach_grant` row for that face on the ledger, and a row is written when it changed: `first`, `first_with_history`, `widened` (an id or `*` appeared, or a lane was switched on) or `narrowed`, with the ids added and removed, the lane switches and the store each allowlist came from. Faces are compared separately, so two deployments with different env do not hide behind each other. An unchanged start writes nothing, and a reordered list is the same grant. Ids only: no path, host or secret. The baseline is the ledger itself, read under the chain's check and your `PROXIMO_AUDIT_EXPECTED_HEAD` pin, and it follows a sealed rotation archive, so there is no sidecar to delete. A ledger with no reach row but with history (a key, rows or an archive) reads `first_with_history`, never a clean first; once on a box upgraded from before this check. Two kinds of "cannot prove" differ on purpose. If the ledger cannot be read or the row cannot be written and a lane is open, the door refuses to start; with every lane closed it starts and says so. If the chain does not verify (a torn line, a pin no longer held), the door starts, compares against the last readable row anyway, writes the row as `unproven` with the reason, says so loudly on stderr, and `doctor` flags it and reports incomplete: the engine keeps receipting on such a chain, so refusing would only brick the box. Concurrent starts write one row for one change. `doctor` gains a `reach` section: the grant per lane with its source, the last change (and per face), and whether a door has recorded today's grant. Set `PROXIMO_REACH_PRIVILEGE` to a PVE privilege and doctor also asks Proxmox, per allowlisted container (at most 25, each a receipt), whether the served token holds it, and flags the ones it does not, and what it did not ask about. That is an advisory, not 0.44's gate, which refused container ops and whose break-glass widened reach; no privilege is defaulted, because what means "may run a command as root" is the operator's judgement (`VM.Console` is a console attach, not `pct exec`). Not restored: the `reach-audit` verb (doctor carries its evidence) and witnessing a re-pointed ssh target (the row holds ids only).

**A doctor report you can paste.** `proximo-core doctor --receipt` prints the doctor's report as one text with a fingerprint, and sends nothing. It is built by allowlist: `core/receipt.py` names, per key the doctor writes, the one kind of value that may appear (a boolean, a count, a strict version, a word from a fixed list, an environment variable's name), drops every key it does not name, and shows every free-text string (an error, a reason, a file name) as `[text]`. A flag is shown by its code, from the fixed head of its sentence, never its tail. A first version scrubbed with patterns and an independent review walked a registry target's name, the CONTAIN trip file's prose and the operator's log name through it; patterns cannot find a name with no shape. The pattern scrub stays as a second line over what the allowlist lets through, linear in the input and with any dotted name as a host, and `--deny NAME` removes a name the operator knows (`acme` also removes `acme-prod`). The fingerprint hashes only the defect's shape, the flag codes and the pillar states, so one defect on two estates has one fingerprint and counts or versions do not move it. The module imports only `hashlib`, `json` and `re`, and a test reads its import statements. The exit code is the doctor's. 0.44 had this as `proximo doctor --receipt`; the 0.45 cut removed it with the directory it sat in (capability `shareable-doctor-receipt`).

**A plan can look past its target.** New: consult, the plan's second look (`records/consult.toml`, `proximo.core.consult`, the estate model in `proximo.core.estate`). A mutation whose record names a judge has that judge's reads made before the change, each through `engine.execute` (receipted, withheld, tainted, bounded) under a budget of 96 reads and 768 KiB; a pure function names what the change hits, and the plan carries a `consult` section (`affects`, `warnings`, `complete`, `raise_to`, `reads`, `seen_at`, and `omits` for what it does not read). One judge ships, `content_delete` (0.44's in-use disk check, restored): deleting a storage volume a guest config still names shows that guest and slot, because the vendor's delete publishes no check for a guest that still names the volume. It reads `GET /cluster/resources` asking only for `type,vmid,node,status`, so a guest's row stays at about 60 to 80 bytes and an estate of about 60 guests fits one read at 6 KiB (a smaller read cap holds fewer, and a list it cuts reads as incomplete, never as all the guests). It reads the token's whole `GET /access/permissions` map, and one `GET .../pending` per guest, which carries both views: what the guest runs with now (a disk marked for a pending delete still counts, since a running guest without hotplug still has it) and what it takes at its next start. The disks of both views count, and names come from each guest's config. The pending reads join `records/taint.toml` like the config reads. A consult that cannot finish says `complete: false` and raises the tier to the judge's worst case. That covers a read refused, failed, cut by the door's read cap or over the budget; an answer of the wrong shape, including a pending key given twice or a disk key whose value is not a volume; an empty guest config; a token whose map does not show `VM.Audit` reaching every guest (held, propagating, at the most specific path defined on the way to `/vms`, which is `/vms` when defined and `/` otherwise, and on every `/vms/<id>` path defined below it, and on every pool path defined, since a pool's ACL also scopes its members and the map does not say who they are), because the vendor lists only the guests a token can see and a guest it cannot see may hold the volume; a map the read cap cuts (a token with very many ACL paths, about 170 bytes each) reads the same way; a guest the volume's own name says owns it missing from the list, with a warning that says how to tell a hidden guest from a destroyed one (a destroyed guest's volume reads as loud, the safe side); and any failure of the consult's own. A raise never lowers a tier, never opens an untiered address, and refuses nothing. A hibernated guest's saved memory (`vmstate`) is a disk, and a volume matches by its name's path parts on the same storage, so a linked clone's disk is found by its short name and the base volume a clone is built on is in use by the clone. Snapshot sections are not read, and `omits` says so; a saved-memory volume no config names reads as the worst case. Two edges read loud: a cluster with no guests at all, because the door refuses a named projection of an empty list; and a guest whose notes are near PVE's 8 KiB limit, because its pending read passes a 6 KiB read cap, so every content delete on that estate reads incomplete until the operator raises `PROXIMO_RAW_MAX_BYTES`. `execute` consults again before the consent is spent, so a failed consult never burns the grant, and the section on the executing receipt is marked `seen_at: execute`: what was read before the call ran, not the plan the operator approved, since the grant binds the call and not the consult's answer. The resources and pending reads are untrusted and mark the session before they reach the wire (the permissions read is not). After the consult the call is judged again by the session's marker, not by what the section says, so `PROXIMO_TAINT_FORBID` refuses the delete whether or not a plan ran first and even when a consult read failed after marking. A plan says so: refused with `needs: taint`, or, when it is refused first for the arm, with the wall under `also_refused` and in its reason (`needs: taint`, or `needs: consent` under `PROXIMO_TAINT_REQUIRE_CONSENT`), and with `taint_required` when the taint is what made consent mandatory. A refusal the second look meets for another reason (a containment trip, a lapsed arm) names its own pillar and is not put down to the consult. A plan refused for anything but arm or consent reads nothing. Under `PROXIMO_TAINT_FENCE` the plan fences the section's affects, warnings and why, and a tier reason the consult wrote. The plan envelope gains `consult` on a consulted address (door contract 3); a row gains the `consult` column.

**Stopping the door is destructive.** A service stop, restart or reload names its service in the path, so one tier per address could not tell stopping sshd from stopping a timer: the whole family was `restorable`, including the services that hold the door open. `tiers.toml` gains `[raise]`: a tier raised by a value the call names, never lowered, never opening an untiered address (the build and the loader refuse both). On the owner's ruling, stopping, restarting or reloading networking, the API daemons and proxies, the cluster stack or ssh is `destructive` on PVE, PBS and PMG; every other service keeps its tier, and starting one is not raised. The plan shows the raised tier beside the authored one (`tier_authored`, `tier_raised`; on a template path, `tier_may_rise`), and the executing receipt carries it. The ladder will read this tier, not the authored word.

**Every capability is on a record.** `records/capabilities.toml` lists what Proximo does for its operator, where each came from, and the tests that prove it; `tests/test_capabilities.py` runs those tests and fails when a capability leaves without a ruling on its own row. The 0.45.0 cut removed 25 capabilities by directory; they are recorded as owed and come back one by one.

**The runbooks come back.** Five MCP prompts, listed by `prompts/list` and read by `prompts/get`, hand an agent a runbook: safe migration, diagnose the cluster, provision a container, safe backup, review receipts (capability `runbook-prompts`, cut in 0.45, returned by ruling 2026-10-25). They speak only the six tools and the core's rules: find an address before guessing it, plan before calling, a call without `confirm` returns the plan, and the receipts are verified against a pinned head (`review_receipts` takes the head you hold; without one it says the tail is unproven). A test resolves every address and every tool a runbook names against the table and the door's own tool list, and bounds each prompt at 1,800 characters (the longest, with the largest valid arguments, is 1,781), so a runbook cannot go stale or grow past what a small model reads. They register on the one server `build_server` makes, so the stdio door and the MCP-over-HTTP door serve the same five; Every mutating runbook shows the plan to the operator and calls with `confirm=true` only after they approve. Their arguments (vmid, node, hostname, head) are validated before they are spliced in; a quote, a newline or an oversize value is refused. `tools/list` is still exactly six.

**The anchor publishes the ledger head off-box.** One behaviour the 0.45 cut lost, restored (capability `offbox-anchor`). The hash chain catches an edited interior row but not a cut or wiped tail, and the manual pin (`expected_head`, `PROXIMO_AUDIT_EXPECTED_HEAD`) leaves the copying to a human. Set `PROXIMO_AUDIT_ANCHOR_SINK` to `file` (with `PROXIMO_AUDIT_ANCHOR_FILE_PATH`) or `http` (with `PROXIMO_AUDIT_ANCHOR_URL`, https or loopback; optional `..._TOKEN_PATH`, `..._CA_BUNDLE`) and the ledger head is published after a write, at most once per `PROXIMO_AUDIT_ANCHOR_INTERVAL` seconds (default 60). Unset, nothing is published and nothing is read. `audit_verify` reads it back as a row the chain must still hold, the same semantics as the env pin: a cut below it, a wipe or a replaced file fails, later rows pass, and `tail_verified` is true only when the anchored head is the chain's head. A pin only moves forward along a chain that still holds it, so a cut tail followed by an honest write cannot re-pin the anchor to the cut chain (0.44 learned that late). Once set, an anchor that is unreachable, empty, diverged or misconfigured reads as `ok: false`; a publish failure never fails the call that wrote the row and shows as the anchor being unreachable, empty or stale in `audit_verify` and in doctor's PROVE station (`pillars.PROVE.anchor`), which names state and counts and never a path, URL or token. Also fixed: `audit_verify` with a pin set and the ledger file deleted answered ok; a pin names a ledger that must exist, so it now fails. Every sink call has a total deadline and a 4 KB read cap, the http client honours no proxy variable, and a ledger that was anchored once never publishes into an empty sink until the operator sets `PROXIMO_AUDIT_ANCHOR_REARM=1` for one write. Not restored: 0.44's syslog and journal sinks, write-only witnesses that could never be read back.

**find hears a typo and an operator's word.** One behaviour the 0.45 cut lost, restored (capability `lexical-find`). `proximo_find` read only the words the table spells, so "memory usage of a container" found a probe and a node status, and "snaphsot" found nothing. The vocabulary (`records/vocab.toml`) grows from 4 lines to 16, each quoting the vendor's own use of the word (memory, cpu and usage mean the status address, whose PBS sentence reads "Read node memory, CPU and (root) disk usage"; ram, disk, health, log, backup, permission, machine, stats and ssl likewise), and a test now checks that every quoted fragment is a sentence the vendor published. A word no tier knows is first read as an inflection of one that is known (`restarting`, `destroyed`, `rolledback`): one that folds to a verb is read as description and never picks the method (only a verb the operator said does), and another word is offered as a weaker alternative. Failing that, a word of six letters or more with no digit in it is offered as a typo of a known word: character 3 and 4-grams, TF-IDF, cosine, in pure stdlib (`core/lexical.py`), and then only a slip of the fingers (neighbouring letters swapped, a letter dropped or doubled inside the word, a key struck beside the right one, the first letter right), so "weather" is never "rather". What the operator said is never replaced, a guess weighs one less than the same landing said and never reaches a parameter name, and the answer says so: `"match": "lexical"` on the rows that leaned on a guess and `"guessed": {"snaphsot": "snapshot"}`. Against `/usr/share/dict/words` 0.62% of its words of six letters or more are offered as a typo of a different table word (the first cut did 4.8%), and at most three words of one question are read (junk words do not use the three; twenty are looked at). A word any tier knows is left alone, nonsense still returns nothing, an answer that acts (`proximo_plan` on words) never takes the tier, and a single plan match reached only through a vocabulary word comes back as a choice. `PROXIMO_LEXICAL=off` turns the tier off. The index is built on the first misspelt question and cached; a warm `proximo_find` still takes about 6 ms, a cold start is unchanged, and the first misspelt question pays about 38 ms once. The answer is the same handful, and a lexical one adds two short keys.

**An allowlist is a grant, and names its source.** Two behaviours the 0.45 cut lost, restored (capability `allowlist-compares-grants`). The env-file loader compared `PROXIMO_CT_ALLOWLIST` and `PROXIMO_AGENT_ALLOWLIST` as raw text, so the same ids in another order or spacing (dogfood: the same 22 CTIDs) were reported SHADOWED, sending the operator to hunt a change that was not there. They now compare through the core's own allowlist parser, so a reordered list is one grant and a different grant is still shadowed; every other key still compares as text. An allowlist refusal now names the store that fed the value (the env file, the process environment, or both with the environment winning and the file's copy SHADOWED) and says the value is fixed at launch, so a restart or reconnect applies a change. It names the store by kind, never the file's path or a value. 0.44 printed the default path; the core does not, to follow the rule that doctor reports state and never where.

**An empty list the token could not see is refused.** Restores token-sight, lost in the 0.45 cut. Proxmox answers 200 and an EMPTY list, not a refusal, where it hides what the token may not see: PVE filters backup volumes out of a storage's content listing per volume (a token needs `Datastore.AllocateSpace` on the storage and `VM.Backup` on the owner guest, or `Datastore.Allocate` on the storage), and PBS shows a caller holding only `Datastore.Backup` just the groups and snapshots it owns (`Datastore.Audit` shows all). 0.44 refused to read that as "no backups"; the core served `[]` as data.

**New: `records/sight.toml`.** The judgement is a record line like every other: the address, the alternatives of `privilege@path` that make the list sighted, when it applies (`when`: a parameter's values; absent counts), what an empty answer cannot be taken to mean, and the why. Three lines ship: the PVE storage content listing (when `content` is `backup` or not given), and the PBS snapshot and group listings (`Datastore.Audit` at the datastore, or at the namespace when `ns` is given). When a read on such a row comes back empty, the engine reads the same plane's `GET /access/permissions` and judges it: sighted is served as before; blind is refused with `needs=sight`, naming the privileges the token would need; a map that cannot be read, or is not a permission map, is refused too ("not vouched"), where 0.44 returned `[]`. A refusal is receipted as `core.refuse` with `state` blind or unknown, and a sighted empty list carries `sight: sighted` on its `core.execute` row. A non-empty list is served unchanged and the permissions are never read. A privilege is held where its key is defined, on the path or on an ancestor that propagates. Nothing is translated into roles, and the refusal is one short sentence. The build refuses a line on a plane that publishes no permission read, on an address that is not a served read, a name the address does not publish or the path binds, a malformed requirement, or a missing sentence; the loader refuses a file carrying a line the build would not write.

**The door is door contract 3.** What moved since contract 2, all in `docs/door-contract.json`: `needs` gains `sight`; the input schemas drop their nullable `anyOf` and `title` entries (null is still accepted); `proximo_read` takes `args` (`params` still accepted, deprecated) and `proximo_plan` takes `fields`; every tool description is rewritten shorter; a plan answer drops `channel` and `untrusted` and gains `next` and `parameters_more`; a find answer gains `next`, `returned` and `params_more`. A client that reads keys it knows keeps working.

**The consult under the exit.** Folded where the consult met the door's new caps. The consult's reads are the door reading for its own verdict, so they read under the evaluation cap (6 KiB, as the consult was built for), not the model's 1.125 KiB read cap, which held about a dozen guests; an estate of about 60 guests is judged whole again at the defaults. The wall an unarmed plan names under `also_refused` reaches the model whole (it was clipped at 160 characters, hiding whose reads marked the session, and the plan then went over its ceiling and lost the wall to the over-cap answer): the wall is said once, in `also_refused`, and the plan's `reason` names its pillar and points there. A consult's `omits` is no longer repeated inside `warnings`.

**The exit, held on every door (lens F).** A refusal on REST and A2A now goes through the same seal as one on MCP: a vendor row with 5,000-character key names had come back in a REST error at 75,123 bytes, with tag characters raw. The refusal ceiling is now bytes, the mark included: `echo` escapes first and counts what it shows, and a refusal is cut by its encoded bytes, so CJK or escaped text can no longer push one past 512. The over-cap answer is measured again and falls back to the verdict, `needs`, the consent id and the operator's line. `proximo-core consent show` prints nothing from a row that does not prove itself: the refused proposal carries a `binding` (a hash of the proposal as stored, fingerprints included), and show checks it, the recomputed id (a rollback's net signature is now kept on its consent refusal, so its id reproduces), one proposal per id and the keyed chain; a planted fingerprint no longer switches the id check off. What could reorder the operator's terminal (bidi marks, zero-width and control characters) is shown as its escape. Pinned: `audit_entries` on every door never hands a model a row's `detail` or a vendor's exitstatus; the ledger keeps both.

**The exit holds on mcp 1.x too.** On the 1.x SDK the door sealed only a success: an unknown tool name, pydantic's argument text and a refusal reached the model whole (90 KB for a 90,000-character name). Both majors now share one error exit (`mcpcompat._bounded`), so every refusal fits 512 bytes on either.

**4,126 tests.**

## [0.48.1] — 2026-10-25

**Pool tokens read their pool; what a clone needs.** Issue #100 findings 2 and 3, measured again on a PVE 9.2.2 lab node. A patch: `mint`'s printed recipe and SETUP; the engine, the data file and the door are unchanged.

**Fixed: `mint pve --write --scope /pool/<name>` left both tokens unable to read the pool.** In PVE an ACL on a deeper path replaces what a principal inherits there. The recipe's `PVEVMAdmin` on `/pool/<name>` for the user replaced the user's `PVEAuditor` from `/`, so the read token (its own rights intersected with the user's) kept only `VM.Audit` and `VM.GuestAgent.Audit` on the pool, the write token held no `Pool.Audit`, and `GET /pools/<name>` answered 403 to both. For every pool path in a PVE write scope (`/pool` or `/pool/<name>`) the recipe now also prints the grant of `PVEAuditor` on that path to the user and the write token, and says why; on the lab both reads came back and the only privileges added were the five audit ones. `mint` prints a recipe and calls nothing, so **a token already minted for a pool is not fixed by upgrading**: run the two `PVEAuditor` lines once, or re-mint. A guest scope's (`/vms/<id>`) grant commands and the other planes' recipes are unchanged.

**New: what a clone outside the scope needs, said where you mint.** A pool-scoped token, as minted, cannot clone a template kept outside the pool. Hunted on the lab from the vendor's own refusals, which name one missing privilege at a time, full and linked clones alike: `VM.Clone` on `/vms/<template>`, `Datastore.AllocateSpace` on `/storage/<target>` and `SDN.Use` on the bridge (`/sdn/zones/localnetwork/<bridge>` for a plain Linux bridge), each to the token and the user; the built-in roles `PVETemplateUser`, `PVEDatastoreUser` and `PVESDNUser` carry them, each with only its own audit privilege beside it. The PVE write recipe's grant step says so, and SETUP has a section, the commands, and two troubleshooting rows. Proximo does not grant those paths for you: which template, storage and bridge are yours to name. Reported with reproductions by kevwillow.

**1,973 tests** on Python 3.12 and 3.13; the mcp 1.x leg runs 1,971 and skips the two 2.x-only seams.

## [0.48.0] — 2026-10-25

**A restore says what identity it keeps.** A minor: a new authored record and a new plan key (door contract 2). No verdict moves, and nothing Proximo sends the vendor changes.

**Said, not defaulted: what #82 asked for, which the 0.45 cut lost.** The call is unchanged: a restore without `unique` still gives the copy the backup's identity, as Proxmox does; the plan now says so before it runs. Issue #100, from the reporter of #82: 0.44.2's fix for #82 (a restored copy wore the original's MAC and SMBIOS UUID) lived in `pve_restore`, and the 0.45.0 cut removed it with the other wrappers without naming it. Measured again on a PVE 9.2.2 lab node through the shell door: a QEMU restore to a new VMID without `unique` came back with the source's MAC and SMBIOS UUID, and its plan said nothing about either; with `unique=1` both were new.

**New: plan notes.** `records/notes.toml` holds consequences the tier cannot say, keyed on the address like every record: a condition read from the call's own arguments (`given`, `not_given`; a boolean read through the same words `coerce_args` sends the vendor, a string given unless blank), what the plan says, and why. Only a definite answer silences a note: a value that cannot be told before the wire (a boolean of `2`, a list, a word nobody reads as a boolean) shows it. A plan whose arguments meet a line carries `notes: [{says, why}]`, and the receipt's `executing` row carries the same sentences under `notes`. A note never reads the target and never changes a verdict: it shows the same armed, unarmed, with no credential or with the target's read refused, and the tier still decides. Two lines ship: a QEMU restore (`archive`) without `unique` says it keeps the backup's MAC and SMBIOS UUID, a container restore (`restore`) without `unique` says it keeps the backup's MAC; each says it is right for a rebuild in place and that a copy wants `unique=1`. Proximo does not send `unique` for you: 0.44.2 did, by parsing the archive's name for its source VMID, and the core does not change what the vendor's call does. The build refuses a note on an address that is not a served mutation, a name the address does not publish or names on both sides, an empty condition, or a missing sentence; and a name twice, a name the path binds, a sentence with space around it, or two notes with one condition; the loader refuses a file carrying a note the build would not write.

**The door is door contract 2.** The plan answer gains `notes` (a list of `says` and `why`), present only when a note holds; `docs/door-contract.json` samples a restore so the key is part of the contract. Nothing else in the door moved.

**Proved live.** On a PVE 9.2.2 lab node through the shell door: the restore without `unique` kept the source's MAC and SMBIOS UUID and its plan and receipt carried the note; `unique=1` gave new ones and carried none. The container line rests on the vendor's sentence; the lab had no container template to restore. Two adversarial lenses went over the branch: the first found the plan reading `unique=n` as given while the vendor was sent false (the note silent on exactly the call it exists for); one boolean reader now serves both, and a test sends every spelling through the plan and the receipt and holds them to one answer.

**1,964 tests** on Python 3.12 and 3.13; the mcp 1.x leg runs 1,962 and skips the two 2.x-only seams.

## [0.47.0] — 2026-10-24

**Self-owned grants refused; a stdlib ledger checker.** A minor: it refuses consent grants that worked before, adds an opt-in for one-user boxes, and adds a checker and a written ledger format.

**Changed (refuses what worked before).** SECURITY.md's hardened recipe put consent grants in `/etc/proximo`, mode `1770 root:proximo`: the agent's group could create files there, and the gate never asked who placed a grant, so the agent could write its own and it was accepted. A grant owned by the agent's own user is now refused (`consent: "self"`). On an install where the human and the agent are one user, root included, consent refuses every mutation it guards until the agent runs as its own account. The recipe now gives grants their own directory, owned by the operator's account, that the agent can read and not create in; `packaging/proximo.env.example` shows it.

**New: `PROXIMO_CONSENT_SAME_USER=advisory`.** For a one-user box where consent is the agent stopping to ask, not a lock: same-user grants are accepted, still spent once and still bound by the TTL, and never called granted. The plan shows `consent: "advisory"` and says so in its reason, every such spend receipt carries `"advisory": true`, and DIAGNOSE flags the box. It trusts the agent not to write its own grant, which the default refuses to trust. Off unless exactly `advisory`; any other value refuses mutations; a blank value is unset.

**Fixed: the spend.** It was `os.remove`, so a root-placed grant in that sticky directory could never be spent: the agent's grants worked and the operator's did not. A grant now spends once by a marker beside the ledger (`.proximo-consent-spent/`), with a `core.consent_spent` row as the evidence. The grant is judged and spent on one `lstat`, the marker is keyed on that file (device, inode, mtime; re-writing the grant is a new approval, renaming it onto another plan is not), and the core removes the grant only if the path still holds that file. If the spend's receipt cannot be written, nothing reaches the wire and the grant is not used up. `proximo_plan` shows a used grant as `consent: "spent"`.

**New: the ledger format, written down, and a checker that needs no Proximo.** `docs/ledger-format.md` (format `ledger: 1`) and `scripts/verify_ledger.py`, one file of standard-library Python: whoever is handed a log and its key can check it. Its tests hold it to the core on every planted break, file by file.

**Fixed: Proximo's own ledger check.** It read the log in text mode, so a lone `\r` the writer never writes was read as a row break, and the checker and `audit_verify` could give opposite verdicts on one file; every check that gives a verdict now reads the rows as the writer joined them. A row with a 5,000-digit number, deep nesting, a lone surrogate or bytes that are not UTF-8 crashed `audit_verify`; each is now a broken row at its line.

**Tiers: the re-cut.** VM start, shutdown, resume, snapshot create and snapshot description are `restorable` on their own lines (they shared the `destructive` qemu family with destroy); VM and container reboot and VM suspend are `disruptive`; container resume, snapshot create and snapshot description are `restorable`. `vzdump`, PBS sync jobs, PBS realm sync and `pve:/access/users` are `destructive`; the PBS notification test and S3 check are `disruptive`. Severity still gates nothing on its own: a tier is what a plan and its receipt say.

**Security.** `opentelemetry-api`, which `mcp` pulls in and uses to extract trace context, moves from 1.44.0 to 1.45.1, past CVE-2026-114603: a crafted `tracestate` header took quadratic time to parse. The lock and the hash-pinned requirements carry the fix; CI's `pip-audit` refused the release until they did.

**1,858 tests** on Python 3.13.

## [0.46.2] — 2026-10-22

**Six columns derived; two dead example keys removed.** A patch: a stricter loader, a corrected example file, and tests. No new capability; door contract 1 is unchanged and `proximo.json.gz` is byte-for-byte 0.46.0's.

**The loader derives six columns from the data file's own rows.** 0.46.1 read `access` as written and checked that the columns twin, state, expect, task status, lane and creates named rows that existed. A forged `proximo.json.gz` with a POST marked `read` was served as a read, past the arm, tier and consent gates; a lane on an ungated row, a state beside a served twin, a create on a read, and the other shapes the build never writes were served too. The loader now computes `access`, twin, state, expect, task status and lane from the file's rows the way the build does (`access` from the method, the rest from the file's own reads and twins) and refuses the file whole on the first column that differs, naming the column and both values; a `creates` is held to the build's eligibility rule (an ungated POST with served GET and DELETE twins at its path), since the build takes which rows create from an authored record. A `snapshot` parameter that is not a table is refused with a sentence instead of a traceback. The loader is no stricter than the build: every shape the build writes loads.

**The example registry teaches only the keys the core reads (#98).** `packaging/targets.example.toml` showed `ssh_target` on one target and `node` on three. The loader the 0.45.0 cut removed read them; the core never has, and the registry ignores a key it does not know, so an operator who set them got nothing. 0.45.0 through 0.46.1 shipped the example that way. The four lines are gone, the header says the ssh lanes dial only the env's `PROXIMO_SSH_TARGET` and that the node a call means is in its path, and a test drives the real loader over the shipped example and fails on any key whose value can change without the loader noticing.

**1,780 tests** on Python 3.12 and 3.13; the mcp 1.x leg runs 1,778 and skips the two 2.x-only seams.

## [0.46.1] — 2026-10-21

**Every column, every rollback target, held to its rule.** The one data file carries seven cross-column rules the build keeps and the engine reads without a guard (which opt-in lane a gated row is served on, the read that shows a mutation's target, where the plane reports its task, a container command's snapshot net and its rollback), and the loader checked that the addresses they named existed and nothing else: a forged `proximo.json.gz` with a lane on an ungated row, a read with a read of its own, a state beside a served twin, a mutation with no task to poll or a net on another container's path was served. `apitree.published()` now holds every column to the build's rule, in the build's own words, and refuses the file whole on the first row that breaks one. The vendor's rows are asked before the shell lane's authored rows whatever the file's order (a forged file with the ssh exec row ahead of an overlapping vendor wildcard answered the ssh row). The shipped file is unchanged and loads; every one of the 1,804 rows resolves, plans and executes identically to 0.46.0 through a fake wire.

**A rollback's target is the row's own spelling.** `undo` of a container command whose snapshot it captured bound the capture's target to the row's template and refilled it, without coercing the bound values to the vendor's types or comparing the refill to the capture's spelling, so a forged capture with anything in the vmid slot (`abc`, `0101`, `+101`, `1e2`), a trailing slash or a percent-encoded node rolled back. The target is now held to the engine's own rule: the row, its placeholders bound and coerced to the vendor's types, refilled and compared to the capture's spelling; anything that does not round-trip rolls nothing back, with a sentence. A negative or absurdly large vmid still round-trips; a ledger-verified capture is the fix for that, not a tighter spelling check.

**Tests that could not fail, and the lens that found them.** Lens 3 (over the 0.46.0 branch) named the residuals this release folds; lens 4 went over the fold. Fixed: a raw-door test that asserted the ssh refusal on rows the door never reached, a task-wait test whose UPID named the same node as its path, a secret-column oracle that was the merge rule copied into the test, a surviving mutant filed as equivalent that a trailing slash split, five loader clauses each refused only by a sibling clause, and the named-row lookup whose own cases the new rules had taken. Every fold is a test that dies with its mutant replanted; 1,738 tests. Door contract 1 unchanged.

**certifi moves past PYSEC-2026-4320.** Raised on 2026-10-20 (GHSA-6q48-6c7w-9gw2): certifi 2026.5.20 bundles emSign root CAs whose intermediate CA keys were compromised. certifi reaches Proximo through httpx (via httpcore); the lock and the hash-pinned exports the image and CI install from move to 2026.10.19, the first release without those roots. The internal CI's audit went red on the release commit before anything public carried it; this is the fold.

## [0.46.0] — 2026-10-20

**One JSON: every address, every judgement, one file.** The package carried the vendor's API twice (a governance table and the four api-viewer trees) and joined seven authored records onto it at every start, checking each line as it went. It now carries one data file, `src/proximo/core/proximo.json.gz`: one row per address the four products publish, plus the shell lane's authored rows, each with the vendor's schema and description and every judgement Proximo makes about it (its tier and the sentence that justifies it, a held refusal, the taint channel, the fields withheld and the arguments fingerprinted, a judged create), with DIAGNOSE's battery and `find`'s vocabulary beside the rows and a `built` header naming every input by hash. The records live in `records/` (the vendor stage, generated and dated; the seven TOMLs, each line with its why) and ship in nothing: `scripts/build_proximo_json.py` joins them, and every check the engine ran at start-up runs there instead, refusing the build by name on a line that would do nothing (a tier key that matches no address, a taint line on a tunnel, a create without the twins its undo needs, a shell row the vendor now publishes). A record edited without a rebuild is red in the suite; a damaged shipped file refuses every address with a sentence, never a traceback, and a file carrying no judgements at all refuses too. The engine's special cases became columns the build computes and anyone can read on the row: which opt-in lane a gated row is served on, the read that shows a mutation's target (`twin` at the same path, or the parent's `/current` with the status a power action aims at), a container command's snapshot net and its rollback (authored in `shell.toml`, refused unless the door serves both on the command's own container), where the plane reports a task, and the secret rule merged with the read twin's. The engine asks the row and never "which command is this?". Proof: every command-shaped fact the old engine derived, dumped per row before and reproduced from the columns after, identical on all 1,804 rows; door contract 1 unchanged; three adversarial lenses over the branch (one BLOCKING and four MAJOR folded, each replanted red; a lens's own eight-scenario dump through a fake wire found the engine identical). `engine.py` is 1,103 code lines, from 1,446. If you pinned `table.json.gz` by hash: it and `apidoc/` are gone from the wheel; pin `proximo.json.gz`, or the vendor stage's hash in its `built` header, which moves only when Proxmox's api-viewer does.

**The copy gate reads the control table.** `scripts/copy_ripple_check.py` (always on in the suite) now counts SECURITY.md's control rows and holds every surface's count claim to them, read the way a reader sees it (entities, tags and emphasis stripped, numbers as words up to ninety-nine, either order); the README's "13 trust controls" had been stale since 0.41.1 and the gate did not know. A satellite with no count claim is still unchecked.

**The door has a contract: door contract 1.** Every client of the MCP door (an agent, an integration, a script) depends on its interface: the six tools as `tools/list` hands them over (name, description, input schema, read-only hint) and the shapes their answers come back in (two levels of keys for a find, a plan, a read, an audit read, and a call that ran, with its UNDO capture and its task; the words of a refusal in each lane a sample reaches: arm, rate, forbid, consent, contain, an unpublished argument, a held address, the shell lane, an unconfigured plane, an unpublished address; and the eighteen `needs` a refusal can carry). `docs/door-contract.json` is that door, generated in process by `scripts/gen_door_contract.py` (one estate, a synthetic armed box behind a stand-in client, a scratch ledger, nothing dialed; ids, times and the scratch path are normalised out of a refusal's words, and an authored sentence inside them reads `<why>`), and `tests/test_door_contract.py` holds the shipped door to it: a drift is red until it is made on purpose with `--bump`, which raises the number, and a number this CHANGELOG does not announce is red too. Values that move with an authored record (a tier's `why`, the tier itself) are content, not contract; their keys are. Build against a contract number, not a version: a release that leaves the number alone leaves the door alone. Planted control: one word added to one description, and the generator refuses to call it the same contract.

## [0.45.1] — 2026-10-19

**A TLS failure names itself.** Issue #90, from a site on 0.44.2 with a stock two-node PVE 9.2 cluster: Proxmox renewed a node's certificate on its own, the fingerprint pin broke, and every call read `ConnectError` until an operator found the new certificate with openssl by hand. On 0.45 both doors already print the pin error's text (pinned and observed); the doctor, and every ledger row, kept only the exception's type, because `spine.wire_error` drops the message (it carries the request URL). `wire_error` now walks the transport's chain (httpx wraps httpcore wraps ssl) to the certificate error and names it with what it holds that is neither a locator nor a secret: a pin mismatch's two SHA-256 fingerprints (`tls: "pin mismatch"`, `pinned`, `observed`; the pin error is a typed `tls.PinMismatch` now, its message unchanged), or a verify failure's OpenSSL code and OpenSSL's own reason for it (`tls: "certificate not verified"`, `verify_code`, `verify_message`). The reason comes from a table of OpenSSL's static strings, read from libcrypto when it was written, never from the exception: Python appends the dialed target to the hostname, email and IP mismatch messages, and a message is text anything could have built (the security lens on this change forced a hand-built error carrying an internal hostname under an unlisted code, which a denylist of 62/63/64 would have recorded). An unknown or non-integer code keeps the code alone, and reading the error can never cost the row: a hand-built error with no attributes, or one whose attribute raises, still leaves its type. The doctor's flag says the fix in one line: the fingerprint the server presents and the one pinned, then re-pin (SETUP's new troubleshooting row says why: Proxmox renews node certificates on its own); or the reason the certificate did not verify, which on Python 3.13 is the reporter's own finding for a stock PVE root, "CA cert does not include key usage extension". `tests/test_tls_diagnosis.py` drives real TLS on a loopback socket through the doctor, end to end, with certificates made the way PVE makes them (a root with `CA:TRUE` and no `keyUsage`, SKI and AKI on both): a wrong pin, the right pin, an untrusted certificate, the stock root under a strict and a lax interpreter, and a certificate for another address, whose row keeps the code and never the address dialed. Planted control: with the old `wire_error` and doctor, four of the five fail (the right pin passes either way). SETUP's troubleshooting table gains the renewal row.

**`tls_strict = false` trusts PVE's own root.** The other half of #90, on John's call: a pinned leaf breaks each time Proxmox renews a node's certificate (the reporter traced it to `pveupdate`, which renews as expiry nears), and the durable answer is trusting the cluster CA (`/etc/pve/pve-root-ca.pem`), which Python 3.13 refuses under its default `VERIFY_X509_STRICT` because PVE issues it with no `keyUsage`. `PROXIMO_TLS_STRICT=false` (each plane: `PROXIMO_<P>_TLS_STRICT`; a target's `tls_strict = false`) clears that one flag for the CA bundle and nothing else: the chain is still built to the bundle and the hostname or IP is still matched. It refuses, never quietly ignores, when there is no CA bundle to relax or a fingerprint pin is set, and the doctor reports `tls_strict` and flags it when it is off. Tested end to end with the PVE-shaped root: it reaches the box on 3.13 and 3.12, a certificate for another address is still refused with strictness off, and both refusals hold; planted controls (the flag left set; the refusal removed) fail the tests aimed at them.

**0.45.0's image was signed from `main`.** The 0.45.0 release job's entrypoint smoke grepped for 0.44's usage text and refused a working image, so 0.45.0's image was rebuilt by hand through the same workflow's `workflow_dispatch` on a commit whose `src/` is the v0.45.0 tag's; its provenance names `release.yml@refs/heads/main`. The smoke now greps for the door's own line and a test reads the pattern out of the workflow. 0.45.1's image is signed from its tag.

**Dependabot #88 and #89, folded.** setup-uv 10.3.0, codeql-action 4.39.0, scorecard-action 2.5.0, and the `python:3.13-slim` base image's current digest, each checked upstream before it moved.

## [0.45.0] — 2026-10-19

**Proximo is the core: six tools over every address.** 0.44 was 924 hand-written wrappers. 0.45 is six MCP tools (`proximo_find`, `proximo_plan`, `proximo_read`, `proximo_call`, `audit_entries`, `audit_verify`) over every address PVE, PBS, PMG and PDM publish, with the six pillars (PLAN, CONSENT, PROVE, UNDO, DIAGNOSE, CONTAIN) at the one seam every call passes, through every door (CONSENT once its directory is set): stdio MCP, MCP over HTTP, REST, A2A and the `proximo-core` shell. What 0.44 had that 0.45 does not is named in the cut entry below; the short form: the wrappers' names, the runbook prompts, memory and wiki, per-tool guidance, the multi-step mutations as single tools (each step is still an address), the reach mirror, and `proximo doctor --receipt`. SCOPE and LEASE now live in the Proxmox token itself (`proximo-core mint`). The entries below are the build record, newest first; where an early entry names a command or tool that a later one renamed or cut, the later entry holds.

**The cut: 0.44 is gone, the package is the core.** Everything outside `src/proximo/core/` is gone: the 0.44 server and its 924 wrappers, its config, memory, wiki, knowledge, reach mirror, the pruning and parity tooling, the live-smoke tier that drove the wrappers, the demo, and the test files bound to them (186,848 lines; the cut list was generated, with planted controls, and is the inventory the lens read). What the core gives up with it, the three open calls answered on John's GO of 2026-10-18: the ledger is keyed, always (`PROXIMO_AUDIT_KEYED` is retired and refused at every door while set off, `true` is nothing lost; the keyed-to-unkeyed downgrade path goes; an unkeyed or mixed log is still sealed and archived on the first write through a door, never deleted, and the doctor names the archive); the five 0.44 runbook prompts go (they were 0.44's list, and nothing in the bar chose them); `proximo doctor --receipt` goes (0.44's redacted, pasteable report for a bug report, which sent nothing itself) with the issue template that asked for it (John, 2026-10-19: the core's `proximo-core doctor` stays, the paste does not); `mcpcompat` stays (one SDK major is an adopter-facing bound with its own rail) and the store stays (the engine's `since=` reads it). The suite is one caller now; the inventory test holds the tree to the cut instead of to a seam: every file under the package is the core, every core module imports, and no test or script names a `proximo` module that is gone, by import at any level, by string literal, or by a bare script import, with twelve planted controls. The lens on the cut found the generator had taken eleven test files that tested code which stays (the A2A card and signing, the REST door's OpenAPI document, the core doors' own files, the import closure, the secrets record, the mcp seam); they are back, with the 0.44 probes removed. The public docs say what the core is: six tools, every published address, the arena record. Suite on the cut tree: 1,580 passed.

**Bar 3, measured and driven.** The 0.45 bar's third line says the door runs in a 4K window on a small local model. Measured: `tools/list` over stdio is 5,544 bytes; a stock 1.5B's chat template renders the six tools at 1,568 prompt tokens, counted by its own server. Driven: that model (qwen2.5-1.5b-instruct q4, llama.cpp, a 4,096-token context the server enforces) spoke to `proximo` over stdio against a real PVE node, read-only, three runs; its calls landed, every refusal named the fix, the prompt peaked at 3,074 tokens, and it did not finish the task: it invented field names, was told the real ones, and answered with a number it never read. The drive taught the door two things, folded here: the `plane` parameter carries its four choices in the schema (the first run sent `default`; the third picked `pve` unprompted), and `proximo_read`'s description shows a real `fields=` example where it showed a placeholder the model copied. Three descriptions were trimmed so the door, a plan and one estate read stay under the suite's 2,500-token budget. The window holds; a 1.5B does not.

**`proximo` is the core.** The default-command swap, the last step of the seam move: every console script is a door of the governed core and nothing else. `proximo` (and `proximo-proxmox`, and `python -m proximo`) is the MCP door over stdio: six tools (`proximo_find`, `proximo_plan`, `proximo_read`, `proximo_call`, `audit_entries`, `audit_verify`) over every address the vendor publishes, where 0.44 served a facade over 924 wrappers. `proximo-http`, `proximo-mcp-http` and `proximo-a2a` are the core's network doors behind the one perimeter, same env names, same ports, same refusals; the `proximo-core-*` spellings of the same doors are gone, `proximo-core` (the shell door) stays and carries the operator's verbs: `proximo mint|doctor|badge|arm|disarm` runs there. `arm` and `disarm` are the core's own now: the write token's bytes (or the read-only token's) installed at the served token path, atomically, mode 600, one ledger row each, and the engine's arm predicate reads the swap on the next call; a group- or world-readable source is refused, as every secret loaded by path is; the 0.44 verb's per-session arms (`--session`) and `reap` were LEASE and are gone with it, as are `harden` (folded into `doctor`, 2026-10-09), `reach-audit` (the reach mirror, 0.44's) and `tools-checksum` (there is no tool surface to pin). Every door sources the operator's `~/.config/proximo/proximo.env` (`PROXIMO_ENV_FILE` to point elsewhere) before its first env read, the process environment winning, as the 0.44 commands did; the core doors had relied on those commands for it, and the swap's security review caught the gap before it shipped. Every door refuses to start on a switch the core does not read: `PROXIMO_SURFACES`, and the retired `PROXIMO_SCOPE_PATH` / `PROXIMO_ARM_TTL` the engine already refuses per call. `--help` on every door prints usage and exits before any config is read; the stdio door refuses any other argument. Every door, the stdio one included, stamps `session_start`/`session_end` in the ledger on every start, not only with the principal feature configured (the stdio door's rows are driven by a crash test, not read from its text). The badge is minted with `proximo badge mint` as before, now the shell door's verb (rc 3 on a refusal, one line prefixed `proximo-core badge:`). What an operator sets does not change (`PROXIMO_API_BASE_URL`, `PROXIMO_TOKEN_PATH`, the `PROXIMO_<FACE>_*` door variables, `PROXIMO_AUDIT_LOG`); `PROXIMO_SURFACES` is refused at start, the core has no surfaces. The 0.44 server, its wrappers and its config are still in the distribution and reachable by no command; they go at the cut.

**The perimeter is the core's.** The REST face, the MCP-over-HTTP app, the web guard and the A2A package (card, signing, executor, app) were 0.44 files the core's network doors imported lazily, the last four lines of the core's reach into 0.44 that `tests/test_gate_mutations_inventory.py` pinned on 2026-10-16. They are `proximo.core.perimeter` now (`rest`, `mcp_http`, `guard`, `a2a`), git renames with their history, and the caller badge the guard's camera reads went with them as `core.perimeter.badge`; `proximo.principal` keeps the name tag's re-export and the 0.44 session-row switch. The seam set is empty and held empty: a core file that reaches 0.44 on any path is red with its name. The 0.44 commands (`proximo-http`, `proximo-mcp-http`, `proximo-a2a`, `proximo badge`, the doctor's pin count) import the new names and behave as before; nothing an operator types or sets changed.

**The perimeter has no caller of its own.** The three 0.44 network commands (`proximo-http`, `proximo-mcp-http`, `proximo-a2a`) each carried a `main` that set the serving face, applied surfaces, read its env, refused a public bind without a token, built the app, wrote the session rows and served; the three are now one `serve_face`, called by each command's console shim with the face's own build. Nothing an operator sets changes: the same env names, ports, refusal text and ledger rows, pinned by a test that stands in for `serve_face` and reads what each shim hands it. With the mains gone from the faces, the four perimeter modules (the REST face, the MCP-HTTP face, the shared guard, the A2A package) lost their fallbacks too: whoever builds them passes the dispatch (or the MCP instance), the row writer and the tool list, and the faces reach nothing of the 0.44 server, `governed` or the targets on any path, only each other and the caller badge. The console shims pass the 0.44 server; the core doors pass their own. Embedders who called `build_app()` bare now pass a caller. Two inventory assertions hold the line, red before the change and green after, and the planted reaches go red.

**The perimeter is proven on both callers.** The 0.44 faces' perimeter tests (bearer, CSRF, the Host allowlist, card signing: nine files) built the 0.44 app by default, so the core doors, which serve the same perimeter with `dispatch.Core` behind it, were proven only by their own smaller files. Every perimeter test now runs twice, once through the face's `build_app` and once through the core door's (`tests/conftest.py`, `caller`), and the five places that read which caller is under test say which surface they expect (six tools on the core; the 0.44 hundreds on the face): the OpenAPI path count, the MCP server's name, the card's skill count twice, and the CSRF spy's patch target. This is step 0 of moving the four perimeter modules under the core: when the 0.44 default goes, the `"0.44"` value and those five sites are edited, and the other tests in the nine files do not change.

**Every gate goes red under a core-only test.** Parity row B13, the half the record called PARTIAL since 2026-09-28: six gates were caught only by a 0.44 door test, and at the flip that test goes with the door. `scripts/gate_mutations.py` neuters 26 gates one at a time (arm, tier, gated, held, the cross-plane config, contain, the retired switches, forbid, both taint couplings, consent's look and its spend, rate, the taint mark, withhold, placeholders, argument validation, the undo read, the executing row, the refusal receipt, the spelling check, the excluded tunnels, and PROVE's four checks on the live chain) and runs the 27 core-only test files with `-x`, after a green baseline of the unmutated set; a kill is a FAILED test and nothing else, because the first pass of this round called a collection error a kill. Core-only is judged by a transitive import walk, not a grep: the lens of the same day found three files of the first set reaching 0.44 two hops away (`proximo.taint`, and `proximo.projection` through `proximo.backends`), so the two bridge tests that compare the core with the 0.44 reader and classifier moved to `tests/test_bridge_044_*.py` (they go at the flip) and `test_prune_wrappers.py` left the set. The first pass, before the lens, on a core-only set a grep had judged, killed 23. Three survived, all in the live chain's verify. Two were reason-only: the `prev_hash` link and the keyed-downgrade check, where every row's hash is computed over the running previous hash with the ledger's key, so a removed, reordered or downgraded row still fails the hash compare, and what the checks carry is the DIAGNOSIS, "removed or reordered" and "downgrade" instead of "altered" (an operator reading "altered" for a row cut from the middle looks for the wrong attacker). The third was a hole: the pinned-head check, PROVE's off-box anchor against a cut tail, and with it neutered `audit_verify(expected_head=...)` answered ok on a truncated ledger while every core-only test stayed green. `tests/test_prove_live_chain.py` drives `audit_verify` on a live ledger through the door and pins the outcome for each class of break (a removed row, a swapped pair, an edit in place, a row re-signed without the key, a cut tail that only the pinned head sees), with a control that reads intact first; all three survivors are killed by it. The round on the tree this ships with (2026-10-16 03:04Z, the committed harness, serial, baseline 894 passed): 26 of 26 killed, 0 survived. `tests/test_gate_mutations_inventory.py` holds every neutered string to exactly one site, so a gate that moves turns red there instead of the round printing SKIP. The same test inventories the flip's seam: importing any core module pulls in nothing of 0.44, and the core's whole reach into 0.44 is four modules imported inside functions of the network doors, five lines (the REST face, the A2A app and its signing-key loader, the MCP-over-HTTP app, and the web guard that reads a face's env and refuses an unauthenticated public bind), pinned as a set; at the flip those lines move or the doors go, and a fifth module is red until it is judged. Its lens planted what the first walk called lazy and was not: an import nested in a `try`, an `if` or a class body runs on import and is read so now, `if TYPE_CHECKING:` never runs, and a relative `from .. import name` names a submodule; ten planted shapes are the control.

**The token file stays out of the system's own trees.** `mint` held `--token-file` to shell-safe characters and nothing else, so `/etc/shadow`, `-rf` and `$HOMEevil` passed the shape and the recipe printed `> /etc/shadow` for root to run (lens 2026-10-06, MINOR, carried on every wrap since). The file is now `$HOME/...` or an absolute path of plain segments (no `.` or `..`, no segment opening with `-`, no `.ssh`), a file at the root of the filesystem (`/vmlinuz`) and a path under the system's own trees (`/etc`, `/usr`, `/var`, `/proc`, `/dev`, `/boot` and their kin, in any case) are refused by name with the reason, and relative paths are refused because the recipe runs in a cwd nobody chose. What is under your home or a data directory is yours to choose: the rule keeps the recipe off the system, it does not judge your own files.

**A `%` escape in a bare path segment no longer cuts the scrub.** `safe_text(paths=True)` left `<path>%20b/c` behind a URL-escaped segment (lens 2026-10-09, MINOR). The bare POSIX, Windows, UNC and `~` rules take a `%` followed by two hex digits in a segment, and only that: `80%/90%/95%` is still prose (the lens's own probe).

**The 4K door's sentence says what is measured and what is not.** The entry below claimed a local model in a 4,000-token window drives the whole estate; the cost is measured, the drive is not yet proven, and the sentence now says so (the proof waits on a model window).

**Main's release line rides on this branch.** 0.44.1, 0.44.2, the `pve_disk_move` format parameter and the two live-smoke fixes are merged in, fifteen commits the core branch had fallen behind.

**Every path shape leaves an answer.** The scrubber every door uses (`safe_text(paths=True)`) took a single-quoted POSIX path and a bare one of two or more segments, and the lens of 2026-10-09 named what it did not: a path holding a space, a Windows drive path, a `~` path. A probe added one: `~user/...` carried a username through. The one rule now takes a path in either quote (Python's repr switches to double quotes for a path holding an apostrophe; JSON always uses them), a bare Windows drive path, `~/` and `~user/`, and folds the tail a bare path with a space left standing beside the marker; over-scrubbing is the safe side of this seam. Its lens (four MAJOR, folded the same day): a path glued to a colon, a UNC or doubled-slash path, a bare spaced path's slashless filename, and the residue a single-quoted path leaves when an apostrophe cuts it early are taken too. The doctor's four repeated refusals (the record, `undo.toml`, the target registry, a read the spine refused) go through the same scrubber as the trip line; no raise text that reaches those four sites carries a path today (the ledger's `no ledger at <path>` does, and the doctor's ledger section drops it), so the tests drive one that does. Named, not changed: a bare IPv6 literal with no scheme would pass the address rule, and no text the synchronous wire produces carries one.

**The gate diagnoses itself: `proximo-core doctor`.** Parity row B6, with `harden` folded in, sorted "keep, small" by the 0.45 bar. The operator's verb at setup, CLI only (the six tools are the 4K window): it reads the record (rows, mutations, tiered, held, judged creates, untrusted; a record that does not parse is reported in its own words and the report goes on, since every mutation is refused with it), each plane (configured or the missing variables named the way the wire names them; arm state as the engine grades it; the vendor's own `GET /version` and `GET /access/permissions` run through the engine like any read, receipted and bounded, the permissions counted and sampled by path and never translated: 0.44's doctor turned PVE privileges into a capability vocabulary with role hints, which re-does the vendor's RBAC in Proximo's words, bar 4; PMG publishes no permissions read and its section says so), the target registry (count and names), the ledger (keyed, key readable, rows, the chain whole or broken at a row, mutations in flight), and the six pillars: PLAN by construction, CONSENT standing when its directory is set, PROVE when the ledger is keyed and whole, UNDO when it is on (with the judged creates counted), DIAGNOSE with each opt-in lane's state and allowlist size, CONTAIN with the trip (configured, tripped, the operator's reason), the rate cap, the forbid count and the four taint switches, each read through the spine's own reader. An empty pillar carries the one line that raises it, which is `harden`'s recipe folded to a sentence; two of 0.44's four stations, the reach MIRROR and the off-box PROVE anchor, have no mechanism in the core and are not here. A retired switch (SCOPE, LEASE) is flagged with the spine's own sentence. Stations report yes, never where: no switch's path, no secret's path, no token byte and not the ledger's path reach the answer, and the wire's own refusal of a readable token file goes out with its path scrubbed; a test sets every path with a marker and asserts the marker absent, with a planted path as its control. Flags are advisory and move no exit code; the exit is the shell door's contract (0 ran whole, 3 nothing configured, 4 a configured plane unreachable or the chain unjudgeable), never 2. The module is held under 250 non-blank lines by a test; 0.44's was 676 plus 167 of `harden`. The lens on the first cut found two things the report said that were not so: a vendor read the door's size law had cut came back with no data and was reported as a clean read of nothing (version null, zero permissions, complete), so a cut is now an error with its byte count and the report is not whole; and the trip file's text went out verbatim and unbounded, a mis-pointed trip path dumping whatever file it named, so it is one bounded line with every path scrubbed, and a tripped box no longer reports complete. The two vendor reads are reads through the engine and land as rows on the ledger, two per configured plane, and on a fresh box the first one mints the audit key; the ledger section is read after them for that reason.

**A create at an item path runs with UNDO on.** UNDO reads a mutation's GET twin before it runs and refuses when that read fails (no net, no risky act), so a CREATE at an item path, a token, a realm-sync job, a metric server, could never be made with UNDO on: its twin 404s (PVE answers 500 for "no such user") until the record exists (live, the lab, 2026-10-06). The fix is keyed on the address, never the shape: of the 28 published POSTs at an item path, 13 have a GET and a DELETE twin, and several are actions whose "absent" would have made undo delete what was there (PMG's `backup/{filename}` POST restores a backup, PVE's `content/{volume}` POST copies a volume, the firewall group POST adds a rule while its DELETE removes the group, the ipset POSTs add an entry while their DELETE removes the set). `undo.toml` names the five creates, each with the vendor's own POST, GET and DELETE sentences as its why: the three API-token creates (PVE, PBS, PDM), PVE's realm-sync job and its external metric server. For one of them a failed read-back is captured `before: absent` with the vendor's status (`read_back`), the create runs, and `undo <id>` is the DELETE the vendor publishes at the same path, through the engine like the PUT (plan by default, armed, tiered, consented, receipted with `restores`, its own capture the record as it stands now; a record already gone is a noop). The proof of absence is not the failed read but the create landing: every listed vendor refuses a duplicate, so the DELETE is sent only when the ledger shows the captured create's own terminal row `ok`; a create the vendor refused, one not seen to finish, or no terminal row at all deletes nothing and says why. A plan of a listed create whose read fails says the record is not there (`creates`, `exists: false`, the read's status) instead of a bare error. The record is refused at load unless every line is a published, ungated POST with a published, ungated GET and DELETE at its path and a sentence; an unlisted POST at an item path keeps today's refusal, and opening a sixth line is John's hand by name. Not proven live: that PVE's realm-sync and metric-server creates refuse a duplicate id (the token creates are, 2026-10-06). The lens on the first cut found the proof mis-paired: a create's refused outcome is a `core.error` row, the pairing accepted only `core.execute` rows and keyed on the intent (the path alone), so a later write at the same path that succeeded read as the create's landing and undo deleted the record that had been there all along. The terminal rows (the ok row and the error row) now carry their capture's id and the restore pairs by that id alone (two creates at one path interleaved each find their own landing), and a capture already put back is put back once: a second `undo` of it is refused by the ledger's own row, since a record made at that path since would be the one removed. **Proven live on the lab (2026-10-08, PVE 9.2):** a token created through the core with UNDO on was captured absent (PVE answers 500 for the read-back of a token that is not there, as it does for a missing user), the create landed and its ok row named the capture, `undo <id>` planned then sent the vendor's DELETE under its own capture and `restores`, the read-back was the vendor's own "no such token", and the second `undo` was refused as already put back; the ledger's keyed chain verified whole and no row carried the token's value.

**`mint` makes the write token the vendor bounds.** With SCOPE and LEASE gone to the vendor, the write token's own ACL and `expire` are the only bounds, so `proximo-core mint <plane>` (and `proximo mint`, one module now in the core) prints the vendor's commands for it, to run on the vendor's host. `--write` refuses without `--scope` (an ACL path: `/vms/101`, `/pool/<name>`, `/datastore/<store>`; `/` or `/vms` say "everything" out loud) and expires in 8h unless `--expire` says otherwise (`<n>m|h|d`, or `never` by name); the expiry is computed when the command runs, never baked in when it prints. Re-minting rotates: the past token of the same name (on PMG, the user) is deleted first, because the vendor keeps an expired one and refuses a second. Every value typed into it (`--scope`, `--user`, `--token-name`, `--token-file`) is held to a shape a shell cannot misread, the token's directory is made first (the vendor's create succeeds even when the redirect fails, and a secret printed once is gone), the file is written under `umask 177` and an empty one is named. Read and write are two files wired as the arm pair; the default names are now `read`/`write` in `$HOME/.config/proximo/<plane>-<name>.token` (0.44's were `mcp` and `<plane>.token`). PMG has no tokens and no ACL paths, so its read and write credentials are two users in two-line credential files (the mode in which arming switches users), bounded only by `expire`, and a `--scope` on pmg is refused. Verify reads the file itself (`proximo-core <plane> GET /version`, and on the token planes `GET /access/permissions`, the vendor's own account of what the token can do). Two secrets cross a command line and the recipe says so: PMG's `pmgsh` takes the service password only as an argument; PDM's bootstrap sends root's password on stdin, to loopback only, with its ticket in a private `mktemp` jar. Fixed on the way, all inherited from 0.44's recipe: a PBS token was granted alone, but a PBS token is user ∩ token like PVE's (no privsep toggle is not no intersection; a token-only grant answered "permission check failed", 2026-06-15), so it could do nothing; the PMG user was created at `/config/users`, which PMG does not publish (a test now holds every printed address to the vendor's table); the PDM jar was a fixed name in shared `/tmp`, made before the umask, and root's password rode curl's argv. **Proven live on the lab (2026-10-06)**, each recipe run as printed on PVE 9.2, PBS 4.2 and PMG 9.1 (PDM 1.1 from the token create on, through `proximo-core`, since the lab stages no PDM root password): a write token scoped to `/vms/9101` reads and changes that guest and gets the vendor's own 403 on `/vms/9102`; a `--expire 1m` token answers 401 at sixty-two seconds; re-minting with a new scope leaves only the new one (deleting a token drops its ACL rows); PBS tokens really are user ∩ token (token-only 403, both 200). The live run found four more, all fixed and pinned: PBS's `generate-token` refuses `--output-format` and answers `Result: {json}`, so its capture got nothing (a test now drives each printed capture on the vendor's real output); PMG publishes `enable` with default 0, so every PMG user was born disabled and every login answered 401; the second recipe on one user stopped at "already exists" (the user step is now a no-op when the user exists); and PBS applies an ACL change a few seconds late, which verify now says. The lens on that live-proof fold found three more, folded: the token's directory was made with `install -d -m 700`, which re-modes a directory that already exists (as root, `--token-file /tmp/x.token` would have turned `/tmp` from 1777 to 700), so it is `mkdir -p -m 700` now, a no-op on a directory that is there; PDM's root-password prompt read from the recipe's own next line when the recipe was fed to `bash -s`, so it reads the terminal; and the PBS user check was asserted by grep, so each of these three is now a test that runs the printed line (the directory's mode before and after, the prompt with a sentinel line behind it, the user check on a list with and without the user). Still print-only: mint calls nothing, reads no secret and writes nothing.

**The core stops re-doing what Proxmox does.** John, 2026-10-05: the 0.45 bar is the six pillars over every address the vendor publishes, through every door, in a 4K window, and nothing the vendor already does. Three things went. The argument constraints this branch carried for a night (pattern, length, bounds, enum): Proxmox enforces its own and answers 400, and that answer is already a ledger row with its status; a lens found four ways the copy refused a right answer and one way it froze the door. SCOPE: a write token whose ACL names the guest's path or a pool is the scope, enforced server-side where no bug of ours can widen it. LEASE: a token's own `expire` is the lease. A core door still configured with `PROXIMO_SCOPE_PATH` or `PROXIMO_ARM_TTL` refuses every mutation and says why, instead of quietly losing a gate it thinks it has (`PROXIMO_ARM_TTL=0`, LEASE's own "off", refuses nothing). 0.44's `proximo_api_plan` and `proximo_api_call` run through the core, so on this tree they follow it: a 0.44 box configured for SCOPE or LEASE is refused at that door, and its two tool descriptions no longer name either gate; the 0.44 wrappers keep their own SCOPE and LEASE until the flip removes them. Kept from the night's work: a `oneOf` body requires a name only when every variant does (PVE's HA rules required `nodes` of a resource-affinity rule, which the vendor does not), and two test fixtures now carry values the vendor accepts.

**PBS's nested bodies reach the table.** Parity row B19, its first half. PBS (and PVE's HA rules) publish an address's parameters inside `allOf` blocks, and PVE's HA rules inside a `oneOf` keyed by rule `type`; the table builder read only the top level, so 78 addresses had no parameters in the table and the engine refused every argument there: the core could not update a PBS datastore, remote, user, realm, sync job or notification endpoint, and no undo restored one. `scripts/build_governance_table.py` now merges the nested blocks (and the HA rules' discriminator, which the vendor requires and publishes with its own enum). The vendor schema fetched 2026-10-05 rebuilt the previous table byte for byte before the change, and the new table builds byte for byte twice. Before the 78 addresses opened, their parameters were swept for secret-shaped names: every one (passwords, an OpenID client key, metrics and webhook tokens, S3 and sync keys) is fingerprinted in receipts by the existing name rule. The sweep found a hole the flatten would have widened, on every plane: a PLAN answer echoed a secret-named field raw, the live read's old value under `from` and the caller's new one under `to` and `arguments`. The plan now holds them to the receipt's rule (without the bearer clause, which names a mutation's answer, not a read's state). The secret-returns scanner had the same blind spot for nested return schemas; walked, it surfaced five fields on PBS, each judged from the vendor's own description (token and key IDs, a rate limit, the S3 key ID whose secret half is already dropped).

**One Proximo, every box it is given.** Parity row B16, multi-target: this host runs two live Proxmox estates, and the core doors reached only the one the environment configures, while the engine already governed whatever box it was handed (a `wire.Plane`: its own arm pair, its forbid added to the floor, its rate against the env's with the tightest winning, its name on every receipt). `proximo.core.registry` now reads `PROXIMO_TARGETS` for the core, moved out of 0.44's `targets` and `envelope` so both read one parser and one box-rate rule (two names for one box are one budget). `proximo_plan`, `proximo_read` and `proximo_call` take `target`, and the shell door `--target`; the REST and A2A doors carry it through. A target's mutation is judged by its own arm pair: the env box armed says nothing about another estate, and the refusal names the missing `arm_source`. An unknown name is refused without listing the registry, a target of another kind is refused, a secret file other users can read is refused with the fix and not its path, and a diagnosis of a remote box never runs the host's shell probes over this host's ssh. The selector is advertised only where a registry is configured, 0.44's rule: on a one-estate box the 4K window pays nothing for it; on a box with a registry the door costs about 43 tokens more, which puts the 4K bar's door, plan and one read about 41 tokens over (the gate measures the one-estate door). Every core tool now REFUSES an argument it does not declare, where the SDK used to drop it: on a box without a registry, a call naming a target had run on the env box (lens 3), and a misspelt `wait` or `fields` vanished the same way. Over REST and A2A that refusal is a 400. Scope (`PROXIMO_SCOPE_PATH`) is keyed on the path alone, so a scope entry admits the same path on every box, and CONTAIN's trip stops every box: both are named in the parity plan, not changed here. The rest of row B16 is judged in the parity plan, and it names seven subcommands of the 0.44 `proximo` command the flip has to carry.

**REST and A2A are doors over the core.** Parity row B11, its first half: every protocol is a door, rebuilt thin. The 0.44 REST face (`proximo-http`: `POST /tools/{name}`, an OpenAPI document) and A2A face (`proximo-a2a`: an agent card, one JSON-RPC endpoint) ran the 0.44 server's tools through `governed.call_governed`, and the core had no REST and no A2A. Two new commands, `proximo-core-http` and `proximo-core-a2a`, serve the six core tools (`doors/mcp.py`) over those same two faces, the way `proximo-core-mcp-http` already served them over the MCP-HTTP face: `httpface.build_app` and `a2a.app.build_app` take a `dispatch=` (`proximo.core.doors.dispatch.Core`, the six tools on the core's own MCP instance) and a `record=` (the core's row writer), so the Host guard, the cross-origin guard, the bearer check, the badge camera, the OpenAPI document, the card and its signature are the bytes the 0.44 faces run, with the core's engine behind them and the 0.44 server never loaded (a fresh-interpreter probe pins it, with the 0.44 face as its control). Same env names, ports and face names as the 0.44 faces, so a host configured for one serves the other with the same files and ports; not carried, and said so: `PROXIMO_SURFACES` (refused at start, the core has no surfaces), the 0.44 reach-grant check at serve time (parity row B16), and session rows land on every start and stop. Three error messages that quoted a foreign text, two 0.44 (a vendor error body on file-restore downloads, the registry's path on a TOML error) and the core's own shell lane (ssh's stderr, both exits), no longer do, now that the text travels to REST and A2A callers. The adapter itself moved: `governed` is now `core.doors.dispatch` applied to the 0.44 instance, so the two surfaces cannot drift. Two things the 0.44 faces did wrong, found driving the new doors with the real clients and fixed for both: (1) a `ProximoError` raised inside a tool reached a REST or A2A caller as the type name alone, so every refusal read "ProximoError" where the MCP doors said "not armed", the tier a mutation lacks, the consent id; the text is the answer now, and a foreign exception is still a type name only; (2) the A2A executor never enqueued the Task before its first status event, so every refusal, unknown tool and malformed message crashed the request (`InvalidAgentResponseError`) instead of failing the task, while the success path worked because an artifact creates the task on its own; the old tests drove the executor with a queue that ran no ordering check. The Task goes first now, so a non-blocking send answers `submitted` and the client polls, per the protocol. The default `proximo` / `proximo-proxmox` commands still boot the 0.44 server: the swap's mechanical half, last.

**The download lane: bytes land on disk.** A byte stream lands on this host, never in an answer. Parity rows L6 and L7, the first lane of the flip. Five published GETs answer bytes, not JSON: a file pulled out of a backup on PVE (`/nodes/{node}/storage/{storage}/file-restore/download`) or PBS (`pxar-file-download`), a PBS blob or index (`download`, `download-decoded`) and a quarantined mail on PMG (`/quarantine/download`). The core gated all five shut with a pointer to a 0.44 tool. Now they are the download lane (`proximo.core.download`): the bytes stream into a fresh private directory under `PROXIMO_RESTORE_DIR` (0700, the file 0600, created O_EXCL|O_NOFOLLOW so nothing is overwritten or written through a link), capped by `PROXIMO_RESTORE_MAX_BYTES` from Content-Length before the first byte and again while streaming, and the answer carries the local path, the byte count and the sha256, never a byte; a refusal or an error removes the partial and the directory and is receipted `core.error`. The local name is the caller's own argument (the decoded `filepath`, the `file-name`, the mail's `mailid`; basename only, 200 bytes, control bytes and separators replaced, `.tar.zst` when tar was asked), never the vendor's Content-Disposition: that header on a quarantined mail is attacker text. Only a 200 is a download (a 3xx or a 204 would land an empty page as the file with a receipt saying ok), and the vendor's error body is never echoed: a 401's text can carry the credential the caller sent. A plan with the lane off learns no landing directory, and a refused question (fields, since, wait on a stream) leaves a `core.refuse` receipt. The lane is opt-in like every lane that touches this host: `PROXIMO_ENABLE_DOWNLOAD=1`, refused `needs=download` otherwise, and a template path names nothing to pull. 0.44 asked `confirm=True` per pull; the core asks the operator once per deployment and caps every pull. `fields`, `since` and `wait` are refused on a stream, a plan dials nothing and names the landing directory and the cap, the quarantined mail is marked untrusted in `taint.toml`, and the raw GET door still refuses all five (it answers JSON). L7 is beyond 0.44: nothing in 0.44 served the raw mail download. Not carried, said plainly: 0.44 pre-read the entry's size from the listing and refused an over-cap pull before the first byte; the core has no listing probe, so an over-cap pull without a length header stops at the cap and removes the partial, which costs bandwidth, not safety; and without the listing a directory pulled without `tar` lands as a zip with no extension. With this there is no hard-gated published address left: every row is served, a lane, held, or excluded as not a JSON call.

**Every published mutation has a verdict.** John, 2026-10-04: "equip the fighter for the arena, allow them to enter the arena from any gate offered." The tier record was harvested from the 0.44 wrappers' own blast sentences, so every address those wrappers never reached arrived in the core with no line, and the engine refused it as unjudged even when armed: 136 published mutations on 2026-10-04 (node reboot and shutdown on three planes, datacenter options, cluster create and join, the bulk guest actions, 86 of PDM's 118). `tiers.toml` gains the families the harvest never reached (87 → 147 family lines, each sentence written from the vendor's own published description, plus 4 address lines sharper than their family) and a `[tier.held]` table for the 20 addresses the door refuses ON PURPOSE: the login-ticket flow (`/access/ticket`, `/access/openid/*`, `/access/oidc/*`, `/access/vncticket`: the door would log in with a password the caller supplies and hand back a credential usable outside the door, around every pillar), PVE's `POST /nodes/{node}/execute` (a batch of API calls the seam never sees), PDM's `POST /auto-install/answer` (answers an installing machine's answer file, root password in plain text) and PVE's internal-use `POST /cluster/config/nodes/{node}` (answers the corosync authkey). A held line is a judgement with a sentence, not an absence: `govern()` reads it before arm and refuses `needs=held` with the sentence, a plan of it reads no live state, a held address is never also tiered, and a held line that carries a tier, has no sentence, or names a read or a tunnel refuses the record at load. Opening one is a line moved from `[tier.held]` to `[tier]`, John's hand by name. `tests/test_arena.py` is the guard: a mutation the engine may open (ungated, or on an opt-in lane) that is neither tiered nor held is red, with the planted controls (a family line removed → `needs=tier`; a held line removed → the same address reads as unjudged). `scripts/arena.py` generates `docs/arena.md`, the inventory a reviewer reads instead of a claim; the test refuses a stale copy. Lens 1 on the first cut found what the record did not say: **a mutation whose answer is a one-time secret its read never shows** reached the caller raw, because the secret record was consulted by the read twin alone (0.44's `pve_token_create` served the value once by design and its docstring said so; the core's door served the same address with no line and no label). Lens 2 then found that the fold had closed five addresses and not the class, so the class is now held by the same vendor-schema guard that held the reads: `scripts/secret_returns.py` scans every method's return schema (it had scanned GETs alone) and `tests/test_secret_record.py` demands a line for every credential-named field a mutation answers with. `engine.secret_rule` is the address's own line MERGED with its read twin's (the twin's drops still withhold a mutation's echo; bearer comes from the own line): a mint (an API token's value on PVE, PBS and PDM, on create and on regenerate; PDM's auto-install tokens and the token a prepared answer file mints; a second factor's recovery codes on all four planes; a storage's auto-generated encryption key) is served whole to the caller who asked, labelled `bearer_credential`, and fingerprinted whole in any receipt; a create that echoes the secrets the caller sent (the prepared answer file's hashed root password and subscription key, a PDM scan's token, the subscription pool's keys) drops the echo; the OpenTelemetry metric server's `otel-headers` and a second factor's value are fingerprinted in the ledger. Not closed here, said plainly: the 5 byte-stream downloads (parity rows L6/L7, a download door is real work) and the 17 console-ticket POSTs, which stay excluded because they mint a credential for an interactive console no JSON door can consume; one line from John opens either.

**The host's own battery, behind its own switch.** Parity row B3's last half and B5's node shell: 0.44's `pve_node_diagnose` ran seven fixed read-only commands on the PVE host over ssh (failed units, the PVE services' states, the host journal's errors, `df`, `free`, `pveversion -v`, `pvecm status`) behind `PROXIMO_ENABLE_NODE_SHELL`, and it had no command line for the host at all. Both stay true. One authored read, `GET /nodes/{node}/probe` with `probe` naming one of the seven, runs 0.44's argv verbatim on the host itself after the same guard as the container lane (the host the ssh target reached must be the node the path names, or nothing runs) and with the same per-call markers. There is no host exec row, and the wire cannot dial one. It carries the battery only: 0.44's `pve_node_logs` (one unit's host journal over ssh) maps to the vendor's own `GET /nodes/{node}/journal` with `unit`, a governed, untrusted read, but not the same tool: it is not behind the node switch or 0.44's reach mirror (every journal read is the token's to make), it reads any node the token can where 0.44 read only the host its ssh reached, it answers the vendor's lines rather than a command's exit and streams, its count is `lastentries` where 0.44's `lines` defaulted to fifty, the vendor implies a unit's `.service` suffix where `journalctl -u` takes any unit, and it has not been called live yet. The lane is its own: `PROXIMO_ENABLE_NODE_SHELL` opens it, the container lane's switch does not, and neither opens the other; it has no allowlist because the node is singular and the guard refuses any other host, and a path that names no node is refused. It is never arm-gated, so a broken host is diagnosed disarmed, and its output is marked untrusted, since a host's journal and unit list carry names its guests choose. A node diagnosis now runs the API reads and the seven probes. `pvecm status` exits nonzero on a node that is not in a cluster, so its exit is data; any other probe that does not exit clean, or whose output the wire cut, keeps its output, is not read for flags and makes the diagnosis incomplete. A closed lane is now one line, for both lanes: judged once by govern, its probes named and not attempted, the lane's own refusal in the answer's `shell`, one flag that says the diagnosis is incomplete, and the refusal on the diagnosis's ledger row. Seven refused sections had put a node diagnosis with the lane off over the 4K door's read share. Proven live on a production host, reads only: the seven ran, the standalone node's `pvecm` exit read as data, the battery found a failed unit, and with the lane off the answer was one line and fit the door. The lens found two gaps in the compaction: a node path with an encoded slash raised out of the diagnosis with no receipt, and a registered target, or no ssh target, still gave seven identical refusals; each is one skipped line now, the second in the wire's own words. Named and left open: with a lane on, a diagnosis carries each command's whole output up to the wire's share, so a real host's answer does not fit the 4K door, and a test pins that and fails the day it fits; and 0.44's reach mirror, its check of the token's privilege at the node or guest before a shell call, is not carried for either shell lane.

**Inside the container, a diagnosis.** Parity row B3, the container's shell battery: 0.44's `ct_diagnose` ran five fixed commands inside the container after the API read (failed units, `df`, the journal's errors, `free`, listening ports) and flagged systemd's failed units. One authored read on the container shell lane, `GET /nodes/{node}/lxc/{vmid}/probe` with `probe` naming one of the five, runs 0.44's argv verbatim; any other name is refused before anything dials, and the caller never sends a command. It is gated like the lane (`PROXIMO_ENABLE_EXEC` and the container on `PROXIMO_CT_ALLOWLIST`) and never arm-gated, and its output is marked untrusted. The battery loads only rows that are ungated or on an opt-in lane; a probe on a hard-gated read still refuses the load. A failed-units flag counts the lines `systemctl --failed` prints and is judged only when it exited clean, so a container without systemd says it is incomplete instead of reporting a failed unit; a command that is not installed says so. Proven live on a sealed lab container: the five ran, the battery found the one unit that had failed there, a unit planted to fail took the count from one to two and back to one when it was cleared, and with the lane off the diagnosis said incomplete instead of healthy. The lens found the shell wire's cut reported as a complete read: a stream cut to fit the cap read as the whole of it, and two hundred and forty failed units were counted as fifty-one. A cut record is now kept, named with its original length, never counted, and incomplete. It also found a vendor read whose `snapshot` parameter is a name could make a plan announce a snapshot; only a shell row that publishes one does now.

**A snapshot first, and undo puts the container back.** Parity row B2's snapshot half: 0.44's `ct_exec(snapshot=true)` took a container snapshot before the command and refused the command when the snapshot did not land. `snapshot=true` on the container `exec` and `psql` rows now takes the vendor's own container snapshot as a governed mutation of its own (armed, tiered, receipted, waited to completion), and anything short of a task that finished OK refuses the command before it runs. The capture names the snapshot and its rollback, and `undo <id>` is the vendor's rollback of that snapshot, governed like any write (the MCP door plans it until confirmed; the shell door runs it, and `--plan` previews), which verifies the ledger first, rebuilds the address from the command's own target and refuses one that does not match, and sends `start`, because the container was running when the snapshot was taken and the rollback leaves it stopped. Under enforced consent the snapshot rides the command's grant: one grant covers both and is spent once, and the exemption holds only for the vendor's container snapshot of that command's own node and container; arm, tier, contain, scope, lease, forbid, taint and rate still judge it, its receipt names the command and the grant that covered it, and the command's plan says it also takes a snapshot. A flag that is not a boolean is refused, and the shell lane refuses a registered target, because the snapshot would land on that target's API while the command ran on this box. Proven live: on a lab container whose storage cannot snapshot, the snapshot failed and the command did not run; on a throwaway container on thin storage, the snapshot landed, a marker was written, the rollback ran, the container came back running and the marker was gone, the second time under enforced consent with one grant. The first lens found the two the fix refuses: a flag of `1` ran the command with no snapshot, and the registered-target split.

**Inside a container, through the same seam.** Parity row B5, its container half: 0.44 ran `ct_exec`, `ct_psql` and `ct_logs` over ssh beside the API path, with the gates wired by hand, and the core had no path for them because the vendor publishes no REST address for `pct exec`. Three authored rows (`shell.toml`; five since, with the probe rows above) now sit in the vendor's own container tree, `POST /nodes/{node}/lxc/{vmid}/exec`, `.../psql` and `GET .../logs`, and from there they are governed like every other row: an opt-in that is refused when unset (`PROXIMO_ENABLE_EXEC` and `PROXIMO_CT_ALLOWLIST`, 0.44's names, whole CTIDs), arm and a destructive tier for the two that change things, the output marked untrusted, the argv and the SQL fingerprinted out of the ledger. Only the wire differs. It runs ssh non-interactively, has no default target, and before `pct` runs it checks that the host it reached is the node the path names, so a call aimed at one node can no longer land in a container on another while every receipt says otherwise. Each call carries two markers a container cannot see, so an exit code is reported as the command's own unless the guard or ssh itself produced it, and a 255 after the command started says it cannot tell the command's exit from a dropped connection. The load refuses a row the vendor also publishes. Proven live on a sealed lab container: the journal, `id` as root inside it, `psql` against its own database, the three refusals (switch off, a container off the allowlist, the wrong node, whose command never ran), and a keyed ledger that verifies with no command or SQL in it. Two adversarial passes found false "nothing ran" claims twice (a command exiting 254 or 255, and ssh noise ahead of the marker); both are fixed with tests that were red first. The snapshot before exec, the shell batteries and the node shell followed (above).

**Inside a guest, opted in per VMID.** Parity row B5, its QEMU half, and rows L4 and L5: 0.44 reached inside a guest through the qemu-guest-agent behind `PROXIMO_ENABLE_AGENT` and a per-VMID allowlist; the core refused the whole `/nodes/{node}/qemu/{vmid}/agent` subtree, 27 addresses (14 reads, 13 mutations), with a pointer to tools that die with 0.44. The subtree is now an opt-in gate, not a wall: an agent address opens only when `PROXIMO_ENABLE_AGENT` is set and the guest's VMID is on `PROXIMO_AGENT_ALLOWLIST` (empty denies, `*` allows every guest, otherwise whole VMIDs, so `10` does not open `101`), and then every other pillar applies as it would anywhere, so a guest exec is a mutation that is refused unless armed and tiered. Unlike every other opt-in control, this one is refused when unset rather than inert, because the subtree was refused before. The 13 mutations carry tiers with 0.44's own blast sentences (exec, file-write, set-user-password and the bare agent command destructive; freeze, thaw, shutdown and the three suspends disruptive; fstrim restorable; ping and fsfreeze-status read-back, since they change nothing). The 14 reads and the bare agent command are marked untrusted, since a guest writes what they return, and a new `args` field in `secrets.toml` keeps a guest exec's command and input and a file-write's content out of the ledger, which matching on parameter names alone did not. The table is not rebuilt and its gate string is unchanged: the opt-in lives in govern, keyed on one prefix. An adversarial pass found the bare agent command's answer unlabelled (it runs read commands too); that line is in, with a test that was red first. Still to come in B5: the exec-status poll (the ssh exec lane and the shell batteries followed, above). The reach mirror (0.44 also checked the token's privilege at `/vms/{vmid}`) is not carried.

**A diagnosis is a battery of the vendor's reads.** Parity row B3, DIAGNOSE, the pillar the core did not have: 0.44 gathered a node's status, storage usage and the failures among its last fifty tasks (`pve_diagnose`), a container's status plus an in-container shell battery (`ct_diagnose`) and the node's API half plus a host shell battery (`pve_node_diagnose`); the core gathered nothing. One rule, like PLAN's read and UNDO's write: a diagnosis is a fixed battery of the reads the vendor publishes about a subject, each run through `execute` (receipted, withheld, tainted, bounded like any read), and the flags are 0.44's own thresholds on fields the vendor publishes, from an authored record (`proximo.core.diagnose`, `diagnose.toml`: three subjects, five probes; the shell batteries above added twelve). A subject is its own published index address, `/nodes/{node}`, `/nodes/{node}/lxc/{vmid}` or `/nodes/{node}/qemu/{vmid}`, so a concrete path resolves to it like any read and binds the probes' placeholders; a probe naming an address the table does not publish as an ungated GET (or, since, a read on an opt-in lane) refuses the load (the planted misspelling went red), and a flag with no sentence or an unknown shape refuses it too. On both doors it is a read's mode, like `since=` and `wait=`: `proximo-core pve GET /nodes/pve1 --diagnose` and `proximo_read(plane, path, diagnose=true)`, the path alone (arguments, fields, since, wait and a method other than GET are refused). The answer is `derived: true`: the status fields 0.44 kept, the storage rows lean (name, type, active, enabled, used, total, the vendor's fraction), the task window as asked, seen and counted by outcome with the failed rows (ten whole, the count entire), the flags, and the shell half named under `skipped` (both shell batteries have since joined the diagnosis, above, and a VM's in-guest half is still named there). Nothing incomplete is quiet: a probe the vendor fails or the spine refuses is a section with the reason and a flag that says the diagnosis is incomplete, the battery goes on past it, and the one `core.diagnose` row is written after the battery with every section's outcome, never an ok stamped before the reads ran (0.44's own lens finding). A window is not a history: fifty task rows are more than the door's cap, so the read comes back cut and the section says how many of the fifty it saw; the operator's cap widens it. An untrusted probe keeps its label on its section and the answer, and fenced it is not read for flags and says so (planted: no authored probe was untrusted then, so one was; the shell batteries' probes are, since). The task classifier is 0.44's rule in the core's words, and one test drives both copies over the same rows. The fixtures are real reads from one node through Proximo, scrubbed (node, ids, names, tags, storage names, token ids replaced; the vendor's keys, counters and status strings kept, including a real failure's exit text). Twenty-two controls planted and watched red: the row dropped, the row written first, the incomplete flag dropped on a vendor failure, incomplete always false, a spine refusal aborting the battery, an inactive storage evaluated as full, WARNINGS read as failed, the fence unrecognised, the untrusted label dropped, the window sentence dropped, the failed rows unbounded, the rows read raw instead of projected, a POST accepted as a diagnose, arguments ignored on the MCP door, a template path accepted, the memory threshold moved, `derived` false, the door's text silent, an inert probe not refused, a probe binding a placeholder its subject does not carry, a parameter the probe does not publish, and a state the vendor did not report flagged as not running (that one could not fail until its test existed). The door's text grew by the one mode and was trimmed elsewhere to pay for it: 1,181 to 1,185 tokens, the 4K gate holds with two to spare. Subjects on the other three planes wait for a real fixture; 0.44 had none there either. The lens (sonnet, two blocking, both this build's own and in the unsafe direction) then broke it: a vendor integer too large for a float raised out of the flag arithmetic after the three receipts and before the diagnosis row, and a finite fraction whose percentage was not overflowed in the rounding (now the arithmetic catches the overflow as no fraction, a percentage that does not fit says "over 100", and every section's flag evaluation is contained, 0.44's own posture: whatever a vendor value does, the section stays, the battery goes on, the row is written and says the flags were not evaluated); and an untrusted probe whose read was refused before its data lost its label and copied the refusal's text, which can quote the rows' own keys, as the door's words (now the label comes from the address before the read, and a refusal's words on an untrusted address are fenced when the fence is on and labelled when it is not). Folded with it: the projection's own refusal, when no row carries a named field (no rows, none finished, every storage offline), is not a failed read; the read is taken again raw, receipted again and projected here, so an all-offline node gets its inactive sentences instead of "read failed"; and a flag sentence that cannot render refuses the load instead of aborting a battery. Eight more controls planted and watched red (the overflow uncaught, the flags uncontained, the label set after the read, the refusal's words unfenced, the projection refusal not re-read, the sentence unchecked, the render check narrowed to one error class, the percentage rounded raw): thirty in all. A second lens on that fold found one more, in the fold itself: the raw re-read projected a row carrying none of the fields the battery reads to an empty record, and an empty task row has no end time, so two rows the door could not read a field of came back as a healthy "2 running" (now a row carrying none of the named fields, or a list that is not records, is an unevaluated section with the count of such rows, never a window; a schema the battery does not know is not a window to count). Folded with it: an integer too large for a float is a number the arithmetic cannot judge, so the section says its flags were not evaluated instead of reading clean (the first fold had swallowed it as no fraction), and the load check renders a sentence with a number, so a legal `{pct:d}` loads and `{a.b}` is still refused. Four more controls (blank rows counted, the overflow swallowed, the render check on a string, non-record rows uncounted): thirty-four in all. A third lens found one more, there since the build and named by the second: a rows probe whose body is not a list (a dict, a string, a number) read as an empty window, no flags, a healthy row (now the mirror of the record probes' guard: a body of the wrong shape is a section that says what it answered). One more control (the guard removed): thirty-five in all. Named and left: a cut task window is data (`window`), not an incompleteness flag; one hostile row hides the true flags of its probe's other rows, loudly (the section says the flags were not evaluated); a box whose ledger cannot be written still answers a diagnosis, the engine's rule for a read, and the answer does not say its receipts are missing.

**A capture is written back by the vendor's write.** Parity row B2, UNDO's restore, the half the core did not have: every mutation with a GET twin already captured the record before it ran (`core.undo_point`), and nothing restored from it, while 0.44 had `prior_config` and `pve_guest_config_revert`. One rule, like PLAN's read: the restore is the PUT the vendor publishes at the same path (204 PUT addresses across the four planes have a GET twin, 178 of them tiered), written with the captured record as a governed mutation through `execute`, armed, tiered, consented, rated, receipted, and captured itself, so an undo is undoable; nothing is invented where the vendor publishes no such write (a deleted record, a collection, a path with no PUT each get the reason). Every executed mutation now returns `undo.id`, the receipt row's own hash (an `intent` is shared by every mutation at a path and would have picked the latest), the row names its plane, and `audit_entries` rows carry their id, so a capture is findable without the file. A restore is spelled the way the shell door spells it, `proximo-core pve undo <id>` and `proximo_call(method="undo", path=<id>)`; the MCP door plans until confirmed and the shell door runs it unless `--plan`, as it runs every write: the plan is the PUT's own plan over the record read now (one governed read, handed to the plan so it is not read twice), so `change` says what goes back and `noop` says nothing drifted, and a noop writes nothing and spends no grant. The write carries only the keys that drifted, compared as strings; a key added since rides on the write's own delete list where it publishes one (a comma string on PVE and PMG, an array on PBS and PDM; a boolean `delete` is a flag and is never used) and is named as skipped where it does not; `digest` is the CURRENT record's, never the capture's, so a write that raced is refused by the vendor (0.44's rule); a parameter the PUT requires rides along at its captured value (PVE's node DNS needs `search` on every write). What is never written is named under `skipped`: a value the receipt withheld (a credential, fingerprinted on the row; the planted control wrote a storage password through and went red) and a key the write does not publish (`meta` on a QEMU config, `type` on a storage; the vendor's schema is the allowlist, no hand list). PROVE guards UNDO: the chain is verified under the ledger's own key before the capture is trusted, and a break refuses the restore with a receipt (`needs: prove`); on a box that opted out of keying (`PROXIMO_AUDIT_KEYED=false`) an unkeyed chain proves accident, not an adversary, and a capture rewritten by whoever can write the file is restored as written, the ledger's own policy (lens 4); a truncated capture (over the 64 KB bound, hash only) and a capture recorded before rows carried a plane say so. A seventh tool cost 260 tokens against the 4K gate's nine of room, so the restore rides on `proximo_call` and the door's descriptions were trimmed: door 1,178 to 1,181 tokens, the gate holds with six to spare. The fixtures are two real guest configs read from the estate through Proximo and scrubbed to documentation addresses (`net0`/`net1`, `meta`, `smbios1`, `vmgenid`, `digest`: the keys Proxmox sends, not the keys a test imagined). The lens (sonnet, six blocking, every one this series' own and in the unsafe direction) then broke the first fold: the chain was verified by the archive walker, which trusts each row's declared algorithm, so a keyed ledger rewritten as an unkeyed chain with a forged capture passed and reached the wire (now the live verifier under the ledger's own key, which is what the key exists to catch); with the taint fence on, the fence's wrapper was diffed as the record and the restore sent the whole guest config with no lock (the wrapper is refused by its own shape); every key added since the capture rode the delete list, so `unused0` after a detach and `lock` under a backup would have been deleted (now only a key the captured mutation itself added, read from its `executing` row, is removed; the rest are named); a POST's capture restored through the PUT at the same path where the two are different operations (apt repositories: POST changes a repo, PUT adds a standard one) and answered `noop` (now a POST restores through the PUT only where every parameter the PUT publishes the POST publishes too, QEMU's async config and nothing else of the twenty such paths; a PUT with no published parameters refuses rather than noop, 37 of the 204, 32 of them PBS, the B19 gap; a noop says "no published key differs" and lists `differs_unwritten`); a capture made on a registered box restored onto the env box's path (now the box the row names is the only box); and a write whose task failed still claimed `restored` (now `status: failed` with `attempted`). Folded with it: `args` on an undo refused on both doors, a captured `delete` and a null never sent, the not-found sentence says the live log was searched and archives were not. Twenty-eight controls planted and watched red on the build and its first fold, fifteen on the build (the withheld check dropped, the digest from the capture, the chain not verified, the restores link dropped, a boolean delete used as a list, a required parameter not carried, a noop that still writes, an unpublished key written, a deleted record restored, a truncated capture restored, no id on the answer, the shell door's undo gone, the MCP door's undo gone, the plane off the row, a collection written) and thirteen on the fold (the archive walker back, the wrapper accepted, every added key deleted, the same-write rule dropped, an empty-body PUT not refused, a noop silent about unwritten diffs, the box not checked, a failed task claiming restored, args ignored on the MCP door, args ignored on the shell door, a captured delete sent, a null sent, the archive sentence dropped). A second lens on that fold found three more, in the fold itself: the chain check held only while the key file existed (delete `audit.key` beside the log and the same forgery read as a clean unkeyed chain; a box configured keyed whose key is gone now refuses outright, an unkeyed box keeps its UNDO, and an unreadable key file is a refusal, not a traceback); a credential the mutation set never reached the diff, because the read strips credentials from the data and names them under `withheld` (now a withheld name the capture lacks is named as skipped and listed under `differs_unwritten`, so undoing a mutation that only set a password never reads "nothing differs"); and `failed` was claimed for a write merely submitted, timed out or unpollable (now `failed` only when the task finished and failed, else `submitted`, `timed_out` or `unknown`, with `attempted`). Folded with it: the evidence is read ONCE and verified, found in and paired within those bytes (the verifier now judges lines, `verify_lines`; three separate reads of a writable file let a swap between them put a forged capture on the wire); the executing row is paired by the capture's own id in its preview, not by the path's intent, which mispaired interleaved twins; the plan carries the twin's `untrusted` label, not the PUT row's. Eight controls planted on that fold and watched red: the key-gone check removed, a bad key file uncaught, the withheld-now names dropped, every unfinished task read as failed, pairing by intent, a second read for the pairing, the PUT row's label over the twin's; one planted control could not fail and showed a redundant clause, which went. A third lens, the stop-rule round, found one more, in the second fold's one-read change: the rows were split with `splitlines`, which also cuts on U+2028, U+2029 and U+0085, characters `json.dumps(ensure_ascii=False)` leaves raw inside a string, so a genuine row holding one (a pasted description) became two unparseable fragments, the restore said "not in the live log", and `audit_verify`, which shares the verifier, accused a clean ledger: rows are split on the newline the writer joined them with, and nothing else (control: `splitlines` back, three red). `tests/test_core_undo.py`, 49 tests; thirty-six controls in all. Named and left: the refusal's receipt on a keyed log whose key is gone mints a new key and seals the forged unkeyed log as an archive under the rotation's own name, the ledger's standing upgrade policy, the refuse row the only trace; the restore's own capture row carries no untrusted label (every capture's); the snapshot half of 0.44's UNDO (`snapshot=true` before exec, the safety snapshot before a PDM rollback) rides with B5 exec, where its host is (since: the snapshot before exec is in, above; the PDM one is not); the arguments of a restore come from the read before the write's own capture read, so where the PUT publishes no `digest` (112 of 204; the lens counted 120 over a wider set) a raced write is unlocked (the capture window itself is every mutation's); a plane-less capture (recorded before this) restores into whatever plane the operator names; a legitimate value containing the literal `[redacted]` is skipped as withheld; a captured list for a string-typed parameter is sent as a list; credentials the capture holds raw because no rule names them (a webhook header, a key in a URL's query) are written back as faithfully as they were kept.

**A mutation's plan reads the target as it stands.** Parity row B1, PLAN's live state, the pillar the public was told about: 0.44's plans read the guest's status or config per tool and branched (a start on a running guest was a no-op), while the core's plan answered the verdict, the tier sentence and the published schema and read nothing. Two rules pick the read and nothing else: the GET twin the vendor publishes at the same path and serves (543 of the 865 mutations across the four planes; a gated twin is named, not read, and so is the one twin that needs an argument the path cannot give, so 542 are read), else the `/current` beside a PVE power or HA action (15: 13 guest power, 2 HA arm/disarm; an HA status list is summarized, not dumped). The read goes through `execute` as the governed read it is, receipted, withheld, tainted and bounded like any read, and the plan answers `current` (the record lean, plus the argument keys at their raw values), `change` (from/to per argument the path does not already bind; an argument that contradicts the path is refused by the verdict with execute's own sentence, armed or not, never read as a no-op (two lenses; the 0.44 `proximo_api_plan` door inherits that verdict too, where it used to answer allowed and let execute refuse); compared as strings: the vendor answers 2048 and the operator sends "2048"; lens: `vmid` had read as a change on every config plan, and a store's own name echoed by its record had made a garbage collection a no-op) and `noop`, claimed only where a state was compared: a start on a running guest, a stop or shutdown on a stopped one, arguments the record already holds; an action with no arguments is never a no-op (lens: a PBS garbage collection and a subscription refresh had read as nothing-will-happen, the unsafe direction for a small model). A delete shows the record and a 404 says it does not exist; a create is not a diff, it says whether an identity the vendor enforces (an id, a storage; a name is a display name) and it COMPARED is already there, and says when it compared none (lens: a snapshot's `snapname` against rows keyed `name` had read as "does not exist"); a PUT or DELETE whose read is a collection says so and claims nothing (lens: `DELETE /pools` had read as a create); a twin that is itself attacker-authored (a mail in the postfix queue, a guest's description fields) carries `untrusted` and its channel on `current`, and fenced it is not diffed at all; a twin that needs an argument the path cannot give is named, not read; a record over the door's cap says the change cannot be shown; where the vendor publishes no read, or the box holds no credential, or the path is a template, `current` says why, so it is never silently empty (a site on 0.44 reported a plan whose `current` was `{}`); a credential the floor refuses says the floor's words with the file path taken out, quoted or bare, in the plan's answer and in execute's refusal alike, since both answer any caller over any face. A plan still writes no receipt of its own and still answers the verdict on a bare box; the invariant that moved, deliberately, is that a plan on a configured box now makes one governed GET with its own receipt (`tests/test_spine.py`, two assertions; `tests/test_api_door.py`, one: the 0.44 server's `proximo_api_plan` is thin over the core's plan and inherits the read, and its docstring, which the read had falsified, is the one line of the 0.44 server this changes). The blast engine's prose is not carried: the tier's authored sentence is the blast radius with authority. PDM publishes no `/current`, so its remote actions get the honest sentence. Door 1,155 to 1,178 tokens, the 4K gate holds. `tests/test_plan_live_state.py`, 35 tests; nineteen controls planted and watched red: the read dropped, noop never, the `/current` rule dropped, the bare-box check removed, a loose compare, the gate leg dropped, noop on empty arguments, a collection read as a create, the untrusted label dropped, an unaskable twin read anyway, the path's keys diffed again, exists claimed without a compare, the file path kept in the floor's words, the plan's conflict check dropped, a row that lacks the key read as "None", the quoted path kept, the refusal's path kept, the conflict check gated on allowed, the conflict verdict masking a tunnel's.

**A task-backed call reports finished, not submitted.** Parity row B4, the one a small model needs most: a migrate, backup, clone, snapshot or start that the vendor ACCEPTS answers with a task id (a UPID), and the core handed that id back and stopped, while 0.44 had `pve_task_wait` and `pve_task_status`. One helper, `spine.task_wait`, carries 0.44's contract whole (a failed or timed-out task is a result, never an exception; `succeeded` is fail-closed on `exitstatus == OK`), and the engine polls the plane's own task-status address through the client it already built, every two seconds, up to `wait` seconds (`proximo_call`, `--wait`; default 60, max 600, 0 submits only). The answer carries `task`: upid, finished, succeeded, status, exitstatus, timed_out, polls, seconds. On the ledger any answer that says UPID closes the executing row as `submitted`, never `ok` (PROVE must not say ok for an outcome nobody has seen; a process that dies mid-wait leaves an honest `submitted`, with the id on it, and no task row; an id that is not the shape lands on the row scrubbed and bounded, never raw), and one `core.task` row closes the wait as finished, failed, timed_out or error with the poll count, the seconds and the last status seen; `in_flight` knows that row, like the UNDO capture before an executing row, closes nothing (each had popped a twin's open executing). A poll that fails is receipted with the vendor's status and the answer still carries the id (losing it to an exception is what makes a caller fire the work twice). The poll is the mutation's own read-back, like UNDO's: through the client already built, not governed again. A task's exit text is scrubbed of locators and bounded in the receipt and in the answer alike. The node comes from the UPID, read from where `UPID:` starts, because a token-started task ends `root@pam!proximo:` and a split on the `!` read every such task as no task (lens); PBS's `\\x3a`/`\\x2f` escapes in a worker id are admitted; a PDM remote's task is polled at the remote's own address, the remote taken from the path the operator was allowed, never from the id's prefix. The id is vendor bytes going back into a path: one that is not a UPID shape (a slash, a percent) is handed back unpolled and says so. `proximo_read` takes the same `wait` on a `.../tasks/{upid}/status` address, 0.44's wait on a UPID already in hand, and refuses it anywhere else. The door costs 1,037 to 1,155 tokens and the 4K gate holds. `tests/test_core_task_wait.py`, 34 tests, each mechanism planted back and watched red: the answer closed as ok, the remote form dropped, the exit text raw on the ledger, a slash admitted into the id, the clamp gone, the split on `!` again, the wait's receipt closing a twin, a failed poll raising through, the answer's exit text raw, a malformed id closed ok, an unshaped id raw on the row, the undo capture closing a twin, the last status dropped. The 0.44 tools are untouched.

**A failed call's row keeps the vendor's status.** Reported by a site running 0.44: the row said `HTTPStatusError` and nothing else, so a 403 (a missing privilege), a 404 (no such guest) and a 500 (the vendor broke) read the same, while the caller had already been told the status. One function, `spine.wire_error`, now builds the error key of every ledger row that names one (17 rows: the core's wire, UNDO read-back and refusal rows, the rate and envelope refusals, the reach-grant write, the reach mirror's privilege read, the PDM auto-undo, and the 0.44 server's seven), so no row records less than the one beside it. A test walks the package for a row built as a literal any other way (the PDM auto-undo row was, lens 1); a row built by a helper and handed over under a name is past that test's sight, and lens 2 found one, the reach mirror's 403 on the privilege read, which now has a driven test of its own. The number only: the exception's message carries the request URL and stays out, and the tests now raise the message httpx writes, URL and all, because a bare "no" could not tell (lens). A failure the vendor never answered carries no status; a response that will not say, or a status that is not an int (a bool is not; an IntEnum is), leaves the type alone. Each door's tests went red with the status taken back out, and eight more controls after the lenses: the PDM row put back, the mirror row put back, the message leaked, the bool admitted, the IntEnum dropped, the enum kept as an enum, the raising response uncaught, the server merge dropping the mirror's dict.

**`proximo_find` answers in plain words.** Parity row B10, the one a small model cannot work without: matching every word against the path found the right address first 38% of the time on 0.44's own tool names and answered 2% of 0.44's own docstring sentences at all. `proximo.core.search` now lets a verb pick the method (`list` GET, `create` POST, `update` PUT, `delete` DELETE), scores the other words by where they land (a path segment, the vendor's own description of the operation, a parameter name), folds plurals, and drops a parenthetical. The descriptions are vendored beside the API trees (`apidoc/*.desc.json`, written by `scripts/api_coverage.py fetch`) and rank without shipping in the answer. Synonyms are a record, `vocab.toml`, each line quoting the vendor's own use of the word (a guest is qemu or lxc). A nonsense query returns nothing, and on the bundle a question several planes answer says which. hit@5 on 0.44's 449 thin wrappers, per plane and bundle: tool names 50/46 to 94/90, docstring sentences 2/2 to 86/84, and 82/81 on a held-out half no tuning read. `tests/test_search.py` gates it, and runs the old rule through the same gate as the control. `proximo_plan` given words acts on a single match, so it asks more: the method filters and is never a word, and every word must be a segment of the path itself (lens: the literal "post" was a word to find and a parameter name was proof enough, so "POST create subscription keys" planned `/auto-install/prepared`). Over the whole table, an address planned by its own words lands on itself or on a choice, never on another address; a test sweeps all 1,799, and the lens's bug planted back reds it. Found building it: the stemmer folded `nodes` to `nod`, so "node" matched no `/nodes/` segment; six mechanisms planted back, each watched red.

**Nine grants 0.44 had and the core refused.** Parity rows L1-L3: PBS prune and verify jobs (create, update, delete, run) and PMG `regextest` were in the table with no tier, so the door refused operations 0.44 performed. Each line carries the 0.44 plan's own sentence and risk: job config restorable, a prune RUN destructive (it deletes snapshots per retention, permanently), a verify run restorable, `regextest` read-back (a POST that reads). Grant pin 152 to 161. Row B18 checked by planting: deleting an address line lets the family grant reopen the call under a coarser tier (LXC start went restorable to destructive), and the exact grant pin goes red on it.

**PMG arms by its own pair, in credential mode.** Parity row B12: the core refused every PMG mutation, because PMG's login took the username from env and only the password from a file, and a swap that cannot change the user is not an arm. `PROXIMO_PMG_CREDENTIAL_PATH` (registry: `credential_path`) is a file of two lines, `user@realm` then the password; the login reads the user from the same bytes the arm compares, so the swap changes who logs in, and PMG reads `PROXIMO_PMG_ARM_SOURCE` / `_READONLY_SOURCE` (or a target's pair) like PBS and PDM. Password mode keeps its refusal, which now names the way out; both modes set at once is refused. A malformed credential file refuses by shape, never content. `tests/test_plane_arm.py` +13; three controls went red (PMG always refused, the user from config instead of the file, PMG never reading a pair). The 0.44 `pmg_*` tools still log in by password mode. Lens (sonnet, 1 BLOCKING, a class older than PMG): `execute` built the client AFTER the spending gates, so any config error found while building it (both PMG modes set; on every plane, a secret file group or other can read) consumed the operator's one-shot consent grant and a rate slot and left no receipt. The client is built before anything is spent now, and a build that fails is a receipted refusal (`needs: config`), its text scrubbed of locators and registered secrets like every other exception on the ledger; building reads env and stats the file, never the secret. A read spends nothing, so it still marks taint first and a box with both faults reports `taint` (second lens). The env box's arm view also refuses the both-modes conflict, so a plan never reads armed for a box `execute` cannot build. A UTF-8 BOM is stripped from the user line. Each fold watched red.

**The door withholds every credential 0.44 withheld.** Parity rows L8 and L9. Seven lines in `secrets.toml` (61 to 68): PMG `/config/admin` (`http_proxy` userinfo), PBS `/config/s3` and `/{id}` (`secret-key`), PBS `/config/tape-encryption-keys` and `/{fingerprint}` (key material), PBS `/config/datastore/{name}` (the UNDO capture), and a new `bearer` shape for PMG `/quarantine/link`: the link IS the answer, so both doors serve it whole and label it `bearer_credential`, and every receipt fingerprints it whole. The guard had missed them by shape (it knew `_strip_*` and one `_redact_` name): it now sees `_redact_*` calls, inline comprehension drops and masks, and a helper doing either, and 0.44's 37 stripping reads are pinned from the v0.44.0 source (`tests/fixtures/strips-0.44.json`), because a strip whose backend the cut deleted left the scan's sight (8 did). Two lens rounds broke it (the ledger ignored `bearer`; cloudinit's mask lived in a helper), both folded; every mechanism was planted back and watched red.

**Each plane its own arm; PVE's never arms the rest.** Found wiring the planes' pairs, and the reason this entry exists: the shell door and the MCP door pass no config for the env box, and `govern` asked `arm_state(None)`, which grades PVE's pair, for EVERY row. With PVE armed, a tiered PBS, PMG or PDM mutation through either door read as armed. The registry path had been hardened against one box's arm authorizing another (lens 4, 2026-09-23); the env path had not. Now a row with no config asks its own plane's env view (`wire.env_arm_view`: env names only, no secret read, never raises), and PBS and PDM have their own pair on the env box, `PROXIMO_PBS_ARM_SOURCE` / `_READONLY_SOURCE` and `PROXIMO_PDM_…`: their token file carries its identity, so a swap really changes who asks. PMG has none (since: a PMG box on a credential rather than a password login pairs like the others, above), and the refusal says why: its login takes the username from env and only the password from a file, so a swap cannot switch a read-only user for a write one. For every plane, PVE included, an arm source and a read-only source holding the same secret are refused (only the same PATH was before: two files, one secret read as armed forever; this box's live PVE pair was checked and holds two). A PBS or PDM box with no pair is refused naming its own variables. `tests/test_plane_arm.py`, 11; four controls went red (PVE-only pairs, no one-secret check, no PMG reason, the `cfg=None` grading put back). `packaging/proximo.env.example` and `docs/SETUP.md` name the variables. Lens (sonnet, 2 BLOCKING, folded, each planted back and watched red): the env-box match (token file + base URL, lens 4) never checked the product, so a PBS Plane at PVE's URL with PVE's token file inherited PVE's arm and a disruptive PBS mutation governed allowed; only a PVE box (or the 0.44 config, which has no product and is the PVE box) can be the env box now. And a registry PMG target with an `arm_source` read as armed while this entry said PMG stays refused; PMG is refused on every path now, the registry's included (`packaging/targets.example.toml` says so); since, that holds for the password login only, and a credential-mode PMG arms. Checked on this box: no PBS, PMG or PDM env plane is configured for either live Proximo server, so the `cfg=None` hole was not reachable here.

**Over the cap, whole; since, from disk.** Step 5, the smaller one (John, 2026-09-27: "would this matter if we could just make sure all calls fit"). The 4K door already makes every call fit; two things fitting cannot give. (1) A default list read over the cap used to come back cut, a fitting answer with most of the estate missing (16 of 37 rows). Now it answers whole and smaller: `total`, a `tally` per state field (a field of names or flags with at most 5 values, a row lacking it counted as `(absent)`), and the `minority`, the rows not in their type's most common state, with their ids; `minority_total`, and a minority too big for the cap is itself cut with `minority_returned`. Rows asked for by name (`fields=`) keep the row cut, and so does a list with no state to count (a log's lines are the answer). Live, cluster resources at a 1 KB cap: 37 rows in 348 tokens, the minority the 6 stopped lab containers and 3 storages on a different backend. (2) "What changed since yesterday" is not a call; the vendor keeps no yesterday. Every list read the engine serves now leaves a snapshot (`proximo.core.store`: lean rows after the credential withhold, one directory per plane + box + path + arguments, `latest` plus the first snapshot of each UTC day for 8 days, 0700/0600, written by a per-process temp and a rename), and `proximo_read(since="24h")` / `proximo-core ... --since 24h` answers `added`, `gone` and `changed` with their counts from disk, no vendor call, receipted `core.recall`, stamped with both snapshots' times and says so when it cannot reach back as far as asked. Proven live with the token path pointed at nothing (a live read exits 3; since answers, 115 tokens). An untrusted address is kept, and answering from it marks the session and fences the rows exactly as the read does: cluster resources is itself in the taint record. Found live and fixed: PVE hands a comma list back in any order (storage `content`), which read as three changes between two reads seconds apart; the same set is not a change. The box is in the key, so a registry target behind the same ledger is never diffed against the env box. `PROXIMO_STORE=off` keeps nothing; `PROXIMO_STORE_DIR` moves it. The door grows 986 → 1,036 tokens. Tests: `tests/test_store.py`, 14; seven planted controls each went red. Deliberate test edits: the syslog cap test now uses distinct lines (a log has no state, so it is still cut), the fetchmail withhold test asserts the summary and the cut both withhold, the 4K row-cut test names `fields="all"`, and the pinned read schema gains `since`. Not proven: that a 3B model answers "what changed" right; that needs a model window, not yet run. Lens (sonnet, 4 BLOCKING, folded, each planted back and watched red): the summary itself was unbounded (150 five-valued fields made 9 KB against a 2 KB cap), so a summary that does not fit falls back to the row cut and the minority gets only the room the tally leaves; a log with a `level` field summarized and erased every line, so a list whose rows carry their own content (a field on every row, unique on most, not an id) keeps the cut (`tags` on cluster resources is on guests only and does not trip it); a corrupt snapshot crashed `since=` with a traceback, so an unreadable day file is skipped and an unreadable latest is a receipted refusal; a symlink planted at the (computable) key path was written through, so every store directory must be a real directory the process owns and is made 0700, else the snapshot is skipped and the read still served. Live after the fold: cluster resources at a 1 KB cap 1,040 bytes, minority 4 of 9 returned with its count; the node's 50 tasks answer as 49 OK and the one that failed. Named, not proven either way: a clock stepped backwards can give a day file a later `ts` than `latest`.

**The core door on the network; rows say who asked.** `proximo-core-mcp-http` serves the six core tools over MCP Streamable HTTP, so Proximo can run on a host the agent cannot reach into: the agent holds an endpoint and a bearer, and the Proxmox token, the arm pair, the consent grants and the rest of the file-backed pillars stay behind the door, where they are walls rather than speed bumps. It is not a second perimeter: `proximo.mcphttp.build_app` takes the MCP instance to serve (`instance=`), and the core door hands it `build_server()`, so the Host guard, the cross-origin guard, the bearer and the caller badge are the bytes every network face mounts. Same `PROXIMO_MCP_HTTP_*` env and port (41243) as the 0.44 face, a public bind with no token never starts, an unknown argument refuses, and building the app never loads the 0.44 server (tested in a fresh interpreter). Session rows land through the core's one ledger opener, `session_end` in a `finally` (tested with a crashing server). And the core's rows now carry the principal the 0.44 rows always did: the name tag (`PROXIMO_PRINCIPAL`) or the badge a network face verified, stamped at `engine._record`, absent when neither is configured so those rows are byte-identical to before. Before this, one box's ledger said who asked on the 0.44 tools and not on the door. The name-tag half of `proximo.principal` moved to `proximo.core.principal` (stdlib only, inside the core's closure) and the old module re-exports it: one process global and one context variable, never two. Tests: `tests/test_core_mcp_http.py`; three planted mutants (the 0.44 server imported unconditionally, the `finally` dropped, the stamp removed) each went red. Lens (sonnet): the badge's identity does reach the row (`via: verified`) through the SDK's task, driven with a real badge; BLOCKING, folded: with `PROXIMO_CALLER_KEYS_DIR` set the shared camera wrote `caller_arrived` through the 0.44 server's ledger, so the first protected request loaded `proximo.server`; `guard_middleware` now takes the face's recorder (`record=`), the core door passes its own, and a test serves a real badge in a fresh interpreter (red with the old recorder planted back).

**A systemd stop keeps its departure row, on every face.** uvicorn 0.49 catches SIGTERM, shuts down, then re-raises it under the handler that was installed before it ran; under the default handler that killed the process before the face's `finally`, so every `systemctl stop` of `proximo-mcp-http`, `proximo-http` or `proximo-a2a` wrote `session_start` and never `session_end`, and exited by signal. The crash tests raised an exception, not a signal, and stayed green. `webguard.serve` is now the one way a face runs uvicorn: it installs a SIGTERM handler that exits 0, so the `finally` runs, and puts the previous handler back. Found driving the core door live; pinned by a test that starts each face's console script, sends it a real SIGTERM, and requires exit 0 with both session rows (all four went red with the handler removed).

**The 4K door.** Built so a local model in a 4,000-token window can drive the whole estate. The cost is measured; the drive is not yet proven, because no small model has driven the core door end to end (that proof waits on a model window). Measured on the real cluster through the shell door (2026-09-27): the door's six tools cost 907 tokens and one estate read, cluster resources, 37 rows, cost 4,299, because the core served the vendor's raw rows where the 0.44 wrappers projected them. Four rules at the one seam, no wrapper: (1) a list read comes back LEAN with a `total`: a row keeps its names, states and ids (strings, bools, nulls, any `*id` key) and drops its counters; `fields="all"` is the vendor's rows untouched, `fields="a,b"` is exactly those in that order, and a name no row carries is refused with the names that exist; a row that would keep nothing stays whole (projection fails open, only the cap fails closed); the count is taken from the raw rows before projection. (2) `PROXIMO_RAW_MAX_BYTES` defaults to 6 KB, one answer's share of a 4K window, and a list over the cap is cut by rows with `total` and `returned` beside the rows that fit, never a byte head, so the count survives the cut; a dict over the cap is reported by size with a head as before. `bounded` is one copy for both doors, so the 0.44 raw GET door (`proximo_api_get`) reads the same 6 KB default and cuts a list by rows too; set `PROXIMO_RAW_MAX_BYTES` to keep the old 256 KB. (3) `proximo_find` ranks a plane you named first, a read before a mutation, then the shortest published address, and hands back 5 by default. (4) `proximo_plan` takes words: a `path` with no leading slash is a query, one match is planned, several come back to pick from, none is find's refusal, and the words never reach the spelling gate as a path. The order inside the envelope is withhold, then project, then bound. `tests/test_four_k_door.py` measures the bar in the unit the sentence uses, with a values-free shape fixture of the real 37-row read and the control that must fail (the same rows raw are over the cap): door 986 + plan 101 + one projected estate read 1,216 = 2,303 tokens, under 2,500 with 1,500 left for the model (re-measured after the lens fold's description text). Live, the same cluster question: 4,299 raw, 1,216 lean, 372 with `fields="name,status"`. Lens (sonnet, 4 blocking, folded the same night): projection is row by row, so one non-record in a list no longer switches lean off for the rest; a blank `fields` is refused, `all` is recognised however it is spelled, and a list of non-records refuses `fields` outright; the shell door takes `--fields`; `proximo_find`'s first cut ranked on path length alone and "pbs datastore" put a disruptive PMG mutation first; the shipped ranking above is the fold. `proximo_plan` refuses a blank query and its no-match refusal says a path starts with a slash. Named and left: a mutation's echoed body is not leaned (the cap gap there predates this); PVE encodes booleans as 0/1 (measured on `/cluster/resources`), so `template` and `shared` fall with the counters there; PBS and PDM were not checked; the CLI prints indented JSON, ~38% larger than the compact wire the gate measures.

**Family grain: 87 sentences.** On John's ruling (2026-09-26, "family grain, go with 87"), `tiers.toml` gains a `[tier.family]` table: one line per family the proof measured, a tier and a sentence each, 87 lines. A family line opens every ungated mutating address in its family that has no address line; the address lines stay and address beats family. The loader already refuses a family that matches nothing, a tier outside the vocabulary and a blank sentence, so the test is one pin. `engine.table()` now stamps a family tier only on what a line may open: a read, a gated call or a tunnel in a tiered family used to print the family's tier.

**One engine, every address, every pillar.**
The engine, the vendor's governance table (every address the four products publish, 1,799 of them, with 5,786 typed parameters), the audit ledger, the arm predicate, one wire client for four planes, the shell door and the MCP door live in `src/proximo/core` (import `proximo.core`). Its import closure is `httpx` and nothing else, measured by a test that compares what the doors load against what `import httpx` alone loads. It is the engine `proximo-proxmox` runs on, not a second product: the distribution an adopter installs stays `proximo-proxmox`, one wheel, one dependency graph (the core was briefly a workspace member, `proximo-core`, and never published). Every old import name in `proximo` is an alias of the moved module. Nothing in the MCP, A2A or HTTP faces changes shape.

**The MCP door over the engine: six tools, every address.** `proximo-core-mcp` serves `proximo_find`, `proximo_plan`, `proximo_read`, `proximo_call`, `audit_entries` and `audit_verify` over the same `resolve`, `govern` and `execute` the shell door uses, with `readOnlyHint` true on five and false on the one that can mutate. The mcp dual-major seam moves into the core (`proximo_core.mcpcompat` then, `proximo.core.mcpcompat` since the fold back), with the unknown-tool pointer injected by each server rather than reached for. Driven over real stdio against the estate: a live read, a mutation plan refused as not armed, the refusal receipted in the same keyed chain.

**The spine runs for every address, not for the wrappers that remembered it.** CONTAIN, SCOPE, LEASE, FORBID, CONSENT, the RATE envelope and UNDO move into the core (`proximo.core.spine`) and run at the engine's one seam, in the 0.44 order, for every mutating address the four products publish. In 0.44 ARM gated three shell tools and the other pillars gated whichever wrapper called them; here ARM and TIER decide first and the pillars follow for all 865 mutating addresses. The pure half (contain, scope, lease, forbid, and a look at the consent grant) runs in `govern`, so `proximo_plan` and `--plan` report every refusal the call would meet, the consent id and the grant file an operator would create, on a box that holds no credential. The spending half (the consent consume, single-use, and the rate reservation) runs in `execute` after the arguments validate, so a typo spends neither; rate runs after consent so a doomed attempt cannot burn the budget the operator's own approved work needs. Each pillar keeps the two invariants it earned under lenses: env unset means inert, and once opted in, anything that prevents proving the gate clear reads as refused. Every gate was deleted in turn and its test watched go red. An existing 0.44 scope file keeps working: the core keys a concrete path to the same `kind/vmid` spelling the contract pins. The 0.44 modules now import their readers from the core, so each predicate has one copy. A ledger-schema note: the core receipts every refusal as action `core.refuse`, outcome `refused`, with the pillar in `detail.needs` (`arm`, `tier`, `contain`, `scope`, `lease`, `forbid`, `consent`, `rate`, `undo`, `arguments`); the 0.44 tools keep their typed `blocked:*` outcomes, so anything keyed on those strings reads the surviving tools and not the door.

**The governed door is on the shipped server.** `proximo` (the server an adopter runs) now serves `proximo_api_find`, `proximo_api_plan` and `proximo_api_call` beside the 0.43 `proximo_api_get`: search the vendor's table, get the verdict with the consent id and the published schema on a box that holds no credential, and run a governed mutation on any published address through the whole spine. Dry-run by default, like every mutation this server serves: `proximo_api_call` without `confirm=True` returns its plan and touches nothing, and the core's own `proximo_call` gained the same gate. Receipts land on the instance ledger the wrappers write, one chain. The door reaches registered remotes the way every wrapper does: `proximo_target` names a PROXIMO_TARGETS entry, resolved for the plane's kind into the Plane the core governs and dials, with the target's own arm pair, forbid list (an addition to the floor) and rate cap (the tightest wins); the receipt carries the target's name as `remote`, and a target with no arm_source of its own is refused by name, never armed by the env box. Its rows carry the principal like every core row (below), and `audit_entries` reads `remote` back on every row that has one. The cap on a registered target is the box's, not the name's: the mount takes the tightest across every registry entry at one base_url (0.44's own rule), so a second alias with no rate fields is not a second budget; and a target `rate_window` of zero or less is garbled, refusing every mutation on that box instead of reading as unset; the env box is one token file AT one base_url, so a registry entry for another host that names the env token file with no arm pair of its own is refused by name instead of riding the env box's arm; and a consent id names the box, so a grant written while reviewing one box's plan does not authorize the same mutation on another (lens 4, two lenses). Lens 5 tightened both: an env that names no base_url cannot claim any box as its own (the host check no longer falls back to the token file when `PROXIMO_API_BASE_URL` is unset), and the box in a consent id is the plane's base_url for the env box too, so the env box and its registered alias mint one id and one grant. The secret-name rule covers `totp`, `otp` and plural `-tokens`/`-keys`; a tier record that does not parse refuses every mutation by name instead of a traceback; and the deletion applier cuts a table entry whole when a comment or blank line sits before its name, and hands over to a human what it cannot cut whole. Surviving tool hints that pointed at a deleted wrapper ("revert with X") now name the door and the address. `audit_verify` on the server takes `path=<archive name>` too. Three more tools, so the surface was 927 at this point; bucket A below takes it to 788.

**139 thin read wrappers are gone; the door serves their addresses.** Step 3, first cut, on evidence: `scripts/prune_wrappers.py` classifies the live registry by structure and `scripts/prune_apply.py` removes a bucket, its imports and its tests by syntax-tree range, with a rehearsal mode that prints every cut and writes nothing. Bucket A is a READ-ONLY wrapper whose body is one backend call naming exactly one published GET and nothing else but a target string; `proximo_api_get` reaches every one of those addresses, is target-aware, and a read carries no tier judgement. A read the taint model marks by name stays (the door serves it untainted). Two facts for adopters: a deleted wrapper returned the backend's data, the raw door returns its envelope with the data inside and the published path it matched; and the door caps a body at `PROXIMO_RAW_MAX_BYTES` (256 KiB then; 6 KiB by default since, the 4K door) where a wrapper did not. Receipts for those reads now carry `proximo_api_get` as the action with the plane and path as the target. The surface is 788 (from 927). Thin mutations wait: every wrapper is target-aware through the registry and the door is not yet, so a governed mutation on a registered remote would be lost; that door brick comes first. Adopters who pin `PROXIMO_TOOLS_PIN` re-pin on upgrade, as with any surface change.

**125 thin mutation wrappers are gone; the tier table is the record.** Step 3, second cut, on the same evidence, and the door serves their addresses: bucket B is a mutating wrapper whose body is one backend call naming exactly one published address whose blast-radius tier is authored in `tiers.toml`; `proximo_api_call` reaches every one of them, on the env box and on every registered remote, through the whole spine. The surface is 663 (from 788). Three things move with the cut. The generator that wrote `tiers.toml` read those wrappers' plan functions, so it lost its source: it ran once more, reproduced the shipped bytes exactly, and retired; `tiers.toml` is the hand-authored record now, 150 grants, each with its why, pinned to an exact count so a grant added or withdrawn is a decision. The wrappers each kept their own secret key set out of the ledger (a password, an S3 secret key, a proxy URL's userinfo); the engine carries that as one rule at its one seam: a secret-named argument is ledgered as a fingerprint, a URL's userinfo is masked to its host, the read-back captured for UNDO gets the same scrub, and an argument refusal names the parameter with a secret-named value as its fingerprint (the reason is the refusal row). The rule is by NAME, so it over-reaches on purpose where a wrapper had judged a field readable (PBS's S3 `access_key`, an identifier by AWS convention, is fingerprinted too, and so are `sshkeys` and `root-ssh-keys`, public material: a guest-config receipt and its UNDO read-back show those as fingerprints; nothing restores from the read-back by code, a human does (since: `undo` restores by code, B2), and the exemption is a one-line follow-up if that reads as a loss). Five homogeneous confirm-sweep files whose whole table was bucket B went with it rather than skip on an empty parameter set. And the applier learned the table shapes the rehearsal could not see (the name line inside a multi-line `pytest.param`, a one-line tuple, a parametrize table in a decorator): the first apply left 100 orphaned tuples in 20 files that the rehearsal had called clean, repaired from the pre-cut tree and pinned by a planted control. For adopters: a deleted wrapper's dry run returned its PLAN, the door's `confirm=False` returns the engine's plan with the tier and its why; the receipt action is `core.execute` with the published address, `remote` names the box; a vendor's null return comes back as the vendor sent it; and `PROXIMO_TOOLS_PIN` re-pins on upgrade.

**The functions the wrappers left behind are gone too.** Buckets A and B deleted wrappers; each one had called a `plan_*` and an op function in a lane module that nothing else called afterwards. `scripts/prune_backends.py` finds them the way a linker would: every reference resolved per file through that file's own definitions and imports (a same-named function elsewhere is not a caller; `from . import x` is), roots at decorated tools, module-level names, `noqa: F401` re-exports, `[project.scripts]`, `scripts/**` and string dispatch, a tokenizer as a second eye that blocks the list on any code reference the tree did not see, and the rule that a dead plan's blast sentence must already be in `tiers.toml` or the function is a hand item, not a cut. `prune_apply.py --backends` removes 396 functions (7,150 lines) from 36 lane modules, three modules whole (`hw_mappings`, `pbs_disks`, `pbs_metrics`) with their emptied `tools/` shells, and the 1,306 test functions that reached them through their own imports; the two tape modules left holding one validator each fold into the planes that use them. Source 93,612 → 84,275 lines; the wheel 1,374,973 → 1,277,530 bytes (under 0.44.0's 1,287,740); the tool surface stays 663. The docstring ripple that bucket B left for later is done: 124 endpoint-table rows and 27 rating bullets for deleted wrappers are gone, and a deleted tool named in model-facing text (98 sites in `docs/TOOLS.md`, `pve_task_status` alone 21 times) now names the door and the address. Still alive only because a live-smoke script imports them: `access.token_revoke`, `pbs_config.traffic_control_get`, `pmg_welcomelist.welcomelist_object_delete`/`welcomelist_objects_list`, `storage_admin.storage_create`/`_check_storage_type`; dead outside the lanes and left for a hand: `a2a/signing.make_verifier`/`verifier_for_jwk`, `access_governance.realms_list`, `arm.release_session_locks`, `config_edit.plan_config_get`, `taint.clear_taint`/`taint_sources`. `test_no_lane_function_is_dead` (tests/test_prune_backends.py) now keeps the tree that way.

**The tier table ships, and every grant carries its reason.** `tiers.toml` is no longer empty: a generator (`scripts/harvest_tiers.py`, retired below with the wrappers it read) wrote it from the wrappers' own written blast-radius judgements, read from the syntax tree, 150 addresses (pbs 81, pve 53, pmg 16; destructive 38, disruptive 79, restorable 33), one operation per line, each as `{ tier, why }` where `why` is every blast-radius sentence the plan constructs, whole and in order, with the tool and label it came from; the engine carries it into `proximo_plan`, `proximo_find` and `--plan`. A line without a `why` is refused at load. Refused on purpose: any plan that constructs more than one Plan (two judgements on one address, whatever labels they wear) and any blast text the tree cannot read whole (a variable, a call, a conditional), because a grant carrying a fragment is a lie to the only human who reads it. A lens found the first cut of this file with 90 truncated sentences and one grant whose sentence described the branch that refuses while the other branch deletes a role; a test now regenerates the file in memory and requires the shipped bytes to match. The tests that guarded the proposal now guard the shipped file: every key is a live mutating address, no family lines (at that step; the family lines followed), no plan that constructs two Plans, and a sentence that says permanent means destructive. The RISK-to-tier mapping (high to destructive, medium to disruptive, low to restorable, with the sentence winning over the label) is stated in the file's header as ratified. Severity does not gate: presence is the whole permission, as before. Every other mutating address, the guest lifecycle included, stays refused even when armed until its wrapper's judgement can be joined to one address (since: the family lines in `tiers.toml` tier them, the guest lifecycle included).

**UNDO by construction, said in every receipt.** Before a mutation the engine reads back what the vendor publishes about the same address, receipts it (bounded at 64 KiB, larger read-backs as size and hash) as a `core.undo_point` row, and the result says `undo: {captured, read}`. Where the vendor publishes no read of that address the receipt says so; where it publishes one and the read fails, the mutation does not run. `PROXIMO_UNDO=off` opts out and the receipt carries that too. No reverse call is invented: the tier is the human's judgement on recoverability, the receipt is the evidence.

**A mutation is on the chain before the wire is touched.** The core used to receipt only after the call, so a process killed between the request and the receipt left nothing. Now an `executing` row carrying the whole preview (arguments after coercion, tier, consent id, the undo capture, an intent id) is written before the wire and closed by the terminal row; a stranded one is what `in_flight` reports. Proven with a control that dies on the mutation and leaves the row open.

**One chain, both doors, and the writer looks at what it extends.** The shell door's receipt used to be written with a bare `AuditLedger(path)`, unkeyed, while the MCP door opens the ledger keyed by default; on the estate that appended 25 unkeyed rows to a chain keyed since June, and the next keyed start sealed all 8,599 rows into an archive as if none had been keyed. Both doors now open the ledger through `open_ledger`. And `AuditLedger.record` refuses, under its append lock, a writer whose algorithm disagrees with the chain's last row, naming `open_ledger` as the door that migrates a chain instead of corrupting it; the bare constructor still reads and still appends where it agrees. `detect_mode` reads the whole file and reports `mixed`; the custody row a rotation writes says `prev_alg: mixed` and the seam line instead of a false `sha256`. `audit_verify(path=<archive name>)` walks a sealed archive row by row under the algorithm each row carries and reports the segments, so an archive is provable and not only intact: the estate's real archive verifies as 8,574 keyed rows then 25 unkeyed, head equal to the custody row's.

**The core's `--plan` printed nothing.** `published_parameters` was a read-only mapping view and `json.dumps` refused it, so the plan crashed. Found by the standalone-install test on its first run, never by the suite, because nothing had driven `main --plan` and parsed its output. Fixed and pinned.

**Query booleans are 1/0 on every plane.** The four curated backends disagreed with each other (pve's raw door sent `True`, pbs `1`, pmg and pdm `true`); the core sends the vendor's own form. A parity test puts the old backends and the new client behind one mock transport and asserts the bytes agree wherever the old backends agreed with each other.

**Taint keys on addresses; the door is the taint-tracked path.** The 0.44 taint model classified BY TOOL NAME the reads whose response carries guest- or externally-authored bytes, so the governed door served `GET /nodes/{node}/syslog` untainted while the wrapper for it was the only tracked path. `src/proximo/core/taint.toml` is the record now: 89 addresses (pmg 34, pve 29, pbs 21, pdm 5), generated once by `scripts/harvest_taint.py` from the name set joined to the addresses those tools reach, then read line by line (a wave comment that argued about the wiki had landed on the pdm rows; a tool's `(ADVERSARIAL): get x` label is not an argument; a `{}` that fit ten rows is two hand lines; the gated guest-agent family stays out because the engine refuses it before any pillar; since, the agent lane is opt-in and its 15 lines are in). Every row carries `untrusted` and `channel`, `proximo_api_plan` and the envelope report them, and the engine marks the SAME sticky file the wrappers mark, before the wire on both branches (a raising wire still taints), refuses with a receipt when the marker cannot be written, fences the data under `PROXIMO_TAINT_FENCE`, and runs the two couplings in `govern` in the 0.44 order: `PROXIMO_TAINT_FORBID` after FORBID (a wall after an untrusted read, no consent escape) and `PROXIMO_TAINT_REQUIRE_CONSENT` before CONSENT (refused outright with no grant dir). The marker, its switches and the fence live in `proximo.core.spine` once; the 0.44 module imports them. The ceph plan factories' embedded CAPTURE now names the address it reads, so the mark outlives the wrapper whose name it carried. HONEST LIMIT: the record is total over what the 0.44 wrappers classified, not over every read the door publishes; an address no wrapper ever served is unclassified and served as before, untainted.

**25 taint-marked thin reads are gone; the door serves them, marked.** The carve-out that kept an adversarial one-hop read out of bucket A now asks the record: an address in `taint.toml` is a read the door marks, so the wrapper is thin like any other (a control proves a record line for another address frees nothing). Surface 663 → 638; the 25 names leave `taint.ADVERSARIAL_TOOLS` with the comment blocks that argued only for them (the sentences are in the record), 78 names remain. The applier learned one more shape from its rehearsal: a test class whose every method named a deleted tool was left as a bare header, an IndentationError the rehearsal reported as a crash; an emptied class goes whole now, with a planted control. The docstring ripple ran in two passes (model-facing text names the door and the address; internal prose the bare address) and a hand pass caught what a substitution made false: "in `taint.ADVERSARIAL_TOOLS` instead" after an address that is in the record. `pve_guest_config_get` stays: its one address is a `{kind}` shorthand for two rows and the generator proves one. The 15 lane functions the 25 left behind (142 lines; `pbs_s3.py` whole with its `tools/` shell) went the way the backends cut went: `scripts/prune_backends.py` names them, `prune_apply --backends` cuts them with the 53 tests that reached them through their imports. The catalog rows re-measured: one domain ~9,466 (27 tools), two domains ~13,591, the pve catalog ~71,080, the full surface ~218,227. Source 84,275 → 83,553 lines; wheel 1,277,530 → 1,269,366 bytes. A lens (sonnet) over the four commits found no blocking case and four non-blocking, each folded: `api_coverage.owner_literals` dropped a literal whose query tail carried a PEP8 space (`?file={quote(file, safe='/')}`), so the guest-agent file read joined to no address (inert only because that row is gated; the path part decides now, planted); two apt-changelog docstrings the ripple had left as fragments; the no-tool-clears-taint guard never scanned `core/doors/` (a planted dead import passed it; it scans them now and the plant goes red); and SECURITY.md said `proximo_api_*` classifies by address when `proximo_api_get`, the raw GET door, taints by its own name on every read.

**Neither door hands the model a credential a curated read withheld.** The curated reads strip credentials before the model sees them (a PBS remote's password, a PMG fetchmail pass and LDAP bind password, an ACME plugin's DNS-provider keys, an SDN lock token); the raw GET door (`proximo_api_get`, shipped in 0.43 and live in 0.44.0) and the governed door served the same addresses with every field the vendor sent, which broke the raw door's own second law ("it never launders a gate"). `src/proximo/core/secrets.toml` names 61 addresses (68 since) and their credential fields, built from every read a backend still strips plus every GET whose vendor return schema declares a credential, read field by field (`tokenid`, `public_key` and a config key's NAME are not credentials; ACME plugin `data` is one though its name says nothing). Both doors withhold those fields at any depth, mask a proxy URL's `user:pass@` to its host, and say what they withheld in `withheld`. Two shapes a field name cannot reach have their own rules: PVE's pending and cloud-init reads carry the guest's cloud-init password as a `{key: "cipassword", value: ...}` row (the row's value is withheld), and the rendered cloud-init user-data carries it as a `password:` line in a text body (the line is masked). A mutation's own response goes through its read's line, because PBS's update of an OpenID realm echoes the config with its `client-key`. The record fails closed: absent, unparseable, a line with no field or no why, or a line for an address the door does not serve refuses the table by name. The ledger reads the same record: a mutation's arguments and its UNDO read-back fingerprint those fields, where the name rule alone had passed an ACME plugin's `data` raw on both halves (and `audit_entries` serves the ledger to the model). `tests/test_secret_record.py` holds the record to both of its sources, each with a planted control: every backend that strips a read (the paths read from the code), and every credential-shaped field the vendor's return schemas declare (`scripts/secret_returns.py` writes them to `tests/fixtures/vendor-secret-returns.json`; each is a line or a named exclusion with its reason). The adversarial lens found the second source had been done by hand and missed a PDM node-status's subscription keys and an answer file's subscription key, plus the row, text and mutation-echo shapes above; all folded, thirteen planted mutations went red and were restored by hash. Also fixed on the way: the ledger's URL-userinfo mask split at the FIRST `@`, so `http://user:p@ss@host` leaked `ss`; it splits at the last now, the rule `pbs_admin`'s proxy mask already kept.

**24 more thin reads are gone; the generator had been counting setup as work.** Bucket C held 68 reads the generator called "N statements beyond the read call". Read one by one, most of the extra statements were `n = node or cfg.node` or a conditional target string: setup that names the call, not work around it. Three generator rules were wrong and are fixed with a planted control each: a call-free assign is setup; `wait_for_task` composes (`pve_task_wait` is a poll, not a read); and the mask rule, which knew `redact|mask`, now knows the `_strip_*` credential family. That last one matters most. Two of the 68 (the PMG subscription key, PMG's PBS-remote password) had been kept out of bucket A only by the statement count, and the fix to the count would have freed them had the mask rule not been fixed first. With the rules right, 24 reads were bucket A (23 of the 68, plus `pve_node_disk_smart`, which the owner-literal fold had already freed), each read before it went: PBS job lists, group notes, protected flag, remote group scan and permissions; PDM permissions; eight PMG node reads; six PVE SDN node-status reads and SMART. The door serves every address; the seven taint-marked ones (group notes, remote scan, the two postfix queue reads, the PMG report, SDN ip-vrf and mac-vrf) are in `taint.toml`, so the door marks them, and their names leave the 0.44 set (78 → 71). The 23 lane functions only they called went too, with 44 tests. Surface 638 → 614 (pin, README, SETUP, the brand images renamed by content hash, `PROXIMO_SURFACES=pve,exec` 199 → 192, `=pve` 195 → 188); the pve catalog token row 71,080 → 69,647 and the full surface 218,227 → 212,868, measured with the pin's own measure. Source 83,661 → 82,949 lines. The rest of the 68 stay, for stated reasons: an output bound (the journal's default `lastentries`, a `cap_newest`), a lean projection and task-outcome windowing, a memory feed (`pve_cluster_resources`, `pve_list_guests`), a credential strip, two reads in one, or a name the generator cannot join to one address yet (24 fell to E: import aliases and names shared across planes).

**The governed door caps a read's size, like the raw door.** The raw GET door has always reported a body over `PROXIMO_RAW_MAX_BYTES` (256 KiB by default then; 6 KiB since) as truncated, with its size and a 2 KiB head, instead of handing it back; the governed door (`proximo_read`, the engine) had no cap at all. The wrappers bounded output with their defaults (`limit=100` on PVE's syslog, 50 on PMG's task log), and the door serves the vendor's defaults, some of which the vendor never declares. One `rawdoor.bounded()` now serves both doors; the head is cut from the body after the secret record has withheld its fields, so a truncated read cannot leak what a whole one would not. Two planted mutations (no cap; cap before withhold) went red.

**The generator joins a call through the tool's own imports, and one literal is no longer one read.** `prune_wrappers` joined a called function to its address by NAME, so an alias (`apt_changelog as pmg_apt_changelog_op`) joined nothing and a name several modules define (`dns_get`, `task_status`) joined too many: 149 tools sat in bucket E behind the name alone (130 of them thin reads). It resolves the name through the tool file's `from proximo... import` block now, to one function in one file, and reads THAT body for a mask (under an alias the mask check had looked up nothing, and would have freed PMG's PBS-remote list with its password). A second rule came with it: a backend is thin only when it is validators, a params dict and one `_get` it returns; a loop, a decode, a second read or a computed answer keeps the wrapper (nine did: the base64 catalog decodes, the per-type notification loop, PMG's computed statistics among them). Both rules planted both ways.

**117 more thin reads are gone; the generator reads the call it joins.** The two generator rules above (a call resolved through the tool's own imports; a backend that is validators, a params dict and one returned `_get`) were what bucket E had been waiting for: 117 reads it had filed behind an alias or a shared name proved to be one published GET each, and `prune_apply --bucket A` cut them with their tests; `prune_backends` then named the 66 lane functions (666 lines across 12 modules) only they had called, and `--backends` cut those with the 184 tests that reached them through their imports. The door serves every address; the 27 names that leave `taint.ADVERSARIAL_TOOLS` (71 → 44) are addresses `taint.toml` already marks, and the comment blocks that argued only for them go with them. Surface 614 → 497 (the pin, README, SETUP, the brand images renamed by content hash, `PROXIMO_SURFACES=pve,exec` 192 → 182, `=pve` 188 → 178); the pve catalog token row 69,647 → 67,524 and the full surface 212,868 → 189,661, measured with the pin's own measure (one and two domains did not move). The per-tool average budget moves 1,400 → 1,550 B for the reason bucket A moved it: the 117 that left averaged 806 B, so the mean of what remains is 1,526 B; 59 survivors grew 7 to 81 bytes each (1,525 B in all) where a description now names the door and an address instead of a deleted tool, and every other survivor is byte-identical. Source 82,989 → 80,199 lines. Three shapes the applier's rehearsal cannot see, each read back by hand: a test that names a deleted tool only as its VICTIM (the escape hatch, the lean-wiring projection, the PDM path shapes, the diagnose prompt) is not a test of that tool and stays, re-aimed at a survivor or at the address; a plane-roster test that asserts its own count (`test_pmg_tools_registered_with_fastmcp`, 113 names) went whole because every row it held named a deleted tool, and is back at 79; and a parametrize table the cut empties runs nothing, silently (the PMG routing reads: table and function removed together). Where two tools on two planes became one address, six comments had read it twice; they and seven bare mentions the substitution walked past (a doctor hint, three tool docstrings, three lane notes) now say the door and the address once. Still naming deleted tools: the live-smoke scripts, 18 of them (16 from the earlier buckets, `pve_cluster_status` and `pve_tfa_list` from this one); they are a hand item, as the lane functions they keep alive already were. Three tests moved with the count, one of them a finding: the manifest-load floor in `test_lexical` (500 → 100; the pin owns the size), a door test that imported `tests.` (bare `pytest`, the CI form, has `tests/` on `sys.path` and not the root), and the 8k-window guard, which had compared BYTES to a token-sized threshold and so stayed green while SETUP.md said dynamic mode is "the only mode that fits an ~8k context": measured in the unit the sentence is about, four domain toolsets already sat under 4k tokens before this cut and six do now, so the sentence names them and the test holds it to the measurement both ways.

**The first two hand grants, and the core runs its own lab.** `tiers.toml` carries its first lines written by a person rather than harvested: `POST /nodes/{node}/lxc/{vmid}/status/start` and `.../shutdown`, both restorable, each with its why (150 → 152, the exact pin moves on purpose). Walked the same night on real hardware through the shell door alone: the estate's PVE live and the three lab planes (PBS 4.2, PMG 9.1, PDM 1.1), the core planning the start with the grant's own sentence, starting three containers, reading every plane, shutting them down, 24 keyed receipts on one chain, every mutation with its `executing` row before the wire and its tier on the terminal row. Before the grants the same walk had to borrow the shipped server to start the lab: the core said "an unjudged mutation is refused even when armed", which is the wall the record is for. Also seen on the walk: a plane configured from the environment other than PVE carries no arm pair, so its mutations refuse with `needs=arm` by construction (then; since, PBS and PDM read their own pairs and a credential-mode PMG arms); and a `--plan` writes no receipt, only an attempted execution does.

**The proof: the core does what the wrappers do, measured per tool.** `tests/test_prove_core.py` drives every one of the 497 remaining tools with synthesized arguments under the shape suite's fakes, recovers every backend call it makes as an address, and resolves it in the core's table: five claims, each with a control that must fail. Reach, static: every source literal the coverage scanner can read resolves or sits under a gated prefix. Reach, dynamic: zero calls fail to resolve; the exceptions are named, not hidden (three wrappers send a CIDR as two path segments where the vendor publishes one, so the door needs the encoded form; one PBS mutation the vendor exposes on GET, which the core would read as a read; five gated by design; three that fakes cannot drive, with their address from the static claim). Bytes: 599 distinct request shapes, old backend and core behind one mock transport, identical except six that differ only in a query boolean the core spells the vendor's way (compared per parameter, exactly). Governance: 101 reads resolve and carry no tier by nature; 25 mutations carry a tier on every address they reach; 336 wrappers perform a mutation on at least one address with no sentence, 361 addresses in 87 families, staged by family with the wrappers' own risk labels for a hand to write the why (since written: the gap is zero) (`scripts/prove_core.py OUT_DIR` writes the report and the proposed record outside the tree; two wrappers that judged one address differently are written AMBIGUOUS, never averaged, as the record's header requires; a no-op under the fixture proposes nothing). A lens over the harness moved three of those numbers: it found the drive never varied `scope`, so the cluster- and node-wide firewall addresses had no row; that a wrapper's last address stood for all of them, which hid the two hand grants behind an untiered sibling; and that reads and tiered mutations had been counted as one. Every mutating address a wrapper reaches is its own row now. Behaviour: the 23 non-REST tools named one by one; the audit pair and the four door tools are the core already, the DIAGNOSE composers are reads the door serves, memory and wiki are separate features, and the shell door (`ct_exec`, `ct_logs`, `ct_psql`, `ct_diagnose`, `pve_node_logs`) was the one capability the core did not have, said here above the fold; the shell lanes (above) now serve the first four, and `pve_node_logs` maps to the vendor's own `GET /nodes/{node}/journal` with `unit`, a governed read (how it differs: the node shell paragraph above). The proof's shape is pinned; each number moves on purpose as sentences land, and the wrappers go whole when the record holds theirs.

## [0.44.2] — 2026-10-10

**A restored guest gets its own MAC address.**
The plan now says what network identity a restore will wear. Reported as issue #82 by an adopter on PVE 9.2.2: `pve_restore` of a QEMU backup to a new VMID produced a copy with the original's MAC address and SMBIOS UUID, and the plan said only that a new guest would be created. The QEMU branch sent PVE `{vmid, archive}` and nothing else, on a docstring that called `storage` an LXC-only parameter. PVE's own API takes `unique` ("Assign a unique random ethernet address") and `storage` ("Default storage") on the create-from-archive call for both guest kinds, which the reporter confirmed by direct API call.

`restore_guest` now sends `storage` for both kinds and asks for `unique=1` by default. The one exception is a `force` overwrite of the same VMID the archive came from, which keeps the archive's MAC, because that is what a restore in place means; a `force` restore of one guest's archive onto another VMID gets a fresh MAC, since the source may still be running. `unique` is a tool parameter now and an explicit value wins either way. `storage` is a behaviour change for QEMU: the old call sent none, so PVE put the disks back on the storages named in the archive; now they land on the `storage` you pass, and the plan's change line and blast radius say so. When the VMID exists and `force` is not set, PVE rejects the restore and the plan carries no identity note. The plan carries a `note` naming the network identity the restored guest will wear: a new MAC with everything inside the disks copied as-is (hostname, `/etc/machine-id`, which systemd-networkd derives its DHCP client id from, keys), with the reporter's own recipe for a test restore beside a running original (`link_down=1` on the NIC, read it through the guest agent); or, with `unique=false`, the same MAC and the warning that two machines with one identity share the bridge. What `unique` does is read from the vendor's own source, not guessed: qemu-server 9.2.11's `restore_update_config_line` gives every `netN` a new random MAC and `smbios1` a new UUID when `unique` is set, and regenerates `vmgenid` on every restore; without `unique` the MAC and the SMBIOS UUID come out of the archive as they went in. The plan note says MAC and SMBIOS UUID for QEMU and MAC alone for LXC, and hedges both the identity and the storage line with "if the restore proceeds" when the existence read failed. The in-place rule reads the archive's source VMID from both shapes PVE restores from, a vzdump file archive by its basename and a PBS snapshot by its `vm/<vmid>/` or `ct/<vmid>/` path, anchored so a decoy in the storage id or an earlier directory cannot name the wrong guest; an archive whose name carries no VMID is never in place, so it fails toward a fresh MAC.

**Proved live, not only read.** On a standalone PVE 9.2 lab node, through this library: a disk-less VM backed up with vzdump and restored twice. The default restore came back with a new MAC and a new SMBIOS UUID; the `unique=false` restore came back wearing the archive's MAC and UUID, which is the shape the issue reported; `vmgenid` was new on both. The proof found a second defect: PVE answers a status or config read for a VMID with no config on that node with HTTP 500 and the message "Configuration file 'nodes/<node>/<qemu-server|lxc>/<vmid>.conf' does not exist", never with a 404 (read live, both kinds, both endpoints). The restore, delete, template-convert and migrate plans confirmed absence only on a 404, so on a real PVE they had never once confirmed a guest absent and called every new-VMID restore "could not verify". That file is per node, so the 500 alone means "not on this node": in a cluster a guest alive on node B answers the same through node A. `backends.guest_absent` now confirms absence only when the message names this guest's own config file and `/cluster/resources?type=vm` lists no guest with that VMID; a 404 stays absent; a roster that cannot be read, a roster that lists the VMID, or any other error stays unknown and hedged. Eight more 404-only existence reads for users, realms, pools and ACLs are untouched: different endpoints, not probed live.

Twenty-four new tests in `tests/test_backup.py` and three in `tests/test_server_plan.py`: the QEMU body carries `storage`; both kinds carry `unique=1` for a new VMID, omit it on an in-place `force` overwrite, and carry it again on a `force` restore across VMIDs; an explicit `unique` wins on both kinds; the plan note names the identity in both shapes, names the SMBIOS UUID for QEMU only, and is absent when PVE will reject the restore; the plan names the storage; the tool threads `unique` to both the plan and the API call; PVE's 500 "does not exist" answer with an empty cluster roster reads as confirmed absence, the same 500 with the VMID alive on another node stays unknown (a force restore onto it is not "creates new"), another 500 or an unreadable roster stays unknown and hedged, and the delete, template-convert and migrate plans confirm absence on the live shape too. The confirm-sweep fixture learned the new `unique` key. Four adversarial lens rounds on this release found the `force` default wrong across VMIDs, the `storage` change undisclosed, the in-place rule blind to PBS snapshot volids, and the first cut of the absence rule blind to a guest alive on another cluster node; all four are folded here.

## [0.44.1] — 2026-10-03

**Our pinned PyJWT and urllib3 clear sixteen advisories.**
Sixteen advisories published on 2026-09-29 and 2026-09-30, and raised on this repository on 2026-10-02, cover two packages Proximo's own artifacts pin: thirteen against PyJWT (one critical, five high) and three against urllib3 (two high). The lock, both hash-pinned `requirements/*.txt` exports, the container image and the SBOM move from `pyjwt==2.13.0` to `2.15.0` and from `urllib3==2.7.0` to `2.8.0`. No other package moved. The wheel and sdist hashes match PyPI's own listing for both releases, and `pip-audit` reports the sixteen on the old pins and nothing on the new ones.

PyJWT reaches Proximo two ways: through `mcp`, and through the optional A2A face's card signing (`a2a/signing.py`). The signing path accepts ES256 only, which already refused the HMAC key-confusion class several of these advisories describe, but the parser-level ones (a deeply nested header raising `RecursionError` before any key is consulted) sit in front of that allowlist, so an A2A card from an untrusted peer could reach them. `tests/test_a2a_signing.py` signs and verifies with the real library, no mocks, and passes on 2.15.0. urllib3 is not in the runtime install at all: it reaches the dev export only, through `requests`.

Nothing an adopter pinned changes. Neither package is named in `pyproject.toml`, so a fresh `pip install` already resolved the current releases. The pins that were stale were ours: the lock, and the image built from it.

**The image build actions move to their current releases.**
`docker/setup-buildx-action` 4.4.1, `docker/setup-qemu-action` 4.4.0 and `docker/build-push-action` 7.4.0, each pinned by commit sha with the exact version in the comment. `build-push-action` had been commented `# v7`, a moving major that hid which release the sha was; it now names one. All three shas were dereferenced against the upstream tags before this shipped.

## [0.44.0] — 2026-09-21

**No tool leaks an exception's raw text any more.**
A runtime leak found by an adversarial lens closed one site and named the class: `f"{type(e).__name__}: {e}"` reached the model from thirteen sites across eleven modules, and httpx builds its message from the request URL, so a failed call could carry the estate's internal host and port out to the caller. `redact()` cannot catch that: it hides registered literals and auth shapes, not addresses, and the string does not exist until the call fails, so no source audit finds it either. All thirteen now go through `safe_exception_text` in `_secretfile.py`, and `tests/test_no_raw_exception_text.py` scans `src/` so the shape cannot come back, with a planted control proving the matcher sees what it forbids and does not accuse the safe type-name-only form.

**Our own artifacts run the newest mcp.**
The lock, both hash-pinned `requirements/*.txt` exports, the container image and the SBOM move from `mcp==1.28.1` to `mcp==2.2.0`. `[tool.uv] constraint-dependencies` held them at 1.x from the dual-support port in 0.39.0, described there as waiting on "its own later deliberate act"; this is that act. The hold was load-bearing right up to the previous release: until 0.43.0, mcp 2.x sanitized every exception that was not its own `ToolError` into `Error executing tool <name>`, so a 2.x client read every Proximo refusal as a bare tool name. Shipping a 2.x image before that fix would have shipped a governance layer whose refusals said nothing.

**The published floor does not move, and one CI leg is now the only thing keeping that honest.**
`mcp>=1.24,<3` still admits 1.x, so nothing an adopter pinned stops resolving. The dual-major matrix is inverted to match reality: leg 2 runs the lock's own hash-pinned 2.x, and leg 1 overrides down to `mcp>=1.24,<2` unpinned. The override is always whichever major the lock is not. That leg is now the only proof behind the 1.x half of the published range, and the workflow says so: if it is ever dropped, the 1.x claim comes out of `pyproject.toml` in the same commit. Proven both ways before this shipped, on the newest of each major: 12,482 passed / 12 skipped on mcp 2.2.0, and 12,478 / 16 on mcp 1.30.0, which is newer than the 1.28.1 the lock had been pinning.

**What the dependency surface actually gained.**
Five packages enter the installed set (`httpcore2`, `httpx2`, `mcp-types`, `opentelemetry-api`, `truststore`) and two leave (`pydantic-settings`, `python-dotenv`). A sixth, `httpx2-jsfetch`, appears in the lock but carries `sys_platform == 'emscripten'`, so it never installs on any platform Proximo runs on. `pip-audit` is clean on both the runtime and dev exports at these pins. Re-pin `PROXIMO_TOOLS_PIN` after upgrading if you use it.

## [0.43.0] — 2026-09-20

**Every published read on every plane, by path.**
`proximo_api_get(plane, path, params)` is the raw GET door: the floor under the curated tools. The path is matched against the vendored API trees (`proximo/apidoc/`, one file per product, dated) with GET as the only method BEFORE the wire is touched; write-only paths, console and migration tunnels and unknown paths are refused with the nearest published reads named. Reads a curated tool already gates (the qemu-agent family behind `PROXIMO_ENABLE_AGENT`, the byte streams the file-restore tools land on disk) are refused with that tool named, so the door never launders a gate. The result is the vendor's `data` in a labelled envelope (`derived: false`, the published path it matched); a body over `PROXIMO_RAW_MAX_BYTES` (256 KiB) comes back labelled truncated with its size, never as a silent prefix. Its own toolset (`raw`), reachable in every mode by name through `proximo_read`, audited under its own name, adversarial in the taint model by construction. 913 tools at this point; the identity core below takes it to 924.

**PDM has an identity core of its own now.**
Eleven `pdm_*` tools for users, API tokens, ACL and effective permissions: the first native PDM mutations (`pdm_user_create/update/delete`, `pdm_token_create/update/delete`, `pdm_acl_update`), PLAN by default and confirm-gated like every other write, plus `pdm_user_get`, `pdm_user_tokens_list`, `pdm_user_token_get` and `pdm_permissions_get`. PDM's access API is PBS's (the same proxmox-access crate), so the PBS helpers drive it through a PdmBackend that gained a JSON `PUT`; the plane name on actions and PLAN targets follows the backend. A user's password and a token's secret never reach the ledger. Live-proven against PDM 1.1.4 in the lab: user create, update (clearing properties rides as the JSON array PDM wants), token create with the secret handed back once, ACL grant and revoke, effective permissions, delete. One fact the proof surfaced now sits in the PLAN text and the tool descriptions on both planes: a token's privileges are its own grants bounded by its owning user's on the same path (the shared access crate does `privs &= owner_privs`), so a token granted Auditor alone resolves to nothing until the user holds it too. The proof also read twelve PBS/PDM PLAN strings ending in a stray `f` (an f-string prefix inside the closing quote, from the plane refactor); fixed, with a text-level test on every access-plan string for both planes. 924 tools.

**Secrets cannot leave through an error.**
Every secret Proximo reads by path (the PVE, PBS and PDM tokens, the PMG password, the web and anchor bearers, the audit key, the arm token) is registered with an output scrubber at read time, and every error text that leaves through the MCP wire is passed through it: a ProximoError scrubs its own message at construction, the tool boundary scrubs the message of anything else a tool body raised (in place, type and cause chain kept), and the wire handler on both SDK majors scrubs what is left, including the argument-validation echo the SDK produces before a tool body ever runs. The PMG session ticket and the A2A and badge signing keys are registered too. The four auth-header shapes Proximo sends scrub even when the value was never registered. Values under eight characters are not registered, so a short secret cannot shred every message it occurs in. Until now HTTP errors were cut to a status line and the error class carried no secrets by design, but a subprocess error with an argv password or an echoed request header had no scrubber in front of the model.

**The tool surface has a checksum you can pin.**
`proximo tools-checksum` prints the sha256 of what this config serves, every tool's name, description and input schema after scoping and the door choice, and the count; the server prints the same line at every start. `PROXIMO_TOOLS_PIN` refuses to start on a mismatch and names both hashes. The sum is per config and per version, and the docs say so.

**A refusal keeps its reason on the mcp 2.x SDK.**
On mcp 2.x every exception that is not the SDK's own `ToolError` is sanitized to `Error executing tool <name>`, so a client on that SDK read every Proximo refusal (an expired arm lease, a missing consent, a scope block, the did-you-mean pointer for an unknown tool, the read door's `proximo_read refuses …`) as a bare tool name. The 1.x SDK had always passed the text through, and the one test on the wrap asserted only the `Error executing tool` prefix, so the 2.x CI leg stayed green. The compat server now translates exactly one class, `ProximoError` (the caller-safe channel, never a secret), back into a `ToolError` that carries the reason with the cause chain intact; every other exception keeps the SDK's own contract, pinned by a control. Read back on the dogfood server (mcp 2.2.0) that showed the bare line.

**The coverage receipt is generated, not typed.**
`scripts/api_coverage.py` measures how much of the four API trees the curated tools reach (71% of 1,721 operations touched; PDM 23%). A tool module that imports another plane's helpers credits its plane with exactly those defs. Controls both ways in `tests/test_api_coverage.py`.

**The same surface cost more on Python 3.12 than on 3.13.**
Tool descriptions originate in `fn.__doc__`, and CPython 3.13 strips each docstring's common leading whitespace at compile time while 3.12 does not. Nothing normalized it, so the identical 924-tool surface served 1,202,345 B of `tools/list` on 3.12 against 1,185,831 B on 3.13: a 16,514 B difference that is entirely source indentation, billed to every 3.12 client on every connection. `door.dedent_description` now runs for every registered tool inside the same single pass that already strips schema titles and collapses nullable unions, so both interpreters serve 1,185,057 B. A 3.12 client stops paying 17,288 bytes of leading spaces, and a 3.13 client saves the 774 B of trailing whitespace the compiler's dedent leaves behind. The budget test that caught this was green on the development box and red in CI for exactly this reason, which is the finding worth keeping: a payload budget measured on one interpreter says nothing about what the other serves. Three guards land with it, including a mechanism test whose input is built as a string so that no compiler can pre-dedent it, and the registry-wide check states in its own docstring that it is interpreter-sensitive in magnitude rather than implying it is not.

**Two anyio advisories closed in the image.**
`anyio` 4.13.0 to 4.15.1 (CVE-2026-63374 and CVE-2026-64847; the fix arrived in 4.14.2). Wheel installs resolve their own `anyio`; the container image carries the pinned export, so it needed this release to move.

## [0.42.0] — 2026-09-17

**One file out of a backup, without restoring the guest.**
Four tools, two planes, one landing spot. `pve_file_restore_list` / `pve_file_restore_download` walk a guest's PBS-backed backup through PVE's file-restore API (the same sighted grant, `proxmox-backup-file-restore` on the node for VM images); `pbs_catalog_list` / `pbs_file_download` walk any snapshot's catalog directly on the backup server, host backups included. The wire grammar was walked in the lab before the module existed: base64 paths, no length header on downloads, zip or tar.zst for a directory. The download is a governed mutation: the PLAN names source, remote path, destination and cap and pre-reads the entry's size; `confirm=True` streams the bytes into a fresh private subdirectory under `PROXIMO_RESTORE_DIR`, capped by `PROXIMO_RESTORE_MAX_BYTES` from the length header when present and while streaming when not, removing the partial on any refusal. The result carries path, byte count and sha256, never the bytes. Tool count 908 → 912.

**A blind token's empty backup listing is refused.**
PVE hides backup volumes from a storage's content listing unless the token holds `Datastore.AllocateSpace` on the storage and `VM.Backup` on the owner guest (or `Datastore.Allocate` on the storage). The default read-only token from the setup guide holds neither, so `pve_backup_list` answered `[]` on a storage full of archives, and `pve_restore` had no volid to take. The freshness fence has said so since 0.19; the plain listing now does too: an empty result from a provably blind token raises with the exact grant to make (a narrow `ProximoBackupSight` role on the storage and the guests, to the token and its user). A non-empty listing never triggers the permissions read, and an unreadable permission map proves nothing and still returns `[]`. The PBS plane gets the same fence: a token holding only `Datastore.Backup` (the role PBS's own ACL example gives a backup client) is shown its own groups alone, so `pbs_snapshots_list` and `pbs_groups_list` answered `[]` for every other owner's guest (reproduced in the lab with a Backup-only token against a datastore holding another owner's group); both now refuse in that state and name `DatastoreAudit`. The permission collector behind this (shared with `pve_doctor` and the freshness fence) now follows PVE's own contract: a privilege is held where its key is *defined*, and the value is the propagate flag; a `--propagate 0` grant on a leaf path was previously dropped as if absent, and a grant on an ancestor now reaches the leaf only when it propagates. `docs/SETUP.md` gains "Seeing backups, and restoring one", which also names what stays outside Proximo: restoring a PBS `host`-type backup as a whole. Whole-guest restore from a PBS-backed storage goes through `pve_restore`, as it has since 0.19.1.

**The internal nightly pins its own fingerprint.**
`live-smoke.yml` (gitea only) failed closed every night from 2026-06-24 because the PVE node's certificate fingerprint lived in a repo variable nobody set. The pin now ships in the workflow as a default the variable overrides; a rotated certificate fails closed with a mismatch, which is the correct red. The workflow's PBS precheck also stops calling an unreachable test box "down" when the runner simply has no route to it.

## [0.41.1] — 2026-09-13

**The security patch layer only ran on a digest bump.**
The Dockerfile has applied Debian's security patches at build time since `cb4674e` (2026-07-12), so that a newly-disclosed base CVE with a released fix would clear on the next build rather than wait for a base-image digest bump. Every image build passes `cache-from: type=gha` and that `RUN` line never changes, so BuildKit replayed the layer. It did still run, but only ever incidentally: when the pinned digest moved and invalidated everything after it, or when the cache entry aged out. Its last two executions were 2026-08-31 and 2026-09-04, the second forced by the digest bump in `be15230`. Never once because a fix was published.

Read from the published images' own OCI configs: 0.41.0 was built 2026-09-13 and shipped the 2026-09-04 apt layer, byte-identical to 0.40.0's, which is why the two scan identically at 3 CRITICAL and 9 HIGH Debian CVEs across `perl-base`, `libpcre2-8-0`, `libsqlite3-0` and `gzip`. Debian 13.7 published every one of those fixes on 2026-09-12. So the image went out one day behind the archive, and would have stayed behind: the pinned base is already the newest `python:3.13-slim`, so no digest bump is pending to carry them, and the digest bump was the only thing that ever did.

`APT_SECURITY_EPOCH` now carries the run id at all three build sites, so the layer rebuilds every run, and it is declared in the runtime stage because `ARG` scope is per-stage. The added cost is the apt step alone: the hash-pinned pip install downstream already rebuilt every release, since the wheel changes each time. Measured `image` job durations say rebuilding is not the slower path (3m47s for the run that rebuilt the chain, against 4m25s and 4m20s for two that replayed it). `tests/test_dockerfile_pins.py` holds the ARG, its stage, and the build-arg at every call site including a raw `docker build` and a `.yaml` workflow. One seam opens on purpose: the scanned layer and the shipped layer are no longer byte-identical, the release one always being fresher.

The Trivy gate that found this was working correctly throughout. It went red when its database and the Debian archive caught up, not when the defect appeared, which is why a green scan last week said nothing about the image last week.

**Correction to the 0.41.0 note below.**
It said the one contact that came through the removed HELLO door "arrived by email". Nothing supports that, and it should not have shipped. The line now reads that nothing ever came through it.

## [0.41.0] — 2026-09-13

**An LXC on the Proxmox host, one line.**
`packaging/lxc/` carries a container script, an install script and a card in the community-scripts shape, run on their MIT engine pointed at Proximo's own tree: a Debian 13 container with Proximo from PyPI, a minted bearer, `/etc/proximo/proximo.env`, and `proximo-mcp-http.service` bound on 41243 with the container's own address in the Host allowlist, running as a dedicated `proximo` user under a hardened unit with the PROVE ledger at `/var/log/proximo/audit.log`. The same line inside the container updates it through the engine's release check. The script turns the engine's telemetry off: no prompt, nothing posted to community-scripts, no status or advisory lookups. The engine is pinned to a commit, and the script refuses to run if that engine stops defining what it overrides. Not listed by community-scripts; the files are in their shape. README and SETUP carry the line.

**Create plans disclose the bridge, and the doctor probes it.**
`pve_create_container` with a `netN` option now names the bridge(s) and the `SDN.Use` requirement PVE 8+ checks apart from `VM.Allocate`; the clone plan has said this since June, the create plan never looked at its own net options. `pve_doctor` gained two rows, `SDN.Use` on the bridge and `Datastore.AllocateSpace` on the storage, so a token that can create guests is no longer reported able when the create would answer 403. Found live: a create through the operator token, refused on `/sdn/zones/localnetwork/vmbr0`. Tool-description examples moved from Debian 12 to Debian 13.

**Removed: the HELLO front door.**
`proximo hello`, `src/proximo/hello.py` and the anonymous feedback page at
`john-broadway.github.io/hello/` are gone, and `AGENTS.md` is rewritten flat — every
operational fact kept (the sharp edges, the verification steps, the no-telemetry
statement), the greeting and the invitation removed. Nothing ever came through it.
CHANGELOG entries from 0.19.0 and earlier still name that URL and the contact address:
they are the historical record, and the page stops resolving once it comes down. Outside
that history, neither is carried in the shipped docs any more. `proximo hello` now exits 2
as an unrecognised verb, like any other.

## [0.40.0] — 2026-09-05

**Doctor says where near-root exec lands.**
`ct_exec` and the node shell do not travel over the API. They ride `ssh <target> pct exec`, or run
`pct` on the box Proximo runs on, so the machine the API reads and the machine a near-root command
lands on can differ, and until now nothing said so. `proximo doctor` now reports `exec_lands_on`
whenever a shell feature is on, resolves the ssh target through ssh's own config, counts every name
and address this machine goes by as one host, and flags SPLIT TARGET when the two are not the same
machine, naming both and a remedy an operator can follow as written. The check was found by
live-proving against the lab and cut four times, twice after it fired on our own deployment; the
detail is below. Also in this release: the shadow-key flag compares every set-valued key the way
its gate reads it, so a reordered allowlist or a differently cased toolset is no longer reported as
a change while a mode keyword stays a single token, and the TLS warning counts a pinned fingerprint
as verification. 908 tools, unchanged. No breaking change.

**An allowlist shadow compares grants, not bytes.**
0.39.1 taught the loader to name every file key the process environment shadows with a differing
value. Dogfooded on our own box within an hour of that ship, it flagged `PROXIMO_CT_ALLOWLIST`
when both stores held the SAME 22 CTIDs, differing only in the position of one id. The compare was
`os.environ[key] != val`, raw bytes, so a reordered list of identical ids read as a changed value.
An operator following that remedy diffs the two lines, finds the same containers, and has nothing
to fix: a flag true in its bytes and misleading in its substance. 0.39.1's own stated intent is
that a same-value shadow stays silent, and by the semantics of the value it should have.
Now: `parse_allowlist` is the one allowlist parser, `effective_grant` reduces a parsed allowlist
the way the gate reads it, and `values_differ` compares through both. The allowlists
(`PROXIMO_CT_ALLOWLIST`, `PROXIMO_AGENT_ALLOWLIST`) compare as grants: order, spacing and
repetition carry no meaning, and `*` alongside explicit ids is the same grant as a bare `*`,
because `ct_permitted` and `agent_permitted` both short-circuit on `*`. Only a change of
membership is reported. That ruling drew the line at the allowlists; the same day's residual,
closed 2026-09-05 on "fix as you find, own as you go", moves it to every key whose gate builds a
set: `PROXIMO_TOOLS`, `PROXIMO_TOOLSETS` and `PROXIMO_SURFACES` (`door.tool_keep` /
`toolset_keep` / `surface_keep`, the last two lowercasing every token, so `PVE.Storage,pve.guests`
is the same registry as `pve.guests,pve.storage`) and every face's `PROXIMO_<face>_ALLOWED_HOSTS`
(`webguard.read_face_env` feeds a membership check). `PROXIMO_SURFACES` was found by sweeping the
class after the first three, not by the ruling: fix one site, sweep its twins. A second lens then
broke the widening itself: `dynamic` alone is the mode keyword `_apply_surfaces` matches
whole-string and STARTS the facade, while `dynamic,dynamic` misses that match, reaches
`toolset_keep` and REFUSES to start; the lowercased-set view called them the same value, i.e. told
an operator debugging a startup crash that the file and the environment agree. A mode keyword
(`dynamic`/`catalog`/`all` for toolsets, `all` for surfaces) is now a distinguished single token,
never a set, and the keyword sets are pinned to `door`'s own constants. Every other key keeps string semantics, deliberately: a path or a node
name that differs by one byte IS a different value, commas included (`/a,/b` is not `/b,/a`).
Precedence is untouched and the process environment still wins.
The comparison is pinned to the gate rather than asserted to match it: a parametrized test runs
the real `ct_permitted` and `agent_permitted` over a probe set for nine value pairs, on both
lanes, and requires `values_differ` to answer exactly when the two grants enforce differently.
That test is what caught the `*` case, which the first cut of this fix got wrong.
`reach_audit._current_allowlist` had its own private re-split of `PROXIMO_CT_ALLOWLIST`. It was
byte-equivalent to `parse_allowlist`, which is luck rather than a design, and it now routes
through it. The drift guard that pins `SET_VALUED_KEYS` against the source's own reads was blind
to `os.getenv`, to subscripting, to single quotes and to every module except `config.py`; it now
scans every module under `src/proximo` for any of those spellings, and carries a control per
spelling. A guard that sees one spelling in one file is a coincidence, not a control.
Proven by the incident's own shape, by controls that must fail (an id added, `*` against an
explicit list, a scalar key whose commas are reordered, a toolset added, `*` against one host),
and by planted mutants. Each widened key is pinned against its gate's own function
(`door.tool_keep`, `door.toolset_keep`, `webguard.read_face_env`) over value pairs, the way the
allowlists are pinned against `ct_permitted`, never against a second copy of the split; the drift
guard now runs both ways (a set-valued read the source makes must be in `SET_VALUED_KEYS`, and a
name there nothing reads is a dead entry) and derives the faces from the `read_face_env` call sites.
Measured on the loader's and config's test files: restoring the byte compare fails 24 tests,
dropping the toolset lowercasing fails 4, dropping the faces fails 4; blinding either branch of
`values_differ` is caught by the controls above plus the pre-existing shadow tests; planting an
allowlist read in another module in the blind spelling fails the drift guard.
**Live-proving against the lab found two things mocks cannot reach.**
The live tier had not passed since 2026-06-24, 47 releases ago, so the read/plan smokes were run
by hand against a real PVE 9.2.2 in the lab with a read-only token and a pinned fingerprint. Four
of five passed; the fifth skipped because the lab holds no resource pool. The run itself then
produced two defects, both of the same family: a claim the code makes about itself that is not
true when a second real target is involved.
`PROXIMO_VERIFY_TLS=false` with a fingerprint warned that "the backend will refuse to start
(fail-closed)", and then the backend started and read the node. The guard was
`not verify_tls and not ca_bundle` and never counted the fingerprint, while `ApiBackend` returns
on the fingerprint branch BEFORE the fail-closed check. A pinned fingerprint is the option the
refusal message itself recommends first for a self-signed PVE, so this warned an operator away
from the safe configuration. `PbsBackend` had the guard right on both of its sites; only the PVE
path was wrong. Now it counts all three ways of verifying the channel and names the fingerprint
first, and the control still fires for the genuinely unverified case.
**SPLIT TARGET, the more serious one.** `doctor` truthfully reported `api_base_url` pointing at
the lab, `node` at `pve-test1`, `ssh_target` at `pve` and twenty-two PRODUCTION CTIDs, all in one
config. `ct_exec` does not travel over the API: `ExecBackend` runs `ssh <ssh_target> pct exec`
scoped by the CT allowlist, so the two halves described different deployments. The documented lab
pattern sets a lab base URL, token, pin and audit log by script env and says nothing about
`PROXIMO_SSH_TARGET` or the allowlist, so both fell back to the shared prod file. A session that
believed it was in the lab and called `ct_exec` would have landed in a production container.
**The first cut of this check was aimed at the wrong subject and a lens caught it.** It compared
which config STORE fed the api url and the allowlist, and never read `PROXIMO_SSH_TARGET` at all,
so it went silent whenever one store fed both while ssh_target pointed elsewhere. That includes
the remedy its own message recommended: put the api url and the allowlist in the same store, leave
ssh_target in the file, and exec still lands on production with the flag quiet. It also false-fired
on pure-targets and directly-built configs, where one registry entry feeds one machine, and its
message could name the same store on both sides while asserting they differed. It now compares the
HOSTS. **A second lens (2026-09-05) broke that rebuild in seven places, three of them surviving
mutants.** On-host mode (`ssh_target` empty or `local`) was exempted entirely, though local `pct`
runs on the box Proximo runs on while the API may read another machine; the ssh user and the case
were part of the compare, so `svc@Prod-PVE` against `prod-pve` fired forever and the remedy told the
operator to drop the service account; a hostless API url made the compare impossible and the check
went quiet with exec armed; a deny-all allowlist reported nothing about where exec would land; and
the node shell (`node_probe`/`node_logs` under `enable_node_shell`, no allowlist at all) rides the
same ssh target and sat outside the check. Live-proved the same night against the lab with the
shared prod file feeding exec: the flag fired and named `pve`; the remedy, followed by hostname,
kept it firing because the API is addressed by IP. Now every ssh-riding feature is covered and
named in the flag; the compare strips `user@` and lowercases both sides; on-host mode compares the
API host against this machine's names (loopback and the kernel hostname, no DNS); a hostless API
url says it cannot be checked; `exec_lands_on` is reported whenever any shell feature is on and is
pinned in every shape (deleting it fails ten tests; each of the other five mutants planted alone
fails only the test written for it, three parametrized cases for the on-host pair). Then the
rebuilt check was run from the dogfood venv against this box's own production config and fired:
the API by IP, the ssh target the alias `pve`, and `ssh -G pve` resolving to that very IP. The
"honest limit" had become a permanent flag on the flagship deployment, and the same lens found
`localhost` against `127.0.0.1` firing with a remedy that named an `is_local` sentinel. Third
cut: the ssh target is resolved through ssh's OWN config (`ssh -G -- <target>`: local, no
connection, no DNS, three-second cap, literal host on any failure or no ssh binary), and every
name for this host (loopback, the kernel hostname) counts as one host on both sides; when the
API is this host the remedy says `local`. The remedy is followable literally: an IP is a valid
ssh target. A registry target that omits `ssh_target` inherits the `pve` default and is flagged
unless `pve` resolves to the API host; that is the 09-04 hazard's own shape, reported, not a
false fire. Honest limit, still stated in the flag: DNS is not consulted, so a remote name and
its address still read as different. A fourth cut the next session, the third's sibling: that
this-host set was loopback and the kernel hostname, so Proximo running ON the PVE node with the
API at the node's own LAN address (`https://<node-ip>:8006`), or at the FQDN PVE writes into
`/etc/hosts` beside the short name, fired forever in the on-host branch. Now the set carries every
address bound to an interface, read from procfs (`/proc/net/fib_trie`'s `host LOCAL` leaves and
`/proc/net/if_inet6`; no binary, since the shipped image has no iproute2) and every `/etc/hosts`
name for one of those addresses, and an IP literal compares by address, not spelling (`::1`
against `0:0::1`). Both readers are seams the suite stubs to empty, so the runner's own addresses
never enter a test, and each also runs for real over captured kernel shapes. A fourth lens then
planted `break` for `pass` in both readers' parse handlers and stayed green, because the bad-line
sample was too short to reach the handler; it also found the v6 length guard and the ssh side's
canonicalization each unpinned. Three tests close those, each failing with its mutant re-planted.
The remaining limit is the one the flag states: DNS is not consulted.
`doctor` also carried the same fail-closed TLS claim this entry fixes in `config.py`, forty lines
above the new code, in the file the change edited: a pinned deployment was told its API traffic was
not cert-validated. Fixed, and `fingerprint` now appears in doctor's config block, because a reader
seeing `tls_verify=False` and `ca_bundle=None` could not otherwise tell the channel is wire-pinned.
The PBS, PMG and PDM warning TEXTS omitted the fingerprint as a remedy too (their guards were
already correct); all now name all three ways to verify the channel.
A claim withdrawn: an earlier draft said neither defect was reachable by any of the tests because
nothing mocked runs against two real deployments at once. That is false for the TLS one, which a
plain unit test kills. It did not need a second deployment, only a test nobody had written.

**live-smoke: a run that ran nothing is not a pass.**
`live-smoke` had been red for 65 consecutive nightly runs, last green at run #106, and nobody had
read the log. Two causes, neither a product defect. The six PVE smokes fail because `2ff59b1`
(2026-06-24 22:29Z, about seventeen hours after run #106 went green on `0a496db`, an ancestor of
it) made the backend fail-closed when `PROXIMO_VERIFY_TLS=false` carries no fingerprint and no CA.
That is a fixable misconfiguration and it stays loudly red until `vars.PROXIMO_FINGERPRINT` is set;
the workflow now passes that variable through and documents it. The five PBS smokes fail because
the test PBS lives on the lab bridge, which is off unless someone is testing, and the workflow's
precheck bails when it is unreachable while its own comment says the tier "must SKIP cleanly ...
not red". That bail is a bare `exit 0`, which ends only that STEP, so the smoke step ran the tier
anyway. It now DECLARES the skip by clearing `PROXIMO_PBS_BASE_URL`, which is the mechanism the
workflow's documented contract already described.
The orchestrator side is a class, swept: `BASE_FILES` holds every base var that names a FILE, both
CA bundles and both token paths, and a var that is set while naming no file reports
`(set, but names no file)` instead of reading as a ready tier. The token paths had the identical
defect twenty lines away in the same YAML, where the Materialize step announces a SKIP and then
does not write the token. `isfile` and not `exists`, because httpx takes a cafile only and a
directory of certs raises at connect time.
**The exit code is the part that matters, and the first cut of this got it backwards.**
`cmd_run` ended `return 1 if failed else 0` with `ran` computed and never used, so a night where
the lab is off and every smoke skips exited 0 and CI read GREEN on zero evidence. Making the tier
skip cleanly without touching that would have traded a true red for a false green, which is the
one outcome this workflow's header forbids. An adversarial lens caught it in the commit that
introduced the skip. `_verdict` is now pure and tested: any failure exits 1, `ran == 0` exits 2
with `REFUSED: this run ran nothing`, and a PARTIAL run still passes, because a nightly that
proves the PVE tier while the lab is off is a real pass for what it ran and the skips stay named
in the summary. Verified end to end: the all-skip run that exited 0 now exits 2.
An honest note on the backstop: for PBS a missing CA bundle is evidence the precheck did not
finish, NOT proof the tier cannot connect. `PbsBackend` returns inside `if config.fingerprint:`
before it reads `ca_bundle`, so with a fingerprint pinned the bundle is unused. The declaration in
the workflow is the real mechanism; the file check catches a path that goes missing another way.
Test isolation came with it: the tier check reads env vars naming files, and this box's own
`pbs-ci.env` exports one, so an autouse fixture now clears them and each test sets what it means
to test.

One honest limit, measured and left open on purpose: the false-positive class is closed for the
allowlists, not everywhere. `PROXIMO_TOOLS` and `PROXIMO_TOOLSETS` are set-valued in enforcement
too (`door.tool_keep` and `toolset_keep` build sets, the latter case-insensitively), and
`PROXIMO_*_ALLOWED_HOSTS` is called a "comma-separated Host allowlist" in the product's own help
text. All three still report a reordered value as a differing one. This change was scoped to the
allowlists the permission gates read, and widening it to the tool-scoping and host keys is a
separate call, so the scope-boundary test now records that residual instead of implying those keys
are order-sensitive.

Also fixed, found by this work: the 2026-09-02 incident test asserted that the allowlist values
were absent from ALL of stderr, and stderr legitimately carries the env file's path. Pytest's run
counter reached `pytest-3001`, the path contained "300", and the test failed on the path rather
than on a leak. The assertion now strips the path before looking, and the env file is written under
a directory named `run-300` so the collision is permanent and the flake cannot return as luck.

## [0.39.1] — 2026-09-04

**An allowlist refusal names the store that fed it.**
`ct_exec` and its siblings refused a CTID with "not in PROXIMO_CT_ALLOWLIST, add it there", and
"there" was a variable, not a store. The variable lives in two stores, the MCP client's
`mcpServers.<name>.env` block and `~/.config/proximo/proximo.env`, and the loader fills from the
file only the keys the block has not set, so an operator who edits the file's copy of a key the
block also holds edits a dead line (hit live on 2026-09-02, the refusal repeating verbatim after a
reconnect). Now: the loader prints every file key the process environment shadows with a different
value (keys, never values; a same-value shadow is the documented shell-export flow and stays
silent); the config records where each allowlist came from (`ct_allowlist_source`,
`agent_allowlist_source`, per constructor, a neutral phrase for a directly built config); every
allowlist refusal at the server and backend layers names that source (both launch shapes named:
the client's env block for a stdio server, the unit's `EnvironmentFile` for the daemon), says when
the file's copy is shadowed, and says a restart or reconnect is required because the value is
fixed at launch; and
`proximo doctor` reports the source and flags a shadowed key whose value differs. Off-box safety
kept: the messages name the default file unexpanded or by `PROXIMO_ENV_FILE`, never an expanded
local path. Refusing to start on a disagreement was rejected as a downgrade for inline-config
deployments. The CLI verbs whose stderr is a pinned contract (`badge`, `reach-audit` and the
others the entry point already keeps quiet) no longer get the loader's lines in front of their
own prefix; the server and daemon entries still announce. Proven by the incident's own shape as
a test, by absence controls that pass only when nothing is shadowed, and by two adversarial
rounds. The first round's three surviving mutants (a reset placed after a failed open, an unsorted
flag loop, a diff taken before quote-stripping) each got the test that kills it. The second round
found that `proximo --help` still printed the loader's lines before its usage text (help is quiet
now, and pinned), that the two structural tests guarding the quiet-verb gate accepted any earlier
mention of the gate's name as proof (they now assert the gate is the condition on the call), and
that the mirror-aware `*` warning had no coverage on the registry-target constructor (it has,
with the control).

**The public commit subject carries the reason now.** The body-only fix left four
releases (0.36.1 through 0.39.0) reading as bare `release: vX.Y.Z` in the one place GitHub
shows text beside files, which is the first thing a visitor scans (caught by John on 0.39.0).
The subject becomes `release: vX.Y.Z: <thesis>`, taken from the CHANGELOG entry's opening
bold thesis. This line right here is the kind that carries it. A missing, empty, or
subject-overflowing thesis refuses loudly at release time instead of shipping bare; proven
by a bare-subject mutant that reds five tests, and by this very entry, whose first draft
opened with a bullet and was refused by the gate it documents.

**The base image moves to the tag head, and the reason is the fold law, not a red gate.**
Dependabot PR #59 (2026-08-30) offered python:3.13-slim `7ce4b6d`; on a curated mirror a bump is
folded on canon and the PR closed as superseded once it is published, never merely closed. The
tag had already moved past the offer to `9d2e555` (2026-09-02), so the fold goes there. Measured
with trivy 0.74.0 against the registry (amd64, CRITICAL and HIGH, unfixed ignored): the BASE
digest 0.39.0 pins, `ffb752e`, carries 30 fixable HIGH findings in OS packages (util-linux 2.41-5
across nine binary packages, CVE-2026-53612/53613/53614, DSA-6442-1 of 2026-08-14; openssl 3.5.6
across three, CVE-2026-14456, DSA-6465-1 of 2026-08-25); #59's digest still carries the openssl
one; the tag head carries none of them, only pip's vendored setuptools and msgpack, the class the
runtime stage already uninstalls. None of that reaches the shipped image: the runtime stage runs
`apt-get upgrade` at build time (since 0.21.1), so every built image has carried the fixed packages
regardless of the pinned base, and the public trivy gate, which scans the BUILT image, reported
zero findings on 2026-08-31 and 2026-09-01 for exactly that reason. A first draft of this entry
called the shipped pin "a scheduled red"; it was not, and the draft's error was scanning the base
where the gate scans the build. What the bump buys is a base that needs no build-time upgrade to
be clean, which narrows how much of the image's content depends on Debian's mirror state at build
time rather than on the pin. Both FROM lines move together; all three digests confirmed OCI index
digests over the same eight platforms; the Dockerfile's digest verified byte for byte against the
registry's tag digest by `scripts/base_image_digest_check.py`, whose four verdicts (MATCH,
BEHIND, DISAGREE, UNKNOWN) are each provoked deliberately in `tests/test_base_image_digest_check.py`
with the registry replaced, so the control runs offline; four planted mutants, each letting a bad
pin through, turn that file red. `tests/test_dockerfile_pins.py` now refuses a Dockerfile whose two
stages pin different bases, a partial bump no suite had ever caught.

**The release gates learned what they were looking at.** An adversarial pass on this
release's own machinery, not on the code it ships. The copy gate never inspected the README's
install badge, the first line under "Install & run" and the one place a visitor looks to answer
"what version is this": set to 0.31.0 on the 0.39.1 tree, the gate still answered "copy:
consistent" and the suite stayed green. It is checked now, in the backticks and in the release
tag URL both, and a deleted badge is itself a finding so removal is not the way to silence it.
`public_commit_message.py` matched its opening thesis with a pattern that could not express
"empty": a literal `****` skipped forward and captured an unrelated later bold span, which
shipped as a subject when the runaway happened to stay under the length ceiling. The pattern now
requires a real first character, so that input refuses in the check written for it rather than
being caught sideways by a different one. `release.sh` ran the version test through
`python -m pytest`, the form this repo's own notes call a blind spot because it puts the repo
root on `sys.path` and CI does not; it runs bare now. And because the script's first action
rewrites the version files, its working tree is always dirty by the time the leak audit runs, and
that audit reads git HEAD: it now says so, naming how many uncommitted paths it could not see,
because a clean verdict over the wrong subject is worth less than no verdict.

**The `*` allowlist warning knows when the mirror is on.** The setup doc's own lane for a large
estate is `PROXIMO_CT_ALLOWLIST=*` with the reach mirror, where the served token's ACL map is the
whole boundary for container shell reach. The load-time warning still said "least-privilege
disabled" there, which is false: least-privilege moved to PVE's table. With a reach privilege
named, the warning now says so and names the privilege; with none, or with a set-but-blank
value (a refused misconfiguration the mirror never admits anyone through), the plain allow-all
text stands. The qemu-agent lane's warning is unchanged: PVE path-scopes that lane natively and
the mirror never gates it. Proven by a control per branch.

## [0.39.0] — 2026-08-31

**The junction gets its law.** A Proxmox server is two roots on two planes, the product and
the metal, with no law spanning them. This release closes the span for guest reach: the shell
channel PVE could never scope now obeys the platform's own permission table (the mirror), every
change to reach on either side of the junction lands in the PROVE ledger (the witness, bricks 1
and 3), the privilege choice gets a live evidence packet (`proximo reach-audit`), the host side
opens read-only (the node battery), and the opt-in pillars become a checked posture
(`proximo harden`). The design argument ships as `docs/JUNCTION.md`.

**The host side of the junction: a read-only node shell battery.** Until now Proximo doored
only the *guest* slice of the shell lane (`ct_exec` and friends); the PVE *host* shell — the
residue lane JUNCTION.md names as the reason both lanes must exist (upgrades, cluster
services, recovery) — passed through no door and landed in no ledger. Two new read-only tools
close the read half: `pve_node_logs` (tail one host unit's journal) and `pve_node_diagnose` (the
API-only node health PLUS a fixed shell battery over ssh: failed units, PVE service states,
host journal errors, disk, memory, pveversion, cluster status). The battery is fixed argv by
construction — the same DIAGNOSE law as the container probes, the caller names a key and never
argv, so it cannot express a mutation; `pve_node_logs` takes a `unit` name in the value
position of a fixed `journalctl -u` argv (shlex-quoted, the exact `ct_logs` rigor). What the
API plane genuinely cannot give and this can: per-unit host journal filtering, the non-journal
probes (pveversion, pvecm, service states), and any of it while the API is down. **There is
deliberately NO `node_exec`:** the host's
mutation lane stays undoored until its fail-posture is designed rather than defaulted
(recovery is exactly when the API cannot answer, so a fail-closed node-mutation mirror would
contradict its own purpose). Gated by its OWN opt-in `PROXIMO_ENABLE_NODE_SHELL` (host-journal
breadth is a wider disclosure than one container's, so opting into guest exec must not open
the host battery), and — the mirror extended one altitude up — by the served token holding
the reach privilege at `/nodes/<node>`. One privilege governs the whole shell channel now;
where the operator grants it (a guest path, a pool, the node) is the reach. Tool count
906 → 908.

**The gate that governs everything was itself ungoverned.** The CT/agent allowlists are the reach
grant: the standing perimeter every PLAN, CONSENT and PROVE runs inside, and the perimeter for the
one channel PVE's own ACL model cannot scope (`ssh -> pct exec` answers to no PVE privilege).
Widening that grant is the most consequential mutation in the system — and it was the only one the
PROVE ledger never saw: an env edit could take the reach from 3 guests to `*` between restarts with
no durable trace. Brick 1 of the grant model closes exactly that, before any grouping syntax is
allowed to grow the reach.

- **New `reach_grant` PROVE entries at serve start, on every door.** Each serve entry point
  (stdio, HTTP, A2A, MCP-over-HTTP — beside the same `session_start` seam, guarded by the face
  contract) snapshots the RESOLVED grant across the env lane and every pve target in the registry,
  compares it to a sidecar state file beside the ledger, and records any delta with exactly what
  was added and removed, per lane, per source. An unchanged restart records nothing: the ledger
  stays signal, not heartbeat. The snapshot carries the id lanes AND the switches that decide
  whether the reach is live (`enable_exec`/`enable_agent`, `ssh_target`) — a digest that stays put
  while exec flips on, or while the same CTIDs re-point at a different physical host, would be a
  digest lying about behavior. The entry lands BEFORE the sidecar moves: with the opposite order a
  crash between the two would persist the widened snapshot with no entry and every later start
  would read `unchanged` — the permanent swallow (caught by the adversarial pass, reproduced).
- **Failure honesty over plausibility.** A present-but-unreadable sidecar records
  `state_unreadable`; a MISSING sidecar on a box whose chain already holds `reach_grant` history
  records `state_missing` with the last recorded digest — deletion is the cheaper clobber, and
  neither may pose as a first run. An unwritable state path records `state_write_failed` as a
  second entry (the delta entry, if any, already landed) and keeps serving, loud on every start.
  A missing env triple reports the env lane ABSENT; any OTHER env-config failure reports an
  error — absent, empty and broken are three different facts, and conflating them would fake
  grant-removal entries on transient failures. A registry target that fails to build is recorded
  as an error under its name; a target vanishing from the registry is itself a grant change; and
  targets are namespaced (`target:<name>`) so a target literally named `env` cannot shadow the
  env lane (adversarial pass, reproduced). Monitor the `state_*` outcomes as loudly as
  `changed` — a change landing while the sidecar is missing/unwritable is witnessed by digest
  mismatch and counts, never by a per-lane delta (no readable baseline to diff).
- **Honest limit, stated:** the check runs at serve START. The targets registry file is re-read
  on mtime change while the server runs, so a registry edit changes real exec reach mid-run and
  is only witnessed at the next serve start; reverted before that restart, it leaves no trace
  here. (The env lane has no such window.) Closing it means checking at backend-build time —
  deliberately out of brick 1's scope. Entries are `mutation=False` (the check changes nothing;
  the edit happened outside Proximo), so read them via `action="reach_grant"`, not
  `mutations_only`.
- **`proximo doctor` reads the grant back resolved**: the actual ids, both lanes, the switches,
  plus a `lane_digest` (named distinctly — the ledger's digest covers the whole instance
  snapshot and the two are not comparable). The old `ct_allowlist` summary stays. `--receipt`
  swaps the id lists for counts + digest before rendering — bare CTIDs match no redaction
  pattern, and the roster is exactly the estate shape a receipt promises to remove. The
  `pve_doctor` tool serves the resolved ids to authenticated callers by design: they can already
  enumerate guests, and the operator reading their own perimeter is the feature.
- Vocabulary: this surface names the allowlists what they are — the **reach grant**. Env vars are
  unchanged (`PROXIMO_CT_ALLOWLIST` / `PROXIMO_AGENT_ALLOWLIST`); nothing existing breaks.

**New `proximo harden` — the strong posture made the easy posture.** The pillars that bind the
agent rather than trusting it (CONSENT, CONTAIN, the off-box PROVE anchor, the ARM pattern) are
opt-in by necessity — a pillar Proximo raised for you would be a pillar the agent could lower —
but opt-in security that goes unerected is prose. `proximo harden` reads which stations stand
and prints the exact operator-shell recipe for each empty one (your terminal, never the
agent's; state on ground outside the agent's write reach), each ending in a verify line.
Print-only like `mint`: it creates nothing. Configured stations report *standing*, never
*where* (doctor's disclosure rule). `--check` exits 1 while any core station is empty — cron
teeth that keep "opt-in" from drifting into "forgotten".

**Fixed: an unknown CLI verb no longer falls through to serving.** `proximo <typo>` used to
pass every verb branch and land in the stdio serve path — surfaces applied, banner printed, a
`session_start` ledger entry when the principal feature is on, and the process blocking on the
operator's terminal. Found by the adversarial pass on `harden` itself, whose first-draft verify
line named a nonexistent verb and would have demonstrated the trap verbatim. Unknown verbs now
exit 2 with the usage block; bare `proximo` remains the stdio serve contract.

**New `proximo reach-audit` — the reach-privilege decision packet for the mirror.** The next grant-model
step derives shell reach from the served token's own Proxmox-side permission map, keyed on a
REACH PRIVILEGE the operator chooses — and since PVE has custom roles but no custom
privileges, whatever privilege carries the reach aliases with every existing and future grant of it. This verb prints
that evidence live, per candidate: a SEMANTICS line stating what the privilege actually gates
in stock PVE (the choice has two axes, and aliasing is only one — `VM.Console` gates a console
ATTACH, a login prompt, not execution, so keying the mirror on it would grant more than PVE
means by the grant; an audited privilege outside the swept set gets a check-it-yourself
fallback, never a guessed claim), the roles carrying it (the standing hazard), today's grants
of those roles (`/` flagged), and the served token's derived per-guest reach — asked of PVE
per guest path, because the full permission map returns only ACL-anchored paths (a pool-member
guest has no `/vms/<id>` key there; the explicit per-path query resolves propagation and
deeper-NoAccess revocation server-side). Output names whose map was derived (token id, never
the secret — and the id reader REFUSES a file that does not match the PVE token shape, since
the estate's own PBS/PDM token files use a colon form one flag-slip away, and a splitter
failing open would have printed the whole secret). Compares against the current allowlist as
+added/-removed (audited guests only, said so). Print-only, read-only, and the query-count
header is printed and flushed BEFORE the sweep runs — the first lens round caught it merely
leading the output while temporally following the flood it warned about.

**New: the reach MIRROR's enforcement gate (dormant until configured).** With
`PROXIMO_REACH_PRIVILEGE` set to a privilege name, `ct_exec`/`ct_psql` are permitted only where
the SERVED token holds that privilege — asked of PVE per guest path
(`/access/permissions?path=/vms/<id>`), whose answer resolves propagation and deeper-NoAccess
revocation server-side; the full map cannot answer this (ACL-anchored paths only, probed
live). One GET per check, PVE's own resolution, zero reimplementation: the shell channel now
obeys the same map the API channel always obeyed. Semantics by design: INTERSECTION with the
allowlist (checked first — the mirror only narrows; a mirror-driven estate sets the allowlist
to `*`); FAIL-CLOSED on an unanswerable map (`blocked:mirror_unavailable` — the break-glass
for an API outage is unsetting the reach privilege, itself a witnessed reach-grant change, since the
privilege joins the grant snapshot); dormant-unset means zero behavior change. The served
token's map governs, so disarmed = no reach privilege = no shell reach: the mirror composes with the
arm for free. Choose the privilege from `proximo reach-audit`'s evidence — a custom role
carrying one privilege decouples AI reach from human role grants (the privilege still
aliases via built-in roles carrying it). The second lens round extended the
gate to the read-only shell siblings `ct_logs`/`ct_diagnose` (reach is reach — journald from
an unmarked guest is disclosure at allowlist breadth; they stay ARM-free per the diagnose
ruling, authority and reach being different questions), made the reach privilege a SNAPSHOT-level
witnessed source (a pure-targets box still enforces, so its flips must still move the digest
and show in the delta), and refuses a whitespace-only privilege as `blocked:mirror_misconfigured`
rather than silently falling open to allowlist-only reach. Honest limits stated in the module:
tool-seam enforcement (the backend seam keeps allowlist+arm, no API client at that layer);
keying drift in the per-path answer fails CLOSED, never open.

**New `docs/JUNCTION.md`: the design argument, written down.** Every AI integration for
Proxmox picks a lane — API wrapper (governed, incomplete) or root SSH (complete, ungoverned) —
and the fork is forced by the architecture: a Proxmox server is two roots on two planes, the
metal and the product, with no law spanning them. The page names what the API already governs
(most of the estate), what structurally cannot leave the metal (applying upgrades, recovery,
the OS floor, guest shell reach), and how Proximo governs the junction: the API lane inherits
the product's law, the shell lane gets the arm/consent/PROVE discipline the product cannot
extend to it, and the mirror makes the platform's own permission table govern guest reach.
Linked from the README documentation table. An adversarial lens on the first cut returned 12
findings, all in the page's absolutes rather than the mechanism, and the page was rewritten at
each: witnessing claims now say exactly what the ledger records (the reach configuration at
serve start, refusals at the door — not `pveum` grants, which land in no task log and produce
no ledger entry), the break-glass is stated as the widening it is (unsetting the reach privilege falls
back to the allowlist alone, the very reason the flip is witnessed), the arm and consent are
named opt-in with the two-deployment caveat, shell plans are called advisory (no blast-radius
engine on that lane), Ceph's install console concession is credited, and the token's RBAC is
called the hard floor everywhere (THREAT_MODEL.md's one "hard ceiling" aligned to match
SECURITY.md). reachmirror.py's own docstring shared the break-glass defect and was fixed with
it. **The absorption then happened (same day): SECURITY.md gained the MIRROR section and
controls-table row (beside the reach-grant witness section that already covered brick 1),
THREAT_MODEL's exec-edge row now names the arm and the mirror, VERIFY.md gained §7–8 (the
arm refusal and the mirror's fail-closed refusal, runnable on your own server — stated
honestly as needing one, unlike §1–6), SETUP.md walks the four-step erection
(reach-audit evidence → pveum role/grant → env → verify-the-refusal-first), the env
example names `PROXIMO_REACH_PRIVILEGE`, and AGENTS.md teaches the three `blocked:mirror*`
refusals as grant boundaries. JUNCTION.md's pointer sentence now points at pages that
actually carry the content it promises. The absorption then took its own lens round
(4 HIGH / 6 MED / 4 LOW, all in the fresh prose): the "empty aliasing table" claim was
mechanically false everywhere it appeared (a custom role adds a row and removes none —
it decouples AI reach from human role grants, and the built-in roles still carry the
privilege), SETUP's walkthrough now grants BOTH sides of a privsep token (the page's own
intersection rule — token-only left the mirror refusing), the aliasing hazard is scoped to
grants landing on the served principal, VERIFY §7 states the co-located ARM caveat instead
of asserting it away and quotes the exact `blocked:not_armed` outcome, VERIFY §8 puts the
env var in the server's env and names the exec-edge prerequisites, the controls table
gained the ARM row THREAT_MODEL was already selling, and pveum-grant witnessing claims say
what the ledger actually records.** **And one lens finding got a code fix, not a doc
retreat: `arm_source` joined the reach-grant snapshot as a switch** — unsetting
`PROXIMO_ARM_SOURCE` between restarts silently removed the exec write gate, a serve-start
widening of exactly this perimeter, with no entry; now the flip (and a re-pointed source
path, the `ssh_target` precedent) moves the digest and lands in the ledger.

**Brick 3: the witness sees the PVE side.** The honest limit written twice above — a
`pveum` grant lands in no ledger — is retired at the cause instead of restated: while the
mirror is enforcing, the serve-start reach-grant snapshot now DERIVES the served token's
per-guest reach (reach-audit's per-path primitive, one query per allowlisted guest; a `*`
allowlist first enumerates the configured node's live CONTAINERS — `type == "lxc"` only,
since a QEMU vmid in a container-reach key would witness reach the mirror never grants —
so guest creation/destruction moves the digest too: on an allow-all estate that IS a reach
change). The first derive on an existing sidecar is annotated `derived_baseline` (a
one-time upgrade shape, not a mass grant); a pure-targets box records `derived_absent`
(absent, empty and broken stay three different facts); a non-numeric allowlist token is
skipped and reported (`derived_skipped`) instead of poisoning the derive. A PVE-side grant or revoke between
starts lands as a witnessed `mirror.derived_ct` delta: every change to reach, on either
side of the junction, now reaches the ledger. Granularity stated plainly: enforcement is
per-check and immediate, the witness is serve-start. Failure honesty follows the env-lane
precedent — any derive failure records `derived_error` and omits the list, so churn in an
entry carrying the error reads as unproven, never as revocation. No factory passed = no
derive = byte-identical snapshots (zero digest churn for anything but the serve seam,
which passes one built lazily and only while enforcing).

**Also in this release:** the three standing pyright errors fixed at their causes (overloads
for `httpx_verify`, the narrowed unix path passed as a parameter, `_PROBE_ARGV` annotated);
real estate guest ids moved out of public fixtures, with the release leak-audit now refusing
the class; the test suite can no longer write the dev box's real PROVE ledger (autouse tmp
redirect, proven by planted control); an unknown CLI verb exits 2 with usage instead of
falling through to serving; CI tokens ride scoped auth headers and `GIT_CONFIG_*`, never the
clone URL or ARGV; `codeql-action` pinned to one dereferenced sha estate-wide; and the release
recipe carries the rails pacioli earned (proven trees before public main moves, curated-twin
tags, a release title that says something).

## [0.38.0] — 2026-08-24

**The arm did not gate the one path it most needed to.** `arm`/`disarm` swap the PVE API token,
so the boundary is enforced by PVE's own permission check — which binds only the API backend.
`ct_exec`/`ct_psql` reach containers over `ssh -> pct exec` as root on the Proxmox host, authority
that never touches the token. A fully disarmed caller could run arbitrary in-container commands
with every other gate satisfied. Found on the dogfood estate 2026-08-24, by noticing that a
read-only session was still executing.

- **New `armgate` leg: `enforce_arm`, wired at the two ssh seams and at the backend.** With
  `PROXIMO_ARM_SOURCE` set, a confirmed `ct_exec`/`ct_psql` is refused unless the served token's
  bytes equal the arm source's; the refusal records `blocked:not_armed` to the PROVE ledger before
  raising. `ExecBackend.run` checks independently, so a future caller reaching the backend directly
  cannot ride on the allowlist alone — the same defence-in-depth the `enable_exec` check already had.
- **`LEASE` could not have caught this, structurally.** It proves the served token is *fresh*,
  never that it is the *write* one — and `arm.py` deliberately stamps a fresh mtime on `disarm`
  too, so a disarmed token reads as a brand-new lease. Freshness and authority are different
  questions; this asks the second.
- **The predicate fails closed by construction.** Armed *iff* the served token equals the arm
  source. The inverse ("armed unless it matches the read-only source") fails OPEN on a garbled,
  rotated or truncated token, which matches neither. Equality also self-heals on rotation: an
  unrecognized token refuses and the operator re-arms. `PROXIMO_READONLY_SOURCE` is read for
  message quality only, never for enforcement. An empty served token is never armed (`b"" == b""`).
- **Dormant unless you use the arm pattern.** No `PROXIMO_ARM_SOURCE` => no enforcement and zero
  behavior change, which is correct for mint-and-revoke deployments: no write token exists at rest
  there, so there is no standing authority to gate.
- **Still available while disarmed:** dry-run plans (`confirm=False`), and `ct_logs`, whose argv is
  fixed in the backend (`journalctl`, read-only flags) and cannot express a mutation. `logs()` now
  calls a private unchecked path rather than a bypass flag, so no public parameter can skip the gate.
- **SECURITY.md is honest about what kind of boundary this is.** It is local machinery, the thing
  that document otherwise warns not to mistake for a boundary: it closes *drift*, not an attacker
  who already has code execution and can reach the ssh key directly. The stronger posture is named
  — give the exec path its own ssh identity and swap the key, not just the token.
- Tool descriptions state the limit negatively ("NOT AVAILABLE WHILE DISARMED"); manifest and
  `docs/TOOLS.md` regenerated to match.

**Then an adversarial pass took the gate apart, and four things came back.** Four independent
lenses (reachability, predicate, test-vacuity, mutation) plus two refute passes that tried to kill
each finding rather than confirm it. The gate itself held: no path to `ssh -> pct exec` skips the
check, and 7 of 8 mutations to the gate were caught by the suite. Everything below is what sat
*around* the gate.

- **The gate now judges the box the command is aimed at, not the process environment.** This is
  the important one. `arm_state()` read `PROXIMO_ARM_SOURCE` and `PROXIMO_TOKEN_PATH` from the
  process env only, while `ct_exec` resolved its backend per target. With the target registry in
  use, armed on the default box read as armed on every registry target. `packaging/targets.example.toml`
  had already promised the opposite ("arming stays out-of-band and per-target"), and `envelope.py`
  already resolved the active target correctly, so this was a promise the code quietly broke.
  `arm_source` and `readonly_source` are now per-target registry fields, never inherited from the
  env, and a target with exec enabled and no `arm_source` of its own is refused with a reason that
  names the field. `ExecBackend.run` grades `self.config`, which it already held.
- **`PROXIMO_ARM_SOURCE` pointing at `PROXIMO_TOKEN_PATH` is refused.** One file in both roles made
  the predicate compare a file to itself, reporting armed forever, silently, with no way for
  `disarm` to ever change the answer. Compared as configured paths, deliberately not by inode: a
  symlinked token stays armed on purpose, because `arm` installs via temp+rename and replaces it.
- **`ct_diagnose` joins `ct_logs` as available while disarmed, and that is the point of DIAGNOSE.**
  Its probe battery ran through the arm-gated path, so while disarmed all five probes raised, the
  reasons were swallowed into `{"error": "ProximoError"}`, nothing reached the ledger, and the call
  recorded `outcome="ok"`. You diagnose a box precisely when it is broken and you are not armed.
  The battery moved into `backends.py` beside the one method allowed to run it ungated, reached by
  a new `ExecBackend.probe(ctid, key)` that takes a KEY and never argv, so "the argv is fixed in
  this class" is now a property of the code rather than a promise made by another module.
  `enable_exec`, CTID validation and the allowlist all still apply.
- **Failing probes report why.** A bare exception class name is not a diagnosis: allowlist denial,
  exec-disabled and a dead ssh host all rendered identically.
- **The gate order is pinned by a test.** `enforce_arm` runs before `enforce_lease` so the operator
  is told to re-arm rather than to renew. Swapping them left all 11,999 tests green, because no
  test had ever configured a disarmed token and an expired lease at once. Neither order lets the
  command through, so this was never a bypass, only the wrong remedy in the ledger and the message.
- **A flaky anchor test asserted an ordering nothing guarantees.** `SyslogSink.publish` opens a
  new connection per call and the test collector is a `ThreadingTCPServer`, so two handler threads
  append to one list: TCP orders bytes within a connection and promises nothing across two.
  Measured on that harness, 4 of 300 runs recorded the second head first, and it surfaced as a head
  mismatch, which reads like the sink writing the wrong head. The test now asserts what the design
  guarantees, and the sink's docstring states the limit: append-only is the property it holds,
  arrival order is not, so order a trail by `ts` or by the chain.

## [0.37.0] — 2026-08-23

**Two open findings closed, and one of them was recorded backwards.** A `journal` anchor sink
(new capability, hence the minor) and a TLS pin that means the same thing on every interpreter.

- **`journal` anchor sink — the second write-only witness, and the module's last named
  extension.** Same trust shape as `syslog` (`fetches_pins=False`, `last_pin` raises rather than
  returning a fake first-run `None`, an append-only trail instead of one overwritten pin, so
  automatic tail detection is honestly unavailable and pairs with
  `PROXIMO_AUDIT_EXPECTED_HEAD`, a readable sink, or journal-side comparison). Different wire:
  journald's native protocol over a unix datagram socket, which needs no collector stood up and
  inherits the journal's own retention, rotation and FSS sealing. Read the trail with
  `journalctl -t proximo-anchor -o json`. Configure with `PROXIMO_AUDIT_ANCHOR_SINK=journal`;
  the socket path is fixed by systemd, so `PROXIMO_AUDIT_ANCHOR_JOURNAL_SOCKET` exists mainly
  for testing. A datagram to a unix socket still reports failure, which is the property that
  keeps a publish a check rather than a hope.
- **Its field-injection defence keeps fidelity rather than sanitizing it away.** journald
  separates fields with LF, so a newline in a value could inject `PRIORITY=0` or a forged
  `MESSAGE`. The syslog sink defends by reducing header slots to tokens, which costs data. This
  uses journald's length-prefixed binary form, so hostile values travel intact and an injected
  field is structurally impossible. Verified against the real journal, not only a test double.
- **A pinned TLS bundle is now a trust anchor on every interpreter.** Python 3.13 changed what
  `create_default_context()` enables: 3.12 sets neither `VERIFY_X509_STRICT` nor
  `VERIFY_X509_PARTIAL_CHAIN`, 3.13 sets both. The consequence was that the same pinned file
  verified on one interpreter and failed on the next, in opposite directions depending on
  whether you pinned a node certificate or your cluster CA, and a combined bundle fixed
  neither. `httpx_verify` now sets `VERIFY_X509_PARTIAL_CHAIN` on a pinned context, so pinning a
  file means what an operator means by it: trust exactly this. `VERIFY_X509_STRICT` is left
  alone; adding it would break CA pins on 3.12, and clearing it would relax conformance
  checking nobody asked to relax.
- **Pin your node's certificate, not your cluster CA.** Proxmox issues its cluster CA with
  `CA:TRUE` and no `keyUsage` extension, which a strict-verifying stack rejects outright with
  "CA cert does not include key usage extension". That is the verifier being right, not a bug to
  work around, so the guidance changed instead: `docs/SETUP.md` and
  `packaging/proximo.env.example` now say pin the node certificate, and the troubleshooting
  table answers that exact OpenSSL string. The previous advice pointed at the cluster CA.

## [0.36.1] — 2026-08-23

- **The runtime image drops the installer, and the held base bump is taken.** `f4411bd`
  declined python:3.13-slim `ffb752e` on 2026-08-17 because Trivy found two HIGH issues in it
  (setuptools 70.3.0 / CVE-2025-47273, msgpack 1.1.2 / GHSA-6v7p-g79w-8964) and wrote down that
  the pin rollback was "a hold, not a cure". This is the cure. Both findings live in a single
  place, pip's vendored tree (`pip/_vendor/vendor.txt` pins exactly those two), so the runtime
  stage now uninstalls setuptools, wheel and pip once the hash-pinned install is done. The
  runtime never installs anything, so the installer was pure CVE surface and pure attack
  surface: an adopter's container no longer ships a working package manager. This retires the
  whole finding class rather than declining the same digest every week, and it makes true a
  claim this Dockerfile's own header had been making since the two-stage build landed.
- Verified in the order that makes the proof mean something: the digest bump landed alone and
  first so the scan could name the failure, and only then the strip. A cold start with pip,
  setuptools and wheel removed serves all 7 resident tools, so nothing in the runtime path
  reached for `pkg_resources`.
- **Correction to the 2026-08-17 reading, measured against both images.** That entry treated the
  newer base as the thing that introduced the two findings. It did not. Scanning both digests
  from the registry with the gate's own criteria (Trivy 0.70.0, CRITICAL/HIGH, ignore-unfixed):
  the old base reports pip 26.1.2 and zero Python findings, the new base reports pip 26.2.1 and
  the two. But the pip wheels for 26.1.2 and 26.2.1 vendor the identical versions,
  `msgpack==1.1.2` and `setuptools==70.3.0`. The vulnerable code is in the image Proximo ships
  today and has been all along; what changed is that the scanner started seeing it. Holding the
  old pin never removed that code, it only removed the report of it. Both digests also carry the
  same 36 fixable Debian findings, which the runtime stage's `apt-get upgrade` clears, which is
  why the shipping image scans green on a base that does not.

## [0.36.0] — 2026-08-22

**One external end-to-end report became the whole release.** An adopter ran Proximo end to end
and reported three findings: two were shipped mechanisms an adopter could not see — the
per-tool `readOnlyHint`s swallowed by the unannotated facade, and the off-box anchor hidden by
its own nudge — and one gap the report showed plainly: the client could not tell a status read
from a power cycle through the default door. This release is the fixes plus everything the
fixes pointed at: the enforced `proximo_read` door, a daily fresh-resolve smoke of the
published wheel, and two new anchor sinks (`http` and the write-only `syslog` witness). Tool
estate unchanged at 906 registered; the default doorway gains one resident tool
(`proximo_read`) and now measures ~1,740 tokens.

- **`proximo_read` — the enforced read-only door.** In the default lean mode every call rides
  `proximo_call`, whose only honest static hint is `readOnlyHint: false` (a hint cannot vary per
  dispatched call — annotations ride `tools/list`, which is static), so a client's permission
  policy could not tell a status read from a power cycle. `proximo_read(tool, arguments)` is the
  hatch's read-only twin: same reach (the full pre-prune catalog), same single dispatch funnel,
  `readOnlyHint: true` — and the hint is an **enforced promise, not a label**. The verdict comes
  from the same leading `READ-ONLY:`/`MUTATION:` marker that emits every readOnlyHint, so promise
  and enforcement cannot diverge; anything not marked read-only refuses BEFORE dispatch,
  fail-closed — a MUTATION tool, an unmarked tool, and `proximo_call` itself (the laundering
  loophole). Registered where the facade is (the dynamic default door); catalog modes carry
  per-tool hints already.
- **33 read tools gained their missing `READ-ONLY:` marker** (`*_list`/`*_get`/`*_status`
  shapes across pve/pbs/pmg — each body verified a pure read before stamping). They were
  hint-invisible to clients and would have been refused by the read door's fail-closed rule.
  A new gate pins the unmarked set to exactly the two tools that defy the binary
  (`audit_verify`, which may advance the anchor pin file; `proximo_call`, which dispatches
  either kind) so a tool can never ship unmarked again.
- **The facade carries readOnlyHints now.** The per-tool hints (0.32.0) never reached a
  lean-mode client, because the DEFAULT door was three unannotated facade tools — "the client
  can't tell a status read from a power cycle." `proximo_find_tools` and `proximo_tool_schema`
  are local catalog reads and say so (`readOnlyHint: true`); `proximo_call` honestly says
  `false`. On an mcp SDK older than the annotations kwarg the hints degrade to absent (never a
  crash); an explicit `annotations=` through the `tool()` wrapper now degrades the same way
  instead of raising TypeError at import on the 1.24 floor.
- **Daily fresh-resolve smoke of the published wheel** (`.github/workflows/pypi-smoke.yml`) —
  closes the report's honest residual: CI's dual-major matrix tests the checkout, and the
  release-time verify fresh-resolves the published wheel, but between releases nobody exercised
  the exact path an adopter's bare `uvx proximo-proxmox` takes. Two daily legs: an unpinned
  resolve of PyPI's latest with every published extra (plus an import probe of the real face
  modules — the shims defer imports, so only this catches a dead extra), and the still-supported
  mcp 1.x pin. Both run `scripts/pypi_smoke.py` — the release verify's cold-start check,
  extracted from its inline heredoc so ONE verifier serves both workflows and the release-day
  path is exercised daily instead of rotting between releases (every check preserved; the
  per-major serverInfo read now routes through the installed wheel's own `_mcpcompat` seam,
  which floors verify-only re-verification at v0.33.0 — the script refuses older wheels by
  name). A red here means a dependency
  release broke fresh adopter installs (the mcp 2.0.0 class); it detects, a human remediates.
  The PyPI-served version string is shape-validated before it may touch a shell command, and
  the verifier fails by explicit exit, never assert (an assert vanishes under `python -O`).
- **HTTP anchor sink** (`PROXIMO_AUDIT_ANCHOR_SINK=http` + `PROXIMO_AUDIT_ANCHOR_URL`) — the
  extension finding 3 named, built: GET/PUT one pin resource on a receiver on a DIFFERENT host,
  which is where the anchor's trust model wants it. Same payload, same single validation path
  as the file sink (extracted into one `_validate_pin` so a second sink cannot drift), same
  fail-closed shape: only a 404 reads as the first run; any other non-2xx, connection/TLS
  failure, garbage body, or redirect — deliberately not followed; a redirected pin store is a
  tamper signal — refuses. TLS verification has no off switch on this channel by design
  (private CA via `PROXIMO_AUDIT_ANCHOR_CA_BUNDLE`; plain `http://` warns loudly); the bearer
  token is a file reference (`PROXIMO_AUDIT_ANCHOR_TOKEN_PATH`), read fresh per call behind
  the shared secret-file permission floor. Startup auto-pin and `audit_verify`'s anti-poisoning
  export are sink-agnostic and work unchanged. Syslog/journal sinks remain later extensions.
- **Syslog anchor sink — the write-only witness** (`PROXIMO_AUDIT_ANCHOR_SINK=syslog` +
  `PROXIMO_AUDIT_ANCHOR_SYSLOG_ADDRESS`) — the anchor module's other named extension, built
  out the same day. Different trust shape, stated as such: syslog can carry a head OUT but
  never hand one back, so the sink declares `fetches_pins=False`, every clean `audit_verify`
  APPENDS the current head to the collector's trail (SECURITY.md's "root-only append log"
  sentence, mechanized — the anti-poisoning v.ok guard still withholds a tampered head), and
  automatic startup verification is honestly unavailable with this sink alone — Proximo warns
  at startup when neither a manual pin nor a readable sink covers detection. Transports chosen
  so a publish can always FAIL: unix socket (datagram, stream fallback that names both
  attempts) or TCP — TLS-verified against `PROXIMO_AUDIT_ANCHOR_CA_BUNDLE` when set (proven
  in tests against a real TLS collector, wrong-CA refusal included), plaintext warns loudly;
  UDP refused by design (fire-and-forget cannot fail, so it cannot be a check). RFC 5424
  frames, LF-terminated; header slots are sanitized tokens so a hostile field cannot forge a
  second record (full fidelity rides the JSON payload). A write-only sink that forgets its
  flag fails LOUD (the fetch raises, the verify refuses) — a designed default, tested.
- **`audit_verify`'s unpinned nudge names the automated anchor.** The off-box anchor
  (`PROXIMO_AUDIT_ANCHOR_SINK=file`, shipped 0.13.0) was invisible from the tool itself: the
  nudge named only the manual `PROXIMO_AUDIT_EXPECTED_HEAD` path, so an end-to-end adopter
  reasonably read the anchor as unshipped. The nudge now leads with the automated pin, and
  `packaging/proximo.env.example` documents both anchor vars beside the manual one.
- **Every doorway figure re-measured** (all had drifted 4-8% in-band across 0.34/0.35's
  description work; the hints and the new door are deliberate additions on top): the default
  door is **~1,740 tokens** (printed ~1,449 before tonight), MEMORY=0 ~1,166; three-exact-tools
  ~1,704; `pve.guests` ~9,781; two domains ~16,825; pve-only catalog ~101,398; full surface
  ~289,839. SETUP.md's "12x over the 8,192-token default window" also corrected to ~35x — the
  12x was the one-plane figure wearing the full surface's sentence. A new every-live-surface
  gate now requires the current figure and refuses any superseded one on every file that
  prints it.

## [0.35.0] — 2026-08-16

**The three sibling planes get the task envelope PVE got in 0.34.0. BREAKING response shapes
on `pbs_tasks_list`, `pmg_tasks_list` and `pdm_tasks_list`.** Asking the same question of a
different plane returned an unclassified pile of rows, and on PDM a fresh status key per
distinct failure. Each plane's vocabulary was live-probed on the lab BEFORE its classifier
existed, because PVE's shape is a PVE fact until another plane proves its own. That probe
paid immediately: the planes disagree in ways that would have been invisible from PVE. Tool
estate unchanged at 906; no tool added or removed.

### Breaking: bare list to windowed envelope

- **`pbs_tasks_list`, `pmg_tasks_list`, `pdm_tasks_list`** now return
  `{returned, by_outcome, tasks}` instead of a bare list of rows. `by_outcome` classifies
  each RAW row server-side (`running` / `ok` / `warnings` / `failed` / `unknown`) through the
  same single `classify_task_outcome` that 0.34.0 introduced for PVE, so a custom projection
  cannot skew the counts.
- As in 0.34.0 there is deliberately **no `total`**, for a reason that differs per plane and
  is stated per plane rather than averaged. PBS and PMG push `limit` into the query and
  truncate before this server sees a row, so the population count never arrives. PDM does
  not: its endpoint is asked for everything it will give and this server applies the cap, so
  `returned` counts what was kept. It still claims no `total`, because what that endpoint
  windows before answering has not been measured, and a number we have not proven describes
  the population must not wear its name.
- Each of the three gains a **`fields`** escape hatch: omit for the lean default, `all` for
  the full raw payload, or a comma-separated list. The raw rows stay reachable, always.
- The lean field set is **per plane, not shared**, because the column names are not shared.
  PBS and PDM name their task columns `worker_type`/`worker_id` where PVE and PMG say
  `type`/`id`. Asking for one plane's names on another is **refused, with the available names
  listed**, so the disagreement surfaces loudly instead of as a quietly thinner row. The one
  boundary where it cannot: a window that returned zero rows has nothing to validate against,
  so `fields` is accepted and the empty list comes back empty. That case is reachable here
  (PMG's `errors=True` returned zero rows on every probe), so it is stated rather than
  rounded off. PDM
  additionally keeps `node`, because its `upid` is remote-qualified
  (`pve:pve-test4!UPID:...`) and `node` is the only other place the remote's identity appears.

### Measured, and what stayed unmeasured

- **PBS**: a running row omits BOTH `endtime` and `status`, proven twice by catching an apt
  refresh and a garbage collection in flight. PVE's tell is a missing `endtime` alone, so the
  shared classifier was compatible here by luck rather than by design. It is now recorded
  either way. `errors=True` on PBS returns `WARNINGS` rows, live-proven.
- **PDM**: status carries raw error text, live-proven with four distinct strings that now
  collapse to one `failed` count instead of four keys.
- **PMG resisted four honest attempts to make it fail** (an apt index refresh on an
  offline-sealed bridge, two service restarts, a backup; all `OK`, `errors=True` empty every
  time). PMG's failure and running vocabularies are therefore **unobserved, not known**, and
  the tool's own docstring says so rather than implying coverage. The classifier is correct
  there by degradation, not by measurement: an unrecognised status classes `failed`, and a
  finished row whose status is empty or missing classes `unknown`. Never `ok`, which requires
  `endtime` present and the status to be exactly `OK`. One caveat the compression must not
  swallow: a row with no `endtime` classes `running` BEFORE status is consulted, so a keyless
  DICT (`{}`) lands in `running` rather than `unknown`. A row that is not a dict at all is
  caught earlier and classes `unknown`. That `{}` wart is pinned by its own test rather than
  papered over, and closing it means changing a classifier PVE depends on.

### Fixed

- `pbs_tasks_list` and `pmg_tasks_list` had **no test guarding their return shape at all**,
  which is why changing their contract broke nothing and why the guard needed writing.

### Dependencies

- **The `python:3.13-slim` bump is deliberately NOT taken.** Dependabot offered `ffb752e`
  (Python 3.13.15); the image built on it fails the blocking Trivy gate with two HIGH findings
  in the tooling that ships beside the interpreter, `setuptools` 70.3.0 (CVE-2025-47273) and
  `msgpack` 1.1.2 (GHSA-6v7p-g79w-8964). Neither package is a Proximo dependency; neither
  appears in `pyproject.toml`, `uv.lock`, or any `requirements/*.txt`, and the shipped wheel is
  unaffected. Measured rather than assumed: the same Trivy v0.70.0 scanned the outgoing digest
  `9662417` clean four days earlier, and all three advisories predate that scan, so the base is
  the only variable. The pin stays on `9662417` until the newer base carries fixed tooling or
  the image stops shipping build tooling at all.
- `github/codeql-action` re-pinned to `ff2f1c6`
  (tagged both v4.37.7 and v4, and the pin comment now names the exact patch rather than the
  moving major); `astral-sh/setup-uv` v9.0.0 to v10.0.1.
- **v10 disables the cache by default under FOUR conditions, not the three its release notes
  list**: `pull_request_target`, `workflow_run`, `release`, and a **tag push**. The fourth is
  in the action's own source and `action.yml` at the pinned commit, and absent from the
  release-notes body. This repo uses the action exactly once, in the job whose triggers are
  `push` restricted to `branches: [main]`, plus `pull_request`, `schedule` and
  `workflow_dispatch`. That branch filter is the load-bearing fact: it means no tag push ever
  reaches the job, so none of the four conditions applies here. Widen the filter to tags and
  the reasoning inverts.

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
    Design: `docs/plans/2026-07-06-agent-front-door-design.md` (internal-only).

## [0.17.0] — 2026-07-06

### Added
- **`proximo mint`** — print-only token-onboarding runbook (sibling to `proximo doctor`):
  the exact create → write → grant → wire → verify steps per product (PVE/PBS/PMG/PDM),
  least-privilege by default (`--write` opt-in), `--json` for structured output. Bakes in
  the per-product credential formats (`=` vs `:` vs password) and the two hard-won grant
  gotchas (PDM user∩token intersection; PVE privsep token ACLs). Makes no API call and
  never handles a secret. See `docs/plans/2026-07-06-mint-helper-design.md` (internal-only).
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
  undo_point all chained). See `docs/plans/2026-07-06-pdm-fleet-control-design.md` (internal-only).
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
  (Spec: `docs/specs/2026-06-15-blast-radius-engine.md` (internal-only).)
- **Computed blast-radius (access/ACL class).** `pve_acl_modify` now extracts its shadow/widen
  reasoning into the pure `proximo.blast.compute_acl_blast`, populates the structured `affected`
  field, **completes** the target's shadow by resolving their own group-inherited grants (#1), and
  lists who-else-can-reach the path as explicit **UNCHANGED** context (#2). Honest per-principal
  model: only the target gains/loses; group members are never reported as gaining/losing. privsep=1
  tokens do not fold owner groups. Fail-closed throughout (caveat retained when a read fails; risk
  never lowered). (Spec: `docs/specs/2026-06-15-acl-blast-radius.md` (internal-only).)
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
  never below the MEDIUM floor. (Spec: `docs/specs/2026-06-15-firewall-network-blast-radius.md` (internal-only).)
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
  bridge, not an SDN vnet. (Spec: `docs/specs/2026-06-15-firewall-network-blast-radius.md` (internal-only).)
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
