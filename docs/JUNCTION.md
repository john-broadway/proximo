# The Junction: two roots, one governed door

Every AI integration for Proxmox makes you pick a lane. Wrap the API and you get governance
without completeness: the permission table holds, the task log records, and the agent still
cannot finish the job. Hand over root on SSH and you get completeness without governance:
everything works, and nothing that happens on that channel is scoped, logged, or revocable by
the platform. The fork is usually presented as a safety preference. It is not a preference.
It is forced by the architecture of the product, and this page names the force.

This is the design argument behind Proximo. The controls it motivates are specified in
[`SECURITY.md`](../SECURITY.md) (the mirror and the arm included), threat-modeled in
[`THREAT_MODEL.md`](./THREAT_MODEL.md), proven runnable in [`VERIFY.md`](../VERIFY.md)
(§7–8 are the arm and mirror proofs, on your own server), and erected step by step in
[`SETUP.md`](./SETUP.md).

## Two roots on two planes

A Proxmox server is two systems wearing one hostname.

**Plane 1 is the metal**: a Debian root over SSH. It sees containers as directories and
processes. The only law it obeys is Unix permissions. The Proxmox ACL table does not exist
at this altitude, and nothing done here asks it.

**Plane 2 is the product**: the Proxmox API. Every act passes a permission table and runs
as a named principal, and its worker-spawning operations land in a task log. Its writ ends
at its own endpoints. It has no reach into what a root shell does on the node it runs on.

Proxmox lives on a root it never fully absorbed. Both planes are required to operate an
estate, and no law spans them. That gap is the junction, and every "AI + Proxmox" project
sits in it, whether it says so or not.

## Credit where due: most of the estate is already on plane 2

The fork is narrower than it looks, because Proxmox has spent a decade pulling the metal up
into the API. Networking (bridges, bonds, VLANs, apply and reload), storage and disk
operations (ZFS pools, LVM, GPT init), service control, certificates and ACME, the firewall,
cluster create and join, Ceph management end to end (installing it is apt work, conceded to
a console the same way upgrades are), backup jobs, DNS, time, even the APT repositories and
update index: all of it is API-governed today. Where the API covers an act, Proximo
drives the API and inherits the product's own permission table. Symbiosis, not
reimplementation.

## The residue: what stays on the metal, and why it cannot move

What remains on plane 1 is small in surface and structural in kind. It is not exotic
breakout work. It is the product's own maintenance manual.

1. **Applying upgrades.** The API lists updates, refreshes the index, manages repositories.
   No endpoint installs anything. The web UI's own Upgrade button opens a console shell.
   The product itself concedes this act to the metal.
2. **Recovery.** When the API daemon is down, when the cluster filesystem is wedged, when
   quorum is lost and `/etc/pve` goes read-only, plane 2 cannot act. The API cannot heal
   the API. Every real repair happens on the metal by definition.
3. **The OS floor.** Everything Debian allows that Proxmox never modeled: sysctl, hook
   scripts, packages the product does not know about, kernel and boot.
4. **Shell reach into guests.** `pct exec` runs as node root entering the container from
   above. The guest is never asked, and no PVE privilege has ever governed the act.

Notice the shape: the residue is exactly the acts that change the OS underneath the product,
plus the moments the product is down. It can never be governed *by* Proxmox, because it
lives precisely where Proxmox is absent or dead. Any tool that pretends the API lane is
enough has quietly excluded upgrades, recovery, and the OS floor from its job description.
Any tool that answers with bare root SSH has quietly excluded governance from its.

## The junction, governed

Proximo refuses the fork. Both lanes pass through one door, and each lane gets the strongest
law available to it.

**The API lane inherits the product's law.** The minted token's RBAC bounds everything
Proximo can do there, enforced server-side by Proxmox itself ([`SECURITY.md`](../SECURITY.md)
calls it the hard floor); every call runs as that principal, and every mutation lands in
Proximo's tamper-evident PROVE ledger beside the product's own records.

**The shell lane gets the law the product cannot extend to it.** Nothing above the metal can
see this channel, so the discipline is built at the door. Always on: the guest allowlist, a
dry-run plan before any shell mutation (with an advisory read-vs-write classification, and
honestly advisory: shell commands get no blast-radius engine), and every act landing in the
same hash-chained ledger. Opt-in, and stated plainly as opt-in: an explicit arm the agent
cannot perform for itself, consent as a file the server can read but not mint, a kill-switch,
a lease on the arm. Each is inert until configured, and each becomes a wall rather than a
discipline only when its state sits outside the agent's own write reach: the two-deployment
model [`SECURITY.md`](../SECURITY.md) leads with. Not the API's law, and not pretending to
be.

**The mirror makes plane 2 govern the part of plane 1 it can name.** For shell reach into
guests, the shell tools Proximo serves ask Proxmox itself: does the served token hold the
operator's chosen reach privilege at `/vms/<ctid>`? One GET per check, resolved by PVE's
own permission engine, propagation and revocation included. A natural reach privilege is the
privilege PVE uses for root-level command execution inside VM guests through the agent,
extended over the container channel the platform never modeled. Choose it from evidence:
PVE has custom roles but no custom privileges, so the reach privilege aliases with every
role that carries it, and any grant of such a role to the served principal silently
becomes shell reach; `proximo reach-audit` prints exactly what any candidate aliases with
on your cluster. An operator who wants AI reach granted separately from human rights
builds a one-privilege custom role with `pveum` and grants it per path — the built-in
roles still carry the privilege, which is what the audit table is for watching. Either way the vocabulary is Proxmox's and the grants are Proxmox's: reach moves
by `pveum`, the live map is consulted on every check, and the reach privilege itself
is part of the witnessed reach grant the ledger records at serve start.

## The honest limit

Root cannot be caged by anything it runs. A node root that wants to ignore its own leash
can. What Proximo builds is not a cage and does not claim to be one: it is self-governance
made auditable. Obedience is the only path through the tools this door serves, refusals are
ledgered, and the reach configuration (allowlist, switches, reach privilege — and, while
enforcing, the derived per-guest map itself, so a `pveum` change lands as a delta too) is
witnessed at every serve start, so switching the mirror off is itself a recorded reach
change. When the API is
unreachable the mirror fails closed: no reachable map, no reach. The break-glass is
unsetting the reach privilege to fall back to the allowlist alone, and on a mirror-driven estate
whose allowlist is wide open that is a widening, which is exactly why the flip is the thing
the witness records. The residue keeps its honest name, and the record keeps the receipts.

If you are an agent reading this: [`AGENTS.md`](../AGENTS.md) states the sharp edges first.
The short version of this page is one sentence. You are being handed two roots on two
planes, and the door you are standing in is what makes that survivable for the person who
handed them to you.
