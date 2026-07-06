# The NVMe-oF Transport ID (TID)

A **TID** identifies one NVMe-oF connection: the transport tuple plus the subsystem and host identifiers that together name one host-to-controller association. `libnvmf_tid_get_canonical()` renders it as a deterministic, fixed-field-order string. A caller that wants a compact name (e.g. nvme-discoverd deriving a systemd unit name) hashes that string itself — libnvme doesn't hash it (see "Naming is the caller's job").

> The code is the source of truth; for exact signatures see the kdoc in `src/nvme/tid.h`.

## Fields

A TID carries eight fields:

- **Addressing** — `transport`, `traddr`, `trsvcid`, `host_traddr`, `host_iface`.
- **Subsystem** — `subsysnqn`.
- **Host identity** — `hostnqn`, `hostid`.

`libnvmf_tid_get_canonical()` renders these in fixed field order (`transport=tcp;traddr=1.2.3.4;trsvcid=8009;…`), omitting unset fields, so the same logical TID always yields the same string regardless of set order.

## Addressing is numeric-only

`traddr`/`host_traddr` must be numeric IP addresses; a hostname makes construction fail — libnvme never resolves, defers, or carries one (rationale: `design/INTEGRATION.md`). `libnvmf_traddr_is_numeric(traddr)` checks a candidate address up front, using the same numeric definition the constructors enforce internally (an IPv6 scope suffix like `fe80::1%eth0` counts as numeric).

## Sanitization

Sanitization normalizes an address that *will* be accepted into one consistent spelling — it is not validation. It makes the canonical form deterministic per producer, and gives the connection-identity matcher (below) cheap string equality instead of a semantic address comparison.

This is structural, not a convention to remember: addressing fields are only ever set via `libnvmf_tid_from_fields()`, `libnvmf_tid_parse()`, or `libnvmf_tid_dup()` — the per-field addressing setters are gone from the public API — and `transport` is an immutable constructor argument, since sanitizing an address requires knowing the transport.

| Field | tcp / rdma | fc | loop |
|---|---|---|---|
| `traddr` | numeric → canonicalize; hostname → **fails** | as-is | as-is |
| `host_traddr` | numeric → canonicalize; hostname → **fails** | as-is | (n/a) |
| `trsvcid` / `host_iface` | as-is | (n/a) | (n/a) |

Canonicalization is `inet_pton()`/`inet_ntop()` — numeric only, never blocking. An IPv6 scope stays in `traddr` (`fe80::1%eth0`) rather than moving to `host_iface`, since that field is TCP-only.

Sanitization guarantees one spelling per producer — not that two canonical forms agree iff they name the same connection. `::ffff:1.2.3.4` and `1.2.3.4` canonicalize differently even though the kernel may route them identically; not treated as a defect, since the TID was never a unique connection identifier to begin with (see below).

**Deferred, not yet enforced:** FC WWN syntax validation, and dropping a field a transport has no use for (e.g. `host_iface` on RDMA). Until then an inapplicable or malformed field is carried as written rather than rejected.

## Identity: subsysnqn, hostnqn, hostid

Set together via one call, applied after addressing:

```c
int libnvmf_tid_set_identity(struct libnvmf_tid *tid, const char *subsysnqn,
                             const char *hostnqn, const char *hostid);
```

`NULL` leaves a field unset. Two rules enforced here:

- **One host is one `(hostnqn, hostid)` pair** — mirrors the kernel's `nvmf_host_add()`.
- **hostid must be stable across connects.** What breaks trackability is regenerating a value on every connect, not how the value was chosen — a hostid randomly generated once and persisted (e.g. `/etc/nvme/hostid`) is fine. Deterministic alternatives per spec: `0h` (TP4110, but collides across personas) or derived from a UUID-format HostNQN (TP4126 method b, via `libnvme_hostid_from_hostnqn()`).

Resolution order for an absent hostid: explicit → `/etc/nvme/hostid` → derive from HostNQN UUID → `0h`. `set_identity()` performs only the UUID derivation itself; it never reads a file or invents `0h`, and leaves the field unset if it can't derive one.

## Naming is the caller's job

`libnvmf_tid_get_canonical()` is the naming primitive; libnvme does not hash it. A caller that wants a compact, stable name — e.g. nvme-discoverd deriving its `nvme-discoverd-<hash>.service` unit name — hashes the canonical string itself. Two producers only agree on the resulting name if they built the TID from byte-identical fields — the IPv4-mapped-vs-bare-IPv4 case above is one way that can silently fail.

## The canonical form is not connection identity

The canonical form (or a hash of it) names a *candidate* connection, not a live one — that's decided by the kernel. On TCP, `traddr` drives routing which picks the interface, and the interface determines the source address. So, a TID pinning `host_traddr` or `host_iface` and one leaving them unset can canonicalize differently yet resolve to the same connection. The kernel reports its actual source in a separate sysfs attribute, `src_addr`.

A candidate TID must go through a **connection-identity matcher** that reads sysfs, including `src_addr`, before connecting — never a canonical-string or hash comparison. libnvme already has this logic internally (`tree-fabrics.c`); exposing it publicly is prep work for nvme-discoverd, not part of the TID.

## API summary

Construct (sanitizing, numeric-only):

- `libnvmf_tid_from_fields(transport, …)` — fails if `traddr`/`host_traddr` isn't numeric on an IP transport.
- `libnvmf_tid_parse(ctx, "transport=…;…")` — same rule; a malformed token is logged and skipped.
- `libnvmf_tid_parse_strict(ctx, …)` — same, but a malformed token fails the whole parse.
- `libnvmf_tid_dup(tid)` — copy.
- `libnvmf_traddr_is_numeric(traddr)` — check before resolving/building.

Identify: `libnvmf_tid_set_identity(tid, subsysnqn, hostnqn, hostid)`.

Consume:

- `libnvmf_tid_get_canonical(tid)` — full 8-field identity string, for matching/dedup/hashing, never a log line.
- `libnvmf_tid_str(tid)` — compact rendering for log lines, `(transport, traddr, trsvcid[, subsysnqn][, host_iface][, host_traddr])`, hostnqn/hostid omitted (matches nvme-stas). Never swap with `get_canonical()`.
- `libnvmf_tid_is_empty(tid)` — true if NULL or no fields set.
- Field getters.

## Still open

- Transport-applicability checks (drop/reject inapplicable fields, FC WWN syntax) — deferred, not yet enforced.
- Whether the CLI's connect-arg path (`nvme-cli/fabrics.c`) should build/canonicalize a TID the same way, so `nvme connect` names a connection identically to config.
