# Integrating libnvme into an application

> **libnvme owns NVMe protocol I/O. The caller owns policy, non-determinism, and its own concurrency.**

The code is the source of truth; this document explains the boundary and the reasoning behind it. For exact signatures see the kdoc in `src/nvme/*.h`.

## Why this needs stating

The CLI/library split extracted code by mechanical convenience, not by a stated rule, so some caller responsibilities ended up inside the library. Hostname resolution is the clearest example — it sits inside libnvme today even though it was always the caller's job. This document is the rule that the boundary should have had from the start.

## The boundary

- **NVMe protocol I/O** — ioctls to `/dev/nvmeX`, the `/dev/nvme-fabrics` connect write, log pages, Identify, sysfs enumeration. If it *is* NVMe, it belongs in the library.
- **Policy** — any choice with more than one defensible answer (which resolved address to use, which source address to bind, how hard to retry). The right answer depends on the deployment, not on NVMe, so policy belongs to the caller.
- **Non-determinism** — anything not a pure function of its inputs (DNS is the archetype). It poisons anything downstream that needs to be reproducible.
- **Concurrency** — *when* and on which thread a call runs relative to the application's event loop. Only the application knows its loop.

Hostname resolution fails the policy and non-determinism tests outright, and (below) also blocks — three independent reasons it belongs to the caller, not the library.

## libnvme is synchronous and blocking

Every libnvme API blocks the calling thread by default: connect blocks on the `/dev/nvme-fabrics` write, Get Log Page and Identify block on ioctls, and even device-tree enumeration is real sysfs I/O. The one opt-in exception is I/O passthru over io_uring: `libnvme_submit_io_passthru()` queues a command without blocking, though `libnvme_reap_passthru()` still blocks to collect the result — a caller has to explicitly build that path. No file descriptors to poll for the default synchronous path, no callbacks, no loop of its own — deliberately: integrating with every event-loop implementation in existence (sd_event, GLib, raw epoll, libuv, ...) doesn't scale, and would lock every caller into whichever one libnvme picked.

## The main-loop contract

A process with a main loop must never call libnvme from the loop thread. Offload it:

- **Worker thread** — for in-process blocking calls (Discovery Log Page, Identify, sysfs scan); post the result back via an eventfd/pipe the loop already watches. This is how nvme-stas drives nearly every libnvme call.
- **Subprocess or systemd unit** — for connect, when isolation and lifecycle supervision are wanted too.

nvme-discoverd uses both: it retrieves Discovery Log Pages on a worker thread but performs connects by starting a systemd unit, so the fully-blocking call never touches its loop.

## Worked example: hostname resolution

A hostname can only enter through `traddr`, from a CLI argument or a config file — a Discovery Log Page's address family is numeric-only by spec, `host_traddr` is a source address a hostname can't sensibly name, and `host_iface` is a kernel-resolved interface name. The caller resolves `traddr` before calling libnvme — inline for a one-shot CLI, on a worker thread for a daemon — and picks among the results itself (e.g. IPv4 vs. IPv6). Internally, libnvme's Transport ID (TID) constructors enforce this by rejecting hostnames outright (`design/TID.md`).

## Rule of thumb

*Is it NVMe protocol I/O?* → the library. *Is it policy, non-deterministic, or event-loop-aware?* → the caller. Something that's both: split it, keep the protocol part in the library, leave policy and scheduling to the caller.
