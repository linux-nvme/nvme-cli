# NVMe Orchestrator Coexistence – Discussion Summary

## Key Observation

The NVMe Ownership Registry and orchestrator coexistence address two different problems:

1. **Ownership coordination** – Who currently manages an existing controller?
2. **Discovery policy coordination** – Which controllers should be connected in the first place?

The ownership registry solves the first problem. Fabric zoning conflicts primarily arise from the second.

---

## Ownership Registry Remains Valuable

The ownership registry provides a lightweight, cooperative mechanism for orchestrators to:

- Declare ownership of connected controllers.
- Avoid accidental disconnects of controllers managed by another orchestrator.
- Support ownership transfer when a higher-authority orchestrator (e.g. STAS) determines it should manage a controller.
- Enable ownership-aware `disconnect-all` behavior.

The registry is intentionally advisory rather than enforceable, which is appropriate because all orchestrators run with root privileges.

---

## Systemd-Based Protection

If running `nvme-discoverd` and `nvme-stas` simultaneously proves harmful, a useful safeguard is:

```ini
[Unit]
Conflicts=nvme-discoverd.service
```

This provides runtime mutual exclusion as a safety net.

However, `Conflicts=` alone does not establish priority. It only prevents both services from running at the same time.

---

## Discovery Policy Requires a Separate Mechanism

The ownership registry cannot prevent reconnect loops because ownership is attached to a kernel controller instance (`nvmeX`), which disappears when the controller is disconnected.

A reconnect creates a new controller instance and a new registry entry.

Therefore, discovery-policy decisions must be expressed using stable identifiers such as:

- Subsystem NQN
- Transport type
- Target address
- Host interface
- Other discovery-log attributes

rather than kernel device names.

---

## Dynamic Exclusion Mechanism for discoverd

> **Note:** This mechanism is not planned for immediate implementation. It becomes relevant when mDNS discovery support is added to nvme-discoverd — that is the point at which nvme-discoverd and nvme-stas can discover the same controllers independently, creating the conditions for serious connect/disconnect conflicts. The design is documented here to inform that future work.

A promising approach is for discoverd to support runtime exclusion rules.

Example:

```
/run/nvme/discoverd-exclusions/
    stas.conf
    admin.conf
```

discoverd would:

1. Monitor the directory using inotify.
2. Rebuild its effective exclusion set whenever files change.
3. Apply exclusions to future discovery events only.

**Design decision: exclusions are forward-only.** When an exclusion file is written or updated, discoverd stops connecting to matching controllers in the future but does not disconnect controllers it has already connected. Disconnecting existing controllers is the owner's responsibility — discoverd's role is connecting, not disconnecting things it did not connect. This keeps responsibility boundaries clean and avoids the same connect/disconnect bounce loop in reverse.

### Exclusion File Format

**Design decision: use the nvme-stas key=value format.**

Each exclusion entry uses the same semicolon-separated key=value syntax already defined by nvme-stas:

```
exclude = transport=tcp;traddr=fe80::2c6e:dee7:857:26bb
exclude = host-iface=enp0s8
exclude = nqn=nqn.2014-08.org.nvmexpress:uuid:some-subsystem
```

A **minimal-match** approach is used: only the fields present in the entry are checked. Specifying `host-iface=enp0s8` alone excludes all controllers reachable on that interface, regardless of transport or address.

Rationale for this choice:
- nvme-stas is the primary producer of exclusion files — it can write entries in its native format with no transformation
- libsystemd's conf-parser is internal to systemd and not part of the public API, so discoverd cannot link against it directly; however, it could serve as the basis for discoverd's own parser — provided the systemd source code is lifted with its copyright statements intact (systemd is LGPL-2.1-or-later, which is compatible with libnvme's license)
- `sd-json` was only made public in systemd 257 (2025-09-17) and is too new to depend on for broad distro compatibility
- The format is simple enough that discoverd needs only a small custom parser

---

## Advantages of Runtime Exclusions

### Ephemeral State

Using `/run` ensures exclusions automatically disappear on reboot and do not become stale.

### Clear Ownership Boundaries

- STAS owns its exclusion files.
- discoverd owns its configuration.
- No component edits another component's configuration files.

### Extensible Design

Multiple policy producers can coexist:

- STAS
- Administrative tools
- Future orchestration components

discoverd simply consumes the resulting exclusion set.

### Fabric-Zoning Friendly

STAS can translate CDC/fabric-zoning decisions into exclusion rules that discoverd respects, preventing connect/disconnect loops before they occur.

---

## Recommended Architecture

The mechanisms are complementary:

| Mechanism | Purpose |
|------------|---------|
| Ownership Registry | Coordinate ownership of existing controllers |
| Runtime Exclusions | Prevent unwanted future connections |
| systemd Conflicts | Provide operational safety and mutual exclusion |

Together these provide a clean separation between ownership coordination, discovery policy coordination, and service management.
