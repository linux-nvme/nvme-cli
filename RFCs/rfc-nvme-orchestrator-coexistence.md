# NVMe-oF Orchestrator Coexistence

## 1. Key Observation

When multiple NVMe-oF orchestrators run simultaneously on the same host, conflicts are bound to arise. Two distinct problems must be addressed:

1. **Ownership coordination** — Who currently manages an existing controller?
2. **Discovery policy coordination** — Which controllers should be connected in the first place?

In practice, these problems manifest as two failure scenarios: one orchestrator may disconnect a controller that another is actively managing, or connect to a controller that another has deliberately excluded. The sections that follow introduce one protection mechanism for each.

---

## 2. Two Prevention Requirements

When multiple orchestrators are active simultaneously, two distinct conflict scenarios must be guarded against:

**Accidental Disconnect Prevention** — an orchestrator must not disconnect a controller that another orchestrator is actively managing. An unexpected disconnect can cause I/O errors or data loss on live storage.

**Accidental Connect Prevention** — an orchestrator must not connect to controllers that have been deliberately excluded. The exclusion may reflect fabric zoning policy, administrative intent, or a decision by another orchestrator to manage those controllers exclusively.

Solving one does not solve the other. The sections below introduce one mechanism for each requirement:

- The **Ownership Registry** prevents accidental disconnections.
- The **Exclusion List** prevents accidental connections.

---

## 3. Disconnect Prevention with the Ownership Registry

The ownership registry provides a lightweight, cooperative mechanism for orchestrators to:

- Declare ownership of connected controllers.
- Avoid accidental disconnects of controllers managed by another orchestrator.
- Enable ownership-aware `disconnect-all` behavior.

The registry is intentionally advisory rather than enforceable, which is appropriate because all orchestrators run with root privileges.

See `rfc-nvme-registry.md` for the full design: registry layout, ownership semantics, API reference, and CLI commands.

---

## 4. Connect Prevention with the Exclusion List

The exclusion list is a **human-administered** mechanism at `/etc/nvme/exclusions/`. Orchestrators do not write to it — it is for the local administrator to configure which controllers orchestrating tools should not connect to. Entries use stable transport identifiers (NQN, address, interface) so they survive across disconnects and reconnects, unlike the registry which is keyed on ephemeral device names.

Its design center is **auto-discovered** controllers — those that appear dynamically via mDNS or CDC DLP responses — where there is no configuration entry to remove in order to suppress an unwanted connection. The canonical use cases are blocking a specific mDNS-discovered DC and blocking all connections over a specific network interface. A controller that is explicitly listed in a static configuration file is suppressed by removing that config entry, not by adding an exclusion.

Enforcement is cooperative: each orchestrator reads the list at startup and skips connecting any matching controller.

See `rfc-nvme-exclusion.md` for the full design: file format, use cases, management commands, enforcement model, and authority hierarchy.

### 4.1 Advantages of the Exclusion Design

#### 4.1.1 Clear responsibility boundaries

- The local administrator manages the exclusion list.
- Each orchestrator has its own configuration file.
- No component writes to another component's files.

#### 4.1.2 No IPC coupling

nvme-discoverd and nvme-stas have zero runtime coupling. There is no callback protocol, no varlink registration, no D-Bus signal. Each daemon reads files; the exclusion list and ownership registry are the coordination primitives. This means each daemon can be stopped, started, or restarted independently without affecting the other.

#### 4.1.3 Extensible

Multiple `.conf` files in `/etc/nvme/exclusions/` allow different administrative boundaries to maintain separate exclusion lists without interfering with each other.

---

## 5. Orchestrator Hierarchy

The ownership registry and the exclusion list each address one side of the coexistence problem. Putting them together gives a clear picture of how all NVMe-oF tools relate to each other.

Not all tools are equal. They fall into three tiers based on how much policy enforcement they perform:

**Tier 1 — Raw commands** (`nvme connect`, `nvme disconnect`): targeted, explicit, and unconditional. The caller specifies a single controller and the command executes without consulting any policy mechanism. `nvme connect` ignores the exclusion list; `nvme disconnect` ignores the ownership registry. These are power tools: the caller's intent is unambiguous. Note however that if a user manually disconnects a controller that a daemon orchestrator manages, that daemon may reconnect it — the controller is in its desired set. A `nvme disconnect` alone cannot achieve a persistent disconnect against an active daemon. To keep the controller disconnected, add an exclusion entry with `nvme disconnect --exclude` (a single atomic step that writes the entry then disconnects) or separately with `nvme exclusion add` followed by `nvme disconnect`. Without an exclusion entry, the daemon will reconnect at its next retry interval.

**Tier 2 — Manually-triggered orchestrators** (`nvme connect-all`, `nvme disconnect-all`): policy-aware, broad-scope commands that the user invokes directly. They operate across many controllers at once; the caller does not necessarily know which controllers are managed by a running daemon. Guardrails are appropriate at this scope. `nvme connect-all` respects the exclusion list before connecting; `nvme disconnect-all` respects the ownership registry before disconnecting.

`connect-all` deliberately uses a NULL owner (no registry participation), with one exception: `connect-all --nbft` registers `owner=nbft` to protect firmware boot volumes. Plain `connect-all` leaves connections unowned so that `disconnect-all` can always undo its work — unowned controllers are always safe to disconnect.

This may raise a concern for FC environments where dracut uses `nvme connect-all` to connect FC controllers before `switch_root`: those connections would be unowned and vulnerable to an accidental `disconnect-all`. The protection comes from nvme-discoverd: as part of its startup reconciliation, discoverd repeats the FC Kickstart (writing to `/sys/class/fc/fc_udev_device/nvme_discovery`) and claims ownership of all FC-discovered controllers by passing `--owner discoverd`. By the time the system is fully up and a user could run `disconnect-all`, discoverd has already registered ownership and those controllers are protected. See `rfc-nvme-discoverd.md` §7. Discovery Sources for the FC Kickstart details.

**Tier 3 — Daemon orchestrators** (`nvme-discoverd`, `nvme-stas`): persistent, event-driven, and fully policy-enforcing. They register ownership on connect and respect both the ownership registry and the exclusion list. nvme-stas additionally enforces CDC fabric zoning (TP8010): before any CDC-driven disconnect, nvme-stas checks the registry and skips any controller owned by another orchestrator. NBFT and discoverd-managed controllers are automatically protected by this same rule, with no special-case logic required (see [§7. TP8010 Fabric Zoning Conflicts](#7-tp8010-fabric-zoning-conflicts)).

**Summary table:**

| Command / Daemon | Checks exclusion list | Checks ownership registry | Registers ownership |
|---|---|---|---|
| `nvme connect` | No — always connects | N/A | No |
| `nvme disconnect` | N/A | No — always disconnects | N/A |
| `nvme connect-all` | Yes | N/A | No (NULL owner)¹ |
| `nvme disconnect-all` | N/A | Yes — skips owned controllers | N/A |
| `nvme-discoverd` | Yes² | Yes — skips owned controllers | Yes (`owner=discoverd`) |
| `nvme-stas` | Yes + CDC authority | Yes — skips if owned by another | Yes (`owner=stas`) |

¹ Exception: `connect-all --nbft` registers `owner=nbft`.
² Exception: nvme-discoverd always reconnects NBFT-sourced controllers regardless of any exclusion list entry.

**Manual operations and daemon orchestrators.** If a user manually `nvme disconnect`s a controller that nvme-stas owns, nvme-stas may reconnect it — the controller is in its desired set. If a user manually `nvme connect`s a controller, no registry entry is written; the connection is unowned. nvme-discoverd leaves it alone — discoverd never disconnects. nvme-stas may still disconnect it if CDC fabric zoning demands: nvme-stas skips only controllers owned by *another* orchestrator; unowned controllers are fair game for fabric zoning (TP8010) enforcement.

**Tools that bypass libnvme or use NULL owner** produce unowned connections — no registry entry is written, and `disconnect-all` treats them as freely disconnectable. The most common sources are:

- **UDisks**: a D-Bus daemon that provides block-device management to desktop environments; it calls libblockdev (`bd_nvme_connect`), which calls libnvme internally, but neither participates in registry ownership.
- **libblockdev**: a C library used by storage tools including UDisks; calls `nvmf_add_ctrl()` directly with no plans for registry ownership participation.
- **Direct `/dev/nvme-fabrics` writes**: any process writing connection parameters to the fabrics interface without going through libnvme (embedded systems, kdump environments, custom scripts); always unowned.

This is correct by design: these are one-shot or user-driven connections not managed by a running daemon. All unowned connections — including those made by plain `connect-all` — are freely disconnectable; that invariant is what makes the `connect-all` → `disconnect-all` workflow reliable.

---

## 6. Natural Division of Labor

In most deployments, nvme-stas and nvme-discoverd naturally partition work by discovery mechanism, without requiring explicit coordination:

- **nvme-stas** owns mDNS-discovered TCP controllers. According to TP8009, NVMe-oF controllers are advertised via mDNS using the `_nvme-disc._tcp` DNS-SD service type, so controllers discovered through mDNS are always NVMe/TCP. Auto-discovery is nvme-stas' core feature.
- **nvme-discoverd** manages NBFT-defined controllers and manually-configured controllers (any transport — TCP, FC, RDMA) through its own configuration file. FC and RDMA environments are almost never mDNS-discovered; their controllers reach discoverd through static config or FC Kickstart PDUs. NBFT controllers start with `owner=nbft` in the registry (set by `nvme connect-all --nbft` during boot). nvme-discoverd handles reconnection and preserves the `owner=nbft` label for NBFT-sourced controllers: the transient unit passes `--owner nbft` rather than `--owner discoverd`, ensuring `nvme disconnect-all --owner discoverd` never targets a firmware-defined boot volume. See `rfc-nvme-discoverd.md` §7. Discovery Sources for details.

Note: NBFT can contain TCP controllers (NVMe-oF boot over TCP is common), so nvme-discoverd will handle TCP too in that case — but these are firmware-defined, not mDNS-discovered, so there is no overlap with nvme-stas.

**nvme-stas refuses to own NBFT-sourced controllers.** nvme-stas reads the NBFT ACPI table at startup (it already does this for other purposes). If any controller in nvme-stas's desired set — from static configuration or a CDC DLP — matches an NBFT entry, nvme-stas logs an error-level journal entry and skips that controller entirely: no connect, no disconnect. This prevents a misconfiguration (e.g. an NBFT boot device listed in nvme-stas's config or appearing in a CDC DLP) from causing nvme-stas to claim ownership of a device that nvme-discoverd manages.

In this common deployment pattern, the registry and exclusion list are rarely exercised. They exist as guardrails for mixed or edge-case configurations.

---

## 7. TP8010 Fabric Zoning Conflicts

Before any CDC-driven disconnect, nvme-stas checks the ownership registry and skips the controller if it is owned by another orchestrator. This single rule eliminates conflict scenarios without requiring nvme-stas to read discoverd's configuration:

- A controller connected by nvme-discoverd carries `owner=discoverd` — nvme-stas never disconnects it.
- An NBFT boot-path controller carries `owner=nbft` — nvme-stas never disconnects it.
- Since nvme-stas never disconnects a controller owned by another orchestrator, there is nothing for nvme-discoverd to reconnect — a bounce loop cannot occur.

**NBFT controllers are also immune to nvme-discoverd's exclusion list.** nvme-discoverd reconnects NBFT-sourced controllers unconditionally, regardless of any matching exclusion list entry. An exclusion entry targeting a boot device is a misconfiguration; nvme-discoverd logs a warning and reconnects. See `rfc-nvme-registry.md` §4 for the `owner=nbft` semantics.

Note that NBFT immunity has two distinct sources: **disconnect immunity** is emergent from the registry-check rule — nvme-stas skips any controller it does not own, so `owner=nbft` controllers are protected without any NBFT-specific logic in nvme-stas; **exclusion-list immunity** is a deliberate special case implemented in nvme-discoverd itself, which overrides its own exclusion list check for controllers present in its NBFT cache.

---

## 8. mDNS Discovery (TP8009) — One Orchestrator at a Time

At most one orchestrator must have mDNS discovery enabled at a time. If both nvme-stas and nvme-discoverd browse `_nvme-disc._tcp` simultaneously, they race to connect to the same mDNS-discovered DCs. The kernel prevents true duplicate connections — the first to connect wins and the other gets `EALREADY`. The real problem is the operational noise: duplicate Get Log Page commands to the same DCs, duplicate AEN reactions, ownership ambiguity in the registry, and duplicated journal entries. The ownership ambiguity also undermines CDC fabric zoning (TP8010): nvme-stas can only enforce zoning on controllers it owns — if nvme-discoverd wins the connection race for an mDNS-discovered controller, that controller carries `owner=discoverd` and nvme-stas cannot disconnect it even if the CDC's zone policy demands it.

nvme-stas actively detects this misconfiguration: at startup it reads `/etc/nvme/discoverd.conf` and emits an error-level journal entry if `zeroconf=true` is set, prompting the administrator to disable mDNS in one of the two daemons. The defaults already avoid the conflict in most deployments: nvme-stas enables mDNS by default; nvme-discoverd disables it by default (`zeroconf=false`). The administrator must make a deliberate choice to enable mDNS in nvme-discoverd, and should do so only when nvme-stas is not installed on the same host.

A future architecture could designate a single mDNS listener that publishes discovered DCs to other orchestrators, eliminating independent mDNS stacks entirely. That design is out of scope for the current release cycle.

---

## 9. Recommended Architecture

The mechanisms are complementary:

| Mechanism | Purpose |
|------------|---------|
| Ownership Registry | Coordinate ownership of existing controllers; prevent accidental disconnects |
| Exclusion List (`/etc/nvme/exclusions/`) | Prevent unwanted future connections; human-administered |

Together these provide a clean separation of concerns: the registry coordinates ownership of live connections; the exclusion list enforces discovery policy. No mechanism requires runtime IPC between orchestrators.
