# NVMe-oF Connection Configuration

This is the host-side configuration that specifies **which NVMe over Fabrics (NVMe-oF) controllers a host should connect to, and with what parameters**. The configuration file uses the INI format.

The format is parsed by **libnvme**, so every cooperating consumer reads one format through one parser: `nvme connect-all` / `nvme config` in nvme-cli, the **nvme-discoverd** daemon, and (through the Python bindings) **nvme-stas**. It sits alongside two other host-wide coordination files, the [ownership registry](REGISTRY.md) and the [exclusion list](EXCLUSIONS.md), and shares their transport-ID identity model (`src/nvme/tid.h`).

> This document describes the configuration **format and intent**. Once the parser lands, the header kdoc and the `nvme-*` man pages are the authoritative reference; the code is the source of truth.

## Design goals

- **One shared format for every libnvme consumer** — nvme-cli, nvme-discoverd, and (via the Python bindings) nvme-stas all read the same file through the same parser.
- **Human-editable, systemd-style** — `[Section]` / `key = value`, comments, and drop-ins, the same idiom as systemd's own `.conf` files.
- **Deterministic parsing and precedence** — the same input always resolves to the same connections, with one well-defined merge order.
- **Validated before connecting** — a dry-run entry point catches a bad configuration before it reaches the kernel.
- **Extensible without breaking existing configurations** — unknown keys are ignored rather than rejected, so new keys can be added later without breaking older parsers.
- **Both the common case and advanced deployments** — a small host needs only the main file; a host presenting several distinct identities gets one drop-in per identity.
- **No `json-c` dependency in libnvme** — the previous format needed an optional third-party library to parse; this one does not.

## Single vs. multiple host personalities

**One host personality (the common case).** The host has a single identity — one Host NVMe Qualified Name (NQN) and one Host Identifier — and connects to its fabrics under that identity. This is what most systems need, and the whole configuration fits in the single `nvme-fabrics.conf` main file: the per-type defaults plus the discovery controllers and subsystems to connect. The `[Host]` section is optional here — you may include one to state the identity explicitly, but if it is omitted the connections fall back to the default (legacy) identity in `/etc/nvme/hostnqn` and `/etc/nvme/hostid`.

**Multiple host personalities.** A single host can deliberately present *different* identities — different `(Host NQN, Host Identifier)` pairs — to different fabrics, as though it were several independent hosts. Each such identity is a *personality*. Each one gets its own file under `nvme-fabrics.conf.d/`, opening with its own `[Host]` block; keeping one persona per file is what stops them from getting tangled.

This distinction matters once authentication or Transport Layer Security (TLS) enter the picture. Authentication credentials, such as a TLS Pre-Shared Key (PSK) or a DH-CHAP (Diffie-Hellman HMAC-CHAP) secret, are associated with a host identity and an NVMe subsystem, not with the machine itself.

Separate host identities let different credential sets be configured for different NVMe-oF deployments: a credential configured for one host identity cannot be used by another, and credentials for a single deployment can be updated or revoked by editing only that identity's configuration.

This matters most for hosts that connect to multiple independently administered or multi-tenant NVMe-oF deployments, each with its own access control policy and credentials.

The identity rules that make personalities valid (why each needs a distinct Host NQN *and* Host Identifier) are in [Host identity and multiple personalities](#host-identity-and-multiple-personalities); the file mechanics follow next.

## File layout

A configuration is a **main file plus an optional drop-in directory**, the same `foo.conf` + `foo.conf.d/` pattern systemd uses. The default main file is `/etc/nvme/nvme-fabrics.conf`, and its drop-in directory is the main file's name with `.d` appended: `/etc/nvme/nvme-fabrics.conf.d/`.

```
/etc/nvme/
    nvme-fabrics.conf       # main file: per-type defaults (+ optionally connections)
    nvme-fabrics.conf.d/    # optl. drop-ins, 1 persona per file (or none = default)
        black-fabric.conf
        white-fabric.conf
```

The drop-in directory name is derived mechanically from whatever file you point at, so the convention generalizes to any base name. If *bob* keeps his own config, it is `nvme-for-bob.conf` + `nvme-for-bob.conf.d/*.conf`.

**Both parts are optional**, read independently:

- The **main file** may hold a complete configuration on its own — the per-type defaults *and* connection sections — which is all most single-personality hosts need; `nvme-fabrics.conf.d/` need not exist at all.
- An **empty or absent main file** with a populated `.conf.d/` is fully valid: read the main file *if it exists*, then read `<file>.d/*.conf` *if that directory exists*. This is the layout for a host that wants only explicit, non-default personalities and no default config.
- If **neither exists**, the configuration is empty (no connections) — a gentle no-op, not an error.

> A consumer daemon may keep its *own* configuration file for daemon-specific behavior — for example nvme-discoverd's `discoverd.conf` carries its discovery-source toggles (`nbft`, `zeroconf`, …) and log level. Those keys are specific to that consumer and documented by it; they are **not** part of the shared connectivity format described here.

### Pointing at a configuration — `--config` and the `.d/` rule

`--config FILE` names the main file, and its drop-in directory is always `<FILE>.d/`. Because the directory is derived from the filename, one option reroots the whole tree coherently and there is never a second path to keep in sync:

- `--config /etc/nvme/nvme-fabrics.conf` → reads that file **and** `/etc/nvme/nvme-fabrics.conf.d/`.
- `--config /home/bob/nvme-for-bob.conf` → reads that file **and** `/home/bob/nvme-for-bob.conf.d/` — rerooted to any base directory for free.
- Omitting `--config` → the default `/etc/nvme/nvme-fabrics.conf` (+ its `.d/`).
- `--config /etc/nvme/config.json` (a legacy JSON file, recognized by its `.json` extension) → a hard error naming `nvme config-convert`; libnvme's reader never reads JSON.

Because the config is reached by an explicit path (`--config FILE`, or `libnvmf_config_read(ctx, file)` at the API level), unit testing is straightforward: point at a throwaway file under `/tmp` (and its derived `.d/`) instead of the default `/etc/nvme/nvme-fabrics.conf`.

## Top-level config file (`nvme-fabrics.conf`)

`[Discovery Controller Defaults]` and `[I/O Controller Defaults]` hold the default connection parameters (`ctrl-loss-tmo`, `reconnect-delay`, `keep-alive-tmo`, digests, queue counts, …) for connections of that *type*, unless something more specific overrides them (see [Precedence](#precedence-and-the-merge-model)). There is deliberately no third, type-agnostic defaults section: some parameters do want a different default per controller class — most clearly the keep-alive timeout: `keep-alive-tmo = 30` for a Discovery Controller, `keep-alive-tmo = 5` (the kernel default) for an I/O Controller — and a value that happens to apply to both is simply written in both sections. That's a deliberate choice, not an oversight: checking one `*Defaults` section shows the *whole* effective default set for that class, rather than requiring a reader to also mentally merge in a separate global scope; the occasional duplicated line is a small price for that directness.

Two more scopes are available for controllers that are *discovered*, not configured — it is up to the orchestrator (nvme-discoverd, nvme-stas) to apply them when connecting to what it finds:

- For a controller with no configured origin (e.g. an mDNS-found DC), the top-level file's `[Discovery Controller Defaults]` / `[I/O Controller Defaults]` pair.
- For an I/O Controller or a referral Discovery Controller learned at runtime from a Discovery Log Page (DLP), the scope of the *file* the discovering DC belongs to — that DC's identity (`hostnqn` / `hostid`) and host binding (`host-traddr` / `host-iface`), plus **the file's defaults for its own type**: `[I/O Controller Defaults]` for a discovered IOC, `[Discovery Controller Defaults]` for a referral DC, never the discovering DC's own resolved tunables.

A fabric's drop-in therefore supplies defaults for both its configured controllers and the ones an orchestrator discovers through its DCs, each keyed to what it is. (A drop-in may carry its own copy of either `*Defaults` section; see [Precedence](#precedence-and-the-merge-model) for how the overlay works.)

```ini
# /etc/nvme/nvme-fabrics.conf — a complete single-personality configuration

[Discovery Controller Defaults]
keep-alive-tmo = 30                  # DC keep-alive default
ctrl-loss-tmo  = 600                 # duplicated in both *Defaults sections

[I/O Controller Defaults]
keep-alive-tmo = 5                   # IOC keep-alive default (kernel default)
ctrl-loss-tmo  = 600                 # duplicated in both *Defaults sections

[Host]
# hostnqn omitted → /etc/nvme/hostnqn
# hostid omitted → /etc/nvme/hostid
hostsymname = lab-host-01

[Discovery Controller]
controller = transport=tcp;traddr=192.168.1.10;trsvcid=8009

[Discovery Controller]
nqn        = nqn.2014-08.org.example:cdc.main
controller = transport=tcp;traddr=192.168.1.11;trsvcid=8009

[Subsystem]
nqn        = nqn.2024-01.com.example:data.vol1
controller = transport=tcp;traddr=192.168.1.20;trsvcid=4420

[Subsystem]
nqn           = nqn.2024-01.com.example:data.vol2
ctrl-loss-tmo = 1800            # override the [I/O Controller Defaults] default for this subsystem
controller    = transport=tcp;traddr=192.168.1.21;trsvcid=4420
controller    = transport=tcp;traddr=192.168.1.22;trsvcid=4420
```

## Drop-in config files (`nvme-fabrics.conf.d/`)

A drop-in typically adds a new host persona — opening with its own `[Host]` block naming that persona's `hostnqn` — plus the connections made under that identity. (A drop-in may also omit `[Host]` entirely, adding more connections under the default persona instead.) It may also carry its own copy of either `*Defaults` section, each a scoped overlay limited to that drop-in's own connections (see [Precedence](#precedence-and-the-merge-model)).

```ini
# /etc/nvme/nvme-fabrics.conf.d/prod-fabric.conf
[Host]
hostnqn     = nqn.2014-08.org.nvmexpress:uuid:1111…-A
hostid      = 46ba5037-7ce5-41fa-9452-48477bf00080
hostsymname = Hydra

# This file's own defaults: overlay the top-level ones, for these connections only

[Discovery Controller Defaults]
keep-alive-tmo = 45    # this fabric's DCs are remote — longer than the top-level 30

[I/O Controller Defaults]
reconnect-delay = 20   # slower reconnect for this fabric's IOCs

# --- Discovery Controllers: list as many as needed ---

[Discovery Controller]
nqn        = nqn.2014-08.org.example:cdc.prod
tls        = true
tls-key    = NVMeTLSkey-1:01:…cdc
controller = transport=tcp;traddr=10.0.0.5;trsvcid=8009

[Discovery Controller]
# nqn omitted → the well-known discovery NQN
controller = transport=tcp;traddr=10.0.0.6;trsvcid=8009

# --- I/O Subsystems: list as many as needed ---

[Subsystem]
nqn           = nqn.2024-01.com.example:prod.vol1
tls           = true
tls-key       = NVMeTLSkey-1:01:…vol1     # bound to (this host, this subsysnqn)
ctrl-loss-tmo = 1800                       # overrides the top-level 600 default
controller    = transport=tcp;traddr=10.0.0.9;trsvcid=4420;host-iface=eth0
controller    = transport=tcp;traddr=10.0.0.10;trsvcid=4420;host-iface=eth1

[Subsystem]
nqn           = nqn.2024-01.com.example:prod.vol2
controller    = transport=tcp;traddr=10.0.0.9;trsvcid=4420
```

## Connections

A connection is described by an optional `[Host]` block plus one or more **endpoint sections**. By convention `[Host]` is written first, but its placement carries no meaning — a file's `[Host]` applies to every endpoint section in that file (see [Singleton vs repeatable sections](#singleton-vs-repeatable-sections)).

- **`[Host]`** — the host identity (`hostnqn`, `hostid`, `hostsymname`, `dhchap-secret`, …) used for every connection in that file. **A file with no `[Host]` connects as the system default identity** (`/etc/nvme/hostnqn` / `hostid`) — see [Host identity and multiple personalities](#host-identity-and-multiple-personalities).
- **`[Discovery Controller]`** — a Discovery Controller to connect to. Its NQN is the section's `nqn =`; if omitted it defaults to the well-known discovery NQN (`nqn.2014-08.org.nvmexpress.discovery`).
- **`[Subsystem]`** — an I/O subsystem to connect to, named by its `nqn =`.

The **role is the section name** — there is no `type =` key. **Both `[Discovery Controller]` and `[Subsystem]` may be repeated** — list one section per controller or subsystem you want to connect. Within an endpoint section, each **`controller =` line is one path** to that endpoint; repeating it expresses multipath. Per-endpoint keys (`tls`, `tls-key`, `dhchap-*`, `ctrl-loss-tmo`, …) override the type defaults for that endpoint and all its paths.

### `controller =` address syntax

Each path is a `controller =` line whose value is a `;`-separated `key=value` list using the `nvme connect` option names. The addressing keys — `transport`, `traddr`, `trsvcid`, and optionally `host-traddr` / `host-iface` for per-path host binding (the two paths above are pinned to `eth0` and `eth1`) — identify the path; this is the same address form nvme-stas uses (and the legacy `discovery.conf`), minus the subsystem `nqn`, which now comes from the section header.

Beyond addressing, **any `nvme connect` option may appear on the line as a per-path override** (`keep-alive-tmo`, `ctrl-loss-tmo`, `reconnect-delay`, …) — fine-tuning down to a single controller — with the sole exception of the security parameters, which stay on the section (see [Precedence](#precedence-and-the-merge-model)).

> A URL form (`tcp://10.0.0.10:4420`) was considered and rejected: it carries only the target triple (no `host-traddr` / `host-iface`, which are genuinely per-path in multi-NIC multipath), and it is ambiguous for Fibre Channel (FC), whose World Wide Name (WWN) `traddr` is full of colons and has no port. One uniform, transport-agnostic form is preferred over a URL-plus-extension hybrid.

### Multipath

A `[Subsystem]` (or `[Discovery Controller]`) names one endpoint; each `controller =` line under it is **one path = one controller** the host instantiates via `nvme connect`. The subsystem's namespaces are reachable through every path — native NVMe multipath groups all controllers reporting that subsysnqn. The parser **accepts any number** of `controller =` lines: **1 is normal** (single path), and there is **no upper bound and no power-of-two rule** (2 is merely the common dual-fabric deployment; 3, 4, … are equally valid). Security stays at the section level across all paths — see [Precedence](#precedence-and-the-merge-model).

### Precedence and the merge model

A connection parameter is resolved most-specific-first:

**`controller =` line > endpoint section (`[Discovery Controller]` / `[Subsystem]`) > `[Host]` > type defaults (`[Discovery Controller Defaults]` / `[I/O Controller Defaults]`) > kernel default**

The type-defaults level is selected by the controller's class — a DC connection draws from `[Discovery Controller Defaults]`, an IOC from `[I/O Controller Defaults]`. There is no third, type-agnostic rung beneath them: a value that applies to both classes is simply set in both sections (see [Top-level config file](#top-level-config-file-nvme-fabricsconf)). So a `keep-alive-tmo` on a `controller =` line wins over its `[Subsystem]` section, which wins over the file's `[Host]`, which wins over the type default, which wins over the kernel built-in.

The one non-obvious rung is `[Host]` sitting **above** the type defaults: a `keep-alive-tmo` in a persona's `[Host]` beats even the same file's `[Discovery Controller Defaults]`. That is deliberate — the ladder orders by *ownership*, not category. The `*Defaults` sections are baseline plumbing for a whole class of controllers; a key in `[Host]` was written for that persona specifically, so the persona's value follows its connections.

**Drop-ins are additive, with file-scoped defaults.** A drop-in mostly *adds* connections, but may also carry its own copy of `[Discovery Controller Defaults]` or `[I/O Controller Defaults]`, each a scoped overlay limited to that drop-in's own connections:

- a key set there overrides the top-level default *for that file only*;
- a key left unset inherits from the top-level section;
- nothing leaks to sibling drop-ins or back to the top level.

The type-default rungs are computed per file this way, so the result never depends on the order drop-ins are read in.

**Exception — per-link security stays at the section level.** The TLS and DH-CHAP parameters (see [Security parameters](#security-parameters)) are *not* overridable on a `controller =` line: the PSK and authentication secrets are bound to the `(hostnqn, subsysnqn)` pair, so they are constant across all paths to an endpoint and belong on `[Host]` or an endpoint section. Everything else — `ctrl-loss-tmo`, `keep-alive-tmo`, digests, queue counts, `reconnect-delay`, … — can be overridden per path on the `controller =` line.

### Security parameters

A connection's security settings fall into two families — **authentication** (DH-CHAP, which proves the host and controller identities in-band) and **encryption** (TLS, which protects the data on the wire) — plus one parameter that bridges them. Because they are bound to the host+subsystem relationship, they live on **`[Host]` or an endpoint section**, never on a `controller =` path (the exception above): set on `[Host]` when a persona uses the same credential for everything, on `[Discovery Controller]`/`[Subsystem]` when one endpoint needs its own.

**Authentication — DH-CHAP**

| Key | Meaning |
|---|---|
| `dhchap-secret` | the host's secret — authenticates the host to the controller |
| `dhchap-ctrl-secret` | the controller's secret — adds bidirectional (mutual) authentication |

Bidirectional auth for one specific subsystem, rather than the whole persona:

```ini
[Subsystem]
nqn                = nqn.2024-01.com.example:secure.vol1
dhchap-secret      = DHHC-1:00:…    # this host, proving itself to the controller
dhchap-ctrl-secret = DHHC-1:00:…    # this controller, proving itself back
controller         = transport=tcp;traddr=10.0.0.9;trsvcid=4420
```

> **`dhchap-secret`/`dhchap-ctrl-secret` are always literal in this file.** Unlike `tls-key` below, DH-CHAP has no keyring-reference form, so the secret sits in the clear in whatever reads `nvme-fabrics.conf` — typically world-readable, like the rest of `/etc/nvme/`. Fine for testing, not for production; a real secret-at-rest story for DH-CHAP is still an open item.

**Encryption — TLS**

| Key | Meaning |
|---|---|
| `tls` | enable TLS for the connection |
| `tls-key` | the Pre-Shared Key (PSK): a keyring key id, or the key in interchange format (`NVMeTLSkey-1:01:…`) |
| `tls-key-identity` | the identity string bound to the PSK |
| `keyring` | the keyring the PSK is looked up in (default `.nvme`); usually set once as a `[Host]` default, or duplicated in both `*Defaults` sections |

**Bridging the two**

| Key | Meaning |
|---|---|
| `concat` | *secure concatenation* — derive the TLS PSK from a successful DH-CHAP authentication rather than a pre-provisioned key, chaining the two steps (so it requires the DH-CHAP secrets to be set) |

The key *material* lives in the kernel keyring, not in this file: `tls-key` names a key, it does not store one (except in the interchange-format spelling). libnvme provisions and looks those keys up — `nvme gen-tls-key` / `nvme tls-key`, default keyring `.nvme` — and the kernel's TLS handshake daemon (`tlshd`, from ktls-utils) reads the PSK from the keyring when the connection is made. This file only says *which* key and keyring to use and whether TLS and authentication are on.

### Reverting a parameter to the kernel default

Because the cascade only ever *sets* values, a more-specific level needs a way to *un-set* one an outer level imposed — for instance a drop-in that wants the kernel's built-in `ctrl-loss-tmo` even though the top-level `[I/O Controller Defaults]` pinned it to 450. Hardcoding the number is both inconvenient (the admin must dig it out of the kernel) and wrong (it pins a value, not "the default", and silently diverges if the kernel default ever changes).

An **empty assignment** expresses this, exactly as a systemd drop-in resets a setting:

| Form | Meaning |
|---|---|
| key absent | inherit through the cascade (normal) |
| `key =` *(empty)* | reset → omit the parameter from `nvme connect`, let the kernel apply its built-in default |
| `key = value` | set to that value |

An empty value is used rather than a `default` keyword on purpose: `default` is unambiguous for a number (it can never be a valid integer) but ambiguous for a string — `host-iface = default` could not be told apart from binding to an interface literally named `default`. The empty form carries one meaning regardless of the value's type, and it reads cleanly for strings too (`host-iface =` means "no interface binding", i.e. the kernel default).

> Because `keep-alive-tmo` is special — `nvme connect` only applies the 30 s discovery default when it recognizes the well-known discovery NQN — `keep-alive-tmo =` hands the choice back to the kernel, which for a unique-NQN Discovery Controller means the 5 s I/O default. That is exactly what the empty form promises (let the kernel decide); set an explicit `keep-alive-tmo = 30` if you want a DC's keep-alive guaranteed — pinning it in `[Discovery Controller Defaults]` is exactly what that section is for.

### Singleton vs repeatable sections

- **Repeatable** — `[Subsystem]`, `[Discovery Controller]`. Multiple are normal; that is how you list many endpoints.
- **Singleton** — the two `*Defaults` sections. Conceptually one of each in scope. A repeat **within one file** is almost always a mistake, so it merges (key-by-key, last wins) **and emits a warning** rather than failing. A `*Defaults` section appearing across several *files* is expected — that is the file-scoped overlay above — and is silent.
- **`[Host]` is a hard singleton — one per file, position-independent.** A file's `[Host]` applies to *every* endpoint section in that file, wherever it sits — before or after them; there is no positional scoping. A second `[Host]` in the same file is an **error** (Tier 1) — see [Single vs. multiple host personalities](#single-vs-multiple-host-personalities) for why personas never merge.

### How sections expand into connections

The runtime unit is the **controller**, and a connection *is* a controller. At parse time the files resolve into a flat set of controllers: a `[Discovery Controller]` is one DC connection, and a `[Subsystem]` with N `controller =` lines **expands into N I/O-controller connections**, one per path — the grouping is an authoring convenience that then evaporates. Controllers learned at runtime from a Discovery Log Page or an Asynchronous Event Notification (AEN) are *discovered, not configured*, and are not part of this file format.

## Host identity and multiple personalities

Getting personalities right (see [Single vs. multiple host personalities](#single-vs-multiple-host-personalities)) depends on how the NVMe specification identifies a host, which turns on *two* identifiers that drive *different* subsystem mechanisms (Base 2.3 §5.2.26.1.32; TP4110, TP4126):

- **Host NQN** — the host's *name*. The subsystem uses it for **access-control lists** and to filter the discovery log. It is "who you are" at the identity level.
- **Host Identifier (HostID)** — a 128-bit value the subsystem uses to decide whether multiple controllers belong to **the same host**, for **reservations and registrations**. Per Base 2.3 §5.2.26.1.32, *"controllers … that have the same Host Identifier are assumed to be associated with the same host and have the same reservation and registration rights."* Mandatory and extended 128-bit for NVMe-oF (§5.2.26.1.32.2); a zero HostID forfeits host association, so this format treats zero as invalid. TP4126 pairs HostNQN and HostID from one System UUID — they're meant to travel together.

The consequences for configuration:

- **A distinct personality is a distinct `(HostNQN, HostID)` pair, and a `hostnqn` belongs to exactly one file.** The specification permits several HostIDs under one HostNQN, but the Linux kernel does not currently support that, so this format is deliberately stricter: reusing a `hostnqn` across files — the top-level file and a drop-in, or two drop-ins — is an error, regardless of `hostid` (revisit if the kernel ever supports it). Reusing a `hostid` across two *distinct* personas (different `hostnqn`) is a separate collision, independent of that kernel limitation: it makes the subsystem treat them as the *same* host (merged reservation/registration rights) — a real functional collision, not a style nit.
- **The default persona** — the top-level `[Host]`, or no `[Host]` at all — falls back to the system identity: `hostnqn` from `/etc/nvme/hostnqn`, `hostid` from `/etc/nvme/hostid`. If a fallback file does not exist, the parameter is simply omitted from the connect and **the kernel generates one** (see the caveat below). This is the single legacy default; an explicit value overrides it.
- **A drop-in `[Host]` must state its `hostnqn`** — the persona's name is what distinguishes it, so leaving it unset is an error (Tier 1). Its `hostid` is **optional**: if unset, it is omitted and the kernel generates one. There is deliberately **no** `/etc/nvme/hostid` fallback for drop-ins — inheriting the system HostID is precisely the same-host collision described above. (`hostsymname`, keys, etc. remain optional throughout — they do not discriminate identity.)

> **Kernel-generated HostID caveat.** When `hostid` is omitted, the kernel supplies a random one. That satisfies the spec, but the value is **not stable**: it changes on every reboot, and can change again when the identity's last controller disconnects and the host is re-created. Persistent reservations and registrations are keyed on HostID, so a host that relies on them across reboots must pin `hostid` explicitly (or, for the default persona, in `/etc/nvme/hostid`). Hosts that do not use reservations can safely let the kernel generate.

## Validation

The shared parser validates a configuration when it is read and reports problems in two tiers. Validation lives in libnvme so every consumer gets identical checks; relational checks (which compare two entries) fail the configuration **as a unit** and name the offending entries, rather than silently connecting a partial set. A dry-run/validate entry point in nvme-cli runs both tiers and reports without connecting (the natural home is `nvme config` — or a dedicated command if that would overload it). For a daemon, a validation failure on `SIGHUP` reload **rejects the new configuration and keeps the last-good one running** — a fat-fingered edit never tears down working connections.

**Tier 1 — spec violations → error.** The configuration is non-compliant, not merely sloppy:

- `hostid` explicitly set but zero or malformed (not a valid 128-bit / UUID value) — see [Host identity](#host-identity-and-multiple-personalities).
- A drop-in `[Host]` with no `hostnqn` — the persona has no name (see [Host identity](#host-identity-and-multiple-personalities)).
- More than one `[Host]` section in a single file — see [Singleton vs repeatable sections](#singleton-vs-repeatable-sections).
- Duplicate `hostid` across distinct personas (different `hostnqn`, same explicit `hostid`) — see [Host identity](#host-identity-and-multiple-personalities).
- A `hostnqn` reused across files (the top-level file and a drop-in, or two drop-ins) — one persona, one file (see [Host identity](#host-identity-and-multiple-personalities)).
- Malformed `hostnqn` / `subsysnqn` (NQN syntax, Base 2.3 §4.7).
- An empty value (`key =`) on a **required** field (`nqn`, `traddr`, `transport`) — there is no kernel default to fall back to, so it is a missing required value.

**Tier 2 — config hygiene → warning** (loud, non-blocking):

- A repeated singleton section within one file (a `*Defaults` section).
- A persona with no explicit `hostid` — legal, but the kernel-generated value is unstable across reboots, which breaks persistent reservations (see the caveat in [Host identity](#host-identity-and-multiple-personalities)).
- Unknown keys — ignored, same fail-safe posture as the exclusion list.

## Parser conventions

The parser follows systemd conventions. Boolean values accept `1`/`yes`/`y`/`true`/`t`/`on` and `0`/`no`/`n`/`false`/`f`/`off` (all case-insensitive), matching systemd's `parse_boolean()`. Lines beginning with `#` are comments; blank lines are ignored. An empty value (`key =`) is meaningful — it resets a cascade-able tunable to the kernel default (above) — so the parser distinguishes a key that is absent from one present with an empty value. Every key has **exactly one spelling**: no hidden aliases, no underscore variants, and the subsystem NQN is written `nqn` (not `subsysnqn`). This is greenfield work — there are no legacy INI files to stay compatible with, so there is nothing ambiguous to parse or document.

Connection-parameter keys are the **same names as the `nvme connect` command-line options** — `keep-alive-tmo`, `ctrl-loss-tmo`, `reconnect-delay`, `host-iface`, `dhchap-secret`, and so on (hyphenated, not the underscored spellings the legacy `config.json` used). What you write here is exactly what you would pass on the command line, which is the rule to reach for when in doubt about a key's name. The one key with no connect option is `hostsymname`: the host's symbolic name, sent to a Discovery Controller by the Discovery Information Management (DIM) command (`nvme dim`, TP8010). It is carried here for nvme-stas (which reads this format through the Python bindings) and for eventual TP8010 support in nvme-discoverd.

## Relationship to the registry and exclusion list

The three host-wide files cover complementary questions for the same goal — letting independent actors share a host's NVMe-oF connections:

| | This config | [Registry](REGISTRY.md) | [Exclusion list](EXCLUSIONS.md) |
|---|---|---|---|
| Question | *What should be connected?* | *Who owns this controller?* | *May anyone connect this controller?* |
| Location | `/etc/nvme/` (persistent config) | `/run/nvme/registry/` (runtime, per-boot) | `/etc/nvme/exclusions.conf` + `.conf.d/` (persistent config) |
| Author | the administrator | libnvme, automatically on connect | the administrator |

All three rest on the same transport-ID identity (`src/nvme/tid.h`) and the same principle: cooperation by convention, not enforcement.

## Glossary

| Term | Meaning |
|---|---|
| AEN | Asynchronous Event Notification — a controller-initiated event, e.g. a Discovery Controller signalling that its log page changed. |
| DC | Discovery Controller — a controller whose Discovery Log Page lists the controllers a host may connect; it exposes no namespaces. |
| DH-CHAP | Diffie-Hellman HMAC-CHAP — the NVMe in-band authentication protocol; its secret is bound to a (host, subsystem) pair. |
| DLP | Discovery Log Page — the list of connectable controllers a host retrieves from a Discovery Controller. |
| FC | Fibre Channel — an NVMe-oF transport. |
| HostID | Host Identifier — a 128-bit value identifying a host for reservations and registrations; the same HostID implies the same host. |
| IOC | I/O Controller — a controller that exposes namespaces (storage), as opposed to a Discovery Controller. |
| `kato` | Keep Alive Time-Out — the spec/kernel term for the `keep-alive-tmo` connection parameter (named `--keep-alive-tmo` on the CLI and `keep-alive-tmo` here). |
| mDNS | multicast DNS — zero-configuration discovery used to find Discovery Controllers (a future feature). |
| NQN | NVMe Qualified Name — the name identifying a host (Host NQN) or a subsystem (Subsystem NQN) on a fabric. |
| NVMe | Non-Volatile Memory Express. |
| NVMe-oF | NVMe over Fabrics — NVMe carried over a network transport (TCP, RDMA, Fibre Channel). |
| PSK | Pre-Shared Key — the TLS key material that secures a fabric connection. |
| TID | transport ID — the stable per-connection identity (`src/nvme/tid.h`) shared with the registry and exclusion list. |
| TLS | Transport Layer Security — encrypts NVMe/TCP connections. |
| UUID | Universally Unique Identifier. |
| WWN | World Wide Name — a Fibre Channel address. |

## References

Specification documents this design cites (section numbers refer to the revisions below):

- **NVM Express Base Specification, Revision 2.3** (2025-08-01, Ratified) — NVMe Qualified Names (§4.7); Host Identifier feature (§5.2.26.1.32), its NVMe-oF requirements (§5.2.26.1.32.2)
- **TP4110** — Align PCIe and Fabrics HOSTID Management (Ratified 2022-01-11)
- **TP4126** — NVMe-oF Boot HostNQN and HostID (Ratified 2023-01-25)
- **TP8010** — NVMe-oF Centralized Discovery Controller (Ratified 2022-01-12) — the Discovery Information Management (DIM) command that carries `hostsymname`
- **TP8009** — Automated Discovery of NVMe-oF Discovery Controllers in IP Networks (Ratified 2022-01-11) and **TP8024** — mDNS Discovery update (Ratified 2024-06-11) — the mDNS discovery behind auto-discovered DCs

## Further reading

- [`src/nvme/tid.h`](../src/nvme/tid.h) — the transport-ID identity shared across config, registry, and exclusion
- [REGISTRY.md](REGISTRY.md) — the ownership registry
- [EXCLUSIONS.md](EXCLUSIONS.md) — the exclusion list

## Notes

nvme-cli has historically stored saved connections in `/etc/nvme/config.json`, via the optional `json-c` library. That format is superseded by the INI format described here: it removes libnvme's dependency on `json-c`, it supports comments (JSON does not), and it matches the hand-edit style of systemd's own `.conf` / `.network` / `.service` files.

libnvme itself never reads `config.json` — INI is the only format it understands. The transition is staged entirely in nvme-cli, above the library: `nvme config-convert` reads the legacy `config.json` / `discovery.conf` once and writes the INI equivalent, then renames each converted legacy file to `<name>.converted` so a repeat run does not read it again. Routine operation only reads the INI — the tool never rewrites it.

`discovery.conf` is also superseded. By its own man page it is "a list of connect-all commands to run": limited to Discovery Controllers by construction, with no way to express an I/O Controller or global defaults, and no `[Host]`-style persona (the hostnqn/hostid pair has to be repeated on every line for one identity, with nothing validating the result). The format here covers the full set, so it replaces `discovery.conf` too.

libnvme's own JSON dump of the live topology (`libnvme_dump_tree()`) was retired, not ported: `nvme list -vvv -o json` already walks the same host/subsystem/controller/namespace tree and renders it as JSON.
