<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# NVMe-oF Multipath and ANA

A subsystem can be reachable through more than one controller: two NICs, two
fabrics, two ports on the target. NVMe multipath groups these controllers
together, so the namespace behind them shows up as one block device instead of
several.

This page covers native NVMe multipath, the ANA states a path can be in, and how
to watch multipath activity live with `nvme top`.

## Native NVMe multipath

The Linux kernel has built-in NVMe multipath. It is controlled by the
`CONFIG_NVME_MULTIPATH` kernel option and, at boot, by the `nvme_core.multipath`
module parameter.

When it is on, every controller for the same subsystem and namespace merges into
one device, for example one `/dev/nvme0n1`. You do not see a separate block
device per path. I/O to that device goes out over whichever path native
multipath currently picks.

When it is off, each controller keeps its own separate namespace device. You can
still use them, but nothing merges the paths for you. This is the case where
device-mapper multipath (`multipathd`), a separate Linux subsystem, is normally
used instead. Configuring `multipathd` is outside the scope of nvme-cli and this
guide.

## Checking subsystem and path status

```bash
$ nvme list-subsys
```

This lists every subsystem, the controllers connected to it, and each
controller's transport, address, and state. Add `-o json` for a machine-readable
form.

## ANA states

Asymmetric Namespace Access (ANA) lets a controller report how well it can
currently reach a namespace. Native multipath uses this to pick the best path. A
path can be in one of these states:

| State | Meaning |
|---|---|
| optimized | Best path. Send I/O here. |
| non-optimized | Reachable, but not preferred. Used if no optimized path is available. |
| inaccessible | The namespace exists but cannot be reached through this path right now. |
| persistent loss | The namespace is permanently gone through this path. |
| change | The controller is updating its ANA state. Treat as temporary. |

## I/O policy

The I/O policy decides how native multipath spreads I/O across optimized paths.
It is a per-subsystem sysfs attribute:

```bash
$ cat /sys/class/nvme-subsystem/nvme-subsys0/iopolicy
numa
```

| Policy | Behavior |
|---|---|
| `numa` | Default. Prefer paths local to the NUMA node making the request. |
| `round-robin` | Spread requests evenly across all optimized paths. |
| `queue-depth` | Send each request down the optimized path with the fewest requests in flight. |

Set it by writing to the same file, or with a udev rule if you want it applied
automatically for a specific array.
[How to set up NVMe-oF autoconnect](autoconnect.md) shows
real examples of the second approach, in its "Vendor tuning rules" section.

## Watching multipath live with `nvme top`

`nvme top` is an interactive dashboard, similar to the Unix `top` command, for
NVMe devices and their paths. It needs a terminal. For scripts, use the JSON
output (see below).

```bash
$ nvme top
$ nvme top --delay 5    # refresh every 5 seconds instead of the default 1
```

The first screen is a **Subsystem Summary**: one row per subsystem, with its
namespace count, path count, controller count, I/O policy, and live
IOPS/latency/bandwidth/utilization.

Press **Enter** on a subsystem to drill in. This shows three more tables for
that subsystem:

- **Namespace Stat** -- per-namespace IOPS, latency, bandwidth, retry and error
  counts.
- **Controller Summary** -- per-controller transport, address, state, reset
  count, reconnect count, and error count.
- **Path Health** -- per-path ANA state, retry count, failover count, and error
  count.

Use the up/down arrows or Page Up/Page Down to scroll, **Esc** to go back to the
subsystem list, and **q** to quit.

Since nvme-cli 3.2, `nvme top --output-format=json` takes two samples
`--delay` seconds apart, prints the rates and counters as one JSON document and
exits. Use this output in scripts and monitoring tools. See [`nvme-top(1)`](man:nvme-top) for
the fields:

```bash
$ nvme top --delay=5 --output-format=json
```

[nvme-mcp](mcp.md) builds on this output. It lets an AI agent watch the
paths, flag unhealthy ones and compare the I/O policies.

`nvme top` is built by default (`-Dtop=enabled`). It is not available on
Windows and FreeBSD.

## See also

- [nvme-mcp](mcp.md) to watch multipath I/O with an AI agent.
- [How to set up NVMe-oF autoconnect](autoconnect.md) for the
  vendor udev rules that set I/O policy automatically.
- [How to configure NVMe-oF connections](fabrics-config.md)
  for setting up the multiple paths (`controller =` lines) that make multipath
  possible in the first place.
