<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# nvme-mcp

nvme-mcp is an [MCP](https://modelcontextprotocol.io) server. It lets an AI
agent watch the I/O of the NVMe subsystems of a host. The agent can see which
path carries how much I/O, and which path is slow, has errors or is not
optimized. It can also compare the multipath I/O policies under a workload.

nvme-mcp is new in nvme-cli 3.2. It is in `scripts/mcp/` in the source tree.

## How it works

nvme-mcp reads the output of `nvme top --output-format=json`. This output is
also new in 3.2. `nvme top` takes two samples of the block layer statistics
`--delay` seconds apart. It prints the rates and the counters of the
subsystems, namespaces, paths and controllers as one JSON document:

```bash
nvme top --delay=5 --output-format=json
```

See [`nvme-top(1)`](man:nvme-top) for the fields of the document. You can also use this
output in your own scripts and monitoring tools.

nvme-mcp only measures the I/O that runs anyway. It does not start any I/O
itself.

## Requirements

- Linux. `nvme top` is not available on other systems.
- Python 3.10 or later. nvme-mcp needs only the standard library. If
  `python3` is older, nvme-mcp runs the newest `python3.N` it finds.
- An nvme binary that supports `nvme top -o json` (3.2 or later).

nvme-mcp does not need root for most work. `nvme top` reads only sysfs files
that every user can read. root is needed for:

- The kernel log in `nvme_watch`. When `kernel.dmesg_restrict` is 1, only root
  can read `/dev/kmsg`. Many distributions set this. Without root,
  `nvme_watch` works, but it reports `KernelLogError` instead of the kernel log
  lines.
- The tools of `--allow-iopolicy`. Only root can write the `iopolicy` file of
  a subsystem.

nvme-mcp is not built or installed. Run it from the source tree.

## Setup

Add nvme-mcp as an MCP server to your agent. With Claude Code:

```bash
claude mcp add nvme -- /path/to/nvme-cli/scripts/mcp/nvme-mcp
```

nvme-mcp uses the `nvme` binary in `PATH`. Use `--nvme` to select another
binary, for example one from your build directory:

```bash
claude mcp add nvme -- /path/to/nvme-cli/scripts/mcp/nvme-mcp \
    --nvme /path/to/nvme-cli/.build/nvme
```

By default, nvme-mcp only reads. Add `--allow-iopolicy` to also offer the
tools that change the I/O policy of a subsystem. These tools need root, so run
nvme-mcp with `sudo`. With `sudo`, `nvme_watch` also gets the kernel log:

```bash
claude mcp add nvme -- sudo /path/to/nvme-cli/scripts/mcp/nvme-mcp \
    --allow-iopolicy
```

## Tools

| Tool | What it does |
|---|---|
| `nvme_snapshot` | Shows the rates and counters of the subsystems, namespaces, paths and controllers over an interval, as `nvme top` prints them. |
| `nvme_path_health` | Shows each path with its share of the I/O, its latency, and the transport and address of its controller. Flags problems (see below). |
| `nvme_watch` | Samples for up to 10 minutes and reports what changed, with the time it was seen. |
| `nvme_set_iopolicy` | Sets the I/O policy of a subsystem. Only with `--allow-iopolicy`. |
| `nvme_compare_iopolicies` | Measures a subsystem under each I/O policy in turn. Then it restores the old policy. Only with `--allow-iopolicy`. |

Each tool takes an optional `subsystem`, for example `nvme-subsys0`. Without
it, the tool reports all subsystems.

A call samples for `interval` seconds, so it takes that long. The default is 2
seconds. `nvme_watch` takes `duration` seconds. The default is 30 seconds.

### nvme_path_health

`nvme_path_health` flags a path when:

- Its ANA state is not optimized.
- Its latency is much higher than the latency of its sibling paths.
- Its share of the I/O is uneven, with the `round-robin` or `queue-depth`
  policy.
- Its retry, failover or error count went up since the previous call.

It also reports namespaces without an optimized path, and controllers that are
not live.

### nvme_watch

`nvme_watch` samples back to back and reports:

- Changes of the controller state and the ANA state.
- Paths that stop or start to carry I/O.
- Controllers, paths and namespaces that go away or appear.
- Counters that go up.
- Stalls: periods in which a namespace had no I/O after it had a load.
- For each path: its transport, address, average IOPS and the seconds
  without I/O.
- The kernel log lines about nvme.

The times are seconds from the start. `Started` is the wall clock time of the
start. Use it to compare the times with other tools.

To see a failover, start `nvme_watch` first. Then cause the failover while it
runs, for example from a parallel tool call.

### nvme_compare_iopolicies

`nvme_compare_iopolicies` sets each policy (`numa`, `round-robin`,
`queue-depth`) in turn. It waits `settle` seconds (default 2) and measures for
`interval` seconds (default 10). A workload must run during the whole call,
because nvme-mcp does not create I/O. Start it before, for example with fio.

## Examples

Ask the agent questions like these:

- "Are all paths of nvme-subsys0 healthy?"
- "Watch the I/O for 60 seconds while I disable the port on the target. What
  happened?"
- "fio is running against nvme-subsys1. Which I/O policy gives the best
  throughput?"

## See also

- [NVMe-oF Multipath and ANA](multipath-ana.md)
- [nvme-mcp README](https://github.com/linux-nvme/nvme-cli/blob/master/scripts/mcp/README.md)
- [`nvme-top(1)`](man:nvme-top)
