# nvme-mcp

An [MCP](https://modelcontextprotocol.io) server which lets an agent watch
the I/O of the NVMe subsystems of a host: which path carries how much I/O,
which one is slow, has errors or is not optimized, and how the multipath
I/O policies compare under a workload.

It reads `nvme top --output-format=json`, see nvme-top(1). It needs Python
3.10 or newer and nothing beyond its standard library, and runs from the
source tree. Like nvme top, it has to run as root.

## Tools

| Tool | What it does |
| --- | --- |
| `nvme_snapshot` | The rates and counters of the subsystems, namespaces, paths and controllers over an interval, as nvme top prints them |
| `nvme_path_health` | Each path with its I/O share and latency, and the transport and address of its controller, flagged when its ANA state is not optimized, its latency is an outlier among its siblings, its share is uneven under round-robin or queue-depth, or its retry, failover or error count went up since the previous call. Also namespaces without an optimized path and controllers which are not live |
| `nvme_watch` | Samples back to back for up to 10 minutes and reports what changed, with the second it was seen: controller and ANA states, paths which stopped or started to carry I/O, controllers, paths and namespaces which went away or appeared, and rising counters, once for a run of rises. Also the stalls, the periods a namespace had no I/O after it had a load (I/O in 3 samples in a row), and per path its transport, address, average IOPS and the seconds it had no I/O, and the kernel log lines about nvme with the time they were seen, repeated ones once with a count. Times are seconds from the start; `Started` is the wall clock time of the start, to line them up with other tools |
| `nvme_set_iopolicy` | Sets the I/O policy of a subsystem (only with `--allow-iopolicy`) |
| `nvme_compare_iopolicies` | Measures a subsystem under each I/O policy in turn and restores its policy (only with `--allow-iopolicy`) |

A call samples for `interval` seconds, so it takes that long, and
`nvme_watch` for `duration` seconds. To see a failover, start it while
`nvme_watch` runs, e.g. from a parallel tool call. The tools start no
I/O: to compare the I/O policies, run a workload, e.g. with fio, during
the whole call.

## Use

With Claude Code, for example:

```
claude mcp add nvme -- sudo /path/to/nvme-cli/scripts/mcp/nvme-mcp
claude mcp add nvme -- sudo /path/to/nvme-cli/scripts/mcp/nvme-mcp \
    --allow-iopolicy --nvme /path/to/build/nvme
```

`--nvme` picks the nvme binary, which needs `nvme top -o json`.

## Development

```
python3 -m unittest discover -s tests   # or: meson test -C BUILD nvme-mcp
ruff check . && ruff format --check . && mypy
                                        # or: meson compile -C BUILD lint-mcp-tool
```
