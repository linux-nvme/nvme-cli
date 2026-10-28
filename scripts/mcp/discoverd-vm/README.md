# discoverd-vm-mcp

An [MCP](https://modelcontextprotocol.io) server which lets an agent test,
in a VM, what a system shutdown does to the nvme-discoverd connection
units and the file systems mounted on them: when systemd stops a unit,
and whether its `ExecStop=` disconnects a controller that is still
mounted. The VM is a Fedora VM with a loopback nvme-tcp target, XFS on
the namespace, and nvme-discoverd connecting it.
Each scenario mounts the file system in a given way, leaves dirty data,
reboots or stops the connection unit, and compares what the VM logged
with what the scenario expects.

It is built like nvme-mcp in `..`: Python 3.11 or newer, nothing beyond
the standard library, and the tools which change the VM only with
`--allow-changes`. It runs from the source tree.

## Tools

| Tool | What it does |
| --- | --- |
| `vm_status` | Whether the VM runs and answers ssh, its kernel and systemd, the nvme-cli source it was built from, whether nvme-discoverd is active, the NVMe controllers, the connection units, and the mounts of NVMe devices |
| `list_scenarios` | The scenarios in `scenarios/`, with what each expects |
| `shutdown_log` | The shutdown lines of the previous boot and their analysis |
| `vm_create` | Builds the VM from scratch, see below (only with `--allow-changes`) |
| `vm_start`, `vm_stop` | Start the VM and wait for ssh, power it off (only with `--allow-changes`) |
| `vm_sync_build` | Copies the local nvme-cli tree to the VM, builds and installs it, and recreates the connection units so they use the new build (only with `--allow-changes`) |
| `run_scenario` | Resets the VM, creates a new XFS, mounts it as the scenario says, writes dirty data, reboots or stops the connection unit, and compares the result with the scenario's `[expect]` (only with `--allow-changes`) |

Connection units are transient: they keep the `ExecStop=` of the build
that created them. Restarting nvme-discoverd does not change them, so
`vm_sync_build` and every scenario stop them and let nvme-discoverd
create them again.

## The VM

`vm_create` builds the VM in the VM directory (`--vm-dir`, default
`~/.local/share/discoverd-vm`):

1. Downloads the Fedora Cloud image and checks its SHA-256 (once).
2. Creates an ssh key, a cloud-init seed with a user `test` (sudo, the
   key) and the build dependencies, and a qcow2 disk on top of the image.
3. Boots it with KVM. ssh is forwarded to `127.0.0.1:2222` (`--port`).
4. Copies the nvme-cli tree (`--source`) to `/root/nvme-cli`, builds and
   installs it, sets up the loopback target, and lets nvme-discoverd
   connect it.

The host needs `qemu-system-x86_64`, `qemu-img`, `xorriso` or
`genisoimage`, `ssh`, `rsync`, and access to `/dev/kvm`. The first
`vm_create` takes about ten minutes, mostly the download and the package
installs.

The VM reports `nvme version ... (git ...)` without the real commit,
because the copy has no `.git`. `vm_sync_build` records the
`git describe` of the local tree in the VM, and `vm_status` shows it as
`source`.

## Scenarios

A scenario is a TOML file in `scenarios/`:

```toml
description = "..."
action = "reboot"          # or "stop-unit": stop the unit at runtime

[build]
stop_unit = true           # the VM must run a build whose ExecStop= runs
                           # nvme-discoverd --stop-unit; false: a build
                           # without it; omit: any build

[setup]
mount = "root-like"        # a mount unit systemd never stops (like
                           # root), or "netdev", or "nofail" (fstab)
dirty_mb = 200             # dirty data left for the shutdown
netem_delay_ms = 30        # delay on lo, so the flush takes time

[expect]
disconnect = "skipped"     # skipped, after-unmount, while-mounted,
                           # done (stop-unit), none
log_recovery = false       # checked after the reboot
data_intact = true
```

Only the log lines after the scenario's start marker count: the setup
unmounts and reconnects too.

## Use

With Claude Code, for example:

```
claude mcp add discoverd-vm -- /path/to/nvme-cli/scripts/mcp/discoverd-vm/discoverd-vm-mcp \
    --source /path/to/nvme-cli --allow-changes
```

Then ask for the VM to be created, and for a scenario to be run.

## Development

```
python3 -m unittest discover -s tests   # or: meson test -C BUILD discoverd-vm-mcp
ruff check . && ruff format --check .   # or: meson compile -C BUILD lint-discoverd-vm-mcp
```
