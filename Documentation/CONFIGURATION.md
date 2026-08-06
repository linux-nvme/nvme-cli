<!-- SPDX-License-Identifier: GPL-2.0-only -->
# Configuration

nvme-cli and libnvme use a handful of files under `/etc/nvme` and `/run/nvme`
to coordinate host identity, saved NVMe-oF connections, and shared state
between independent tools on the same host.

## NVMe-oF connection configuration

Which NVMe-oF controllers `nvme connect-all` / `nvme discover` should use is
stored in an INI-format file, `/etc/nvme/nvme-fabrics.conf`, with an optional
drop-in directory `/etc/nvme/nvme-fabrics.conf.d/` for hosts that present
multiple identities. This format, and the precedence rules for merging the
main file with drop-ins, are documented in
[libnvme/design/CONFIG.md](../libnvme/design/CONFIG.md).

Older releases (pre-3.0) stored this configuration as `/etc/nvme/config.json`
(JSON) or `/etc/nvme/discovery.conf` (argv-style). These formats are no
longer read by libnvme directly; convert them once with:

```shell
$ nvme config-convert
```

See `man nvme-config-convert` for details.

## Host identity

The default host NQN and host identifier are read from `/etc/nvme/hostnqn`
and `/etc/nvme/hostid`. A host presenting multiple personalities can instead
declare identity per drop-in file in `nvme-fabrics.conf.d/` — see
[libnvme/design/CONFIG.md](../libnvme/design/CONFIG.md).

## Coordinating multiple orchestrators on one host

NVMe-oF connections on a host are often managed by more than one independent
actor at once — the initramfs (NBFT/FC-kickstart boot connections), a human
running `nvme connect-all` / `nvme disconnect-all`, and daemons such as
`nvme-discoverd` or `nvme-stas`. Two runtime mechanisms let them cooperate
without stepping on each other:

- **Ownership registry** (`/run/nvme/registry/`): records which orchestrator
  owns each connected controller, so a sweeping command like
  `nvme disconnect-all` can avoid tearing down a connection another
  component depends on. This is per-boot runtime state written automatically
  by libnvme on connect. See [libnvme/design/REGISTRY.md](../libnvme/design/REGISTRY.md).
- **Exclusion list** (`/etc/nvme/exclusions.conf`, with an optional
  `/etc/nvme/exclusions.conf.d/`): a persistent, administrator-authored list
  of controllers that no orchestrator may auto-connect, useful for taking a
  path out of service (e.g. during maintenance or testing) regardless of
  which orchestrator would otherwise reconnect it. Manage it with the
  `nvme exclusion-*` commands or the `nvme disconnect --exclude` shortcut.
  See [libnvme/design/EXCLUSIONS.md](../libnvme/design/EXCLUSIONS.md).

Both are cooperative mechanisms, not enforcement: every orchestrator runs as
root and could bypass them, but well-behaved tools consult them first.
