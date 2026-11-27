<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# How to connect to a target over Fibre Channel

Fibre Channel (FC) is one of the transports `nvme connect` supports. Addressing
works differently from TCP and RDMA: there is no IP address, and you must give
your own host's address explicitly.

This page is a worked example. For the general rules on `--traddr` and
`--host-traddr`, see
[Using `--host-traddr` and `--host-iface`](host-traddr-host-iface.md).

## Requirements

- An FC host bus adapter (HBA) with a driver that supports FC-NVMe (for example
  `lpfc` or `qla2xxx`).
- The kernel's `nvme_fc` module.
- Fabric zoning that lets your host port see the target port. This is the same
  zoning an FC-SCSI setup needs; nvme-cli plays no part in it.

## Addressing

Both `--traddr` (the target) and `--host-traddr` (your host) use the same
format:

```
nn-<Node WWN>:pn-<Port WWN>
```

`--host-traddr` is **mandatory** for FC. There is no default, and `--host-iface`
is not supported for FC.

## Find your host port's address

Read the World Wide Node Name (WWNN) and World Wide Port Name (WWPN) from sysfs.
Each local FC host adapter port has its own `hostN` entry:

```bash
$ cat /sys/class/fc_host/host0/node_name
0x200400110011cc22
$ cat /sys/class/fc_host/host0/port_name
0x200500110011cc22
```

These two values become your `--host-traddr`:
`nn-0x200400110011cc22:pn-0x200500110011cc22`.

If more than one HBA port is present, check each `/sys/class/fc_host/hostN/` in
turn to find the one connected to your target's fabric.

## Discover

```bash
nvme discover -t fc \
    -a nn-0x200400110011bb11:pn-0x200500110011bb11 \
    -w nn-0x200400110011cc22:pn-0x200500110011cc22
```

`-a` is the target's Discovery Controller address; `-w` is your host port from
the previous step. An empty result is usually a zoning problem, not an
nvme-cli problem. First check that the target is visible to this host port.
Use the tools of your FC switch or the configuration of the target (for
example `nvmetcli`).

## Connect

```bash
nvme connect -t fc \
    -a nn-0x200400110011bb11:pn-0x200500110011bb11 \
    -w nn-0x200400110011cc22:pn-0x200500110011cc22 \
    -n nqn.2014-08.com.example:nvme.1
```

## Persisting the connection

Add the same entry to `nvme-fabrics.conf` with `nvme config create`, so `nvme
connect-all` reconnects it later:

```bash
nvme config create --transport fc \
    --traddr=nn-0x200400110011bb11:pn-0x200500110011bb11 \
    --host-traddr=nn-0x200400110011cc22:pn-0x200500110011cc22 \
    --hostnqn=nqn.2014-08.org.nvmexpress:uuid:62a4ab74-1e18-11f1-8bb7-6c1ff71ba506 \
    --discovery
```

See [How to configure NVMe-oF connections](fabrics-config.md)
for the full format.

## Connecting automatically at boot

FC discovery events can trigger autoconnect on their own, without a config file.
See the "Fibre Channel boot" section of
[How to set up NVMe-oF autoconnect](autoconnect.md).
