<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# How to connect to a target

This page shows how to connect a host to an NVMe over Fabrics (NVMe-oF)
target with nvme-cli 3.x. It covers TCP and RDMA. For Fibre Channel, see [How
to connect over Fibre Channel](fibre-channel.md).

All commands on this page need root.

## Before you start

You need:

- The address of the target, for example `192.168.1.10`.
- The transport: `tcp` or `rdma`.
- The host NQN. This is the identity of the host. The target uses it to
  decide which subsystems the host may see.

Load the kernel module of the transport:

```bash
modprobe nvme-tcp      # or: modprobe nvme-rdma
```

nvme-cli reads the host NQN from `/etc/nvme/hostnqn` and the host ID from
`/etc/nvme/hostid`. A distribution package usually creates these files. If
they are missing, create them:

```bash
nvme gen-hostnqn > /etc/nvme/hostnqn
```

Since nvme-cli 3.1, `nvme gen-hostnqn` must run as root.

Give the host NQN to the administrator of the target. The target must allow
this NQN.

## Step 1: Discover the subsystems

A Discovery Controller lists the subsystems that the host may connect to.
Ask it with `nvme discover`:

```bash
nvme discover --transport=tcp --traddr=192.168.1.10
```

Without `--trsvcid`, nvme-cli uses port 8009 for a TCP Discovery Controller
and port 4420 for RDMA.

The output has one entry for each subsystem port. Each entry shows the
transport (`trtype`), the address (`traddr`), the port (`trsvcid`) and the
NQN of the subsystem (`subnqn`):

```
=====Discovery Log Entry 1======
trtype  : tcp
adrfam  : ipv4
subtype : nvme subsystem
treq    : not specified, sq flow control disable supported
portid  : 2
trsvcid : 8009
subnqn  : nqn.2024-01.com.example:storage.vol1
traddr  : 192.168.1.10
eflags  : none
sectype : none
```

The Linux target (nvmet) lists only the subsystems of the port that received
the discovery request. In this example, this is port 8009. `nvme connect-all`
then connects the subsystem on port 8009 too.

Since nvme-cli 3.2, `nvme discover` keeps the connection to the Discovery
Controller when the target supports it. See [NVMe-oF Persistent Discovery
Controllers](pdc.md). Use `--persistent=no`
to disconnect it after the discovery.

## Step 2: Connect

There are two ways to connect.

**Connect to everything the Discovery Controller lists.** `nvme connect-all`
discovers and connects in one step:

```bash
nvme connect-all --transport=tcp --traddr=192.168.1.10
```

**Connect to one subsystem.** Use the values from the discovery output:

```bash
nvme connect --transport=tcp --traddr=192.168.1.10 --trsvcid=4420 \
    --nqn=nqn.2024-01.com.example:storage.vol1
```

Without `--trsvcid`, `nvme connect` uses port 4420.

To connect to a Discovery Controller with a unique NQN, add `--discovery`
(since 3.2). Without this option, the kernel treats such a controller as an
I/O controller.

## Step 3: Check the connection

```bash
nvme list-subsys
nvme list
```

`nvme list-subsys` shows each subsystem with its controllers and their state.
A working controller has the state `live`. `nvme list` shows the namespaces.
They are block devices, for example `/dev/nvme1n1`.

Do not use the `/dev/nvmeXnY` names in scripts or in `/etc/fstab`. They can
change after a reboot or a reconnect. Use the names in `/dev/disk/by-id/`
instead. See the [FAQ](faq.md).

If you mount a file system from an NVMe-oF namespace, add the `_netdev`
option in `/etc/fstab`.

## Step 4: Disconnect

Disconnect one controller by its name:

```bash
nvme disconnect --device=nvme1
```

Disconnect all controllers of a subsystem:

```bash
nvme disconnect --nqn=nqn.2024-01.com.example:storage.vol1
```

`nvme disconnect-all` disconnects only the controllers without an owner in
the [ownership registry](registry-exclusions.md). A
controller that nvme-discoverd or nvme-stas manages has an owner. Because of
this, `disconnect-all` does not remove it.

## Options you may need

| Option | Use |
|---|---|
| `--trsvcid=<port>` | The port, if the target does not use the default. |
| `--hostnqn=<nqn>`, `--hostid=<id>` | Use another host identity than the one in `/etc/nvme/`. |
| `--host-iface=<iface>` | Connect through this network interface. TCP only. |
| `--host-traddr=<addr>` | Use this source address. |
| `--nr-io-queues=<n>` | The number of I/O queues. |
| `--ctrl-loss-tmo=<s>` | How long the kernel tries to reconnect a lost controller. |
| `--tls` | Use TLS. TCP only. See [How to set up TLS for NVMe over TCP](tls.md). |
| `--kxchap-secret=<secret>` | Use in-band authentication. See [How to set up inband authentication](inband-auth.md). |

Since nvme-cli 3.2, `nvme connect` over TCP without `--nr-io-queues` creates
one I/O queue for each queue of the network interface, but not more than the
number of online CPUs. The interface is the one of `--host-iface`, or else
the one of the route to the target. If the interface has only one queue, or
nvme-cli cannot read the number of queues, the kernel default applies.

Since nvme-cli 3.2, every long option needs its full name, for example
`--nqn`, not `--nq`. See [Breaking changes](breaking-changes.md).

## IPv6

Give an IPv6 address as it is:

```bash
nvme connect --transport=tcp --traddr=2001:db8::10 \
    --nqn=nqn.2024-01.com.example:storage.vol1
```

A link-local address (`fe80::...`) is valid only on one link. Add the
interface to the address as a scope, as defined in
[RFC 4007](https://datatracker.ietf.org/doc/html/rfc4007):

```bash
nvme connect --transport=rdma --traddr=fe80::20c:caff:fe12:2a0c%enp129s0f0np0 \
    --nqn=nqn.2024-01.com.example:storage.vol1
```

For TCP, you can use `--host-iface` instead of the scope. For RDMA, use the
scope. RDMA does not support `--host-iface`. Do not use `--host-traddr` with
RDMA over IPv6.

Since nvme-cli 3.2, `nvme discover` and `nvme connect-all` add the scope of
the Discovery Controller to the link-local addresses in its discovery log
page. In 3.0 and 3.1, these addresses had no scope. On a host with more than
one link, the connection could then use the wrong link.

See [Using the host-traddr and host-iface
options](host-traddr-host-iface.md) for the details of
`--host-iface` and `--host-traddr`.

## Make the connection permanent

The commands on this page connect until the next reboot. To connect at every
boot, write the connection into `/etc/nvme/nvme-fabrics.conf`, then let the
autoconnect connect it:

- [How to configure NVMe-oF connections](fabrics-config.md)
- [How to set up NVMe-oF autoconnect](autoconnect.md)

## See also

- [NVMe-oF Multipath and ANA](multipath-ana.md)
- [Troubleshooting](troubleshooting.md)
- [`nvme-discover(1)`](man:nvme-discover), [`nvme-connect(1)`](man:nvme-connect), [`nvme-connect-all(1)`](man:nvme-connect-all),
  [`nvme-disconnect(1)`](man:nvme-disconnect)
