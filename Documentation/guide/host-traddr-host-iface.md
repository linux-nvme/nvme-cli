<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Using `--host-traddr` and `--host-iface` when connecting to an NVMe-oF target

When connecting to an NVMe-oF target, three parameters are relevant to address
and interface selection:

- `--traddr` (`-a`): the **target transport address**. This is the address
  of the controller to connect to.
- `--host-traddr` (`-w`): the **host transport address**. This is the local
  address that the connection starts from.
- `--host-iface` (`-f`): the **host network interface**, by name. The
  connection uses this interface, whatever the routing table would choose.

Their meaning and necessity depend on the transport. The sections below cover
TCP, RDMA, and Fibre Channel.

---

## TCP

### Default behaviour (neither --host-traddr nor --host-iface specified)

The kernel's routing table selects both the outgoing interface and the source
address based on the destination address (`--traddr`). This is the normal case
for most setups.

### `--host-iface`

Sets `SO_BINDTODEVICE` on the socket before connecting. This forces the
connection to use a specific network interface, **bypassing the routing table's
interface selection entirely**.

Use this when:
- Multiple interfaces can reach the target and you want to pin to a specific one
- You need to use a specific interface for IPv4 or IPv6

```bash
# Force connection through eth1
nvme connect -t tcp -a 192.168.1.10 -s 4420 --host-iface=eth1 -n <nqn>
```

**`--host-iface` does not set the source address.** Unless `--host-traddr` is
also specified, the kernel assigns the source address automatically from the
bound interface.

### `--host-traddr`

Calls `bind()` on the socket before connecting, pinning the **source IP
address** of the connection.

A network interface can be assigned more than one IP address. There is typically
one primary address, which is what the kernel uses as the source address for
outgoing connections by default. Additional secondary addresses can also be
assigned to the same interface. To originate a connection from one of those
secondary addresses rather than the primary, `--host-traddr` must be specified
explicitly.

Reasons to use a secondary address as the source:
- **Target-side access control**: the target controller may be configured with
  an allow-list of initiator source addresses; if only a secondary address is on
  that list, `--host-traddr` is required
- **Policy-based routing**: some networks route traffic differently depending on
  the source address, allowing finer-grained path control
- **High availability**: floating/virtual IP addresses can be secondary
  addresses that move between hosts; originating from such an address ensures
  the target always sees the same initiator IP regardless of which physical host
  is active

```bash
# Originate from a specific local address
nvme connect -t tcp -a 192.168.1.10 -s 4420 --host-traddr=192.168.1.100 -n <nqn>
```

**`--host-traddr` does not affect interface selection for TCP.** The interface
is still chosen by the routing table (or by `--host-iface` if also specified).

### Combining both

Both options can be specified together and are independent:

```bash
# Force interface eth1 AND originate from a specific source address
nvme connect -t tcp -a 192.168.1.10 -s 4420 \
    --host-iface=eth1 --host-traddr=192.168.1.100 -n <nqn>
```

### IPv4 vs IPv6: interface selection

For **IPv4**, `--host-iface` is the only way to force a specific interface.
There is no address-level mechanism to encode interface information in an IPv4
address.

For **IPv6**, there are two ways to specify the interface for link-local
addresses:

1. `--host-iface` (recommended):
```bash
nvme connect -t tcp -a fe80::abcd:1234 -s 4420 --host-iface=eth0 -n <nqn>
```

2. A scoped address in `--traddr` using the `address%interface` notation defined
   by [RFC 4007](https://datatracker.ietf.org/doc/html/rfc4007):
```bash
nvme connect -t tcp -a fe80::abcd:1234%eth0 -s 4420 -n <nqn>
```

Scoped addresses are **not recommended** due to limited testing across the full
kernel and userspace stack. `--host-iface` is better validated and works for
both IPv4 and IPv6, making it the more portable choice.

---

## RDMA

### Default behaviour (neither option specified)

The RDMA Connection Manager (CM) resolves the destination address (`--traddr`)
using the kernel routing table and automatically selects the RDMA device and
source address. This works for most single-HCA setups.

### `--host-iface`

**Not supported for RDMA.** Specifying `--host-iface` with `-t rdma` is
rejected.

### `--host-traddr`

Optional for RDMA. When specified, it is passed as the source address to
`rdma_resolve_addr()`. The RDMA CM uses this address both to set the source
address of the connection **and** to select the RDMA device. RDMA selects the
device by address, not by interface name.

Use this when:
- Multiple RDMA HCAs are present and you need to control which one is used
- The RDMA CM's automatic device selection picks the wrong device

```bash
# Force use of the RDMA HCA that owns 192.168.2.100
nvme connect -t rdma -a 192.168.2.10 -s 4420 --host-traddr=192.168.2.100 -n <nqn>
```

> **Note:** Unlike TCP, RDMA does not separate the source address from the
> interface selection. `--host-traddr` controls both.

---

## Fibre Channel

### `--host-traddr` (mandatory)

For Fibre Channel, `--host-traddr` is **required**. It specifies the local FC
port (Node Name and Port Name) that the connection should originate from. The
kernel driver uses it to look up the matching local FC port from the registered
port list.

Both `--traddr` (remote target port) and `--host-traddr` (local host port) use
the FC address format `nn-<WWNN>:pn-<WWPN>`:

```bash
nvme connect -t fc \
    -a nn-0x200400110011bb11:pn-0x200500110011bb11 \
    -w nn-0x200400110011cc22:pn-0x200500110011cc22 \
    -n <nqn>
```

### `--host-iface`

**Not supported for Fibre Channel.**

---

## Summary

| Parameter | TCP | RDMA | Fibre Channel |
|-----------|-----|------|---------------|
| `--host-iface` | Optional — forces interface via `SO_BINDTODEVICE` | Not supported | Not supported |
| `--host-traddr` | Optional — sets source IP only; does not affect interface selection | Optional — sets source address and selects RDMA device | **Mandatory** — identifies the local FC port |
| Default (neither) | Routing table selects interface and source address | RDMA CM selects device and source address via routing | N/A — connection fails without `--host-traddr` |
