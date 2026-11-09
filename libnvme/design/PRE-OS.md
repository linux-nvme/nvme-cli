# The pre-OS environment and the OS environment

A host that boots from NVMe-oF has its root file system on connections
that exist before the operating system runs. This document describes
how those connections are handed from the environment that sets them up
to the one that runs from them, without either disconnecting what the
other depends on.

> The code is the source of truth. This document summarizes behavior and
> intent; see nvme-discoverd(8), nvme-connect-all(1), nvme-disconnect(1),
> `REGISTRY.md`, and the scenarios in `discoverd/tests/test_handover.py`.

## Terms

- **The pre-OS environment**: everything that runs before the real root,
  the firmware (UEFI, the NBFT it writes) and the initrd (dracut and the
  `nvme` it runs). NBFT and initrd are technologies; the environment is
  what matters.
- **The OS environment**: the real root after the switch, with systemd
  and nvme-discoverd.

## The rule

**The context that connects a controller owns it.** There is no
hand-over of ownership. The pre-OS environment owns what it connects,
and the OS environment keeps those connections connected, but never
owns or disconnects them.

One exception: **pre-OS discovery controllers**. They carry no file
system, and nvme-discoverd disconnects them like its own: it parks one
for EPCSD=0, and its unit disconnects it when it stops, also at the
shutdown. The pre-OS environment disconnected a discovery controller
without persistence too. The I/O controllers are never disconnected.

The owner is recorded in the registry (`REGISTRY.md`) as **`pre-os`**.
Its old name **`nbft`**, which nvme-cli 3.0 to 3.2 record for
`connect-all --nbft`, is the same owner: `libnvme_set_owner()` records
`nbft` as `pre-os`, and `libnvmf_owner_equal()` and
`libnvmf_registry_attr_equal()` match the two.

Every pre-OS connection is treated alike, whether it carries the root
file system or not: the NBFT can list non-bootable namespaces, and a
configured connection can be anything. They cannot be told apart when
they are connected.

## In the pre-OS environment

dracut's nvmf module runs every `nvme connect-all` with
`--owner=pre-os`, when nvme follows this model (its help of `--owner`
names `pre-os`). `connect-all --nbft` defaults to that owner itself.

With the owner `pre-os`, nvme

- connects with **`ctrl_loss_tmo=-1`** unless one is given, so that the
  kernel never gives a path up (libnvme, for every connect: the NBFT,
  the configuration, the I/O controllers of a discovery log page, and
  the reconnects of nvme-discoverd). This holds for every pre-OS path,
  also a non-bootable NBFT namespace without multipath: on TCP and
  RDMA, I/O to it blocks for good when its target is gone for good.
  On FC, `ctrl_loss_tmo` has no effect after `dev_loss_tmo`: the kernel
  deletes the controller, and only nvme-discoverd brings the path back
  (see below). With `pre-os = false`, or without nvme-discoverd, a lost
  FC path stays lost until the next boot. Known limitation: libnvme
  can't tell an explicit `ctrl_loss_tmo=600` from the default, so it
  becomes -1 too, as for the defaults of `vendor.d`;
- **records each connection it is asked for** in
  `RUNDIR/nvme/pre-os.conf.d/`, before it connects, so that a path that
  fails to connect is known too. `/run` moves to the real root.

The record:

- is in the format of nvme-fabrics.conf(5), so that nvme-discoverd reads
  it with `libnvmf_config_read()`;
- has one drop-in per host (the format allows one host per file), named
  after the host, with all its connections; nvme updates it under a
  lock on the directory, as several `nvme` can run at once in the initrd
  (FC discovery events, autoconnect);
- lists what was asked for: a discovery controller, not the controllers
  its log page lists (nvme-discoverd learns those from it);
- carries **no credentials**: no KX-HMAC-CHAP secrets and no inline TLS
  key. The pre-OS environment loads its keys into the kernel's keyring;
  in the OS environment, nvme-keysd does;
- is only written in the initrd (`/etc/initrd-release`, os-release(5)):
  nvme-discoverd reconnects these paths with the same owner and must not
  add to it.

The NBFT is still there after the switch, so its connections are not
recorded.

## In the OS environment

nvme-discoverd (with `pre-os = true`, the default; `nbft` is the old
name of the key) treats as **pre-OS connections**: the NBFT's, those in
`pre-os.conf`, and what the log page of a pre-OS discovery controller
lists. For them:

- It tracks them with its normal code: a lost path, or one the pre-OS
  environment could not connect, is connected again with retries, also
  over a restart of the daemon.
- It connects them with **`--owner=pre-os`** and with the parameters of
  `pre-os.conf`, which win over the configuration's. What a pre-OS
  discovery controller lists gets the parameters of that controller's
  entry, as `connect-all` gave its options to everything it connected.
- The units of pre-OS **I/O controllers have no `ExecStop=`**: nothing
  in the OS environment disconnects them, also not at the shutdown. The
  units of pre-OS discovery controllers do disconnect: a discovery
  controller carries no file system, and one without persistence is
  parked for EPCSD=0, as the pre-OS environment disconnected it too.
- The **exclusion list does not apply** to them.
- A controller with the owner `pre-os` that is no pre-OS connection it
  knows of is left alone, like one of any other owner.

With `pre-os = false`, nvme-discoverd leaves all of them alone.

FC needs nvme-discoverd most: the kernel deletes an FC controller after
`dev_loss_tmo`, whatever `ctrl_loss_tmo` says. nvme-discoverd then issues
an FC kickstart and reads the log page of the discovery controller
again, which connects the path back.

`nvme disconnect` and `nvme disconnect-all` honor the owner too: an
owned controller is disconnected only for `--owner` of its owner, or
with `--force`.

## The shutdown

Nothing in the OS environment disconnects a pre-OS controller. The root
file system cannot be unmounted while the system runs from it; the
kernel keeps the connection until the end.

dracut's nvmf module asks for the shutdown initramfs when the initrd
connected pre-OS controllers (`need_shutdown`). systemd switches back to
it at the end of the shutdown, the old root is unmounted there, and the
module's shutdown hook disconnects the pre-OS controllers: the target
sees a clean shutdown instead of waiting for the keep-alive timeout.
Without the shutdown initramfs, the power-off ends the connections.

File systems on NVMe-oF that are mounted in the OS environment need
`_netdev`: systemd orders only those before the network goes down and
before nvme-discoverd's units disconnect. A mount without `_netdev` is
not supported.

## Older initrds

| initrd | records | the OS environment |
|---|---|---|
| nvme-cli 2 | no owner | the NBFT paths are still pre-OS connections (from the NBFT) |
| nvme-cli 3.0 to 3.2 | `nbft` for `--nbft` | the same owner as `pre-os` |
| dracut without `--owner=pre-os` | no owner for FC and configured connections | nvme-discoverd adopts them as its own and disconnects them at the shutdown |

The last row is the case to watch on an upgrade: a new nvme-cli in the
real root with an initrd built by a dracut that doesn't pass
`--owner=pre-os`. An FC or configured root is adopted by nvme-discoverd
and disconnected at the shutdown, as before this model. Update dracut
and rebuild the initrd together with nvme-cli.

## Tests

- `discoverd/tests/test_handover.py`: the pre-OS environment with the
  real `nvme` under the fabrics mock, the switch to the real root, and
  nvme-discoverd in a sandbox: adoption, loss, a path that failed at
  boot, restart, reload, exclusions, FC, the shutdown.
- `tests/cli/nvme_fabrics_mock_test.py`: the owner, `ctrl_loss_tmo`,
  the record, the disconnect.
- nvme-lab's hand-over scenarios boot a Debian root from NVMe/TCP (one
  and two paths) and over NVMe/FC (nvme-fcloop) through dracut, with
  nvme-discoverd, and check the shutdown.
