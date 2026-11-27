<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# NVMe-oF ownership registry and exclusion list

Several tools can connect NVMe-oF controllers on one host: the initramfs
(NBFT boot connections), an administrator with `nvme connect-all`,
nvme-discoverd and nvme-stas. These tools are called orchestrators. Since
nvme-cli 3.0, two mechanisms help them share a host:

| | Ownership registry | Exclusion list |
|---|---|---|
| Question | Who owns this controller? | May a tool connect this controller? |
| Prevents | an accidental disconnect | an accidental connect |
| Location | `/run/nvme/registry/` (lost at reboot) | `/etc/nvme/exclusions.conf` (persistent) |
| Written by | libnvme, when it connects a controller | the administrator |
| Used by | `nvme disconnect-all` | every orchestrator, before it connects |

Both are cooperative. They are not access control. Every orchestrator runs as
root and could ignore them. They only let well-behaved tools avoid mistakes.

Both mechanisms apply only to fabrics controllers. Local PCIe controllers are
never affected.

## Ownership registry

### Why

`nvme disconnect-all` acts on the whole host. Without the registry, it also
disconnects a boot volume from NBFT, or a controller that a daemon manages.
See [issue #2913](https://github.com/linux-nvme/nvme-cli/issues/2913).

### How it works

libnvme records the owner of a controller when it connects it. The owner is a
name, for example `nbft`, `discoverd` or `stas`. The registry has one
directory for each owned controller:

```
/run/nvme/registry/
    nvme0/
        owner      # the owner name, for example "lab"
        seqnum     # internal, used for the cleanup
```

A controller without an entry has no owner. A udev rule removes the entry when
the kernel removes the controller.

### Set the owner

Use `--owner` with `connect`, `connect-all` or `discover`:

```bash
nvme connect --transport=tcp --traddr=192.168.30.30 \
    --nqn=nqn.2024-01.com.example:storage.vol1 --owner=lab
```

- Without `--owner`, a new controller has no owner. An existing controller
  keeps its owner.
- `nvme connect-all --nbft` sets the owner `nbft`. `--owner` overrides it.
- `--owner=` (empty) removes the owner.

### Show the registry

```
# nvme registry list
nvme0
  owner        lab
  seqnum       4093
```

`nvme list -v` shows the owner in the `Orchestrator` column. `-` means no
owner. `kernel` means a PCIe controller.

```
Device           Orchestrator Cntlid SN                   MN       ...
---------------- ------------ ------ -------------------- -------- ...
nvme0            lab          1      35efdb862d80bcb0fa47 Linux    ...
nvme1            -            2      35efdb862d80bcb0fa47 Linux    ...
```

`nvme registry update` and `nvme registry delete` change an entry. They ask
for a confirmation before they change or remove an owner.

### disconnect-all

| Command | Disconnects |
|---|---|
| `nvme disconnect-all` | only fabrics controllers without an owner |
| `nvme disconnect-all --owner=NAME` | only fabrics controllers of the owner `NAME` |
| `nvme disconnect-all --force` | all fabrics controllers |

`--owner` and `--force` ask for `yes` on a terminal. In a script, they do not
ask.

`nvme disconnect --device=nvme0` and `nvme disconnect --nqn=...` always
disconnect. They name the controller, so the intent is clear.

In nvme-cli 2.x, `nvme disconnect-all` disconnected all fabrics controllers.
Use `--force` to get this behavior.

## Exclusion list

### Why

Sometimes a controller must stay disconnected: it is in maintenance, the
target misbehaves, or the path belongs to another host. But orchestrators
connect everything they discover. The connection often comes from a source
the administrator cannot edit on the host: the NBFT in the firmware, the
discovery log page of a target, or mDNS. The exclusion list is the one place
on the host to say "do not connect this".

### The file

The default list is `/etc/nvme/exclusions.conf`. Named lists are drop-in
files in `/etc/nvme/exclusions.conf.d/`. A controller is excluded if any entry
of any list matches.

```ini
[exclusions]
exclusion = nqn=nqn.2024-01.com.example:storage.vol1;traddr=192.168.30.30
exclusion = nqn=nqn.2024-01.com.example:retired
exclusion = host-iface=eth3
```

An entry is a list of `key=value` fields, separated by `;`. The keys have the
names of the `nvme connect` options: `transport`, `traddr`, `trsvcid`, `nqn`,
`host-traddr`, `host-iface`, `hostnqn` and `hostid`.

Only the fields in the entry are compared:

- `nqn=...` alone excludes the subsystem on all transports and addresses.
- `traddr` and `trsvcid` narrow the entry to one path.
- An entry with an unknown key never matches. A typo cannot exclude too much.
- If the file cannot be read, nothing is excluded.

Orchestrators read the list before each connect. A change applies at once.
You do not have to restart anything.

### Manage the list

```bash
nvme exclusion add --entry="nqn=nqn.2024-01.com.example:storage.vol1;traddr=192.168.30.30"
nvme exclusion list
nvme exclusion remove            # asks which entry to remove
nvme exclusion edit              # opens the list in $EDITOR
nvme exclusion create --name=maintenance
nvme exclusion delete --name=maintenance
```

`--name` selects a named list. Without it, the commands use the default list.

To take a controller out of service, disconnect it with `--exclude`. This
adds an entry first, so no orchestrator connects it again:

```bash
nvme disconnect --device=nvme0 --exclude
```

The new entry names the transport, the address, the port and the NQN:

```
# nvme exclusion list
(default)
  transport=tcp;traddr=192.168.30.30;trsvcid=4420;nqn=nqn.2024-01.com.example:storage.vol1
```

### What is checked

`nvme connect-all` and nvme-discoverd check the list before they connect a
controller that they found: an entry of a discovery log page, an
NBFT record or an entry of `nvme-fabrics.conf`. Other orchestrators can use
`libnvmf_exclusion_match()` of libnvme for the same check. `nvme connect-all`
logs:

```
skipping excluded controller (tcp, 192.168.30.30, 8009, nqn.2024-01.com.example:storage.vol1)
```

The list does not block `nvme connect` with an address, because the intent is
clear. With `-v`, `nvme connect` prints a note and connects:

```
connect: Note: nqn.2024-01.com.example:storage.vol1 is on the exclusion list; connecting anyway
```

## See also

- [How to connect to a target](connect.md)
- [nvme-discoverd](discoverd.md)
- [`libnvme/design/REGISTRY.md`](https://github.com/linux-nvme/nvme-cli/blob/master/libnvme/design/REGISTRY.md)
  and
  [`libnvme/design/EXCLUSIONS.md`](https://github.com/linux-nvme/nvme-cli/blob/master/libnvme/design/EXCLUSIONS.md)
- [`nvme-registry-list(1)`](man:nvme-registry-list), [`nvme-exclusion-add(1)`](man:nvme-exclusion-add), [`nvme-disconnect-all(1)`](man:nvme-disconnect-all)
