<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Troubleshooting

## nvme show-regs /dev/nvme0 returns: nvme0 failed to map

It's more of a "feature" than an issue. The kernel will not allow user space to
map a device's IO memory when that config option is set and the tooling can't
get around that limitation.

When the Linux kernel is configured with CONFIG_IO_STRICT_DEVMEM, the kernel
prevents user space from mapping IO memory. Either compile a kernel without this
option enabled or set the kernel command line option `iomem=relaxed`.

Also, when secure boot is enabled, the `lockdown` is activated, which prevents
mapping PCI BARs to user space.

## `nvme list` shows wrong disk/block size

nvme-cli v2 relies on the kernel reporting the correct disk/block size via the
sysfs interface.

Also ensure libnvme has:

- https://github.com/linux-nvme/libnvme/pull/754/commits/9b3435bc9b2ff61e40284ed2d5d36dc39a46b3a5
- https://github.com/linux-nvme/libnvme/pull/803/commits/00efe8364b0a94e7057333f9bdf579dbc982429c

and Linux kernel has (v6.8):

- https://github.com/torvalds/linux/commit/a1a825ab6a60380240ca136596732fdb80bad87a

`nvme id-ns` shows the correct disk/block size because it will issue a command
to read the current value.

## `nvme list` shows old firmware version after firmware update

nvme-cli reads the firmware version from sysfs. Older kernels don't update the
firmware entry in sysfs after a firmware upgrade. After a reboot, the correct
version will be shown. Alternatively you can use `nvme id-ctrl` to check the
firmware version.

Linux kernel fix (v6.2)
- https://github.com/torvalds/linux/commit/a8eb6c1ba48bddea82e8d74cbe6e119f006be97d

If this still doesn't fix your problem, it needs to be addressed in the kernel.
`nvme list` is a non-privileged operation and thus can't issue any NVMe Commands
via the passthru interface. This is on purpose.

The workaround is to use `nvme id-ctrl`, reset the PCI device or reboot the
machine.

## `nvme ns create` (and other `nvme ns` commands) print nothing on success

This is a behavior change in nvme-cli 3.0, not a bug. `nvme ns create`, `nvme
ns delete`, `nvme ns attach` and `nvme ns detach` no longer print a
confirmation message by default. The same is true for the deprecated aliases
`create-ns`, `delete-ns`, `attach-ns` and `detach-ns`.

nvme-cli 1.x/2.x printed, e.g.:

```
$ nvme create-ns /dev/nvme0 -s 223741251 -c 223741251 -f 0
create-ns: Success, created nsid:6
```

nvme-cli 3.0 completes the same command silently:

```
$ nvme ns create /dev/nvme0 -s 223741251 -c 223741251 -f 0
$
```

The namespace **is** still created. Only the success message is gone. Check `$?`
for the exit code, or run `nvme ns list /dev/nvme0` (or `nvme id ctrl`) to see
the assigned nsid.

### Getting the confirmation message back

Add `-v`/`--verbose`:

```
$ nvme ns create /dev/nvme0 -s 223741251 -c 223741251 -f 0 -v
create-ns: success
nsid: 6
```

### Why

These four namespace-management commands report success only via their exit code
by default now. The human-readable confirmation (and the `nsid` it reports) is
gated behind `--verbose` on the assumption that a scripted/automated caller
already checks the exit code and can look up the nsid via `ns-list`, while an
interactive caller can opt into the message with `-v`.

## `nvme config --scan --update` fails with "Invalid sub-command"

This command is gone in nvme-cli 3.0. `nvme config` is now a group of
subcommands (`create`, `show`, `validate`, `convert`, `status`), not a single
command with flags. There is no direct replacement for `--scan --update`; the
whole model changed. See
[How to configure NVMe-oF connections](fabrics-config.md) for
the new `nvme config create` workflow, and
[Migrating from nvme-cli 2.x to 3.0](migrating-2-to-3.md) for the
full list of command changes.

## `nvme connect`: unrecognized option `--dump-config`

nvme-cli 3.0 removed `--dump-config` and `--output-format json` from `nvme
connect`, `nvme discover`, and `nvme connect-all`. There is no direct
replacement flag. Build the same connection entry with `nvme config create`
instead, and persist it in `nvme-fabrics.conf`. See
[How to configure NVMe-oF connections](fabrics-config.md).

## `nvme check-tls-key --insert`: unrecognized option

nvme-cli 3.0 split `check-tls-key` into two commands: `nvme keys check-tls-psk`
(checks a key, never changes the keyring) and `nvme keys insert-tls-psk`
(always inserts). The old `--insert` flag has no equivalent under
`check-tls-psk`. Use `nvme keys insert-tls-psk` instead. See
[The `nvme keys` Plugin](keys-plugin.md).

## `nvme keys check-kxchap-secret`/`check-tls-psk` print nothing

This is a behavior change in nvme-cli 3.0, not a bug: these two `check-*`
commands report their verdict through the exit code only by default now.

```
$ nvme keys check-kxchap-secret --keydata DHHC-1:01:ia6zGodOr4SEG0Zzaw398rpY0wqipUWj4jWjUh4HWUz6aQ2n:
$ echo $?
0
```

Add `-v`/`--verbose` to get the human-readable verdict back:

```
$ nvme keys check-kxchap-secret -v --keydata DHHC-1:01:ia6zGodOr4SEG0Zzaw398rpY0wqipUWj4jWjUh4HWUz6aQ2n:
Secret is valid (HMAC 1, length 32, CRC ...)
```

A key that fails the check always prints its error to stderr and exits with
a non-zero status. Only the message on success needs `--verbose`. See [The
`nvme keys` Plugin](keys-plugin.md).

## Ensuring correct shutdown ordering for NVMe/TCP mounted filesystems

When using NVMe/TCP, it is common to have filesystems mounted from remote NVMe
namespaces.

During shutdown, the correct ordering is:

1. Unmount all filesystems using the NVMe/TCP devices
2. Run `nvme disconnect-all`
3. Shut down networking

If `nvme disconnect-all` runs too early, mounted filesystems may hang or
shutdown may fail because the remote block devices disappear before unmounting
completes.

The recommended solution is to create a dedicated systemd service and use a
systemd drop-in override instead of modifying vendor unit files directly.

In nvme-cli 3.0, plain `nvme disconnect-all` only disconnects controllers with
no recorded owner in the ownership registry (see
[Migrating from nvme-cli 2.x to 3.0](migrating-2-to-3.md)). A
controller connected by an orchestrator, or by
[NVMe-oF autoconnect](autoconnect.md), has an owner and is
left alone. A shutdown script wants everything gone, so add `--force`:

Create a new service:

```bash
sudo tee /etc/systemd/system/nvme-disconnect.service >/dev/null <<'EOF'
[Unit]
Description=Disconnect NVMe Fabrics devices at shutdown
DefaultDependencies=no
Before=network.target shutdown.target
After=remote-fs.target umount.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nvme disconnect-all --force

[Install]
WantedBy=shutdown.target
EOF
```

Enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable nvme-disconnect.service
```

This ensures that:

- remote filesystems are unmounted first,
- `nvme disconnect-all` is executed afterwards,
- networking remains available until disconnect processing is complete.

Do **not** place local modifications into `/usr/lib/systemd/system/`.

If later versions of `nvme-cli` ship a vendor-provided unit, local
customizations should instead be placed under:

```text
/etc/systemd/system/<unit>.d/
```

using `systemctl edit`.

Additional information about systemd unit overrides can be found in:

```bash
man systemd.unit
man systemctl
```

Relevant project documentation:

- https://www.freedesktop.org/software/systemd/man/systemd.unit.html
