# The NBFT initramfs module

Focused solely on providing the Boot from NVMe over TCP functionality, intended
to replace parts of the existing `95nvmf` dracut module. At the moment this all
depends on the recently added NetworkManager NBFT support, though the desire is
to support more network management frameworks in the future.

While this module is currently built around dracut, the amount of dracut
involvement in this module is kept to a required minimum with the intention
of supporting more initramfs frameworks (like `mkosi`) in the future.

This is achieved by splitting the framework-specific directives into systemd
unit dropins while keeping the main unit files generic.

Related nvme-cli meson configure options:
* `-Ddracut-module` (default=false) - enables the 95nbft dracut module
* `-Ddracutmodulesdir` (default=`$prefix/lib/dracut/modules.d/`)
* `-Dnetworkmanagerdir` (default=`$prefix/lib/NetworkManager/`)


# The design

(see [dracut.bootup(7)](https://man7.org/linux/man-pages/man7/dracut.bootup.7.html)
for the overall boot process flow)

There are two primary tasks this initramfs module performs:
* early network configuration preparation steps
* the actual NVMe/TCP connection attempts

The actual network interface setup is often distribution-specific and requires
NBFT parser support in each network management framework.

With dracut and NetworkManager the boot process looks roughly as follows:
* `nbft-boot-pre.service` is run, creates udev network link files and tells
  dracut to activate networking
* dracut runs `nm-initrd-generator` (the `35network-manager` module) and starts
  the NetworkManager daemon
* `systemd-udev-trigger.service` renames the network interfaces
* `nm-wait-online-initrd.service` finishes, indicating networking is up and ready.
  This typically satisfies reaching the `network-online.target` point.
* `nbft-boot-connect.service` initiates actual NVMe connections
* the dracut initqueue is waiting for specific block devices (rootfs) to appear

Two major packages are responsible for this: this nvme-cli dracut module and
the added NBFT support in NetworkManager.

## The dracut 95nbft module

The dracut `module-setup.sh` only installs two systemd unit files sandwiched
between specific dracut phases, nothing else. By default the module is always
included in the initramfs unless _hostonly_ is requested in which case the system
is tested for ACPI NBFT tables presence and the module is only included in such
a case.

The systemd unit files are only run when the ACPI NBFT tables are present and
no `rd.nvmf.nonbft` kernel commandline argument was provided that otherwise
instruct the boot process to skip the NBFT machinery.

## nbft-boot-pre.service

Calls the nvme-cli nbft plugin to generate network link files for each interface
found in all NBFT tables. The interface naming in form of `nbftXhY` consists
of an ACPI NBFT table index (defaults to 0) and the specified HFI index.
In a typical scenario only `nbft0h1`, `nbft0h2`, `nbft1h1`, ... interfaces are
present, however it's up to the pre-OS driver to supply arbitrary indexes,
possibly leading to interface names skipping the order to something like
`nbft0h100` and `nbft99h123`. Comparing to the old `95nvmf` dracut module
ordering, this naming scheme is geared towards (semi-)stable predictable
network interface names. Keep in mind that the contents of the NBFT tables
is generated from scratch upon every system start and is not always persistent
between reboots.

The network link files are then picked up by udev on trigger via
`systemd-udev-trigger.service` to apply the new interface names.

For simplicity and for the time being this systemd unit replaces the `95nvmf`
dracut cmdline hook and adds the `rd.neednet=1` `cmdline.d` argument.

## nm-initrd-generator NBFT support

https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/merge_requests/2077

Executed before the NetworkManager daemon starts the added NBFT support parses
the ACPI NBFT tables available and generates system connections. Only
referenced by MAC addresses, relying on udev to perform actual interface
renaming.

The `nm-initrd-generator` doesn't link to `libnvme.so.1` but opens it through
`dlopen()` in runtime. This allows for smaller hostonly initramfs images in case
the NBFT tables are not present in the system. The library is being pulled in
indirectly through the dracut module's requirement of nvme-cli. The
`rd.nvmf.nonbft` kernel commandline argument is respected as well.

## nbft-boot-connect.service

Modprobes required modules (`nvme-fabrics`) first.

Performs actual NVMe connections by calling `nvme connect-all --nbft`. The
nvme-cli code has been modified to return non-zero return code in case one
or more SSNS records fail to connect (except those marked as _'unavailable'_
by the pre-OS driver), resulting in the service startup failure with defined
respawn of 10 seconds (TBD). This ensures multiple connection attempts while
NetworkManager reacts on link events in the background and the dracut initqueue
eagerly waits for new block devices to appears, to be scanned and mounted. Once
the required block device appears, the wait cycle is ended and the system
continues booting, stopping any queued `nbft-boot-connect.service` respawns
seamlessly.

The difference from the old dracut `95nvmf` module is that the nvme connection
attempts are not driven by network link up events but have fixed respawn
interval. This may potentially help the cases where the NIC is slow to
initialize, reports link up yet it takes another 5+ seconds before it's fully
able to send/receive packets. We've seen this issue with some 25Gb NICs.


# The post-switchroot boot flow

## nvmf-connect-nbft.service

This unit is supposed to run once the `network-online.target` has been reached
and calls `nvme connect-all --nbft` again. This ensures additional connection
attempt for records that failed to connect in the initramfs phase. As long as
this call matches existing connections and skips SSNS records that have been
already connected, in an ideal case this would result in an no-op. This is
mostly a one-shot service run in NetworkManager based distros since the target
typically stays reached until reboot.

## NetworkManager dispatcher hooks

The nvme-cli package installs a custom NetworkManager dispatcher service hook
(`99-nvme-nbft-connect.sh`) that just restarts `nvmf-connect-nbft.service` on
_link up_ events on `nbft*` interfaces. At the time the hook runs the interface
in question has been fully configured by NetworkManager. This ensures further
reconnection attempts in multipath scenarios where a network interface just came
alive. This is designed as a secondary measure with the kernel nvme host driver
connection recovery being the primary mechanism.

In order to make link events work properly the `nbft*` interfaces need to be set
not to ignore carrier events. This is done through a custom override snippet
(`95-nvme-nbft-no-ignore-carrier.conf`) as some distributions may opt to follow
legacy server networking behaviour (see the `NetworkManager-config-server` package).
