<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Breaking changes

This page lists the changes in each nvme-cli 3.x release that can break a
script, a configuration, a build or a program that uses libnvme. New features
and bug fixes are not listed here. The full list of changes is in
[NEWS.md](https://github.com/linux-nvme/nvme-cli/blob/master/NEWS.md).

Read the sections of every release between your old and your new version.

- [nvme-cli 3.2](#nvme-cli-32)
- [nvme-cli 3.1](#nvme-cli-31)
- [nvme-cli 3.0](#nvme-cli-30)

## nvme-cli 3.2

Released 2026-10-30.

### Command line

nvme-cli parses its command line itself now. Before, it used getopt. The rules
are stricter:

- Long options need two dashes and the full name. Abbreviations are an
  error, for example `--namespace` for `--namespace-id`.
- A single dash always starts short options. `-verbose` is read as
  `-v -e -r -b -o -s -e`.
- An option with an optional value needs the value attached:
  `--persistent=force` or `-pforce`. `--persistent force` is an error now.
  Before, it connected in `auto` mode and dropped `force` without a message.
- An extra operand is an error. A command that takes a device fails without
  one. Before, extra operands were ignored.
- Every command checks `--output-format`. An invalid value is an error, also
  for commands that do not print anything.

Options and operands can still be given in any order.

Numbers are parsed strictly, on the command line and in `nvme-cli.conf`:

- Text after the number is an error. Before, it was ignored:
  `--timeout=10s` set a timeout of 10 milliseconds.
- A leading zero, a `+` and leading spaces are errors. Before, a leading zero
  made the number octal: `--namespace-id=010` was namespace 8. Write `10`, or
  `0x10` for hexadecimal. `0` itself is fine.
- An unsigned option rejects a negative number. Before, `-1` wrapped around
  to the largest value. Use the names for the special values instead: `all`
  for a namespace ID of 0xffffffff, `infinite` for `--timeout`. `-1` is still
  accepted for these two.
- A signed option rejects a value out of its range.
- Sizes with a suffix use a `.` as the decimal point in every locale.
  `1.500k` is 1500 now. Before, it was 1000.

Some option values have a fixed range now:

- `--sel` of `get-feature`, the `feat` commands and the `ocp` and `shannon`
  get-feature commands accepts 0 to 3, or `current`, `default`, `saved` and
  `supported`.
- `--output-format-version` accepts only 1 and 2.
- Options that take one of a few words reject other words before the device
  is opened. Examples are `show-topology --ranking` and
  `ocp internal-log --telemetry-type`.
- `lm migration-recv` requires `--sel`.

Global options mean the same for every command:

- Some commands had their own `--human-readable` (`-H`) or `--verbose` (`-V`).
  These are gone. Use the global `--verbose` (`-v`). `-V` is an error for
  these commands.
- Some options lost their short name, because a global option uses it. For
  example, `config convert --output` has no `-o` any more.
- `--human-readable` and `-H` print a deprecation warning. Use `--verbose`.

See [NEWS.md](https://github.com/linux-nvme/nvme-cli/blob/master/NEWS.md)
for the full list of options.

### Exit status and messages

- `nvme <command> --help` prints to stdout and exits with 0. Before, it
  printed to stderr and exited with 1.
- A usage error prints the error, the synopsis and a pointer to the help.
  Before, it printed the whole help.
- Error messages start with the command name, for example
  `id ns: /dev/nvme0: Permission denied`.
- On a terminal, the command name of an error is red. Set `NO_COLOR` to a
  non-empty value to turn colors off.
- `nvme help` does not list the deprecated commands any more. They still work,
  with a warning.

### Output

- The normal (not JSON) output of `id-ctrl`, `id-ns` and most other identify,
  log page and feature commands uses a table with computed column widths.
  The field names and values are the same. The spacing is different. Use
  `-o json` in scripts. The JSON output did not change.
- The JSON output of `show-regs`, `get-reg` and `get-property` has one form:
  `{"cc": 4587521}`. The values are unsigned. With `-v`, each register is an
  object of its value and its fields.
- `show-regs`, `get-reg` and `get-property -v` decode the register fields
  with the names of the specification. `CAP.CSS`, `CAP.AMS`, `CAP.CRMS` and
  `VS` are split into their fields. `show-regs` names the Version register
  `vs` instead of `version`.
- The JSON output of `log reachability-groups` and
  `reachability-associations` lists the IDs of a descriptor in an array.
- The JSON output of `wdc vs-smart-add-log` prints the C1 performance
  statistics as 64 bit values.

### Commands

- `--persistent` of `discover`, `connect-all` and `config create
  --discovery` defaults to `auto`. Before, the default was `no`. A Discovery
  Controller now stays connected when the target reports EPCSD. Use
  `--persistent=no` for the old behavior. See [NVMe-oF Persistent Discovery
  Controllers](pdc.md).
- `nvme connect` over TCP without `--nr-io-queues` uses one I/O queue per
  queue of the network interface, at most one per online CPU.
- `nvme set-reg` uses a Property Set only for a fabrics controller. It
  refuses a register the host may not write.
- `--dry-run` also skips resets, namespace rescans, the `sed` operations that
  change the drive, and fabrics connects and disconnects.
- `nvme copy` sends the Expected Logical Block Tags and Application Tags in
  little endian again, as in 2.x. 3.0 and 3.1 sent them in big endian. See
  [issue #4278](https://github.com/linux-nvme/nvme-cli/issues/4278).
- The ScaleFlux plugin does not support the proprietary ScaleFlux kernel
  driver any more. The clean card feature is removed.
- The deprecated `tls-key` command no longer accepts abbreviated options.
  `tls-key`, `gen-dhchap-key` and `check-dhchap-key` reject extra operands.

### Autoconnect and nvme-discoverd

- nvme-discoverd is built by default when libsystemd 253 or later is
  available. The legacy udev/systemd autoconnect is then not built, and its
  files are not installed. Build with `-Dnvme-discoverd=disabled` to keep the
  old behavior. See [How to set up NVMe-oF
  autoconnect](autoconnect.md).
- `meson install` installs `nvme-discoverd.conf.sample` instead of
  `nvme-discoverd.conf`. Your settings are no longer overwritten.
- `epcsd-poll-interval-minutes`, `fc-kickstart-interval-minutes` and
  `dc-giveup-timeout` moved from `[Global]` to `[Discovery]` in
  `nvme-discoverd.conf`. In `[Global]`, they are ignored with a warning. See
  [nvme-discoverd](discoverd.md#configuration).

### Build

- The `docs-build` option is removed. Remove `-Ddocs-build=true` from your
  meson arguments, because meson rejects an unknown option. `-Ddocs` installs
  the man pages that are in the source tree. The `update-docs` target
  regenerates them.
- The WDC, SanDisk, Micron, Samsung and Solidigm plugins use libarchive to
  create log archives. They do not call `tar` or `zip` any more. Without
  libarchive, these subcommands fail with an error.

### libnvme

- The Identify Controller bit field constants for OAES, BPCAP, MEC, OACS,
  FRMW, LPA and AVSCC use the names of the NVM Express Base Specification
  2.4. The old names are removed. For example, `NVME_CTRL_OACS_FORMAT` is now
  `NVME_CTRL_OACS_FNVMS`. NEWS.md has the full list.
- `libnvme3.pc` reports the nvme-cli release version, for example 3.2.
  Before, it reported 1.0.0. The soname `libnvme3.so.1` did not change.

## nvme-cli 3.1

Released 2026-09-18.

### Commands

- `nvme gen-hostnqn` must run as root. Without root, it cannot read the DMI
  and device tree files, and it returned a random identifier before.

### Build

- meson 1.0.0 or later is required. Before, 0.62.0 was enough.
- Building the man pages requires `xmlto`.
- `-Ddocs=man` and `-Ddocs=all` install the man pages from the source tree,
  unless `-Ddocs-build=true` is given. 3.2 removes `docs-build` again.

### libnvme

- `NVME_CAP_NSSRC()` is renamed to `NVME_CAP_NSSRS()`, the name in the
  specification.
- `libnvmf_generate_hostid()` uses the machine ID when DMI and the device tree
  do not give a host ID. Before, it used a random UUID. The machine ID itself
  is not published.

## nvme-cli 3.0

Released 2026-09-07.

nvme-cli 3.0 has many breaking changes. [Migrating from nvme-cli 2.x to
3.0](migrating-2-to-3.md) describes them. In short:

- Many top-level commands moved into plugins. For example, `nvme smart-log`
  is now `nvme log smart` and `nvme id-ctrl` is now `nvme id ctrl`. The old
  commands still work, with a warning. They are removed in the next major
  version. `-Ddeprecated-cmds=disabled` removes them at build time.
- `nvme rpmb --cmd=<action>` is now `nvme rpmb <action>`. The old form does
  not work any more.
- The key commands moved into the `nvme keys` plugin. DH-HMAC-CHAP is now
  called KX-HMAC-CHAP. The output of several key commands changed.
- `nvme-fabrics.conf` replaces `config.json` and `discovery.conf`. The first
  command that reads the configuration, for example `nvme connect-all`
  without options, converts an old file. `nvme config convert` does it
  explicitly.
- `nvme disconnect-all` disconnects only controllers without an owner in the
  ownership registry.
- `nvme ns create`, `delete`, `attach` and `detach` print nothing on success.
  Use `-v` to get the old output.
- `nvme resv report` uses the names of the NVM Express Base Specification
  2.4: `regctl` is now `regstrnt` in the output and in the JSON keys.
- The default JSON output format version is 2. In 2.x, it was 1. This
  changes `nvme list -v -o json`: each namespace lists its paths, instead of
  each controller listing its namespaces. Use `--output-format-version=1` for
  the old layout. See [Using nvme-cli in scripts](scripting.md).
- `--dump-config` is removed from `connect`, `discover` and `connect-all`.
- The `pdc-enabled` build option is removed. Use `--persistent` or
  `persistent =` in `nvme-fabrics.conf`.
- A C11 compiler is required.
- libnvme is renamed to libnvme3, and libnvme-mi is part of it. The API
  changed in many places.

## See also

- [NEWS.md](https://github.com/linux-nvme/nvme-cli/blob/master/NEWS.md)
- [Migrating from nvme-cli 2.x to 3.0](migrating-2-to-3.md)
