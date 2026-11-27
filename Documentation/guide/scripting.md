<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Using nvme-cli in scripts

This page describes how to use nvme-cli in scripts and monitoring tools, so
that they keep working with new releases.

## Use the JSON output

Parse the JSON output, not the normal output:

```bash
nvme list -o json
nvme id ctrl /dev/nvme0 -o json
nvme log smart /dev/nvme0 -o json
```

The normal output is for people. It is not a stable interface. For example,
nvme-cli 3.2 changed the layout of the normal output of `id-ctrl`, `id-ns` and
many log page and feature commands to computed column widths. The JSON output
did not change.

`jq` is a convenient tool to read the JSON output:

```bash
# The model number of every namespace device
nvme list -o json | jq -r '.Devices[] | "\(.DevicePath) \(.ModelNumber)"'
```

`--help` of a command lists the output formats that it supports. Since nvme-cli
3.2, a command rejects a format that it does not support.

### Output format version

`--output-format-version` selects the version of the JSON output. Today, it
changes only `nvme list -v -o json`:

- Version 2, the default since nvme-cli 3.0: each subsystem lists its
  `Namespaces`, and each namespace lists its `Paths` with the controller data.
- Version 1, the default in nvme-cli 2.x: each subsystem lists its
  `Controllers`, and each controller lists its `Namespaces`.

A script written for the 2.x layout can request it:

```bash
nvme list -v -o json --output-format-version=1
```

### I/O statistics

Since nvme-cli 3.2, `nvme top -o json` takes two samples `--delay` seconds
apart and prints the rates and counters of the subsystems, namespaces, paths
and controllers. It does not need root. See [`nvme-top(1)`](man:nvme-top) and
[nvme-mcp](mcp.md).

## Check the exit status

`nvme` exits with 0 on success and 1 on failure. Some commands print nothing
on success, for example `nvme ns create` since nvme-cli 3.0. Check the exit
status, not the output:

```bash
if ! nvme id ctrl /dev/nvme9 -o json > ctrl.json; then
    echo "id ctrl failed" >&2
fi
```

The error message goes to stderr and starts with the command name:

```
id ctrl: /dev/nvme9: No such file or directory
```

Since nvme-cli 3.2, `nvme <command> --help` exits with 0 and prints to
stdout. A usage error exits with 1.

## Write full option names

Since nvme-cli 3.2, the command line is parsed strictly:

- Write long options in full: `--namespace-id`, not `--namespace`.
- Attach an optional value: `--persistent=force`.
- Write numbers in decimal or with `0x`. A leading zero is an error, not an
  octal number.
- Use `all` for all namespaces and `infinite` for no timeout, not `-1`.

See [Breaking changes](breaking-changes.md) for the full list.

## Do not use device names

The kernel numbers controllers and namespaces in the order it finds them.
`/dev/nvme0n1` can be another device after a reboot or a reconnect. Use the
names in `/dev/disk/by-id/`, the serial number or the NQN instead. See the
[FAQ](faq.md).

## Turn off colors

On a terminal, error messages are colored since nvme-cli 3.2. Output to a pipe
or a file has no colors. Set `NO_COLOR` to a non-empty value to turn colors
off everywhere.

## Set defaults for all commands

`/etc/nvme/nvme-cli.conf` sets defaults for the global options. A default in
this file also applies to your scripts. Give the options that your script
needs on its command line. See [Global options](global-options.md).

## See also

- [Breaking changes](breaking-changes.md)
- [Global options](global-options.md)
