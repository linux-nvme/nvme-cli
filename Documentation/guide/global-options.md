<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Global options and nvme-cli.conf

Every `nvme` command accepts the global options. Since nvme-cli 3.0,
`/etc/nvme/nvme-cli.conf` can set defaults for them.

## Global options

| Option | Meaning |
|---|---|
| `-o`, `--output-format=<fmt>` | Output format: `normal`, `json`, `binary` or `tabular`. Not every command supports every format. `--help` lists the formats of a command. |
| `--output-format-version=<n>` | Version of the JSON output: `1` or `2`. The default is `2`. |
| `-v`, `--verbose` | Print more details. Give it more than once for even more details. |
| `--quiet` | Print no informational messages. Errors are still printed. |
| `--timeout=<ms>` | Timeout of the command in milliseconds. `infinite` waits without a limit. |
| `--dry-run` | Show what the command would do, but do not do it. |
| `--no-retries` | Do not retry after a transient error. |
| `--no-ioctl-probing` | Do not probe for the 64-bit ioctls. |
| `--set-options=<key=value>,...` | Set libnvme options: `force-4k`, `mi-probe-enabled`, `test-base-dir` and `test-sysfs-dir`. |

Since nvme-cli 3.2, global options mean the same for every command, and every
command accepts them. Some commands had their own `--human-readable` (`-H`)
or `--verbose` (`-V`). Use `-v` instead. `-H` and `--human-readable` still
work, with a deprecation warning. See [Breaking changes](breaking-changes.md).

### --dry-run

`--dry-run` skips the NVMe commands. Since nvme-cli 3.2, it also skips
resets, namespace rescans, the `sed` operations that change the drive, and
fabrics connects and disconnects. Combine it with `-vv` to see what `nvme
connect` would send to the kernel:

```
# nvme connect --dry-run -vv --transport=tcp --traddr=192.168.30.30 \
    --nqn=nqn.2024-01.com.example:storage.vol1
...
connect ctrl, 'nqn=nqn.2024-01.com.example:storage.vol1,transport=tcp,traddr=192.168.30.30,trsvcid=4420,hostnqn=...,hostid=...,ctrl_loss_tmo=600'
dry-run: connect skipped
```

## nvme-cli.conf

`/etc/nvme/nvme-cli.conf` sets defaults for the global options for all users.
An option on the command line always wins over the file:

```ini
# /etc/nvme/nvme-cli.conf
[Global]
no-ioctl-probing = true
output-format = json
timeout = 5000
```

- The keys have the names of the long options, without `--`: `verbose`,
  `quiet`, `output-format`, `timeout`, `dry-run`, `no-retries`,
  `no-ioctl-probing`, `output-format-version` and `set-options`.
- `verbose` takes the level. `verbose = 2` is the same as `-vv`.
- Booleans accept `1`, `yes`, `true`, `on` and `0`, `no`, `false`, `off`.
- Only the `[Global]` section is used.
- A missing file changes nothing. A file that cannot be read is an error.
- There is no drop-in directory, and no option to select another file.

`nvme` warns about an unknown key or a bad value and ignores it. The rest of
the file still applies:

```
/etc/nvme/nvme-cli.conf:4: unknown key "bogus", ignoring
/etc/nvme/nvme-cli.conf:2: invalid value "10s" for "timeout", ignoring
```

Since nvme-cli 3.2, numbers are parsed strictly, also in this file. For
example, `timeout = 10s` is invalid. Before 3.2, it set a timeout of 10
milliseconds.

The file must be readable by all users. With [privilege
separation](privsep.md), `nvme` reads it after it drops root. Do not
put secrets into this file.

## Environment

| Variable | Meaning |
|---|---|
| `NO_COLOR` | Set to a non-empty value to turn colors off (since 3.2). |
| `NVME_SANDBOX` | `0` turns the decoder sandbox off, `1` turns it on. See [Privilege Separation](privsep.md). |
| `NVME_PRIVSEP_UID`, `NVME_PRIVSEP_GID` | The user and group for privilege separation, when `sudo` is not used. |

## See also

- [Using nvme-cli in scripts](scripting.md)
- [`nvme(1)`](man:nvme), [`nvme-cli.conf(5)`](man:nvme-cli.conf)
