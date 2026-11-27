<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Migrating from nvme-cli 2.x to 3.0

nvme-cli 3.0 moved many top-level commands into plugins. It also renamed a few
commands and changed some default behavior.

Old commands still work. They print a deprecation warning on stderr. They may be
removed in a future release. Update your scripts when you can.

This page lists the changes that affect the command line. For the full list,
including internal library changes, see
[NEWS.md](https://github.com/linux-nvme/nvme-cli/blob/master/NEWS.md).

## Command renames

### Key management (`nvme keys`)

| 2.x command | 3.0 command |
|---|---|
| `nvme gen-dhchap-key` | `nvme keys gen-kxchap-secret` |
| `nvme check-dhchap-key` | `nvme keys check-kxchap-secret` |
| `nvme gen-tls-key` | `nvme keys gen-tls-psk` |
| `nvme check-tls-key` | `nvme keys check-tls-psk` |
| `nvme check-tls-key --insert` | `nvme keys insert-tls-psk` (no direct equivalent under `check-tls-psk`) |
| `nvme tls --import` | `nvme keys import` |
| `nvme tls --export` | `nvme keys export` |
| `nvme tls --revoke` | `nvme keys revoke` |

See [How to set up TLS for NVMe-TCP](tls.md) and
[How to set up inband authentication](inband-auth.md) for
full examples. DH-HMAC-CHAP is also renamed to KX-HMAC-CHAP throughout, matching
NVMe TP4201. The secret format (`DHHC-1:...`) is unchanged.

### Log pages (`nvme log`)

| 2.x command | 3.0 command |
|---|---|
| `nvme smart-log` | `nvme log smart` |
| `nvme ana-log` | `nvme log ana` |
| `nvme error-log` | `nvme log error` |
| `nvme fw-log` | `nvme log fw` |
| `nvme telemetry-log` | `nvme log telemetry` |
| `nvme self-test-log` | `nvme log self-test` |
| `nvme sanitize-log` | `nvme log sanitize` |

Every other `nvme *-log` command moved the same way (drop the `-log` suffix, add
`nvme log` in front). `nvme get-log` is the one exception; it did not move. Run
`nvme log --help` for the full list.

### Identify (`nvme id`)

| 2.x command | 3.0 command |
|---|---|
| `nvme id-ctrl` | `nvme id ctrl` |
| `nvme id-ns` | `nvme id ns` |
| `nvme list-ns` | `nvme id ns-list` |
| `nvme list-ctrl` | `nvme id ctrl-list` |
| `nvme nvm-id-ctrl` | `nvme id nvm-ctrl` |
| `nvme nvm-id-ns` | `nvme id nvm-ns` |

Every other `nvme id-*`/`nvm-id-*`/`list-*` Identify command moved the same way.
Run `nvme id --help` for the full list.

### Namespace management (`nvme ns`)

| 2.x command | 3.0 command |
|---|---|
| `nvme create-ns` | `nvme ns create` |
| `nvme delete-ns` | `nvme ns delete` |
| `nvme attach-ns` | `nvme ns attach` |
| `nvme detach-ns` | `nvme ns detach` |
| `nvme get-ns-id` | `nvme ns get-id` |

See [Troubleshooting](troubleshooting.md) for the change in output of `nvme ns
create`/`delete`/`attach`/`detach`.

### Reservations (`nvme resv`)

| 2.x command | 3.0 command |
|---|---|
| `nvme resv-acquire` | `nvme resv acquire` |
| `nvme resv-register` | `nvme resv register` |
| `nvme resv-release` | `nvme resv release` |
| `nvme resv-report` | `nvme resv report` |

### Other moved commands

These command groups moved the same way, one plugin per group:

| 2.x commands | 3.0 plugin |
|---|---|
| `nvme nvme-mi-recv`, `nvme nvme-mi-send` | `nvme nvme-mi recv`, `nvme nvme-mi send` |
| `nvme io-mgmt-recv`, `nvme io-mgmt-send` | `nvme io-mgmt recv`, `nvme io-mgmt send` |
| `nvme dir-receive`, `nvme dir-send` | `nvme dir receive`, `nvme dir send` |
| `nvme security-send`, `nvme security-recv` | `nvme security send`, `nvme security recv` |
| `nvme fw-commit`, `nvme fw-download` | `nvme fw commit`, `nvme fw download` |

### Connection configuration (`nvme config`)

`nvme config --scan --update` is gone. There is no direct replacement command;
the whole model changed. See
[How to configure NVMe-oF connections](fabrics-config.md) for
the new `nvme config create`/`show`/`validate`/`convert`/`status` commands, and
for how to migrate an existing `config.json`/`discovery.conf`.

`--dump-config` is removed from `nvme connect`, `nvme discover`, and `nvme
connect-all`. There is no direct replacement flag.

## Behavior changes

These commands did not rename, but behave differently in 3.0:

- **`nvme gen-dhchap-key` / `nvme keys gen-kxchap-secret`**: the secret is no
  longer transformed using the NQN and hash function given with `--hmac`. It is
  emitted as given. `--nqn`/`-n` is accepted and ignored, with a warning. A
  `--secret` with an odd number of hex characters is now rejected, instead of
  silently padded.

- **`nvme check-dhchap-key` / `nvme keys check-kxchap-secret`**: output wording
  changed from "Key is valid"/"Key is loaded" to "Secret is valid"/"Secret is
  loaded". Exit codes are unchanged.

- **`nvme keys check-kxchap-secret` / `nvme keys check-tls-psk`**: the verdict
  line (the wording above, or "Configured PSK is valid"/"TLS PSK is loaded"
  for `check-tls-psk`) now prints only with `-v`/`--verbose`. Without it, only
  the exit status reports success or failure; errors still print to stderr
  unconditionally.

- **`nvme ns create`/`delete`/`attach`/`detach`**: no confirmation message on
  success by default. `nvme ns create` also no longer prints the assigned
  `nsid`. Add `-v`/`--verbose` to get the old output back. See
  [Troubleshooting](troubleshooting.md).

- **`nvme disconnect-all`**: no longer disconnects every fabric controller by
  default. It only disconnects controllers with no recorded owner in the new
  ownership registry. A controller owned by another orchestrator is left alone.

- **`config.json`/`discovery.conf`**: replaced by the INI file
  `nvme-fabrics.conf`. The first command that reads the configuration, for
  example `nvme connect-all` without options, converts an existing legacy
  file automatically. See
  [How to configure NVMe-oF connections](fabrics-config.md).

## libnvme

The library itself was renamed from **libnvme** to **libnvme3**, and
**libnvme-mi** was merged into it. If you package or link against libnvme
directly (not just through the `nvme` CLI), see
[NEWS.md](https://github.com/linux-nvme/nvme-cli/blob/master/NEWS.md) for the
full list of API changes.
