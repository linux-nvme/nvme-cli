# nvme-keysd

A daemon that puts NVMe/TCP TLS pre-shared keys (PSKs) into the kernel's `.nvme` keyring before a connection needs them. The kernel finds the key there when `nvme connect` or `nvme-discoverd` connects with TLS.

> Technology preview. The `nvme-keysd` meson option defaults to `disabled`. Keys come from systemd credentials only (`key-source = systemd-creds`).

## Design

- **Runs once.** The unit is `Type=oneshot`. The daemon imports the keys and exits.
- **Least privilege.** The daemon runs as uid 0, because the kernel checks access to the `.nvme` keyring by uid. It needs no capabilities and no network. The systemd unit drops both.
- **No key material in logs or core dumps.** The daemon disables core dumps at startup (`PR_SET_DUMPABLE`).

## Source layout

| File | Role |
|---|---|
| `main.c` | Startup, `--should-start`, the import run |
| `config.c` | The daemon's own settings (`nvme-keysd.conf`) |
| `import.c` | Imports the credentials named in the fabrics configuration and puts the PSKs in the keyring |
| `creds.c` | Decrypts one credential through systemd-creds (`io.systemd.Credentials.Decrypt`) |

Logging comes from `daemon-util/`, shared with the other nvme-cli daemons.

## Configuration

- **`nvme-keysd.conf`**: the daemon's own settings (`debug-level`). Optional; a missing file or key keeps its default.
- **The shared NVMe-oF fabrics configuration** (`nvme-fabrics.conf(5)`): which key belongs to which host and subsystem.

Both are read at each start. `systemctl restart nvme-keysd` imports the keys again, and picks up new or changed credentials.

The unit runs `nvme-keysd --should-start` as `ExecCondition=`. When no entry of the fabrics configuration has a key source, the unit is skipped: the daemon does not start, and `nvme_keyring` is not loaded.
