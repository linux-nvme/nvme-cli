# nvme-keysd

A daemon that puts NVMe/TCP TLS pre-shared keys (PSKs) into the kernel's `.nvme` keyring before a connection needs them. The kernel finds the key there when `nvme connect` or `nvme-discoverd` connects with TLS.

> Technology preview. The `nvme-keysd` meson option defaults to `disabled`. The daemon's main loop and configuration exist; importing keys does not yet.

## Design

- **Single-threaded.** One `sd_event` loop, the same model as `nvme-discoverd`.
- **Least privilege.** The daemon runs as uid 0, because the kernel checks access to the `.nvme` keyring by uid. It needs no capabilities and no network. The systemd unit drops both.
- **No key material in logs or core dumps.** The daemon disables core dumps at startup (`PR_SET_DUMPABLE`).

## Source layout

| File | Role |
|---|---|
| `main.c` | Startup, signal handling, the main loop |
| `config.c` | The daemon's own settings (`nvme-keysd.conf`) |

Logging comes from `daemon-util/`, shared with the other nvme-cli daemons.

## Configuration

- **`nvme-keysd.conf`**: the daemon's own settings (`debug-level`). Optional; a missing file or key keeps its default.
- **The shared NVMe-oF fabrics configuration** (`nvme-fabrics.conf(5)`): which key belongs to which host and subsystem.

`nvme-keysd.conf` is reloaded on `SIGHUP`.
