# nvme-keysd

A daemon that puts NVMe/TCP TLS pre-shared keys (PSKs) into the kernel's `.nvme` keyring before a connection needs them. The kernel finds the key there when `nvme connect` or `nvme-discoverd` connects with TLS.

> Technology preview. The `nvme-keysd` meson option defaults to `disabled`. Keys come from systemd credentials (`tls-key-source = systemd-creds`) or from a KMIP key management server (`tls-key-source = kmip:<name>`). The `kmip` meson option (default `auto`) builds the `nvme-keysd-kmip` helper.

## Design

- **Runs once, unless KMIP is used.** The unit is `Type=notify`. The daemon imports the keys from systemd credentials, reports ready and exits. With KMIP keys, it keeps running and gets them in the background, with retries.
- **Least privilege.** The daemon runs as uid 0, because the kernel checks access to the `.nvme` keyring by uid. It needs no capabilities and no network. The systemd unit drops both.
- **KMIP in a separate process.** `nvme-keysd-kmip` does all communication with the KMS, over TLS. It runs with a dynamic user and no privileges. systemd starts one instance per connection to its Varlink socket. The daemon itself never parses KMS replies.
- **No key material in logs or core dumps.** The daemon disables core dumps at startup (`PR_SET_DUMPABLE`).

## Source layout

nvme-keysd:

| File | Role |
|---|---|
| `main.c` | Startup, `--should-start`, the import run |
| `config.c` | The daemon's own settings (`nvme-keysd.conf`), including the `[kmip:<name>]` sections |
| `import.c` | Imports the keys named in the fabrics configuration and puts the PSKs in the keyring |
| `creds.c` | Decrypts one credential through systemd-creds (`io.systemd.Credentials.Decrypt`) |
| `kmip-client.c` | Gets the KMIP keys through `nvme-keysd-kmip`, on the event loop |

nvme-keysd-kmip:

| File | Role |
|---|---|
| `kmip-main.c` | The Varlink service: one request, one key |
| `kmip.c` | KMIP 1.4 requests and responses (Locate by Name, Get) |
| `ttlv.c` | KMIP TTLV encoding |
| `kmip-tls.c` | KMIP over TLS |
| `kmip-psk.c` | Converts a key object to a PSK in the interchange format |

`config.c` is built into both programs. `kmip-varlink.h` describes the Varlink interface between them. Logging comes from `daemon-util/`, shared with the other nvme-cli daemons.

## Configuration

- **`nvme-keysd.conf`**: the daemon's own settings (`debug-level`) and the KMSes (`[kmip:<name>]`). Optional; a missing file or key keeps its default.
- **The shared NVMe-oF fabrics configuration** (`nvme-fabrics.conf(5)`): which key belongs to which host and subsystem.

Both are read at each start. `systemctl restart nvme-keysd` imports the keys again, and picks up new or changed credentials and KMIP keys.

The unit runs `nvme-keysd --should-start` as `ExecCondition=`. When no entry of the fabrics configuration has a key source, the unit is skipped: the daemon does not start, and `nvme_keyring` is not loaded.
