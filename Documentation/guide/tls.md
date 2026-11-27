<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# How to Set Up TLS for NVMe-TCP

Enabling TLS for the NVMe-TCP transport requires a few configuration steps for
both the kernel and userland.

## Kernel Configuration

To support TCP authentication and TLS encryption, enable the following kernel
options:

- For DHCHAP authentication: `CONFIG_NVME_HOST_AUTH`

- For TLS transport encryption: `CONFIG_NVME_TCP_TLS`

These configuration options depend on other config options, but they will be
auto-selected. Of course, `CONFIG_TLS` also has to be selected, but for most
configurations this happens automatically, too.

## Userland

For the userland configuration two components need to be configured. First, the
tlshd TLS handshake daemon needs to be running and TLS keys need to be loaded
into the kernel keystore.

### Setting Up `tlshd`

For TLS protocol support, which handles authentication and encryption, the
kernel handles data encryption only, so userland support is required for the TLS
handshake. The `tlshd` daemon implements the handshake process.

#### Requirements

Ensure `tlshd` includes the commit `311d9438b984` ("tlshd: always link .nvme
default keyring into the session") - likely in `ktls-utils` version 0.12.
Alternatively, you can set the keyring manually in `/etc/tlshd.conf`:

```ini
[authenticate]
keyrings = .nvme
```

#### Enable/start tlshd

No additional configuration is necessary for `tlshd`; simply start it as a
daemon:

```bash
systemctl enable --now tlshd
```

### Loading Keys on Boot or Module Load

When the kernel is establishing a TCP connection with TLS, the NVMe subsystem
loads keys from the kernel keystore. This means these keys must be available in
the keystore before establishing a connection.

nvme-cli provides command line interfaces to create, import and export keys into
the kernel keystore, though it's not the only way to import/export keys. If
there is another system component managing the keys, the following steps for
creating and making the keys persistent over boot cycles are not necessary.

To stress this point, the nvme-cli is explicitly trying to avoid handling the
keys, the only requirement is that the keys are present in the keystore.

[nvme-keysd](keysd.md) is such a component. It loads the keys at boot from
encrypted systemd credentials or from a key management server (KMIP). With
nvme-keysd, the keys are not stored in plain text on disk.

> nvme-cli 3.0 moved key management into a `nvme keys` plugin, e.g. `nvme
> gen-tls-key` is now `nvme keys gen-tls-psk`. The commands below use the 3.0
> names; the 2.x names are noted alongside them and still work today as
> deprecated aliases that print a warning on stderr, but may be removed in a
> future release. One exception: `nvme check-tls-key --insert` has no
> equivalent under `nvme keys check-tls-psk`. Use `nvme keys insert-tls-psk`
> instead (see below).

#### Creating a New Key

`nvme gen-tls-key` in nvme-cli 2.x, now `nvme keys gen-tls-psk`:

```bash
nvme keys gen-tls-psk \
  --hostnqn nqn.2014-08.org.nvmexpress:uuid:befdec4c-2234-11b2-a85c-ca77c773af36 \
  --subsysnqn nqn.io-1 --hmac 1 --identity 1 --insert --keyfile /etc/nvme/tls-keys
```

This command creates a new host key, inserts it into the kernel keyring, and
appends the derived TLS PSK to the keyfile (`/etc/nvme/tls-keys`).

### Inserting an Existing Key

In nvme-cli 2.x, this was `nvme check-tls-key --insert`. nvme-cli 3.0 split
checking and inserting into two commands. Use `nvme keys insert-tls-psk`. It
always inserts the key, so it has no `--insert` option:

```bash
nvme keys insert-tls-psk \
  --hostnqn nqn.2014-08.org.nvmexpress:uuid:befdec4c-2234-11b2-a85c-ca77c773af36 \
  --subsysnqn nqn.io-1 --identity 1 \
  --keydata NVMeTLSkey-1:01:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACtVQoZ: \
  --keyfile /etc/nvme/tls-keys
```

This command inserts the configured key (`--keydata`) into the kernel keyring
and appends the derived TLS PSK to the keyfile. To check whether a key is
already loaded without inserting it, use `nvme keys check-tls-psk` (nvme-cli
2.x: `nvme check-tls-key`, without `--insert`).

### Loading Keys on Boot or Module Load

The kernel keyring does not persist keys, so userland must import keys into the
keyring upon each boot or module load (for NVMe-TCP). The nvme-tcp module
provides the `psk` type keystore, so it is only possible to load keys into the
keystore when the nvme-tcp module is available:

```bash
nvme keys import --keyfile /etc/nvme/tls-keys
```

(nvme-cli 2.x: `nvme tls --import --keyfile ...`.)

The `70-nvmf-keys.rules` udev rule
([source](https://github.com/linux-nvme/nvme-cli/blob/master/nvmf-autoconnect/udev-rules/70-nvmf-keys.rules.in))
will load keys from `/etc/nvme/tls-keys` automatically.

```text
ACTION=="add", SUBSYSTEM=="module", KERNEL=="nvme_tcp", TEST=="@SYSCONFDIR@/nvme/tls-keys", RUN+="@SBINDIR@/nvme keys import --keyfile @SYSCONFDIR@/nvme/tls-keys"
```

`/etc/nvme/tls-keys` holds the keys in plain text. To keep them encrypted, use
[nvme-keysd](keysd.md) instead.

### Recommendation for Handling TLS Keys

The `nvme connect` command also allows passing a TLS key directly via the
command line or a JSON config file. Avoid this method in production
environments, as it may expose keys. To name a key in `nvme-fabrics.conf`
without the key itself, use [nvme-keysd](keysd.md).

### Establishing a Connection

Once the keys are in the keystore, add the `--tls` option to establish a secure
connection:

```bash
nvme connect --transport tcp --traddr 192.168.154.148 --trsvcid 4420 \
             --hostnqn nqn.2014-08.org.nvmexpress:uuid:befdec4c-2234-11b2-a85c-ca77c773af36 \
             --hostid befdec4c-2234-11b2-a85c-ca77c773af36 \
             --nqn nqn.io-1 --tls
```

nvme-cli 3.0 removed `--dump-config`/`--output-format json` from `nvme connect`
(nvme-cli 2.x used them here to print the resulting connection as a
`config.json` you could feed back in); there is no direct replacement. To make
this connection persist across reboots, build the equivalent entry directly in
the INI `nvme-fabrics.conf` with `nvme config create`, using the same options:

```bash
nvme config create --transport tcp --traddr 192.168.154.148 --trsvcid 4420 \
             --hostnqn nqn.2014-08.org.nvmexpress:uuid:befdec4c-2234-11b2-a85c-ca77c773af36 \
             --hostid befdec4c-2234-11b2-a85c-ca77c773af36 \
             --nqn nqn.io-1 --tls
```

Running the same command again is a no-op. `nvme connect-all` (or plain `nvme
connect`, which reads the same file by default) will then pick up the saved
entry. See
[How to add a new INI configuration parameter](ini-parameter.md)
and
[`CONFIG.md`](https://github.com/linux-nvme/nvme-cli/blob/master/libnvme/design/CONFIG.md)
for the format, and `nvme config show`/`nvme config validate` for inspecting the
result.

## Setting Up the Target

The same steps for creating keys and importing/exporting keys to/from the kernel
are necessary for the target as they are for the host (see above).

For the above example, you can use the `nvmetcli` config:

```json
{
  "hosts": [
    {
      "nqn": "nqn.2014-08.org.nvmexpress:uuid:befdec4c-2234-11b2-a85c-ca77c773af36"
    }
  ],
  "ports": [
    {
      "addr": {
        "adrfam": "ipv4",
        "traddr": "0.0.0.0",
        "treq": "not required",
        "trsvcid": "4420",
        "trtype": "tcp",
        "tsas": "tls1.3"
      },
      "ana_groups": [
        {
          "ana": {
            "state": "optimized"
          },
          "grpid": 1
        }
      ],
      "param": {
        "inline_data_size": "16384",
        "pi_enable": "0"
      },
      "portid": 0,
      "referrals": [],
      "subsystems": [
        "nqn.io-1"
      ]
    }
  ],
  "subsystems": [
    {
      "allowed_hosts": [
        "nqn.2014-08.org.nvmexpress:uuid:befdec4c-2234-11b2-a85c-ca77c773af36"
      ],
      "attr": {
        "allow_any_host": "0",
        "cntlid_max": "65519",
        "cntlid_min": "1",
        "firmware": "6.8.0-rc",
        "ieee_oui": "0x000000",
        "model": "Linux",
        "pi_enable": "0",
        "qid_max": "128",
        "serial": "0c74361069d9db6c65ef",
        "version": "1.3"
      },
      "namespaces": [
        {
          "ana": {
            "grpid": "1"
          },
          "ana_grpid": 1,
          "device": {
            "nguid": "00000000-0000-0000-0000-000000000000",
            "path": "/dev/vdb",
            "uuid": "91fdba0d-f87b-4c25-b80f-db7be1418b9e"
          },
          "enable": 1,
          "nsid": 1
        }
      ],
      "nqn": "nqn.io-1"
    }
  ]
}
```
Do note the `treq` setting: If the `tsas` setting is `none`, the only possible
value is `not specified`. If `tsas` is set to `tls1.3`, the default will be set
to `not required`, indicating that both TLS and non-TLS connections are allowed.
To force TLS-only connections set the `treq` to `required`. Be aware that then
also discovery connections are required to be TLS-encrypted.

## Key rotation

It is possible to refresh / rotate the key on an existing connection by storing
the new key in the key store, and writing the resulting key serial number into
the `/sys/class/nvme/nvmeX/tls_key` sysfs attribute. This will cause the
connection to be reset and a new TLS connection will be started with the new
key. Do ensure that the key is present on the target before attempting to
reconnect; otherwise the reconnect might fail.

nvme-keysd does not do this. When it replaces a key, existing connections are
not affected, and new connections use the new key. See
[nvme-keysd](keysd.md#replacing-a-key).

# NVMe authentication with secure concatenation

It is also possible to start a TLS connection with the credentials generated by
the NVMe KX-HMAC-CHAP (formerly DH-HMAC-CHAP; see
[How to set up inband authentication](inband-auth.md))
authentication protocol (the so-called "Secure Concatenation"). After
KX-HMAC-CHAP authentication has been performed on the admin queue a key is
generated from the key material of the authentication, the admin queue is reset,
and a TLS connection is started with the generated key.

## Target considerations for secure concatenation

The target does not require additional configuration for secure concatenation
beyond the 'normal' authentication and the TLS settings mentioned above. The
only requirement is that `treq` must be set to `not required` as the
authentication needs to run on an unencrypted TLS connection initially.

## Host considerations for secure concatenation

The `--concat` argument needs to be added to the `nvme connect` call in addition
to the authentication parameters. Be aware that a connection reset will trigger
a new authentication, and a new TLS key will be generated. Hence a separate key
rotation is not required here.

## Debugging tips

- Increase the debug log output in tlshd:
```ini
[debug]
loglevel=9
```

- To verify if any key is present you can look at the `/proc/keys` output:
```bash
cat /proc/keys | grep -i nvme
```

- The key's description is the key identifier and is defined in the TCP
  transport specification (see the 'TLS PSK and PSK Identity Derivation'
  section). The format is `NVMe<version>R<hmac> <hostnqn> <subsysnqn> <PSK
  digest>`

- The exported keys in the /etc/nvme/tls-keys file are one per line and the
  lines are formatted as `<identity> <PSK in interchange format>`. The `<PSK>`
  is the derived TLS PSK and neither the retained nor the configured PSK.

- If several keys are available in the keystore that match up to the `<PSK
  digest>`, the first match will be used. If this is the wrong key, it can be
  revoked by (nvme-cli 2.x: `nvme tls --revoke <identity>`)
```bash
nvme keys revoke --identity=<identity>
```

- It's possible to provide a TLS key directly via the `nvme connect --tls
  --tls-key` command. If only the key is provided, nvme-cli assumes it is a
  configured PSK and thus does all the key transformation and creates the
  identity automatically. If the `--tls-key-identity` is also present, nvme-cli
  assumes it is a derived TLS PSK and does not attempt transformation on it and
  inserts the key directly into the keystore.

- When the `nvme connect --tls-key` command is used, the `-vv` options will show
  the connect arguments passed to the kernel, including the key id numbers.
  These are in hex format and match with the output from `/proc/keys`.

- When using the `--tls-key` option, it is not possible to refresh the key. So
  it is recommended to use this option for debugging only, and not use it in
  production.
