# How to Set Up TLS for NVMe-TCP

Enabling TLS for the NVMe-TCP transport requires a few configuration
steps for both the kernel and userland.

## Kernel Configuration

To support TCP authentication and TLS encryption, enable the following
kernel options:

- For DHCHAP authentication:
  `CONFIG_NVME_HOST_AUTH`

- For TLS transport encryption:
  `CONFIG_NVME_TCP_TLS`

These configuration option depend on another config option but these
will be auto selected.

## Userland

For the userland configuration two components need to be configured.
First, the tlshd TLS handshake daemon needs to be running and TLS keys
need to be loaded into the kernel keystore.

### Setting Up `tlshd`

For TLS protocol support, which handles authentication and encryption,
the kernel handles data encryption only, so userland support is required
for the TLS handshake. The `tlshd` daemon implements the handshake
process.

#### Requirements

Ensure `tlshd` includes the commit `311d9438b984` ("tlshd: always link
.nvme default keyring into the session") - likely in `ktls-utils` version
0.12. Alternatively, you can set the keyring manually in
`/etc/tlshd.conf`:

```ini
[authenticate]
keyrings = .nvme
```

#### Enable/start tlshd

No additional configuration is necessary for `tlshd`; simply start it as
a daemon:

```bash
systemctl enable --now tlshd
```

### Loading Keys on Boot or Module Load

When the kernel is establishing a TCP connection with TLS, the NVMe
subsystem loads keys from the kernel keystore. This means these keys
must be available in the keystore before establishing a connection.

nvme-cli provides command line interfaces to create, import and export
keys into the kernel keystore. Though it's not the only way to
import/export keys. If there is another system component managing the
keys, the following steps for creating and making the keys persistent
over boot cycles are not necessary.

To stress this point, the nvme-cli is explicitly trying to avoid handling
the keys, the only requirement is that the keys are present in the
keystore.

#### Creating a New Key

```bash
nvme gen-tls-key \
  --hostnqn nqn.2014-08.org.nvmexpress:uuid:befdec4c-2234-11b2-a85c-ca77c773af36 \
  --subsysnqn nqn.io-1 --hmac 1 --identity 1 --insert --keyfile /etc/nvme/tls-keys
```

This command creates a new host key, inserts it into the kernel keyring,
and appends the derived TLS PSK to the keyfile (`/etc/nvme/tls-keys`).

### Inserting an Existing Key

```bash
nvme check-tls-key \
  --hostnqn nqn.2014-08.org.nvmexpress:uuid:befdec4c-2234-11b2-a85c-ca77c773af36 \
  --subsysnqn nqn.io-1 --identity 1 \
  --keydata NVMeTLSkey-1:01:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACtVQoZ: \
  --insert --keyfile /etc/nvme/tls-keys
```

This command inserts the configured key (`--keydata`) into the kernel
keyring and appends the derived TLS PSK to the keyfile.

### Loading Keys on Boot or Module Load

The kernel keyring does not persist keys, so userland must import keys
into the keyring upon each boot or module load (for NVMe-TCP). The
nvme-tcp module provides the `psk` type keystore, thus only when the
nvme-tcp module is available it possible to load keys into the keystore:

```bash
nvme tls --import --keyfile /etc/nvme/tls-keys
```

The `70-nvmf-keys.rules` udev rule
([source](https://github.com/linux-nvme/nvme-cli/blob/master/nvmf-autoconnect/udev-rules/70-nvmf-keys.rules.in))
will load keys from `/etc/nvme/tls-keys` automatically.

```udev
ACTION=="add", SUBSYSTEM=="module", KERNEL=="nvme_tcp", TEST=="@SYSCONFDIR@/tls-keys", RUN+="@SBINDIR@/nvme tls --import --keyfile @SYSCONFDIR@/tls-keys"
```

### Recommendation for Handling TLS Keys

The `nvme connect` command also allows passing a TLS key directly via the
command line or a JSON config file. Avoid this method in production
environments, as it may expose keys.

### Establishing a Connection

Once the keys are in the keystore, add the `--tls` option to establish a
secure connection:

```bash
nvme connect --transport tcp --traddr 192.168.154.148 --trsvcid 4420 \
             --hostnqn nqn.2014-08.org.nvmexpress:uuid:befdec4c-2234-11b2-a85c-ca77c773af36 \
             --hostid befdec4c-2234-11b2-a85c-ca77c773af36 \
             --nqn nqn.io-1 --tls --dump-config --output-format json
```

The resulting JSON output can be saved to simplify future connections:

```json
[
  {
    "hostnqn": "nqn.2014-08.org.nvmexpress:uuid:befdec4c-2234-11b2-a85c-ca77c773af36",
    "hostid": "befdec4c-2234-11b2-a85c-ca77c773af36",
    "subsystems": [
      {
        "nqn": "nqn.io-1",
        "ports": [
          {
            "transport": "tcp",
            "traddr": "192.168.154.148",
            "trsvcid": "4420",
            "dhchap_key": "none",
            "tls": true
          }
        ]
      }
    ]
  }
]
```

Using this JSON file, you can connect with:

```bash
nvme connect --config config.json
```

## Setting Up the Target

The same steps for creating keys and importing/exporting keys to/from the
kernel are necessary for the target as they are for the host (see above).

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
        "treq": "not specified",
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

- The keys description is the key identifier and is defined in the TCP
transport specification (see the 'TLS PSK and PSK Identity Derivation'
section). The format is `NVMe<version>R<hmac> <hostnqn> <subsynqn> <PSK digest>`

- The exported keys in the /etc/nvme/tls-keys file are one per line and
the lines are formatted as `<identity> <PSK in interchange format>`. The
`<PSK>` is the derive TLS PSK and not the retained nor the configured PSK.

- If several keys available in the keystore which match up to the `<PSK digest>`
the first match will be used. If this is the wrong key, it can be revoked by
```bash
nvme tls --revoke <identity>
```

- It's possible to provide a TLS key directly via the `nvme connect --tls
--tls-key` command. If only the key is provided, nvme-cli assumes it is a
configured PSK and thus does all the key transformation and creates the
identity automatically. If the `--tls-key-identity` is also present
nvme-cli assumes it is a derived TLS PSK and does not attempt
transformation on it and inserts the key directly into the keystore.

- When the `nvme connect --tls-key` command is used, the `-vv` options
will show the connect arguments passed to the kernel, including the key
id numbers. These are in hex format and match with the output from
`/proc/keys`.
