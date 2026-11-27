<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# How to set up inband authentication

NVMe in-band authentication lets the controller and the host check each
other's identity when they connect. The protocol is KX-HMAC-CHAP. Before
nvme-cli 3.0, it was called DH-HMAC-CHAP. Both sides share a secret.

This page uses the nvme-cli 3.x command names. The 2.x names still work in 3.x
as deprecated aliases. They print a warning and will be removed in the next
major version.

| nvme-cli 3.x | nvme-cli 2.x |
|---|---|
| `nvme keys gen-kxchap-secret` | `nvme gen-dhchap-key` |
| `nvme keys check-kxchap-secret` | `nvme check-dhchap-key` |
| `--kxchap-secret` | `--dhchap-secret` |
| `--kxchap-ctrl-secret` | `--dhchap-ctrl-secret` |

## Unidirectional and bidirectional authentication

- **Unidirectional:** the controller authenticates the host. The host needs
  its own secret, the host secret (`--kxchap-secret`).
- **Bidirectional:** the controller authenticates the host, and the host also
  authenticates the controller. The host needs the host secret and the
  controller secret (`--kxchap-ctrl-secret`).

The host decides which one is used. If the target knows both secrets, a
unidirectional connection still works.

## Generate the secrets

Generate one secret for the host. For bidirectional authentication, generate a
second one for the controller:

```bash
# nvme keys gen-kxchap-secret
DHHC-1:00:qMSb6q2k5Qdi4byvNPHJLfLdvQ+H25eMIbPFqpFjK89VDG10:
```

The output is the secret in the DHHC-1 format of the NVMe specification. The
second field is the hash function that the consumer applies to the secret:

| `--hmac` | Hash function | Default length |
|---|---|---|
| 0 (default) | none | 32 bytes |
| 1 | SHA-256 | 32 bytes |
| 2 | SHA-384 | 48 bytes |
| 3 | SHA-512 | 64 bytes |

```bash
# nvme keys gen-kxchap-secret --hmac=2
DHHC-1:02:UtLfK7fSXYsHWJ7Owbs835A9DO9bTQGaG/Vu7R/LGjRXYt82LDSFVJO9aEFjSOISKjo4ag==:
```

Use `--secret-length` (32, 48 or 64) to select another length.

Since nvme-cli 3.0, `--hmac` only records the hash function. The secret itself
is not changed. nvme-cli 2.x transformed the secret with `--hmac` and the NQN
of `--nqn`. Because of this, 2.x and 3.x print different secrets for the same
input when `--hmac` is not 0. The deprecated `gen-dhchap-key` accepts `--nqn`,
prints a warning and ignores it.

Secure concatenation supports only SHA-256 and SHA-384 (`--hmac=1` or
`--hmac=2`). Do not use a secret for SHA-512 with secure concatenation.

## Configure the target

On a Linux target (nvmet), the secrets belong to the host entry. The
attribute names still use the old name, `dhchap`. With configfs:

```bash
cd /sys/kernel/config/nvmet
HOSTNQN=nqn.2014-08.org.nvmexpress:uuid:066d3885-3e3f-498c-b6e8-695c71636a13

mkdir hosts/$HOSTNQN
echo "DHHC-1:00:qMSb6q2k5Qdi4byvNPHJLfLdvQ+H25eMIbPFqpFjK89VDG10:" \
    > hosts/$HOSTNQN/dhchap_key
# Only for bidirectional authentication:
echo "DHHC-1:02:UtLfK7fSXYsHWJ7Owbs835A9DO9bTQGaG/Vu7R/LGjRXYt82LDSFVJO9aEFjSOISKjo4ag==:" \
    > hosts/$HOSTNQN/dhchap_ctrl_key
echo "hmac(sha256)" > hosts/$HOSTNQN/dhchap_hash
echo null > hosts/$HOSTNQN/dhchap_dhgroup

# Allow only this host on the subsystem:
echo 0 > subsystems/nqn.2024-01.com.example:auth.vol1/attr_allow_any_host
ln -s $PWD/hosts/$HOSTNQN subsystems/nqn.2024-01.com.example:auth.vol1/allowed_hosts/
```

With nvmetcli, the same settings are in the `hosts` section of the JSON file:

```json
{
  "hosts": [
    {
      "nqn": "nqn.2014-08.org.nvmexpress:uuid:066d3885-3e3f-498c-b6e8-695c71636a13",
      "dhchap_key": "DHHC-1:00:qMSb6q2k5Qdi4byvNPHJLfLdvQ+H25eMIbPFqpFjK89VDG10:",
      "dhchap_ctrl_key": "DHHC-1:02:UtLfK7fSXYsHWJ7Owbs835A9DO9bTQGaG/Vu7R/LGjRXYt82LDSFVJO9aEFjSOISKjo4ag==:",
      "dhchap_hash": "hmac(sha256)",
      "dhchap_dhgroup": "null"
    }
  ]
}
```

`dhchap_hash` selects the HMAC function of the protocol: `hmac(sha256)` (the
default), `hmac(sha384)` or `hmac(sha512)`. It does not depend on the `--hmac`
value of the secret. The secret should be at least as long as the output of
this hash function.

`dhchap_dhgroup` selects the Diffie-Hellman group: `null`, `ffdhe2048`,
`ffdhe3072`, `ffdhe4096`, `ffdhe6144` or `ffdhe8192`. With `null`, there is no
Diffie-Hellman exchange and no shared key. Secure concatenation needs a group
other than `null`, because the TLS key comes from the shared key.

## Connect

Unidirectional:

```bash
nvme connect --transport=tcp --traddr=192.168.30.30 \
    --nqn=nqn.2024-01.com.example:auth.vol1 \
    --kxchap-secret="DHHC-1:00:qMSb6q2k5Qdi4byvNPHJLfLdvQ+H25eMIbPFqpFjK89VDG10:"
```

Bidirectional:

```bash
nvme connect --transport=tcp --traddr=192.168.30.30 \
    --nqn=nqn.2024-01.com.example:auth.vol1 \
    --kxchap-secret="DHHC-1:00:qMSb6q2k5Qdi4byvNPHJLfLdvQ+H25eMIbPFqpFjK89VDG10:" \
    --kxchap-ctrl-secret="DHHC-1:02:UtLfK7fSXYsHWJ7Owbs835A9DO9bTQGaG/Vu7R/LGjRXYt82LDSFVJO9aEFjSOISKjo4ag==:"
```

The kernel log shows the result:

```
nvme nvme0: qid 0: authenticated with hash hmac(sha384) dhgroup ffdhe2048
nvme nvme0: qid 0: authenticated
```

If the target requires authentication and no secret is given, the connect
fails with:

```
connect: failed to connect: TLS PSK or KX-HMAC-CHAP secret not available
```

A wrong controller secret makes the bidirectional connect fail with
`failed to write to nvme-fabrics device`. The kernel log has the details.

## Save the configuration

Save the connection with its secret in `/etc/nvme/nvme-fabrics.conf` with
`nvme config create`. It takes the same options as `nvme connect`:

```bash
nvme config create --transport=tcp --traddr=192.168.30.30 --trsvcid=4420 \
    --nqn=nqn.2024-01.com.example:auth.vol1 \
    --kxchap-secret="DHHC-1:00:qMSb6q2k5Qdi4byvNPHJLfLdvQ+H25eMIbPFqpFjK89VDG10:"
```

This adds the entry:

```ini
[Subsystem]
nqn = nqn.2024-01.com.example:auth.vol1
kxchap-secret = DHHC-1:00:qMSb6q2k5Qdi4byvNPHJLfLdvQ+H25eMIbPFqpFjK89VDG10:
controller = transport=tcp;traddr=192.168.30.30;trsvcid=4420
```

If the entry exists already, the command does nothing. `nvme config show` and
`nvme config validate` show and check the file.

`nvme connect-all` without options connects all entries of the file, with
their secrets. The autoconnect and nvme-discoverd also use the file. `nvme
connect` does not read the file. It uses only its command line, or the file
given with `--config`.

The secret is stored in plain text in this file. In nvme-cli 3.2, `nvme
config create` writes the file with mode 0644, so every user can read it.
This also happens when the file had another mode before. Restrict it to root
after each `nvme config create`:

```bash
chmod 600 /etc/nvme/nvme-fabrics.conf
```

Since nvme-cli 3.2, a subsystem found through discovery can have its own
secrets in the file. See [How to configure NVMe-oF
connections](fabrics-config.md#secrets-for-discovered-subsystems).

## See also

- [The `nvme keys` Plugin](keys-plugin.md)
- [How to set up TLS for NVMe over TCP](tls.md)
- [How to configure NVMe-oF connections](fabrics-config.md)
- [`nvme-keys-gen-kxchap-secret(1)`](man:nvme-keys-gen-kxchap-secret), [`nvme-connect(1)`](man:nvme-connect), [`nvme-fabrics.conf(5)`](man:nvme-fabrics.conf)
- [NVMe in-band authentication](https://blogs.oracle.com/linux/post/nvme-inband-authentication)
  (Oracle Linux blog)
