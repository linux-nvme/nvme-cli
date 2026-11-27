<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# nvme-keysd

nvme-keysd loads TLS PSKs for NVMe/TCP into the kernel's `.nvme` keyring. It
gets the keys from encrypted systemd credentials, or from a key management
server (KMS) over KMIP. Because of this, the keys do not appear in plain text in
`nvme-fabrics.conf`. The kernel finds the key in the keyring when `nvme connect`
or nvme-discoverd connects with TLS.

nvme-keysd is new in nvme-cli 3.2. It is a **technology preview**. It is
disabled by default. Build with `-Dnvme-keysd=enabled` to try it. It requires
the `fabrics` build option, OpenSSL, libkeyutils and libsystemd 257 or later.
At runtime it needs systemd 257 or later.

KMIP support is in the `nvme-keysd-kmip` helper. The `kmip` build option
controls it. Its default is `auto`, so the helper is built whenever nvme-keysd
is built.

The design is discussed in
[issue #3719](https://github.com/linux-nvme/nvme-cli/issues/3719). Comments
there are welcome.

## Why does it exist?

TLS for NVMe/TCP uses a pre-shared key (PSK). The kernel reads the PSK from the
`.nvme` keyring. Without nvme-keysd, there are two ways to get a PSK there (see
[How to set up TLS for NVMe-TCP](tls.md)):

- Write the PSK in plain text into `/etc/nvme/tls-keys`. A udev rule imports
  this file when the `nvme_tcp` module loads.
- Write the PSK in plain text as `tls-key` in `nvme-fabrics.conf`.

In both cases the key is stored in plain text on disk. Anyone who can read the
file or a backup of it has the key.

nvme-keysd offers two other places for the key:

- **systemd credentials.** The PSK is stored encrypted on disk. systemd decrypts
  it with the TPM2 chip or a host key.
- **A KMS.** The PSK is not stored on the host at all. The KMS holds the keys of
  all hosts in one place.

In both cases, `nvme-fabrics.conf` contains only the name of the key, not the
key itself.

The plain-text methods keep working. Nothing changes for existing
configurations.

## How it works

At boot, `nvme-keysd.service` does the following:

1. It runs `nvme-keysd --should-start`. If no entry in `nvme-fabrics.conf` has
   a `tls-key-source` other than `inline`, the unit stops here. It does not
   load any module.
2. It loads the `nvme_keyring` module. This module creates the `.nvme` keyring.
3. nvme-keysd reads `nvme-fabrics.conf`. For each entry with
   `tls-key-source = systemd-creds`, it decrypts the named credential through
   systemd-creds.
4. It writes the PSK into the keyring. The key identity contains the host NQN
   and the subsystem NQN, as with `nvme connect`.
5. It reports to systemd that it is ready. The units that start after
   nvme-keysd now find these keys.
6. Without a `kmip` entry, it exits. With a `kmip` entry, it keeps running and
   gets the KMIP keys in the background. See [KMIP](#kmip).

Later, a connection with TLS finds the key in the keyring. The connection does
not use the `tls-key` value. The kernel searches the keyring by host NQN and
subsystem NQN.

## Usage

Create a PSK in the NVMe PSK interchange format
(`NVMeTLSkey-1:<hmac>:<base64 data>:`). `nvme keys gen-tls-psk` creates keys in
this format. See [The `nvme keys` Plugin](keys-plugin.md).

Encrypt the key into the credential directory:

```bash
systemd-creds encrypt psk.txt /etc/nvme/creds/vol1-psk
shred -u psk.txt
```

The file name is the credential name. systemd-creds stores this name in the
credential. When nvme-keysd decrypts the file, systemd-creds checks that the
stored name matches the file name. So do not rename the file after you encrypt
it. If you use `--name`, it must match the file name.

Name the credential in `nvme-fabrics.conf`:

```ini
[Subsystem]
nqn            = nqn.2024-01.com.example:storage.vol1
controller     = transport=tcp;traddr=192.0.2.10;trsvcid=4420
tls            = true
tls-key-source = systemd-creds
tls-key        = vol1-psk
```

`tls-key-source` accepts these values:

| Value | Meaning |
|---|---|
| `inline` | Default. `tls-key` contains the key itself. |
| `systemd-creds` | `tls-key` contains the name of a credential in `/etc/nvme/creds/`. |
| `kmip:<name>` | `tls-key` contains the Name of a key on the KMS `<name>`. `kmip` alone is enough when only one KMS is configured. See [KMIP](#kmip). |

nvme-keysd writes the key into the keyring named by the `keyring` key of the
entry, in the endpoint section or in `[Host]`. The default is `.nvme`.

Enable the service once, after nvme-keysd is installed. A distribution package
may already do this. After a build from source with meson, do it by hand:

```bash
systemctl enable --now nvme-keysd.service
```

Do not run this command again when you change the configuration. Restart the
service instead, after you add or change an entry, a credential or a KMIP key:

```bash
systemctl restart nvme-keysd.service
```

Check the log:

```bash
journalctl -u nvme-keysd.service
```

## KMIP

With `tls-key-source = kmip:<name>`, nvme-keysd gets the PSK from a KMS that
supports KMIP 1.4. `<name>` is a `[kmip:<name>]` section of
`/etc/nvme/nvme-keysd.conf`.

### The key on the KMS

`tls-key` is the Name of the key on the KMS. The key is one of:

- Secret Data that holds the PSK in the PSK interchange format.
- A Symmetric Key of 32 bytes (SHA-256) or 48 bytes (SHA-384).

Only a key in the Active state is used. Two Active keys with the same Name are
an error.

### Setup

The KMS knows the host by its TLS client certificate. Store the client private
key as a systemd credential in `/etc/nvme/creds/kmip/`. systemd gives it to the
helper as `kmip_<file>`, so `--name` must be `kmip_` followed by the file name:

```bash
systemd-creds encrypt --name=kmip_my-client-key client-key.pem \
	/etc/nvme/creds/kmip/my-client-key
shred -u client-key.pem
```

The CA and the client certificate are not secret. They must be readable by any
user, because the helper runs without privileges.

Describe the KMS in `/etc/nvme/nvme-keysd.conf`:

```ini
[kmip:my-kms]
server      = kms1.example.com
server      = kms2.example.com
ca          = /etc/nvme/kmip/ca.pem
client-cert = /etc/nvme/kmip/client.pem
client-key  = my-client-key
```

Name the key in `nvme-fabrics.conf`:

```ini
[Subsystem]
nqn            = nqn.2024-01.com.example:storage.vol1
controller     = transport=tcp;traddr=192.0.2.10;trsvcid=4420
tls            = true
tls-key-source = kmip:my-kms
tls-key        = my-vol1-psk
```

The keys of the section:

| Key | Meaning |
|---|---|
| `server` | Host name or IP address. Required. Repeat it for each server of the cluster. |
| `port` | TCP port of the servers. Default 5696. |
| `ca` | CA certificate that signed the server certificates (PEM). Default: the system CAs. |
| `client-cert` | Client certificate (PEM). Requires `client-key`. |
| `client-key` | File name of the client private key in `/etc/nvme/creds/kmip/`. Requires `client-cert`. |
| `timeout` | Time limit for one server: connect, TLS handshake and requests. Default 10s. Each TCP connect fails after 3 seconds at most. |

### Servers and retries

The servers of one KMS are nodes of one cluster and hold the same keys.
nvme-keysd tries them in order, until one answers. Different KMSes are asked in
parallel.

nvme-keysd does not delay the boot for a KMS. When it cannot get a key, it
tries again after 5 seconds, then after twice the previous delay, up to 5
minutes. `systemctl status nvme-keysd` shows how many KMIP keys are not
imported yet.

A connection that needs a KMIP key can therefore start before the key is in the
keyring. nvme-discoverd connects again later. A single `nvme connect` does not.

## Replacing a key

**systemd credentials:** replace the credential file with a new key. Then
restart nvme-keysd.

**KMIP:** activate the new key on the KMS with the same Name, and deactivate
the old key. Then restart nvme-keysd. nvme-keysd gets a KMIP key once, at
start. It does not check the KMS for a new key later.

nvme-keysd imports the new key. Then it revokes every other key for the same
host NQN and subsystem NQN. Because of this, the kernel always finds exactly one
key.

Existing connections are not affected. TLS uses the PSK only during the
handshake. New connections use the new key.

A key that is already in the keyring is not written again.

## Failure behavior

nvme-keysd never logs key material.

If nvme-keysd cannot decrypt a credential, it logs an error. It imports the
other keys. If it cannot get a KMIP key, it logs an error and tries again (see
[Servers and retries](#servers-and-retries)). The helper logs its errors under
the identifier `nvme-keysd-kmip`:

```bash
journalctl -t nvme-keysd-kmip
```

nvme-keysd never revokes a key because you removed its entry from
`nvme-fabrics.conf`. Because of this, it cannot break a live connection by
mistake. Use `nvme keys revoke` to remove a key by hand.

## Configuration

nvme-keysd has its own optional file, `/etc/nvme/nvme-keysd.conf`. The
`[Global]` section holds the daemon's settings. The `[kmip:<name>]` sections
describe the KMSes (see [Setup](#setup)).

`meson install` does not install this file. It installs a commented
`nvme-keysd.conf.sample` instead. Copy it to `nvme-keysd.conf` to change a
setting.

```ini
[Global]
debug-level = info
```

`debug-level` is one of `err`, `warn`, `info` or `debug`. The default is
`info`. `--debug` on the command line overrides it. A missing file or key keeps
the default.

| Option | Meaning |
|---|---|
| `-c`, `--config=<FILE>` | Use `<FILE>` instead of `/etc/nvme/nvme-keysd.conf`. |
| `--fabrics-config=<FILE>` | Use `<FILE>` instead of `/etc/nvme/nvme-fabrics.conf`. |
| `--creds-dir=<DIR>` | Use `<DIR>` instead of `/etc/nvme/creds`. |
| `--should-start` | Exit with 0 if an entry has a `tls-key-source` other than `inline`. Otherwise exit with 1. |
| `-d`, `--debug` | Enable debug logging for nvme-keysd and libnvme. |

## Security

nvme-keysd runs as uid 0, because the kernel checks access to the `.nvme`
keyring by uid. The unit removes all capabilities. A system call filter
restricts it further. Core dumps are disabled. nvme-keysd has no network
access.

The unit does not use `PrivateNetwork=`. A PSK belongs to the network namespace
of the process that adds it. The kernel deletes the key when this namespace goes
away. In a private namespace, every key would be deleted when nvme-keysd exits.

The `nvme-keysd-kmip` helper does all communication with the KMS. It runs with
a dynamic user, without privileges, and only it has network access. nvme-keysd
talks to it over a local socket. systemd starts one helper per request. The
helper parses the replies of the KMS, so a bug in this parser does not run as
root. systemd decrypts the client private key for the helper. Only that helper
instance can read it.

`/etc/nvme/creds/` has mode 0700. A copy of an encrypted credential is useless
on another machine, if the credential is bound to the TPM2 chip or the host
key.

root can still read a PSK from the keyring. This is also true without
nvme-keysd.

## Current limits

- Only TLS PSKs. KX-HMAC-CHAP secrets still need `dhchap-secret` in plain text.
  The kernel cannot read them from a keyring yet.
- KMIP 1.4 only. nvme-keysd gets a KMIP key only at start.
- No status command yet. A new `nvme keys` subcommand is planned. It shows which
  keys nvme-keysd manages and where they come from.
- No live re-keying. This depends on work in the NVM Express organization.

## See also

- [`nvme-keysd(8)`](man:nvme-keysd), [`nvme-fabrics.conf(5)`](man:nvme-fabrics.conf), `systemd-creds(1)`
- [How to set up TLS for NVMe-TCP](tls.md)
- [The `nvme keys` Plugin](keys-plugin.md)
- [How to configure NVMe-oF connections](fabrics-config.md)
- [nvme-discoverd](discoverd.md)
- [nvme-keysd's own README](https://github.com/linux-nvme/nvme-cli/blob/master/keysd/README.md)
- [Issue #3719: How to deal with secrets/keys?](https://github.com/linux-nvme/nvme-cli/issues/3719)
