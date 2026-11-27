<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# The `nvme keys` Plugin

nvme-cli 3.0 moved key and secret management into one plugin: `nvme keys`. It
handles both kinds of credential NVMe-oF uses:

- **TLS pre-shared keys (PSKs)** -- encrypt the connection.
- **KX-HMAC-CHAP secrets** -- authenticate the host and controller to each
  other. KX-HMAC-CHAP was called DH-HMAC-CHAP before NVMe TP4201.

If you used `nvme gen-dhchap-key`, `nvme gen-tls-key`, `nvme check-tls-key`, or
`nvme tls` before, see
[Migrating from nvme-cli 2.x to 3.0](migrating-2-to-3.md) for the
old-to-new command mapping. For task-based walkthroughs, see
[How to set up TLS for NVMe-TCP](tls.md) and
[How to set up inband authentication](inband-auth.md).

This page is a reference for the eight `nvme keys` subcommands. Run `nvme keys
<subcommand> --help` for the full option list.

## KX-HMAC-CHAP secrets

### `nvme keys gen-kxchap-secret`

Generates a KX-HMAC-CHAP secret and prints it in the DHHC-1 string format:

```bash
# nvme keys gen-kxchap-secret --hmac=1
DHHC-1:01:ia6zGodOr4SEG0Zzaw398rpY0wqipUWj4jWjUh4HWUz6aQ2n:
```

| Option | Meaning |
|---|---|
| `-m`, `--hmac` | Hash function to record (0 = none, 1 = SHA-256, 2 = SHA-384, 3 = SHA-512). Default 0. |
| `-s`, `--secret` | Secret value in hex. Random if not given. |
| `-l`, `--secret-length` | Secret length: 32, 48, or 64 bytes. |

Use the printed value with `--kxchap-secret` on `nvme connect`, or with
`kxchap-secret` in `nvme-fabrics.conf`.

### `nvme keys check-kxchap-secret`

Checks that a string is a valid KX-HMAC-CHAP secret, and optionally whether it
is already loaded in a keyring. Add `-v`/`--verbose` to print the verdict;
without it, only the exit status reports success or failure:

```bash
$ nvme keys check-kxchap-secret -v --keydata DHHC-1:01:ia6zGodOr4SEG0Zzaw398rpY0wqipUWj4jWjUh4HWUz6aQ2n:
```

| Option | Meaning |
|---|---|
| `-d`, `--keydata` | Secret to check. Read from stdin if not given. |
| `-i`, `--identity` | Also check whether this identity is already loaded in the keyring. |
| `-k`, `--keyring` | Keyring to check. Default `.nvme`. |
| `-t`, `--keytype` | Keyring key type to look up. Default `kxchap`. |
| `-v`, `--verbose` | Print the verdict on stdout. Without it, only the exit status reports success or failure. |

This command never changes the keyring.

## TLS pre-shared keys

There are two ways to get a TLS PSK into the keyring: generate a new one, or
insert one you already have.

### `nvme keys gen-tls-psk`

Generates a new configured PSK from random data. With `--insert`, it also
derives the retained PSK and then the TLS PSK from it. It stores the TLS PSK in
the keyring. The kernel uses this key:

```bash
nvme keys gen-tls-psk --hostnqn <host-nqn> --subsysnqn <subsys-nqn> \
  --hmac 1 --identity 1 --insert --keyfile /etc/nvme/tls-keys
```

| Option | Meaning |
|---|---|
| `-n`, `--hostnqn` | Host NQN the key is derived for. |
| `-c`, `--subsysnqn` | Subsystem NQN the key is derived for. |
| `-m`, `--hmac` | Hash function (1 = SHA-256, 2 = SHA-384). Default 1. |
| `-I`, `--identity` | TLS identity version: 0 (original) or 1 (TP8018). |
| `-i`, `--insert` | Also derive and store the TLS PSK in the keyring. |
| `-C`, `--compat` | Use the original non-RFC 8446 algorithm when deriving the retained and TLS PSKs, for compatibility with older implementations. |
| `-f`, `--keyfile` | Also append the key to this file. Requires `--insert`. |

The configured PSK is always printed, in interchange format
(`NVMeTLSkey-1:01:...`), whether or not `--insert` is given.

### `nvme keys insert-tls-psk`

Takes a configured PSK you already have (in interchange format) and derives
the retained PSK and then the TLS PSK from it, storing the TLS PSK. Use this
when you received a PSK from somewhere else, rather than generating a fresh
one:

```bash
nvme keys insert-tls-psk --hostnqn <host-nqn> --subsysnqn <subsys-nqn> \
  --keydata NVMeTLSkey-1:01:... --keyfile /etc/nvme/tls-keys
```

| Option | Meaning |
|---|---|
| `-n`, `--hostnqn` | Host NQN to derive the retained PSK for. |
| `-c`, `--subsysnqn` | Subsystem NQN to derive the retained PSK for. Required. |
| `-d`, `--keydata` | PSK to insert. Read from stdin if not given. |
| `-I`, `--identity` | TLS identity version: 0 or 1. |
| `-C`, `--compat` | Use the original non-RFC 8446 algorithm when deriving the retained and TLS PSKs, for compatibility with older implementations. |
| `-f`, `--keyfile` | Also append the key to this file. |

This command always inserts. There is no `--insert` flag, unlike
`gen-tls-psk`.

### `nvme keys check-tls-psk`

Checks that a string is a valid configured PSK. With `--subsysnqn`, it also
checks whether the TLS PSK derived from it is already in the keyring. Like
other `check-*` commands, add `-v`/`--verbose` to print the
verdict; without it, only the exit status reports success or failure:

```bash
$ nvme keys check-tls-psk -v --keydata NVMeTLSkey-1:01:... --subsysnqn <subsys-nqn>
```

| Option | Meaning |
|---|---|
| `-d`, `--keydata` | PSK to check. Read from stdin if not given. |
| `-c`, `--subsysnqn` | Also check whether the derived TLS PSK is already loaded. |
| `-n`, `--hostnqn` | Host NQN. Only used together with `--subsysnqn`. |
| `-I`, `--identity` | TLS identity version: 0 or 1. |
| `-C`, `--compat` | Use the original non-RFC 8446 algorithm when deriving the TLS PSK identity. No effect with identity version 0. |
| `-v`, `--verbose` | Print the verdict on stdout. Without it, only the exit status reports success or failure. |

This command never changes the keyring. Use `insert-tls-psk` to actually load
a key.

## Keyring bulk operations

These three subcommands work on both KX-HMAC-CHAP secrets and TLS PSKs already
in interchange/DHHC-1 form. The key type is detected from the string's prefix.

### `nvme keys import`

Loads one or more keys into a keyring:

```bash
nvme keys import --keyfile /etc/nvme/tls-keys
```

Without `--identity`, it reads `<description> <key>` pairs in bulk, one per line
-- the format `nvme keys export` writes. With `--identity`, it loads a single
key under that explicit identity instead, from `--keydata` or stdin:

```bash
nvme keys import --identity host2 --keydata DHHC-1:00:...
```

| Option | Meaning |
|---|---|
| `-k`, `--keyring` | Keyring to import into. Default `.nvme`. |
| `-f`, `--keyfile` | File to read from. Bulk mode only. |
| `-d`, `--keydata` | Key to insert. Single-identity mode only. |
| `-i`, `--identity` | Identity to store a single key under. |

### `nvme keys export`

Writes every key in a keyring out as `<description> <key>` pairs, one per line:

```bash
nvme keys export --keyfile /etc/nvme/tls-keys
```

| Option | Meaning |
|---|---|
| `-k`, `--keyring` | Keyring to export from. Default `.nvme`. |
| `-f`, `--keyfile` | File to write to. Default stdout. |

### `nvme keys revoke`

Removes one key from a keyring, by its description:

```bash
nvme keys revoke --identity="NVMe0R01 hostnqn0 subsys0"
```

| Option | Meaning |
|---|---|
| `-i`, `--identity` | Description of the key to remove. Required. |
| `-k`, `--keyring` | Keyring to remove from. Default `.nvme`. |
| `-t`, `--keytype` | Key type to remove. Default `psk`. |

## Defaults to remember

- The default keyring is always `.nvme`.
- The default keytype is `psk` for TLS commands and `kxchap` for KX-HMAC-CHAP
  commands. Pass `--keytype` explicitly if you use a different keyring layout.
- Most setups pass a KX-HMAC-CHAP secret directly, with `--kxchap-secret` on
  `nvme connect` or `kxchap-secret` in `nvme-fabrics.conf`. `nvme keys
  import`/`check-kxchap-secret` can also load one into a keyring under key type
  `kxchap`, but no released Linux kernel looks a secret up there yet.
