<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# How to securely erase an NVMe device

nvme-cli has two commands that erase data beyond recovery: `nvme sanitize` and
`nvme format --ses`. Both are destructive. Neither has an undo.

If your drive is TCG Opal-locked, see
[How to enable TCG Opal support with nvme-cli and cryptsetup](tcg-opal.md)
instead. `nvme sed revert` is a third way to destroy data, specific to Opal
drives.

## `nvme sanitize`: erase the whole device

Sanitize acts on the whole device, not one namespace. Pick an action with
`-a`/`--sanact`:

| Action | Meaning |
|---|---|
| `start-block-erase` | Erase every block. Fast on drives with a hardware erase. |
| `start-crypto-erase` | Delete the drive's internal encryption key. Every block becomes unreadable instantly. |
| `start-overwrite` | Overwrite every block with a pattern, `--owpass` times. Slowest, most thorough. |
| `exit-failure` | Clear a failed sanitize operation so a new one can start. |
| `exit-media-verification` | Leave the media verification state (see `--emvs` below). |

```bash
# nvme sanitize /dev/nvme0 --sanact=start-crypto-erase
```

Not every drive supports every action. `nvme sanitize` checks the controller's
capabilities first and refuses an unsupported action with an error, instead of
sending a command the drive would reject.

A few options change how the action runs:

| Option | Meaning |
|---|---|
| `-n`, `--owpass` | Number of overwrite passes. Only for `start-overwrite`. |
| `-u`, `--ause` | Allow Unrestricted Sanitize Exit. Lets you cancel and reuse the drive even if sanitize fails. |
| `-d`, `--no-dealloc` | Do not deallocate blocks after a successful sanitize. |
| `-e`, `--emvs` | Enter a media verification state after a successful sanitize, instead of returning to normal use. |

`nvme sanitize` does not ask for confirmation and does not wait before sending
the command. Double-check the device before you press Enter.

## Checking progress

A sanitize operation can take a long time on a large drive. Either wait for it
in the same command:

```bash
# nvme sanitize /dev/nvme0 --sanact=start-block-erase --wait
```

or poll the sanitize log page from another shell (nvme-cli 2.x: `nvme
sanitize-log`):

```bash
$ nvme log sanitize /dev/nvme0
```

| Status | Meaning |
|---|---|
| 0x0000 | Never sanitized. |
| 0x0001 | Most recent sanitize completed successfully. |
| 0x0002 | A sanitize operation is in progress. Check the percentage complete field. |
| 0x0003 | Most recent sanitize failed. |

## `nvme format --ses`: erase one namespace while formatting

`nvme format` reformats one namespace (or all of them, if the controller allows
it). Add `--ses` to also erase the data:

| Value | Meaning |
|---|---|
| 0 | No erase. Default. |
| 1 | User Data Erase. All user data becomes unreadable. The drive may do this by deleting an internal encryption key, if all data is encrypted. |
| 2 | Cryptographic Erase. Always done by deleting an internal encryption key. |

```bash
# nvme format /dev/nvme0n1 --ses=2
```

Unlike `nvme sanitize`, `nvme format` does warn you first: it prints a warning
and waits 10 seconds, during which Ctrl-C cancels the operation. Pass `--force`
to skip the wait and warning, for example in a script.

## Which one to use

Use `nvme sanitize` to erase an entire drive before decommissioning or
repurposing it. It works at the device level, and its progress and result are
tracked in a log page you can check later. Use `nvme format --ses` when you are
already reformatting one namespace (for example to change the LBA format) and
want the old data erased as part of the same operation.
