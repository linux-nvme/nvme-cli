<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# How to add a new INI configuration parameter

This page lists every place you change to add a new key to the NVMe-oF INI
configuration (`nvme-fabrics.conf` and its drop-in files). It is for
developers. The format itself is described in
[`libnvme/design/CONFIG.md`](https://github.com/linux-nvme/nvme-cli/blob/master/libnvme/design/CONFIG.md).

The example on this page is the `persistent` key. It sets the persistence
mode of a Discovery Controller: `no`, `auto` or `force`. It is a good example
because it needed a new kind of value: one of a fixed set of strings
(STRENUM). Because of this, it touches every step. Most new keys are a plain
`INT`, `BOOL` or `STRING`. These need only steps 1, 2, 4, 6, 8 and 9.

All file names are relative to the top of the nvme-cli source tree. The page
was checked against nvme-cli 3.2.

## Step 1: Decide the type and the class of the key

Each key in the `keys[]` table in `libnvme/src/nvme/config-ini.c` has a type
and a class.

The **type** (`enum libnvmf_key_type` in `config-ini.h`) decides how the value
is checked:

| Type | Value |
|---|---|
| `LIBNVMF_KEY_STRING` | Any string. |
| `LIBNVMF_KEY_INT` | A number, parsed with `strtol()` in base 0. |
| `LIBNVMF_KEY_BOOL` | A boolean, parsed with `shr_parse_bool()`. |
| `LIBNVMF_KEY_STRENUM` | One of a fixed set of strings. Needs a `strenum_validate` function (step 2b). In 3.2, `persistent` is the only key of this type. |

The **class** (`enum libnvmf_key_class` in `config-ini.h`) decides where the
key may appear:

| Class | Where |
|---|---|
| `LIBNVMF_KEY_TUNABLE` | Any section. A `controller =` line may override it for one path. Most connection settings have this class, for example `nr-io-queues` and `keep-alive-tmo`. |
| `LIBNVMF_KEY_SECURITY` | Any section, but never on a `controller =` line. Security settings belong to the pair of host NQN and subsystem NQN, not to a path. Examples are `tls` and `tls-key-source`. |
| `LIBNVMF_KEY_IDENTITY` | Only in `[Host]`: `hostnqn`, `hostid`, `hostsymname`. |
| `LIBNVMF_KEY_NQN`, `LIBNVMF_KEY_CONTROLLER` | Only in endpoint sections: `[Discovery Controller]` or `[Subsystem]`. |
| `LIBNVMF_KEY_DC_TUNABLE` | Only in Discovery Controller sections and paths. |

`persistent` has the type `LIBNVMF_KEY_STRENUM`, because it has three fixed
values. It has the class `LIBNVMF_KEY_DC_TUNABLE`, because it has no meaning
for an I/O controller. The parser rejects it there.

## Step 2: Add the key to `keys[]` in `config-ini.c`

```c
{ "persistent", LIBNVMF_KEY_STRENUM, LIBNVMF_KEY_DC_TUNABLE, check_persistent },
```

**2a.** A `STRING`, `INT` or `BOOL` key does not use the fourth field
(`strenum_validate`). Leave it out, like the other rows of the table.

**2b. Only for STRENUM:** write a small `check_<name>()` function and use it
as `strenum_validate`:

```c
static int check_persistent(const char *value)
{
	enum libnvmf_persistent p;

	return _libnvmf_persistent_from_str(value, &p);
}
```

`libnvmf_key_check_value()` in `config-ini.c` calls `strenum_validate` for
every STRENUM key. You do not change it. A second STRENUM key needs only its
own `check_<name>()` function.

## Step 3: Store the value

Most settings have a field in `struct libnvme_fabrics_config`, for example
`nr_io_queues` and `keep_alive_tmo`. A new plain setting adds a field there.

**Only for STRENUM:** the value needs a translation between the string and the
enum. Because of this, it is not a plain field. `persistent` is the field
`enum libnvmf_persistent persistent` of `struct libnvmf_context` in
`private-fabrics.h`:

```c
enum libnvmf_persistent persistent; // !access:read=custom,write=custom
```

The enum is private. Callers see only the strings `"no"`, `"auto"` and
`"force"`. The annotation `!access:read=custom,write=custom` excludes the
field from the accessor generator. Hand-written accessors translate between
the enum and the string instead. The setter uses
`_libnvmf_persistent_from_str()` in `fabrics.c`. The getter translates the
enum back with a `switch`.

A plain `INT`, `BOOL` or `STRING` key does not need this. Its value goes
directly into its field.

## Step 4: Apply the value at connect time

The INI resolver merges the values first. Drop-in files override the main
file, and a path overrides its section. Then `apply_param()` in
`libnvme/src/nvme/config.c` applies each key of the final
`struct libnvmf_params`. It has one branch for each key:

```c
} else if (!strcmp(key, "persistent")) {
	libnvmf_context_set_persistent(fctx, value);
}
```

The branch of a plain setting writes the field directly, for example
`cfg->nr_io_queues = strtol(value, NULL, 0);`. The branch of `persistent`
calls its accessor, because the accessor translates the string.

An empty value (`key =`) resets the key. `apply_param()` returns early for an
empty value, for every key. A new key needs nothing for this.

## Step 5: Add the public accessors

**Only for STRENUM:** `persistent` is excluded from the generator (step 3).
So it needs hand-written accessors with kernel-doc comments and
`__shr_public`: `libnvmf_context_set_persistent()` and
`libnvmf_context_get_persistent()` in `fabrics.c`.

For a plain setting, the accessor generator creates the accessors. Run:

```bash
meson compile -C .build update-fabrics-accessors
```

See
[`accessor-workflow.md`](https://github.com/linux-nvme/nvme-cli-ai/blob/main/.claude/rules/accessor-workflow.md)
in nvme-cli-ai for the details.

## Step 6: Add the option to the commands

Add a command line option to every command that creates or changes a
connection. The option calls `libnvmf_params_set()`. This is the same store
that the INI parser fills. Because of this, the value is checked by the same
`check_persistent()`, from a file and from the command line.

`persistent` is an option in three places:

- `nvme discover` and `nvme connect-all`: `fabrics_discover()` in
  `src/fabrics.c`.
- The converter of `discovery.conf` lines: `nvmf_convert_discovery_line()` in
  `src/fabrics.c`.
- `nvme config create`: `src/config-create.c`. It calls
  `libnvmf_params_set(params, "persistent", persistent)` before it writes the
  entry.

The option is defined like this:

```c
OPT_STRING_OPTIONAL("persistent", 'p', "no|auto|force", &persistent_arg, ...)
```

`OPT_STRING_OPTIONAL` allows the option without a value. Then the default
`auto` applies. A value must be attached with `=`. A key without a useful
default uses `OPT_STRING`, `OPT_INT`, or `OPT_FLAG` for a `BOOL`.

## Step 7: Migrate the old `config.json` value

Skip this step if the key did not exist before the INI format.

`persistent` existed: `config.json` had a boolean `"persistent"` field.
`apply_dc_persistent()` in `src/config-convert.c` converts it:

```c
/*
 * The legacy config.json format predates EPCSD; its boolean "persistent"
 * meant unconditional persistence. Map true to "force", not the new
 * best-effort "auto" default, so migrating an existing config.json doesn't
 * silently change behavior for a connection that was persistent before.
 */
```

The comment is the important part of this step. The mapping is a decision:
what did the old value mean, and which new value keeps this behavior? Write
the reason down at the code.

## Step 8: Document the key

**Always update the man pages.** They describe each option. Keep the
description of every option from step 6 in line with what it does.
`Documentation/nvme-discover.txt`, `Documentation/nvme-connect-all.txt` and
`Documentation/nvme-config-create.txt` describe `--persistent`. Use their text
as a template.

Describe the rules of an option with an optional value. Since nvme-cli 3.2,
the value must be attached: `--persistent=force` works, `--persistent force`
is an error. In 3.0 and 3.1, a separate value was silently dropped.

**Do not add the key to `CONFIG.md`.** `CONFIG.md` explains the mechanics of
the format: sections, precedence and drop-in files. It is not a list of all
keys. That list is `keys[]` in `config-ini.c`. A second list would get out of
date. Change `CONFIG.md` only when the key adds or changes a mechanic, for
example a new section type or a new precedence rule.

## Step 9: Test the key

- **`libnvme/tests/config-ini.c`:** test the parser.
  - Add a positive test. It checks that the key is parsed and that
    `libnvmf_params_get()` returns it. See the `"persistent = auto\n"` test.
  - Add a negative test for each place where the class forbids the key. See
    the tests that reject `persistent` in `[I/O Controller Defaults]` and in
    `[Subsystem]`.
- **`libnvme/tests/test-fabrics.c`:** if the value controls a decision at run
  time, test this decision directly. `persistent` and EPCSD control
  `dc_decide()`. See `test_dc_decide()`.

## Checklist

| Step | File | Skip if |
|---|---|---|
| 1 | None (a decision) | Never |
| 2 | `libnvme/src/nvme/config-ini.c` | Never |
| 2b | `libnvme/src/nvme/config-ini.c` (and the type comment in `config-ini.h`) | Not STRENUM |
| 3 | `libnvme/src/nvme/private-fabrics.h` (or the file of the struct) | A plain key that uses an existing field |
| 4 | `libnvme/src/nvme/config.c` (`apply_param()`) | Never |
| 5 | `libnvme/src/nvme/fabrics.c`, or the accessor generator | The field uses generated accessors |
| 6 | Every command that should set it (`src/fabrics.c`, `src/config-create.c`, ...) | The key exists only in the file |
| 7 | `src/config-convert.c` | No `config.json` equivalent |
| 8 | `Documentation/*.txt`; `libnvme/design/CONFIG.md` only for a new mechanic | Man pages: never |
| 9 | `libnvme/tests/config-ini.c` (and `test-fabrics.c` for run time logic) | Never |

## Further reading

`persistent` and EPCSD were added in several pull requests:

- [PR #3698](https://github.com/linux-nvme/nvme-cli/pull/3698): INI configuration support
- [PR #3708](https://github.com/linux-nvme/nvme-cli/pull/3708): `nvme config create`
- [PR #3776](https://github.com/linux-nvme/nvme-cli/pull/3776): the STRENUM type
- [PR #3811](https://github.com/linux-nvme/nvme-cli/pull/3811): fix of the disconnect logic in `dc_decide()`
