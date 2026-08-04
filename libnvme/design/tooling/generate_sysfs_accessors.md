# Generate Sysfs Accessors Tool

This tool generates an **opaque, sysfs-backed C struct** and its accessor functions from a **Python dict**, rather than from an annotated header the way `generate_accessors.py` does. It currently drives only `struct libnvme_ctrl_sysfs`.

------

## Why this tool exists, separate from `generate_accessors.py`

`generate_accessors.py`'s whole model is "parse a struct out of a shared header, emit accessors alongside it — the struct keeps living in that header." `struct libnvme_ctrl_sysfs` needs the opposite: nobody outside a small, fixed set of generated `.c` files may ever see its layout, not even via a private header, since anything sitting in a header eventually gets included by someone. That means the struct definition itself must be generator *output*, emitted straight into each consuming `.c` file, never generator *input* — there is no header to parse, so a dict is the input instead.

This tool does not duplicate `generate_accessors.py`'s machinery. It imports it as a library and reuses its `Member` model and its emitters (the getter/setter bodies, the SWIG fragment, the `.ld` placement); only the frontend differs.

------

## Scope: what's deliberately excluded

`transport`, `traddr`, `trsvcid`, `host_traddr`, `host_iface`, `subsysnqn`, and `address` are **not** in `CTRL_SYSFS`, even though they're also read from sysfs. Each is set exactly once, unconditionally, at ctrl-creation time (from connect-time params or from resolving the ctrl's identity during a scan), and is read regardless of whether any getter is ever called. Laziness buys nothing for a value that's always resolved immediately either way — the whole point of this mechanism is deferring reads a caller might never need. These fields stay plain, eager fields on `struct libnvme_ctrl`.

------

## Usage

```
meson compile -C <build-dir> update-accessors
```

regenerates `ctrl-sysfs.h`/`.c`/`.i` alongside the other accessor families (aliased target, same as `update-common-accessors` and `update-fabrics-accessors`). Configuring with `-Dcheck-accessors=true` runs the same target read-only, for CI drift detection.

`ctrl-sysfs.ld` is **not** part of that auto-update — same as `accessors.ld`/`accessors-fabrics.ld`, which version section a symbol belongs to is a maintainer decision, so `update-ctrl-sysfs.sh` only diffs it and prints a `Symbols to ADD`/`Symbols to REMOVE` report; you edit the file by hand. Pre-3.0, "add" means adding the line to the existing `LIBNVME_CTRL_SYSFS_3` section, and "remove" means deleting the line, since ABI breaks are intentional and permitted before the 3.0 release. After a stable release, a symbol that genuinely needs to disappear is an ABI break no `.ld` edit can express by itself — it needs a SONAME bump (`libnvme_so_version` in the top-level `meson.build`), not just a version-script change.

To run this generator on its own, without the other two:

```
./generate_sysfs_accessors.py --specs <path> --out-dir <dir> [--ld-out-dir <dir>] [--swig-out-dir <dir>] [--check]
```

`--specs` is the path to the module providing `SYSFS_SPECS` (e.g. `../../src/nvme/sysfs_accessors_specs.py`) — a list of struct spec dicts, `CTRL_SYSFS` today, `NS_SYSFS`/`SUBSYS_SYSFS` joining it once namespaces/subsystems get the same treatment. Every entry in the list is generated in this one run; there is no per-struct selection flag. `--out-dir` is the directory to write the generated `.h`/`.c` files into. `--ld-out-dir` is where the `.ld` file goes, alongside the other version scripts (defaults to `--out-dir`). `--swig-out-dir` is where the `.i` fragment goes (defaults to `--out-dir`). `--check` runs read-only: it exits non-zero and lists which files are stale instead of writing them.

------

## How to add a new plain sysfs attribute

Most changes to `struct libnvme_ctrl_sysfs` are this case: one new field, backed by one sysfs attribute file, no special loader.

1. Open `sysfs_accessors_specs.py` and find the `CTRL_SYSFS['members']` list.
2. Add a new dict entry:
   ```python
   {
       'name': 'my_field',
       'attr': 'my_sysfs_attribute_name',
       'type': 'char *',
       'reconfigure_reset': True,
   },
   ```
3. Decide `reconfigure_reset`:
   - `True` if the kernel can legitimately change this value under a live connection (a firmware update, a counter) — the field is invalidated on rescan and re-read from sysfs on next access.
   - `False` if the value is part of this controller's identity and cannot change without it becoming a different controller (an address/NQN-shaped field) — the field survives a rescan.
4. If the field needs a numeric type instead of `char *` (e.g. `long`), set `'type': 'long'`. Only `char *` and numeric types are supported; there is no array/struct member support here (unlike `generate_accessors.py`, which handles those cases for non-lazy structs).
5. Regenerate and review the diff:
   ```
   ./generate_sysfs_accessors.py --specs sysfs_accessors_specs.py --out-dir ../../src/nvme --ld-out-dir ../../src
   ```
6. Run `make checkpatch-diff` on the regenerated files.

You do **not** need to touch the emitter functions, or anything in `generate_accessors.py`, for this case.

------

## How to add an always-live (volatile) attribute

For a numeric attribute that must be re-read from sysfs on every call rather than cached (matches the existing diagnostic counters):

```python
{
    'name': 'my_counter',
    'attr': 'diag/my_counter',
    'type': 'long',
    'volatile': True,
},
```

`volatile` members are never cached and never freed (there is no allocation to free) — `reconfigure_reset` has no effect on them and can be omitted.

------

## How to add a member that needs a public setter (`writable`)

`writable: True` does **not** mean the sysfs attribute itself is writable — every member in this dict is sysfs-observed and read-only from the kernel's side. It means libnvme needs a way to inject a value into the cache from somewhere other than the normal lazy sysfs read. There are two situations where that comes up:

- **Dual-direction fields**: the value is set from connect-time config on one code path and observed from sysfs on another (e.g. `dhchap_host_key`, `keyring`).
- **Backfill fallback**: a caller needs to supply a value sysfs doesn't provide on older kernels (e.g. `cntrltype`/`dctype`'s legacy-kernel Identify-based fallback in `fabrics.c`, used when those two sysfs attributes don't exist).

If either applies, add `'writable': True` to the member (or to a group, to make every member of that group writable — see below). This generates a public `libnvme_ctrl_set_<name>()` alongside the getter.

------

## How to add a member filled by a loader (`groups`)

Use a group instead of a plain member when one sysfs read naturally produces **several** values at once, so there is no way to read "just one" of them independently. The existing `identity` group is the example: one sysfs read (Linux) or one Identify command (Windows) yields `firmware`, `model`, `serial`, `cntrltype`, `cntlid`, and `dctype` together.

1. Add a new entry to `CTRL_SYSFS['groups']`:
   ```python
   {
       'loader': 'my_loader_function_name',
       'reconfigure_reset': True,
       'members': ['field_a', 'field_b'],
   },
   ```
2. `loader` is a C function name. The generated getter calls it as `loader(w)`, passing the owning `struct libnvme_ctrl *`. Declare it once in the generated header (automatic — `generate_header()` emits a prototype for every group's `loader`) and define it in whichever hand-written `ctrl-sysfs-custom-*.c` file(s) actually need to fill this group — see "Where loader bodies live" below.
3. The first access to *any* member of the group triggers the loader; every other member's cache-miss guard then finds its value already loaded and never calls the loader again. Loaders must leave every member they don't fill at `NULL` (not garbage) so the generated accessor can stamp the "read, absent" sentinel correctly.
4. If the loader body genuinely needs to differ by OS or by fabrics-enabled/disabled, that's a fact about the hand-written `.c` files, not about this dict — there's no `variant` key to set. A one-line comment above the group entry noting "loader body varies by OS" (or similar) is enough; see the existing `identity` and `phy_slot` groups for the pattern.

------

## Where loader bodies live, and why the `#include` runs this direction

This generator produces exactly **one** `.c` file, `ctrl-sysfs.c` — the struct definition and every generated accessor, unconditionally. There is no per-OS or per-fabrics generated `.c` variant to keep in sync; build-axis selection is entirely a hand-written-file concern:

| File | Selected by | Defines |
|---|---|---|
| `ctrl-sysfs-custom-linux.c` | `meson.build`'s `sources` (`host_system != 'windows'`) | `libnvme_ctrl_load_identity`, `libnvme_ctrl_load_phy_slot` |
| `ctrl-sysfs-custom-win.c` | `meson.build`'s `sources` (`host_system == 'windows'`) | same two, Windows bodies |
| `ctrl-sysfs-custom-fabrics.c` | `#ifdef CONFIG_FABRICS` inside whichever of the two files above is compiled | `libnvmf_ctrl_load_fabrics_attrs` |
| `ctrl-sysfs-custom-no-fabrics.c` | `#else` of the same `#ifdef` | same, no-op stub |

Exactly one of `ctrl-sysfs-custom-linux.c` / `ctrl-sysfs-custom-win.c` is ever listed in `meson.build`'s `sources` (the OS axis). That file starts with `#include "ctrl-sysfs.c"` to bring the struct definition and every accessor into its own translation unit, then a `#ifdef CONFIG_FABRICS` block `#include`s exactly one of the two fabrics-axis files (which don't need their own `#include "ctrl-sysfs.c"` — the struct is already visible by the time they're pulled in), then defines its own loader bodies. Both axes end up resolved by plain C preprocessor directives, readable top-to-bottom in the one file that's actually compiled — nothing about which loader body applies to which build lives in this generator or in `CTRL_SYSFS`.

This is the opposite of how `generate_accessors.py`'s own custom-accessor mechanism works (there, the *generated* file includes the hand-written one). It's inverted here specifically so this generator has zero per-build-axis output and zero custom-file mapping to maintain — that knowledge lives entirely in the hand-written files' own `#include`/`#ifdef` lines.

One trade-off worth knowing: `ctrl-sysfs.c` is never listed in `meson.build`'s `sources` directly (only reached via the `#include` above) — but since it contains real accessor functions, adding it to `sources` by mistake would produce duplicate-symbol *link* errors (unlike `ctrl-sysfs-custom-fabrics.c`/`-no-fabrics.c`, which would fail to *compile* standalone since they have no struct definition of their own).

------

## `CTRL_SYSFS` top-level keys

These identify the generated artifact itself and are set once, not per-member:

| Key | Meaning |
|---|---|
| `struct_name` | The generated C struct's tag name (`libnvme_ctrl_sysfs`). |
| `owner_type` | The struct this one nests inside (`libnvme_ctrl`). |
| `owner_field` | The pointer field name on `owner_type` (`sysfs`, so generated field paths read `sysfs->model`). |
| `source` | Filename of the generated `.c` (struct definition + every accessor). |
| `header` | Filename of the generated common header. |
| `ld` | Filename of the generated linker version-script. |
| `swig` | Filename of the generated SWIG fragment. |
| `ld_section` | Version-script section name the symbols nest inside. |

You would only change these when adding a second spec dict to `sysfs_accessors_specs.py` for a different struct (namespaces/subsystems is the anticipated follow-on) — each dict gets its own set of these keys and is added to `SYSFS_SPECS` alongside `CTRL_SYSFS`; see the module docstring's design note.

------

## What you never need to hand-edit

The struct definition, all getters/setters, the alloc/reset/free functions, the header, the `.ld` file, and the SWIG fragment are all generated — never hand-edit `ctrl-sysfs.h`, `ctrl-sysfs.c`, `ctrl-sysfs.ld`, or `ctrl-sysfs.i`. The only hand-written files are the `ctrl-sysfs-custom-*.c` loader bodies — see "Where loader bodies live" above for how they pull in the generated struct definition.
