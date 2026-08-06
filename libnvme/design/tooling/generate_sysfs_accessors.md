# Generate Sysfs Accessors Tool

This tool generates an **opaque, sysfs-backed C struct** and its accessor functions from a **Python dict**, rather than from an annotated header the way `generate_accessors.py` does. It drives `struct libnvme_ctrl_sysfs`, `struct libnvme_path_sysfs`, `struct libnvme_ns_sysfs`, and `struct libnvme_subsystem_sysfs`.

------

## Why this tool exists, separate from `generate_accessors.py`

`generate_accessors.py`'s whole model is "parse a struct out of a shared header, emit accessors alongside it — the struct keeps living in that header." A sysfs-backed struct needs the opposite: nobody outside a small, fixed set of generated `.c` files may ever see its layout, not even via a private header, since anything sitting in a header eventually gets included by someone. That means the struct definition itself must be generator *output*, emitted straight into each consuming `.c` file, never generator *input* — there is no header to parse, so a dict is the input instead.

This tool does not duplicate `generate_accessors.py`'s machinery. It imports it as a library and reuses its `Member` model and its emitters (the getter/setter bodies, the SWIG fragment, the `.ld` placement); only the frontend differs.

------

## Getter shape: every getter returns `int` and takes a caller default

Every sysfs-backed getter returns `int` and delivers its value through an out-param, plus a caller-supplied default:

```c
int libnvme_ctrl_get_model(const struct libnvme_ctrl *p, const char **val, const char *dflt);
int libnvme_path_get_grpid(const struct libnvme_path *p, int *val, int dflt);
```

| Return | Meaning |
|---|---|
| `0` | success, `*val` written |
| `-ENOENT` | the attribute does not exist (or this platform has no source for it at all) |
| `-EINVAL` | the attribute was read but its content could not be parsed |
| other negative errno | the load itself failed (e.g. `-ENOMEM`), propagated from the loader or an allocation |

`*val = dflt` is the first thing every getter body does, before any cache check, attribute read, or loader call — a caller who does not want the fine-grained distinction can pass `NULL`/`0` and use the value unconditionally, without checking the return code or declaring an initializer of their own. `dflt` is only ever visible on a non-`0` return; a successful call always overwrites it with the real value.

A plain getter (`const char *foo(...)`) cannot distinguish "absent" from "read failed" — this shape can, on every platform, not just where Windows makes the distinction unavoidable.

Setters keep their original shape (`void`) — a `writable` member's value is always supplied by the caller, so there is nothing to fail.

------

## Scope: what's deliberately excluded

`transport`, `traddr`, `trsvcid`, `host_traddr`, `host_iface`, `subsysnqn`, and `address` are **not** in `CTRL_SYSFS`, even though they're also read from sysfs. Each is set exactly once, unconditionally, at ctrl-creation time (from connect-time params or from resolving the ctrl's identity during a scan), and is read regardless of whether any getter is ever called. Laziness buys nothing for a value that's always resolved immediately either way — the whole point of this mechanism is deferring reads a caller might never need. These fields stay plain, eager fields on the owning struct.

------

## Usage

```
meson compile -C <build-dir> update-accessors
```

regenerates every spec's `.h`/`.c`/`.i` alongside the other accessor families (aliased target, same as `update-common-accessors` and `update-fabrics-accessors`). Configuring with `-Dcheck-accessors=true` runs the same target read-only, for CI drift detection.

Every spec's `.ld` is **not** part of that auto-update — same as `accessors.ld`/`accessors-fabrics.ld`, which version section a symbol belongs to is a maintainer decision, so `update-sysfs-accessors.sh` only diffs it and prints a `Symbols to ADD`/`Symbols to REMOVE` report; you edit the file by hand. Pre-3.0, "add" means adding the line to the spec's existing top-level section, and "remove" means deleting the line, since ABI breaks are intentional and permitted before the 3.0 release. After a stable release, a symbol that genuinely needs to disappear is an ABI break no `.ld` edit can express by itself — it needs a SONAME bump (`libnvme_so_version` in the top-level `meson.build`), not just a version-script change. A brand-new spec's `.ld` does not exist yet the first time it is generated; the script reports every symbol as "to add" and tells you to create the file by hand with a fresh top-level tag.

To run this generator on its own, without the other two:

```
./generate_sysfs_accessors.py --specs <path> --out-dir <dir> [--ld-out-dir <dir>] [--swig-out-dir <dir>] [--check]
```

`--specs` is the path to the module providing `SYSFS_SPECS` (e.g. `../../src/nvme/sysfs_accessors_specs.py`) — a list of struct spec dicts. Every entry in the list is generated in this one run; there is no per-struct selection flag. `--out-dir` is the directory to write the generated `.h`/`.c` files into. `--ld-out-dir` is where the `.ld` file goes, alongside the other version scripts (defaults to `--out-dir`). `--swig-out-dir` is where the `.i` fragment goes (defaults to `--out-dir`). `--check` runs read-only: it exits non-zero and lists which files are stale instead of writing them.

------

## How to add a new plain sysfs attribute

Most changes to a sysfs-backed struct are this case: one new field, backed by one sysfs attribute file, no special loader, present the same way on every platform.

1. Open `sysfs_accessors_specs.py` and find the relevant spec's `['members']` list.
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
   - `False` (or omit it) if the value is part of the object's identity and cannot change without it becoming a different object (an address/NQN-shaped field), **or** if the owning object is never reconfigured in place at all (e.g. `libnvme_path` — a path is always destroyed and recreated on rescan, never updated, so `reconfigure_reset` is meaningless for any `PATH_SYSFS` member and every one omits it).
4. If the field needs a numeric type instead of `char *` (e.g. `long`, `int`, an `enum`), set `'type'` accordingly — see "Cached vs. volatile, string vs. numeric" below for what changes underneath. Only `char *` and numeric types are supported; there is no array/struct member support here (unlike `generate_accessors.py`, which handles those cases for non-lazy structs).
5. Regenerate and review the diff:
   ```
   ./generate_sysfs_accessors.py --specs sysfs_accessors_specs.py --out-dir ../../src/nvme --ld-out-dir ../../src --swig-out-dir ../../libnvme3
   ```
6. Run `make checkpatch-diff` on the regenerated files.

You do **not** need to touch the emitter functions, or anything in `generate_accessors.py`, for this case.

------

## Cached vs. volatile, string vs. numeric: which emitter you get

Four independent axes combine into the getter body the generator picks — there is no key that selects an emitter directly, it falls out of `type` and `volatile`:

| | `char *` | numeric (`int`/`long`/`enum ...`) |
|---|---|---|
| **cached** (no `volatile`) | plain pointer field; `NULL` = not loaded, `NO_SYSFS_ATTR` = absent, real pointer = value | **boxed**: `TYPE *` field, same NULL/`NO_SYSFS_ATTR`/real-pointer tri-state — the bare type has no spare value to mean "not loaded" (`0` is a legitimate reading), so a numeric member reuses the string members' mechanism via one heap allocation instead of inventing a second one |
| **`volatile: True`** | plain `char *` field, re-read every call, freed and replaced only when the new read differs from the cached copy (so a caller holding the returned pointer across two calls reading the same value never sees it freed under it) | plain value field (`volatile long`/`volatile int` in C too — a real qualifier, not just documentation, since the value is deliberately never cached), re-parsed on every call |

Both cached and volatile getters return `-ENOENT` if the attribute cannot be read, and `-EINVAL` (or `-ENOMEM` for the boxed-numeric allocation) if it can be read but not parsed — never the previous cached value on failure, always the caller-supplied `dflt` (see "Getter shape" above).

------

## How to add an always-live (volatile) attribute

```python
{
    'name': 'my_counter',
    'attr': 'diag/my_counter',
    'type': 'long',   # or 'int' -- add a _SCANF_FMT entry in
                       # generate_accessors.py if it's a new numeric type
    'volatile': True,
},
```

`volatile` members are never cached. A volatile numeric holds no allocation and is never freed. A volatile *string* member does hold a real allocation (see the table above) and **is** freed at final teardown — `final_free_field_paths()` special-cases this; do not add `reconfigure_reset` to a volatile member, it has no effect either way.

------

## How to add a member that needs a public setter (`writable`)

`writable: True` does **not** mean the sysfs attribute itself is writable — every member in this dict is sysfs-observed and read-only from the kernel's side. It means libnvme needs a way to inject a value into the cache from somewhere other than the normal lazy sysfs read. There are two situations where that comes up:

- **Dual-direction fields**: the value is set from connect-time config on one code path and observed from sysfs on another (e.g. `dhchap_host_key`, `keyring`).
- **Backfill fallback**: a caller needs to supply a value sysfs doesn't provide on older kernels (e.g. `cntrltype`/`dctype`'s legacy-kernel Identify-based fallback in `fabrics.c`, used when those two sysfs attributes don't exist), or on a platform with no sysfs at all (e.g. subsystem `model`/`serial`/`firmware`, pushed from Windows's ctrl map).

If either applies, add `'writable': True` to the member (or to a group, to make every member of that group writable — see below). This generates a public `libnvme_ctrl_set_<name>()` alongside the getter.

------

## How to add a member filled by a loader (`groups`)

Use a group instead of a plain member when one sysfs read naturally produces **several** values at once, so there is no way to read "just one" of them independently. The existing `identity` group is the example: one sysfs read (Linux) or one Identify command (Windows) yields `firmware`, `model`, `serial`, `cntrltype`, `cntlid`, and `dctype` together.

1. Add a new entry to the spec's `['groups']`:
   ```python
   {
       'loader': 'my_loader_function_name',
       'reconfigure_reset': True,
       'members': ['field_a', 'field_b'],
   },
   ```
2. `loader` is a C function name. The generated getter calls it as `loader(w)`, passing the owning struct pointer, and propagates a nonzero return to its own caller unchanged (the load itself failed, not just "attribute absent"). Declare it once in the generated header (automatic — `generate_header()` emits a prototype for every group's `loader`, but only when the spec has at least one group) and define it in whichever hand-written `*-custom-*.c` file(s) actually need to fill this group — see "Generated file layout" below.
3. The first access to *any* member of the group triggers the loader; every other member's cache-miss guard then finds its value already loaded and never calls the loader again. Loaders must leave every member they don't fill at `NULL` (not garbage) so the generated accessor can stamp the "read, absent" sentinel correctly.
4. If the loader body genuinely needs to differ by `CONFIG_FABRICS` (or any axis other than OS), that's a fact about the hand-written `.c` files, not about this dict — there's no key to set. A one-line comment above the group entry noting "loader body varies by CONFIG_FABRICS" (or similar) is enough; see the existing `identity` and `fabrics` groups for the pattern. If the loader (or the *grouping itself*) needs to differ by **OS**, see "Per-OS resolution" below instead — that is a real, first-class axis this generator understands, unlike fabrics-or-other build flags.
5. Groups themselves are not yet OS-resolved (a spec's `['groups']` list is a single, OS-invariant list) — no current spec needs a group whose loader or membership differs per OS. Extend `build_members()` the same way member resolution works, if one ever does.

------

## Per-OS resolution: most members need nothing at all

A member only needs a `'linux'`/`'win'` override when its **value source** — which function gets called, or how members are grouped — genuinely differs per platform:

```python
{'name': 'ana_state', 'type': 'char *', 'attr': 'ana_state', 'volatile': True,
 'win': {'absent': True}},
```

**Most members do not need this.** `libnvme_get_{ctrl,ns,path,subsys}_attr()` already has a Windows implementation that unconditionally returns `NULL` — so for a plain `'attr'` member, Windows absence falls out of the existing attr-reader stub for free; the generated getter body is identical C on both platforms, it just behaves differently at runtime because the function it calls does. Only add an override when a *different function* needs to be called, or the *grouping* itself changes — no current spec needs that case; `'absent': True` (every `PATH_SYSFS` member on Windows) is the only override in use today. A member whose OS difference can't be expressed by changing what one function returns (e.g. `NS_SYSFS`'s `lba_*` members: Linux calls two small loaders, Windows calls one big Identify command) uses `'custom': True` instead — a hand-written getter body in `*-custom-<os>.c`, with only the prototype and the struct field generated (see `sysfs_accessors_specs.py`'s `NS_SYSFS` entry for worked examples).

`'absent': True` means the platform has no source for the member at all: the generated getter writes `dflt` to the out-param and always returns `-ENOENT`, no attribute read or loader call ever happens, and (for `PATH_SYSFS`, where every member is absent on Windows) the owning-struct parameter is `__shr_unused` since the body never touches it.

`'type'` and `'writable'` are never valid inside a `'linux'`/`'win'` override — a member's public signature (name, type, whether a setter exists) must be identical on every platform; only where a value comes from may vary. Enforcing this is currently a documentation convention, not a generator-level check.

### Generated file layout

The generator resolves each member's effective Linux and Windows definition and decides where its getter body goes:

- **identical on both** → the spec's shared `.c` file (`source` key)
- **differ** → each OS's own file (`source_linux`, `source_win` keys) — only emitted if at least one member actually differs

The struct definition, `_alloc()`/`_reset()`/`_free()`, and every OS-common getter always live in the shared file — **the struct never splits**, even when some of its members' getters do, because every cached member (string or boxed numeric) has the same storage shape regardless of which loader fills it.

For `PATH_SYSFS`, every member differs (absent on Windows), so the shared file holds only the struct definition and lifecycle functions, and both `path-sysfs-linux.c` and `path-sysfs-win.c` exist. For `CTRL_SYSFS`, no member differs at all, so only the shared `ctrl-sysfs.c` exists — exactly the file this generator has always produced. `NS_SYSFS` is the case where a spec's shared file is non-trivial *and* both per-OS files exist alongside it (its `lba_*`/`csi`/`eui64`/`nguid`/`uuid` members are `'custom': True`, hand-written in `ns-sysfs-custom-linux.c`/`ns-sysfs-custom-win.c`, while its `diag/*` counters are OS-common and live in the shared `ns-sysfs.c`).

The per-OS `.c` files carry no `#include`s of their own — they rely on being `#include`d *after* the shared file in the hand-written `*-custom-<os>.c`, which brings the struct definition and everything else into scope first:

```c
// path-sysfs-custom-linux.c (hand-written)
#include "path-sysfs.c"          // struct def + OS-common getters
#include "path-sysfs-linux.c"    // Linux-only getters, generated
```

Exactly one of `*-custom-linux.c` / `*-custom-win.c` is ever listed in `meson.build`'s `sources` (the OS axis, same mechanism as `ctrl-sysfs-custom-linux.c`/`-win.c`). If a spec also needs a `CONFIG_FABRICS` split (as `CTRL_SYSFS` does for its fabrics group), that nesting happens inside whichever `*-custom-<os>.c` is compiled, exactly as today — fabrics is a build flag, not an OS, and stays entirely a hand-written-file concern.

One trade-off worth knowing: a spec's shared `.c` (and any per-OS `.c`) is never listed in `meson.build`'s `sources` directly (only reached via the `#include` chain above) — but since it contains real accessor functions, adding it to `sources` by mistake would produce duplicate-symbol *link* errors.

------

## `attr_reader`

Every spec must declare which C function its plain-`attr` and volatile members call to read a sysfs attribute:

```python
'attr_reader': 'libnvme_get_ctrl_attr',   # or _ns_attr / _path_attr / _subsys_attr
```

This is a required top-level key with no default — there is deliberately no magic fallback to `libnvme_get_ctrl_attr` for a spec that forgets to set it.

------

## Spec top-level keys

These identify the generated artifact itself and are set once, not per-member:

| Key | Meaning |
|---|---|
| `struct_name` | The generated C struct's tag name (`libnvme_ctrl_sysfs`, `libnvme_path_sysfs`, ...). |
| `owner_type` | The struct this one nests inside (`libnvme_ctrl`, `libnvme_path`, ...). |
| `owner_field` | The pointer field name on `owner_type` (`sysfs`, so generated field paths read `sysfs->model`). |
| `attr_reader` | The C function name for reading one plain sysfs attribute — see above. |
| `source` | Filename of the generated shared `.c` (struct definition + every OS-common accessor). |
| `source_linux` | Filename of the Linux-only `.c`. Only required if some member's resolution actually differs per OS; omit otherwise. |
| `source_win` | Likewise, for Windows. |
| `header` | Filename of the generated common header. |
| `ld` | Filename of the generated linker version-script. |
| `swig` | Filename of the generated SWIG fragment. |
| `ld_section` | Version-script section name the symbols nest inside — needs its own top-level tag distinct from every other spec's (`ld` rejects two `--version-script` files defining the same tag). A placeholder like `LIBNVME_CTRL_SYSFS_NEXT`, not a real version number: the committed `.ld` is hand-written and never auto-overwritten (see "Usage" above), so this string only feeds the generator's own scratch copy — never diffed, never enforced, never echoed back to the maintainer. The real tag is a maintainer decision made by hand at commit time. |

Add a new spec dict to `sysfs_accessors_specs.py` with its own set of these keys and append it to `SYSFS_SPECS`.

------

## Python bindings

SWIG's `%extend struct X { TYPE member; }` "property" convention only works when the underlying getter has the shape `TYPE get_X(const struct X *)` — this generator's getters, `int`-returning with an out-param, cannot be wrapped that way directly. `generate_swig()` interposes a small wrapper per readable member (`emit_swig_getter_wrapper()`) that resolves the three states a lazy read can produce:

- a value → return it (`const char *` directly for a string member; `PyLong_FromLong()` wrapped as `PyObject *` for a numeric one — SWIG picks its member-property typemap from the type *declared in `%extend`*, not from the wrapper's real C return type, so a numeric member must be declared `PyObject *` there or SWIG force-casts the wrapper's pointer to the declared numeric type, corrupting it)
- `-ENOENT` → Python `None`
- any other error → raise `NvmeError`, via the same `raise_nvme()`/`%exception ClassName::member { $action; if (PyErr_Occurred()) SWIG_fail; }` pattern already used for `connect`/`disconnect`/`discover` in `nvme.i`

The wrapper always passes `NULL` (string) or `0` (numeric) as the real getter's `dflt` argument — it never reads the out-param on a non-`0` return anyway, so which default the C call used is irrelevant to the Python-visible result.

Adding a Python conversion for a new numeric type means adding one entry to `_PY_FROM` in `generate_sysfs_accessors.py` (mirrors `generate_accessors.py`'s own `_SCANF_FMT` table) — deliberately not a general type mapper, add an entry only when a real member needs it.

------

## What you never need to hand-edit

The struct definition, all getters/setters, the alloc/reset/free functions, the header, the `.ld` file, and the SWIG fragment are all generated — never hand-edit a spec's `.h`, `.c` (shared or per-OS), `.ld`, or `.i`. The only hand-written files are the `*-custom-<os>.c` loader bodies — see "Generated file layout" above for how they pull in the generated struct definition.
