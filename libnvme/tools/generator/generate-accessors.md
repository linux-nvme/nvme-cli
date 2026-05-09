# Generate Accessors Tool

This tool generates **setter and getter functions** for C structs automatically. It also optionally generates a **constructor and destructor** (`foo_new` / `foo_free`) and a **defaults initialiser** (`foo_init_defaults`). It supports dynamic strings, fixed-size char arrays, `char **` arrays, and `const` fields, with control over which structs and members participate via **in-source annotations**.

Beyond C code, the tool can also emit **SWIG fragments** that expose the generated accessors to the Python bindings, and **dict-table headers** used by the Python layer to populate structs from Python dictionaries.

------

## Design model

### C public API

The structs processed by this tool are **private** — defined in internal headers such as `private.h` and never exposed directly to external callers. The generated accessor functions form the stable public ABI: external code accesses struct fields only through them.

Internal C code within libnvme is free to read and write struct members directly. Accessor functions are required even for internal code only when a member has **special handling** — for example, two fields that must always be written together, or a field whose value must be validated or derived from another. Those cases are hand-written and annotated with `custom`; everything else is `generated` and accessed directly.

### Python bindings

The same opaqueness applies to the Python layer: C structs are invisible to Python callers and are instead surfaced as properties of Python classes (`GlobalCtx`, `Host`, `Ctrl`, etc.). The public Python API is dict-based for configuration; users never see the underlying C structs.

The SWIG-generated glue code, however, is not subject to this restriction — it has full access to the private headers and reads/writes struct members directly (`p->member`) for any axis annotated `generated`. A hand-written (custom) accessor is called only when a member requires special handling, making `custom` annotations the exception rather than the rule.

------

## Usage

```
python3 generate-accessors.py [options] <header-files>
```

**Options:**

| Short | Long       | Argument | Description                                              |
| ----- | ---------- | -------- | -------------------------------------------------------- |
| `-h`  | `--h-out`  | `<file>` | Full path of the `*.h` file to generate. Default: `accessors.h` |
| `-c`  | `--c-out`  | `<file>` | Full path of the `*.c` file to generate. Default: `accessors.c` |
| `-l`  | `--ld-out` | `<file>` | Full path of the `*.ld` file to generate. Default: `accessors.ld` |
| `-s`  | `--swig-out`       | `<file>` | Generated SWIG fragment (`*.i`). Omit to skip.           |
| `-d`  | `--dict-table-out` | `<file>` | Generated dict-table header (`*.h`). Omit to skip.       |
| `-p`  | `--prefix` | `<str>`  | Prefix prepended to every generated function name        |
| `-v`  | `--verbose`| none     | Verbose output showing which structs are being processed |
| `-H`  | `--help`   | none     | Show this help message                                   |

------

## Generated files

Each output file is produced only when the corresponding command-line flag is supplied. The table below shows which annotation in the header source drives that file's content.

| Flag               | Generated file        | Controlling annotation | Purpose                                                      |
| ------------------ | --------------------- | ---------------------- | ------------------------------------------------------------ |
| `--h-out`          | `accessors.h`         | `!generate-accessors`  | C header — accessor function declarations                    |
| `--c-out`          | `accessors.c`         | `!generate-accessors`  | C implementation — accessor function bodies                  |
| `--ld-out`         | `accessors.ld`        | `!generate-accessors`  | Linker version-script — exports accessor symbols in the shared library ABI |
| `--swig-out`       | `accessors.i`         | `!generate-python`     | SWIG fragment — typemaps that expose accessors and accessible structs to the Python bindings |
| `--dict-table-out` | `fctx_field_tables.h` | `!generate-dict-table` | C header — sentinel-terminated field offset tables used for dict parsing in the Python bindings |

The first three flags share the same annotation (`!generate-accessors`) and are typically generated together in one invocation. The SWIG fragment (`--swig-out`) uses a separate annotation (`!generate-python`) and the dict-table header (`--dict-table-out`) uses yet another (`!generate-dict-table`); both may be passed to the same invocation as the other flags or to a separate one.

------

## Annotations

Struct inclusion and member behavior are controlled by **annotations written as `//` line comments directly in the header file**. Each annotation begins with a `!keyword` token. Optional parameters — called **metadata** — follow the keyword after a colon (`:`) and carry additional configuration. Multiple annotations may share one comment, separated by spaces.

```
// !keyword                          annotation with no metadata
// !keyword:key=value                annotation with metadata  key=value
// !keyword:key1=value1,key2=value2  annotation with metadata  key1=value1,key2=value2
// !keyword1 !keyword2:key=value     two annotations on one line
```

The canonical form is `// !token` (one space between `//` and `!`); `//!token` and `//\t!token` are also accepted.

### Access model — two independent axes

Accessor generation is controlled by **two independent axes**:

- **`read`** — whether a getter exists for the field, and if so, how it is provided
- **`write`** — whether a setter exists for the field, and if so, how it is provided

Each axis takes one of three modes:

| Mode        | Meaning                                                      |
| ----------- | ------------------------------------------------------------ |
| `generated` | This generator emits the accessor                            |
| `custom`    | An accessor is expected to exist and is provided as a hand-written function; the generator emits nothing |
| `none`      | No accessor exists for this axis; the generator emits nothing |

Only `generated` produces output in this generator. The `custom` and `none` modes are **semantic declarations**: they advertise intent to downstream consumers — such as the Python-binding generator and the `nvme.i` consistency check — which need to distinguish "no accessor at all" from "accessor provided by hand".

### Struct inclusion — `generate-accessors`

Place the annotation on the same line as the struct's opening brace to opt that struct in to code generation. The optional metadata sets the **default mode for each axis** of every member of the struct:

```c
struct libnvme_ctrl { // !generate-accessors
    /* shorthand for read=generated, write=generated */
};

struct libnvme_ctrl { // !generate-accessors:read=generated,write=generated
    /* fully explicit form of the same default */
};

struct libnvme_ctrl { // !generate-accessors:read=generated,write=none
    /* all members read-only by default; setters require a per-member override */
};
```

Only structs carrying this annotation are processed. All other structs in the header are ignored.

**Built-in defaults.** Any axis not named in the metadata falls back to `generated`. The bare `// !generate-accessors` form is therefore shorthand for `// !generate-accessors:read=generated,write=generated`.

Individual members can always override the struct-level default using a per-member annotation (see below).

### Member-level override — `access`

Place the annotation on a member's declaration line to override the struct-level default for this field:

```c
struct libnvme_ctrl { // !generate-accessors:read=generated,write=none
    char *name;                  /* effective: read=generated, write=none (inherited) */
    char *dhchap_host_key;       // !access:write=generated
    /* effective: read=generated (inherited), write=generated */
    long command_error_count;    // !access:read=custom
    /* effective: read=custom, write=none (inherited) — hand-written getter */
};
```

**Partial metadata** is allowed — any axis not named in the metadata is **inherited from the struct-level default**, which is in turn drawn from the struct's `// !generate-accessors` annotation (or from the built-in default when none is given). The order of `read` and `write` in the metadata is not significant.

**Common patterns:**

| Member annotation                        | Effective (inside `// !generate-accessors`)   | Meaning                                      |
| ---------------------------------------- | --------------------------------------------- | -------------------------------------------- |
| *(no annotation)*                        | `read=generated, write=generated`             | Both accessors auto-generated                |
| `// !access:read=generated,write=none`   | `read=generated, write=none`                  | Read-only (auto-generated getter only)       |
| `// !access:read=none,write=generated`   | `read=none, write=generated`                  | Write-only (auto-generated setter only)      |
| `// !access:read=none,write=none`        | `read=none, write=none`                       | Purely internal; no accessor of any kind     |
| `// !access:read=custom,write=none`      | `read=custom, write=none`                     | Hand-written getter only                     |
| `// !access:read=none,write=custom`      | `read=none, write=custom`                     | Hand-written setter only                     |
| `// !access:read=custom,write=custom`    | `read=custom, write=custom`                   | Hand-written getter and setter               |
| `// !access:read=generated,write=custom` | `read=generated, write=custom`                | Mixed: generated getter, hand-written setter |

### The `const` qualifier

A `const`-qualified member forces `write=none` regardless of what the annotation (or inherited default) says — the generator cannot emit a setter for a member that the C type system forbids from being assigned. `const char *` members are also **never** freed by the destructor; they are assumed to point to externally owned storage.

### Struct lifecycle — `generate-lifecycle`

Place the annotation on the same line as the struct's opening brace to generate a constructor and a destructor for that struct. This annotation takes **no metadata** — its presence means "generate," its absence means "don't":

```c
struct libnvmf_uri { // !generate-accessors !generate-lifecycle
    char *scheme;
    char *host;
    char *path;    // !lifecycle:none   /* excluded from destructor */
};
```

This generates:

- **`libnvmf_uri_new(struct libnvmf_uri **pp)`** — allocates a zeroed instance on the heap. Returns `0` on success, `-EINVAL` if `pp` is `NULL`, or `-ENOMEM` on allocation failure.
- **`libnvmf_uri_free(struct libnvmf_uri *p)`** — frees all `char *` and `char **` members (except those marked `// !lifecycle:none`) and then frees the struct itself. A `NULL` argument is silently ignored.

`generate-lifecycle` can appear alongside `generate-accessors` in the same comment. `const char *` members are **never** freed by the destructor — they are assumed to point to externally owned storage.

### Lifecycle member exclusion — `lifecycle:none`

Place the annotation on a member's declaration line to exclude it from the destructor's free logic:

```c
struct libnvmf_uri { // !generate-lifecycle
    char *host;
    char *borrowed;  // !lifecycle:none   /* not freed — caller owns this */
};
```

This annotation has no effect on accessor generation. Combine with `// !access:read=none,write=none` if both should be suppressed.

### Member defaults — `default:VALUE`

Place the annotation on a member's declaration line to assign a compile-time default value. When any member in the struct carries this annotation, a `foo_init_defaults()` function is generated:

```c
struct libnvmf_discovery_args { // !generate-accessors !generate-lifecycle
    int max_retries;  // !default:6
    __u8 lsp;         // !default:NVMF_LOG_DISC_LSP_NONE
};
```

This generates `libnvmf_discovery_args_init_defaults()`, which sets each annotated field to its default value. If `generate-lifecycle` is also present, the constructor automatically calls `init_defaults()` after allocation.

The value is emitted verbatim, so any valid C expression — integer literals, macro names, enum constants — is accepted.

`init_defaults()` can be used independently of `generate-lifecycle`.

### Python SWIG fragment — `generate-python`

Place the annotation on the same line as the struct's opening brace to include that struct in the SWIG output file (`--swig-out`). This annotation is independent of `!generate-accessors` — a struct may carry either or both:

```c
struct libnvme_ctrl { // !generate-accessors !generate-python
    /* C accessors + SWIG Python fragment both generated */
};

struct libnvme_ctrl { // !generate-python
    /* SWIG fragment only — public accessors (if any) are hand-written */
};
```

The optional `alias=NAME` metadata renames the struct in Python without changing the C identifier:

```c
struct libnvme_fabrics_config { // !generate-accessors !generate-python:alias=FabricsConfig
    /* Python class will be FabricsConfig, not libnvme_fabrics_config */
};
```

For each struct carrying this annotation the generator emits into `accessors.i`:

- `%rename(NAME) struct_name;` when `alias=NAME` is set.
- `%rename` directives and `#define` bridges for any member whose `read` or `write` axis is `custom` — these map SWIG's expected `struct_member_get/set` naming to libnvme's `struct_get/set_member` convention.
- A `struct { ... };` declaration body containing plain field entries for generated members and a `%extend { ... }` block for custom members. Read-only members (`write=none`) are preceded by `%immutable`.
- A `%pythoncode` block that installs a strict `__setattr__` guard, causing Python to raise `AttributeError` for any attribute name not already present on the class.

`!generate-python` is scanned separately from `!generate-accessors`. A struct without `!generate-accessors` is still parsed for SWIG purposes, treating all member axes as `generated` by default.

### Python member visibility — `python:none`

Place the annotation on a member's declaration line to exclude it from the SWIG fragment entirely. The member's C accessors (controlled by `!access`) are unaffected:

```c
struct libnvme_ctrl { // !generate-accessors !generate-python
    char *name;
    char *internal_tag;  // !python:none   /* not exposed to Python */
};
```

### Python member renaming — `python:alias=NAME`

Place the annotation on a member's declaration line to give it a different Python attribute name while keeping the C member name unchanged:

```c
struct libnvme_ctrl { // !generate-accessors !generate-python
    char *subsysnqn;
    int   kato_ms;      // !python:alias=kato   /* Python sees .kato */
};
```

`!python:alias=NAME` can be combined with `!access` and `!python:none` (though combining with `!python:none` is pointless since the member is excluded anyway).

### Dict-table generation — `generate-dict-table`

Place the annotation on the same line as the struct's opening brace to include that struct in the dict-table output file (`--dict-table-out`). This annotation takes **no metadata** — its presence means "generate," its absence means "don't":

```c
struct libnvme_fabrics_config { // !generate-accessors !generate-dict-table
    int  queue_size;
    bool duplicate_connect;
    char *hostnqn;   // !dict-table:none   /* excluded from the table */
};
```

The generator buckets each eligible member by C type and emits:

- One sentinel-terminated `fctx_field_t` array per bucket (`int`, `long`, `bool`, `char *`), using `offsetof` to record the field's byte offset.
- A flat `NULL`-terminated `const char * const` array listing all included field names.

These tables are consumed exclusively by the Python binding layer (`nvme.i`) to fill a `struct libnvme_fabrics_config` from a Python `dict` without a long chain of `strcmp` comparisons.

**Supported member types:**

| C type(s)                                              | Bucket     | Written via         |
| ------------------------------------------------------ | ---------- | ------------------- |
| `int`, `unsigned int`, `int32_t`, `__s32`, `uint32_t`, `__u32` | `int`  | `*(int *)ptr`       |
| `long`, `unsigned long`, `long long`, …, `int64_t`, `__s64`, `uint64_t`, `__u64` | `long` | `*(long *)ptr` |
| `bool`, `_Bool`                                        | `bool`     | `*(bool *)ptr`      |
| `char *`                                               | `char *`   | key array only — values handled by hand-written code |

`const`-qualified members and members with unsupported types (narrow integers, `void *`, nested structs, …) are skipped; the generator prints a warning for unknown scalars or multi-level pointers. Annotate those members with `// !dict-table:none` to suppress the warning.

### Dict-table member exclusion — `dict-table:none`

Place the annotation on a member's declaration line to exclude it from the dict-table output silently:

```c
struct libnvme_fabrics_config { // !generate-dict-table
    int  queue_size;
    char *hostnqn;   // !dict-table:none   /* handled by hand-written code */
};
```

This annotation has no effect on accessor generation. It is independent of `!access` and `!lifecycle`.

### Annotation summary

| Annotation                                             | Where        | Effect                                                                                  |
| ------------------------------------------------------ | ------------ | --------------------------------------------------------------------------------------- |
| `// !generate-accessors`                               | struct brace | Include struct; defaults: `read=generated, write=generated`                             |
| `// !generate-accessors:read=M,write=M`                | struct brace | Include struct; set struct-level default for each axis                                  |
| `// !generate-accessors:read=M`                        | struct brace | Partial metadata; other axis inherits the built-in default (`generated`)                |
| `// !generate-lifecycle`                               | struct brace | Generate constructor + destructor (no metadata)                                         |
| `// !generate-python`                                  | struct brace | Include struct in the SWIG fragment output file (no metadata)                           |
| `// !generate-python:alias=NAME`                       | struct brace | Same, and rename the struct to NAME in Python                                           |
| `// !generate-dict-table`                              | struct brace | Include struct in the dict-table output file (no metadata)                              |
| `// !access:read=M,write=M`                            | member line  | Override struct-level defaults for this member                                          |
| `// !access:read=M`                                    | member line  | Partial metadata; other axis is inherited from the struct-level default                 |
| `// !lifecycle:none`                                   | member line  | Exclude member from destructor free logic                                               |
| `// !default:VALUE`                                    | member line  | Set field to VALUE in `init_defaults()`                                                 |
| `// !python:none`                                      | member line  | Exclude member from SWIG fragment; C accessors unaffected                               |
| `// !python:alias=NAME`                                | member line  | Rename Python attribute to NAME; C member name unchanged                                |
| `// !dict-table:none`                                  | member line  | Exclude member from dict-table output; silences unsupported-type warnings               |
| `const` qualifier on member                            | member type  | Force `write=none`; suppress free in destructor                                         |

In the table above, `M` is one of `generated`, `custom`, or `none`.

------

## Example

The following example is based on `struct libnvmf_uri` from `libnvme/src/nvme/private-fabrics.h`. The struct as defined in that file carries only `// !generate-accessors`; `!generate-lifecycle` and `// !default:4420` are added here to illustrate all features in one place.

### Annotated header

```c
/* Based on libnvme/src/nvme/private-fabrics.h */
struct libnvmf_uri { // !generate-accessors !generate-lifecycle
    char *scheme;
    char *protocol;
    char *userinfo;
    char *host;
    int port;              // !default:4420
    char **path_segments;
    char *query;
    char *fragment;        // !access:write=none
};
```

What each member demonstrates:

- `scheme`, `protocol`, `userinfo`, `host`, `query` — `char *` with both getter and setter; the setter stores a `strdup()` copy and frees the old value.
- `port` — scalar `int` with `!default:4420`; triggers generation of `libnvmf_uri_init_defaults()`.
- `path_segments` — `char **` NULL-terminated string array; setter deep-copies all elements; destructor frees each element and the container.
- `fragment` — `!access:write=none` yields a getter only; no setter is emitted.
- `!generate-lifecycle` — adds `libnvmf_uri_new()` and `libnvmf_uri_free()`; the constructor calls `init_defaults()` automatically.

### Command

```
python3 generate-accessors.py \
    --h-out  src/nvme/accessors-fabrics.h \
    --c-out  src/nvme/accessors-fabrics.c \
    --ld-out src/accessors-fabrics.ld \
    src/nvme/private-fabrics.h
```

### Generated `accessors-fabrics.h`

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* ... banner ... */

#ifndef _ACCESSORS_FABRICS_H_
#define _ACCESSORS_FABRICS_H_

/* ... standard includes ... */

/* Forward declarations. These are internal (opaque) structs. */
struct libnvmf_uri;

/****************************************************************************
 * Accessors for: struct libnvmf_uri
 ****************************************************************************/

/**
 * libnvmf_uri_new() - Allocate and initialise a libnvmf_uri object.
 * @pp: On success, *pp is set to the newly allocated object.
 *
 * Allocates a zeroed &struct libnvmf_uri on the heap.
 * The caller must release it with libnvmf_uri_free().
 *
 * Return: 0 on success, -EINVAL if @pp is NULL,
 *         -ENOMEM if allocation fails.
 */
int libnvmf_uri_new(struct libnvmf_uri **pp);

/**
 * libnvmf_uri_free() - Release a libnvmf_uri object.
 * @p: Object previously returned by libnvmf_uri_new().
 *     A NULL pointer is silently ignored.
 */
void libnvmf_uri_free(struct libnvmf_uri *p);

/**
 * libnvmf_uri_init_defaults() - Apply default values to a libnvmf_uri instance.
 * @p: The &struct libnvmf_uri instance to initialise.
 *
 * Sets each field that carries a !default annotation to its compile-time
 * default value. Called automatically by libnvmf_uri_new() but may also be
 * called directly to reset an instance to its defaults.
 */
void libnvmf_uri_init_defaults(struct libnvmf_uri *p);

void libnvmf_uri_set_scheme(struct libnvmf_uri *p, const char *scheme);
const char *libnvmf_uri_get_scheme(const struct libnvmf_uri *p);

void libnvmf_uri_set_protocol(struct libnvmf_uri *p, const char *protocol);
const char *libnvmf_uri_get_protocol(const struct libnvmf_uri *p);

void libnvmf_uri_set_userinfo(struct libnvmf_uri *p, const char *userinfo);
const char *libnvmf_uri_get_userinfo(const struct libnvmf_uri *p);

void libnvmf_uri_set_host(struct libnvmf_uri *p, const char *host);
const char *libnvmf_uri_get_host(const struct libnvmf_uri *p);

void libnvmf_uri_set_port(struct libnvmf_uri *p, int port);
int libnvmf_uri_get_port(const struct libnvmf_uri *p);

void libnvmf_uri_set_path_segments(struct libnvmf_uri *p,
		const char *const *path_segments);
const char *const *libnvmf_uri_get_path_segments(
		const struct libnvmf_uri *p);

void libnvmf_uri_set_query(struct libnvmf_uri *p, const char *query);
const char *libnvmf_uri_get_query(const struct libnvmf_uri *p);

/* fragment: getter only — !access:write=none suppresses the setter */
const char *libnvmf_uri_get_fragment(const struct libnvmf_uri *p);

#endif /* _ACCESSORS_FABRICS_H_ */
```

### Generated `accessors-fabrics.c`

```c
// SPDX-License-Identifier: LGPL-2.1-or-later
/* ... banner ... */

#include <stdlib.h>
#include <string.h>
#include "accessors-fabrics.h"
#include "private-fabrics.h"
#include "compiler-attributes.h"

/****************************************************************************
 * Accessors for: struct libnvmf_uri
 ****************************************************************************/

__public int libnvmf_uri_new(struct libnvmf_uri **pp)
{
	if (!pp)
		return -EINVAL;
	*pp = calloc(1, sizeof(struct libnvmf_uri));
	if (!*pp)
		return -ENOMEM;
	libnvmf_uri_init_defaults(*pp);
	return 0;
}

__public void libnvmf_uri_free(struct libnvmf_uri *p)
{
	if (!p)
		return;
	free(p->scheme);
	free(p->protocol);
	free(p->userinfo);
	free(p->host);
	if (p->path_segments) {
		size_t i;
		for (i = 0; p->path_segments[i]; i++)
			free(p->path_segments[i]);
		free(p->path_segments);
	}
	free(p->query);
	free(p->fragment);
	free(p);
}

__public void libnvmf_uri_init_defaults(struct libnvmf_uri *p)
{
	if (!p)
		return;
	p->port = 4420;
}

__public void libnvmf_uri_set_scheme(struct libnvmf_uri *p,
		const char *scheme)
{
	free(p->scheme);
	p->scheme = scheme ? strdup(scheme) : NULL;
}

__public const char *libnvmf_uri_get_scheme(const struct libnvmf_uri *p)
{
	return p->scheme;
}

/* ... similar implementations for protocol, userinfo, host, query ... */

__public void libnvmf_uri_set_port(struct libnvmf_uri *p, int port)
{
	p->port = port;
}

__public int libnvmf_uri_get_port(const struct libnvmf_uri *p)
{
	return p->port;
}

__public void libnvmf_uri_set_path_segments(struct libnvmf_uri *p,
		const char *const *path_segments)
{
	char **new_array = NULL;
	size_t i;

	if (path_segments) {
		for (i = 0; path_segments[i]; i++)
			;

		new_array = calloc(i + 1, sizeof(char *));
		if (new_array != NULL) {
			for (i = 0; path_segments[i]; i++) {
				new_array[i] = strdup(path_segments[i]);
				if (!new_array[i]) {
					while (i > 0)
						free(new_array[--i]);
					free(new_array);
					new_array = NULL;
					break;
				}
			}
		}
	}

	for (i = 0; p->path_segments && p->path_segments[i]; i++)
		free(p->path_segments[i]);
	free(p->path_segments);
	p->path_segments = new_array;
}

__public const char *const *libnvmf_uri_get_path_segments(
		const struct libnvmf_uri *p)
{
	return (const char *const *)p->path_segments;
}

__public const char *libnvmf_uri_get_fragment(const struct libnvmf_uri *p)
{
	return p->fragment;
}
```

> **Notes:**
> - `fragment` has no setter — `!access:write=none` suppresses it — but the destructor still frees it because `!lifecycle:none` was not set.
> - `path_segments` (`char **`) setter: builds the new deep-copy first, then frees the old array. This ensures the struct is always in a valid state even if `strdup` fails partway through.
> - `port` (`int`) receives a direct assignment in `init_defaults()`. For `char *` members with a string default, `init_defaults()` uses a compare-before-replace pattern: if the current value already matches the default (`strcmp`), nothing happens; otherwise the old value is freed and the default is `strdup()`'d.
> - The constructor calls `init_defaults()` after `calloc()`, so freshly allocated objects start at their defined defaults rather than zero.

### Generated `accessors-fabrics.ld`

```
# SPDX-License-Identifier: LGPL-2.1-or-later
/* ... banner ... */

LIBNVMF_ACCESSORS_3 {
	global:
		libnvmf_uri_new;
		libnvmf_uri_free;
		libnvmf_uri_init_defaults;
		libnvmf_uri_get_scheme;
		libnvmf_uri_set_scheme;
		libnvmf_uri_get_protocol;
		libnvmf_uri_set_protocol;
		libnvmf_uri_get_userinfo;
		libnvmf_uri_set_userinfo;
		libnvmf_uri_get_host;
		libnvmf_uri_set_host;
		libnvmf_uri_get_port;
		libnvmf_uri_set_port;
		libnvmf_uri_get_path_segments;
		libnvmf_uri_set_path_segments;
		libnvmf_uri_get_query;
		libnvmf_uri_set_query;
		libnvmf_uri_get_fragment;
};
```

> **Note:** `fragment` has no `set` entry because `!access:write=none` suppresses the setter. The version node name (`LIBNVMF_ACCESSORS_3`) is assigned by the maintainer in the `.ld` file; the generator reports symbol drift but does not overwrite it.

------

## Limitations

- `typedef struct` is not supported.
- Nested structs (a `struct` member whose type is also a `struct`) are skipped.
- Only `char *` and `char **` pointer members are supported; other pointer types are skipped.
