# Generate Accessors Tool

This tool generates **setter and getter functions** for C structs automatically. It also optionally generates **constructor and destructor functions** (`foo_new` / `foo_free`). It supports dynamic strings, fixed-size char arrays, and `const` fields, with control over which structs and members participate via **in-source annotations**.

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
| `-p`  | `--prefix` | `<str>`  | Prefix prepended to every generated function name        |
| `-v`  | `--verbose`| none     | Verbose output showing which structs are being processed |
| `-H`  | `--help`   | none     | Show this help message                                   |

------

## Annotations

Struct inclusion and member behavior are controlled by **annotations written as `//` line comments directly in the header file**. After `//`, each `!keyword` token (optionally followed by `:qualifier` or `:VALUE`) is a command. Multiple annotations may share one comment, separated by spaces. The canonical form is `// !token` (one space between `//` and `!`); `//!token` and `//\t!token` are also accepted.

### Struct inclusion — `generate-accessors`

Place the annotation on the same line as the struct's opening brace to opt that struct in to code generation. An optional mode qualifier sets the **default behaviour for all members** of that struct:

| Annotation                               | Default for all members           |
| ---------------------------------------- | --------------------------------- |
| `// !generate-accessors`                 | getter **and** setter (default)   |
| `// !generate-accessors:none`            | no accessors                      |
| `// !generate-accessors:readonly`        | getter only                       |
| `// !generate-accessors:writeonly`       | setter only                       |

```c
struct nvme_ctrl { // !generate-accessors          /* both getter and setter */
    ...
};

struct nvme_ctrl { // !generate-accessors:readonly /* getter only by default */
    ...
};
```

Only structs carrying this annotation will have accessors generated. All other structs in the header are ignored.

Individual members can always override the struct-level default using a per-member annotation (see below).

### Member exclusion — `accessors:none`

Place the annotation on a member's declaration line to suppress accessor generation for that member entirely (no setter, no getter):

```c
struct nvme_ctrl { // !generate-accessors
    char *name;
    char *state;      // !access:none
    char *subsysnqn;  // !access:none
};
```

### Read-only members — `accessors:readonly`

Place the annotation on a member's declaration line to generate only a getter (no setter). This has the same effect as declaring the member `const`, but without changing the type in the struct. Also useful to override a `generate-accessors:writeonly` struct default for individual members:

```c
struct nvme_ctrl { // !generate-accessors
    char *name;
    char *firmware;   // !access:readonly
    char *model;      // !access:readonly
};
```

Members declared with the `const` qualifier are also automatically read-only.

### Write-only members — `accessors:writeonly`

Place the annotation on a member's declaration line to generate only a setter (no getter). Useful to override a `generate-accessors:readonly` struct default for individual members:

```c
struct nvme_ctrl { // !generate-accessors:readonly
    char *name;       /* getter only (struct default) */
    char *token;      // !access:writeonly    /* setter only override */
};
```

### Read-write members — `accessors:readwrite`

Place the annotation on a member's declaration line to generate both a getter and a setter, overriding a restrictive struct-level default (`none`, `readonly`, or `writeonly`):

```c
struct nvme_ctrl { // !generate-accessors:none
    char *name;       /* no accessors (struct default) */
    char *model;      // !access:readwrite    /* both getter and setter */
    char *firmware;   // !access:readonly     /* getter only */
};
```

### Struct lifecycle — `generate-lifecycle`

Place the annotation on the same line as the struct's opening brace to generate a constructor and a destructor for that struct:

```c
struct nvme_ctrl { // !generate-lifecycle
    char *name;
    char *subsysnqn;
    char *serial;   // !lifecycle:none   /* excluded from destructor */
};
```

This generates:

- **`nvme_ctrl_new(struct nvme_ctrl **pp)`** — allocates a zeroed instance on the heap. Returns `0` on success, `-EINVAL` if `pp` is `NULL`, or `-ENOMEM` on allocation failure.
- **`nvme_ctrl_free(struct nvme_ctrl *p)`** — frees all `char *` and `char **` members (except those marked `// !lifecycle:none`) and then frees the struct itself. A `NULL` argument is silently ignored.

`generate-lifecycle` can appear alongside `generate-accessors` in the same comment:

```c
struct nvme_ctrl { // !generate-accessors !generate-lifecycle
    char *name;
    char *subsysnqn;
};
```

`const char *` members are **never** freed by the destructor — they are assumed to point to externally owned storage.

### Lifecycle member exclusion — `lifecycle:none`

Place the annotation on a member's declaration line to exclude it from the destructor's free logic:

```c
struct nvme_ctrl { // !generate-lifecycle
    char *name;
    char *borrowed;  // !lifecycle:none   /* not freed — caller owns this */
};
```

This annotation has no effect on accessor generation. Combine with `// !access:none` if both should be suppressed.

### Member defaults — `default:VALUE`

Place the annotation on a member's declaration line to assign a compile-time default value. When any member in the struct carries this annotation, a `foo_init_defaults()` function is generated:

```c
struct libnvmf_discovery_args { // !generate-accessors !generate-lifecycle
    int max_retries;  // !default:6
    __u8 lsp;         // !default:NVMF_LOG_DISC_LSP_NONE
};
```

This generates `libnvmf_discovery_args_init_defaults()`, which sets each annotated field to its default value. If `generate-lifecycle` is also present, the constructor automatically calls `init_defaults()` after allocation. This lets callers re-initialise an existing instance without freeing and reallocating it.

The value is emitted verbatim, so any valid C expression — integer literals, macro names, enum constants — is accepted.

`init_defaults()` can be used independently of `generate-lifecycle`.

### Annotation summary

| Annotation                               | Where        | Effect                                                    |
| ---------------------------------------- | ------------ | --------------------------------------------------------- |
| `// !generate-accessors`                 | struct brace | Include struct, default: getter + setter                  |
| `// !generate-accessors:none`            | struct brace | Include struct, default: no accessors                     |
| `// !generate-accessors:readonly`        | struct brace | Include struct, default: getter only                      |
| `// !generate-accessors:writeonly`       | struct brace | Include struct, default: setter only                      |
| `// !generate-lifecycle`                 | struct brace | Generate constructor + destructor                         |
| `// !access:none`                        | member line  | Skip this member entirely (accessors only)                |
| `// !access:readonly`                    | member line  | Generate getter only                                      |
| `// !access:writeonly`                   | member line  | Generate setter only                                      |
| `// !access:readwrite`                   | member line  | Generate getter and setter                                |
| `// !lifecycle:none`                     | member line  | Exclude member from destructor free logic                 |
| `// !default:VALUE`                      | member line  | Set field to VALUE in `init_defaults()`                   |
| `const` qualifier on member              | member type  | Suppress setter; suppress free in destructor              |

------

## Example

### Header file (`person.h`)

```c
struct person { // !generate-accessors
    char *name;
    int age;
    const char *id;       /* const → getter only, no annotation needed */
    char *secret;         // !access:none
    char *role;           // !access:readonly
};

struct car { // !generate-accessors
    char *model;
    int year;
    const char *vin;
};
```

### Command

```
python3 generate-accessors.py person.h
```

### Generated `accessors.h`

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* ... banner ... */

#ifndef _ACCESSORS_H_
#define _ACCESSORS_H_

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <nvme/types.h>

/* Forward declarations. These are internal (opaque) structs. */
struct person;
struct car;

/****************************************************************************
 * Accessors for: struct person
 ****************************************************************************/

/**
 * person_set_name() - Set name.
 * @p: The &struct person instance to update.
 * @name: New string; a copy is stored. Pass NULL to clear.
 */
void person_set_name(struct person *p, const char *name);

/**
 * person_get_name() - Get name.
 * @p: The &struct person instance to query.
 *
 * Return: The value of the name field, or NULL if not set.
 */
const char *person_get_name(const struct person *p);

/**
 * person_set_age() - Set age.
 * @p: The &struct person instance to update.
 * @age: Value to assign to the age field.
 */
void person_set_age(struct person *p, int age);

/**
 * person_get_age() - Get age.
 * @p: The &struct person instance to query.
 *
 * Return: The value of the age field.
 */
int person_get_age(const struct person *p);

/**
 * person_get_id() - Get id.
 * @p: The &struct person instance to query.
 *
 * Return: The value of the id field, or NULL if not set.
 */
const char *person_get_id(const struct person *p);

/**
 * person_get_role() - Get role.
 * @p: The &struct person instance to query.
 *
 * Return: The value of the role field, or NULL if not set.
 */
const char *person_get_role(const struct person *p);

/****************************************************************************
 * Accessors for: struct car
 ****************************************************************************/

/**
 * car_set_model() - Set model.
 * @p: The &struct car instance to update.
 * @model: New string; a copy is stored. Pass NULL to clear.
 */
void car_set_model(struct car *p, const char *model);

/**
 * car_get_model() - Get model.
 * @p: The &struct car instance to query.
 *
 * Return: The value of the model field, or NULL if not set.
 */
const char *car_get_model(const struct car *p);

/**
 * car_set_year() - Set year.
 * @p: The &struct car instance to update.
 * @year: Value to assign to the year field.
 */
void car_set_year(struct car *p, int year);

/**
 * car_get_year() - Get year.
 * @p: The &struct car instance to query.
 *
 * Return: The value of the year field.
 */
int car_get_year(const struct car *p);

/**
 * car_get_vin() - Get vin.
 * @p: The &struct car instance to query.
 *
 * Return: The value of the vin field, or NULL if not set.
 */
const char *car_get_vin(const struct car *p);

#endif /* _ACCESSORS_H_ */
```

> **Note:** The `secret` member is absent because of `// !access:none` — excluded members leave no trace in the output. The `role` member has only a getter because of `// !access:readonly`. The `id` and `vin` members have only getters because they are declared `const`.

### Generated `accessors.c`

```c
// SPDX-License-Identifier: LGPL-2.1-or-later
/* ... banner ... */

#include <stdlib.h>
#include <string.h>
#include "accessors.h"

#include "person.h"
#include "compiler-attributes.h"

/****************************************************************************
 * Accessors for: struct person
 ****************************************************************************/

__public void person_set_name(struct person *p, const char *name)
{
	free(p->name);
	p->name = name ? strdup(name) : NULL;
}

__public const char *person_get_name(const struct person *p)
{
	return p->name;
}

__public void person_set_age(struct person *p, int age)
{
	p->age = age;
}

__public int person_get_age(const struct person *p)
{
	return p->age;
}

__public const char *person_get_id(const struct person *p)
{
	return p->id;
}

__public const char *person_get_role(const struct person *p)
{
	return p->role;
}

/****************************************************************************
 * Accessors for: struct car
 ****************************************************************************/

__public void car_set_model(struct car *p, const char *model)
{
	free(p->model);
	p->model = model ? strdup(model) : NULL;
}

__public const char *car_get_model(const struct car *p)
{
	return p->model;
}

__public void car_set_year(struct car *p, int year)
{
	p->year = year;
}

__public int car_get_year(const struct car *p)
{
	return p->year;
}

__public const char *car_get_vin(const struct car *p)
{
	return p->vin;
}
```

### Generated `accessors.ld`

```
# SPDX-License-Identifier: LGPL-2.1-or-later
/* ... banner ... */

LIBNVME_ACCESSORS_3 {
	global:
		person_get_name;
		person_set_name;
		person_get_age;
		person_set_age;
		person_get_id;
		person_get_role;
		car_get_model;
		car_set_model;
		car_get_year;
		car_set_year;
		car_get_vin;
};
```

> **Note:** Only symbols for members that have accessors generated appear in the linker script. The `secret` member (excluded via `// !access:none`) and the write-only `token` example would have no getter entry. The version node name `LIBNVME_ACCESSORS_3` is hardcoded in the generator.

------

## Lifecycle example

### Header file (`person.h`) — with lifecycle

Adding `// !generate-lifecycle` to the same struct enables constructor and destructor generation alongside the accessors:

```c
struct person { // !generate-accessors !generate-lifecycle
    char *name;
    int age;
    const char *id;       /* const → getter only; NOT freed by destructor */
    char *secret;         // !access:none
    char *role;           // !access:readonly
};
```

### Additional declarations in `accessors.h`

The constructor and destructor declarations are appended after the accessor declarations for the same struct:

```c
/**
 * person_new() - Allocate and initialise a person object.
 * @pp: On success, *pp is set to the newly allocated object.
 *
 * Allocates a zeroed &struct person on the heap.
 * The caller must release it with person_free().
 *
 * Return: 0 on success, -EINVAL if @pp is NULL,
 *         -ENOMEM if allocation fails.
 */
int person_new(struct person **pp);

/**
 * person_free() - Release a person object.
 * @p: Object previously returned by person_new().
 *     A NULL pointer is silently ignored.
 */
void person_free(struct person *p);
```

### Additional implementations in `accessors.c`

```c
__public int person_new(struct person **pp)
{
	if (!pp)
		return -EINVAL;
	*pp = calloc(1, sizeof(struct person));
	return *pp ? 0 : -ENOMEM;
}

__public void person_free(struct person *p)
{
	if (!p)
		return;
	free(p->name);
	free(p->secret);
	free(p->role);
	free(p);
}
```

> **Notes:**
> - `id` is `const char *` — the destructor never frees `const` members.
> - `secret` is `// !access:none` but is still freed — `lifecycle:none` is the annotation to suppress a free.
> - `age` is `int` — only `char *` and `char **` members are freed.

### Additional entries in `accessors.ld`

```
		person_new;
		person_free;
```

------

## Defaults example

```c
struct conn_opts { // !generate-accessors !generate-lifecycle
    int port;            // !default:4420
    char *transport;     // !default:"tcp"
    const char *trsvcid; // !default:"4420"
};
```

### Generated declaration in `accessors.h`

```c
/**
 * conn_opts_init_defaults() - Apply default values to a conn_opts instance.
 * @p: The &struct conn_opts instance to initialise.
 *
 * Sets each field that carries a default annotation to its
 * compile-time default value.  Called automatically by
 * conn_opts_new() but may also be called directly to reset
 * an instance to its defaults without reallocating it.
 */
void conn_opts_init_defaults(struct conn_opts *p);
```

### Generated implementation in `accessors.c`

Note how `transport` (`char *`) is assigned via `strdup()` — the struct owns
the memory and the destructor frees it. In contrast, `trsvcid` (`const char *`)
receives a plain assignment to a string literal — no heap allocation, no free.

```c
__public void conn_opts_init_defaults(struct conn_opts *p)
{
	if (!p)
		return;
	p->port = 4420;
	if (!p->transport || strcmp(p->transport, "tcp") != 0) {
		free(p->transport);
		p->transport = strdup("tcp");
	}
	p->trsvcid = "4420";
}

__public int conn_opts_new(struct conn_opts **pp)
{
	if (!pp)
		return -EINVAL;
	*pp = calloc(1, sizeof(struct conn_opts));
	if (!*pp)
		return -ENOMEM;
	conn_opts_init_defaults(*pp);
	return 0;
}

__public void conn_opts_free(struct conn_opts *p)
{
	if (!p)
		return;
	free(p->transport);
	free(p);
}
```

> **Notes:**
> - Scalar members (`int`, `__u8`, etc.) are assigned directly.
> - `char *` members use a compare-before-replace pattern: if the current
>   value already matches the default (`strcmp`), nothing happens; otherwise
>   the old value is freed and the new default is `strdup()`'d. This makes
>   `init_defaults()` safe to call on an already-initialised struct without
>   leaking memory.
> - `const char *` members are assigned directly (no `strdup`) since they
>   are assumed to point to externally owned storage. They are also not
>   freed by the destructor, as seen in `conn_opts_free` — `trsvcid` has
>   no `free()` call.
> - The constructor (`_new`) calls `init_defaults()` after `calloc()`, so
>   freshly allocated structs always start at their defined defaults rather
>   than zero.

### Additional entries in `accessors.ld`

```
		conn_opts_new;
		conn_opts_free;
		conn_opts_init_defaults;
		conn_opts_get_port;
		conn_opts_set_port;
		conn_opts_get_transport;
		conn_opts_set_transport;
		conn_opts_get_trsvcid;
```

------

## Limitations

- `typedef struct` is not supported.
- Nested structs (a `struct` member whose type is also a `struct`) are skipped.
- Only `char *` and `char **` pointer members are supported; other pointer types are skipped.

------

## Notes

1. **Dynamic strings** (`char *`) — setters store a `strdup()` copy; passing `NULL` clears the field.
2. **String arrays** (`char **`) — setters deep-copy NULL-terminated arrays (each element and the container).
3. **Fixed char arrays** (`char foo[N]`) — setters use `snprintf`, always NUL-terminated.
4. **`const` members** — only a getter is generated, no setter (applies regardless of any annotation). `const char *` members are also skipped by the destructor.
5. **`// !access:readonly`** — same effect as `const`: getter only.
6. **`// !access:writeonly`** — setter only; getter is suppressed.
7. **`// !access:readwrite`** — both getter and setter; overrides a restrictive struct-level default.
8. **`// !access:none`** — member is completely ignored by the accessor generator. The destructor still frees it unless `// !lifecycle:none` is also present.
9. **Struct-level mode** — the qualifier on `generate-accessors` sets the default for every member in the struct; per-member annotations override the struct default.
10. **`// !generate-lifecycle`** — generates `foo_new()` (constructor) and `foo_free()` (destructor). Can appear on the same line as `generate-accessors`. A struct needs only one of the two annotations.
11. **`// !lifecycle:none`** — excludes a member from the destructor's free logic. Use this when the struct does not own the pointed-to memory.
12. **Destructor NULL safety** — `free(NULL)` is a no-op per the C standard, so destructors with no string members to dereference emit only `free(p)` with no NULL guard. Destructors that do dereference `p->field` guard with `if (!p) return;` first. In both cases passing NULL to the destructor is safe.
13. **`// !default:VALUE`** — generates `foo_init_defaults()` that sets the annotated field to `VALUE`. Scalar members are assigned directly. `char *` members use a compare-before-replace pattern: if the current value already equals the default (`strcmp`), nothing happens; otherwise the old value is freed and the new default is `strdup()`'d. `const char *` members are assigned directly (no `strdup`). Quoted string values (`"foo bar"`) may contain spaces.
14. **`init_defaults()` and `new()`** — when a struct has both `generate-lifecycle` and at least one `// !default:`, the constructor calls `init_defaults()` after `calloc()`. Without `generate-lifecycle`, `init_defaults()` is still generated as a standalone function.
15. **`init_defaults()` for re-initialisation** — callers can call `init_defaults()` directly on an already-allocated instance to reset scalar fields to their defaults without freeing and reallocating the struct.
16. **`--prefix`** — prepended to every function name (e.g. `--prefix nvme_` turns `ctrl_set_name` into `nvme_ctrl_set_name`).
17. **Line length** — generated code is automatically wrapped to stay within the 80-column limit required by `checkpatch.pl`.
