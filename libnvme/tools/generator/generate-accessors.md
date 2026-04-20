# Generate Accessors Tool

This tool generates **setter and getter functions** for C structs automatically. It supports dynamic strings, fixed-size char arrays, and `const` fields, with control over which structs and members participate via **in-source annotations**.

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

Struct inclusion and member behaviour are controlled by **annotations written as
`//` comments directly in the header file**. The canonical form is `// !token`
(one space between `//` and `!`). The parser also accepts `//!token` and
`//\t!token` — any amount of whitespace between `//` and `!` is treated
identically, making the annotation resilient to contributor variation.

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
    char *state;      // !accessors:none
    char *subsysnqn;  // !accessors:none
};
```

### Read-only members — `accessors:readonly`

Place the annotation on a member's declaration line to generate only a getter (no setter). This has the same effect as declaring the member `const`, but without changing the type in the struct. Also useful to override a `generate-accessors:writeonly` struct default for individual members:

```c
struct nvme_ctrl { // !generate-accessors
    char *name;
    char *firmware;   // !accessors:readonly
    char *model;      // !accessors:readonly
};
```

Members declared with the `const` qualifier are also automatically read-only.

### Write-only members — `accessors:writeonly`

Place the annotation on a member's declaration line to generate only a setter (no getter). Useful to override a `generate-accessors:readonly` struct default for individual members:

```c
struct nvme_ctrl { // !generate-accessors:readonly
    char *name;       /* getter only (struct default) */
    char *token;      // !accessors:writeonly    /* setter only override */
};
```

### Read-write members — `accessors:readwrite`

Place the annotation on a member's declaration line to generate both a getter and a setter, overriding a restrictive struct-level default (`none`, `readonly`, or `writeonly`):

```c
struct nvme_ctrl { // !generate-accessors:none
    char *name;       /* no accessors (struct default) */
    char *model;      // !accessors:readwrite    /* both getter and setter */
    char *firmware;   // !accessors:readonly     /* getter only */
};
```

### Annotation summary

| Annotation                               | Where        | Effect                                      |
| ---------------------------------------- | ------------ | ------------------------------------------- |
| `// !generate-accessors`                 | struct brace | Include struct, default: getter + setter    |
| `// !generate-accessors:none`            | struct brace | Include struct, default: no accessors       |
| `// !generate-accessors:readonly`        | struct brace | Include struct, default: getter only        |
| `// !generate-accessors:writeonly`       | struct brace | Include struct, default: setter only        |
| `// !accessors:none`                     | member line  | Skip this member entirely                   |
| `// !accessors:readonly`                 | member line  | Generate getter only                        |
| `// !accessors:writeonly`                | member line  | Generate setter only                        |
| `// !accessors:readwrite`                | member line  | Generate getter and setter                  |
| `const` qualifier on member             | member type  | Suppress setter (built-in, always applies)  |

------

## Example

### Header file (`person.h`)

```c
struct person { // !generate-accessors
    char *name;
    int age;
    const char *id;       /* const → getter only, no annotation needed */
    char *secret;         // !accessors:none
    char *role;           // !accessors:readonly
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

> **Note:** The `secret` member is absent because of `// !accessors:none` — excluded members leave no trace in the output. The `role` member has only a getter because of `// !accessors:readonly`. The `id` and `vin` members have only getters because they are declared `const`.

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

> **Note:** Only symbols for members that have accessors generated appear in the linker script. The `secret` member (excluded via `// !accessors:none`) and the write-only `token` example would have no getter entry. The version node name `LIBNVME_ACCESSORS_3` is hardcoded in the generator.

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
4. **`const` members** — only a getter is generated, no setter (applies regardless of any annotation).
5. **`// !accessors:readonly`** — same effect as `const`: getter only.
6. **`// !accessors:writeonly`** — setter only; getter is suppressed.
7. **`// !accessors:readwrite`** — both getter and setter; overrides a restrictive struct-level default.
8. **`// !accessors:none`** — member is completely ignored by the generator.
9. **Struct-level mode** — the qualifier on `generate-accessors` sets the default for every member in the struct; per-member annotations override the struct default.
10. **`--prefix`** — prepended to every function name (e.g. `--prefix nvme_` turns `ctrl_set_name` into `nvme_ctrl_set_name`).
11. **Line length** — generated code is automatically wrapped to stay within the 80-column limit required by `checkpatch.pl`.
