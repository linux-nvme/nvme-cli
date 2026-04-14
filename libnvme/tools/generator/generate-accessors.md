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

Struct inclusion and member behaviour are controlled by **annotations written as comments directly in the header file**. Both `/* */` (block) and `//` (line) comment styles are supported for every annotation.

### Struct inclusion — `generate-accessors`

Place the annotation on the same line as the struct's opening brace to opt that struct in to code generation:

```c
struct nvme_ctrl { /*!generate-accessors*/
    ...
};
```

```c
struct nvme_ctrl { //!generate-accessors
    ...
};
```

Only structs carrying this annotation will have accessors generated. All other structs in the header are ignored.

### Member exclusion — `accessors:none`

Place the annotation on a member's declaration line to suppress accessor generation for that member entirely (no setter, no getter):

```c
struct nvme_ctrl { /*!generate-accessors*/
    char *name;
    char *state;      //!accessors:none
    char *subsysnqn;  /*!accessors:none*/
};
```

### Read-only members — `accessors:readonly`

Place the annotation on a member's declaration line to generate only a getter (no setter). This has the same effect as declaring the member `const`, but without changing the type in the struct:

```c
struct nvme_ctrl { /*!generate-accessors*/
    char *name;
    char *firmware;   //!accessors:readonly
    char *model;      /*!accessors:readonly*/
};
```

Members declared with the `const` qualifier are also automatically read-only.

### Annotation summary

| Annotation                  | Where        | Effect                          |
| --------------------------- | ------------ | ------------------------------- |
| `/*!generate-accessors*/`   | struct brace | Include this struct             |
| `//!generate-accessors`     | struct brace | Include this struct             |
| `/*!accessors:none*/`       | member line  | Skip this member entirely       |
| `//!accessors:none`         | member line  | Skip this member entirely       |
| `/*!accessors:readonly*/`   | member line  | Generate getter only            |
| `//!accessors:readonly`     | member line  | Generate getter only            |
| `const` qualifier on member | member type  | Generate getter only (built-in) |

------

## Example

### Header file (`person.h`)

```c
struct person { /*!generate-accessors*/
    char *name;
    int age;
    const char *id;       /* const → getter only, no annotation needed */
    char *secret;         //!accessors:none
    char *role;           //!accessors:readonly
};

struct car { /*!generate-accessors*/
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
#include <linux/types.h> /* __u32, __u64, etc. */

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

/* secret: no accessors (//!accessors:none) */

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

void car_set_model(struct car *p, const char *model);
const char *car_get_model(const struct car *p);

void car_set_year(struct car *p, int year);
int car_get_year(const struct car *p);

const char *car_get_vin(const struct car *p);

#endif /* _ACCESSORS_H_ */
```

> **Note:** The `secret` member is absent because of `//!accessors:none`. The `role` member has only a getter because of `//!accessors:readonly`. The `id` and `vin` members have only getters because they are declared `const`.

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

/* ... struct car accessors follow the same pattern ... */
```

------

## Limitations

- `typedef struct` is not supported.
- Nested structs (a `struct` member whose type is also a `struct`) are skipped.
- Only `char *` pointer members are supported; other pointer types are skipped.

------

## Notes

1. **Dynamic strings** (`char *`) — setters store a `strdup()` copy; passing `NULL` clears the field.
2. **Fixed char arrays** (`char foo[N]`) — setters use `snprintf`, always NUL-terminated.
3. **`const` members** — only a getter is generated, no setter.
4. **`//!accessors:readonly`** — same effect as `const`: getter only.
5. **`//!accessors:none`** — member is completely ignored by the generator.
6. **`--prefix`** — prepended to every function name (e.g. `--prefix nvme_` turns `ctrl_set_name` into `nvme_ctrl_set_name`).
7. **Line length** — generated code is automatically wrapped to stay within the 80-column limit required by `checkpatch.pl`.
