# Generate Accessors Tool

This tool generates **setter and getter functions** for C structs automatically.
 It supports dynamic strings, fixed-size char arrays, const fields, and exclusion/inclusion lists.

------

## Compilation / Testing

```bash
make
make test
```

------

## Usage

```
./generate-accessors [options] <header-files>
```

**Options:**

| Short | Long        | Argument | Description                                                  |
| ----- | ----------- | -------- | ------------------------------------------------------------ |
| `-h`  | `--h-out`   | `<file>` | Output: Full path (incl. directories) of the *.h file to generate. |
| `-c`  | `--c-out`   | `<file>` | Output: Full path (incl. directories) of the *.c file to generate. |
| `-e`  | `--excl`    | `<file>` | Exclusion list file with `struct::member` per line           |
| `-i`  | `--incl`    | `<file>` | Inclusion list file with `struct` per line. The list of `struct` to be included in the generation. When not specified, accessors will be generated for all `struct` found in the `header-file`. |
| `-p`  | `--prefix`  | `<str>`  | Prefix for generated function names                          |
| `-v`  | `--verbose` | none     | Verbose output showing which `struct` is being processed     |
| `-H`  | `--help`    | none     | Show this help message                                       |

------

## Examples

### Single Struct Example

Header file `person.h`:

```
struct person {
    char *name;
    int age;
    const char *id;
};
```

Command:

```
./generate-accessors person.h
```

Generated `accessors.h`:

```
// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 *
 *   ____                           _           _    ____          _
 *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___
 * | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \/ _` | | |   / _ \ / _` |/ _ \
 * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/
 *  \____|\___|_| |_|\___|_|  \__,_|\__\___|\__,_|  \____\___/ \__,_|\___|
 *
 * Auto-generated struct member accessors (setter/getter)
 */

#ifndef ACCESSORS_H
#define ACCESSORS_H

#include <stdlib.h>
#include <string.h>

#include "structs.h"

/****************************************************************************
 * Accessors for: struct person
 */
void person_name_set(struct person *p, const char *name);
const char * person_name_get(struct person *p);

void person_age_set(struct person *p, int age);
int person_age_get(struct person *p);

int person_id_get(struct person *p);

#endif /* ACCESSORS_H */

```

Generated `accessors.c`:

```
// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 *
 *   ____                           _           _    ____          _
 *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___
 * | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \/ _` | | |   / _ \ / _` |/ _ \
 * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/
 *  \____|\___|_| |_|\___|_|  \__,_|\__\___|\__,_|  \____\___/ \__,_|\___|
 *
 * Auto-generated struct member accessors (setter/getter)
 */

#include <stdlib.h>
#include <string.h>
#include "accessors.h"

/****************************************************************************
 * Accessors for: struct person
 */
void person_name_set(struct person *p, const char *name) {
    free(p->name);
    p->name = name ? strdup(name) : NULL;
}

const char * person_name_get(struct person *p) {
    return p->name;
}

void person_age_set(struct person *p, int age) {
    p->age = age;
}

int person_age_get(struct person *p) {
    return p->age;
}

int person_id_get(struct person *p) {
    return p->id;
}
```

------

### Multi-Struct Example

Header file `example_structs.h`:

```
struct person {
    char *name;
    int age;
    const char *id;
};

struct car {
    char *model;
    int year;
    const char *vin;
};
```

Command:

```
./generate-accessors --prefix my_ example_structs.h
```

Generated `accessors.h`:

```
// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 *
 *   ____                           _           _    ____          _
 *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___
 * | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \/ _` | | |   / _ \ / _` |/ _ \
 * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/
 *  \____|\___|_| |_|\___|_|  \__,_|\__\___|\__,_|  \____\___/ \__,_|\___|
 *
 * Auto-generated struct member accessors (setter/getter)
 */

#ifndef ACCESSORS_H
#define ACCESSORS_H

#include <stdlib.h>
#include <string.h>

#include "example_structs.h"

/****************************************************************************
 * Accessors for: struct person
 */
void my_person_name_set(struct person *p, const char *name);
const char * my_person_name_get(struct person *p);

void my_person_age_set(struct person *p, int age);
int my_person_age_get(struct person *p);

const char * my_person_id_get(struct person *p);


/****************************************************************************
 * Accessors for: struct car
 */
void my_car_model_set(struct car *p, const char *model);
const char * my_car_model_get(struct car *p);

void my_car_year_set(struct car *p, int year);
int my_car_year_get(struct car *p);

const char * my_car_vin_get(struct car *p);

#endif /* ACCESSORS_H */

```

Generated `accessors.c`:

```
// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 *
 *   ____                           _           _    ____          _
 *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___
 * | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \/ _` | | |   / _ \ / _` |/ _ \
 * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/
 *  \____|\___|_| |_|\___|_|  \__,_|\__\___|\__,_|  \____\___/ \__,_|\___|
 *
 * Auto-generated struct member accessors (setter/getter)
 */

#include <stdlib.h>
#include <string.h>
#include "accessors.h"

/****************************************************************************
 * Accessors for: struct person
 */
void my_person_name_set(struct person *p, const char *name) {
    free(p->name);
    p->name = name ? strdup(name) : NULL;
}

const char * my_person_name_get(struct person *p) {
    return p->name;
}

void my_person_age_set(struct person *p, int age) {
    p->age = age;
}

int my_person_age_get(struct person *p) {
    return p->age;
}

const char * my_person_id_get(struct person *p) {
    return p->id;
}

/****************************************************************************
 * Accessors for: struct car
 */
void my_car_model_set(struct car *p, const char *model) {
    free(p->model);
    p->model = model ? strdup(model) : NULL;
}

const char * my_car_model_get(struct car *p) {
    return p->model;
}

void my_car_year_set(struct car *p, int year) {
    p->year = year;
}

int my_car_year_get(struct car *p) {
    return p->year;
}

const char * my_car_vin_get(struct car *p) {
    return p->vin;
}
```

------

### Notes

1. **Dynamic strings** (`char *`) are NULL-safe.
2. **Const fields** generate **getter-only functions**.
3. Numeric fields and other types have normal setters/getters.
4. The `--prefix` option adds a custom prefix to all generated functions.
5. The exclusion list (`--excl`) prevents generating accessors for specific `struct:member` pairs.
7. The inclusion list (`--incl`) limits generation to only the listed `struct` names.