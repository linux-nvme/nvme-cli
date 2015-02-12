////////////////////////////////////////////////////////////////////////
//
// Copyright 2014 PMC-Sierra, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you
// may not use this file except in compliance with the License. You may
// obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0 Unless required by
// applicable law or agreed to in writing, software distributed under the
// License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for
// the specific language governing permissions and limitations under the
// License.
//
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
//
//   Author: Logan Gunthorpe
//
//   Date:   Oct 23 2014
//
//   Description:
//     Functions for dealing with number suffixes
//
////////////////////////////////////////////////////////////////////////

#include "suffix.h"

#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

static struct si_suffix {
    double magnitude;
    const char *suffix;
} si_suffixes[] = {
    {1e15,  "P"},
    {1e12,  "T"},
    {1e9,   "G"},
    {1e6,   "M"},
    {1e3,   "k"},
    {1e0,   ""},
    {1e-3,  "m"},
    {1e-6,  "u"},
    {1e-9,  "n"},
    {1e-12, "p"},
    {1e-15, "f"},
    {0}
};

const char *suffix_si_get(double *value)
{
    struct si_suffix *s;

    for (s = si_suffixes; s->magnitude != 0; s++) {
        if (*value >= s->magnitude) {
            *value /= s->magnitude;
            return s->suffix;
        }
    }

    return "";
}

static struct binary_suffix {
    int shift;
    const char *suffix;
} binary_suffixes[] = {
    {50, "Pi"},
    {40, "Ti"},
    {30, "Gi"},
    {20, "Mi"},
    {10, "Ki"},
    {0,  ""},
};

const char *suffix_binary_get(long long *value) {
    struct binary_suffix *s;

    for (s = binary_suffixes; s->shift != 0; s++) {
        if (llabs(*value) >= (1LL << s->shift)) {
            *value = (*value + (1 << (s->shift - 1))) /  (1 << s->shift);
            return s->suffix;
        }
    }

    return "";
}

const char *suffix_dbinary_get(double *value) {
    struct binary_suffix *s;

    for (s = binary_suffixes; s->shift != 0; s++) {
        if (llabs(*value) >= (1LL << s->shift)) {
            *value = *value /  (1 << s->shift);
            return s->suffix;
        }
    }

    return "";
}

long long suffix_binary_parse(const char *value)
{
    char *suffix;
    errno = 0;
    long long ret = strtol(value, &suffix, 0);
    if (errno)
        return 0;

    struct binary_suffix *s;
    for (s = binary_suffixes; s->shift != 0; s++) {
        if (tolower(suffix[0]) == tolower(s->suffix[0])) {
            ret <<= s->shift;
            return ret;
        }
    }

    if (suffix[0] != '\0')
                errno = EINVAL;

    return ret;
}
