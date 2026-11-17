// SPDX-License-Identifier: GPL-2.0-or-later
//
// Use shr_snprintf_append() to append to a string buffer. After an
// snprintf() that cuts its output, the offset is past the end of the
// buffer and the size of the next call wraps around. Report only: the
// offset must become a size_t.

@@
expression n, b, s, p;
@@
(
* n += snprintf(b + n, s - n, ...)
|
* n += vsnprintf(b + n, s - n, ...)
|
* p += snprintf(p, s - (p - b), ...)
|
* p += vsnprintf(p, s - (p - b), ...)
)
