// SPDX-License-Identifier: GPL-2.0-or-later
//
// Use asprintf() to build a string, not malloc() and snprintf() with the
// same size. Report only: if the pointer is __cleanup_free, set it to
// NULL when asprintf() fails.

@@
expression p, E, x;
@@
* p = malloc(E);
  ...
(
* snprintf(p, E, ...);
|
* x = snprintf(p, E, ...);
)
