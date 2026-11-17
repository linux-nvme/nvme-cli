// SPDX-License-Identifier: GPL-2.0-or-later
//
// Use shr_xstrdup() to copy a string that may be NULL.

@@
expression x;
@@
(
- (x ? strdup(x) : NULL)
+ shr_xstrdup(x)
|
- x ? strdup(x) : NULL
+ shr_xstrdup(x)
)
