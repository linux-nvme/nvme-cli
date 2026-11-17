// SPDX-License-Identifier: GPL-2.0-or-later
//
// Use shr_strscpy() to copy a string into a buffer and terminate it.

@@
expression d, s, n;
@@
- strncpy(d, s, n - 1);
+ shr_strscpy(d, s, n);
(
- d[n - 1] = '\0';
|
- d[n - 1] = 0;
)
