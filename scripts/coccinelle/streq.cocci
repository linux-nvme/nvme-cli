// SPDX-License-Identifier: GPL-2.0-or-later
//
// Use streq() to test two strings for equality. strcmp() stays where
// the order of the strings matters.

@@
expression a, b;
@@
(
- strcmp(a, b) == 0
+ streq(a, b)
|
- strcmp(a, b) != 0
+ !streq(a, b)
)
