// SPDX-License-Identifier: GPL-2.0-or-later
//
// Use shr_streq0() for a string comparison that guards a possibly NULL
// string. Only a constant second operand is matched: shr_streq0() treats
// two NULLs as equal, the open-coded forms do not.

@@
expression x;
constant c;
@@
(
- (!x || strcmp(x, c))
+ !shr_streq0(x, c)
|
- (!x || strcmp(x, c) != 0)
+ !shr_streq0(x, c)
|
- !x || strcmp(x, c)
+ !shr_streq0(x, c)
|
- !x || strcmp(x, c) != 0
+ !shr_streq0(x, c)
|
- (x && !strcmp(x, c))
+ shr_streq0(x, c)
|
- (x && strcmp(x, c) == 0)
+ shr_streq0(x, c)
|
- x && !strcmp(x, c)
+ shr_streq0(x, c)
|
- x && strcmp(x, c) == 0
+ shr_streq0(x, c)
)
