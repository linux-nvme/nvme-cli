// SPDX-License-Identifier: GPL-2.0-or-later
//
// Use shr_startswith() to test whether a string starts with a prefix:
// strncmp() with the length of the prefix, and ccan's strstarts().
// strncmp() used for ordering is not changed.

@initialize:python@
@@
import re

# True if n is the length of x: strlen(x), or for a string literal its
# length as a number or sizeof(x) - 1.
def prefix_len(x, n):
	x = re.sub(r'\s+', '', x)
	n = re.sub(r'\s+', '', n)
	if n == 'strlen(%s)' % x:
		return True
	if not re.fullmatch(r'"([^"\\]|\\.)*"', x):
		return False
	l = len(x[1:-1].encode('latin1').decode('unicode_escape'))
	return n in (str(l), 'sizeof(%s)-1' % x)

@e@
expression s, x, n;
position p;
@@
strncmp@p(s, x, n)

@script:python@
x << e.x;
n << e.n;
@@
if not prefix_len(x, n):
	cocci.include_match(False)

@@
expression e.s, e.x, e.n, a;
position e.p;
@@
(
- !strncmp@p(s, x, n)
+ shr_startswith(s, x)
|
- strncmp@p(s, x, n) == 0
+ shr_startswith(s, x)
|
- strncmp@p(s, x, n) != 0
+ !shr_startswith(s, x)
|
- strncmp@p(s, x, n)
+ !shr_startswith(s, x)
  && a
|
a &&
- strncmp@p(s, x, n)
+ !shr_startswith(s, x)
|
- strncmp@p(s, x, n)
+ !shr_startswith(s, x)
  || a
|
a ||
- strncmp@p(s, x, n)
+ !shr_startswith(s, x)
)

@c@
expression s, x, n;
position p;
@@
strncmp@p(s, x, n)

@script:python@
x << c.x;
n << c.n;
@@
if not prefix_len(x, n):
	cocci.include_match(False)

@@
expression c.s, c.x, c.n;
position c.p;
statement S;
@@
(
if (
- strncmp@p(s, x, n)
+ !shr_startswith(s, x)
 ) S
|
while (
- strncmp@p(s, x, n)
+ !shr_startswith(s, x)
 ) S
)

@@
expression s, x;
@@
- strstarts(s, x)
+ shr_startswith(s, x)
