// SPDX-License-Identifier: GPL-2.0-or-later
#include <string.h>

struct s {
	char *name;
};

char *f(struct s *p, const char *a, const char *b)
{
	p->name = shr_xstrdup(a);
	p->name = shr_xstrdup(a);
	/* Not changed: another operand, another fallback */
	p->name = a ? strdup(b) : NULL;
	p->name = a ? strdup(a) : "";

	return shr_xstrdup(b);
}
