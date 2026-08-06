// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wrap-util.h>

static bool check_bool(const char *name, bool got)
{
	printf(" - %s [%s]\n", name, got ? "PASS" : "FAIL");
	return got;
}

static char *capture(const char *s, int indent, int start)
{
	static char buf[1024];
	FILE *stream = tmpfile();
	size_t n;

	shr_print_word_wrapped(s, indent, start, stream);
	rewind(stream);
	n = fread(buf, 1, sizeof(buf) - 1, stream);
	buf[n] = '\0';
	fclose(stream);

	return buf;
}

int main(void)
{
	bool pass = true;
	char *out;

	printf("test_print_word_wrapped:\n");

	out = capture("short text", 0, 0);
	pass &= check_bool("short text fits on one line", strchr(out, '\n') == NULL);
	pass &= check_bool("short text is printed verbatim", !strcmp(out, "short text"));

	out = capture("one two three four five six seven eight nine ten eleven twelve "
		      "thirteen fourteen fifteen sixteen", 4, 4);
	pass &= check_bool("long text wraps onto more than one line", strchr(out, '\n') != NULL);
	pass &= check_bool("wrapped continuation line is indented",
			    strstr(out, "\n    ") != NULL);

	out = capture("line one\nline two", 2, 0);
	pass &= check_bool("embedded newline forces a break",
			    strstr(out, "line one\n  line two") != NULL);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
