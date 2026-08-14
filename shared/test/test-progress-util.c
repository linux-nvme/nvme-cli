// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/progress-util.h>

static bool check_bool(const char *name, bool got)
{
	printf(" - %s [%s]\n", name, got ? "PASS" : "FAIL");
	return got;
}

static char *capture(void (*fn)(FILE *stream))
{
	static char buf[512];
	FILE *stream = tmpfile();
	size_t n;

	memset(buf, 0, sizeof(buf));
	fn(stream);
	rewind(stream);
	n = fread(buf, 1, sizeof(buf) - 1, stream);
	buf[n] = '\0';
	fclose(stream);

	return buf;
}

static void run_zero(FILE *stream)
{
	shr_spinner("Task", 0.0, stream);
}

static void run_half(FILE *stream)
{
	shr_spinner("Task", 0.5, stream);
}

static void run_full(FILE *stream)
{
	shr_spinner("Task", 1.0, stream);
}

static void run_clamped(FILE *stream)
{
	shr_spinner("Task", 5.0, stream);
}

int main(void)
{
	bool pass = true;
	char *out;

	printf("test_spinner:\n");

	out = capture(run_zero);
	pass &= check_bool("0% output contains the label", strstr(out, "Task") != NULL);
	pass &= check_bool("0% output shows 0%", strstr(out, "0%") != NULL);

	out = capture(run_half);
	pass &= check_bool("50% output shows 50%", strstr(out, "50%") != NULL);

	out = capture(run_full);
	pass &= check_bool("100% output shows 100%", strstr(out, "100%") != NULL);

	out = capture(run_clamped);
	pass &= check_bool("percent > 1.0 is clamped to 100%", strstr(out, "100%") != NULL);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
