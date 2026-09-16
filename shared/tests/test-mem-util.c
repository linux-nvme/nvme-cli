// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */

#include <stdbool.h>
#include <stdio.h>

#include <shared/mem-util.h>

static bool check_bool(const char *name, bool got)
{
	printf(" - %s [%s]\n", name, got ? "PASS" : "FAIL");
	return got;
}

static bool test_buf_has_room(void)
{
	/*
	 * storage is wider than the logical buffer so that a pointer past
	 * "end" below still lands inside storage -- forming a pointer past
	 * the end of the actual backing array would be undefined behavior.
	 */
	unsigned char storage[32] = { 0 };
	unsigned char *buf = storage;
	const void *end = buf + 16;
	bool pass = true;

	printf("test_buf_has_room:\n");

	pass &= check_bool("a chunk that fits at the start fits",
			    shr_buf_has_room(buf, end, 16));
	pass &= check_bool("a chunk one byte too big does not fit",
			    !shr_buf_has_room(buf, end, 17));
	pass &= check_bool("a zero-size chunk always fits",
			    shr_buf_has_room(buf, end, 0));
	pass &= check_bool("a zero-size chunk fits even exactly at end",
			    shr_buf_has_room(end, end, 0));
	pass &= check_bool("a nonzero-size chunk does not fit exactly at end",
			    !shr_buf_has_room(end, end, 1));
	pass &= check_bool("a chunk that fits partway through fits",
			    shr_buf_has_room(buf + 10, end, 6));
	pass &= check_bool("a chunk that overruns partway through does not fit",
			    !shr_buf_has_room(buf + 10, end, 7));
	pass &= check_bool("a pointer already past end never fits",
			    !shr_buf_has_room(buf + 17, end, 0));

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_buf_has_room();

	fflush(stdout);
	return pass ? 0 : 1;
}
