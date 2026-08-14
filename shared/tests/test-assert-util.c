// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/assert-util.h>
#include <shared/proc-util.h>

#if defined(_WIN32)
#include <io.h>
#define read _read
#define close _close
#else
#include <unistd.h>
#endif

/*
 * Re-invoked with this argument, the test becomes the child whose failing
 * assertion is under test. Windows has no fork(), so the child is a fresh
 * process running this same binary rather than a copy of it.
 */
#define CHILD_ARG "--assert-child"

static bool check_bool(const char *name, bool got, bool want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %d, want %d [FAIL]\n", name, got, want);
	return false;
}

/*
 * shr_assert() must be a no-op when the condition holds: no output, no
 * termination.
 */
static bool test_pass_is_silent(void)
{
	printf("test_pass_is_silent:\n");

	shr_assert(1 == 1);

	return check_bool("condition true", true, true);
}

/*
 * The child half of test_fail_flushes_and_reports(): print unterminated
 * (buffered) output, then fail a shr_assert(). Never returns.
 */
static void assert_child(void)
{
	/* Unterminated: only survives if something flushes it. */
	printf("marker-before-failure");
	shr_assert(1 == 2);
	_Exit(EXIT_SUCCESS); /* unreachable */
}

/*
 * Run a child that prints unterminated (buffered) output, then fails a
 * shr_assert(). Capture everything the child writes to stdout/stderr and
 * how it exits, to verify:
 *  - the buffered output written before the failure was not lost, i.e.
 *    fflush(NULL) actually flushes stdio buffers before exiting - the
 *    exact case plain assert()/abort() gets wrong.
 *  - the diagnostic names this file and the failing condition text.
 *  - the process exits normally instead of being killed by a signal
 *    (contrasts with assert()'s SIGABRT via abort()).
 */
static bool test_fail_flushes_and_reports(const char *self)
{
	const char *const argv[] = { self, CHILD_ARG, NULL };
	char buf[4096] = { 0 };
	char scratch[4096];
	size_t total = 0;
	bool pass = true;
	bool exited = false;
	int code = 0;
	int fds[2];
	ssize_t n;
	shr_proc_t proc;

	printf("test_fail_flushes_and_reports:\n");

	if (shr_pipe(fds)) {
		printf(" - shr_pipe() failed [FAIL]\n");
		return false;
	}

	if (shr_spawn(argv, fds[1], fds[1], &proc)) {
		close(fds[0]);
		close(fds[1]);
		printf(" - shr_spawn() failed [FAIL]\n");
		return false;
	}
	close(fds[1]); /* only the child holds a writer now */

	/*
	 * Drain the pipe to EOF before waiting. Keep the first sizeof(buf)-1
	 * bytes and discard any overflow, but keep reading either way: stopping
	 * early would leave the child's next write() to a full pipe unread, and
	 * closing fds[0] would then SIGPIPE it (reported as signaled, not
	 * exited). Reading to EOF also avoids a deadlock on a full buffer.
	 */
	while ((n = read(fds[0], scratch, sizeof(scratch))) > 0) {
		size_t room = sizeof(buf) - 1 - total;
		size_t take = ((size_t)n < room) ? (size_t)n : room;

		memcpy(buf + total, scratch, take);
		total += take;
	}
	close(fds[0]);
	buf[total] = '\0';

	if (shr_wait_proc(proc, &exited, &code)) {
		printf(" - shr_wait_proc() failed [FAIL]\n");
		return false;
	}

	pass &= check_bool("child exited (not signaled)", exited, true);
	pass &= check_bool("child exit status nonzero", code != 0, true);

	pass &= check_bool("buffered output before failure survived",
			   strstr(buf, "marker-before-failure") != NULL, true);
	pass &= check_bool("diagnostic names this file",
			   strstr(buf, "test-assert-util.c") != NULL, true);
	pass &= check_bool("diagnostic names failing condition",
			   strstr(buf, "1 == 2") != NULL, true);

	if (!pass)
		printf(" - captured output:\n%s\n", buf);

	return pass;
}

int main(int argc, char *argv[])
{
	bool pass = true;

	if (argc > 1 && !strcmp(argv[1], CHILD_ARG))
		assert_child();

	pass &= test_pass_is_silent();
	pass &= test_fail_flushes_and_reports(argv[0]);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
