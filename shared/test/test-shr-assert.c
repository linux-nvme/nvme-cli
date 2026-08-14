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
#include <sys/wait.h>
#include <unistd.h>

#include <shared/shr-assert.h>

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
static bool test_fail_flushes_and_reports(void)
{
	char buf[4096] = { 0 };
	int pipefd[2];
	ssize_t total = 0, n;
	pid_t pid;
	int status;
	bool pass = true;

	printf("test_fail_flushes_and_reports:\n");

	if (pipe(pipefd)) {
		printf(" - pipe() failed [FAIL]\n");
		return false;
	}

	pid = fork();
	if (pid < 0) {
		printf(" - fork() failed [FAIL]\n");
		return false;
	}

	if (pid == 0) {
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);

		/* Unterminated: only survives if something flushes it. */
		printf("marker-before-failure");
		shr_assert(1 == 2);
		_exit(EXIT_SUCCESS); /* unreachable */
	}

	close(pipefd[1]);
	while (total < (ssize_t)sizeof(buf) - 1 &&
	       (n = read(pipefd[0], buf + total, sizeof(buf) - 1 - total)) > 0)
		total += n;
	close(pipefd[0]);
	buf[total] = '\0';

	waitpid(pid, &status, 0);

	pass &= check_bool("child exited (not signaled)", WIFEXITED(status), true);
	if (WIFEXITED(status))
		pass &= check_bool("child exit status nonzero", WEXITSTATUS(status) != 0, true);

	pass &= check_bool("buffered output before failure survived",
			   strstr(buf, "marker-before-failure") != NULL, true);
	pass &= check_bool("diagnostic names this file",
			   strstr(buf, "test-shr-assert.c") != NULL, true);
	pass &= check_bool("diagnostic names failing condition",
			   strstr(buf, "1 == 2") != NULL, true);

	if (!pass)
		printf(" - captured output:\n%s\n", buf);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_pass_is_silent();
	pass &= test_fail_flushes_and_reports();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
