// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 *
 * Tests for shared/crash-util:
 *  - shr_install_crash_handler() succeeds
 *  - shr_print_backtrace() emits a "backtrace:" header
 *  - a child raising SIGSEGV prints the diagnostic + backtrace to stderr and
 *    dies with the default disposition (WIFSIGNALED / WTERMSIG == SIGSEGV),
 *    proving the crash handler preserves kill-status/core semantics.
 */
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <shared/crash-util.h>

static bool check_bool(const char *name, bool got)
{
	printf(" - %s [%s]\n", name, got ? "PASS" : "FAIL");
	return got;
}

static bool test_install(void)
{
	bool pass = true;

	printf("test_install:\n");

	pass &= check_bool("handler installs successfully",
			   shr_install_crash_handler() == 0);

	return pass;
}

static bool test_install_skips_existing_handler(void)
{
	bool pass = true;
	struct sigaction pre = { 0 }, post = { 0 }, post_abrt = { 0 };

	printf("test_install_skips_existing_handler:\n");

	/*
	 * Pretend the application already installed a custom SIGSEGV handler
	 * (e.g. Sentry, systemd-coredump). shr_install_crash_handler() must
	 * detect that and skip SIGSEGV while still installing handlers for the
	 * other signals. Verify by checking SIGSEGV (preserved) and SIGABRT
	 * (installed).
	 */
	pre.sa_handler = (void (*)(int))(uintptr_t)0xdeadbeef;
	pre.sa_flags = SA_RESTART;
	pass &= check_bool("preinstall SIGSEGV handler succeeds",
			   sigaction(SIGSEGV, &pre, NULL) == 0);

	pass &= check_bool("install returns success",
			   shr_install_crash_handler() == 0);

	pass &= check_bool("SIGSEGV handler preserved",
			   sigaction(SIGSEGV, NULL, &post) == 0 &&
			   post.sa_handler == pre.sa_handler);

	/* SIGABRT was not claimed by the app, so ours should be installed. */
	pass &= check_bool("SIGABRT handler installed",
			   sigaction(SIGABRT, NULL, &post_abrt) == 0 &&
			   post_abrt.sa_handler != SIG_DFL);

	/* Restore the default handler so later tests can install ours cleanly. */
	struct sigaction dfl;
	memset(&dfl, 0, sizeof(dfl));
	dfl.sa_handler = SIG_DFL;
	sigaction(SIGSEGV, &dfl, NULL);
	sigaction(SIGABRT, &dfl, NULL);

	return pass;
}

/*
 * Must run before any other test in this binary calls backtrace() for
 * any reason -- the whole point is to prove shr_install_crash_handler()
 * safely warms up backtrace() on a genuinely cold process, where the
 * very first ever call to backtrace() happens inside a signal handler
 * if the warmup is missing or broken. If this ran after
 * test_warmup_backtrace() or test_manual_backtrace(), a forked child
 * would inherit an already-warmed-up process via copy-on-write and this
 * test could pass even with a regression that removes the internal
 * warmup call.
 */
static bool test_crash_sigsegv_cold(void)
{
	bool pass = true;
	int p[2];
	pid_t pid;
	int status = 0;
	char buf[8192];
	ssize_t n;
	size_t len = 0;

	printf("test_crash_sigsegv_cold:\n");

	pass &= check_bool("pipe", pipe(p) == 0);
	if (!pass)
		return pass;

	fflush(NULL);

	pid = fork();
	if (pid == 0) {
		close(p[0]);
		dup2(p[1], STDERR_FILENO);
		close(p[1]);

		/*
		 * shr_install_crash_handler() must itself call
		 * shr_warmup_backtrace() -- this process has never called
		 * backtrace() before this line.
		 */
		if (shr_install_crash_handler())
			_exit(EXIT_FAILURE);
		raise(SIGSEGV);
		_exit(EXIT_FAILURE);
	}

	close(p[1]);

	while (len < sizeof(buf) - 1 &&
	       (n = read(p[0], buf + len, sizeof(buf) - 1 - len)) > 0)
		len += n;
	buf[len] = '\0';
	close(p[0]);

	pass &= check_bool("child killed by SIGSEGV",
			   waitpid(pid, &status, 0) == pid &&
			   WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
	pass &= check_bool("stderr has backtrace on cold process",
			   strstr(buf, "backtrace:") != NULL);

	return pass;
}

static bool test_warmup_backtrace(void)
{
	bool pass = true;

	printf("test_warmup_backtrace:\n");

	/*
	 * The warmup must be safe to call any number of times and must not
	 * change process state in an observable way. We exercise it before
	 * installing the crash handler (the path an external caller would
	 * use) and again after, to make sure it is idempotent.
	 */
	pass &= check_bool("call before install does not crash",
			   (shr_warmup_backtrace(), true));
	pass &= check_bool("install after warmup still works",
			   shr_install_crash_handler() == 0);
	pass &= check_bool("call after install is still safe",
			   (shr_warmup_backtrace(), true));

	return pass;
}

static bool test_manual_backtrace(void)
{
	bool pass = true;
	int p[2];
	char buf[4096];
	ssize_t n;

	printf("test_manual_backtrace:\n");

	pass &= check_bool("pipe", pipe(p) == 0);
	if (!pass)
		return pass;

	shr_print_backtrace(p[1]);
	close(p[1]);

	n = read(p[0], buf, sizeof(buf) - 1);
	close(p[0]);

	pass &= check_bool("read produced output", n > 0);
	if (n <= 0)
		return pass;

	buf[n] = '\0';
	pass &= check_bool("contains backtrace header",
			   strstr(buf, "backtrace:") != NULL);

	return pass;
}

static bool test_crash_sigsegv(void)
{
	bool pass = true;
	int p[2];
	pid_t pid;
	int status = 0;
	char buf[8192];
	ssize_t n;
	size_t len = 0;

	printf("test_crash_sigsegv:\n");

	pass &= check_bool("pipe", pipe(p) == 0);
	if (!pass)
		return pass;

	/* Flush before fork so the child does not duplicate buffered output. */
	fflush(NULL);

	pid = fork();
	if (pid == 0) {
		close(p[0]);
		dup2(p[1], STDERR_FILENO);
		close(p[1]);

		if (shr_install_crash_handler())
			_exit(EXIT_FAILURE);
		raise(SIGSEGV);

		/* The handler re-raises with the default disposition, so we should
		 * never get here unless the handler is broken. */
		_exit(EXIT_FAILURE);
	}

	close(p[1]);

	/* Read until EOF: the child's stderr stays open until it dies, so a
	 * short read is no reason to stop -- and closing the pipe early would
	 * SIGPIPE-kill the child mid-backtrace. */
	while (len < sizeof(buf) - 1 &&
	       (n = read(p[0], buf + len, sizeof(buf) - 1 - len)) > 0)
		len += n;
	buf[len] = '\0';
	close(p[0]);

	pass &= check_bool("child killed by SIGSEGV",
			   waitpid(pid, &status, 0) == pid &&
			   WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
	pass &= check_bool("stderr has fatal diagnostic",
			   strstr(buf, "fatal: signal SIGSEGV") != NULL);
	pass &= check_bool("stderr has backtrace",
			   strstr(buf, "backtrace:") != NULL);

	return pass;
}

int main(void)
{
	bool pass = true;

	/* Must be first: see comment on test_crash_sigsegv_cold(). */
	pass &= test_crash_sigsegv_cold();

	pass &= test_warmup_backtrace();
	pass &= test_install();
	pass &= test_install_skips_existing_handler();
	pass &= test_manual_backtrace();
	pass &= test_crash_sigsegv();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}