// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 *
 * Linux/macOS implementation of the crash handler. Uses backtrace() and
 * backtrace_symbols_fd() from <execinfo.h>, both async-signal-safe, so the
 * whole handler performs only write()-based I/O (see signal-safety(7)).
 */
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <execinfo.h>

#include "crash-util.h"

#define SHR_CRASH_BT_DEPTH 64

static void *shr_crash_bt[SHR_CRASH_BT_DEPTH];

struct shr_crash_sig {
	int sig;
	const char *name;
};

static const struct shr_crash_sig shr_crash_signals[] = {
	{ SIGSEGV, "SIGSEGV" },
	{ SIGABRT, "SIGABRT" },
	{ SIGFPE,  "SIGFPE"  },
	{ SIGILL,  "SIGILL"  },
#ifdef SIGBUS
	{ SIGBUS,  "SIGBUS"  },
#endif
};

/*
 * strlen() is not async-signal-safe, so measure the length inline and emit
 * the bytes with a single write(). Assigning to a discarded variable also
 * keeps warn_unused_result (enabled by _FORTIFY_SOURCE) quiet.
 */
static void crash_write_str(int fd, const char *s)
{
	size_t len = 0;
	ssize_t ret;

	if (!s)
		return;

	while (s[len])
		len++;

	ret = write(fd, s, len);
	(void)ret;
}

/* Decimal conversion without snprintf(): stdio locks FILE internals. */
static void crash_write_uint(int fd, unsigned int n)
{
	char buf[10];	/* enough for any 32-bit unsigned int */
	int i = sizeof(buf);
	ssize_t ret;

	do {
		buf[--i] = '0' + (n % 10);
		n /= 10;
	} while (n && i);

	ret = write(fd, buf + i, sizeof(buf) - i);
	(void)ret;
}

static const char *crash_sig_name(int sig)
{
	size_t i;

	for (i = 0; i < sizeof(shr_crash_signals) / sizeof(shr_crash_signals[0]); i++)
		if (shr_crash_signals[i].sig == sig)
			return shr_crash_signals[i].name;

	return "SIG?";
}

void shr_print_backtrace(int fd)
{
	int n = backtrace(shr_crash_bt, SHR_CRASH_BT_DEPTH);

	crash_write_str(fd, "backtrace:\n");
	backtrace_symbols_fd(shr_crash_bt, n, fd);
	crash_write_str(fd, "\n");
}

/*
 * Warm up backtrace(): the first call in a process may trigger lazy-loading
 * of libgcc_s.so via an internal malloc(), which is unsafe inside a signal
 * handler. Calling it once here, during normal startup, ensures the library
 * is already mapped before any crash handler runs.
 */
void shr_warmup_backtrace(void)
{
	/*
	 * Call backtrace() with a small stack buffer. We discard the result -
	 * all we need is to trigger the lazy-load. backtrace() is async-
	 * signal-safe, so this is always safe to call.
	 */
	void *dummy[1];

	backtrace(dummy, 1);
}

static void shr_crash_handler(int sig)
{
	int fd = STDERR_FILENO;

	/*
	 * The reporting below writes to stderr, which may be a pipe whose read
	 * end has already gone away (e.g. 'nvme ... 2>&1 | head'). Doing a
	 * write() to such a pipe raises SIGPIPE, whose default action is to
	 * terminate -- which would mask the very crash we are reporting. Ignore
	 * SIGPIPE for the duration of the handler so write() instead returns
	 * EPIPE harmlessly (signal() is async-signal-safe).
	 */
	signal(SIGPIPE, SIG_IGN);

	crash_write_str(fd, "fatal: signal ");
	crash_write_str(fd, crash_sig_name(sig));
	crash_write_str(fd, " (pid ");
	crash_write_uint(fd, getpid());
	crash_write_str(fd, ")\n");

	shr_print_backtrace(fd);

	/*
	 * SA_RESETHAND restored the default disposition before calling us, so
	 * this kills the process with the default action for the signal rather
	 * than returning into (possibly corrupted) user code. Sanity-check the
	 * return in case a platform refuses to deliver the signal again.
	 */
	if (raise(sig) != 0)
		_exit(EXIT_FAILURE);
}

int shr_install_crash_handler(void)
{
	struct sigaction act = { 0 }, old_act = { 0 };
	size_t i;
	int ret = 0;

	/*
	 * Warm up backtrace() before installing signal handlers. The first call
	 * may trigger lazy-loading of libgcc_s.so via an internal malloc(),
	 * which is unsafe inside a signal handler. See shr_warmup_backtrace()
	 * and backtrace(3) notes.
	 */
	shr_warmup_backtrace();

	sigemptyset(&act.sa_mask);
	act.sa_handler = shr_crash_handler;
	/*
	 * SA_RESETHAND: reset to the default disposition before entering the
	 * handler so the re-raise() above takes the default action, and a fault
	 * inside the handler cannot recurse forever.
	 * SA_NODEFER: do not block the signal while the handler runs.
	 */
	act.sa_flags = SA_RESETHAND | SA_NODEFER;

	/*
	 * Decide per signal, independently, whether to install. This respects
	 * applications that embed libnvme and bring their own crash reporting
	 * for a specific signal (e.g. Sentry, systemd-coredump, SA_SIGINFO
	 * handlers with richer context) without giving up backtraces for every
	 * other signal in the set just because one of them is already claimed.
	 */
	for (i = 0; i < sizeof(shr_crash_signals) / sizeof(shr_crash_signals[0]); i++) {
		if (sigaction(shr_crash_signals[i].sig, NULL, &old_act) == -1) {
			ret = ret ? ret : -errno;
			continue;
		}
		if (old_act.sa_handler != SIG_DFL)
			continue;

		if (sigaction(shr_crash_signals[i].sig, &act, NULL) == -1)
			ret = ret ? ret : -errno;
	}

	return ret;
}