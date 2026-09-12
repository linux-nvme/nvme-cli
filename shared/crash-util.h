// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */
#pragma once

/**
 * shr_install_crash_handler() - Install fatal-signal handlers that dump the
 * call stack to stderr
 *
 * Installs handlers for the fatal signals (SIGSEGV, SIGABRT, SIGFPE, SIGILL
 * and, where defined, SIGBUS) that print a short diagnostic plus the current
 * call stack (via backtrace_symbols_fd(), which is async-signal-safe) and then
 * re-raise the signal with its default disposition, so core dumps and the
 * process' kill status are preserved for debuggers and CI.
 *
 * Return: 0 on success, negative errno on failure.
 */
int shr_install_crash_handler(void);

/**
 * shr_warmup_backtrace() - Pre-load libgcc_s.so used by backtrace()
 *
 * The first call to backtrace() in a process may internally call malloc()
 * to lazy-load libgcc_s.so (the unwinding library). That malloc() is not
 * safe inside a signal handler, so this function should be called once
 * during normal startup, before shr_install_crash_handler(), to trigger
 * the lazy-load ahead of time. shr_install_crash_handler() calls this
 * itself, so callers normally do not need to invoke it directly. Only use
 * this if you want to capture backtraces from a signal handler in code
 * that does not go through shr_install_crash_handler().
 */
void shr_warmup_backtrace(void);

/**
 * shr_print_backtrace() - Print the calling thread's call stack to @fd
 * @fd: File descriptor to write to, e.g. STDERR_FILENO.
 *
 * Always prints a "backtrace:" header line, then one line per stack frame as
 * produced by backtrace_symbols_fd(). Safe to call at any time; also used
 * internally by the crash handler.
 */
void shr_print_backtrace(int fd);