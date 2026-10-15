// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>

#if defined(__linux__)
#include <stddef.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#ifdef TCGETS2
#include <asm/termbits.h>	/* struct termios2 */
#else
#include <termios.h>		/* struct termios, e.g. of TCGETS on powerpc */
#endif
#include <sys/prctl.h>
#include <sys/syscall.h>
#elif defined(__FreeBSD__)
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <termios.h>
#endif

#include <ccan/array_size/array_size.h>

#include "io-util.h"
#include "sandbox-util.h"

/* Exit status of a child which found no sandbox to enter. */
#define SANDBOX_UNAVAILABLE	125

/* Sent by the child once it runs sandboxed, before it runs @fn. */
#define SANDBOX_MARKER		'S'

/* The result pipe in the child. */
#define SANDBOX_FD		3

static bool sandbox_enabled;

/* Set in the child: a parser calling another one is sandboxed already. */
static bool in_sandbox;

void shr_sandbox_enable(bool enable)
{
	sandbox_enabled = enable;
}

/* The child keeps stdio and the result pipe only. */
static int keep_fds(int fd)
{
	long max;

	if (fd != SANDBOX_FD && dup2(fd, SANDBOX_FD) < 0)
		return -errno;
#ifdef NVME_HAVE_CLOSE_RANGE
	if (!close_range(SANDBOX_FD + 1, ~0U, 0))
		return 0;
#endif
	max = sysconf(_SC_OPEN_MAX);
	if (max < 0)
		max = 65536;
	for (fd = SANDBOX_FD + 1; fd < max; fd++)
		close(fd);

	return 0;
}

#if defined(__linux__)

#if defined(__x86_64__)
#define SANDBOX_AUDIT_ARCH	AUDIT_ARCH_X86_64
#elif defined(__i386__)
#define SANDBOX_AUDIT_ARCH	AUDIT_ARCH_I386
#elif defined(__aarch64__)
#define SANDBOX_AUDIT_ARCH	AUDIT_ARCH_AARCH64
#elif defined(__arm__)
#define SANDBOX_AUDIT_ARCH	AUDIT_ARCH_ARM
#elif defined(__powerpc64__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define SANDBOX_AUDIT_ARCH	AUDIT_ARCH_PPC64LE
#elif defined(__powerpc64__)
#define SANDBOX_AUDIT_ARCH	AUDIT_ARCH_PPC64
#elif defined(__s390x__)
#define SANDBOX_AUDIT_ARCH	AUDIT_ARCH_S390X
#elif defined(__riscv) && __riscv_xlen == 64
#define SANDBOX_AUDIT_ARCH	AUDIT_ARCH_RISCV64
#elif defined(__loongarch64)
#define SANDBOX_AUDIT_ARCH	AUDIT_ARCH_LOONGARCH64
#endif

#ifdef SANDBOX_AUDIT_ARCH
struct filter {
	struct sock_filter insn[64];
	unsigned int len;
};

static void emit(struct filter *f, struct sock_filter insn)
{
	if (f->len < ARRAY_SIZE(f->insn))
		f->insn[f->len] = insn;
	f->len++;
}

static void ret(struct filter *f, __u32 action)
{
	emit(f, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, action));
}

/* Loads the 32 bit word at @off of struct seccomp_data. */
static void load(struct filter *f, __u32 off)
{
	emit(f, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, off));
}

static void jump_eq(struct filter *f, __u32 k, __u8 jt, __u8 jf)
{
	emit(f, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, k,
					     jt, jf));
}

/* Allows the system call, or the argument, in the accumulator. */
static void allow(struct filter *f, __u32 k)
{
	jump_eq(f, k, 0, 1);
	ret(f, SECCOMP_RET_ALLOW);
}

/* The kernel takes ioctl requests and pids as 32 bit, the low word. */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ARG_LOW(n)	(offsetof(struct seccomp_data, args[n]) + 4)
#else
#define ARG_LOW(n)	offsetof(struct seccomp_data, args[n])
#endif
#endif /* SANDBOX_AUDIT_ARCH */

/*
 * Memory management, writes, the terminal queries of stdio and word
 * wrapping, random numbers (hash tables seed themselves), exit, and what
 * abort() and the runtime of sanitizers need. Signals go to the child
 * itself only. Other system calls fail with EPERM, so that libc falls
 * back gracefully, e.g. gettext() when it cannot open a message catalog.
 *
 * Return: 0, -EOPNOTSUPP without seccomp support, or another negative
 * error code.
 */
static int sandbox_enter(void)
{
#ifdef SANDBOX_AUDIT_ARCH
	struct filter f = { .len = 0 };
	struct sock_fprog prog;

	load(&f, offsetof(struct seccomp_data, arch));
	jump_eq(&f, SANDBOX_AUDIT_ARCH, 1, 0);
	ret(&f, SECCOMP_RET_KILL_PROCESS);
	load(&f, offsetof(struct seccomp_data, nr));
#ifdef __X32_SYSCALL_BIT
	emit(&f, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
					      __X32_SYSCALL_BIT, 0, 1));
	ret(&f, SECCOMP_RET_KILL_PROCESS);
#endif

	allow(&f, __NR_write);
	allow(&f, __NR_writev);
	allow(&f, __NR_brk);
#ifdef __NR_mmap
	allow(&f, __NR_mmap);
#endif
#ifdef __NR_mmap2
	allow(&f, __NR_mmap2);
#endif
	allow(&f, __NR_munmap);
	allow(&f, __NR_mremap);
	allow(&f, __NR_madvise);
#ifdef __NR_fstat
	allow(&f, __NR_fstat);
#endif
#ifdef __NR_newfstatat
	allow(&f, __NR_newfstatat);
#endif
#ifdef __NR_fstatat64
	allow(&f, __NR_fstatat64);
#endif
#ifdef __NR_getrandom
	allow(&f, __NR_getrandom);
#endif
	allow(&f, __NR_sigaltstack);
#ifdef __NR_futex
	allow(&f, __NR_futex);
#endif
#ifdef __NR_futex_time64
	allow(&f, __NR_futex_time64);
#endif
	allow(&f, __NR_sched_yield);
	allow(&f, __NR_rt_sigprocmask);
	allow(&f, __NR_rt_sigreturn);
	allow(&f, __NR_getpid);
	allow(&f, __NR_gettid);
	allow(&f, __NR_exit);
	allow(&f, __NR_exit_group);

	/* tgkill() of the child itself, for abort(); skips 4 if not. */
	jump_eq(&f, __NR_tgkill, 0, 4);
	load(&f, ARG_LOW(0));
	allow(&f, getpid());
	ret(&f, SECCOMP_RET_ERRNO | EPERM);

	/* ioctl() for the terminal queries only. */
	jump_eq(&f, __NR_ioctl, 1, 0);
	ret(&f, SECCOMP_RET_ERRNO | EPERM);
	load(&f, ARG_LOW(1));
	allow(&f, TCGETS);
#ifdef TCGETS2
	allow(&f, TCGETS2);	/* isatty() of glibc 2.42 and later */
#endif
	allow(&f, TIOCGWINSZ);
	ret(&f, SECCOMP_RET_ERRNO | ENOTTY);

	if (f.len > ARRAY_SIZE(f.insn))
		return -E2BIG;

	prog.len = f.len;
	prog.filter = f.insn;
	/* Without seccomp filter support, PR_SET_SECCOMP fails with EINVAL. */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0))
		return errno == EINVAL ? -EOPNOTSUPP : -errno;

	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

#elif defined(__FreeBSD__)

/* Limits a descriptor to writes and the terminal queries. */
static int limit_fd(int fd)
{
	static const unsigned long cmds[] = { TIOCGETA, TIOCGWINSZ };
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_WRITE, CAP_FSTAT, CAP_IOCTL);
	if (cap_rights_limit(fd, &rights) && errno != EBADF)
		return -errno;
	if (cap_ioctls_limit(fd, cmds, ARRAY_SIZE(cmds)) && errno != EBADF)
		return -errno;

	return 0;
}

static int sandbox_enter(void)
{
	int fd, err;

	if (!feature_present("security_capability_mode"))
		return -EOPNOTSUPP;

	for (fd = 0; fd <= SANDBOX_FD; fd++) {
		err = limit_fd(fd);
		if (err)
			return err;
	}
	if (cap_enter())
		return -errno;

	return 0;
}

#else

static int sandbox_enter(void)
{
	return -EOPNOTSUPP;
}

#endif

/* valgrind runs in the child too, where the sandbox stops it. */
static bool under_valgrind(void)
{
	const char *preload = getenv("LD_PRELOAD");

	return preload && strstr(preload, "vgpreload");
}

static void __attribute__((noreturn))
sandbox_child(int fd, int (*fn)(void *arg), void *arg,
	      const struct shr_sandbox_region *regions, unsigned int nr)
{
	char marker = SANDBOX_MARKER;
	unsigned int i;
	int32_t r;
	int err;

	err = keep_fds(fd);
	if (!err)
		err = sandbox_enter();
	if (err)
		_exit(err == -EOPNOTSUPP ? SANDBOX_UNAVAILABLE : 1);
	in_sandbox = true;
	if (shr_write_all(SANDBOX_FD, &marker, 1))
		_exit(1);

	r = fn(arg);

	/* The buffers hold output of @fn only, the caller flushed its own. */
	fflush(stdout);
	fflush(stderr);

	if (shr_write_all(SANDBOX_FD, &r, sizeof(r)))
		_exit(1);
	for (i = 0; i < nr; i++)
		if (shr_write_all(SANDBOX_FD, regions[i].addr, regions[i].size))
			_exit(1);

	/* _exit() skips the atexit handlers of the caller. */
	_exit(0);
}

/*
 * Return: 0 with the return value of @fn and the regions in @buf,
 * -EOPNOTSUPP if the child found no sandbox, or another negative error
 * code.
 */
static int sandbox_fork(int (*fn)(void *arg), void *arg,
			const struct shr_sandbox_region *regions,
			unsigned int nr, char *buf, size_t size)
{
	int fds[2], status, err = -EPROTO;
	char marker;
	ssize_t n;
	pid_t pid;

	/* The child would write out the buffered output a second time. */
	fflush(stdout);
	fflush(stderr);

	if (pipe(fds))
		return -errno;

	pid = fork();
	if (pid < 0) {
		err = -errno;
		close(fds[0]);
		close(fds[1]);
		return err;
	}
	if (!pid) {
		close(fds[0]);
		sandbox_child(fds[1], fn, arg, regions, nr);
	}
	close(fds[1]);

	n = shr_read_full(fds[0], &marker, 1);
	if (n == 1 && marker == SANDBOX_MARKER &&
	    shr_read_full(fds[0], buf, size) == (ssize_t)size &&
	    shr_read_full(fds[0], &marker, 1) == 0)
		err = 0;
	close(fds[0]);

	while (waitpid(pid, &status, 0) < 0)
		if (errno != EINTR)
			return -ECHILD;

	/* Only a child which did not enter the sandbox may report that. */
	if (n == 0)
		return WIFEXITED(status) &&
			WEXITSTATUS(status) == SANDBOX_UNAVAILABLE ?
			-EOPNOTSUPP : -ECHILD;
	/* A malformed result, whatever became of the child afterwards. */
	if (err)
		return err;
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		return -ECHILD;

	return 0;
}

int shr_sandbox_run(int (*fn)(void *arg), void *arg,
		const struct shr_sandbox_region *regions, unsigned int nr)
{
	size_t size = sizeof(int32_t);
	unsigned int i;
	int32_t r;
	char *buf, *p;
	int err;

	if (!sandbox_enabled || in_sandbox || under_valgrind())
		return fn(arg);

	for (i = 0; i < nr; i++)
		size += regions[i].size;
	buf = malloc(size);
	if (!buf)
		return -ENOMEM;

	err = sandbox_fork(fn, arg, regions, nr, buf, size);
	if (err) {
		free(buf);
		return err == -EOPNOTSUPP ? fn(arg) : err;
	}

	memcpy(&r, buf, sizeof(r));
	p = buf + sizeof(r);
	/* Only what changed: the caller may pass read-only memory. */
	for (i = 0; i < nr; i++) {
		if (memcmp(regions[i].addr, p, regions[i].size))
			memcpy(regions[i].addr, p, regions[i].size);
		p += regions[i].size;
	}
	free(buf);

	return r;
}
