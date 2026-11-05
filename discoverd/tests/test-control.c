// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <systemd/sd-event.h>

#include <shared/fs-util.h>
#include <shared/string-util.h>

#include "control.h"

static const char *dir;
static sd_event *event;
static bool failed;

/* What the callbacks saw. */
static char seen[1024];
static bool busy;
static int defer_runs;

static void check(const char *name, bool ok)
{
	printf(" - %s [%s]\n", name, ok ? "PASS" : "FAIL");
	if (!ok)
		failed = true;
}

static void check_str(const char *name, const char *got, const char *want)
{
	bool ok = shr_streq0(got, want);

	if (ok)
		printf(" - %s [PASS]\n", name);
	else
		printf(" - %s: got '%s', want '%s' [FAIL]\n", name,
		       got ? got : "(null)", want ? want : "(null)");
	if (!ok)
		failed = true;
}

static void on_uevent(const struct uevent *ev,
		      void *user_data __attribute__((unused)))
{
	const char *aen = ev->property(ev, "NVME_AEN");
	size_t len = strlen(seen);

	snprintf(seen + len, sizeof(seen) - len, "%s %s %s aen=%s;",
		 ev->subsystem, ev->action,
		 ev->devname ? ev->devname : "(none)", aen ? aen : "-");
}

static bool on_busy(void *user_data __attribute__((unused)))
{
	return busy;
}

static void on_dump(FILE *f, void *user_data __attribute__((unused)))
{
	fprintf(f, "{\"defer_runs\":%d}", defer_runs);
}

static int count_defer(sd_event_source *src,
		       void *user_data __attribute__((unused)))
{
	defer_runs++;
	sd_event_source_disable_unref(src);
	return 0;
}

static int connect_to(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	int n = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	if (n < 0 || (size_t)n >= sizeof(addr.sun_path) || fd < 0 ||
	    connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		perror("connect");
		exit(EXIT_FAILURE);
	}
	fcntl(fd, F_SETFL, O_NONBLOCK);

	return fd;
}

static void send_str(int fd, const char *s)
{
	if (write(fd, s, strlen(s)) != (ssize_t)strlen(s)) {
		perror("write");
		exit(EXIT_FAILURE);
	}
}

/*
 * Run the event loop until @want reply lines arrived, for at most a
 * second, and at least once. Returns the replies, each followed by a
 * newline.
 */
static char *replies(int fd, int want)
{
	static char buf[4096];
	size_t len = 0;
	int lines = 0, i;
	ssize_t n;

	buf[0] = '\0';
	for (i = 0; i < 1000 && (lines < want || !i); i++) {
		sd_event_run(event, 1000);
		n = read(fd, buf + len, sizeof(buf) - 1 - len);
		if (n > 0) {
			for (ssize_t k = 0; k < n; k++)
				lines += buf[len + k] == '\n';
			len += n;
			buf[len] = '\0';
		}
	}

	return buf;
}

/* Run the event loop for a while, without expecting anything. */
static void spin(int iterations)
{
	while (iterations--)
		sd_event_run(event, 1000);
}

static void test_requests(int fd)
{
	printf("requests:\n");

	seen[0] = '\0';
	send_str(fd, "uevent nvme add nvme3\n"
		     "uevent nvme change nvme3 NVME_AEN=0x70f002 X=1\n"
		     "uevent fc change - FC_EVENT=nvmediscovery\n");
	check_str("one ok per uevent", replies(fd, 3), "ok\nok\nok\n");
	check_str("uevents dispatched", seen,
		  "nvme add nvme3 aen=-;nvme change nvme3 aen=0x70f002;"
		  "fc change (none) aen=-;");

	send_str(fd, "dump\n");
	check_str("dump", replies(fd, 1), "{\"defer_runs\":0}\n");

	send_str(fd, "bogus\n");
	check_str("unknown request", replies(fd, 1),
		  "error unknown request\n");
	send_str(fd, "uevent nvme add\n");
	check_str("short uevent", replies(fd, 1),
		  "error uevent needs SUBSYSTEM ACTION DEVNAME\n");
	send_str(fd, "uevent nvme add nvme1 NOEQUALS\n");
	check_str("bad property", replies(fd, 1), "error bad property\n");
}

static void test_sync(int fd)
{
	sd_event_source *src;
	char *r;

	printf("sync:\n");

	// Work the event loop has ready runs before the sync is answered.
	defer_runs = 0;
	sd_event_add_defer(event, &src, count_defer, NULL);
	send_str(fd, "sync\ndump\n");
	r = replies(fd, 2);
	check_str("pending work first", r, "ok\n{\"defer_runs\":1}\n");

	// While busy, neither the sync nor what follows is answered.
	busy = true;
	seen[0] = '\0';
	send_str(fd, "sync\nuevent nvme remove nvme3\n");
	spin(50);
	r = replies(fd, 0);
	check_str("no reply while busy", r, "");
	check_str("held back after the sync", seen, "");

	busy = false;
	r = replies(fd, 2);
	check_str("answered when idle", r, "ok\nok\n");
	check_str("then the next request", seen, "nvme remove nvme3 aen=-;");
}

int main(void)
{
	static const struct control_callbacks callbacks = {
		.uevent = on_uevent,
		.busy = on_busy,
		.dump = on_dump,
	};
	char tmpl[] = "/tmp/discoverd-control-test-XXXXXX";
	char path[PATH_MAX];
	struct control *c;
	int fd, r;

	dir = mkdtemp(tmpl);
	if (!dir) {
		perror("mkdtemp");
		return EXIT_FAILURE;
	}
	snprintf(path, sizeof(path), "%s/control.sock", dir);

	if (sd_event_new(&event) < 0)
		return EXIT_FAILURE;

	r = control_start(event, path, &callbacks, NULL, &c);
	if (r < 0) {
		printf("control_start: %s\n", strerror(-r));
		return EXIT_FAILURE;
	}

	fd = connect_to(path);
	spin(5); // accept

	test_requests(fd);
	test_sync(fd);

	close(fd);
	control_stop(c);
	check("socket removed", access(path, F_OK) < 0);

	sd_event_unref(event);
	shr_rmdir_recursive(dir);

	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
