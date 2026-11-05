// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <systemd/sd-event.h>

#include <shared/fs-util.h>
#include <shared/string-util.h>

#include "units-local.h"

static const char *dir;
static char log_path[PATH_MAX];

static bool failed;

/* The job results the runner reported, in order. */
static char results[1024];

static void on_job(const char *unit_name, bool success,
		   void *user_data __attribute__((unused)))
{
	size_t len = strlen(results);

	snprintf(results + len, sizeof(results) - len, "%s:%s ",
		 unit_name, success ? "done" : "failed");
}

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

/* The commands of the test units log what runs to log_path. */
static char *logged(void)
{
	char *content = NULL;

	if (shr_read_file_as_string(NULL, log_path, NULL, &content) < 0)
		return strdup("");

	return content;
}

static void clear_log(void)
{
	unlink(log_path);
	results[0] = '\0';
}

/* Run what the event loop has ready: the queued job results. */
static void run_loop(sd_event *event)
{
	while (sd_event_run(event, 0) > 0)
		;
}

static char *cmd(const char *what)
{
	char *c;

	if (asprintf(&c, "echo %s >> %s", what, log_path) < 0)
		exit(EXIT_FAILURE);

	return c;
}

static void test_connection(struct local_units *lu, sd_event *event)
{
	char *start = cmd("start");
	const char *const argv[] = { "/bin/sh", "-c", start, NULL };
	struct unit_spec s = {
		.name = "conn.service",
		.description = "a connection",
		.connection = true,
		.exec_start = argv,
		.exec_start_post = cmd("start-post"),
		.exec_stop = cmd("stop"),
		.exec_stop_post = cmd("stop-post"),
	};
	char *l;

	printf("connection unit:\n");
	clear_log();

	check("start", local_units_start(lu, &s) == 0);
	l = logged();
	check_str("ExecStart, then ExecStartPost", l, "start\nstart-post\n");
	free(l);
	check_str("result not before the event loop", results, "");
	run_loop(event);
	check_str("result from the event loop", results, "conn.service:done ");
	check("loaded", local_units_exists(lu, "conn.service"));
	check("second start", local_units_start(lu, &s) == -EEXIST);

	clear_log();
	check("restart", local_units_restart(lu, "conn.service") == 0);
	l = logged();
	check_str("restart stops, then starts", l,
		  "stop\nstop-post\nstart\nstart-post\n");
	free(l);
	run_loop(event);
	check_str("restart result", results, "conn.service:done ");
	check("still loaded", local_units_exists(lu, "conn.service"));

	clear_log();
	check("stop", local_units_stop(lu, "conn.service") == 0);
	l = logged();
	check_str("ExecStop, then ExecStopPost", l, "stop\nstop-post\n");
	free(l);
	run_loop(event);
	check_str("no result for a stop", results, "");
	check("unloaded", !local_units_exists(lu, "conn.service"));
	check("stop again", local_units_stop(lu, "conn.service") == -ENOENT);
	check("restart unloaded",
	      local_units_restart(lu, "conn.service") == -ENOENT);

	free(start);
	free(s.exec_start_post);
	free(s.exec_stop);
	free(s.exec_stop_post);
}

static void test_failed(struct local_units *lu, sd_event *event)
{
	const char *const argv[] = { "/bin/false", NULL };
	struct unit_spec s = {
		.name = "fail.service",
		.description = "a failing connection",
		.connection = true,
		.exec_start = argv,
		.exec_start_post = cmd("start-post"),
		.exec_stop = cmd("stop"),
		.exec_stop_post = cmd("stop-post"),
	};
	char *l;

	printf("failed start:\n");
	clear_log();

	check("start", local_units_start(lu, &s) == 0);
	l = logged();
	check_str("only ExecStopPost", l, "stop-post\n");
	free(l);
	run_loop(event);
	check_str("failed result", results, "fail.service:failed ");
	check("collected", !local_units_exists(lu, "fail.service"));

	free(s.exec_start_post);
	free(s.exec_stop);
	free(s.exec_stop_post);
}

static void test_oneshot(struct local_units *lu, sd_event *event)
{
	char *start = cmd("connect-all");
	const char *const argv[] = { "/bin/sh", "-c", start, NULL };
	struct unit_spec s = {
		.name = "connect-all.service",
		.description = "connect-all",
		.exec_start = argv,
	};
	char *l;

	printf("unit without RemainAfterExit:\n");
	clear_log();

	check("start", local_units_start(lu, &s) == 0);
	l = logged();
	check_str("ExecStart", l, "connect-all\n");
	free(l);
	run_loop(event);
	check_str("result", results, "connect-all.service:done ");
	check("collected when done",
	      !local_units_exists(lu, "connect-all.service"));

	free(start);
}

static void test_names(struct local_units *lu)
{
	const char *const argv[] = { "/bin/true", NULL };
	struct unit_spec s = {
		.description = "bad name",
		.exec_start = argv,
	};

	printf("unit names:\n");

	s.name = "../escape.service";
	check("no path in a name", local_units_start(lu, &s) == -EINVAL);
	s.name = "";
	check("no empty name", local_units_start(lu, &s) == -EINVAL);
}

static bool has(const char *haystack, const char *needle)
{
	return strstr(haystack, needle) != NULL;
}

/* The journal lives next to the units, in @units. */
static void test_journal(const char *units)
{
	char *j = NULL;

	printf("journal:\n");

	if (shr_read_file_as_string(units, "journal", NULL, &j) < 0) {
		check("journal written", false);
		return;
	}

	check("start", has(j, "{\"op\":\"start\",\"unit\":\"conn.service\""));
	check("start: description",
	      has(j, "\"description\":\"a connection\""));
	check("start: kind", has(j, "\"connection\":true,\"is_fc\":false"));
	check("start: ExecStart",
	      has(j, "\"exec_start\":[\"/bin/sh\",\"-c\","));
	check("failed result",
	      has(j, "\"fail.service\",\"result\":\"failed\"}\n"));
	check("stop", has(j, "{\"op\":\"stop\",\"unit\":\"conn.service\"}"));
	check("restart",
	      has(j, "{\"op\":\"restart\",\"unit\":\"conn.service\"}"));
	free(j);
}

int main(void)
{
	char tmpl[] = "/tmp/discoverd-units-local-test-XXXXXX";
	struct local_units *lu;
	sd_event *event = NULL;
	char units[PATH_MAX];

	dir = mkdtemp(tmpl);
	if (!dir) {
		perror("mkdtemp");
		return EXIT_FAILURE;
	}
	snprintf(log_path, sizeof(log_path), "%s/log", dir);
	snprintf(units, sizeof(units), "%s/units", dir);

	if (sd_event_new(&event) < 0)
		return EXIT_FAILURE;

	lu = local_units_new(event, units, on_job, NULL);
	if (!lu)
		return EXIT_FAILURE;

	test_connection(lu, event);
	test_failed(lu, event);
	test_oneshot(lu, event);
	test_names(lu);

	test_journal(units);

	local_units_free(lu);
	sd_event_unref(event);
	shr_rmdir_recursive(dir);

	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
