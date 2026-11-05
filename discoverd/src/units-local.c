// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <daemon-util/log.h>
#include <shared/cleanup-util.h>
#include <shared/fs-util.h>

#include "json-util.h"
#include "units-local.h"

#define SH_PATH "/bin/sh"

/* An argv read back from DIR/<unit>/exec_start has at most this many. */
#define MAX_ARGS 64

struct local_units {
	sd_event *event;
	char *dir;
	unit_job_callback callback;
	void *user_data;
};

/* A job result on its way to the callback. */
struct job_result {
	struct local_units *lu;
	char *unit_name;
	bool success;
};

/* Open the journal for one record. The caller adds fields and closes it. */
static FILE *journal_open(struct local_units *lu, const char *op,
			  const char *unit_name)
{
	char path[PATH_MAX];
	FILE *f;
	int n;

	n = snprintf(path, sizeof(path), "%s/journal", lu->dir);
	if (n < 0 || (size_t)n >= sizeof(path))
		return NULL;

	f = fopen(path, "ae");
	if (!f) {
		log_warn("cannot open %s: %s", path, strerror(errno));
		return NULL;
	}

	fputs("{\"op\":", f);
	json_string(f, op);
	fputs(",\"unit\":", f);
	json_string(f, unit_name);

	return f;
}

static void journal_close(FILE *f)
{
	if (!f)
		return;

	fputs("}\n", f);
	fclose(f);
}

static void journal(struct local_units *lu, const char *op,
		    const char *unit_name)
{
	journal_close(journal_open(lu, op, unit_name));
}

static void journal_start(struct local_units *lu,
			  const struct unit_spec *s)
{
	FILE *f = journal_open(lu, "start", s->name);
	const char *const *a;

	if (!f)
		return;

	fputs(",\"description\":", f);
	json_string(f, s->description);
	fprintf(f, ",\"connection\":%s,\"is_fc\":%s",
		s->connection ? "true" : "false",
		s->is_fc ? "true" : "false");
	fputs(",\"exec_start\":[", f);
	for (a = s->exec_start; *a; a++) {
		if (a != s->exec_start)
			fputc(',', f);
		json_string(f, *a);
	}
	fputs("],\"exec_start_post\":", f);
	json_string(f, s->exec_start_post);
	fputs(",\"exec_stop\":", f);
	json_string(f, s->exec_stop);
	fputs(",\"exec_stop_post\":", f);
	json_string(f, s->exec_stop_post);
	journal_close(f);
}

static void journal_result(struct local_units *lu, const char *unit_name,
			   bool success)
{
	FILE *f = journal_open(lu, "result", unit_name);

	if (!f)
		return;

	fputs(",\"result\":", f);
	json_string(f, success ? "done" : "failed");
	journal_close(f);
}

static int unit_dir(const struct local_units *lu, const char *unit_name,
		    char *buf, size_t len)
{
	int n;

	/* A unit name never names a path: it comes from tid_unit_name(). */
	if (!*unit_name || strchr(unit_name, '/') || unit_name[0] == '.')
		return -EINVAL;

	n = snprintf(buf, len, "%s/%s", lu->dir, unit_name);

	return n < 0 || (size_t)n >= len ? -ENAMETOOLONG : 0;
}

static int write_file(const char *dir, const char *name, const char *content)
{
	char path[PATH_MAX];
	FILE *f;
	int n, r = 0;

	n = snprintf(path, sizeof(path), "%s/%s", dir, name);
	if (n < 0 || (size_t)n >= sizeof(path))
		return -ENAMETOOLONG;

	f = fopen(path, "we");
	if (!f)
		return -errno;
	if (fputs(content, f) < 0)
		r = -EIO;
	if (fclose(f) && !r)
		r = -errno;

	return r;
}

/* The content of DIR/<unit>/@name, or NULL if there is none. */
static char *read_file(const char *dir, const char *name)
{
	char *content = NULL;

	if (shr_read_file_as_string(dir, name, NULL, &content) < 0)
		return NULL;

	return content;
}

static bool has_file(const char *dir, const char *name)
{
	char path[PATH_MAX];
	int n = snprintf(path, sizeof(path), "%s/%s", dir, name);

	return n >= 0 && (size_t)n < sizeof(path) && !access(path, F_OK);
}

/* Run @argv and wait for it. Returns true if it exited with 0. */
static bool run(const char *const *argv)
{
	sigset_t none;
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0) {
		log_err("fork: %s", strerror(errno));
		return false;
	}

	if (pid == 0) {
		// The daemon blocks the signals it handles in its event loop.
		sigemptyset(&none);
		sigprocmask(SIG_SETMASK, &none, NULL);
		execv(argv[0], (char *const *)argv);
		_exit(127);
	}

	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR) {
			log_err("waitpid: %s", strerror(errno));
			return false;
		}
	}

	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* Run shell commands @cmd, if any. Their result is ignored, as with '-'. */
static void run_shell(const char *cmd)
{
	const char *const argv[] = { SH_PATH, "-c", cmd, NULL };

	if (cmd)
		run(argv);
}

static int report_result(sd_event_source *src, void *user_data)
{
	struct job_result *j = user_data;

	if (j->lu->callback)
		j->lu->callback(j->unit_name, j->success, j->lu->user_data);

	free(j->unit_name);
	free(j);
	sd_event_source_disable_unref(src);

	return 0;
}

/* Report the job result from the event loop, as JobRemoved arrives. */
static int queue_result(struct local_units *lu, const char *unit_name,
			bool success)
{
	struct job_result *j;
	int r;

	j = calloc(1, sizeof(*j));
	if (!j)
		return -ENOMEM;

	j->lu = lu;
	j->success = success;
	j->unit_name = strdup(unit_name);
	if (!j->unit_name) {
		free(j);
		return -ENOMEM;
	}

	r = sd_event_add_defer(lu->event, NULL, report_result, j);
	if (r < 0) {
		free(j->unit_name);
		free(j);
	}

	return r;
}

/*
 * Run a unit's start: ExecStart=, then ExecStartPost=. A unit that failed,
 * or one without RemainAfterExit= (connect-all), is collected.
 */
static int run_start(struct local_units *lu, const char *dir,
		     const char *unit_name, const char *const *argv,
		     bool remain)
{
	__cleanup_free char *start_post = read_file(dir, "exec_start_post");
	__cleanup_free char *stop_post = NULL;
	bool success = run(argv);

	if (success)
		run_shell(start_post);

	if (!success || !remain) {
		stop_post = read_file(dir, "exec_stop_post");
		run_shell(stop_post);
		shr_rmdir_recursive(dir);
	}

	journal_result(lu, unit_name, success);

	return queue_result(lu, unit_name, success);
}

/* Run a unit's stop: ExecStop=, then ExecStopPost=. */
static void run_stop(const char *dir)
{
	__cleanup_free char *stop = read_file(dir, "exec_stop");
	__cleanup_free char *stop_post = read_file(dir, "exec_stop_post");

	run_shell(stop);
	run_shell(stop_post);
}

struct local_units *local_units_new(sd_event *event, const char *dir,
				    unit_job_callback callback,
				    void *user_data)
{
	struct local_units *lu;
	int r;

	r = shr_mkdir_p(dir, 0755);
	if (r < 0) {
		log_err("cannot create %s: %s", dir, strerror(-r));
		return NULL;
	}

	lu = calloc(1, sizeof(*lu));
	if (!lu)
		return NULL;

	lu->event = event;
	lu->callback = callback;
	lu->user_data = user_data;
	lu->dir = strdup(dir);
	if (!lu->dir) {
		free(lu);
		return NULL;
	}

	return lu;
}

void local_units_free(struct local_units *lu)
{
	if (!lu)
		return;

	free(lu->dir);
	free(lu);
}

bool local_units_exists(struct local_units *lu, const char *unit_name)
{
	char dir[PATH_MAX];

	if (unit_dir(lu, unit_name, dir, sizeof(dir)) < 0)
		return false;

	return shr_isdir(dir);
}

int local_units_start(struct local_units *lu, const struct unit_spec *s)
{
	__cleanup_free char *argv_text = NULL;
	char dir[PATH_MAX];
	const char *const *a;
	size_t size = 0;
	FILE *f;
	int r;

	r = unit_dir(lu, s->name, dir, sizeof(dir));
	if (r < 0)
		return r;

	if (mkdir(dir, 0755) < 0)
		return -errno; // -EEXIST: the unit is loaded

	f = open_memstream(&argv_text, &size);
	if (!f) {
		r = -ENOMEM;
		goto err;
	}
	for (a = s->exec_start; *a; a++) {
		// One argument per line: an argument cannot hold a newline.
		if (strchr(*a, '\n')) {
			fclose(f);
			r = -EINVAL;
			goto err;
		}
		fprintf(f, "%s\n", *a);
	}
	if (fclose(f)) {
		r = -ENOMEM;
		goto err;
	}

	r = write_file(dir, "description", s->description);
	if (!r)
		r = write_file(dir, "exec_start", argv_text);
	if (!r && s->exec_start_post)
		r = write_file(dir, "exec_start_post", s->exec_start_post);
	if (!r && s->exec_stop)
		r = write_file(dir, "exec_stop", s->exec_stop);
	if (!r && s->exec_stop_post)
		r = write_file(dir, "exec_stop_post", s->exec_stop_post);
	if (!r && s->connection)
		r = write_file(dir, "remain_after_exit", "yes\n");
	if (r < 0)
		goto err;

	journal_start(lu, s);

	return run_start(lu, dir, s->name, s->exec_start, s->connection);
err:
	shr_rmdir_recursive(dir);
	return r;
}

int local_units_restart(struct local_units *lu, const char *unit_name)
{
	__cleanup_free char *argv_text = NULL;
	const char *argv[MAX_ARGS + 1];
	char dir[PATH_MAX];
	char *p, *nl;
	bool remain;
	int argc = 0, r;

	r = unit_dir(lu, unit_name, dir, sizeof(dir));
	if (r < 0)
		return r;
	if (!shr_isdir(dir))
		return -ENOENT;

	journal(lu, "restart", unit_name);
	run_stop(dir);

	argv_text = read_file(dir, "exec_start");
	if (!argv_text)
		return -EIO;

	for (p = argv_text; *p; p = nl + 1) {
		nl = strchr(p, '\n');
		if (!nl || argc == MAX_ARGS)
			return -EIO;
		*nl = '\0';
		argv[argc++] = p;
	}
	argv[argc] = NULL;
	if (!argc)
		return -EIO;

	remain = has_file(dir, "remain_after_exit");

	return run_start(lu, dir, unit_name, argv, remain);
}

int local_units_stop(struct local_units *lu, const char *unit_name)
{
	char dir[PATH_MAX];
	int r;

	r = unit_dir(lu, unit_name, dir, sizeof(dir));
	if (r < 0)
		return r;
	if (!shr_isdir(dir)) {
		log_err("StopUnit(%s): Unit %s not loaded.", unit_name,
			unit_name);
		return -ENOENT;
	}

	journal(lu, "stop", unit_name);
	run_stop(dir);
	shr_rmdir_recursive(dir);

	return 0;
}

int local_units_reset_failed(struct local_units *lu, const char *unit_name)
{
	journal(lu, "reset-failed", unit_name);
	return 0;
}
