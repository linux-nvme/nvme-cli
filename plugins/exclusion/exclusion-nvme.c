// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libnvme.h>

#include "common.h"
#include "nvme.h"
#include "nvme-print.h"
#include "util/cleanup.h"

#define CREATE_CMD
#include "exclusion-nvme.h"

/*
 * Mutating exclusion commands write the root-owned exclusion lists under
 * /etc/nvme.  Fail early with a clear message rather than letting the write
 * fail later with a bare -EACCES.
 */
static int require_root(void)
{
	if (geteuid() != 0) {
		nvme_show_error("this command requires root privileges (try sudo)");
		return -EPERM;
	}
	return 0;
}

static int excl_create(int argc, char **argv, struct command *acmd,
		       struct plugin *plugin)
{
	const char *desc = "Create a new NVMeoF exclusion list.";
	const char *name_help = "exclusion list name (omit for the default list)";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int ret;

	struct config {
		char *name;
	} cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("name", 'N', "NAME", &cfg.name, name_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = require_root();
	if (ret)
		return ret;

	ctx = libnvme_create_global_ctx();
	ret = libnvmf_exclusion_create(ctx, cfg.name);
	if (ret == -EEXIST)
		nvme_show_error("exclusion list '%s' already exists", cfg.name);
	else if (ret)
		nvme_show_error("create failed: %s", libnvme_strerror(-ret));
	return ret;
}

static int excl_delete(int argc, char **argv, struct command *acmd,
		       struct plugin *plugin)
{
	const char *desc = "Delete an NVMeoF exclusion list entirely.";
	const char *name_help = "exclusion list name (omit for the default list)";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int ret;

	struct config {
		char *name;
	} cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("name", 'N', "NAME", &cfg.name, name_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = require_root();
	if (ret)
		return ret;

	ctx = libnvme_create_global_ctx();
	ret = libnvmf_exclusion_delete(ctx, cfg.name);
	if (ret == -ENOENT)
		nvme_show_error("exclusion list '%s' not found", cfg.name);
	else if (ret)
		nvme_show_error("delete failed: %s", libnvme_strerror(-ret));
	return ret;
}

static void print_list_name(const char *name, void *user_data __attribute__((unused)))
{
	printf("%s\n", name);
}

static void print_entry(const char *entry, void *user_data __attribute__((unused)))
{
	printf("  %s\n", entry);
}

static int excl_list(int argc, char **argv, struct command *acmd,
		     struct plugin *plugin)
{
	const char *desc = "List exclusion lists, or entries within a named list.";
	const char *name_help = "exclusion list name (omit to list all lists)";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int ret;

	struct config {
		char *name;
	} cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("name", 'N', "NAME", &cfg.name, name_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ctx = libnvme_create_global_ctx();

	if (!cfg.name) {
		ret = libnvmf_exclusion_list_for_each(ctx, print_list_name, NULL);
		if (ret)
			nvme_show_error("list failed: %s", libnvme_strerror(-ret));
		return ret;
	}

	ret = libnvmf_exclusion_entry_for_each(ctx, cfg.name, print_entry, NULL);
	if (ret == -ENOENT)
		nvme_show_error("exclusion list '%s' not found", cfg.name);
	else if (ret)
		nvme_show_error("list failed: %s", libnvme_strerror(-ret));
	return ret;
}

static int excl_add(int argc, char **argv, struct command *acmd,
		    struct plugin *plugin)
{
	const char *desc = "Add an entry to an NVMeoF exclusion list.";
	const char *name_help = "exclusion list name (omit for the default list)";
	const char *entry_help = "semicolon-separated key=value entry "
		"(e.g. \"transport=tcp;traddr=192.168.1.1\")";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int ret;

	struct config {
		char *name;
		char *entry;
	} cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("name",  'N', "NAME",  &cfg.name,  name_help),
		OPT_STRING("entry", 'e', "ENTRY", &cfg.entry, entry_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!cfg.entry) {
		nvme_show_error("--entry required");
		return -EINVAL;
	}

	ret = require_root();
	if (ret)
		return ret;

	ctx = libnvme_create_global_ctx();
	if (!libnvmf_exclusion_entry_valid(ctx, cfg.entry)) {
		nvme_show_error("invalid entry: %s", cfg.entry);
		return -EINVAL;
	}

	ret = libnvmf_exclusion_add(ctx, cfg.name, cfg.entry);
	if (ret == -EINVAL)
		nvme_show_error("invalid list name: %s", cfg.name);
	else if (ret)
		nvme_show_error("add failed: %s", libnvme_strerror(-ret));
	return ret;
}

struct entry_collection {
	char **entries;
	size_t count, cap;
};

static void collect_entry(const char *entry, void *user_data)
{
	struct entry_collection *ec = user_data;

	if (ec->count == ec->cap) {
		size_t newcap = ec->cap ? ec->cap * 2 : 16;
		char **newarr = realloc(ec->entries, newcap * sizeof(*newarr));

		if (!newarr)
			return;
		ec->entries = newarr;
		ec->cap = newcap;
	}
	ec->entries[ec->count] = strdup(entry);
	if (ec->entries[ec->count])
		ec->count++;
}

static int cmp_entry(const void *a, const void *b)
{
	return strcmp(*(const char * const *)a, *(const char * const *)b);
}

static int excl_remove(int argc, char **argv, struct command *acmd,
		       struct plugin *plugin)
{
	const char *desc = "Interactively remove an entry from an NVMeoF exclusion list.";
	const char *name_help = "exclusion list name (omit for the default list)";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct entry_collection ec = { 0 };
	char answer[32];
	size_t i, choice;
	int ret;

	struct config {
		char *name;
	} cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("name", 'N', "NAME", &cfg.name, name_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = require_root();
	if (ret)
		return ret;

	ctx = libnvme_create_global_ctx();
	ret = libnvmf_exclusion_entry_for_each(ctx, cfg.name, collect_entry, &ec);
	if (ret) {
		if (ret == -ENOENT)
			nvme_show_error("exclusion list '%s' not found", cfg.name);
		else
			nvme_show_error("list failed: %s", libnvme_strerror(-ret));
		return ret;
	}

	if (ec.count == 0) {
		printf("exclusion list '%s' has no entries\n", cfg.name);
		free(ec.entries);
		return 0;
	}

	qsort(ec.entries, ec.count, sizeof(*ec.entries), cmp_entry);

	for (i = 0; i < ec.count; i++)
		printf("%3zu. %s\n", i + 1, ec.entries[i]);

	printf("Which entry do you want to delete? [1-%zu, or empty to cancel] ",
	       ec.count);
	fflush(stdout);

	if (!fgets(answer, sizeof(answer), stdin) ||
	    sscanf(answer, "%zu", &choice) != 1 ||
	    choice < 1 || choice > ec.count) {
		printf("cancelled\n");
		ret = 0;
		goto out;
	}

	ret = libnvmf_exclusion_remove(ctx, cfg.name, ec.entries[choice - 1]);
	if (ret)
		nvme_show_error("remove failed: %s", libnvme_strerror(-ret));

out:
	for (i = 0; i < ec.count; i++)
		free(ec.entries[i]);
	free(ec.entries);
	return ret;
}

static int run_editor(const char *path)
{
	const char *editor = getenv("EDITOR");
	pid_t pid;
	int status;

	if (!editor || !*editor)
		editor = "vi";

	pid = fork();
	if (pid < 0)
		return -errno;
	if (pid == 0) {
		char cmd[PATH_MAX + 64];

		/*
		 * Pass the path as $1 and reference it in the command so the
		 * editor actually opens the file, while still allowing $EDITOR
		 * to carry arguments (word-split by the shell).
		 */
		snprintf(cmd, sizeof(cmd), "%s \"$1\"", editor);
		execl("/bin/sh", "sh", "-c", cmd, "sh", path, (char *)NULL);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -errno;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -EIO;
}

/*
 * Validate a file: every "exclusion = ..." line must be a valid entry and
 * must sit inside the [exclusions] section.  Mirrors libnvme's write-side
 * validation but reports each offense with its line number.
 * Returns 0 if the file is valid, -EINVAL and prints errors otherwise.
 */
static int validate_conf_file(struct libnvme_global_ctx *ctx, const char *path)
{
	FILE *f;
	char line[4096];
	unsigned lineno = 0;
	bool in_excl = false;
	int errors = 0;

	f = fopen(path, "r");
	if (!f)
		return -errno;

	while (fgets(line, sizeof(line), f)) {
		char *s, *eq, *key, *val;

		lineno++;
		s = line;
		while (*s == ' ' || *s == '\t')
			s++;
		if (!*s || *s == '#' || *s == '\n')
			continue;

		if (*s == '[') {
			char *end = strchr(s, ']');

			if (!end) {
				nvme_show_error(
					"line %u: malformed section header\n",
					lineno);
				errors++;
				in_excl = false;
				continue;
			}
			*end = '\0';
			s++;
			while (*s == ' ' || *s == '\t')
				s++;
			while (end > s && (end[-1] == ' ' || end[-1] == '\t'))
				*--end = '\0';
			in_excl = !strcmp(s, "exclusions");
			continue;
		}

		eq = strchr(s, '=');
		if (!eq)
			continue;
		*eq = '\0';
		key = s;
		while (*key == ' ' || *key == '\t')
			key++;
		char *ke = key + strlen(key);
		while (ke > key && (ke[-1] == ' ' || ke[-1] == '\t'))
			ke--;
		*ke = '\0';

		if (strcmp(key, "exclusion"))
			continue;

		if (!in_excl) {
			nvme_show_error(
				"line %u: entry outside the [exclusions] section\n",
				lineno);
			errors++;
			continue;
		}

		val = eq + 1;
		while (*val == ' ' || *val == '\t')
			val++;
		char *ve = val + strlen(val);
		while (ve > val && (ve[-1] == '\n' || ve[-1] == ' ' || ve[-1] == '\t'))
			ve--;
		*ve = '\0';

		/* Pure check — no filesystem side effects. */
		if (!libnvmf_exclusion_entry_valid(ctx, val)) {
			nvme_show_error("line %u: invalid entry: %s",
				lineno, val);
			errors++;
		}
	}
	fclose(f);
	return errors ? -EINVAL : 0;
}

/*
 * Read a whole file into a newly allocated, NUL-terminated string (caller
 * frees).  Returns NULL on error (errno set).
 */
static char *read_file(const char *path)
{
	FILE *f = fopen(path, "r");
	long sz;
	char *buf;
	size_t n;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) < 0) {
		fclose(f);
		return NULL;
	}
	sz = ftell(f);
	if (sz < 0) {
		fclose(f);
		return NULL;
	}
	rewind(f);

	buf = malloc(sz + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	n = fread(buf, 1, sz, f);
	if (ferror(f)) {
		free(buf);
		fclose(f);
		return NULL;
	}
	buf[n] = '\0';
	fclose(f);
	return buf;
}

/*
 * excl_edit() - the "nvme exclusion edit" command.
 *
 * Opens an exclusion list in the user's $EDITOR for hand-editing, in the same
 * spirit as "visudo" or "crontab -e".  It is a read-modify-write cycle with
 * optimistic concurrency:
 *
 *   1. Read the current list through libnvme (libnvmf_exclusion_read), which
 *      also returns an opaque @version token snapshotting the on-disk content.
 *   2. Copy the text to a private scratch file under $TMPDIR (0600).  The
 *      editor needs a real path, but we never let it touch the live file in
 *      the exclusion directory.
 *   3. run_editor() forks $EDITOR on the scratch file and waits for it to exit.
 *   4. Validate the result; if it has bad entries, offer to re-open the editor
 *      (the re_edit loop) so the user can fix them without losing work.
 *   5. Write the edited text back by list name (libnvmf_exclusion_write),
 *      passing @version.  If the list changed on disk in the meantime the
 *      write fails with -ESTALE and nothing is clobbered.
 *
 * Whenever the changes are not saved (validation given up on, or -ESTALE), the
 * scratch file is deliberately left in place and its path printed, so the
 * user's edits are recoverable.  Requires root.
 */
static int excl_edit(int argc, char **argv, struct command *acmd,
		     struct plugin *plugin)
{
	const char *desc = "Interactively edit an NVMeoF exclusion list.";
	const char *name_help = "exclusion list name (omit for the default list)";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_free char *text = NULL;
	const char *tmpdir;
	char tmp_path[PATH_MAX];
	uint64_t version;
	int fd, ret;

	struct config {
		char *name;
	} cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("name", 'N', "NAME", &cfg.name, name_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = require_root();
	if (ret)
		return ret;

	ctx = libnvme_create_global_ctx();

	/*
	 * Read the current list through libnvme: the plugin never needs to know
	 * where exclusion lists live.  A missing list reads as empty so it can
	 * be created here.  @version is an opaque token used at save time to
	 * detect a concurrent editor.
	 */
	ret = libnvmf_exclusion_read(ctx, cfg.name, &text, &version);
	if (ret) {
		nvme_show_error("cannot read '%s': %s",
			cfg.name, libnvme_strerror(-ret));
		return ret;
	}

	/*
	 * Edit a private scratch copy under $TMPDIR -- NOT in the exclusion dir.
	 * The editor needs a real path, but the result is installed by name via
	 * libnvmf_exclusion_write().  mkstemp() creates the copy 0600.
	 */
	tmpdir = getenv("TMPDIR");
	if (!tmpdir || !*tmpdir)
		tmpdir = "/tmp";
	snprintf(tmp_path, sizeof(tmp_path), "%s/nvme-excl-%s.XXXXXX",
		 tmpdir, cfg.name);

	fd = mkstemp(tmp_path);
	if (fd < 0) {
		ret = -errno;
		nvme_show_error("cannot create temp file: %s",
			libnvme_strerror(-ret));
		return ret;
	}
	{
		FILE *dst = fdopen(fd, "w");

		if (!dst) {
			ret = -errno;
			close(fd);
			unlink(tmp_path);
			return ret;
		}
		fputs(text, dst);
		fclose(dst);
	}

re_edit:
	ret = run_editor(tmp_path);
	if (ret) {
		nvme_show_error("editor failed");
		unlink(tmp_path);
		return ret;
	}

	ret = validate_conf_file(ctx, tmp_path);
	if (ret) {
		char ans[8];

		nvme_show_error("File has errors. Re-edit? [y/N] ");
		fflush(stderr);
		if (fgets(ans, sizeof(ans), stdin) &&
		    (ans[0] == 'y' || ans[0] == 'Y'))
			goto re_edit;

		nvme_show_error(
			"Discarding changes -- your edits are kept at %s\n",
			tmp_path);
		return -EINVAL;
	}

	{
		__cleanup_free char *edited = read_file(tmp_path);

		if (!edited) {
			ret = errno ? -errno : -EIO;
			nvme_show_error("cannot read back temp file: %s",
				libnvme_strerror(-ret));
			unlink(tmp_path);
			return ret;
		}
		ret = libnvmf_exclusion_write(ctx, cfg.name, edited, version);
	}

	if (ret == -ESTALE) {
		nvme_show_error(
			"the list changed on disk since you opened it; your "
			"edits were NOT saved -- kept at %s\n", tmp_path);
		return ret;
	}
	if (ret) {
		nvme_show_error("cannot save: %s -- your edits are kept at %s",
			libnvme_strerror(-ret), tmp_path);
		return ret;
	}

	unlink(tmp_path);
	return 0;
}
