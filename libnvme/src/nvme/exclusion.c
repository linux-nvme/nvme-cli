// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

/*
 * System-wide NVMe-oF exclusion list.
 *
 * Storage: a hand-edited main file SYSCONFDIR/nvme/exclusions.conf plus managed
 * drop-in lists under SYSCONFDIR/nvme/exclusions.conf.d/<name>.conf.  Matching
 * consults the main file and every drop-in.
 * Format:  an "[exclusions]" INI section holding one "exclusion = key=val;..."
 * line per entry; # lines are comments.  Other sections are reserved for
 * future use and their content is ignored.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cleanup.h"
#include "compiler-attributes.h"
#include "exclusion.h"
#include "lib.h"
#include "nvme/accessors-fabrics.h"
#include "nvme/tid.h"
#include "private.h"
#include "private-fabrics.h"

#define EXCL_BASE_DEFAULT SYSCONFDIR "/nvme"
#define EXCL_MAIN_NAME    "exclusions.conf"
#define EXCL_DROPIN_NAME  "exclusions.conf.d"
#define EXCL_MAIN_PATH    EXCL_BASE_DEFAULT "/" EXCL_MAIN_NAME
#define EXCL_DROPIN_PATH  EXCL_BASE_DEFAULT "/" EXCL_DROPIN_NAME
#define EXCL_SECTION      "exclusions"
#define EXCL_LINE_KEY     "exclusion"
#define EXCL_LINE_MAX     4096
#define EXCL_FILE_MAX     (1 * 1024 * 1024) /* 1 MiB cap on one list file */

/* Header written whenever a list file is first created (via create or add). */
#define EXCL_HEADER_FMT \
	"# NVMe-oF exclusion list: %s\n" \
	"# Format: exclusion = key=val;key=val\n" \
	"# Keys: transport, traddr, trsvcid, nqn, host-traddr, host-iface, hostnqn, hostid\n" \
	"\n" \
	"[" EXCL_SECTION "]\n"

/*
 * Path helpers.  The normal (production) paths are fixed compile-time literals,
 * returned directly.  A ctx test sandbox (libnvme_set_test_base_dir()) reroots
 * them under a throwaway /tmp directory; the path is built once into a static
 * and cached.  Caching in a process-wide static is safe even though the
 * sandbox is a per-ctx property: it is a single-process test feature, so a
 * process is either all-production or all-test and the first call fixes the
 * right value for the whole run.  Returning fixed paths this way keeps the
 * callers free of local path buffers; only excl_path() for a *named* drop-in
 * (whose path varies with @name) fills a caller buffer.
 */
static const char *excl_base(struct libnvme_global_ctx *ctx)
{
	return ctx->test_base_dir ? ctx->test_base_dir : EXCL_BASE_DEFAULT;
}

/*
 * Return a fixed exclusion path: the compile-time literal @prod_path in
 * production, or <test_base_dir>/@name under a sandbox (built into @buf and
 * remembered in @cache).  See the note above on why the static cache is safe.
 */
static const char *excl_fixed_path(struct libnvme_global_ctx *ctx,
				   const char *prod_path, const char *name,
				   const char **cache, char *buf, size_t len)
{
	int n;

	if (*cache)
		return *cache;
	if (!ctx->test_base_dir) {
		*cache = prod_path;
	} else {
		n = snprintf(buf, len, "%s/%s", ctx->test_base_dir, name);
		*cache = (n > 0 && (size_t)n < len) ? buf : NULL;
	}
	return *cache;
}

/* Directory holding the managed drop-in lists (<base>/exclusions.conf.d). */
static const char *excl_dropin_dir(struct libnvme_global_ctx *ctx)
{
	static const char *cache;
	static char buf[PATH_MAX];

	return excl_fixed_path(ctx, EXCL_DROPIN_PATH, EXCL_DROPIN_NAME,
			       &cache, buf, sizeof(buf));
}

/* Path of the main hand-edited list (<base>/exclusions.conf). */
static const char *excl_main_path(struct libnvme_global_ctx *ctx)
{
	static const char *cache;
	static char buf[PATH_MAX];

	return excl_fixed_path(ctx, EXCL_MAIN_PATH, EXCL_MAIN_NAME,
			       &cache, buf, sizeof(buf));
}

/*
 * Directory that contains a list's file -- where its atomic-write temp file is
 * created and which is fsync'd to make a rename durable.  The default list
 * (@name == NULL) sits directly under the base dir; a named list is a drop-in.
 */
static const char *excl_dir(struct libnvme_global_ctx *ctx, const char *name)
{
	return name ? excl_dropin_dir(ctx) : excl_base(ctx);
}

/*
 * Path of a list file.  @name == NULL is the main hand-edited list; a non-NULL
 * name is a managed drop-in (<base>/exclusions.conf.d/<name>.conf).  Validating
 * the name here (with the shared libnvmf_valid_name) guards every public entry
 * point uniformly against unsafe characters and path traversal.  The named path
 * varies with @name so it is built into @buf; the main path is a fixed literal.
 * Returns NULL on an invalid name or truncation.
 */
static const char *excl_path(struct libnvme_global_ctx *ctx,
			     const char *name, char *buf, size_t len)
{
	int n;

	if (!name)
		return excl_main_path(ctx);

	if (!libnvmf_valid_name(name))
		return NULL;

	n = snprintf(buf, len, "%s/%s.conf", excl_dropin_dir(ctx), name);
	return (n > 0 && (size_t)n < len) ? buf : NULL;
}

static int ensure_excl_dir(struct libnvme_global_ctx *ctx, const char *name)
{
	const char *dir = excl_dir(ctx, name);

	if (!dir)
		return -ENAMETOOLONG;
	return libnvmf_mkdir_p(dir, 0755);
}

/* Build the atomic-write temp template "<dir>/.excl.tmp.XXXXXX" in @tmp. */
static int excl_tmp(const char *dir, char *tmp, size_t len)
{
	int n = snprintf(tmp, len, "%s/.excl.tmp.XXXXXX", dir);

	return (n > 0 && (size_t)n < len) ? 0 : -ENAMETOOLONG;
}

static bool addr_equal(const char *entry_val, const char *caller_val,
		       const char *transport)
{
	if (streq0(transport, "fc"))
		return streqcase0(entry_val, caller_val);

	return libnvme_ipaddrs_eq(entry_val, caller_val) ||
	       streq0(entry_val, caller_val);
}

/*
 * Minimal match: only the fields the entry (@e) actually sets are checked
 * against the target @tid.  traddr/host_traddr use addr_equal() for
 * transport-aware address comparison; the rest compare verbatim.
 */
static bool tid_subset_match(const struct libnvmf_tid *e,
			     const struct libnvmf_tid *tid)
{
	if (e->transport && !streq0(e->transport, tid->transport))
		return false;
	if (e->traddr &&
	    !(tid->traddr &&
	      addr_equal(e->traddr, tid->traddr, tid->transport)))
		return false;
	if (e->trsvcid && !streq0(e->trsvcid, tid->trsvcid))
		return false;
	if (e->subsysnqn && !streq0(e->subsysnqn, tid->subsysnqn))
		return false;
	if (e->host_traddr &&
	    !(tid->host_traddr &&
	      addr_equal(e->host_traddr, tid->host_traddr, tid->transport)))
		return false;
	if (e->host_iface && !streq0(e->host_iface, tid->host_iface))
		return false;
	if (e->hostnqn && !streq0(e->hostnqn, tid->hostnqn))
		return false;
	if (e->hostid && !streq0(e->hostid, tid->hostid))
		return false;
	return true;
}

/*
 * Check one entry against a transport ID (minimal match): the entry is parsed
 * into a partial TID, and only the fields it sets are compared against @tid.  A
 * malformed entry (unknown key, bare token, or empty value) or one that sets no
 * fields matches nothing -- we never guess.  Parsed silently (ctx == NULL):
 * matching runs on every connect, so a bad hand-edited entry must stay quiet.
 */
static bool entry_matches(const char *entry, const struct libnvmf_tid *tid)
{
	struct libnvmf_tid *e = libnvmf_tid_parse_strict(NULL, entry);
	bool matches;

	if (!e)
		return false;
	if (libnvmf_tid_is_empty(e)) {
		libnvmf_tid_free(e);
		return false;
	}

	matches = tid_subset_match(e, tid);
	libnvmf_tid_free(e);
	return matches;
}

/*
 * Validate an entry before writing it: it must parse cleanly (every key known,
 * no malformed token) and set at least one field.  @ctx is used only to log
 * what was wrong; it may be NULL to validate silently.
 */
static bool entry_valid(struct libnvme_global_ctx *ctx, const char *entry)
{
	struct libnvmf_tid *e = libnvmf_tid_parse_strict(ctx, entry);
	bool valid = e && !libnvmf_tid_is_empty(e);

	libnvmf_tid_free(e);
	return valid;
}

__libnvme_public bool libnvmf_exclusion_entry_valid(struct libnvme_global_ctx *ctx,
						    const char *entry)
{
	if (!ctx)
		return false;
	return entry_valid(ctx, entry);
}

/*
 * Scan one .conf file.  For match scan: call entry_matches() on each entry,
 * returning true on first match.  For iteration: call the callback on each entry.
 */
enum excl_line_type {
	EXCL_LINE_IGNORE,  /* blank, comment, foreign key or foreign section */
	EXCL_LINE_SECTION, /* well-formed section header; *in_excl updated */
	EXCL_LINE_ENTRY,   /* "exclusion =" inside [exclusions]; *val set */
	EXCL_LINE_STRAY,   /* "exclusion =" outside [exclusions] */
	EXCL_LINE_JUNK,    /* malformed section header */
};

/*
 * Classify one line of an exclusion list; the single scan step shared by the
 * read, validate, add and remove paths so they can never drift apart.  @s is
 * a trimmed, mutable scratch copy of the line.  @in_excl carries the "inside
 * [exclusions]?" state across calls (start it at false); a malformed section
 * header clears it, so the entries that follow are ignored rather than
 * misattributed -- the fail-safe direction.
 */
static enum excl_line_type classify_line(char *s, bool *in_excl, char **val)
{
	char *eq, *key;

	if (!*s || *s == '#')
		return EXCL_LINE_IGNORE;

	if (*s == '[') {
		char *end = strchr(s, ']');

		if (!end) {
			*in_excl = false;
			return EXCL_LINE_JUNK;
		}
		*end = '\0';
		*in_excl = !strcmp(libnvmf_trim(s + 1), EXCL_SECTION);
		return EXCL_LINE_SECTION;
	}

	eq = strchr(s, '=');
	if (!eq)
		return EXCL_LINE_IGNORE;
	*eq = '\0';
	key = libnvmf_trim(s);
	if (strcmp(key, EXCL_LINE_KEY))
		return EXCL_LINE_IGNORE;
	if (!*in_excl)
		return EXCL_LINE_STRAY;

	*val = libnvmf_trim(eq + 1);
	return EXCL_LINE_ENTRY;
}

typedef bool (*scan_fn)(const char *entry, void *ctx);

static bool scan_conf_file(const char *path, scan_fn fn, void *ctx)
{
	FILE *f;
	char line[EXCL_LINE_MAX];
	bool in_excl = false;
	bool result = false;

	f = fopen(path, "r");
	if (!f)
		return false;

	while (fgets(line, sizeof(line), f)) {
		char *s = libnvmf_trim(line);
		char *val;

		if (classify_line(s, &in_excl, &val) != EXCL_LINE_ENTRY)
			continue;

		if (fn(val, ctx)) {
			result = true;
			break;
		}
	}
	fclose(f);
	return result;
}

static bool match_entry(const char *entry, void *ctx)
{
	return entry_matches(entry, ctx);
}

__libnvme_public bool libnvmf_exclusion_match(struct libnvme_global_ctx *ctx,
					      const struct libnvmf_tid *tid)
{
	const char *dir, *mainp;
	DIR *d;
	struct dirent *de;
	bool found = false;

	if (!ctx || !tid)
		return false;

	/* The hand-edited main list first, then each managed drop-in. */
	mainp = excl_main_path(ctx);
	if (mainp && scan_conf_file(mainp, match_entry, (void *)tid))
		return true;

	dir = excl_dropin_dir(ctx);
	if (!dir)
		return false;

	d = opendir(dir);
	if (!d)
		return false; /* fail-open: directory missing = nothing excluded */

	while ((de = readdir(d)) && !found) {
		char path[PATH_MAX];
		const char *dot = strrchr(de->d_name, '.');
		size_t nlen;

		if (!dot || strcmp(dot, ".conf"))
			continue;

		nlen = (size_t)(dot - de->d_name);
		if (nlen == 0)
			continue;

		if (snprintf(path, sizeof(path), "%s/%s", dir,
			     de->d_name) >= (int)sizeof(path))
			continue;
		found = scan_conf_file(path, match_entry, (void *)tid);
	}
	closedir(d);
	return found;
}

struct iter_ctx {
	void (*callback)(const char *entry, void *user_data);
	void *user_data;
};

static bool iter_entry(const char *entry, void *ctx)
{
	struct iter_ctx *ic = ctx;

	ic->callback(entry, ic->user_data);
	return false; /* never stop early */
}

__libnvme_public int libnvmf_exclusion_list_for_each(
	struct libnvme_global_ctx *ctx,
	void (*callback)(const char *name, void *user_data),
	void *user_data)
{
	const char *dir;
	DIR *d;
	struct dirent *de;

	if (!ctx)
		return -EINVAL;

	dir = excl_dropin_dir(ctx);
	if (!dir)
		return -ENAMETOOLONG;

	d = opendir(dir);
	if (!d) {
		if (errno == ENOENT)
			return 0;
		return -errno;
	}

	while ((de = readdir(d))) {
		char name_buf[NAME_MAX];
		const char *dot;
		size_t nlen;

		dot = strrchr(de->d_name, '.');
		if (!dot || strcmp(dot, ".conf"))
			continue;

		nlen = (size_t)(dot - de->d_name);
		if (nlen == 0 || nlen >= sizeof(name_buf))
			continue;

		memcpy(name_buf, de->d_name, nlen);
		name_buf[nlen] = '\0';
		callback(name_buf, user_data);
	}
	closedir(d);
	return 0;
}

__libnvme_public int libnvmf_exclusion_entry_for_each(
	struct libnvme_global_ctx *ctx,
	const char *name,
	void (*callback)(const char *entry, void *user_data),
	void *user_data)
{
	const char *path;
	char pathbuf[PATH_MAX];
	struct iter_ctx ic = { .callback = callback, .user_data = user_data };

	if (!ctx)
		return -EINVAL;

	path = excl_path(ctx, name, pathbuf, sizeof(pathbuf));
	if (!path)
		return -EINVAL;

	if (access(path, F_OK) < 0)
		return -ENOENT;

	scan_conf_file(path, iter_entry, &ic);
	return 0;
}

__libnvme_public int libnvmf_exclusion_create(struct libnvme_global_ctx *ctx,
					      const char *name)
{
	const char *path;
	char pathbuf[PATH_MAX];
	int fd, ret;

	if (!ctx)
		return -EINVAL;

	ret = ensure_excl_dir(ctx, name);
	if (ret)
		return ret;

	path = excl_path(ctx, name, pathbuf, sizeof(pathbuf));
	if (!path)
		return -EINVAL;

	fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
	if (fd < 0)
		return -errno;

	/*
	 * Set the mode explicitly: O_CREAT honors the caller's umask, so a tight
	 * root umask would otherwise yield a non-world-readable list.  Exclusion
	 * lists follow /etc/nvme policy -- readable by all, writable by root.
	 */
	if (fchmod(fd, 0644) < 0) {
		ret = -errno;
		close(fd);
		unlink(path);
		return ret;
	}

	/* Write the standard header comment. */
	dprintf(fd, EXCL_HEADER_FMT, name ? name : "default");
	close(fd);
	return 0;
}

__libnvme_public int libnvmf_exclusion_delete(struct libnvme_global_ctx *ctx,
					      const char *name)
{
	const char *path;
	char pathbuf[PATH_MAX];

	if (!ctx)
		return -EINVAL;

	path = excl_path(ctx, name, pathbuf, sizeof(pathbuf));
	if (!path)
		return -EINVAL;

	if (unlink(path) < 0)
		return -errno;
	return 0;
}

__libnvme_public int libnvmf_exclusion_add(struct libnvme_global_ctx *ctx,
					   const char *name, const char *entry)
{
	char pathbuf[PATH_MAX], tmp[PATH_MAX], line[EXCL_LINE_MAX];
	const char *path, *dir;
	FILE *fin, *fout;
	int fd, ret = 0;

	if (!ctx)
		return -EINVAL;
	if (!entry_valid(ctx, entry))
		return -EINVAL;

	ret = ensure_excl_dir(ctx, name);
	if (ret)
		return ret;

	path = excl_path(ctx, name, pathbuf, sizeof(pathbuf));
	if (!path)
		return -EINVAL;
	dir = excl_dir(ctx, name);
	if (!dir || excl_tmp(dir, tmp, sizeof(tmp)))
		return -ENAMETOOLONG;

	fd = libnvmf_mkstemp(tmp);
	if (fd < 0)
		return fd;

	/* mkstemp creates 0600; widen to /etc/nvme policy (world-readable). */
	if (fchmod(fd, 0644) < 0) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		return ret;
	}

	fout = fdopen(fd, "w");
	if (!fout) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		return ret;
	}

	/* Copy existing content if the file exists. */
	fin = fopen(path, "r");
	if (fin) {
		bool in_excl = false, has_section = false;

		while (fgets(line, sizeof(line), fin)) {
			char parsebuf[EXCL_LINE_MAX];
			char *val;

			fputs(line, fout);

			/* Classify a scratch copy; "line" must stay intact. */
			strncpy(parsebuf, line, sizeof(parsebuf) - 1);
			parsebuf[sizeof(parsebuf) - 1] = '\0';
			classify_line(libnvmf_trim(parsebuf), &in_excl, &val);
			has_section |= in_excl;
		}
		fclose(fin);

		/*
		 * A hand-made file may lack the [exclusions] header; appending
		 * the entry bare would leave it outside the section, where the
		 * readers ignore it.  (Re-)open the section before appending --
		 * a repeated header is legal INI and merely re-enters it.
		 */
		if (!has_section || !in_excl)
			fprintf(fout, "\n[%s]\n", EXCL_SECTION);
	} else {
		fprintf(fout, EXCL_HEADER_FMT, name ? name : "default");
	}

	fprintf(fout, "%s = %s\n", EXCL_LINE_KEY, entry);

	if (fflush(fout) != 0 || fsync(fileno(fout)) != 0) {
		ret = -errno;
		fclose(fout);
		unlink(tmp);
		return ret;
	}
	if (fclose(fout) != 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}

	if (rename(tmp, path) < 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}
	libnvmf_fsync_dir(dir); /* make the rename durable */
	return ret;
}

/*
 * Build an exclusion entry string from a controller's transport parameters.
 * It emits the transport-addressing tuple that identifies the path --
 * transport, traddr and subsysnqn unconditionally, trsvcid and host-iface
 * when set -- and deliberately omits the host identity (hostnqn/hostid), so an
 * exclusion built from a controller applies regardless of which host persona
 * is connecting.
 */
static int excl_entry_from_ctrl(libnvme_ctrl_t c, char *buf, size_t len)
{
	int n = 0;

	if (!c->transport || !c->traddr || !c->subsysnqn)
		return -EINVAL;

	/* Emit only the fields that are present; never a bare "trsvcid=". */
#define APPEND(fmt, ...) \
	do { \
		if (n >= 0 && (size_t)n < len) \
			n += snprintf(buf + n, len - n, fmt, ##__VA_ARGS__); \
	} while (0)

	APPEND("transport=%s;traddr=%s", c->transport, c->traddr);
	if (c->trsvcid && *c->trsvcid)
		APPEND(";trsvcid=%s", c->trsvcid);
	APPEND(";nqn=%s", c->subsysnqn);
	if (c->host_iface && *c->host_iface)
		APPEND(";host-iface=%s", c->host_iface);

#undef APPEND

	return (n > 0 && (size_t)n < len) ? 0 : -ENAMETOOLONG;
}

__libnvme_public int libnvmf_exclusion_add_ctrl(struct libnvme_global_ctx *ctx,
						const char *name,
						struct libnvme_ctrl *c)
{
	char entry[EXCL_LINE_MAX];
	int ret;

	if (!ctx || !c)
		return -EINVAL;

	ret = excl_entry_from_ctrl(c, entry, sizeof(entry));
	if (ret)
		return ret;

	return libnvmf_exclusion_add(ctx, name, entry);
}

__libnvme_public int libnvmf_exclusion_add_subsysnqn(
		struct libnvme_global_ctx *ctx, const char *name,
		const char *subsysnqn)
{
	char entry[EXCL_LINE_MAX];
	int n;

	if (!ctx || !subsysnqn || !*subsysnqn)
		return -EINVAL;

	n = snprintf(entry, sizeof(entry), "nqn=%s", subsysnqn);
	if (n <= 0 || (size_t)n >= sizeof(entry))
		return -ENAMETOOLONG;

	return libnvmf_exclusion_add(ctx, name, entry);
}

__libnvme_public int libnvmf_exclusion_remove(struct libnvme_global_ctx *ctx,
					      const char *name, const char *entry)
{
	char pathbuf[PATH_MAX], tmp[PATH_MAX], line[EXCL_LINE_MAX];
	const char *path, *dir;
	bool in_excl = false;
	bool removed = false;
	FILE *fin, *fout;
	int fd, ret = 0;

	if (!ctx)
		return -EINVAL;

	path = excl_path(ctx, name, pathbuf, sizeof(pathbuf));
	if (!path)
		return -EINVAL;

	fin = fopen(path, "r");
	if (!fin)
		return -ENOENT;
	dir = excl_dir(ctx, name);
	if (!dir || excl_tmp(dir, tmp, sizeof(tmp))) {
		fclose(fin);
		return -ENAMETOOLONG;
	}

	fd = libnvmf_mkstemp(tmp);
	if (fd < 0) {
		ret = fd;
		fclose(fin);
		return ret;
	}

	/* mkstemp creates 0600; widen to /etc/nvme policy (world-readable). */
	if (fchmod(fd, 0644) < 0) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		fclose(fin);
		return ret;
	}

	fout = fdopen(fd, "w");
	if (!fout) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		fclose(fin);
		return ret;
	}

	while (fgets(line, sizeof(line), fin)) {
		char parsebuf[EXCL_LINE_MAX];
		char *val;

		/* Classify a scratch copy; libnvmf_trim() mutates in place and
		 * would otherwise clobber the trailing newline in "line" before
		 * it gets passed through to fout.
		 */
		strncpy(parsebuf, line, sizeof(parsebuf) - 1);
		parsebuf[sizeof(parsebuf) - 1] = '\0';

		/* Everything except the entry being removed passes through. */
		if (classify_line(libnvmf_trim(parsebuf), &in_excl,
				  &val) == EXCL_LINE_ENTRY &&
		    !removed && !strcmp(val, entry))
			removed = true; /* skip this line */
		else
			fputs(line, fout);
	}

	fclose(fin);

	if (fflush(fout) != 0 || fsync(fileno(fout)) != 0) {
		ret = -errno;
		fclose(fout);
		unlink(tmp);
		return ret;
	}
	if (fclose(fout) != 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}

	if (!removed) {
		unlink(tmp);
		return -ENOENT;
	}

	if (rename(tmp, path) < 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}
	libnvmf_fsync_dir(dir); /* make the rename durable */
	return ret;
}

/*
 * FNV-1a 64-bit over a byte range.  Used as an opaque optimistic-concurrency
 * token: read() hands the caller the hash of the file it saw, write() refuses
 * if the file no longer hashes to that value.  Never returns 0 -- that value
 * is reserved to mean "the list did not exist".
 */
static uint64_t content_hash(const char *buf, size_t len)
{
	uint64_t h = libnvmf_fnv1a_64(buf, len);

	return h ? h : 1;
}

/*
 * Read the whole file at @path into a newly allocated, NUL-terminated buffer.
 * On success sets *out (caller frees) and *len (excluding the NUL), returns 0.
 * Returns -ENOENT if the file does not exist, or a negative errno otherwise.
 */
static int slurp(const char *path, char **out, size_t *len)
{
	struct stat st;
	char *buf;
	size_t off = 0;
	int fd, ret = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) < 0) {
		ret = -errno;
		goto out;
	}
	if (st.st_size > EXCL_FILE_MAX) {
		ret = -EFBIG;
		goto out;
	}

	buf = malloc(st.st_size + 1);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	while (off < (size_t)st.st_size) {
		ssize_t n = read(fd, buf + off, st.st_size - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			ret = -errno;
			goto out;
		}
		if (n == 0)
			break;
		off += n;
	}
	buf[off] = '\0';
	*out = buf;
	*len = off;
out:
	close(fd);
	return ret;
}

/* Hash the current on-disk list.  Sets *out to 0 when the list is absent. */
static int hash_file(const char *path, uint64_t *out)
{
	__cleanup_free char *buf = NULL;
	size_t len;
	int ret;

	ret = slurp(path, &buf, &len);
	if (ret == -ENOENT) {
		*out = 0;
		return 0;
	}
	if (ret)
		return ret;
	*out = content_hash(buf, len);
	return 0;
}

/*
 * Validate every "exclusion = ..." line in @text.  Comments, blank lines and
 * non-exclusion keys are ignored.  Returns 0 if all entries are valid, -EINVAL
 * otherwise.  The public write path validates here too -- it cannot trust the
 * caller to have pre-checked the buffer.  Writing is stricter than reading:
 * a malformed section header or an entry outside [exclusions] would be
 * silently skipped by the readers (disarming the entry), so reject the buffer
 * loudly here instead of letting an editor persist it.
 */
static int validate_conf_buf(struct libnvme_global_ctx *ctx, const char *text)
{
	__cleanup_free char *copy = strdup(text);
	char *save = NULL, *line;
	bool in_excl = false;
	int ret = 0;

	if (!copy)
		return -ENOMEM;

	for (line = strtok_r(copy, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *s = libnvmf_trim(line), *val;

		switch (classify_line(s, &in_excl, &val)) {
		case EXCL_LINE_ENTRY:
			if (!entry_valid(ctx, val))
				ret = -EINVAL;
			break;
		case EXCL_LINE_STRAY:
		case EXCL_LINE_JUNK:
			ret = -EINVAL;
			break;
		default:
			break;
		}
		if (ret)
			break;
	}
	return ret;
}

__libnvme_public int libnvmf_exclusion_read(struct libnvme_global_ctx *ctx,
					    const char *name, char **text,
					    uint64_t *version)
{
	char pathbuf[PATH_MAX];
	const char *path;
	size_t len;
	int ret;

	if (!ctx)
		return -EINVAL;
	if (!text || !version)
		return -EINVAL;
	*text = NULL;
	*version = 0;

	path = excl_path(ctx, name, pathbuf, sizeof(pathbuf));
	if (!path)
		return -EINVAL;

	ret = slurp(path, text, &len);
	if (ret == -ENOENT) {
		/* A missing list reads as empty so an editor can create it. */
		*text = strdup("");
		return *text ? 0 : -ENOMEM;
	}
	if (ret)
		return ret;

	*version = content_hash(*text, len);
	return 0;
}

__libnvme_public int libnvmf_exclusion_write(struct libnvme_global_ctx *ctx,
					     const char *name, const char *text,
					     uint64_t version)
{
	char pathbuf[PATH_MAX], tmp[PATH_MAX];
	const char *path, *dir;
	uint64_t cur;
	int dir_fd, fd, ret;

	if (!ctx)
		return -EINVAL;
	if (!text)
		return -EINVAL;

	ret = validate_conf_buf(ctx, text);
	if (ret)
		return ret;

	ret = ensure_excl_dir(ctx, name);
	if (ret)
		return ret;

	path = excl_path(ctx, name, pathbuf, sizeof(pathbuf));
	if (!path)
		return -EINVAL;

	/*
	 * Optimistic concurrency: serialize only the compare-and-swap window
	 * (recheck the on-disk version, then rename) under a directory lock.
	 * The editor ran unlocked, so two editors never block on each other --
	 * the second to save sees a changed version and gets -ESTALE rather than
	 * silently clobbering the first.
	 */
	dir = excl_dir(ctx, name);
	if (!dir || excl_tmp(dir, tmp, sizeof(tmp)))
		return -ENAMETOOLONG;
	dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd < 0)
		return -errno;
	if (flock(dir_fd, LOCK_EX) < 0) {
		ret = -errno;
		goto out;
	}

	ret = hash_file(path, &cur);
	if (ret)
		goto out;
	if (cur != version) {
		ret = -ESTALE;
		goto out;
	}

	fd = libnvmf_mkstemp(tmp);
	if (fd < 0) {
		ret = fd;
		goto out;
	}

	/* mkstemp creates 0600; widen to /etc/nvme policy (world-readable). */
	if (fchmod(fd, 0644) < 0) {
		ret = -errno;
		goto err_tmp;
	}
	ret = write_all(fd, text, strlen(text));
	if (ret)
		goto err_tmp;
	if (fsync(fd) < 0) {
		ret = -errno;
		goto err_tmp;
	}
	close(fd);

	if (rename(tmp, path) < 0) {
		ret = -errno;
		unlink(tmp);
		goto out;
	}
	libnvmf_fsync_dir(dir); /* make the rename durable */
	ret = 0;
	goto out;

err_tmp:
	close(fd);
	unlink(tmp);
out:
	close(dir_fd); /* releases the flock */
	return ret;
}
