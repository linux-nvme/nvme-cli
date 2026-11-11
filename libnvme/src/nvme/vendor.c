// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *
 * The defaults of storage vendors for their controllers, the I/O policy
 * of the subsystem and ctrl_loss_tmo, from one INI file per vendor in
 * the vendor.d directories of SYSCONFDIR, RUNDIR and PREFIX/lib. libnvme
 * applies them to a controller right after it connected it.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shared/ini-util.h>
#include <shared/string-util.h>

#include "cleanup.h"
#include "lib.h"
#include "private.h"
#include "private-fabrics.h"

#define VENDOR_ETC_DIR	SYSCONFDIR "/nvme/vendor.d"
#define VENDOR_RUN_DIR	RUNDIR "/nvme/vendor.d"
/* VENDOR_USR_DIR: PREFIX/lib/nvme/vendor.d, from the build */

struct vendor_model {
	char *source;		/* file:line of the section, for the log */
	char *model;		/* a udev match pattern, see udev_match() */
	char *transport;	/* a udev match pattern; NULL: any */
	char *iopolicy;		/* NULL: leave alone */
	char *ctrl_loss_tmo;	/* NULL: leave alone */
};

struct libnvmf_vendor_defaults {
	struct vendor_model *models;
	unsigned int nr;
};

static void model_clear(struct vendor_model *m)
{
	free(m->source);
	free(m->model);
	free(m->transport);
	free(m->iopolicy);
	free(m->ctrl_loss_tmo);
}

void libnvmf_vendor_free(struct libnvmf_vendor_defaults *vd)
{
	unsigned int i;

	if (!vd)
		return;
	for (i = 0; i < vd->nr; i++)
		model_clear(&vd->models[i]);
	free(vd->models);
	free(vd);
}

unsigned int libnvmf_vendor_count(const struct libnvmf_vendor_defaults *vd)
{
	return vd ? vd->nr : 0;
}

struct parse_ctx {
	struct libnvme_global_ctx *ctx;
	struct libnvmf_vendor_defaults *vd;
	const char *path;
	struct vendor_model *cur;	/* the open [Model] section, or NULL */
};

/* A section without a model, or without a value to set, is dropped. */
static void close_section(struct parse_ctx *pc)
{
	struct vendor_model *m = pc->cur;

	pc->cur = NULL;
	if (!m)
		return;
	if (!m->model || (!m->iopolicy && !m->ctrl_loss_tmo)) {
		libnvme_msg(pc->ctx, LIBNVME_LOG_WARN,
			    "%s: [Model] without model, iopolicy or ctrl-loss-tmo, ignored\n",
			    m->source);
		model_clear(m);
		pc->vd->nr--;
	}
}

static int open_section(struct parse_ctx *pc, unsigned int line)
{
	struct libnvmf_vendor_defaults *vd = pc->vd;
	struct vendor_model *models, *m;

	models = realloc(vd->models, (vd->nr + 1) * sizeof(*models));
	if (!models)
		return -ENOMEM;
	vd->models = models;
	m = &models[vd->nr++];
	memset(m, 0, sizeof(*m));
	if (asprintf(&m->source, "%s:%u", pc->path, line) < 0) {
		m->source = NULL;
		vd->nr--;
		return -ENOMEM;
	}
	pc->cur = m;
	return 0;
}

static int set_key(struct parse_ctx *pc, const char *key, const char *value,
		   unsigned int line)
{
	struct vendor_model *m = pc->cur;
	char **field;

	if (!strcmp(key, "model"))
		field = &m->model;
	else if (!strcmp(key, "transport"))
		field = &m->transport;
	else if (!strcmp(key, "iopolicy"))
		field = &m->iopolicy;
	else if (!strcmp(key, "ctrl-loss-tmo"))
		field = &m->ctrl_loss_tmo;
	else {
		libnvme_msg(pc->ctx, LIBNVME_LOG_WARN,
			    "%s:%u: unknown key '%s', ignored\n", pc->path,
			    line, key);
		return 0;
	}

	if (!*value) {
		libnvme_msg(pc->ctx, LIBNVME_LOG_WARN,
			    "%s:%u: empty '%s', ignored\n", pc->path, line,
			    key);
		return 0;
	}
	free(*field);
	*field = strdup(value);
	return *field ? 0 : -ENOMEM;
}

static int parse_event(enum shr_ini_event event, const char *section,
		       const char *key, const char *value, unsigned int line,
		       void *user_data)
{
	struct parse_ctx *pc = user_data;

	switch (event) {
	case SHR_INI_SECTION:
		close_section(pc);
		if (!strcmp(key, "Model"))
			return open_section(pc, line);
		libnvme_msg(pc->ctx, LIBNVME_LOG_WARN,
			    "%s:%u: unknown section [%s], ignored\n", pc->path,
			    line, key);
		return 0;
	case SHR_INI_KV:
		if (!pc->cur) {
			libnvme_msg(pc->ctx, LIBNVME_LOG_WARN,
				    "%s:%u: key outside a [Model] section, ignored\n",
				    pc->path, line);
			return 0;
		}
		return set_key(pc, key, value, line);
	case SHR_INI_JUNK:
		libnvme_msg(pc->ctx, LIBNVME_LOG_WARN,
			    "%s:%u: malformed line, ignored\n", pc->path, line);
		/*
		 * A malformed section header ends the section before it: the
		 * keys after it don't belong to that [Model].
		 */
		if (!section)
			close_section(pc);
		return 0;
	}
	return 0;
}

static int load_file(struct libnvme_global_ctx *ctx,
		     struct libnvmf_vendor_defaults *vd, const char *path)
{
	struct parse_ctx pc = { .ctx = ctx, .vd = vd, .path = path };
	int r;

	r = shr_ini_parse_file(path, parse_event, &pc);
	close_section(&pc);
	if (r == -ENOMEM)
		return r;
	if (r < 0)
		libnvme_msg(ctx, LIBNVME_LOG_WARN, "%s: %s, ignored\n", path,
			    strerror(-r));
	return 0;
}

static int conf_filter(const struct dirent *d)
{
	size_t n = strlen(d->d_name);

	return d->d_name[0] != '.' && n > 5 &&
	       !strcmp(d->d_name + n - 5, ".conf");
}

struct vendor_file {
	char *name;
	char *path;
};

static int vendor_file_cmp(const void *a, const void *b)
{
	const struct vendor_file *fa = a, *fb = b;

	return strcmp(fa->name, fb->name);
}

/*
 * Add the files of @dir to @files, except those a directory before it
 * already gave a file of the same name.
 */
static int collect_dir(const char *dir, struct vendor_file **files,
		       size_t *nr)
{
	struct dirent **entries;
	int n, i, r = 0;

	n = scandir(dir, &entries, conf_filter, alphasort);
	if (n < 0)
		return 0;	/* no directory, no files */

	for (i = 0; i < n; i++) {
		const char *name = entries[i]->d_name;
		struct vendor_file *grown;
		bool seen = false;
		size_t j;

		for (j = 0; j < *nr && !seen; j++)
			seen = !strcmp((*files)[j].name, name);
		if (!r && !seen) {
			grown = realloc(*files, (*nr + 1) * sizeof(**files));
			if (!grown) {
				r = -ENOMEM;
			} else {
				*files = grown;
				grown[*nr].name = strdup(name);
				if (asprintf(&grown[*nr].path, "%s/%s", dir,
					     name) < 0)
					grown[*nr].path = NULL;
				if (!grown[*nr].name || !grown[*nr].path) {
					free(grown[*nr].name);
					free(grown[*nr].path);
					r = -ENOMEM;
				} else {
					(*nr)++;
				}
			}
		}
		free(entries[i]);
	}
	free(entries);
	return r;
}

/* A link to /dev/null turns off the file of that name. */
static bool masked(const char *path)
{
	char target[16];
	ssize_t n = readlink(path, target, sizeof(target) - 1);

	if (n < 0)
		return false;
	target[n] = '\0';
	return !strcmp(target, "/dev/null");
}

struct libnvmf_vendor_defaults *libnvmf_vendor_load(
		struct libnvme_global_ctx *ctx, const char *const *dirs,
		size_t nr_dirs)
{
	struct libnvmf_vendor_defaults *vd = calloc(1, sizeof(*vd));
	struct vendor_file *files = NULL;
	size_t nr = 0, i;
	int r = 0;

	if (!vd)
		return NULL;
	/*
	 * As udev rules and sysctl.d: a file of the same name in a directory
	 * before replaces one in a directory after it, and all files are read
	 * in the order of their names, whatever their directory.
	 */
	for (i = 0; i < nr_dirs && !r; i++)
		r = collect_dir(dirs[i], &files, &nr);
	if (!r)
		qsort(files, nr, sizeof(*files), vendor_file_cmp);
	for (i = 0; i < nr; i++) {
		if (!r && !masked(files[i].path))
			r = load_file(ctx, vd, files[i].path);
		free(files[i].name);
		free(files[i].path);
	}
	free(files);
	if (r < 0) {
		libnvmf_vendor_free(vd);
		return NULL;
	}
	return vd;
}

/*
 * The defaults of @ctx, loaded on first use: SYSCONFDIR, RUNDIR and the
 * shipped directory, or <test_base_dir>/vendor.d, <test_base_dir>/run/vendor.d
 * and <test_base_dir>/usr/vendor.d in a sandbox.
 */
static const struct libnvmf_vendor_defaults *vendor_defaults(
		struct libnvme_global_ctx *ctx)
{
	__cleanup_free char *etc = NULL, *run = NULL, *usr = NULL;
	const char *dirs[3] = {
		VENDOR_ETC_DIR, VENDOR_RUN_DIR, VENDOR_USR_DIR,
	};

	if (ctx->vendor)
		return ctx->vendor;
	if (ctx->test_base_dir) {
		if (asprintf(&etc, "%s/vendor.d", ctx->test_base_dir) < 0)
			etc = NULL;
		if (asprintf(&run, "%s/run/vendor.d", ctx->test_base_dir) < 0)
			run = NULL;
		if (asprintf(&usr, "%s/usr/vendor.d", ctx->test_base_dir) < 0)
			usr = NULL;
		if (!etc || !run || !usr)
			return NULL;
		dirs[0] = etc;
		dirs[1] = run;
		dirs[2] = usr;
	}
	ctx->vendor = libnvmf_vendor_load(ctx, dirs, 3);
	return ctx->vendor;
}

static int write_attr(const char *path, const char *value)
{
	size_t len = strlen(value);
	ssize_t n;
	int fd, r = 0;

	fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = write(fd, value, len);
	if (n < 0)
		r = -errno;
	else if ((size_t)n != len)
		r = -EIO;
	close(fd);
	return r;
}

/* A sysfs attribute without its trailing whitespace, as udev compares it. */
static char *read_attr(const char *path)
{
	char buf[256];
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0)
		return NULL;
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == ' ' ||
			 buf[n - 1] == '\t'))
		n--;
	buf[n] = '\0';
	return strdup(buf);
}

static char *read_attr_in(const char *dir, const char *name)
{
	__cleanup_free char *path = NULL;

	if (!dir || asprintf(&path, "%s/%s", dir, name) < 0)
		return NULL;
	return read_attr(path);
}

/*
 * Match @value as udev matches ATTR{...}=="@pattern": alternatives
 * separated by '|', each a shell glob (fnmatch(3)).
 */
static bool udev_match(const char *pattern, const char *value)
{
	__cleanup_free char *alts = strdup(pattern);
	char *alt, *save = NULL;

	if (!alts || !value)
		return false;
	for (alt = strtok_r(alts, "|", &save); alt;
	     alt = strtok_r(NULL, "|", &save))
		if (!fnmatch(alt, value, 0))
			return true;
	return false;
}

/* The nvme-subsystem directory that has controller @devname as a child. */
static char *subsys_dir(struct libnvme_global_ctx *ctx, const char *devname)
{
	const char *class = libnvme_subsys_sysfs_dir(ctx);
	struct dirent *d;
	char *found = NULL;
	DIR *dir;

	if (!class)
		return NULL;
	dir = opendir(class);
	if (!dir)
		return NULL;
	while (!found && (d = readdir(dir))) {
		__cleanup_free char *path = NULL;

		if (d->d_name[0] == '.')
			continue;
		if (asprintf(&path, "%s/%s/%s", class, d->d_name,
			     devname) < 0)
			break;
		if (!access(path, F_OK) &&
		    asprintf(&found, "%s/%s", class, d->d_name) < 0)
			found = NULL;
	}
	closedir(dir);
	return found;
}

/*
 * Set attribute @name at @path, of @dev (the controller, or for the
 * iopolicy its subsystem), to @want: through the privilege separation
 * helper if @ctx has one, as connect and disconnect do.
 */
static void set_attr(struct libnvme_global_ctx *ctx, const char *devname,
		     const char *dev, const char *path, const char *name,
		     const char *want, const struct vendor_model *m)
{
	__cleanup_free char *cur = read_attr(path);
	int r;

	/* The kernel shows a ctrl_loss_tmo of -1 as "off". */
	if (cur && (!strcmp(cur, want) ||
		    (!strcmp(cur, "off") && !strcmp(want, "-1"))))
		return;
	if (ctx->privsep)
		r = __libnvme_privsep_set_attr(ctx->privsep, dev, name, want);
	else
		r = write_attr(path, want);
	if (r < 0)
		libnvme_msg(ctx, LIBNVME_LOG_WARN,
			    "%s: cannot set %s %s: %s\n", devname, name, want,
			    strerror(-r));
	else
		libnvme_msg(ctx, LIBNVME_LOG_INFO, "%s: %s %s (%s)\n",
			    devname, name, want, m->source);
}

void libnvmf_vendor_apply(struct libnvme_global_ctx *ctx,
			  const struct libnvmf_vendor_defaults *vd,
			  const char *devname, bool keep_ctrl_loss_tmo)
{
	__cleanup_free char *ctrl = NULL, *model = NULL, *transport = NULL;
	__cleanup_free char *subsys = NULL, *subsystype = NULL;
	__cleanup_free char *tmo_path = NULL, *policy_path = NULL;
	const char *ctrl_class = libnvme_ctrl_sysfs_dir(ctx);
	unsigned int i;

	if (!vd || !vd->nr || !ctrl_class ||
	    asprintf(&ctrl, "%s/%s", ctrl_class, devname) < 0)
		return;
	if (asprintf(&tmo_path, "%s/ctrl_loss_tmo", ctrl) < 0)
		return;
	model = read_attr_in(ctrl, "model");
	transport = read_attr_in(ctrl, "transport");
	if (!model)
		return;
	subsys = subsys_dir(ctx, devname);
	subsystype = read_attr_in(subsys, "subsystype");
	if (subsys && asprintf(&policy_path, "%s/iopolicy", subsys) < 0)
		policy_path = NULL;

	/* Later files and sections win, as later udev rules do. */
	for (i = 0; i < vd->nr; i++) {
		const struct vendor_model *m = &vd->models[i];

		if (!udev_match(m->model, model) ||
		    (m->transport && !udev_match(m->transport, transport)))
			continue;
		/* Only an NVM subsystem, as ATTR{subsystype}=="nvm" */
		if (m->iopolicy && policy_path && subsystype &&
		    !strcmp(subsystype, "nvm"))
			set_attr(ctx, devname, strrchr(subsys, '/') + 1,
				 policy_path, "iopolicy", m->iopolicy, m);
		if (m->ctrl_loss_tmo && !keep_ctrl_loss_tmo &&
		    !(transport && !strcmp(transport, "loop")))
			set_attr(ctx, devname, devname, tmo_path,
				 "ctrl_loss_tmo", m->ctrl_loss_tmo, m);
	}
}

void libnvmf_vendor_apply_connected(struct libnvme_global_ctx *ctx,
				    int instance, int ctrl_loss_tmo)
{
	char devname[32];

	snprintf(devname, sizeof(devname), "nvme%d", instance);
	libnvmf_vendor_apply(ctx, vendor_defaults(ctx), devname,
			     ctrl_loss_tmo != NVMF_DEF_CTRL_LOSS_TMO);
}
