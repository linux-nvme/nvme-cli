// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * /etc/nvme/nvme-cli.conf: a global INI config file for the options
 * defined by NVME_ARGS() in nvme.h (struct nvme_args). Values from this
 * file become the new defaults; any command-line flag still overrides
 * them, since this is loaded before argument parsing runs.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ini.h>
#include <parse-util.h>

#include "global-config.h"
#include "args.h"

struct global_config_ctx {
	const char *path;
};

static int parse_uint(const char *value, unsigned int *out)
{
	unsigned long v;
	char *end;

	if (!value || !*value || *value == '-')
		return -EINVAL;

	errno = 0;
	v = strtoul(value, &end, 0);
	if (errno || *end || v > (unsigned long)~0U)
		return -EINVAL;

	*out = (unsigned int)v;
	return 0;
}

static int apply_kv(struct global_config_ctx *gc, const char *key,
		     const char *value, unsigned int line)
{
	unsigned int uval;
	bool bval;
	char *dup;
	int err;

	if (!strcmp(key, "verbose")) {
		err = parse_uint(value, &uval);
		if (err)
			goto bad_value;
		nvme_args.verbose = uval;
	} else if (!strcmp(key, "quiet")) {
		err = parse_bool(value, &bval);
		if (err)
			goto bad_value;
		nvme_args.quiet = bval;
	} else if (!strcmp(key, "output-format")) {
		dup = strdup(value);
		if (!dup)
			return -ENOMEM;
		nvme_args.output_format = dup;
	} else if (!strcmp(key, "timeout")) {
		err = parse_uint(value, &uval);
		if (err)
			goto bad_value;
		nvme_args.timeout = uval;
	} else if (!strcmp(key, "dry-run")) {
		err = parse_bool(value, &bval);
		if (err)
			goto bad_value;
		nvme_args.dry_run = bval;
	} else if (!strcmp(key, "no-retries")) {
		err = parse_bool(value, &bval);
		if (err)
			goto bad_value;
		nvme_args.no_retries = bval;
	} else if (!strcmp(key, "no-ioctl-probing")) {
		err = parse_bool(value, &bval);
		if (err)
			goto bad_value;
		nvme_args.no_ioctl_probing = bval;
	} else if (!strcmp(key, "output-format-version")) {
		err = parse_uint(value, &uval);
		if (err)
			goto bad_value;
		nvme_args.output_format_ver = uval;
	} else if (!strcmp(key, "set-options")) {
		dup = strdup(value);
		if (!dup)
			return -ENOMEM;
		nvme_args.set_options = dup;
	} else {
		fprintf(stderr, "%s:%u: unknown key \"%s\", ignoring\n",
			gc->path, line, key);
	}

	return 0;

bad_value:
	if (err == -EINVAL) {
		fprintf(stderr,
			"%s:%u: invalid value \"%s\" for \"%s\", ignoring\n",
			gc->path, line, value, key);
		err = 0;
	}
	return err;
}

static int global_config_event(enum ini_event event, const char *section,
				const char *key, const char *value,
				unsigned int line, void *user_data)
{
	struct global_config_ctx *gc = user_data;

	switch (event) {
	case INI_SECTION:
		return 0;
	case INI_KV:
		if (section && !strcmp(section, "Global"))
			return apply_kv(gc, key, value, line);
		fprintf(stderr,
			"%s:%u: \"%s\" outside the [Global] section, ignoring\n",
			gc->path, line, key);
		return 0;
	case INI_JUNK:
		fprintf(stderr, "%s:%u: malformed line \"%s\", ignoring\n",
			gc->path, line, key);
		return 0;
	}

	return 0;
}

int nvme_load_global_config_from(const char *path)
{
	struct global_config_ctx gc = { .path = path };
	int err;

	err = ini_parse_file(path, global_config_event, &gc);
	if (err && err == -ENOENT)
		err = 0;
	return err;
}

int nvme_load_global_config(void)
{
	return nvme_load_global_config_from(PATH_NVME_CLI_INI);
}
