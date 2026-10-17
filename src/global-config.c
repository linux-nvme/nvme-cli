// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * /etc/nvme/nvme-cli.conf: a global INI config file for the global options
 * (global-options.c, struct nvme_args). Its keys are their long names.
 * Values from this file become the new defaults; any command-line flag
 * still overrides them: the global options in front of the command are
 * parsed before the file is loaded, the file skips those, and the options
 * of the command are parsed afterwards.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/ini-util.h>
#include <shared/parse-util.h>
#include <shared/string-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "global-config.h"

struct global_config_ctx {
	const char *path;
};

/*
 * The strings of the global options which a file sets point into its
 * text, so the text of every loaded file is kept.
 */
struct config_file {
	struct config_file *next;
	char *text;
};

static struct config_file *config_files;

/*
 * The count of an option given on the command line, which the last valid
 * value of the files adds to.
 */
struct given_count {
	struct given_count *next;
	int *count;
	int given;
};

static struct given_count *given_counts;

void nvme_global_config_free(void)
{
	struct config_file *file;
	struct given_count *g;

	while (given_counts) {
		g = given_counts;
		given_counts = g->next;
		free(g);
	}

	while (config_files) {
		file = config_files;
		config_files = file->next;
		free(file->text);
		free(file);
	}
}

/* A number of the config file up to @max, -EINVAL if it is none */
static int parse_uint(const char *value, uint64_t max, uint64_t *out)
{
	return shr_parse_u64(value, max, out) ? -EINVAL : 0;
}

/* The command-line count of @count, before a file added to it */
static int *given_count(int *count)
{
	struct given_count *g;

	for (g = given_counts; g; g = g->next)
		if (g->count == count)
			return &g->given;

	g = calloc(1, sizeof(*g));
	if (!g)
		return NULL;
	g->count = count;
	g->given = *count;
	g->next = given_counts;
	given_counts = g;

	return &g->given;
}

/* The keys are the global options which the help shows */
static struct argconfig_commandline_options *find_key(const char *key)
{
	struct argconfig_commandline_options *s;

	for (s = argconfig_get_global_options(); s && s->option; s++) {
		if (s->config_type == CFG_GROUP_SEPARATOR || s->deprecated)
			continue;
		if (!strcmp(s->option, key))
			return s;
	}

	return NULL;
}

/* Set the global option @s to @value, warn about an invalid one */
static int set_value(struct global_config_ctx *gc,
		     struct argconfig_commandline_options *s, const char *k,
		     const char *value, unsigned int line)
{
	uint64_t uval;
	bool bval;
	int err;

	/* 'timeout = infinite' like on the command line */
	if (argconfig_set_value_name(s, value))
		return 0;

	switch (s->config_type) {
	case CFG_FLAG:
		err = shr_parse_bool(value, &bval);
		if (err)
			goto bad_value;
		*(bool *)s->default_value = bval;
		break;
	case CFG_INCREMENT:
		/* the number of times the option is given */
		err = parse_uint(value, INT_MAX, &uval);
		if (err)
			goto bad_value;
		*(int *)s->default_value = uval;
		break;
	case CFG_POSITIVE:
		err = parse_uint(value, UINT32_MAX, &uval);
		if (!err && !argconfig_in_range(s, uval))
			err = -EINVAL;
		if (err)
			goto bad_value;
		*(uint32_t *)s->default_value = uval;
		break;
	case CFG_STRING:
	case CFG_FILE:
	case CFG_DIR:
		*(char **)s->default_value = (char *)value;
		break;
	default:
		fprintf(stderr, "%s:%u: key \"%s\" can't be set, ignoring\n",
			gc->path, line, k ? k : "");
		break;
	}

	return 0;

bad_value:
	if (err == -EINVAL) {
		__cleanup_free char *v = shr_escape(value);

		fprintf(stderr,
			"%s:%u: invalid value \"%s\" for \"%s\", ignoring\n",
			gc->path, line, v ? v : "", k ? k : "");
		err = 0;
	}
	return err;
}

static int apply_kv(struct global_config_ctx *gc, const char *key,
		     const char *value, unsigned int line)
{
	struct argconfig_commandline_options *s = find_key(key);
	__cleanup_free char *k = shr_escape(key);
	union {
		bool b;
		int i;
		uint32_t u;
		char *str;
	} scratch = {};

	if (!s || !s->default_value) {
		fprintf(stderr, "%s:%u: unknown key \"%s\", ignoring\n",
			gc->path, line, k ? k : "");
		return 0;
	}

	if (!argconfig_given(argconfig_get_global_options(),
			     s->default_value))
		return set_value(gc, s, k, value, line);

	/*
	 * An option given on the command line wins, the value is checked
	 * all the same. A count adds up as if the file came first: the
	 * last valid value of the file adds to the count given.
	 */
	{
		struct argconfig_commandline_options tmp = *s;
		int *count = s->default_value, *given;
		int err;

		/* an invalid value leaves it alone */
		scratch.i = -1;
		tmp.default_value = &scratch;
		err = set_value(gc, &tmp, k, value, line);
		if (err || s->config_type != CFG_INCREMENT || scratch.i < 0)
			return err;

		given = given_count(count);
		if (!given)
			return -ENOMEM;
		*count = scratch.i > INT_MAX - *given ?
			INT_MAX : *given + scratch.i;
		return 0;
	}
}

static int global_config_event(enum shr_ini_event event, const char *section,
				const char *key, const char *value,
				unsigned int line, void *user_data)
{
	struct global_config_ctx *gc = user_data;
	__cleanup_free char *k = NULL;

	switch (event) {
	case SHR_INI_SECTION:
		return 0;
	case SHR_INI_KV:
		if (section && !strcmp(section, "Global"))
			return apply_kv(gc, key, value, line);
		k = shr_escape(key);
		fprintf(stderr,
			"%s:%u: \"%s\" outside the [Global] section, ignoring\n",
			gc->path, line, k ? k : "");
		return 0;
	case SHR_INI_JUNK:
		k = shr_escape(key);
		fprintf(stderr, "%s:%u: malformed line \"%s\", ignoring\n",
			gc->path, line, k ? k : "");
		return 0;
	}

	return 0;
}

/* Parse @text in place and keep it */
static int load_text(char *text, const char *name)
{
	struct global_config_ctx gc = { .path = name };
	struct config_file *file;

	file = calloc(1, sizeof(*file));
	if (!file) {
		free(text);
		return -ENOMEM;
	}
	file->text = text;
	file->next = config_files;
	config_files = file;

	return shr_ini_parse_inplace(text, global_config_event, &gc);
}

int nvme_load_global_config_from(const char *path)
{
	char *text;
	int err;

	err = shr_ini_read_file(path, &text);
	if (err)
		return err == -ENOENT ? 0 : err;

	return load_text(text, path);
}

int nvme_load_global_config_buf(const char *text, const char *name)
{
	char *copy = strdup(text);

	if (!copy)
		return -ENOMEM;

	return load_text(copy, name);
}

int nvme_load_global_config(void)
{
	return nvme_load_global_config_from(PATH_NVME_CLI_INI);
}
