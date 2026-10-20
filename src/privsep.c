// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * Privilege separation: when root runs nvme-cli on behalf of a user and
 * the command does not need root, nvme-cli starts the libnvme privsep
 * helper, drops the privileges and opens the devices through the helper.
 *
 * The decision runs first in main() and uses only the environment and the
 * command main() looked up, so that neither the configuration file nor
 * the options of the command are parsed with root privileges.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef CONFIG_PRIVSEP
#include <grp.h>
#include <sys/auxv.h>
#endif

#include <libnvme.h>
#ifdef CONFIG_PRIVSEP
#include <libnvme-privsep.h>
#endif

#include "argconfig.h"
#include "args.h"
#include "plugin.h"
#include "privsep.h"

#ifdef CONFIG_PRIVSEP
static struct libnvme_privsep *privsep;
#endif

/* MI talks to the MCTP sockets itself, which needs privileges. */
static bool mi_device(const struct plugin_call *call)
{
	unsigned int net, eid;
	int i;

	for (i = 1; i < call->argc; i++)
		if (sscanf(call->argv[i], "mctp:%u,%u", &net, &eid) == 2)
			return true;

	return false;
}

/* Whether the command main() looked up may run without root */
static bool privsep_wanted(const struct plugin_call *call)
{
	return call->action == PLUGIN_RUN && !call->cmd->needs_root &&
		!mi_device(call);
}

#ifdef CONFIG_PRIVSEP
/*
 * Helper binary for the test suite. Honored only when nvme-cli runs
 * unprivileged, where the helper gains nothing over nvme-cli itself.
 */
#define PRIVSEP_TEST_HELPER_ENV "NVME_PRIVSEP_TEST_HELPER"

static void privsep_free(void)
{
	libnvme_privsep_free(privsep);
	privsep = NULL;
}

/* Accepts decimal ids only, never (uid_t)-1 or (gid_t)-1. */
static int parse_id(const char *str, unsigned int *id)
{
	unsigned long v;
	char *end;

	if (!str || *str < '0' || *str > '9')
		return -EINVAL;

	errno = 0;
	v = strtoul(str, &end, 10);
	if (errno || *end || v >= (unsigned int)-1)
		return -EINVAL;

	*id = v;
	return 0;
}

static int env_target(const char *uid_env, const char *gid_env,
		uid_t *uid, gid_t *gid)
{
	unsigned int u, g;

	if (parse_id(getenv(uid_env), &u) || parse_id(getenv(gid_env), &g)) {
		argconfig_error("invalid %s or %s", uid_env, gid_env);
		return -EINVAL;
	}
	*uid = u;
	*gid = g;

	return 0;
}

/*
 * The user to drop to: the user who ran sudo, or the user root named in
 * the environment. Only root itself, not a setuid nvme-cli, can be
 * trusted to set the environment.
 *
 * Return: 1 if there is one, 0 to keep running as root, or a negative
 * error code.
 */
static int privsep_target(uid_t *uid, gid_t *gid)
{
	int ret;

	if (getuid() || geteuid() || getauxval(AT_SECURE))
		return 0;

	if (getenv("SUDO_UID"))
		ret = env_target("SUDO_UID", "SUDO_GID", uid, gid);
	else if (getenv("NVME_PRIVSEP_UID"))
		ret = env_target("NVME_PRIVSEP_UID", "NVME_PRIVSEP_GID",
				 uid, gid);
	else
		return 0;
	if (ret)
		return ret;

	return *uid ? 1 : 0;
}

static int privsep_drop(uid_t uid, gid_t gid)
{
	uid_t ruid, euid, suid;

	/*
	 * The supplementary groups become the target group only: looking
	 * up the ones of the target user would run NSS as root.
	 */
	if (setgroups(1, &gid) || setresgid(gid, gid, gid) ||
	    setresuid(uid, uid, uid))
		return -errno;

	/* The drop must not be reversible. */
	if (!setuid(0) || getresuid(&ruid, &euid, &suid) ||
	    ruid != uid || euid != uid || suid != uid)
		return -EPERM;

	return 0;
}

static const char *test_helper(void)
{
	if (getauxval(AT_SECURE) || !geteuid())
		return NULL;

	return getenv(PRIVSEP_TEST_HELPER_ENV);
}

static int privsep_start(void)
{
	const char *helper = test_helper();
	uid_t uid;
	gid_t gid;
	int ret;

	if (!helper) {
		ret = privsep_target(&uid, &gid);
		if (ret <= 0)
			return ret;
	}

	ret = libnvme_privsep_spawn(helper, &privsep);
	if (ret) {
		argconfig_error(
			"failed to start the privilege separation helper: %s",
			libnvme_strerror(-ret));
		return ret;
	}
	atexit(privsep_free);

	if (helper)
		return 0;

	ret = privsep_drop(uid, gid);
	if (ret)
		argconfig_error("failed to drop privileges: %s",
				libnvme_strerror(-ret));

	return ret;
}
#else
static int privsep_start(void)
{
	return 0;
}
#endif

static bool privsep_active(void)
{
#ifdef CONFIG_PRIVSEP
	return privsep;
#else
	return false;
#endif
}

int nvme_privsep_init(const struct plugin_call *call)
{
	if (!privsep_wanted(call))
		return 0;

	return privsep_start();
}

int nvme_privsep_check(struct command *cmd)
{
	if (!privsep_active() || !cmd->needs_root)
		return 0;

	argconfig_error("'%s' needs root privileges", cmd->name);
	return -EPERM;
}

void nvme_privsep_attach(struct libnvme_global_ctx *ctx)
{
#ifdef CONFIG_PRIVSEP
	if (privsep)
		libnvme_set_privsep(ctx, privsep);
#endif
}
