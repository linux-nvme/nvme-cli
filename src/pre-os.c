// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libnvme.h>

#include <shared/hash-util.h>

#include "args.h"
#include "cleanup.h"
#include "global-ctx.h"
#include "pre-os.h"

#define PATH_PRE_OS_CONF	RUNDIR "/nvme/pre-os.conf"

const char *nvme_pre_os_conf_path(void)
{
	static char *cache;
	const char *base = nvme_test_base_dir();

	if (!base)
		return PATH_PRE_OS_CONF;
	if (!cache && asprintf(&cache, "%s/pre-os.conf", base) < 0) {
		cache = NULL;
		return PATH_PRE_OS_CONF;
	}

	return cache;
}

bool nvme_pre_os_records(const char *owner)
{
	__cleanup_free char *path = NULL;
	const char *base = nvme_test_base_dir();

	if (!owner || !libnvmf_owner_equal(owner, "pre-os"))
		return false;
	if (nvme_args.dry_run)
		return false;
	if (!base)
		return !access("/etc/initrd-release", F_OK);
	if (asprintf(&path, "%s/etc/initrd-release", base) < 0)
		return false;

	return !access(path, F_OK);
}

static int mkdir_one(const char *path, mode_t mode)
{
	if (mkdir(path, mode) && errno != EEXIST)
		return -errno;
	return 0;
}

struct copy_ctx {
	struct libnvmf_config_emitter *emitter;
	const char *skip;	/* canonical TID of the connection replaced */
	int err;
};

/* Copy a connection recorded before, except the one recorded again. */
static void copy_conn(const struct libnvmf_config_conn *conn, void *user_data)
{
	struct copy_ctx *cc = user_data;
	struct libnvmf_tid *tid = NULL;
	bool same;

	if (cc->err)
		return;
	if (libnvmf_tid_from_fields(libnvmf_config_conn_get_transport(conn),
			libnvmf_config_conn_get_traddr(conn),
			libnvmf_config_conn_get_trsvcid(conn),
			libnvmf_config_conn_get_subsysnqn(conn),
			libnvmf_config_conn_get_host_traddr(conn),
			libnvmf_config_conn_get_host_iface(conn),
			libnvmf_config_conn_get_hostnqn(conn),
			libnvmf_config_conn_get_hostid(conn), &tid) || !tid) {
		cc->err = -EINVAL;
		return;
	}
	same = !strcmp(libnvmf_tid_get_canonical(tid), cc->skip);
	libnvmf_tid_free(tid);
	if (same)
		return;

	cc->err = libnvmf_config_emit_add(cc->emitter,
			libnvmf_config_conn_is_dc(conn),
			libnvmf_config_conn_get_transport(conn),
			libnvmf_config_conn_get_traddr(conn),
			libnvmf_config_conn_get_trsvcid(conn),
			libnvmf_config_conn_get_subsysnqn(conn),
			libnvmf_config_conn_get_host_traddr(conn),
			libnvmf_config_conn_get_host_iface(conn),
			libnvmf_config_conn_get_hostnqn(conn),
			libnvmf_config_conn_get_hostid(conn),
			libnvmf_config_conn_get_params(conn), NULL);
}

/*
 * The configuration format has one host per file, so each host of the
 * pre-OS environment gets a drop-in of its own, named after it, with
 * all its connections. Several nvme can run at once in the initrd (FC
 * discovery events, autoconnect): a lock on the directory serializes
 * the update of a drop-in.
 */
struct strip_ctx {
	struct libnvmf_params *params;
	bool tls_key_inline;
	int err;
};

static void strip_param(const char *key, const char *value, void *user_data)
{
	struct strip_ctx *sc = user_data;

	if (sc->err)
		return;
	if (!strcmp(key, "kxchap-secret") ||
	    !strcmp(key, "kxchap-ctrl-secret") ||
	    (!strcmp(key, "tls-key") && sc->tls_key_inline))
		return;
	sc->err = libnvmf_params_set(sc->params, key, value);
}

/*
 * @params without the credentials: the pre-OS environment loads the keys
 * into the kernel's keyring, and in the OS environment nvme-keysd does.
 */
static struct libnvmf_params *strip_credentials(
		const struct libnvmf_params *params)
{
	struct strip_ctx sc = { .params = libnvmf_params_new() };
	const char *src;

	if (!sc.params)
		return NULL;
	if (params) {
		src = libnvmf_params_get(params, "tls-key-source");
		sc.tls_key_inline = !src || !*src || !strcmp(src, "inline");
		libnvmf_params_for_each(params, strip_param, &sc);
	}
	if (sc.err) {
		libnvmf_params_free(sc.params);
		return NULL;
	}

	return sc.params;
}

int nvme_pre_os_record(struct libnvme_global_ctx *ctx, bool is_dc,
		const struct libnvmf_tid *tid,
		const struct libnvmf_params *params)
{
	struct libnvmf_config_emitter *emitter = NULL;
	struct libnvmf_params *clean = NULL;
	struct libnvmf_config *old = NULL;
	const char *nqn = libnvmf_tid_get_subsysnqn(tid);
	__cleanup_free char *parent = NULL;
	__cleanup_free char *dir = NULL;
	__cleanup_free char *file = NULL;
	__cleanup_free char *host = NULL;
	const char *conf = nvme_pre_os_conf_path();
	struct copy_ctx cc = { 0 };
	char *slash;
	int ret, dfd;

	/*
	 * The kernel takes a connection to the well-known discovery NQN for
	 * a discovery controller, also without --discovery.
	 */
	if (nqn && !strcmp(nqn, NVME_DISC_SUBSYS_NAME))
		is_dc = true;

	parent = strdup(conf);
	if (!parent)
		return -ENOMEM;
	slash = strrchr(parent, '/');
	if (slash && slash != parent) {
		*slash = '\0';
		ret = mkdir_one(parent, 0755);
		if (ret)
			return ret;
	}
	if (asprintf(&dir, "%s.d", conf) < 0) {
		dir = NULL;
		return -ENOMEM;
	}
	ret = mkdir_one(dir, 0700);
	if (ret)
		return ret;
	if (asprintf(&host, "%s %s",
		     libnvmf_tid_get_hostnqn(tid) ?: "",
		     libnvmf_tid_get_hostid(tid) ?: "") < 0) {
		host = NULL;
		return -ENOMEM;
	}
	if (asprintf(&file, "%s/%016" PRIx64 ".conf", dir,
		     shr_fnv1a_64(host, strlen(host))) < 0) {
		file = NULL;
		return -ENOMEM;
	}

	dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0)
		return -errno;
	if (flock(dfd, LOCK_EX) < 0) {
		ret = -errno;
		goto out;
	}

	emitter = libnvmf_config_emit_new(ctx);
	if (!emitter) {
		ret = -ENOMEM;
		goto out;
	}
	if (!access(file, F_OK)) {
		ret = libnvmf_config_read(ctx, file, &old);
		if (ret)
			goto out;
		cc.emitter = emitter;
		cc.skip = libnvmf_tid_get_canonical(tid);
		libnvmf_config_conn_for_each(old, copy_conn, &cc);
		ret = cc.err;
		if (ret)
			goto out;
	}

	clean = strip_credentials(params);
	if (!clean) {
		ret = -ENOMEM;
		goto out;
	}
	ret = libnvmf_config_emit_add(emitter, is_dc,
			libnvmf_tid_get_transport(tid),
			libnvmf_tid_get_traddr(tid),
			libnvmf_tid_get_trsvcid(tid),
			libnvmf_tid_get_subsysnqn(tid),
			libnvmf_tid_get_host_traddr(tid),
			libnvmf_tid_get_host_iface(tid),
			libnvmf_tid_get_hostnqn(tid),
			libnvmf_tid_get_hostid(tid), clean, NULL);
	if (!ret)
		ret = libnvmf_config_emit_write_file(emitter, file);
out:
	libnvmf_params_free(clean);
	libnvmf_config_emit_free(emitter);
	libnvmf_config_free(old);
	close(dfd);	/* drops the lock */
	return ret;
}
