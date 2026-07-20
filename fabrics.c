// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016 Intel Corporation. All rights reserved.
 * Copyright (c) 2016 HGST, a Western Digital Company.
 * Copyright (c) 2016 Samsung Electronics Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This file implements the discovery controller feature of NVMe over
 * Fabrics specification standard.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#ifdef NVME_HAVE_NETDB
#include <netdb.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include <libnvme.h>

#ifdef NVME_HAVE_LIBKMOD
#include <libkmod.h>
#endif

#include "common.h"
#include "config-convert.h"
#include "nvme.h"
#include "nvme-print.h"
#include "fabrics.h"
#include "util/cleanup.h"
#include "logging.h"
#include "util/sighdl.h"

#define PATH_NVMF_RUNDIR	RUNDIR "/nvme"
#define MAX_DISC_ARGS		32
#define MAX_DISC_RETRIES	10

#define NVMF_DEF_DISC_TMO	30

/* Name of file to output log pages in their raw format */
static char *raw;
static bool persistent;
static bool quiet;
static bool dump_config;

static const char *nvmf_tport		= "transport type";
static const char *nvmf_traddr		= "transport address";
static const char *nvmf_nqn		= "subsystem nqn";
static const char *nvmf_trsvcid		= "transport service id (e.g. IP port)";
static const char *nvmf_htraddr		= "host traddr (e.g. FC WWN's)";
static const char *nvmf_hiface		= "host interface (for tcp transport)";
static const char *nvmf_hostnqn		= "user-defined hostnqn";
static const char *nvmf_hostid		= "user-defined hostid (if default not used)";
static const char *nvmf_hostkey		= "user-defined dhchap key (if default not used)";
static const char *nvmf_ctrlkey		= "user-defined dhchap controller key (for bi-directional authentication)";
static const char *nvmf_nr_io_queues	= "number of io queues to use (default is core count)";
static const char *nvmf_nr_write_queues	= "number of write queues to use (default 0)";
static const char *nvmf_nr_poll_queues	= "number of poll queues to use (default 0)";
static const char *nvmf_queue_size	= "number of io queue elements to use (default 128)";
static const char *nvmf_keep_alive_tmo	= "keep alive timeout period in seconds";
static const char *nvmf_reconnect_delay	= "reconnect timeout period in seconds";
static const char *nvmf_ctrl_loss_tmo	= "controller loss timeout period in seconds";
static const char *nvmf_fast_io_fail_tmo = "fast I/O fail timeout (default off)";
static const char *nvmf_tos		= "type of service";
static const char *nvmf_keyring		= "Keyring for TLS key lookup (key id or keyring name)";
static const char *nvmf_tls_key		= "TLS key to use (key id or key in interchange format)";
static const char *nvmf_tls_key_legacy	= "TLS key to use (key id)";
static const char *nvmf_tls_key_identity = "TLS key identity";
static const char *nvmf_dup_connect	= "allow duplicate connections between same transport host and subsystem port";
static const char *nvmf_disable_sqflow	= "disable controller sq flow control (default false)";
static const char *nvmf_hdr_digest	= "enable transport protocol header digest (TCP transport)";
static const char *nvmf_data_digest	= "enable transport protocol data digest (TCP transport)";
static const char *nvmf_tls		= "enable TLS";
static const char *nvmf_concat		= "enable secure concatenation";
static const char *nvmf_config_file	= "Use specified JSON configuration file or 'none' to disable";

#define NVMF_ARGS(n, f, ...)                                                                  \
	NVME_ARGS(n,                                                                              \
		OPT_STRING("transport",       't', "STR", &f.transport,     nvmf_tport),         \
		OPT_STRING("nqn",             'n', "STR", &f.subsysnqn,     nvmf_nqn),           \
		OPT_STRING("traddr",          'a', "STR", &f.traddr,        nvmf_traddr),        \
		OPT_STRING("trsvcid",         's', "STR", &f.trsvcid,       nvmf_trsvcid),       \
		OPT_STRING("host-traddr",     'w', "STR", &f.host_traddr,   nvmf_htraddr),       \
		OPT_STRING("host-iface",      'f', "STR", &f.host_iface,    nvmf_hiface),        \
		OPT_STRING("hostnqn",         'q', "STR", &f.hostnqn,       nvmf_hostnqn),       \
		OPT_STRING("hostid",          'I', "STR", &f.hostid,        nvmf_hostid),        \
		OPT_STRING("dhchap-secret",   'S', "STR", &f.hostkey,       nvmf_hostkey),       \
		OPT_STRING("dhchap-ctrl-secret", 'C', "STR", &f.ctrlkey,    nvmf_ctrlkey),       \
		OPT_STRING("keyring",          0,  "STR", &f.keyring,       nvmf_keyring),       \
		OPT_STRING("tls-key",          0,  "STR", &f.tls_key,       nvmf_tls_key),       \
		OPT_STRING("tls-key-identity", 0,  "STR", &f.tls_key_identity, nvmf_tls_key_identity), \
		OPT_INT("nr-io-queues",       'i', &f.nr_io_queues,       nvmf_nr_io_queues),    \
		OPT_INT("nr-write-queues",    'W', &f.nr_write_queues,    nvmf_nr_write_queues), \
		OPT_INT("nr-poll-queues",     'P', &f.nr_poll_queues,     nvmf_nr_poll_queues),  \
		OPT_INT("queue-size",         'Q', &f.queue_size,         nvmf_queue_size),      \
		OPT_INT("keep-alive-tmo",     'k', &f.keep_alive_tmo,     nvmf_keep_alive_tmo),  \
		OPT_INT("reconnect-delay",    'c', &f.reconnect_delay,    nvmf_reconnect_delay), \
		OPT_INT("ctrl-loss-tmo",      'l', &f.ctrl_loss_tmo,      nvmf_ctrl_loss_tmo),   \
		OPT_INT("fast_io_fail_tmo",   'F', &f.fast_io_fail_tmo,   nvmf_fast_io_fail_tmo),\
		OPT_INT("tos",                'T', &f.tos,                nvmf_tos),             \
		OPT_INT("tls_key",              0, &f.tls_key_id,         nvmf_tls_key_legacy),  \
		OPT_FLAG("duplicate-connect", 'D', &f.duplicate_connect,  nvmf_dup_connect),     \
		OPT_FLAG("disable-sqflow",      0, &f.disable_sqflow,     nvmf_disable_sqflow),  \
		OPT_FLAG("hdr-digest",        'g', &f.hdr_digest,         nvmf_hdr_digest),      \
		OPT_FLAG("data-digest",       'G', &f.data_digest,        nvmf_data_digest),     \
		OPT_FLAG("tls",                 0, &f.tls,                nvmf_tls),             \
		OPT_FLAG("concat",              0, &f.concat,             nvmf_concat),          \
		##__VA_ARGS__                                                                    \
	)

static void nvmf_default_args(struct nvmf_args *fa)
{
	fa->tos = -1;
	fa->ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO;
}

static void save_discovery_log(char *raw, struct nvmf_discovery_log *log)
{
	uint64_t numrec = le64_to_cpu(log->numrec);
	int fd, len, ret;

	fd = open(raw, O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (fd < 0) {
		nvme_show_error("failed to open %s: %s", raw, libnvme_strerror(errno));
		return;
	}

	len = sizeof(struct nvmf_discovery_log) + numrec * sizeof(struct nvmf_disc_log_entry);

	ret = write(fd, log, len);
	if (ret < 0)
		nvme_show_error("failed to write to %s: %s",
			raw, libnvme_strerror(errno));
	else
		nvme_show_verbose_info("Discovery log is saved to %s", raw);

	close(fd);
}

static int setup_common_context(struct libnvmf_context *fctx,
		struct nvmf_args *fa);

struct hook_fabrics_data {
	struct nvmf_args *fa;
	nvme_print_flags_t flags;
	bool quiet;
	char *raw;
	char **argv;
	FILE *f;
	bool idempotent;
};

static bool hook_decide_retry(struct libnvmf_context *fctx, int err,
		void *user_data)
{
	if (err == -EAGAIN || (err == -EINTR && !nvme_sigint_received)) {
		print_debug("libnvmf_add_ctrl returned '%s'\n", libnvme_strerror(-err));
		return true;
	}

	return false;
}

static void hook_connected(struct libnvmf_context *fctx,
		struct libnvme_ctrl *c, void *user_data)
{
	struct hook_fabrics_data *hfd = user_data;

	if (hfd->quiet)
		return;

	if (hfd->flags == NORMAL) {
		nvme_show_verbose_info("connecting to device: %s", libnvme_ctrl_get_name(c));
		return;
	}

#ifdef CONFIG_JSONC
	if (hfd->flags == JSON) {
		struct json_object *root;

		root = json_create_object();

		json_object_add_value_string(root, "device",
			libnvme_ctrl_get_name(c));

		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
	}
#endif
}

static void hook_already_connected(struct libnvmf_context *fctx,
		struct libnvme_host *host, const char *subsysnqn,
		const char *transport, const char *traddr,
		const char *trsvcid, void *user_data)
{
	struct hook_fabrics_data *hfd = user_data;

	if (quiet)
		return;

	if (hfd->idempotent) {
		nvme_show_verbose_info(
			"already connected to hostnqn=%s,nqn=%s,transport=%s,traddr=%s,trsvcid=%s",
			libnvme_host_get_hostnqn(host), subsysnqn,
			transport, traddr, trsvcid);
		return;
	}

	nvme_show_error("already connected to hostnqn=%s,nqn=%s,transport=%s,traddr=%s,trsvcid=%s",
		libnvme_host_get_hostnqn(host), subsysnqn,
		transport, traddr, trsvcid);
}

static void hook_discovery_log(struct libnvmf_context *fctx,
		bool connect, struct nvmf_discovery_log *log,
		uint64_t numrec, void *user_data)
{
	struct hook_fabrics_data *hfd = user_data;

	if (hfd->raw)
		save_discovery_log(hfd->raw, log);
	else if (!connect)
		nvme_show_discovery_log(log, numrec, hfd->flags);
}

static int hook_parser_init(struct libnvmf_context *dctx, void *user_data)
{
	struct hook_fabrics_data *hfd = user_data;

	hfd->f = fopen(PATH_NVMF_DISC, "r");
	if (hfd->f == NULL) {
		nvme_show_error("No params given and no %s", PATH_NVMF_DISC);
		return -ENOENT;
	}

	hfd->argv = calloc(MAX_DISC_ARGS, sizeof(char *));
	if (!hfd->argv)
		return -1;

	hfd->argv[0] = "discover";

	return 0;
}

static void hook_parser_cleanup(struct libnvmf_context *fctx, void *user_data)
{
	struct hook_fabrics_data *hfd = user_data;

	free(hfd->argv);
	fclose(hfd->f);
}

/*
 * Resolve *addr in place if it names a tcp/rdma hostname; left untouched for
 * any other transport, a NULL/"none" address, or one that is already
 * numeric. Resolution is the caller's job, not libnvme's -- this is where
 * that happens.
 *
 * Deliberately crude and sequential: one blocking getaddrinfo() call at a
 * time, no threads. nvme-cli is a one-shot tool, so multiple discovery.conf
 * lines simply resolve one after another.
 */
static int nvmf_resolve_addr(const char *transport, const char **addr)
{
#ifdef NVME_HAVE_NETDB
	struct addrinfo hints = { .ai_family = AF_UNSPEC };
	struct addrinfo *host_info = NULL;
	char addrstr[NVMF_TRADDR_SIZE];
	const char *p = NULL;
	char *resolved;
	int ret;
#endif

	if (!*addr || !transport)
		return 0;
	if (strcmp(transport, "tcp") && strcmp(transport, "rdma"))
		return 0;
	if (!strcmp(*addr, "none"))
		return 0;
	if (libnvmf_traddr_is_numeric(*addr))
		return 0;

#ifdef NVME_HAVE_NETDB
	ret = getaddrinfo(*addr, NULL, &hints, &host_info);
	if (ret) {
		nvme_show_error("failed to resolve host '%s': %s",
			*addr, gai_strerror(ret));
		return -EINVAL;
	}

	switch (host_info->ai_family) {
	case AF_INET:
		p = inet_ntop(host_info->ai_family,
			&(((struct sockaddr_in *)host_info->ai_addr)->sin_addr),
			addrstr, NVMF_TRADDR_SIZE);
		break;
	case AF_INET6:
		p = inet_ntop(host_info->ai_family,
			&(((struct sockaddr_in6 *)
				host_info->ai_addr)->sin6_addr),
			addrstr, NVMF_TRADDR_SIZE);
		break;
	default:
		break;
	}

	if (!p) {
		nvme_show_error(
			"failed to resolve host '%s': unrecognized address family",
			*addr);
		freeaddrinfo(host_info);
		return -EINVAL;
	}

	freeaddrinfo(host_info);

	resolved = strdup(addrstr);
	if (!resolved)
		return -ENOMEM;

	*addr = resolved;

	return 0;
#else /* NVME_HAVE_NETDB */
	nvme_show_error(
		"hostname resolution is not available in this build; use a numeric address");
	return -ENOTSUP;
#endif /* NVME_HAVE_NETDB */
}

static int nvmf_resolve_args(struct nvmf_args *fa)
{
	int ret;

	ret = nvmf_resolve_addr(fa->transport, &fa->traddr);
	if (ret)
		return ret;

	return nvmf_resolve_addr(fa->transport, &fa->host_traddr);
}

static int set_fabrics_options(struct libnvmf_context *fctx,
		struct nvmf_args *fa)
{
	libnvmf_context_set_io_queues(fctx, fa->nr_io_queues,
			fa->nr_write_queues, fa->nr_poll_queues,
			fa->queue_size, fa->disable_sqflow);
	libnvmf_context_set_reconnect_policy(fctx, fa->ctrl_loss_tmo,
			fa->reconnect_delay, fa->fast_io_fail_tmo);
	libnvmf_context_set_keep_alive_tmo(fctx, fa->keep_alive_tmo);
	libnvmf_context_set_tos(fctx, fa->tos);
	libnvmf_context_set_keyring_id(fctx, fa->keyring_id);
	libnvmf_context_set_tls_key_id(fctx, fa->tls_key_id);
	libnvmf_context_set_tls_configured_key_id(fctx,
			fa->tls_configured_key_id);
	libnvmf_context_set_duplicate_connect(fctx, fa->duplicate_connect);
	libnvmf_context_set_hdr_digest(fctx, fa->hdr_digest);
	libnvmf_context_set_data_digest(fctx, fa->data_digest);
	libnvmf_context_set_tls(fctx, fa->tls);
	libnvmf_context_set_concat(fctx, fa->concat);

	return 0;
}

static int hook_parser_next_line(struct libnvmf_context *fctx, void *user_data)
{
	struct hook_fabrics_data *hfd = user_data;
	struct nvmf_args fa;
	char *ptr, *p;
	static char line[4096];
	int argc, ret = 0;
	bool force = false;

	NVMF_ARGS(opts, fa,
		  OPT_FLAG("persistent",   'p', &persistent, "persistent discovery connection"),
		  OPT_FLAG("force",          0, &force,      "Force persistent discovery controller creation"));

	memcpy(&fa, hfd->fa, sizeof(fa));
	do {
		do {
			if (fgets(line, sizeof(line), hfd->f) == NULL)
				return -EOF;

			if (line[0] == '#' || line[0] == '\n')
				continue;

			argc = 1;
			p = line;
			while ((ptr = strsep(&p, " =\n")) != NULL)
				hfd->argv[argc++] = ptr;
			hfd->argv[argc] = NULL;

			fa.subsysnqn = NVME_DISC_SUBSYS_NAME;
			if (argconfig_parse(argc, hfd->argv, "config", opts))
				continue;
		} while (!fa.transport && !fa.traddr);

		if (!fa.trsvcid)
			fa.trsvcid = libnvmf_get_default_trsvcid(fa.transport,
								 true);

		/*
		 * An unresolvable hostname fails only its own line; keep
		 * connecting the remaining ones.
		 */
	} while (nvmf_resolve_args(&fa));

	ret = setup_common_context(fctx, &fa);
	if (ret)
		return ret;

	libnvmf_context_set_discovery_hooks(fctx, hook_discovery_log,
		hook_parser_init, hook_parser_cleanup, hook_parser_next_line);

	return 0;
}

/*
 * Parse one discovery.conf line -- the same argv-style syntax 'nvme
 * discover'/'connect-all' accept, reusing NVMF_ARGS so every short and long
 * form works identically to real usage -- and hand the parsed arguments to
 * nvme_config_convert_discovery_args(). @line is modified in place (strsep()).
 *
 * A blank line, a comment, or one with neither transport nor traddr is
 * silently skipped (0, nothing added): matches hook_parser_next_line()'s
 * own tolerance for a discovery.conf that mixes real entries with commentary.
 */
int nvmf_convert_discovery_line(struct libnvmf_config_emitter *emitter,
		char *line)
{
	struct nvmf_args fa = { 0 };
	char *argv[MAX_DISC_ARGS] = { "discovery.conf" };
	char *ptr, *p = line;
	int argc = 1;
	bool line_persistent = false, line_force = false;

	NVMF_ARGS(opts, fa,
		  OPT_FLAG("persistent", 'p', &line_persistent,
			   "persistent discovery connection"),
		  OPT_FLAG("force",        0, &line_force,
			   "Force persistent discovery controller creation"));

	if (line[0] == '#' || line[0] == '\n' || line[0] == '\0')
		return 0;

	fa.tos = -1;
	fa.ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO;

	while ((ptr = strsep(&p, " =\n")) != NULL && argc < MAX_DISC_ARGS - 1)
		argv[argc++] = ptr;
	argv[argc] = NULL;

	fa.subsysnqn = NVME_DISC_SUBSYS_NAME;
	if (argconfig_parse(argc, argv, "discovery.conf", opts))
		return 0;

	if (!fa.transport && !fa.traddr)
		return 0;

	return nvme_config_convert_discovery_args(emitter, &fa);
}

static int setup_common_context(struct libnvmf_context *fctx,
		struct nvmf_args *fa)
{
	int err;

	err = libnvmf_context_set_connection(fctx,
		fa->subsysnqn, fa->transport,
		fa->traddr, fa->trsvcid,
		fa->host_traddr, fa->host_iface);
	if (err)
		return err;

	err = libnvmf_context_set_hostnqn(fctx,
		fa->hostnqn, fa->hostid);
	if (err)
		return err;

	err = libnvmf_context_set_crypto(fctx,
		fa->hostkey, fa->ctrlkey,
		fa->keyring, fa->tls_key,
		fa->tls_key_identity);
	if (err)
		return err;

	return set_fabrics_options(fctx, fa);
}

static int create_common_context(struct libnvme_global_ctx *ctx,
		bool persistent, struct nvmf_args *fa,
		void *user_data, struct libnvmf_context **fctxp)
{
	struct libnvmf_context *fctx;
	int err;

	err = libnvmf_context_create(ctx, hook_decide_retry, hook_connected,
		hook_already_connected, user_data, &fctx);
	if (err)
		return err;

	err = setup_common_context(fctx, fa);
	if (err)
		goto err;

	err = libnvmf_context_set_crypto(fctx, fa->hostkey, fa->ctrlkey,
		fa->keyring, fa->tls_key, fa->tls_key_identity);
	if (err)
		goto err;

	libnvmf_context_set_persistent(fctx, persistent);

	*fctxp = fctx;

	return 0;

err:
	libnvmf_context_free(fctx);
	return err;
}

static int create_discovery_context(struct libnvme_global_ctx *ctx,
		bool persistent, const char *device,
		struct nvmf_args *fa,
		void *user_data, struct libnvmf_context **fctxp)
{
	struct libnvmf_context *fctx;
	int err;

	err = create_common_context(ctx, persistent, fa, user_data,
		&fctx);
	if (err)
		return err;

	err = libnvmf_context_set_discovery_hooks(fctx, hook_discovery_log,
		hook_parser_init, hook_parser_cleanup, hook_parser_next_line);
	if (err)
		goto err;

	libnvmf_context_set_default_max_discovery_retries(fctx,
			MAX_DISC_RETRIES);
	libnvmf_context_set_default_keep_alive_timeout(fctx, NVMF_DEF_DISC_TMO);

	err = libnvmf_context_set_device(fctx, device);
	if (err)
		goto err;

	*fctxp = fctx;
	return 0;

err:
	libnvmf_context_free(fctx);
	return err;
}

static int nvme_read_volatile_config(struct libnvme_global_ctx *ctx)
{
	char *filename, *ext;
	struct dirent *dir;
	DIR *d;
	int ret = -ENOENT;

	d = opendir(PATH_NVMF_RUNDIR);
	if (!d)
		return -ENOTDIR;

	while ((dir = readdir(d))) {
		if (dir->d_type != DT_REG)
			continue;

		ext = strchr(dir->d_name, '.');
		if (!ext || strcmp("json", ext + 1))
			continue;

		if (asprintf(&filename, "%s/%s", PATH_NVMF_RUNDIR, dir->d_name) < 0) {
			ret = -ENOMEM;
			break;
		}

		if (libnvme_read_config(ctx, filename))
			ret = 0;

		free(filename);
	}
	closedir(d);

	return ret;
}

static int nvme_read_config_checked(struct libnvme_global_ctx *ctx,
				    const char *filename)
{
	if (access(filename, F_OK))
		return -errno;

	return libnvme_read_config(ctx, filename);
}

static void load_nvme_fabrics_module(void)
{
#ifdef NVME_HAVE_LIBKMOD
	struct kmod_ctx *ctx;
	struct kmod_module *mod;
	int err, state;
	int timeout = 20; /* 2 seconds */

	ctx = kmod_new(NULL, NULL);
	if (!ctx)
		return;

	err = kmod_module_new_from_name(ctx, "nvme-fabrics", &mod);
	if (err)
		goto unref;

	state = kmod_module_get_initstate(mod);
	if (state != KMOD_MODULE_LIVE && state != KMOD_MODULE_BUILTIN) {
		err = kmod_module_probe_insert_module(mod,
			KMOD_PROBE_APPLY_BLACKLIST, NULL, NULL, NULL, NULL);
		if (err)
			goto mod_unref;

		while (timeout--) {
			state = kmod_module_get_initstate(mod);
			if (state == KMOD_MODULE_LIVE)
				goto mod_unref;

			/* 100 ms */
			usleep(100 * 1000);
		}
		err = -ENOENT;
	}

mod_unref:
	kmod_module_unref(mod);
unref:
	kmod_unref(ctx);

	if (err)
		nvme_show_error("Couldn't load the nvme-fabrics module");
#endif
}

#define NBFT_SYSFS_PATH		"/sys/firmware/acpi/tables"

int fabrics_discovery(const char *desc, int argc, char **argv, bool connect)
{
	__cleanup_free char *hnqn = NULL;
	__cleanup_free char *hid = NULL;
	char *config_file = PATH_NVMF_CONFIG;
	nvme_print_flags_t flags;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvmf_context struct libnvmf_context *fctx = NULL;
	int ret;
	struct nvmf_args fa = { .subsysnqn = NVME_DISC_SUBSYS_NAME };
	char *device = NULL;
	bool force = false;
	bool json_config = false;
	bool nbft = false, nonbft = false;
	char *nbft_path = NBFT_SYSFS_PATH;
	char *owner = NULL;

	NVMF_ARGS(opts, fa,
		  OPT_STRING("device",     'd', "DEV", &device,       "use existing discovery controller device"),
		  OPT_FILE("raw",          'r', &raw,                 "save raw output to file"),
		  OPT_FLAG("persistent",   'p', &persistent,          "persistent discovery connection"),
		  OPT_FLAG("quiet",          0, &quiet,               "suppress already connected errors"),
		  OPT_STRING("config",     'J', "FILE", &config_file, nvmf_config_file),
		  OPT_FLAG("dump-config",  'O', &dump_config,         "Dump configuration file to stdout"),
		  OPT_FLAG("force",          0, &force,               "Force persistent discovery controller creation"),
		  OPT_FLAG("nbft",           0, &nbft,                "Only look at NBFT tables"),
		  OPT_FLAG("no-nbft",        0, &nonbft,              "Do not look at NBFT tables"),
		  OPT_STRING("owner",        0, "NAME", &owner,       "record this owner in the registry"),
		  OPT_STRING("nbft-path",    0, "STR", &nbft_path,    "user-defined path for NBFT tables"));

	nvmf_default_args(&fa);

	load_nvme_fabrics_module();

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = validate_output_format(nvme_args.output_format, &flags);
	if (ret < 0) {
		nvme_show_error("Invalid output format");
		return ret;
	}

	if (!strcmp(config_file, "none"))
		config_file = NULL;

	log_level = map_log_level(nvme_args.verbose, quiet);

	ret = nvme_create_global_ctx(&ctx);
	if (ret) {
		nvme_show_error("Failed to create topology root: %s",
			libnvme_strerror(-ret));
		return ret;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	/*
	 * --nbft defaults the owner to "nbft" so legacy boot scripts that
	 * call "connect-all --nbft" record ownership unchanged.  An explicit
	 * --owner overrides that default.
	 */
	if (owner || nbft) {
		ret = libnvme_set_owner(ctx, owner ? owner : "nbft");
		if (ret) {
			nvme_show_error("failed to set owner: %s",
				libnvme_strerror(-ret));
			return ret;
		}
	}

	if (!nvme_read_config_checked(ctx, config_file))
		json_config = true;
	if (!nvme_read_volatile_config(ctx))
		json_config = true;

	libnvme_skip_namespaces(ctx);
	ret = libnvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		nvme_show_error("Failed to scan topology: %s",
			libnvme_strerror(-ret));
		return ret;
	}

	if (device) {
		if (!strcmp(device, "none"))
			device = NULL;
		else if (!strncmp(device, "/dev/", 5))
			device += 5;
	}

	ret = nvmf_resolve_args(&fa);
	if (ret)
		return ret;

	ret = libnvmf_host_get_ids(ctx, fa.hostnqn, fa.hostid, &hnqn, &hid);
	if (ret) {
		nvme_show_error("failed to determine hostnqn/hostid: %s",
			libnvme_strerror(-ret));
		return ret;
	}
	fa.hostnqn = hnqn;
	fa.hostid = hid;

	struct hook_fabrics_data dld = {
		.fa = &fa,
		.flags = flags,
		.raw = raw,
	};
	ret = create_discovery_context(ctx, persistent, device, &fa,
		&dld, &fctx);
	if (ret)
		return ret;

	if (!device && !fa.transport && !fa.traddr) {
		if (!nonbft)
			ret = libnvmf_discovery_nbft(ctx, fctx,
				connect, nbft_path);
		if (nbft)
			goto out_free;

		if (json_config)
			ret = libnvmf_discovery_config_json(ctx, fctx,
				connect, force);
		if (ret || access(PATH_NVMF_DISC, F_OK))
			goto out_free;

		ret = libnvmf_discovery_config_file(ctx, fctx, connect, force);
		goto out_free;
	}

	ret = libnvmf_discovery(ctx, fctx, connect, force);

out_free:
	if (dump_config)
		libnvme_dump_config(ctx, STDOUT_FILENO);

	return ret;
}

int fabrics_connect(const char *desc, int argc, char **argv)
{
	__cleanup_free char *hnqn = NULL;
	__cleanup_free char *hid = NULL;
	char *config_file = NULL;
	char *owner = NULL;
	char *devid_file = NULL;
	bool idempotent = false;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvmf_context struct libnvmf_context *fctx = NULL;
	__cleanup_nvme_ctrl libnvme_ctrl_t c = NULL;
	int ret;
	nvme_print_flags_t flags;
	struct nvmf_args fa = { 0 };

	NVMF_ARGS(opts, fa,
		  OPT_STRING("config",             'J', "FILE", &config_file, nvmf_config_file),
		  OPT_STRING("owner",                0, "NAME", &owner,           "record this owner in the registry"),
		  OPT_STRING("devid-file", 0, "FILE", &devid_file,
			     "write connected device name to FILE"),
		  OPT_FLAG("idempotent", 0, &idempotent,
			   "exit 0 if already connected"),
		  OPT_FLAG("dump-config",          'O', &dump_config,             "Dump JSON configuration to stdout"));

	nvmf_default_args(&fa);

	load_nvme_fabrics_module();

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = validate_output_format(nvme_args.output_format, &flags);
	if (ret < 0) {
		nvme_show_error("Invalid output format");
		return ret;
	}

	if (config_file && strcmp(config_file, "none"))
		goto do_connect;

	if (!fa.subsysnqn) {
		nvme_show_error(
			"required argument [--nqn | -n] not specified\n");
		return -EINVAL;
	}

	if (!fa.transport) {
		nvme_show_error(
			"required argument [--transport | -t] not specified\n");
		return -EINVAL;
	}

	if (strcmp(fa.transport, "loop")) {
		if (!fa.traddr) {
			nvme_show_error(
				"required argument [--traddr | -a] not specified for transport %s\n",
				fa.transport);
			return -EINVAL;
		}
	}

	ret = nvmf_resolve_args(&fa);
	if (ret)
		return ret;

do_connect:
	log_level = map_log_level(nvme_args.verbose, quiet);

	ret = nvme_create_global_ctx(&ctx);
	if (ret) {
		nvme_show_error("Failed to create topology root: %s",
			libnvme_strerror(-ret));
		return ret;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	if (owner) {
		ret = libnvme_set_owner(ctx, owner);
		if (ret) {
			nvme_show_error("failed to set owner: %s",
				libnvme_strerror(-ret));
			return ret;
		}
	}

	libnvme_read_config(ctx, config_file);
	nvme_read_volatile_config(ctx);

	libnvme_skip_namespaces(ctx);
	ret = libnvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		nvme_show_error("Failed to scan topology: %s",
			libnvme_strerror(-ret));
		return ret;
	}

	ret = libnvmf_host_get_ids(ctx, fa.hostnqn, fa.hostid, &hnqn, &hid);
	if (ret) {
		nvme_show_error("failed to determine hostnqn/hostid: %s",
			libnvme_strerror(-ret));
		return ret;
	}
	fa.hostnqn = hnqn;
	fa.hostid = hid;

	struct hook_fabrics_data hfd = {
		.flags = flags,
		.quiet = dump_config,
		.raw = raw,
		.idempotent = idempotent,
	};
	ret = create_common_context(ctx, persistent, &fa, &hfd, &fctx);
	if (ret)
		return ret;

	if (devid_file)
		libnvmf_context_set_devid_file(fctx, devid_file);

	if (config_file)
		return libnvmf_connect_config_json(ctx, fctx);

	/*
	 * The exclusion list governs auto-connecting orchestrators, not an
	 * explicit "nvme connect", so we never block it here. But under
	 * --verbose, note when the target matches an exclusion entry so the
	 * operator knows they are overriding their own opt-out.
	 */
	if (nvme_args.verbose) {
		struct libnvmf_tid *tid;

		tid = libnvmf_tid_from_fields(fa.transport, fa.traddr,
					      fa.trsvcid, fa.subsysnqn,
					      fa.host_traddr, fa.host_iface,
					      fa.hostnqn, fa.hostid);
		if (tid && libnvmf_exclusion_match(ctx, tid))
			nvme_show_error(
				"Note: %s is on the exclusion list; connecting anyway\n",
				fa.subsysnqn ? fa.subsysnqn : "this controller");
		libnvmf_tid_free(tid);
	}

	ret = libnvmf_connect(ctx, fctx);
	if (idempotent && (ret == -EALREADY || ret == -ENVME_CONNECT_ALREADY))
		ret = 0;
	if (ret) {
		nvme_show_error("failed to connect: %s",
			libnvme_strerror(-ret));
		return ret;
	}

	if (dump_config)
		libnvme_dump_config(ctx, STDOUT_FILENO);

	return 0;
}

static libnvme_ctrl_t lookup_nvme_ctrl(struct libnvme_global_ctx *ctx,
				    const char *name)
{
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			libnvme_subsystem_for_each_ctrl(s, c) {
				if (!strcmp(libnvme_ctrl_get_name(c), name))
					return c;
			}
		}
	}
	return NULL;
}

static void nvmf_disconnect_nqn(struct libnvme_global_ctx *ctx, char *nqn)
{
	int i = 0;
	char *n = nqn;
	char *p;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;

	while ((p = strsep(&n, ",")) != NULL) {
		if (!strlen(p))
			continue;
		libnvme_for_each_host(ctx, h) {
			libnvme_for_each_subsystem(h, s) {
				if (strcmp(libnvme_subsystem_get_subsysnqn(s), p))
					continue;
				libnvme_subsystem_for_each_ctrl(s, c) {
					if (!libnvmf_disconnect_ctrl(c))
						i++;
				}
			}
		}
	}
	nvme_show_verbose_result("NQN:%s disconnected %d controller(s)", nqn, i);
}

int fabrics_disconnect(const char *desc, int argc, char **argv)
{
	const char *device = "nvme device handle";
	const char *exclude_help = "write exclusion entry before disconnecting";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	libnvme_ctrl_t c;
	char *p;
	int ret;

	struct config {
		char *nqn;
		char *device;
		bool  exclude;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("nqn",        'n', "NAME", &cfg.nqn,     nvmf_nqn),
		OPT_STRING("device",     'd', "DEV",  &cfg.device,  device),
		OPT_FLAG("exclude", 'x', &cfg.exclude, exclude_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (cfg.nqn && cfg.device) {
		nvme_show_error(
			"Both device name [--device | -d] and NQN [--nqn | -n] are specified\n");
		return -EINVAL;
	}
	if (!cfg.nqn && !cfg.device) {
		nvme_show_error(
			"Neither device name [--device | -d] nor NQN [--nqn | -n] provided\n");
		return -EINVAL;
	}

	log_level = map_log_level(nvme_args.verbose, false);

	ret = nvme_create_global_ctx(&ctx);
	if (ret) {
		nvme_show_error("Failed to create topology root: %s",
			libnvme_strerror(-ret));
		return ret;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	libnvme_skip_namespaces(ctx);
	ret = libnvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		/*
		 * Do not report an error when the modules are not
		 * loaded, this allows the user to unconditionally call
		 * disconnect.
		 */
		if (ret == -ENOENT)
			return 0;

		nvme_show_error("Failed to scan topology: %s",
			libnvme_strerror(-ret));
		return ret;
	}

	if (cfg.nqn) {
		/*
		 * Disconnecting by NQN affects every controller of that
		 * subsystem; with --exclude, write a matching subsysnqn=
		 * exclusion to the main list first so orchestrators see it
		 * before the removal events fire.
		 */
		if (cfg.exclude) {
			ret = libnvmf_exclusion_add_subsysnqn(ctx, NULL,
							      cfg.nqn);
			if (ret)
				nvme_show_error(
					"Warning: failed to write exclusion entry: %s\n",
					libnvme_strerror(-ret));
		}
		nvmf_disconnect_nqn(ctx, cfg.nqn);
	}

	if (cfg.device) {
		char *d;

		d = cfg.device;
		while ((p = strsep(&d, ",")) != NULL) {
			if (!strncmp(p, "/dev/", 5))
				p += 5;
			c = lookup_nvme_ctrl(ctx, p);
			if (!c) {
				nvme_show_error(
					"Did not find device %s\n", p);
				return -ENODEV;
			}
			/*
			 * Write exclusion entry before disconnecting so that
			 * orchestrators see the exclusion in place before the
			 * device removal event fires.
			 */
			if (cfg.exclude) {
				ret = libnvmf_exclusion_add_ctrl(ctx, NULL,
								 c);
				if (ret)
					nvme_show_error(
						"Warning: failed to write exclusion entry: %s\n",
						libnvme_strerror(-ret));
			}
			ret = libnvmf_disconnect_ctrl(c);
			if (ret)
				nvme_show_error(
					"Failed to disconnect %s: %s\n",
					p, libnvme_strerror(-ret));
		}
	}

	return 0;
}

/* disconnect-all policy: should controller @c be torn down? */
static bool disconnect_all_match(struct libnvme_global_ctx *ctx,
				 libnvme_ctrl_t c, const char *transport,
				 const char *owner, bool force)
{
	if (transport && strcmp(transport, libnvme_ctrl_get_transport(c)))
		return false;
	if (!libnvme_ctrl_is_transport_fabric(c))
		return false;
	if (force)
		return true;

	/*
	 * attr_equal() returns 0 only on an exact match; a read error (<0)
	 * compares as "not a match", so we never disconnect on error.
	 */
	return libnvmf_registry_attr_equal(ctx, libnvme_ctrl_get_name(c),
					   "owner", owner) == 0;
}

int fabrics_disconnect_all(const char *desc, int argc, char **argv)
{
	const char *owner_help = "disconnect only controllers owned by NAME";
	const char *force_help = "disconnect all controllers regardless of ownership";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;
	int ret;

	struct config {
		char *transport;
		char *owner;
		bool force;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("transport", 't', "STR", &cfg.transport, nvmf_tport),
		OPT_STRING("owner", 0, "NAME", &cfg.owner, owner_help),
		OPT_FLAG("force", 0, &cfg.force, force_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (cfg.force && cfg.owner) {
		nvme_show_error("--force and --owner are mutually exclusive");
		return -EINVAL;
	}

	if ((cfg.force || cfg.owner) && isatty(STDIN_FILENO)) {
		char ans[8] = { 0 };

		if (cfg.force)
			fprintf(stderr,
				"WARNING: --force disconnects all NVMeoF controllers\n"
				"regardless of ownership. Type 'yes' to confirm: ");
		else
			fprintf(stderr,
				"WARNING: --owner disconnects all NVMeoF controllers\n"
				"owned by '%s'. Type 'yes' to confirm: ",
				cfg.owner);
		if (!fgets(ans, sizeof(ans), stdin)) {
			nvme_show_error("Aborted.");
			return -EINVAL;
		}
		ans[strcspn(ans, "\n")] = '\0';
		if (strcmp(ans, "yes") != 0) {
			nvme_show_error("Aborted.");
			return -EINVAL;
		}
	}

	log_level = map_log_level(nvme_args.verbose, false);

	ret = nvme_create_global_ctx(&ctx);
	if (ret) {
		nvme_show_error("Failed to create topology root: %s",
			libnvme_strerror(-ret));
		return ret;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	libnvme_skip_namespaces(ctx);
	ret = libnvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		/*
		 * Do not report an error when the modules are not
		 * loaded, this allows the user to unconditionally call
		 * disconnect.
		 */
		if (ret == -ENOENT)
			return 0;

		nvme_show_error("Failed to scan topology: %s",
			libnvme_strerror(-ret));
		return ret;
	}

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			libnvme_subsystem_for_each_ctrl(s, c) {
				if (!disconnect_all_match(ctx, c, cfg.transport,
							  cfg.owner, cfg.force))
					continue;
				if (libnvmf_disconnect_ctrl(c))
					nvme_show_error(
						"failed to disconnect %s\n",
						libnvme_ctrl_get_name(c));
			}
		}
	}

	return 0;
}

int fabrics_config(const char *desc, int argc, char **argv)
{
	bool scan_tree = false, modify_config = false, update_config = false;
	__cleanup_free char *hnqn = NULL;
	__cleanup_free char *hid = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	char *config_file = PATH_NVMF_CONFIG;
	struct nvmf_args fa = { };
	int ret;

	NVMF_ARGS(opts, fa,
		  OPT_STRING("config",             'J', "FILE", &config_file, nvmf_config_file),
		  OPT_FLAG("scan",                 'R', &scan_tree,           "Scan current NVMeoF topology"),
		  OPT_FLAG("modify",               'M', &modify_config,       "Modify JSON configuration file"),
		  OPT_FLAG("dump",                 'O', &dump_config,         "Dump JSON configuration to stdout"),
		  OPT_FLAG("update",               'U', &update_config,       "Update JSON configuration file"));

	nvmf_default_args(&fa);

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!strcmp(config_file, "none"))
		config_file = NULL;

	log_level = map_log_level(nvme_args.verbose, quiet);

	ret = nvme_create_global_ctx(&ctx);
	if (ret) {
		nvme_show_error("Failed to create topology root: %s",
			libnvme_strerror(-ret));
		return ret;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	libnvme_read_config(ctx, config_file);

	if (scan_tree) {
		libnvme_skip_namespaces(ctx);
		ret = libnvme_scan_topology(ctx, NULL, NULL);
		if (ret < 0) {
			nvme_show_error("Failed to scan topology: %s",
				libnvme_strerror(-ret));
			return ret;
		}
	}

	if (modify_config) {
		__cleanup_nvmf_context struct libnvmf_context *fctx = NULL;

		if (!fa.subsysnqn) {
			nvme_show_error(
				"required argument [--nqn | -n] needed with --modify\n");
			return -EINVAL;
		}

		if (!fa.transport) {
			nvme_show_error(
				"required argument [--transport | -t] needed with --modify\n");
			return -EINVAL;
		}

		ret = libnvmf_host_get_ids(ctx, fa.hostnqn, fa.hostid,
				&hnqn, &hid);
		if (ret) {
			nvme_show_error("failed to determine hostnqn/hostid: %s",
				libnvme_strerror(-ret));
			return ret;
		}
		fa.hostnqn = hnqn;
		fa.hostid = hid;

		ret = create_common_context(ctx, persistent, &fa, NULL, &fctx);
		if (ret)
			return ret;

		ret = libnvmf_config_modify(ctx, fctx);
		if (ret) {
			nvme_show_error("failed to update config");
			return ret;
		}
	}

	if (update_config) {
		__cleanup_fd int fd = -1;

		fd = open(config_file, O_RDONLY, 0);
		if (fd != -1)
			libnvme_dump_config(ctx, fd);
	}

	if (dump_config)
		libnvme_dump_config(ctx, STDOUT_FILENO);

	return 0;
}

static int dim_operation(libnvme_ctrl_t c, enum nvmf_dim_tas tas, const char *name)
{
	static const char * const task[] = {
		[NVMF_DIM_TAS_REGISTER]   = "register",
		[NVMF_DIM_TAS_DEREGISTER] = "deregister",
	};
	const char *t;
	int status;
	__u32 result;

	t = (tas > NVMF_DIM_TAS_DEREGISTER || !task[tas]) ? "reserved" : task[tas];
	status = libnvmf_register_ctrl(c, tas, &result);
	if (status == NVME_SC_SUCCESS) {
		nvme_show_verbose_result("%s DIM %s command success", name, t);
	} else if (status < NVME_SC_SUCCESS) {
		nvme_show_error("%s DIM %s command error. Status:0x%04x - %s",
			name, t, status, libnvme_status_to_string(status, false));
	} else {
		nvme_show_error("%s DIM %s command error. Result:0x%04x, Status:0x%04x - %s",
			name, t, result, status, libnvme_status_to_string(status, false));
	}

	return libnvme_status_to_errno(status, true);
}

int fabrics_dim(const char *desc, int argc, char **argv)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	enum nvmf_dim_tas tas;
	libnvme_ctrl_t c;
	char *p;
	int ret;

	struct {
		char *nqn;
		char *device;
		char *tas;
	} cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("nqn",    'n', "NAME", &cfg.nqn,    "Comma-separated list of DC nqn"),
		OPT_STRING("device", 'd', "DEV",  &cfg.device, "Comma-separated list of DC nvme device handle."),
		OPT_STRING("task",   't', "TASK", &cfg.tas,    "[register|deregister]"));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!cfg.nqn && !cfg.device) {
		nvme_show_error(
			"Neither device name [--device | -d] nor NQN [--nqn | -n] provided\n");
		return -EINVAL;
	}

	if (!cfg.tas) {
		nvme_show_error(
			"Task [--task | -t] must be specified\n");
		return -EINVAL;
	}

	/* Allow partial name (e.g. "reg" for "register" */
	if (strstarts("register", cfg.tas)) {
		tas = NVMF_DIM_TAS_REGISTER;
	} else if (strstarts("deregister", cfg.tas)) {
		tas = NVMF_DIM_TAS_DEREGISTER;
	} else {
		nvme_show_error("Invalid --task: %s", cfg.tas);
		return -EINVAL;
	}

	log_level = map_log_level(nvme_args.verbose, false);

	ret = nvme_create_global_ctx(&ctx);
	if (ret) {
		nvme_show_error("Failed to create topology root: %s",
			libnvme_strerror(-ret));
		return ret;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	libnvme_skip_namespaces(ctx);
	ret = libnvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		nvme_show_error("Failed to scan topology: %s",
			libnvme_strerror(-ret));
		return ret;
	}

	if (cfg.nqn) {
		libnvme_host_t h;
		libnvme_subsystem_t s;
		char *n = cfg.nqn;

		while ((p = strsep(&n, ",")) != NULL) {
			if (!strlen(p))
				continue;
			libnvme_for_each_host(ctx, h) {
				libnvme_for_each_subsystem(h, s) {
					if (strcmp(libnvme_subsystem_get_subsysnqn(s), p))
						continue;
					libnvme_subsystem_for_each_ctrl(s, c)
						ret = dim_operation(c, tas, p);
				}
			}
		}
	}

	if (cfg.device) {
		char *d = cfg.device;

		while ((p = strsep(&d, ",")) != NULL) {
			if (!strncmp(p, "/dev/", 5))
				p += 5;
			ret = libnvme_scan_ctrl(ctx, p, &c);
			if (ret) {
				nvme_show_error(
					"Did not find device %s: %s\n",
					p, libnvme_strerror(ret));
				return ret;
			}
			ret = dim_operation(c, tas, p);
		}
	}

	return ret;
}
