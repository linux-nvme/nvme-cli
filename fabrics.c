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

#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <dirent.h>
#include <inttypes.h>
#include <libgen.h>
#include <sys/stat.h>
#include <stddef.h>
#include <syslog.h>
#include <time.h>

#include <sys/types.h>
#include <linux/types.h>

#include <libnvme.h>

#include "common.h"
#include "nvme.h"
#include "nvme-print.h"
#include "fabrics.h"
#include "util/cleanup.h"
#include "logging.h"
#include "util/sighdl.h"

#define PATH_NVMF_DISC		SYSCONFDIR "/nvme/discovery.conf"
#define PATH_NVMF_CONFIG	SYSCONFDIR "/nvme/config.json"
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
static const char *nvmf_context		= "execution context identification string";

#define NVMF_ARGS(n, t, c, ...)                                                                  \
	struct argconfig_commandline_options n[] = {                                             \
		OPT_STRING("transport",       't', "STR", &t.transport,     nvmf_tport),         \
		OPT_STRING("nqn",             'n', "STR", &t.subsysnqn,     nvmf_nqn),           \
		OPT_STRING("traddr",          'a', "STR", &t.traddr,        nvmf_traddr),        \
		OPT_STRING("trsvcid",         's', "STR", &t.trsvcid,       nvmf_trsvcid),       \
		OPT_STRING("host-traddr",     'w', "STR", &t.host_traddr,   nvmf_htraddr),       \
		OPT_STRING("host-iface",      'f', "STR", &t.host_iface,    nvmf_hiface),        \
		OPT_STRING("hostnqn",         'q', "STR", &t.hostnqn,       nvmf_hostnqn),       \
		OPT_STRING("hostid",          'I', "STR", &t.hostid,        nvmf_hostid),        \
		OPT_STRING("dhchap-secret",   'S', "STR", &t.hostkey,       nvmf_hostkey),       \
		OPT_STRING("dhchap-ctrl-secret", 'C', "STR", &t.ctrlkey,    nvmf_ctrlkey),       \
		OPT_STRING("keyring",          0,  "STR", &t.keyring,       nvmf_keyring),       \
		OPT_STRING("tls-key",          0,  "STR", &t.tls_key,       nvmf_tls_key),       \
		OPT_STRING("tls-key-identity", 0,  "STR", &t.tls_key_identity, nvmf_tls_key_identity), \
		OPT_INT("nr-io-queues",       'i', &c.nr_io_queues,       nvmf_nr_io_queues),    \
		OPT_INT("nr-write-queues",    'W', &c.nr_write_queues,    nvmf_nr_write_queues), \
		OPT_INT("nr-poll-queues",     'P', &c.nr_poll_queues,     nvmf_nr_poll_queues),  \
		OPT_INT("queue-size",         'Q', &c.queue_size,         nvmf_queue_size),      \
		OPT_INT("keep-alive-tmo",     'k', &c.keep_alive_tmo,     nvmf_keep_alive_tmo),  \
		OPT_INT("reconnect-delay",    'c', &c.reconnect_delay,    nvmf_reconnect_delay), \
		OPT_INT("ctrl-loss-tmo",      'l', &c.ctrl_loss_tmo,      nvmf_ctrl_loss_tmo),   \
		OPT_INT("fast_io_fail_tmo",   'F', &c.fast_io_fail_tmo,   nvmf_fast_io_fail_tmo),\
		OPT_INT("tos",                'T', &c.tos,                nvmf_tos),             \
		OPT_INT("tls_key",              0, &c.tls_key,            nvmf_tls_key_legacy),  \
		OPT_FLAG("duplicate-connect", 'D', &c.duplicate_connect,  nvmf_dup_connect),     \
		OPT_FLAG("disable-sqflow",      0, &c.disable_sqflow,     nvmf_disable_sqflow),  \
		OPT_FLAG("hdr-digest",        'g', &c.hdr_digest,         nvmf_hdr_digest),      \
		OPT_FLAG("data-digest",       'G', &c.data_digest,        nvmf_data_digest),     \
		OPT_FLAG("tls",                 0, &c.tls,                nvmf_tls),             \
		OPT_FLAG("concat",              0, &c.concat,             nvmf_concat),          \
		__VA_ARGS__,                                                                     \
		OPT_END()                                                                        \
	}

static bool is_persistent_discovery_ctrl(nvme_host_t h, nvme_ctrl_t c)
{
	if (nvme_host_is_pdc_enabled(h, DEFAULT_PDC_ENABLED))
		return nvme_ctrl_is_unique_discovery_ctrl(c);

	return false;
}

nvme_ctrl_t lookup_ctrl(nvme_host_t h, struct tr_config *trcfg)
{
	nvme_subsystem_t s;
	nvme_ctrl_t c;

	nvme_for_each_subsystem(h, s) {
		c = nvme_ctrl_find(s,
				   trcfg->transport,
				   trcfg->traddr,
				   trcfg->trsvcid,
				   trcfg->subsysnqn,
				   trcfg->host_traddr,
				   trcfg->host_iface);
		if (c)
			return c;
	}

	return NULL;
}

static int set_discovery_kato(struct nvme_fabrics_config *cfg)
{
	int tmo = cfg->keep_alive_tmo;

	/* Set kato to NVMF_DEF_DISC_TMO for persistent controllers */
	if (persistent && !cfg->keep_alive_tmo)
		cfg->keep_alive_tmo = NVMF_DEF_DISC_TMO;
	/* Set kato to zero for non-persistent controllers */
	else if (!persistent && (cfg->keep_alive_tmo > 0))
		cfg->keep_alive_tmo = 0;

	return tmo;
}

static int nvme_add_ctrl(nvme_host_t h, nvme_ctrl_t c,
			 struct nvme_fabrics_config *cfg)
{
	int ret;

retry:
	/*
	 * __create_discover_ctrl and callers depend on errno being set
	 * in the error case.
	 */
	ret = nvmf_add_ctrl(h, c, cfg);
	if (!ret)
		return 0;

	if (ret == -EAGAIN || (ret == -EINTR && !nvme_sigint_received)) {
		print_debug("nvmf_add_ctrl returned '%s'\n", strerror(-ret));
		goto retry;
	}

	return ret;
}

static int __create_discover_ctrl(struct nvme_global_ctx *ctx, nvme_host_t h,
				  struct nvme_fabrics_config *cfg,
				  struct tr_config *trcfg,
				  nvme_ctrl_t *ctrl)
{
	nvme_ctrl_t c;
	int tmo, ret;

	ret = nvme_create_ctrl(ctx, trcfg->subsysnqn, trcfg->transport,
			     trcfg->traddr, trcfg->host_traddr,
			     trcfg->host_iface, trcfg->trsvcid, &c);
	if (ret)
		return ret;

	nvme_ctrl_set_discovery_ctrl(c, true);
	nvme_ctrl_set_unique_discovery_ctrl(c,
		     strcmp(trcfg->subsysnqn, NVME_DISC_SUBSYS_NAME));
	tmo = set_discovery_kato(cfg);

	ret = nvme_add_ctrl(h, c, cfg);
	cfg->keep_alive_tmo = tmo;
	if (ret) {
		nvme_free_ctrl(c);
		return ret;
	}

	*ctrl = c;
	return 0;
}

int nvmf_create_discover_ctrl(struct nvme_global_ctx *ctx, nvme_host_t h,
			      struct nvme_fabrics_config *cfg,
			      struct tr_config *trcfg,
			      nvme_ctrl_t *ctrl)
{
	_cleanup_free_ struct nvme_id_ctrl *id = NULL;
	nvme_ctrl_t c;
	int ret;

	ret = __create_discover_ctrl(ctx, h, cfg, trcfg, &c);
	if (ret)
		return ret;

	if (nvme_ctrl_is_unique_discovery_ctrl(c)) {
		*ctrl = c;
		return 0;
	}

	id = nvme_alloc(sizeof(*id));
	if (!id) {
		nvme_free_ctrl(c);
		return -ENOMEM;
	}

	/* Find out the name of discovery controller */
	ret = nvme_ctrl_identify(c, id);
	if (ret)  {
		fprintf(stderr,	"failed to identify controller, error %s\n",
			nvme_strerror(-ret));
		nvme_disconnect_ctrl(c);
		nvme_free_ctrl(c);
		return ret;
	}

	if (!strcmp(id->subnqn, NVME_DISC_SUBSYS_NAME)) {
		*ctrl = c;
		return 0;
	}

	/*
	 * The subsysnqn is not the well-known name. Prefer the unique
	 * subsysnqn over the well-known one.
	 */
	nvme_disconnect_ctrl(c);
	nvme_free_ctrl(c);

	trcfg->subsysnqn = id->subnqn;
	ret = __create_discover_ctrl(ctx, h, cfg, trcfg, &c);
	if (ret)
		return ret;

	*ctrl = c;
	return 0;
}

static void save_discovery_log(char *raw, struct nvmf_discovery_log *log)
{
	uint64_t numrec = le64_to_cpu(log->numrec);
	int fd, len, ret;

	fd = open(raw, O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s: %s\n", raw, strerror(errno));
		return;
	}

	len = sizeof(struct nvmf_discovery_log) + numrec * sizeof(struct nvmf_disc_log_entry);

	ret = write(fd, log, len);
	if (ret < 0)
		fprintf(stderr, "failed to write to %s: %s\n",
			raw, strerror(errno));
	else
		printf("Discovery log is saved to %s\n", raw);

	close(fd);
}

struct cb_discovery_log_data {
	nvme_print_flags_t flags;
	char *raw;
};

static void cb_discovery_log(struct nvmf_discovery_ctx *dctx,
		bool connect, struct nvmf_discovery_log *log,
		uint64_t numrec, void *user_data)
{
	struct cb_discovery_log_data *dld = user_data;

	if (dld->raw)
		save_discovery_log(dld->raw, log);
	else if (!connect)
		nvme_show_discovery_log(log, numrec, dld->flags);
}

static void already_connected(struct nvme_host *host,
		struct nvmf_disc_log_entry *entry,
		void *user_data)
{
	if (quiet)
		return;

	fprintf(stderr,
	"already connected to hostnqn=%s,nqn=%s,transport=%s,traddr=%s,trsvcid=%s\n",
		nvme_host_get_hostnqn(host), entry->subnqn,
		nvmf_trtype_str(entry->trtype), entry->traddr, entry->trsvcid);
}

static bool nvmf_decide_retry(struct nvmf_discovery_ctx *dctx, int err,
		void *user_data)
{
	if (err == -EAGAIN || (err == -EINTR && !nvme_sigint_received)) {
		print_debug("nvmf_add_ctrl returned '%s'\n", strerror(-err));
		return true;
	}

	return false;
}

static void nvmf_connected(struct nvmf_discovery_ctx *dctx,
		struct nvme_ctrl *c, void *user_data)
{
	struct cb_discovery_log_data *dld = user_data;

	if (dld->flags == NORMAL) {
		printf("device: %s\n", nvme_ctrl_get_name(c));
		return;
	}

#ifdef CONFIG_JSONC
	if (dld->flags == JSON) {
		struct json_object *root;

		root = json_create_object();

		json_object_add_value_string(root, "device",
			nvme_ctrl_get_name(c));

		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
	}
#endif
}

static int create_discovery_log_ctx(struct nvme_global_ctx *ctx,
		bool persistent, struct tr_config *trcfg,
		struct nvme_fabrics_config *defcfg,
		void *user_data, struct nvmf_discovery_ctx **dctxp)
{
	struct nvmf_discovery_ctx *dctx;
	int err;

	err = nvmf_discovery_ctx_create(ctx, user_data, &dctx);
	if (err)
		return err;

	err = nvmf_discovery_ctx_max_retries(dctx, MAX_DISC_RETRIES);
	if (err)
		goto err;

	err = nvmf_discovery_ctx_keep_alive_timeout(dctx, NVMF_DEF_DISC_TMO);
	if (err)
		goto err;

	err = nvmf_discovery_ctx_discovery_log_set(dctx, cb_discovery_log);
	if (err)
		goto err;

	err = nvmf_discovery_ctx_already_connected_set(dctx, already_connected);
	if (err)
		goto err;

	err = nvmf_discovery_ctx_decide_retry_set(dctx, nvmf_decide_retry);
	if (err)
		goto err;

	err = nvmf_discovery_ctx_connected_set(dctx, nvmf_connected);
	if (err)
		goto err;

	err = nvmf_discovery_ctx_persistent_set(dctx, persistent);
	if (err)
		goto err;

	err = nvmf_discovery_ctx_host_traddr_set(dctx, trcfg->host_traddr);
	if (err)
		goto err;

	err = nvmf_discovery_ctx_host_iface_set(dctx, trcfg->host_iface);
	if (err)
		goto err;

	err = nvmf_discovery_ctx_default_fabrics_config_set(dctx, defcfg);
	if (err)
		goto err;

	*dctxp = dctx;
	return 0;

err:
	free(dctx);
	return err;
}

static int discover_from_conf_file(struct nvme_global_ctx *ctx, nvme_host_t h,
				   const char *desc, bool connect,
				   const struct nvme_fabrics_config *defcfg)
{
	_cleanup_free_ struct nvmf_discovery_ctx *dctx = NULL;
	char *ptr, **argv, *p, line[4096];
	int argc, ret = 0;
	unsigned int verbose = 0;
	_cleanup_file_ FILE *f = NULL;
	nvme_print_flags_t flags;
	char *format = "normal";
	struct nvme_fabrics_config cfg;
	struct tr_config trcfg;
	bool force = false;
	NVMF_ARGS(opts, trcfg, cfg,
		  OPT_FMT("output-format", 'o', &format,     output_format),
		  OPT_FILE("raw",          'r', &raw,        "save raw output to file"),
		  OPT_FLAG("persistent",   'p', &persistent, "persistent discovery connection"),
		  OPT_FLAG("quiet",          0, &quiet,      "suppress already connected errors"),
		  OPT_INCR("verbose",      'v', &verbose,    "Increase logging verbosity"),
		  OPT_FLAG("force",          0, &force,      "Force persistent discovery controller creation"));

	nvmf_default_config(&cfg);

	ret = validate_output_format(format, &flags);
	if (ret < 0) {
		nvme_show_error("Invalid output format");
		return ret;
	}

	f = fopen(PATH_NVMF_DISC, "r");
	if (f == NULL) {
		fprintf(stderr, "No params given and no %s\n", PATH_NVMF_DISC);
		return -ENOENT;
	}

	argv = calloc(MAX_DISC_ARGS, sizeof(char *));
	if (!argv)
		return -1;

	argv[0] = "discover";
	memset(line, 0, sizeof(line));
	while (fgets(line, sizeof(line), f) != NULL) {
		nvme_ctrl_t c;

		if (line[0] == '#' || line[0] == '\n')
			continue;

		argc = 1;
		p = line;
		while ((ptr = strsep(&p, " =\n")) != NULL)
			argv[argc++] = ptr;
		argv[argc] = NULL;

		memcpy(&cfg, defcfg, sizeof(cfg));
		trcfg.subsysnqn = NVME_DISC_SUBSYS_NAME;
		ret = argconfig_parse(argc, argv, desc, opts);
		if (ret)
			goto next;
		if (!trcfg.transport && !trcfg.traddr)
			goto next;

		if (!trcfg.trsvcid)
			trcfg.trsvcid =
				nvmf_get_default_trsvcid(trcfg.transport, true);

		struct cb_discovery_log_data dld = {
			.flags = flags,
			.raw = raw,
		};
		ret = create_discovery_log_ctx(ctx, true, &trcfg, &cfg,
			&dld, &dctx);
		if (ret)
			return ret;

		if (!force) {
			c = lookup_ctrl(h, &trcfg);
			if (c) {
				nvmf_discovery(ctx, dctx, connect, c);
				goto next;
			}
		}

		ret = nvmf_create_discover_ctrl(ctx, h, &cfg, &trcfg, &c);
		if (ret)
			goto next;

		nvmf_discovery_ctx_persistent_set(dctx, persistent);
		nvmf_discovery(ctx, dctx, connect, c);
		if (!(persistent || is_persistent_discovery_ctrl(h, c)))
			ret = nvme_disconnect_ctrl(c);
		nvme_free_ctrl(c);

next:
		memset(&cfg, 0, sizeof(cfg));
	}
	free(argv);

	return ret;
}

static int nvme_read_volatile_config(struct nvme_global_ctx *ctx)
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

		if (nvme_read_config(ctx, filename))
			ret = 0;

		free(filename);
	}
	closedir(d);

	return ret;
}

static int nvme_read_config_checked(struct nvme_global_ctx *ctx,
				    const char *filename)
{
	if (access(filename, F_OK))
		return -errno;

	return nvme_read_config(ctx, filename);
}

#define NBFT_SYSFS_PATH		"/sys/firmware/acpi/tables"

/* returns negative errno values */
int nvmf_discover(const char *desc, int argc, char **argv, bool connect)
{
	char *config_file = PATH_NVMF_CONFIG;
	_cleanup_free_ char *hnqn = NULL;
	_cleanup_free_ char *hid = NULL;
	char *context = NULL;
	nvme_print_flags_t flags;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_free_ struct nvmf_discovery_ctx *dctx = NULL;
	nvme_host_t h;
	nvme_ctrl_t c = NULL;
	unsigned int verbose = 0;
	int ret;
	char *format = "normal";
	struct nvme_fabrics_config cfg;
	struct tr_config trcfg = { .subsysnqn = NVME_DISC_SUBSYS_NAME };
	char *device = NULL;
	bool force = false;
	bool json_config = false;
	bool nbft = false, nonbft = false;
	char *nbft_path = NBFT_SYSFS_PATH;

	NVMF_ARGS(opts, trcfg, cfg,
		  OPT_STRING("device",     'd', "DEV", &device,       "use existing discovery controller device"),
		  OPT_FMT("output-format", 'o', &format,              output_format),
		  OPT_FILE("raw",          'r', &raw,                 "save raw output to file"),
		  OPT_FLAG("persistent",   'p', &persistent,          "persistent discovery connection"),
		  OPT_FLAG("quiet",          0, &quiet,               "suppress already connected errors"),
		  OPT_STRING("config",     'J', "FILE", &config_file, nvmf_config_file),
		  OPT_INCR("verbose",      'v', &verbose,             "Increase logging verbosity"),
		  OPT_FLAG("dump-config",  'O', &dump_config,         "Dump configuration file to stdout"),
		  OPT_FLAG("force",          0, &force,               "Force persistent discovery controller creation"),
		  OPT_FLAG("nbft",           0, &nbft,                "Only look at NBFT tables"),
		  OPT_FLAG("no-nbft",        0, &nonbft,              "Do not look at NBFT tables"),
		  OPT_STRING("nbft-path",    0, "STR", &nbft_path,    "user-defined path for NBFT tables"),
		  OPT_STRING("context",      0, "STR", &context,       nvmf_context));

	nvmf_default_config(&cfg);

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = validate_output_format(format, &flags);
	if (ret < 0) {
		nvme_show_error("Invalid output format");
		return ret;
	}

	if (!strcmp(config_file, "none"))
		config_file = NULL;

	log_level = map_log_level(verbose, quiet);

	ctx = nvme_create_global_ctx(stderr, log_level);
	if (!ctx) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -ENOMEM;
	}
	if (context)
		nvme_set_application(ctx, context);

	if (!nvme_read_config_checked(ctx, config_file))
		json_config = true;
	if (!nvme_read_volatile_config(ctx))
		json_config = true;

	nvme_skip_namespaces(ctx);
	ret = nvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed to scan topology: %s\n",
			nvme_strerror(-ret));
		return ret;
	}

	ret = nvme_host_get_ids(ctx, trcfg.hostnqn, trcfg.hostid, &hnqn, &hid);
	if (ret < 0)
		return ret;

	h = nvme_lookup_host(ctx, hnqn, hid);
	if (!h) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (device) {
		if (!strcmp(device, "none"))
			device = NULL;
		else if (!strncmp(device, "/dev/", 5))
			device += 5;
	}
	if (trcfg.hostkey)
		nvme_host_set_dhchap_key(h, trcfg.hostkey);

	struct cb_discovery_log_data dld = {
		.flags = flags,
		.raw = raw,
	};
	ret = create_discovery_log_ctx(ctx, persistent, &trcfg,
		&cfg, &dld, &dctx);
	if (ret)
		return ret;

	if (!device && !trcfg.transport && !trcfg.traddr) {
		if (!nonbft)
			ret = nvmf_discovery_nbft(ctx, dctx,
				trcfg.hostnqn, trcfg.hostid, hnqn, hid, connect,
				&cfg, nbft_path);
		if (nbft)
			goto out_free;

		if (json_config)
			ret = nvmf_discovery_config_json(ctx, dctx,
				trcfg.hostnqn, trcfg.hostid, connect, force);
		if (ret || access(PATH_NVMF_DISC, F_OK))
			goto out_free;

		ret = discover_from_conf_file(ctx, h, desc, connect, &cfg);
		goto out_free;
	}

	if (!trcfg.trsvcid)
		trcfg.trsvcid = nvmf_get_default_trsvcid(trcfg.transport, true);

	if (device && !force) {
		ret = nvme_scan_ctrl(ctx, device, &c);
		if (!ret) {
			/* Check if device matches command-line options */
			if (!nvme_ctrl_config_match(c, trcfg.transport,
					trcfg.traddr, trcfg.trsvcid,
					trcfg.subsysnqn, trcfg.host_traddr,
					trcfg.host_iface)) {
				fprintf(stderr,
				    "ctrl device %s found, ignoring non matching command-line options\n",
				    device);
			}

			if (!nvme_ctrl_is_discovery_ctrl(c)) {
				fprintf(stderr,
					"ctrl device %s found, ignoring non discovery controller\n",
					device);

				nvme_free_ctrl(c);
				c = NULL;
				persistent = false;
			} else {
				/*
				 * If the controller device is found it must
				 * be persistent, and shouldn't be disconnected
				 * on exit.
				 */
				persistent = true;
				/*
				 * When --host-traddr/--host-iface are not specified on the
				 * command line, use the discovery controller's (c) host-
				 * traddr/host-iface for the connections to controllers
				 * returned in the Discovery Log Pages. This is essential
				 * when invoking "connect-all" with --device to reuse an
				 * existing persistent discovery controller (as is done
				 * for the udev rules). This ensures that host-traddr/
				 * host-iface are consistent with the discovery controller (c).
				 */
				if (!trcfg.host_traddr)
					trcfg.host_traddr = (char *)nvme_ctrl_get_host_traddr(c);
				if (!trcfg.host_iface)
					trcfg.host_iface = (char *)nvme_ctrl_get_host_iface(c);
			}
		} else {
			/*
			 * No controller found, fall back to create one.
			 * But that controller cannot be persistent.
			 */
			fprintf(stderr,
				"ctrl device %s not found%s\n", device,
				persistent ? ", ignoring --persistent" : "");
			persistent = false;
		}
	}
	if (!c && !force) {
		c = lookup_ctrl(h, &trcfg);
		if (c)
			persistent = true;
	}
	if (!c) {
		/* No device or non-matching device, create a new controller */
		ret = nvmf_create_discover_ctrl(ctx, h, &cfg, &trcfg, &c);
		if (ret) {
			if (ret != -ENVME_CONNECT_IGNORED)
				fprintf(stderr,
					"failed to add controller, error %s\n",
					nvme_strerror(-ret));
			goto out_free;
		}
	}

	ret = nvmf_discovery(ctx, dctx, connect, c);
	if (!(persistent || is_persistent_discovery_ctrl(h, c)))
		nvme_disconnect_ctrl(c);
	nvme_free_ctrl(c);

out_free:
	if (dump_config)
		nvme_dump_config(ctx);

	return ret;
}

static void nvme_parse_tls_args(const char *keyring, const char *tls_key,
				const char *tls_key_identity,
				struct nvme_fabrics_config *cfg, nvme_ctrl_t c)
{
	if (keyring) {
		char *endptr;
		long id = strtol(keyring, &endptr, 0);

		if (endptr != keyring)
			cfg->keyring = id;
		else
			nvme_ctrl_set_keyring(c, keyring);
	}

	if (tls_key_identity)
		nvme_ctrl_set_tls_key_identity(c, tls_key_identity);

	if (tls_key) {
		char *endptr;
		long id = strtol(tls_key, &endptr, 0);

		if (endptr != tls_key)
			cfg->tls_key = id;
		else
			nvme_ctrl_set_tls_key(c, tls_key);
	}
}

int nvmf_connect(const char *desc, int argc, char **argv)
{
	_cleanup_free_ char *hnqn = NULL;
	_cleanup_free_ char *hid = NULL;
	char *config_file = NULL;
	char *context = NULL;
	unsigned int verbose = 0;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	nvme_host_t h;
	_cleanup_nvme_ctrl_ nvme_ctrl_t c = NULL;
	int ret;
	nvme_print_flags_t flags;
	struct nvme_fabrics_config cfg = { 0 };
	struct tr_config trcfg = { 0 };
	char *format = "normal";

	NVMF_ARGS(opts, trcfg, cfg,
		  OPT_STRING("config",             'J', "FILE", &config_file, nvmf_config_file),
		  OPT_INCR("verbose",              'v', &verbose,             "Increase logging verbosity"),
		  OPT_FLAG("dump-config",          'O', &dump_config,             "Dump JSON configuration to stdout"),
		  OPT_FMT("output-format",         'o', &format,       "Output format: normal|json"),
		  OPT_STRING("context",              0, "STR", &context,  nvmf_context));

	nvmf_default_config(&cfg);

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = validate_output_format(format, &flags);
	if (ret < 0) {
		nvme_show_error("Invalid output format");
		return ret;
	}

	if (config_file && strcmp(config_file, "none"))
		goto do_connect;

	if (!trcfg.subsysnqn) {
		fprintf(stderr,
			"required argument [--nqn | -n] not specified\n");
		return -EINVAL;
	}

	if (!trcfg.transport) {
		fprintf(stderr,
			"required argument [--transport | -t] not specified\n");
		return -EINVAL;
	}

	if (strcmp(trcfg.transport, "loop")) {
		if (!trcfg.traddr) {
			fprintf(stderr,
				"required argument [--traddr | -a] not specified for transport %s\n",
				trcfg.transport);
			return -EINVAL;
		}
	}

do_connect:
	log_level = map_log_level(verbose, quiet);

	ctx = nvme_create_global_ctx(stderr, log_level);
	if (!ctx) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -ENOMEM;
	}
	if (context)
		nvme_set_application(ctx, context);

	nvme_read_config(ctx, config_file);
	nvme_read_volatile_config(ctx);

	nvme_skip_namespaces(ctx);
	ret = nvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed to scan topology: %s\n",
			nvme_strerror(-ret));
		return ret;
	}

	ret = nvme_host_get_ids(ctx, trcfg.hostnqn, trcfg.hostid, &hnqn, &hid);
	if (ret < 0)
		return ret;

	h = nvme_lookup_host(ctx, hnqn, hid);
	if (!h)
		return -ENOMEM;
	if (trcfg.hostkey)
		nvme_host_set_dhchap_key(h, trcfg.hostkey);
	if (!trcfg.trsvcid)
		trcfg.trsvcid = nvmf_get_default_trsvcid(trcfg.transport, false);

	if (config_file)
		return nvmf_connect_config_json(ctx, trcfg.hostnqn,
			trcfg.hostid, &cfg);

	c = lookup_ctrl(h, &trcfg);
	if (c && nvme_ctrl_get_name(c) && !cfg.duplicate_connect) {
		fprintf(stderr, "already connected\n");
		return -EALREADY;
	}

	ret = nvme_create_ctrl(ctx, trcfg.subsysnqn, trcfg.transport,
		trcfg.traddr, trcfg.host_traddr, trcfg.host_iface,
		trcfg.trsvcid, &c);
	if (ret)
		return ret;

	if (trcfg.ctrlkey)
		nvme_ctrl_set_dhchap_key(c, trcfg.ctrlkey);

	nvme_parse_tls_args(trcfg.keyring, trcfg.tls_key,
		trcfg.tls_key_identity, &cfg, c);

	/*
	 * We are connecting to a discovery controller, so let's treat
	 * this as a persistent connection and specify a KATO.
	 */
	if (!strcmp(trcfg.subsysnqn, NVME_DISC_SUBSYS_NAME)) {
		persistent = true;

		set_discovery_kato(&cfg);
	}

	ret = nvme_add_ctrl(h, c, &cfg);
	if (ret) {
		fprintf(stderr, "could not add new controller: %s\n",
			nvme_strerror(-ret));
		return ret;
	}

	/* always print connected device */
	nvme_show_connect_msg(c, flags);

	if (dump_config)
		nvme_dump_config(ctx);

	return 0;
}

static nvme_ctrl_t lookup_nvme_ctrl(struct nvme_global_ctx *ctx,
				    const char *name)
{
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;

	nvme_for_each_host(ctx, h) {
		nvme_for_each_subsystem(h, s) {
			nvme_subsystem_for_each_ctrl(s, c) {
				if (!strcmp(nvme_ctrl_get_name(c), name))
					return c;
			}
		}
	}
	return NULL;
}

static void nvmf_disconnect_nqn(struct nvme_global_ctx *ctx, char *nqn)
{
	int i = 0;
	char *n = nqn;
	char *p;
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;

	while ((p = strsep(&n, ",")) != NULL) {
		if (!strlen(p))
			continue;
		nvme_for_each_host(ctx, h) {
			nvme_for_each_subsystem(h, s) {
				if (strcmp(nvme_subsystem_get_nqn(s), p))
					continue;
				nvme_subsystem_for_each_ctrl(s, c) {
					if (!nvme_disconnect_ctrl(c))
						i++;
				}
			}
		}
	}
	printf("NQN:%s disconnected %d controller(s)\n", nqn, i);
}

int nvmf_disconnect(const char *desc, int argc, char **argv)
{
	const char *device = "nvme device handle";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	nvme_ctrl_t c;
	char *p;
	int ret;

	struct config {
		char *nqn;
		char *device;
		unsigned int verbose;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_STRING("nqn",        'n', "NAME", &cfg.nqn,    nvmf_nqn),
		OPT_STRING("device",     'd', "DEV",  &cfg.device, device),
		OPT_INCR("verbose",      'v', &cfg.verbose, "Increase logging verbosity"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (cfg.nqn && cfg.device) {
		fprintf(stderr,
			"Both device name [--device | -d] and NQN [--nqn | -n] are specified\n");
		return -EINVAL;
	}
	if (!cfg.nqn && !cfg.device) {
		fprintf(stderr,
			"Neither device name [--device | -d] nor NQN [--nqn | -n] provided\n");
		return -EINVAL;
	}

	log_level = map_log_level(cfg.verbose, false);

	ctx = nvme_create_global_ctx(stderr, log_level);
	if (!ctx) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -ENOMEM;
	}
	nvme_skip_namespaces(ctx);
	ret = nvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		/*
		 * Do not report an error when the modules are not
		 * loaded, this allows the user to unconditionally call
		 * disconnect.
		 */
		if (ret == -ENOENT)
			return 0;

		fprintf(stderr, "Failed to scan topology: %s\n",
			nvme_strerror(-ret));
		return ret;
	}

	if (cfg.nqn)
		nvmf_disconnect_nqn(ctx, cfg.nqn);

	if (cfg.device) {
		char *d;

		d = cfg.device;
		while ((p = strsep(&d, ",")) != NULL) {
			if (!strncmp(p, "/dev/", 5))
				p += 5;
			c = lookup_nvme_ctrl(ctx, p);
			if (!c) {
				fprintf(stderr,
					"Did not find device %s\n", p);
				return -ENODEV;
			}
			ret = nvme_disconnect_ctrl(c);
			if (ret)
				fprintf(stderr,
					"Failed to disconnect %s: %s\n",
					p, nvme_strerror(-ret));
		}
	}

	return 0;
}

int nvmf_disconnect_all(const char *desc, int argc, char **argv)
{
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	int ret;

	struct config {
		char *transport;
		unsigned int verbose;
	};

	struct config cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_STRING("transport", 'r', "STR", (char *)&cfg.transport, nvmf_tport),
		OPT_INCR("verbose",  'v', &cfg.verbose, "Increase logging verbosity"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	log_level = map_log_level(cfg.verbose, false);

	ctx = nvme_create_global_ctx(stderr, log_level);
	if (!ctx) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -ENOMEM;
	}
	nvme_skip_namespaces(ctx);
	ret = nvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		/*
		 * Do not report an error when the modules are not
		 * loaded, this allows the user to unconditionally call
		 * disconnect.
		 */
		if (ret == -ENOENT)
			return 0;

		fprintf(stderr, "Failed to scan topology: %s\n",
			nvme_strerror(-ret));
		return ret;
	}

	nvme_for_each_host(ctx, h) {
		nvme_for_each_subsystem(h, s) {
			nvme_subsystem_for_each_ctrl(s, c) {
				if (cfg.transport &&
				    strcmp(cfg.transport,
					   nvme_ctrl_get_transport(c)))
					continue;
				else if (!strcmp(nvme_ctrl_get_transport(c),
						 "pcie"))
					continue;
				if (nvme_disconnect_ctrl(c))
					fprintf(stderr,
						"failed to disconnect %s\n",
						nvme_ctrl_get_name(c));
			}
		}
	}

	return 0;
}

int nvmf_config(const char *desc, int argc, char **argv)
{
	char *subsysnqn = NULL;
	char *transport = NULL, *traddr = NULL;
	char *trsvcid = NULL, *hostnqn = NULL, *hostid = NULL;
	char *host_traddr = NULL, *host_iface = NULL;
	_cleanup_free_ char *hnqn = NULL;
	_cleanup_free_ char *hid = NULL;
	char *hostkey = NULL, *ctrlkey = NULL;
	char *keyring = NULL, *tls_key = NULL, *tls_key_identity = NULL;
	char *config_file = PATH_NVMF_CONFIG;
	unsigned int verbose = 0;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	int ret;
	struct nvme_fabrics_config cfg;
	struct tr_config trcfg = { };
	bool scan_tree = false, modify_config = false, update_config = false;

	NVMF_ARGS(opts, trcfg, cfg,
		  OPT_STRING("dhchap-ctrl-secret", 'C', "STR", &ctrlkey,      nvmf_ctrlkey),
		  OPT_STRING("config",             'J', "FILE", &config_file, nvmf_config_file),
		  OPT_INCR("verbose",              'v', &verbose,             "Increase logging verbosity"),
		  OPT_FLAG("scan",                 'R', &scan_tree,           "Scan current NVMeoF topology"),
		  OPT_FLAG("modify",               'M', &modify_config,       "Modify JSON configuration file"),
		  OPT_FLAG("dump",                 'O', &dump_config,         "Dump JSON configuration to stdout"),
		  OPT_FLAG("update",               'U', &update_config,       "Update JSON configuration file"));

	nvmf_default_config(&cfg);

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!strcmp(config_file, "none"))
		config_file = NULL;

	log_level = map_log_level(verbose, quiet);

	ctx = nvme_create_global_ctx(stderr, log_level);
	if (!ctx) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -ENOMEM;
	}

	nvme_read_config(ctx, config_file);

	if (scan_tree) {
		nvme_skip_namespaces(ctx);
		ret = nvme_scan_topology(ctx, NULL, NULL);
		if (ret < 0) {
			fprintf(stderr, "Failed to scan topology: %s\n",
				nvme_strerror(-ret));
			return -ret;
		}
	}

	if (modify_config) {
		nvme_host_t h;
		nvme_subsystem_t s;
		nvme_ctrl_t c;

		if (!subsysnqn) {
			fprintf(stderr,
				"required argument [--nqn | -n] needed with --modify\n");
			return -EINVAL;
		}

		if (!transport) {
			fprintf(stderr,
				"required argument [--transport | -t] needed with --modify\n");
			return -EINVAL;
		}

		if (!hostnqn)
			hostnqn = hnqn = nvmf_hostnqn_from_file();
		if (!hostid && hnqn)
			hostid = hid = nvmf_hostid_from_file();
		h = nvme_lookup_host(ctx, hostnqn, hostid);
		if (!h) {
			fprintf(stderr, "Failed to lookup host '%s'\n",
				hostnqn);
			return -ENODEV;
		}
		if (hostkey)
			nvme_host_set_dhchap_key(h, hostkey);
		s = nvme_lookup_subsystem(h, NULL, subsysnqn);
		if (!s) {
			fprintf(stderr, "Failed to lookup subsystem '%s'\n",
				subsysnqn);
			return -ENODEV;
		}
		c = nvme_lookup_ctrl(s, transport, traddr,
				     host_traddr, host_iface,
				     trsvcid, NULL);
		if (!c) {
			fprintf(stderr, "Failed to lookup controller\n");
			return -ENODEV;
		}
		if (ctrlkey)
			nvme_ctrl_set_dhchap_key(c, ctrlkey);
		nvme_parse_tls_args(keyring, tls_key, tls_key_identity, &cfg, c);

		nvmf_update_config(c, &cfg);
	}

	if (update_config)
		nvme_update_config(ctx);

	if (dump_config)
		nvme_dump_config(ctx);

	return 0;
}

static int dim_operation(nvme_ctrl_t c, enum nvmf_dim_tas tas, const char *name)
{
	static const char * const task[] = {
		[NVMF_DIM_TAS_REGISTER]   = "register",
		[NVMF_DIM_TAS_DEREGISTER] = "deregister",
	};
	const char *t;
	int status;
	__u32 result;

	t = (tas > NVMF_DIM_TAS_DEREGISTER || !task[tas]) ? "reserved" : task[tas];
	status = nvmf_register_ctrl(c, tas, &result);
	if (status == NVME_SC_SUCCESS) {
		printf("%s DIM %s command success\n", name, t);
	} else if (status < NVME_SC_SUCCESS) {
		fprintf(stderr, "%s DIM %s command error. Status:0x%04x - %s\n",
			name, t, status, nvme_status_to_string(status, false));
	} else {
		fprintf(stderr, "%s DIM %s command error. Result:0x%04x, Status:0x%04x - %s\n",
			name, t, result, status, nvme_status_to_string(status, false));
	}

	return nvme_status_to_errno(status, true);
}

int nvmf_dim(const char *desc, int argc, char **argv)
{
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	enum nvmf_dim_tas tas;
	nvme_ctrl_t c;
	char *p;
	int ret;

	struct {
		char *nqn;
		char *device;
		char *tas;
		unsigned int verbose;
	} cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_STRING("nqn",    'n', "NAME", &cfg.nqn,    "Comma-separated list of DC nqn"),
		OPT_STRING("device", 'd', "DEV",  &cfg.device, "Comma-separated list of DC nvme device handle."),
		OPT_STRING("task",   't', "TASK", &cfg.tas,    "[register|deregister]"),
		OPT_INCR("verbose",  'v', &cfg.verbose, "Increase logging verbosity"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!cfg.nqn && !cfg.device) {
		fprintf(stderr,
			"Neither device name [--device | -d] nor NQN [--nqn | -n] provided\n");
		return -EINVAL;
	}

	if (!cfg.tas) {
		fprintf(stderr,
			"Task [--task | -t] must be specified\n");
		return -EINVAL;
	}

	/* Allow partial name (e.g. "reg" for "register" */
	if (strstarts("register", cfg.tas)) {
		tas = NVMF_DIM_TAS_REGISTER;
	} else if (strstarts("deregister", cfg.tas)) {
		tas = NVMF_DIM_TAS_DEREGISTER;
	} else {
		fprintf(stderr, "Invalid --task: %s\n", cfg.tas);
		return -EINVAL;
	}

	log_level = map_log_level(cfg.verbose, false);

	ctx = nvme_create_global_ctx(stderr, log_level);
	if (!ctx) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -ENODEV;
	}
	nvme_skip_namespaces(ctx);
	ret = nvme_scan_topology(ctx, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed to scan topology: %s\n",
			nvme_strerror(-ret));
		return ret;
	}

	if (cfg.nqn) {
		nvme_host_t h;
		nvme_subsystem_t s;
		char *n = cfg.nqn;

		while ((p = strsep(&n, ",")) != NULL) {
			if (!strlen(p))
				continue;
			nvme_for_each_host(ctx, h) {
				nvme_for_each_subsystem(h, s) {
					if (strcmp(nvme_subsystem_get_nqn(s), p))
						continue;
					nvme_subsystem_for_each_ctrl(s, c)
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
			ret = nvme_scan_ctrl(ctx, p, &c);
			if (ret) {
				fprintf(stderr,
					"Did not find device %s: %s\n",
					p, nvme_strerror(ret));
				return ret;
			}
			ret = dim_operation(c, tas, p);
		}
	}

	return ret;
}
