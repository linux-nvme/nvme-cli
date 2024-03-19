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
#include "nbft.h"
#include "nvme-print.h"
#include "fabrics.h"
#include "util/logging.h"

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
static const char *nvmf_tos		= "type of service";
static const char *nvmf_keyring		= "Keyring for TLS key lookup";
static const char *nvmf_tls_key		= "TLS key to use";
static const char *nvmf_dup_connect	= "allow duplicate connections between same transport host and subsystem port";
static const char *nvmf_disable_sqflow	= "disable controller sq flow control (default false)";
static const char *nvmf_hdr_digest	= "enable transport protocol header digest (TCP transport)";
static const char *nvmf_data_digest	= "enable transport protocol data digest (TCP transport)";
static const char *nvmf_tls		= "enable TLS";
static const char *nvmf_concat		= "enable secure concatenation";
static const char *nvmf_config_file	= "Use specified JSON configuration file or 'none' to disable";
static const char *nvmf_context		= "execution context identification string";

#define NVMF_ARGS(n, c, ...)                                                                     \
	struct argconfig_commandline_options n[] = {                                             \
		OPT_STRING("transport",       't', "STR", &transport,     nvmf_tport),           \
		OPT_STRING("nqn",             'n', "STR", &subsysnqn,     nvmf_nqn),             \
		OPT_STRING("traddr",          'a', "STR", &traddr,        nvmf_traddr),          \
		OPT_STRING("trsvcid",         's', "STR", &trsvcid,       nvmf_trsvcid),         \
		OPT_STRING("host-traddr",     'w', "STR", &c.host_traddr, nvmf_htraddr),         \
		OPT_STRING("host-iface",      'f', "STR", &c.host_iface,  nvmf_hiface),          \
		OPT_STRING("hostnqn",         'q', "STR", &hostnqn,       nvmf_hostnqn),         \
		OPT_STRING("hostid",          'I', "STR", &hostid,        nvmf_hostid),          \
		OPT_STRING("dhchap-secret",   'S', "STR", &hostkey,       nvmf_hostkey),         \
		OPT_INT("nr-io-queues",       'i', &c.nr_io_queues,       nvmf_nr_io_queues),    \
		OPT_INT("nr-write-queues",    'W', &c.nr_write_queues,    nvmf_nr_write_queues), \
		OPT_INT("nr-poll-queues",     'P', &c.nr_poll_queues,     nvmf_nr_poll_queues),  \
		OPT_INT("queue-size",         'Q', &c.queue_size,         nvmf_queue_size),      \
		OPT_INT("keep-alive-tmo",     'k', &c.keep_alive_tmo,     nvmf_keep_alive_tmo),  \
		OPT_INT("reconnect-delay",    'c', &c.reconnect_delay,    nvmf_reconnect_delay), \
		OPT_INT("ctrl-loss-tmo",      'l', &c.ctrl_loss_tmo,      nvmf_ctrl_loss_tmo),   \
		OPT_INT("tos",                'T', &c.tos,                nvmf_tos),             \
		OPT_INT("keyring",              0, &c.keyring,            nvmf_keyring),         \
		OPT_INT("tls_key",              0, &c.tls_key,            nvmf_tls_key),         \
		OPT_FLAG("duplicate-connect", 'D', &c.duplicate_connect,  nvmf_dup_connect),     \
		OPT_FLAG("disable-sqflow",    'd', &c.disable_sqflow,     nvmf_disable_sqflow),  \
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

static nvme_ctrl_t __create_discover_ctrl(nvme_root_t r, nvme_host_t h,
					  struct nvme_fabrics_config *cfg,
					  struct tr_config *trcfg)
{
	nvme_ctrl_t c;
	int tmo, ret;

	c = nvme_create_ctrl(r, trcfg->subsysnqn, trcfg->transport,
			     trcfg->traddr, trcfg->host_traddr,
			     trcfg->host_iface, trcfg->trsvcid);
	if (!c)
		return NULL;

	nvme_ctrl_set_discovery_ctrl(c, true);
	nvme_ctrl_set_unique_discovery_ctrl(c,
		     strcmp(trcfg->subsysnqn, NVME_DISC_SUBSYS_NAME));
	tmo = set_discovery_kato(cfg);

	errno = 0;
	ret = nvmf_add_ctrl(h, c, cfg);

	cfg->keep_alive_tmo = tmo;
	if (ret) {
		nvme_free_ctrl(c);
		return NULL;
	}

	return c;
}

static nvme_ctrl_t create_discover_ctrl(nvme_root_t r, nvme_host_t h,
					struct nvme_fabrics_config *cfg,
					struct tr_config *trcfg)
{
	nvme_ctrl_t c;

	c = __create_discover_ctrl(r, h, cfg, trcfg);
	if (!c)
		return NULL;

	if (nvme_ctrl_is_unique_discovery_ctrl(c))
		return c;

	/* Find out the name of discovery controller */
	struct nvme_id_ctrl id = { 0 };

	if (nvme_ctrl_identify(c, &id)) {
		fprintf(stderr,	"failed to identify controller, error %s\n",
			nvme_strerror(errno));
		nvme_disconnect_ctrl(c);
		nvme_free_ctrl(c);
		return NULL;
	}

	if (!strcmp(id.subnqn, NVME_DISC_SUBSYS_NAME))
		return c;

	/*
	 * The subsysnqn is not the well-known name. Prefer the unique
	 * subsysnqn over the well-known one.
	 */
	nvme_disconnect_ctrl(c);
	nvme_free_ctrl(c);

	trcfg->subsysnqn = id.subnqn;
	return __create_discover_ctrl(r, h, cfg, trcfg);
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

static int __discover(nvme_ctrl_t c, struct nvme_fabrics_config *defcfg,
		      char *raw, bool connect, bool persistent,
		      enum nvme_print_flags flags)
{
	struct nvmf_discovery_log *log = NULL;
	nvme_subsystem_t s = nvme_ctrl_get_subsystem(c);
	nvme_host_t h = nvme_subsystem_get_host(s);
	uint64_t numrec;

	struct nvme_get_discovery_args args = {
		.c = c,
		.args_size = sizeof(args),
		.max_retries = MAX_DISC_RETRIES,
		.result = 0,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lsp = 0,
	};

	log = nvmf_get_discovery_wargs(&args);
	if (!log) {
		fprintf(stderr, "failed to get discovery log: %s\n",
			nvme_strerror(errno));
		return -errno;
	}

	numrec = le64_to_cpu(log->numrec);
	if (raw)
		save_discovery_log(raw, log);
	else if (!connect) {
		nvme_show_discovery_log(log, numrec, flags);
	} else if (connect) {
		int i;

		for (i = 0; i < numrec; i++) {
			struct nvmf_disc_log_entry *e = &log->entries[i];
			nvme_ctrl_t cl;
			bool discover = false;
			bool disconnect;
			nvme_ctrl_t child;
			int tmo = defcfg->keep_alive_tmo;

			struct tr_config trcfg = {
				.subsysnqn	= e->subnqn,
				.transport	= nvmf_trtype_str(e->trtype),
				.traddr		= e->traddr,
				.host_traddr	= defcfg->host_traddr,
				.host_iface	= defcfg->host_iface,
				.trsvcid	= e->trsvcid,
			};

			/* Already connected ? */
			cl = lookup_ctrl(h, &trcfg);
			if (cl && nvme_ctrl_get_name(cl))
				continue;

			/* Skip connect if the transport types don't match */
			if (strcmp(nvme_ctrl_get_transport(c),
				   nvmf_trtype_str(e->trtype)))
				continue;

			if (e->subtype == NVME_NQN_DISC ||
			    e->subtype == NVME_NQN_CURR) {
				__u16 eflags = le16_to_cpu(e->eflags);
				/*
				 * Does this discovery controller return the
				 * same information?
				 */
				if (eflags & NVMF_DISC_EFLAGS_DUPRETINFO)
					continue;

				/* Are we supposed to keep the discovery controller around? */
				disconnect = !persistent;

				if (strcmp(e->subnqn, NVME_DISC_SUBSYS_NAME)) {
					/*
					 * Does this discovery controller doesn't
					 * support explicit persistent connection?
					 */
					if (!(eflags & NVMF_DISC_EFLAGS_EPCSD))
						disconnect = true;
					else
						disconnect = false;
				}

				set_discovery_kato(defcfg);
			} else {
				/* NVME_NQN_NVME */
				disconnect = false;
			}

			errno = 0;
			child = nvmf_connect_disc_entry(h, e, defcfg,
							&discover);

			defcfg->keep_alive_tmo = tmo;

			if (child) {
				if (discover)
					__discover(child, defcfg, raw,
						   true, persistent, flags);

				if (disconnect) {
					nvme_disconnect_ctrl(child);
					nvme_free_ctrl(child);
				}
			} else if (errno == ENVME_CONNECT_ALREADY && !quiet) {
				char *traddr = log->entries[i].traddr;

				fprintf(stderr,
					"traddr=%s is already connected\n",
					traddr);
			}
		}
	}

	free(log);
	return 0;
}

static char *get_default_trsvcid(const char *transport,
				 bool discovery_ctrl)
{
	if (!transport)
		return NULL;
	if (!strcmp(transport, "tcp")) {
		if (discovery_ctrl)
			/* Default port for NVMe/TCP discovery controllers */
			return stringify(NVME_DISC_IP_PORT);
		/* Default port for NVMe/TCP io controllers */
		return stringify(NVME_RDMA_IP_PORT);
	} else if (!strcmp(transport, "rdma")) {
		/* Default port for NVMe/RDMA controllers */
		return stringify(NVME_RDMA_IP_PORT);
	}

	return NULL;
}

static int discover_from_conf_file(nvme_root_t r, nvme_host_t h,
				   const char *desc, bool connect,
				   const struct nvme_fabrics_config *defcfg)
{
	char *transport = NULL, *traddr = NULL, *trsvcid = NULL;
	char *hostnqn = NULL, *hostid = NULL, *hostkey = NULL;
	char *subsysnqn = NULL;
	char *ptr, **argv, *p, line[4096];
	int argc, ret = 0;
	unsigned int verbose = 0;
	FILE *f;
	enum nvme_print_flags flags;
	char *format = "normal";
	struct nvme_fabrics_config cfg;
	bool force = false;

	NVMF_ARGS(opts, cfg,
		  OPT_FMT("output-format", 'o', &format,     output_format),
		  OPT_FILE("raw",          'r', &raw,        "save raw output to file"),
		  OPT_FLAG("persistent",   'p', &persistent, "persistent discovery connection"),
		  OPT_FLAG("quiet",        'S', &quiet,      "suppress already connected errors"),
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
		errno = ENOENT;
		return -1;
	}

	argv = calloc(MAX_DISC_ARGS, sizeof(char *));
	if (!argv) {
		ret = -1;
		goto out;
	}

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
		subsysnqn = NVME_DISC_SUBSYS_NAME;
		ret = argconfig_parse(argc, argv, desc, opts);
		if (ret)
			goto next;
		if (!transport && !traddr)
			goto next;

		if (!trsvcid)
			trsvcid = get_default_trsvcid(transport, true);

		struct tr_config trcfg = {
			.subsysnqn	= subsysnqn,
			.transport	= transport,
			.traddr		= traddr,
			.host_traddr	= cfg.host_traddr,
			.host_iface	= cfg.host_iface,
			.trsvcid	= trsvcid,
		};

		if (!force) {
			c = lookup_ctrl(h, &trcfg);
			if (c) {
				__discover(c, &cfg, raw, connect,
					   true, flags);
				goto next;
			}
		}

		c = create_discover_ctrl(r, h, &cfg, &trcfg);
		if (!c)
			goto next;

		__discover(c, &cfg, raw, connect, persistent, flags);
		if (!(persistent || is_persistent_discovery_ctrl(h, c)))
			ret = nvme_disconnect_ctrl(c);
		nvme_free_ctrl(c);

next:
		memset(&cfg, 0, sizeof(cfg));
	}
	free(argv);
out:
	fclose(f);
	return ret;
}

static int discover_from_json_config_file(nvme_root_t r, nvme_host_t h,
					  const char *desc, bool connect,
					  const struct nvme_fabrics_config *defcfg,
					  enum nvme_print_flags flags,
					  bool force)
{
	const char *transport, *traddr, *host_traddr, *host_iface, *trsvcid, *subsysnqn;
	nvme_subsystem_t s;
	nvme_ctrl_t c, cn;
	struct nvme_fabrics_config cfg;
	int ret = 0;

	nvme_for_each_subsystem(h, s) {
		nvme_subsystem_for_each_ctrl(s, c) {
			transport = nvme_ctrl_get_transport(c);
			traddr = nvme_ctrl_get_traddr(c);
			host_traddr = nvme_ctrl_get_host_traddr(c);
			host_iface = nvme_ctrl_get_host_iface(c);

			if (!transport && !traddr)
				continue;

			/* ignore none fabric transports */
			if (strcmp(transport, "tcp") &&
			    strcmp(transport, "rdma") &&
			    strcmp(transport, "fc"))
				continue;

			/* ignore if no host_traddr for fc */
			if (!strcmp(transport, "fc")) {
				if (!host_traddr) {
					fprintf(stderr, "host_traddr required for fc\n");
					continue;
				}
			}

			/* ignore if host_iface set for any transport other than tcp */
			if (!strcmp(transport, "rdma") || !strcmp(transport, "fc")) {
				if (host_iface) {
					fprintf(stderr, "host_iface not permitted for rdma or fc\n");
					continue;
				}
			}

			trsvcid = nvme_ctrl_get_trsvcid(c);
			if (!trsvcid || !strcmp(trsvcid, ""))
				trsvcid = get_default_trsvcid(transport, true);

			if (force)
				subsysnqn = nvme_ctrl_get_subsysnqn(c);
			else
				subsysnqn = NVME_DISC_SUBSYS_NAME;

			if (nvme_ctrl_is_persistent(c))
				persistent = true;

			memcpy(&cfg, defcfg, sizeof(cfg));

			struct tr_config trcfg = {
				.subsysnqn	= subsysnqn,
				.transport	= transport,
				.traddr		= traddr,
				.host_traddr	= host_traddr,
				.host_iface	= host_iface,
				.trsvcid	= trsvcid,
			};

			if (!force) {
				cn = lookup_ctrl(h, &trcfg);
				if (cn) {
					__discover(cn, &cfg, raw, connect,
						   true, flags);
					continue;
				}
			}

			cn = create_discover_ctrl(r, h, &cfg, &trcfg);
			if (!cn)
				continue;

			__discover(cn, &cfg, raw, connect, persistent, flags);
			if (!(persistent || is_persistent_discovery_ctrl(h, cn)))
				ret = nvme_disconnect_ctrl(cn);
			nvme_free_ctrl(cn);
		}
	}

	return ret;
}

static int nvme_read_volatile_config(nvme_root_t r)
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

		if (nvme_read_config(r, filename))
			ret = 0;

		free(filename);
	}
	closedir(d);

	return ret;
}

char *nvmf_hostid_from_hostnqn(const char *hostnqn)
{
	const char *uuid;

	if (!hostnqn)
		return NULL;

	uuid = strstr(hostnqn, "uuid:");
	if (!uuid)
		return NULL;

	return strdup(uuid + strlen("uuid:"));
}

void nvmf_check_hostid_and_hostnqn(const char *hostid, const char *hostnqn, unsigned int verbose)
{
	char *hostid_from_file, *hostid_from_hostnqn;

	if (!hostid)
		return;

	hostid_from_file = nvmf_hostid_from_file();
	if (hostid_from_file && strcmp(hostid_from_file, hostid)) {
		if (verbose)
			fprintf(stderr,
				"warning: use generated hostid instead of hostid file\n");
		free(hostid_from_file);
	}

	if (!hostnqn)
		return;

	hostid_from_hostnqn = nvmf_hostid_from_hostnqn(hostnqn);
	if (hostid_from_hostnqn && strcmp(hostid_from_hostnqn, hostid)) {
		if (verbose)
			fprintf(stderr,
				"warning: use hostid which does not match uuid in hostnqn\n");
		free(hostid_from_hostnqn);
	}
}

int nvmf_discover(const char *desc, int argc, char **argv, bool connect)
{
	char *subsysnqn = NVME_DISC_SUBSYS_NAME;
	char *hostnqn = NULL, *hostid = NULL, *hostkey = NULL;
	char *hostnqn_arg, *hostid_arg;
	char *transport = NULL, *traddr = NULL, *trsvcid = NULL;
	char *config_file = PATH_NVMF_CONFIG;
	char *hnqn = NULL, *hid = NULL;
	char *context = NULL;
	enum nvme_print_flags flags;
	nvme_root_t r;
	nvme_host_t h;
	nvme_ctrl_t c = NULL;
	unsigned int verbose = 0;
	int ret;
	char *format = "normal";
	struct nvme_fabrics_config cfg;
	char *device = NULL;
	bool force = false;
	bool json_config = false;
	bool nbft = false, nonbft = false;
	char *nbft_path = NBFT_SYSFS_PATH;

	NVMF_ARGS(opts, cfg,
		  OPT_STRING("device",     'd', "DEV", &device,       "use existing discovery controller device"),
		  OPT_FMT("output-format", 'o', &format,              output_format),
		  OPT_FILE("raw",          'r', &raw,                 "save raw output to file"),
		  OPT_FLAG("persistent",   'p', &persistent,          "persistent discovery connection"),
		  OPT_FLAG("quiet",        'S', &quiet,               "suppress already connected errors"),
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

	r = nvme_create_root(stderr, log_level);
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}
	if (context)
		nvme_root_set_application(r, context);
	ret = nvme_scan_topology(r, NULL, NULL);
	if (ret < 0) {
		if (errno != ENOENT)
			fprintf(stderr, "Failed to scan topology: %s\n",
				nvme_strerror(errno));
		nvme_free_tree(r);
		return ret;
	}

	if (!nvme_read_config(r, config_file))
		json_config = true;
	if (!nvme_read_volatile_config(r))
		json_config = true;

	hostnqn_arg = hostnqn;
	hostid_arg = hostid;
	if (!hostnqn)
		hostnqn = hnqn = nvmf_hostnqn_from_file();
	if (!hostnqn) {
		hostnqn = hnqn = nvmf_hostnqn_generate();
		hostid = hid = nvmf_hostid_from_hostnqn(hostnqn);
	}
	if (!hostid)
		hostid = hid = nvmf_hostid_from_file();
	if (!hostid && hostnqn)
		hostid = hid = nvmf_hostid_from_hostnqn(hostnqn);
	nvmf_check_hostid_and_hostnqn(hostid, hostnqn, verbose);
	h = nvme_lookup_host(r, hostnqn, hostid);
	if (!h) {
		ret = ENOMEM;
		goto out_free;
	}
	if (device) {
		if (!strcmp(device, "none"))
			device = NULL;
		else if (!strncmp(device, "/dev/", 5))
			device += 5;
	}
	if (hostkey)
		nvme_host_set_dhchap_key(h, hostkey);

	if (!device && !transport && !traddr) {
		if (!nonbft)
			discover_from_nbft(r, hostnqn_arg, hostid_arg,
					   hostnqn, hostid, desc, connect,
					   &cfg, nbft_path, flags, verbose);

		if (nbft)
			goto out_free;

		if (json_config)
			ret = discover_from_json_config_file(r, h, desc,
							     connect, &cfg,
							     flags, force);
		if (ret || access(PATH_NVMF_DISC, F_OK))
			goto out_free;

		ret = discover_from_conf_file(r, h, desc, connect, &cfg);
		goto out_free;
	}

	if (!trsvcid)
		trsvcid = get_default_trsvcid(transport, true);

	struct tr_config trcfg = {
		.subsysnqn	= subsysnqn,
		.transport	= transport,
		.traddr		= traddr,
		.host_traddr	= cfg.host_traddr,
		.host_iface	= cfg.host_iface,
		.trsvcid	= trsvcid,
	};

	if (device && !force) {
		c = nvme_scan_ctrl(r, device);
		if (c) {
			/* Check if device matches command-line options */
			if (!nvme_ctrl_config_match(c, transport, traddr, trsvcid, subsysnqn,
						    cfg.host_traddr, cfg.host_iface)) {
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
				if (!cfg.host_traddr)
					cfg.host_traddr = (char *)nvme_ctrl_get_host_traddr(c);
				if (!cfg.host_iface)
					cfg.host_iface = (char *)nvme_ctrl_get_host_iface(c);
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
		c = create_discover_ctrl(r, h, &cfg, &trcfg);
		if (!c) {
			if (errno != ENVME_CONNECT_IGNORED)
				fprintf(stderr,
					"failed to add controller, error %s\n",
					nvme_strerror(errno));
			ret = errno;
			goto out_free;
		}
	}

	ret = __discover(c, &cfg, raw, connect, persistent, flags);
	if (!(persistent || is_persistent_discovery_ctrl(h, c)))
		nvme_disconnect_ctrl(c);
	nvme_free_ctrl(c);

out_free:
	free(hnqn);
	free(hid);
	if (dump_config)
		nvme_dump_config(r);
	nvme_free_tree(r);

	return ret;
}

int nvmf_connect(const char *desc, int argc, char **argv)
{
	char *subsysnqn = NULL;
	char *transport = NULL, *traddr = NULL;
	char *trsvcid = NULL, *hostnqn = NULL, *hostid = NULL;
	char *hostkey = NULL, *ctrlkey = NULL;
	char *hnqn = NULL, *hid = NULL;
	char *config_file = PATH_NVMF_CONFIG;
	char *context = NULL;
	unsigned int verbose = 0;
	nvme_root_t r;
	nvme_host_t h;
	nvme_ctrl_t c;
	int ret;
	enum nvme_print_flags flags;
	struct nvme_fabrics_config cfg = { 0 };
	char *format = "normal";


	NVMF_ARGS(opts, cfg,
		  OPT_STRING("dhchap-ctrl-secret", 'C', "STR", &ctrlkey,      nvmf_ctrlkey),
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

	if (!subsysnqn) {
		fprintf(stderr,
			"required argument [--nqn | -n] not specified\n");
		return -EINVAL;
	}

	if (!transport) {
		fprintf(stderr,
			"required argument [--transport | -t] not specified\n");
		return -EINVAL;
	}

	if (strcmp(transport, "loop")) {
		if (!traddr) {
			fprintf(stderr,
				"required argument [--traddr | -a] not specified for transport %s\n",
				transport);
			return -EINVAL;
		}
	}

	if (!strcmp(config_file, "none"))
		config_file = NULL;

	log_level = map_log_level(verbose, quiet);

	r = nvme_create_root(stderr, log_level);
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}
	if (context)
		nvme_root_set_application(r, context);
	ret = nvme_scan_topology(r, NULL, NULL);
	if (ret < 0) {
		if (errno != ENOENT)
			fprintf(stderr, "Failed to scan topology: %s\n",
				nvme_strerror(errno));
		nvme_free_tree(r);
		return ret;
	}
	nvme_read_config(r, config_file);
	nvme_read_volatile_config(r);

	if (!hostnqn)
		hostnqn = hnqn = nvmf_hostnqn_from_file();
	if (!hostnqn) {
		hostnqn = hnqn = nvmf_hostnqn_generate();
		hostid = hid = nvmf_hostid_from_hostnqn(hostnqn);
	}
	if (!hostid)
		hostid = hid = nvmf_hostid_from_file();
	if (!hostid && hostnqn)
		hostid = hid = nvmf_hostid_from_hostnqn(hostnqn);
	nvmf_check_hostid_and_hostnqn(hostid, hostnqn, verbose);
	h = nvme_lookup_host(r, hostnqn, hostid);
	if (!h) {
		errno = ENOMEM;
		goto out_free;
	}
	if (hostkey)
		nvme_host_set_dhchap_key(h, hostkey);
	if (!trsvcid)
		trsvcid = get_default_trsvcid(transport, false);

	struct tr_config trcfg = {
		.subsysnqn	= subsysnqn,
		.transport	= transport,
		.traddr		= traddr,
		.host_traddr	= cfg.host_traddr,
		.host_iface	= cfg.host_iface,
		.trsvcid	= trsvcid,
	};

	c = lookup_ctrl(h, &trcfg);
	if (c && nvme_ctrl_get_name(c)) {
		fprintf(stderr, "already connected\n");
		errno = EALREADY;
		goto out_free;
	}

	c = nvme_create_ctrl(r, subsysnqn, transport, traddr,
			     cfg.host_traddr, cfg.host_iface, trsvcid);
	if (!c) {
		errno = ENOMEM;
		goto out_free;
	}
	if (ctrlkey)
		nvme_ctrl_set_dhchap_key(c, ctrlkey);

	errno = 0;
	ret = nvmf_add_ctrl(h, c, &cfg);
	if (ret)
		fprintf(stderr, "could not add new controller: %s\n",
			nvme_strerror(errno));
	else {
		errno = 0;
		if (flags != -EINVAL)
			nvme_show_connect_msg(c, flags);
	}

out_free:
	free(hnqn);
	free(hid);
	if (dump_config)
		nvme_dump_config(r);
	nvme_free_tree(r);
	return -errno;
}

static nvme_ctrl_t lookup_nvme_ctrl(nvme_root_t r, const char *name)
{
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;

	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			nvme_subsystem_for_each_ctrl(s, c) {
				if (!strcmp(nvme_ctrl_get_name(c), name))
					return c;
			}
		}
	}
	return NULL;
}

static void nvmf_disconnect_nqn(nvme_root_t r, char *nqn)
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
		nvme_for_each_host(r, h) {
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
	nvme_root_t r;
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

	if (!cfg.nqn && !cfg.device) {
		fprintf(stderr,
			"Neither device name [--device | -d] nor NQN [--nqn | -n] provided\n");
		return -EINVAL;
	}

	log_level = map_log_level(cfg.verbose, false);

	r = nvme_create_root(stderr, log_level);
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}
	ret = nvme_scan_topology(r, NULL, NULL);
	if (ret < 0) {
		if (errno != ENOENT)
			fprintf(stderr, "Failed to scan topology: %s\n",
				nvme_strerror(errno));
		nvme_free_tree(r);
		return ret;
	}

	if (cfg.nqn)
		nvmf_disconnect_nqn(r, cfg.nqn);

	if (cfg.device) {
		char *d;

		d = cfg.device;
		while ((p = strsep(&d, ",")) != NULL) {
			if (!strncmp(p, "/dev/", 5))
				p += 5;
			c = lookup_nvme_ctrl(r, p);
			if (!c) {
				fprintf(stderr,
					"Did not find device %s\n", p);
				nvme_free_tree(r);
				return -errno;
			}
			ret = nvme_disconnect_ctrl(c);
			if (ret)
				fprintf(stderr,
					"Failed to disconnect %s: %s\n",
					p, nvme_strerror(errno));
		}
	}
	nvme_free_tree(r);

	return 0;
}

int nvmf_disconnect_all(const char *desc, int argc, char **argv)
{
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_root_t r;
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

	r = nvme_create_root(stderr, log_level);
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}
	ret = nvme_scan_topology(r, NULL, NULL);
	if (ret < 0) {
		if (errno != ENOENT)
			fprintf(stderr, "Failed to scan topology: %s\n",
				nvme_strerror(errno));
		nvme_free_tree(r);
		return ret;
	}

	nvme_for_each_host(r, h) {
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
	nvme_free_tree(r);

	return 0;
}

int nvmf_config(const char *desc, int argc, char **argv)
{
	char *subsysnqn = NULL;
	char *transport = NULL, *traddr = NULL;
	char *trsvcid = NULL, *hostnqn = NULL, *hostid = NULL;
	char *hnqn = NULL, *hid = NULL;
	char *hostkey = NULL, *ctrlkey = NULL;
	char *config_file = PATH_NVMF_CONFIG;
	unsigned int verbose = 0;
	nvme_root_t r;
	int ret;
	struct nvme_fabrics_config cfg;
	bool scan_tree = false, modify_config = false, update_config = false;

	NVMF_ARGS(opts, cfg,
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

	r = nvme_create_root(stderr, log_level);
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}
	if (scan_tree) {
		ret = nvme_scan_topology(r, NULL, NULL);
		if (ret < 0) {
			if (errno != ENOENT)
				fprintf(stderr, "Failed to scan topology: %s\n",
					nvme_strerror(errno));
			nvme_free_tree(r);
			return ret;
		}
	}
	nvme_read_config(r, config_file);

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
		h = nvme_lookup_host(r, hostnqn, hostid);
		if (!h) {
			fprintf(stderr, "Failed to lookup host '%s': %s\n",
				hostnqn, nvme_strerror(errno));
			goto out;
		}
		if (hostkey)
			nvme_host_set_dhchap_key(h, hostkey);
		s = nvme_lookup_subsystem(h, NULL, subsysnqn);
		if (!s) {
			fprintf(stderr, "Failed to lookup subsystem '%s': %s\n",
				subsysnqn, nvme_strerror(errno));
			goto out;
		}
		c = nvme_lookup_ctrl(s, transport, traddr,
				     cfg.host_traddr, cfg.host_iface,
				     trsvcid, NULL);
		if (!c) {
			fprintf(stderr, "Failed to lookup controller: %s\n",
				nvme_strerror(errno));
			goto out;
		}
		nvmf_update_config(c, &cfg);
		if (ctrlkey)
			nvme_ctrl_set_dhchap_key(c, ctrlkey);
	}

	if (update_config)
		nvme_update_config(r);

	if (dump_config)
		nvme_dump_config(r);

out:
	if (hid)
		free(hid);
	if (hnqn)
		free(hnqn);
	nvme_free_tree(r);
	return -errno;
}

static void dim_operation(nvme_ctrl_t c, enum nvmf_dim_tas tas, const char *name)
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
}

int nvmf_dim(const char *desc, int argc, char **argv)
{
	enum nvmf_dim_tas tas;
	nvme_root_t r;
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

	r = nvme_create_root(stderr, log_level);
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}
	ret = nvme_scan_topology(r, NULL, NULL);
	if (ret < 0) {
		if (errno != ENOENT)
			fprintf(stderr, "Failed to scan topology: %s\n",
				nvme_strerror(errno));
		nvme_free_tree(r);
		return ret;
	}

	if (cfg.nqn) {
		nvme_host_t h;
		nvme_subsystem_t s;
		char *n = cfg.nqn;

		while ((p = strsep(&n, ",")) != NULL) {
			if (!strlen(p))
				continue;
			nvme_for_each_host(r, h) {
				nvme_for_each_subsystem(h, s) {
					if (strcmp(nvme_subsystem_get_nqn(s), p))
						continue;
					nvme_subsystem_for_each_ctrl(s, c) {
						dim_operation(c, tas, p);
					}
				}
			}
		}
	}

	if (cfg.device) {
		char *d = cfg.device;

		while ((p = strsep(&d, ",")) != NULL) {
			if (!strncmp(p, "/dev/", 5))
				p += 5;
			c = nvme_scan_ctrl(r, p);
			if (!c) {
				fprintf(stderr,
					"Did not find device %s: %s\n",
					p, nvme_strerror(errno));
				nvme_free_tree(r);
				return -errno;
			}
			dim_operation(c, tas, p);
		}
	}

	nvme_free_tree(r);

	return 0;
}
