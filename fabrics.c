/* SPDX-License-Identifier: GPL-2.0-only */
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

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "nvme-print.h"

#define PATH_NVMF_DISC		SYSCONFDIR "/nvme/discovery.conf"
#define PATH_NVMF_CONFIG	SYSCONFDIR "/nvme/config.json"
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
static const char *nvmf_dup_connect	= "allow duplicate connections between same transport host and subsystem port";
static const char *nvmf_disable_sqflow	= "disable controller sq flow control (default false)";
static const char *nvmf_hdr_digest	= "enable transport protocol header digest (TCP transport)";
static const char *nvmf_data_digest	= "enable transport protocol data digest (TCP transport)";
static const char *nvmf_config_file	= "Use specified JSON configuration file or 'none' to disable";

#define NVMF_OPTS(c)									\
	OPT_STRING("transport",       't', "STR", &transport,	nvmf_tport), \
	OPT_STRING("traddr",          'a', "STR", &traddr,	nvmf_traddr), \
	OPT_STRING("trsvcid",         's', "STR", &trsvcid,	nvmf_trsvcid), \
	OPT_STRING("host-traddr",     'w', "STR", &c.host_traddr,	nvmf_htraddr), \
	OPT_STRING("host-iface",      'f', "STR", &c.host_iface,	nvmf_hiface), \
	OPT_STRING("hostnqn",         'q', "STR", &hostnqn,	nvmf_hostnqn), \
	OPT_STRING("hostid",          'I', "STR", &hostid,	nvmf_hostid), \
	OPT_STRING("nqn",             'n', "STR", &subsysnqn,	nvmf_nqn), \
	OPT_STRING("dhchap-secret",   'S', "STR", &hostkey,     nvmf_hostkey), \
	OPT_INT("nr-io-queues",       'i', &c.nr_io_queues,       nvmf_nr_io_queues),	\
	OPT_INT("nr-write-queues",    'W', &c.nr_write_queues,    nvmf_nr_write_queues),\
	OPT_INT("nr-poll-queues",     'P', &c.nr_poll_queues,     nvmf_nr_poll_queues),	\
	OPT_INT("queue-size",         'Q', &c.queue_size,         nvmf_queue_size),	\
	OPT_INT("keep-alive-tmo",     'k', &c.keep_alive_tmo,     nvmf_keep_alive_tmo),	\
	OPT_INT("reconnect-delay",    'c', &c.reconnect_delay,    nvmf_reconnect_delay),\
	OPT_INT("ctrl-loss-tmo",      'l', &c.ctrl_loss_tmo,      nvmf_ctrl_loss_tmo),	\
	OPT_INT("tos",                'T', &c.tos,                nvmf_tos),		\
	OPT_FLAG("duplicate-connect", 'D', &c.duplicate_connect,  nvmf_dup_connect),	\
	OPT_FLAG("disable-sqflow",    'd', &c.disable_sqflow,     nvmf_disable_sqflow),	\
	OPT_FLAG("hdr-digest",        'g', &c.hdr_digest,         nvmf_hdr_digest),	\
	OPT_FLAG("data-digest",       'G', &c.data_digest,        nvmf_data_digest)	\

struct tr_config {
	const char *subsysnqn;
	const char *transport;
	const char *traddr;
	const char *host_traddr;
	const char *host_iface;
	const char *trsvcid;
};

static void space_strip_len(int max, char *str)
{
	int i;

	for (i = max - 1; i >= 0; i--) {
		if (str[i] != '\0' && str[i] != ' ')
			return;
		else
			str[i] = '\0';
	}
}

/*
 * Compare two C strings and handle NULL pointers gracefully.
 * If either of the two strings is NULL, return 0
 * to let caller ignore the compare.
 */
static inline int strcmp0(const char *s1, const char *s2)
{
	if (!s1 || !s2)
		return 0;
	return strcmp(s1, s2);
}

/*
 * Compare two C strings and handle NULL pointers gracefully.
 * If either of the two strings is NULL, return 0
 * to let caller ignore the compare.
 */
static inline int strcasecmp0(const char *s1, const char *s2)
{
	if (!s1 || !s2)
		return 0;
	return strcasecmp(s1, s2);
}

static bool disc_ctrl_config_match(nvme_ctrl_t c, struct tr_config *trcfg)
{
	if (!strcmp0(nvme_ctrl_get_transport(c), trcfg->transport) &&
	    !strcasecmp0(nvme_ctrl_get_traddr(c), trcfg->traddr) &&
	    !strcmp0(nvme_ctrl_get_trsvcid(c), trcfg->trsvcid) &&
	    !strcmp0(nvme_ctrl_get_host_traddr(c), trcfg->host_traddr) &&
	    !strcmp0(nvme_ctrl_get_host_iface(c), trcfg->host_iface))
		return true;

	return false;
}

static bool ctrl_config_match(nvme_ctrl_t c, struct tr_config *trcfg)
{
	if (!strcmp0(nvme_ctrl_get_subsysnqn(c), trcfg->subsysnqn) &&
	    disc_ctrl_config_match(c, trcfg))
		return true;

	return false;
}

static nvme_ctrl_t __lookup_ctrl(nvme_root_t r, struct tr_config *trcfg,
			     bool (*filter)(nvme_ctrl_t, struct tr_config *))
{
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;

	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			nvme_subsystem_for_each_ctrl(s, c) {
				if (!(filter(c, trcfg)))
					continue;
				return c;
			}
		}
	}

	return NULL;
}

static nvme_ctrl_t lookup_discovery_ctrl(nvme_root_t r, struct tr_config *trcfg)
{
	return __lookup_ctrl(r, trcfg, disc_ctrl_config_match);
}

static nvme_ctrl_t lookup_ctrl(nvme_root_t r, struct tr_config *trcfg)
{
	return __lookup_ctrl(r, trcfg, ctrl_config_match);
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

	if (!persistent)
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

static void print_discovery_log(struct nvmf_discovery_log *log, int numrec)
{
	int i;

	printf("\nDiscovery Log Number of Records %d, "
	       "Generation counter %"PRIu64"\n",
		numrec, le64_to_cpu(log->genctr));

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_log_entry *e = &log->entries[i];

		space_strip_len(NVMF_TRSVCID_SIZE, e->trsvcid);
		space_strip_len(NVMF_TRADDR_SIZE, e->traddr);

		printf("=====Discovery Log Entry %d======\n", i);
		printf("trtype:  %s\n", nvmf_trtype_str(e->trtype));
		printf("adrfam:  %s\n",
			strlen(e->traddr) ?
			nvmf_adrfam_str(e->adrfam): "");
		printf("subtype: %s\n", nvmf_subtype_str(e->subtype));
		printf("treq:    %s\n", nvmf_treq_str(e->treq));
		printf("portid:  %d\n", le16_to_cpu(e->portid));
		printf("trsvcid: %s\n", e->trsvcid);
		printf("subnqn:  %s\n", e->subnqn);
		printf("traddr:  %s\n", e->traddr);
		printf("eflags:  %s\n",
		       nvmf_eflags_str(le16_to_cpu(e->eflags)));

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			printf("rdma_prtype: %s\n",
				nvmf_prtype_str(e->tsas.rdma.prtype));
			printf("rdma_qptype: %s\n",
				nvmf_qptype_str(e->tsas.rdma.qptype));
			printf("rdma_cms:    %s\n",
				nvmf_cms_str(e->tsas.rdma.cms));
			printf("rdma_pkey: 0x%04x\n",
				le16_to_cpu(e->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			printf("sectype: %s\n",
				nvmf_sectype_str(e->tsas.tcp.sectype));
			break;
		}
	}
}

static void json_discovery_log(struct nvmf_discovery_log *log, int numrec)
{
	struct json_object *root;
	struct json_object *entries;
	int i;

	root = json_create_object();
	entries = json_create_array();
	json_object_add_value_uint64(root, "genctr", le64_to_cpu(log->genctr));
	json_object_add_value_array(root, "records", entries);

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_log_entry *e = &log->entries[i];
		struct json_object *entry = json_create_object();

		nvme_strip_spaces(e->trsvcid, NVMF_TRSVCID_SIZE);
		nvme_strip_spaces(e->subnqn, NVMF_NQN_SIZE);
		nvme_strip_spaces(e->traddr, NVMF_TRADDR_SIZE);

		json_object_add_value_string(entry, "trtype",
					     nvmf_trtype_str(e->trtype));
		json_object_add_value_string(entry, "adrfam",
					     nvmf_adrfam_str(e->adrfam));
		json_object_add_value_string(entry, "subtype",
					     nvmf_subtype_str(e->subtype));
		json_object_add_value_string(entry,"treq",
					     nvmf_treq_str(e->treq));
		json_object_add_value_uint(entry, "portid",
					   le16_to_cpu(e->portid));
		json_object_add_value_string(entry, "trsvcid", e->trsvcid);
		json_object_add_value_string(entry, "subnqn", e->subnqn);
		json_object_add_value_string(entry, "traddr", e->traddr);
		json_object_add_value_string(entry, "eflags",
					     nvmf_eflags_str(le16_to_cpu(e->eflags)));

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			json_object_add_value_string(entry, "rdma_prtype",
				nvmf_prtype_str(e->tsas.rdma.prtype));
			json_object_add_value_string(entry, "rdma_qptype",
				nvmf_qptype_str(e->tsas.rdma.qptype));
			json_object_add_value_string(entry, "rdma_cms",
				nvmf_cms_str(e->tsas.rdma.cms));
			json_object_add_value_uint(entry, "rdma_pkey",
				le16_to_cpu(e->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			json_object_add_value_string(entry, "sectype",
				nvmf_sectype_str(e->tsas.tcp.sectype));
			break;
		}
		json_array_add_value_object(entries, entry);
	}
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void save_discovery_log(char *raw, struct nvmf_discovery_log *log)
{
	uint64_t numrec = le64_to_cpu(log->numrec);
	int fd, len, ret;

	fd = open(raw, O_CREAT|O_RDWR|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s: %s\n",
			raw, strerror(errno));
		return;
	}

	len = sizeof(struct nvmf_discovery_log) +
		numrec * sizeof(struct nvmf_disc_log_entry);
	ret = write(fd, log, len);
	if (ret < 0)
		fprintf(stderr, "failed to write to %s: %s\n",
			raw, strerror(errno));
	else
		printf("Discovery log is saved to %s\n", raw);

	close(fd);
}

static void print_connect_msg(nvme_ctrl_t c)
{
	printf("device: %s\n", nvme_ctrl_get_name(c));
}

static void json_connect_msg(nvme_ctrl_t c)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_string(root, "device", nvme_ctrl_get_name(c));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int __discover(nvme_ctrl_t c, struct nvme_fabrics_config *defcfg,
		      char *raw, bool connect, bool persistent,
		      enum nvme_print_flags flags)
{
	struct nvmf_discovery_log *log = NULL;
	nvme_subsystem_t s = nvme_ctrl_get_subsystem(c);
	nvme_host_t h = nvme_subsystem_get_host(s);
	nvme_root_t r = nvme_host_get_root(h);
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
		return errno;
	}

	numrec = le64_to_cpu(log->numrec);
	if (raw)
		save_discovery_log(raw, log);
	else if (!connect) {
		switch (flags) {
		case NORMAL:
			print_discovery_log(log, numrec);
			break;
		case JSON:
			json_discovery_log(log, numrec);
			break;
		case BINARY:
			d_raw((unsigned char *)log,
			      sizeof(struct nvmf_discovery_log) +
			      numrec * sizeof(struct nvmf_disc_log_entry));
			break;
		default:
			break;
		}
	} else if (connect) {
		int i;

		for (i = 0; i < numrec; i++) {
			struct nvmf_disc_log_entry *e = &log->entries[i];
			bool discover = false;
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
			if (lookup_ctrl(r, &trcfg))
				continue;

			/* Skip connect if the transport types don't match */
			if (strcmp(nvme_ctrl_get_transport(c), nvmf_trtype_str(e->trtype)))
				continue;

			if (e->subtype == NVME_NQN_DISC ||
			    e->subtype == NVME_NQN_CURR)
				set_discovery_kato(defcfg);

			errno = 0;
			child = nvmf_connect_disc_entry(h, e, defcfg,
							&discover);

			defcfg->keep_alive_tmo = tmo;

			if (child) {
				if (discover)
					__discover(child, defcfg, raw,
						   true, persistent, flags);
				if (e->subtype != NVME_NQN_NVME &&
				    !persistent) {
					nvme_disconnect_ctrl(child);
					nvme_free_ctrl(child);
				}
			} else if (errno == ENVME_CONNECT_ALREADY && !quiet) {
				char *traddr = log->entries[i].traddr;

				space_strip_len(NVMF_TRADDR_SIZE, traddr);
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
		if (discovery_ctrl) {
			/* Default port for NVMe/TCP discovery controllers */
			return stringify(NVME_DISC_IP_PORT);
		} else {
			/* Default port for NVMe/TCP io controllers */
			return stringify(NVME_RDMA_IP_PORT);
		}
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

	OPT_ARGS(opts) = {
		NVMF_OPTS(cfg),
		OPT_FMT("output-format", 'o', &format,        output_format),
		OPT_FILE("raw",          'r', &raw,           "save raw output to file"),
		OPT_FLAG("persistent",   'p', &persistent,    "persistent discovery connection"),
		OPT_FLAG("quiet",        'S', &quiet,         "suppress already connected errors"),
		OPT_INCR("verbose",      'v', &verbose,       "Increase logging verbosity"),
		OPT_FLAG("force",          0, &force,         "Force persistent discovery controller creation"),
		OPT_END()
	};

	nvmf_default_config(&cfg);

	ret = flags = validate_output_format(format);
	if (ret < 0)
		return ret;

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
			c = lookup_discovery_ctrl(r, &trcfg);
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
		if (!persistent)
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
	const char *transport, *traddr, *trsvcid, *subsysnqn;
	nvme_subsystem_t s;
	nvme_ctrl_t c, cn;
	struct nvme_fabrics_config cfg;
	int ret = 0;

	nvme_for_each_subsystem(h, s) {
		nvme_subsystem_for_each_ctrl(s, c) {
			transport = nvme_ctrl_get_transport(c);
			traddr = nvme_ctrl_get_traddr(c);

			if (!transport && !traddr)
				continue;

			/* ignore none fabric transports */
			if (strcmp(transport, "tcp") &&
			    strcmp(transport, "rdma") &&
			    strcmp(transport, "fc"))
				continue;

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
				.host_traddr	= cfg.host_traddr,
				.host_iface	= cfg.host_iface,
				.trsvcid	= trsvcid,
			};

			if (!force) {
				cn = lookup_discovery_ctrl(r, &trcfg);
				if (cn) {
					__discover(c, &cfg, raw, connect,
						   true, flags);
					continue;
				}
			}

			cn = create_discover_ctrl(r, h, &cfg, &trcfg);
			if (!cn)
				continue;

			__discover(cn, &cfg, raw, connect, persistent, flags);
			if (!persistent)
				ret = nvme_disconnect_ctrl(cn);
			nvme_free_ctrl(cn);
		}
	}

	return ret;
}

int nvmf_discover(const char *desc, int argc, char **argv, bool connect)
{
	char *subsysnqn = NVME_DISC_SUBSYS_NAME;
	char *hostnqn = NULL, *hostid = NULL, *hostkey = NULL;
	char *transport = NULL, *traddr = NULL, *trsvcid = NULL;
	char *config_file = PATH_NVMF_CONFIG;
	char *hnqn = NULL, *hid = NULL;
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

	OPT_ARGS(opts) = {
		OPT_STRING("device",   'd', "DEV", &device, "use existing discovery controller device"),
		NVMF_OPTS(cfg),
		OPT_FMT("output-format", 'o', &format,        output_format),
		OPT_FILE("raw",          'r', &raw,           "save raw output to file"),
		OPT_FLAG("persistent",   'p', &persistent,    "persistent discovery connection"),
		OPT_FLAG("quiet",        'S', &quiet,         "suppress already connected errors"),
		OPT_STRING("config",     'J', "FILE", &config_file, nvmf_config_file),
		OPT_INCR("verbose",      'v', &verbose,       "Increase logging verbosity"),
		OPT_FLAG("dump-config",  'O', &dump_config,   "Dump configuration file to stdout"),
		OPT_FLAG("force",          0, &force,         "Force persistent discovery controller creation"),
		OPT_END()
	};

	nvmf_default_config(&cfg);

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = flags = validate_output_format(format);
	if (ret < 0)
		return ret;

	if (!strcmp(config_file, "none"))
		config_file = NULL;

	r = nvme_create_root(stderr, map_log_level(verbose, quiet));
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}
	ret = nvme_scan_topology(r, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed to scan topology: %s\n",
			 nvme_strerror(errno));
		nvme_free_tree(r);
		return ret;
	}
	if (!nvme_read_config(r, config_file))
		json_config = true;

	if (!hostnqn)
		hostnqn = hnqn = nvmf_hostnqn_from_file();
	if (!hostnqn)
		hostnqn = hnqn = nvmf_hostnqn_generate();
	if (!hostid)
		hostid = hid = nvmf_hostid_from_file();
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
			if (!ctrl_config_match(c, &trcfg)) {
				fprintf(stderr,
					"ctrl device %s found, ignoring "
					"non matching command-line options\n",
					device);
			}

			if (!nvme_ctrl_is_discovery_ctrl(c)) {
				fprintf(stderr,
					"ctrl device %s found, ignoring "
					"non discovery controller\n",
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
		c = lookup_discovery_ctrl(r, &trcfg);
		if (c)
			persistent = true;
	}
	if (!c) {
		/* No device or non-matching device, create a new controller */
		c = create_discover_ctrl(r, h, &cfg, &trcfg);
	        if (!c) {
			fprintf(stderr,
				"failed to add controller, error %s\n",
				nvme_strerror(errno));
			ret = errno;
			goto out_free;
		}
	}

	ret = __discover(c, &cfg, raw, connect,
			 persistent, flags);
	if (!persistent)
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
	unsigned int verbose = 0;
	nvme_root_t r;
	nvme_host_t h;
	nvme_ctrl_t c;
	int ret;
	struct nvme_fabrics_config cfg;
	enum nvme_print_flags flags = -1;
	char *format = "";

	OPT_ARGS(opts) = {
		NVMF_OPTS(cfg),
		OPT_STRING("dhchap-ctrl-secret", 'C', "STR", &ctrlkey,  nvmf_ctrlkey),
		OPT_STRING("config", 'J', "FILE", &config_file, nvmf_config_file),
		OPT_INCR("verbose", 'v', &verbose, "Increase logging verbosity"),
		OPT_FLAG("dump-config", 'O', &dump_config, "Dump JSON configuration to stdout"),
		OPT_FMT("output-format", 'o', &format, "Output format: normal|json"),
		OPT_END()
	};

	nvmf_default_config(&cfg);

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!strcmp(format, ""))
		flags = -1;
	else if (!strcmp(format, "normal"))
		flags = NORMAL;
	else if (!strcmp(format, "json"))
		flags = JSON;
	else
		return EINVAL;

	if (!subsysnqn) {
		fprintf(stderr,
			"required argument [--nqn | -n] not specified\n");
		return EINVAL;
	}

	if (!transport) {
		fprintf(stderr,
			"required argument [--transport | -t] not specified\n");
		return EINVAL;
	}

	if (strcmp(transport, "loop")) {
		if (!traddr) {
			fprintf(stderr,
				"required argument [--traddr | -a] not specified for transport %s\n",
				transport);
			return EINVAL;
		}
	}

	if (!strcmp(config_file, "none"))
		config_file = NULL;

	r = nvme_create_root(stderr, map_log_level(verbose, quiet));
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}
	ret = nvme_scan_topology(r, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed to scan topology: %s\n",
			 nvme_strerror(errno));
		nvme_free_tree(r);
		return ret;
	}
	nvme_read_config(r, config_file);

	if (!hostnqn)
		hostnqn = hnqn = nvmf_hostnqn_from_file();
	if (!hostnqn)
		hostnqn = hnqn = nvmf_hostnqn_generate();
	if (!hostid)
		hostid = hid = nvmf_hostid_from_file();
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

	if (lookup_ctrl(r, &trcfg)) {
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
		if (flags == NORMAL)
			print_connect_msg(c);
		else if (flags == JSON)
			json_connect_msg(c);
	}

out_free:
	free(hnqn);
	free(hid);
	if (dump_config)
		nvme_dump_config(r);
	nvme_free_tree(r);
	return errno;
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

int nvmf_disconnect(const char *desc, int argc, char **argv)
{
	const char *device = "nvme device handle";
	nvme_root_t r;
	nvme_host_t h;
	nvme_subsystem_t s;
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
		OPT_STRING("nqn",    'n', "NAME", &cfg.nqn,    nvmf_nqn),
		OPT_STRING("device", 'd', "DEV",  &cfg.device, device),
		OPT_INCR("verbose",  'v', &cfg.verbose, "Increase logging verbosity"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!cfg.nqn && !cfg.device) {
		fprintf(stderr,
			"Neither device name [--device | -d] nor NQN [--nqn | -n] provided\n");
		return EINVAL;
	}

	r = nvme_create_root(stderr, map_log_level(cfg.verbose, false));
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}
	ret = nvme_scan_topology(r, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed to scan topology: %s\n",
			 nvme_strerror(errno));
		nvme_free_tree(r);
		return ret;
	}

	if (cfg.nqn) {
		int i = 0;
		char *n = cfg.nqn;

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
		printf("NQN:%s disconnected %d controller(s)\n", cfg.nqn, i);
	}

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
				return errno;
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

	r = nvme_create_root(stderr, map_log_level(cfg.verbose, false));
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}
	ret = nvme_scan_topology(r, NULL, NULL);
	if (ret < 0) {
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

	OPT_ARGS(opts) = {
		NVMF_OPTS(cfg),
		OPT_STRING("dhchap-ctrl-secret", 'C', "STR", &ctrlkey,  nvmf_ctrlkey),
		OPT_STRING("config", 'J', "FILE", &config_file, nvmf_config_file),
		OPT_INCR("verbose", 'v', &verbose, "Increase logging verbosity"),
		OPT_FLAG("scan", 'R', &scan_tree, "Scan current NVMeoF topology"),
		OPT_FLAG("modify", 'M', &modify_config, "Modify JSON configuration file"),
		OPT_FLAG("dump", 'O', &dump_config, "Dump JSON configuration to stdout"),
		OPT_FLAG("update", 'U', &update_config, "Update JSON configuration file"),
		OPT_END()
	};

	nvmf_default_config(&cfg);

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!strcmp(config_file, "none"))
		config_file = NULL;

	r = nvme_create_root(stderr, map_log_level(verbose, quiet));
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}
	if (scan_tree) {
		ret = nvme_scan_topology(r, NULL, NULL);
		if (ret < 0) {
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
			return EINVAL;
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
	return errno;
}

static void dim_operation(nvme_ctrl_t c, enum nvmf_dim_tas tas, const char * name)
{
	static const char * const task[] = {
		[NVMF_DIM_TAS_REGISTER]   = "register",
		[NVMF_DIM_TAS_DEREGISTER] = "deregister",
	};
	const char * t;
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
		return EINVAL;
	}

	if (!cfg.tas) {
		fprintf(stderr,
			"Task [--task | -t] must be specified\n");
		return EINVAL;
	}

	/* Allow partial name (e.g. "reg" for "register" */
	if (strstarts("register", cfg.tas)) {
		tas = NVMF_DIM_TAS_REGISTER;
	} else if (strstarts("deregister", cfg.tas)) {
		tas = NVMF_DIM_TAS_DEREGISTER;
	} else {
		fprintf(stderr, "Invalid --task: %s\n", cfg.tas);
		return EINVAL;
	}

	r = nvme_create_root(stderr, map_log_level(cfg.verbose, false));
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}
	ret = nvme_scan_topology(r, NULL, NULL);
	if (ret < 0) {
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
				return errno;
			}
			dim_operation(c, tas, p);
		}
	}

	nvme_free_tree(r);

	return 0;
}
