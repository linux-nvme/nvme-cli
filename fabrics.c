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

#define PATH_NVMF_DISC		"/etc/nvme/discovery.conf"
#define PATH_NVMF_CONFIG	"/etc/nvme/config.json"
#define MAX_DISC_ARGS		32
#define MAX_DISC_RETRIES	10

/* Name of file to output log pages in their raw format */
static char *raw;
static bool persistent;
static bool quiet;

static const char *nvmf_tport		= "transport type";
static const char *nvmf_traddr		= "transport address";
static const char *nvmf_nqn		= "subsystem nqn";
static const char *nvmf_trsvcid		= "transport service id (e.g. IP port)";
static const char *nvmf_htraddr		= "host traddr (e.g. FC WWN's)";
static const char *nvmf_hiface		= "host interface (for tcp transport)";
static const char *nvmf_hostnqn		= "user-defined hostnqn";
static const char *nvmf_hostid		= "user-defined hostid (if default not used)";
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
	OPT_STRING("host-traddr",     'w', "STR", &host_traddr,	nvmf_htraddr), \
	OPT_STRING("host-iface",      'f', "STR", &host_iface,	nvmf_hiface), \
	OPT_STRING("hostnqn",         'q', "STR", &hostnqn,	nvmf_hostnqn), \
	OPT_STRING("hostid",          'I', "STR", &hostid,	nvmf_hostid), \
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
	OPT_FLAG("data-digest",       'G', &c.data_digest,        nvmf_data_digest)     \


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
		printf("adrfam:  %s\n", nvmf_adrfam_str(e->adrfam));
		printf("subtype: %s\n", nvmf_subtype_str(e->subtype));
		printf("treq:    %s\n", nvmf_treq_str(e->treq));
		printf("portid:  %d\n", e->portid);
		printf("trsvcid: %s\n", e->trsvcid);
		printf("subnqn:  %s\n", e->subnqn);
		printf("traddr:  %s\n", e->traddr);

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			printf("rdma_prtype: %s\n",
				nvmf_prtype_str(e->tsas.rdma.prtype));
			printf("rdma_qptype: %s\n",
				nvmf_qptype_str(e->tsas.rdma.qptype));
			printf("rdma_cms:    %s\n",
				nvmf_cms_str(e->tsas.rdma.cms));
			printf("rdma_pkey: 0x%04x\n",
				e->tsas.rdma.pkey);
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
	json_object_add_value_uint(root, "genctr", le64_to_cpu(log->genctr));
	json_object_add_value_array(root, "records", entries);

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_log_entry *e = &log->entries[i];
		struct json_object *entry = json_create_object();

		json_object_add_value_string(entry, "trtype",
					     nvmf_trtype_str(e->trtype));
		json_object_add_value_string(entry, "adrfam",
					     nvmf_adrfam_str(e->adrfam));
		json_object_add_value_string(entry, "subtype",
					     nvmf_subtype_str(e->subtype));
		json_object_add_value_string(entry,"treq",
					     nvmf_treq_str(e->treq));
		json_object_add_value_uint(entry, "portid", e->portid);
		json_object_add_value_string(entry, "trsvcid",
					     e->trsvcid);
		json_object_add_value_string(entry, "subnqn", e->subnqn);
		json_object_add_value_string(entry, "traddr", e->traddr);

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			json_object_add_value_string(entry, "rdma_prtype",
				nvmf_prtype_str(e->tsas.rdma.prtype));
			json_object_add_value_string(entry, "rdma_qptype",
				nvmf_qptype_str(e->tsas.rdma.qptype));
			json_object_add_value_string(entry, "rdma_cms",
				nvmf_cms_str(e->tsas.rdma.cms));
			json_object_add_value_uint(entry, "rdma_pkey",
				e->tsas.rdma.pkey);
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
		nvme_msg(LOG_ERR, "failed to open %s: %s\n",
			 raw, strerror(errno));
		return;
	}

	len = sizeof(struct nvmf_discovery_log) +
		numrec * sizeof(struct nvmf_disc_log_entry);
	ret = write(fd, log, len);
	if (ret < 0)
		nvme_msg(LOG_ERR, "failed to write to %s: %s\n",
			 raw, strerror(errno));
	else
		printf("Discovery log is saved to %s\n", raw);

	close(fd);
}

static int __discover(nvme_ctrl_t c, const struct nvme_fabrics_config *defcfg,
		      char *raw, bool connect, bool persistent,
		      enum nvme_print_flags flags)
{
	struct nvmf_discovery_log *log = NULL;
	nvme_subsystem_t s = nvme_ctrl_get_subsystem(c);
	nvme_host_t h = nvme_subsystem_get_host(s);
	uint64_t numrec;
	int ret;

	ret = nvmf_get_discovery_log(c, &log, MAX_DISC_RETRIES);
	if (ret) {
		if (ret > 0)
			nvme_show_status(ret);
		else
			nvme_msg(LOG_ERR, "Failed to get discovery log: %d\n",
				 ret);
		return nvme_status_to_errno(ret, false);
	}


	numrec = le64_to_cpu(log->numrec);
	if (raw)
		save_discovery_log(raw, log);
	else if (!connect) {
		if (flags == JSON)
			json_discovery_log(log, numrec);
		else
			print_discovery_log(log, numrec);
	} else if (connect) {
		int i;

		for (i = 0; i < numrec; i++) {
			struct nvmf_disc_log_entry *e = &log->entries[i];
			bool discover = false;
			nvme_ctrl_t child;

			errno = 0;
			child = nvmf_connect_disc_entry(h, e, defcfg,
							&discover);
			if (child) {
				if (discover)
					__discover(child, defcfg, raw,
						   persistent,
						   true, flags);
				if (!persistent) {
					nvme_disconnect_ctrl(child);
					nvme_free_ctrl(child);
				}
			} else if (errno == EALREADY && !quiet) {
				char *traddr = log->entries[i].traddr;

				space_strip_len(NVMF_TRADDR_SIZE, traddr);
				nvme_msg(LOG_ERR,
					 "traddr=%s is already connected\n",
					 traddr);
			}
		}
	}

	free(log);
	return 0;
}

static int discover_from_conf_file(nvme_host_t h, const char *desc,
	bool connect, const struct nvme_fabrics_config *defcfg)
{
	char *transport = NULL, *traddr = NULL, *trsvcid = NULL;
	char *host_traddr = NULL, *host_iface = NULL;
	char *hostnqn = NULL, *hostid = NULL;
	char *ptr, **argv, *p, line[4096];
	int argc, ret = 0;
	FILE *f;

	struct nvme_fabrics_config cfg = {
		.tos = -1,
		.ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO,
	};

	OPT_ARGS(opts) = {
		NVMF_OPTS(cfg),
	};

	f = fopen(PATH_NVMF_DISC, "r");
	if (f == NULL) {
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
		ret = argconfig_parse(argc, argv, desc, opts);
		if (ret)
			goto next;

		if (!transport && !traddr)
			goto next;

		c = nvme_create_ctrl(NVME_DISC_SUBSYS_NAME, transport,
				     traddr, host_traddr, host_iface, trsvcid);
		if (!c)
			goto next;
		errno = 0;
		ret = nvmf_add_ctrl(h, c, &cfg, false);
		if (!ret) {
			__discover(c, defcfg, NULL, persistent,
				   connect, 0);
			if (!persistent)
				ret = nvme_disconnect_ctrl(c);
			nvme_free_ctrl(c);
		}
next:
		memset(&cfg, 0, sizeof(cfg));
	}
	free(argv);
out:
	fclose(f);
	return ret;
}

int nvmf_discover(const char *desc, int argc, char **argv, bool connect)
{
	char *nqn = NVME_DISC_SUBSYS_NAME;
	char *hostnqn = NULL, *hostid = NULL;
	char *host_traddr = NULL, *host_iface = NULL;
	char *transport = NULL, *traddr = NULL, *trsvcid = NULL;
	char *hnqn = NULL, *hid = NULL;
	char *config_file = PATH_NVMF_CONFIG;
	enum nvme_print_flags flags;
	nvme_root_t r;
	nvme_host_t h;
	unsigned int verbose = 0;
	int ret;
	char *format = "normal";
	const char *tmp_device;

	struct nvme_fabrics_config cfg = {
		.tos = -1,
	};

	char *device = NULL;

	OPT_ARGS(opts) = {
		OPT_STRING("device",   'd', "DEV", &device, "use existing discovery controller device"),
		NVMF_OPTS(cfg),
		OPT_FMT("output-format", 'o', &format,        output_format),
		OPT_FILE("raw",          'r', &raw,           "save raw output to file"),
		OPT_FLAG("persistent",   'p', &persistent,    "persistent discovery connection"),
		OPT_FLAG("quiet",        'S', &quiet,         "suppress already connected errors"),
		OPT_STRING("config",     'C', "FILE", &config_file, nvmf_config_file),
		OPT_INCR("verbose",      'v', &verbose,       "Increase logging verbosity"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = flags = validate_output_format(format);
	if (ret < 0)
		return ret;

	switch (verbose) {
	case 0:
		nvme_log_level = LOG_WARNING;
		break;
	case 1:
		nvme_log_level = LOG_NOTICE;
		break;
	case 2:
		nvme_log_level = LOG_INFO;
		break;
	default:
		nvme_log_level = LOG_DEBUG;
		break;
	}
	if (quiet)
		nvme_log_level = LOG_ERR;

	if (!strcmp(config_file, "none"))
		config_file = NULL;
	r = nvme_scan(config_file);
	if (persistent && !cfg.keep_alive_tmo)
		cfg.keep_alive_tmo = 30;
	if (!hostnqn)
		hostnqn = hnqn = nvmf_hostnqn_from_file();
	if (!hostid)
		hostid = hid = nvmf_hostid_from_file();
	h = nvme_lookup_host(r, hostnqn, hostid);
	if (!h) {
		ret = ENOMEM;
		goto out_free;
	}
	if (device && !strcmp(device, "none"))
		device = NULL;

	if (!device && !transport && !traddr)
		ret = discover_from_conf_file(h, desc, connect, &cfg);
	else {
		nvme_ctrl_t c;

		c = nvme_create_ctrl(nqn, transport, traddr,
				     host_traddr, host_iface, trsvcid);
		if (!c) {
			ret = ENOMEM;
			goto out_free;
		}
		tmp_device = nvme_ctrl_get_name(c);
		if (!tmp_device) {
			errno = 0;
			ret = nvmf_add_ctrl(h, c, &cfg, false);
		} else if (strcmp(tmp_device, device)) {
			device = NULL;
			ret = 0;
		}

		if (!ret) {
			ret = __discover(c, &cfg, raw, connect,
					 persistent, flags);
			if (!device && !persistent)
				nvme_disconnect_ctrl(c);
			nvme_free_ctrl(c);
		} else {
			nvme_msg(LOG_ERR, "no controller found\n");
			ret = errno;
			nvme_free_ctrl(c);
		}
	}
out_free:
	if (hnqn)
		free(hnqn);
	if (hid)
		free(hid);

	return ret;
}

int nvmf_connect(const char *desc, int argc, char **argv)
{
	char *hnqn = NULL, *hid = NULL;
	char *subsysnqn = NULL;
	char *transport = NULL, *traddr = NULL;
	char *host_traddr = NULL, *host_iface = NULL;
	char *trsvcid = NULL, *hostnqn = NULL, *hostid = NULL;
	char *config_file = PATH_NVMF_CONFIG;
	unsigned int verbose = 0;
	nvme_root_t r;
	nvme_host_t h;
	nvme_ctrl_t c;
	int ret;

	struct nvme_fabrics_config cfg = {
		.tos = -1,
		.ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO,
	};

	OPT_ARGS(opts) = {
		OPT_STRING("nqn", 'n', "NAME", &subsysnqn, nvmf_nqn),
		NVMF_OPTS(cfg),
		OPT_STRING("config", 'C', "FILE", &config_file, nvmf_config_file),
		OPT_INCR("verbose", 'v', &verbose, "Increase logging verbosity"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	switch (verbose) {
	case 0:
		nvme_log_level = LOG_WARNING;
		break;
	case 1:
		nvme_log_level = LOG_NOTICE;
		break;
	case 2:
		nvme_log_level = LOG_INFO;
		break;
	default:
		nvme_log_level = LOG_DEBUG;
		break;
	}

	if (!subsysnqn) {
		nvme_msg(LOG_ERR,
			 "required argument [--nqn | -n] not specified\n");
		return EINVAL;
	}

	if (!transport) {
		nvme_msg(LOG_ERR,
			 "required argument [--transport | -t] not specified\n");
		return EINVAL;
	}

	if (strcmp(transport, "loop")) {
		if (!traddr) {
			nvme_msg(LOG_ERR,
				 "required argument [--address | -a] not specified for transport %s\n",
				 transport);
			return EINVAL;
		}
	}

	if (strcmp(config_file, "none"))
		config_file = NULL;
	r = nvme_scan(config_file);
	if (!hostnqn)
		hostnqn = hnqn = nvmf_hostnqn_from_file();
	if (!hostid)
		hostid = hid = nvmf_hostid_from_file();
	h = nvme_lookup_host(r, hostnqn, hostid);
	if (!h) {
		errno = ENOMEM;
		goto out_free;
	}
	c = nvme_create_ctrl(subsysnqn, transport, traddr,
			     host_traddr, host_iface, trsvcid);
	if (!c) {
		errno = ENOMEM;
		goto out_free;
	}

	errno = 0;
	ret = nvmf_add_ctrl(h, c, &cfg, cfg.disable_sqflow);
	if (ret)
		nvme_msg(LOG_ERR, "no controller found\n");
out_free:
	if (hnqn)
		free(hnqn);
	if (hid)
		free(hid);
	nvme_free_tree(r);
	return errno;
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

	switch (cfg.verbose) {
	case 0:
		nvme_log_level = LOG_WARNING;
		break;
	case 1:
		nvme_log_level = LOG_NOTICE;
		break;
	case 2:
		nvme_log_level = LOG_INFO;
		break;
	default:
		nvme_log_level = LOG_DEBUG;
		break;
	}

	if (!cfg.nqn && !cfg.device) {
		nvme_msg(LOG_ERR,
			 "Neither device name [--device | -d] nor NQN [--nqn | -n] provided\n");
		return EINVAL;
	}
	r = nvme_scan(NULL);
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
			c = nvme_scan_ctrl(r, p);
			if (!c) {
				nvme_msg(LOG_ERR,
					 "Did not find device: %s\n", p);
				nvme_free_tree(r);
				return errno;
			}
			ret = nvme_disconnect_ctrl(c);
			if (!ret)
				printf("Disconnected %s\n", p);
			else
				nvme_msg(LOG_ERR,
					 "Failed to disconnect %s: %s\n",
					 p, strerror(errno));
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

	switch (cfg.verbose) {
	case 0:
		nvme_log_level = LOG_WARNING;
		break;
	case 1:
		nvme_log_level = LOG_NOTICE;
		break;
	case 2:
		nvme_log_level = LOG_INFO;
		break;
	default:
		nvme_log_level = LOG_DEBUG;
		break;
	}

	r = nvme_scan(NULL);
	if (!r) {
		nvme_msg(LOG_ERR, "Failed to scan nvme subsystem: %s\n",
			 strerror(errno));
		return errno;
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
					nvme_msg(LOG_ERR,
						 "failed to disconnect %s\n",
						 nvme_ctrl_get_name(c));
			}
		}
	}
	nvme_free_tree(r);

	return 0;
}
