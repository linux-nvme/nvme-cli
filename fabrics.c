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
#include <sys/ioctl.h>
#include <inttypes.h>
#include <libgen.h>
#include <sys/stat.h>
#include <stddef.h>
#include <syslog.h>
#include <time.h>

#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "util/parser.h"
#include "nvme-ioctl.h"
#include "nvme-status.h"
#include "fabrics.h"

#include "nvme.h"
#include "util/argconfig.h"
#include "common.h"
#include "util/log.h"
#include "util/cleanup.h"

#ifdef HAVE_SYSTEMD
#include <systemd/sd-id128.h>
#define NVME_HOSTNQN_ID SD_ID128_MAKE(c7,f4,61,81,12,be,49,32,8c,83,10,6f,9d,dd,d8,6b)
#endif

#define NVMF_HOSTID_SIZE	36

/* default to 600 seconds of reconnect attempts before giving up */
#define NVMF_DEF_CTRL_LOSS_TMO		600

const char *conarg_nqn = "nqn";
const char *conarg_transport = "transport";
const char *conarg_traddr = "traddr";
const char *conarg_trsvcid = "trsvcid";
const char *conarg_host_traddr = "host_traddr";

#define PATH_NVME_FABRICS	"/dev/nvme-fabrics"
#define PATH_NVMF_DISC		"/etc/nvme/discovery.conf"
#define PATH_NVMF_CONFIG	"/etc/nvme/config.json"
#define PATH_NVMF_HOSTNQN	"/etc/nvme/hostnqn"
#define PATH_NVMF_HOSTID	"/etc/nvme/hostid"
#define MAX_DISC_ARGS		10
#define MAX_DISC_RETRIES	10

enum {
	OPT_INSTANCE,
	OPT_CNTLID,
	OPT_ERR
};

static const match_table_t opt_tokens = {
	{ OPT_INSTANCE,		"instance=%d"	},
	{ OPT_CNTLID,		"cntlid=%d"	},
	{ OPT_ERR,		NULL		},
};

const char *arg_str(const char * const *strings,
		size_t array_size, size_t idx)
{
	if (idx < array_size && strings[idx])
		return strings[idx];
	return "unrecognized";
}

const char * const trtypes[] = {
	[NVMF_TRTYPE_RDMA]	= "rdma",
	[NVMF_TRTYPE_FC]	= "fc",
	[NVMF_TRTYPE_TCP]	= "tcp",
	[NVMF_TRTYPE_LOOP]	= "loop",
};

static const char *trtype_str(__u8 trtype)
{
	return arg_str(trtypes, ARRAY_SIZE(trtypes), trtype);
}

static const char * const adrfams[] = {
	[NVMF_ADDR_FAMILY_PCI]	= "pci",
	[NVMF_ADDR_FAMILY_IP4]	= "ipv4",
	[NVMF_ADDR_FAMILY_IP6]	= "ipv6",
	[NVMF_ADDR_FAMILY_IB]	= "infiniband",
	[NVMF_ADDR_FAMILY_FC]	= "fibre-channel",
	[NVMF_ADDR_FAMILY_LOOP]	= "loop",
};

static inline const char *adrfam_str(__u8 adrfam)
{
	return arg_str(adrfams, ARRAY_SIZE(adrfams), adrfam);
}

static const char * const subtypes[] = {
	[NVME_NQN_DISC]		= "discovery subsystem",
	[NVME_NQN_NVME]		= "nvme subsystem",
};

static inline const char *subtype_str(__u8 subtype)
{
	return arg_str(subtypes, ARRAY_SIZE(subtypes), subtype);
}

static const char * const treqs[] = {
	[NVMF_TREQ_NOT_SPECIFIED]	= "not specified",
	[NVMF_TREQ_REQUIRED]		= "required",
	[NVMF_TREQ_NOT_REQUIRED]	= "not required",
	[NVMF_TREQ_DISABLE_SQFLOW]	= "not specified, "
					  "sq flow control disable supported",
};

static inline const char *treq_str(__u8 treq)
{
	return arg_str(treqs, ARRAY_SIZE(treqs), treq);
}

static const char * const sectypes[] = {
	[NVMF_TCP_SECTYPE_NONE]		= "none",
	[NVMF_TCP_SECTYPE_TLS]		= "tls",
};

static inline const char *sectype_str(__u8 sectype)
{
	return arg_str(sectypes, ARRAY_SIZE(sectypes), sectype);
}

static const char * const prtypes[] = {
	[NVMF_RDMA_PRTYPE_NOT_SPECIFIED]	= "not specified",
	[NVMF_RDMA_PRTYPE_IB]			= "infiniband",
	[NVMF_RDMA_PRTYPE_ROCE]			= "roce",
	[NVMF_RDMA_PRTYPE_ROCEV2]		= "roce-v2",
	[NVMF_RDMA_PRTYPE_IWARP]		= "iwarp",
};

static inline const char *prtype_str(__u8 prtype)
{
	return arg_str(prtypes, ARRAY_SIZE(prtypes), prtype);
}

static const char * const qptypes[] = {
	[NVMF_RDMA_QPTYPE_CONNECTED]	= "connected",
	[NVMF_RDMA_QPTYPE_DATAGRAM]	= "datagram",
};

static inline const char *qptype_str(__u8 qptype)
{
	return arg_str(qptypes, ARRAY_SIZE(qptypes), qptype);
}

static const char * const cms[] = {
	[NVMF_RDMA_CMS_RDMA_CM]	= "rdma-cm",
};

static const char *cms_str(__u8 cm)
{
	return arg_str(cms, ARRAY_SIZE(cms), cm);
}

/*
 * parse strings with connect arguments to find a particular field.
 * If field found, return string containing field value. If field
 * not found, return the string "none".
 */
char *parse_conn_arg(const char *conargs, const char delim, const char *field)
{
	char *s, *e;
	size_t cnt;

	/*
	 * There are field name overlaps: traddr and host_traddr.
	 * By chance, both connect arg strings are set up to
	 * have traddr field followed by host_traddr field. Thus field
	 * name matching doesn't overlap in the searches. Technically,
	 * as is, the loop and delimiter checking isn't necessary.
	 * However, better to be prepared.
	 */
	do {
		s = strstr(conargs, field);
		if (!s)
			goto empty_field;
		/* validate prior character is delimiter */
		if (s == conargs || *(s - 1) == delim) {
			/* match requires next character to be assignment */
			s += strlen(field);
			if (*s == '=')
				/* match */
				break;
		}
		/* field overlap: seek to delimiter and keep looking */
		conargs = strchr(s, delim);
		if (!conargs)
			goto empty_field;
		conargs++;	/* skip delimiter */
	} while (1);
	s++;		/* skip assignment character */
	e = strchr(s, delim);
	if (e)
		cnt = e - s;
	else
		cnt = strlen(s);

	return strndup(s, cnt);

empty_field:
	return strdup("none");
}

int ctrl_instance(const char *device)
{
	char d[64];
	const char *p;
	int ret, instance;

	p = strrchr(device, '/');
	if (p == NULL)
		p = device;
	else
		p++;
	ret = sscanf(p, "nvme%d", &instance);
	if (ret <= 0)
		return -EINVAL;
	if (snprintf(d, sizeof(d), "nvme%d", instance) <= 0 ||
	    strcmp(p, d))
		return -EINVAL;
	return instance;
}

/*
 * Given a controller name, compare the attributes against
 * the connect port configuration given.
 * Return true/false based on whether it matches
 */
static bool ctrl_matches_portconfig(const char *name,
				    struct port_config *port_cfg)
{
	bool found = false;
	char *path = NULL, *addr, *traddr, *trsvcid, *host_traddr;
	int ret;
	bool persistent = true;

	ret = asprintf(&path, "%s/%s", SYS_NVME, name);
	if (ret < 0)
		return found;

	addr = nvme_get_ctrl_attr(path, "address");
	if (!addr) {
		fprintf(stderr, "nvme_get_ctrl_attr failed\n");
		return found;
	}

	if (!strcmp(port_cfg->subsys->nqn, NVME_DISC_SUBSYS_NAME)) {
		char *kato_str = nvme_get_ctrl_attr(path, "kato"), *p;
		unsigned int kato = 0;

		/*
		 * When looking up discovery controllers we have to skip
		 * any non-persistent controllers (ie those with a zero
		 * kato value). Otherwise the controller will vanish from
		 * underneath us as they are owned by another program.
		 *
		 * On older kernels, the 'kato' attribute isn't present.
		 * Assume a persistent controller for these installations.
		 */
		if (kato_str) {
			kato = strtoul(kato_str, &p, 0);
			if (p == kato_str)
				kato = 0;
			free(kato_str);
			persistent = (kato != 0);
		}
	}

	if (!persistent)
		return found;

	if (strcmp(port_cfg->subsys->nqn,
		   nvme_get_ctrl_attr(path, "subsysnqn")))
		return found;
	if (strcmp(port_cfg->transport,
		   nvme_get_ctrl_attr(path, "transport")))
		return found;
	traddr = parse_conn_arg(addr, ' ', conarg_traddr);
	trsvcid = parse_conn_arg(addr, ' ', conarg_trsvcid);
	host_traddr = parse_conn_arg(addr, ' ', conarg_host_traddr);
	if ((!strcmp(traddr, port_cfg->traddr) ||
	     !strcmp(port_cfg->traddr, "none")) &&
	    (trsvcid && !strcmp(trsvcid, port_cfg->trsvcid)) &&
	    (host_traddr && !strcmp(host_traddr, port_cfg->host_traddr)))
		found = true;

	free(addr);
	free(path);

	return found;
}

/*
 * Look through the system to find an existing controller whose
 * attributes match the connect arguments specified
 * If found, a string containing the controller name (ex: "nvme?")
 * is returned.
 * If not found, a NULL is returned.
 */
static char *find_ctrl_from_portconfig(struct port_config *port_cfg)
{
	struct dirent **devices;
	char *devname = NULL;
	int i, n;

	if (!port_cfg)
		return NULL;

	n = scandir(SYS_NVME, &devices, scan_ctrls_filter, alphasort);
	if (n < 0) {
		msg(LOG_ERR, "no NVMe controller(s) detected.\n");
		return NULL;
	}

	for (i = 0; i < n; i++) {
		if (ctrl_matches_portconfig(devices[i]->d_name, port_cfg)) {
			devname = strdup(devices[i]->d_name);
			if (devname == NULL)
				msg(LOG_ERR, "no memory for ctrl name %s\n",
						devices[i]->d_name);
			goto cleanup_devices;
		}
	}

cleanup_devices:
	for (i = 0; i < n; i++)
		free(devices[i]);
	free(devices);

	return devname;
}

static int add_ctrl(struct port_config *port_cfg, const char *argstr)
{
	substring_t args[MAX_OPT_ARGS];
	char buf[BUF_SIZE], *options, *p;
	int token, ret, fd, len = strlen(argstr);

	fd = open(PATH_NVME_FABRICS, O_RDWR);
	if (fd < 0) {
		msg(LOG_ERR, "Failed to open %s: %s\n",
			 PATH_NVME_FABRICS, strerror(errno));
		ret = -errno;
		goto out;
	}

	ret = write(fd, argstr, len);
	if (ret != len) {
		if (errno != EALREADY)
			msg(LOG_NOTICE, "Failed to write to %s: %s\n",
				 PATH_NVME_FABRICS, strerror(errno));
		ret = -errno;
		goto out_close;
	}

	len = read(fd, buf, BUF_SIZE);
	if (len < 0) {
		msg(LOG_ERR, "Failed to read from %s: %s\n",
			 PATH_NVME_FABRICS, strerror(errno));
		ret = -errno;
		goto out_close;
	}

	buf[len] = '\0';
	options = buf;
	while ((p = strsep(&options, ",\n")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, opt_tokens, args);
		switch (token) {
		case OPT_INSTANCE:
			if (match_int(args, &token))
				goto out_fail;
			ret = token;
			port_cfg->discovered = true;
			goto out_close;
		default:
			/* ignore */
			break;
		}
	}

out_fail:
	msg(LOG_ERR, "Failed to parse ctrl info for \"%s\"\n", argstr);
	ret = -EINVAL;
out_close:
	close(fd);
out:
	return ret;
}

static int remove_ctrl_by_path(char *sysfs_path)
{
	int ret, fd;

	fd = open(sysfs_path, O_WRONLY);
	if (fd < 0) {
		ret = -errno;
		msg(LOG_ERR, "Failed to open %s: %s\n", sysfs_path,
				strerror(errno));
		goto out;
	}

	if (write(fd, "1", 1) != 1) {
		ret = -errno;
		goto out_close;
	}

	ret = 0;
out_close:
	close(fd);
out:
	return ret;
}

int remove_ctrl(int instance)
{
	char *sysfs_path;
	int ret;

	if (asprintf(&sysfs_path, "/sys/class/nvme/nvme%d/delete_controller",
			instance) < 0) {
		ret = -errno;
		goto out;
	}

	ret = remove_ctrl_by_path(sysfs_path);
	free(sysfs_path);
out:
	return ret;
}

enum {
	DISC_OK,
	DISC_NO_LOG,
	DISC_GET_NUMRECS,
	DISC_GET_LOG,
	DISC_RETRY_EXHAUSTED,
	DISC_NOT_EQUAL,
};

static int nvmf_get_log_page_discovery(const char *dev_path,
		struct nvmf_disc_rsp_page_hdr **logp, int *numrec, int *status)
{
	struct nvmf_disc_rsp_page_hdr *log;
	unsigned int hdr_size;
	unsigned long genctr;
	int error, fd, max_retries = MAX_DISC_RETRIES, retries = 0;

	fd = open(dev_path, O_RDWR);
	if (fd < 0) {
		error = -errno;
		msg(LOG_ERR, "Failed to open %s: %s\n",
				dev_path, strerror(errno));
		goto out;
	}

	/* first get_log_page we just need numrec entry from discovery hdr.
	 * host supplies its desired bytes via dwords, per NVMe spec.
	 */
	hdr_size = round_up((offsetof(struct nvmf_disc_rsp_page_hdr, numrec) +
			    sizeof(log->numrec)), sizeof(__u32));

	/*
	 * Issue first get log page w/numdl small enough to retrieve numrec.
	 * We just want to know how many records to retrieve.
	 */
	log = calloc(1, hdr_size);
	if (!log) {
		perror("could not alloc memory for discovery log header");
		error = -ENOMEM;
		goto out_close;
	}

	error = nvme_discovery_log(fd, log, hdr_size);
	if (error) {
		error = DISC_GET_NUMRECS;
		goto out_free_log;
	}

	do {
		unsigned int log_size;

		/* check numrec limits */
		*numrec = le64_to_cpu(log->numrec);
		genctr = le64_to_cpu(log->genctr);
		free(log);

		if (*numrec == 0) {
			error = DISC_NO_LOG;
			goto out_close;
		}

		/* we are actually retrieving the entire discovery tables
		 * for the second get_log_page(), per
		 * NVMe spec so no need to round_up(), or there is something
		 * seriously wrong with the standard
		 */
		log_size = sizeof(struct nvmf_disc_rsp_page_hdr) +
			sizeof(struct nvmf_disc_rsp_page_entry) * *numrec;

		/* allocate discovery log pages based on page_hdr->numrec */
		log = calloc(1, log_size);
		if (!log) {
			perror("could not alloc memory for discovery log page");
			error = -ENOMEM;
			goto out_close;
		}

		/*
		 * issue new get_log_page w/numdl+numdh set to get all records,
		 * up to MAX_DISC_LOGS.
		 */
		error = nvme_discovery_log(fd, log, log_size);
		if (error) {
			error = DISC_GET_LOG;
			goto out_free_log;
		}

		/*
		 * The above call to nvme_discovery_log() might result
		 * in several calls (with different offsets), so we need
		 * to fetch the header again to have the most up-to-date
		 * value for the generation counter
		 */
		genctr = le64_to_cpu(log->genctr);
		error = nvme_discovery_log(fd, log, hdr_size);
		if (error) {
			error = DISC_GET_LOG;
			goto out_free_log;
		}
	} while (genctr != le64_to_cpu(log->genctr) &&
		 ++retries < max_retries);

	/*
	 * If genctr is still different with the one in the log entry, it
	 * means the retires have been exhausted to max_retries.  Then it
	 * should be retried by the caller or the user.
	 */
	if (genctr != le64_to_cpu(log->genctr)) {
		error = DISC_RETRY_EXHAUSTED;
		goto out_free_log;
	}

	if (*numrec != le64_to_cpu(log->numrec)) {
		error = DISC_NOT_EQUAL;
		goto out_free_log;
	}

	/* needs to be freed by the caller */
	*logp = log;
	error = DISC_OK;
	goto out_close;

out_free_log:
	free(log);
out_close:
	close(fd);
out:
	*status = nvme_status_to_errno(error, true);
	return error;
}

static int space_strip_len(int max, const char *str)
{
	int i;

	for (i = max - 1; i >= 0; i--)
		if (str[i] != '\0' && str[i] != ' ')
			break;

	return i + 1;
}

static void print_discovery_log(struct nvmf_disc_rsp_page_hdr *log, int numrec)
{
	int i;

	printf("\nDiscovery Log Number of Records %d, "
	       "Generation counter %"PRIu64"\n",
		numrec, le64_to_cpu(log->genctr));

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_rsp_page_entry *e = &log->entries[i];

		printf("=====Discovery Log Entry %d======\n", i);
		printf("trtype:  %s\n", trtype_str(e->trtype));
		printf("adrfam:  %s\n", adrfam_str(e->adrfam));
		printf("subtype: %s\n", subtype_str(e->subtype));
		printf("treq:    %s\n", treq_str(e->treq));
		printf("portid:  %d\n", e->portid);
		printf("trsvcid: %.*s\n",
		       space_strip_len(NVMF_TRSVCID_SIZE, e->trsvcid),
		       e->trsvcid);
		printf("subnqn:  %s\n", e->subnqn);
		printf("traddr:  %.*s\n",
		       space_strip_len(NVMF_TRADDR_SIZE, e->traddr),
		       e->traddr);

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			printf("rdma_prtype: %s\n",
				prtype_str(e->tsas.rdma.prtype));
			printf("rdma_qptype: %s\n",
				qptype_str(e->tsas.rdma.qptype));
			printf("rdma_cms:    %s\n",
				cms_str(e->tsas.rdma.cms));
			printf("rdma_pkey: 0x%04x\n",
				e->tsas.rdma.pkey);
			break;
		case NVMF_TRTYPE_TCP:
			printf("sectype: %s\n",
				sectype_str(e->tsas.tcp.sectype));
			break;
		}
	}
}

static void json_discovery_log(struct nvmf_disc_rsp_page_hdr *log, int numrec)
{
	struct json_object *root;
	struct json_object *entries;
	int i;

	root = json_create_object();
	entries = json_create_array();
	json_object_add_value_uint(root, "genctr", le64_to_cpu(log->genctr));
	json_object_add_value_array(root, "records", entries);

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_rsp_page_entry *e = &log->entries[i];
		struct json_object *entry = json_create_object();

		json_object_add_value_string(entry, "trtype",
					     trtype_str(e->trtype));
		json_object_add_value_string(entry, "adrfam",
					     adrfam_str(e->adrfam));
		json_object_add_value_string(entry, "subtype",
					     subtype_str(e->subtype));
		json_object_add_value_string(entry,"treq",
					     treq_str(e->treq));
		json_object_add_value_uint(entry, "portid", e->portid);
		json_object_add_value_string(entry, "trsvcid",
					     e->trsvcid);
		json_object_add_value_string(entry, "subnqn", e->subnqn);
		json_object_add_value_string(entry, "traddr", e->traddr);

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			json_object_add_value_string(entry, "rdma_prtype",
				prtype_str(e->tsas.rdma.prtype));
			json_object_add_value_string(entry, "rdma_qptype",
				qptype_str(e->tsas.rdma.qptype));
			json_object_add_value_string(entry, "rdma_cms",
				cms_str(e->tsas.rdma.cms));
			json_object_add_value_uint(entry, "rdma_pkey",
				e->tsas.rdma.pkey);
			break;
		case NVMF_TRTYPE_TCP:
			json_object_add_value_string(entry, "sectype",
				sectype_str(e->tsas.tcp.sectype));
			break;
		}
		json_array_add_value_object(entries, entry);
	}
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static struct host_config *lookup_host(struct fabrics_config *fabrics_cfg,
				       const char *hostnqn, const char *hostid)
{
	struct host_config *host_cfg;

	if (!hostnqn)
		return NULL;
	list_for_each_entry(host_cfg, &fabrics_cfg->host_list, entry) {
		if (strcmp(host_cfg->hostnqn, hostnqn))
			continue;
		if (hostid && strcmp(host_cfg->hostid, hostid))
			continue;
		return host_cfg;
	}
	host_cfg = malloc(sizeof(struct host_config));
	INIT_LIST_HEAD(&host_cfg->entry);
	INIT_LIST_HEAD(&host_cfg->subsys_list);
	host_cfg->hostnqn = strdup(hostnqn);
	host_cfg->fabrics = fabrics_cfg;
	if (hostid)
		host_cfg->hostid = strdup(hostid);
	list_add(&host_cfg->entry, &fabrics_cfg->host_list);
	return host_cfg;
}

static struct subsys_config *lookup_subsys(struct host_config *host_cfg,
					   const char *nqn)
{
	struct subsys_config *subsys_cfg;

	if (!nqn || !strlen(nqn))
		return NULL;
	list_for_each_entry(subsys_cfg, &host_cfg->subsys_list, entry) {
		if (!strcmp(subsys_cfg->nqn, nqn))
			return subsys_cfg;
	}
	subsys_cfg = malloc(sizeof(struct subsys_config));
	if (!subsys_cfg)
		return NULL;
	INIT_LIST_HEAD(&subsys_cfg->entry);
	INIT_LIST_HEAD(&subsys_cfg->port_list);
	subsys_cfg->nqn = strdup(nqn);
	subsys_cfg->host = host_cfg;
	list_add(&subsys_cfg->entry, &host_cfg->subsys_list);
	return subsys_cfg;
}

static struct port_config *lookup_port(struct subsys_config *subsys_cfg,
		const char *transport, const char *traddr,
		const char *host_traddr, const char *trsvcid)
{
	struct port_config *port_cfg;

	if (!transport)
		return NULL;
	list_for_each_entry(port_cfg, &subsys_cfg->port_list, entry) {
		if (strcmp(port_cfg->transport, transport))
			continue;
		if (traddr &&
		    strcmp(port_cfg->traddr, traddr))
			continue;
		if (host_traddr &&
		    strcmp(port_cfg->host_traddr, host_traddr))
			continue;
		if (trsvcid &&
		    strcmp(port_cfg->trsvcid, trsvcid))
			continue;
		return port_cfg;
	}
	port_cfg = malloc(sizeof(struct port_config));
	if (!port_cfg)
		return NULL;
	memset(port_cfg, 0, sizeof(struct port_config));
	INIT_LIST_HEAD(&port_cfg->entry);
	port_cfg->transport = strdup(transport);
	if (traddr)
		port_cfg->traddr = strdup(traddr);
	else
		port_cfg->traddr = strdup("none");
	if (host_traddr)
		port_cfg->host_traddr = strdup(host_traddr);
	else
		port_cfg->host_traddr = strdup("none");
	if (trsvcid)
		port_cfg->trsvcid = strdup(trsvcid);
	else
		port_cfg->trsvcid = strdup("none");
	port_cfg->subsys = subsys_cfg;
	list_add(&port_cfg->entry, &subsys_cfg->port_list);
	return port_cfg;
}

#define JSON_UPDATE_INT_OPTION(c, k, a, o)				\
	if (!strcmp(# a, k ) && !c->a) c->a = json_object_get_int(o);
#define JSON_UPDATE_BOOL_OPTION(c, k, a, o)				\
	if (!strcmp(# a, k ) && !c->a) c->a = json_object_get_boolean(o);

static void json_update_attributes(struct port_config *port_cfg,
				   struct json_object *port_obj)
{
	json_object_object_foreach(port_obj, key_str, val_obj) {
		JSON_UPDATE_INT_OPTION(port_cfg, key_str,
				       nr_io_queues, val_obj);
		JSON_UPDATE_INT_OPTION(port_cfg, key_str,
				       nr_write_queues, val_obj);
		JSON_UPDATE_INT_OPTION(port_cfg, key_str,
				       nr_poll_queues, val_obj);
		JSON_UPDATE_INT_OPTION(port_cfg, key_str,
				       queue_size, val_obj);
		JSON_UPDATE_INT_OPTION(port_cfg, key_str,
				       keep_alive_tmo, val_obj);
		JSON_UPDATE_INT_OPTION(port_cfg, key_str,
				       reconnect_delay, val_obj);
		if (!strcmp("ctrl_loss_tmo", key_str) &&
		    port_cfg->ctrl_loss_tmo != NVMF_DEF_CTRL_LOSS_TMO)
			port_cfg->ctrl_loss_tmo = json_object_get_int(val_obj);
		if (!strcmp("tos", key_str) && port_cfg->tos != -1)
			port_cfg->tos = json_object_get_int(val_obj);
		JSON_UPDATE_BOOL_OPTION(port_cfg, key_str,
					duplicate_connect, val_obj);
		JSON_UPDATE_BOOL_OPTION(port_cfg, key_str,
					disable_sqflow, val_obj);
		JSON_UPDATE_BOOL_OPTION(port_cfg, key_str,
					hdr_digest, val_obj);
		JSON_UPDATE_BOOL_OPTION(port_cfg, key_str,
					data_digest, val_obj);
		JSON_UPDATE_BOOL_OPTION(port_cfg, key_str,
					persistent, val_obj);
	}
}

static void json_parse_port(struct subsys_config *subsys_cfg,
			    struct json_object *port_obj)
{
	struct json_object *attr_obj;
	struct port_config *port_cfg;
	const char *transport, *traddr = NULL;
	const char *host_traddr = NULL, *trsvcid = NULL;

	attr_obj = json_object_object_get(port_obj, "transport");
	if (!attr_obj)
		return;
	transport = json_object_get_string(attr_obj);
	attr_obj = json_object_object_get(port_obj, "traddr");
	if (attr_obj)
		traddr = json_object_get_string(attr_obj);
	attr_obj = json_object_object_get(port_obj, "host_traddr");
	if (attr_obj)
		host_traddr = json_object_get_string(attr_obj);
	attr_obj = json_object_object_get(port_obj, "trsvcid");
	if (attr_obj)
		trsvcid = json_object_get_string(attr_obj);
	port_cfg = lookup_port(subsys_cfg, transport,
			       traddr, host_traddr, trsvcid);
	if (port_cfg)
		json_update_attributes(port_cfg, port_obj);
}

static void json_parse_subsys(struct host_config *host_cfg,
			      struct json_object *subsys_obj)
{
	struct json_object *nqn_obj, *port_array;
	struct subsys_config *subsys_cfg;
	const char *nqn;
	int p;

	nqn_obj = json_object_object_get(subsys_obj, "nqn");
	if (!nqn_obj)
		return;
	nqn = json_object_get_string(nqn_obj);
	subsys_cfg = lookup_subsys(host_cfg, nqn);
	port_array = json_object_object_get(subsys_obj, "ports");
	if (!port_array)
		return;
	for (p = 0; p < json_object_array_length(port_array); p++) {
		struct json_object *port_obj;

		port_obj = json_object_array_get_idx(port_array, p);
		json_parse_port(subsys_cfg, port_obj);
	}
}

static void json_parse_host(struct fabrics_config *fabrics_cfg,
			    struct json_object *host_obj)
{
	struct json_object *attr_obj, *subsys_array, *subsys_obj;
	const char *hostnqn, *hostid = NULL;
	struct host_config *host_cfg;
	int s;

	attr_obj = json_object_object_get(host_obj, "hostnqn");
	if (!attr_obj)
		return;
	hostnqn = json_object_get_string(attr_obj);
	attr_obj = json_object_object_get(host_obj, "hostid");
	if (attr_obj)
		hostid = json_object_get_string(attr_obj);
	host_cfg = lookup_host(fabrics_cfg, hostnqn, hostid);
	subsys_array = json_object_object_get(host_obj, "subsystems");
	if (!subsys_array)
		return;
	for (s = 0; s < json_object_array_length(subsys_array); s++) {
		subsys_obj = json_object_array_get_idx(subsys_array, s);
		json_parse_subsys(host_cfg, subsys_obj);
	}
}

static void json_read_config(struct fabrics_config *fabrics_cfg)
{
	struct json_object *json_root, *host_obj;
	int h;

	json_root = json_object_from_file(fabrics_cfg->config);
	if (!json_root) {
		fprintf(stderr, "Failed to read %s, %s\n",
			PATH_NVMF_CONFIG, json_util_get_last_err());
		json_root = json_object_new_array();
		return;
	}
	for (h = 0; h < json_object_array_length(json_root); h++) {
		host_obj = json_object_array_get_idx(json_root, h);
		json_parse_host(fabrics_cfg, host_obj);
	}
	json_object_put(json_root);
}

#define JSON_STRING_OPTION(c, p, o)				\
	if ((c)->o && strcmp((c)->o, "none"))			\
		json_object_add_value_string((p), # o , (c)->o)
#define JSON_INT_OPTION(c, p, o, d)					\
	if ((c)->o != d) json_object_add_value_int((p), # o , (c)->o)
#define JSON_BOOL_OPTION(c, p, o)					\
	if ((c)->o) json_object_add_value_bool((p), # o , (c)->o)

static void json_update_port(struct json_object *port_array,
			     struct port_config *port_cfg)
{
	struct json_object *port_obj = json_create_object();

	json_object_add_value_string(port_obj, "transport",
				     port_cfg->transport);
	JSON_STRING_OPTION(port_cfg, port_obj, traddr);
	JSON_STRING_OPTION(port_cfg, port_obj, trsvcid);
	JSON_STRING_OPTION(port_cfg, port_obj, host_traddr);
	JSON_INT_OPTION(port_cfg, port_obj, nr_io_queues, 0);
	JSON_INT_OPTION(port_cfg, port_obj, nr_write_queues, 0);
	JSON_INT_OPTION(port_cfg, port_obj, nr_poll_queues, 0);
	JSON_INT_OPTION(port_cfg, port_obj, queue_size, 0);
	JSON_INT_OPTION(port_cfg, port_obj, keep_alive_tmo, 0);
	JSON_INT_OPTION(port_cfg, port_obj, reconnect_delay, 0);
	if (strcmp(port_cfg->transport, "loop"))
		JSON_INT_OPTION(port_cfg, port_obj, ctrl_loss_tmo,
				NVMF_DEF_CTRL_LOSS_TMO);
	JSON_INT_OPTION(port_cfg, port_obj, tos, -1);
	JSON_BOOL_OPTION(port_cfg, port_obj, duplicate_connect);
	JSON_BOOL_OPTION(port_cfg, port_obj, disable_sqflow);
	JSON_BOOL_OPTION(port_cfg, port_obj, hdr_digest);
	JSON_BOOL_OPTION(port_cfg, port_obj, data_digest);
	JSON_BOOL_OPTION(port_cfg, port_obj, persistent);
	json_object_array_add(port_array, port_obj);
}

static void json_update_subsys(struct json_object *subsys_array,
			       struct subsys_config *subsys_cfg)
{
	struct port_config *port_cfg;
	struct json_object *subsys_obj = json_create_object();
	struct json_object *port_array;

	json_object_add_value_string(subsys_obj, "nqn",
				     subsys_cfg->nqn);
	port_array = json_create_array();
	list_for_each_entry(port_cfg, &subsys_cfg->port_list, entry)
		json_update_port(port_array, port_cfg);
	if (json_object_array_length(port_array))
		json_object_object_add(subsys_obj, "ports", port_array);
	else
		json_object_put(port_array);
	json_object_array_add(subsys_array, subsys_obj);
}

static void json_update_config(struct fabrics_config *fabrics_cfg)
{
	struct host_config *host_cfg;
	struct json_object *json_root, *host_obj;
	struct json_object *subsys_array;

	json_root = json_create_array();
	list_for_each_entry(host_cfg, &fabrics_cfg->host_list, entry) {
		struct subsys_config *subsys_cfg;

		host_obj = json_create_object();
		json_object_add_value_string(host_obj, "hostnqn",
					     host_cfg->hostnqn);
		if (host_cfg->hostid)
			json_object_add_value_string(host_obj, "hostid",
						     host_cfg->hostid);
		subsys_array = json_create_array();
		list_for_each_entry(subsys_cfg, &host_cfg->subsys_list, entry)
			json_update_subsys(subsys_array, subsys_cfg);
		if (json_object_array_length(subsys_array))
			json_object_object_add(host_obj, "subsystems",
					       subsys_array);
		else
			json_object_put(subsys_array);
		json_object_array_add(json_root, host_obj);
	}
	if (json_object_to_file_ext(fabrics_cfg->config, json_root,
				    JSON_C_TO_STRING_PRETTY) < 0) {
		fprintf(stderr, "Failed to write %s, %s\n",
			PATH_NVMF_CONFIG, json_util_get_last_err());
	}
	json_object_put(json_root);
}

static void save_discovery_log(struct nvmf_disc_rsp_page_hdr *log,
			       int numrec, const char *logfile)
{
	int fd;
	int len, ret;

	fd = open(logfile, O_CREAT|O_RDWR|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		msg(LOG_ERR, "failed to open %s: %s\n",
			logfile, strerror(errno));
		return;
	}

	len = sizeof(struct nvmf_disc_rsp_page_hdr) +
			numrec * sizeof(struct nvmf_disc_rsp_page_entry);
	ret = write(fd, log, len);
	if (ret < 0)
		msg(LOG_ERR, "failed to write to %s: %s\n",
			logfile, strerror(errno));
	else
		printf("Discovery log is saved to %s\n", logfile);

	close(fd);
}

static char *hostnqn_read_file(void)
{
	FILE *f;
	char hostnqn[NVMF_NQN_SIZE];
	char *ret = NULL;

	f = fopen(PATH_NVMF_HOSTNQN, "r");
	if (f == NULL)
		return false;

	if (fgets(hostnqn, sizeof(hostnqn), f) == NULL ||
	    !strlen(hostnqn))
		goto out;

	ret = strndup(hostnqn, strcspn(hostnqn, "\n"));

out:
	fclose(f);
	return ret;
}

static char *hostnqn_generate_systemd(void)
{
#ifdef HAVE_SYSTEMD
	sd_id128_t id;
	char *ret;

	if (sd_id128_get_machine_app_specific(NVME_HOSTNQN_ID, &id) < 0)
		return NULL;

	if (asprintf(&ret, "nqn.2014-08.org.nvmexpress:uuid:" SD_ID128_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(id)) == -1)
		ret = NULL;

	return ret;
#else
	return NULL;
#endif
}

static char *hostnqn_read_dmi(void)
{
	char uuid[16];
	char *ret = NULL;

	if (uuid_from_dmi(uuid) < 0)
		return NULL;
	if (asprintf(&ret, "nqn.2014-08.org.nvmexpress:uuid:%s", uuid) == -1)
		return NULL;
	return ret;
}

/* returns an allocated string or NULL */
char *hostnqn_read(void)
{
	char *ret;

	ret = hostnqn_read_file();
	if (ret)
		return ret;

	ret = hostnqn_read_dmi();
	if (ret)
		return ret;

	ret = hostnqn_generate_systemd();
	if (ret)
		return ret;

	return NULL;
}

static int nvmf_hostnqn_file(struct host_config *cfg)
{
	cfg->hostnqn = hostnqn_read();

	return cfg->hostnqn != NULL;
}

static int nvmf_hostid_file(struct host_config *cfg)
{
	FILE *f;
	char hostid[NVMF_HOSTID_SIZE + 1];
	int ret = false;

	f = fopen(PATH_NVMF_HOSTID, "r");
	if (f == NULL)
		return false;

	if (fgets(hostid, sizeof(hostid), f) == NULL)
		goto out;

	cfg->hostid = strdup(hostid);
	if (!cfg->hostid)
		goto out;

	ret = true;
out:
	fclose(f);
	return ret;
}

static int
add_bool_argument(char **argstr, int *max_len, char *arg_str, bool arg)
{
	int len;

	if (arg) {
		len = snprintf(*argstr, *max_len, ",%s", arg_str);
		if (len < 0)
			return -EINVAL;
		*argstr += len;
		*max_len -= len;
	}

	return 0;
}

static int
add_int_argument(char **argstr, int *max_len, char *arg_str, int arg,
		 bool allow_zero)
{
	int len;

	if ((arg && !allow_zero) || (arg != -1 && allow_zero)) {
		len = snprintf(*argstr, *max_len, ",%s=%d", arg_str, arg);
		if (len < 0)
			return -EINVAL;
		*argstr += len;
		*max_len -= len;
	}

	return 0;
}

static int
add_argument(char **argstr, int *max_len, char *arg_str, const char *arg)
{
	int len;

	if (arg && strcmp(arg, "none")) {
		len = snprintf(*argstr, *max_len, ",%s=%s", arg_str, arg);
		if (len < 0)
			return -EINVAL;
		*argstr += len;
		*max_len -= len;
	}

	return 0;
}

int build_options(struct port_config *port_cfg, char *argstr,
			 int max_len, bool discover)
{
	int len;
	struct subsys_config *subsys_cfg = port_cfg->subsys;
	struct host_config *host_cfg = subsys_cfg->host;

	if (!port_cfg->transport) {
		msg(LOG_ERR, "need a transport (-t) argument\n");
		return -EINVAL;
	}

	if (strncmp(port_cfg->transport, "loop", 4)) {
		if (!port_cfg->traddr || !strcmp(port_cfg->traddr, "none")) {
			msg(LOG_ERR, "need a address (-a) argument\n");
			return -EINVAL;
		}
	}

	/* always specify nqn as first arg - this will init the string */
	len = snprintf(argstr, max_len, "nqn=%s", subsys_cfg->nqn);
	if (len < 0)
		return -EINVAL;
	argstr += len;
	max_len -= len;

	if (add_argument(&argstr, &max_len, "transport", port_cfg->transport) ||
	    add_argument(&argstr, &max_len, "traddr", port_cfg->traddr) ||
	    add_argument(&argstr, &max_len, "host_traddr",
			 port_cfg->host_traddr) ||
	    add_argument(&argstr, &max_len, "trsvcid", port_cfg->trsvcid) ||
	    ((host_cfg->hostnqn || nvmf_hostnqn_file(host_cfg)) &&
		    add_argument(&argstr, &max_len, "hostnqn",
				 host_cfg->hostnqn)) ||
	    ((host_cfg->hostid || nvmf_hostid_file(host_cfg)) &&
		    add_argument(&argstr, &max_len, "hostid",
				 host_cfg->hostid)) ||
	    (!discover &&
	      add_int_argument(&argstr, &max_len, "nr_io_queues",
				port_cfg->nr_io_queues, false)) ||
	    add_int_argument(&argstr, &max_len, "nr_write_queues",
				port_cfg->nr_write_queues, false) ||
	    add_int_argument(&argstr, &max_len, "nr_poll_queues",
				port_cfg->nr_poll_queues, false) ||
	    (!discover &&
	      add_int_argument(&argstr, &max_len, "queue_size",
				port_cfg->queue_size, false)) ||
	    add_int_argument(&argstr, &max_len, "keep_alive_tmo",
				port_cfg->keep_alive_tmo, false) ||
	    add_int_argument(&argstr, &max_len, "reconnect_delay",
				port_cfg->reconnect_delay, false) ||
	    (strncmp(port_cfg->transport, "loop", 4) &&
	     add_int_argument(&argstr, &max_len, "ctrl_loss_tmo",
				port_cfg->ctrl_loss_tmo, true)) ||
	    add_int_argument(&argstr, &max_len, "tos",
				port_cfg->tos, true) ||
	    add_bool_argument(&argstr, &max_len, "duplicate_connect",
				port_cfg->duplicate_connect) ||
	    add_bool_argument(&argstr, &max_len, "disable_sqflow",
				port_cfg->disable_sqflow) ||
	    add_bool_argument(&argstr, &max_len, "hdr_digest",
				port_cfg->hdr_digest) ||
	    add_bool_argument(&argstr, &max_len, "data_digest",
				port_cfg->data_digest))
		return -EINVAL;

	return 0;
}

static void set_discovery_kato(struct port_config *port_cfg)
{
	/* Set kato to NVMF_DEF_DISC_TMO for persistent controllers */
	if (port_cfg->persistent && !port_cfg->keep_alive_tmo)
		port_cfg->keep_alive_tmo = NVMF_DEF_DISC_TMO;
	/* Set kato to zero for non-persistent controllers */
	else if (!port_cfg->persistent && (port_cfg->keep_alive_tmo > 0))
		port_cfg->keep_alive_tmo = 0;
}

static void discovery_trsvcid(struct port_config *port_cfg)
{
	if (!strcmp(port_cfg->transport, "tcp")) {
		/* Default port for NVMe/TCP discovery controllers */
		port_cfg->trsvcid = __stringify(NVME_DISC_IP_PORT);
	} else if (!strcmp(port_cfg->transport, "rdma")) {
		/* Default port for NVMe/RDMA controllers */
		port_cfg->trsvcid = __stringify(NVME_RDMA_IP_PORT);
	}
}

static bool traddr_is_hostname(struct port_config *port_cfg)
{
	char addrstr[NVMF_TRADDR_SIZE];

	if (!port_cfg->transport)
		return false;
	if (!port_cfg->traddr || !strcmp(port_cfg->traddr, "none"))
		return false;
	if (strcmp(port_cfg->transport, "tcp") &&
	    strcmp(port_cfg->transport, "rdma"))
		return false;
	if (inet_pton(AF_INET, port_cfg->traddr, addrstr) > 0 ||
	    inet_pton(AF_INET6, port_cfg->traddr, addrstr) > 0)
		return false;
	return true;
}

static int hostname2traddr(struct port_config *port_cfg)
{
	struct addrinfo *host_info, hints = {.ai_family = AF_UNSPEC};
	char addrstr[NVMF_TRADDR_SIZE];
	const char *p;
	int ret;

	ret = getaddrinfo(port_cfg->traddr, NULL, &hints, &host_info);
	if (ret) {
		msg(LOG_ERR, "failed to resolve host %s info\n",
			port_cfg->traddr);
		return ret;
	}

	switch (host_info->ai_family) {
	case AF_INET:
		p = inet_ntop(host_info->ai_family,
			&(((struct sockaddr_in *)host_info->ai_addr)->sin_addr),
			addrstr, NVMF_TRADDR_SIZE);
		break;
	case AF_INET6:
		p = inet_ntop(host_info->ai_family,
			&(((struct sockaddr_in6 *)host_info->ai_addr)->sin6_addr),
			addrstr, NVMF_TRADDR_SIZE);
		break;
	default:
		msg(LOG_ERR, "unrecognized address family (%d) %s\n",
			host_info->ai_family, port_cfg->traddr);
		ret = -EINVAL;
		goto free_addrinfo;
	}

	if (!p) {
		msg(LOG_ERR, "failed to get traddr for %s\n",
			port_cfg->traddr);
		ret = -errno;
		goto free_addrinfo;
	}
	port_cfg->traddr = strdup(addrstr);

free_addrinfo:
	freeaddrinfo(host_info);
	return ret;
}

static int connect_ctrl(struct host_config *host_cfg, char *host_traddr,
			struct nvmf_disc_rsp_page_entry *e)
{
	struct subsys_config *subsys_cfg;
	struct port_config *port_cfg;
	char argstr[BUF_SIZE], *p;
	char traddr[NVMF_TRADDR_SIZE];
	char trsvcid[NVMF_TRSVCID_SIZE];
	const char *transport;
	bool discover, disable_sqflow = true;
	int len, ret;

retry:
	p = argstr;
	discover = false;

	switch (e->subtype) {
	case NVME_NQN_DISC:
		discover = true;
	case NVME_NQN_NVME:
		break;
	default:
		msg(LOG_ERR, "skipping unsupported subtype %d\n",
			 e->subtype);
		return -EINVAL;
	}

	subsys_cfg = lookup_subsys(host_cfg, e->subnqn);
	if (!subsys_cfg) {
		msg(LOG_ERR, "cannot allocate subsys '%s', skipping\n",
			e->subnqn);
		return -ENOENT;
	}
	len = sprintf(p, "nqn=%s", subsys_cfg->nqn);
	if (len < 0)
		return -EINVAL;
	p += len;

	transport = trtype_str(e->trtype);
	if (!strcmp(transport, "unrecognized")) {
		msg(LOG_ERR, "skipping unsupported transport %d\n",
				 e->trtype);
		return -EINVAL;
	}

	len = sprintf(p, ",transport=%s", transport);
	if (len < 0)
		return -EINVAL;
	p += len;

	switch (e->trtype) {
	case NVMF_TRTYPE_RDMA:
	case NVMF_TRTYPE_TCP:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_IP4:
			/* FALLTHRU */
		case NVMF_ADDR_FAMILY_IP6:
			sprintf(traddr, "%.*s",
				space_strip_len(NVMF_TRADDR_SIZE, e->traddr),
				e->traddr);
			len = sprintf(p, ",traddr=%s", traddr);
			if (len < 0)
				return -EINVAL;
			p += len;

			sprintf(trsvcid, "%.*s",
				space_strip_len(NVMF_TRSVCID_SIZE, e->trsvcid),
				e->trsvcid);
			len = sprintf(p, ",trsvcid=%s", trsvcid);
			if (len < 0)
				return -EINVAL;
			p += len;
			break;
		default:
			msg(LOG_ERR, "skipping unsupported adrfam\n");
			return -EINVAL;
		}
		break;
	case NVMF_TRTYPE_FC:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_FC:
			sprintf(traddr, "%.*s",
				space_strip_len(NVMF_TRADDR_SIZE, e->traddr),
				e->traddr);
			len = sprintf(p, ",traddr=%s", traddr);
			if (len < 0)
				return -EINVAL;
			p += len;
			break;
		default:
			msg(LOG_ERR, "skipping unsupported adrfam\n");
			return -EINVAL;
		}
		break;
	}

	port_cfg = lookup_port(subsys_cfg, transport, traddr,
			       host_traddr, trsvcid);
	if (!port_cfg) {
		msg(LOG_ERR, "failed to allocate port %s/%s, skipping\n",
			transport, traddr);
		return -ENOMEM;
	}
	if (host_cfg->hostnqn && strcmp(host_cfg->hostnqn, "none")) {
		len = sprintf(p, ",hostnqn=%s", host_cfg->hostnqn);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (host_cfg->hostid && strcmp(host_cfg->hostid, "none")) {
		len = sprintf(p, ",hostid=%s", host_cfg->hostid);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (port_cfg->queue_size && !discover) {
		len = sprintf(p, ",queue_size=%d", port_cfg->queue_size);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (port_cfg->nr_io_queues && !discover) {
		len = sprintf(p, ",nr_io_queues=%d", port_cfg->nr_io_queues);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (port_cfg->nr_write_queues) {
		len = sprintf(p, ",nr_write_queues=%d", port_cfg->nr_write_queues);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (port_cfg->nr_poll_queues) {
		len = sprintf(p, ",nr_poll_queues=%d", port_cfg->nr_poll_queues);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (port_cfg->host_traddr && strcmp(port_cfg->host_traddr, "none")) {
		len = sprintf(p, ",host_traddr=%s", port_cfg->host_traddr);
		if (len < 0)
			return -EINVAL;
		p+= len;
	}

	if (port_cfg->reconnect_delay) {
		len = sprintf(p, ",reconnect_delay=%d",
			      port_cfg->reconnect_delay);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if ((e->trtype != NVMF_TRTYPE_LOOP) &&
	    (port_cfg->ctrl_loss_tmo >= -1)) {
		len = sprintf(p, ",ctrl_loss_tmo=%d", port_cfg->ctrl_loss_tmo);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (port_cfg->tos != -1) {
		len = sprintf(p, ",tos=%d", port_cfg->tos);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (port_cfg->keep_alive_tmo) {
		len = sprintf(p, ",keep_alive_tmo=%d",
			      port_cfg->keep_alive_tmo);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (port_cfg->hdr_digest) {
		len = sprintf(p, ",hdr_digest");
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (port_cfg->data_digest) {
		len = sprintf(p, ",data_digest");
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (e->treq & NVMF_TREQ_DISABLE_SQFLOW && disable_sqflow) {
		len = sprintf(p, ",disable_sqflow");
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (discover) {
		enum nvme_print_flags flags;

		flags = validate_output_format(host_cfg->fabrics->output_format);
		if (flags < 0)
			flags = NORMAL;
		ret = do_discover(port_cfg, argstr, true, flags);
	} else
		ret = add_ctrl(port_cfg, argstr);
	if (ret == -EINVAL && disable_sqflow &&
	    e->treq & NVMF_TREQ_DISABLE_SQFLOW) {
		/* disable_sqflow param might not be supported, try without it */
		disable_sqflow = false;
		goto retry;
	}
	return ret;
}

static bool discover_match_found(struct host_config *host_cfg,
				 struct nvmf_disc_rsp_page_entry *entry,
				 const char *host_traddr)
{
	struct port_config *port_cfg;
	struct subsys_config *subsys_cfg;

	list_for_each_entry(subsys_cfg, &host_cfg->subsys_list, entry) {
		if (!strcmp(subsys_cfg->nqn, entry->subnqn)) {
			list_for_each_entry(port_cfg, &subsys_cfg->port_list,
					    entry) {
				if (strcmp(port_cfg->transport,
					   trtype_str(entry->trtype)))
					continue;
				if (strcmp(port_cfg->traddr, entry->traddr))
					continue;
				if (host_traddr &&
				    strcmp(host_traddr,
					   port_cfg->host_traddr))
					continue;
				if (port_cfg->trsvcid &&
				    strcmp(port_cfg->trsvcid, entry->trsvcid))
					continue;
				return port_cfg->discovered;
			}
		}
	}

	subsys_cfg = lookup_subsys(host_cfg, entry->subnqn);
	if (!subsys_cfg)
		return false;

	port_cfg = lookup_port(subsys_cfg, trtype_str(entry->trtype),
			       entry->traddr, host_traddr, entry->trsvcid);

	/* check if we have a matching existing controller */
	return find_ctrl_from_portconfig(port_cfg) != NULL;
}

static bool should_connect(struct port_config *port_cfg,
			   struct nvmf_disc_rsp_page_entry *entry,
			   bool matching_only)
{
	int len;

	if (discover_match_found(port_cfg->subsys->host, entry,
				 port_cfg->host_traddr))
		return false;

	if (!matching_only || !port_cfg->traddr ||
	    !strcmp(port_cfg->traddr, "none"))
		return true;

	len = space_strip_len(NVMF_TRADDR_SIZE, entry->traddr);
	return !strncmp(port_cfg->traddr, entry->traddr, len);
}

static int connect_ctrls(struct port_config *port_cfg,
			 struct nvmf_disc_rsp_page_hdr *log, int numrec)
{
	struct subsys_config *subsys_cfg = port_cfg->subsys;
	struct host_config *host_cfg = subsys_cfg->host;
	struct fabrics_config *fabrics_cfg = host_cfg->fabrics;
	int i;
	int instance;
	int ret = 0;

	for (i = 0; i < numrec; i++) {
		if (!should_connect(port_cfg, &log->entries[i],
				    fabrics_cfg->matching_only))
			continue;

		instance = connect_ctrl(host_cfg, port_cfg->host_traddr,
					&log->entries[i]);

		/* clean success */
		if (instance >= 0)
			continue;

		/* already connected print message	*/
		if (instance == -EALREADY) {
			const char *traddr = log->entries[i].traddr;

			if (!fabrics_cfg->quiet)
				msg(LOG_ERR,
					"traddr=%.*s is already connected\n",
					space_strip_len(NVMF_TRADDR_SIZE,
							traddr),
					traddr);
			continue;
		}

		/*
		 * don't error out. The Discovery Log may contain
		 * devices that aren't necessarily connectable via
		 * the system/host transport port. Let those items
		 * fail and continue on to the next log element.
		 */
	}

	return ret;
}

static struct host_config *nvmf_get_host_identifiers(struct fabrics_config *fabrics_cfg,
						     int ctrl_instance)
{
	char *path;
	struct host_config *host_cfg;

	if (asprintf(&path, "%s/nvme%d", SYS_NVME, ctrl_instance) < 0)
		return NULL;
	host_cfg = lookup_host(fabrics_cfg, nvme_get_ctrl_attr(path, "hostnqn"),
			       nvme_get_ctrl_attr(path, "hostid"));
	return host_cfg;
}

int do_discover(struct port_config *port_cfg, char *argstr,
		bool connect, enum nvme_print_flags flags)
{
	struct subsys_config *subsys_cfg = port_cfg->subsys;
	struct host_config *host_cfg = subsys_cfg->host;
	struct fabrics_config *fabrics_cfg = host_cfg->fabrics;
	struct nvmf_disc_rsp_page_hdr *log = NULL;
	char *dev_name;
	int instance, numrec = 0, ret, err;
	int status = 0;

	if (port_cfg->device) {
		/*
		 * if the cfg->device passed in matches the connect args
		 *    cfg->device is left as-is
		 * else if there exists a controller that matches the
		 *         connect args
		 *    cfg->device is the matching ctrl name
		 * else if no ctrl matches the connect args
		 *    cfg->device is set to null. This will attempt to
		 *    create a new ctrl.
		 * endif
		 */
		if (!ctrl_matches_portconfig(port_cfg->device, port_cfg))
			port_cfg->device = find_ctrl_from_portconfig(port_cfg);
	}

	if (!port_cfg->device) {
		instance = add_ctrl(port_cfg, argstr);
	} else {
		struct host_config *tmp_host_cfg;

		instance = ctrl_instance(port_cfg->device);
		tmp_host_cfg = nvmf_get_host_identifiers(fabrics_cfg, instance);
		if (host_cfg != tmp_host_cfg) {
			/* Host identifiers changed, switch subtree */
			char *subsysnqn = subsys_cfg->nqn;
			char *transport, *traddr, *host_traddr, *trsvcid;

			subsys_cfg = lookup_subsys(tmp_host_cfg, subsysnqn);
			if (!subsys_cfg) {
				msg(LOG_ERR,
					"Failed to allocate subsys '%s'\n",
					subsysnqn);
				return -ENOMEM;
			}
			transport = port_cfg->transport;
			traddr = port_cfg->traddr;
			host_traddr = port_cfg->host_traddr;
			trsvcid = port_cfg->trsvcid;
			port_cfg = lookup_port(subsys_cfg, transport, traddr,
					       host_traddr, trsvcid);
		}
	}
	if (instance < 0)
		return instance;

	if (asprintf(&dev_name, "/dev/nvme%d", instance) < 0)
		return -errno;
	ret = nvmf_get_log_page_discovery(dev_name, &log, &numrec, &status);
	free(dev_name);
	if (port_cfg && port_cfg->persistent)
		printf("Persistent device: nvme%d\n", instance);
	if (!port_cfg || (!port_cfg->device && !port_cfg->persistent)) {
		err = remove_ctrl(instance);
		if (err)
			return err;
	}

	switch (ret) {
	case DISC_OK:
		if (connect) {
			if (port_cfg)
				ret = connect_ctrls(port_cfg, log, numrec);
			else
				ret = -ENOMEM;
		} else if (fabrics_cfg->raw || flags == BINARY)
			save_discovery_log(log, numrec, fabrics_cfg->raw);
		else if (flags == JSON)
			json_discovery_log(log, numrec);
		else
			print_discovery_log(log, numrec);
		break;
	case DISC_GET_NUMRECS:
		msg(LOG_ERR, "Get number of discovery log entries failed.\n");
		ret = status;
		break;
	case DISC_GET_LOG:
		msg(LOG_ERR, "Get discovery log entries failed.\n");
		ret = status;
		break;
	case DISC_NO_LOG:
		fprintf(stdout, "No discovery log entries to fetch.\n");
		ret = DISC_OK;
		break;
	case DISC_RETRY_EXHAUSTED:
		fprintf(stdout, "Discovery retries exhausted.\n");
		ret = -EAGAIN;
		break;
	case DISC_NOT_EQUAL:
		msg(LOG_ERR,
		    "Numrec values of last two get discovery log page not equal\n");
		ret = -EBADSLT;
		break;
	default:
		msg(LOG_ERR, "Get discovery log page failed: %d\n", ret);
		break;
	}

	return ret;
}

static int discover_from_conf_file(struct fabrics_config *fabrics_cfg,
		struct host_config *static_host,
		struct port_config *static_port, const char *desc, char *argstr,
		const struct argconfig_commandline_options *opts, bool connect)
{
	struct subsys_config *subsys_cfg;
	FILE *f;
	char line[256], *ptr, *args, **argv;
	int argc, err, ret = 0;

	f = fopen(PATH_NVMF_DISC, "r");
	if (f == NULL) {
		msg(LOG_ERR, "No discover params given and no %s\n",
			PATH_NVMF_DISC);
		return -EINVAL;
	}

	subsys_cfg = lookup_subsys(static_host, NVME_DISC_SUBSYS_NAME);
	if (!subsys_cfg) {
		msg(LOG_ERR, "Failed to allocate subsys '%s'\n",
			NVME_DISC_SUBSYS_NAME);
		return -ENOMEM;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		enum nvme_print_flags flags;
		struct port_config *port_cfg;

		if (line[0] == '#' || line[0] == '\n')
			continue;

		args = strdup(line);
		if (!args) {
			msg(LOG_ERR, "failed to strdup args\n");
			ret = -ENOMEM;
			goto out;
		}

		argv = calloc(MAX_DISC_ARGS, BUF_SIZE);
		if (!argv) {
			perror("failed to allocate argv vector\n");
			free(args);
			ret = -ENOMEM;
			goto out;
		}

		argc = 0;
		argv[argc++] = "discover";
		while ((ptr = strsep(&args, " =\n")) != NULL)
			argv[argc++] = ptr;

		err = argconfig_parse(argc, argv, desc, opts);
		if (err)
			goto free_and_continue;

		port_cfg = lookup_port(subsys_cfg, static_port->transport,
				   static_port->traddr,
				   static_port->host_traddr,
				   static_port->trsvcid);
		if (!port_cfg) {
			/* Continue with static port */
			port_cfg = static_port;
		}
		if (port_cfg != static_port) {
			port_cfg->nr_io_queues =
				static_port->nr_io_queues;
			port_cfg->nr_write_queues =
				static_port->nr_write_queues;
			port_cfg->nr_poll_queues =
				static_port->nr_poll_queues;
			port_cfg->queue_size =
				static_port->queue_size;
			port_cfg->keep_alive_tmo =
				static_port->keep_alive_tmo;
			port_cfg->reconnect_delay =
				static_port->reconnect_delay;
			port_cfg->ctrl_loss_tmo =
				static_port->ctrl_loss_tmo;
			port_cfg->tos =
				static_port->tos;
			port_cfg->duplicate_connect =
				static_port->duplicate_connect;
			port_cfg->disable_sqflow =
				static_port->disable_sqflow;
			port_cfg->hdr_digest =
				static_port->hdr_digest;
			port_cfg->data_digest =
				static_port->data_digest;
			port_cfg->persistent =
				static_port->persistent;
		}

		err = flags = validate_output_format(fabrics_cfg->output_format);
		if (err < 0)
			goto free_and_continue;
		set_discovery_kato(port_cfg);

		if (traddr_is_hostname(port_cfg)) {
			ret = hostname2traddr(port_cfg);
			if (ret)
				goto out;
		}

		if (!port_cfg->trsvcid || !strcmp(port_cfg->trsvcid, "none"))
			discovery_trsvcid(port_cfg);

		err = build_options(port_cfg, argstr, BUF_SIZE, true);
		if (err) {
			ret = err;
			goto free_and_continue;
		}

		err = do_discover(port_cfg, argstr, connect, flags);
		if (err)
			ret = err;

free_and_continue:
		free(args);
		free(argv);
	}

out:
	fclose(f);
	return ret;
}

int fabrics_discover(const char *desc, int argc, char **argv, bool connect)
{
	char argstr[BUF_SIZE];
	int ret;
	enum nvme_print_flags flags;
	struct fabrics_config fabrics_cfg = {
		.config = PATH_NVMF_CONFIG,
		.output_format = "normal",
	};
	struct host_config static_host;
	struct subsys_config *subsys_cfg;
	struct port_config static_port = {
		.traddr = "none",
		.trsvcid = "none",
		.host_traddr = "none",
		.device = "none",
		.ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO,
		.tos = -1,
	};

	OPT_ARGS(opts) = {
		OPT_LIST("transport",      't', &static_port.transport,       "transport type"),
		OPT_LIST("traddr",         'a', &static_port.traddr,          "transport address"),
		OPT_LIST("trsvcid",        's', &static_port.trsvcid,         "transport service id (e.g. IP port)"),
		OPT_LIST("host-traddr",    'w', &static_port.host_traddr,     "host traddr (e.g. FC WWN's)"),
		OPT_LIST("hostnqn",        'q', &static_host.hostnqn,         "user-defined hostnqn (if default not used)"),
		OPT_LIST("hostid",         'I', &static_host.hostid,          "user-defined hostid (if default not used)"),
		OPT_LIST("raw",            'r', &fabrics_cfg.raw,             "raw output file"),
		OPT_LIST("device",         'd', &static_port.device,          "use existing discovery controller device"),
		OPT_LIST("config",         'C', &fabrics_cfg.config,          "use JSON configuration file (if default is not used)"),
		OPT_INT("keep-alive-tmo",  'k', &static_port.keep_alive_tmo,  "keep alive timeout period in seconds"),
		OPT_INT("reconnect-delay", 'c', &static_port.reconnect_delay, "reconnect timeout period in seconds"),
		OPT_INT("ctrl-loss-tmo",   'l', &static_port.ctrl_loss_tmo,   "controller loss timeout period in seconds"),
		OPT_INT("tos",             'T', &static_port.tos,             "type of service"),
		OPT_FLAG("hdr_digest",     'g', &static_port.hdr_digest,      "enable transport protocol header digest (TCP transport)"),
		OPT_FLAG("data_digest",    'G', &static_port.data_digest,     "enable transport protocol data digest (TCP transport)"),
		OPT_INT("nr-io-queues",    'i', &static_port.nr_io_queues,    "number of io queues to use (default is core count)"),
		OPT_INT("nr-write-queues", 'W', &static_port.nr_write_queues, "number of write queues to use (default 0)"),
		OPT_INT("nr-poll-queues",  'P', &static_port.nr_poll_queues,  "number of poll queues to use (default 0)"),
		OPT_INT("queue-size",      'Q', &static_port.queue_size,      "number of io queue elements to use (default 128)"),
		OPT_FLAG("persistent",     'p', &static_port.persistent,      "persistent discovery connection"),
		OPT_FLAG("quiet",          'S', &fabrics_cfg.quiet,           "suppress already connected errors"),
		OPT_FLAG("matching",       'm', &fabrics_cfg.matching_only,   "connect only records matching the traddr"),
		OPT_FMT("output-format",   'o', &fabrics_cfg.output_format,   output_format),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		goto out;

	ret = flags = validate_output_format(fabrics_cfg.output_format);
	if (ret < 0)
		goto out;
	if (static_port.device && !strcmp(static_port.device, "none"))
		static_port.device = NULL;

	INIT_LIST_HEAD(&fabrics_cfg.host_list);
	INIT_LIST_HEAD(&static_host.entry);
	static_host.fabrics = &fabrics_cfg;
	list_add(&static_host.entry, &fabrics_cfg.host_list);
	INIT_LIST_HEAD(&static_host.subsys_list);
	subsys_cfg = lookup_subsys(&static_host, NVME_DISC_SUBSYS_NAME);
	if (!subsys_cfg) {
		msg(LOG_ERR, "Failed to allocate subsys '%s'\n",
			NVME_DISC_SUBSYS_NAME);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&static_port.entry);
	static_port.subsys = subsys_cfg;
	list_add(&static_port.entry, &subsys_cfg->port_list);

	if (!static_host.hostnqn)
		nvmf_hostnqn_file(&static_host);
	if (!static_host.hostid)
		nvmf_hostid_file(&static_host);
	if (fabrics_cfg.config && strcmp(fabrics_cfg.config, "none"))
		json_read_config(&fabrics_cfg);

	if (!static_port.transport && !static_port.traddr) {
		ret = discover_from_conf_file(&fabrics_cfg, &static_host,
					      &static_port, desc, argstr,
					      opts, connect);
	} else {
		set_discovery_kato(&static_port);

		if (traddr_is_hostname(&static_port)) {
			ret = hostname2traddr(&static_port);
			if (ret)
				goto out;
		}

		if (!static_port.trsvcid ||
		    !strcmp(static_port.trsvcid, "none"))
			discovery_trsvcid(&static_port);

		ret = build_options(&static_port, argstr, BUF_SIZE, true);
		if (ret)
			goto out;

		ret = do_discover(&static_port, argstr, connect, flags);
	}

	if (fabrics_cfg.config && strcmp(fabrics_cfg.config, "none"))
		json_update_config(&fabrics_cfg);
out:
	return nvme_status_to_errno(ret, true);
}

int fabrics_connect(const char *desc, int argc, char **argv)
{
	char argstr[BUF_SIZE];
	int instance, ret;
	struct fabrics_config fabrics_cfg = {
		.config = PATH_NVMF_CONFIG,
		.output_format = "normal",
	};
	struct host_config static_host = {
		.hostnqn = NULL,
		.hostid = NULL,
	};
	struct subsys_config static_subsys = {
		.nqn = NULL,
	};
	struct port_config static_port = {
		.traddr = "none",
		.trsvcid = "none",
		.host_traddr = "none",
		.ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO,
		.tos = -1,
	};

	OPT_ARGS(opts) = {
		OPT_LIST("transport",         't', &static_port.transport,         "transport type"),
		OPT_LIST("nqn",               'n', &static_subsys.nqn,               "nqn name"),
		OPT_LIST("traddr",            'a', &static_port.traddr,            "transport address"),
		OPT_LIST("trsvcid",           's', &static_port.trsvcid,           "transport service id (e.g. IP port)"),
		OPT_LIST("host-traddr",       'w', &static_port.host_traddr,       "host traddr (e.g. FC WWN's)"),
		OPT_LIST("hostnqn",           'q', &static_host.hostnqn,           "user-defined hostnqn"),
		OPT_LIST("hostid",            'I', &static_host.hostid,            "user-defined hostid (if default not used)"),
		OPT_LIST("config",            'C', &fabrics_cfg.config,            "use JSON configuration file (default /etc/nvme/config.json)"),
		OPT_INT("nr-io-queues",       'i', &static_port.nr_io_queues,      "number of io queues to use (default is core count)"),
		OPT_INT("nr-write-queues",    'W', &static_port.nr_write_queues,   "number of write queues to use (default 0)"),
		OPT_INT("nr-poll-queues",     'P', &static_port.nr_poll_queues,    "number of poll queues to use (default 0)"),
		OPT_INT("queue-size",         'Q', &static_port.queue_size,        "number of io queue elements to use (default 128)"),
		OPT_INT("keep-alive-tmo",     'k', &static_port.keep_alive_tmo,    "keep alive timeout period in seconds"),
		OPT_INT("reconnect-delay",    'c', &static_port.reconnect_delay,   "reconnect timeout period in seconds"),
		OPT_INT("ctrl-loss-tmo",      'l', &static_port.ctrl_loss_tmo,     "controller loss timeout period in seconds"),
		OPT_INT("tos",                'T', &static_port.tos,               "type of service"),
		OPT_FLAG("duplicate-connect", 'D', &static_port.duplicate_connect, "allow duplicate connections between same transport host and subsystem port"),
		OPT_FLAG("disable-sqflow",    'd', &static_port.disable_sqflow,    "disable controller sq flow control (default false)"),
		OPT_FLAG("hdr-digest",        'g', &static_port.hdr_digest,        "enable transport protocol header digest (TCP transport)"),
		OPT_FLAG("data-digest",       'G', &static_port.data_digest,       "enable transport protocol data digest (TCP transport)"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		goto out;

	INIT_LIST_HEAD(&fabrics_cfg.host_list);
	INIT_LIST_HEAD(&static_host.entry);
	list_add(&static_host.entry, &fabrics_cfg.host_list);
	INIT_LIST_HEAD(&static_host.subsys_list);
	INIT_LIST_HEAD(&static_subsys.entry);
	list_add(&static_subsys.entry, &static_host.subsys_list);
	INIT_LIST_HEAD(&static_subsys.port_list);
	INIT_LIST_HEAD(&static_port.entry);
	list_add(&static_port.entry, &static_subsys.port_list);

	if (traddr_is_hostname(&static_port)) {
		ret = hostname2traddr(&static_port);
		if (ret)
			goto out;
	}

	if (!static_host.hostnqn)
		nvmf_hostnqn_file(&static_host);
	if (!static_host.hostid)
		nvmf_hostid_file(&static_host);
	if (fabrics_cfg.config && strcmp(fabrics_cfg.config, "none"))
		json_read_config(&fabrics_cfg);

	ret = build_options(&static_port, argstr, BUF_SIZE, false);
	if (ret)
		goto out;

	if (!static_subsys.nqn) {
		msg(LOG_ERR, "need a -n argument\n");
		ret = -EINVAL;
		goto out;
	}

	instance = add_ctrl(&static_port, argstr);
	if (instance < 0)
		ret = instance;

	if (fabrics_cfg.config && strcmp(fabrics_cfg.config, "none"))
		json_update_config(&fabrics_cfg);
out:
	return nvme_status_to_errno(ret, true);
}

static int scan_sys_nvme_filter(const struct dirent *d)
{
	if (!strcmp(d->d_name, "."))
		return 0;
	if (!strcmp(d->d_name, ".."))
		return 0;
	return 1;
}

/*
 * Returns 1 if disconnect occurred, 0 otherwise.
 */
static int disconnect_subsys(const char *nqn, char *ctrl)
{
	char *sysfs_nqn_path = NULL, *sysfs_del_path = NULL;
	char subsysnqn[NVMF_NQN_SIZE] = {};
	int fd, ret = 0;

	if (asprintf(&sysfs_nqn_path, "%s/%s/subsysnqn", SYS_NVME, ctrl) < 0)
		goto free;
	if (asprintf(&sysfs_del_path, "%s/%s/delete_controller", SYS_NVME, ctrl) < 0)
		goto free;

	fd = open(sysfs_nqn_path, O_RDONLY);
	if (fd < 0) {
		msg(LOG_ERR, "Failed to open %s: %s\n",
				sysfs_nqn_path, strerror(errno));
		goto free;
	}

	if (read(fd, subsysnqn, NVMF_NQN_SIZE) < 0)
		goto close;

	subsysnqn[strcspn(subsysnqn, "\n")] = '\0';
	if (strcmp(subsysnqn, nqn))
		goto close;

	if (!remove_ctrl_by_path(sysfs_del_path))
		ret = 1;
 close:
	close(fd);
 free:
	free(sysfs_del_path);
	free(sysfs_nqn_path);
	return ret;
}

/*
 * Returns the number of controllers successfully disconnected.
 */
static int disconnect_by_nqn(const char *nqn)
{
	struct dirent **devices = NULL;
	int i, n, ret = 0;

	if (strlen(nqn) > NVMF_NQN_SIZE)
		return -EINVAL;

	n = scandir(SYS_NVME, &devices, scan_sys_nvme_filter, alphasort);
	if (n < 0)
		return n;

	for (i = 0; i < n; i++)
		ret += disconnect_subsys(nqn, devices[i]->d_name);

	for (i = 0; i < n; i++)
		free(devices[i]);
	free(devices);

	return ret;
}

static int disconnect_by_device(const char *device)
{
	int instance;

	instance = ctrl_instance(device);
	if (instance < 0)
		return instance;
	return remove_ctrl(instance);
}

int fabrics_disconnect(const char *desc, int argc, char **argv)
{
	const char *nqn = "nqn name";
	const char *device = "nvme device";
	int ret;
	struct subsys_config static_subsys;
	struct port_config static_port = {
		.ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO,
	};
	OPT_ARGS(opts) = {
		OPT_LIST("nqn",    'n', &static_subsys.nqn,    nqn),
		OPT_LIST("device", 'd', &static_port.device, device),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		goto out;

	if (!static_subsys.nqn && !static_port.device) {
		msg(LOG_ERR, "need a -n or -d argument\n");
		ret = -EINVAL;
		goto out;
	}

	if (static_subsys.nqn) {
		ret = disconnect_by_nqn(static_subsys.nqn);
		if (ret < 0)
			msg(LOG_ERR, "Failed to disconnect by NQN: %s\n",
				static_subsys.nqn);
		else {
			printf("NQN:%s disconnected %d controller(s)\n",
			       static_subsys.nqn, ret);
			ret = 0;
		}
	}

	if (static_port.device) {
		ret = disconnect_by_device(static_port.device);
		if (ret)
			msg(LOG_ERR,
				"Failed to disconnect by device name: %s\n",
				static_port.device);
	}

out:
	return nvme_status_to_errno(ret, true);
}

int fabrics_disconnect_all(const char *desc, int argc, char **argv)
{
	struct nvme_topology t = { };
	int i, j, err;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		goto out;

	err = scan_subsystems(&t, NULL, 0, 0, NULL);
	if (err) {
		msg(LOG_ERR, "Failed to scan namespaces\n");
		goto out;
	}

	for (i = 0; i < t.nr_subsystems; i++) {
		struct nvme_subsystem *s = &t.subsystems[i];

		for (j = 0; j < s->nr_ctrls; j++) {
			struct nvme_ctrl *c = &s->ctrls[j];

			if (!c->transport || !strcmp(c->transport, "pcie"))
				continue;
			err = disconnect_by_device(c->name);
			if (err)
				goto free;
		}
	}
free:
	free_topology(&t);
out:
	return nvme_status_to_errno(err, true);
}
