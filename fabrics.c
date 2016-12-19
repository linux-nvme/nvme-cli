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
#include <asm/byteorder.h>
#include <inttypes.h>
#include <linux/types.h>

#include "parser.h"
#include "nvme-ioctl.h"
#include "fabrics.h"

#include "nvme.h"
#include "argconfig.h"

#include "common.h"

static struct config {
	char *nqn;
	char *transport;
	char *traddr;
	char *trsvcid;
	char *host_traddr;
	char *hostnqn;
	char *nr_io_queues;
	char *keep_alive_tmo;
	char *reconnect_delay;
	char *raw;
	char *device;
} cfg = { NULL };

#define BUF_SIZE		4096
#define PATH_NVME_FABRICS	"/dev/nvme-fabrics"
#define PATH_NVMF_DISC		"/etc/nvme/discovery.conf"
#define PATH_NVMF_HOSTNQN	"/etc/nvme/hostnqn"
#define SYS_NVME		"/sys/class/nvme"
#define MAX_DISC_ARGS		10

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

static const char *arg_str(const char * const *strings,
		size_t array_size, size_t idx)
{
	if (idx < array_size && strings[idx])
		return strings[idx];
	return "unrecognized";
}

static const char * const trtypes[] = {
	[NVMF_TRTYPE_RDMA]	= "rdma",
	[NVMF_TRTYPE_FC]	= "fibre-channel",
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
};

static inline const char *treq_str(__u8 treq)
{
	return arg_str(treqs, ARRAY_SIZE(treqs), treq);
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

static int do_discover(char *argstr, bool connect);

static int add_ctrl(const char *argstr)
{
	substring_t args[MAX_OPT_ARGS];
	char buf[BUF_SIZE], *options, *p;
	int token, ret, fd, len = strlen(argstr);

	fd = open(PATH_NVME_FABRICS, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n",
			 PATH_NVME_FABRICS, strerror(errno));
		ret = -errno;
		goto out;
	}

	if (write(fd, argstr, len) != len) {
		fprintf(stderr, "Failed to write to %s: %s\n",
			 PATH_NVME_FABRICS, strerror(errno));
		ret = -errno;
		goto out_close;
	}

	len = read(fd, buf, BUF_SIZE);
	if (len < 0) {
		fprintf(stderr, "Failed to read from %s: %s\n",
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
			goto out_close;
		default:
			/* ignore */
			break;
		}
	}

out_fail:
	fprintf(stderr, "Failed to parse ctrl info for \"%s\"\n", argstr);
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
		ret = errno;
		goto out;
	}

	if (write(fd, "1", 1) != 1) {
		ret = errno;
		goto out_close;
	}

	ret = 0;
out_close:
	close(fd);
out:
	return ret;
}

static int remove_ctrl(int instance)
{
	char *sysfs_path;
	int ret;

	if (asprintf(&sysfs_path, "/sys/class/nvme/nvme%d/delete_controller",
			instance) < 0) {
		ret = errno;
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
	DISC_NOT_EQUAL,
};

static int nvmf_get_log_page_discovery(const char *dev_path,
		struct nvmf_disc_rsp_page_hdr **logp, int *numrec)
{
	struct nvmf_disc_rsp_page_hdr *log;
	unsigned int log_size = 0;
	unsigned long genctr;
	int error, fd;

	fd = open(dev_path, O_RDWR);
	if (fd < 0) {
		error = -errno;
		goto out;
	}

	/* first get_log_page we just need numrec entry from discovery hdr.
	 * host supplies its desired bytes via dwords, per NVMe spec.
	 */
	log_size = round_up((offsetof(struct nvmf_disc_rsp_page_hdr, numrec) +
			    sizeof(log->numrec)), sizeof(__u32));

	/*
	 * Issue first get log page w/numdl small enough to retrieve numrec.
	 * We just want to know how many records to retrieve.
	 */
	log = calloc(1, log_size);
	if (!log) {
		error = -ENOMEM;
		goto out_close;
	}

	error = nvme_discovery_log(fd, log, log_size);
	if (error) {
		error = DISC_GET_NUMRECS;
		goto out_free_log;
	}

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

	if (*numrec != le32_to_cpu(log->numrec) || genctr != le64_to_cpu(log->genctr)) {
		error = DISC_NOT_EQUAL;
		goto out_free_log;
	}

	/* needs to be freed by the caller */
	*logp = log;
	goto out_close;

	error = DISC_OK;
out_free_log:
	free(log);
out_close:
	close(fd);
out:
	return error;
}

static void print_discovery_log(struct nvmf_disc_rsp_page_hdr *log, int numrec)
{
	int i;

	printf("\nDiscovery Log Number of Records %d, "
	       "Generation counter %"PRIu64"\n",
		numrec, (uint64_t)le64_to_cpu(log->genctr));

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_rsp_page_entry *e = &log->entries[i];

		printf("=====Discovery Log Entry %d======\n", i);
		printf("trtype:  %s\n", trtype_str(e->trtype));
		printf("adrfam:  %s\n", adrfam_str(e->adrfam));
		printf("subtype: %s\n", subtype_str(e->subtype));
		printf("treq:    %s\n", treq_str(e->treq));
		printf("portid:  %d\n", e->portid);
		printf("trsvcid: %s\n", e->trsvcid);
		printf("subnqn:  %s\n", e->subnqn);
		printf("traddr:  %s\n", e->traddr);

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
		}
	}
}

static void save_discovery_log(struct nvmf_disc_rsp_page_hdr *log, int numrec)
{
	int fd;
	int len, ret;

	fd = open(cfg.raw, O_CREAT|O_RDWR|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s: %s\n",
			cfg.raw, strerror(errno));
		return;
	}

	len = sizeof(struct nvmf_disc_rsp_page_hdr) +
			numrec * sizeof(struct nvmf_disc_rsp_page_entry);
	ret = write(fd, log, len);
	if (ret < 0)
		fprintf(stderr, "failed to write to %s: %s\n",
			cfg.raw, strerror(errno));
	else
		printf("Discovery log is saved to %s\n", cfg.raw);

	close(fd);
}

static int nvmf_hostnqn_file(void)
{
	FILE *f;
	char hostnqn[NVMF_NQN_SIZE];
	int ret = false;

	f = fopen(PATH_NVMF_HOSTNQN, "r");
	if (f == NULL)
		return false;

	if (fgets(hostnqn, sizeof(hostnqn), f) == NULL)
		goto out;

	cfg.hostnqn = strdup(hostnqn);
	if (!cfg.hostnqn)
		goto out;

	ret = true;
out:
	fclose(f);
	return ret;
}

static int build_options(char *argstr, int max_len)
{
	int len;

	if (!cfg.transport) {
		fprintf(stderr, "need a transport (-t) argument\n");
		return -EINVAL;
	}

	if (strncmp(cfg.transport, "loop", 4)) {
		if (!cfg.traddr) {
			fprintf(stderr, "need a address (-a) argument\n");
			return -EINVAL;
		}
	}

	len = snprintf(argstr, max_len, "nqn=%s", cfg.nqn);
	if (len < 0)
		return -EINVAL;
	argstr += len;
	max_len -= len;

	len = snprintf(argstr, max_len, ",transport=%s", cfg.transport);
	if (len < 0)
		return -EINVAL;
	argstr += len;
	max_len -= len;

	if (cfg.traddr) {
		len = snprintf(argstr, max_len, ",traddr=%s", cfg.traddr);
		if (len < 0)
			return -EINVAL;
		argstr += len;
		max_len -= len;
	}

	if (cfg.host_traddr) {
		len = snprintf(argstr, max_len, ",host_traddr=%s", cfg.host_traddr);
		if (len < 0)
			return -EINVAL;
		argstr += len;
		max_len -= len;
	}

	if (cfg.trsvcid) {
		len = snprintf(argstr, max_len, ",trsvcid=%s", cfg.trsvcid);
		if (len < 0)
			return -EINVAL;
		argstr += len;
		max_len -= len;
	}

	if (cfg.hostnqn || nvmf_hostnqn_file()) {
		len = snprintf(argstr, max_len, ",hostnqn=%s", cfg.hostnqn);
		if (len < 0)
			return -EINVAL;
		argstr += len;
		max_len -= len;
	}

	if (cfg.nr_io_queues) {
		len = snprintf(argstr, max_len, ",nr_io_queues=%s",
				cfg.nr_io_queues);
		if (len < 0)
			return -EINVAL;
		argstr += len;
		max_len -= len;
	}

	if (cfg.keep_alive_tmo) {
		len = snprintf(argstr, max_len, ",keep_alive_tmo=%s", cfg.keep_alive_tmo);
		if (len < 0)
			return -EINVAL;
		argstr += len;
		max_len -= len;
	}

	if (cfg.reconnect_delay) {
		len = snprintf(argstr, max_len, ",reconnect_delay=%s", cfg.reconnect_delay);
		if (len < 0)
			return -EINVAL;
		argstr += len;
		max_len -= len;
	}

	return 0;
}

static int connect_ctrl(struct nvmf_disc_rsp_page_entry *e)
{
	char argstr[BUF_SIZE], *p = argstr;
	bool discover = false;
	int len;

	switch (e->subtype) {
	case NVME_NQN_DISC:
		discover = true;
	case NVME_NQN_NVME:
		break;
	default:
		fprintf(stderr, "skipping unsupported subtype %d\n",
			 e->subtype);
		return -EINVAL;
	}

	len = sprintf(p, "nqn=%s", e->subnqn);
	if (len < 0)
		return -EINVAL;
	p += len;

	if (cfg.hostnqn) {
		len = sprintf(p, ",hostnqn=%s", cfg.hostnqn);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	switch (e->trtype) {
	case NVMF_TRTYPE_LOOP: /* loop */
		len = sprintf(p, ",transport=loop");
		if (len < 0)
			return -EINVAL;
		p += len;
		/* we can safely ignore the rest of the entries */
		break;
	case NVMF_TRTYPE_RDMA:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_IP4:
		case NVMF_ADDR_FAMILY_IP6:
			/* FALLTHRU */
			len = sprintf(p, ",transport=rdma");
			if (len < 0)
				return -EINVAL;
			p += len;

			len = sprintf(p, ",traddr=%s", e->traddr);
			if (len < 0)
				return -EINVAL;
			p += len;

			len = sprintf(p, ",trsvcid=%s", e->trsvcid);
			if (len < 0)
				return -EINVAL;
			p += len;
			break;
		default:
			fprintf(stderr, "skipping unsupported adrfam\n");
			return -EINVAL;
		}
		break;
	case NVMF_TRTYPE_FC:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_FC:
			len = sprintf(p, ",transport=fc");
			if (len < 0)
				return -EINVAL;
			p += len;

			len = sprintf(p, ",traddr=%s", e->traddr);
			if (len < 0)
				return -EINVAL;
			p += len;
			break;
		default:
			fprintf(stderr, "skipping unsupported adrfam\n");
			return -EINVAL;
		}
		break;
	default:
		fprintf(stderr, "skipping unsupported transport %d\n",
				 e->trtype);
		return -EINVAL;
	}

	if (discover)
		return do_discover(argstr, true);
	else
		return add_ctrl(argstr);
}

static void connect_ctrls(struct nvmf_disc_rsp_page_hdr *log, int numrec)
{
	int i;

	for (i = 0; i < numrec; i++)
		connect_ctrl(&log->entries[i]);
}

static int do_discover(char *argstr, bool connect)
{
	struct nvmf_disc_rsp_page_hdr *log = NULL;
	char *dev_name;
	int instance, numrec = 0, ret;

	instance = add_ctrl(argstr);
	if (instance < 0)
		return instance;

	if (asprintf(&dev_name, "/dev/nvme%d", instance) < 0)
		return errno;
	ret = nvmf_get_log_page_discovery(dev_name, &log, &numrec);
	free(dev_name);
	remove_ctrl(instance);

	switch (ret) {
	case DISC_OK:
		if (connect)
			connect_ctrls(log, numrec);
		else if (cfg.raw)
			save_discovery_log(log, numrec);
		else
			print_discovery_log(log, numrec);
		break;
	case DISC_GET_NUMRECS:
		fprintf(stderr,
			"Get number of discovery log entries failed.\n");
		break;
	case DISC_GET_LOG:
		fprintf(stderr, "Get discovery log entries failed.\n");
		break;
	case DISC_NO_LOG:
		fprintf(stderr, "No discovery log entries to fetch.\n");
		break;
	case DISC_NOT_EQUAL:
		fprintf(stderr,
		"Numrec values of last two get dicovery log page not equal\n");
		break;
	default:
		fprintf(stderr, "Get dicovery log page failed: %d\n", ret);
		break;
	}

	return ret;
}

static int discover_from_conf_file(const char *desc, char *argstr,
		const struct argconfig_commandline_options *opts, bool connect)
{
	FILE *f;
	char line[256], *ptr, *args, **argv;
	int argc, err, ret = 0;

	f = fopen(PATH_NVMF_DISC, "r");
	if (f == NULL) {
		fprintf(stderr, "No discover params given and no %s conf\n",
			PATH_NVMF_DISC);
		return -EINVAL;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		if (line[0] == '#' || line[0] == '\n')
			continue;

		args = strdup(line);
		if (!args) {
			fprintf(stderr, "failed to strdup args\n");
			ret = -ENOMEM;
			goto out;
		}

		argv = calloc(MAX_DISC_ARGS, BUF_SIZE);
		if (!argv) {
			fprintf(stderr, "failed to allocate argv vector\n");
			free(args);
			ret = -ENOMEM;
			goto out;
		}

		argc = 0;
		argv[argc++] = "discover";
		while ((ptr = strsep(&args, " =\n")) != NULL)
			argv[argc++] = ptr;

		argconfig_parse(argc, argv, desc, opts, &cfg, sizeof(cfg));

		err = build_options(argstr, BUF_SIZE);
		if (err) {
			ret = err;
			continue;
		}

		err = do_discover(argstr, connect);
		if (err) {
			ret = err;
			continue;
		}

		free(args);
		free(argv);
	}

out:
	fclose(f);
	return ret;
}

int discover(const char *desc, int argc, char **argv, bool connect)
{
	char argstr[BUF_SIZE];
	int ret;
	const struct argconfig_commandline_options command_line_options[] = {
		{"transport",   't', "LIST", CFG_STRING, &cfg.transport,   required_argument, "transport type" },
		{"traddr",      'a', "LIST", CFG_STRING, &cfg.traddr,      required_argument, "transport address" },
		{"trsvcid",     's', "LIST", CFG_STRING, &cfg.trsvcid,     required_argument, "transport service id (e.g. IP port)" },
		{"host-traddr", 'w', "LIST", CFG_STRING, &cfg.host_traddr, required_argument, "host traddr (e.g. FC WWN's)" },
		{"hostnqn",     'q', "LIST", CFG_STRING, &cfg.hostnqn,     required_argument, "user-defined hostnqn (if default not used)" },
		{"raw",         'r', "LIST", CFG_STRING, &cfg.raw,         required_argument, "raw output file" },
		{NULL},
	};

	argconfig_parse(argc, argv, desc, command_line_options, &cfg,
			sizeof(cfg));

	cfg.nqn = NVME_DISC_SUBSYS_NAME;

	if (!cfg.transport && !cfg.traddr) {
		return discover_from_conf_file(desc, argstr,
				command_line_options, connect);
	} else {
		ret = build_options(argstr, BUF_SIZE);
		if (ret)
			return ret;

		return do_discover(argstr, connect);
	}
}

int connect(const char *desc, int argc, char **argv)
{
	char argstr[BUF_SIZE];
	int instance, ret;
	const struct argconfig_commandline_options command_line_options[] = {
		{"transport",       't', "LIST", CFG_STRING, &cfg.transport,       required_argument, "transport type" },
		{"nqn",             'n', "LIST", CFG_STRING, &cfg.nqn,             required_argument, "nqn name" },
		{"traddr",          'a', "LIST", CFG_STRING, &cfg.traddr,          required_argument, "transport address" },
		{"trsvcid",         's', "LIST", CFG_STRING, &cfg.trsvcid,         required_argument, "transport service id (e.g. IP port)" },
		{"host-traddr",     'w', "LIST", CFG_STRING, &cfg.host_traddr,     required_argument, "host traddr (e.g. FC WWN's)" },
		{"hostnqn",         'q', "LIST", CFG_STRING, &cfg.hostnqn,         required_argument, "user-defined hostnqn" },
		{"nr-io-queues",    'i', "LIST", CFG_STRING, &cfg.nr_io_queues,    required_argument, "number of io queues to use (default is core count)" },
		{"keep-alive-tmo",  'k', "LIST", CFG_STRING, &cfg.keep_alive_tmo,  required_argument, "keep alive timeout period in seconds" },
		{"reconnect-delay", 'c', "LIST", CFG_STRING, &cfg.reconnect_delay, required_argument, "reconnect timeout period in seconds" },
		{NULL},
	};

	argconfig_parse(argc, argv, desc, command_line_options, &cfg,
			sizeof(cfg));

	ret = build_options(argstr, BUF_SIZE);
	if (ret)
		return ret;

	if (!cfg.nqn) {
		fprintf(stderr, "need a -n argument\n");
		return -EINVAL;
	}

	instance = add_ctrl(argstr);
	if (instance < 0)
		return instance;
	return 0;
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
static int disconnect_subsys(char *nqn, char *ctrl)
{
	char *sysfs_nqn_path = NULL, *sysfs_del_path = NULL;
	char subsysnqn[NVMF_NQN_SIZE] = {};
	int fd, ret = 0;

	if (asprintf(&sysfs_nqn_path, "%s/%s/subsysnqn", SYS_NVME, ctrl) < 0)
		goto free;
	if (asprintf(&sysfs_del_path, "%s/%s/delete_controller", SYS_NVME, ctrl) < 0)
		goto free;

	fd = open(sysfs_nqn_path, O_RDONLY);
	if (fd < 0)
		goto free;

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
static int disconnect_by_nqn(char *nqn)
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

static int disconnect_by_device(char *device)
{
	int instance;
	int ret;

	ret = sscanf(device, "nvme%d", &instance);
	if (ret < 0)
		return ret;

	return remove_ctrl(instance);
}

int disconnect(const char *desc, int argc, char **argv)
{
	const char *nqn = "nqn name";
	const char *device = "nvme device";
	int ret = 0;

	const struct argconfig_commandline_options command_line_options[] = {
		{"nqn",    'n', "LIST", CFG_STRING, &cfg.nqn,    required_argument, nqn},
		{"device", 'd', "LIST", CFG_STRING, &cfg.device, required_argument, device},
		{NULL},
	};

	argconfig_parse(argc, argv, desc, command_line_options, &cfg,
			sizeof(cfg));
	if (!cfg.nqn && !cfg.device) {
		fprintf(stderr, "need a -n or -d argument\n");
		return -EINVAL;
	}

	if (cfg.nqn) {
		ret = disconnect_by_nqn(cfg.nqn);
		if (ret < 0)
			fprintf(stderr, "Failed to disconnect by NQN: %s\n",
				cfg.nqn);
		else
			printf("NQN:%s disconnected %d controller(s)\n", cfg.nqn, ret);
	}

	if (cfg.device) {
		ret = disconnect_by_device(cfg.device);
		if (ret)
			fprintf(stderr,
				"Failed to disconnect by device name: %s\n",
				cfg.device);
	}

	return ret;
}
