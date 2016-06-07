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
#include <sys/ioctl.h>
#include <libudev.h>

#include <linux/types.h>

#include "parser.h"
#include "nvme-ioctl.h"
#include "fabrics.h"

#include "linux/nvme.h"
#include "src/argconfig.h"

#include "common.h"

struct config {
	char *nqn;
	char *transport;
	char *traddr;
	char *trsvcid;
	char *raw;
} cfg = { 0 };

#define BUF_SIZE		4096
#define PATH_NVME_FABRICS	"/dev/nvme-fabrics"

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

static int add_ctrl(const char *argstr)
{
	substring_t args[MAX_OPT_ARGS];
	char buf[BUF_SIZE], *options, *p;
	size_t len = strlen(argstr);
	int token, ret, fd;

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
	unsigned log_size = 0;
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
	*numrec = le64toh(log->numrec);
	genctr = le64toh(log->genctr);
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

	if (*numrec != le32toh(log->numrec) || genctr != le64toh(log->genctr)) {
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

	printf("Discovery Log Number of Records %d, Generation counter %lld\n",
		numrec, log->genctr);

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_rsp_page_entry *e = &log->entries[i];

		printf("=====Discovery Log Entry %d======\n", i);
		printf("trtype:  %d\n", e->trtype);
		printf("adrfam:  %d\n", e->adrfam);
		printf("nqntype: %d\n", e->nqntype);
		printf("treq:    %d\n", e->treq);
		printf("portid:  %d\n", e->portid);
		printf("trsvcid: %s\n", e->trsvcid);
		printf("subnqn:  %s\n", e->subnqn);
		printf("traddr:  %s\n", e->traddr);

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			printf("rdma_prtype: %d\n", e->tsas.rdma.prtype);
			printf("rdma_qptype: %d\n", e->tsas.rdma.qptype);
			printf("rdma_cms:    %d\n", e->tsas.rdma.cms);
			printf("rdma_pkey: 0x%04x\n", e->tsas.rdma.pkey);
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
		fprintf(stderr, "failed to open %s: %s\n", cfg.raw, strerror(errno));
		return;
	}

	len = sizeof(struct nvmf_disc_rsp_page_hdr) +
			numrec * sizeof(struct nvmf_disc_rsp_page_entry);
	ret = write(fd, log, len);
	if (ret < 0)
		fprintf(stderr, "failed to write to %s: %s\n", cfg.raw, strerror(errno));
	else
		printf("Discovery log is saved to %s\n", cfg.raw);

	close(fd);
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

	if (cfg.trsvcid) {
		len = snprintf(argstr, max_len, ",trsvcid=%s", cfg.trsvcid);
		if (len < 0)
			return -EINVAL;
		argstr += len;
		max_len -= len;
	}

	return 0;
}

int discover(const char *desc, int argc, char **argv)
{
	char argstr[BUF_SIZE];
	struct nvmf_disc_rsp_page_hdr *log = NULL;
	char *dev_name;
	int instance, numrec = 0, ret;
	const struct argconfig_commandline_options command_line_options[] = {
		{"transport", 't', "LIST", CFG_STRING, &cfg.transport, required_argument,
			"transport type" },
		{"traddr", 'a', "LIST", CFG_STRING, &cfg.traddr, required_argument,
			"transport address" },
		{"trsvcid", 's', "LIST", CFG_STRING, &cfg.trsvcid, required_argument,
			"transport service id (e.g. IP port)" },
		{"raw", 'r', "LIST", CFG_STRING, &cfg.raw, required_argument,
			"raw" },
		{0},
	};

	argconfig_parse(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	cfg.nqn = NVME_DISC_SUBSYS_NAME;

	ret = build_options(argstr, BUF_SIZE);
	if (ret)
		return ret;

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
		if (cfg.raw)
			save_discovery_log(log, numrec);
		else
			print_discovery_log(log, numrec);
		break;
	case DISC_GET_NUMRECS:
		fprintf(stderr, "Get number of discovery log entries failed.\n");
		break;
	case DISC_GET_LOG:
		fprintf(stderr, "Get discovery log entries failed.\n");
		break;
	case DISC_NO_LOG:
		fprintf(stderr, "No discovery log entries to fetch.\n");
		break;
	case DISC_NOT_EQUAL:
		fprintf(stderr, "Numrec values of last two get dicovery log page not equal\n");
		break;
	default:
		fprintf(stderr, "Get dicovery log page failed: %d\n", ret);
		break;
	}

	return ret;
}
