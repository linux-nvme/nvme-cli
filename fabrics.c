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

#include "parser.h"
#include "nvme-ioctl.h"
#include "nvme-status.h"
#include "fabrics.h"

#include "nvme.h"
#include "argconfig.h"

#include "common.h"

#define NVMF_HOSTID_SIZE	36

static struct config {
	char *nqn;
	char *transport;
	char *traddr;
	char *trsvcid;
	char *host_traddr;
	char *hostnqn;
	char *hostid;
	int  nr_io_queues;
	int  nr_write_queues;
	int  nr_poll_queues;
	int  queue_size;
	int  keep_alive_tmo;
	int  reconnect_delay;
	int  ctrl_loss_tmo;
	char *raw;
	char *device;
	int  duplicate_connect;
	int  disable_sqflow;
	int  hdr_digest;
	int  data_digest;
} cfg = { NULL };

#define BUF_SIZE		4096
#define PATH_NVME_FABRICS	"/dev/nvme-fabrics"
#define PATH_NVMF_DISC		"/etc/nvme/discovery.conf"
#define PATH_NVMF_HOSTNQN	"/etc/nvme/hostnqn"
#define PATH_NVMF_HOSTID	"/etc/nvme/hostid"
#define SYS_NVME		"/sys/class/nvme"
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

static const char *arg_str(const char * const *strings,
		size_t array_size, size_t idx)
{
	if (idx < array_size && strings[idx])
		return strings[idx];
	return "unrecognized";
}

static const char * const trtypes[] = {
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
		ret = -errno;
		fprintf(stderr, "Failed to open %s: %s\n", sysfs_path,
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

static int remove_ctrl(int instance)
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
		fprintf(stderr, "Failed to open %s: %s\n",
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

	cfg.hostnqn = strndup(hostnqn, strcspn(hostnqn, "\n"));
	if (!cfg.hostnqn)
		goto out;

	ret = true;
out:
	fclose(f);
	return ret;
}

static int nvmf_hostid_file(void)
{
	FILE *f;
	char hostid[NVMF_HOSTID_SIZE + 1];
	int ret = false;

	f = fopen(PATH_NVMF_HOSTID, "r");
	if (f == NULL)
		return false;

	if (fgets(hostid, sizeof(hostid), f) == NULL)
		goto out;

	cfg.hostid = strdup(hostid);
	if (!cfg.hostid)
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
add_int_argument(char **argstr, int *max_len, char *arg_str, int arg)
{
	int len;

	if (arg) {
		len = snprintf(*argstr, *max_len, ",%s=%d", arg_str, arg);
		if (len < 0)
			return -EINVAL;
		*argstr += len;
		*max_len -= len;
	}

	return 0;
}

static int
add_argument(char **argstr, int *max_len, char *arg_str, char *arg)
{
	int len;

	if (arg) {
		len = snprintf(*argstr, *max_len, ",%s=%s", arg_str, arg);
		if (len < 0)
			return -EINVAL;
		*argstr += len;
		*max_len -= len;
	}

	return 0;
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

	/* always specify nqn as first arg - this will init the string */
	len = snprintf(argstr, max_len, "nqn=%s", cfg.nqn);
	if (len < 0)
		return -EINVAL;
	argstr += len;
	max_len -= len;

	if (add_argument(&argstr, &max_len, "transport", cfg.transport) ||
	    add_argument(&argstr, &max_len, "traddr", cfg.traddr) ||
	    add_argument(&argstr, &max_len, "host_traddr", cfg.host_traddr) ||
	    add_argument(&argstr, &max_len, "trsvcid", cfg.trsvcid) ||
	    ((cfg.hostnqn || nvmf_hostnqn_file()) &&
		    add_argument(&argstr, &max_len, "hostnqn", cfg.hostnqn)) ||
	    ((cfg.hostid || nvmf_hostid_file()) &&
		    add_argument(&argstr, &max_len, "hostid", cfg.hostid)) ||
	    add_int_argument(&argstr, &max_len, "nr_io_queues",
				cfg.nr_io_queues) ||
	    add_int_argument(&argstr, &max_len, "nr_write_queues",
				cfg.nr_write_queues) ||
	    add_int_argument(&argstr, &max_len, "nr_poll_queues",
				cfg.nr_poll_queues) ||
	    add_int_argument(&argstr, &max_len, "queue_size", cfg.queue_size) ||
	    add_int_argument(&argstr, &max_len, "keep_alive_tmo",
				cfg.keep_alive_tmo) ||
	    add_int_argument(&argstr, &max_len, "reconnect_delay",
				cfg.reconnect_delay) ||
	    add_int_argument(&argstr, &max_len, "ctrl_loss_tmo",
				cfg.ctrl_loss_tmo) ||
	    add_bool_argument(&argstr, &max_len, "duplicate_connect",
				cfg.duplicate_connect) ||
	    add_bool_argument(&argstr, &max_len, "disable_sqflow",
				cfg.disable_sqflow) ||
	    add_bool_argument(&argstr, &max_len, "hdr_digest", cfg.hdr_digest) ||
	    add_bool_argument(&argstr, &max_len, "data_digest", cfg.data_digest))
		return -EINVAL;

	return 0;
}

static int connect_ctrl(struct nvmf_disc_rsp_page_entry *e)
{
	char argstr[BUF_SIZE], *p;
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

	if (cfg.hostid) {
		len = sprintf(p, ",hostid=%s", cfg.hostid);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (cfg.queue_size) {
		len = sprintf(p, ",queue_size=%d", cfg.queue_size);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (cfg.nr_io_queues) {
		len = sprintf(p, ",nr_io_queues=%d", cfg.nr_io_queues);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (cfg.nr_write_queues) {
		len = sprintf(p, ",nr_write_queues=%d", cfg.nr_write_queues);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (cfg.nr_poll_queues) {
		len = sprintf(p, ",nr_poll_queues=%d", cfg.nr_poll_queues);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (cfg.host_traddr) {
		len = sprintf(p, ",host_traddr=%s", cfg.host_traddr);
		if (len < 0)
			return -EINVAL;
		p+= len;
	}

	if (cfg.ctrl_loss_tmo) {
		len = sprintf(p, ",ctrl_loss_tmo=%d", cfg.ctrl_loss_tmo);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (cfg.keep_alive_tmo && !discover) {
		len = sprintf(p, ",keep_alive_tmo=%d", cfg.keep_alive_tmo);
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	transport = trtype_str(e->trtype);
	if (!strcmp(transport, "unrecognized")) {
		fprintf(stderr, "skipping unsupported transport %d\n",
				 e->trtype);
		return -EINVAL;
	}

	len = sprintf(p, ",transport=%s", transport);
	if (len < 0)
		return -EINVAL;
	p += len;

	if (cfg.hdr_digest) {
		len = sprintf(p, ",hdr_digest");
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (cfg.data_digest) {
		len = sprintf(p, ",data_digest");
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	switch (e->trtype) {
	case NVMF_TRTYPE_RDMA:
	case NVMF_TRTYPE_TCP:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_IP4:
		case NVMF_ADDR_FAMILY_IP6:
			/* FALLTHRU */
			len = sprintf(p, ",traddr=%.*s",
				      space_strip_len(NVMF_TRADDR_SIZE, e->traddr),
				      e->traddr);
			if (len < 0)
				return -EINVAL;
			p += len;

			len = sprintf(p, ",trsvcid=%.*s",
				      space_strip_len(NVMF_TRSVCID_SIZE, e->trsvcid),
				      e->trsvcid);
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
	case NVMF_TRTYPE_FC:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_FC:
			len = sprintf(p, ",traddr=%.*s",
				      space_strip_len(NVMF_TRADDR_SIZE, e->traddr),
				      e->traddr);
			if (len < 0)
				return -EINVAL;
			p += len;
			break;
		default:
			fprintf(stderr, "skipping unsupported adrfam\n");
			return -EINVAL;
		}
		break;
	}

	if (e->treq & NVMF_TREQ_DISABLE_SQFLOW && disable_sqflow) {
		len = sprintf(p, ",disable_sqflow");
		if (len < 0)
			return -EINVAL;
		p += len;
	}

	if (discover)
		ret = do_discover(argstr, true);
	else
		ret = add_ctrl(argstr);
	if (ret == -EINVAL && e->treq & NVMF_TREQ_DISABLE_SQFLOW) {
		/* disable_sqflow param might not be supported, try without it */
		disable_sqflow = false;
		goto retry;
	}
	return ret;
}

static int connect_ctrls(struct nvmf_disc_rsp_page_hdr *log, int numrec)
{
	int i;
	int instance;
	int ret = 0;

	for (i = 0; i < numrec; i++) {
		instance = connect_ctrl(&log->entries[i]);

		/* clean success */
		if (instance >= 0)
			continue;

		/* already connected print message	*/
		if (instance == -EALREADY) {
			const char *traddr = log->entries[i].traddr;
			fprintf(stderr,
				"traddr=%.*s is already connected\n",
				space_strip_len(NVMF_TRADDR_SIZE, traddr),
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

static int do_discover(char *argstr, bool connect)
{
	struct nvmf_disc_rsp_page_hdr *log = NULL;
	char *dev_name;
	int instance, numrec = 0, ret, err;
	int status = 0;

	instance = add_ctrl(argstr);
	if (instance < 0)
		return instance;

	if (asprintf(&dev_name, "/dev/nvme%d", instance) < 0)
		return -errno;
	ret = nvmf_get_log_page_discovery(dev_name, &log, &numrec, &status);
	free(dev_name);
	err = remove_ctrl(instance);
	if (err)
		return err;

	switch (ret) {
	case DISC_OK:
		if (connect)
			ret = connect_ctrls(log, numrec);
		else if (cfg.raw)
			save_discovery_log(log, numrec);
		else
			print_discovery_log(log, numrec);
		break;
	case DISC_GET_NUMRECS:
		fprintf(stderr,
			"Get number of discovery log entries failed.\n");
		ret = status;
		break;
	case DISC_GET_LOG:
		fprintf(stderr, "Get discovery log entries failed.\n");
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
		fprintf(stderr,
		"Numrec values of last two get discovery log page not equal\n");
		ret = -EBADSLT;
		break;
	default:
		fprintf(stderr, "Get discovery log page failed: %d\n", ret);
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

		err = argconfig_parse(argc, argv, desc, opts, &cfg, sizeof(cfg));
		if (err)
			continue;

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
		{"hostid",      'I', "LIST", CFG_STRING, &cfg.hostid,      required_argument, "user-defined hostid (if default not used)"},
		{"raw",         'r', "LIST", CFG_STRING, &cfg.raw,         required_argument, "raw output file" },
		{"keep-alive-tmo",  'k', "LIST", CFG_INT, &cfg.keep_alive_tmo,  required_argument, "keep alive timeout period in seconds" },
		{"reconnect-delay", 'c', "LIST", CFG_INT, &cfg.reconnect_delay, required_argument, "reconnect timeout period in seconds" },
		{"ctrl-loss-tmo",   'l', "LIST", CFG_INT, &cfg.ctrl_loss_tmo,   required_argument, "controller loss timeout period in seconds" },
		{"hdr_digest", 'g', "", CFG_NONE, &cfg.hdr_digest, no_argument, "enable transport protocol header digest (TCP transport)" },
		{"data_digest", 'G', "", CFG_NONE, &cfg.data_digest, no_argument, "enable transport protocol data digest (TCP transport)" },
		{"nr-io-queues",    'i', "LIST", CFG_INT, &cfg.nr_io_queues,    required_argument, "number of io queues to use (default is core count)" },
		{"nr-write-queues", 'W', "LIST", CFG_INT, &cfg.nr_write_queues,    required_argument, "number of write queues to use (default 0)" },
		{"nr-poll-queues",  'P', "LIST", CFG_INT, &cfg.nr_poll_queues,    required_argument, "number of poll queues to use (default 0)" },
		{"queue-size",      'Q', "LIST", CFG_INT, &cfg.queue_size,      required_argument, "number of io queue elements to use (default 128)" },
		{NULL},
	};

	ret = argconfig_parse(argc, argv, desc, command_line_options, &cfg,
			sizeof(cfg));
	if (ret)
		goto out;

	cfg.nqn = NVME_DISC_SUBSYS_NAME;

	if (!cfg.transport && !cfg.traddr) {
		ret = discover_from_conf_file(desc, argstr,
				command_line_options, connect);
	} else {
		ret = build_options(argstr, BUF_SIZE);
		if (ret)
			goto out;

		ret = do_discover(argstr, connect);
	}

out:
	return nvme_status_to_errno(ret, true);
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
		{"hostid",          'I', "LIST", CFG_STRING, &cfg.hostid,      required_argument, "user-defined hostid (if default not used)"},
		{"nr-io-queues",    'i', "LIST", CFG_INT, &cfg.nr_io_queues,    required_argument, "number of io queues to use (default is core count)" },
		{"nr-write-queues", 'W', "LIST", CFG_INT, &cfg.nr_write_queues,    required_argument, "number of write queues to use (default 0)" },
		{"nr-poll-queues",  'P', "LIST", CFG_INT, &cfg.nr_poll_queues,    required_argument, "number of poll queues to use (default 0)" },
		{"queue-size",      'Q', "LIST", CFG_INT, &cfg.queue_size,      required_argument, "number of io queue elements to use (default 128)" },
		{"keep-alive-tmo",  'k', "LIST", CFG_INT, &cfg.keep_alive_tmo,  required_argument, "keep alive timeout period in seconds" },
		{"reconnect-delay", 'c', "LIST", CFG_INT, &cfg.reconnect_delay, required_argument, "reconnect timeout period in seconds" },
		{"ctrl-loss-tmo",   'l', "LIST", CFG_INT, &cfg.ctrl_loss_tmo,   required_argument, "controller loss timeout period in seconds" },
		{"duplicate_connect", 'D', "", CFG_NONE, &cfg.duplicate_connect, no_argument, "allow duplicate connections between same transport host and subsystem port" },
		{"disable_sqflow", 'd', "", CFG_NONE, &cfg.disable_sqflow, no_argument, "disable controller sq flow control (default false)" },
		{"hdr_digest", 'g', "", CFG_NONE, &cfg.hdr_digest, no_argument, "enable transport protocol header digest (TCP transport)" },
		{"data_digest", 'G', "", CFG_NONE, &cfg.data_digest, no_argument, "enable transport protocol data digest (TCP transport)" },
		{NULL},
	};

	ret = argconfig_parse(argc, argv, desc, command_line_options, &cfg,
			sizeof(cfg));
	if (ret)
		goto out;

	ret = build_options(argstr, BUF_SIZE);
	if (ret)
		goto out;

	if (!cfg.nqn) {
		fprintf(stderr, "need a -n argument\n");
		ret = -EINVAL;
		goto out;
	}

	instance = add_ctrl(argstr);
	if (instance < 0)
		ret = instance;

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
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n",
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

	device = basename(device);
	ret = sscanf(device, "nvme%d", &instance);
	if (ret < 0)
		return ret;
	if (!ret)
		return -1;

	return remove_ctrl(instance);
}

int disconnect(const char *desc, int argc, char **argv)
{
	const char *nqn = "nqn name";
	const char *device = "nvme device";
	int ret;

	const struct argconfig_commandline_options command_line_options[] = {
		{"nqn",    'n', "LIST", CFG_STRING, &cfg.nqn,    required_argument, nqn},
		{"device", 'd', "LIST", CFG_STRING, &cfg.device, required_argument, device},
		{NULL},
	};

	ret = argconfig_parse(argc, argv, desc, command_line_options, &cfg,
			sizeof(cfg));
	if (ret)
		goto out;

	if (!cfg.nqn && !cfg.device) {
		fprintf(stderr, "need a -n or -d argument\n");
		ret = -EINVAL;
		goto out;
	}

	if (cfg.nqn) {
		ret = disconnect_by_nqn(cfg.nqn);
		if (ret < 0)
			fprintf(stderr, "Failed to disconnect by NQN: %s\n",
				cfg.nqn);
		else {
			printf("NQN:%s disconnected %d controller(s)\n", cfg.nqn, ret);
			ret = 0;
		}
	}

	if (cfg.device) {
		ret = disconnect_by_device(cfg.device);
		if (ret)
			fprintf(stderr,
				"Failed to disconnect by device name: %s\n",
				cfg.device);
	}

out:
	return nvme_status_to_errno(ret, true);
}

int disconnect_all(const char *desc, int argc, char **argv)
{
	struct subsys_list_item *slist;
	int i, j, ret, subcnt = 0;
	const struct argconfig_commandline_options command_line_options[] = {
		{NULL},
	};

	ret = argconfig_parse(argc, argv, desc, command_line_options, &cfg,
			sizeof(cfg));
	if (ret)
		goto out;

	slist = get_subsys_list(&subcnt, NULL, NVME_NSID_ALL);
	for (i = 0; i < subcnt; i++) {
		struct subsys_list_item *subsys = &slist[i];

		for (j = 0; j < subsys->nctrls; j++) {
			struct ctrl_list_item *ctrl = &subsys->ctrls[j];
			if (!strcmp(ctrl->transport, "pcie"))
				continue;

			ret = disconnect_by_device(ctrl->name);
			if (ret)
				goto free;
		}
	}

free:
	free_subsys_list(slist, subcnt);
out:
	return nvme_status_to_errno(ret, true);
}
