// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/list/list.h>
#include <ccan/str/str.h>

#include <libnvme.h>

#include "cleanup.h"
#include "cleanup-linux.h"
#include "private.h"
#include "private-fabrics.h"
#include "compiler-attributes.h"

const char *nvmf_dev = "/dev/nvme-fabrics";

static inline void free_uri(struct libnvmf_uri **uri)
{
	libnvmf_uri_free(*uri);
}
#define __cleanup_uri __cleanup(free_uri)

/**
 * strchomp() - Strip trailing spaces
 * @str: String to strip
 * @max: Maximum length of string
 */
static void strchomp(char *str, int max)
{
	int i;

	for (i = max - 1; i >= 0 && str[i] == ' '; i--) {
		str[i] = '\0';
	}
}

const char *arg_str(const char * const *strings,
		size_t array_size, size_t idx)
{
	if (idx < array_size && strings[idx])
		return strings[idx];
	return "unrecognized";
}

#define NVMF_HOSTID_SIZE	37

#define NVMF_HOSTNQN_FILE	SYSCONFDIR "/nvme/hostnqn"
#define NVMF_HOSTID_FILE	SYSCONFDIR "/nvme/hostid"

static int uuid_from_device_tree(char *system_uuid)
{
	__cleanup_fd int f = -1;
	ssize_t len;

	f = open(libnvme_uuid_ibm_filename(), O_RDONLY);
	if (f < 0)
		return -ENXIO;

	memset(system_uuid, 0, NVME_UUID_LEN_STRING);
	len = read(f, system_uuid, NVME_UUID_LEN_STRING - 1);
	if (len < 0)
		return -ENXIO;

	return strlen(system_uuid) ? 0 : -ENXIO;
}

/*
 * See System Management BIOS (SMBIOS) Reference Specification
 * https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.2.0.pdf
 */
#define DMI_SYSTEM_INFORMATION	1

static bool is_dmi_uuid_valid(const char *buf, size_t len)
{
	int i;

	/* UUID bytes are from byte 8 to 23 */
	if (len < 24)
		return false;

	/* Test it's a invalid UUID with all zeros */
	for (i = 8; i < 24; i++) {
		if (buf[i])
			break;
	}
	if (i == 24)
		return false;

	return true;
}

static int read_file(char *filename, char *buf, size_t size)
{
	__cleanup_fd int f = -1;
	int len;

	f = open(filename, O_RDONLY);
	if (f < 0)
		return -errno;
	len = read(f, buf, size - 1);
	if (len < 0)
		return -errno;
	buf[len] = 0;

	return len;
}

static int uuid_from_dmi_entries(char *system_uuid)
{
	__cleanup_dir DIR *d = NULL;
	const char *entries_dir = libnvme_dmi_entries_dir();
	char filename[PATH_MAX];
	struct dirent *de;
	char buf[513] = {0};
	int len, type;

	system_uuid[0] = '\0';
	d = opendir(entries_dir);
	if (!d)
		return -ENXIO;
	while ((de = readdir(d))) {
		if (de->d_name[0] == '.')
			continue;
		snprintf(filename, sizeof(filename), "%s/%s/type", entries_dir,
			 de->d_name);
		len = read_file(filename, buf, sizeof(buf));
		if (len <= 0)
			continue;
		if (sscanf(buf, "%d", &type) != 1)
			continue;
		if (type != DMI_SYSTEM_INFORMATION)
			continue;
		snprintf(filename, sizeof(filename), "%s/%s/raw", entries_dir,
			 de->d_name);
		len = read_file(filename, buf, sizeof(buf));
		if (len <= 0)
			continue;

		if (!is_dmi_uuid_valid(buf, len))
			continue;

		/* Sigh. https://en.wikipedia.org/wiki/Overengineering */
		/* DMTF SMBIOS 3.0 Section 7.2.1 System UUID */
		sprintf(system_uuid,
			"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
			"%02x%02x%02x%02x%02x%02x",
			(uint8_t)buf[8 + 3], (uint8_t)buf[8 + 2],
			(uint8_t)buf[8 + 1], (uint8_t)buf[8 + 0],
			(uint8_t)buf[8 + 5], (uint8_t)buf[8 + 4],
			(uint8_t)buf[8 + 7], (uint8_t)buf[8 + 6],
			(uint8_t)buf[8 + 8], (uint8_t)buf[8 + 9],
			(uint8_t)buf[8 + 10], (uint8_t)buf[8 + 11],
			(uint8_t)buf[8 + 12], (uint8_t)buf[8 + 13],
			(uint8_t)buf[8 + 14], (uint8_t)buf[8 + 15]);
		break;
	}
	return strlen(system_uuid) ? 0 : -ENXIO;
}

#define PATH_DMI_PROD_UUID  "/sys/class/dmi/id/product_uuid"

/**
 * uuid_from_product_uuid() - Get system UUID from product_uuid
 * @system_uuid: Where to save the system UUID.
 *
 * Return: 0 on success, -ENXIO otherwise.
 */
static int uuid_from_product_uuid(char *system_uuid)
{
	__cleanup_file FILE *stream = NULL;

	stream = fopen(PATH_DMI_PROD_UUID, "re");
	if (!stream)
		return -ENXIO;

	system_uuid[0] = '\0';

	/* The kernel is handling the byte swapping according DMTF
	 * SMBIOS 3.0 Section 7.2.1 System UUID */

	/*
	 * Expect exactly:
	 * xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	 */
	if (!fgets(system_uuid, NVME_UUID_LEN_STRING, stream))
		return -ENXIO;

	if (strlen(system_uuid) != NVME_UUID_LEN_STRING - 1)
		return -ENXIO;

	if (system_uuid[8]  != '-' || system_uuid[13] != '-' ||
	    system_uuid[18] != '-' || system_uuid[23] != '-')
		return -ENXIO;

	system_uuid[NVME_UUID_LEN_STRING - 1] = '\0';

	return 0;
}

/**
 * uuid_from_dmi() - read system UUID
 * @system_uuid: buffer for the UUID
 *
 * The system UUID can be read from two different locations:
 *
 *     1) /sys/class/dmi/id/product_uuid
 *     2) /sys/firmware/dmi/entries
 *
 * Note that the second location is not present on Debian-based systems.
 *
 * Return: 0 on success, negative errno otherwise.
 */
static int uuid_from_dmi(char *system_uuid)
{
	int ret = uuid_from_product_uuid(system_uuid);
	if (ret != 0)
		ret = uuid_from_dmi_entries(system_uuid);
	return ret;
}

__libnvme_public char *libnvmf_generate_hostid(void)
{
	int ret;
	char uuid_str[NVME_UUID_LEN_STRING];
	unsigned char uuid[NVME_UUID_LEN];

	ret = uuid_from_dmi(uuid_str);
	if (ret < 0)
		ret = uuid_from_device_tree(uuid_str);
	if (ret < 0) {
		if (libnvme_random_uuid(uuid) < 0)
			memset(uuid, 0, NVME_UUID_LEN);
		libnvme_uuid_to_string(uuid, uuid_str);
	}

	return strdup(uuid_str);
}

__libnvme_public char *libnvmf_generate_hostnqn_from_hostid(char *hostid)
{
	char *hid = NULL;
	char *hostnqn;
	int ret;

	if (!hostid)
		hostid = hid = libnvmf_generate_hostid();

	ret = asprintf(&hostnqn, "nqn.2014-08.org.nvmexpress:uuid:%s", hostid);
	free(hid);

	return (ret < 0) ? NULL : hostnqn;
}

__libnvme_public char *libnvmf_generate_hostnqn(void)
{
	return libnvmf_generate_hostnqn_from_hostid(NULL);
}

static char *nvmf_read_file(const char *f, int len)
{
	char buf[len];
	__cleanup_fd int fd = -1;
	int ret;

	fd = open(f, O_RDONLY);
	if (fd < 0)
		return NULL;

	memset(buf, 0, len);
	ret = read(fd, buf, len - 1);

	if (ret < 0 || !strlen(buf))
		return NULL;
	return strndup(buf, strcspn(buf, "\n"));
}

__libnvme_public char *libnvmf_read_hostnqn(void)
{
	char *hostnqn = getenv("LIBNVME_HOSTNQN");

	if (hostnqn) {
		if (!strcmp(hostnqn, ""))
			return NULL;
		return strdup(hostnqn);
	}

	return nvmf_read_file(NVMF_HOSTNQN_FILE, NVMF_NQN_SIZE);
}

__libnvme_public char *libnvmf_read_hostid(void)
{
	char *hostid = getenv("LIBNVME_HOSTID");

	if (hostid) {
		if (!strcmp(hostid, ""))
			return NULL;
		return strdup(hostid);
	}

	return nvmf_read_file(NVMF_HOSTID_FILE, NVMF_HOSTID_SIZE);
}

int libnvmf_host_get_ids(struct libnvme_global_ctx *ctx,
		      const char *hostnqn_arg, const char *hostid_arg,
		      char **hostnqn, char **hostid)
{
	__cleanup_free char *nqn = NULL;
	__cleanup_free char *hid = NULL;
	__cleanup_free char *hnqn = NULL;
	libnvme_host_t h;

	/* command line argumments */
	if (hostid_arg)
		hid = strdup(hostid_arg);
	if (hostnqn_arg)
		hnqn = strdup(hostnqn_arg);

	/* JSON config: assume the first entry is the default host */
	h = libnvme_first_host(ctx);
	if (h) {
		if (!hid)
			hid = xstrdup(libnvme_host_get_hostid(h));
		if (!hnqn)
			hnqn = xstrdup(libnvme_host_get_hostnqn(h));
	}

	/* /etc/nvme/hostid and/or /etc/nvme/hostnqn */
	if (!hid)
		hid = libnvmf_read_hostid();
	if (!hnqn)
		hnqn = libnvmf_read_hostnqn();

	/* incomplete configuration, thus derive hostid from hostnqn */
	if (!hid && hnqn)
		hid = libnvme_hostid_from_hostnqn(hnqn);

	/*
	 * fallback to use either DMI information or device-tree. If all
	 * fails generate one
	 */
	if (!hid) {
		hid = libnvmf_generate_hostid();
		if (!hid)
			return -ENOMEM;

		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			 "warning: using auto generated hostid and hostnqn\n");
	}

	/* incomplete configuration, thus derive hostnqn from hostid */
	if (!hnqn) {
		hnqn = libnvmf_generate_hostnqn_from_hostid(hid);
		if (!hnqn)
			return -ENOMEM;
	}

	/* sanity checks */
	nqn = libnvme_hostid_from_hostnqn(hnqn);
	if (nqn && strcmp(nqn, hid)) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			 "warning: use hostid '%s' which does not match uuid in hostnqn '%s'\n",
			 hid, hnqn);
	}

	*hostid = hid;
	*hostnqn = hnqn;
	hid = NULL;
	hnqn = NULL;

	return 0;
}

const char * const trtypes[] = {
	[NVMF_TRTYPE_RDMA]	= "rdma",
	[NVMF_TRTYPE_FC]	= "fc",
	[NVMF_TRTYPE_TCP]	= "tcp",
	[NVMF_TRTYPE_LOOP]	= "loop",
};

__libnvme_public const char *libnvmf_trtype_str(__u8 trtype)
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

__libnvme_public const char *libnvmf_adrfam_str(__u8 adrfam)
{
	return arg_str(adrfams, ARRAY_SIZE(adrfams), adrfam);
}

static const char * const subtypes[] = {
	[NVME_NQN_DISC]		= "discovery subsystem referral",
	[NVME_NQN_NVME]		= "nvme subsystem",
	[NVME_NQN_CURR]		= "current discovery subsystem",
};

__libnvme_public const char *libnvmf_subtype_str(__u8 subtype)
{
	return arg_str(subtypes, ARRAY_SIZE(subtypes), subtype);
}

static const char * const treqs[] = {
	[NVMF_TREQ_NOT_SPECIFIED]	= "not specified",
	[NVMF_TREQ_REQUIRED]		= "required",
	[NVMF_TREQ_NOT_REQUIRED]	= "not required",
	[NVMF_TREQ_NOT_SPECIFIED |
	 NVMF_TREQ_DISABLE_SQFLOW]	= "not specified, "
				"sq flow control disable supported",
	[NVMF_TREQ_REQUIRED |
	 NVMF_TREQ_DISABLE_SQFLOW]	= "required, "
				"sq flow control disable supported",
	[NVMF_TREQ_NOT_REQUIRED |
	 NVMF_TREQ_DISABLE_SQFLOW]	= "not required, "
				"sq flow control disable supported",
};

__libnvme_public const char *libnvmf_treq_str(__u8 treq)
{
	return arg_str(treqs, ARRAY_SIZE(treqs), treq);
}

static const char * const eflags_strings[] = {
	[NVMF_DISC_EFLAGS_NONE]		= "none",
	[NVMF_DISC_EFLAGS_EPCSD]	= "explicit discovery connections",
	[NVMF_DISC_EFLAGS_DUPRETINFO]	= "duplicate discovery information",
	[NVMF_DISC_EFLAGS_EPCSD |
	 NVMF_DISC_EFLAGS_DUPRETINFO]	= "explicit discovery connections, "
					  "duplicate discovery information",
	[NVMF_DISC_EFLAGS_NCC]		= "no cdc connectivity",
	[NVMF_DISC_EFLAGS_EPCSD |
	 NVMF_DISC_EFLAGS_NCC]		= "explicit discovery connections, "
					  "no cdc connectivity",
	[NVMF_DISC_EFLAGS_DUPRETINFO |
	 NVMF_DISC_EFLAGS_NCC]		= "duplicate discovery information, "
					  "no cdc connectivity",
	[NVMF_DISC_EFLAGS_EPCSD |
	 NVMF_DISC_EFLAGS_DUPRETINFO |
	 NVMF_DISC_EFLAGS_NCC]		= "explicit discovery connections, "
					  "duplicate discovery information, "
					  "no cdc connectivity",
};

__libnvme_public const char *libnvmf_eflags_str(__u16 eflags)
{
	return arg_str(eflags_strings, ARRAY_SIZE(eflags_strings), eflags);
}

static const char * const sectypes[] = {
	[NVMF_TCP_SECTYPE_NONE]		= "none",
	[NVMF_TCP_SECTYPE_TLS]		= "tls",
	[NVMF_TCP_SECTYPE_TLS13]	= "tls13",
};

__libnvme_public const char *libnvmf_sectype_str(__u8 sectype)
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

__libnvme_public const char *libnvmf_prtype_str(__u8 prtype)
{
	return arg_str(prtypes, ARRAY_SIZE(prtypes), prtype);
}

static const char * const qptypes[] = {
	[NVMF_RDMA_QPTYPE_CONNECTED]	= "connected",
	[NVMF_RDMA_QPTYPE_DATAGRAM]	= "datagram",
};

__libnvme_public const char *libnvmf_qptype_str(__u8 qptype)
{
	return arg_str(qptypes, ARRAY_SIZE(qptypes), qptype);
}

static const char * const cms[] = {
	[NVMF_RDMA_CMS_RDMA_CM]	= "rdma-cm",
};

__libnvme_public const char *libnvmf_cms_str(__u8 cm)
{
	return arg_str(cms, ARRAY_SIZE(cms), cm);
}

void libnvmf_default_config(struct libnvme_fabrics_config *cfg)
{
	cfg->tos = -1;
	cfg->ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO;
}

__libnvme_public int libnvmf_context_create(struct libnvme_global_ctx *ctx,
		bool (*decide_retry)(struct libnvmf_context *fctx, int err,
			void *user_data),
		void (*connected)(struct libnvmf_context *fctx,
			struct libnvme_ctrl *c, void *user_data),
		void (*already_connected)(struct libnvmf_context *fctx,
			struct libnvme_host *host, const char *subsysnqn,
			const char *transport, const char *traddr,
			const char *trsvcid, void *user_data),
		void *user_data, struct libnvmf_context **fctxp)
{
	struct libnvmf_context *fctx;

	fctx = calloc(1, sizeof(*fctx));
	if (!fctx)
		return -ENOMEM;

	fctx->ctx = ctx;

	libnvmf_default_config(&fctx->ctrl_params.cfg);

	fctx->hooks.decide_retry = decide_retry;
	fctx->hooks.connected = connected;
	fctx->hooks.already_connected = already_connected;

	fctx->hooks.user_data = user_data;

	*fctxp = fctx;
	return 0;
}

__libnvme_public void libnvmf_context_free(struct libnvmf_context *fctx)
{
	if (!fctx)
		return;

	free(fctx->tls_key);
	free(fctx);
}

__libnvme_public int libnvmf_context_set_discovery_hooks(
		struct libnvmf_context *fctx,
		void (*discovery_log)(struct libnvmf_context *fctx,
			bool connect,
			struct nvmf_discovery_log *log,
			uint64_t numrec, void *user_data),
		int (*parser_init)(struct libnvmf_context *fctx,
			void *user_data),
		void (*parser_cleanup)(struct libnvmf_context *fctx,
			void *user_data),
		int (*parser_next_line)(struct libnvmf_context *fctx,
			void *user_data))
{
	fctx->hooks.discovery_log = discovery_log;
	fctx->hooks.parser_init = parser_init;
	fctx->hooks.parser_cleanup = parser_cleanup;
	fctx->hooks.parser_next_line = parser_next_line;

	return 0;
}



__libnvme_public int libnvmf_context_set_connection(
		struct libnvmf_context *fctx, const char *subsysnqn,
		const char *transport, const char *traddr, const char *trsvcid,
		const char *host_traddr, const char *host_iface)
{
	fctx->ctrl_params.subsysnqn = subsysnqn;
	fctx->ctrl_params.transport = transport;
	fctx->ctrl_params.traddr = traddr;
	fctx->ctrl_params.trsvcid = trsvcid;
	fctx->ctrl_params.host_traddr = host_traddr;
	fctx->ctrl_params.host_iface = host_iface;

	return 0;
}

static const char *hostid_from_hostnqn(const char *hostnqn)
{
	const char *match;

	if (!hostnqn)
		return NULL;

	match = strstr(hostnqn, "uuid:");
	if (!match)
		return NULL;

	return match + strlen("uuid:");
}

__libnvme_public int libnvmf_context_set_hostnqn(struct libnvmf_context *fctx,
		const char *hostnqn, const char *hostid)
{
	fctx->hostnqn = hostnqn;
	if (!hostid)
		hostid = hostid_from_hostnqn(hostnqn);
	fctx->hostid = hostid;

	return 0;
}

__libnvme_public int libnvmf_context_set_crypto(struct libnvmf_context *fctx,
		const char *hostkey, const char *ctrlkey,
		const char *keyring, const char *tls_key,
		const char *tls_key_identity)
{
	int err;

	fctx->hostkey = hostkey;
	fctx->ctrlkey = ctrlkey;
	fctx->keyring = keyring;
	fctx->tls_key_identity = tls_key_identity;

	if (!tls_key)
		return 0;

	if (!strncmp(tls_key, "pin:", 4)) {
		__cleanup_free unsigned char *raw_secret = NULL;
		__cleanup_free char *encoded_key = NULL;
		int key_len = 32;

		err = libnvmf_create_raw_secret(fctx->ctx, tls_key,
			key_len, &raw_secret);
		if (err)
			return err;

		err = libnvmf_export_tls_key(fctx->ctx, raw_secret,
			key_len, &encoded_key);
		if (err)
			return err;

		fctx->tls_key = encoded_key;
		encoded_key = NULL;
		return 0;
	}

	fctx->tls_key = strdup(tls_key);
	return 0;
}

__libnvme_public int libnvmf_context_set_device(
		struct libnvmf_context *fctx, const char *device)
{
	fctx->device = device;

	return 0;
}

__libnvme_public int libnvmf_context_set_devid_file(
		struct libnvmf_context *fctx, const char *devid_file)
{
	fctx->devid_file = devid_file;

	return 0;
}

/*
 * O_NOFOLLOW guards the one hazard the caller can't see: a symlink at the
 * final path component. O_TRUNC is deliberately absent -- a name recorded
 * by an earlier successful connect must survive a failed one.
 *
 * Return: an open fd, or -errno.
 */
static int open_devid_file(struct libnvmf_context *fctx)
{
	int fd;

	fd = open(fctx->devid_file,
		O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0644);
	if (fd < 0) {
		libnvme_msg(fctx->ctx, LIBNVME_LOG_ERR,
			"failed to open devid-file %s: %s\n",
			fctx->devid_file, libnvme_strerror(errno));
		return -errno;
	}

	return fd;
}

static void write_devid_file(struct libnvmf_context *fctx, int fd,
		libnvme_ctrl_t c)
{
	if (fd < 0 || !c)
		return;

	if (ftruncate(fd, 0) < 0 ||
	    dprintf(fd, "%s\n", libnvme_ctrl_get_name(c)) < 0)
		libnvme_msg(fctx->ctx, LIBNVME_LOG_WARN,
			"failed to write devid-file %s: %s\n",
			fctx->devid_file, libnvme_strerror(errno));
}

__libnvme_public int libnvmf_context_set_io_queues(
		struct libnvmf_context *fctx, int nr_io_queues,
		int nr_write_queues, int nr_poll_queues,
		int queue_size, bool disable_sqflow)
{
	fctx->ctrl_params.cfg.nr_io_queues = nr_io_queues;
	fctx->ctrl_params.cfg.nr_write_queues = nr_write_queues;
	fctx->ctrl_params.cfg.nr_poll_queues = nr_poll_queues;
	fctx->ctrl_params.cfg.queue_size = queue_size;
	fctx->ctrl_params.cfg.disable_sqflow = disable_sqflow;

	return 0;
}

__libnvme_public int libnvmf_context_set_reconnect_policy(
		struct libnvmf_context *fctx, int ctrl_loss_tmo,
		int reconnect_delay, int fast_io_fail_tmo)
{
	fctx->ctrl_params.cfg.ctrl_loss_tmo = ctrl_loss_tmo;
	fctx->ctrl_params.cfg.reconnect_delay = reconnect_delay;
	fctx->ctrl_params.cfg.fast_io_fail_tmo = fast_io_fail_tmo;

	return 0;
}

/*
 * Derived from Linux's supported options (the opt_tokens table)
 * when the mechanism to report supported options was added (f18ee3d988157).
 * Not all of these options may actually be supported,
 * but we retain the old behavior of passing all that might be.
 */
static const struct libnvme_fabric_options default_supported_options = {
	.ctrl_loss_tmo = true,
	.data_digest = true,
	.disable_sqflow = true,
	.discovery = true,
	.duplicate_connect = true,
	.fast_io_fail_tmo = true,
	.hdr_digest = true,
	.host_iface = true,
	.host_traddr = true,
	.hostid = true,
	.hostnqn = true,
	.keep_alive_tmo = true,
	.nqn = true,
	.nr_io_queues = true,
	.nr_poll_queues = true,
	.nr_write_queues = true,
	.queue_size = true,
	.reconnect_delay = true,
	.tos = true,
	.traddr = true,
	.transport = true,
	.trsvcid = true,
};

#define MERGE_CFG_OPTION(c, n, o, d)			\
	if ((c)->o == d) (c)->o = (n)->o
static void merge_config(libnvme_ctrl_t c,
		const struct libnvme_fabrics_config *cfg)
{
	MERGE_CFG_OPTION(&c->cfg, cfg, nr_io_queues, 0);
	MERGE_CFG_OPTION(&c->cfg, cfg, nr_write_queues, 0);
	MERGE_CFG_OPTION(&c->cfg, cfg, nr_poll_queues, 0);
	MERGE_CFG_OPTION(&c->cfg, cfg, queue_size, 0);
	MERGE_CFG_OPTION(&c->cfg, cfg, keep_alive_tmo, 0);
	MERGE_CFG_OPTION(&c->cfg, cfg, reconnect_delay, 0);
	MERGE_CFG_OPTION(&c->cfg, cfg, ctrl_loss_tmo,
			  NVMF_DEF_CTRL_LOSS_TMO);
	MERGE_CFG_OPTION(&c->cfg, cfg, fast_io_fail_tmo, 0);
	MERGE_CFG_OPTION(&c->cfg, cfg, tos, -1);
	MERGE_CFG_OPTION(&c->cfg, cfg, keyring_id, 0);
	MERGE_CFG_OPTION(&c->cfg, cfg, tls_key_id, 0);
	MERGE_CFG_OPTION(&c->cfg, cfg, tls_configured_key_id, 0);
	MERGE_CFG_OPTION(&c->cfg, cfg, duplicate_connect, false);
	MERGE_CFG_OPTION(&c->cfg, cfg, disable_sqflow, false);
	MERGE_CFG_OPTION(&c->cfg, cfg, hdr_digest, false);
	MERGE_CFG_OPTION(&c->cfg, cfg, data_digest, false);
	MERGE_CFG_OPTION(&c->cfg, cfg, tls, false);
	MERGE_CFG_OPTION(&c->cfg, cfg, concat, false);
}

#define UPDATE_CFG_OPTION(c, n, o, d)			\
	if ((n)->o != d) (c)->o = (n)->o
static void update_config(libnvme_ctrl_t c,
		const struct libnvme_fabrics_config *cfg)
{
	UPDATE_CFG_OPTION(&c->cfg, cfg, nr_io_queues, 0);
	UPDATE_CFG_OPTION(&c->cfg, cfg, nr_write_queues, 0);
	UPDATE_CFG_OPTION(&c->cfg, cfg, nr_poll_queues, 0);
	UPDATE_CFG_OPTION(&c->cfg, cfg, queue_size, 0);
	UPDATE_CFG_OPTION(&c->cfg, cfg, keep_alive_tmo, 0);
	UPDATE_CFG_OPTION(&c->cfg, cfg, reconnect_delay, 0);
	UPDATE_CFG_OPTION(&c->cfg, cfg, ctrl_loss_tmo,
			  NVMF_DEF_CTRL_LOSS_TMO);
	UPDATE_CFG_OPTION(&c->cfg, cfg, fast_io_fail_tmo, 0);
	UPDATE_CFG_OPTION(&c->cfg, cfg, tos, -1);
	UPDATE_CFG_OPTION(&c->cfg, cfg, keyring_id, 0);
	UPDATE_CFG_OPTION(&c->cfg, cfg, tls_key_id, 0);
	UPDATE_CFG_OPTION(&c->cfg, cfg, tls_configured_key_id, 0);
	UPDATE_CFG_OPTION(&c->cfg, cfg, duplicate_connect, false);
	UPDATE_CFG_OPTION(&c->cfg, cfg, disable_sqflow, false);
	UPDATE_CFG_OPTION(&c->cfg, cfg, hdr_digest, false);
	UPDATE_CFG_OPTION(&c->cfg, cfg, data_digest, false);
	UPDATE_CFG_OPTION(&c->cfg, cfg, tls, false);
	UPDATE_CFG_OPTION(&c->cfg, cfg, concat, false);
}

static int __add_bool_argument(char **argstr, char *tok, bool arg)
{
	char *nstr;

	if (!arg)
		return 0;
	if (asprintf(&nstr, "%s,%s", *argstr, tok) < 0) {
		return -ENOMEM;
	}
	free(*argstr);
	*argstr = nstr;

	return 0;
}

static int __add_hex_argument(char **argstr, char *tok, int arg, bool allow_zero)
{
	char *nstr;

	if (arg < 0 || (!arg && !allow_zero))
		return 0;
	if (asprintf(&nstr, "%s,%s=0x%08x", *argstr, tok, arg) < 0) {
		return -ENOMEM;
	}
	free(*argstr);
	*argstr = nstr;

	return 0;
}

static int __add_int_argument(char **argstr, char *tok, int arg, bool allow_zero)
{
	char *nstr;

	if (arg < 0 || (!arg && !allow_zero))
		return 0;
	if (asprintf(&nstr, "%s,%s=%d", *argstr, tok, arg) < 0) {
		return -ENOMEM;
	}
	free(*argstr);
	*argstr = nstr;

	return 0;
}

static int __add_int_or_minus_one_argument(char **argstr, char *tok, int arg)
{
	char *nstr;

	if (arg < -1)
		return 0;
	if (asprintf(&nstr, "%s,%s=%d", *argstr, tok, arg) < 0) {
		return -ENOMEM;
	}
	free(*argstr);
	*argstr = nstr;

	return 0;
}

static int __add_argument(char **argstr, const char *tok, const char *arg)
{
	char *nstr;

	if (!arg || arg[0] == '\0' || !strcmp(arg, "none"))
		return 0;
	if (asprintf(&nstr, "%s,%s=%s", *argstr, tok, arg) < 0) {
		return -ENOMEM;
	}
	free(*argstr);
	*argstr = nstr;

	return 0;
}

static int __nvmf_supported_options(struct libnvme_global_ctx *ctx);
#define nvmf_check_option(ctx, tok)					\
({									\
	!__nvmf_supported_options(ctx) && ctx->options->tok;		\
})

#define add_bool_argument(ctx, argstr, tok, arg)			\
({									\
	int ret;							\
	if (nvmf_check_option(ctx, tok)) {				\
		ret = __add_bool_argument(argstr,			\
					  stringify(tok),		\
					  arg);				\
	} else {							\
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,				\
			 "option \"%s\" ignored\n",			\
			 stringify(tok));				\
		ret = 0;						\
	}								\
	ret;								\
})

#define add_hex_argument(ctx, argstr, tok, arg, allow_zero)		\
({									\
	int ret;							\
	if (nvmf_check_option(ctx, tok)) {				\
		ret = __add_hex_argument(argstr,			\
					stringify(tok),			\
					arg,				\
					allow_zero);			\
	} else {							\
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,				\
			 "option \"%s\" ignored\n",			\
			 stringify(tok));				\
		ret = 0;						\
	}								\
	ret;								\
})

#define add_int_argument(ctx, argstr, tok, arg, allow_zero)		\
({									\
	int ret;							\
	if (nvmf_check_option(ctx, tok)) {				\
		ret = __add_int_argument(argstr,			\
					stringify(tok),			\
					arg,				\
					allow_zero);			\
	} else {							\
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,				\
			 "option \"%s\" ignored\n",			\
			 stringify(tok));				\
		ret = 0;						\
	}								\
	ret;								\
})

#define add_int_or_minus_one_argument(ctx, argstr, tok, arg)		\
({									\
	int ret;							\
	if (nvmf_check_option(ctx, tok)) {				\
		ret = __add_int_or_minus_one_argument(argstr,		\
						     stringify(tok),	\
						     arg);		\
	} else {							\
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,				\
			 "option \"%s\" ignored\n",			\
			 stringify(tok));				\
		ret = 0;						\
	}								\
	ret;								\
})

#define add_argument(ctx, argstr, tok, arg)				\
({									\
	int ret;							\
	if (nvmf_check_option(ctx, tok)) {				\
		ret = __add_argument(argstr,				\
				     stringify(tok),			\
				     arg);				\
	} else {							\
		libnvme_msg(ctx, LIBNVME_LOG_WARN,				\
			 "option \"%s\" ignored\n",			\
			 stringify(tok));				\
		ret = 0;						\
	}								\
	ret;								\
})

static int inet4_pton(const char *src, uint16_t port,
		      struct sockaddr_storage *addr)
{
	struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;

	if (strlen(src) > INET_ADDRSTRLEN)
		return -EINVAL;

	if (inet_pton(AF_INET, src, &addr4->sin_addr.s_addr) <= 0)
		return -EINVAL;

	addr4->sin_family = AF_INET;
	addr4->sin_port = htons(port);

	return 0;
}

static int inet6_pton(struct libnvme_global_ctx *ctx, const char *src, uint16_t port,
		      struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
	const char *scope = NULL;
	char *p;

	if (strlen(src) > INET6_ADDRSTRLEN)
		return -EINVAL;

	__cleanup_free char *tmp = strdup(src);
	if (!tmp) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "cannot copy: %s\n", src);
		return -ENOMEM;
	}

	p = strchr(tmp, '%');
	if (p) {
		*p = '\0';
		scope = src + (p - tmp) + 1;
	}

	if (inet_pton(AF_INET6, tmp, &addr6->sin6_addr) != 1)
		return -EINVAL;

	if (IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr) && scope) {
		addr6->sin6_scope_id = if_nametoindex(scope);
		if (addr6->sin6_scope_id == 0) {
			libnvme_msg(ctx, LIBNVME_LOG_ERR,
				 "can't find iface index for: %s (%m)\n", scope);
			return -EINVAL;
		}
	}

	addr6->sin6_family = AF_INET6;
	addr6->sin6_port = htons(port);
	return 0;
}

/**
 * inet_pton_with_scope - convert an IPv4/IPv6 to socket address
 * @ctx: Global context
 * @af: address family, AF_INET, AF_INET6 or AF_UNSPEC for either
 * @src: the start of the address string
 * @trsvcid: transport service identifier
 * @addr: output socket address
 *
 * Return 0 on success, errno otherwise.
 */
static int inet_pton_with_scope(struct libnvme_global_ctx *ctx, int af,
				const char *src, const char * trsvcid,
				struct sockaddr_storage *addr)
{
	int      ret  = -EINVAL;
	uint16_t port = 0;

	if (trsvcid) {
		unsigned long long tmp = strtoull(trsvcid, NULL, 0);
		port = (uint16_t)tmp;
		if (tmp != port) {
			libnvme_msg(ctx, LIBNVME_LOG_ERR, "trsvcid out of range: %s\n",
				 trsvcid);
			return -ERANGE;
		}
	} else {
		port = 0;
	}

	switch (af) {
	case AF_INET:
		ret = inet4_pton(src, port, addr);
		break;
	case AF_INET6:
		ret = inet6_pton(ctx, src, port, addr);
		break;
	case AF_UNSPEC:
		ret = inet4_pton(src, port, addr);
		if (ret)
			ret = inet6_pton(ctx, src, port, addr);
		break;
	default:
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "unexpected address family %d\n", af);
	}

	return ret;
}

bool traddr_is_hostname(struct libnvme_global_ctx *ctx,
		const char *transport, const char *traddr)
{
	if (!traddr || !transport)
		return false;
	if (!strcmp(traddr, "none"))
		return false;
	if (strcmp(transport, "tcp") && strcmp(transport, "rdma"))
		return false;

	return !libnvmf_traddr_is_numeric(traddr);
}

/*
 * Reject a hostname traddr/host_traddr and canonicalize a numeric one,
 * routing the check through the TID constructor so the tree keeps one
 * definition of acceptable and canonical addressing.  Resolving a
 * hostname is the caller's job, not libnvme's, so the connect paths
 * simply refuse one instead of resolving it.
 */
static int nvmf_sanitize_addrs(struct libnvme_global_ctx *ctx, libnvme_ctrl_t c)
{
	struct libnvmf_tid *tid;
	const char *canon;
	char *dup;

	if (traddr_is_hostname(ctx, c->transport, c->traddr)) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			"traddr '%s' is not a numeric address; hostname resolution is the caller's responsibility\n",
			c->traddr);
		return -ENVME_CONNECT_TRADDR;
	}

	if (traddr_is_hostname(ctx, c->transport, c->host_traddr)) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			"host-traddr '%s' is not a numeric address; hostname resolution is the caller's responsibility\n",
			c->host_traddr);
		return -ENVME_CONNECT_TRADDR;
	}

	tid = libnvmf_tid_from_fields(c->transport, c->traddr, c->trsvcid,
			NULL, c->host_traddr, c->host_iface, NULL, NULL);
	if (!tid)
		return -ENOMEM;

	canon = libnvmf_tid_get_traddr(tid);
	if (canon) {
		dup = strdup(canon);
		if (!dup) {
			libnvmf_tid_free(tid);
			return -ENOMEM;
		}
		free(c->traddr);
		c->traddr = dup;
	}

	canon = libnvmf_tid_get_host_traddr(tid);
	if (canon) {
		dup = strdup(canon);
		if (!dup) {
			libnvmf_tid_free(tid);
			return -ENOMEM;
		}
		free(c->host_traddr);
		c->host_traddr = dup;
	}

	libnvmf_tid_free(tid);

	return 0;
}

static int build_options(libnvme_host_t h, libnvme_ctrl_t c, char **argstr)
{
	const char *transport = libnvme_ctrl_get_transport(c);
	const char *hostnqn, *hostid, *hostkey, *ctrlkey = NULL;
	bool discover = false, discovery_nqn = false;
	struct libnvme_global_ctx *ctx = h->ctx;
	long keyring_id = 0;
	long key_id = 0;
	int ret;

	if (!transport) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "need a transport (-t) argument\n");
		return -ENVME_CONNECT_TARG;
	}

	if (strncmp(transport, "loop", 4)) {
		if (!libnvme_ctrl_get_traddr(c)) {
			libnvme_msg(h->ctx, LIBNVME_LOG_ERR, "need a address (-a) argument\n");
			return -ENVME_CONNECT_AARG;
		}
	}

	/* always specify nqn as first arg - this will init the string */
	if (asprintf(argstr, "nqn=%s",
		     libnvme_ctrl_get_subsysnqn(c)) < 0) {
		return -ENOMEM;
	}

	if (!strcmp(libnvme_ctrl_get_subsysnqn(c), NVME_DISC_SUBSYS_NAME)) {
		libnvme_ctrl_set_discovery_ctrl(c, true);
		libnvme_ctrl_set_unique_discovery_ctrl(c, false);
		discovery_nqn = true;
	}

	if (libnvme_ctrl_get_discovery_ctrl(c))
		discover = true;

	hostnqn = libnvme_host_get_hostnqn(h);
	hostid = libnvme_host_get_hostid(h);
	hostkey = libnvme_host_get_dhchap_host_key(h);
	if (!hostkey)
		hostkey = libnvme_ctrl_get_dhchap_host_key(c);

	if (hostkey)
		ctrlkey = libnvme_ctrl_get_dhchap_ctrl_key(c);

	if (c->cfg.tls && c->cfg.concat) {
		libnvme_msg(h->ctx, LIBNVME_LOG_ERR, "cannot specify --tls and --concat together\n");
		return -ENVME_CONNECT_INVAL;
	}

	if (c->cfg.concat && !hostkey) {
		libnvme_msg(h->ctx, LIBNVME_LOG_ERR, "required argument [--dhchap-secret | -S] not specified with --concat\n");
		return -ENVME_CONNECT_INVAL;
	}

	if (c->cfg.tls) {
		ret = __libnvmf_import_keys_from_config(h, c,
			&keyring_id, &key_id);
		if (ret)
			return ret;

		if (key_id == 0) {
			if (c->cfg.tls_configured_key_id)
				key_id = c->cfg.tls_configured_key_id;
			else
				key_id = c->cfg.tls_key_id;
		}
	}

	if (add_argument(ctx, argstr, transport, transport) ||
	    add_argument(ctx, argstr, traddr,
			 libnvme_ctrl_get_traddr(c)) ||
	    add_argument(ctx, argstr, host_traddr,
			 libnvme_ctrl_get_host_traddr(c)) ||
	    add_argument(ctx, argstr, host_iface,
			 libnvme_ctrl_get_host_iface(c)) ||
	    add_argument(ctx, argstr, trsvcid,
			 libnvme_ctrl_get_trsvcid(c)) ||
	    (hostnqn && add_argument(ctx, argstr, hostnqn, hostnqn)) ||
	    (hostid && add_argument(ctx, argstr, hostid, hostid)) ||
	    (discover && !discovery_nqn &&
	     add_bool_argument(ctx, argstr, discovery, true)) ||
	    (hostkey &&
	     add_argument(ctx, argstr, dhchap_secret, hostkey)) ||
	    (ctrlkey &&
	     add_argument(ctx, argstr, dhchap_ctrl_secret, ctrlkey)) ||
	    (!discover &&
	     add_int_argument(ctx, argstr, nr_io_queues,
			      c->cfg.nr_io_queues, false)) ||
	    (!discover &&
	     add_int_argument(ctx, argstr, nr_write_queues,
			      c->cfg.nr_write_queues, false)) ||
	    (!discover &&
	     add_int_argument(ctx, argstr, nr_poll_queues,
			      c->cfg.nr_poll_queues, false)) ||
	    (!discover &&
	     add_int_argument(ctx, argstr, queue_size,
			      c->cfg.queue_size, false)) ||
	    add_int_argument(ctx, argstr, keep_alive_tmo,
			     c->cfg.keep_alive_tmo, false) ||
	    add_int_argument(ctx, argstr, reconnect_delay,
			     c->cfg.reconnect_delay, false) ||
	    (strcmp(transport, "loop") &&
	     add_int_or_minus_one_argument(ctx, argstr, ctrl_loss_tmo,
			      c->cfg.ctrl_loss_tmo)) ||
	    (strcmp(transport, "loop") &&
	     add_int_argument(ctx, argstr, fast_io_fail_tmo,
			      c->cfg.fast_io_fail_tmo, false)) ||
	    (strcmp(transport, "loop") &&
	     add_int_argument(ctx, argstr, tos, c->cfg.tos, true)) ||
	    add_hex_argument(ctx, argstr, keyring, keyring_id, false) ||
	    (!strcmp(transport, "tcp") &&
	     add_hex_argument(ctx, argstr, tls_key, key_id, false)) ||
	    add_bool_argument(ctx, argstr, duplicate_connect,
			      c->cfg.duplicate_connect) ||
	    add_bool_argument(ctx, argstr, disable_sqflow,
			      c->cfg.disable_sqflow) ||
	    (!strcmp(transport, "tcp") &&
	     add_bool_argument(ctx, argstr, hdr_digest, c->cfg.hdr_digest)) ||
	    (!strcmp(transport, "tcp") &&
	     add_bool_argument(ctx, argstr, data_digest, c->cfg.data_digest)) ||
	    (!strcmp(transport, "tcp") &&
	     add_bool_argument(ctx, argstr, tls, c->cfg.tls)) ||
	    (!strcmp(transport, "tcp") &&
	     add_bool_argument(ctx, argstr, concat, c->cfg.concat))) {
		free(*argstr);
		return -1;
	}

	return 0;
}

#define parse_option(ctx, v, name)	   		\
	if (!strcmp(v, stringify(name))) {	 	\
		ctx->options->name = true;		\
		continue;		   		\
	}

static int __nvmf_supported_options(struct libnvme_global_ctx *ctx)
{
	char buf[0x1000], *options, *p, *v;
	__cleanup_fd int fd = -1;
	ssize_t len;

	if (ctx->options)
		return 0;

	ctx->options = calloc(1, sizeof(*ctx->options));
	if (!ctx->options)
		return -ENOMEM;

	fd = open(nvmf_dev, O_RDONLY);
	if (fd < 0) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "Failed to open %s: %s\n",
			 nvmf_dev, libnvme_strerror(errno));
		return -ENVME_CONNECT_OPEN;
	}

	memset(buf, 0x0, sizeof(buf));
	len = read(fd, buf, sizeof(buf) - 1);
	if (len < 0) {
		if (errno == EINVAL) {
			/*
			 * Older Linux kernels don't allow reading from nvmf_dev
			 * to get supported options, so use a default set
			 */
			libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			         "Cannot read %s, using default options\n",
			         nvmf_dev);
			*ctx->options = default_supported_options;
			return 0;
		}

		libnvme_msg(ctx, LIBNVME_LOG_ERR, "Failed to read from %s: %s\n",
			 nvmf_dev, libnvme_strerror(errno));
		return -ENVME_CONNECT_READ;
	}

	buf[len] = '\0';
	options = buf;

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "kernel supports: ");

	while ((p = strsep(&options, ",\n")) != NULL) {
		if (!*p)
			continue;
		v = strsep(&p, "= ");
		if (!v)
			continue;
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "%s ", v);

		parse_option(ctx, v, cntlid);
		parse_option(ctx, v, concat);
		parse_option(ctx, v, ctrl_loss_tmo);
		parse_option(ctx, v, data_digest);
		parse_option(ctx, v, dhchap_ctrl_secret);
		parse_option(ctx, v, dhchap_secret);
		parse_option(ctx, v, disable_sqflow);
		parse_option(ctx, v, discovery);
		parse_option(ctx, v, duplicate_connect);
		parse_option(ctx, v, fast_io_fail_tmo);
		parse_option(ctx, v, hdr_digest);
		parse_option(ctx, v, host_iface);
		parse_option(ctx, v, host_traddr);
		parse_option(ctx, v, hostid);
		parse_option(ctx, v, hostnqn);
		parse_option(ctx, v, instance);
		parse_option(ctx, v, keep_alive_tmo);
		parse_option(ctx, v, keyring);
		parse_option(ctx, v, nqn);
		parse_option(ctx, v, nr_io_queues);
		parse_option(ctx, v, nr_poll_queues);
		parse_option(ctx, v, nr_write_queues);
		parse_option(ctx, v, queue_size);
		parse_option(ctx, v, reconnect_delay);
		parse_option(ctx, v, tls);
		parse_option(ctx, v, tls_key);
		parse_option(ctx, v, tos);
		parse_option(ctx, v, traddr);
		parse_option(ctx, v, transport);
		parse_option(ctx, v, trsvcid);
	}
	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "\n");
	return 0;
}

/*
 * Best-effort registry update after a successful connect: record ownership
 * when an owner is set, otherwise clear any stale entry for a recycled
 * instance.  Failures are logged but never fail the connection.
 */
static void registry_update_on_connect(struct libnvme_global_ctx *ctx,
				       int instance)
{
	int ret;

	if (ctx->owner)
		ret = libnvmf_registry_create_instance(ctx, instance,
						       ctx->owner);
	else
		ret = libnvmf_registry_delete_instance(ctx, instance);
	if (ret)
		libnvme_msg(ctx, LIBNVME_LOG_WARN,
			    "nvme%d: registry update failed: %s\n",
			    instance, libnvme_strerror(-ret));
}

static int __nvmf_add_ctrl(struct libnvme_global_ctx *ctx, const char *argstr)
{
	__cleanup_fd int fd = -1;
	int ret, len = strlen(argstr);
	int instance;
	char buf[0x1000], *options, *p;

	fd = open(nvmf_dev, O_RDWR);
	if (fd < 0) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "Failed to open %s: %s\n",
			 nvmf_dev, libnvme_strerror(errno));
		return -ENVME_CONNECT_OPEN;
	}

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "connect ctrl, '%.*s'\n",
		 (int)strcspn(argstr,"\n"), argstr);
	ret = write(fd, argstr, len);
	if (ret != len) {
		libnvme_msg(ctx, LIBNVME_LOG_INFO, "Failed to write to %s: %s\n",
			 nvmf_dev, libnvme_strerror(errno));
		switch (errno) {
		case EALREADY:
			return -ENVME_CONNECT_ALREADY;
		case EINVAL:
			return -ENVME_CONNECT_INVAL;
		case EADDRINUSE:
			return -ENVME_CONNECT_ADDRINUSE;
		case ENODEV:
			return -ENVME_CONNECT_NODEV;
		case EOPNOTSUPP:
			return -ENVME_CONNECT_OPNOTSUPP;
		case ECONNREFUSED:
			return -ENVME_CONNECT_CONNREFUSED;
		case EADDRNOTAVAIL:
			return -ENVME_CONNECT_ADDRNOTAVAIL;
		case ENOKEY:
			return -ENVME_CONNECT_NOKEY;
		default:
			return -ENVME_CONNECT_WRITE;
		}
	}

	memset(buf, 0x0, sizeof(buf));
	len = read(fd, buf, sizeof(buf) - 1);
	if (len < 0) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "Failed to read from %s: %s\n",
			 nvmf_dev, libnvme_strerror(errno));
		return -ENVME_CONNECT_READ;
	}
	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "connect ctrl, response '%.*s'\n",
		 (int)strcspn(buf, "\n"), buf);
	buf[len] = '\0';
	options = buf;
	while ((p = strsep(&options, ",\n")) != NULL) {
		if (!*p)
			continue;
		if (sscanf(p, "instance=%d", &instance) == 1) {
			registry_update_on_connect(ctx, instance);
			return instance;
		}
	}

	libnvme_msg(ctx, LIBNVME_LOG_ERR, "Failed to parse ctrl info for \"%s\"\n", argstr);
	return -ENVME_CONNECT_PARSE;
}


__libnvme_public int libnvmf_create_ctrl(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, libnvme_ctrl_t *cp)
{
	return libnvme_create_ctrl(ctx, &fctx->ctrl_params, cp);
}

__libnvme_public int libnvmf_add_ctrl(libnvme_host_t h, libnvme_ctrl_t c)
{
	libnvme_subsystem_t s;
	__cleanup_free char *argstr = NULL;
	int ret;

	/* Are duplicate connections allowed on existing controller */
	if (libnvme_ctrl_get_name(c) && !c->cfg.duplicate_connect)
		return -ENVME_CONNECT_ALREADY;

	/* apply configuration from config file (JSON) */
	s = libnvme_lookup_subsystem(h, NULL, libnvme_ctrl_get_subsysnqn(c));
	if (s) {
		libnvme_ctrl_t fc;
		struct libnvmf_context fctx = {
			.ctrl_params = {
				.transport = libnvme_ctrl_get_transport(c),
				.traddr = libnvme_ctrl_get_traddr(c),
				.host_traddr = libnvme_ctrl_get_host_traddr(c),
				.host_iface = libnvme_ctrl_get_host_iface(c),
				.trsvcid = libnvme_ctrl_get_trsvcid(c),
			},
		};

		fc = libnvmf_ctrl_find(s, &fctx);
		if (fc) {
			const char *key;

			merge_config(c, &fc->cfg);
			/*
			 * An authentication key might already been set
			 * in @cfg, so ensure to update @c with the correct
			 * controller key.
			 */
			key = libnvme_ctrl_get_dhchap_host_key(fc);
			if (key)
				libnvme_ctrl_set_dhchap_host_key(c, key);
			key = libnvme_ctrl_get_dhchap_ctrl_key(fc);
			if (key)
				libnvme_ctrl_set_dhchap_ctrl_key(c, key);
			key = libnvme_ctrl_get_keyring(fc);
			if (key)
				libnvme_ctrl_set_keyring(c, key);
			key = libnvme_ctrl_get_tls_key_identity(fc);
			if (key)
				libnvme_ctrl_set_tls_key_identity(c, key);
			key = libnvme_ctrl_get_tls_key(fc);
			if (key)
				libnvme_ctrl_set_tls_key(c, key);
		}

	}

	libnvme_ctrl_set_discovered(c, true);
	ret = nvmf_sanitize_addrs(h->ctx, c);
	if (ret)
		return ret;

	ret = build_options(h, c, &argstr);
	if (ret)
		return ret;

	ret = __nvmf_add_ctrl(h->ctx, argstr);
	if (ret < 0)
		return ret;

	libnvme_msg(h->ctx, LIBNVME_LOG_INFO, "nvme%d: %s connected\n", ret,
		 libnvme_ctrl_get_subsysnqn(c));
	return libnvme_init_ctrl(h, c, ret);
}

__libnvme_public int libnvmf_connect_ctrl(libnvme_ctrl_t c)
{
	__cleanup_free char *argstr = NULL;
	int ret;

	ret = nvmf_sanitize_addrs(c->s->h->ctx, c);
	if (ret)
		return ret;

	ret = build_options(c->s->h, c, &argstr);
	if (ret)
		return ret;

	ret = __nvmf_add_ctrl(c->s->h->ctx, argstr);
	if (ret < 0)
		return ret;

	return 0;
}

__libnvme_public int libnvmf_disconnect_ctrl(libnvme_ctrl_t c)
{
	struct libnvme_global_ctx *ctx = c->s && c->s->h ? c->s->h->ctx : NULL;
	int ret;

	ret = libnvme_set_attr(libnvme_ctrl_get_sysfs_dir(c),
			    "delete_controller", "1");
	if (ret < 0) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			"%s: failed to disconnect, error %d\n", c->name, errno);
		return ret;
	}
	libnvme_msg(ctx, LIBNVME_LOG_INFO, "%s: %s disconnected\n",
		c->name, c->subsysnqn);
	nvme_deconfigure_ctrl(c);
	return 0;
}

static void nvmf_update_tls_concat(struct nvmf_disc_log_entry *e,
		libnvme_ctrl_t c, libnvme_host_t h)
{
	if (!e)
		return;

	if (e->trtype != NVMF_TRTYPE_TCP ||
	    e->tsas.tcp.sectype == NVMF_TCP_SECTYPE_NONE)
		return;

	if (e->treq & NVMF_TREQ_REQUIRED) {
		libnvme_msg(h->ctx, LIBNVME_LOG_DEBUG,
			"setting --tls due to treq %s and sectype %s\n",
			libnvmf_treq_str(e->treq),
			libnvmf_sectype_str(e->tsas.tcp.sectype));

		c->cfg.tls = true;
		return;
	}

	if (e->treq & NVMF_TREQ_NOT_REQUIRED) {
		libnvme_msg(h->ctx, LIBNVME_LOG_DEBUG,
			"setting --concat due to treq %s and sectype %s\n",
			libnvmf_treq_str(e->treq),
			libnvmf_sectype_str(e->tsas.tcp.sectype));

		c->cfg.concat = true;
		return;
	}
}

/*
 * Enumerated-connect gate: consult the exclusion list before connecting a
 * controller that was enumerated from a Discovery Log Page, the NBFT table,
 * or a configuration file.  Controllers named explicitly by the user
 * ("nvme connect", "nvme discover" with an address) are deliberately not
 * checked -- a targeted human action overrides the list.
 */
static bool nvmf_excluded(struct libnvme_global_ctx *ctx,
			  const char *transport, const char *traddr,
			  const char *trsvcid, const char *subsysnqn,
			  const char *host_traddr, const char *host_iface,
			  const char *hostnqn, const char *hostid)
{
	struct libnvmf_tid *tid;
	bool excluded;

	tid = libnvmf_tid_from_fields(transport, traddr, trsvcid, subsysnqn,
				      host_traddr, host_iface, hostnqn,
				      hostid);
	if (!tid)
		return false; /* fail-safe: never block on allocation failure */

	excluded = libnvmf_exclusion_match(ctx, tid);
	if (excluded) {
		const char *rendered = libnvmf_tid_str(tid);
		libnvme_msg(ctx, LIBNVME_LOG_INFO,
			 "skipping excluded controller %s\n",
			 rendered ? rendered : subsysnqn);
	}
	libnvmf_tid_free(tid);

	return excluded;
}

static bool nvmf_ctrl_excluded(struct libnvme_global_ctx *ctx,
			       struct libnvme_host *h, struct libnvme_ctrl *c)
{
	return nvmf_excluded(ctx, c->transport, c->traddr, c->trsvcid,
			     c->subsysnqn, c->host_traddr, c->host_iface,
			     libnvme_host_get_hostnqn(h),
			     libnvme_host_get_hostid(h));
}

static int nvmf_connect_disc_entry(libnvme_host_t h,
		struct nvmf_disc_log_entry *e,
		struct libnvmf_context *fctx,
		bool *discover, libnvme_ctrl_t *cp)
{
	libnvme_ctrl_t c;
	int ret;

	switch (e->trtype) {
	case NVMF_TRTYPE_RDMA:
	case NVMF_TRTYPE_TCP:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_IP4:
		case NVMF_ADDR_FAMILY_IP6:
			fctx->ctrl_params.traddr = e->traddr;
			fctx->ctrl_params.trsvcid = e->trsvcid;
			break;
		default:
			libnvme_msg(h->ctx, LIBNVME_LOG_ERR,
				 "skipping unsupported adrfam %d\n",
				 e->adrfam);
			return -EINVAL;
		}
		break;
        case NVMF_TRTYPE_FC:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_FC:
			fctx->ctrl_params.traddr = e->traddr;
			break;
		default:
			libnvme_msg(h->ctx, LIBNVME_LOG_ERR,
				 "skipping unsupported adrfam %d\n",
				 e->adrfam);
			return -EINVAL;
		}
		break;
	case NVMF_TRTYPE_LOOP:
		fctx->ctrl_params.traddr = strlen(e->traddr) ? e->traddr : NULL;
		break;
	default:
		libnvme_msg(h->ctx, LIBNVME_LOG_ERR, "skipping unsupported transport %d\n",
			 e->trtype);
		return -EINVAL;
	}

	fctx->ctrl_params.transport = libnvmf_trtype_str(e->trtype);
	fctx->ctrl_params.subsysnqn = e->subnqn;

	libnvme_msg(h->ctx, LIBNVME_LOG_DEBUG,
		 "lookup ctrl (transport: %s, traddr: %s, trsvcid %s)\n",
		 fctx->ctrl_params.transport, fctx->ctrl_params.traddr,
		 fctx->ctrl_params.trsvcid);

	if (nvmf_excluded(h->ctx, fctx->ctrl_params.transport,
			  fctx->ctrl_params.traddr, fctx->ctrl_params.trsvcid,
			  fctx->ctrl_params.subsysnqn,
			  fctx->ctrl_params.host_traddr,
			  fctx->ctrl_params.host_iface,
			  libnvme_host_get_hostnqn(h),
			  libnvme_host_get_hostid(h)))
		return -EPERM;

	ret = libnvme_create_ctrl(h->ctx, &fctx->ctrl_params, &c);
	if (ret) {
		libnvme_msg(h->ctx, LIBNVME_LOG_DEBUG, "skipping discovery entry, "
			 "failed to allocate %s controller with traddr %s\n",
			 fctx->ctrl_params.transport, fctx->ctrl_params.traddr);
		return ret;
	}

	switch (e->subtype) {
	case NVME_NQN_CURR:
		libnvme_ctrl_set_discovered(c, true);
		libnvme_ctrl_set_unique_discovery_ctrl(c,
				strcmp(e->subnqn, NVME_DISC_SUBSYS_NAME));
		break;
	case NVME_NQN_DISC:
		if (discover)
			*discover = true;
		libnvme_ctrl_set_discovery_ctrl(c, true);
		libnvme_ctrl_set_unique_discovery_ctrl(c,
				strcmp(e->subnqn, NVME_DISC_SUBSYS_NAME));
		break;
	default:
		libnvme_msg(h->ctx, LIBNVME_LOG_ERR, "unsupported subtype %d\n",
			 e->subtype);
		fallthrough;
	case NVME_NQN_NVME:
		libnvme_ctrl_set_discovery_ctrl(c, false);
		libnvme_ctrl_set_unique_discovery_ctrl(c, false);
		break;
	}

	if (libnvme_ctrl_get_discovered(c)) {
		libnvme_free_ctrl(c);
		return -EAGAIN;
	}

	if (e->treq & NVMF_TREQ_DISABLE_SQFLOW &&
	    nvmf_check_option(h->ctx, disable_sqflow))
		c->cfg.disable_sqflow = true;

	/* update tls or concat */
	nvmf_update_tls_concat(e, c, h);

	ret = libnvmf_add_ctrl(h, c);
	if (!ret) {
		*cp = c;
		return 0;
	}

	if (ret == EINVAL && c->cfg.disable_sqflow) {
		/* disable_sqflow is unrecognized option on older kernels */
		libnvme_msg(h->ctx, LIBNVME_LOG_INFO, "failed to connect controller, "
			 "retry with disabling SQ flow control\n");
		c->cfg.disable_sqflow = false;
		ret = libnvmf_add_ctrl(h, c);
		if (!ret) {
			*cp = c;
			return 0;
		}
	}
	libnvme_free_ctrl(c);
	return -ENOENT;
}

/*
 * Most of nvmf_discovery_log is reserved, so only fetch the initial bytes.
 * 8 bytes for GENCTR, 8 for NUMREC, and 2 for RECFMT.
 * Since only multiples of 4 bytes are allowed, round 18 up to 20.
 */
#define DISCOVERY_HEADER_LEN 20

static int nvme_discovery_log(libnvme_ctrl_t ctrl,
			      const struct libnvmf_discovery_args *args,
			      struct nvmf_discovery_log **logp)
{
	struct libnvme_global_ctx *ctx = ctrl->ctx;
	struct nvmf_discovery_log *log;
	int retries = 0;
	int err;
	const char *name = libnvme_ctrl_get_name(ctrl);
	uint64_t genctr, numrec;
	struct libnvme_transport_handle *hdl;

	hdl = libnvme_ctrl_get_transport_handle(ctrl);
	struct libnvme_passthru_cmd cmd;

	log = libnvme_alloc(sizeof(*log));
	if (!log) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			 "could not allocate memory for discovery log header\n");
		return -ENOMEM;
	}

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "%s: get header (try %d/%d)\n",
		 name, retries, args->max_retries);
	nvme_init_get_log_discovery(&cmd, 0, log, DISCOVERY_HEADER_LEN);
	err = libnvme_get_log(hdl, &cmd, false, DISCOVERY_HEADER_LEN);
	if (err) {
		libnvme_msg(ctx, LIBNVME_LOG_INFO,
			 "%s: discover try %d/%d failed, errno %d status 0x%x\n",
			 name, retries, args->max_retries, errno, err);
		goto out_free_log;
	}

	do {
		size_t entries_size;

		numrec = le64_to_cpu(log->numrec);
		genctr = le64_to_cpu(log->genctr);

		if (numrec == 0)
			break;

		libnvme_free(log);
		entries_size = sizeof(*log->entries) * numrec;
		log = libnvme_alloc(sizeof(*log) + entries_size);
		if (!log) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
				 "could not alloc memory for discovery log page\n");
			return -ENOMEM;
		}

		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			 "%s: get %" PRIu64 " records (genctr %" PRIu64 ")\n",
			 name, numrec, genctr);

		nvme_init_get_log_discovery(&cmd, sizeof(*log), log->entries, entries_size);
		cmd.cdw10 |= NVME_FIELD_ENCODE(args->lsp,
					       NVME_LOG_CDW10_LSP_SHIFT,
					       NVME_LOG_CDW10_LSP_MASK);
		err = libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
		if (err) {
			libnvme_msg(ctx, LIBNVME_LOG_INFO,
				 "%s: discover try %d/%d failed, errno %d status 0x%x\n",
				 name, retries, args->max_retries, errno, err);
			goto out_free_log;
		}

		/*
		 * If the log page was read with multiple Get Log Page commands,
		 * genctr must be checked afterwards to ensure atomicity
		 */
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "%s: get header again\n", name);

		nvme_init_get_log_discovery(&cmd, 0, log, DISCOVERY_HEADER_LEN);
		err = libnvme_get_log(hdl, &cmd, false, DISCOVERY_HEADER_LEN);
		if (err) {
			libnvme_msg(ctx, LIBNVME_LOG_INFO,
				 "%s: discover try %d/%d failed, errno %d status 0x%x\n",
				 name, retries, args->max_retries, errno, err);
			goto out_free_log;
		}
	} while (genctr != le64_to_cpu(log->genctr) &&
		 ++retries < args->max_retries);

	if (genctr != le64_to_cpu(log->genctr)) {
		libnvme_msg(ctx, LIBNVME_LOG_INFO, "%s: discover genctr mismatch\n", name);
		err = -EAGAIN;
	} else if (numrec != le64_to_cpu(log->numrec)) {
		libnvme_msg(ctx, LIBNVME_LOG_INFO,
			 "%s: numrec changed unexpectedly "
			 "from %" PRIu64 " to %" PRIu64 "\n",
			 name, numrec, le64_to_cpu(log->numrec));
		err = -EBADSLT;
	} else {
		*logp = log;
		return 0;
	}

out_free_log:
	libnvme_free(log);
	return err;
}

static void sanitize_discovery_log_entry(struct libnvme_global_ctx *ctx,
		struct nvmf_disc_log_entry *e)
{
	strchomp(e->trsvcid, sizeof(e->trsvcid));
	strchomp(e->traddr, sizeof(e->traddr));

	/*
	 * Report traddr always in 'nn-0x:pn-0x' format, but some discovery logs
	 * provide 'nn-0x,pn-0x'.
	 */
	if (e->trtype == NVMF_TRTYPE_FC) {
		char *comma = strchr(e->traddr, ',');

		if (comma) {
			libnvme_msg(ctx, LIBNVME_LOG_WARN,
				"invalid traddr separator ',' instead ':', fixing it");
			*comma = ':';
		}
	}
}

__libnvme_public int libnvmf_get_discovery_log(libnvme_ctrl_t ctrl,
				    const struct libnvmf_discovery_args *args,
				    struct nvmf_discovery_log **logp)
{
	static const struct libnvmf_discovery_args defaults = {
		.max_retries = 6,
		.lsp         = NVMF_LOG_DISC_LSP_NONE,
	};
	struct nvmf_discovery_log *log;
	int err;

	if (!args)
		args = &defaults;

	err = nvme_discovery_log(ctrl, args, &log);
	if (err)
		return err;

	for (int i = 0; i < le64_to_cpu(log->numrec); i++)
		sanitize_discovery_log_entry(ctrl->ctx, &log->entries[i]);

	*logp = log;
	return 0;
}


/**
 * nvmf_get_tel() - Calculate the amount of memory needed for a DIE.
 * @hostsymname:	Symbolic name (may be NULL)
 *
 * Each Discovery Information Entry (DIE) must contain at a minimum an
 * Extended Attribute for the HostID. The Entry may optionally contain an
 * Extended Attribute for the Symbolic Name.
 *
 * Return: Total Entry Length
 */
static __u32 nvmf_get_tel(const char *hostsymname)
{
	__u32 tel = sizeof(struct nvmf_ext_die);
	__u16 len;

	/* Host ID is mandatory */
	tel += libnvmf_exat_size(NVME_UUID_LEN);

	/* Symbolic name is optional */
	len = hostsymname ? strlen(hostsymname) : 0;
	if (len)
		tel += libnvmf_exat_size(len);

	return tel;
}

/**
 * nvmf_fill_die() - Fill a Discovery Information Entry.
 * @die:	Pointer to Discovery Information Entry to be filled
 * @h:		Pointer to the host data structure
 * @tel:	Length of the DIE
 * @trtype:	Transport type
 * @adrfam:	Address family
 * @reg_addr:	Address to register. Setting this to an empty string tells
 *		the DC to infer address from the source address of the socket.
 * @tsas:	Transport Specific Address Subtype for the address being
 *		registered.
 */
static void nvmf_fill_die(struct nvmf_ext_die *die, struct libnvme_host *h,
			  __u32 tel, __u8 trtype, __u8 adrfam,
			  const char *reg_addr, union nvmf_tsas *tsas)
{
	__u16 numexat = 0;
	size_t symname_len;
	struct nvmf_ext_attr *exat;

	die->tel = cpu_to_le32(tel);
	die->trtype = trtype;
	die->adrfam = adrfam;

	memcpy(die->nqn, h->hostnqn, MIN(sizeof(die->nqn), strlen(h->hostnqn)));
	memcpy(die->traddr, reg_addr, MIN(sizeof(die->traddr), strlen(reg_addr)));

	if (tsas)
		memcpy(&die->tsas, tsas, sizeof(die->tsas));

	/* Extended Attribute for the HostID (mandatory) */
	numexat++;
	exat = die->exat;
	exat->exattype = cpu_to_le16(NVMF_EXATTYPE_HOSTID);
	exat->exatlen  = cpu_to_le16(libnvmf_exat_len(NVME_UUID_LEN));
	libnvme_uuid_from_string(h->hostid, exat->exatval);

	/* Extended Attribute for the Symbolic Name (optional) */
	symname_len = h->hostsymname ? strlen(h->hostsymname) : 0;
	if (symname_len) {
		__u16 exatlen = libnvmf_exat_len(symname_len);

		numexat++;
		exat = libnvmf_exat_ptr_next(exat);
		exat->exattype = cpu_to_le16(NVMF_EXATTYPE_SYMNAME);
		exat->exatlen  = cpu_to_le16(exatlen);
		memcpy(exat->exatval, h->hostsymname, symname_len);
		/* Per Base specs, ASCII strings must be padded with spaces */
		memset(&exat->exatval[symname_len], ' ', exatlen - symname_len);
	}

	die->numexat = cpu_to_le16(numexat);
}

/**
 * nvmf_dim() - Explicit reg, dereg, reg-update issuing DIM
 * @c:		Host NVMe controller instance maintaining the admin queue used to
 *		submit the DIM command to the DC.
 * @tas:	Task field of the Command Dword 10 (cdw10). Indicates whether to
 *		perform a Registration, Deregistration, or Registration-update.
 * @trtype:	Transport type (&enum nvmf_trtype - must be NVMF_TRTYPE_TCP)
 * @adrfam:	Address family (&enum nvmf_addr_family)
 * @reg_addr:	Address to register. Setting this to an empty string tells
 *		the DC to infer address from the source address of the socket.
 * @tsas:	Transport Specific Address Subtype for the address being
 *		registered.
 * @result:	Location where to save the command-specific result returned by
 *		the discovery controller.
 *
 * Perform explicit registration, deregistration, or
 * registration-update (specified by @tas) by sending a Discovery
 * Information Management (DIM) command to the Discovery Controller
 * (DC).
 *
 * Return: 0 on success; on failure -1 is returned and errno is set
 */
static int nvmf_dim(libnvme_ctrl_t c, enum nvmf_dim_tas tas, __u8 trtype,
		    __u8 adrfam, const char *reg_addr, union nvmf_tsas *tsas,
		    __u32 *result)
{
	struct libnvme_global_ctx *ctx = c->s && c->s->h ? c->s->h->ctx : NULL;
	__cleanup_free struct nvmf_dim_data *dim = NULL;
	struct libnvme_transport_handle *hdl = libnvme_ctrl_get_transport_handle(c);
	struct libnvme_passthru_cmd cmd;
	struct nvmf_ext_die  *die;
	__u32 tdl;
	__u32 tel;
	int ret;

	if (!c->s) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			 "%s: failed to perform DIM. subsystem undefined.\n",
			 c->name);
		return -EINVAL;
	}

	if (!c->s->h) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			 "%s: failed to perform DIM. host undefined.\n",
			 c->name);
		return -EINVAL;
	}

	if (!c->s->h->hostid) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			 "%s: failed to perform DIM. hostid undefined.\n",
			 c->name);
		return -EINVAL;
	}

	if (!c->s->h->hostnqn) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			 "%s: failed to perform DIM. hostnqn undefined.\n",
			 c->name);
		return -EINVAL;
	}

	if (strcmp(c->transport, "tcp")) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			 "%s: DIM only supported for TCP connections.\n",
			 c->name);
		return -EINVAL;
	}

	/* Register one Discovery Information Entry (DIE) of size TEL */
	tel = nvmf_get_tel(c->s->h->hostsymname);
	tdl = sizeof(struct nvmf_dim_data) + tel;

	dim = (struct nvmf_dim_data *)calloc(1, tdl);
	if (!dim) {
		return -ENOMEM;
	}

	dim->tdl    = cpu_to_le32(tdl);
	dim->nument = cpu_to_le64(1);    /* only one DIE to register */
	dim->entfmt = cpu_to_le16(NVMF_DIM_ENTFMT_EXTENDED);
	dim->etype  = cpu_to_le16(NVMF_DIM_ETYPE_HOST);
	dim->ektype = cpu_to_le16(0x5F); /* must be 0x5F per specs */

	memcpy(dim->eid, c->s->h->hostnqn,
	       MIN(sizeof(dim->eid), strlen(c->s->h->hostnqn)));

	ret = libnvmf_get_entity_name(dim->ename, sizeof(dim->ename));
	if (ret < 0)
		libnvme_msg(ctx, LIBNVME_LOG_INFO, "%s: Failed to retrieve ENAME. %s.\n",
			 c->name, libnvme_strerror(-ret));
	else if (ret == 0)
		libnvme_msg(ctx, LIBNVME_LOG_INFO, "%s: Failed to retrieve ENAME.\n",
			 c->name);

	ret = libnvmf_get_entity_version(dim->ever, sizeof(dim->ever));
	if (ret <= 0)
		libnvme_msg(ctx, LIBNVME_LOG_INFO, "%s: Failed to retrieve EVER.\n", c->name);

	die = &dim->die->extended;
	nvmf_fill_die(die, c->s->h, tel, trtype, adrfam, reg_addr, tsas);

	nvme_init_dim_send(&cmd, tas, dim, tdl);
	return libnvme_exec_admin_passthru(hdl, &cmd);
}

/**
 * nvme_get_adrfam() - Get address family for the address we're registering
 * with the DC.
 *
 * We retrieve this info from the socket itself. If we can't get the source
 * address from the socket, then we'll infer the address family from the
 * address of the DC since the DC address has the same address family.
 *
 * @c: Host NVMe controller instance maintaining the admin queue used to
 *   submit the DIM command to the DC.
 *
 * Return: The address family of the source address associated with the
 *   socket connected to the DC.
 */
static __u8 nvme_get_adrfam(libnvme_ctrl_t c)
{
	struct sockaddr_storage addr;
	__u8 adrfam = NVMF_ADDR_FAMILY_IP4;
	struct libnvme_global_ctx *ctx = c->s && c->s->h ? c->s->h->ctx : NULL;

	if (!inet_pton_with_scope(ctx, AF_UNSPEC, c->traddr, c->trsvcid, &addr)) {
		if (addr.ss_family == AF_INET6)
			adrfam = NVMF_ADDR_FAMILY_IP6;
	}

	return adrfam;
}

/* These string definitions must match with the kernel */
static const char *cntrltype_str[] = {
	[NVME_CTRL_CNTRLTYPE_IO] = "io",
	[NVME_CTRL_CNTRLTYPE_DISCOVERY] = "discovery",
	[NVME_CTRL_CNTRLTYPE_ADMIN] = "admin",
};

static const char *dctype_str[] = {
	[NVME_CTRL_DCTYPE_NOT_REPORTED] = "none",
	[NVME_CTRL_DCTYPE_DDC] = "ddc",
	[NVME_CTRL_DCTYPE_CDC] = "cdc",
};

/**
 * nvme_fetch_cntrltype_dctype_from_id - Get cntrltype and dctype from identify command
 * @c:	Controller instance
 *
 * On legacy kernels the cntrltype and dctype are not exposed through the
 * sysfs. We must get them directly from the controller by performing an
 * identify command.
 */
static int nvme_fetch_cntrltype_dctype_from_id(libnvme_ctrl_t c)
{
	__cleanup_libnvme_free struct nvme_id_ctrl *id = NULL;
	int ret;

	id = libnvme_alloc(sizeof(*id));
	if (!id)
		return -ENOMEM;

	ret = libnvme_ctrl_identify(c, id);
	if (ret)
		return ret;

	if (!c->cntrltype) {
		if (id->cntrltype > NVME_CTRL_CNTRLTYPE_ADMIN || !cntrltype_str[id->cntrltype])
			c->cntrltype = strdup("reserved");
		else
			c->cntrltype = strdup(cntrltype_str[id->cntrltype]);
	}

	if (!c->dctype) {
		if (id->dctype > NVME_CTRL_DCTYPE_CDC || !dctype_str[id->dctype])
			c->dctype = strdup("reserved");
		else
			c->dctype = strdup(dctype_str[id->dctype]);
	}
	return 0;
}

__libnvme_public bool libnvmf_is_registration_supported(libnvme_ctrl_t c)
{
	if (!c->cntrltype || !c->dctype)
		if (nvme_fetch_cntrltype_dctype_from_id(c))
			return false;

	return !strcmp(c->dctype, "ddc") || !strcmp(c->dctype, "cdc");
}

__libnvme_public int libnvmf_register_ctrl(
		libnvme_ctrl_t c, enum nvmf_dim_tas tas, __u32 *result)
{
	if (!libnvmf_is_registration_supported(c))
		return -ENOTSUP;

	/* We're registering our source address with the DC. To do
	 * that, we can simply send an empty string. This tells the DC
	 * to retrieve the source address from the socket and use that
	 * as the registration address.
	 */
	return nvmf_dim(c, tas, NVMF_TRTYPE_TCP, nvme_get_adrfam(c), "", NULL, result);
}

#define IS_XDIGIT(c) ((c >= '0' && c <= '9') || \
		      (c >= 'A' && c <= 'F') || \
		      (c >= 'a' && c <= 'f'))
#define XDIGIT_VAL(c) ((c >= '0' && c <= '9') ? c - '0' : ( \
		       (c >= 'A' && c <= 'F') ? c - 'A' + 10 : c - 'a' + 10))

/* returns newly allocated string */
static char *unescape_uri(const char *str, int len)
{
	char *dst;
	int l;
	int i, j;

	l = len > 0 ? len : strlen(str);
	dst = malloc(l + 1);
	for (i = 0, j = 0; i < l; i++, j++) {
		if (str[i] == '%' && i + 2 < l &&
		    IS_XDIGIT(str[i + 1]) && IS_XDIGIT(str[i + 2])) {
			dst[j] = (XDIGIT_VAL(str[i + 1]) << 4) +
				  XDIGIT_VAL(str[i + 2]);
			i += 2;
		} else
			dst[j] = str[i];
	}
	dst[j] = '\0';
	return dst;
}

__libnvme_public int libnvmf_uri_parse(
		const char *str, struct libnvmf_uri **urip)
{
	__cleanup_uri struct libnvmf_uri *uri = NULL;
	__cleanup_free char *scheme = NULL;
	__cleanup_free char *authority = NULL;
	__cleanup_free char *path = NULL;
	__cleanup_free char *h = NULL;
	const char *host;
	int i;

	/* As defined in Boot Specification rev. 1.0:
	 *
	 * section 1.5.7: NVMe-oF URI Format
	 *  nvme+tcp://192.168.1.1:4420/
	 *  nvme+tcp://[FE80::1010]:4420/
	 *
	 * section 3.1.2.5.3: DHCP Root-Path - a hierarchical NVMe-oF URI Format
	 *  NVME<+PROTOCOL>://<SERVERNAME/IP>[:TRANSPORT PORT]/<SUBSYS NQN>/<NID>
	 * or
	 *  NVME<+PROTOCOL>://<DISCOVERY CONTROLLER ADDRESS>[:DISCOVERY-
	 *  -CONTROLLER PORT]/NQN.2014-08.ORG.NVMEXPRESS.DISCOVERY/<NID>
	 */

	uri = calloc(1, sizeof(struct libnvmf_uri));
	if (!uri)
		return -ENOMEM;

	if (sscanf(str, "%m[^:/]://%m[^/?#]%ms",
		   &scheme, &authority, &path) < 2)
		return -EINVAL;

	if (sscanf(scheme, "%m[^+]+%ms",
		   &uri->scheme, &uri->protocol) < 1)
		return -EINVAL;

	/* split userinfo */
	host = strrchr(authority, '@');
	if (host) {
		host++;
		uri->userinfo = unescape_uri(authority, host - authority);
	} else
		host = authority;

	/* try matching IPv6 address first */
	if (sscanf(host, "[%m[^]]]:%d",
		   &uri->host, &uri->port) < 1) {
		/* treat it as IPv4/hostname */
		if (sscanf(host, "%m[^:]:%d",
			   &h, &uri->port) < 1)
			return -EINVAL;
		uri->host = unescape_uri(h, 0);
	}

	/* split path into elements */
	if (path) {
		char *e, *elem;

		/* separate the fragment */
		e = strrchr(path, '#');
		if (e) {
			uri->fragment = unescape_uri(e + 1, 0);
			*e = '\0';
		}
		/* separate the query string */
		e = strrchr(path, '?');
		if (e) {
			uri->query = unescape_uri(e + 1, 0);
			*e = '\0';
		}

		/* count elements first */
		for (i = 0, e = path; *e; e++)
			if (*e == '/' && *(e + 1) != '/')
				i++;
		uri->path_segments = calloc(i + 2, sizeof(char *));

		i = 0;
		elem = strtok_r(path, "/", &e);
		if (elem)
			uri->path_segments[i++] = unescape_uri(elem, 0);
		while (elem && strlen(elem)) {
			elem = strtok_r(NULL, "/", &e);
			if (elem)
				uri->path_segments[i++] = unescape_uri(elem, 0);
		}
	}

	*urip = uri;
	uri = NULL;

	return 0;
}

__libnvme_public void libnvmf_uri_free(struct libnvmf_uri *uri)
{
	char **s;

	if (!uri)
		return;
	free(uri->scheme);
	free(uri->protocol);
	free(uri->userinfo);
	free(uri->host);
	for (s = uri->path_segments; s && *s; s++)
		free(*s);
	free(uri->path_segments);
	free(uri->query);
	free(uri->fragment);
	free(uri);
}

static libnvme_ctrl_t lookup_ctrl(libnvme_host_t h, struct libnvmf_context *fctx)
{
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;

	libnvme_for_each_subsystem(h, s) {
		c = libnvmf_ctrl_find(s, fctx);
		if (c)
			return c;
	}

	return NULL;
}

static int lookup_host(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, struct libnvme_host **host)
{
	__cleanup_free char *hnqn = NULL;
	__cleanup_free char *hid = NULL;
	struct libnvme_host *h;
	int err;

	err = libnvmf_host_get_ids(ctx, fctx->hostnqn, fctx->hostid,
		&hnqn, &hid);
	if (err < 0)
		return err;

	h = libnvme_lookup_host(ctx, hnqn, hid);
	if (!h)
		return -ENOMEM;

	*host = h;

	return 0;
}

static int setup_connection(struct libnvmf_context *fctx, struct libnvme_host *h,
		bool discovery)
{
	if (fctx->hostkey)
		libnvme_host_set_dhchap_host_key(h, fctx->hostkey);

	if (!fctx->ctrl_params.trsvcid)
		fctx->ctrl_params.trsvcid =
			libnvmf_get_default_trsvcid(fctx->ctrl_params.transport,
				discovery);

	return 0;
}


static int set_discovery_kato(struct libnvmf_context *fctx)
{
	int tmo = fctx->ctrl_params.cfg.keep_alive_tmo;

	/* Set kato to NVMF_DEF_DISC_TMO for persistent controllers */
	if (fctx->persistent && !fctx->ctrl_params.cfg.keep_alive_tmo)
		fctx->ctrl_params.cfg.keep_alive_tmo =
			fctx->default_keep_alive_timeout;
	/* Set kato to zero for non-persistent controllers */
	else if (!fctx->persistent &&
		 (fctx->ctrl_params.cfg.keep_alive_tmo > 0))
		fctx->ctrl_params.cfg.keep_alive_tmo = 0;

	return tmo;
}

static void nvme_parse_tls_args(const char *keyring, const char *tls_key,
				const char *tls_key_identity,
				struct libnvme_fabrics_config *cfg, libnvme_ctrl_t c)
{
	if (keyring) {
		char *endptr;
		long id = strtol(keyring, &endptr, 0);

		if (endptr != keyring)
			cfg->keyring_id = id;
		else
			libnvme_ctrl_set_keyring(c, keyring);
	}

	if (tls_key_identity)
		libnvme_ctrl_set_tls_key_identity(c, tls_key_identity);

	if (tls_key) {
		char *endptr;
		long id = strtol(tls_key, &endptr, 0);

		if (endptr != tls_key)
			cfg->tls_key_id = id;
		else
			libnvme_ctrl_set_tls_key(c, tls_key);
	}
}


static int _nvmf_discovery(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, bool connect,
		struct libnvme_ctrl *c)
{
	__cleanup_free struct nvmf_discovery_log *log = NULL;
	libnvme_subsystem_t s = libnvme_ctrl_get_subsystem(c);
	libnvme_host_t h = libnvme_subsystem_get_host(s);
	uint64_t numrec;
	int err;

	struct libnvmf_discovery_args args = {
		.max_retries = fctx->default_max_discovery_retries,
		.lsp = NVMF_LOG_DISC_LSP_NONE,
	};

	err = nvme_discovery_log(c, &args, &log);
	if (err) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "failed to get discovery log: %s\n",
			libnvme_strerror(err));
		return err;
	}

	numrec = le64_to_cpu(log->numrec);
	if (fctx->hooks.discovery_log)
		fctx->hooks.discovery_log(fctx, connect, log, numrec,
			fctx->hooks.user_data);

	if (!connect)
		return 0;

	for (int i = 0; i < numrec; i++) {
		struct nvmf_disc_log_entry *e = &log->entries[i];
		libnvme_ctrl_t cl;
		bool discover = false;
		bool disconnect;
		libnvme_ctrl_t child = { 0 };
		int tmo = fctx->ctrl_params.cfg.keep_alive_tmo;
		struct libnvmf_context nfctx = *fctx;

		sanitize_discovery_log_entry(c->ctx, e);

		nfctx.ctrl_params.subsysnqn = e->subnqn;
		nfctx.ctrl_params.transport = libnvmf_trtype_str(e->trtype);
		nfctx.ctrl_params.traddr = e->traddr;
		nfctx.ctrl_params.trsvcid = e->trsvcid;

		/* Already connected ? */
		cl = lookup_ctrl(h, &nfctx);
		if (cl && libnvme_ctrl_get_name(cl))
			continue;

		/* Skip connect if the transport types don't match */
		if (strcmp(libnvme_ctrl_get_transport(c),
			   nfctx.ctrl_params.transport))
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

			/*
			 * Are we supposed to keep the discovery
			 * controller around?
			 */
			disconnect = !nfctx.persistent;

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

			set_discovery_kato(&nfctx);
		} else {
			/* NVME_NQN_NVME */
			disconnect = false;
		}

		err = nvmf_connect_disc_entry(h, e, &nfctx, &discover, &child);

		nfctx.ctrl_params.cfg.keep_alive_tmo = tmo;

		if (child) {
			if (discover)
				_nvmf_discovery(ctx, &nfctx, true, child);

			if (disconnect) {
				libnvmf_disconnect_ctrl(child);
				libnvme_free_ctrl(child);
			}
		} else if (err == -ENVME_CONNECT_ALREADY) {
			struct nvmf_disc_log_entry *e = &log->entries[i];

			nfctx.hooks.already_connected(&nfctx, h, e->subnqn,
				libnvmf_trtype_str(e->trtype), e->traddr,
				e->trsvcid, nfctx.hooks.user_data);
		}
	}

	return 0;
}

__libnvme_public const char *libnvmf_get_default_trsvcid(const char *transport,
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

static bool is_persistent_discovery_ctrl(libnvme_host_t h, libnvme_ctrl_t c)
{
	if (libnvme_host_is_pdc_enabled(h, DEFAULT_PDC_ENABLED))
		return libnvme_ctrl_get_unique_discovery_ctrl(c);

	return false;
}

static int libnvme_add_ctrl(struct libnvmf_context *fctx,
		struct libnvme_host *h, struct libnvme_ctrl *c)
{
	int err;

retry:
	err = libnvmf_add_ctrl(h, c);
	if (!err)
		return 0;
	if (fctx->hooks.decide_retry(fctx, err, fctx->hooks.user_data))
		goto retry;

	return err;
}

static int __create_discovery_ctrl(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, libnvme_host_t h,
		struct libnvme_ctrl **ctrl)
{
	libnvme_ctrl_t c;
	int tmo, ret;

	ret = libnvme_create_ctrl(ctx, &fctx->ctrl_params, &c);
	if (ret)
		return ret;

	libnvme_ctrl_set_discovery_ctrl(c, true);
	libnvme_ctrl_set_unique_discovery_ctrl(c,
		strcmp(fctx->ctrl_params.subsysnqn,
		       NVME_DISC_SUBSYS_NAME));
	tmo = set_discovery_kato(fctx);

	if (libnvme_ctrl_get_unique_discovery_ctrl(c) && fctx->hostkey) {
		libnvme_ctrl_set_dhchap_host_key(c, fctx->hostkey);
		if (fctx->ctrlkey)
			libnvme_ctrl_set_dhchap_ctrl_key(c, fctx->ctrlkey);
	}

	ret = libnvme_add_ctrl(fctx, h, c);
	fctx->ctrl_params.cfg.keep_alive_tmo = tmo;
	if (ret) {
		libnvme_free_ctrl(c);
		return ret;
	}

	*ctrl = c;
	return 0;
}

static int nvmf_create_discovery_ctrl(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, libnvme_host_t h,
		struct libnvme_ctrl **ctrl)
{
	__cleanup_libnvme_free struct nvme_id_ctrl *id = NULL;
	struct libnvme_ctrl *c;
	int ret;

	ret = __create_discovery_ctrl(ctx, fctx, h, &c);
	if (ret)
		return ret;

	if (libnvme_ctrl_get_unique_discovery_ctrl(c)) {
		*ctrl = c;
		return 0;
	}

	id = libnvme_alloc(sizeof(*id));
	if (!id) {
		libnvme_free_ctrl(c);
		return -ENOMEM;
	}

	ret = libnvme_open(ctx, c->name, &c->hdl);
	if (ret) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "failed to open %s\n", c->name);
		return ret;
	}

	/* Find out the name of discovery controller */
	ret = libnvme_ctrl_identify(c, id);
	if (ret)  {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			 "failed to identify controller, error %s\n",
			 libnvme_strerror(-ret));
		libnvmf_disconnect_ctrl(c);
		libnvme_free_ctrl(c);
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
	libnvmf_disconnect_ctrl(c);
	libnvme_free_ctrl(c);

	fctx->ctrl_params.subsysnqn = id->subnqn;
	ret = __create_discovery_ctrl(ctx, fctx, h, &c);
	if (ret)
		return ret;

	*ctrl = c;
	return 0;
}

int _discovery_config_json(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, libnvme_host_t h, libnvme_ctrl_t c,
		bool connect, bool force)
{
	struct libnvmf_context nfctx = *fctx;
	libnvme_ctrl_t cn;
	int ret = 0;

	nfctx.ctrl_params.transport = libnvme_ctrl_get_transport(c);
	nfctx.ctrl_params.traddr = libnvme_ctrl_get_traddr(c);
	nfctx.ctrl_params.host_traddr = libnvme_ctrl_get_host_traddr(c);
	nfctx.ctrl_params.host_iface = libnvme_ctrl_get_host_iface(c);

	if (!nfctx.ctrl_params.transport || !nfctx.ctrl_params.traddr)
		return 0;

	/* ignore none fabric transports */
	if (strcmp(nfctx.ctrl_params.transport, "tcp") &&
	    strcmp(nfctx.ctrl_params.transport, "rdma") &&
	    strcmp(nfctx.ctrl_params.transport, "fc"))
		return 0;

	/* ignore if no host_traddr for fc */
	if (!strcmp(nfctx.ctrl_params.transport, "fc")) {
		if (!nfctx.ctrl_params.host_traddr) {
			libnvme_msg(ctx, LIBNVME_LOG_ERR,
				 "host_traddr required for fc\n");
			return 0;
		}
	}

	/* ignore if host_iface set for any transport other than tcp */
	if (!strcmp(nfctx.ctrl_params.transport, "rdma") ||
	    !strcmp(nfctx.ctrl_params.transport, "fc")) {
		if (nfctx.ctrl_params.host_iface) {
			libnvme_msg(ctx, LIBNVME_LOG_ERR,
				 "host_iface not permitted for rdma or fc\n");
			return 0;
		}
	}

	nfctx.ctrl_params.trsvcid = libnvme_ctrl_get_trsvcid(c);
	if (!nfctx.ctrl_params.trsvcid ||
	    !strcmp(nfctx.ctrl_params.trsvcid, ""))
		nfctx.ctrl_params.trsvcid =
			libnvmf_get_default_trsvcid(
				nfctx.ctrl_params.transport, true);

	if (force)
		nfctx.ctrl_params.subsysnqn = libnvme_ctrl_get_subsysnqn(c);
	else
		nfctx.ctrl_params.subsysnqn = NVME_DISC_SUBSYS_NAME;

	if (libnvme_ctrl_get_persistent(c))
		nfctx.persistent = true;

	if (nvmf_excluded(ctx, nfctx.ctrl_params.transport,
			  nfctx.ctrl_params.traddr, nfctx.ctrl_params.trsvcid,
			  nfctx.ctrl_params.subsysnqn,
			  nfctx.ctrl_params.host_traddr,
			  nfctx.ctrl_params.host_iface,
			  libnvme_host_get_hostnqn(h),
			  libnvme_host_get_hostid(h)))
		return 0;

	if (!force) {
		cn = lookup_ctrl(h, &nfctx);
		if (cn) {
			nfctx.persistent = true;
			_nvmf_discovery(ctx, &nfctx, connect, cn);
			return 0;
		}
	}

	ret = nvmf_create_discovery_ctrl(ctx, &nfctx, h, &cn);
	if (ret)
		return 0;

	_nvmf_discovery(ctx, &nfctx, connect, cn);
	if (!(fctx->persistent || is_persistent_discovery_ctrl(h, cn)))
		ret = libnvmf_disconnect_ctrl(cn);
	libnvme_free_ctrl(cn);

	return ret;
}

__libnvme_public int libnvmf_discovery_config_json(
		struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx,
		bool connect, bool force)
{
	const char *hnqn, *hid;
	struct libnvme_subsystem *s;
	struct libnvme_host *h;
	struct libnvme_ctrl *c;
	int ret = 0, err;

	err = lookup_host(ctx, fctx, &h);
	if (err)
		return err;

	err = setup_connection(fctx, h, false);
	if (err)
		return err;

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			hnqn = libnvme_host_get_hostnqn(h);
			if (fctx->hostnqn && hnqn &&
					strcmp(fctx->hostnqn, hnqn))
				continue;
			hid = libnvme_host_get_hostid(h);
			if (fctx->hostid && hid &&
					strcmp(fctx->hostid, hid))
				continue;

			libnvme_subsystem_for_each_ctrl(s, c) {
				err = _discovery_config_json(ctx, fctx, h, c,
					connect, force);
				if (err) {
					libnvme_msg(ctx, LIBNVME_LOG_ERR,
						"failed to connect to hostnqn=%s,nqn=%s,%s\n",
						libnvme_host_get_hostnqn(h),
						libnvme_subsystem_get_name(s),
						libnvme_ctrl_get_traddr(c));

					if (!ret)
						ret = err;
				}
			}
		}
	}

	return ret;
}

__libnvme_public int libnvmf_connect_config_json(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx)
{
	const char *hnqn, *hid;
	const char *transport;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c, _c;
	int ret = 0, err;

	err = lookup_host(ctx, fctx, &h);
	if (err)
		return err;

	err = setup_connection(fctx, h, false);
	if (err)
		return err;

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			hnqn = libnvme_host_get_hostnqn(h);
			if (fctx->hostnqn && hnqn &&
					strcmp(fctx->hostnqn, hnqn))
				continue;
			hid = libnvme_host_get_hostid(h);
			if (fctx->hostid && hid &&
					strcmp(fctx->hostid, hid))
				continue;

			libnvme_subsystem_for_each_ctrl_safe(s, c, _c) {
				transport = libnvme_ctrl_get_transport(c);

				/* ignore none fabric transports */
				if (strcmp(transport, "tcp") &&
				    strcmp(transport, "rdma") &&
				    strcmp(transport, "fc"))
					continue;

				if (nvmf_ctrl_excluded(ctx, h, c))
					continue;

				err = libnvmf_connect_ctrl(c);
				if (err) {
					if (err == -ENVME_CONNECT_ALREADY)
						continue;

					libnvme_msg(ctx, LIBNVME_LOG_ERR,
						 "failed to connect to hostnqn=%s,nqn=%s,%s\n",
						 libnvme_host_get_hostnqn(h),
						 libnvme_subsystem_get_name(s),
						 libnvme_ctrl_get_traddr(c));

					if (!ret)
						ret = err;
				}
			}
		}
	}

	return ret;
}

__libnvme_public int libnvmf_discovery_config_file(
		struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx,
		bool connect, bool force)
{
	int err;

	err = fctx->hooks.parser_init(fctx, fctx->hooks.user_data);
	if (err)
		return err;

	do {
		struct libnvmf_context nfctx = *fctx;
		err = fctx->hooks.parser_next_line(&nfctx, fctx->hooks.user_data);
		if (err)
			break;
		if (nvmf_excluded(ctx, nfctx.ctrl_params.transport,
				  nfctx.ctrl_params.traddr,
				  nfctx.ctrl_params.trsvcid,
				  nfctx.ctrl_params.subsysnqn,
				  nfctx.ctrl_params.host_traddr,
				  nfctx.ctrl_params.host_iface,
				  nfctx.hostnqn, nfctx.hostid))
			continue;
		libnvmf_discovery(ctx, &nfctx, connect, force);
	} while (!err);

	fctx->hooks.parser_cleanup(fctx, fctx->hooks.user_data);

	if (err != -EOF)
		return err;

	return 0;
}

__libnvme_public int libnvmf_config_modify(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx)
{
	__cleanup_free char *hnqn = NULL;
	__cleanup_free char *hid = NULL;
	struct libnvme_host *h;
	struct libnvme_subsystem *s;
	struct libnvme_ctrl *c;

	if (!fctx->hostnqn)
		fctx->hostnqn = hnqn = libnvmf_read_hostnqn();
	if (!fctx->hostid && hnqn)
		fctx->hostid = hid = libnvmf_read_hostid();

	h = libnvme_lookup_host(ctx, fctx->hostnqn, fctx->hostid);
	if (!h) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "Failed to lookup host '%s'\n",
			fctx->hostnqn);
		return -ENODEV;
	}

	if (fctx->hostkey)
		libnvme_host_set_dhchap_host_key(h, fctx->hostkey);

	s = libnvme_lookup_subsystem(h, NULL, fctx->ctrl_params.subsysnqn);
	if (!s) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "Failed to lookup subsystem '%s'\n",
			fctx->ctrl_params.subsysnqn);
		return -ENODEV;
	}

	c = libnvme_lookup_ctrl(s, &fctx->ctrl_params, NULL);
	if (!c) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "Failed to lookup controller\n");
		return -ENODEV;
	}
	if (fctx->ctrlkey)
		libnvme_ctrl_set_dhchap_ctrl_key(c, fctx->ctrlkey);

	nvme_parse_tls_args(fctx->keyring, fctx->tls_key,
			    fctx->tls_key_identity, &fctx->ctrl_params.cfg, c);

	update_config(c, &fctx->ctrl_params.cfg);

	return 0;
}

#define NBFT_SYSFS_FILENAME	"NBFT*"

static int nbft_filter(const struct dirent *dent)
{
	return !fnmatch(NBFT_SYSFS_FILENAME, dent->d_name, FNM_PATHNAME);
}

__libnvme_public int libnvmf_nbft_read_files(
		struct libnvme_global_ctx *ctx, char *path,
		struct nbft_file_entry **head)
{
	struct nbft_file_entry *entry = NULL;
	struct libnbft_info *nbft;
	struct dirent **dent;
	char filename[PATH_MAX];
	int i, count, ret;

	count = scandir(path, &dent, nbft_filter, NULL);
	if (count < 0)
		return -errno;

	for (i = 0; i < count; i++) {
		snprintf(filename, sizeof(filename), "%s/%s", path,
			dent[i]->d_name);

		ret = libnvmf_read_nbft(ctx, &nbft, filename);
		if (!ret) {
			struct nbft_file_entry *new;

			new = calloc(1, sizeof(*new));
			if (!new)
				return -ENOMEM;
			new->nbft = nbft;
			if (entry) {
				entry->next = new;
				entry = entry->next;
			} else {
				entry = new;
				*head = entry;
			}
		}
		free(dent[i]);
	}
	free(dent);
	return 0;
}

__libnvme_public void libnvmf_nbft_free(
		struct libnvme_global_ctx *ctx, struct nbft_file_entry *head)
{
	if (!head)
		return;

	while (head) {
		struct nbft_file_entry *next = head->next;

		libnvmf_free_nbft(ctx, head->nbft);
		free(head);

		head = next;
	}
}

static bool validate_uri(struct libnvme_global_ctx *ctx,
			 struct libnbft_discovery *dd,
			 struct libnvmf_uri *uri)
{
	if (!uri) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			 "Discovery Descriptor %d: failed to parse URI %s\n",
			 dd->index, dd->uri);
		return false;
	}
	if (strcmp(uri->scheme, "nvme") != 0) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			 "Discovery Descriptor %d: unsupported scheme '%s'\n",
			 dd->index, uri->scheme);
		return false;
	}
	if (!uri->protocol || strcmp(uri->protocol, "tcp") != 0) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			 "Discovery Descriptor %d: unsupported transport '%s'\n",
			 dd->index, uri->protocol);
		return false;
	}

	return true;
}

static int nbft_connect(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, struct libnvme_host *h,
		struct nvmf_disc_log_entry *e,
		struct libnbft_subsystem_ns *ss)
{
	libnvme_ctrl_t c;
	int saved_log_level;
	bool saved_log_tstamp;
	bool saved_log_pid;
	int ret;

	saved_log_level = libnvme_get_logging_level(ctx, &saved_log_tstamp,
		&saved_log_pid);

	c = lookup_ctrl(h, fctx);
	if (c && libnvme_ctrl_get_name(c))
		return 0;

	if (nvmf_excluded(ctx, fctx->ctrl_params.transport,
			  fctx->ctrl_params.traddr, fctx->ctrl_params.trsvcid,
			  fctx->ctrl_params.subsysnqn,
			  fctx->ctrl_params.host_traddr,
			  fctx->ctrl_params.host_iface,
			  libnvme_host_get_hostnqn(h),
			  libnvme_host_get_hostid(h)))
		return 0;

	ret = libnvme_create_ctrl(ctx, &fctx->ctrl_params, &c);
	if (ret)
		return ret;

	/* Pause logging for unavailable SSNSs */
	if (ss && ss->unavailable && saved_log_level < 1)
		libnvme_set_logging_level(ctx, -1, false, false);

	/* Update tls or concat */
	nvmf_update_tls_concat(e, c, h);

	ret = libnvmf_add_ctrl(h, c);

	/* Resume logging */
	if (ss && ss->unavailable && saved_log_level < 1)
		libnvme_set_logging_level(ctx,
				  saved_log_level,
				  saved_log_pid,
				  saved_log_tstamp);

	if (ret) {
		libnvme_free_ctrl(c);
		/*
		 * In case this SSNS was marked as 'unavailable' and
		 * our connection attempt has failed, ignore it.
		 */
		if (ss && ss->unavailable) {
			libnvme_msg(ctx, LIBNVME_LOG_INFO,
				"SSNS %d reported as unavailable, skipping\n",
				ss->index);
			return 0;
		}
		return ret;
	}

	if (fctx->hooks.connected)
		fctx->hooks.connected(fctx, c, fctx->hooks.user_data);

	return 0;
}

static int nbft_discovery(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, struct libnbft_discovery *dd,
		struct libnvme_host *h, struct libnvme_ctrl *c)
{
	struct nvmf_discovery_log *log = NULL;
	int ret;
	int i;

	struct libnvmf_discovery_args args = {
		.max_retries = 10 /* MAX_DISC_RETRIES */,
		.lsp = NVMF_LOG_DISC_LSP_NONE,
	};

	ret = nvme_discovery_log(c, &args, &log);
	if (ret) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			"Discovery Descriptor %d: failed to get discovery log: %s\n",
			dd->index, libnvme_strerror(ret));
		return ret;
	}

	for (i = 0; i < le64_to_cpu(log->numrec); i++) {
		struct nvmf_disc_log_entry *e = &log->entries[i];
		struct libnvmf_context nfctx = *fctx;
		libnvme_ctrl_t cl;
		int tmo = fctx->ctrl_params.cfg.keep_alive_tmo;

		sanitize_discovery_log_entry(c->ctx, e);

		nfctx.ctrl_params.subsysnqn = e->subnqn;
		nfctx.ctrl_params.transport = libnvmf_trtype_str(e->trtype);
		nfctx.ctrl_params.traddr = e->traddr;
		nfctx.ctrl_params.trsvcid = e->trsvcid;

		if (e->subtype == NVME_NQN_CURR)
			continue;

		/* Already connected ? */
		cl = lookup_ctrl(h, &nfctx);
		if (cl && libnvme_ctrl_get_name(cl))
			continue;

		/* Skip connect if the transport types don't match */
		if (strcmp(libnvme_ctrl_get_transport(c),
			   nfctx.ctrl_params.transport))
			continue;

		if (e->subtype == NVME_NQN_DISC) {
			libnvme_ctrl_t child;

			ret = nvmf_connect_disc_entry(h, e, &nfctx,
				NULL, &child);
			if (ret)
				continue;
			nbft_discovery(ctx, &nfctx, dd, h, child);
			libnvmf_disconnect_ctrl(child);
			libnvme_free_ctrl(child);
		} else {
			ret = nbft_connect(ctx, &nfctx, h, e, NULL);

			/*
			 * With TCP/DHCP, it can happen that the OS
			 * obtains a different local IP address than the
			 * firmware had. Retry without host_traddr.
			 */
			if (ret == -ENVME_CONNECT_ADDRNOTAVAIL &&
			    !strcmp(nfctx.ctrl_params.transport, "tcp") &&
			    strlen(dd->hfi->tcp_info.dhcp_server_ipaddr) > 0) {
				const char *htradr =
					nfctx.ctrl_params.host_traddr;

				nfctx.ctrl_params.host_traddr = NULL;
				ret = nbft_connect(ctx, &nfctx, h, e, NULL);

				if (ret == 0)
					libnvme_msg(ctx, LIBNVME_LOG_INFO,
						"Discovery Descriptor %d: connect with host_traddr=\"%s\" failed, success after omitting host_traddr\n",
						dd->index,
						htradr);
			}

			if (ret)
				libnvme_msg(ctx, LIBNVME_LOG_ERR,
					"Discovery Descriptor %d: no controller found\n",
					dd->index);
			if (ret == -ENOMEM)
				break;
		}

		fctx->ctrl_params.cfg.keep_alive_tmo = tmo;
	}

	libnvme_free(log);
	return 0;
}

#define VLAN_PROC_PATH "/proc/net/vlan"

/*
 * Return 0 for no vlan_id, to be consistent with the NBFT spec.
 */
static int get_vlan_id(const char *ifname)
{
	char path[256], line[256];
	int vlan_id = 0;
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", VLAN_PROC_PATH, ifname);
	f = fopen(path, "r");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, " VID: %d", &vlan_id) == 1) {
			fclose(f);
			return vlan_id;
		}
	}

	fclose(f);
	return 0;
}

/*
 * Find network interface corresponding to the NBFT HFI
 * by looking for mac address and vlan id.
 */
static char *nbft_find_hfi_iface(struct libnbft_hfi *hfi)
{
	struct ifaddrs *ifaddr, *ifa;
	char *result = NULL;

	if (strcmp((char *)hfi->transport, "tcp"))
		return NULL;

	if (getifaddrs(&ifaddr) != 0)
		return NULL;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		struct sockaddr_ll *sll;

		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family != AF_PACKET)
			continue;

		sll = (struct sockaddr_ll *)ifa->ifa_addr;

		if (sll->sll_halen != ETH_ALEN)
			continue;

		if (!memcmp(sll->sll_addr, hfi->tcp_info.mac_addr, ETH_ALEN)) {
			int vlan_id = get_vlan_id(ifa->ifa_name);

			if (vlan_id == hfi->tcp_info.vlan) {
				result = strdup(ifa->ifa_name);
				break;
			}
		}
	}

	freeifaddrs(ifaddr);
	return result;
}

__libnvme_public int libnvmf_discovery_nbft(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, bool connect, char *nbft_path)
{
	const char *hostnqn = NULL, *hostid = NULL, *host_traddr = NULL;
	char uuid[NVME_UUID_LEN_STRING];
	struct nbft_file_entry *entry = NULL;
	struct libnbft_subsystem_ns **ss;
	struct libnbft_hfi *hfi;
	struct libnbft_discovery **dd;
	struct libnvme_host *h;
	int ret, rr, i;

	ret = lookup_host(ctx, fctx, &h);
	if (ret)
		return ret;

	ret = setup_connection(fctx, h, false);
	if (ret)
		return ret;

	if (!connect)
		/* TODO: print discovery-type info from NBFT tables */
		return 0;

	ret = libnvmf_nbft_read_files(ctx, nbft_path, &entry);
	if (ret) {
		if (ret != -ENOENT)
			libnvme_msg(ctx, LIBNVME_LOG_ERR,
				"Failed to access ACPI tables directory\n");
		else
			ret = 0;  /* nothing to connect */
		goto out_free;
	}

	for (; entry; entry = entry->next) {
		if (fctx->hostnqn)
			hostnqn = fctx->hostnqn;
		else {
			hostnqn = entry->nbft->host.nqn;
			if (!hostnqn)
				hostnqn = fctx->hostnqn;
		}

		if (fctx->hostid)
			hostid = fctx->hostid;
		else if (*entry->nbft->host.id) {
			ret = libnvme_uuid_to_string(entry->nbft->host.id, uuid);
			if (!ret)
				hostid = uuid;
			else
				hostid = fctx->hostid;
		}

		h = libnvme_lookup_host(ctx, hostnqn, hostid);
		if (!h) {
			ret = -ENOENT;
			goto out_free;
		}

		/* Subsystem Namespace Descriptor List */
		for (ss = entry->nbft->subsystem_ns_list; ss && *ss; ss++)
			for (i = 0; i < (*ss)->num_hfis; i++) {
				struct libnvmf_context nfctx = *fctx;

				hfi = (*ss)->hfis[i];

				/* Skip discovery NQN records */
				if (strcmp((*ss)->subsys_nqn,
						NVME_DISC_SUBSYS_NAME) == 0) {
					libnvme_msg(ctx, LIBNVME_LOG_INFO,
						"SSNS %d points to well-known discovery NQN, skipping\n",
						(*ss)->index);
					continue;
				}

				nfctx.ctrl_params.host_traddr = NULL;
				if (!fctx->ctrl_params.host_traddr &&
				    !strncmp((*ss)->transport, "tcp", 3))
					nfctx.ctrl_params.host_traddr =
						hfi->tcp_info.ipaddr;

				nfctx.ctrl_params.subsysnqn = (*ss)->subsys_nqn;
				nfctx.ctrl_params.transport = (*ss)->transport;
				nfctx.ctrl_params.traddr = (*ss)->traddr;
				nfctx.ctrl_params.trsvcid = (*ss)->trsvcid;
				nfctx.ctrl_params.host_iface = nbft_find_hfi_iface(hfi);
				if (!nfctx.ctrl_params.host_iface)
					libnvme_msg(ctx, LIBNVME_LOG_INFO,
						"SSNS %d: could not find host interface for HFI %d\n",
						(*ss)->index, hfi->index);

				rr = nbft_connect(ctx, &nfctx, h, NULL, *ss);

				/*
				 * With TCP/DHCP, it can happen that the OS
				 * obtains a different local IP address than the
				 * firmware had. Retry without host_traddr.
				 */
				if (rr == -ENVME_CONNECT_ADDRNOTAVAIL &&
				    !strcmp(nfctx.ctrl_params.transport,
					    "tcp") &&
				    strlen(hfi->tcp_info.dhcp_server_ipaddr) > 0) {
					nfctx.ctrl_params.host_traddr = NULL;

					rr = nbft_connect(ctx, &nfctx, h, NULL,
						*ss);

					if (rr == 0)
						libnvme_msg(ctx, LIBNVME_LOG_INFO,
							"SSNS %d: connect with host_traddr=\"%s\" failed, success after omitting host_traddr\n",
							(*ss)->index,
							host_traddr);
				}

				if (nfctx.ctrl_params.host_iface)
					free((char *)nfctx.ctrl_params.host_iface);

				if (rr) {
					libnvme_msg(ctx, LIBNVME_LOG_ERR,
						"SSNS %d: no controller found\n",
						(*ss)->index);
					/* report an error */
					ret = rr;
				}

				if (rr == -ENOMEM)
					goto out_free;
			}

		/* Discovery Descriptor List */
		for (dd = entry->nbft->discovery_list; dd && *dd; dd++) {
			__cleanup_uri struct libnvmf_uri *uri = NULL;
			__cleanup_free char *trsvcid = NULL;
			struct libnvmf_context nfctx = *fctx;
			bool persistent = false;
			bool linked = false;
			libnvme_ctrl_t c;

			/* only perform discovery when no SSNS record references it */
			for (ss = entry->nbft->subsystem_ns_list;
					ss && *ss; ss++)
				if ((*ss)->discovery &&
				    (*ss)->discovery->index == (*dd)->index &&
				    /* unavailable boot attempts are not discovered
				     * and may get transferred along with a well-known
				     * discovery NQN into an SSNS record.
				     */
				    strcmp((*ss)->subsys_nqn,
						NVME_DISC_SUBSYS_NAME) != 0) {
					linked = true;
					break;
				}
			if (linked)
				continue;

			hfi = (*dd)->hfi;
			ret = libnvmf_uri_parse((*dd)->uri, &uri);
			if (ret)
				continue;
			if (!validate_uri(ctx, *dd, uri))
				continue;

			host_traddr = NULL;
			if (!fctx->ctrl_params.host_traddr &&
			    !strncmp(uri->protocol, "tcp", 3))
				host_traddr = hfi->tcp_info.ipaddr;
			if (uri->port > 0) {
				if (asprintf(&trsvcid, "%d", uri->port) < 0) {
					ret = -ENOMEM;
					goto out_free;
				}
			} else
				trsvcid =
					strdup(libnvmf_get_default_trsvcid(
						uri->protocol, true));

			nfctx.ctrl_params.subsysnqn = NVME_DISC_SUBSYS_NAME;
			nfctx.ctrl_params.transport =  uri->protocol;
			nfctx.ctrl_params.traddr = uri->host;
			nfctx.ctrl_params.trsvcid = trsvcid;
			nfctx.ctrl_params.host_traddr = host_traddr;
			nfctx.ctrl_params.host_iface = nbft_find_hfi_iface(hfi);
			if (!nfctx.ctrl_params.host_iface)
				libnvme_msg(ctx, LIBNVME_LOG_INFO,
					"SSNS %d: could not find host interface for HFI %d\n",
					(*ss)->index, hfi->index);

			/* Lookup existing discovery controller */
			c = lookup_ctrl(h, &nfctx);
			if (c && libnvme_ctrl_get_name(c))
				persistent = true;

			if (!c) {
				ret = nvmf_create_discovery_ctrl(ctx, &nfctx,
					h, &c);
				if (ret == -ENVME_CONNECT_ADDRNOTAVAIL &&
				    !strcmp(nfctx.ctrl_params.transport,
					    "tcp") &&
				    strlen(hfi->tcp_info.dhcp_server_ipaddr) > 0) {
					nfctx.ctrl_params.traddr = NULL;
					ret = nvmf_create_discovery_ctrl(ctx,
						&nfctx, h, &c);
				}
			} else
				ret = 0;

			if (nfctx.ctrl_params.host_iface)
				free((char *)nfctx.ctrl_params.host_iface);

			if (ret) {
				libnvme_msg(ctx, LIBNVME_LOG_ERR,
					"Discovery Descriptor %d: failed to add discovery controller: %s\n",
					(*dd)->index, libnvme_strerror(-ret));
				goto out_free;
			}

			rr = nbft_discovery(ctx, &nfctx, *dd, h, c);
			if (!persistent)
				libnvmf_disconnect_ctrl(c);
			libnvme_free_ctrl(c);
			if (rr == -ENOMEM) {
				ret = rr;
				goto out_free;
			}
		}
	}
out_free:
	libnvmf_nbft_free(ctx, entry);
	return ret;
}

__libnvme_public int libnvmf_discovery(
		struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx,
		bool connect, bool force)
{
	struct libnvme_ctrl *c = NULL;
	struct libnvme_host *h;
	int ret;

	ret = lookup_host(ctx, fctx, &h);
	if (ret)
		return ret;

	ret = setup_connection(fctx, h, true);
	if (ret)
		return ret;

	if (fctx->device && !force) {
		ret = libnvme_scan_ctrl(ctx, fctx->device, &c);
		if (!ret) {
			/* Check if device matches command-line options */
			if (!libnvmf_ctrl_match_config(c, fctx)) {
				libnvme_msg(ctx, LIBNVME_LOG_ERR,
				    "ctrl device %s found, ignoring non matching command-line options\n",
				    fctx->device);
			}

			if (!libnvme_ctrl_get_discovery_ctrl(c)) {
				libnvme_msg(
					ctx, LIBNVME_LOG_ERR,
					"ctrl device %s found, ignoring non discovery controller\n",
					fctx->device);

				libnvme_free_ctrl(c);
				c = NULL;
				fctx->persistent = false;
			} else {
				/*
				 * If the controller device is found it must
				 * be persistent, and shouldn't be disconnected
				 * on exit.
				 */
				fctx->persistent = true;
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
				if (!fctx->ctrl_params.host_traddr)
					fctx->ctrl_params.host_traddr = (char *)
						libnvme_ctrl_get_host_traddr(c);
				if (!fctx->ctrl_params.host_iface)
					fctx->ctrl_params.host_iface = (char *)
						libnvme_ctrl_get_host_iface(c);
			}
		} else {
			/*
			 * No controller found, fall back to create one.
			 * But that controller cannot be persistent.
			 */
			libnvme_msg(ctx, LIBNVME_LOG_ERR,
				"ctrl device %s not found%s\n", fctx->device,
				fctx->persistent ? ", ignoring --persistent" : "");
			fctx->persistent = false;
		}
	}

	if (!c && !force) {
		c = lookup_ctrl(h, fctx);
		if (c)
			fctx->persistent = true;
	}
	if (!c) {
		/* No device or non-matching device, create a new controller */
		ret = nvmf_create_discovery_ctrl(ctx, fctx, h, &c);
		if (ret) {
			if (ret != -ENVME_CONNECT_IGNORED)
				libnvme_msg(ctx, LIBNVME_LOG_ERR,
					 "failed to add controller, error %s\n",
					 libnvme_strerror(-ret));
			return ret;
		}
	}

	ret = _nvmf_discovery(ctx, fctx, connect, c);
	if (!(fctx->persistent || is_persistent_discovery_ctrl(h, c)))
		libnvmf_disconnect_ctrl(c);
	libnvme_free_ctrl(c);

	return ret;
}

__libnvme_public int libnvmf_connect(
		struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx)
{
	__cleanup_fd int devid_fd = -1;
	struct libnvme_host *h;
	struct libnvme_ctrl *c;
	int err;

	/* Open before touching kernel state, so a bad path fails fast. */
	if (fctx->devid_file) {
		devid_fd = open_devid_file(fctx);
		if (devid_fd < 0)
			return devid_fd;
	}

	err = lookup_host(ctx, fctx, &h);
	if (err)
		return err;

	err = setup_connection(fctx, h, false);
	if (err)
		return err;

	c = lookup_ctrl(h, fctx);
	if (c && libnvme_ctrl_get_name(c) &&
	    !fctx->ctrl_params.cfg.duplicate_connect) {
		write_devid_file(fctx, devid_fd, c);
		fctx->hooks.already_connected(fctx, h,
			libnvme_ctrl_get_subsysnqn(c),
			libnvme_ctrl_get_transport(c),
			libnvme_ctrl_get_traddr(c),
			libnvme_ctrl_get_trsvcid(c), fctx->hooks.user_data);
		return -EALREADY;
	}

	err = libnvme_create_ctrl(ctx, &fctx->ctrl_params, &c);
	if (err)
		return err;

	if (fctx->hostkey) {
		libnvme_ctrl_set_dhchap_host_key(c, fctx->hostkey);
		if (fctx->ctrlkey)
			libnvme_ctrl_set_dhchap_ctrl_key(c, fctx->ctrlkey);
	}

	nvme_parse_tls_args(fctx->keyring, fctx->tls_key,
		fctx->tls_key_identity, &fctx->ctrl_params.cfg, c);
	update_config(c, &fctx->ctrl_params.cfg);

	/*
	 * We are connecting to a discovery controller, so let's treat
	 * this as a persistent connection and specify a KATO.
	 */
	if (!strcmp(fctx->ctrl_params.subsysnqn, NVME_DISC_SUBSYS_NAME)) {
		fctx->persistent = true;

		set_discovery_kato(fctx);
	}

	err = libnvme_add_ctrl(fctx, h, c);
	if (err) {
		/*
		 * Kernel-level race: something else connected between our
		 * scan and this ioctl. @c is our own unconnected draft, not
		 * the winner -- rescan to find it.
		 */
		if (err == -ENVME_CONNECT_ALREADY &&
		    libnvme_scan_topology(ctx, NULL, NULL) == 0)
			write_devid_file(fctx, devid_fd, lookup_ctrl(h, fctx));

		libnvme_msg(ctx, LIBNVME_LOG_ERR, "could not add new controller: %s\n",
			libnvme_strerror(-err));
		libnvme_free_ctrl(c);
		return err;
	}

	write_devid_file(fctx, devid_fd, c);
	fctx->hooks.connected(fctx, c, fctx->hooks.user_data);

	return 0;
}
