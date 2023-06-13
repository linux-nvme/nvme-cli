// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>

#include <ccan/endian/endian.h>
#include <ccan/list/list.h>
#include <ccan/array_size/array_size.h>
#include <ccan/str/str.h>

#include "fabrics.h"
#include "linux.h"
#include "ioctl.h"
#include "util.h"
#include "log.h"
#include "private.h"

#define NVMF_HOSTID_SIZE	37

#define NVMF_HOSTNQN_FILE	SYSCONFDIR "/nvme/hostnqn"
#define NVMF_HOSTID_FILE	SYSCONFDIR "/nvme/hostid"

const char *nvmf_dev = "/dev/nvme-fabrics";

/**
 * strchomp() - Strip trailing white space
 * @str: String to strip
 * @max: Maximum length of string
 */
static void strchomp(char *str, int max)
{
	int i;

	for (i = max - 1; i >= 0; i--) {
		if (str[i] != '\0' && str[i] != ' ')
			return;
		else
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

const char * const trtypes[] = {
	[NVMF_TRTYPE_RDMA]	= "rdma",
	[NVMF_TRTYPE_FC]	= "fc",
	[NVMF_TRTYPE_TCP]	= "tcp",
	[NVMF_TRTYPE_LOOP]	= "loop",
};

const char *nvmf_trtype_str(__u8 trtype)
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

const char *nvmf_adrfam_str(__u8 adrfam)
{
	return arg_str(adrfams, ARRAY_SIZE(adrfams), adrfam);
}

static const char * const subtypes[] = {
	[NVME_NQN_DISC]		= "discovery subsystem referral",
	[NVME_NQN_NVME]		= "nvme subsystem",
	[NVME_NQN_CURR]		= "current discovery subsystem",
};

const char *nvmf_subtype_str(__u8 subtype)
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

const char *nvmf_treq_str(__u8 treq)
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

const char *nvmf_eflags_str(__u16 eflags)
{
	return arg_str(eflags_strings, ARRAY_SIZE(eflags_strings), eflags);
}

static const char * const sectypes[] = {
	[NVMF_TCP_SECTYPE_NONE]		= "none",
	[NVMF_TCP_SECTYPE_TLS]		= "tls",
	[NVMF_TCP_SECTYPE_TLS13]	= "tls13",
};

const char *nvmf_sectype_str(__u8 sectype)
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

const char *nvmf_prtype_str(__u8 prtype)
{
	return arg_str(prtypes, ARRAY_SIZE(prtypes), prtype);
}

static const char * const qptypes[] = {
	[NVMF_RDMA_QPTYPE_CONNECTED]	= "connected",
	[NVMF_RDMA_QPTYPE_DATAGRAM]	= "datagram",
};

const char *nvmf_qptype_str(__u8 qptype)
{
	return arg_str(qptypes, ARRAY_SIZE(qptypes), qptype);
}

static const char * const cms[] = {
	[NVMF_RDMA_CMS_RDMA_CM]	= "rdma-cm",
};

const char *nvmf_cms_str(__u8 cm)
{
	return arg_str(cms, ARRAY_SIZE(cms), cm);
}

/*
 * Derived from Linux's supported options (the opt_tokens table)
 * when the mechanism to report supported options was added (f18ee3d988157).
 * Not all of these options may actually be supported,
 * but we retain the old behavior of passing all that might be.
 */
static const struct nvme_fabric_options default_supported_options = {
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

void nvmf_default_config(struct nvme_fabrics_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->tos = -1;
	cfg->ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO;
}

#define MERGE_CFG_OPTION(c, n, o, d)			\
	if ((c)->o == d) (c)->o = (n)->o
#define MERGE_CFG_OPTION_STR(c, n, o, d)		\
	if ((c)->o == d && (n)->o) (c)->o = strdup((n)->o)
static struct nvme_fabrics_config *merge_config(nvme_ctrl_t c,
		const struct nvme_fabrics_config *cfg)
{
	struct nvme_fabrics_config *ctrl_cfg = nvme_ctrl_get_config(c);

	MERGE_CFG_OPTION_STR(ctrl_cfg, cfg, host_traddr, NULL);
	MERGE_CFG_OPTION_STR(ctrl_cfg, cfg, host_iface, NULL);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, nr_io_queues, 0);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, nr_write_queues, 0);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, nr_poll_queues, 0);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, queue_size, 0);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, keep_alive_tmo, 0);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, reconnect_delay, 0);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, ctrl_loss_tmo,
			  NVMF_DEF_CTRL_LOSS_TMO);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, fast_io_fail_tmo, 0);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, tos, -1);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, keyring, 0);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, tls_key, 0);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, duplicate_connect, false);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, disable_sqflow, false);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, hdr_digest, false);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, data_digest, false);
	MERGE_CFG_OPTION(ctrl_cfg, cfg, tls, false);

	return ctrl_cfg;
}

#define UPDATE_CFG_OPTION(c, n, o, d)			\
	if ((n)->o != d) (c)->o = (n)->o
void nvmf_update_config(nvme_ctrl_t c, const struct nvme_fabrics_config *cfg)
{
	struct nvme_fabrics_config *ctrl_cfg = nvme_ctrl_get_config(c);

	UPDATE_CFG_OPTION(ctrl_cfg, cfg, host_traddr, NULL);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, host_iface, NULL);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, nr_io_queues, 0);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, nr_write_queues, 0);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, nr_poll_queues, 0);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, queue_size, 0);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, keep_alive_tmo, 0);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, reconnect_delay, 0);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, ctrl_loss_tmo,
			  NVMF_DEF_CTRL_LOSS_TMO);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, fast_io_fail_tmo, 0);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, tos, -1);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, keyring, 0);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, tls_key, 0);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, duplicate_connect, false);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, disable_sqflow, false);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, hdr_digest, false);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, data_digest, false);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, tls, false);
}

static int __add_bool_argument(char **argstr, char *tok, bool arg)
{
	char *nstr;

	if (!arg)
		return 0;
	if (asprintf(&nstr, "%s,%s", *argstr, tok) < 0) {
		errno = ENOMEM;
		return -1;
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
		errno = ENOMEM;
		return -1;
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
		errno = ENOMEM;
		return -1;
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
		errno = ENOMEM;
		return -1;
	}
	free(*argstr);
	*argstr = nstr;

	return 0;
}

#define add_bool_argument(o, argstr, tok, arg)				\
({									\
	int ret;							\
	if (r->options->tok) {						\
		ret = __add_bool_argument(argstr,			\
					  stringify(tok),		\
					  arg);				\
	} else {							\
		nvme_msg(r, LOG_DEBUG,					\
			 "option \"%s\" ignored\n",			\
			 stringify(tok));				\
		ret = 0;						\
	}								\
	ret;								\
})

#define add_int_argument(o, argstr, tok, arg, allow_zero) \
({									\
	int ret;							\
	if (r->options->tok) {						\
		ret = __add_int_argument(argstr,			\
					stringify(tok),			\
					arg,				\
					allow_zero);			\
	} else {							\
		nvme_msg(r, LOG_DEBUG,					\
			 "option \"%s\" ignored\n",			\
			 stringify(tok));				\
		ret = 0;						\
	}								\
	ret;								\
})

#define add_int_or_minus_one_argument(o, argstr, tok, arg)		\
({									\
	int ret;							\
	if (r->options->tok) {						\
		ret = __add_int_or_minus_one_argument(argstr,		\
						     stringify(tok),	\
						     arg);		\
	} else {							\
		nvme_msg(r, LOG_DEBUG,					\
			 "option \"%s\" ignored\n",			\
			 stringify(tok));				\
		ret = 0;						\
	}								\
	ret;								\
})

#define add_argument(r, argstr, tok, arg)				\
({									\
	int ret;							\
	if (r->options->tok) {						\
		ret = __add_argument(argstr,				\
				     stringify(tok),			\
				     arg);				\
	} else {							\
		nvme_msg(r, LOG_NOTICE,					\
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

static int inet6_pton(nvme_root_t r, const char *src, uint16_t port,
		      struct sockaddr_storage *addr)
{
	int ret = -EINVAL;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
	const char *scope = NULL;
	char *p;

	if (strlen(src) > INET6_ADDRSTRLEN)
		return -EINVAL;

	char  *tmp = strdup(src);
	if (!tmp) {
		nvme_msg(r, LOG_ERR, "cannot copy: %s\n", src);
		return -ENOMEM;
	}

	p = strchr(tmp, '%');
	if (p) {
		*p = '\0';
		scope = src + (p - tmp) + 1;
	}

	if (inet_pton(AF_INET6, tmp, &addr6->sin6_addr) != 1)
		goto free_tmp;

	if (IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr) && scope) {
		addr6->sin6_scope_id = if_nametoindex(scope);
		if (addr6->sin6_scope_id == 0) {
			nvme_msg(r, LOG_ERR,
				 "can't find iface index for: %s (%m)\n", scope);
			goto free_tmp;
		}
	}

	addr6->sin6_family = AF_INET6;
	addr6->sin6_port = htons(port);
	ret = 0;

free_tmp:
	free(tmp);
	return ret;
}

/**
 * inet_pton_with_scope - convert an IPv4/IPv6 to socket address
 * @r: nvme_root_t object
 * @af: address family, AF_INET, AF_INET6 or AF_UNSPEC for either
 * @src: the start of the address string
 * @trsvcid: transport service identifier
 * @addr: output socket address
 *
 * Return 0 on success, errno otherwise.
 */
static int inet_pton_with_scope(nvme_root_t r, int af,
				const char *src, const char * trsvcid,
				struct sockaddr_storage *addr)
{
	int      ret  = -EINVAL;
	uint16_t port = 0;

	if (trsvcid) {
		unsigned long long tmp = strtoull(trsvcid, NULL, 0);
		port = (uint16_t)tmp;
		if (tmp != port) {
			nvme_msg(r, LOG_ERR, "trsvcid out of range: %s\n",
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
		ret = inet6_pton(r, src, port, addr);
		break;
	case AF_UNSPEC:
		ret = inet4_pton(src, port, addr);
		if (ret)
			ret = inet6_pton(r, src, port, addr);
		break;
	default:
		nvme_msg(r, LOG_ERR, "unexpected address family %d\n", af);
	}

	return ret;
}

static bool traddr_is_hostname(nvme_root_t r, nvme_ctrl_t c)
{
	struct sockaddr_storage addr;

	if (!c->traddr)
		return false;
	if (strcmp(c->transport, "tcp") && strcmp(c->transport, "rdma"))
		return false;
	if (inet_pton_with_scope(r, AF_UNSPEC, c->traddr, c->trsvcid, &addr) == 0)
		return false;
	return true;
}

static int build_options(nvme_host_t h, nvme_ctrl_t c, char **argstr)
{
	struct nvme_fabrics_config *cfg = nvme_ctrl_get_config(c);
	const char *transport = nvme_ctrl_get_transport(c);
	const char *hostnqn, *hostid, *hostkey, *ctrlkey;
	bool discover = false, discovery_nqn = false;
	nvme_root_t r = h->r;

	if (!transport) {
		nvme_msg(h->r, LOG_ERR, "need a transport (-t) argument\n");
		errno = ENVME_CONNECT_TARG;
		return -1;
	}

	if (strncmp(transport, "loop", 4)) {
		if (!nvme_ctrl_get_traddr(c)) {
			nvme_msg(h->r, LOG_ERR, "need a address (-a) argument\n");
			errno = ENVME_CONNECT_AARG;
			return -1;
		}
	}

	/* always specify nqn as first arg - this will init the string */
	if (asprintf(argstr, "nqn=%s",
		     nvme_ctrl_get_subsysnqn(c)) < 0) {
		errno = ENOMEM;
		return -1;
	}
	if (!strcmp(nvme_ctrl_get_subsysnqn(c), NVME_DISC_SUBSYS_NAME)) {
		nvme_ctrl_set_discovery_ctrl(c, true);
		nvme_ctrl_set_unique_discovery_ctrl(c, false);
		discovery_nqn = true;
	}
	if (nvme_ctrl_is_discovery_ctrl(c))
		discover = true;
	hostnqn = nvme_host_get_hostnqn(h);
	hostid = nvme_host_get_hostid(h);
	hostkey = nvme_host_get_dhchap_key(h);
	if (!hostkey)
		hostkey = nvme_ctrl_get_dhchap_host_key(c);
	ctrlkey = nvme_ctrl_get_dhchap_key(c);
	if (add_argument(r, argstr, transport, transport) ||
	    add_argument(r, argstr, traddr,
			 nvme_ctrl_get_traddr(c)) ||
	    add_argument(r, argstr, host_traddr,
			 cfg->host_traddr) ||
	    add_argument(r, argstr, host_iface,
			 cfg->host_iface) ||
	    add_argument(r, argstr, trsvcid,
			 nvme_ctrl_get_trsvcid(c)) ||
	    (hostnqn && add_argument(r, argstr, hostnqn, hostnqn)) ||
	    (hostid && add_argument(r, argstr, hostid, hostid)) ||
	    (discover && !discovery_nqn &&
	     add_bool_argument(r, argstr, discovery, true)) ||
	    (!discover && hostkey &&
	     add_argument(r, argstr, dhchap_secret, hostkey)) ||
	    (!discover && ctrlkey &&
	     add_argument(r, argstr, dhchap_ctrl_secret, ctrlkey)) ||
	    (!discover &&
	     add_int_argument(r, argstr, nr_io_queues,
			      cfg->nr_io_queues, false)) ||
	    (!discover &&
	     add_int_argument(r, argstr, nr_write_queues,
			      cfg->nr_write_queues, false)) ||
	    (!discover &&
	     add_int_argument(r, argstr, nr_poll_queues,
			      cfg->nr_poll_queues, false)) ||
	    (!discover &&
	     add_int_argument(r, argstr, queue_size,
			      cfg->queue_size, false)) ||
	    add_int_argument(r, argstr, keep_alive_tmo,
			     cfg->keep_alive_tmo, false) ||
	    add_int_argument(r, argstr, reconnect_delay,
			     cfg->reconnect_delay, false) ||
	    (strcmp(transport, "loop") &&
	     add_int_or_minus_one_argument(r, argstr, ctrl_loss_tmo,
			      cfg->ctrl_loss_tmo)) ||
	    (strcmp(transport, "loop") &&
	     add_int_argument(r, argstr, fast_io_fail_tmo,
			      cfg->fast_io_fail_tmo, false)) ||
	    (strcmp(transport, "loop") &&
	     add_int_argument(r, argstr, tos, cfg->tos, true)) ||
	    add_int_argument(r, argstr, keyring, cfg->keyring, false) ||
	    (!strcmp(transport, "tcp") &&
	     add_int_argument(r, argstr, tls_key, cfg->tls_key, false)) ||
	    add_bool_argument(r, argstr, duplicate_connect,
			      cfg->duplicate_connect) ||
	    add_bool_argument(r, argstr, disable_sqflow,
			      cfg->disable_sqflow) ||
	    (!strcmp(transport, "tcp") &&
	     add_bool_argument(r, argstr, hdr_digest, cfg->hdr_digest)) ||
	    (!strcmp(transport, "tcp") &&
	     add_bool_argument(r, argstr, data_digest, cfg->data_digest)) ||
	    (!strcmp(transport, "tcp") &&
	     add_bool_argument(r, argstr, tls, cfg->tls))) {
		free(*argstr);
		return -1;
	}

	return 0;
}

#define parse_option(r, v, name)	   \
	if (!strcmp(v, stringify(name))) { \
		r->options->name = true;   \
		continue;		   \
	}

static  int __nvmf_supported_options(nvme_root_t r)
{
	char buf[0x1000], *options, *p, *v;
	int fd, ret;
	ssize_t len;

	if (r->options)
		return 0;

	r->options = calloc(1, sizeof(*r->options));
	if (!r->options)
		return -ENOMEM;

	fd = open(nvmf_dev, O_RDONLY);
	if (fd < 0) {
		nvme_msg(r, LOG_ERR, "Failed to open %s: %s\n",
			 nvmf_dev, strerror(errno));
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
			nvme_msg(r, LOG_DEBUG,
			         "Cannot read %s, using default options\n",
			         nvmf_dev);
			*r->options = default_supported_options;
			ret = 0;
			goto out_close;
		}

		nvme_msg(r, LOG_ERR, "Failed to read from %s: %s\n",
			 nvmf_dev, strerror(errno));
		ret = -ENVME_CONNECT_READ;
		goto out_close;
	}

	buf[len] = '\0';
	options = buf;

	nvme_msg(r, LOG_DEBUG, "kernel supports: ");

	while ((p = strsep(&options, ",\n")) != NULL) {
		if (!*p)
			continue;
		v = strsep(&p, "= ");
		if (!v)
			continue;
		nvme_msg(r, LOG_DEBUG, "%s ", v);

		parse_option(r, v, cntlid);
		parse_option(r, v, ctrl_loss_tmo);
		parse_option(r, v, data_digest);
		parse_option(r, v, dhchap_ctrl_secret);
		parse_option(r, v, dhchap_secret);
		parse_option(r, v, disable_sqflow);
		parse_option(r, v, discovery);
		parse_option(r, v, duplicate_connect);
		parse_option(r, v, fast_io_fail_tmo);
		parse_option(r, v, hdr_digest);
		parse_option(r, v, host_iface);
		parse_option(r, v, host_traddr);
		parse_option(r, v, hostid);
		parse_option(r, v, hostnqn);
		parse_option(r, v, instance);
		parse_option(r, v, keep_alive_tmo);
		parse_option(r, v, keyring);
		parse_option(r, v, nqn);
		parse_option(r, v, nr_io_queues);
		parse_option(r, v, nr_poll_queues);
		parse_option(r, v, nr_write_queues);
		parse_option(r, v, queue_size);
		parse_option(r, v, reconnect_delay);
		parse_option(r, v, tls);
		parse_option(r, v, tls_key);
		parse_option(r, v, tos);
		parse_option(r, v, traddr);
		parse_option(r, v, transport);
		parse_option(r, v, trsvcid);
	}
	nvme_msg(r, LOG_DEBUG, "\n");
	ret = 0;

out_close:
	close(fd);
	return ret;
}

static int __nvmf_add_ctrl(nvme_root_t r, const char *argstr)
{
	int ret, fd, len = strlen(argstr);
	char buf[0x1000], *options, *p;

	fd = open(nvmf_dev, O_RDWR);
	if (fd < 0) {
		nvme_msg(r, LOG_ERR, "Failed to open %s: %s\n",
			 nvmf_dev, strerror(errno));
		return -ENVME_CONNECT_OPEN;
	}

	nvme_msg(r, LOG_DEBUG, "connect ctrl, '%.*s'\n",
		 (int)strcspn(argstr,"\n"), argstr);
	ret = write(fd, argstr, len);
	if (ret != len) {
		nvme_msg(r, LOG_NOTICE, "Failed to write to %s: %s\n",
			 nvmf_dev, strerror(errno));
		switch (errno) {
		case EALREADY:
			ret = -ENVME_CONNECT_ALREADY;
			break;
		case EINVAL:
			ret = -ENVME_CONNECT_INVAL;
			break;
		case EADDRINUSE:
			ret = -ENVME_CONNECT_ADDRINUSE;
			break;
		case ENODEV:
			ret = -ENVME_CONNECT_NODEV;
			break;
		case EOPNOTSUPP:
			ret = -ENVME_CONNECT_OPNOTSUPP;
			break;
		case ECONNREFUSED:
			ret = -ENVME_CONNECT_CONNREFUSED;
			break;
		case EADDRNOTAVAIL:
			ret = -ENVME_CONNECT_ADDRNOTAVAIL;
			break;
		default:
			ret = -ENVME_CONNECT_WRITE;
			break;
		}
		goto out_close;
	}

	memset(buf, 0x0, sizeof(buf));
	len = read(fd, buf, sizeof(buf) - 1);
	if (len < 0) {
		nvme_msg(r, LOG_ERR, "Failed to read from %s: %s\n",
			 nvmf_dev, strerror(errno));
		ret = -ENVME_CONNECT_READ;
		goto out_close;
	}
	nvme_msg(r, LOG_DEBUG, "connect ctrl, response '%.*s'\n",
		 (int)strcspn(buf, "\n"), buf);
	buf[len] = '\0';
	options = buf;
	while ((p = strsep(&options, ",\n")) != NULL) {
		if (!*p)
			continue;
		if (sscanf(p, "instance=%d", &ret) == 1)
			goto out_close;
	}

	nvme_msg(r, LOG_ERR, "Failed to parse ctrl info for \"%s\"\n", argstr);
	ret = -ENVME_CONNECT_PARSE;
out_close:
	close(fd);
	return ret;
}

int nvmf_add_ctrl(nvme_host_t h, nvme_ctrl_t c,
		  const struct nvme_fabrics_config *cfg)
{
	nvme_subsystem_t s;
	const char *root_app, *app;
	char *argstr;
	int ret;

	/* highest prio have configs from command line */
	cfg = merge_config(c, cfg);

	/* apply configuration from config file (JSON) */
	s = nvme_lookup_subsystem(h, NULL, nvme_ctrl_get_subsysnqn(c));
	if (s) {
		nvme_ctrl_t fc;

		fc = __nvme_lookup_ctrl(s, nvme_ctrl_get_transport(c),
					nvme_ctrl_get_traddr(c),
					nvme_ctrl_get_host_traddr(c),
					nvme_ctrl_get_host_iface(c),
					nvme_ctrl_get_trsvcid(c),
					NULL);
		if (fc) {
			const char *key;

			cfg = merge_config(c, nvme_ctrl_get_config(fc));
			/*
			 * An authentication key might already been set
			 * in @cfg, so ensure to update @c with the correct
			 * controller key.
			 */
			key = nvme_ctrl_get_dhchap_host_key(fc);
			if (key)
				nvme_ctrl_set_dhchap_host_key(c, key);
			key = nvme_ctrl_get_dhchap_key(fc);
			if (key)
				nvme_ctrl_set_dhchap_key(c, key);
		}

	}

	root_app = nvme_root_get_application(h->r);
	app = nvme_subsystem_get_application(s);
	if (root_app) {
		/*
		 * configuration is managed by an application,
		 * refuse to act on subsystems which either have
		 * no application set or which habe a different
		 * application string.
		 */
		if (!app || strcmp(app, root_app)) {
			nvme_msg(h->r, LOG_INFO, "skip %s, not managed by %s\n",
				 nvme_subsystem_get_nqn(s), root_app);
			errno = ENVME_CONNECT_INVAL;
			return -1;
		}
	}

	nvme_ctrl_set_discovered(c, true);
	if (traddr_is_hostname(h->r, c)) {
		char *traddr = c->traddr;

		c->traddr = hostname2traddr(h->r, traddr);
		if (!c->traddr) {
			c->traddr = traddr;
			errno = ENVME_CONNECT_TRADDR;
			return -1;
		}
		free(traddr);
	}

	ret = __nvmf_supported_options(h->r);
	if (ret)
		return ret;
	ret = build_options(h, c, &argstr);
	if (ret)
		return ret;

	ret = __nvmf_add_ctrl(h->r, argstr);
	free(argstr);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}

	nvme_msg(h->r, LOG_INFO, "nvme%d: %s connected\n", ret,
		 nvme_ctrl_get_subsysnqn(c));
	return nvme_init_ctrl(h, c, ret);
}

nvme_ctrl_t nvmf_connect_disc_entry(nvme_host_t h,
				    struct nvmf_disc_log_entry *e,
				    const struct nvme_fabrics_config *cfg,
				    bool *discover)
{
	const char *transport;
	char *traddr = NULL, *trsvcid = NULL;
	nvme_ctrl_t c;
	int ret;

	switch (e->trtype) {
	case NVMF_TRTYPE_RDMA:
	case NVMF_TRTYPE_TCP:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_IP4:
		case NVMF_ADDR_FAMILY_IP6:
			traddr = e->traddr;
			trsvcid = e->trsvcid;
			break;
		default:
			nvme_msg(h->r, LOG_ERR,
				 "skipping unsupported adrfam %d\n",
				 e->adrfam);
			errno = EINVAL;
			return NULL;
		}
		break;
        case NVMF_TRTYPE_FC:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_FC:
			traddr = e->traddr;
			break;
		default:
			nvme_msg(h->r, LOG_ERR,
				 "skipping unsupported adrfam %d\n",
				 e->adrfam);
			errno = EINVAL;
			return NULL;
		}
		break;
	case NVMF_TRTYPE_LOOP:
		traddr = strlen(e->traddr) ? e->traddr : NULL;
		break;
	default:
		nvme_msg(h->r, LOG_ERR, "skipping unsupported transport %d\n",
			 e->trtype);
		errno = EINVAL;
		return NULL;
	}

	transport = nvmf_trtype_str(e->trtype);

	nvme_msg(h->r, LOG_DEBUG, "lookup ctrl "
		 "(transport: %s, traddr: %s, trsvcid %s)\n",
		 transport, traddr, trsvcid);
	c = nvme_create_ctrl(h->r, e->subnqn, transport, traddr,
			     cfg->host_traddr, cfg->host_iface, trsvcid);
	if (!c) {
		nvme_msg(h->r, LOG_DEBUG, "skipping discovery entry, "
			 "failed to allocate %s controller with traddr %s\n",
			 transport, traddr);
		errno = ENOMEM;
		return NULL;
	}

	switch (e->subtype) {
	case NVME_NQN_CURR:
		nvme_ctrl_set_discovered(c, true);
		nvme_ctrl_set_unique_discovery_ctrl(c,
				strcmp(e->subnqn, NVME_DISC_SUBSYS_NAME));
		break;
	case NVME_NQN_DISC:
		if (discover)
			*discover = true;
		nvme_ctrl_set_discovery_ctrl(c, true);
		nvme_ctrl_set_unique_discovery_ctrl(c,
				strcmp(e->subnqn, NVME_DISC_SUBSYS_NAME));
		break;
	default:
		nvme_msg(h->r, LOG_ERR, "unsupported subtype %d\n",
			 e->subtype);
		fallthrough;
	case NVME_NQN_NVME:
		nvme_ctrl_set_discovery_ctrl(c, false);
		nvme_ctrl_set_unique_discovery_ctrl(c, false);
		break;
	}

	if (nvme_ctrl_is_discovered(c)) {
		nvme_free_ctrl(c);
		errno = EAGAIN;
		return NULL;
	}

	if (e->treq & NVMF_TREQ_DISABLE_SQFLOW)
		c->cfg.disable_sqflow = true;

	if (e->trtype == NVMF_TRTYPE_TCP &&
	    (e->treq & NVMF_TREQ_REQUIRED ||
	     e->treq & NVMF_TREQ_NOT_REQUIRED))
		c->cfg.tls = true;

	ret = nvmf_add_ctrl(h, c, cfg);
	if (!ret)
		return c;

	if (errno == EINVAL && c->cfg.disable_sqflow) {
		errno = 0;
		/* disable_sqflow is unrecognized option on older kernels */
		nvme_msg(h->r, LOG_INFO, "failed to connect controller, "
			 "retry with disabling SQ flow control\n");
		c->cfg.disable_sqflow = false;
		ret = nvmf_add_ctrl(h, c, cfg);
		if (!ret)
			return c;
	}
	nvme_free_ctrl(c);
	return NULL;
}

static struct nvmf_discovery_log *nvme_discovery_log(nvme_ctrl_t c,
						     struct nvme_get_log_args *args,
						     int max_retries)
{
	nvme_root_t r = c->s && c->s->h ? c->s->h->r : NULL;
	struct nvmf_discovery_log *log = NULL;
	int ret, retries = 0;
	const char *name = nvme_ctrl_get_name(c);
	uint64_t genctr, numrec;
	unsigned int size;
	int fd = nvme_ctrl_get_fd(c);

	args->fd = fd;

	do {
		size = sizeof(struct nvmf_discovery_log);

		free(log);
		log = calloc(1, size);
		if (!log) {
			nvme_msg(r, LOG_ERR,
				 "could not allocate memory for discovery log header\n");
			errno = ENOMEM;
			return NULL;
		}

		nvme_msg(r, LOG_DEBUG, "%s: get header (try %d/%d)\n",
			name, retries, max_retries);
		args->rae = true;
		args->lpo = 0;
		args->len = size;
		args->log = log;
		ret = nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, args);
		if (ret) {
			nvme_msg(r, LOG_INFO,
				 "%s: discover try %d/%d failed, error %d\n",
				 name, retries, max_retries, errno);
			goto out_free_log;
		}

		numrec = le64_to_cpu(log->numrec);
		genctr = le64_to_cpu(log->genctr);

		if (numrec == 0)
			break;

		size = sizeof(struct nvmf_discovery_log) +
			sizeof(struct nvmf_disc_log_entry) * numrec;

		free(log);
		log = calloc(1, size);
		if (!log) {
			nvme_msg(r, LOG_ERR,
				 "could not alloc memory for discovery log page\n");
			errno = ENOMEM;
			return NULL;
		}

		nvme_msg(r, LOG_DEBUG,
			 "%s: get %" PRIu64
			 " records (length %d genctr %" PRIu64 ")\n",
			 name, numrec, size, genctr);

		args->rae = true;
		args->lpo = sizeof(struct nvmf_discovery_log);
		args->len = size - sizeof(struct nvmf_discovery_log);
		args->log = log->entries;
		ret = nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, args);
		if (ret) {
			nvme_msg(r, LOG_INFO,
				 "%s: discover try %d/%d failed, error %d\n",
				 name, retries, max_retries, errno);
			goto out_free_log;
		}

		/*
		 * If the log page was read with multiple Get Log Page commands,
		 * genctr must be checked afterwards to ensure atomicity
		 */
		nvme_msg(r, LOG_DEBUG, "%s: get header again\n", name);

		args->rae = false;
		args->lpo = 0;
		args->len = sizeof(struct nvmf_discovery_log);
		args->log = log;
		ret = nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, args);
		if (ret) {
			nvme_msg(r, LOG_INFO,
				 "%s: discover try %d/%d failed, error %d\n",
				 name, retries, max_retries, errno);
			goto out_free_log;
		}
	} while (genctr != le64_to_cpu(log->genctr) &&
		 ++retries < max_retries);

	if (genctr != le64_to_cpu(log->genctr)) {
		nvme_msg(r, LOG_INFO, "%s: discover genctr mismatch\n", name);
		errno = EAGAIN;
	} else if (numrec != le64_to_cpu(log->numrec)) {
		nvme_msg(r, LOG_INFO,
			 "%s: numrec changed unexpectedly "
			 "from %" PRIu64 " to %" PRIu64 "\n",
			 name, numrec, le64_to_cpu(log->numrec));
		errno = EBADSLT;
	} else {
		return log;
	}

out_free_log:
	free(log);
	return NULL;
}

static void sanitize_discovery_log_entry(struct nvmf_disc_log_entry  *e)
{
	switch (e->trtype) {
	case NVMF_TRTYPE_RDMA:
	case NVMF_TRTYPE_TCP:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_IP4:
		case NVMF_ADDR_FAMILY_IP6:
			strchomp(e->traddr, NVMF_TRADDR_SIZE);
			strchomp(e->trsvcid, NVMF_TRSVCID_SIZE);
			break;
		}
		break;
        case NVMF_TRTYPE_FC:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_FC:
			strchomp(e->traddr, NVMF_TRADDR_SIZE);
			break;
		}
		break;
	case NVMF_TRTYPE_LOOP:
		strchomp(e->traddr, NVMF_TRADDR_SIZE);
		break;
	}
}

int nvmf_get_discovery_log(nvme_ctrl_t c, struct nvmf_discovery_log **logp,
			   int max_retries)
{
	struct nvmf_discovery_log *log;

	struct nvme_get_log_args args = {
		.args_size = sizeof(args),
		.fd = nvme_ctrl_get_fd(c),
		.nsid = NVME_NSID_NONE,
		.lsp = NVMF_LOG_DISC_LSP_NONE,
		.lsi = NVME_LOG_LSI_NONE,
		.uuidx = NVME_UUID_NONE,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
		.lid = NVME_LOG_LID_DISCOVER,
		.log = NULL,
		.len = 0,
		.csi = NVME_CSI_NVM,
		.rae = false,
		.ot = false,
	};

	log = nvme_discovery_log(c, &args, max_retries);
	if (!log)
		return -1;

	for (int i = 0; i < le64_to_cpu(log->numrec); i++)
		sanitize_discovery_log_entry(&log->entries[i]);

	*logp = log;
	return 0;
}

struct nvmf_discovery_log *nvmf_get_discovery_wargs(struct nvme_get_discovery_args *args)
{
	struct nvmf_discovery_log *log;

	struct nvme_get_log_args _args = {
		.args_size = sizeof(_args),
		.fd = nvme_ctrl_get_fd(args->c),
		.nsid = NVME_NSID_NONE,
		.lsp = args->lsp,
		.lsi = NVME_LOG_LSI_NONE,
		.uuidx = NVME_UUID_NONE,
		.timeout = args->timeout,
		.result = args->result,
		.lid = NVME_LOG_LID_DISCOVER,
		.log = NULL,
		.len = 0,
		.csi = NVME_CSI_NVM,
		.rae = false,
		.ot = false,
	};

	log = nvme_discovery_log(args->c, &_args, args->max_retries);
	if (!log)
		return NULL;

	for (int i = 0; i < le64_to_cpu(log->numrec); i++)
		sanitize_discovery_log_entry(&log->entries[i]);

	return log;
}

#define PATH_UUID_IBM	"/proc/device-tree/ibm,partition-uuid"

static int uuid_from_device_tree(char *system_uuid)
{
	ssize_t len;
	int f;

	f = open(PATH_UUID_IBM, O_RDONLY);
	if (f < 0)
		return -ENXIO;

	memset(system_uuid, 0, NVME_UUID_LEN_STRING);
	len = read(f, system_uuid, NVME_UUID_LEN_STRING - 1);
	close(f);
	if (len < 0)
		return -ENXIO;

	return strlen(system_uuid) ? 0 : -ENXIO;
}

#define PATH_DMI_ENTRIES       "/sys/firmware/dmi/entries"

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

static int uuid_from_dmi_entries(char *system_uuid)
{
	int f;
	DIR *d;
	struct dirent *de;
	char buf[512] = {0};

	system_uuid[0] = '\0';
	d = opendir(PATH_DMI_ENTRIES);
	if (!d)
		return -ENXIO;
	while ((de = readdir(d))) {
		char filename[PATH_MAX];
		int len, type;

		if (de->d_name[0] == '.')
			continue;
		sprintf(filename, "%s/%s/type", PATH_DMI_ENTRIES, de->d_name);
		f = open(filename, O_RDONLY);
		if (f < 0)
			continue;
		len = read(f, buf, 512);
		close(f);
		if (len <= 0)
			continue;
		if (sscanf(buf, "%d", &type) != 1)
			continue;
		if (type != DMI_SYSTEM_INFORMATION)
			continue;
		sprintf(filename, "%s/%s/raw", PATH_DMI_ENTRIES, de->d_name);
		f = open(filename, O_RDONLY);
		if (f < 0)
			continue;
		len = read(f, buf, 512);
		close(f);

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
	closedir(d);
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
	FILE *stream;
	ssize_t nread;
	int ret;
	char *line = NULL;
	size_t len = 0;

	stream = fopen(PATH_DMI_PROD_UUID, "re");
	if (!stream)
		return -ENXIO;
	system_uuid[0] = '\0';

	nread = getline(&line, &len, stream);
	if (nread != NVME_UUID_LEN_STRING) {
		ret = -ENXIO;
		goto out;
	}

	/* The kernel is handling the byte swapping according DMTF
	 * SMBIOS 3.0 Section 7.2.1 System UUID */

	memcpy(system_uuid, line, NVME_UUID_LEN_STRING - 1);
	system_uuid[NVME_UUID_LEN_STRING - 1] = '\0';

	ret = 0;

out:
	free(line);
	fclose(stream);

	return ret;
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

char *nvmf_hostnqn_generate()
{
	char *hostnqn;
	int ret;
	char uuid_str[NVME_UUID_LEN_STRING];
	unsigned char uuid[NVME_UUID_LEN];

	ret = uuid_from_dmi(uuid_str);
	if (ret < 0) {
		ret = uuid_from_device_tree(uuid_str);
	}
	if (ret < 0) {
		if (nvme_uuid_random(uuid) < 0)
			memset(uuid, 0, NVME_UUID_LEN);
		nvme_uuid_to_string(uuid, uuid_str);
	}

	if (asprintf(&hostnqn, "nqn.2014-08.org.nvmexpress:uuid:%s", uuid_str) < 0)
		return NULL;

	return hostnqn;
}

static char *nvmf_read_file(const char *f, int len)
{
	char buf[len];
	int ret, fd;

	fd = open(f, O_RDONLY);
	if (fd < 0)
		return NULL;

	memset(buf, 0, len);
	ret = read(fd, buf, len - 1);
	close (fd);

	if (ret < 0 || !strlen(buf))
		return NULL;
	return strndup(buf, strcspn(buf, "\n"));
}

char *nvmf_hostnqn_from_file()
{
	return nvmf_read_file(NVMF_HOSTNQN_FILE, NVMF_NQN_SIZE);
}

char *nvmf_hostid_from_file()
{
	return nvmf_read_file(NVMF_HOSTID_FILE, NVMF_HOSTID_SIZE);
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
	tel += nvmf_exat_size(NVME_UUID_LEN);

	/* Symbolic name is optional */
	len = hostsymname ? strlen(hostsymname) : 0;
	if (len)
		tel += nvmf_exat_size(len);

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
static void nvmf_fill_die(struct nvmf_ext_die *die, struct nvme_host *h,
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
	exat->exatlen  = cpu_to_le16(nvmf_exat_len(NVME_UUID_LEN));
	nvme_uuid_from_string(h->hostid, exat->exatval);

	/* Extended Attribute for the Symbolic Name (optional) */
	symname_len = h->hostsymname ? strlen(h->hostsymname) : 0;
	if (symname_len) {
		__u16 exatlen = nvmf_exat_len(symname_len);

		numexat++;
		exat = nvmf_exat_ptr_next(exat);
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
static int nvmf_dim(nvme_ctrl_t c, enum nvmf_dim_tas tas, __u8 trtype,
		    __u8 adrfam, const char *reg_addr, union nvmf_tsas *tsas,
		    __u32 *result)
{
	nvme_root_t r = c->s && c->s->h ? c->s->h->r : NULL;
	struct nvmf_dim_data *dim;
	struct nvmf_ext_die  *die;
	__u32 tdl;
	__u32 tel;
	int ret;

	struct nvme_dim_args args = {
		.args_size = sizeof(args),
		.fd = nvme_ctrl_get_fd(c),
		.result = result,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.tas = tas
	};

	if (!c->s) {
		nvme_msg(r, LOG_ERR,
			 "%s: failed to perform DIM. subsystem undefined.\n",
			 c->name);
		errno = EINVAL;
		return -1;
	}

	if (!c->s->h) {
		nvme_msg(r, LOG_ERR,
			 "%s: failed to perform DIM. host undefined.\n",
			 c->name);
		errno = EINVAL;
		return -1;
	}

	if (!c->s->h->hostid) {
		nvme_msg(r, LOG_ERR,
			 "%s: failed to perform DIM. hostid undefined.\n",
			 c->name);
		errno = EINVAL;
		return -1;
	}

	if (!c->s->h->hostnqn) {
		nvme_msg(r, LOG_ERR,
			 "%s: failed to perform DIM. hostnqn undefined.\n",
			 c->name);
		errno = EINVAL;
		return -1;
	}

	if (strcmp(c->transport, "tcp")) {
		nvme_msg(r, LOG_ERR,
			 "%s: DIM only supported for TCP connections.\n",
			 c->name);
		errno = EINVAL;
		return -1;
	}

	/* Register one Discovery Information Entry (DIE) of size TEL */
	tel = nvmf_get_tel(c->s->h->hostsymname);
	tdl = sizeof(struct nvmf_dim_data) + tel;

	dim = (struct nvmf_dim_data *)calloc(1, tdl);
	if (!dim) {
		errno = ENOMEM;
		return -1;
	}

	dim->tdl    = cpu_to_le32(tdl);
	dim->nument = cpu_to_le64(1);    /* only one DIE to register */
	dim->entfmt = cpu_to_le16(NVMF_DIM_ENTFMT_EXTENDED);
	dim->etype  = cpu_to_le16(NVMF_DIM_ETYPE_HOST);
	dim->ektype = cpu_to_le16(0x5F); /* must be 0x5F per specs */

	memcpy(dim->eid, c->s->h->hostnqn,
	       MIN(sizeof(dim->eid), strlen(c->s->h->hostnqn)));

	ret = get_entity_name(dim->ename, sizeof(dim->ename));
	if (ret <= 0)
		nvme_msg(r, LOG_INFO, "%s: Failed to retrieve ENAME. %s.\n",
			 c->name, strerror(errno));

	ret = get_entity_version(dim->ever, sizeof(dim->ever));
	if (ret <= 0)
		nvme_msg(r, LOG_INFO, "%s: Failed to retrieve EVER.\n", c->name);

	die = &dim->die->extended;
	nvmf_fill_die(die, c->s->h, tel, trtype, adrfam, reg_addr, tsas);

	args.data_len = tdl;
	args.data = dim;
	ret = nvme_dim_send(&args);

	free(dim);

	return ret;
}

/**
 * nvme_get_adrfam() - Get address family for the address we're registering
 * with the DC.
 *
 * We retrieve this info from the socket itself. If we can't get the source
 * address from the socket, then we'll infer the address family from the
 * address of the DC since the DC address has the same address family.
 *
 * @ctrl: Host NVMe controller instance maintaining the admin queue used to
 *   submit the DIM command to the DC.
 *
 * Return: The address family of the source address associated with the
 *   socket connected to the DC.
 */
static __u8 nvme_get_adrfam(nvme_ctrl_t c)
{
	struct sockaddr_storage addr;
	__u8 adrfam = NVMF_ADDR_FAMILY_IP4;
	nvme_root_t r = c->s && c->s->h ? c->s->h->r : NULL;

	if (!inet_pton_with_scope(r, AF_UNSPEC, c->traddr, c->trsvcid, &addr)) {
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
static int nvme_fetch_cntrltype_dctype_from_id(nvme_ctrl_t c)
{
	struct nvme_id_ctrl id = { 0 };
	int ret;

	ret = nvme_ctrl_identify(c, &id);
	if (ret)
		return ret;

	if (!c->cntrltype) {
		if (id.cntrltype > NVME_CTRL_CNTRLTYPE_ADMIN || !cntrltype_str[id.cntrltype])
			c->cntrltype = strdup("reserved");
		else
			c->cntrltype = strdup(cntrltype_str[id.cntrltype]);
	}

	if (!c->dctype)	{
		if (id.dctype > NVME_CTRL_DCTYPE_CDC || !dctype_str[id.dctype])
			c->dctype = strdup("reserved");
		else
			c->dctype = strdup(dctype_str[id.dctype]);
	}
	return 0;
}

bool nvmf_is_registration_supported(nvme_ctrl_t c)
{
	if (!c->cntrltype || !c->dctype)
		if (nvme_fetch_cntrltype_dctype_from_id(c))
			return false;

	return !strcmp(c->dctype, "ddc") || !strcmp(c->dctype, "cdc");
}

int nvmf_register_ctrl(nvme_ctrl_t c, enum nvmf_dim_tas tas, __u32 *result)
{
	if (!nvmf_is_registration_supported(c)) {
		errno = ENOTSUP;
		return -1;
	}

	/* We're registering our source address with the DC. To do
	 * that, we can simply send an empty string. This tells the DC
	 * to retrieve the source address from the socket and use that
	 * as the registration address.
	 */
	return nvmf_dim(c, tas, NVMF_TRTYPE_TCP, nvme_get_adrfam(c), "", NULL, result);
}
