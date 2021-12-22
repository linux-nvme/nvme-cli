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

#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>

#include <ccan/endian/endian.h>
#include <ccan/list/list.h>
#include <ccan/array_size/array_size.h>

#include "fabrics.h"
#include "linux.h"
#include "ioctl.h"
#include "util.h"
#include "log.h"
#include "private.h"

#define NVMF_HOSTID_SIZE	37
#define UUID_SIZE		37  /* 1b4e28ba-2fa1-11d2-883f-0016d3cca427 + \0 */

const char *nvmf_dev = "/dev/nvme-fabrics";
const char *nvmf_hostnqn_file = "/etc/nvme/hostnqn";
const char *nvmf_hostid_file = "/etc/nvme/hostid";

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
	[NVMF_TREQ_DISABLE_SQFLOW]	= "not specified, "
					  "sq flow control disable supported",
};

const char *nvmf_treq_str(__u8 treq)
{
	return arg_str(treqs, ARRAY_SIZE(treqs), treq);
}

static const char * const eflags_strings[] = {
	[NVMF_DISC_EFLAGS_NONE]		= "not specified",
	[NVMF_DISC_EFLAGS_EPCSD]	= "explicit discovery connections",
	[NVMF_DISC_EFLAGS_DUPRETINFO]	= "duplicate discovery information",
	[NVMF_DISC_EFLAGS_BOTH]		= "explicit discovery connections, "
					  "duplicate discovery information",
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

void nvmf_default_config(struct nvme_fabrics_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->tos = -1;
	cfg->ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO;
}

#define UPDATE_CFG_OPTION(c, n, o, d)			\
	if ((c)->o == d) (c)->o = (n)->o
static struct nvme_fabrics_config *merge_config(nvme_ctrl_t c,
		const struct nvme_fabrics_config *cfg)
{
	struct nvme_fabrics_config *ctrl_cfg = nvme_ctrl_get_config(c);

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
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, duplicate_connect, false);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, disable_sqflow, false);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, hdr_digest, false);
	UPDATE_CFG_OPTION(ctrl_cfg, cfg, data_digest, false);

	return ctrl_cfg;
}

static int add_bool_argument(char **argstr, char *tok, bool arg)
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

static int add_int_argument(char **argstr, char *tok, int arg, bool allow_zero)
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

static int add_argument(char **argstr, const char *tok, const char *arg)
{
	char *nstr;

	if (!(arg && strcmp(arg, "none")))
		return 0;
	if (asprintf(&nstr, "%s,%s=%s", *argstr, tok, arg) < 0) {
		errno = ENOMEM;
		return -1;
	}
	free(*argstr);
	*argstr = nstr;

	return 0;
}

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

static int inet6_pton(const char *src, uint16_t port,
		      struct sockaddr_storage *addr)
{
	int ret = -EINVAL;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;

	if (strlen(src) > INET6_ADDRSTRLEN)
		return -EINVAL;

	char  *tmp = strdup(src);
	if (!tmp)
		nvme_msg(LOG_ERR, "cannot copy: %s\n", src);

	const char *scope = NULL;
	char *p = strchr(tmp, SCOPE_DELIMITER);
	if (p) {
		*p = '\0';
		scope = src + (p - tmp) + 1;
	}

	if (inet_pton(AF_INET6, tmp, &addr6->sin6_addr) != 1)
		goto free_tmp;

	if (IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr) && scope) {
		addr6->sin6_scope_id = if_nametoindex(scope);
		if (addr6->sin6_scope_id == 0) {
			nvme_msg(LOG_ERR,
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
 * @af: address family, AF_INET, AF_INET6 or AF_UNSPEC for either
 * @src: the start of the address string
 * @addr: output socket address
 *
 * Return 0 on success, errno otherwise.
 */
static int inet_pton_with_scope(int af, const char *src, const char * trsvcid,
				struct sockaddr_storage *addr)
{
	int      ret  = -EINVAL;
	uint16_t port = 0;

	if (trsvcid) {
		unsigned long long tmp = strtoull(trsvcid, NULL, 0);
		port = (uint16_t)tmp;
		if (tmp != port) {
			nvme_msg(LOG_ERR, "trsvcid out of range: %s\n", trsvcid);
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
		ret = inet6_pton(src, port, addr);
		break;
	case AF_UNSPEC:
		ret = inet4_pton(src, port, addr);
		if (ret)
			ret = inet6_pton(src, port, addr);
		break;
	default:
		nvme_msg(LOG_ERR, "unexpected address family %d\n", af);
	}

	return ret;
}

static bool traddr_is_hostname(nvme_ctrl_t c)
{
	struct sockaddr_storage addr;

	if (!c->traddr)
		return false;
	if (strcmp(c->transport, "tcp") && strcmp(c->transport, "rdma"))
		return false;
	if (inet_pton_with_scope(AF_UNSPEC, c->traddr, c->trsvcid, &addr) == 0)
		return false;
	return true;
}

static int hostname2traddr(nvme_ctrl_t c)
{
	struct addrinfo *host_info, hints = {.ai_family = AF_UNSPEC};
	char addrstr[NVMF_TRADDR_SIZE];
	const char *p;
	int ret;

	ret = getaddrinfo(c->traddr, NULL, &hints, &host_info);
	if (ret) {
		nvme_msg(LOG_ERR, "failed to resolve host %s info\n", c->traddr);
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
		nvme_msg(LOG_ERR, "unrecognized address family (%d) %s\n",
			host_info->ai_family, c->traddr);
		ret = -EINVAL;
		goto free_addrinfo;
	}

	if (!p) {
		nvme_msg(LOG_ERR, "failed to get traddr for %s\n", c->traddr);
		ret = -errno;
		goto free_addrinfo;
	}
	c->traddr = strdup(addrstr);

free_addrinfo:
	freeaddrinfo(host_info);
	return ret;
}

static int build_options(nvme_host_t h, nvme_ctrl_t c, char **argstr)
{
	struct nvme_fabrics_config *cfg = nvme_ctrl_get_config(c);
	const char *transport = nvme_ctrl_get_transport(c);
	const char *hostnqn, *hostid, *hostkey, *ctrlkey;
	bool discover = false, discovery_nqn = false;

	if (!transport) {
		nvme_msg(LOG_ERR, "need a transport (-t) argument\n");
		errno = EINVAL;
		return -1;
	}

	if (strncmp(transport, "loop", 4)) {
		if (!nvme_ctrl_get_traddr(c)) {
			nvme_msg(LOG_ERR, "need a address (-a) argument\n");
			errno = EINVAL;
			return -1;
		}
		/* Use the default ctrl loss timeout if unset */
                if (cfg->ctrl_loss_tmo == -1)
			cfg->ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO;
	}

	/* always specify nqn as first arg - this will init the string */
	if (asprintf(argstr, "nqn=%s",
		     nvme_ctrl_get_subsysnqn(c)) < 0) {
		errno = ENOMEM;
		return -1;
	}
	if (!strcmp(nvme_ctrl_get_subsysnqn(c), NVME_DISC_SUBSYS_NAME)) {
		nvme_ctrl_set_discovery_ctrl(c, true);
		discovery_nqn = true;
	}
	if (nvme_ctrl_is_discovery_ctrl(c))
		discover = true;
	hostnqn = nvme_host_get_hostnqn(h);
	hostid = nvme_host_get_hostid(h);
	hostkey = nvme_host_get_dhchap_key(h);
	ctrlkey = nvme_ctrl_get_dhchap_key(c);
	if (add_argument(argstr, "transport", transport) ||
	    add_argument(argstr, "traddr",
			 nvme_ctrl_get_traddr(c)) ||
	    add_argument(argstr, "host_traddr",
			 nvme_ctrl_get_host_traddr(c)) ||
	    add_argument(argstr, "host_iface",
			 nvme_ctrl_get_host_iface(c)) ||
	    add_argument(argstr, "trsvcid",
			 nvme_ctrl_get_trsvcid(c)) ||
	    (hostnqn && add_argument(argstr, "hostnqn", hostnqn)) ||
	    (hostid && add_argument(argstr, "hostid", hostid)) ||
	    (discover && !discovery_nqn &&
	     add_bool_argument(argstr, "discovery", true)) ||
	    (!discover && hostkey &&
	     add_argument(argstr, "dhchap_secret", hostkey)) ||
	    (!discover && ctrlkey &&
	     add_argument(argstr, "dhchap_ctrl_secret", ctrlkey)) ||
	    (!discover &&
	     add_int_argument(argstr, "nr_io_queues",
			      cfg->nr_io_queues, false)) ||
	    (!discover &&
	     add_int_argument(argstr, "nr_write_queues",
			      cfg->nr_write_queues, false)) ||
	    (!discover &&
	     add_int_argument(argstr, "nr_poll_queues",
			      cfg->nr_poll_queues, false)) ||
	    (!discover &&
	     add_int_argument(argstr, "queue_size",
			      cfg->queue_size, false)) ||
	    add_int_argument(argstr, "keep_alive_tmo",
			     cfg->keep_alive_tmo, false) ||
	    add_int_argument(argstr, "reconnect_delay",
			     cfg->reconnect_delay, false) ||
	    (strcmp(transport, "loop") &&
	     add_int_argument(argstr, "ctrl_loss_tmo",
			      cfg->ctrl_loss_tmo, false)) ||
	    (strcmp(transport, "loop") &&
	     add_int_argument(argstr, "fast_io_fail_tmo",
			      cfg->fast_io_fail_tmo, false)) ||
	    (strcmp(transport, "loop") &&
	     add_int_argument(argstr, "tos", cfg->tos, true)) ||
	    add_bool_argument(argstr, "duplicate_connect",
			      cfg->duplicate_connect) ||
	    add_bool_argument(argstr, "disable_sqflow",
			      cfg->disable_sqflow) ||
	    (!strcmp(transport, "tcp") &&
	     add_bool_argument(argstr, "hdr_digest", cfg->hdr_digest)) ||
	    (!strcmp(transport, "tcp") &&
	     add_bool_argument(argstr, "data_digest", cfg->data_digest))) {
		free(*argstr);
		return -1;
	}

	return 0;
}

static int __nvmf_add_ctrl(const char *argstr)
{
	int ret, fd, len = strlen(argstr);
	char buf[0x1000], *options, *p;

	fd = open(nvmf_dev, O_RDWR);
	if (fd < 0) {
		nvme_msg(LOG_ERR, "Failed to open %s: %s\n",
			 nvmf_dev, strerror(errno));
		return -1;
	}

	nvme_msg(LOG_DEBUG, "connect ctrl, '%.*s'\n",
		 (int)strcspn(argstr,"\n"), argstr);
	ret = write(fd, argstr, len);
	if (ret != len) {
		nvme_msg(LOG_NOTICE, "Failed to write to %s: %s\n",
			 nvmf_dev, strerror(errno));
		ret = -1;
		goto out_close;
	}

	len = read(fd, buf, sizeof(buf));
	if (len < 0) {
		nvme_msg(LOG_ERR, "Failed to read from %s: %s\n",
			 nvmf_dev, strerror(errno));
		ret = -1;
		goto out_close;
	}
	nvme_msg(LOG_DEBUG, "connect ctrl, response '%.*s'\n",
		 (int)strcspn(buf, "\n"), buf);
	buf[len] = '\0';
	options = buf;
	while ((p = strsep(&options, ",\n")) != NULL) {
		if (!*p)
			continue;
		if (sscanf(p, "instance=%d", &ret) == 1)
			goto out_close;
	}

	nvme_msg(LOG_ERR, "Failed to parse ctrl info for \"%s\"\n", argstr);
	errno = EINVAL;
	ret = -1;
out_close:
	close(fd);
	return ret;
}

int nvmf_add_ctrl_opts(nvme_ctrl_t c, struct nvme_fabrics_config *cfg)
{
	nvme_subsystem_t s = nvme_ctrl_get_subsystem(c);
	nvme_host_t h = nvme_subsystem_get_host(s);
	char *argstr;
	int ret;

	cfg = merge_config(c, cfg);
	if (traddr_is_hostname(c)) {
		ret = hostname2traddr(c);
		if (ret)
			return ret;
	}

	ret = build_options(h, c, &argstr);
	if (ret)
		return ret;

	ret = __nvmf_add_ctrl(argstr);
	free(argstr);
	if (ret >= 0)
		nvme_msg(LOG_INFO, "nvme%d: ctrl connected\n", ret);
	return ret;
}

int nvmf_add_ctrl(nvme_host_t h, nvme_ctrl_t c,
		  const struct nvme_fabrics_config *cfg,
		  bool disable_sqflow)
{
	char *argstr;
	int ret;

	cfg = merge_config(c, cfg);
	nvme_ctrl_disable_sqflow(c, disable_sqflow);
	nvme_ctrl_set_discovered(c, true);
	if (traddr_is_hostname(c)) {
		ret = hostname2traddr(c);
		if (ret)
			return ret;
	}

	ret = build_options(h, c, &argstr);
	if (ret)
		return ret;

	ret = __nvmf_add_ctrl(argstr);
	free(argstr);
	if (ret < 0)
		return ret;

	nvme_msg(LOG_INFO, "nvme%d: ctrl connected\n", ret);
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
	bool disable_sqflow = false;
	int ret;

	switch (e->trtype) {
	case NVMF_TRTYPE_RDMA:
	case NVMF_TRTYPE_TCP:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_IP4:
		case NVMF_ADDR_FAMILY_IP6:
			nvme_chomp(e->traddr, NVMF_TRADDR_SIZE);
			nvme_chomp(e->trsvcid, NVMF_TRSVCID_SIZE);
			traddr = e->traddr;
			trsvcid = e->trsvcid;
			break;
		default:
			nvme_msg(LOG_ERR, "skipping unsupported adrfam %d\n",
				 e->adrfam);
			errno = EINVAL;
			return NULL;
		}
		break;
        case NVMF_TRTYPE_FC:
		switch (e->adrfam) {
		case NVMF_ADDR_FAMILY_FC:
			nvme_chomp(e->traddr, NVMF_TRADDR_SIZE),
			traddr = e->traddr;
			trsvcid = NULL;
			break;
		default:
			nvme_msg(LOG_ERR, "skipping unsupported adrfam %d\n",
				 e->adrfam);
			errno = EINVAL;
			return NULL;
		}
	case NVMF_TRTYPE_LOOP:
		break;
	default:
		nvme_msg(LOG_ERR, "skipping unsupported transport %d\n",
			 e->trtype);
		errno = EINVAL;
		return NULL;
	}

	transport = nvmf_trtype_str(e->trtype);

	nvme_msg(LOG_DEBUG, "lookup ctrl "
		 "(transport: %s, traddr: %s, trsvcid %s)\n",
		 transport, traddr, trsvcid);
	c = nvme_create_ctrl(e->subnqn, transport, traddr, NULL, NULL, trsvcid);
	if (!c) {
		nvme_msg(LOG_DEBUG, "skipping discovery entry, "
			 "failed to allocate %s controller with traddr %s\n",
			 transport, traddr);
		errno = ENOMEM;
		return NULL;
	}

	switch (e->subtype) {
	case NVME_NQN_CURR:
		nvme_ctrl_set_discovered(c, true);
		break;
	case NVME_NQN_DISC:
		if (discover)
			*discover = true;
		nvme_ctrl_set_discovery_ctrl(c, true);
		break;
	default:
		nvme_msg(LOG_ERR, "unsupported subtype %d\n",
			 e->subtype);
		/* fallthrough */
	case NVME_NQN_NVME:
		nvme_ctrl_set_discovery_ctrl(c, false);
		break;
	}

	if (nvme_ctrl_is_discovered(c)) {
		errno = EAGAIN;
		return NULL;
	}

	if (e->treq & NVMF_TREQ_DISABLE_SQFLOW)
		disable_sqflow = true;

	ret = nvmf_add_ctrl(h, c, cfg, disable_sqflow);
	if (!ret)
		return c;

	if (errno == EINVAL && disable_sqflow) {
		errno = 0;
		/* disable_sqflow is unrecognized option on older kernels */
		nvme_msg(LOG_INFO, "failed to connect controller, "
			 "retry with disabling SQ flow control\n");
		disable_sqflow = false;
		ret = nvmf_add_ctrl(h, c, cfg, disable_sqflow);
		if (!ret)
			return c;
	}
	nvme_msg(LOG_ERR, "failed to connect controller, error %d\n", errno);
	nvme_free_ctrl(c);
	return NULL;
}

static int nvme_discovery_log(int fd, __u32 len, struct nvmf_discovery_log *log, bool rae)
{
	return __nvme_get_log_page(fd, 0, NVME_LOG_LID_DISCOVER, rae, 512,
				   len, log);
}

int nvmf_get_discovery_log(nvme_ctrl_t c, struct nvmf_discovery_log **logp,
			   int max_retries)
{
	struct nvmf_discovery_log *log;
	int hdr, ret, retries = 0;
	const char *name = nvme_ctrl_get_name(c);
	uint64_t genctr, numrec;
	unsigned int size;

	hdr = sizeof(struct nvmf_discovery_log);
	log = malloc(hdr);
	if (!log) {
		nvme_msg(LOG_ERR,
			 "could not allocate memory for discovery log header\n");
		errno = ENOMEM;
		return -1;
	}
	memset(log, 0, hdr);

	nvme_msg(LOG_DEBUG, "%s: discover length %d\n", name, 0x100);
	ret = nvme_discovery_log(nvme_ctrl_get_fd(c), 0x100, log, true);
	if (ret) {
		nvme_msg(LOG_INFO, "%s: discover failed, error %d\n",
			 name, errno);
		goto out_free_log;
	}

	do {
		numrec = le64_to_cpu(log->numrec);
		genctr = le64_to_cpu(log->genctr);

		if (numrec == 0) {
			*logp = log;
			return 0;
		}

		size = sizeof(struct nvmf_discovery_log) +
			sizeof(struct nvmf_disc_log_entry) * (numrec);

		free(log);
		log = malloc(size);
		if (!log) {
			nvme_msg(LOG_ERR,
				 "could not alloc memory for discovery log page\n");
			errno = ENOMEM;
			return -1;
		}
		memset(log, 0, size);

		nvme_msg(LOG_DEBUG, "%s: discover length %d\n", name, size);
		ret = nvme_discovery_log(nvme_ctrl_get_fd(c), size, log, false);
		if (ret) {
			nvme_msg(LOG_INFO,
				 "%s: discover try %d/%d failed, error %d\n",
				 name, retries, max_retries, errno);
			goto out_free_log;
		}

		genctr = le64_to_cpu(log->genctr);
		nvme_msg(LOG_DEBUG, "%s: discover genctr %lu, retry\n",
			 name, genctr);
		ret = nvme_discovery_log(nvme_ctrl_get_fd(c), hdr, log, true);
		if (ret) {
			nvme_msg(LOG_INFO,
				 "%s: discover try %d/%d failed, error %d\n",
				 name, retries, max_retries, errno);
			goto out_free_log;
		}
	} while (genctr != le64_to_cpu(log->genctr) &&
		 ++retries < max_retries);

	if (genctr != le64_to_cpu(log->genctr)) {
		nvme_msg(LOG_INFO, "%s: discover genctr mismatch\n", name);
		errno = EAGAIN;
		ret = -1;
	} else if (numrec != le64_to_cpu(log->numrec)) {
		nvme_msg(LOG_INFO, "%s: could only fetch %lu of %lu records\n",
			 name, numrec, le64_to_cpu(log->numrec));
		errno = EBADSLT;
		ret = -1;
	} else {
		*logp = log;
		return 0;
	}

out_free_log:
	free(log);
	return ret;
}

#define PATH_UUID_IBM	"/proc/device-tree/ibm,partition-uuid"

static int uuid_from_device_tree(char *system_uuid)
{
	ssize_t len;
	int f;

	f = open(PATH_UUID_IBM, O_RDONLY);
	if (f < 0)
		return -ENXIO;

	memset(system_uuid, 0, UUID_SIZE);
	len = read(f, system_uuid, UUID_SIZE - 1);
	close(f);
	if (len < 0)
		return -ENXIO;

	return strlen(system_uuid) ? 0 : -ENXIO;
}

#define PATH_DMI_ENTRIES       "/sys/firmware/dmi/entries"

static int uuid_from_dmi_entries(char *system_uuid)
{
	int f;
	DIR *d;
	struct dirent *de;
	char buf[512];

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
		if (len < 0)
			continue;
		if (sscanf(buf, "%d", &type) != 1)
			continue;
		if (type != 1)
			continue;
		sprintf(filename, "%s/%s/raw", PATH_DMI_ENTRIES, de->d_name);
		f = open(filename, O_RDONLY);
		if (f < 0)
			continue;
		len = read(f, buf, 512);
		close(f);
		if (len < 0)
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

/**
 * @brief Get system UUID from /sys/class/dmi/id/product_uuid and fix
 *        endianess.
 *
 * @param system_uuid - Where to save the system UUID.
 *
 * @return 0 on success, -ENXIO otherwise.
 */
#define PATH_DMI_PROD_UUID  "/sys/class/dmi/id/product_uuid"
static int uuid_from_product_uuid(char *system_uuid)
{
	FILE *stream = NULL;
	int   ret    = -ENXIO;

	system_uuid[0] = '\0';

	if ((stream = fopen(PATH_DMI_PROD_UUID, "re")) != NULL) {
		char    *line  = NULL;
		size_t   len   = 0;
		ssize_t  nread = getline(&line, &len, stream);

		if (nread == UUID_SIZE) {
			/* Per "DMTF SMBIOS 3.0 Section 7.2.1 System UUID", the
			 * UUID retrieved from the DMI has the wrong endianess.
			 * The following copies "line" to "system_uuid" while
			 * swapping from little-endian to network-endian. */
			static const int swaptbl[] = {
				6,7,4,5,2,3,0,1,8,11,12,9,10,13,16,17,14,15,18,19,
				20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,
				-1 /* sentinel */
			};
			int i;

			for (i = 0; swaptbl[i] != -1; i++)
				system_uuid[i] = line[swaptbl[i]];
			system_uuid[UUID_SIZE-1] = '\0';

			ret = 0;
		}

		free(line);
		fclose(stream);
	}

	return ret;
}

/**
 * @brief The system UUID can be read from two different locations:
 *
 *     1) /sys/class/dmi/id/product_uuid
 *     2) /sys/firmware/dmi/entries
 *
 * Note that the second location is not present on Debian-based systems.
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
	char uuid_str[UUID_SIZE];
#ifdef CONFIG_LIBUUID
	uuid_t uuid;
#endif

	ret = uuid_from_dmi(uuid_str);
	if (ret < 0) {
		ret = uuid_from_device_tree(uuid_str);
	}
#ifdef CONFIG_LIBUUID
	if (ret < 0) {
		uuid_generate_random(uuid);
		uuid_unparse_lower(uuid, uuid_str);
		ret = 0;
	}
#endif
	if (ret < 0)
		return NULL;

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
	return nvmf_read_file(nvmf_hostnqn_file, NVMF_NQN_SIZE);
}

char *nvmf_hostid_from_file()
{
	return nvmf_read_file(nvmf_hostid_file, NVMF_HOSTID_SIZE);
}
