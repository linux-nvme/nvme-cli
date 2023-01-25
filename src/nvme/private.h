// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 SUSE Software Solutions
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 */

#ifndef _LIBNVME_PRIVATE_H
#define _LIBNVME_PRIVATE_H

#include <ccan/list/list.h>
#include <poll.h>
#include <sys/socket.h>

#include "fabrics.h"
#include "mi.h"


extern const char *nvme_ctrl_sysfs_dir;
extern const char *nvme_subsys_sysfs_dir;
extern const char *nvme_ns_sysfs_dir;

struct nvme_path {
	struct list_node entry;
	struct list_node nentry;

	struct nvme_ctrl *c;
	struct nvme_ns *n;

	char *name;
	char *sysfs_dir;
	char *ana_state;
	int grpid;
};

struct nvme_ns {
	struct list_node entry;
	struct list_head paths;

	struct nvme_subsystem *s;
	struct nvme_ctrl *c;

	int fd;
	__u32 nsid;
	char *name;
	char *generic_name;
	char *sysfs_dir;

	int lba_shift;
	int lba_size;
	int meta_size;
	uint64_t lba_count;
	uint64_t lba_util;

	uint8_t eui64[8];
	uint8_t nguid[16];
	unsigned char uuid[NVME_UUID_LEN];
	enum nvme_csi csi;
};

struct nvme_ctrl {
	struct list_node entry;
	struct list_head paths;
	struct list_head namespaces;
	struct nvme_subsystem *s;

	int fd;
	char *name;
	char *sysfs_dir;
	char *address;
	char *firmware;
	char *model;
	char *state;
	char *numa_node;
	char *queue_count;
	char *serial;
	char *sqsize;
	char *transport;
	char *subsysnqn;
	char *traddr;
	char *trsvcid;
	char *dhchap_key;
	char *dhchap_ctrl_key;
	char *cntrltype;
	char *dctype;
	bool discovery_ctrl;
	bool unique_discovery_ctrl;
	bool discovered;
	bool persistent;
	struct nvme_fabrics_config cfg;
};

struct nvme_subsystem {
	struct list_node entry;
	struct list_head ctrls;
	struct list_head namespaces;
	struct nvme_host *h;

	char *name;
	char *sysfs_dir;
	char *subsysnqn;
	char *model;
	char *serial;
	char *firmware;
	char *subsystype;
};

struct nvme_host {
	struct list_node entry;
	struct list_head subsystems;
	struct nvme_root *r;

	char *hostnqn;
	char *hostid;
	char *dhchap_key;
	char *hostsymname;
	bool pdc_enabled;
	bool pdc_enabled_valid; /* set if pdc_enabled doesn't have an undefined
				 * value */
};

struct nvme_root {
	char *config_file;
	struct list_head hosts;
	struct list_head endpoints; /* MI endpoints */
	FILE *fp;
	int log_level;
	bool log_pid;
	bool log_timestamp;
	bool modified;
	bool mi_probe_enabled;
};

int nvme_set_attr(const char *dir, const char *attr, const char *value);

int json_read_config(nvme_root_t r, const char *config_file);

int json_update_config(nvme_root_t r, const char *config_file);

int json_dump_tree(nvme_root_t r);

nvme_ctrl_t __nvme_lookup_ctrl(nvme_subsystem_t s, const char *transport,
			       const char *traddr, const char *host_traddr,
			       const char *host_iface, const char *trsvcid,
			       nvme_ctrl_t p);

#if (LOG_FUNCNAME == 1)
#define __nvme_log_func __func__
#else
#define __nvme_log_func NULL
#endif

void __attribute__((format(printf, 4, 5)))
__nvme_msg(nvme_root_t r, int lvl, const char *func, const char *format, ...);

#define nvme_msg(r, lvl, format, ...)					\
	do {								\
		if ((lvl) <= MAX_LOGLEVEL)				\
			__nvme_msg(r, lvl, __nvme_log_func,		\
				   format, ##__VA_ARGS__);		\
	} while (0)

/* mi internal headers */

/* internal transport API */
struct nvme_mi_req {
	struct nvme_mi_msg_hdr *hdr;
	size_t hdr_len;
	void *data;
	size_t data_len;
	__u32 mic;
};

struct nvme_mi_resp {
	struct nvme_mi_msg_hdr *hdr;
	size_t hdr_len;
	void *data;
	size_t data_len;
	__u32 mic;
};

struct nvme_mi_transport {
	const char *name;
	bool mic_enabled;
	int (*submit)(struct nvme_mi_ep *ep,
		      struct nvme_mi_req *req,
		      struct nvme_mi_resp *resp);
	void (*close)(struct nvme_mi_ep *ep);
	int (*desc_ep)(struct nvme_mi_ep *ep, char *buf, size_t len);
	int (*check_timeout)(struct nvme_mi_ep *ep, unsigned int timeout);
};

/* quirks */

/* Set a minimum time between receiving a response from one command and
 * sending the next request. Some devices may ignore new commands sent too soon
 * after the previous request, so manually insert a delay
 */
#define NVME_QUIRK_MIN_INTER_COMMAND_TIME	(1 << 0)

struct nvme_mi_ep {
	struct nvme_root *root;
	const struct nvme_mi_transport *transport;
	void *transport_data;
	struct list_node root_entry;
	struct list_head controllers;
	bool controllers_scanned;
	unsigned int timeout;
	unsigned int mprt_max;
	unsigned long quirks;

	/* inter-command delay, for NVME_QUIRK_MIN_INTER_COMMAND_TIME */
	unsigned int inter_command_us;
	struct timespec last_resp_time;
	bool last_resp_time_valid;
};

struct nvme_mi_ctrl {
	struct nvme_mi_ep	*ep;
	__u16			id;
	struct list_node	ep_entry;
};

struct nvme_mi_ep *nvme_mi_init_ep(struct nvme_root *root);
void nvme_mi_ep_probe(struct nvme_mi_ep *ep);

/* for tests, we need to calculate the correct MICs */
__u32 nvme_mi_crc32_update(__u32 crc, void *data, size_t len);

/* we have a facility to mock MCTP socket operations in the mi-mctp transport,
 * using this ops type. This should only be used for test, and isn't exposed
 * in the shared lib */;
struct mctp_ioc_tag_ctl;
struct __mi_mctp_socket_ops {
	int (*socket)(int, int, int);
	ssize_t (*sendmsg)(int, const struct msghdr *, int);
	ssize_t (*recvmsg)(int, struct msghdr *, int);
	int (*poll)(struct pollfd *, nfds_t, int);
	int (*ioctl_tag)(int, unsigned long, struct mctp_ioc_tag_ctl *);
};
void __nvme_mi_mctp_set_ops(const struct __mi_mctp_socket_ops *newops);

#endif /* _LIBNVME_PRIVATE_H */
