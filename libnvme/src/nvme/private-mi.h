// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 Code Construct Pty Ltd
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */

#pragma once

#ifdef CONFIG_MI

#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include <sys/socket.h>

#include <ccan/list/list.h>

#include <nvme/mi.h>

/* internal transport API */
struct libnvme_mi_req {
	struct nvme_mi_msg_hdr *hdr;
	size_t hdr_len;
	void *data;
	size_t data_len;
	__u32 mic;
};

struct libnvme_mi_resp {
	struct nvme_mi_msg_hdr *hdr;
	size_t hdr_len;
	void *data;
	size_t data_len;
	__u32 mic;
};

struct libnvme_mi_aem_ctx {
	struct nvme_mi_aem_occ_list_hdr *occ_header;
	struct nvme_mi_aem_occ_data *list_start;
	struct nvme_mi_aem_occ_data *list_current;
	int list_current_index;
	struct libnvme_mi_aem_config callbacks;
	int last_generation_num;
	struct libnvme_mi_event event;
};

struct libnvme_mi_ep {
	struct libnvme_global_ctx *ctx;
	const struct libnvme_mi_transport *transport;
	void *transport_data;
	struct list_node root_entry;
	struct list_head controllers;
	bool quirks_probed;
	bool controllers_scanned;
	unsigned int timeout;
	unsigned int mprt_max;
	unsigned long quirks;

	__u8 csi;

	/* inter-command delay, for LIBNVME_QUIRK_MIN_INTER_COMMAND_TIME */
	unsigned int inter_command_us;
	struct timespec last_resp_time;
	bool last_resp_time_valid;

	struct libnvme_mi_aem_ctx *aem_ctx;
};

struct libnvme_mi_transport {
	const char *name;
	bool mic_enabled;
	int (*submit)(struct libnvme_mi_ep *ep,
		      struct libnvme_mi_req *req,
		      struct libnvme_mi_resp *resp);
	void (*close)(struct libnvme_mi_ep *ep);
	int (*desc_ep)(struct libnvme_mi_ep *ep, char *buf, size_t len);
	int (*check_timeout)(struct libnvme_mi_ep *ep, unsigned int timeout);
	int (*aem_fd)(struct libnvme_mi_ep *ep);
	int (*aem_read)(struct libnvme_mi_ep *ep,
			  struct libnvme_mi_resp *resp);
	int (*aem_purge)(struct libnvme_mi_ep *ep);
};

struct libnvme_mi_ep *libnvme_mi_init_ep(struct libnvme_global_ctx *ctx);
void libnvme_mi_ep_probe(struct libnvme_mi_ep *ep);

/* for tests, we need to calculate the correct MICs */
__u32 libnvme_mi_crc32_update(__u32 crc, void *data, size_t len);

/* we have a facility to mock MCTP socket operations in the mi-mctp transport,
 * using this ops type. This should only be used for test, and isn't exposed
 * in the shared lib */;
struct mctp_ioc_tag_ctl;
struct __mi_mctp_socket_ops {
	int (*msg_socket)(void);
	int (*aem_socket)(__u8 eid, unsigned int network);
	ssize_t (*sendmsg)(int, const struct msghdr *, int);
	ssize_t (*recvmsg)(int, struct msghdr *, int);
	int (*poll)(struct pollfd *, nfds_t, int);
	int (*ioctl_tag)(int, unsigned long, struct mctp_ioc_tag_ctl *);
};
void __libnvme_mi_mctp_set_ops(const struct __mi_mctp_socket_ops *newops);

/* quirks */

/* Set a minimum time between receiving a response from one command and
 * sending the next request. Some devices may ignore new commands sent too soon
 * after the previous request, so manually insert a delay
 */
#define LIBNVME_QUIRK_MIN_INTER_COMMAND_TIME		(1 << 0)

/* Some devices may not support using CSI 1.  Attempting to set an
 * endpoint to use this with these devices should return an error
 */
#define LIBNVME_QUIRK_CSI_1_NOT_SUPPORTED		(1 << 1)

#endif

int __libnvme_transport_handle_open_mi(struct libnvme_transport_handle *hdl,
		const char *devname);
int __libnvme_transport_handle_init_mi(struct libnvme_transport_handle *hdl);
void __libnvme_transport_handle_close_mi(struct libnvme_transport_handle *hdl);
