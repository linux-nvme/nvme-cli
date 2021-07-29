// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 Code Construct Pty Ltd
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#if HAVE_LINUX_MCTP_H
#include <linux/mctp.h>
#endif

#include <ccan/endian/endian.h>

#include "private.h"
#include "log.h"
#include "mi.h"


#if !defined(AF_MCTP)
#define AF_MCTP 45
#endif

#if !HAVE_LINUX_MCTP_H
/* As of kernel v5.15, these AF_MCTP-related definitions are provided by
 * linux/mctp.h. However, we provide a set here while that header percolates
 * through to standard includes.
 *
 * These were all introduced in the same version as AF_MCTP was defined,
 * so we can key off the presence of that.
 */

typedef __u8			mctp_eid_t;

struct mctp_addr {
	mctp_eid_t		s_addr;
};

struct sockaddr_mctp {
	unsigned short int	smctp_family;
	__u16			__smctp_pad0;
	unsigned int		smctp_network;
	struct mctp_addr	smctp_addr;
	__u8			smctp_type;
	__u8			smctp_tag;
	__u8			__smctp_pad1;
};

#define MCTP_NET_ANY		0x0

#define MCTP_ADDR_NULL		0x00
#define MCTP_ADDR_ANY		0xff

#define MCTP_TAG_MASK		0x07
#define MCTP_TAG_OWNER		0x08

#endif /* !AF_MCTP */

#define MCTP_TYPE_NVME		0x04
#define MCTP_TYPE_MIC		0x80

struct nvme_mi_transport_mctp {
	int	net;
	__u8	eid;
	int	sd;
};

static const struct nvme_mi_transport nvme_mi_transport_mctp;

static int nvme_mi_mctp_submit(struct nvme_mi_ep *ep,
			       struct nvme_mi_req *req,
			       struct nvme_mi_resp *resp)
{
	struct nvme_mi_transport_mctp *mctp;
	struct iovec req_iov[3], resp_iov[2];
	struct msghdr req_msg, resp_msg;
	struct sockaddr_mctp addr;
	unsigned char *rspbuf;
	ssize_t len;
	__le32 mic;
	int i;

	if (ep->transport != &nvme_mi_transport_mctp)
		return -EINVAL;

	mctp = ep->transport_data;

	memset(&addr, 0, sizeof(addr));
	addr.smctp_family = AF_MCTP;
	addr.smctp_network = mctp->net;
	addr.smctp_addr.s_addr = mctp->eid;
	addr.smctp_type = MCTP_TYPE_NVME | MCTP_TYPE_MIC;
	addr.smctp_tag = MCTP_TAG_OWNER;

	i = 0;
	req_iov[i].iov_base = ((__u8 *)req->hdr) + 1;
	req_iov[i].iov_len = req->hdr_len - 1;
	i++;

	if (req->data_len) {
		req_iov[i].iov_base = req->data;
		req_iov[i].iov_len = req->data_len;
		i++;
	}

	mic = cpu_to_le32(req->mic);
	req_iov[i].iov_base = &mic;
	req_iov[i].iov_len = sizeof(mic);
	i++;

	memset(&req_msg, 0, sizeof(req_msg));
	req_msg.msg_name = &addr;
	req_msg.msg_namelen = sizeof(addr);
	req_msg.msg_iov = req_iov;
	req_msg.msg_iovlen = i;

	len = sendmsg(mctp->sd, &req_msg, 0);
	if (len < 0) {
		nvme_msg(ep->root, LOG_ERR,
			 "Failure sending MCTP message: %m\n");
		return len;
	}

	resp_iov[0].iov_base = ((__u8 *)resp->hdr) + 1;
	resp_iov[0].iov_len = resp->hdr_len - 1;

	/* we use a temporary buffer to receive the response, and then
	 * split into data & mic. This avoids having to re-arrange response
	 * data on a recv that was shorter than expected */
	rspbuf = malloc(resp->data_len + sizeof(mic));
	if (!rspbuf)
		return -ENOMEM;

	resp_iov[1].iov_base = rspbuf;
	resp_iov[1].iov_len = resp->data_len + sizeof(mic);

	memset(&resp_msg, 0, sizeof(resp_msg));
	resp_msg.msg_name = &addr;
	resp_msg.msg_namelen = sizeof(addr);
	resp_msg.msg_iov = resp_iov;
	resp_msg.msg_iovlen = 2;

	len = recvmsg(mctp->sd, &resp_msg, 0);

	if (len < 0) {
		nvme_msg(ep->root, LOG_ERR,
			 "Failure receiving MCTP message: %m\n");
		free(rspbuf);
		return len;
	}

	if (len < resp->hdr_len + sizeof(mic) - 1) {
		nvme_msg(ep->root, LOG_ERR,
			 "Invalid MCTP response: too short (%zd bytes, needed %zd)\n",
			 len, resp->hdr_len + sizeof(mic) - 1);
		free(rspbuf);
		return -EIO;
	}
	resp->hdr->type = MCTP_TYPE_NVME | MCTP_TYPE_MIC;

	len -= resp->hdr_len - 1;

	memcpy(&mic, rspbuf + len - sizeof(mic), sizeof(mic));
	len -= sizeof(mic);

	memcpy(resp->data, rspbuf, len);
	resp->data_len = len;

	free(rspbuf);

	resp->mic = le32_to_cpu(mic);

	return 0;
}

static void nvme_mi_mctp_close(struct nvme_mi_ep *ep)
{
	struct nvme_mi_transport_mctp *mctp;

	if (ep->transport != &nvme_mi_transport_mctp)
		return;

	mctp = ep->transport_data;
	close(mctp->sd);
	free(ep->transport_data);
}

static const struct nvme_mi_transport nvme_mi_transport_mctp = {
	.name = "mctp",
	.mic_enabled = true,
	.submit = nvme_mi_mctp_submit,
	.close = nvme_mi_mctp_close,
};

nvme_mi_ep_t nvme_mi_open_mctp(nvme_root_t root, unsigned int netid, __u8 eid)
{
	struct nvme_mi_transport_mctp *mctp;
	struct nvme_mi_ep *ep;

	ep = nvme_mi_init_ep(root);
	if (!ep)
		return NULL;

	mctp = malloc(sizeof(*mctp));
	if (!mctp)
		goto err_free_ep;

	mctp->net = netid;
	mctp->eid = eid;

	mctp->sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (mctp->sd < 0)
		goto err_free_ep;

	ep->transport = &nvme_mi_transport_mctp;
	ep->transport_data = mctp;

	return ep;

err_free_ep:
	free(ep);
	return NULL;
}
