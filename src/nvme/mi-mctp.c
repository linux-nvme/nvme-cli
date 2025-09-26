// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 Code Construct Pty Ltd
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <poll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#if HAVE_LINUX_MCTP_H
#include <linux/mctp.h>
#else
#include "nvme/mi-mctp-compat.h"
#endif

#include <ccan/endian/endian.h>

#ifdef CONFIG_DBUS
#include <dbus/dbus.h>

#define MCTP_DBUS_PATH "/au/com/codeconstruct/mctp1"
#define MCTP_DBUS_IFACE "au.com.codeconstruct.MCTP1"
#define MCTP_DBUS_IFACE_ENDPOINT "xyz.openbmc_project.MCTP.Endpoint"
#endif

#include "private.h"
#include "log.h"
#include "mi.h"


#if !defined(AF_MCTP)
#define AF_MCTP 45
#endif

#if !defined(MCTP_TAG_PREALLOC)
/*Adding this here for users with older build MCTP header
 *that require SIOCMCTPALLOC/DROP
 */
#define MCTP_TAG_PREALLOC	0x10

#define SIOCMCTPALLOCTAG	(SIOCPROTOPRIVATE + 0)
#define SIOCMCTPDROPTAG		(SIOCPROTOPRIVATE + 1)

/* Deprecated: use mctp_ioc_tag_ctl2 / TAG2 ioctls instead, which defines the
 * MCTP network ID as part of the allocated tag. Using this assumes the default
 * net ID for allocated tags, which may not give correct behaviour on system
 * with multiple networks configured.
 */
struct mctp_ioc_tag_ctl {
	mctp_eid_t	peer_addr;

	/* For SIOCMCTPALLOCTAG: must be passed as zero, kernel will
	 * populate with the allocated tag value. Returned tag value will
	 * always have TO and PREALLOC set.
	 *
	 * For SIOCMCTPDROPTAG: userspace provides tag value to drop, from
	 * a prior SIOCMCTPALLOCTAG call (and so must have TO and PREALLOC set).
	 */
	__u8		tag;
	__u16		flags;
};
#endif  /* !MCTP_TAG_PREALLOC */

#define MCTP_TYPE_NVME		0x04
#define MCTP_TYPE_MIC		0x80

struct nvme_mi_transport_mctp {
	int	net;
	__u8	eid;
	int	sd;
	void	*resp_buf;
	size_t	resp_buf_size;
	int		sd_aem;
	void	*resp_buf_aem;
	size_t	resp_buf_aem_size;
};

static int ioctl_tag(int sd, unsigned long req, struct mctp_ioc_tag_ctl *ctl)
{
	return ioctl(sd, req, ctl);
}

static int nvme_mi_msg_socket(void)
{
	return socket(AF_MCTP, SOCK_DGRAM, 0);
}

static int nvme_mi_aem_socket(__u8 eid, unsigned int network)
{
	struct sockaddr_mctp local_addr = {0}, remote_addr = {0};
	int sd, rc;

	sd = socket(AF_MCTP, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (sd < 0)
		return sd;

	remote_addr.smctp_family = AF_MCTP;
	remote_addr.smctp_network = network;
	remote_addr.smctp_addr.s_addr = eid;
	remote_addr.smctp_type = MCTP_TYPE_NVME;
	/* connect() will specify a remote EID for the upcoming bind() */
	rc = connect(sd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
	if (rc)
		goto err_close;

	local_addr.smctp_family = AF_MCTP;
	local_addr.smctp_network = network;
	local_addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
	local_addr.smctp_type = MCTP_TYPE_NVME;

	rc = bind(sd, (struct sockaddr *)&local_addr, sizeof(local_addr));
	if (rc)
		goto err_close;

	return sd;

err_close:
	close(sd);
	return -1;
}

static struct __mi_mctp_socket_ops ops = {
	nvme_mi_msg_socket,
	nvme_mi_aem_socket,
	sendmsg,
	recvmsg,
	poll,
	ioctl_tag,
};

void __nvme_mi_mctp_set_ops(const struct __mi_mctp_socket_ops *newops)
{
	ops = *newops;
}
static const struct nvme_mi_transport nvme_mi_transport_mctp;

static __u8 nvme_mi_mctp_tag_alloc(struct nvme_mi_ep *ep)
{
	struct nvme_mi_transport_mctp *mctp;
	struct mctp_ioc_tag_ctl ctl = { 0 };
	static bool logged;
	int rc;

	mctp = ep->transport_data;

	ctl.peer_addr = mctp->eid;

	errno = 0;
	rc = ops.ioctl_tag(mctp->sd, SIOCMCTPALLOCTAG, &ctl);
	if (rc) {
		if (!logged) {
			/* not necessarily fatal, just means we can't handle
			 * "more processing required" messages */
			nvme_msg(ep->root, LOG_INFO,
				 "System does not support explicit tag allocation\n");
			logged = true;
		}
		return MCTP_TAG_OWNER;
	}

	return ctl.tag;
}

static void nvme_mi_mctp_tag_drop(struct nvme_mi_ep *ep, __u8 tag)
{
	struct nvme_mi_transport_mctp *mctp;
	struct mctp_ioc_tag_ctl ctl = { 0 };

	mctp = ep->transport_data;

	if (!(tag & MCTP_TAG_PREALLOC))
		return;

	ctl.peer_addr = mctp->eid;
	ctl.tag = tag;

	ops.ioctl_tag(mctp->sd, SIOCMCTPDROPTAG, &ctl);
}

struct nvme_mi_msg_resp_mpr {
	struct nvme_mi_msg_hdr hdr;
	__u8	status;
	__u8	rsvd0;
	__u16	mprt;
};

/* Check if this response was a More Processing Required response; if so,
 * populate the worst-case expected processing time, given in milliseconds.
 *
 * buf is the incoming message data, including type byte, but excluding
 * the MIC which has been extracted into the mic argument already.
 */
static bool nvme_mi_mctp_resp_is_mpr(void *buf, size_t len,
				     __le32 mic, unsigned int *mpr_time)
{
	struct nvme_mi_msg_resp_mpr *msg;
	__u32 crc;

	/* We need at least the minimal header */
	if (len < sizeof(*msg))
		return false;

	msg = (struct nvme_mi_msg_resp_mpr *)buf;

	if (msg->status != NVME_MI_RESP_MPR)
		return false;

	/* Devices may send a MPR response as a full-sized Admin response,
	 * rather than the minimal MI-only header. Allow this, but only if the
	 * type indicates admin, and the allocated response header is the
	 * correct size for an Admin response.
	 */
	if (!(len == sizeof(*msg) ||
	      ((msg->hdr.nmp >> 3 & 0x0f) == NVME_MI_MT_ADMIN &&
	       len == sizeof(struct nvme_mi_admin_resp_hdr))))
	    return false;

	/* Verify the MIC from the response. We're dealing with linear
	 * header data here, and need to preserve the resp pointer & size
	 * values, so can't use verify_resp_mic here.
	 */
	crc = ~nvme_mi_crc32_update(0xffffffff, buf, len);
	if (le32_to_cpu(mic) != crc)
		return false;

	if (mpr_time)
		*mpr_time = cpu_to_le16(msg->mprt) * 100;

	return true;
}

static int nvme_mi_mctp_aem_fd(struct nvme_mi_ep *ep)
{
	struct nvme_mi_transport_mctp *mctp;

	if (ep->transport != &nvme_mi_transport_mctp) {
		errno = EINVAL;
		return -1;
	}

	mctp = ep->transport_data;
	return mctp->sd_aem;
}

static int nvme_mi_mctp_aem_purge(struct nvme_mi_ep *ep)
{
	struct nvme_mi_transport_mctp *mctp = ep->transport_data;
	struct msghdr msg = {0};
	struct iovec iov;
	char buffer;

	iov.iov_base = &buffer;
	iov.iov_len = sizeof(buffer);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// Read until there is no more data
	while (ops.recvmsg(mctp->sd_aem, &msg, MSG_TRUNC) > 0)
		;

	return 0;
}


static int nvme_mi_mctp_aem_read(struct nvme_mi_ep *ep,
			       struct nvme_mi_resp *resp)
{
	ssize_t len, resp_len, resp_hdr_len, resp_data_len;
	struct sockaddr_mctp src_addr = { 0 };
	struct nvme_mi_transport_mctp *mctp;
	struct iovec resp_iov[1];
	struct msghdr resp_msg;
	int rc, errno_save;
	__le32 mic;

	if (ep->transport != &nvme_mi_transport_mctp) {
		errno = EINVAL;
		return -1;
	}

	/* we need enough space for at least a generic (/error) response */
	if (resp->hdr_len < sizeof(struct nvme_mi_msg_hdr)) {
		errno = EINVAL;
		return -1;
	}

	mctp = ep->transport_data;

	resp_len = resp->hdr_len + resp->data_len + sizeof(mic);
	if (resp_len > mctp->resp_buf_aem_size) {
		void *tmp = realloc(mctp->resp_buf_aem, resp_len);

		if (!tmp) {
			errno_save = errno;
			nvme_msg(ep->root, LOG_ERR,
				 "Failure allocating response buffer: %m\n");
			errno = errno_save;
			rc = -1;
			goto out;
		}
		mctp->resp_buf_aem = tmp;
		mctp->resp_buf_aem_size = resp_len;
	}

	/* offset by one: the MCTP message type is excluded from the buffer */
	resp_iov[0].iov_base = mctp->resp_buf_aem + 1;
	resp_iov[0].iov_len = resp_len - 1;

	memset(&resp_msg, 0, sizeof(resp_msg));
	resp_msg.msg_iov = resp_iov;
	resp_msg.msg_iovlen = 1;
	resp_msg.msg_name = &src_addr;
	resp_msg.msg_namelen = sizeof(src_addr);

	rc = -1;
	len = ops.recvmsg(mctp->sd_aem, &resp_msg, MSG_DONTWAIT);

	if (len < 0) {
		if (errno == EAGAIN)
			goto out;

		errno_save = errno;
		nvme_msg(ep->root, LOG_ERR,
			 "Failure receiving MCTP message: %m\n");
		errno = errno_save;
		goto out;
	}


	if (len == 0) {
		nvme_msg(ep->root, LOG_WARNING, "No data from MCTP endpoint\n");
		errno = EIO;
		goto out;
	}

	if (resp_msg.msg_namelen < sizeof(src_addr)) {
		nvme_msg(ep->root, LOG_WARNING, "Unexpected src address length\n");
		errno = EIO;
		goto out;
	}

	if (mctp->eid != src_addr.smctp_addr.s_addr) {
		//This is unexpected if the socket is bound to the endpoint
		errno = EPROTO;
		goto out;
	}

	/* Re-add the type byte, so we can work on aligned lengths from here */
	((uint8_t *)mctp->resp_buf_aem)[0] = MCTP_TYPE_NVME | MCTP_TYPE_MIC;
	len += 1;

	/* The smallest response data is 8 bytes: generic 4-byte message header
	 * plus four bytes of error data (excluding MIC). Ensure we have enough.
	 */
	if (len < 8 + sizeof(mic)) {
		nvme_msg(ep->root, LOG_ERR,
			 "Invalid MCTP response: too short (%zd bytes, needed %zd)\n",
			 len, 8 + sizeof(mic));
		errno = EPROTO;
		goto out;
	}

	/* Start unpacking the linear resp buffer into the split header + data
	 * + MIC.
	 */

	/* MIC is always at the tail */
	memcpy(&mic, mctp->resp_buf_aem + len - sizeof(mic), sizeof(mic));
	len -= 4;

	/* we expect resp->hdr_len bytes, but we may have less */
	resp_hdr_len = resp->hdr_len;
	if (resp_hdr_len > len)
		resp_hdr_len = len;
	memcpy(resp->hdr, mctp->resp_buf_aem, resp_hdr_len);
	resp->hdr_len = resp_hdr_len;
	len -= resp_hdr_len;

	/* any remaining bytes are the data payload */
	resp_data_len = resp->data_len;
	if (resp_data_len > len)
		resp_data_len = len;
	memcpy(resp->data, mctp->resp_buf_aem + resp_hdr_len, resp_data_len);
	resp->data_len = resp_data_len;

	resp->mic = le32_to_cpu(mic);

	rc = 0;

out:
	return rc;
}

static int nvme_mi_mctp_submit(struct nvme_mi_ep *ep,
			       struct nvme_mi_req *req,
			       struct nvme_mi_resp *resp)
{
	ssize_t len, resp_len, resp_hdr_len, resp_data_len;
	struct nvme_mi_transport_mctp *mctp;
	struct iovec req_iov[3], resp_iov[1];
	struct msghdr req_msg, resp_msg;
	int i, rc, errno_save, timeout;
	struct sockaddr_mctp addr;
	struct pollfd pollfds[1];
	unsigned int mpr_time;
	__le32 mic;
	__u8 tag;

	if (ep->transport != &nvme_mi_transport_mctp) {
		errno = EINVAL;
		return -1;
	}

	/* we need enough space for at least a generic (/error) response */
	if (resp->hdr_len < sizeof(struct nvme_mi_msg_resp)) {
		errno = EINVAL;
		return -1;
	}

	mctp = ep->transport_data;
	tag = nvme_mi_mctp_tag_alloc(ep);

	memset(&addr, 0, sizeof(addr));
	addr.smctp_family = AF_MCTP;
	addr.smctp_network = mctp->net;
	addr.smctp_addr.s_addr = mctp->eid;
	addr.smctp_type = MCTP_TYPE_NVME | MCTP_TYPE_MIC;
	addr.smctp_tag = tag;

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

	len = ops.sendmsg(mctp->sd, &req_msg, 0);
	if (len < 0) {
		errno_save = errno;
		nvme_msg(ep->root, LOG_ERR,
			 "Failure sending MCTP message: %m\n");
		errno = errno_save;
		rc = -1;
		goto out;
	}

	resp_len = resp->hdr_len + resp->data_len + sizeof(mic);
	if (resp_len > mctp->resp_buf_size) {
		void *tmp = realloc(mctp->resp_buf, resp_len);
		if (!tmp) {
			errno_save = errno;
			nvme_msg(ep->root, LOG_ERR,
				 "Failure allocating response buffer: %m\n");
			errno = errno_save;
			rc = -1;
			goto out;
		}
		mctp->resp_buf = tmp;
		mctp->resp_buf_size = resp_len;
	}

	/* offset by one: the MCTP message type is excluded from the buffer */
	resp_iov[0].iov_base = mctp->resp_buf + 1;
	resp_iov[0].iov_len = resp_len - 1;

	memset(&resp_msg, 0, sizeof(resp_msg));
	resp_msg.msg_name = &addr;
	resp_msg.msg_namelen = sizeof(addr);
	resp_msg.msg_iov = resp_iov;
	resp_msg.msg_iovlen = 1;

	pollfds[0].fd = mctp->sd;
	pollfds[0].events = POLLIN;
	timeout = ep->timeout ?: -1;
retry:
	rc = ops.poll(pollfds, 1, timeout);
	if (rc < 0) {
		if (errno == EINTR)
			goto retry;
		errno_save = errno;
		nvme_msg(ep->root, LOG_ERR,
			 "Failed polling on MCTP socket: %m");
		errno = errno_save;
		goto out;
	}

	if (rc == 0) {
		nvme_msg(ep->root, LOG_DEBUG, "Timeout on MCTP socket");
		errno = ETIMEDOUT;
		rc = -1;
		goto out;
	}

	rc = -1;
	len = ops.recvmsg(mctp->sd, &resp_msg, MSG_DONTWAIT);

	if (len < 0) {
		errno_save = errno;
		nvme_msg(ep->root, LOG_ERR,
			 "Failure receiving MCTP message: %m\n");
		errno = errno_save;
		goto out;
	}


	if (len == 0) {
		nvme_msg(ep->root, LOG_WARNING, "No data from MCTP endpoint\n");
		errno = EIO;
		goto out;
	}

	/* Re-add the type byte, so we can work on aligned lengths from here */
	((uint8_t *)mctp->resp_buf)[0] = MCTP_TYPE_NVME | MCTP_TYPE_MIC;
	len += 1;

	/* The smallest response data is 8 bytes: generic 4-byte message header
	 * plus four bytes of error data (excluding MIC). Ensure we have enough.
	 */
	if (len < 8 + sizeof(mic)) {
		nvme_msg(ep->root, LOG_ERR,
			 "Invalid MCTP response: too short (%zd bytes, needed %zd)\n",
			 len, 8 + sizeof(mic));
		errno = EPROTO;
		goto out;
	}

	/* Start unpacking the linear resp buffer into the split header + data
	 * + MIC. We check for a MPR response before fully unpacking, as we'll
	 * need to preserve the resp layout if we need to retry the receive.
	 */

	/* MIC is always at the tail */
	memcpy(&mic, mctp->resp_buf + len - sizeof(mic), sizeof(mic));
	len -= 4;

	/* Check for a More Processing Required response. This is a slight
	 * layering violation, as we're pre-checking the MIC and inspecting
	 * header fields. However, we need to do this in the transport in order
	 * to keep the tag allocated and retry the recvmsg
	 */
	if (nvme_mi_mctp_resp_is_mpr(mctp->resp_buf, len, mic, &mpr_time)) {
		nvme_msg(ep->root, LOG_DEBUG,
			 "Received More Processing Required, waiting for response\n");

		/* if the controller hasn't set MPRT, fall back to our command/
		 * response timeout, or the largest possible MPRT if none set */
		if (!mpr_time)
			mpr_time = ep->timeout ?: 0xffff;

		/* clamp to the endpoint max */
		if (ep->mprt_max && mpr_time > ep->mprt_max)
			mpr_time = ep->mprt_max;

		timeout = mpr_time;
		goto retry;
	}

	/* we expect resp->hdr_len bytes, but we may have less */
	resp_hdr_len = resp->hdr_len;
	if (resp_hdr_len > len)
		resp_hdr_len = len;
	memcpy(resp->hdr, mctp->resp_buf, resp_hdr_len);
	resp->hdr_len = resp_hdr_len;
	len -= resp_hdr_len;

	/* any remaining bytes are the data payload */
	resp_data_len = resp->data_len;
	if (resp_data_len > len)
		resp_data_len = len;
	memcpy(resp->data, mctp->resp_buf + resp_hdr_len, resp_data_len);
	resp->data_len = resp_data_len;

	resp->mic = le32_to_cpu(mic);

	rc = 0;

out:
	nvme_mi_mctp_tag_drop(ep, tag);

	return rc;
}

static void nvme_mi_mctp_close(struct nvme_mi_ep *ep)
{
	struct nvme_mi_transport_mctp *mctp;

	if (ep->transport != &nvme_mi_transport_mctp)
		return;

	mctp = ep->transport_data;
	close(mctp->sd);
	close(mctp->sd_aem);
	free(ep->aem_ctx);
	free(mctp->resp_buf);
	free(mctp->resp_buf_aem);
	free(ep->transport_data);
}

static int nvme_mi_mctp_desc_ep(struct nvme_mi_ep *ep, char *buf, size_t len)
{
	struct nvme_mi_transport_mctp *mctp;

	if (ep->transport != &nvme_mi_transport_mctp) {
		errno = EINVAL;
		return -1;
	}

	mctp = ep->transport_data;

	snprintf(buf, len, "net %d eid %d", mctp->net, mctp->eid);

	return 0;
}

static const struct nvme_mi_transport nvme_mi_transport_mctp = {
	.name = "mctp",
	.mic_enabled = true,
	.submit = nvme_mi_mctp_submit,
	.close = nvme_mi_mctp_close,
	.desc_ep = nvme_mi_mctp_desc_ep,
	.aem_read = nvme_mi_mctp_aem_read,
	.aem_fd = nvme_mi_mctp_aem_fd,
	.aem_purge = nvme_mi_mctp_aem_purge,
};

int nvme_mi_aem_open(nvme_mi_ep_t ep)
{
	struct nvme_mi_transport_mctp *mctp;

	if (ep->transport != &nvme_mi_transport_mctp) {
		errno = EINVAL;
		return -1;
	}

	mctp = ep->transport_data;

	//This doesn't have to be done multiple times
	if (mctp->sd_aem >= 0)
		return 0;

	mctp->sd_aem = ops.aem_socket(mctp->eid, mctp->net);

	if (mctp->sd_aem < 0)
		return -1;

	return 0;
}

nvme_mi_ep_t nvme_mi_open_mctp(nvme_root_t root, unsigned int netid, __u8 eid)
{
	struct nvme_mi_transport_mctp *mctp;
	struct nvme_mi_ep *ep;
	int errno_save;

	ep = nvme_mi_init_ep(root);
	if (!ep)
		return NULL;

	mctp = malloc(sizeof(*mctp));
	if (!mctp) {
		errno_save = errno;
		goto err_close_ep;
	}

	memset(mctp, 0, sizeof(*mctp));
	mctp->sd = -1;
	mctp->sd_aem = -1;

	mctp->resp_buf_size = 4096;
	mctp->resp_buf = malloc(mctp->resp_buf_size);
	if (!mctp->resp_buf) {
		errno_save = errno;
		goto err_free_mctp;
	}

	mctp->resp_buf_aem_size = 4096;
	mctp->resp_buf_aem = malloc(mctp->resp_buf_aem_size);
	if (!mctp->resp_buf_aem) {
		errno_save = errno;
		goto err_free_rspbuf;
	}

	mctp->net = netid;
	mctp->eid = eid;

	mctp->sd = ops.msg_socket();
	if (mctp->sd < 0) {
		errno_save = errno;
		goto err_free_aem_rspbuf;
	}

	ep->transport = &nvme_mi_transport_mctp;
	ep->transport_data = mctp;

	/* Assuming an i2c transport at 100kHz, smallest MTU (64+4). Given
	 * a worst-case clock stretch, and largest-sized packets, we can
	 * expect up to 1.6s per command/response pair. Allowing for a
	 * retry or two (handled by lower layers), 5s is a reasonable timeout.
	 */
	ep->timeout = 5000;

	return ep;

err_free_aem_rspbuf:
	free(mctp->resp_buf_aem);
err_free_rspbuf:
	free(mctp->resp_buf);
err_free_mctp:
	free(mctp);
err_close_ep:
	/* the ep->transport is not set yet, so this will not call back
	 * into nvme_mi_mctp_close() */
	nvme_mi_close(ep);
	errno = errno_save;
	return NULL;
}

#ifdef CONFIG_DBUS

static int nvme_mi_mctp_add(nvme_root_t root, unsigned int netid, __u8 eid)
{
	nvme_mi_ep_t ep = NULL;

	/* ensure we don't already have an endpoint with the same net/eid. if
	 * we do, just skip, no need to re-add. */
	list_for_each(&root->endpoints, ep, root_entry) {
		if (ep->transport != &nvme_mi_transport_mctp) {
			continue;
		}
		const struct nvme_mi_transport_mctp *t = ep->transport_data;
		if (t->eid == eid && t->net == netid)
			return 0;
	}

	ep = nvme_mi_open_mctp(root, netid, eid);
	if (!ep)
		return -1;

	return 0;
}

static bool dbus_object_is_type(DBusMessageIter *obj, int type)
{
	return dbus_message_iter_get_arg_type(obj) == type;
}

static bool dbus_object_is_dict(DBusMessageIter *obj)
{
	return dbus_object_is_type(obj, DBUS_TYPE_ARRAY) &&
		dbus_message_iter_get_element_type(obj) == DBUS_TYPE_DICT_ENTRY;
}

static int read_variant_basic(DBusMessageIter *var, int type, void *val)
{
	if (!dbus_object_is_type(var, type))
		return -1;

	dbus_message_iter_get_basic(var, val);

	return 0;
}

static bool has_message_type(DBusMessageIter *prop, uint8_t type)
{
	DBusMessageIter inner;
	uint8_t *types;
	int i, n;

	if (!dbus_object_is_type(prop, DBUS_TYPE_ARRAY) ||
	    dbus_message_iter_get_element_type(prop) != DBUS_TYPE_BYTE)
		return false;

	dbus_message_iter_recurse(prop, &inner);

	dbus_message_iter_get_fixed_array(&inner, &types, &n);

	for (i = 0; i < n; i++) {
		if (types[i] == type)
			return true;
	}

	return false;
}

static int handle_mctp_endpoint(nvme_root_t root, const char* objpath,
	DBusMessageIter *props)
{
	bool have_eid = false, have_net = false, have_nvmemi = false;
	mctp_eid_t eid;
	int net;
	int rc = 0;

	/* for each property */
	for (;;) {
		DBusMessageIter prop, val;
		const char *propname;

		dbus_message_iter_recurse(props, &prop);

		if (!dbus_object_is_type(&prop, DBUS_TYPE_STRING)) {
			nvme_msg(root, LOG_ERR,
				 "error unmashalling object (propname)\n");
			return -1;
		}

		dbus_message_iter_get_basic(&prop, &propname);

		dbus_message_iter_next(&prop);

		if (!dbus_object_is_type(&prop, DBUS_TYPE_VARIANT)) {
			nvme_msg(root, LOG_ERR,
				 "error unmashalling object (propval)\n");
			return -1;
		}

		dbus_message_iter_recurse(&prop, &val);

		if (!strcmp(propname, "EID")) {
			rc = read_variant_basic(&val, DBUS_TYPE_BYTE, &eid);
			have_eid = true;

		} else if (!strcmp(propname, "NetworkId")) {
			rc = read_variant_basic(&val, DBUS_TYPE_INT32, &net);
			have_net = true;

		} else if (!strcmp(propname, "SupportedMessageTypes")) {
			have_nvmemi = has_message_type(&val, MCTP_TYPE_NVME);
		}

		if (rc)
			return rc;

		if (!dbus_message_iter_next(props))
			break;
	}

	if (have_nvmemi) {
		if (!(have_eid && have_net)) {
			nvme_msg(root, LOG_ERR,
				 "Missing property for %s\n", objpath);
			errno = ENOENT;
			return -1;
		}
		rc = nvme_mi_mctp_add(root, net, eid);
		if (rc < 0) {
			int errno_save = errno;
			nvme_msg(root, LOG_ERR,
				 "Error adding net %d eid %d: %m\n", net, eid);
			errno = errno_save;
		}
	} else {
		/* Ignore other endpoints */
		rc = 0;
	}
	return rc;
}

/* obj is an array of (object path, interfaces) dict entries - ie., dbus type
 *   a{oa{sa{sv}}}
 */
static int handle_mctp_obj(nvme_root_t root, DBusMessageIter *obj)
{
	const char *objpath = NULL;
	DBusMessageIter intfs;

	if (!dbus_object_is_type(obj, DBUS_TYPE_OBJECT_PATH)) {
		nvme_msg(root, LOG_ERR, "error unmashalling object (path)\n");
		return -1;
	}

	dbus_message_iter_get_basic(obj, &objpath);

	dbus_message_iter_next(obj);

	if (!dbus_object_is_dict(obj)) {
		nvme_msg(root, LOG_ERR, "error unmashalling object (intfs)\n");
		return -1;
	}

	dbus_message_iter_recurse(obj, &intfs);

	/* for each interface */
	for (;;) {
		DBusMessageIter props, intf;
		const char *intfname;

		dbus_message_iter_recurse(&intfs, &intf);

		if (!dbus_object_is_type(&intf, DBUS_TYPE_STRING)) {
			nvme_msg(root, LOG_ERR,
				 "error unmashalling object (intf)\n");
			return -1;
		}

		dbus_message_iter_get_basic(&intf, &intfname);

		if (strcmp(intfname, MCTP_DBUS_IFACE_ENDPOINT)) {
			if (!dbus_message_iter_next(&intfs))
				break;
			continue;
		}

		dbus_message_iter_next(&intf);

		if (!dbus_object_is_dict(&intf)) {
			nvme_msg(root, LOG_ERR,
				 "error unmarshalling object (props)\n");
			return -1;
		}

		dbus_message_iter_recurse(&intf, &props);
		return handle_mctp_endpoint(root, objpath, &props);
	}

	return 0;
}

nvme_root_t nvme_mi_scan_mctp(void)
{
	DBusMessage *msg, *resp = NULL;
	DBusConnection *bus = NULL;
	DBusMessageIter args, objs;
	int errno_save, rc = -1;
	nvme_root_t root;
	dbus_bool_t drc;
	DBusError berr;

	root = nvme_mi_create_root(NULL, DEFAULT_LOGLEVEL);
	if (!root) {
		errno = ENOMEM;
		return NULL;
	}

	dbus_error_init(&berr);

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, &berr);
	if (!bus) {
		nvme_msg(root, LOG_ERR, "Failed connecting to D-Bus: %s (%s)\n",
			 berr.message, berr.name);
		goto out;
	}

	msg = dbus_message_new_method_call(MCTP_DBUS_IFACE,
					   MCTP_DBUS_PATH,
					   "org.freedesktop.DBus.ObjectManager",
					   "GetManagedObjects");
	if (!msg) {
		nvme_msg(root, LOG_ERR, "Failed creating call message\n");
		goto out;
	}

	resp = dbus_connection_send_with_reply_and_block(bus, msg,
							 DBUS_TIMEOUT_USE_DEFAULT,
							 &berr);
	dbus_message_unref(msg);
	if (!resp) {
		nvme_msg(root, LOG_ERR, "Failed querying MCTP D-Bus: %s (%s)\n",
			 berr.message, berr.name);
		goto out;
	}

	/* argument container */
	drc = dbus_message_iter_init(resp, &args);
	if (!drc) {
		nvme_msg(root, LOG_ERR, "can't read dbus reply args\n");
		goto out;
	}

	if (!dbus_object_is_dict(&args)) {
		nvme_msg(root, LOG_ERR, "error unmashalling args\n");
		goto out;
	}

	/* objects container */
	dbus_message_iter_recurse(&args, &objs);

	rc = 0;

	for (;;) {
		DBusMessageIter ent;

		dbus_message_iter_recurse(&objs, &ent);

		rc = handle_mctp_obj(root, &ent);
		if (rc)
			break;

		if (!dbus_message_iter_next(&objs))
			break;
	}

out:
	errno_save = errno;
	if (resp)
		dbus_message_unref(resp);
	if (bus)
		dbus_connection_unref(bus);
	dbus_error_free(&berr);

	if (rc < 0) {
		if (root) {
			nvme_mi_free_root(root);
		}
		errno = errno_save;
		root = NULL;
	}
	return root;
}

#else /* CONFIG_DBUS */

nvme_root_t nvme_mi_scan_mctp(void)
{
	return NULL;
}

#endif /* CONFIG_DBUS */
