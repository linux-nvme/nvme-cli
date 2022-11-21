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
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#if HAVE_LINUX_MCTP_H
#include <linux/mctp.h>
#endif

#include <ccan/endian/endian.h>

#ifdef CONFIG_DBUS
#include <dbus/dbus.h>

#define MCTP_DBUS_PATH "/xyz/openbmc_project/mctp"
#define MCTP_DBUS_IFACE "xyz.openbmc_project.MCTP"
#define MCTP_DBUS_IFACE_ENDPOINT "xyz.openbmc_project.MCTP.Endpoint"
#endif

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

static int ioctl_tag(int sd, unsigned long req, struct mctp_ioc_tag_ctl *ctl)
{
	return ioctl(sd, req, ctl);
}

static struct __mi_mctp_socket_ops ops = {
	socket,
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

#ifdef SIOCMCTPALLOCTAG
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

#else /*  !defined SIOMCTPTAGALLOC */

static __u8 nvme_mi_mctp_tag_alloc(struct nvme_mi_ep *ep)
{
	static bool logged;
	if (!logged) {
		nvme_msg(ep->root, LOG_INFO,
			 "Build does not support explicit tag allocation\n");
		logged = true;
	}
	return MCTP_TAG_OWNER;
}

static void nvme_mi_mctp_tag_drop(struct nvme_mi_ep *ep, __u8 tag)
{
}

#endif /* !defined SIOMCTPTAGALLOC */

struct nvme_mi_msg_resp_mpr {
	struct nvme_mi_msg_hdr hdr;
	__u8	status;
	__u8	rsvd0;
	__u16	mprt;
};

/* Check if this response was a More Processing Required response; if so,
 * populate the worst-case expected processing time, given in milliseconds.
 */
static bool nvme_mi_mctp_resp_is_mpr(struct nvme_mi_resp *resp, size_t len,
				     __le32 mic, unsigned int *mpr_time)
{
	struct nvme_mi_admin_resp_hdr *admin_msg;
	struct nvme_mi_msg_resp_mpr *msg;
	size_t clen;
	__u32 crc;

	/* We need at least the minimal header plus checksum */
	if (len < sizeof(*msg) + sizeof(mic))
		return false;

	msg = (struct nvme_mi_msg_resp_mpr *)resp->hdr;

	if (msg->status != NVME_MI_RESP_MPR)
		return false;

	/* Find and verify the MIC from the response, which may not be laid out
	 * in resp as we expect. We have to preserve resp->hdr_len and
	 * resp->data_len, as we will need them for the eventual reply message.
	 * Because of that, we can't use verify_resp_mic here.
	 *
	 * If the packet was at the expected response size, then mic will
	 * be set already; if not, find it within the header/data buffers.
	 */

	/* Devices may send a MPR response as a full-sized Admin response,
	 * rather than the minimal MI-only header. Allow this, but only if the
	 * type indicates admin, and the allocated response header is the
	 * correct size for an Admin response.
	 */
	if (((msg->hdr.nmp >> 3) & 0xf) == NVME_MI_MT_ADMIN &&
	    len == sizeof(*admin_msg) + sizeof(mic) &&
	    resp->hdr_len == sizeof(*admin_msg)) {
		if (resp->data_len)
			mic = *(__le32 *)resp->data;
	} else if (len == sizeof(*msg) + sizeof(mic)) {
		if (resp->hdr_len > sizeof(*msg))
			mic = *(__le32 *)(msg + 1);
		else if (resp->data_len)
			mic = *(__le32 *)(resp->data);
	} else {
		return false;
	}

	/* Since our response is just a header, we're guaranteed to have
	 * all data in resp->hdr. The response may be shorter than the expected
	 * header though, so clamp to len.
	 */
	len -= sizeof(mic);
	clen = len < resp->hdr_len ? len : resp->hdr_len;

	crc = ~nvme_mi_crc32_update(0xffffffff, resp->hdr, clen);
	if (le32_to_cpu(mic) != crc)
		return false;

	if (mpr_time)
		*mpr_time = cpu_to_le16(msg->mprt) * 100;

	return true;
}

static int nvme_mi_mctp_submit(struct nvme_mi_ep *ep,
			       struct nvme_mi_req *req,
			       struct nvme_mi_resp *resp)
{
	struct nvme_mi_transport_mctp *mctp;
	struct iovec req_iov[3], resp_iov[3];
	struct msghdr req_msg, resp_msg;
	int i, rc, errno_save, timeout;
	struct sockaddr_mctp addr;
	struct pollfd pollfds[1];
	unsigned int mpr_time;
	ssize_t len;
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

	resp_iov[0].iov_base = ((__u8 *)resp->hdr) + 1;
	resp_iov[0].iov_len = resp->hdr_len - 1;

	resp_iov[1].iov_base = ((__u8 *)resp->data);
	resp_iov[1].iov_len = resp->data_len;

	resp_iov[2].iov_base = &mic;
	resp_iov[2].iov_len = sizeof(mic);

	memset(&resp_msg, 0, sizeof(resp_msg));
	resp_msg.msg_name = &addr;
	resp_msg.msg_namelen = sizeof(addr);
	resp_msg.msg_iov = resp_iov;
	resp_msg.msg_iovlen = 3;

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
		return -1;
	}

	if (rc == 0) {
		nvme_msg(ep->root, LOG_DEBUG, "Timeout on MCTP socket");
		errno = ETIMEDOUT;
		return -1;
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
	resp->hdr->type = MCTP_TYPE_NVME | MCTP_TYPE_MIC;
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

	/* We can't have header/payload data that isn't a multiple of 4 bytes */
	if (len & 0x3) {
		nvme_msg(ep->root, LOG_WARNING,
			 "Response message has unaligned length (%zd)!\n",
			 len);
		errno = EPROTO;
		goto out;
	}

	/* Check for a More Processing Required response. This is a slight
	 * layering violation, as we're pre-checking the MIC and inspecting
	 * header fields. However, we need to do this in the transport in order
	 * to keep the tag allocated and retry the recvmsg
	 */
	if (nvme_mi_mctp_resp_is_mpr(resp, len, mic, &mpr_time)) {
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

	/* If we have a shorter than expected response, we need to find the
	 * MIC and the correct split between header & data. We know that the
	 * split is 4-byte aligned, so the MIC will be entirely within one
	 * of the iovecs.
	 */
	if (len == resp->hdr_len + resp->data_len + sizeof(mic)) {
		/* Common case: expected data length. Header, data and MIC
		 * are already laid-out correctly. Nothing to do. */

	} else if (len < resp->hdr_len + sizeof(mic)) {
		/* Response is smaller than the expected header. MIC is
		 * somewhere in the header buf */
		resp->hdr_len = len - sizeof(mic);
		resp->data_len = 0;
		memcpy(&mic, ((uint8_t *)resp->hdr) + resp->hdr_len,
		       sizeof(mic));

	} else {
		/* We have a full header, but data is truncated - possibly
		 * zero bytes. MIC is somewhere in the data buf */
		resp->data_len = len - resp->hdr_len - sizeof(mic);
		memcpy(&mic, ((uint8_t *)resp->data) + resp->data_len,
		       sizeof(mic));
	}

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
};

nvme_mi_ep_t nvme_mi_open_mctp(nvme_root_t root, unsigned int netid, __u8 eid)
{
	struct nvme_mi_transport_mctp *mctp;
	struct nvme_mi_ep *ep;
	int errno_save;

	ep = nvme_mi_init_ep(root);
	if (!ep)
		return NULL;

	mctp = malloc(sizeof(*mctp));
	if (!mctp)
		goto err_free_ep;

	mctp->net = netid;
	mctp->eid = eid;

	mctp->sd = ops.socket(AF_MCTP, SOCK_DGRAM, 0);
	if (mctp->sd < 0)
		goto err_free_ep;

	ep->transport = &nvme_mi_transport_mctp;
	ep->transport_data = mctp;

	/* Assuming an i2c transport at 100kHz, smallest MTU (64+4). Given
	 * a worst-case clock stretch, and largest-sized packets, we can
	 * expect up to 1.6s per command/response pair. Allowing for a
	 * retry or two (handled by lower layers), 5s is a reasonable timeout.
	 */
	ep->timeout = 5000;

	nvme_mi_ep_probe(ep);

	return ep;

err_free_ep:
	errno_save = errno;
	nvme_mi_close(ep);
	free(mctp);
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
	int rc;

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
