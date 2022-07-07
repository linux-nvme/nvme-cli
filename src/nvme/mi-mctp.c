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

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#if HAVE_LINUX_MCTP_H
#include <linux/mctp.h>
#endif

#include <ccan/endian/endian.h>

#ifdef CONFIG_LIBSYSTEMD
#include <systemd/sd-event.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-id128.h>

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

static bool nvme_mi_mctp_resp_is_mpr(struct nvme_mi_resp *resp, size_t len)
{
	struct nvme_mi_msg_resp *msg;
	__le32 mic;
	__u32 crc;

	if (len != sizeof(*msg) + sizeof(mic))
		return false;

	msg = (struct nvme_mi_msg_resp *)resp->hdr;

	if (msg->status != NVME_MI_RESP_MPR)
		return false;

	/* We can't use verify_resp_mic here, as the response structure has
	 * not been laid-out properly in resp yet (this is deferred until
	 * we have the actual response).
	 *
	 * We know the data is a fixed size, and linear in the hdr buf, so
	 * calculation is fairly simple. We do need to find the MIC data
	 * though, which could either be in the header buf (if the original
	 * header was larger than the minimal header message), or the start of
	 * the data buf (otherwise).
	 */
	if (resp->hdr_len > sizeof(*msg))
		mic = *(__le32 *)(msg + 1);
	else
		mic = *(__le32 *)(resp->data);

	crc = ~nvme_mi_crc32_update(0xffffffff, msg, sizeof(*msg));
	if (le32_to_cpu(mic) != crc)
		return false;

	return true;
}

static int nvme_mi_mctp_submit(struct nvme_mi_ep *ep,
			       struct nvme_mi_req *req,
			       struct nvme_mi_resp *resp)
{
	struct nvme_mi_transport_mctp *mctp;
	struct iovec req_iov[3], resp_iov[3];
	struct msghdr req_msg, resp_msg;
	struct sockaddr_mctp addr;
	ssize_t len;
	__le32 mic;
	int i, rc;
	__u8 tag;

	if (ep->transport != &nvme_mi_transport_mctp)
		return -EINVAL;

	/* we need enough space for at least a generic (/error) response */
	if (resp->hdr_len < sizeof(struct nvme_mi_msg_resp))
		return -EINVAL;

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
		nvme_msg(ep->root, LOG_ERR,
			 "Failure sending MCTP message: %m\n");
		rc = len;
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

retry:
	rc = -1;
	len = ops.recvmsg(mctp->sd, &resp_msg, 0);

	if (len < 0) {
		nvme_msg(ep->root, LOG_ERR,
			 "Failure receiving MCTP message: %m\n");
		goto out;
	}


	if (len == 0) {
		nvme_msg(ep->root, LOG_WARNING, "No data from MCTP endpoint\n");
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
		goto out;
	}

	/* We can't have header/payload data that isn't a multiple of 4 bytes */
	if (len & 0x3) {
		nvme_msg(ep->root, LOG_WARNING,
			 "Response message has unaligned length (%zd)!\n",
			 len);
		goto out;
	}

	/* Check for a More Processing Required response. This is a slight
	 * layering violation, as we're pre-checking the MIC and inspecting
	 * header fields. However, we need to do this in the transport in order
	 * to keep the tag allocated and retry the recvmsg
	 */
	if (nvme_mi_mctp_resp_is_mpr(resp, len)) {
		nvme_msg(ep->root, LOG_DEBUG,
			 "Received More Processing Required, waiting for response\n");
		/* TODO: when we implement timeouts, inspect the MPR response
		 * for the estimated completion time. */
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

	if (ep->transport != &nvme_mi_transport_mctp)
		return -1;

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

	return ep;

err_free_ep:
	free(ep);
	return NULL;
}

#ifdef CONFIG_LIBSYSTEMD

static void _dbus_err(nvme_root_t root, int rc, int line) {
	nvme_msg(root, LOG_ERR, "MCTP D-Bus failed line %d: %s %d\n",
		line, strerror(-rc), rc);
}

#define dbus_err(r, rc) _dbus_err(r, rc, __LINE__)

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
	if (!ep) {
		return -ENOMEM;
	}

	return 0;
}

/* We can't rely on sd_bus_message_enter_container() == 0 at the end of
   a dictionary (it returns -ENXIO) so we test separately */
static bool container_end(sd_bus_message *m)
{
	return sd_bus_message_peek_type(m, NULL, NULL) == 0;
}

static int handle_mctp_endpoint(nvme_root_t root, const char* objpath,
	sd_bus_message *m)
{
	bool have_eid = false, have_net = false, have_nvmemi = false;
	mctp_eid_t eid;
	int net;
	int rc;

	/* Iterate properties on this interface */
	while (!container_end(m)) {
		/* Enter property dict */
		rc = sd_bus_message_enter_container(m, 'a', "{sv}");
		if (rc < 0) {
			dbus_err(root, rc);
			return rc;
		}

		while (!container_end(m)) {
			char *propname = NULL;
			size_t sz;
			const uint8_t *types = NULL;
			/* Enter property item */
			rc = sd_bus_message_enter_container(m, 'e', "sv");
			if (rc < 0) {
				dbus_err(root, rc);
				return rc;
			}

			rc = sd_bus_message_read(m, "s", &propname);
			if (rc < 0) {
				dbus_err(root, rc);
				return rc;
			}

			if (strcmp(propname, "EID") == 0) {
				rc = sd_bus_message_read(m, "v", "y", &eid);
				have_eid = true;
			} else if (strcmp(propname, "NetworkId") == 0) {
				rc = sd_bus_message_read(m, "v", "i", &net);
				have_net = true;
			} else if (strcmp(propname, "SupportedMessageTypes") == 0) {
				sd_bus_message_enter_container(m, 'v', "ay");
				rc = sd_bus_message_read_array(m, 'y', (const void**)&types, &sz);
				if (rc >= 0)
					for (size_t s = 0; s < sz; s++)
						if (types[s] == MCTP_TYPE_NVME)
							have_nvmemi = true;
				sd_bus_message_exit_container(m);
			} else {
				rc = sd_bus_message_skip(m, "v");
			}

			if (rc < 0) {
				dbus_err(root, rc);
				return rc;
			}

			/* Exit prop item */
			rc = sd_bus_message_exit_container(m);
			if (rc < 0) {
				dbus_err(root, rc);
				return rc;
			}
		}

		/* Exit property dict */
		rc = sd_bus_message_exit_container(m);
		if (rc < 0) {
			dbus_err(root, rc);
			return rc;
		}
	}

	if (have_nvmemi) {
		if (!(have_eid && have_net)) {
			nvme_msg(root, LOG_ERR,
				 "Missing property for %s\n", objpath);
			return -ENOENT;
		}
		rc = nvme_mi_mctp_add(root, net, eid);
		if (rc < 0) {
			nvme_msg(root, LOG_ERR,
				 "Error adding net %d eid %d: %s\n",
				net, eid, strerror(-rc));
		}
	} else {
		/* Ignore other endpoints */
		rc = 0;
	}
	return rc;
}

static int handle_mctp_obj(nvme_root_t root, sd_bus_message *m)
{
	char *objpath = NULL;
	char *ifname = NULL;
	int rc;

	rc = sd_bus_message_read(m, "o", &objpath);
	if (rc < 0) {
		dbus_err(root, rc);
		return rc;
	}

	/* Enter response object: our array of (string, property dict)
	 * values */
	rc = sd_bus_message_enter_container(m, 'a', "{sa{sv}}");
	if (rc < 0) {
		dbus_err(root, rc);
		return rc;
	}


	/* for each interface */
	while (!container_end(m)) {
		/* Enter interface item */
		rc = sd_bus_message_enter_container(m, 'e', "sa{sv}");
		if (rc < 0) {
			dbus_err(root, rc);
			return rc;
		}

		rc = sd_bus_message_read(m, "s", &ifname);
		if (rc < 0) {
			dbus_err(root, rc);
			return rc;
		}

		if (!strcmp(ifname, MCTP_DBUS_IFACE_ENDPOINT)) {

			rc = handle_mctp_endpoint(root, objpath, m);
			if (rc < 0) {
				/* continue to next object */
			}
		} else {
			/* skip the interfaces we don't care about */
			rc = sd_bus_message_skip(m, "a{sv}");
			if (rc < 0) {
				dbus_err(root, rc);
				return rc;
			}
		}

		/* Exit interface item */
		rc = sd_bus_message_exit_container(m);
		if (rc < 0) {
			dbus_err(root, rc);
			return rc;
		}
	}

	/* Exit response object */
	rc = sd_bus_message_exit_container(m);
	if (rc < 0) {
		dbus_err(root, rc);
		return rc;
	}

	return 0;
}

nvme_root_t nvme_mi_scan_mctp(void)
{
	sd_bus *bus = NULL;
	sd_bus_message *resp = NULL;
	sd_bus_error berr = SD_BUS_ERROR_NULL;
	nvme_root_t root;
	int rc;

	root = nvme_mi_create_root(NULL, DEFAULT_LOGLEVEL);
	if (!root) {
		rc = -ENOMEM;
		goto out;
	}

	rc = sd_bus_default_system(&bus);
	if (rc < 0) {
		nvme_msg(root, LOG_ERR, "Failed opening D-Bus: %s\n",
			 strerror(-rc));
		goto out;
	}

	rc = sd_bus_call_method(bus,
			       MCTP_DBUS_IFACE,
			       MCTP_DBUS_PATH,
			       "org.freedesktop.DBus.ObjectManager",
			       "GetManagedObjects",
			       &berr,
			       &resp,
			       "");
	if (rc < 0) {
		nvme_msg(root, LOG_ERR, "Failed querying MCTP D-Bus: %s (%s)\n",
			 berr.message, berr.name);
		goto out;
	}

	rc = sd_bus_message_enter_container(resp, 'a', "{oa{sa{sv}}}");
	if (rc != 1) {
		dbus_err(root, rc);
		if (rc == 0)
			rc = -EPROTO;
		goto out;
	}

	/* Iterate over all managed objects */
	while (!container_end(resp)) {
		rc = sd_bus_message_enter_container(resp, 'e', "oa{sa{sv}}");
		if (rc < 0) {
			dbus_err(root, rc);
			goto out;
		}

		handle_mctp_obj(root, resp);

		rc = sd_bus_message_exit_container(resp);
		if (rc < 0) {
			dbus_err(root, rc);
			goto out;
		}
	}

	rc = sd_bus_message_exit_container(resp);
	if (rc < 0) {
		dbus_err(root, rc);
		goto out;
	}
	rc = 0;

out:
	sd_bus_error_free(&berr);
	sd_bus_message_unref(resp);
	sd_bus_unref(bus);

	if (rc < 0) {
		if (root) {
			nvme_mi_free_root(root);
		}
		root = NULL;
	}
	return root;
}

#else /* CONFIG_LIBSYSTEMD */

nvme_root_t nvme_mi_scan_mctp(void)
{
	return NULL;
}

#endif /* CONFIG_LIBSYSTEMD */
