// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2022 Code Construct
 */

#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>


#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>

#include "libnvme-mi.h"
#include "nvme/private.h"
#include "utils.h"

/* 4096 byte max MCTP message, plus space for header data */
#define MAX_BUFSIZ 8192

struct test_peer;

typedef int (*rx_test_fn)(struct test_peer *peer, void *buf, size_t len, int sd);
typedef int (*poll_test_fn)(struct test_peer *peer,
			    struct pollfd *fds, nfds_t nfds, int timeout);

#define TEST_PEER_SD_COMMANDS_IDX  (0)
#define TEST_PEER_SD_AEMS_IDX      (1)

/* Our fake MCTP "peer".
 *
 * The terms TX (transmit) and RX (receive) are from the perspective of
 * the NVMe device. TX is device-to-libnvme, RX is libnvme-to-device.
 *
 * The RX and TX buffers are linear versions of the data sent and received by
 * libnvme-mi, and *include* the MCTP message type byte (even though it's
 * omitted in the sendmsg/recvmsg interface), so that the buffer inspection
 * in the tests can exactly match the NVMe-MI spec packet diagrams.
 */
static struct test_peer {
	/* rx (sendmsg) data sent from libnvme, and return value */
	unsigned char	rx_buf[MAX_BUFSIZ];
	size_t		rx_buf_len;
	ssize_t		rx_rc; /* if zero, return the sendmsg len */
	int		rx_errno;

	/* tx (recvmsg) data to be received by libnvme and return value */
	unsigned char	tx_buf[MAX_BUFSIZ];
	size_t		tx_buf_len;
	ssize_t		tx_rc; /* if zero, return the recvmsg len */
	int		tx_errno;

	/* Optional, called before TX, may set tx_buf according to request.
	 * Return value stored in tx_res, may be used by test */
	rx_test_fn	tx_fn;
	void		*tx_data;
	int		tx_fn_res;

	poll_test_fn	poll_fn;
	void		*poll_data;

	/* store sd from socket() setup */
	int		sd[2];
} test_peer;

/* ensure tests start from a standard state */
void reset_test_peer(void)
{
	int temp_sd[2] = {test_peer.sd[TEST_PEER_SD_COMMANDS_IDX],
				  test_peer.sd[TEST_PEER_SD_AEMS_IDX]};

	memset(&test_peer, 0, sizeof(test_peer));
	test_peer.tx_buf[0] = NVME_MI_MSGTYPE_NVME;
	test_peer.rx_buf[0] = NVME_MI_MSGTYPE_NVME;
	memcpy(test_peer.sd, temp_sd, 2*sizeof(*temp_sd));
}

/* calculate MIC of peer-to-libnvme data, expand buf by 4 bytes and insert
 * the new MIC */
static void test_set_tx_mic(struct test_peer *peer)
{
	extern __u32 nvme_mi_crc32_update(__u32 crc, void *data, size_t len);
	__u32 crc = 0xffffffff;
	__le32 crc_le;

	assert(peer->tx_buf_len + sizeof(crc_le) <= MAX_BUFSIZ);

	crc = nvme_mi_crc32_update(crc, peer->tx_buf, peer->tx_buf_len);
	crc_le = cpu_to_le32(~crc);
	memcpy(peer->tx_buf + peer->tx_buf_len, &crc_le, sizeof(crc_le));
	peer->tx_buf_len += sizeof(crc_le);
}

int __wrap_msg_socket(void)
{
	/* we do an open here to give the mi-mctp code something to close() */
	test_peer.sd[TEST_PEER_SD_COMMANDS_IDX] = open("/dev/null", 0);
	return test_peer.sd[TEST_PEER_SD_COMMANDS_IDX];
}

int __wrap_aem_socket(__u8 eid, unsigned int network)
{
	/* we do an open here to give the mi-mctp code something to close() */
	test_peer.sd[TEST_PEER_SD_AEMS_IDX] = open("/dev/null", 0);
	return test_peer.sd[TEST_PEER_SD_AEMS_IDX];
}

ssize_t __wrap_sendmsg(int sd, const struct msghdr *hdr, int flags)
{
	size_t i, pos;

	assert(sd == test_peer.sd[TEST_PEER_SD_COMMANDS_IDX]);

	test_peer.rx_buf[0] = NVME_MI_MSGTYPE_NVME;

	/* gather iovec into buf */
	for (i = 0, pos = 1; i < hdr->msg_iovlen; i++) {
		struct iovec *iov = &hdr->msg_iov[i];

		assert(pos + iov->iov_len < MAX_BUFSIZ - 1);
		memcpy(test_peer.rx_buf + pos, iov->iov_base, iov->iov_len);
		pos += iov->iov_len;
	}

	test_peer.rx_buf_len = pos;

	errno = test_peer.rx_errno;

	return test_peer.rx_rc ?: (pos - 1);
}

ssize_t __wrap_recvmsg(int sd, struct msghdr *hdr, int flags)
{
	size_t i, pos, len;

	assert(sd == test_peer.sd[TEST_PEER_SD_COMMANDS_IDX] ||
		   sd == test_peer.sd[TEST_PEER_SD_AEMS_IDX]);

	//Check for purge case
	if (flags & MSG_TRUNC)
		return 0;

	if (test_peer.tx_fn) {
		test_peer.tx_fn_res = test_peer.tx_fn(&test_peer,
						   test_peer.rx_buf,
						   test_peer.rx_buf_len,
						   sd);
	} else {
		if (sd == test_peer.sd[TEST_PEER_SD_COMMANDS_IDX] && test_peer.tx_buf_len == 0) {
			errno = EAGAIN;
			return -1;
		}
		/* set up a few default response fields; caller may have
		 * initialised the rest of the response */
		test_peer.tx_buf[0] = NVME_MI_MSGTYPE_NVME;
		test_peer.tx_buf[1] = test_peer.rx_buf[1] | (NVME_MI_ROR_RSP << 7);
		test_set_tx_mic(&test_peer);
	}

	/* scatter buf into iovec */
	for (i = 0, pos = 1; i < hdr->msg_iovlen && pos < test_peer.tx_buf_len;
	     i++) {
		struct iovec *iov = &hdr->msg_iov[i];

		len = iov->iov_len;
		if (len > test_peer.tx_buf_len - pos)
			len = test_peer.tx_buf_len - pos;

		memcpy(iov->iov_base, test_peer.tx_buf + pos, len);
		pos += len;
	}

	errno = test_peer.tx_errno;

	test_peer.tx_buf_len = 0; //Clear since this is sent
	return test_peer.tx_rc ?: (pos - 1);
}

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	if (!test_peer.poll_fn)
		return 1;

	return test_peer.poll_fn(&test_peer, fds, nfds, timeout);
}

struct mctp_ioc_tag_ctl;

#ifdef SIOCMCTPALLOCTAG
int test_ioctl_tag(int sd, unsigned long req, struct mctp_ioc_tag_ctl *ctl)
{
	assert(sd == test_peer.sd[TEST_PEER_SD_COMMANDS_IDX]);

	switch (req) {
	case SIOCMCTPALLOCTAG:
		ctl->tag = 1 | MCTP_TAG_PREALLOC | MCTP_TAG_OWNER;
		break;
	case SIOCMCTPDROPTAG:
		assert(ctl->tag == (1 | MCTP_TAG_PREALLOC | MCTP_TAG_OWNER));
		break;
	};

	return 0;
}
#else
int test_ioctl_tag(int sd, unsigned long req, struct mctp_ioc_tag_ctl *ctl)
{
	assert(sd == test_peer.sd[TEST_PEER_SD_COMMANDS_IDX]);
	return 0;
}
#endif

static struct __mi_mctp_socket_ops ops = {
	__wrap_msg_socket,
	__wrap_aem_socket,
	__wrap_sendmsg,
	__wrap_recvmsg,
	__wrap_poll,
	test_ioctl_tag,
};

/* tests */
static void test_rx_err(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	peer->rx_rc = -1;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc != 0);
}

static int tx_none(struct test_peer *peer, void *buf, size_t len, int sd)
{
	return 0;
}

static void test_tx_none(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	peer->tx_buf_len = 0;
	peer->tx_fn = tx_none;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc != 0);
}

static void test_tx_err(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	peer->tx_rc = -1;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc != 0);
}

static void test_tx_short(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	peer->tx_buf_len = 11;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc != 0);
}

static int poll_fn_err(struct test_peer *peer, struct pollfd *fds,
				 nfds_t nfds, int timeout)
{
	return -1;
}

static void test_poll_err(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	peer->poll_fn = poll_fn_err;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc != 0);
}

static void test_read_mi_data(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	/* empty response data */
	peer->tx_buf_len = 8 + 32;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc == 0);
}

static void test_mi_resp_err(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	/* simple error response */
	peer->tx_buf[4] = 0x02; /* internal error */
	peer->tx_buf_len = 8;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc == 0x2);
}

static void setup_unaligned_ctrl_list_resp(struct test_peer *peer)
{
	/* even number of controllers */
	peer->tx_buf[8] = 0x02;
	peer->tx_buf[9] = 0x00;

	/* controller ID 1 */
	peer->tx_buf[10] = 0x01;
	peer->tx_buf[11] = 0x00;

	/* controller ID 2 */
	peer->tx_buf[12] = 0x02;
	peer->tx_buf[13] = 0x00;

	peer->tx_buf_len = 14;
}

/* Will call through the xfer/submit API expecting a full-sized list (so
 * resp->data_len is set to sizeof(list)), but the endpoint will return an
 * unaligned short list.
 */
static void test_mi_resp_unaligned(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_ctrl_list list;
	int rc;

	setup_unaligned_ctrl_list_resp(peer);

	memset(&list, 0, sizeof(list));

	rc = nvme_mi_mi_read_mi_data_ctrl_list(ep, 0, &list);
	assert(rc == 0);

	assert(le16_to_cpu(list.num) == 2);
	assert(le16_to_cpu(list.identifier[0]) == 1);
	assert(le16_to_cpu(list.identifier[1]) == 2);
}

/* Will call through the xfer/submit API expecting an unaligned list,
 * and get a response of exactly that size.
 */
static void test_mi_resp_unaligned_expected(nvme_mi_ep_t ep,
					    struct test_peer *peer)
{
	/* direct access to the raw submit() API */
	extern int nvme_mi_submit(nvme_mi_ep_t ep, struct nvme_mi_req *req,
		   struct nvme_mi_resp *resp);
	struct nvme_mi_mi_resp_hdr resp_hdr;
	struct nvme_mi_mi_req_hdr req_hdr;
	struct nvme_ctrl_list list;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	setup_unaligned_ctrl_list_resp(peer);

	memset(&list, 0, sizeof(list));

	memset(&req_hdr, 0, sizeof(req_hdr));
	req_hdr.hdr.type = NVME_MI_MSGTYPE_NVME;
	req_hdr.hdr.nmp = (NVME_MI_ROR_REQ << 7) | (NVME_MI_MT_MI << 3);
	req_hdr.opcode = nvme_mi_mi_opcode_mi_data_read;
	req_hdr.cdw0 = cpu_to_le32(nvme_mi_dtyp_ctrl_list << 24);

	memset(&req, 0, sizeof(req));
	req.hdr = &req_hdr.hdr;
	req.hdr_len = sizeof(req_hdr);

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &resp_hdr.hdr;
	resp.hdr_len = sizeof(resp_hdr);
	resp.data = &list;
	resp.data_len = peer->tx_buf_len;

	rc = nvme_mi_submit(ep, &req, &resp);
	assert(rc == 0);
	assert(resp.data_len == 6); /* 2-byte length, 2*2 byte controller IDs */

	assert(le16_to_cpu(list.num) == 2);
	assert(le16_to_cpu(list.identifier[0]) == 1);
	assert(le16_to_cpu(list.identifier[1]) == 2);
}

static void test_admin_resp_err(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_id_ctrl id;
	nvme_mi_ctrl_t ctrl;
	int rc;

	ctrl = nvme_mi_init_ctrl(ep, 1);
	assert(ctrl);

	/* Simple error response, will be shorter than the expected Admin
	 * command response header. */
	peer->tx_buf[4] = 0x02; /* internal error */
	peer->tx_buf_len = 8;

	rc = nvme_mi_admin_identify_ctrl(ctrl, &id);
	assert(nvme_status_get_type(rc) == NVME_STATUS_TYPE_MI);
	assert(nvme_status_get_value(rc) == NVME_MI_RESP_INTERNAL_ERR);
}

/* test: all 4-byte aligned response sizes - should be decoded into the
 * response status value. We use an admin command here as the header size will
 * be larger than the minimum header size (it contains the completion
 * doublewords), and we need to ensure that an error response is correctly
 * interpreted, including having the MIC extracted from the message.
 */
static void test_admin_resp_sizes(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_id_ctrl id;
	nvme_mi_ctrl_t ctrl;
	unsigned int i;
	int rc;

	ctrl = nvme_mi_init_ctrl(ep, 1);
	assert(ctrl);

	peer->tx_buf[4] = 0x02; /* internal error */

	for (i = 8; i <= 4096 + 8; i+=4) {
		peer->tx_buf_len = i;
		rc = nvme_mi_admin_identify_ctrl(ctrl, &id);
		assert(nvme_status_get_type(rc) == NVME_STATUS_TYPE_MI);
		assert(nvme_status_get_value(rc) == NVME_MI_RESP_INTERNAL_ERR);
	}

	nvme_mi_close_ctrl(ctrl);
}

/* test: timeout value passed to poll */
static int poll_fn_timeout_value(struct test_peer *peer, struct pollfd *fds,
				 nfds_t nfds, int timeout)
{
	assert(timeout == 3141);
	return 1;
}

static void test_poll_timeout_value(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	/* empty response data */
	peer->tx_buf_len = 8 + 32;

	peer->poll_fn = poll_fn_timeout_value;
	nvme_mi_ep_set_timeout(ep, 3141);

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc == 0);
}

/* test: poll timeout expiry */
static int poll_fn_timeout(struct test_peer *peer, struct pollfd *fds,
			   nfds_t nfds, int timeout)
{
	return 0;
}

static void test_poll_timeout(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	peer->poll_fn = poll_fn_timeout;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc != 0);
	assert(errno == ETIMEDOUT);
}

/* test: send a More Processing Required response, then the actual response */
struct mpr_tx_info {
	int msg_no;
	bool admin_quirk;
	size_t final_len;
};

static int tx_mpr(struct test_peer *peer, void *buf, size_t len, int sd)
{
	struct mpr_tx_info *tx_info = peer->tx_data;

	assert(sd == peer->sd[TEST_PEER_SD_COMMANDS_IDX]);

	memset(peer->tx_buf, 0, sizeof(peer->tx_buf));
	peer->tx_buf[0] = NVME_MI_MSGTYPE_NVME;
	peer->tx_buf[1] = test_peer.rx_buf[1] | (NVME_MI_ROR_RSP << 7);

	switch (tx_info->msg_no) {
	case 1:
		peer->tx_buf[4] = NVME_MI_RESP_MPR;
		peer->tx_buf_len = 8;
		if (tx_info->admin_quirk) {
			peer->tx_buf_len = 20;
		}
		break;
	case 2:
		peer->tx_buf[4] = NVME_MI_RESP_SUCCESS;
		peer->tx_buf_len = tx_info->final_len;
		break;
	default:
		assert(0);
	}

	test_set_tx_mic(peer);

	tx_info->msg_no++;

	return 0;
}

static void test_mpr_mi(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	struct mpr_tx_info tx_info;
	int rc;

	tx_info.msg_no = 1;
	tx_info.final_len = sizeof(struct nvme_mi_mi_resp_hdr) + sizeof(ss_info);
	tx_info.admin_quirk = false;

	peer->tx_fn = tx_mpr;
	peer->tx_data = &tx_info;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc == 0);
}

static void test_mpr_admin(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct mpr_tx_info tx_info;
	struct nvme_id_ctrl id;
	nvme_mi_ctrl_t ctrl;
	int rc;

	tx_info.msg_no = 1;
	tx_info.final_len = sizeof(struct nvme_mi_admin_resp_hdr) + sizeof(id);
	tx_info.admin_quirk = false;

	peer->tx_fn = tx_mpr;
	peer->tx_data = &tx_info;

	ctrl = nvme_mi_init_ctrl(ep, 1);

	rc = nvme_mi_admin_identify_ctrl(ctrl, &id);
	assert(rc == 0);

	nvme_mi_close_ctrl(ctrl);
}

/* We have seen drives that send a MPR response as a full Admin message,
 * rather than a MI message; these have a larger message body
 */
static void test_mpr_admin_quirked(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct mpr_tx_info tx_info;
	struct nvme_id_ctrl id;
	nvme_mi_ctrl_t ctrl;
	int rc;

	tx_info.msg_no = 1;
	tx_info.final_len = sizeof(struct nvme_mi_admin_resp_hdr) + sizeof(id);
	tx_info.admin_quirk = true;

	peer->tx_fn = tx_mpr;
	peer->tx_data = &tx_info;

	ctrl = nvme_mi_init_ctrl(ep, 1);

	rc = nvme_mi_admin_identify_ctrl(ctrl, &id);
	assert(rc == 0);

	nvme_mi_close_ctrl(ctrl);
}

/* helpers for the MPR + poll tests */
struct mpr_poll_info {
	int poll_no;
	uint16_t mprt;
	unsigned int timeouts[2];
};

static int poll_fn_mpr_poll(struct test_peer *peer, struct pollfd *fds,
			       nfds_t nfds, int timeout)
{
	struct mpr_poll_info *info = peer->poll_data;

	switch (info->poll_no) {
	case 1:
	case 2:
		assert(timeout == info->timeouts[info->poll_no - 1]);
		break;
	default:
		assert(0);
	}

	info->poll_no++;
	return 1;
}

static int tx_fn_mpr_poll(struct test_peer *peer, void *buf, size_t len, int sd)
{
	struct mpr_tx_info *tx_info = peer->tx_data;
	struct mpr_poll_info *poll_info = peer->poll_data;
	unsigned int mprt;

	assert(sd == peer->sd[TEST_PEER_SD_COMMANDS_IDX]);

	memset(peer->tx_buf, 0, sizeof(peer->tx_buf));
	peer->tx_buf[0] = NVME_MI_MSGTYPE_NVME;
	peer->tx_buf[1] = test_peer.rx_buf[1] | (NVME_MI_ROR_RSP << 7);

	switch (tx_info->msg_no) {
	case 1:
		peer->tx_buf[4] = NVME_MI_RESP_MPR;
		peer->tx_buf_len = 8;
		mprt = poll_info->mprt;
		peer->tx_buf[7] = mprt >> 8;
		peer->tx_buf[6] = mprt & 0xff;
		break;
	case 2:
		peer->tx_buf[4] = NVME_MI_RESP_SUCCESS;
		peer->tx_buf_len = tx_info->final_len;
		break;
	default:
		assert(0);
	}

	test_set_tx_mic(peer);

	tx_info->msg_no++;

	return 0;
}

/* test: correct timeout value used from MPR response */
static void test_mpr_timeouts(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	struct mpr_poll_info poll_info;
	struct mpr_tx_info tx_info;
	int rc;

	nvme_mi_ep_set_timeout(ep, 3141);

	tx_info.msg_no = 1;
	tx_info.final_len = sizeof(struct nvme_mi_mi_resp_hdr) + sizeof(ss_info);

	poll_info.poll_no = 1;
	poll_info.mprt = 1234;
	poll_info.timeouts[0] = 3141;
	poll_info.timeouts[1] = 1234 * 100;

	peer->tx_fn = tx_fn_mpr_poll;
	peer->tx_data = &tx_info;

	peer->poll_fn = poll_fn_mpr_poll;
	peer->poll_data = &poll_info;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc == 0);
}

/* test: MPR value is limited to the max mpr */
static void test_mpr_timeout_clamp(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	struct mpr_poll_info poll_info;
	struct mpr_tx_info tx_info;
	int rc;

	nvme_mi_ep_set_timeout(ep, 3141);
	nvme_mi_ep_set_mprt_max(ep, 123400);

	tx_info.msg_no = 1;
	tx_info.final_len = sizeof(struct nvme_mi_mi_resp_hdr) + sizeof(ss_info);

	poll_info.poll_no = 1;
	poll_info.mprt = 1235;
	poll_info.timeouts[0] = 3141;
	poll_info.timeouts[1] = 1234 * 100;

	peer->tx_fn = tx_fn_mpr_poll;
	peer->tx_data = &tx_info;

	peer->poll_fn = poll_fn_mpr_poll;
	peer->poll_data = &poll_info;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc == 0);
}

/* test: MPR value of zero doesn't result in poll with zero timeout */
static void test_mpr_mprt_zero(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	struct mpr_poll_info poll_info;
	struct mpr_tx_info tx_info;
	int rc;

	nvme_mi_ep_set_timeout(ep, 3141);
	nvme_mi_ep_set_mprt_max(ep, 123400);

	tx_info.msg_no = 1;
	tx_info.final_len = sizeof(struct nvme_mi_mi_resp_hdr) + sizeof(ss_info);

	poll_info.poll_no = 1;
	poll_info.mprt = 0;
	poll_info.timeouts[0] = 3141;
	poll_info.timeouts[1] = 3141;

	peer->tx_fn = tx_fn_mpr_poll;
	peer->tx_data = &tx_info;

	peer->poll_fn = poll_fn_mpr_poll;
	peer->poll_data = &poll_info;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc == 0);
}

enum aem_enable_state {
	AEM_ES_GET_ENABLED,
	AEM_ES_SET_TO_DISABLED,
	AEM_ES_ENABLE_SET_ENABLED,
	AEM_ES_PROCESS,
	AEM_ES_ACK_RESPONSE,
	AEM_ES_ACK_RECEIVED
};

enum aem_failure_condition {
	AEM_FC_NONE,
	AEM_FC_BAD_GET_CONFIG_HEADER_LEN,
	AEM_FC_BAD_GET_CONFIG_TOTAL_LEN,
	AEM_FC_BAD_GET_CONFIG_BUFFER_LEN,
	AEM_FC_BAD_OCC_RSP_HDR_LEN_SYNC,
	AEM_FC_BAD_OCC_RSP_TOTAL_LEN_SYNC,
	AEM_FC_BAD_OCC_RSP_BUFFER_LEN_SYNC,
	AEM_FC_BAD_OCC_RSP_HDR_LEN_AEM,
	AEM_FC_BAD_OCC_RSP_TOTAL_LEN_AEM,
	AEM_FC_BAD_OCC_RSP_BUFFER_LEN_AEM,
};

struct aem_rcv_enable_fn_data {
	enum aem_enable_state state;
	enum aem_failure_condition fc;
	struct nvme_mi_aem_enabled_map ep_enabled_map;
	struct nvme_mi_aem_enabled_map host_enabled_map;
	struct nvme_mi_aem_enabled_map aem_during_process_map;
	struct nvme_mi_aem_enabled_map ack_events_map;
	struct nvme_mi_event *events[256];
	int callback_count;
};

static void populate_tx_occ_list(bool aem_not_ack,
	struct aem_rcv_enable_fn_data *fn_data, struct nvme_mi_aem_enabled_map *to_send)
{
	struct nvme_mi_mi_resp_hdr *resp_hdr =
		(struct nvme_mi_mi_resp_hdr *)test_peer.tx_buf;

	struct nvme_mi_msg_hdr *mi_msg_hdr =
		(struct nvme_mi_msg_hdr *)test_peer.tx_buf;

	size_t hdr_len = sizeof(*resp_hdr);

	struct nvme_mi_aem_occ_list_hdr *list_hdr =
		(struct nvme_mi_aem_occ_list_hdr *)(resp_hdr+1);

	//For AEM, the data is actually in request format
	//since it originates from the endpoint
	if (aem_not_ack) {
		list_hdr = (struct nvme_mi_aem_occ_list_hdr *)(mi_msg_hdr+1);
		hdr_len = sizeof(*mi_msg_hdr);
		mi_msg_hdr->nmp = (NVME_MI_MT_AE << 3);
	} else {
		resp_hdr->status = 0;
	}

	list_hdr->aelver = 0;
	list_hdr->aeolhl = sizeof(*list_hdr);
	list_hdr->numaeo = 0;
	__u32 aeoltl = list_hdr->aeolhl;

	struct nvme_mi_aem_occ_data *data =
		(struct nvme_mi_aem_occ_data *)(list_hdr+1);

	for (int i = 0; i < 255; i++) {
		if (fn_data->events[i] && to_send->enabled[i]) {
			struct nvme_mi_event *event = fn_data->events[i];

			list_hdr->numaeo++;
			aeoltl += sizeof(struct nvme_mi_aem_occ_data);
			aeoltl += event->spec_info_len +
				event->vend_spec_info_len;

			data->aelhlen = sizeof(*data);

			if ((fn_data->fc == AEM_FC_BAD_OCC_RSP_HDR_LEN_SYNC && !aem_not_ack) ||
			    (fn_data->fc == AEM_FC_BAD_OCC_RSP_HDR_LEN_AEM && aem_not_ack))
				data->aelhlen--;

			data->aeoui.aeocidi = event->aeocidi;
			data->aeoui.aeoi = event->aeoi;
			data->aeoui.aessi = event->aessi;
			data->aeosil = event->spec_info_len;
			data->aeovsil = event->vend_spec_info_len;

			if ((fn_data->fc == AEM_FC_BAD_OCC_RSP_TOTAL_LEN_SYNC &&
			     !aem_not_ack) ||
			    (fn_data->fc == AEM_FC_BAD_OCC_RSP_TOTAL_LEN_AEM &&
			     aem_not_ack))
				aeoltl -= 1;

			//Now the data
			uint8_t *spec = (uint8_t *)(data+1);

			if (data->aeosil) {
				memcpy(spec, event->spec_info, event->spec_info_len);
				spec += event->spec_info_len;
			}

			if (data->aeovsil) {
				memcpy(spec, event->vend_spec_info, event->vend_spec_info_len);
				spec += event->vend_spec_info_len;
			}

			data = (struct nvme_mi_aem_occ_data *)(spec);
		}
	}

	nvme_mi_aem_aeolli_set_aeoltl(list_hdr, aeoltl);
	test_peer.tx_buf_len = hdr_len + aeoltl;

	if ((fn_data->fc == AEM_FC_BAD_OCC_RSP_BUFFER_LEN_SYNC && !aem_not_ack) ||
		(fn_data->fc == AEM_FC_BAD_OCC_RSP_BUFFER_LEN_AEM && aem_not_ack))
		test_peer.tx_buf_len--;

	test_set_tx_mic(&test_peer);
}

static void check_aem_sync_message(struct nvme_mi_aem_enabled_map *expected_mask,
				   struct nvme_mi_aem_enabled_map *expected_state,
				   struct aem_rcv_enable_fn_data *fn_data)
{
	//Check the RX buffer for the endpoint.  We should be getting a CONFIG SET AEM
	//with all enabled items disabled
	struct nvme_mi_mi_req_hdr *req =
		(struct nvme_mi_mi_req_hdr *)test_peer.rx_buf;

	struct nvme_mi_aem_supported_list *list =
		(struct nvme_mi_aem_supported_list *)(req+1);

	assert(req->opcode == nvme_mi_mi_opcode_configuration_set);
	assert((le32_to_cpu(req->cdw0) & 0xFF) == NVME_MI_CONFIG_AE);
	assert(list->hdr.aeslver == 0);

	int count = 0;
	//Count how many events we want to act are in the expected state
	for (int i = 0; i < 256; i++) {
		if (expected_mask->enabled[i])
			count++;
	}

	assert(list->hdr.numaes == count);
	assert(list->hdr.aeslhl == sizeof(struct nvme_mi_aem_supported_list));
	assert(list->hdr.aest == list->hdr.aeslhl +
		count * sizeof(struct nvme_mi_aem_supported_item));

	struct nvme_mi_aem_supported_item *item =
		(struct nvme_mi_aem_supported_item *)(list+1);

	//Check the items
	for (int i = 0; i < 256; i++) {
		if (expected_mask->enabled[i]) {
			bool found = false;

			for (int j = 0; j < count; j++) {
				if (nvme_mi_aem_aesi_get_aesid(item[j].aesi) == i &&
					nvme_mi_aem_aesi_get_aese(item[j].aesi) ==
					expected_state->enabled[i]) {
					found = true;
					break;
				}
			}
			assert(found);
		}
	}
}

static int aem_rcv_enable_fn(struct test_peer *peer, void *buf, size_t len, int sd)
{
	struct aem_rcv_enable_fn_data *fn_data = peer->tx_data;
	struct nvme_mi_mi_resp_hdr *tx_hdr = (struct nvme_mi_mi_resp_hdr *)peer->tx_buf;

	/* set up a few default response fields; caller may have
	 * initialised the rest of the response
	 */
	test_peer.tx_buf[0] = NVME_MI_MSGTYPE_NVME;
	test_peer.tx_buf[1] = test_peer.rx_buf[1] | (NVME_MI_ROR_RSP << 7);
	tx_hdr->status = 0;

	switch (fn_data->state) {
	case AEM_ES_GET_ENABLED:
	{
		assert(sd == peer->sd[TEST_PEER_SD_COMMANDS_IDX]);

		//First, we want to return some data about what is already enabled
		struct nvme_mi_aem_supported_list_header *list_hdr =
			(struct nvme_mi_aem_supported_list_header *)(tx_hdr+1);

		if (fn_data->fc == AEM_FC_BAD_GET_CONFIG_HEADER_LEN)
			list_hdr->aeslhl =
				sizeof(struct nvme_mi_aem_supported_list_header) - 1;
		else
			list_hdr->aeslhl =
				sizeof(struct nvme_mi_aem_supported_list_header);

		list_hdr->aeslver = 0;
		struct nvme_mi_aem_supported_item *item =
			(struct nvme_mi_aem_supported_item *)(list_hdr+1);
		int item_count = 0;

		list_hdr->numaes = 0;
		//Count how many events we want to act are enabled
		for (int i = 0; i < 256; i++) {
			if (fn_data->ep_enabled_map.enabled[i]) {
				list_hdr->numaes++;
				nvme_mi_aem_aesi_set_aesid(&item[item_count], i);
				nvme_mi_aem_aesi_set_aee(&item[item_count], 1);
				item[item_count].aesl =
					sizeof(struct nvme_mi_aem_supported_item);
				item_count++;
			}
		}

		list_hdr->aest = list_hdr->aeslhl +
			list_hdr->numaes * sizeof(struct nvme_mi_aem_supported_item);
		if (fn_data->fc == AEM_FC_BAD_GET_CONFIG_TOTAL_LEN)
			list_hdr->aest--;//Shrink

		test_peer.tx_buf_len =
			sizeof(struct nvme_mi_mi_resp_hdr) + list_hdr->aest;
		if (fn_data->fc == AEM_FC_BAD_GET_CONFIG_BUFFER_LEN)
			test_peer.tx_buf_len--;

		test_set_tx_mic(&test_peer);

		fn_data->state = AEM_ES_SET_TO_DISABLED;
		break;
	}
	case AEM_ES_SET_TO_DISABLED:
	{
		assert(sd == peer->sd[TEST_PEER_SD_COMMANDS_IDX]);

		struct nvme_mi_aem_enabled_map expected = {false};
		//The items in the ep_enabled_map should get disabled
		check_aem_sync_message(&fn_data->ep_enabled_map, &expected, fn_data);

		//Need to queue a reasonable response with no OCC
		struct nvme_mi_mi_resp_hdr *tx_hdr =
			(struct nvme_mi_mi_resp_hdr *)test_peer.tx_buf;
		struct nvme_mi_aem_occ_list_hdr *list_hdr =
			(struct nvme_mi_aem_occ_list_hdr *)(tx_hdr+1);

		list_hdr->aelver = 0;
		list_hdr->aeolhl = sizeof(*list_hdr);
		list_hdr->numaeo = 0;
		nvme_mi_aem_aeolli_set_aeoltl(list_hdr, list_hdr->aeolhl);

		test_peer.tx_buf_len = sizeof(struct nvme_mi_mi_resp_hdr) +
			nvme_mi_aem_aeolli_get_aeoltl(list_hdr->aeolli);

		test_set_tx_mic(&test_peer);

		fn_data->state = AEM_ES_ENABLE_SET_ENABLED;
		break;
	}
	case AEM_ES_ENABLE_SET_ENABLED:
		assert(sd == peer->sd[TEST_PEER_SD_COMMANDS_IDX]);

		//We should verify the right things are enabled
		//The items in the host enable map should get enabled
		check_aem_sync_message(&fn_data->host_enabled_map,
			&fn_data->host_enabled_map, fn_data);

		//Prepare an OCC list response
		populate_tx_occ_list(false, fn_data, &fn_data->host_enabled_map);

		fn_data->state = AEM_ES_PROCESS;
		break;
	case AEM_ES_PROCESS:
		//This case is actually a TX without any request from the host
		assert(sd == peer->sd[TEST_PEER_SD_AEMS_IDX]);

		//Prepare an OCC list response
		populate_tx_occ_list(true, fn_data, &fn_data->aem_during_process_map);

		fn_data->state = AEM_ES_ACK_RESPONSE;
		break;
	case AEM_ES_ACK_RESPONSE:
		assert(sd == peer->sd[TEST_PEER_SD_COMMANDS_IDX]);

		//Prepare an OCC list response
		populate_tx_occ_list(false, fn_data, &fn_data->ack_events_map);

		fn_data->state = AEM_ES_ACK_RECEIVED;
		break;
	default:
		assert(false);//Not expected
	}

	return 0;
}

enum nvme_mi_aem_handler_next_action aem_handler(nvme_mi_ep_t ep, size_t num_events, void *userdata)
{
	struct aem_rcv_enable_fn_data *fn_data = userdata;

	fn_data->callback_count++;

	switch (fn_data->state) {
	case AEM_ES_PROCESS:
	case AEM_ES_ACK_RESPONSE:
	case AEM_ES_ACK_RECEIVED:
	{
		//This means we just sent out first OCC data
		int item_count = 0;
		struct nvme_mi_aem_enabled_map *map;

		//Count how many events we want to act are enabled
		switch (fn_data->state) {
		case AEM_ES_PROCESS:
			map = &fn_data->host_enabled_map;
			break;
		case AEM_ES_ACK_RESPONSE:
			map = &fn_data->aem_during_process_map;
			break;
		case AEM_ES_ACK_RECEIVED:
			map = &fn_data->ack_events_map;
			break;
		default:
			assert(false);
		}

		for (int i = 0; i < 256; i++)
			if (map->enabled[i])
				item_count++;

		assert(num_events == item_count);

		for (int i = 0; i < num_events; i++) {
			struct nvme_mi_event *e = nvme_mi_aem_get_next_event(ep);
			uint8_t idx = e->aeoi;

			assert(fn_data->events[idx]);
			assert(fn_data->host_enabled_map.enabled[idx]);
			assert(fn_data->events[idx]->aeocidi == e->aeocidi);
			assert(fn_data->events[idx]->aessi == e->aessi);
			assert(fn_data->events[idx]->spec_info_len ==
				e->spec_info_len);
			assert(memcmp(fn_data->events[idx]->spec_info,
				e->spec_info, e->spec_info_len) == 0);
			assert(fn_data->events[idx]->vend_spec_info_len ==
				e->vend_spec_info_len);
			assert(memcmp(fn_data->events[idx]->vend_spec_info,
				e->vend_spec_info, e->vend_spec_info_len) == 0);
		}

		assert(nvme_mi_aem_get_next_event(ep) == NULL);
		break;
	}
	default:
		assert(false);
	}

	return NVME_MI_AEM_HNA_ACK;
}

static void aem_test_aem_api_helper(nvme_mi_ep_t ep,
	struct nvme_mi_aem_config *config, int expected_event_count)
{
	struct aem_rcv_enable_fn_data *fn_data =
		(struct aem_rcv_enable_fn_data *)test_peer.tx_data;
	int rc = 0;

	test_peer.tx_fn = aem_rcv_enable_fn;

	//This should not work outside the handler
	assert(nvme_mi_aem_get_next_event(ep) == NULL);

	rc = nvme_mi_aem_enable(ep, config, test_peer.tx_data);
	assert(rc == 0);

	//This should not work outside the handler
	assert(nvme_mi_aem_get_next_event(ep) == NULL);

	rc = nvme_mi_aem_process(ep, test_peer.tx_data);
	assert(rc == 0);

	//One for initial enable, one for AEM.  No ACK events
	assert(fn_data->callback_count == expected_event_count);

	//This should not work outside the handler
	assert(nvme_mi_aem_get_next_event(ep) == NULL);
}

static void aem_test_aem_disable_helper(nvme_mi_ep_t ep,
	struct aem_rcv_enable_fn_data *fn_data)
{
	memcpy(&fn_data->ep_enabled_map, &fn_data->host_enabled_map,
		sizeof(fn_data->host_enabled_map));

	fn_data->state = AEM_ES_GET_ENABLED;//This is the flow for disabling
	assert(nvme_mi_aem_disable(ep) == 0);
}

static void test_mi_aem_ep_based_failure_helper(nvme_mi_ep_t ep,
	enum aem_failure_condition fc, struct test_peer *peer)
{
	struct aem_rcv_enable_fn_data fn_data = {0};
	struct nvme_mi_aem_config config = {0};

	config.aemd = 1;
	config.aerd = 2;
	config.enabled_map.enabled[3] = true;
	fn_data.aem_during_process_map.enabled[3] = true;
	struct nvme_mi_event e = {0};

	e.aeoi = 3;
	e.spec_info_len = 0;
	fn_data.events[3] = &e;

	memcpy(&fn_data.host_enabled_map, &config.enabled_map, sizeof(config.enabled_map));

	config.aem_handler = aem_handler;
	peer->tx_data = (void *) &fn_data;
	peer->tx_fn = aem_rcv_enable_fn;

	fn_data.fc = fc;
	switch (fc) {
	case AEM_FC_BAD_GET_CONFIG_HEADER_LEN:
	case AEM_FC_BAD_GET_CONFIG_TOTAL_LEN:
	case AEM_FC_BAD_GET_CONFIG_BUFFER_LEN:
	case AEM_FC_BAD_OCC_RSP_HDR_LEN_SYNC:
	case AEM_FC_BAD_OCC_RSP_TOTAL_LEN_SYNC:
	case AEM_FC_BAD_OCC_RSP_BUFFER_LEN_SYNC:
		//These all should fail before processing
		assert(nvme_mi_aem_enable(ep, &config, &fn_data) == -1);
		assert(errno == EPROTO);
		break;
	case AEM_FC_BAD_OCC_RSP_HDR_LEN_AEM:
	case AEM_FC_BAD_OCC_RSP_TOTAL_LEN_AEM:
	case AEM_FC_BAD_OCC_RSP_BUFFER_LEN_AEM:
		//These should fail on the processing
		assert(nvme_mi_aem_enable(ep, &config, &fn_data) == 0);
		assert(nvme_mi_aem_process(ep, &fn_data) == -1);
		assert(errno == EPROTO);
		break;
	default:
		assert(false);//Unexpected
	}
}

/* test: Check validation of endpoint messages in various stages of aem handling */
static void test_mi_aem_ep_based_failure_conditions(nvme_mi_ep_t ep, struct test_peer *peer)
{
	test_mi_aem_ep_based_failure_helper(ep, AEM_FC_BAD_GET_CONFIG_HEADER_LEN, peer);
	test_mi_aem_ep_based_failure_helper(ep, AEM_FC_BAD_GET_CONFIG_TOTAL_LEN, peer);
	test_mi_aem_ep_based_failure_helper(ep, AEM_FC_BAD_GET_CONFIG_BUFFER_LEN, peer);
	test_mi_aem_ep_based_failure_helper(ep, AEM_FC_BAD_OCC_RSP_HDR_LEN_SYNC, peer);
	test_mi_aem_ep_based_failure_helper(ep, AEM_FC_BAD_OCC_RSP_HDR_LEN_AEM, peer);
	test_mi_aem_ep_based_failure_helper(ep, AEM_FC_BAD_OCC_RSP_TOTAL_LEN_SYNC, peer);
	test_mi_aem_ep_based_failure_helper(ep, AEM_FC_BAD_OCC_RSP_TOTAL_LEN_AEM, peer);
	test_mi_aem_ep_based_failure_helper(ep, AEM_FC_BAD_OCC_RSP_BUFFER_LEN_SYNC, peer);
	test_mi_aem_ep_based_failure_helper(ep, AEM_FC_BAD_OCC_RSP_BUFFER_LEN_AEM, peer);
}

/* test: Check aem process logic when API used improperly */
static void test_mi_aem_enable_invalid_usage(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_aem_config config = {0};

	config.aem_handler = aem_handler;
	config.enabled_map.enabled[0] = false;
	config.aemd = 1;
	config.aerd = 2;

	//Call with invalid config due to nothing enabled
	assert(nvme_mi_aem_enable(ep, &config, NULL) == -1);

	config.aem_handler = NULL;
	config.enabled_map.enabled[0] = true;

	//Call with invalid config due to no callback
	assert(nvme_mi_aem_enable(ep, &config, NULL) == -1);

	//Call with invalid config due to being NULL
	assert(nvme_mi_aem_enable(ep, NULL, NULL) == -1);

	config.aem_handler = aem_handler;
	config.enabled_map.enabled[0] = true;

	//Call with invalid endpoint
	assert(nvme_mi_aem_enable(NULL, &config, NULL) == -1);
}

/* test: Check aem process logic when API used improperly */
static void test_mi_aem_process_invalid_usage(nvme_mi_ep_t ep, struct test_peer *peer)
{
	//Without calling enable first
	assert(nvme_mi_aem_process(ep, NULL) == -1);

	//Call with invalid ep
	assert(nvme_mi_aem_process(NULL, NULL) == -1);
}

/* test: Check aem disable logic when API used improperly */
static void test_mi_aem_disable_invalid_usage(nvme_mi_ep_t ep, struct test_peer *peer)
{
	assert(nvme_mi_aem_disable(NULL) == -1);
}

static void test_mi_aem_get_enabled_invalid_usage(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_aem_enabled_map map;

	assert(nvme_mi_aem_get_enabled(ep, NULL) == -1);
	assert(nvme_mi_aem_get_enabled(NULL, &map) == -1);
}

/* test: Check aem get enabled logic*/
static void test_mi_aem_get_enabled(nvme_mi_ep_t ep, struct test_peer *peer)
{
	//When no events enabled on Endpoint
	struct aem_rcv_enable_fn_data fn_data = {0};
	struct nvme_mi_aem_enabled_map map;

	test_peer.tx_fn = aem_rcv_enable_fn;
	peer->tx_data = (void *) &fn_data;
	fn_data.ep_enabled_map.enabled[8] = true;
	fn_data.ep_enabled_map.enabled[20] = true;
	fn_data.ep_enabled_map.enabled[51] = true;
	fn_data.ep_enabled_map.enabled[255] = true;

	assert(nvme_mi_aem_get_enabled(ep, &map) == 0);
	assert(memcmp(&fn_data.ep_enabled_map, &map, sizeof(map)) == 0);
}


/* test: Check aem disable logic when called without an enable */
static void test_mi_aem_disable_no_enable(nvme_mi_ep_t ep, struct test_peer *peer)
{
	//When no events enabled on Endpoint
	struct aem_rcv_enable_fn_data fn_data = {0};

	test_peer.tx_fn = aem_rcv_enable_fn;
	peer->tx_data = (void *) &fn_data;

	aem_test_aem_disable_helper(ep, &fn_data);

	//When some events enabled on Endpoint
	fn_data.ep_enabled_map.enabled[45] = true;

	aem_test_aem_disable_helper(ep, &fn_data);
}

/* test: Check aem enable logic with ack carrying events */
static void test_mi_aem_api_w_ack_events(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct aem_rcv_enable_fn_data fn_data = {0};
	struct nvme_mi_aem_config config = {0};

	config.aemd = 1;
	config.aerd = 2;
	peer->tx_data = (void *) &fn_data;
	config.aem_handler = aem_handler;

	config.enabled_map.enabled[5] = true;
	config.enabled_map.enabled[15] = true;

	fn_data.aem_during_process_map.enabled[5] = true;

	//No ack_events_map will be enabled in this test
	fn_data.ack_events_map.enabled[15] = true;

	//Will have EP have nothing enabled at start (ep_enabled_map)

	struct nvme_mi_event ev5 = {0};

	ev5.aeoi = 5;
	ev5.aeocidi = 2;
	ev5.aessi = 3;

	struct nvme_mi_event ev15 = {0};
	uint8_t ev15_spec[] = { 45, 15};

	ev15.aeoi = 15;
	ev15.aeocidi = 60213;
	ev15.aessi = 200;
	ev15.spec_info = ev15_spec;
	ev15.spec_info_len = sizeof(ev15_spec);

	fn_data.events[5] = &ev5;
	fn_data.events[15] = &ev15;

	memcpy(&fn_data.host_enabled_map, &config.enabled_map, sizeof(config.enabled_map));

	aem_test_aem_api_helper(ep, &config, 3);

	aem_test_aem_disable_helper(ep, &fn_data);
}

/* test: Check aem enable logic */
static void test_mi_aem_api_simple(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct aem_rcv_enable_fn_data fn_data = {0};
	struct nvme_mi_aem_config config = {0};

	config.aemd = 1;
	config.aerd = 2;
	peer->tx_data = (void *) &fn_data;
	config.aem_handler = aem_handler;

	config.enabled_map.enabled[1] = true;
	config.enabled_map.enabled[3] = true;
	config.enabled_map.enabled[16] = true;

	fn_data.aem_during_process_map.enabled[3] = true;

	//No ack_events_map will be enabled in this test

	fn_data.ep_enabled_map.enabled[3] = true;
	fn_data.ep_enabled_map.enabled[20] = true;
	fn_data.ep_enabled_map.enabled[200] = true;

	struct nvme_mi_event ev1 = {0};
	uint8_t ev1_spec[] = { 98, 56, 32, 12};

	ev1.aeoi = 1;
	ev1.aeocidi = 2;
	ev1.aessi = 3;
	ev1.spec_info = ev1_spec;
	ev1.spec_info_len = sizeof(ev1_spec);

	struct nvme_mi_event ev3 = {0};
	uint8_t ev3_spec[] = { 45, 15};

	ev3.aeoi = 3;
	ev3.aeocidi = 4;
	ev3.aessi = 5;
	ev3.spec_info = ev3_spec;
	ev3.spec_info_len = sizeof(ev3_spec);

	struct nvme_mi_event ev16 = {0};

	ev16.aeoi = 16;
	ev16.aeocidi = 6;
	ev16.aessi = 7;

	fn_data.events[1] = &ev1;
	fn_data.events[3] = &ev3;
	fn_data.events[16] = &ev16;

	memcpy(&fn_data.host_enabled_map, &config.enabled_map, sizeof(config.enabled_map));

	aem_test_aem_api_helper(ep, &config, 2);

	aem_test_aem_disable_helper(ep, &fn_data);
}

#define DEFINE_TEST(name) { #name, test_ ## name }
struct test {
	const char *name;
	void (*fn)(nvme_mi_ep_t, struct test_peer *);
} tests[] = {
	DEFINE_TEST(rx_err),
	DEFINE_TEST(tx_none),
	DEFINE_TEST(tx_err),
	DEFINE_TEST(tx_short),
	DEFINE_TEST(read_mi_data),
	DEFINE_TEST(poll_err),
	DEFINE_TEST(mi_resp_err),
	DEFINE_TEST(mi_resp_unaligned),
	DEFINE_TEST(mi_resp_unaligned_expected),
	DEFINE_TEST(admin_resp_err),
	DEFINE_TEST(admin_resp_sizes),
	DEFINE_TEST(poll_timeout_value),
	DEFINE_TEST(poll_timeout),
	DEFINE_TEST(mpr_mi),
	DEFINE_TEST(mpr_admin),
	DEFINE_TEST(mpr_admin_quirked),
	DEFINE_TEST(mpr_timeouts),
	DEFINE_TEST(mpr_timeout_clamp),
	DEFINE_TEST(mpr_mprt_zero),
	DEFINE_TEST(mi_aem_api_simple),
	DEFINE_TEST(mi_aem_api_w_ack_events),
	DEFINE_TEST(mi_aem_disable_no_enable),
	DEFINE_TEST(mi_aem_process_invalid_usage),
	DEFINE_TEST(mi_aem_enable_invalid_usage),
	DEFINE_TEST(mi_aem_disable_invalid_usage),
	DEFINE_TEST(mi_aem_get_enabled),
	DEFINE_TEST(mi_aem_get_enabled_invalid_usage),
	DEFINE_TEST(mi_aem_ep_based_failure_conditions),
};

static void run_test(struct test *test, FILE *logfd, nvme_mi_ep_t ep,
		     struct test_peer *peer)
{
	printf("Running test %s...", test->name);
	fflush(stdout);
	test->fn(ep, peer);
	printf("  OK\n");
	test_print_log_buf(logfd);
}

int main(void)
{
	nvme_root_t root;
	nvme_mi_ep_t ep;
	unsigned int i;
	FILE *fd;

	fd = test_setup_log();

	__nvme_mi_mctp_set_ops(&ops);

	root = nvme_mi_create_root(fd, DEFAULT_LOGLEVEL);
	assert(root);

	ep = nvme_mi_open_mctp(root, 0, 0);
	assert(ep);

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		reset_test_peer();
		run_test(&tests[i], fd, ep, &test_peer);
	}

	nvme_mi_close(ep);
	nvme_mi_free_root(root);

	test_close_log(fd);

	return EXIT_SUCCESS;
}
