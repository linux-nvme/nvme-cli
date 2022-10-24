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

typedef int (*rx_test_fn)(struct test_peer *peer, void *buf, size_t len);
typedef int (*poll_test_fn)(struct test_peer *peer,
			    struct pollfd *fds, nfds_t nfds, int timeout);

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
	int		sd;
} test_peer;

/* ensure tests start from a standard state */
void reset_test_peer(void)
{
	int tmp = test_peer.sd;
	memset(&test_peer, 0, sizeof(test_peer));
	test_peer.tx_buf[0] = NVME_MI_MSGTYPE_NVME;
	test_peer.rx_buf[0] = NVME_MI_MSGTYPE_NVME;
	test_peer.sd = tmp;
}

/* calculate MIC of peer-to-libnvme data, expand buf by 4 bytes and insert
 * the new MIC */
static void test_set_tx_mic(struct test_peer *peer)
{
	extern __u32 nvme_mi_crc32_update(__u32 crc, void *data, size_t len);
	__u32 crc = 0xffffffff;

	assert(peer->tx_buf_len + sizeof(crc) <= MAX_BUFSIZ);

	crc = nvme_mi_crc32_update(crc, peer->tx_buf, peer->tx_buf_len);
	*(uint32_t *)(peer->tx_buf + peer->tx_buf_len) = cpu_to_le32(~crc);
	peer->tx_buf_len += sizeof(crc);
}

int __wrap_socket(int family, int type, int protocol)
{
	/* we do an open here to give the mi-mctp code something to close() */
	test_peer.sd = open("/dev/null", 0);
	return test_peer.sd;
}

ssize_t __wrap_sendmsg(int sd, const struct msghdr *hdr, int flags)
{
	size_t i, pos;

	assert(sd == test_peer.sd);

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

	assert(sd == test_peer.sd);

	if (test_peer.tx_fn) {
		test_peer.tx_fn_res = test_peer.tx_fn(&test_peer,
						   test_peer.rx_buf,
						   test_peer.rx_buf_len);
	} else {
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
	assert(sd == test_peer.sd);

	switch (req) {
	case SIOCMCTPALLOCTAG:
		ctl->tag = 1 | MCTP_TAG_PREALLOC | MCTP_TAG_OWNER;
		break;
	case SIOCMCTPDROPTAG:
		assert(tag == 1 | MCTP_TAG_PREALLOC | MCTP_TAG_OWNER);
		break;
	};

	return 0;
}
#else
int test_ioctl_tag(int sd, unsigned long req, struct mctp_ioc_tag_ctl *ctl)
{
	assert(sd == test_peer.sd);
	return 0;
}
#endif

static struct __mi_mctp_socket_ops ops = {
	__wrap_socket,
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

static int tx_none(struct test_peer *peer, void *buf, size_t len)
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

/* test: unaligned response sizes - should always report a transport error */
static void test_admin_resp_sizes_unaligned(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_id_ctrl id;
	nvme_mi_ctrl_t ctrl;
	unsigned int i;
	int rc;

	ctrl = nvme_mi_init_ctrl(ep, 1);
	assert(ctrl);

	peer->tx_buf[4] = 0x02; /* internal error */

	for (i = 8; i <= 4096 + 8; i++) {
		peer->tx_buf_len = i;
		if (!(i & 0x3))
			continue;
		rc = nvme_mi_admin_identify_ctrl(ctrl, &id);
		assert(rc < 0);
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

static int tx_mpr(struct test_peer *peer, void *buf, size_t len)
{
	struct mpr_tx_info *tx_info = peer->tx_data;

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

static int tx_fn_mpr_poll(struct test_peer *peer, void *buf, size_t len)
{
	struct mpr_tx_info *tx_info = peer->tx_data;
	struct mpr_poll_info *poll_info = peer->poll_data;
	unsigned int mprt;

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
	DEFINE_TEST(admin_resp_err),
	DEFINE_TEST(admin_resp_sizes),
	DEFINE_TEST(admin_resp_sizes_unaligned),
	DEFINE_TEST(poll_timeout_value),
	DEFINE_TEST(poll_timeout),
	DEFINE_TEST(mpr_mi),
	DEFINE_TEST(mpr_admin),
	DEFINE_TEST(mpr_admin_quirked),
	DEFINE_TEST(mpr_timeouts),
	DEFINE_TEST(mpr_timeout_clamp),
	DEFINE_TEST(mpr_mprt_zero),
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
