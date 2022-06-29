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

	/* Optional, called after RX, may set tx_buf according to request.
	 * Return value stored in rx_res, may be used by test */
	rx_test_fn	rx_fn;
	void		*rx_data;
	int		rx_res;

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


	if (test_peer.rx_fn) {
		test_peer.rx_res = test_peer.rx_fn(&test_peer,
						   test_peer.rx_buf,
						   test_peer.rx_buf_len);
	} else {
		/* set up a few default response fields; caller may have
		 * initialised the rest of the response */
		test_peer.tx_buf[0] = NVME_MI_MSGTYPE_NVME;
		test_peer.tx_buf[1] = test_peer.rx_buf[1] | (NVME_MI_ROR_RSP << 7);
		test_set_tx_mic(&test_peer);
	}

	errno = test_peer.rx_errno;

	return test_peer.rx_rc ?: (pos - 1);
}

ssize_t __wrap_recvmsg(int sd, struct msghdr *hdr, int flags)
{
	size_t i, pos, len;

	assert(sd == test_peer.sd);

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

static struct __mi_mctp_socket_ops ops = {
	__wrap_socket,
	__wrap_sendmsg,
	__wrap_recvmsg,
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

static void test_read_mi_data(nvme_mi_ep_t ep, struct test_peer *peer)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	/* empty response data */
	peer->tx_buf_len = 8 + 32;

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc == 0);
}

#define DEFINE_TEST(name) { #name, test_ ## name }
struct test {
	const char *name;
	void (*fn)(nvme_mi_ep_t, struct test_peer *);
} tests[] = {
	DEFINE_TEST(rx_err),
	DEFINE_TEST(tx_err),
	DEFINE_TEST(tx_short),
	DEFINE_TEST(read_mi_data),
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
