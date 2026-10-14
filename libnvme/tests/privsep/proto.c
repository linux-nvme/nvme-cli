// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *
 * Sends malformed requests to nvme-privsep-helper with mock-ioctl
 * preloaded. Usage: test-privsep-proto HELPER MOCK_LIBRARY
 */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#ifdef TEST_SED
#include <linux/sed-opal.h>
#endif

#include "privsep/privsep-proto.h"

#include "../ioctl/util.h"
#include "mock.h"

static const char *helper;

struct helper {
	int sock;
	pid_t pid;
};

static struct helper start(void)
{
	struct helper h;
	int sv[2];

	check(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv), "socketpair: %m");
	h.pid = fork();
	check(h.pid >= 0, "fork: %m");
	if (!h.pid) {
		if (dup2(sv[1], LIBNVME_PRIVSEP_FD) < 0)
			_exit(127);
		execl(helper, "nvme-privsep-helper", (char *)NULL);
		_exit(127);
	}
	close(sv[1]);
	h.sock = sv[0];

	return h;
}

static int stop(struct helper *h)
{
	int status;

	close(h->sock);
	check(waitpid(h->pid, &status, 0) == h->pid, "waitpid: %m");
	check(WIFEXITED(status), "helper crashed");

	return WEXITSTATUS(status);
}

static void request(struct helper *h, __u32 op, __u32 id, const void *p,
		__u32 len)
{
	struct libnvme_privsep_req req = {
		.op = op,
		.id = id,
		.len = len,
	};

	check(!libnvme_privsep_send(h->sock, &req, sizeof(req)), "send");
	if (len)
		check(!libnvme_privsep_send(h->sock, p, len), "send payload");
}

static __s32 response(struct helper *h, struct libnvme_privsep_resp *resp)
{
	check(!libnvme_privsep_recv(h->sock, resp, sizeof(*resp)),
	      "helper closed the connection");

	return resp->status;
}

static bool closed(struct helper *h)
{
	struct libnvme_privsep_resp resp;

	return libnvme_privsep_recv(h->sock, &resp, sizeof(resp)) == -EPIPE;
}

static void hello(struct helper *h)
{
	struct libnvme_privsep_resp resp;

	request(h, LIBNVME_PRIVSEP_OP_HELLO, 0, NULL, 0);
	check(!response(h, &resp) &&
	      resp.result == LIBNVME_PRIVSEP_VERSION,
	      "hello failed");
}

static void test_clean_exit(void)
{
	struct helper h = start();

	hello(&h);
	check(!stop(&h), "helper failed on a clean shutdown");
}

static void test_no_hello(void)
{
	struct helper h = start();

	request(&h, LIBNVME_PRIVSEP_OP_CLOSE, 1, NULL, 0);
	check(closed(&h), "request before hello served");
	check(stop(&h), "helper did not report the protocol error");
}

static void test_oversized(void)
{
	struct libnvme_privsep_req req = {
		.op = LIBNVME_PRIVSEP_OP_ADMIN,
		.id = 1,
		.len = LIBNVME_PRIVSEP_MAX_PAYLOAD + 1,
	};
	struct helper h = start();

	hello(&h);
	/* The helper must reject the header without reading the payload. */
	check(!libnvme_privsep_send(h.sock, &req, sizeof(req)), "send");
	check(closed(&h), "oversized request served");
	stop(&h);
}

static void test_errors(void)
{
	struct libnvme_privsep_cmd pcmd = {
		.opcode = 0x06,
		.data_len = 16,
	};
	struct libnvme_privsep_resp resp;
	struct helper h = start();
	char buf[64];

	hello(&h);

	request(&h, LIBNVME_PRIVSEP_OP_CLOSE, 1, NULL, 0);
	check(response(&h, &resp) == -EINVAL && !resp.len,
	      "close of an unknown handle");

	request(&h, LIBNVME_PRIVSEP_OP_ADMIN, 0, &pcmd, sizeof(pcmd));
	check(response(&h, &resp) == -EINVAL, "handle id 0 accepted");

	request(&h, LIBNVME_PRIVSEP_OP_ADMIN, 1000, &pcmd, sizeof(pcmd));
	check(response(&h, &resp) == -EINVAL, "handle id 1000 accepted");

	request(&h, LIBNVME_PRIVSEP_OP_ADMIN, 1, &pcmd, sizeof(pcmd) - 1);
	check(response(&h, &resp) == -EINVAL, "truncated command accepted");

	/* An OPEN payload whose name is not NUL-terminated. */
	memset(buf, 'a', sizeof(buf));
	request(&h, LIBNVME_PRIVSEP_OP_OPEN, 0, buf, sizeof(buf));
	check(response(&h, &resp) == -EINVAL, "unterminated name accepted");

	request(&h, LIBNVME_PRIVSEP_OP_OPEN, 0, NULL, 0);
	check(response(&h, &resp) == -EINVAL, "empty open accepted");

	request(&h, 99, 0, NULL, 0);
	check(response(&h, &resp) == -EOPNOTSUPP, "unknown op accepted");

	/* The helper still serves requests after the errors. */
	hello(&h);
	check(!stop(&h), "helper failed after error responses");
}

/* Return: the handle id. */
static __u32 open_dev(struct helper *h, const char *name)
{
	struct libnvme_privsep_open open_req = {
		.flags = O_RDONLY,
	};
	struct libnvme_privsep_open_resp open_resp;
	struct libnvme_privsep_resp resp;
	char payload[sizeof(open_req) + LIBNVME_PRIVSEP_MAX_NAME];
	size_t len = strlen(name) + 1;

	memcpy(payload, &open_req, sizeof(open_req));
	memcpy(payload + sizeof(open_req), name, len);
	request(h, LIBNVME_PRIVSEP_OP_OPEN, 0, payload,
		sizeof(open_req) + len);
	check(!response(h, &resp) && resp.result, "open failed");
	check(resp.len == sizeof(open_resp), "open response length");
	check(!libnvme_privsep_recv(h->sock, &open_resp, resp.len),
	      "open payload");

	return resp.result;
}

static void test_write_len(void)
{
	struct libnvme_privsep_cmd pcmd = {
		.opcode = 0x09,
		.data_len = 32,
	};
	struct libnvme_privsep_resp resp;
	struct helper h = start();
	char data[sizeof(pcmd) + 16];
	__u32 id;

	hello(&h);
	id = open_dev(&h, "NVME_TEST_FD");

	/* A write command with less data than data_len. */
	memcpy(data, &pcmd, sizeof(pcmd));
	request(&h, LIBNVME_PRIVSEP_OP_ADMIN, id, data, sizeof(data));
	check(response(&h, &resp) == -EINVAL, "short write data accepted");
	check(!stop(&h), "helper failed");
}

static void test_device_op_len(void)
{
	struct libnvme_privsep_block_size bs = {
		.block_size = 4096,
	};
	struct libnvme_privsep_resp resp;
	struct helper h = start();
	__u32 id;

	hello(&h);

	request(&h, LIBNVME_PRIVSEP_OP_RESET_CTRL, 1, NULL, 0);
	check(response(&h, &resp) == -EINVAL, "reset of an unknown handle");

	id = open_dev(&h, "NVME_TEST_FD");
	request(&h, LIBNVME_PRIVSEP_OP_RESET_CTRL, id, &bs, sizeof(bs));
	check(response(&h, &resp) == -EINVAL, "reset with payload accepted");

	request(&h, LIBNVME_PRIVSEP_OP_UPDATE_BLOCK_SIZE, id, &bs,
		sizeof(bs) - 1);
	check(response(&h, &resp) == -EINVAL,
	      "truncated block size accepted");

	request(&h, LIBNVME_PRIVSEP_OP_UPDATE_BLOCK_SIZE, id, NULL, 0);
	check(response(&h, &resp) == -EINVAL, "missing block size accepted");

	check(!stop(&h), "helper failed");
}

static void test_regs_len(void)
{
	struct libnvme_privsep_reg reg = {
		.len = LIBNVME_PRIVSEP_MAX_REGS + 4,
	};
	struct libnvme_privsep_resp resp;
	struct helper h = start();
	__u32 id;

	hello(&h);
	id = open_dev(&h, "NVME_TEST_FD");

	request(&h, LIBNVME_PRIVSEP_OP_READ_REGS, id, &reg, sizeof(reg));
	check(response(&h, &resp) == -EINVAL && !resp.len,
	      "oversized register read accepted");

	reg.len = 0;
	request(&h, LIBNVME_PRIVSEP_OP_READ_REGS, id, &reg, sizeof(reg));
	check(response(&h, &resp) == -EINVAL, "empty register read accepted");

	request(&h, LIBNVME_PRIVSEP_OP_READ_REGS, id, &reg, sizeof(reg) - 1);
	check(response(&h, &resp) == -EINVAL,
	      "truncated register request accepted");

	reg.value = 1ULL << 32;
	request(&h, LIBNVME_PRIVSEP_OP_WRITE_REG32, id, &reg, sizeof(reg));
	check(response(&h, &resp) == -EINVAL,
	      "64 bit value for a 32 bit register accepted");

	check(!stop(&h), "helper failed");
}

#ifdef TEST_SED
static void test_sed(void)
{
	/* Large enough for every argument sent below. */
	struct {
		struct libnvme_privsep_sed sed;
		union {
			struct opal_key key;
			struct opal_lock_unlock lu;
			struct opal_lr_act act;
		} arg;
	} req = {
		.sed.request = IOC_OPAL_TAKE_OWNERSHIP,
	};
	size_t len = sizeof(req.sed) + sizeof(req.arg.key);
	struct libnvme_privsep_resp resp;
	struct helper h = start();
	__u32 id;

	hello(&h);

	request(&h, LIBNVME_PRIVSEP_OP_SED, 1, &req, len);
	check(response(&h, &resp) == -EINVAL, "SED on an unknown handle");

	id = open_dev(&h, "nvme0n1");

	/* A wrong key returns a TCG status, so the request reached the mock. */
	request(&h, LIBNVME_PRIVSEP_OP_SED, id, &req, len);
	check(response(&h, &resp) == MOCK_TCG_NOT_AUTHORIZED,
	      "valid SED request not issued");

	request(&h, LIBNVME_PRIVSEP_OP_SED, id, &req, len - 1);
	check(response(&h, &resp) == -EINVAL, "truncated SED argument");

	request(&h, LIBNVME_PRIVSEP_OP_SED, id, &req, len + 1);
	check(response(&h, &resp) == -EINVAL, "oversized SED argument");

	/* The mock returns ENOTTY for the requests it does not know. */
	req.sed.request = IOC_OPAL_SAVE;
	request(&h, LIBNVME_PRIVSEP_OP_SED, id, &req,
		sizeof(req.sed) + sizeof(req.arg.lu));
	check(response(&h, &resp) == -EINVAL, "IOC_OPAL_SAVE accepted");

	req.sed.request = _IOW('p', 222, struct opal_lr_act);
	request(&h, LIBNVME_PRIVSEP_OP_SED, id, &req,
		sizeof(req.sed) + sizeof(req.arg.act));
	check(response(&h, &resp) == -EINVAL, "unknown request accepted");

	req.sed.request = IOC_OPAL_TAKE_OWNERSHIP;
	id = open_dev(&h, "nvme0");
	request(&h, LIBNVME_PRIVSEP_OP_SED, id, &req, len);
	check(response(&h, &resp) == -EINVAL, "SED on a controller");

	check(!stop(&h), "helper failed");
}
#else
static void test_sed(void)
{
}
#endif

static void test_fabrics(void)
{
	static const char refused[] = "nqn=" MOCK_NQN_REFUSED;
	char buf[LIBNVME_PRIVSEP_MAX_FABRICS + 1];
	struct libnvme_privsep_resp resp;
	struct helper h = start();

	hello(&h);

	request(&h, LIBNVME_PRIVSEP_OP_FABRICS, 0, NULL, 0);
	check(!response(&h, &resp), "reading the options failed");
	check(resp.len == strlen(MOCK_FABRICS_OPTIONS),
	      "options length %u", resp.len);
	check(!libnvme_privsep_recv(h.sock, buf, resp.len), "options");
	check(!memcmp(buf, MOCK_FABRICS_OPTIONS, resp.len), "options text");

	request(&h, LIBNVME_PRIVSEP_OP_FABRICS, 0, refused,
		strlen(refused));
	check(response(&h, &resp) == -ECONNREFUSED && !resp.len,
	      "connect error not returned");
	check(resp.result == LIBNVME_PRIVSEP_FABRICS_WRITE,
	      "failed step %llu", (unsigned long long)resp.result);

	request(&h, LIBNVME_PRIVSEP_OP_FABRICS, 1, NULL, 0);
	check(response(&h, &resp) == -EINVAL, "FABRICS with a handle id");

	memcpy(buf, "nqn=a", 6);
	request(&h, LIBNVME_PRIVSEP_OP_FABRICS, 0, buf, 6);
	check(response(&h, &resp) == -EINVAL, "NUL in connect arguments");

	memset(buf, 'a', sizeof(buf));
	request(&h, LIBNVME_PRIVSEP_OP_FABRICS, 0, buf,
		LIBNVME_PRIVSEP_MAX_FABRICS);
	check(response(&h, &resp) == -EINVAL,
	      "oversized connect arguments");

	check(!stop(&h), "helper failed");
}

int main(int argc, char **argv)
{
	check(argc == 3, "usage: %s HELPER MOCK_LIBRARY", argv[0]);
	helper = argv[1];
	check(!setenv("LD_PRELOAD", argv[2], 1), "setenv");

	test_clean_exit();
	test_no_hello();
	test_oversized();
	test_errors();
	test_write_len();
	test_device_op_len();
	test_regs_len();
	test_sed();
	test_fabrics();

	printf("privsep protocol tests passed\n");

	return EXIT_SUCCESS;
}
