// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *
 * Sends malformed requests to nvme-privsep-helper. Usage:
 * test-privsep-proto HELPER
 */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/wait.h>

#include "privsep/privsep-proto.h"

#include "../ioctl/util.h"

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

static void test_write_len(void)
{
	struct libnvme_privsep_open open_req = {
		.flags = O_RDONLY,
	};
	struct libnvme_privsep_cmd pcmd = {
		.opcode = 0x09,
		.data_len = 32,
	};
	struct libnvme_privsep_resp resp;
	struct helper h = start();
	char payload[sizeof(open_req) + sizeof("NVME_TEST_FD")];
	char data[sizeof(pcmd) + 16];
	__u32 id;

	hello(&h);
	memcpy(payload, &open_req, sizeof(open_req));
	memcpy(payload + sizeof(open_req), "NVME_TEST_FD",
	       sizeof("NVME_TEST_FD"));
	request(&h, LIBNVME_PRIVSEP_OP_OPEN, 0, payload, sizeof(payload));
	check(!response(&h, &resp) && resp.result, "open failed");
	id = resp.result;
	check(resp.len == sizeof(struct libnvme_privsep_open_resp),
	      "open response length");
	check(!libnvme_privsep_recv(h.sock, data, resp.len),
	      "open payload");

	/* A write command with less data than data_len. */
	memcpy(data, &pcmd, sizeof(pcmd));
	request(&h, LIBNVME_PRIVSEP_OP_ADMIN, id, data, sizeof(data));
	check(response(&h, &resp) == -EINVAL, "short write data accepted");
	check(!stop(&h), "helper failed");
}

int main(int argc, char **argv)
{
	check(argc == 2, "usage: %s HELPER", argv[0]);
	helper = argv[1];

	test_clean_exit();
	test_no_hello();
	test_oversized();
	test_errors();
	test_write_len();

	printf("privsep protocol tests passed\n");

	return EXIT_SUCCESS;
}
