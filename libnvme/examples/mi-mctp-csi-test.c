// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 */

/**
 * mi-mctp-csi-test: open a MI connection over MCTP, and send two commands
 * in parallel with different CSI buffers
 */

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <pthread.h>

#include <libnvme-mi.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>

void fhexdump(FILE *fp, const unsigned char *buf, int len)
{
	const int row_len = 16;
	int i, j;

	for (i = 0; i < len; i += row_len) {
		char hbuf[row_len * strlen("00 ") + 1];
		char cbuf[row_len + strlen("|") + 1];

		for (j = 0; (j < row_len) && ((i+j) < len); j++) {
			unsigned char c = buf[i + j];

			sprintf(hbuf + j * 3, "%02x ", c);

			if (!isprint(c))
				c = '.';

			sprintf(cbuf + j, "%c", c);
		}

		strcat(cbuf, "|");

		fprintf(fp, "%08x  %*s |%s\n", i,
				0 - (int)sizeof(hbuf) + 1, hbuf, cbuf);
	}
}

void hexdump(const unsigned char *buf, int len)
{
	fhexdump(stdout, buf, len);
}

int do_get_log_page(nvme_mi_ep_t ep, int argc, char **argv)
{
	struct nvme_get_log_args args = { 0 };
	struct nvme_mi_ctrl *ctrl;
	uint8_t buf[4096];
	uint16_t ctrl_id;
	int rc, tmp;

	if (argc < 2) {
		fprintf(stderr, "no controller ID specified\n");
		return -1;
	}

	tmp = atoi(argv[1]);
	if (tmp < 0 || tmp > 0xffff) {
		fprintf(stderr, "invalid controller ID\n");
		return -1;
	}

	ctrl_id = tmp & 0xffff;

	args.args_size = sizeof(args);
	args.log = buf;
	args.len = sizeof(buf);

	if (argc > 2) {
		tmp = atoi(argv[2]);
		args.lid = tmp & 0xff;
	} else {
		args.lid = 0x1;
	}

	ctrl = nvme_mi_init_ctrl(ep, ctrl_id);
	if (!ctrl) {
		warn("can't create controller");
		return -1;
	}

	rc = nvme_mi_admin_get_log(ctrl, &args);
	if (rc) {
		warn("can't perform Get Log page command");
		return -1;
	}

	printf("Get log page (log id = 0x%02x) data:\n", args.lid);
	hexdump(buf, args.len);

	return 0;
}

struct thread_struct {
	nvme_mi_ep_t ep;
	int argc;
	char **argv;
	int rc;
};

void *csi_thread_helper(void *context)
{
	struct thread_struct *s = (struct thread_struct *) context;

	s->rc = do_get_log_page(s->ep, s->argc, s->argv);
	return NULL;
}

enum action {
	ACTION_CSI_TEST,
};

int do_csi_test(struct nvme_global_ctx *ctx, int net, __u8 eid,
		int argc, char **argv)
{
	int rc = 0;
	nvme_mi_ep_t ep1, ep2;

	ep1 = nvme_mi_open_mctp(ctx, net, eid);
	if (!ep1)
		errx(EXIT_FAILURE, "can't open MCTP endpoint %d:%d", net, eid);
	ep2 = nvme_mi_open_mctp(ctx, net, eid);
	if (!ep2)
		errx(EXIT_FAILURE, "can't open MCTP endpoint %d:%d", net, eid);

	pthread_t thread;

	nvme_mi_set_csi(ep1, 0);//Not necessary, but to be explicit
	nvme_mi_set_csi(ep2, 1);
	struct thread_struct s;

	s.ep = ep2;
	s.argc = argc;
	s.argv = argv;

	// Create a new thread to run my_function
	if (pthread_create(&thread, NULL, csi_thread_helper, &s)) {
		fprintf(stderr, "Error creating thread\n");
		return 1;
	}

	rc = do_get_log_page(ep1, argc, argv);

	// Main thread continues to do other work
	printf("Main thread finished with rc=%d\n", rc);

	// Wait for the created thread to finish
	if (pthread_join(thread, NULL)) {
		fprintf(stderr, "Error joining thread\n");
		return 2;
	}

	printf("Second thread finished with rc=%d\n", s.rc);

	nvme_mi_close(ep1);
	nvme_mi_close(ep2);

	if (rc)
		return rc;
	if (s.rc)
		return s.rc;
	return 0;
}

static int do_action_endpoint(enum action action,
				struct nvme_global_ctx *ctx,
				int net,
				uint8_t eid,
				int argc,
				char **argv)
{
	int rc;

	switch (action) {
	case ACTION_CSI_TEST:
		rc = do_csi_test(ctx, net, eid, argc, argv);
		break;
	default:
		/* This shouldn't be possible, as we should be covering all
		 * of the enum action options above. Hoever, keep the compilers
		 * happy and fail gracefully.
		 */
		fprintf(stderr, "invalid action %d?\n", action);
		rc = -1;
	}
	return rc;
}

int main(int argc, char **argv)
{
	struct nvme_global_ctx *ctx;
	enum action action;
	bool usage = true;
	uint8_t eid = 0;
	int rc = 0, net = 0;

	if (argc >= 5) {
		usage = false;
		net = atoi(argv[1]);
		eid = atoi(argv[2]) & 0xff;
		argv += 2;
		argc -= 2;
	}

	if (usage) {
		fprintf(stderr,
			"usage: %s <net> <eid> [action] [action args]\n",
			argv[0]);
		fprintf(stderr, "where action is:\n"
			"  csi-test <controller-id> [<log-id>]\n"
			"\n"
			);
		return EXIT_FAILURE;
	}

	char *action_str = argv[1];

	argc--;
	argv++;

	if (!strcmp(action_str, "csi-test")) {
		action = ACTION_CSI_TEST;
	} else {
		fprintf(stderr, "invalid action '%s'\n", action_str);
		return EXIT_FAILURE;
	}

	ctx = nvme_mi_create_global_ctx(stderr, DEFAULT_LOGLEVEL);
	if (!ctx)
		err(EXIT_FAILURE, "can't create NVMe root");

	rc = do_action_endpoint(action, ctx, net, eid, argc, argv);
	nvme_mi_free_global_ctx(ctx);

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}


