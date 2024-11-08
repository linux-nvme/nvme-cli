// SPDX-License-Identifier: GPL-2.0-or-later

#include "lm-print.h"

#include <inttypes.h>

#include "common.h"
#include "util/types.h"

static struct lm_print_ops stdout_print_ops;

static void stdout_controller_state_data(struct nvme_lm_controller_state_data *data, size_t len,
					 __u32 offset)
{
	if (offset) {
		fprintf(stderr, "cannot understand non-zero offset\n");
		return;
	}

	int human = stdout_print_ops.flags & VERBOSE;

	if (sizeof(struct nvme_lm_controller_state_data_header) <= len) {
		printf("Header:\n");
		printf("%-45s: 0x%x\n", "Version (VER)", data->hdr.ver);
		printf("%-45s: 0x%x\n", "Controller State Attributes (CSATTR)", data->hdr.csattr);
		if (human)
			printf("  [0:0] : 0x%x Controller %sSuspended\n",
				data->hdr.csattr & 1, data->hdr.csattr & 1 ? "" : "NOT ");
		printf("%-45s: %s\n", "NVMe Controller State Size (NVMECSS)",
		       uint128_t_to_string(le128_to_cpu(data->hdr.nvmecss)));
		printf("%-45s: %s\n", "Vendor Specific Size (VSS)",
		       uint128_t_to_string(le128_to_cpu(data->hdr.vss)));

		len -= sizeof(struct nvme_lm_controller_state_data_header);
	} else {
		fprintf(stderr, "WARNING: Header truncated\n");
		len = 0;
	}

	if (!len)
		return;

	if (sizeof(struct nvme_lm_nvme_controller_state_data_header) <= len) {
		int niosq = data->data.hdr.niosq;
		int niocq = data->data.hdr.niocq;

		printf("\nNVMe Controller State Data Structure:\n");
		printf("%-45s: 0x%x\n", "Version (VER)",
		       le16_to_cpu(data->data.hdr.ver));
		printf("%-45s: %d\n", "Number of I/O Submission Queues (NIOSQ)",
		       le16_to_cpu(niosq));
		printf("%-45s: %d\n", "Number of I/O Completion Queues (NIOCQ)",
		       le16_to_cpu(niocq));

		len -= sizeof(struct nvme_lm_nvme_controller_state_data_header);

		if (len < niosq * sizeof(struct nvme_lm_io_submission_queue_data)) {
			fprintf(stderr, "WARNING: I/O Submission Queues truncated\n");
			niosq = len / sizeof(struct nvme_lm_io_submission_queue_data);
		}

		for (int i = 0; i < niosq; ++i) {
			struct nvme_lm_io_submission_queue_data *sq = &(data->data.sqs[i]);
			__u16 iosqa = le16_to_cpu(sq->iosqa);

			printf("\nNVMe I/O Submission Queue Data [%d]:\n", i);
			printf("%-45s: 0x%"PRIu64"\n", "PRP Entry 1 (IOSQPRP1)",
			       le64_to_cpu(sq->iosqprp1));
			printf("%-45s: 0x%x\n", "Queue Size (IOSQQSIZE)",
			       le16_to_cpu(sq->iosqqsize));
			printf("%-45s: 0x%x\n", "Identifier (IOSQQID)",
			       le16_to_cpu(sq->iosqqid));
			printf("%-45s: 0x%x\n", "Completion Queue Identifier (IOSQCQID)",
			       le16_to_cpu(sq->iosqcqid));
			printf("%-45s: 0x%x\n", "Attributes (IOSQA)", iosqa);
			if (human) {
				printf("  [2:1] : 0x%x Queue Priority (IOSQQPRIO)\n",
				       NVME_GET(iosqa, LM_IOSQPRIO));
				printf("  [0:0] : 0x%x Queue %sPhysically Contiguous (IOSQPC)\n",
				       NVME_GET(iosqa, LM_IOSQPC),
				       NVME_GET(iosqa, LM_IOSQPC) ? "" : "NOT ");
			}
			printf("%-45s: 0x%x\n", "I/O Submission Queue Head Pointer (IOSQHP)",
			       le16_to_cpu(sq->iosqhp));
			printf("%-45s: 0x%x\n", "I/O Submission Queue Tail Pointer (IOSQTP)",
			       le16_to_cpu(sq->iosqtp));
		}

		len -= niosq * sizeof(struct nvme_lm_io_submission_queue_data);

		if (len < niocq * sizeof(struct nvme_lm_io_completion_queue_data)) {
			fprintf(stderr, "WARNING: I/O Completion Queues truncated\n");
			niocq = len / sizeof(struct nvme_lm_io_completion_queue_data);
		}

		for (int i = 0; i < niocq; ++i) {
			struct nvme_lm_io_completion_queue_data *cq = &data->data.cqs[niosq + i];
			__u32 iocqa = le32_to_cpu(cq->iocqa);

			printf("\nNVMe I/O Completion Queue Data [%d]:\n", i);
			printf("%-45s: 0x%"PRIu64"\n", "I/O Completion PRP Entry 1 (IOCQPRP1)",
			       le64_to_cpu(cq->iocqprp1));
			printf("%-45s: 0x%x\n", "I/O Completion Queue Size (IOCQQSIZE)",
			       le16_to_cpu(cq->iocqqsize));
			printf("%-45s: 0x%x\n", "I/O Completion Queue Identifier (IOCQQID)",
			       le16_to_cpu(cq->iocqqid));
			printf("%-45s: 0x%x\n", "I/O Completion Queue Head Pointer (IOSQHP)",
			       le16_to_cpu(cq->iocqhp));
			printf("%-45s: 0x%x\n", "I/O Completion Queue Tail Pointer (IOSQTP)",
			       le16_to_cpu(cq->iocqtp));
			printf("%-45s: 0x%x\n", "I/O Completion Queue Attributes (IOCQA)", iocqa);
			if (human) {
				printf("  [31:16] : 0x%x I/O Completion Queue Interrupt Vector "
				       "(IOCQIV)\n",
				       NVME_GET(iocqa, LM_IOCQIEN));
				printf("  [2:2] : 0x%x Slot 0 Phase Tag (S0PT)\n",
				       NVME_GET(iocqa, LM_S0PT));
				printf("  [1:1] : 0x%x Interrupts %sEnabled (IOCQIEN)\n",
				       NVME_GET(iocqa, LM_IOCQIEN),
				       NVME_GET(iocqa, LM_IOCQIEN) ? "" : "NOT ");
				printf("  [0:0] : 0x%x Queue %sPhysically Contiguous (IOCQPC)\n",
				       NVME_GET(iocqa, LM_IOCQPC),
				       NVME_GET(iocqa, LM_IOCQPC) ? "" : "NOT ");
			}
		}
	} else
		fprintf(stderr, "WARNING: NVMe Controller State Data Structure truncated\n");
}

static void stdout_show_controller_data_queue(struct nvme_lm_ctrl_data_queue_fid_data *data)
{
	printf("Head Pointer: 0x%x\n", le32_to_cpu(data->hp));
	printf("Tail Pointer Trigger: 0x%x\n", le32_to_cpu(data->tpt));
}

static struct lm_print_ops stdout_print_ops = {
	.controller_state_data = stdout_controller_state_data,
	.controller_data_queue = stdout_show_controller_data_queue
};

struct lm_print_ops *lm_get_stdout_print_ops(nvme_print_flags_t flags)
{
	stdout_print_ops.flags = flags;
	return &stdout_print_ops;
}
