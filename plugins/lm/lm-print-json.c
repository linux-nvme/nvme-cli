// SPDX-License-Identifier: GPL-2.0-or-later

#include "lm-print.h"
#include "common.h"

static void json_controller_state_data(struct nvme_lm_controller_state_data *data, size_t len,
				      __u32 offset)
{
	if (offset) {
		fprintf(stderr, "cannot understand non-zero offset\n");
		return;
	}

	struct json_object *root = json_create_object();
	struct json_object *nvmecs = json_create_object();
	struct json_object *iosqs = json_create_array();
	struct json_object *iocqs = json_create_array();

	json_object_add_value_uint(root, "version",
				   le16_to_cpu(data->hdr.ver));
	json_object_add_value_uint(root, "controller state attributes",
				   data->hdr.csattr);
	json_object_add_value_uint128(root, "nvme controller state size",
				      le128_to_cpu(data->hdr.nvmecss));
	json_object_add_value_uint128(root, "vendor specific size",
				      le128_to_cpu(data->hdr.vss));

	json_object_add_value_object(root, "nvme controller state", nvmecs);

	json_object_add_value_uint(nvmecs, "version",
				   le16_to_cpu(data->data.hdr.ver));
	json_object_add_value_uint(nvmecs, "number of io submission queues",
				   le16_to_cpu(data->data.hdr.niosq));
	json_object_add_value_uint(nvmecs, "number of io completion queues",
				   le16_to_cpu(data->data.hdr.niocq));

	json_object_add_value_array(nvmecs, "io submission queue list", iosqs);

	for (int i = 0; i < data->data.hdr.niosq; i++) {
		struct nvme_lm_io_submission_queue_data *sq = &data->data.sqs[i];
		struct json_object *sq_obj = json_create_object();

		json_object_add_value_uint64(sq_obj, "io submission prp entry 1",
					     le64_to_cpu(sq->iosqprp1));
		json_object_add_value_uint(sq_obj, "io submission queue size",
					   le16_to_cpu(sq->iosqqsize));
		json_object_add_value_uint(sq_obj, "io submission queue identifier",
					   le16_to_cpu(sq->iosqqid));
		json_object_add_value_uint(sq_obj, "io completion queue identifier",
					   le16_to_cpu(sq->iosqcqid));
		json_object_add_value_uint(sq_obj, "io submission queue attributes",
					   le16_to_cpu(sq->iosqa));
		json_object_add_value_uint(sq_obj, "io submission queue head pointer",
					   le16_to_cpu(sq->iosqhp));
		json_object_add_value_uint(sq_obj, "io submission queue tail pointer",
					   le16_to_cpu(sq->iosqtp));

		json_array_add_value_object(iosqs, sq_obj);
	}

	json_object_add_value_array(nvmecs, "io completion queue list", iocqs);

	for (int i = 0; i < data->data.hdr.niocq; i++) {
		struct nvme_lm_io_completion_queue_data *cq = &data->data.cqs[i];
		struct json_object *cq_obj = json_create_object();

		json_object_add_value_uint64(cq_obj, "io completion prp entry 1",
					     le64_to_cpu(cq->iocqprp1));
		json_object_add_value_uint(cq_obj, "io completion queue size",
					   le16_to_cpu(cq->iocqqsize));
		json_object_add_value_uint(cq_obj, "io completion queue identifier",
					   le16_to_cpu(cq->iocqqid));
		json_object_add_value_uint(cq_obj, "io completion queue head pointer",
					   le16_to_cpu(cq->iocqhp));
		json_object_add_value_uint(cq_obj, "io completion queue tail pointer",
					   le16_to_cpu(cq->iocqtp));
		json_object_add_value_uint(cq_obj, "io completion queue attributes",
					   le32_to_cpu(cq->iocqa));

		json_array_add_value_object(iocqs, cq_obj);
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_controller_data_queue(struct nvme_lm_ctrl_data_queue_fid_data *data)
{
	struct json_object *root = json_create_object();

	json_object_add_value_uint(root, "head_pointer", le32_to_cpu(data->hp));
	json_object_add_value_uint(root, "tail_pointer_trigger", le32_to_cpu(data->tpt));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static struct lm_print_ops json_print_ops = {
	.controller_state_data = json_controller_state_data,
	.controller_data_queue = json_controller_data_queue
};

struct lm_print_ops *lm_get_json_print_ops(nvme_print_flags_t flags)
{
	json_print_ops.flags = flags;
	return &json_print_ops;
}
