// SPDX-License-Identifier: GPL-2.0-or-later
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"

#define CREATE_CMD
#include "nvidia-nvme.h"

struct nvme_vu_id_ctrl_field {
	__u16		json_rpc_2_0_mjr;
	__u16		json_rpc_2_0_mnr;
	__u16		json_rpc_2_0_ter;
	__u8		reserved0[1018];
};

static void json_nvidia_id_ctrl(struct nvme_vu_id_ctrl_field *id,
		char *json_rpc_2_0_ver, struct json_object *root)
{
	json_object_add_value_string(root, "json_rpc_2_0_ver",
				     json_rpc_2_0_ver);
}

static void nvidia_id_ctrl(__u8 *vs, struct json_object *root)
{
	struct nvme_vu_id_ctrl_field *id = (struct nvme_vu_id_ctrl_field *)vs;
	char json_rpc_2_0_ver[16] = { 0 };

	snprintf(json_rpc_2_0_ver, sizeof(json_rpc_2_0_ver), "0x%04x%04x%04x",
		 le16_to_cpu(id->json_rpc_2_0_mjr),
		 le16_to_cpu(id->json_rpc_2_0_mnr),
		 le16_to_cpu(id->json_rpc_2_0_ter));

	if (root) {
		json_nvidia_id_ctrl(id, json_rpc_2_0_ver, root);
		return;
	}

	printf("json_rpc_2_0_ver : %s\n", json_rpc_2_0_ver);
}

static int id_ctrl(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	return __id_ctrl(argc, argv, acmd, plugin, nvidia_id_ctrl);
}
