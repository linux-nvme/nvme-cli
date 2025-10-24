// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright © 2022 Dell Inc. or its subsidiaries. All Rights Reserved.
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
#include "dell-nvme.h"

#define ARRAY_NAME_LEN 80

struct nvme_vu_id_ctrl_field {
	__u16		dell_mjr;
	__u16		dell_mnr;
	__u16		dell_ter;
	__u8		reserved0[1018];
};

static void dell_id_ctrl(__u8 *vs, struct json_object *root)
{
	struct nvme_vu_id_ctrl_field *id = (struct nvme_vu_id_ctrl_field *)vs;
	char array_ver[16] = { 0 };
	char array_name[ARRAY_NAME_LEN + 1] = {0};

	snprintf(array_ver, sizeof(array_ver), "0x%04x%04x%04x",
		 le16_to_cpu(id->dell_mjr),
		 le16_to_cpu(id->dell_mnr),
		 le16_to_cpu(id->dell_ter));

	memcpy(array_name, vs + sizeof(array_ver), ARRAY_NAME_LEN);

	if (root) {
		json_object_add_value_string(root, "array_name", strlen(array_name) > 1 ? array_name : "NULL");
		json_object_add_value_string(root, "array_ver", array_ver);
		return;
	}

	printf("array_name : %s\n", strlen(array_name) > 1 ? array_name : "NULL");
	printf("array_ver  : %s\n", array_ver);
}

static int id_ctrl(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	return __id_ctrl(argc, argv, acmd, plugin, dell_id_ctrl);
}
