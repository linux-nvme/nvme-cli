#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include "linux/nvme_ioctl.h"

#include "common.h"
#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "amzn-nvme.h"

struct nvme_vu_id_ctrl_field {
	__u8			bdev[32];
	__u8			reserved0[992];
};

static void json_amzn_id_ctrl(struct nvme_vu_id_ctrl_field *id,
	char *bdev,
	struct json_object *root)
{
	json_object_add_value_string(root, "bdev", bdev);
}

static void amzn_id_ctrl(__u8 *vs, struct json_object *root)
{
	struct nvme_vu_id_ctrl_field* id = (struct nvme_vu_id_ctrl_field *)vs;

	char bdev[32] = { 0 };

	int len = 0;
	while (len < 31) {
		if (id->bdev[++len] == ' ') {
			break;
		}
	}
	snprintf(bdev, len+1, "%s", id->bdev);

	if (root) {
		json_amzn_id_ctrl(id, bdev, root);
		return;
	}

	printf("bdev      : %s\n", bdev);
}

static int id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, cmd, plugin, amzn_id_ctrl);
}
