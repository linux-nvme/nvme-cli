// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include <unistd.h>
#include "ocp-utils.h"
#include "nvme-print.h"

const unsigned char ocp_uuid[NVME_UUID_LEN] = {
	0xc1, 0x94, 0xd5, 0x5b, 0xe0, 0x94, 0x47, 0x94, 0xa2, 0x1d,
	0x29, 0x99, 0x8f, 0x56, 0xbe, 0x6f };

int ocp_get_uuid_index(struct nvme_dev *dev, int *index)
{
	struct nvme_id_uuid_list uuid_list;
	int err = nvme_identify_uuid(dev_fd(dev), &uuid_list);

	*index = 0;
	if (err)
		return err;

	for (int i = 0; i < NVME_ID_UUID_LIST_MAX; i++) {
		if (memcmp(ocp_uuid, &uuid_list.entry[i].uuid, NVME_UUID_LEN) == 0) {
			*index = i + 1;
			break;
		}
	}
	return err;
}

int ocp_clear_feature(int argc, char **argv, const char *desc, const __u8 fid)
{
	__u32 result = 0;
	__u32 clear = 1 << 31;
	struct nvme_dev *dev;
	int uuid_index = 0;
	bool uuid = true;
	int err;

	OPT_ARGS(opts) = {
		OPT_FLAG("no-uuid", 'n', NULL,
			 "Skip UUID index search (UUID index not required for OCP 1.0)"),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (opts[0].seen)
		uuid = false;

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			fprintf(stderr, "ERROR: No OCP UUID index found\n");
			goto close_dev;
		}
	}

	struct nvme_set_features_args args = {
		.result = &result,
		.data = NULL,
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = 0,
		.cdw11 = clear,
		.cdw12 = 0,
		.cdw13 = 0,
		.cdw15 = 0,
		.data_len = 0,
		.save = 0,
		.uuidx = uuid_index,
		.fid = fid,
	};

	err = nvme_set_features(&args);

	if (err == 0)
		printf("Success : %s\n", desc);
	else if (err > 0)
		nvme_show_status(err);
	else
		printf("Fail : %s\n", desc);
close_dev:
	/* Redundant close() to make static code analysis happy */
	close(dev->direct.fd);
	dev_close(dev);
	return err;
}
