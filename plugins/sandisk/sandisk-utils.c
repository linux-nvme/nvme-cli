// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2025 Sandisk Corporation or its affiliates.
 *
 *   Author: Jeff Lien <jeff.lien@sandisk.com>
 *           Brandon Paupore <brandon.paupore@sandisk.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "nvme-print.h"
#include "sandisk-utils.h"
#include "plugins/wdc/wdc-nvme-cmds.h"

/*  WDC UUID value */
static const __u8 WDC_UUID[NVME_UUID_LEN] = {
	0x2d, 0xb9, 0x8c, 0x52, 0x0c, 0x4c, 0x5a, 0x15,
	0xab, 0xe6, 0x33, 0x29, 0x9a, 0x70, 0xdf, 0xd0
};

/*  Sandisk UUID value */
static const __u8 SNDK_UUID[NVME_UUID_LEN] = {
	0xde, 0x87, 0xd1, 0xeb, 0x72, 0xc5, 0x58, 0x0b,
	0xad, 0xd8, 0x3c, 0x29, 0xd1, 0x23, 0x7c, 0x70
};

int sndk_get_pci_ids(struct nvme_global_ctx *ctx, struct nvme_transport_handle *hdl,
			   uint32_t *device_id, uint32_t *vendor_id)
{
	char vid[256], did[256], id[32];
	nvme_ctrl_t c = NULL;
	nvme_ns_t n = NULL;
	const char *name;
	int fd, ret;

	name = nvme_transport_handle_get_name(hdl);
	ret = nvme_scan_ctrl(ctx, name, &c);
	if (!ret) {
		snprintf(vid, sizeof(vid), "%s/device/vendor",
			nvme_ctrl_get_sysfs_dir(c));
		snprintf(did, sizeof(did), "%s/device/device",
			nvme_ctrl_get_sysfs_dir(c));
		nvme_free_ctrl(c);
	} else {
		ret = nvme_scan_namespace(ctx, name, &n);
		if (!ret) {
			fprintf(stderr, "Unable to find %s\n", name);
			return ret;
		}

		snprintf(vid, sizeof(vid), "%s/device/device/vendor",
			nvme_ns_get_sysfs_dir(n));
		snprintf(did, sizeof(did), "%s/device/device/device",
			nvme_ns_get_sysfs_dir(n));
		nvme_free_ns(n);
	}

	fd = open(vid, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "ERROR: SNDK: %s : Open vendor file failed\n", __func__);
		return -1;
	}

	ret = read(fd, id, 32);
	close(fd);

	if (ret < 0) {
		fprintf(stderr, "%s: Read of pci vendor id failed\n", __func__);
		return -1;
	}
	id[ret < 32 ? ret : 31] = '\0';
	if (id[strlen(id) - 1] == '\n')
		id[strlen(id) - 1] = '\0';

	*vendor_id = strtol(id, NULL, 0);
	ret = 0;

	fd = open(did, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "ERROR: SNDK: %s : Open device file failed\n", __func__);
		return -1;
	}

	ret = read(fd, id, 32);
	close(fd);

	if (ret < 0) {
		fprintf(stderr, "ERROR: SNDK: %s: Read of pci device id failed\n", __func__);
		return -1;
	}
	id[ret < 32 ? ret : 31] = '\0';
	if (id[strlen(id) - 1] == '\n')
		id[strlen(id) - 1] = '\0';

	*device_id = strtol(id, NULL, 0);
	return 0;
}

int sndk_get_vendor_id(struct nvme_transport_handle *hdl, uint32_t *vendor_id)
{
	struct nvme_id_ctrl ctrl;
	int ret;

	memset(&ctrl, 0, sizeof(struct nvme_id_ctrl));
	ret = nvme_identify_ctrl(hdl, &ctrl);
	if (ret) {
		fprintf(stderr, "ERROR: SNDK: nvme_identify_ctrl() failed 0x%x\n", ret);
		return -1;
	}

	*vendor_id = (uint32_t) ctrl.vid;

	return ret;
}

bool sndk_check_device(struct nvme_global_ctx *ctx,
		       struct nvme_transport_handle *hdl)
{
	uint32_t read_device_id = -1, read_vendor_id = -1;
	bool supported;
	int ret;

	ret = sndk_get_pci_ids(ctx, hdl, &read_device_id, &read_vendor_id);
	if (ret < 0) {
		/* Use the identify nvme command to get vendor id due to NVMeOF device. */
		if (sndk_get_vendor_id(hdl, &read_vendor_id) < 0)
			return false;
	}

	supported = false;

	if (read_vendor_id == SNDK_NVME_SNDK_VID ||
	    read_vendor_id == SNDK_NVME_WDC_VID)
		supported = true;
	else
		fprintf(stderr,
			"ERROR: SNDK: unsupported Sandisk device, Vendor ID = 0x%x, Device ID = 0x%x\n",
			read_vendor_id, read_device_id);

	return supported;
}

void sndk_get_commit_action_bin(__u8 commit_action_type, char *action_bin)
{
	switch (commit_action_type) {
	case 0:
		strcpy(action_bin, "000b");
		break;
	case 1:
		strcpy(action_bin, "001b");
		break;
	case 2:
		strcpy(action_bin, "010b");
		break;
	case 3:
		strcpy(action_bin, "011b");
		break;
	case 4:
		strcpy(action_bin, "100b");
		break;
	case 5:
		strcpy(action_bin, "101b");
		break;
	case 6:
		strcpy(action_bin, "110b");
		break;
	case 7:
		strcpy(action_bin, "111b");
		break;
	default:
		strcpy(action_bin, "INVALID");
	}
}

bool sndk_parse_dev_mng_log_entry(void *data,
		__u32 entry_id,
		struct sndk_c2_log_subpage_header **log_entry)
{
	__u32 remaining_len = 0;
	__u32 log_length = 0;
	__u32 log_entry_size = 0;
	__u32 log_entry_id = 0;
	__u32 offset = 0;
	bool found = false;
	struct sndk_c2_log_subpage_header *p_next_log_entry = NULL;
	struct sndk_c2_log_page_header *hdr_ptr = (struct sndk_c2_log_page_header *)data;

	log_length = le32_to_cpu(hdr_ptr->length);
	/* Ensure log data is large enough for common header */
	if (log_length < sizeof(struct sndk_c2_log_page_header)) {
		fprintf(stderr,
		    "ERROR: %s: log smaller than header. log_len: 0x%x  HdrSize: %"PRIxPTR"\n",
		    __func__, log_length, sizeof(struct sndk_c2_log_page_header));
		return found;
	}

	/* Get pointer to first log Entry */
	offset = sizeof(struct sndk_c2_log_page_header);
	p_next_log_entry = (struct sndk_c2_log_subpage_header *)(((__u8 *)data) + offset);
	remaining_len = log_length - offset;

	if (!log_entry) {
		fprintf(stderr, "ERROR: SNDK - %s: No log entry pointer.\n", __func__);
		return found;
	}
	*log_entry = NULL;

	/* Proceed only if there is at least enough data to read an entry header */
	while (remaining_len >= sizeof(struct sndk_c2_log_subpage_header)) {
		/* Get size of the next entry */
		log_entry_size = le32_to_cpu(p_next_log_entry->length);
		log_entry_id = le32_to_cpu(p_next_log_entry->entry_id);

		/*
		 * If log entry size is 0 or the log entry goes past the end
		 * of the data, we must be at the end of the data
		 */
		if (!log_entry_size || log_entry_size > remaining_len) {
			fprintf(stderr, "ERROR: SNDK: %s: Detected unaligned end of the data. ",
				__func__);
			fprintf(stderr, "Data Offset: 0x%x Entry Size: 0x%x, ",
				offset, log_entry_size);
			fprintf(stderr, "Remaining Log Length: 0x%x Entry Id: 0x%x\n",
				remaining_len, log_entry_id);

			/* Force the loop to end */
			remaining_len = 0;
		} else if (!log_entry_id || log_entry_id > 200) {
			/* Invalid entry - fail the search */
			fprintf(stderr, "ERROR: SNDK: %s: Invalid entry found at offset: 0x%x ",
				__func__, offset);
			fprintf(stderr, "Entry Size: 0x%x, Remaining Log Length: 0x%x ",
				log_entry_size, remaining_len);
			fprintf(stderr, "Entry Id: 0x%x\n", log_entry_id);

			/* Force the loop to end */
			remaining_len = 0;
		} else {
			if (log_entry_id == entry_id) {
				found = true;
				*log_entry = p_next_log_entry;
				remaining_len = 0;
			} else {
				remaining_len -= log_entry_size;
			}

			if (remaining_len > 0) {
				/* Increment the offset counter */
				offset += log_entry_size;

				/* Get the next entry */
				p_next_log_entry =
				(struct sndk_c2_log_subpage_header *)(((__u8 *)data) + offset);
			}
		}
	}

	return found;
}

bool sndk_nvme_parse_dev_status_log_entry(void *log_data,
		__u32 entry_id,
		__u32 *ret_data)
{
	struct sndk_c2_log_subpage_header *entry_data = NULL;

	if (sndk_parse_dev_mng_log_entry(log_data, entry_id, &entry_data)) {
		if (entry_data) {
			*ret_data = le32_to_cpu(entry_data->data);
			return true;
		}
	}

	*ret_data = 0;
	return false;
}

bool sndk_nvme_parse_dev_status_log_str(void *log_data,
		__u32 entry_id,
		char *ret_data,
		__u32 *ret_data_len)
{
	struct sndk_c2_log_subpage_header *entry_data = NULL;
	struct sndk_c2_cbs_data *entry_str_data = NULL;

	if (sndk_parse_dev_mng_log_entry(log_data, entry_id, &entry_data)) {
		if (entry_data) {
			entry_str_data = (struct sndk_c2_cbs_data *)&entry_data->data;
			memcpy(ret_data,
				(void *)&entry_str_data->data,
				le32_to_cpu(entry_str_data->length));
			*ret_data_len = le32_to_cpu(entry_str_data->length);
			return true;
		}
	}

	*ret_data = 0;
	*ret_data_len = 0;
	return false;
}


bool sndk_get_dev_mgment_data(struct nvme_global_ctx *ctx, struct nvme_transport_handle *hdl,
				void **data)
{
	bool found = false;
	__u32 device_id = 0, vendor_id = 0;
	int uuid_index = 0;
	struct nvme_id_uuid_list uuid_list;

	*data = NULL;

	/* The sndk_get_pci_ids function could fail when drives are connected
	 * via a PCIe switch.  Therefore, the return code is intentionally
	 * being ignored.  The device_id and vendor_id variables have been
	 * initialized to 0 so the code can continue on without issue for
	 * both cases: sndk_get_pci_ids successful or failed.
	 */
	sndk_get_pci_ids(ctx, hdl, &device_id, &vendor_id);

	memset(&uuid_list, 0, sizeof(struct nvme_id_uuid_list));
	if (!nvme_get_uuid_list(hdl, &uuid_list)) {
		/* check for the Sandisk UUID first  */
		uuid_index = nvme_uuid_find(&uuid_list, SNDK_UUID);

		if (uuid_index < 0) {
			/* The Sandisk UUID is not found;
			 * check for the WDC UUID second.
			 */
			uuid_index = nvme_uuid_find(&uuid_list, WDC_UUID);
		}

		if (uuid_index >= 0)
			found = sndk_get_dev_mgmt_log_page_data(hdl, data, uuid_index);
		else {
			fprintf(stderr, "%s: UUID lists are supported but a matching ",
				__func__);
			fprintf(stderr, "uuid was not found\n");
		}
	} else {
		/* UUID lists are not supported, Default to uuid-index 0  */
		fprintf(stderr, "INFO: SNDK: %s:  UUID Lists not supported\n",
				__func__);
		uuid_index = 0;
		found = sndk_get_dev_mgmt_log_page_data(hdl, data, uuid_index);
	}

	return found;
}

bool sndk_validate_dev_mng_log(void *data)
{
	__u32 remaining_len = 0;
	__u32 log_length = 0;
	__u32 log_entry_size = 0;
	__u32 log_entry_id = 0;
	__u32 offset = 0;
	bool valid_log = false;
	struct sndk_c2_log_subpage_header *p_next_log_entry = NULL;
	struct sndk_c2_log_page_header *hdr_ptr = (struct sndk_c2_log_page_header *)data;

	log_length = le32_to_cpu(hdr_ptr->length);
	/* Ensure log data is large enough for common header */
	if (log_length < sizeof(struct sndk_c2_log_page_header)) {
		fprintf(stderr,
		    "ERROR: %s: log smaller than header. log_len: 0x%x  HdrSize: %"PRIxPTR"\n",
		    __func__, log_length, sizeof(struct sndk_c2_log_page_header));
		return valid_log;
	}

	/* Get pointer to first log Entry */
	offset = sizeof(struct sndk_c2_log_page_header);
	p_next_log_entry = (struct sndk_c2_log_subpage_header *)(((__u8 *)data) + offset);
	remaining_len = log_length - offset;

	/* Proceed only if there is at least enough data to read an entry header */
	while (remaining_len >= sizeof(struct sndk_c2_log_subpage_header)) {
		/* Get size of the next entry */
		log_entry_size = le32_to_cpu(p_next_log_entry->length);
		log_entry_id = le32_to_cpu(p_next_log_entry->entry_id);
		/*
		 * If log entry size is 0 or the log entry goes past the end
		 * of the data, we must be at the end of the data
		 */
		if (!log_entry_size || log_entry_size > remaining_len) {
			fprintf(stderr, "ERROR: SNDK: %s: Detected unaligned end of the data. ",
				__func__);
			fprintf(stderr, "Data Offset: 0x%x Entry Size: 0x%x, ",
				offset, log_entry_size);
			fprintf(stderr, "Remaining Log Length: 0x%x Entry Id: 0x%x\n",
				remaining_len, log_entry_id);

			/* Force the loop to end */
			remaining_len = 0;
		} else if (!log_entry_id || log_entry_id > 200) {
			/* Invalid entry - fail the search */
			fprintf(stderr, "ERROR: SNDK: %s: Invalid entry found at offset: 0x%x ",
				__func__, offset);
			fprintf(stderr, "Entry Size: 0x%x, Remaining Log Length: 0x%x ",
				log_entry_size, remaining_len);
			fprintf(stderr, "Entry Id: 0x%x\n", log_entry_id);

			/* Force the loop to end */
			remaining_len = 0;
			valid_log = false;
		} else {
			/* A valid log has at least one entry and no invalid entries */
			valid_log = true;
			remaining_len -= log_entry_size;
			if (remaining_len > 0) {
				/* Increment the offset counter */
				offset += log_entry_size;
				/* Get the next entry */
				p_next_log_entry =
				(struct sndk_c2_log_subpage_header *)(((__u8 *)data) + offset);
			}
		}
	}

	return valid_log;
}

bool sndk_get_dev_mgmt_log_page_data(struct nvme_transport_handle *hdl,
		void **log_data,
		__u8 uuid_ix)
{
	struct sndk_c2_log_page_header *hdr_ptr;
	struct nvme_passthru_cmd cmd;
	bool valid = false;
	__u32 length = 0;
	void *data;
	int ret = 0;

	data = (__u8 *)malloc(sizeof(__u8) * SNDK_DEV_MGMNT_LOG_PAGE_LEN);
	if (!data) {
		fprintf(stderr, "ERROR: SNDK: malloc: %s\n", strerror(errno));
		return false;
	}

	memset(data, 0, sizeof(__u8) * SNDK_DEV_MGMNT_LOG_PAGE_LEN);

	/* get the log page length */
	nvme_init_get_log(&cmd, NVME_NSID_ALL,
		SNDK_NVME_GET_DEV_MGMNT_LOG_PAGE_ID, NVME_CSI_NVM, data,
		SNDK_DEV_MGMNT_LOG_PAGE_LEN);
	cmd.cdw14 |= NVME_FIELD_ENCODE(uuid_ix,
				       NVME_LOG_CDW14_UUID_SHIFT,
				       NVME_LOG_CDW14_UUID_MASK);
	ret = nvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
	if (ret) {
		fprintf(stderr,
			"ERROR: SNDK: Unable to get 0x%x Log Page with uuid %d, ret = 0x%x\n",
			SNDK_NVME_GET_DEV_MGMNT_LOG_PAGE_ID, uuid_ix, ret);
		goto end;
	}

	hdr_ptr = (struct sndk_c2_log_page_header *)data;
	length = le32_to_cpu(hdr_ptr->length);

	if (length > SNDK_DEV_MGMNT_LOG_PAGE_LEN) {
		/* Log page buffer too small for actual data */
		free(data);
		data = calloc(length, sizeof(__u8));
		if (!data) {
			fprintf(stderr, "ERROR: SNDK: malloc: %s\n", strerror(errno));
			goto end;
		}

		/* get the log page data with the increased length */
		nvme_init_get_log(&cmd, NVME_NSID_ALL,
			SNDK_NVME_GET_DEV_MGMNT_LOG_PAGE_ID, NVME_CSI_NVM, data,
			length);
		cmd.cdw14 |= NVME_FIELD_ENCODE(uuid_ix,
				NVME_LOG_CDW14_UUID_SHIFT,
				NVME_LOG_CDW14_UUID_MASK);
		ret = nvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
		if (ret) {
			fprintf(stderr,
				"ERROR: SNDK: Unable to read 0x%x Log with uuid %d, ret = 0x%x\n",
				SNDK_NVME_GET_DEV_MGMNT_LOG_PAGE_ID, uuid_ix, ret);
			goto end;
		}
	}

	valid = sndk_validate_dev_mng_log(data);
	if (valid) {
		/* Ensure size of log data matches length in log header */
		*log_data = calloc(length, sizeof(__u8));
		if (!*log_data) {
			fprintf(stderr, "ERROR: SNDK: calloc: %s\n", strerror(errno));
			valid = false;
			goto end;
		}
		memcpy((void *)*log_data, data, length);
	} else {
		fprintf(stderr, "ERROR: SNDK: C2 log page not found with uuid index %d\n",
			uuid_ix);
	}

end:
	free(data);
	return valid;
}

__u64 sndk_get_drive_capabilities(struct nvme_global_ctx *ctx,
				  struct nvme_transport_handle *hdl)
{
	uint32_t read_device_id = -1, read_vendor_id = -1;
	__u64 capabilities = 0;
	int ret;

	ret = sndk_get_pci_ids(ctx, hdl, &read_device_id, &read_vendor_id);
	if (ret < 0) {
		if (sndk_get_vendor_id(hdl, &read_vendor_id) < 0)
			return capabilities;
	}

	/*
	 * Below check condition is added due in NVMeOF device
	 * We aren't able to read the device_id in this case
	 * so we can only use the vendor_id
	 */
	if (read_device_id == -1 && read_vendor_id != -1) {
		capabilities = sndk_get_enc_drive_capabilities(ctx, hdl);
		return capabilities;
	}

	switch (read_vendor_id) {
	case SNDK_NVME_WDC_VID:
		switch (read_device_id) {
		case SNDK_NVME_SNTMP_DEV_ID:
		case SNDK_NVME_SNTMP_DEV_ID_1:
			capabilities |= (SNDK_DRIVE_CAP_C0_LOG_PAGE |
					SNDK_DRIVE_CAP_C3_LOG_PAGE |
					SNDK_DRIVE_CAP_CA_LOG_PAGE |
					SNDK_DRIVE_CAP_OCP_C4_LOG_PAGE |
					SNDK_DRIVE_CAP_OCP_C5_LOG_PAGE |
					SNDK_DRIVE_CAP_UDUI |
					SNDK_DRIVE_CAP_VU_FID_CLEAR_PCIE |
					SNDK_DRIVE_CAP_CLOUD_SSD_VERSION |
					SNDK_DRIVE_CAP_LOG_PAGE_DIR |
					SNDK_DRIVE_CAP_DRIVE_STATUS |
					SNDK_DRIVE_CAP_SET_LATENCY_MONITOR);
			break;

		case SNDK_NVME_SN861_DEV_ID_E1S:
			capabilities |= (SNDK_DRIVE_CAP_C0_LOG_PAGE |
				SNDK_DRIVE_CAP_C3_LOG_PAGE |
				SNDK_DRIVE_CAP_CA_LOG_PAGE |
				SNDK_DRIVE_CAP_OCP_C4_LOG_PAGE |
				SNDK_DRIVE_CAP_OCP_C5_LOG_PAGE |
				SNDK_DRIVE_CAP_INTERNAL_LOG |
				SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY_C2 |
				SNDK_DRIVE_CAP_VU_FID_CLEAR_PCIE |
				SNDK_DRIVE_CAP_VU_FID_CLEAR_FW_ACT_HISTORY |
				SNDK_DRIVE_CAP_INFO |
				SNDK_DRIVE_CAP_CLOUD_SSD_VERSION |
				SNDK_DRIVE_CAP_LOG_PAGE_DIR |
				SNDK_DRIVE_CAP_DRIVE_STATUS |
				SNDK_DRIVE_CAP_SET_LATENCY_MONITOR);
			break;

		case SNDK_NVME_SN861_DEV_ID_U2:
		case SNDK_NVME_SN861_DEV_ID_E3S:
			capabilities |= (SNDK_DRIVE_CAP_C0_LOG_PAGE |
				SNDK_DRIVE_CAP_C3_LOG_PAGE |
				SNDK_DRIVE_CAP_CA_LOG_PAGE |
				SNDK_DRIVE_CAP_OCP_C4_LOG_PAGE |
				SNDK_DRIVE_CAP_OCP_C5_LOG_PAGE |
				SNDK_DRIVE_CAP_INTERNAL_LOG |
				SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY_C2 |
				SNDK_DRIVE_CAP_VU_FID_CLEAR_PCIE |
				SNDK_DRIVE_CAP_VU_FID_CLEAR_FW_ACT_HISTORY |
				SNDK_DRIVE_CAP_INFO |
				SNDK_DRIVE_CAP_CLOUD_SSD_VERSION |
				SNDK_DRIVE_CAP_LOG_PAGE_DIR |
				SNDK_DRIVE_CAP_DRIVE_STATUS |
				SNDK_DRIVE_CAP_RESIZE_SN861 |
				SNDK_DRIVE_CAP_SET_LATENCY_MONITOR);
			break;

		default:
			capabilities = 0;
		}
		break;

	case SNDK_NVME_SNDK_VID:
		switch (read_device_id) {
		case SNDK_NVME_SNESSD1_DEV_ID_E1L:
		case SNDK_NVME_SNESSD1_DEV_ID_E2:
		case SNDK_NVME_SNESSD1_DEV_ID_E3S:
		case SNDK_NVME_SNESSD1_DEV_ID_E3L:
		case SNDK_NVME_SNESSD1_DEV_ID_U2:
			capabilities |= (SNDK_DRIVE_CAP_C0_LOG_PAGE |
					SNDK_DRIVE_CAP_C3_LOG_PAGE |
					SNDK_DRIVE_CAP_CA_LOG_PAGE |
					SNDK_DRIVE_CAP_OCP_C4_LOG_PAGE |
					SNDK_DRIVE_CAP_OCP_C5_LOG_PAGE |
					SNDK_DRIVE_CAP_UDUI |
					SNDK_DRIVE_CAP_VU_FID_CLEAR_PCIE |
					SNDK_DRIVE_CAP_CLOUD_SSD_VERSION |
					SNDK_DRIVE_CAP_LOG_PAGE_DIR |
					SNDK_DRIVE_CAP_DRIVE_STATUS |
					SNDK_DRIVE_CAP_SET_LATENCY_MONITOR);
			break;

		case SNDK_NVME_SN7150_DEV_ID_1:
		case SNDK_NVME_SN7150_DEV_ID_2:
		case SNDK_NVME_SN7150_DEV_ID_3:
		case SNDK_NVME_SN7150_DEV_ID_4:
		case SNDK_NVME_SN7150_DEV_ID_5:
			capabilities = SNDK_DRIVE_CAP_UDUI;
			break;

		case SNDK_NVME_SNCSSD1_DEV_ID_M2_2230:
		case SNDK_NVME_SNCSSD1_DEV_ID_M2_2242:
		case SNDK_NVME_SNCSSD1_DEV_ID_M2_2280:
			capabilities = SNDK_DRIVE_CAP_UDUI;
			break;

		default:
			capabilities = 0;
		}
		break;
	default:
		capabilities = 0;
	}

	/* Check for fallback WDC plugin support */
	if (!capabilities)
		capabilities = run_wdc_get_drive_capabilities(ctx, hdl);

	return capabilities;
}

__u64 sndk_get_enc_drive_capabilities(struct nvme_global_ctx *ctx,
					    struct nvme_transport_handle *hdl)
{
	int ret;
	uint32_t read_vendor_id;
	__u64 capabilities = 0;
	__u32 cust_id, market_name_len,
		drive_form_factor = 0;
	char marketing_name[64];
	void *dev_mng_log = NULL;
	int uuid_index = 0;
	struct nvme_id_uuid_list uuid_list;

	memset(marketing_name, 0, 64);

	ret = sndk_get_vendor_id(hdl, &read_vendor_id);
	if (ret < 0)
		return capabilities;

	switch (read_vendor_id) {
	case SNDK_NVME_WDC_VID:
		capabilities = (SNDK_DRIVE_CAP_INTERNAL_LOG |
			SNDK_DRIVE_CAP_DRIVE_STATUS |
			SNDK_DRIVE_CAP_CLEAR_ASSERT |
			SNDK_DRIVE_CAP_RESIZE);

		/* Check for the Sandisk or WDC UUID index  */
		memset(&uuid_list, 0, sizeof(struct nvme_id_uuid_list));
		if (!nvme_get_uuid_list(hdl, &uuid_list)) {
			/* check for the Sandisk UUID first  */
			uuid_index = nvme_uuid_find(&uuid_list, SNDK_UUID);

			if (uuid_index < 0)
				/* The Sandisk UUID is not found;
				 * check for the WDC UUID second.
				 */
				uuid_index = nvme_uuid_find(&uuid_list, WDC_UUID);
		} else {
			/* UUID Lists not supported, Use default uuid index - 0 */
			fprintf(stderr, "INFO: SNDK: %s:  UUID Lists not supported\n",
					__func__);
			uuid_index = 0;
		}

		/* verify the 0xC2 Device Manageability log page is supported */
		if (run_wdc_nvme_check_supported_log_page(ctx, hdl,
				SNDK_NVME_GET_DEV_MGMNT_LOG_PAGE_ID,
				uuid_index) == false) {
			fprintf(stderr, "ERROR: SNDK: 0xC2 Log Page not supported, ");
			fprintf(stderr, "uuid_index: %d\n", uuid_index);
			ret = -1;
			goto out;
		}

		if (!sndk_get_dev_mgment_data(ctx, hdl, &dev_mng_log)) {
			fprintf(stderr, "ERROR: SNDK: 0xC2 Log Page not found\n");
			ret = -1;
			goto out;
		}

		/* Get the customer ID */
		if (!sndk_nvme_parse_dev_status_log_entry(dev_mng_log,
				SNDK_C2_CUSTOMER_ID_ID,
				(void *)&cust_id))
			fprintf(stderr, "ERROR: SNDK: Get Customer FW ID Failed\n");

		/* Get the marketing name */
		if (!sndk_nvme_parse_dev_status_log_str(dev_mng_log,
				SNDK_C2_MARKETING_NAME_ID,
				(char *)marketing_name,
				&market_name_len))
			fprintf(stderr, "ERROR: SNDK: Get Marketing Name Failed\n");

		/* Get the drive form factor */
		if (!sndk_nvme_parse_dev_status_log_entry(dev_mng_log,
				SNDK_C2_FORM_FACTOR,
				(void *)&drive_form_factor))
			fprintf(stderr, "ERROR: SNDK: Getting Form Factor Failed\n");

		/* verify the 0xC3 log page is supported */
		if (run_wdc_nvme_check_supported_log_page(ctx, hdl,
			SNDK_LATENCY_MON_LOG_ID, 0))
			capabilities |= SNDK_DRIVE_CAP_C3_LOG_PAGE;

		/* verify the 0xCB log page is supported */
		if (run_wdc_nvme_check_supported_log_page(ctx, hdl,
			SNDK_NVME_GET_FW_ACT_HISTORY_LOG_ID, 0))
			capabilities |= SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY;

		/* verify the 0xCA log page is supported */
		if (run_wdc_nvme_check_supported_log_page(ctx, hdl,
			SNDK_NVME_GET_DEVICE_INFO_LOG_ID, 0))
			capabilities |= SNDK_DRIVE_CAP_CA_LOG_PAGE;

		/* verify the 0xD0 log page is supported */
		if (run_wdc_nvme_check_supported_log_page(ctx, hdl,
			SNDK_NVME_GET_VU_SMART_LOG_ID, 0))
			capabilities |= SNDK_DRIVE_CAP_D0_LOG_PAGE;

		if ((cust_id == SNDK_CUSTOMER_ID_0x1004) ||
			(cust_id == SNDK_CUSTOMER_ID_0x1008) ||
			(cust_id == SNDK_CUSTOMER_ID_0x1005) ||
			(cust_id == SNDK_CUSTOMER_ID_0x1304))
			/* Set capabilities for OCP compliant drives */
			capabilities |= (SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY_C2 |
					SNDK_DRIVE_CAP_VU_FID_CLEAR_FW_ACT_HISTORY |
					SNDK_DRIVE_CAP_VU_FID_CLEAR_PCIE);
		else if ((!strncmp(marketing_name, SNDK_SN861_MARKETING_NAME_1, market_name_len)) ||
			(!strncmp(marketing_name, SNDK_SN861_MARKETING_NAME_2, market_name_len))) {
			/* Set capabilities for OCP compliant drives */
			capabilities |= (SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY_C2 |
					SNDK_DRIVE_CAP_VU_FID_CLEAR_FW_ACT_HISTORY |
					SNDK_DRIVE_CAP_VU_FID_CLEAR_PCIE);

			/* verify the 0xC0 log page is supported */
			if (run_wdc_nvme_check_supported_log_page(ctx, hdl,
				SNDK_LATENCY_MON_LOG_ID, 0))
				capabilities |= SNDK_DRIVE_CAP_C0_LOG_PAGE;

			if ((drive_form_factor == SNDK_C2_FORM_FACTOR_SFF_U2) ||
				(drive_form_factor == SNDK_C2_FORM_FACTOR_EDSFF_E3S))
				capabilities |= SNDK_DRIVE_CAP_RESIZE_SN861;
			else
				capabilities &= ~SNDK_DRIVE_CAP_RESIZE;
		} else {
			capabilities |= (SNDK_DRIVE_CAP_CLEAR_FW_ACT_HISTORY |
				SNDK_DRIVE_CAP_CLEAR_PCIE);

			/* if the 0xCB log page is supported */
			if (run_wdc_nvme_check_supported_log_page(ctx, hdl,
				SNDK_NVME_GET_FW_ACT_HISTORY_LOG_ID, 0))
				capabilities |= SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY;
		}
		break;
	default:
		capabilities = 0;
	}

out:
	return capabilities;
}

int sndk_get_serial_name(struct nvme_transport_handle *hdl, char *file,
			 size_t len, const char *suffix)
{
	int i;
	int ret;
	int res_len = 0;
	char orig[PATH_MAX] = {0};
	struct nvme_id_ctrl ctrl;
	int ctrl_sn_len = sizeof(ctrl.sn);

	i = sizeof(ctrl.sn) - 1;
	strncpy(orig, file, PATH_MAX - 1);
	memset(file, 0, len);
	memset(&ctrl, 0, sizeof(struct nvme_id_ctrl));
	ret = nvme_identify_ctrl(hdl, &ctrl);
	if (ret) {
		fprintf(stderr, "ERROR: SNDK: nvme_identify_ctrl() failed 0x%x\n", ret);
		return -1;
	}
	/* Remove trailing spaces from the name */
	while (i && ctrl.sn[i] == ' ') {
		ctrl.sn[i] = '\0';
		i--;
	}
	if (ctrl.sn[sizeof(ctrl.sn) - 1] == '\0')
		ctrl_sn_len = strlen(ctrl.sn);

	res_len = snprintf(file, len, "%s%.*s%s", orig, ctrl_sn_len, ctrl.sn, suffix);
	if (len <= res_len) {
		fprintf(stderr,
			"ERROR: SNDK: cannot format SN due to unexpected length\n");
		return -1;
	}

	return 0;
}

void sndk_UtilsGetTime(struct SNDK_UtilsTimeInfo *timeInfo)
{
	time_t currTime;
	struct tm currTimeInfo;

	tzset();
	time(&currTime);
	localtime_r(&currTime, &currTimeInfo);

	timeInfo->year			=  currTimeInfo.tm_year + 1900;
	timeInfo->month			=  currTimeInfo.tm_mon + 1;
	timeInfo->dayOfWeek		=  currTimeInfo.tm_wday;
	timeInfo->dayOfMonth		=  currTimeInfo.tm_mday;
	timeInfo->hour			=  currTimeInfo.tm_hour;
	timeInfo->minute		=  currTimeInfo.tm_min;
	timeInfo->second		=  currTimeInfo.tm_sec;
	timeInfo->msecs			=  0;
	timeInfo->isDST			=  currTimeInfo.tm_isdst;
#ifdef HAVE_TM_GMTOFF
	timeInfo->zone			= -currTimeInfo.tm_gmtoff / 60;
#else /* HAVE_TM_GMTOFF */
	timeInfo->zone			= -1 * (timezone / 60);
#endif /* HAVE_TM_GMTOFF */
}

int sndk_UtilsSnprintf(char *buffer, unsigned int sizeOfBuffer,
		       const char *format, ...)
{
	int res = 0;
	va_list vArgs;

	va_start(vArgs, format);
	res = vsnprintf(buffer, sizeOfBuffer, format, vArgs);
	va_end(vArgs);

	return res;
}

/* Verify the Controller Initiated Option is enabled */
int sndk_check_ctrl_telemetry_option_disabled(struct nvme_transport_handle *hdl)
{
	int err;
	__u64 result;

	err = nvme_get_features(hdl, 0,
		SNDK_VU_DISABLE_CNTLR_TELEMETRY_OPTION_FEATURE_ID,
		NVME_GET_FEATURES_SEL_CURRENT, 0, 0,
		NULL, 4, &result);
	if (!err) {
		if (result) {
			fprintf(stderr,
				"%s: Controller-initiated option telemetry disabled\n",
				__func__);
			return -EINVAL;
		}
	} else {
		fprintf(stderr, "ERROR: SNDK: Get telemetry option feature failed.");
		nvme_show_status(err);
		return -EPERM;
	}

	return 0;
}
