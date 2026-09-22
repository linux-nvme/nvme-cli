// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2025 Sandisk Corporation or its affiliates.
 *
 *   Author: Jeff Lien <jeff.lien@sandisk.com>
 *           Brandon Paupore <brandon.paupore@sandisk.com>
 */

#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>

#include "nvme-cmds.h"
#include "nvme-pci-ids.h"
#include "nvme-print.h"
#include "plugins/wdc/wdc-nvme-cmds.h"
#include "sandisk-utils.h"

/*  WDC UUID value */
static const __u8 WDC_UUID[NVME_UUID_LEN] = {
	0x2d, 0xb9, 0x8c, 0x52, 0x0c, 0x4c, 0x5a, 0x15,
	0xab, 0xe6, 0x33, 0x29, 0x9a, 0x70, 0xdf, 0xd0
};

/* WDC_UUID value for SN640_3 devices and SN655 devices */
static const __u8 WDC_UUID_SN640_3[NVME_UUID_LEN] = {
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
};

/*  Sandisk UUID value */
static const __u8 SNDK_UUID[NVME_UUID_LEN] = {
	0xde, 0x87, 0xd1, 0xeb, 0x72, 0xc5, 0x58, 0x0b,
	0xad, 0xd8, 0x3c, 0x29, 0xd1, 0x23, 0x7c, 0x70
};

static const __u8 SNDK_SCAO_GUID[SNDK_GUID_LENGTH] = {
	0xC5, 0xAF, 0x10, 0x28, 0xEA, 0xBF, 0xF2, 0xA4,
	0x9C, 0x4F, 0x6F, 0x7C, 0xC9, 0x14, 0xD5, 0xAF
};

static const __u8 SNDK_EXT_SMART_GUID[SNDK_GUID_LENGTH] = {
	0x65, 0x43, 0x88, 0x78, 0xAC, 0xD8, 0x78, 0xA1,
	0x66, 0x42, 0x1E, 0x0F, 0x92, 0xD7, 0x6D, 0xC4
};

int sndk_get_vendor_id(struct libnvme_transport_handle *hdl, uint32_t *vendor_id)
{
	struct nvme_id_ctrl ctrl;
	struct libnvme_passthru_cmd cmd;
	int ret;

	memset(&ctrl, 0, sizeof(struct nvme_id_ctrl));
	nvme_init_identify_ctrl(&cmd, &ctrl);
	ret = libnvme_exec_admin_passthru(hdl, &cmd);
	if (ret) {
		nvme_show_error("ERROR: SNDK: nvme_identify_ctrl() failed 0x%x", ret);
		return -1;
	}

	*vendor_id = (uint32_t) ctrl.vid;

	return ret;
}

bool sndk_check_device(struct libnvme_global_ctx *ctx,
		       struct libnvme_transport_handle *hdl)
{
	uint32_t read_device_id = -1, read_vendor_id = -1;
	bool supported;
	int ret;

	ret = nvme_get_pci_ids(ctx, hdl, &read_vendor_id, &read_device_id,
			       NULL, NULL, NULL);
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
		nvme_show_error(
			"ERROR: SNDK: unsupported Sandisk device, Vendor ID = 0x%x, Device ID = 0x%x\n",
			read_vendor_id, read_device_id);

	return supported;
}

__u32 sndk_get_fw_cust_id(struct libnvme_global_ctx *ctx,
		struct libnvme_transport_handle *hdl)
{
	void *dev_mng_log = NULL;
	__u32 cust_id = SNDK_INVALID_CUSTOMER_ID;

	if (!sndk_get_dev_mgment_data(ctx, hdl, &dev_mng_log))
		return cust_id;

	if (!sndk_nvme_parse_dev_status_log_entry(dev_mng_log,
			SNDK_C2_CUSTOMER_ID_ID,
			&cust_id))
		cust_id = SNDK_INVALID_CUSTOMER_ID;

	free(dev_mng_log);
	return cust_id;
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
		nvme_show_error(
		    "ERROR: %s: log smaller than header. log_len: 0x%x  HdrSize: %"PRIxPTR"\n",
		    __func__, log_length, sizeof(struct sndk_c2_log_page_header));
		return found;
	}

	/* Get pointer to first log Entry */
	offset = sizeof(struct sndk_c2_log_page_header);
	p_next_log_entry = (struct sndk_c2_log_subpage_header *)(((__u8 *)data) + offset);
	remaining_len = log_length - offset;

	if (!log_entry) {
		nvme_show_error("ERROR: SNDK - %s: No log entry pointer.", __func__);
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
			nvme_show_error("ERROR: SNDK: %s: Detected unaligned end of the data. ",
				__func__);
			nvme_show_error("Data Offset: 0x%x Entry Size: 0x%x, ",
				offset, log_entry_size);
			nvme_show_error("Remaining Log Length: 0x%x Entry Id: 0x%x",
				remaining_len, log_entry_id);

			/* Force the loop to end */
			remaining_len = 0;
		} else if (!log_entry_id || log_entry_id > 200) {
			/* Invalid entry - fail the search */
			nvme_show_error("ERROR: SNDK: %s: Invalid entry found at offset: 0x%x ",
				__func__, offset);
			nvme_show_error("Entry Size: 0x%x, Remaining Log Length: 0x%x ",
				log_entry_size, remaining_len);
			nvme_show_error("Entry Id: 0x%x", log_entry_id);

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
		size_t ret_data_size,
		__u32 *ret_data_len)
{
	struct sndk_c2_log_subpage_header *entry_data = NULL;
	struct sndk_c2_cbs_data *entry_str_data = NULL;
	__u32 entry_len, entry_total_len, max_payload_len;

	if (!ret_data || !ret_data_len || ret_data_size == 0)
		return false;

	if (sndk_parse_dev_mng_log_entry(log_data, entry_id, &entry_data)) {
		if (entry_data) {
			entry_str_data = (struct sndk_c2_cbs_data *)&entry_data->data;
			entry_len = le32_to_cpu(entry_str_data->length);
			entry_total_len = le32_to_cpu(entry_data->length);
			if (entry_total_len < sizeof(struct sndk_c2_log_subpage_header)) {
				*ret_data = 0;
				*ret_data_len = 0;
				return false;
			}
			max_payload_len = entry_total_len -
				sizeof(struct sndk_c2_log_subpage_header);
			if (entry_len > max_payload_len || entry_len >= ret_data_size) {
				*ret_data = 0;
				*ret_data_len = 0;
				return false;
			}
			memcpy(ret_data, (void *)&entry_str_data->data, entry_len);
			ret_data[entry_len] = '\0';
			*ret_data_len = entry_len;
			return true;
		}
	}

	*ret_data = 0;
	*ret_data_len = 0;
	return false;
}


bool sndk_get_dev_mgment_data(struct libnvme_global_ctx *ctx, struct libnvme_transport_handle *hdl,
				void **data)
{
	bool found = false;
	__u32 device_id = 0, vendor_id = 0;
	int uuid_index = 0;
	struct nvme_id_uuid_list uuid_list;

	*data = NULL;

	/* The nvme_get_pci_ids function could fail when drives are connected
	 * via a PCIe switch.  Therefore, the return code is intentionally
	 * being ignored.  The device_id and vendor_id variables have been
	 * initialized to 0 so the code can continue on without issue for
	 * both cases: nvme_get_pci_ids successful or failed.
	 */
	nvme_get_pci_ids(ctx, hdl, &vendor_id, &device_id, NULL, NULL, NULL);

	memset(&uuid_list, 0, sizeof(struct nvme_id_uuid_list));
	if (!libnvme_get_uuid_list(hdl, &uuid_list)) {
		/* check for the Sandisk UUID first  */
		uuid_index = libnvme_find_uuid(&uuid_list, SNDK_UUID);

		if (uuid_index < 0) {
			/* The Sandisk UUID is not found;
			 * check for the WDC UUID second.
			 */
			uuid_index = libnvme_find_uuid(&uuid_list, WDC_UUID);
			if (uuid_index < 0)
				/* Check for the UUID used on SN640 and SN655 drives */
				uuid_index = libnvme_find_uuid(&uuid_list, WDC_UUID_SN640_3);
		}

		if (uuid_index >= 0)
			found = sndk_get_dev_mgmt_log_page_data(hdl, data, uuid_index);
		else {
			nvme_show_error("%s: UUID lists are supported but a matching ",
				__func__);
			nvme_show_error("uuid was not found");
		}
	} else {
		/* UUID lists are not supported, Default to uuid-index 0  */
		nvme_show_error("INFO: SNDK: %s:  UUID Lists not supported",
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
		nvme_show_error(
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
			nvme_show_error("ERROR: SNDK: %s: Detected unaligned end of the data. ",
				__func__);
			nvme_show_error("Data Offset: 0x%x Entry Size: 0x%x, ",
				offset, log_entry_size);
			nvme_show_error("Remaining Log Length: 0x%x Entry Id: 0x%x",
				remaining_len, log_entry_id);

			/* Force the loop to end */
			remaining_len = 0;
		} else if (!log_entry_id || log_entry_id > 200) {
			/* Invalid entry - fail the search */
			nvme_show_error("ERROR: SNDK: %s: Invalid entry found at offset: 0x%x ",
				__func__, offset);
			nvme_show_error("Entry Size: 0x%x, Remaining Log Length: 0x%x ",
				log_entry_size, remaining_len);
			nvme_show_error("Entry Id: 0x%x", log_entry_id);

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

bool sndk_get_dev_mgmt_log_page_data(struct libnvme_transport_handle *hdl,
		void **log_data,
		__u8 uuid_ix)
{
	struct sndk_c2_log_page_header *hdr_ptr;
	struct libnvme_passthru_cmd cmd;
	bool valid = false;
	__u32 length = 0;
	void *data;
	int ret = 0;

	data = (__u8 *)malloc(sizeof(__u8) * SNDK_DEV_MGMNT_LOG_PAGE_LEN);
	if (!data) {
		nvme_show_error("ERROR: SNDK: malloc: %s", libnvme_strerror(errno));
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
	ret = libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
	if (ret) {
		nvme_show_error(
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
			nvme_show_error("ERROR: SNDK: malloc: %s", libnvme_strerror(errno));
			goto end;
		}

		/* get the log page data with the increased length */
		nvme_init_get_log(&cmd, NVME_NSID_ALL,
			SNDK_NVME_GET_DEV_MGMNT_LOG_PAGE_ID, NVME_CSI_NVM, data,
			length);
		cmd.cdw14 |= NVME_FIELD_ENCODE(uuid_ix,
				NVME_LOG_CDW14_UUID_SHIFT,
				NVME_LOG_CDW14_UUID_MASK);
		ret = libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
		if (ret) {
			nvme_show_error(
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
			nvme_show_error("ERROR: SNDK: calloc: %s", libnvme_strerror(errno));
			valid = false;
			goto end;
		}
		memcpy((void *)*log_data, data, length);
	} else {
		nvme_show_error("ERROR: SNDK: C2 log page not found with uuid index %d",
			uuid_ix);
	}

end:
	free(data);
	return valid;
}

__u64 sndk_get_drive_capabilities(struct libnvme_global_ctx *ctx,
				  struct libnvme_transport_handle *hdl)
{
	uint32_t read_device_id = -1, read_vendor_id = -1;
	__u64 capabilities = 0;
	int ret;

	ret = nvme_get_pci_ids(ctx, hdl, &read_vendor_id, &read_device_id,
				NULL, NULL, NULL);
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
					SNDK_DRIVE_CAP_CLEAR_ASSERT |
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
					SNDK_DRIVE_CAP_CLEAR_ASSERT |
					SNDK_DRIVE_CAP_CLOUD_SSD_VERSION |
					SNDK_DRIVE_CAP_LOG_PAGE_DIR |
					SNDK_DRIVE_CAP_DRIVE_STATUS |
					SNDK_DRIVE_CAP_SET_LATENCY_MONITOR);
			break;

		case SNDK_NVME_SNESSD3_DEV_ID_E2:
		case SNDK_NVME_SNESSD3_DEV_ID_U2:
		case SNDK_NVME_SNESSD3_DEV_ID_E3L:
		case SNDK_NVME_SNESSD3_DEV_ID_E3S:
		case SNDK_NVME_SNESSD3_DEV_ID_E1L:
			capabilities |= (SNDK_DRIVE_CAP_C0_LOG_PAGE |
					SNDK_DRIVE_CAP_C3_LOG_PAGE |
					SNDK_DRIVE_CAP_CA_LOG_PAGE |
					SNDK_DRIVE_CAP_OCP_C4_LOG_PAGE |
					SNDK_DRIVE_CAP_OCP_C5_LOG_PAGE |
					SNDK_DRIVE_CAP_UDUI |
					SNDK_DRIVE_CAP_VU_FID_CLEAR_PCIE |
					SNDK_DRIVE_CAP_CLEAR_ASSERT |
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

		case SNDK_NVME_SN862_DEV_ID_E1S_25:
		case SNDK_NVME_SN862_DEV_ID_E1S_15:
		case SNDK_NVME_SN862_DEV_ID_E1S_95:
		case SNDK_NVME_SN862_DEV_ID_E3S:
		case SNDK_NVME_SN862_DEV_ID_U2:
		case SNDK_NVME_SNESSD2_DEV_ID_E1S_95:
		case SNDK_NVME_SNESSD2_DEV_ID_E1S_15:
		case SNDK_NVME_SNESSD2_DEV_ID_E1L:
		case SNDK_NVME_SNESSD2_DEV_ID_E3S:
		case SNDK_NVME_SNESSD2_DEV_ID_E3L:
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
	default:
		capabilities = 0;
	}

	/* Check for fallback WDC plugin support */
	if (!capabilities)
		capabilities = run_wdc_get_drive_capabilities(ctx, hdl);

	return capabilities;
}

__u64 sndk_get_enc_drive_capabilities(struct libnvme_global_ctx *ctx,
					    struct libnvme_transport_handle *hdl)
{
	int ret;
	uint32_t read_vendor_id;
	__u64 capabilities = 0;
	__u32 cust_id = 0;
	__u32 market_name_len = 0;
	__u32 drive_form_factor = 0;
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
		if (!libnvme_get_uuid_list(hdl, &uuid_list)) {
			/* check for the Sandisk UUID first  */
			uuid_index = libnvme_find_uuid(&uuid_list, SNDK_UUID);

			if (uuid_index < 0) {
				/* The Sandisk UUID is not found;
				 * check for the WDC UUID second.
				 */
				uuid_index = libnvme_find_uuid(&uuid_list, WDC_UUID);
				if (uuid_index < 0)
					/* Check for the UUID used on SN640 and SN655 drives */
					uuid_index = libnvme_find_uuid(&uuid_list, WDC_UUID_SN640_3);
			}
		} else {
			/* UUID Lists not supported, Use default uuid index - 0 */
			nvme_show_error("INFO: SNDK: %s:  UUID Lists not supported",
					__func__);
			uuid_index = 0;
		}

		/* verify the 0xC2 Device Manageability log page is supported */
		if (run_wdc_nvme_check_supported_log_page(ctx, hdl,
				SNDK_NVME_GET_DEV_MGMNT_LOG_PAGE_ID,
				uuid_index) == false) {
			nvme_show_error("ERROR: SNDK: 0xC2 Log Page not supported, ");
			nvme_show_error("uuid_index: %d", uuid_index);
			goto out;
		}

		if (!sndk_get_dev_mgment_data(ctx, hdl, &dev_mng_log)) {
			nvme_show_error("ERROR: SNDK: 0xC2 Log Page not found");
			goto out;
		}

		/* Get the customer ID */
		if (!sndk_nvme_parse_dev_status_log_entry(dev_mng_log,
				SNDK_C2_CUSTOMER_ID_ID,
				(void *)&cust_id))
			nvme_show_error("ERROR: SNDK: Get Customer FW ID Failed");

		/* Get the marketing name */
		if (!sndk_nvme_parse_dev_status_log_str(dev_mng_log,
				SNDK_C2_MARKETING_NAME_ID,
				(char *)marketing_name,
				sizeof(marketing_name),
				&market_name_len))
			nvme_show_error("ERROR: SNDK: Get Marketing Name Failed");

		/* Get the drive form factor */
		if (!sndk_nvme_parse_dev_status_log_entry(dev_mng_log,
				SNDK_C2_FORM_FACTOR,
				(void *)&drive_form_factor))
			nvme_show_error("ERROR: SNDK: Getting Form Factor Failed");

		/* verify the 0xC0 log page is supported */
		if (run_wdc_nvme_check_supported_log_page(ctx, hdl,
				SNDK_NVME_GET_SMART_CLOUD_ATTR_LOG_ID, 0))
			capabilities |= SNDK_DRIVE_CAP_C0_LOG_PAGE;

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
	free(dev_mng_log);
	return capabilities;
}

int sndk_get_serial_name(struct libnvme_transport_handle *hdl, char *file,
			 size_t len, const char *suffix)
{
	int i;
	int ret;
	int res_len = 0;
	char orig[PATH_MAX] = {0};
	struct nvme_id_ctrl ctrl;
	struct libnvme_passthru_cmd cmd;
	int ctrl_sn_len = sizeof(ctrl.sn);

	i = sizeof(ctrl.sn) - 1;
	strncpy(orig, file, PATH_MAX - 1);
	memset(file, 0, len);
	memset(&ctrl, 0, sizeof(struct nvme_id_ctrl));
	nvme_init_identify_ctrl(&cmd, &ctrl);
	ret = libnvme_exec_admin_passthru(hdl, &cmd);
	if (ret) {
		nvme_show_error("ERROR: SNDK: nvme_identify_ctrl() failed 0x%x", ret);
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
		nvme_show_error(
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
#ifdef NVME_HAVE_TM_GMTOFF
	timeInfo->zone			= -currTimeInfo.tm_gmtoff / 60;
#else /* NVME_HAVE_TM_GMTOFF */
	timeInfo->zone			= -1 * (timezone / 60);
#endif /* NVME_HAVE_TM_GMTOFF */
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
int sndk_check_ctrl_telemetry_option_disabled(struct libnvme_transport_handle *hdl)
{
	int err;
	__u64 result;

	err = nvme_get_features(hdl, 0,
		SNDK_VU_DISABLE_CNTLR_TELEMETRY_OPTION_FEATURE_ID,
		NVME_GET_FEATURES_SEL_CURRENT, 0, 0,
		NULL, 4, &result);
	if (!err) {
		if (result) {
			nvme_show_error(
				"%s: Controller-initiated option telemetry disabled\n",
				__func__);
			return -EINVAL;
		}
	} else {
		nvme_show_error("ERROR: SNDK: Get telemetry option feature failed.");
		nvme_show_status(err);
		return -EPERM;
	}

	return 0;
}

static long double sndk_le_to_float(__u8 *data, int byte_len)
{
	long double result = 0;
	int i;

	for (i = 0; i < byte_len; i++) {
		result *= 256;
		result += data[15 - i];
	}

	return result;
}

static void sndk_stringify_log_page_guid(__u8 *guid, char *buf)
{
	char *ptr = buf;
	int i;

	memset(buf, 0, sizeof(char) * (2 * 16 + 1));

	ptr += sprintf(ptr, "0x");
	for (i = 0; i < 16; i++)
		ptr += sprintf(ptr, "%x", guid[15 - i]);
}

static const char *const sndk_cloud_smart_log_thermal_status[] = {
	[0x00] = "unthrottled",
	[0x01] = "first_level",
	[0x02] = "second_level",
	[0x03] = "third_level",
};

static const char *sndk_stringify_cloud_smart_log_thermal_status(__u8 status)
{
	if (status < ARRAY_SIZE(sndk_cloud_smart_log_thermal_status) &&
	    sndk_cloud_smart_log_thermal_status[status])
		return sndk_cloud_smart_log_thermal_status[status];
	return "unrecognized";
}

static void sndk_show_cloud_smart_log_json(struct sndk_ocp_cloud_smart_log *log)
{
	struct json_object *root;
	struct json_object *bad_user_nand_blocks;
	struct json_object *bad_system_nand_blocks;
	struct json_object *e2e_correction_counts;
	struct json_object *user_data_erase_counts;
	struct json_object *thermal_status;
	struct json_object *dssd_specific_ver;
	char buf[2 * sizeof(log->log_page_guid) + 3];
	char lowest_fr[SNDK_FW_REV_LENGTH + 1];
	uint16_t smart_log_ver = (uint16_t)le16_to_cpu(log->log_page_version);

	bad_user_nand_blocks = json_create_object();
	json_object_add_value_uint(bad_user_nand_blocks, "normalized",
				   le16_to_cpu(log->bad_user_nand_blocks.normalized));
	json_object_add_value_uint(bad_user_nand_blocks, "raw",
				   le64_to_cpu(log->bad_user_nand_blocks.raw));

	bad_system_nand_blocks = json_create_object();
	json_object_add_value_uint(bad_system_nand_blocks, "normalized",
				   le16_to_cpu(log->bad_system_nand_blocks.normalized));
	json_object_add_value_uint(bad_system_nand_blocks, "raw",
				   le64_to_cpu(log->bad_system_nand_blocks.raw));

	e2e_correction_counts = json_create_object();
	json_object_add_value_uint(e2e_correction_counts, "corrected",
				   le32_to_cpu(log->e2e_correction_counts.corrected));
	json_object_add_value_uint(e2e_correction_counts, "detected",
				   le32_to_cpu(log->e2e_correction_counts.detected));

	user_data_erase_counts = json_create_object();
	json_object_add_value_uint(user_data_erase_counts, "minimum",
				   le32_to_cpu(log->user_data_erase_counts.minimum));
	json_object_add_value_uint(user_data_erase_counts, "maximum",
				   le32_to_cpu(log->user_data_erase_counts.maximum));

	thermal_status = json_create_object();
	json_object_add_value_string(thermal_status, "current_status",
		sndk_stringify_cloud_smart_log_thermal_status(log->thermal_status.current_status));
	json_object_add_value_uint(thermal_status, "num_events",
				   log->thermal_status.num_events);

	dssd_specific_ver = json_create_object();
	json_object_add_value_uint(dssd_specific_ver, "major_ver",
				   log->dssd_specific_ver.major_ver);
	json_object_add_value_uint(dssd_specific_ver, "minor_ver",
				   le16_to_cpu(log->dssd_specific_ver.minor_ver));
	json_object_add_value_uint(dssd_specific_ver, "point_ver",
				   le16_to_cpu(log->dssd_specific_ver.point_ver));
	json_object_add_value_uint(dssd_specific_ver, "errata_ver",
				   log->dssd_specific_ver.errata_ver);

	root = json_create_object();
	json_object_add_value_uint64(root, "physical_media_units_written",
				     sndk_le_to_float(log->physical_media_units_written, 16));
	json_object_add_value_uint64(root, "physical_media_units_read",
				     sndk_le_to_float(log->physical_media_units_read, 16));
	json_object_add_value_object(root, "bad_user_nand_blocks",
				     bad_user_nand_blocks);
	json_object_add_value_object(root, "bad_system_nand_blocks",
				     bad_system_nand_blocks);
	json_object_add_value_uint(root, "xor_recovery_count",
				   le64_to_cpu(log->xor_recovery_count));
	json_object_add_value_uint(root, "uncorrectable_read_error_count",
				   le64_to_cpu(log->uncorrectable_read_error_count));
	json_object_add_value_uint(root, "soft_ecc_error_count",
				   le64_to_cpu(log->soft_ecc_error_count));
	json_object_add_value_object(root, "e2e_correction_counts",
				     e2e_correction_counts);
	json_object_add_value_uint(root, "system_data_percent_used",
				   log->system_data_percent_used);
	json_object_add_value_uint(root, "refresh_counts",
				   le64_to_cpu(log->refresh_counts));
	json_object_add_value_object(root, "user_data_erase_counts",
				     user_data_erase_counts);
	json_object_add_value_object(root, "thermal_status", thermal_status);
	if (smart_log_ver >= 3)
		json_object_add_value_object(root, "dssd_specific_ver",
				     dssd_specific_ver);
	else
		json_free_object(dssd_specific_ver);
	json_object_add_value_uint(root, "pcie_correctable_error_count",
				   le64_to_cpu(log->pcie_correctable_error_count));
	json_object_add_value_uint(root, "incomplete_shutdowns",
				   le32_to_cpu(log->incomplete_shutdowns));
	json_object_add_value_uint(root, "percent_free_blocks",
				   log->percent_free_blocks);
	json_object_add_value_uint(root, "capacitor_health",
				   le16_to_cpu(log->capacitor_health));
	if (smart_log_ver >= 3) {
		if (smart_log_ver >= 4) {
			sprintf(buf, "%c", log->nvme_base_errata_ver);
			json_object_add_value_string(root, "nvme_base_errata_version", buf);
			sprintf(buf, "%c", log->nvme_cmd_set_errata_ver);
			json_object_add_value_string(root, "nvme_cmd_set_errata_version", buf);
		} else {
			sprintf(buf, "%c", log->nvme_base_errata_ver);
			json_object_add_value_string(root, "nvme_errata_version", buf);
		}
	}

	json_object_add_value_uint(root, "unaligned_io",
				   le64_to_cpu(log->unaligned_io));
	json_object_add_value_uint(root, "security_version_number",
				   le64_to_cpu(log->security_version_number));
	json_object_add_value_uint(root, "total_nuse",
				   le64_to_cpu(log->total_nuse));
	json_object_add_value_uint64(root, "plp_start_count",
				     sndk_le_to_float(log->plp_start_count, 16));
	json_object_add_value_uint64(root, "endurance_estimate",
				     sndk_le_to_float(log->endurance_estimate, 16));
	if (smart_log_ver >= 3) {
		json_object_add_value_uint(root, "pcie_link_retraining_count",
					   le64_to_cpu(log->pcie_link_retraining_cnt));
		json_object_add_value_uint(root, "power_state_change_count",
					   le64_to_cpu(log->power_state_change_cnt));
		if (smart_log_ver >= 4) {
			snprintf(lowest_fr, sizeof(lowest_fr), "%-.*s",
				SNDK_FW_REV_LENGTH,
				log->lowest_permitted_fw_rev);
			json_object_add_value_string(root, "lowest_permitted_fw_rev", lowest_fr);
		} else {
			json_object_add_value_uint128(root, "hardware_revision",
					le128_to_cpu((__u8 *)&log->lowest_permitted_fw_rev[0]));
		}
	}
	json_object_add_value_uint(root, "log_page_version",
				   smart_log_ver);
	sndk_stringify_log_page_guid(log->log_page_guid, buf);
	json_object_add_value_string(root, "log_page_guid", buf);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void sndk_show_cloud_smart_log_normal(struct sndk_ocp_cloud_smart_log *log,
		struct libnvme_transport_handle *hdl)
{
	char buf[2 * sizeof(log->log_page_guid) + 3];
	uint16_t smart_log_ver = (uint16_t)le16_to_cpu(log->log_page_version);

	printf("SMART Cloud Attributes for NVMe device       : %s\n",
	       libnvme_transport_handle_get_name(hdl));
	printf("Physical Media Units Written                 : %'.0Lf\n",
	       sndk_le_to_float(log->physical_media_units_written, 16));
	printf("Physical Media Units Read                    : %'.0Lf\n",
	       sndk_le_to_float(log->physical_media_units_read, 16));
	printf("Bad User NAND Blocks (Normalized)            : %" PRIu16 "%%\n",
	       le16_to_cpu(log->bad_user_nand_blocks.normalized));
	printf("Bad User NAND Blocks (Raw)                   : %" PRIu64 "\n",
	       le64_to_cpu(log->bad_user_nand_blocks.raw));
	printf("Bad System NAND Blocks (Normalized)          : %" PRIu16 "%%\n",
	       le16_to_cpu(log->bad_system_nand_blocks.normalized));
	printf("Bad System NAND Blocks (Raw)                 : %" PRIu64 "\n",
	       le64_to_cpu(log->bad_system_nand_blocks.raw));
	printf("XOR Recovery Count                           : %" PRIu64 "\n",
	       le64_to_cpu(log->xor_recovery_count));
	printf("Uncorrectable Read Error Count               : %" PRIu64 "\n",
	       le64_to_cpu(log->uncorrectable_read_error_count));
	printf("Soft ECC Error Count                         : %" PRIu64 "\n",
	       le64_to_cpu(log->soft_ecc_error_count));
	printf("End to End Correction Counts (Corrected)     : %" PRIu32 "\n",
	       le32_to_cpu(log->e2e_correction_counts.corrected));
	printf("End to End Correction Counts (Detected)      : %" PRIu32 "\n",
	       le32_to_cpu(log->e2e_correction_counts.detected));
	printf("System Data %% Used                           : %" PRIu8 "%%\n",
	       log->system_data_percent_used);
	printf("Refresh Counts                               : %" PRIu64 "\n",
	       le64_to_cpu(log->refresh_counts));
	printf("User Data Erase Counts (Minimum)             : %" PRIu32 "\n",
	       le32_to_cpu(log->user_data_erase_counts.minimum));
	printf("User Data Erase Counts (Maximum)             : %" PRIu32 "\n",
	       le32_to_cpu(log->user_data_erase_counts.maximum));
	printf("Thermal Throttling Status (Current Status)   : %s\n",
	       sndk_stringify_cloud_smart_log_thermal_status(log->thermal_status.current_status));
	printf("Thermal Throttling Status (Number of Events) : %" PRIu8 "\n",
	       log->thermal_status.num_events);
	if (smart_log_ver >= 3) {
		printf("NVMe Major Version                           : %" PRIu8 "\n",
			   log->dssd_specific_ver.major_ver);
		printf("     Minor Version                           : %" PRIu16 "\n",
		le16_to_cpu(log->dssd_specific_ver.minor_ver));
		printf("     Point Version                           : %" PRIu16 "\n",
		le16_to_cpu(log->dssd_specific_ver.point_ver));
		printf("     Errata Version                          : %" PRIu8 "\n",
			   log->dssd_specific_ver.errata_ver);
	}
	printf("PCIe Correctable Error Count                 : %" PRIu64 "\n",
	       le64_to_cpu(log->pcie_correctable_error_count));
	printf("Incomplete Shutdowns                         : %" PRIu32 "\n",
	       le32_to_cpu(log->incomplete_shutdowns));
	printf("%% Free Blocks                                : %" PRIu8 "%%\n",
	       log->percent_free_blocks);
	printf("Capacitor Health                             : %" PRIu16 "%%\n",
	       le16_to_cpu(log->capacitor_health));
	if (smart_log_ver >= 3) {
		if (smart_log_ver >= 4) {
			printf("NVMe Base Errata Version                     : %c\n",
			       log->nvme_base_errata_ver);
			printf("NVMe Command Set Errata Version              : %c\n",
			       log->nvme_cmd_set_errata_ver);
		} else {
			printf("NVMe Errata Version                          : %c\n",
			       log->nvme_base_errata_ver);
		}
	}
	printf("Unaligned IO                                 : %" PRIu64 "\n",
	       le64_to_cpu(log->unaligned_io));
	printf("Security Version Number                      : %" PRIu64 "\n",
	       le64_to_cpu(log->security_version_number));
	printf("Total NUSE                                   : %" PRIu64 "\n",
	       le64_to_cpu(log->total_nuse));
	printf("PLP Start Count                              : %'.0Lf\n",
	       sndk_le_to_float(log->plp_start_count, 16));
	printf("Endurance Estimate                           : %'.0Lf\n",
	       sndk_le_to_float(log->endurance_estimate, 16));
	if (smart_log_ver >= 3) {
		printf("PCIe Link Retraining Count                   : %" PRIu64 "\n",
		       le64_to_cpu(log->pcie_link_retraining_cnt));
		printf("Power State Change Count                     : %" PRIu64 "\n",
		       le64_to_cpu(log->power_state_change_cnt));
		if (smart_log_ver >= 4)
			printf("Lowest Permitted FW Revision                 : %-.*s\n",
				SNDK_FW_REV_LENGTH,
				log->lowest_permitted_fw_rev);
		else
			printf("Hardware Revision                            : %s\n",
				uint128_t_to_string(le128_to_cpu(
					(__u8 *)&log->lowest_permitted_fw_rev[0])));
	}
	printf("Log Page Version                             : %" PRIu16 "\n",
			smart_log_ver);
	sndk_stringify_log_page_guid(log->log_page_guid, buf);
	printf("Log Page GUID                                : %s\n", buf);
	printf("\n\n");
}

static int sndk_print_c0_cloud_attr_log(void *data, int fmt,
		struct libnvme_transport_handle *hdl)
{
	struct sndk_ocp_cloud_smart_log *log = (struct sndk_ocp_cloud_smart_log *)data;

	if (!data) {
		nvme_show_error("ERROR: SNDK: Invalid buffer to read 0xC0 log");
		return -1;
	}

	switch (fmt) {
	case BINARY:
		d_raw((unsigned char *)log, sizeof(struct sndk_ocp_cloud_smart_log));
		break;
	case NORMAL:
		sndk_show_cloud_smart_log_normal(log, hdl);
		break;
	case JSON:
		sndk_show_cloud_smart_log_json(log);
		break;
	}
	return 0;
}

static void sndk_print_eol_c0_normal(void *data)
{
	struct sndk_nvme_c0_eol_log_page *eol_log_page_ptr =
			(struct sndk_nvme_c0_eol_log_page *)data;

	printf("  End of Life Log Page 0xC0 :-\n");
	printf("  Realloc Block Count\t\t\t%"PRIu32"\n",
			le32_to_cpu(eol_log_page_ptr->eol_rbc));
	printf("  Write Amp\t\t\t\t%"PRIu32"\n",
			le32_to_cpu(eol_log_page_ptr->eol_wra));
	printf("  Percent Life Remaining\t\t%"PRIu32"\n",
			le32_to_cpu(eol_log_page_ptr->eol_plr));
	printf("  Program Fail Count\t\t\t%"PRIu32"\n",
			le32_to_cpu(eol_log_page_ptr->eol_pfc));
	printf("  Erase Fail Count\t\t\t%"PRIu32"\n",
			le32_to_cpu(eol_log_page_ptr->eol_efc));
	printf("  Raw Read Error Rate\t\t\t%"PRIu32"\n",
			le32_to_cpu(eol_log_page_ptr->eol_rrer));
}

static void sndk_print_eol_c0_json(void *data)
{
	struct sndk_nvme_c0_eol_log_page *eol_log_page_ptr =
			(struct sndk_nvme_c0_eol_log_page *)data;
	struct json_object *root = json_create_object();

	json_object_add_value_uint(root, "Realloc Block Count",
		le32_to_cpu(eol_log_page_ptr->eol_rbc));
	json_object_add_value_uint(root, "Write Amp",
		le32_to_cpu(eol_log_page_ptr->eol_wra));
	json_object_add_value_uint(root, "Percent Life Remaining",
		le32_to_cpu(eol_log_page_ptr->eol_plr));
	json_object_add_value_uint(root, "Program Fail Count",
		le32_to_cpu(eol_log_page_ptr->eol_pfc));
	json_object_add_value_uint(root, "Erase Fail Count",
		le32_to_cpu(eol_log_page_ptr->eol_efc));
	json_object_add_value_uint(root, "Raw Read Error Rate",
		le32_to_cpu(eol_log_page_ptr->eol_rrer));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int sndk_print_c0_eol_log(void *data, int fmt)
{
	if (!data) {
		nvme_show_error("ERROR: SNDK: Invalid buffer to read 0xC0 log");
		return -1;
	}
	switch (fmt) {
	case BINARY:
		d_raw((unsigned char *)data, SNDK_NVME_EOL_STATUS_LOG_LEN);
		break;
	case NORMAL:
		sndk_print_eol_c0_normal(data);
		break;
	case JSON:
		sndk_print_eol_c0_json(data);
		break;
	}
	return 0;
}

static void sndk_print_ext_smart_cloud_log_normal(void *data, int mask)
{
	struct __packed sndk_nvme_ext_smart_log *ext_smart_log_ptr =
		(struct __packed sndk_nvme_ext_smart_log *)data;
	int i;

	if (mask == SNDK_SCA_V1_NAND_STATS)
		printf("  NAND Statistics :-\n");
	else
		printf("  SMART Cloud Attributes :-\n");

	printf("  Physical Media Units Written TLC (Bytes): %s\n",
		uint128_t_to_string(le128_to_cpu(
					ext_smart_log_ptr->ext_smart_pmuwt)));
	printf("  Physical Media Units Written SLC (Bytes): %s\n",
		uint128_t_to_string(le128_to_cpu(
					ext_smart_log_ptr->ext_smart_pmuws)));
	printf("  Bad User NAND Block Count (Normalized) (Int) : %d\n",
			le16_to_cpu(*(uint16_t *)ext_smart_log_ptr->ext_smart_bunbc));
	printf("  Bad User NAND Block Count (Raw) (Int)	: %"PRIu64"\n",
			le64_to_cpu(*(uint64_t *)ext_smart_log_ptr->ext_smart_bunbc &
					0xFFFFFFFFFFFF0000));
	printf("  XOR Recovery Count (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_xrc));
	printf("  Uncorrectable Read Error Count (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_urec));
	if (mask == SNDK_SCA_V1_ALL) {
		printf("  SSD End to End correction counts (Corrected Errors) (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_eece));
		printf("  SSD End to End correction counts (Detected Errors) (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_eede));
		printf("  SSD End to End correction counts (Uncorrected E2E Errors) (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_eeue));
		printf("  System Data %% life-used : %d %%\n",
			ext_smart_log_ptr->ext_smart_sdpu);
	}
	printf("  User data erase counts (Minimum TLC) (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_mnudec));
	printf("  User data erase counts (Maximum TLC) (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_mxudec));
	printf("  User data erase counts (Minimum SLC) (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_mnec));
	printf("  User data erase counts (Maximum SLC) (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_mxec));
	printf("  User data erase counts (Average SLC) (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_avec));
	printf("  User data erase counts (Average TLC) (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_avudec));
	printf("  Program Fail Count (Normalized) (Int) : %d\n",
			le16_to_cpu(*(uint16_t *)ext_smart_log_ptr->ext_smart_pfc));
	printf("  Program Fail Count (Raw) (Int) : %"PRIu64"\n",
			le64_to_cpu(*(uint64_t *)ext_smart_log_ptr->ext_smart_pfc &
					0xFFFFFFFFFFFF0000));
	printf("  Erase Fail Count (Normalized) (Int) : %d\n",
			le16_to_cpu(*(uint16_t *)ext_smart_log_ptr->ext_smart_efc));
	printf("  Erase Fail Count (Raw) (Int) : %"PRIu64"\n",
			le64_to_cpu(*(uint64_t *)ext_smart_log_ptr->ext_smart_efc &
					0xFFFFFFFFFFFF0000));
	if (mask == SNDK_SCA_V1_ALL) {
		printf("  PCIe Correctable Error Count (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_pcec));
		printf("  %% Free Blocks (User) (Int) : %d %%\n",
			ext_smart_log_ptr->ext_smart_pfbu);
		printf("  Security Version Number (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_svn));
		printf("  %% Free Blocks (System) (Int)	: %d %%\n",
			ext_smart_log_ptr->ext_smart_pfbs);
		printf("  NVMe Stats (# Data Set Management/TRIM Commands Completed) (Int): %s\n",
			uint128_t_to_string(le128_to_cpu(
						ext_smart_log_ptr->ext_smart_dcc)));
		printf("  Total Namespace Utilization (nvme0n1 NUSE) (Bytes) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_tnu));
		printf("  NVMe Stats (# NVMe Format Commands Completed) (Int) : %d\n",
			le16_to_cpu(ext_smart_log_ptr->ext_smart_fcc));
		printf("  Background Back-Pressure Gauge(%%) (Int) : %d\n",
			ext_smart_log_ptr->ext_smart_bbpg);
	}
	printf("  Total # of Soft ECC Error Count (Int)	: %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_seec));
	if (mask == SNDK_SCA_V1_ALL) {
		printf("  Total # of Read Refresh Count (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_rfsc));
	}
	printf("  Bad System NAND Block Count (Normalized) (Int) : %d\n",
			le16_to_cpu(*(uint16_t *)ext_smart_log_ptr->ext_smart_bsnbc));
	printf("  Bad System NAND Block Count (Raw) (Int) : %"PRIu64"\n",
			le64_to_cpu(*(uint64_t *)ext_smart_log_ptr->ext_smart_bsnbc &
					0xFFFFFFFFFFFF0000));
	printf("  Endurance Estimate (Total Writable Lifetime Bytes) (Bytes) :  %s\n",
		uint128_t_to_string(
			le128_to_cpu(ext_smart_log_ptr->ext_smart_eest)));
	if (mask == SNDK_SCA_V1_ALL) {
		printf("  Thermal Throttling Status & Count (Number of thermal throttling events) (Int) : %d\n",
			le16_to_cpu(ext_smart_log_ptr->ext_smart_ttc));
		printf("  Total # Unaligned I/O (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_uio));
	}
	printf("  Total Physical Media Units Read (Bytes) (Int)	:  %s\n",
		uint128_t_to_string(
			le128_to_cpu(ext_smart_log_ptr->ext_smart_pmur)));
	if (mask == SNDK_SCA_V1_ALL) {
		printf("  Command Timeout (# of READ Commands > 5 Seconds) (Int) : %"PRIu32"\n",
			le32_to_cpu(ext_smart_log_ptr->ext_smart_rtoc));
		printf("  Command Timeout (# of WRITE Commands > 5 Seconds) (Int) : %"PRIu32"\n",
			le32_to_cpu(ext_smart_log_ptr->ext_smart_wtoc));
		printf("  Command Timeout (# of TRIM Commands > 5 Seconds) (Int) : %"PRIu32"\n",
			le32_to_cpu(ext_smart_log_ptr->ext_smart_ttoc));
		printf("  Total PCIe Link Retraining Count (Int) : %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_plrc));
		printf("  Active Power State Change Count (Int)	: %"PRIu64"\n",
			le64_to_cpu(ext_smart_log_ptr->ext_smart_pscc));
	}
	printf("  Cloud Boot SSD Spec Version (Int) : %d.%d.%d.%d\n",
			le16_to_cpu(ext_smart_log_ptr->ext_smart_maj),
			le16_to_cpu(ext_smart_log_ptr->ext_smart_min),
			le16_to_cpu(ext_smart_log_ptr->ext_smart_pt),
			le16_to_cpu(ext_smart_log_ptr->ext_smart_err));
	printf("  Cloud Boot SSD HW Revision (Int) : %d.%d.%d.%d\n",
			0, 0, 0, 0);
	if (mask == SNDK_SCA_V1_ALL) {
		printf("  FTL Unit Size	: %"PRIu32"\n",
			le32_to_cpu(ext_smart_log_ptr->ext_smart_ftlus));
		printf("  TCG Ownership Status : %"PRIu32"\n",
			le32_to_cpu(ext_smart_log_ptr->ext_smart_tcgos));
		printf("  Log Page Version (Int) : %d\n",
			le16_to_cpu(ext_smart_log_ptr->ext_smart_lpv));
		printf("  Log page GUID	(Hex) : 0x");
		for (i = SNDK_GUID_LENGTH; i > 0; i--)
			printf("%02x", ext_smart_log_ptr->ext_smart_lpg[i-1]);
		printf("\n");
	}
	printf("\n");
}

static void sndk_print_ext_smart_cloud_log_json(void *data, int mask)
{
	struct __packed sndk_nvme_ext_smart_log *ext_smart_log_ptr =
		(struct __packed sndk_nvme_ext_smart_log *)data;
	struct json_object *root = json_create_object();
	char vers_str[40];

	json_object_add_value_uint128(root, "physical_media_units_bytes_tlc",
				      le128_to_cpu(ext_smart_log_ptr->ext_smart_pmuwt));
	json_object_add_value_uint128(root, "physical_media_units_bytes_slc",
				      le128_to_cpu(ext_smart_log_ptr->ext_smart_pmuws));
	json_object_add_value_uint(root, "bad_user_blocks_normalized",
				   le16_to_cpu(*(uint16_t *)ext_smart_log_ptr->ext_smart_bunbc));
	json_object_add_value_uint64(root, "bad_user_blocks_raw",
	    le64_to_cpu(*(uint64_t *)ext_smart_log_ptr->ext_smart_bunbc & 0xFFFFFFFFFFFF0000));
	json_object_add_value_uint64(root, "xor_recovery_count",
				     le64_to_cpu(ext_smart_log_ptr->ext_smart_xrc));
	json_object_add_value_uint64(root, "uncorrectable_read_errors",
				     le64_to_cpu(ext_smart_log_ptr->ext_smart_urec));
	if (mask == SNDK_SCA_V1_ALL) {
		json_object_add_value_uint64(root, "corrected_e2e_errors",
					     le64_to_cpu(ext_smart_log_ptr->ext_smart_eece));
		json_object_add_value_uint64(root, "detected_e2e_errors",
					     le64_to_cpu(ext_smart_log_ptr->ext_smart_eede));
		json_object_add_value_uint64(root, "uncorrected_e2e_errors",
					     le64_to_cpu(ext_smart_log_ptr->ext_smart_eeue));
		json_object_add_value_uint(root, "system_data_life_used_pct",
					   (__u8)ext_smart_log_ptr->ext_smart_sdpu);
	}
	json_object_add_value_uint64(root, "min_slc_user_data_erase_count",
				     le64_to_cpu(ext_smart_log_ptr->ext_smart_mnec));
	json_object_add_value_uint64(root, "min_tlc_user_data_erase_count",
				     le64_to_cpu(ext_smart_log_ptr->ext_smart_mnudec));
	json_object_add_value_uint64(root, "max_slc_user_data_erase_count",
				     le64_to_cpu(ext_smart_log_ptr->ext_smart_mxec));
	json_object_add_value_uint64(root, "max_tlc_user_data_erase_count",
				     le64_to_cpu(ext_smart_log_ptr->ext_smart_mxudec));
	json_object_add_value_uint64(root, "avg_slc_user_data_erase_count",
				     le64_to_cpu(ext_smart_log_ptr->ext_smart_avec));
	json_object_add_value_uint64(root, "avg_tlc_user_data_erase_count",
				     le64_to_cpu(ext_smart_log_ptr->ext_smart_avudec));
	json_object_add_value_uint(root, "program_fail_count_normalized",
				   le16_to_cpu(*(uint16_t *)ext_smart_log_ptr->ext_smart_pfc));
	json_object_add_value_uint64(root, "program_fail_count_raw",
	    le64_to_cpu(*(uint64_t *)ext_smart_log_ptr->ext_smart_pfc & 0xFFFFFFFFFFFF0000));
	json_object_add_value_uint(root, "erase_fail_count_normalized",
				   le16_to_cpu(*(uint16_t *)ext_smart_log_ptr->ext_smart_efc));
	json_object_add_value_uint64(root, "erase_fail_count_raw",
	    le64_to_cpu(*(uint64_t *)ext_smart_log_ptr->ext_smart_efc & 0xFFFFFFFFFFFF0000));
	if (mask == SNDK_SCA_V1_ALL) {
		json_object_add_value_uint64(root, "pcie_correctable_errors",
					   le64_to_cpu(ext_smart_log_ptr->ext_smart_pcec));
		json_object_add_value_uint(root, "pct_free_blocks_user",
					   (__u8)ext_smart_log_ptr->ext_smart_pfbu);
		json_object_add_value_uint64(root, "security_version",
					     le64_to_cpu(ext_smart_log_ptr->ext_smart_svn));
		json_object_add_value_uint(root, "pct_free_blocks_system",
					   (__u8)ext_smart_log_ptr->ext_smart_pfbs);
		json_object_add_value_uint128(root, "num_of_trim_commands",
					      le128_to_cpu(ext_smart_log_ptr->ext_smart_dcc));
		json_object_add_value_uint64(root, "total_nuse_bytes",
					   le64_to_cpu(ext_smart_log_ptr->ext_smart_tnu));
		json_object_add_value_uint(root, "num_of_format_commands",
					   le16_to_cpu(ext_smart_log_ptr->ext_smart_fcc));
		json_object_add_value_uint(root, "background_pressure_gauge",
					   (__u8)ext_smart_log_ptr->ext_smart_bbpg);
	}
	json_object_add_value_uint64(root, "soft_ecc_error_count",
				     le64_to_cpu(ext_smart_log_ptr->ext_smart_seec));
	if (mask == SNDK_SCA_V1_ALL)
		json_object_add_value_uint64(root, "read_refresh_count",
					     le64_to_cpu(ext_smart_log_ptr->ext_smart_rfsc));
	json_object_add_value_uint(root, "bad_system_block_normalized",
				      le16_to_cpu(*(uint16_t *)ext_smart_log_ptr->ext_smart_bsnbc));
	json_object_add_value_uint64(root, "bad_system_block_raw",
	    le64_to_cpu(*(uint64_t *)ext_smart_log_ptr->ext_smart_bsnbc & 0xFFFFFFFFFFFF0000));
	json_object_add_value_uint128(root, "endurance_est_bytes",
				      le128_to_cpu(ext_smart_log_ptr->ext_smart_eest));
	if (mask == SNDK_SCA_V1_ALL) {
		json_object_add_value_uint(root, "num_throttling_events",
					   le16_to_cpu(ext_smart_log_ptr->ext_smart_ttc));
		json_object_add_value_uint64(root, "total_unaligned_io",
					     le64_to_cpu(ext_smart_log_ptr->ext_smart_uio));
	}
	json_object_add_value_uint128(root, "physical_media_units_read_bytes",
				      le128_to_cpu(ext_smart_log_ptr->ext_smart_pmur));
	if (mask == SNDK_SCA_V1_ALL) {
		json_object_add_value_uint(root, "num_read_timeouts",
					   le32_to_cpu(ext_smart_log_ptr->ext_smart_rtoc));
		json_object_add_value_uint(root, "num_write_timeouts",
					   le32_to_cpu(ext_smart_log_ptr->ext_smart_wtoc));
		json_object_add_value_uint(root, "num_trim_timeouts",
					   le32_to_cpu(ext_smart_log_ptr->ext_smart_ttoc));
		json_object_add_value_uint64(root, "pcie_link_retrain_count",
					   le64_to_cpu(ext_smart_log_ptr->ext_smart_plrc));
		json_object_add_value_uint64(root, "active_power_state_change_count",
					   le64_to_cpu(ext_smart_log_ptr->ext_smart_pscc));
	}

	memset((void *)vers_str, 0, sizeof(vers_str));
	sprintf((char *)vers_str, "%d.%d.%d.%d",
		le16_to_cpu(ext_smart_log_ptr->ext_smart_maj),
		le16_to_cpu(ext_smart_log_ptr->ext_smart_min),
		le16_to_cpu(ext_smart_log_ptr->ext_smart_pt),
		le16_to_cpu(ext_smart_log_ptr->ext_smart_err));
	json_object_add_value_string(root, "cloud_boot_ssd_spec_ver", vers_str);
	memset((void *)vers_str, 0, sizeof(vers_str));
	sprintf((char *)vers_str, "%d.%d.%d.%d", 0, 0, 0, 0);
	json_object_add_value_string(root, "cloud_boot_ssd_hw_ver", vers_str);

	if (mask == SNDK_SCA_V1_ALL) {
		char guid[40];

		json_object_add_value_uint(root, "ftl_unit_size",
					   le32_to_cpu(ext_smart_log_ptr->ext_smart_ftlus));
		json_object_add_value_uint(root, "tcg_ownership_status",
					   le32_to_cpu(ext_smart_log_ptr->ext_smart_tcgos));
		json_object_add_value_uint(root, "log_page_ver",
					   le16_to_cpu(ext_smart_log_ptr->ext_smart_lpv));

		memset((void *)guid, 0, sizeof(guid));
		sprintf((char *)guid, "0x%"PRIx64"%"PRIx64"",
			le64_to_cpu(*(uint64_t *)&ext_smart_log_ptr->ext_smart_lpg[8]),
			le64_to_cpu(*(uint64_t *)&ext_smart_log_ptr->ext_smart_lpg[0]));
		json_object_add_value_string(root, "log_page_guid", guid);
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int sndk_print_ext_smart_cloud_log(void *data, int fmt)
{
	if (!data) {
		nvme_show_error("ERROR: SNDK: Invalid buffer to read 0xC0 V1 log");
		return -1;
	}
	switch (fmt) {
	case NORMAL:
		sndk_print_ext_smart_cloud_log_normal(data, SNDK_SCA_V1_ALL);
		break;
	case JSON:
		sndk_print_ext_smart_cloud_log_json(data, SNDK_SCA_V1_ALL);
		break;
	}
	return 0;
}

static int sndk_get_ext_smart_cloud_log(struct libnvme_transport_handle *hdl,
		__u8 **data, int uuid_index, __u32 namespace_id)
{
	struct libnvme_passthru_cmd cmd;
	__u8 *log_ptr = NULL;
	int ret, i;

	log_ptr = calloc(1, sizeof(__u8) * SNDK_NVME_SMART_CLOUD_ATTR_LEN);
	if (!log_ptr) {
		nvme_show_error("ERROR: SNDK: calloc: %s", libnvme_strerror(errno));
		return -1;
	}

	/* Get the 0xC0 log data */
	nvme_init_get_log(&cmd, namespace_id,
			  SNDK_NVME_GET_SMART_CLOUD_ATTR_LOG_ID, NVME_CSI_NVM,
			  log_ptr, SNDK_NVME_SMART_CLOUD_ATTR_LEN);
	cmd.cdw14 |= NVME_FIELD_ENCODE(uuid_index,
			       NVME_LOG_CDW14_UUID_SHIFT,
			       NVME_LOG_CDW14_UUID_MASK);
	ret = libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
	if (!ret) {
		/* Verify GUID matches */
		for (i = 0; i < SNDK_GUID_LENGTH; i++) {
			if (SNDK_EXT_SMART_GUID[i] != log_ptr[SNDK_SCAO_V1_LPG + i]) {
				nvme_show_error("ERROR: SNDK: Unknown GUID in C0 Log Page V1 data");
				int j;

				nvme_show_error("ERROR: SNDK: Expected GUID:  0x");
				for (j = 0; j < SNDK_GUID_LENGTH; j++)
					nvme_show_error("%x", SNDK_EXT_SMART_GUID[j]);
				nvme_show_error("\nERROR: SNDK: Actual GUID:    0x");
				for (j = 0; j < SNDK_GUID_LENGTH; j++)
					nvme_show_error("%x", log_ptr[SNDK_SCAO_V1_LPG + j]);
				nvme_show_error("");

				ret = -1;
				break;
			}
		}
	}

	*data = log_ptr;

	return ret;
}

static int sndk_get_c0_cloud_smart_log(struct libnvme_transport_handle *hdl,
		int uuid_index, __u32 namespace_id, int fmt);

static int sndk_get_c0_eol_log(struct libnvme_transport_handle *hdl,
		int uuid_index, __u32 namespace_id, int fmt)
{
	__u32 length = SNDK_NVME_EOL_STATUS_LOG_LEN;
	struct libnvme_passthru_cmd cmd;
	void *log_ptr = NULL;
	int ret;

	log_ptr = calloc(1, sizeof(__u8) * length);
	if (!log_ptr) {
		nvme_show_error("ERROR: SNDK: calloc: %s", libnvme_strerror(errno));
		return -1;
	}

	if (namespace_id == NVME_NSID_ALL) {
		ret = libnvme_get_nsid(hdl, &namespace_id);
		if (ret < 0)
			namespace_id = NVME_NSID_ALL;
	}

	nvme_init_get_log(&cmd, namespace_id,
			  SNDK_NVME_GET_EOL_STATUS_LOG_OPCODE, NVME_CSI_NVM,
			  log_ptr, length);
	cmd.cdw14 |= NVME_FIELD_ENCODE(uuid_index,
			       NVME_LOG_CDW14_UUID_SHIFT,
			       NVME_LOG_CDW14_UUID_MASK);
	ret = libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
	if (fmt == JSON)
		nvme_show_status(ret);

	if (!ret)
		ret = sndk_print_c0_eol_log(log_ptr, fmt);
	else {
		nvme_show_error("ERROR: SNDK: Unable to read C0 Log Page data");
		nvme_show_error("with uuid index %d", uuid_index);
		ret = -1;
	}

	free(log_ptr);
	return ret;
}

static int sndk_get_c0_cloud_smart_log(struct libnvme_transport_handle *hdl,
		int uuid_index, __u32 namespace_id, int fmt)
{
	struct sndk_ocp_cloud_smart_log *log_ptr = NULL;
	struct libnvme_passthru_cmd cmd;
	int ret, i;

	log_ptr = malloc(sizeof(*log_ptr));
	if (!log_ptr) {
		nvme_show_error("ERROR: SNDK: malloc: %s", libnvme_strerror(errno));
		return -1;
	}

	if (namespace_id == NVME_NSID_ALL) {
		ret = libnvme_get_nsid(hdl, &namespace_id);
		if (ret < 0)
			namespace_id = NVME_NSID_ALL;
	}

	nvme_init_get_log(&cmd, namespace_id,
			  SNDK_NVME_GET_SMART_CLOUD_ATTR_LOG_ID, NVME_CSI_NVM,
			  log_ptr, sizeof(*log_ptr));
	cmd.cdw14 |= NVME_FIELD_ENCODE(uuid_index,
			       NVME_LOG_CDW14_UUID_SHIFT,
			       NVME_LOG_CDW14_UUID_MASK);
	ret = libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
	if (fmt == JSON)
		nvme_show_status(ret);

	if (!ret) {
		for (i = 0; i < 16; i++) {
			if (SNDK_SCAO_GUID[i] != log_ptr->log_page_guid[i]) {
				nvme_show_error("ERROR: SNDK: Unknown GUID in C0 Log Page data");
				int j;

				nvme_show_error("ERROR: SNDK: Expected GUID:  0x");
				for (j = 0; j < 16; j++)
					nvme_show_error("%x", SNDK_SCAO_GUID[j]);
				nvme_show_error("\nERROR: SNDK: Actual GUID:    0x");
				for (j = 0; j < 16; j++)
					nvme_show_error("%x", log_ptr->log_page_guid[j]);
				nvme_show_error("");

				ret = -1;
				break;
			}
		}

		if (!ret)
			ret = sndk_print_c0_cloud_attr_log(log_ptr, fmt, hdl);
	} else {
		nvme_show_error("ERROR: SNDK: Unable to read C0 Log Page data");
		ret = -1;
	}

	free(log_ptr);
	return ret;
}

static int sndk_get_c0_log_page_uuid(struct libnvme_transport_handle *hdl,
		int uuid_index,
		__u32 namespace_id,
		int fmt)
{
	if (!uuid_index)
		return sndk_get_c0_cloud_smart_log(hdl, uuid_index, namespace_id, fmt);

	return sndk_get_c0_eol_log(hdl, uuid_index, namespace_id, fmt);
}

int sndk_get_c0_log_page(struct libnvme_global_ctx *ctx,
		struct libnvme_transport_handle *hdl,
		__u32 device_id,
		char *format,
		int uuid_index,
		__u32 namespace_id)
{
	nvme_print_flags_t fmt;
	void *dev_mng_log = NULL;
	__u32 market_name_len = 0;
	char marketing_name[64];
	__u8 *data;
	int ret;

	memset(marketing_name, 0, sizeof(marketing_name));

	if (!sndk_check_device(ctx, hdl))
		return -1;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		nvme_show_error("ERROR: SNDK: invalid output format");
		return ret;
	}

	switch (device_id) {
	case SNDK_NVME_SN650_DEV_ID:
	case SNDK_NVME_SN650_DEV_ID_1:
	case SNDK_NVME_SN650_DEV_ID_2:
	case SNDK_NVME_SN650_DEV_ID_3:
	case SNDK_NVME_SN650_DEV_ID_4:
	case SNDK_NVME_SN655_DEV_ID:
	case SNDK_NVME_SN655_DEV_ID_1:
	case SNDK_NVME_SNTMP_DEV_ID:
	case SNDK_NVME_SNTMP_DEV_ID_1:
	case SNDK_NVME_SNESSD1_DEV_ID_E1L:
	case SNDK_NVME_SNESSD1_DEV_ID_E2:
	case SNDK_NVME_SNESSD1_DEV_ID_E3S:
	case SNDK_NVME_SNESSD1_DEV_ID_E3L:
	case SNDK_NVME_SNESSD1_DEV_ID_U2:
	case SNDK_NVME_SNESSD3_DEV_ID_E1L:
	case SNDK_NVME_SNESSD3_DEV_ID_E2:
	case SNDK_NVME_SNESSD3_DEV_ID_E3S:
	case SNDK_NVME_SNESSD3_DEV_ID_E3L:
	case SNDK_NVME_SNESSD3_DEV_ID_U2:
		ret = sndk_get_c0_log_page_uuid(hdl, uuid_index, namespace_id, fmt);
		break;
	case SNDK_NVME_ZN350_DEV_ID:
	case SNDK_NVME_ZN350_DEV_ID_1:
	case SNDK_NVME_SN861_DEV_ID_E1S:
	case SNDK_NVME_SN861_DEV_ID_U2:
	case SNDK_NVME_SN861_DEV_ID_E3S:
	case SNDK_NVME_SN862_DEV_ID_E1S_25:
	case SNDK_NVME_SN862_DEV_ID_E1S_15:
	case SNDK_NVME_SN862_DEV_ID_E1S_95:
	case SNDK_NVME_SN862_DEV_ID_E3S:
	case SNDK_NVME_SN862_DEV_ID_U2:
	case SNDK_NVME_SNESSD2_DEV_ID_E1S_95:
	case SNDK_NVME_SNESSD2_DEV_ID_E1S_15:
	case SNDK_NVME_SNESSD2_DEV_ID_E1L:
	case SNDK_NVME_SNESSD2_DEV_ID_E3S:
	case SNDK_NVME_SNESSD2_DEV_ID_E3L:
		ret = sndk_get_c0_cloud_smart_log(hdl, 0, NVME_NSID_ALL, fmt);
		break;
	case SNDK_NVME_SN820CL_DEV_ID:
		/* Get the 0xC0 Extended Smart Cloud Attribute log data */
		data = NULL;
		ret = sndk_get_ext_smart_cloud_log(hdl, &data,
						   uuid_index, namespace_id);

		if (strcmp(format, "json"))
			nvme_show_status(ret);

		if (!ret) {
			/* parse the data */
			ret = sndk_print_ext_smart_cloud_log(data, fmt);
		} else {
			nvme_show_error("ERROR: SNDK: Unable to read C0 Log Page V1 data");
			ret = -1;
		}

		free(data);
		break;
	default:
		if (!sndk_get_dev_mgment_data(ctx, hdl, &dev_mng_log)) {
			nvme_show_error("ERROR: SNDK: 0xC2 Log Page not found");
			ret = -1;
			break;
		}

		if (!sndk_nvme_parse_dev_status_log_str(dev_mng_log,
				SNDK_C2_MARKETING_NAME_ID,
				(char *)marketing_name,
				sizeof(marketing_name),
				&market_name_len)) {
			nvme_show_error("ERROR: SNDK: Get Marketing Name Failed");
			ret = -1;
			break;
		}

		if ((!strncmp(marketing_name, SNDK_SN655_MARKETING_NAME_1, market_name_len)) ||
		    (!strncmp(marketing_name, SNDK_SN655_MARKETING_NAME_2, market_name_len)) ||
		    (!strncmp(marketing_name, SNDK_SN655_MARKETING_NAME_3, market_name_len)) ||
		    (!strncmp(marketing_name, SNDK_SN655_MARKETING_NAME_4, market_name_len))) {
			ret = sndk_get_c0_log_page_uuid(hdl, uuid_index, namespace_id, fmt);
		} else if ((!strncmp(marketing_name, SNDK_SN861_MARKETING_NAME_1,
				     market_name_len)) ||
			   (!strncmp(marketing_name, SNDK_SN861_MARKETING_NAME_2,
				     market_name_len))) {
			ret = sndk_get_c0_cloud_smart_log(hdl, 0, NVME_NSID_ALL, fmt);
		} else {
			nvme_show_error("ERROR: SNDK: Unknown device id: 0x%x or marketing name: %s",
					device_id, marketing_name);
			ret = -1;
		}
		break;
	}

	free(dev_mng_log);
	return ret;
}


static int sndk_get_supported_log_pages(struct libnvme_transport_handle *hdl,
		struct nvme_supported_log_pages *supported,
		int uuid_index)
{
	struct libnvme_passthru_cmd cmd;

	memset(supported, 0, sizeof(*supported));
	nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_SUPPORTED_LOG_PAGES,
			  NVME_CSI_NVM, supported, sizeof(*supported));
	cmd.cdw14 |= NVME_FIELD_ENCODE(uuid_index,
			       NVME_LOG_CDW14_UUID_SHIFT,
			       NVME_LOG_CDW14_UUID_MASK);
	return libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
}

static bool sndk_nvme_check_supported_log_page(struct libnvme_global_ctx *ctx,
		struct libnvme_transport_handle *hdl,
		__u8 log_id,
		__u8 uuid_index)
{
	int i;
	bool found = false;
	int err;
	struct nvme_supported_log_pages *supports;
	void *dev_mng_log = NULL;
	struct sndk_c2_log_subpage_header *log_entry = NULL;
	struct sndk_c2_cbs_data *cbs_data = NULL;

	supports = calloc(1, sizeof(*supports));
	if (!supports)
		return false;

	err = sndk_get_supported_log_pages(hdl, supports, uuid_index);
	if (!err && supports->lid_support[log_id])
		found = true;

	free(supports);

	if (found)
		return true;

	if (sndk_get_dev_mgment_data(ctx, hdl, &dev_mng_log) &&
	    sndk_parse_dev_mng_log_entry(dev_mng_log,
		    SNDK_C2_LOG_PAGES_SUPPORTED_ID, &log_entry) &&
	    log_entry) {
		cbs_data = (struct sndk_c2_cbs_data *)&log_entry->data;
		for (i = 0; i < le32_to_cpu(cbs_data->length); i++) {
			if (log_id == cbs_data->data[i]) {
				found = true;
				break;
			}
		}
	}

	free(dev_mng_log);
	return found;
}

static double sndk_safe_div_fp(double numerator, double denominator)
{
	return denominator ? numerator / denominator : 0;
}

static double sndk_calc_percent(uint64_t numerator, uint64_t denominator)
{
	return denominator ? (numerator * 100.0) / denominator : 0;
}

static void sndk_print_log_normal(struct sndk_ssd_perf_stats *perf)
{
	printf("  C1 Log Page Performance Statistics :-\n");
	printf("  Host Read Commands                             %20"PRIu64"\n",
		le64_to_cpu(perf->hr_cmds));
	printf("  Host Read Blocks                               %20"PRIu64"\n",
		le64_to_cpu(perf->hr_blks));
	printf("  Average Read Size                              %20lf\n",
		sndk_safe_div_fp(le64_to_cpu(perf->hr_blks),
				 le64_to_cpu(perf->hr_cmds)));
	printf("  Host Read Cache Hit Commands                   %20"PRIu64"\n",
		le64_to_cpu(perf->hr_ch_cmds));
	printf("  Host Read Cache Hit_Percentage                 %20"PRIu64"%%\n",
		(uint64_t)sndk_calc_percent(le64_to_cpu(perf->hr_ch_cmds),
					    le64_to_cpu(perf->hr_cmds)));
	printf("  Host Read Cache Hit Blocks                     %20"PRIu64"\n",
		le64_to_cpu(perf->hr_ch_blks));
	printf("  Average Read Cache Hit Size                    %20f\n",
		sndk_safe_div_fp(le64_to_cpu(perf->hr_ch_blks),
				 le64_to_cpu(perf->hr_ch_cmds)));
	printf("  Host Read Commands Stalled                     %20"PRIu64"\n",
		le64_to_cpu(perf->hr_st_cmds));
	printf("  Host Read Commands Stalled Percentage          %20"PRIu64"%%\n",
		(uint64_t)sndk_calc_percent(le64_to_cpu(perf->hr_st_cmds),
					    le64_to_cpu(perf->hr_cmds)));
	printf("  Host Write Commands                            %20"PRIu64"\n",
		le64_to_cpu(perf->hw_cmds));
	printf("  Host Write Blocks                              %20"PRIu64"\n",
		le64_to_cpu(perf->hw_blks));
	printf("  Average Write Size                             %20f\n",
		sndk_safe_div_fp(le64_to_cpu(perf->hw_blks), le64_to_cpu(perf->hw_cmds)));
	printf("  Host Write Odd Start Commands                  %20"PRIu64"\n",
		le64_to_cpu(perf->hw_os_cmds));
	printf("  Host Write Odd Start Commands Percentage       %20"PRIu64"%%\n",
		(uint64_t)sndk_calc_percent(le64_to_cpu(perf->hw_os_cmds),
					    le64_to_cpu(perf->hw_cmds)));
	printf("  Host Write Odd End Commands                    %20"PRIu64"\n",
		le64_to_cpu(perf->hw_oe_cmds));
	printf("  Host Write Odd End Commands Percentage         %20"PRIu64"%%\n",
		(uint64_t)sndk_calc_percent(le64_to_cpu(perf->hw_oe_cmds),
					    le64_to_cpu(perf->hw_cmds)));
	printf("  Host Write Commands Stalled                    %20"PRIu64"\n",
		le64_to_cpu(perf->hw_st_cmds));
	printf("  Host Write Commands Stalled Percentage         %20"PRIu64"%%\n",
		(uint64_t)sndk_calc_percent(le64_to_cpu(perf->hw_st_cmds),
					    le64_to_cpu(perf->hw_cmds)));
	printf("  NAND Read Commands                             %20"PRIu64"\n",
		le64_to_cpu(perf->nr_cmds));
	printf("  NAND Read Blocks Commands                      %20"PRIu64"\n",
		le64_to_cpu(perf->nr_blks));
	printf("  Average NAND Read Size                         %20f\n",
		sndk_safe_div_fp(le64_to_cpu(perf->nr_blks), le64_to_cpu(perf->nr_cmds)));
	printf("  Nand Write Commands                            %20"PRIu64"\n",
		le64_to_cpu(perf->nw_cmds));
	printf("  NAND Write Blocks                              %20"PRIu64"\n",
		le64_to_cpu(perf->nw_blks));
	printf("  Average NAND Write Size                        %20f\n",
		sndk_safe_div_fp(le64_to_cpu(perf->nw_blks), le64_to_cpu(perf->nw_cmds)));
	printf("  NAND Read Before Write                         %20"PRIu64"\n",
		le64_to_cpu(perf->nrbw));
}

static void sndk_print_log_json(struct sndk_ssd_perf_stats *perf)
{
	struct json_object *root = json_create_object();

	json_object_add_value_int(root, "Host Read Commands", le64_to_cpu(perf->hr_cmds));
	json_object_add_value_int(root, "Host Read Blocks", le64_to_cpu(perf->hr_blks));
	json_object_add_value_int(root, "Average Read Size",
		sndk_safe_div_fp(le64_to_cpu(perf->hr_blks), le64_to_cpu(perf->hr_cmds)));
	json_object_add_value_int(root, "Host Read Cache Hit Commands",
		le64_to_cpu(perf->hr_ch_cmds));
	json_object_add_value_int(root, "Host Read Cache Hit Percentage",
		(uint64_t)sndk_calc_percent(le64_to_cpu(perf->hr_ch_cmds),
					    le64_to_cpu(perf->hr_cmds)));
	json_object_add_value_int(root, "Host Read Cache Hit Blocks",
		le64_to_cpu(perf->hr_ch_blks));
	json_object_add_value_int(root, "Average Read Cache Hit Size",
		sndk_safe_div_fp(le64_to_cpu(perf->hr_ch_blks), le64_to_cpu(perf->hr_ch_cmds)));
	json_object_add_value_int(root, "Host Read Commands Stalled",
		le64_to_cpu(perf->hr_st_cmds));
	json_object_add_value_int(root, "Host Read Commands Stalled Percentage",
		(uint64_t)sndk_calc_percent(le64_to_cpu(perf->hr_st_cmds),
					    le64_to_cpu(perf->hr_cmds)));
	json_object_add_value_int(root, "Host Write Commands", le64_to_cpu(perf->hw_cmds));
	json_object_add_value_int(root, "Host Write Blocks", le64_to_cpu(perf->hw_blks));
	json_object_add_value_int(root, "Average Write Size",
		sndk_safe_div_fp(le64_to_cpu(perf->hw_blks), le64_to_cpu(perf->hw_cmds)));
	json_object_add_value_int(root, "Host Write Odd Start Commands",
		le64_to_cpu(perf->hw_os_cmds));
	json_object_add_value_int(root, "Host Write Odd Start Commands Percentage",
		(uint64_t)sndk_calc_percent(le64_to_cpu(perf->hw_os_cmds),
					    le64_to_cpu(perf->hw_cmds)));
	json_object_add_value_int(root, "Host Write Odd End Commands",
		le64_to_cpu(perf->hw_oe_cmds));
	json_object_add_value_int(root, "Host Write Odd End Commands Percentage",
		(uint64_t)sndk_calc_percent(le64_to_cpu(perf->hw_oe_cmds),
					    le64_to_cpu(perf->hw_cmds)));
	json_object_add_value_int(root, "Host Write Commands Stalled",
		le64_to_cpu(perf->hw_st_cmds));
	json_object_add_value_int(root, "Host Write Commands Stalled Percentage",
		(uint64_t)sndk_calc_percent(le64_to_cpu(perf->hw_st_cmds),
					    le64_to_cpu(perf->hw_cmds)));
	json_object_add_value_int(root, "NAND Read Commands", le64_to_cpu(perf->nr_cmds));
	json_object_add_value_int(root, "NAND Read Blocks Commands", le64_to_cpu(perf->nr_blks));
	json_object_add_value_int(root, "Average NAND Read Size",
		sndk_safe_div_fp(le64_to_cpu(perf->nr_blks), le64_to_cpu(perf->nr_cmds)));
	json_object_add_value_int(root, "Nand Write Commands", le64_to_cpu(perf->nw_cmds));
	json_object_add_value_int(root, "NAND Write Blocks", le64_to_cpu(perf->nw_blks));
	json_object_add_value_int(root, "Average NAND Write Size",
		sndk_safe_div_fp(le64_to_cpu(perf->nw_blks), le64_to_cpu(perf->nw_cmds)));
	json_object_add_value_int(root, "NAND Read Before Written", le64_to_cpu(perf->nrbw));
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int sndk_print_log(struct sndk_ssd_perf_stats *perf, int fmt)
{
	if (!perf) {
		nvme_show_error("ERROR: SNDK: Invalid buffer to read perf stats");
		return -1;
	}

	switch (fmt) {
	case NORMAL:
		sndk_print_log_normal(perf);
		break;
	case JSON:
		sndk_print_log_json(perf);
		break;
	}

	return 0;
}

static void sndk_print_fb_ca_log_normal(struct sndk_ssd_ca_perf_stats *perf)
{
	uint64_t converted = 0;

	printf("  CA Log Page Performance Statistics :-\n");
	printf("  NAND Bytes Written                             %20"PRIu64"%20"PRIu64"\n",
		le64_to_cpu(perf->nand_bytes_wr_hi), le64_to_cpu(perf->nand_bytes_wr_lo));
	printf("  NAND Bytes Read                                %20"PRIu64"%20"PRIu64"\n",
		le64_to_cpu(perf->nand_bytes_rd_hi), le64_to_cpu(perf->nand_bytes_rd_lo));

	converted = le64_to_cpu(perf->nand_bad_block);
	printf("  NAND Bad Block Count (Normalized)              %20"PRIu64"\n",
		converted & 0xFFFF);
	printf("  NAND Bad Block Count (Raw)                     %20"PRIu64"\n", converted >> 16);
	printf("  Uncorrectable Read Count                       %20"PRIu64"\n",
		le64_to_cpu(perf->uncorr_read_count));
	printf("  Soft ECC Error Count                           %20"PRIu64"\n",
		le64_to_cpu(perf->ecc_error_count));
	printf("  SSD End to End Detected Correction Count       %20"PRIu32"\n",
		(uint32_t)le32_to_cpu(perf->ssd_detect_count));
	printf("  SSD End to End Corrected Correction Count      %20"PRIu32"\n",
		(uint32_t)le32_to_cpu(perf->ssd_correct_count));
	printf("  System Data Percent Used                       %20"PRIu32"%%\n",
		perf->data_percent_used);
	printf("  User Data Erase Counts Max                     %20"PRIu32"\n",
		(uint32_t)le32_to_cpu(perf->data_erase_max));
	printf("  User Data Erase Counts Min                     %20"PRIu32"\n",
		(uint32_t)le32_to_cpu(perf->data_erase_min));
	printf("  Refresh Count                                  %20"PRIu64"\n",
		le64_to_cpu(perf->refresh_count));

	converted = le64_to_cpu(perf->program_fail);
	printf("  Program Fail Count (Normalized)                %20"PRIu64"\n",
		converted & 0xFFFF);
	printf("  Program Fail Count (Raw)                       %20"PRIu64"\n", converted >> 16);

	converted = le64_to_cpu(perf->user_erase_fail);
	printf("  User Data Erase Fail Count (Normalized)        %20"PRIu64"\n",
		converted & 0xFFFF);
	printf("  User Data Erase Fail Count (Raw)               %20"PRIu64"\n", converted >> 16);

	converted = le64_to_cpu(perf->system_erase_fail);
	printf("  System Area Erase Fail Count (Normalized)      %20"PRIu64"\n",
		converted & 0xFFFF);
	printf("  System Area Erase Fail Count (Raw)             %20"PRIu64"\n", converted >> 16);

	printf("  Thermal Throttling Status                      %20"PRIu8"\n",
		perf->thermal_throttle_status);
	printf("  Thermal Throttling Count                       %20"PRIu8"\n",
		perf->thermal_throttle_count);
	printf("  PCIe Correctable Error Count                   %20"PRIu64"\n",
		le64_to_cpu(perf->pcie_corr_error));
	printf("  Incomplete Shutdown Count                      %20"PRIu32"\n",
		(uint32_t)le32_to_cpu(perf->incomplete_shutdown_count));
	printf("  Percent Free Blocks                            %20"PRIu32"%%\n",
		perf->percent_free_blocks);
}

static void sndk_print_fb_ca_log_json(struct sndk_ssd_ca_perf_stats *perf)
{
	struct json_object *root = json_create_object();
	uint64_t converted = 0;

	json_object_add_value_int(root, "NAND Bytes Written Hi",
		le64_to_cpu(perf->nand_bytes_wr_hi));
	json_object_add_value_int(root, "NAND Bytes Written Lo",
		le64_to_cpu(perf->nand_bytes_wr_lo));
	json_object_add_value_int(root, "NAND Bytes Read Hi", le64_to_cpu(perf->nand_bytes_rd_hi));
	json_object_add_value_int(root, "NAND Bytes Read Lo", le64_to_cpu(perf->nand_bytes_rd_lo));

	converted = le64_to_cpu(perf->nand_bad_block);
	json_object_add_value_int(root, "NAND Bad Block Count (Normalized)", converted & 0xFFFF);
	json_object_add_value_int(root, "NAND Bad Block Count (Raw)", converted >> 16);
	json_object_add_value_int(root, "Uncorrectable Read Count",
		le64_to_cpu(perf->uncorr_read_count));
	json_object_add_value_int(root, "Soft ECC Error Count", le64_to_cpu(perf->ecc_error_count));
	json_object_add_value_int(root, "SSD End to End Detected Correction Count",
		le32_to_cpu(perf->ssd_detect_count));
	json_object_add_value_int(root, "SSD End to End Corrected Correction Count",
		le32_to_cpu(perf->ssd_correct_count));
	json_object_add_value_int(root, "System Data Percent Used", perf->data_percent_used);
	json_object_add_value_int(root, "User Data Erase Counts Max",
		le32_to_cpu(perf->data_erase_max));
	json_object_add_value_int(root, "User Data Erase Counts Min",
		le32_to_cpu(perf->data_erase_min));
	json_object_add_value_int(root, "Refresh Count", le64_to_cpu(perf->refresh_count));

	converted = le64_to_cpu(perf->program_fail);
	json_object_add_value_int(root, "Program Fail Count (Normalized)", converted & 0xFFFF);
	json_object_add_value_int(root, "Program Fail Count (Raw)", converted >> 16);

	converted = le64_to_cpu(perf->user_erase_fail);
	json_object_add_value_int(root, "User Data Erase Fail Count (Normalized)",
		converted & 0xFFFF);
	json_object_add_value_int(root, "User Data Erase Fail Count (Raw)", converted >> 16);

	converted = le64_to_cpu(perf->system_erase_fail);
	json_object_add_value_int(root, "System Area Erase Fail Count (Normalized)",
		converted & 0xFFFF);
	json_object_add_value_int(root, "System Area Erase Fail Count (Raw)", converted >> 16);

	json_object_add_value_int(root, "Thermal Throttling Status", perf->thermal_throttle_status);
	json_object_add_value_int(root, "Thermal Throttling Count", perf->thermal_throttle_count);
	json_object_add_value_int(root, "PCIe Correctable Error",
		le64_to_cpu(perf->pcie_corr_error));
	json_object_add_value_int(root, "Incomplete Shutdown Count",
		le32_to_cpu(perf->incomplete_shutdown_count));
	json_object_add_value_int(root, "Percent Free Blocks", perf->percent_free_blocks);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int sndk_print_fb_ca_log(struct sndk_ssd_ca_perf_stats *perf, int fmt)
{
	if (!perf) {
		nvme_show_error("ERROR: SNDK: Invalid buffer to read perf stats");
		return -1;
	}

	switch (fmt) {
	case NORMAL:
		sndk_print_fb_ca_log_normal(perf);
		break;
	case JSON:
		sndk_print_fb_ca_log_json(perf);
		break;
	}

	return 0;
}

static void sndk_print_bd_ca_log_normal(struct libnvme_transport_handle *hdl, void *data)
{
	struct sndk_bd_ca_log_format *bd_data = (struct sndk_bd_ca_log_format *)data;
	__u64 *raw;
	__u64 raw_swapped;
	__u16 *word_raw1 = NULL, *word_raw2 = NULL, *word_raw3 = NULL;
	__u32 *dword_raw = NULL;
	__u8 *byte_raw = NULL;
	bool valid_id = true;

	while (valid_id) {
		raw = (__u64 *)&bd_data->raw_value[0];
		raw_swapped = (le64_to_cpu(*raw) >> 8);

		switch (bd_data->field_id) {
		case 0x0:
			printf("Additional Smart Log for NVME device:%s namespace-id:%x\n",
					libnvme_transport_handle_get_name(hdl), NVME_NSID_ALL);
			printf("key                               normalized raw\n");
			printf("program_fail_count              : %3"PRIu8"%%       %"PRIu64"\n",
					bd_data->normalized_value, (uint64_t)raw_swapped);
			break;
		case 0x1:
			printf("erase_fail_count                : %3"PRIu8"%%       %"PRIu64"\n",
					bd_data->normalized_value, (uint64_t)raw_swapped);
			break;
		case 0x2:
			word_raw1 = (__u16 *)&bd_data->raw_value[1];
			word_raw2 = (__u16 *)&bd_data->raw_value[3];
			word_raw3 = (__u16 *)&bd_data->raw_value[5];
			printf("wear_leveling                   : %3"PRIu8"%%       min: %"PRIu16", max: %"PRIu16", avg: %"PRIu16"\n",
				bd_data->normalized_value,
				le16_to_cpu(*word_raw1),
				le16_to_cpu(*word_raw2),
				le16_to_cpu(*word_raw3));
			break;
		case 0x3:
			printf("end_to_end_error_detection_count: %3"PRIu8"%%       %"PRIu64"\n",
					bd_data->normalized_value, (uint64_t)raw_swapped);
			break;
		case 0x4:
			printf("crc_error_count                 : %3"PRIu8"%%       %"PRIu64"\n",
					bd_data->normalized_value, (uint64_t)raw_swapped);
			break;
		case 0x5:
			printf("timed_workload_media_wear       : %3"PRIu8"%%       %-.3f%%\n",
					bd_data->normalized_value,
					sndk_safe_div_fp(raw_swapped, 1024.0));
			break;
		case 0x6:
			printf("timed_workload_host_reads       : %3"PRIu8"%%       %"PRIu64"\n",
					bd_data->normalized_value, (uint64_t)raw_swapped);
			break;
		case 0x7:
			printf("timed_workload_timer            : %3"PRIu8"%%       %"PRIu64"\n",
					bd_data->normalized_value, (uint64_t)raw_swapped);
			break;
		case 0x8:
			byte_raw = (__u8 *)&bd_data->raw_value[1];
			dword_raw = (__u32 *)&bd_data->raw_value[2];
			printf("thermal_throttle_status         : %3"PRIu8"%%       %"PRIu16"%%, cnt: %"PRIu16"\n",
				bd_data->normalized_value, *byte_raw,
				le32_to_cpu(*dword_raw));
			break;
		case 0x9:
			printf("retry_buffer_overflow_count     : %3"PRIu8"%%       %"PRIu64"\n",
					bd_data->normalized_value, (uint64_t)raw_swapped);
			break;
		case 0xA:
			printf("pll_lock_loss_count             : %3"PRIu8"%%       %"PRIu64"\n",
					bd_data->normalized_value, (uint64_t)raw_swapped);
			break;
		case 0xB:
			printf("nand_bytes_written              : %3"PRIu8"%%       %"PRIu64"\n",
					bd_data->normalized_value, (uint64_t)raw_swapped);
			break;
		case 0xC:
			printf("host_bytes_written              : %3"PRIu8"%%       %"PRIu64"\n",
					bd_data->normalized_value, (uint64_t)raw_swapped);
			valid_id = false;
			break;
		default:
			printf("  Invalid Field ID = %d\n", bd_data->field_id);
			valid_id = false;
			break;
		}

		bd_data++;
	}
}

static int sndk_print_bd_ca_log(void *data, int fmt, struct libnvme_transport_handle *hdl)
{
	if (!data) {
		nvme_show_error("ERROR: SNDK: Invalid buffer to read data");
		return -1;
	}

	switch (fmt) {
	case NORMAL:
		sndk_print_bd_ca_log_normal(hdl, data);
		break;
	case JSON:
	{
		struct sndk_bd_ca_log_format *bd_data = (struct sndk_bd_ca_log_format *)data;
		__u64 *raw, raw_swapped;
		__u16 *word_raw;
		__u32 *dword_raw;
		__u8 *byte_raw;
		bool valid_id = true;
		struct json_object *root = json_create_object();

		while (valid_id) {
			raw = (__u64 *)&bd_data->raw_value[0];
			raw_swapped = (le64_to_cpu(*raw) >> 8);

			switch (bd_data->field_id) {
			case 0x0:
				json_object_add_value_int(root, "program_fail_count normalized",
						bd_data->normalized_value);
				json_object_add_value_uint64(root, "program_fail_count raw",
						raw_swapped);
				break;
			case 0x1:
				json_object_add_value_int(root, "erase_fail_count normalized",
						bd_data->normalized_value);
				json_object_add_value_uint64(root, "erase_fail_count raw",
						raw_swapped);
				break;
			case 0x2:
				word_raw = (__u16 *)&bd_data->raw_value[1];
				json_object_add_value_int(root, "wear_leveling normalized",
						bd_data->normalized_value);
				json_object_add_value_int(root, "wear_leveling min",
						le16_to_cpu(*word_raw));
				word_raw = (__u16 *)&bd_data->raw_value[3];
				json_object_add_value_int(root, "wear_leveling max",
						le16_to_cpu(*word_raw));
				word_raw = (__u16 *)&bd_data->raw_value[5];
				json_object_add_value_int(root, "wear_leveling avg",
						le16_to_cpu(*word_raw));
				break;
			case 0x3:
				json_object_add_value_int(root,
						"end_to_end_error_detection_count normalized",
						bd_data->normalized_value);
				json_object_add_value_uint64(root,
						"end_to_end_error_detection_count raw",
						raw_swapped);
				break;
			case 0x4:
				json_object_add_value_int(root, "crc_error_count normalized",
						bd_data->normalized_value);
				json_object_add_value_uint64(root, "crc_error_count raw",
						raw_swapped);
				break;
			case 0x5:
				json_object_add_value_int(root,
						"timed_workload_media_wear normalized",
						bd_data->normalized_value);
				json_object_add_value_double(root, "timed_workload_media_wear raw",
						sndk_safe_div_fp(((uint64_t)raw_swapped), 1024.0));
				break;
			case 0x6:
				json_object_add_value_int(root,
						"timed_workload_host_reads normalized",
						bd_data->normalized_value);
				json_object_add_value_uint64(root, "timed_workload_host_reads raw",
						raw_swapped);
				break;
			case 0x7:
				json_object_add_value_int(root, "timed_workload_timer normalized",
						bd_data->normalized_value);
				json_object_add_value_uint64(root, "timed_workload_timer",
						raw_swapped);
				break;
			case 0x8:
				byte_raw = (__u8 *)&bd_data->raw_value[1];
				json_object_add_value_int(root,
						"thermal_throttle_status normalized",
						bd_data->normalized_value);
				json_object_add_value_int(root, "thermal_throttle_status",
						*byte_raw);
				dword_raw = (__u32 *)&bd_data->raw_value[2];
				json_object_add_value_int(root, "thermal_throttle_cnt",
						le32_to_cpu(*dword_raw));
				break;
			case 0x9:
				json_object_add_value_int(root,
						"retry_buffer_overflow_count normalized",
						bd_data->normalized_value);
				json_object_add_value_uint64(root,
						"retry_buffer_overflow_count raw",
						raw_swapped);
				break;
			case 0xA:
				json_object_add_value_int(root, "pll_lock_loss_count normalized",
						bd_data->normalized_value);
				json_object_add_value_uint64(root, "pll_lock_loss_count raw",
						raw_swapped);
				break;
			case 0xB:
				json_object_add_value_int(root, "nand_bytes_written normalized",
						bd_data->normalized_value);
				json_object_add_value_uint64(root, "nand_bytes_written raw",
						raw_swapped);
				break;
			case 0xC:
				json_object_add_value_int(root, "host_bytes_written normalized",
						bd_data->normalized_value);
				json_object_add_value_uint64(root, "host_bytes_written raw",
						raw_swapped);
				valid_id = false;
				break;
			default:
				valid_id = false;
				break;
			}

			bd_data++;
		}

		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
		break;
	}
	default:
		nvme_show_error("ERROR: SNDK: Unknown output format");
		return -1;
	}

	return 0;
}

static bool sndk_should_skip_ca_log_page(uint32_t device_id)
{
	switch (device_id) {
	case SNDK_NVME_SNTMP_DEV_ID:
	case SNDK_NVME_SNTMP_DEV_ID_1:
	case SNDK_NVME_SNESSD1_DEV_ID_E1L:
	case SNDK_NVME_SNESSD1_DEV_ID_E2:
	case SNDK_NVME_SNESSD1_DEV_ID_E3S:
	case SNDK_NVME_SNESSD1_DEV_ID_E3L:
	case SNDK_NVME_SNESSD1_DEV_ID_U2:
		return true;
	}

	return false;
}

int sndk_get_ca_log_page(struct libnvme_global_ctx *ctx,
		struct libnvme_transport_handle *hdl,
		char *format)
{
	nvme_print_flags_t fmt;
	__u32 cust_id;
	uint32_t read_device_id = -1;
	__u8 *data;
	int ret;

	if (!sndk_check_device(ctx, hdl))
		return -1;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		nvme_show_error("ERROR: SNDK: invalid output format");
		return ret;
	}

	ret = nvme_get_pci_ids(ctx, hdl, NULL, &read_device_id,
			       NULL, NULL, NULL);
	if (!ret && sndk_should_skip_ca_log_page(read_device_id))
		return 0;

	if (!sndk_nvme_check_supported_log_page(ctx, hdl,
			SNDK_NVME_GET_DEVICE_INFO_LOG_OPCODE, 0)) {
		nvme_show_error("ERROR: SNDK: 0xCA Log Page not supported");
		return -1;
	}

	cust_id = sndk_get_fw_cust_id(ctx, hdl);
	if (cust_id == SNDK_INVALID_CUSTOMER_ID) {
		nvme_show_error("ERROR: SNDK: invalid customer id");
		return -1;
	}

	if (cust_id == SNDK_CUSTOMER_ID_0x1005) {
		data = calloc(1, SNDK_FB_CA_LOG_BUF_LEN);
		if (!data) {
			nvme_show_error("ERROR: SNDK: calloc: %s", libnvme_strerror(errno));
			return -1;
		}

		ret = nvme_get_log_simple(hdl, SNDK_NVME_GET_DEVICE_INFO_LOG_OPCODE,
				  data, SNDK_FB_CA_LOG_BUF_LEN);
		if (strcmp(format, "json"))
			nvme_show_status(ret);

		if (!ret)
			ret = sndk_print_fb_ca_log((struct sndk_ssd_ca_perf_stats *)data, fmt);
		else {
			nvme_show_error("ERROR: SNDK: Unable to read CA Log Page data");
			ret = -1;
		}

		free(data);
		return ret;
	}

	if (cust_id == SNDK_CUSTOMER_ID_GN || cust_id == SNDK_CUSTOMER_ID_GD ||
	    cust_id == SNDK_CUSTOMER_ID_BD || cust_id == SNDK_CUSTOMER_ID_0x100B) {
		data = calloc(1, SNDK_BD_CA_LOG_BUF_LEN);
		if (!data) {
			nvme_show_error("ERROR: SNDK: calloc: %s", libnvme_strerror(errno));
			return -1;
		}

		ret = nvme_get_log_simple(hdl, SNDK_NVME_GET_DEVICE_INFO_LOG_OPCODE,
				  data, SNDK_BD_CA_LOG_BUF_LEN);
		if (strcmp(format, "json"))
			nvme_show_status(ret);

		if (!ret)
			ret = sndk_print_bd_ca_log(data, fmt, hdl);
		else {
			nvme_show_error("ERROR: SNDK: Unable to read CA Log Page data");
			ret = -1;
		}

		free(data);
		return ret;
	}

	nvme_show_error("ERROR: SNDK: Unsupported Customer id, id = 0x%x", cust_id);
	return -1;
}

int sndk_get_c1_log_page(struct libnvme_global_ctx *ctx,
		struct libnvme_transport_handle *hdl,
		char *format,
		uint8_t interval)
{
	struct sndk_log_page_subpage_header *sph;
	struct sndk_ssd_perf_stats *perf;
	struct sndk_log_page_header *hdr;
	nvme_print_flags_t fmt;
	int total_subpages;
	int skip_cnt = 4;
	__u8 *data;
	__u8 *p;
	int i;
	int ret;

	if (!sndk_check_device(ctx, hdl))
		return -1;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		nvme_show_error("ERROR: SNDK: invalid output format");
		return ret;
	}

	if (interval < 1 || interval > 15) {
		nvme_show_error("ERROR: SNDK: interval out of range [1-15]");
		return -1;
	}

	data = calloc(1, SNDK_ADD_LOG_BUF_LEN);
	if (!data) {
		nvme_show_error("ERROR: SNDK: calloc: %s", libnvme_strerror(errno));
		return -1;
	}

	ret = nvme_get_log_simple(hdl, SNDK_NVME_ADD_LOG_OPCODE,
			  data, SNDK_ADD_LOG_BUF_LEN);
	if (strcmp(format, "json"))
		nvme_show_status(ret);

	if (!ret) {
		hdr = (struct sndk_log_page_header *)data;
		total_subpages = hdr->num_subpages + SNDK_NVME_GET_STAT_PERF_INTERVAL_LIFETIME - 1;
		for (i = 0, p = data + skip_cnt; i < total_subpages; i++, p += skip_cnt) {
			sph = (struct sndk_log_page_subpage_header *)p;
			if (sph->spcode == SNDK_GET_LOG_PAGE_SSD_PERFORMANCE &&
			    sph->pcset == interval) {
				perf = (struct sndk_ssd_perf_stats *)(p + 4);
				ret = sndk_print_log(perf, fmt);
				break;
			}
			skip_cnt = le16_to_cpu(sph->subpage_length) + 4;
		}
		if (ret)
			nvme_show_error("ERROR: SNDK: Unable to read data from buffer");
	}

	free(data);
	return ret;
}
