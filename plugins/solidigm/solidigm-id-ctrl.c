// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include <inttypes.h>
#include "common.h"
#include "solidigm-id-ctrl.h"

struct __packed nvme_vu_id_ctrl_field { // CPC
	__u8	rsvd1[3];
	__u8 ss;
	char health[20];
	__u8 cls;
	__u8 nlw;
	__u8 scap;
	__u8 sstat;
	char bl[8];
	__u8 rsvd2[38];
	__le64 ww;
	char mic_bl[4];
	char mic_fw[4];
	__u8    rsvd3[678];
	__u32 signature;
	__u8 version;
	__u8 product_type;
	__u8 nand_type;
	__u8 form_factor;
	__u32 fw_status;
	__u32 p4_revision; // git hash first 8 characters
	__u32 customer_id;
	__u32 usage_model;
	struct{
		__u32 zns_nvme : 1;  // bit 0
		__u32 mfnd_nvme : 1;  // bit 1
		__u32 cdw1413 : 1;  // bit 2: CDW14 remapping into CDW13
		__u32 vpd_avail : 1;  // bit 3: VPD EEPROM is available
				      //at moment of id-ctrl response
		__u32 rsvd : 28; // bit 4..31 are unused
	}
	command_set;

};

void sldgm_id_ctrl(uint8_t *vs, struct json_object *root)
{
	// text output aligns nicely with property name up to 10 chars
	const char *str_ss = "stripeSize";
	const char *str_health = "health";
	const char *str_cls = "linkSpeed";
	const char *str_nlw = "negLnkWdth";
	const char *str_scap = "secCapab";
	const char *str_sstat = "secStatus";
	const char *str_bl = "bootLoader";
	const char *str_ww = "wwid";
	const char *str_mic_bl = "bwLimGran";
	const char *str_mic_fw = "ioLimGran";
	const char *str_signature = "signature";
	const char *str_version = "version";
	const char *str_product_type = "prodType";
	const char *str_nand_type = "nandType";
	const char *str_form_factor = "formFactor";
	const char *str_fw_status = "fwStatus";
	const char *str_p4_revision = "P4Revision";
	const char *str_customer_id = "customerID";
	const char *str_usage_model = "usageModel";
	const char *str_zns_nvme = "znsNVMe";
	const char *str_mfnd_nvme = "mfndNVMe";
	const char *str_cdw14_cdw13 = "cdw14map13";
	const char *str_vpd_avail = "vpdAvail";

	struct nvme_vu_id_ctrl_field *id = (struct nvme_vu_id_ctrl_field *)vs;

	const char str_heathy[sizeof(id->health)] = "healthy";
	const char *health = id->health[0] ? id->health : str_heathy;

	if (root == NULL) {
		printf("%-10s: %u\n", str_ss, id->ss);
		printf("%-10s: %.*s\n", str_health, (int)sizeof(id->health), health);
		printf("%-10s: %u\n", str_cls, id->cls);
		printf("%-10s: %u\n", str_nlw, id->nlw);
		printf("%-10s: %u\n", str_scap, id->scap);
		printf("%-10s: %u\n", str_sstat, id->sstat);
		printf("%-10s: %.*s\n", str_bl, (int)sizeof(id->bl), id->bl);
		printf("%-10s: 0x%016"PRIx64"\n", str_ww, le64_to_cpu(id->ww));
		printf("%-10s: %.*s\n", str_mic_bl, (int)sizeof(id->mic_bl), id->mic_bl);
		printf("%-10s: %.*s\n", str_mic_fw, (int)sizeof(id->mic_fw), id->mic_fw);
		printf("%-10s: 0x%08X\n", str_signature, id->signature);
		printf("%-10s: 0x%02X\n", str_version, id->version);
		printf("%-10s: %u\n", str_product_type, id->product_type);
		printf("%-10s: %u\n", str_nand_type, id->nand_type);
		printf("%-10s: %u\n", str_form_factor, id->form_factor);
		printf("%-10s: %u\n", str_fw_status, id->fw_status);
		printf("%-10s: 0x%08X\n", str_p4_revision, id->p4_revision);
		printf("%-10s: 0x%08X\n", str_customer_id, id->customer_id);
		printf("%-10s: %u\n", str_usage_model, id->usage_model);
		printf("%-10s: %u\n", str_zns_nvme, id->command_set.zns_nvme);
		printf("%-10s: %u\n", str_mfnd_nvme, id->command_set.mfnd_nvme);
		printf("%-10s: %u\n", str_cdw14_cdw13, id->command_set.cdw1413);
		printf("%-10s: %u\n", str_vpd_avail, id->command_set.vpd_avail);
		return;
	}

	json_object_add_value_uint(root, str_ss, id->ss);
	json_object_object_add(root, str_health,
		json_object_new_string_len(health, sizeof(id->health)));
	json_object_add_value_uint(root, str_cls, id->cls);
	json_object_add_value_uint(root, str_nlw, id->nlw);
	json_object_add_value_uint(root, str_scap, id->scap);
	json_object_add_value_uint(root, str_sstat, id->sstat);
	json_object_object_add(root, str_bl, json_object_new_string_len(id->bl, sizeof(id->bl)));
	json_object_add_value_uint64(root, str_ww, le64_to_cpu(id->ww));
	json_object_object_add(root, str_mic_bl,
		json_object_new_string_len(id->mic_bl, sizeof(id->mic_bl)));
	json_object_object_add(root, str_mic_fw,
		json_object_new_string_len(id->mic_fw, sizeof(id->mic_fw)));
	json_object_add_value_uint(root, str_signature, id->signature);
	json_object_add_value_uint(root, str_version, id->version);
	json_object_add_value_uint(root, str_product_type, id->product_type);
	json_object_add_value_uint(root, str_nand_type, id->nand_type);
	json_object_add_value_uint(root, str_form_factor, id->form_factor);
	json_object_add_value_uint(root, str_fw_status, id->fw_status);
	json_object_add_value_uint(root, str_p4_revision, id->p4_revision);
	json_object_add_value_uint(root, str_customer_id, id->customer_id);
	json_object_add_value_uint(root, str_usage_model, id->usage_model);
	json_object_add_value_uint(root, str_zns_nvme, id->command_set.zns_nvme);
	json_object_add_value_uint(root, str_mfnd_nvme, id->command_set.mfnd_nvme);
	json_object_add_value_uint(root, str_cdw14_cdw13, id->command_set.cdw1413);
	json_object_add_value_uint(root, str_vpd_avail, id->command_set.vpd_avail);
}
