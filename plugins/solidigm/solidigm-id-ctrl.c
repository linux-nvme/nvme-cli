// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include <inttypes.h>
#include "common.h"
#include "solidigm-id-ctrl.h"

struct __packed nvme_vu_id_ctrl_field { /* CDR MR5 */
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
}
