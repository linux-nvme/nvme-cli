/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "nvme-cmds.h"

extern const char *app_tag;
extern const char *app_tag_mask;
extern const char *block_count;
extern const char *force_unit_access;
extern const char *prinfo;
extern const char *ref_tag;
extern const char *storage_tag;
extern const char *storage_tag_check;

int get_pif_sts(struct nvme_id_ns *ns, struct nvme_nvm_id_ns *nvm_ns,
		__u8 *pif, __u8 *sts);
int init_pi_tags(struct libnvme_transport_handle *hdl,
	struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 ilbrt, __u64 lbst,
	__u16 lbat, __u16 lbatm);
int invalid_tags(__u64 storage_tag, __u64 ref_tag, __u8 sts, __u8 pif);
int submit_io(int opcode, char *command, const char *desc, int argc,
	      char **argv);
