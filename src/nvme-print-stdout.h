/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

extern struct print_ops stdout_print_ops;
extern const char dash[100];

void stdout_bits_add_str(struct shr_table *t, const char *bits,
		const char *value, const char *desc_fmt, ...);
char *stdout_power_and_scale_str(__u16 power, __u8 scale);
struct shr_table *stdout_kv_table_create(void);
int stdout_kv_add(struct shr_table *t, const char *name,
		const char *fmt, ...);
void stdout_kv_table_finish(struct shr_table *t, const char *what);
struct shr_table *stdout_bitfields_table(const struct bitfield *fields,
					 unsigned int nr, uint64_t value);
struct shr_table *stdout_bits_table_create(void);
void stdout_bits_add(struct shr_table *t, const char *bits,
		unsigned int val, const char *desc_fmt, ...);
const char *stdout_format_timestamp(__u8 *timestamp_bytes);
void stdout_feature_show_fields(enum nvme_features_id fid, unsigned int result,
				unsigned char *buf);
void stdout_id_ctrl(struct nvme_id_ctrl *ctrl, const char *product_name,
	void (*vendor_show)(__u8 *vs, struct json_object *root));
void stdout_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm);
void stdout_id_domain_list(struct nvme_id_domain_list *id_dom);
void stdout_cmd_set_independent_id_ns(struct nvme_id_independent_id_ns *ns,
				      unsigned int nsid);
void stdout_id_iocs(struct nvme_id_iocs *iocs);
void stdout_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
		  unsigned int lba_index, bool cap_only);
void stdout_id_ns_descs(void *data, unsigned int nsid);
void stdout_id_ns_granularity_list(
	const struct nvme_id_ns_granularity_list *glist);
void stdout_id_nvmset(struct nvme_id_nvmset_list *nvmset,
		      unsigned int nvmset_id);
void stdout_id_uuid_list(const struct nvme_id_uuid_list *uuid_list);
void stdout_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
		      struct nvme_id_ns *ns, unsigned int lba_index,
		      bool cap_only);
void stdout_id_ctrl_rpmbs(__le32 ctrl_rpmbs);
#ifdef CONFIG_FABRICS
void stdout_discovery_log(const struct nvmf_discovery_log *log, int numrec);
#else /* CONFIG_FABRICS */
#define stdout_discovery_log NULL
#endif /* CONFIG_FABRICS */
