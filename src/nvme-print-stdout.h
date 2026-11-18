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
void stdout_id_ctrl_rpmbs(__le32 ctrl_rpmbs);
#ifdef CONFIG_FABRICS
void stdout_discovery_log(const struct nvmf_discovery_log *log, int numrec);
#else /* CONFIG_FABRICS */
#define stdout_discovery_log NULL
#endif /* CONFIG_FABRICS */

/* id */
struct shr_table *stdout_id_ctrl_rpmbs_table(__le32 ctrl_rpmbs);
