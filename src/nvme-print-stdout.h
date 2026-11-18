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
struct shr_table *stdout_bits_table_create(void);
void stdout_bits_add(struct shr_table *t, const char *bits,
		unsigned int val, const char *desc_fmt, ...);
const char *stdout_format_timestamp(__u8 *timestamp_bytes);
