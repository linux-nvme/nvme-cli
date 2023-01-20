/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _MISC_H
#define _MISC_H

/* type conversion helpers */

#include <stdint.h>
#include <linux/types.h>

#include <libnvme.h>

#define ABSOLUTE_ZERO_CELSIUS -273

static inline long kelvin_to_celsius(long t)
{
	return t + ABSOLUTE_ZERO_CELSIUS;
}

/* uint128_t is not always available, define our own. */
union nvme_uint128 {
        __u8  bytes[16];
	__u32 words[4]; /* [0] is most significant word */
};

typedef union nvme_uint128 nvme_uint128_t;

nvme_uint128_t le128_to_cpu(__u8 *data);
long double int128_to_double(__u8 *data);
uint64_t int48_to_long(__u8 *data);

char *uint128_t_to_string(nvme_uint128_t val);
char *uint128_t_to_si_string(nvme_uint128_t val, __u32 bytes_per_unit);
const char *util_uuid_to_string(unsigned char uuid[NVME_UUID_LEN]);
const char *util_fw_to_string(char *c);

#endif /* _MISC_H */
