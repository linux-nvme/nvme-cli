// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <time.h>
#include <limits.h>

#include <ccan/endian/endian.h>

#include "types.h"
#include "util/suffix.h"

nvme_uint128_t le128_to_cpu(__u8 *data)
{
	nvme_uint128_t u;
	nvme_uint128_t tmp;

	memcpy(tmp.bytes, data, 16);
	u.words[0] = le32_to_cpu(tmp.words[3]);
	u.words[1] = le32_to_cpu(tmp.words[2]);
	u.words[2] = le32_to_cpu(tmp.words[1]);
	u.words[3] = le32_to_cpu(tmp.words[0]);
	return u;
}

long double int128_to_double(__u8 *data)
{
	long double result = 0;
	int i;

	for (i = 0; i < 16; i++) {
		result *= 256;
		result += data[15 - i];
	}
	return result;
}

static uint64_t int_to_long(int bits, const __u8 *data)
{
	int i;
	uint64_t result = 0;
	int bytes = (bits + CHAR_BIT - 1) / CHAR_BIT;

	for (i = 0; i < bytes; i++) {
		result <<= CHAR_BIT;
		result += data[bytes - 1 - i];
	}

	return result;
}

uint64_t int48_to_long(const __u8 *data)
{
	return int_to_long(48, data);
}

uint64_t int56_to_long(const __u8 *data)
{
	return int_to_long(56, data);
}

long double uint128_t_to_double(nvme_uint128_t data)
{
	long double result = 0;
	int i;

	for (i = 0; i < sizeof(data.words) / sizeof(*data.words); i++) {
		result *= 4294967296;
		result += data.words[i];
	}

	return result;
}

static char *__uint128_t_to_string(nvme_uint128_t val, bool l10n)
{
	static char str[60];
	int idx = 60;
	__u64 div, rem;
	char *sep = NULL;
	int i, len = 0, cl = 0;

	if (l10n) {
		sep = localeconv()->thousands_sep;
		len = strlen(sep);
		cl = 1;
	}

	/* terminate at the end, and build up from the ones */
	str[--idx] = '\0';

	do {
		if (len && !((sizeof(str) - idx) % (3 + cl))) {
			for (i = 0; i < len; i++)
				str[--idx] = sep[len - i - 1];
		}

		rem = val.words[0];

		div = rem / 10;
		rem = ((rem - div * 10) << 32) + val.words[1];
		val.words[0] = div;

		div = rem / 10;
		rem = ((rem - div * 10) << 32) + val.words[2];
		val.words[1] = div;

		div = rem / 10;
		rem = ((rem - div * 10) << 32) + val.words[3];
		val.words[2] = div;

		div = rem / 10;
		rem = rem - div * 10;
		val.words[3] = div;

		str[--idx] = '0' + rem;
	} while (val.words[0] || val.words[1] || val.words[2] || val.words[3]);

	return str + idx;
}

char *uint128_t_to_string(nvme_uint128_t val)
{
	return __uint128_t_to_string(val, false);
}

char *uint128_t_to_l10n_string(nvme_uint128_t val)
{
	return __uint128_t_to_string(val, true);
}

char *uint128_t_to_si_string(nvme_uint128_t val, __u32 bytes_per_unit)
{
	long double bytes = uint128_t_to_double(val) * bytes_per_unit;
	static char str[40];
	const char *suffix = suffix_si_get_ld(&bytes);
	int n = snprintf(str, sizeof(str), "%.2Lf %sB", bytes, suffix);

	if (n <= 0)
		return "";

	if (n >= sizeof(str))
		str[sizeof(str) - 1] = '\0';

	return str;
}

const char *util_uuid_to_string(unsigned char uuid[NVME_UUID_LEN])
{
	static char uuid_str[NVME_UUID_LEN_STRING];

	nvme_uuid_to_string(uuid, uuid_str);

	return uuid_str;
}

const char *util_fw_to_string(char *c)
{
	static char ret[9];
	int i;

	for (i = 0; i < 8; i++)
		ret[i] = c[i] >= '!' && c[i] <= '~' ? c[i] : '.';
	ret[i] = '\0';
	return ret;
}

int convert_ts(time_t time, char *ts_buf)
{
	struct tm  time_info;
	time_t     time_human, time_ms;
	char       buf[80];

	time_human = time / 1000;
	time_ms = time % 1000;

	gmtime_r((const time_t *)&time_human, &time_info);

	strftime(buf, sizeof(buf), "%Y-%m-%dD|%H:%M:%S", &time_info);
	sprintf(ts_buf, "%s:%03llu", buf, (unsigned long long)time_ms);

	return 0;
}

void util_spinner(const char *disp_name, float percent)
{
	static const char dash[51] = {[0 ... 49] = '=', '\0'};
	static const char space[51] = {[0 ... 49] = ' ', '\0'};
	static const char spin[] = {'-', '\\', '|', '/' };
	static int progress;
	static int i;
	const char *dn = disp_name ? disp_name : "";

	if (percent < 0)
		percent = 0;
	else if (percent > 1)
		percent = 1;

	progress = (int)(percent * 100.0);
	if (progress < 2)
		printf("\r%s [%c%.*s] %3d%%", dn,
		       spin[i % 4], 49,
		       space, progress);
	else if (progress < 100)
		printf("\r%s [%.*s%c%.*s] %3d%%", dn,
		       progress / 2 - 1, dash,
		       spin[i % 4], 50 - progress / 2,
		       space, progress);
	else
		printf("\r%s [%.*s] %3d%%\n", dn,
		       50, dash, 100);
	i++;

	fflush(stdout);
}
