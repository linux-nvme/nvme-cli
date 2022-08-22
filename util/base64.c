// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * base64.c - RFC4648-compliant base64 encoding
 *
 * Copyright (c) 2020 Hannes Reinecke, SUSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

static const char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode() - base64-encode some bytes
 * @src: the bytes to encode
 * @srclen: number of bytes to encode
 * @dst: (output) the base64-encoded string.  Not NUL-terminated.
 *
 * Encodes the input string using characters from the set [A-Za-z0-9+,].
 * The encoded string is roughly 4/3 times the size of the input string.
 *
 * Return: length of the encoded string
 */
int base64_encode(const unsigned char *src, int srclen, char *dst)
{
	int i, bits = 0;
	u_int32_t ac = 0;
	char *cp = dst;

	for (i = 0; i < srclen; i++) {
		ac = (ac << 8) | src[i];
		bits += 8;
		do {
			bits -= 6;
			*cp++ = base64_table[(ac >> bits) & 0x3f];
		} while (bits >= 6);
	}
	if (bits) {
		*cp++ = base64_table[(ac << (6 - bits)) & 0x3f];
		bits -= 6;
	}
	while (bits < 0) {
		*cp++ = '=';
		bits += 2;
	}

	return cp - dst;
}

/**
 * base64_decode() - base64-decode some bytes
 * @src: the base64-encoded string to decode
 * @len: number of bytes to decode
 * @dst: (output) the decoded bytes.
 *
 * Decodes the base64-encoded bytes @src according to RFC 4648.
 *
 * Return: number of decoded bytes
 */
int base64_decode(const char *src, int srclen, unsigned char *dst)
{
	u_int32_t ac = 0;
	int i, bits = 0;
	unsigned char *bp = dst;

        for (i = 0; i < srclen; i++) {
                const char *p = strchr(base64_table, src[i]);

                if (src[i] == '=') {
                        ac = (ac << 6);
			bits += 6;
			if (bits >= 8)
				bits -= 8;
                        continue;
                }
                if (p == NULL || src[i] == 0)
                        return -EINVAL;
                ac = (ac << 6) | (p - base64_table);
                bits += 6;
                if (bits >= 8) {
                        bits -= 8;
                        *bp++ = (unsigned char)(ac >> bits);
                }
	}
	if (ac && ((1 << bits) - 1))
		return -EAGAIN;

	return bp - dst;
}
