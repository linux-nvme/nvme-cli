/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

int base64_encode(const unsigned char *src, int len, char *dst);
int base64_decode(const char *src, int len, unsigned char *dst);
