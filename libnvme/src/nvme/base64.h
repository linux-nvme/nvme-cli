/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 */
#pragma once

int base64_encode(const unsigned char *src, int len, char *dst);
int base64_decode(const char *src, int len, unsigned char *dst);
