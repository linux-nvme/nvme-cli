/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2020 SUSE LLC
 *
 * Author: Hannes Reinecke <hare@suse.de>
 */
#pragma once

int shr_base64_encode(const unsigned char *src, int len, char *dst);
int shr_base64_decode(const char *src, int len, unsigned char *dst);
