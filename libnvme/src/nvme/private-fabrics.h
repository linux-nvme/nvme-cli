/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */
#pragma once

#include <nvme/tree.h>

/**
 * NVMe-oF private struct definitions.
 *
 * Structs in this file are NVMe-oF-specific (fabrics layer). They are kept
 * separate from private.h so that PCIe-only builds can exclude this entire
 * file and its generated accessors (accessors-fabrics.{h,c}) along with the
 * rest of the fabrics layer.
 */

struct libnvmf_discovery_args { /*!generate-accessors*/
	int max_retries;
	__u8 lsp;
};
