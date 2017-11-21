/*
 * Copyright (C) 2017 Red Hat, Inc.
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */

#ifndef _LIBNVME_CTRL_H_
#define _LIBNVME_CTRL_H_

#include <stdint.h>

#include "libnvme_common.h"
#include "libnvme_ctrl_spec.h"

#define NVME_CTRL_RAW_IDENTIFY_DATA_LEN		4096
#define NVME_CTRL_VENDOR_SPECFIC_DATA_LEN	1024

/**
 * nvme_ctrl_dev_path_get() - Retrieve the device path of specified NVMe
 * controller.
 *
 * Retrieve the device path of specified NVMe controller.
 * The function will return empty string if `struct nvme_ctrl` is retried by
 * nvme_ctrl_get_by_fd().
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	String of device path in the form of "/dev/nvme[0-9]+".
 *	Please don't free this memory, it will be released by
 *	nvme_ctrls_free() or nvme_ctrl_free().
 */
_DLL_PUBLIC const char *nvme_ctrl_dev_path_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_ver_str_get() - Retrieve the version of specified NVMe controller.
 *
 * Retrieve the NVMe SPEC version of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	String of device path in the form of "x.y.z", example: "1.3.0".
 *	Please don't free this memory, it will be released by
 *	nvme_ctrls_free() or nvme_ctrl_free().
 */
_DLL_PUBLIC const char *nvme_ctrl_ver_str_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_psds_get() - Retrieve the power state descriptors of specified NVMe
 * controller.
 *
 * Retrieve the PSDS(Power State Descriptors) arrays of specified NVMe
 * controller. The property of PSD could be retried via functions like
 * `nvme_psd_<prop_name>_get()`.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	struct nvme_psd pointer array.
 *	The size of array is `nvme_ctrl_npss_get() + 1`.
 *	Please don't free this memory, it will be released by
 *	nvme_ctrls_free() or nvme_ctrl_free().
 */
_DLL_PUBLIC struct nvme_psd **nvme_ctrl_psds_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_vendor_specfic_get() - Retrieve the vendor specified data of
 * specified NVMe controller.
 *
 * Retrieve the vendor specified data of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t pointer array.
 *	The size of array is NVME_CTRL_VENDOR_SPECFIC_DATA_LEN(1024).
 *	Please don't free this memory, it will be released by
 *	nvme_ctrls_free() or nvme_ctrl_free().
 */
_DLL_PUBLIC const uint8_t *nvme_ctrl_vendor_specfic_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_raw_id_data_get() - Retrieve the raw identify data of specified
 * NVMe controller.
 *
 * Retrieve the raw identify data of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t pointer array.
 *	The size of array is NVME_CTRL_RAW_IDENTIFY_DATA_LEN(4096).
 *	Please don't free this memory, it will be released by
 *	nvme_ctrls_free() or nvme_ctrl_free().
 */
_DLL_PUBLIC const uint8_t *nvme_ctrl_raw_id_data_get(struct nvme_ctrl *cnt);

#endif /* End of _LIBNVME_CTRL_H_ */
