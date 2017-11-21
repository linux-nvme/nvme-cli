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

#ifndef _LIBNVME_H_
#define _LIBNVME_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

#include "libnvme_common.h"
#include "libnvme_ctrl.h"

/*
 * Macro to convert NVMe SPEC version to a integer which could be compared.
 * Example:
 *	if (nvme_ctrl_ver_get(ctrl) >= NVME_SPEC_VERSION(1, 2, 0)) {
 *	    // Then we are facing 1.2.0+ NVMe implementation.
 *	}
 */
#define NVME_SPEC_VERSION(mj, mn, te) \
	(uint32_t) ((htole16(mj) << 16) + (mn << 8) + te)

/**
 * nvme_ctrls_get() - Query all NVMe controllers.
 *
 * Query all NVMe controllers found by operating system.
 * The properties of NVMe controllers could be retrieved by functions like:
 * nvme_ctrl_<prop_name>_get(). The `<prop_name>` here is the abbreviation of
 * certain property used by NVMe SPEC. For example, to retrieved
 * 'Firmware Revision' which is abbreviated to 'FR' in NVMe SPEC, hence the
 * function responsible is `nvme_ctrl_fr_get()`.
 * Besides functions for property defined in NVMe specification, there are
 * more query functions:
 *	* nvme_ctrl_dev_path_get()
 *	* nvme_ctrl_ver_str_get()
 *	* nvme_ctrl_psds_get()
 *	* nvme_ctrl_vendor_specfic_get()
 *	* nvme_ctrl_raw_id_data_get()
 *
 * @cnts:
 *	Output pointer of `struct nvme_ctrl` array. Memory should be freed by
 *	nvme_ctrls_free(). If specified pointer is NULL, your program will be
 *	terminated by assert().
 * @cnt_count:
 *	Output pointer of `struct nvme_ctrl` array size.
 *	If specified pointer is NULL, your program will be terminated by
 *	assert().
 * @err_msg:
 *	Output pointer of error message when available. Memory should be freed
 *	by free(). If specified pointer is NULL, no error message will be
 *	generated.
 *
 * Return:
 *	int. Valid error codes are:
 *
 *	* NVME_OK
 *
 *	* NVME_ERR_BUG
 *
 *	* NVME_ERR_NO_MEMORY
 *
 *	* NVME_ERR_PERMISSION_DENY
 *
 *	Error number could be converted to string by nvme_strerror().
 */
_DLL_PUBLIC int nvme_ctrls_get(struct nvme_ctrl ***cnts, uint32_t *cnt_count,
			       const char **err_msg);

/**
 * nvme_ctrls_free() - Free memory of the struct nvme_ctrl array.
 *
 * Free memory of the struct nvme_ctrl array generated by nvme_ctrls_get().
 *
 * @cnts:
 *	Pointer of `struct nvme_ctrl` array.
 *	If specified pointer is NULL, nothing will be done.
 * @cnt_count:
 *	The `struct nvme_ctrl` array size.
 *	If specified as 0, nothing will be done.
 *
 * Return:
 *	void
 */
_DLL_PUBLIC void nvme_ctrls_free(struct nvme_ctrl **cnts, uint32_t cnt_count);

/**
 * nvme_ctrl_get_by_fd() - Query specified NVMe controller.
 *
 * Query specified NVMe controller by file descriptor.
 * The properties of NVMe controllers could be retrieved by functions like:
 * nvme_ctrl_<prop_name>_get(). The `<prop_name>` here is the abbreviation of
 * certain property used by NVMe SPEC. For example, to retrieved
 * 'Firmware Revision' which is abbreviated to 'FR' in NVMe SPEC, hence the
 * function responsible is `nvme_ctrl_fr_get()`.
 *
 * @fd:
 *	Integer of the file descriptor. Should be read only or read write open
 *	of "/dev/nvme[0-9]+" or "/dev/nvme[0-9]+n[0-9]+".
 * @cnt:
 *	Output pointer of `struct nvme_ctrl`. Memory should be freed by
 *	nvme_ctrl_free(). If specified pointer is NULL, your program will be
 *	terminated by assert().
 * @err_msg:
 *	Output pointer of error message when available. Memory should be freed
 *	by free(). If specified pointer is NULL, no error message will be
 *	generated.
 *
 * Return:
 *	int. Valid error codes are:
 *
 *	* NVME_OK
 *
 *	* NVME_ERR_BUG
 *
 *	* NVME_ERR_NO_MEMORY
 *
 *	* NVME_ERR_PERMISSION_DENY
 *
 *	Error number could be converted to string by nvme_strerror().
 */
_DLL_PUBLIC int nvme_ctrl_get_by_fd(int fd, struct nvme_ctrl **cnt,
				    const char **err_msg);

/**
 * nvme_ctrl_free() - Free the memory used by specified 'struct nvme_ctrl'.
 *
 * Free the memory used by specified 'struct nvme_ctrl' generated by
 * nvme_ctrl_get_by_fd().
 *
 * @cnt:
 *	Pointer of `struct nvme_ctrl`. If specified pointer is NULL, nothing
 *	will be done.
 *
 * Return:
 *	void.
 */
_DLL_PUBLIC void nvme_ctrl_free(struct nvme_ctrl *cnt);

/**
 * nvme_strerror() - Convert error code to string.
 *
 * Convert error code (int) to string (const char *):
 *
 *	* NVME_OK -- "OK"
 *
 *	* NVME_ERR_BUG -- "BUG of libnvme library"
 *
 *	* NVME_ERR_NO_MEMORY -- "Out of memory"
 *
 *	* NVME_ERR_PERMISSION_DENY -- "Permission deny"
 *
 *	* Other invalid error number -- "Invalid argument"
 *
 * @rc:
 *	int. Return code by libnvme functions. When provided error code is not a
 *	valid error code, return "Invalid argument".
 *
 * Return:
 *	const char *. The meaning of provided error code. Please don't free
 *	returned pointer.
 */
_DLL_PUBLIC const char *nvme_strerror(int rc);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* End of _LIBNVME_H_ */
