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

#ifndef _LIBNVME_COMMON_H_
#define _LIBNVME_COMMON_H_

#include <errno.h>

#define _DLL_PUBLIC __attribute__ ((visibility ("default")))

#define NVME_OK				0
#define NVME_ERR_BUG			-1
#define NVME_ERR_NO_MEMORY		ENOMEM
#define NVME_ERR_PERMISSION_DENY	EACCES

#endif /* End of _LIBNVME_COMMON_H_ */
