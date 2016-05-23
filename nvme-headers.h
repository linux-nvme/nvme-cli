#ifndef NVME_HEADERS_H
#define NVME_HEADERS_H

#include "config.h"

#if HAVE_UAPI_LINUX_NVME_IOCTL_H == 1
	#include <uapi/linux/nvme_ioctl.h>
#else
	#include "linux/nvme_ioctl.h"
#endif

#include "linux/nvme.h"

/**
 * Autoconf's also defines a VERSION, we'll use PACKAGE_VERSION instead and
 * undefine VERSION so it will not conflict with our built-in command
 */
#undef VERSION

#endif
