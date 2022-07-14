// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Definitions for the NVM Express interface: libnvme/libnvme-mi device
 * wrappers.
 */

#include <errno.h>

#include <libnvme.h>
#include <libnvme-mi.h>

#include "nvme.h"
#include "nvme-wrap.h"

/*
 * Helper for libnvme functions that pass the fd/ep separately. These just
 * pass the correct handle to the direct/MI function.
 * @op: the name of the libnvme function, without the nvme_/nvme_mi prefix
 * @d: device handle: struct nvme_dev
 */
#define do_admin_op(op, d, ...) ({					\
	int __rc;							\
	if (d->type == NVME_DEV_DIRECT)					\
		__rc = nvme_ ## op(d->direct.fd, __VA_ARGS__);		\
	else if (d->type == NVME_DEV_MI)				\
		__rc = nvme_mi_admin_ ## op (d->mi.ctrl, __VA_ARGS__);	\
	else								\
		__rc = -ENODEV;						\
	__rc; })

/*
 * Helper for libnvme functions use the 'struct _args' pattern. These need
 * the fd and timeout set for the direct interface, and pass the ep as
 * an argument for the MI interface
 * @op: the name of the libnvme function, without the nvme_/nvme_mi prefix
 * @d: device handle: struct nvme_dev
 * @args: op-specific args struct
 */
#define do_admin_args_op(op, d, args) ({				\
	int __rc;							\
	if (d->type == NVME_DEV_DIRECT) {				\
		args->fd = d->direct.fd;				\
		args->timeout = NVME_DEFAULT_IOCTL_TIMEOUT;		\
		__rc = nvme_ ## op(args);				\
	} else if (d->type == NVME_DEV_MI)				\
		__rc = nvme_mi_admin_ ## op (d->mi.ctrl, args);		\
	else								\
		__rc = -ENODEV;						\
	__rc; })

int nvme_cli_identify(struct nvme_dev *dev, struct nvme_identify_args *args)
{
	return do_admin_args_op(identify, dev, args);
}

int nvme_cli_identify_ctrl(struct nvme_dev *dev, struct nvme_id_ctrl *ctrl)
{
	return do_admin_op(identify_ctrl, dev, ctrl);
}

int nvme_cli_identify_ns(struct nvme_dev *dev, __u32 nsid,
			 struct nvme_id_ns *ns)
{
	return do_admin_op(identify_ns, dev, nsid, ns);
}

int nvme_cli_identify_allocated_ns(struct nvme_dev *dev, __u32 nsid,
			 struct nvme_id_ns *ns)
{
	return do_admin_op(identify_allocated_ns, dev, nsid, ns);
}

int nvme_cli_identify_active_ns_list(struct nvme_dev *dev, __u32 nsid,
				     struct nvme_ns_list *list)
{
	return do_admin_op(identify_active_ns_list, dev, nsid, list);
}

int nvme_cli_identify_allocated_ns_list(struct nvme_dev *dev, __u32 nsid,
					struct nvme_ns_list *list)
{
	return do_admin_op(identify_allocated_ns_list, dev, nsid, list);
}

int nvme_cli_get_features(struct nvme_dev *dev,
			  struct nvme_get_features_args *args)
{
	return do_admin_args_op(get_features, dev, args);
}

int nvme_cli_ns_mgmt_delete(struct nvme_dev *dev, __u32 nsid)
{
	return do_admin_op(ns_mgmt_delete, dev, nsid);
}


/* The MI & direct interfaces don't have an exactly-matching API for
 * ns_mgmt_create, as we don't support a timeout for MI.
 */
int nvme_cli_ns_mgmt_create(struct nvme_dev *dev, struct nvme_id_ns *ns,
			__u32 *nsid, __u32 timeout, __u8 csi)
{
	if (dev->type == NVME_DEV_DIRECT)
		return nvme_ns_mgmt_create(dev_fd(dev), ns, nsid, timeout, csi);
	if (dev->type == NVME_DEV_MI)
		return nvme_mi_admin_ns_mgmt_create(dev->mi.ctrl, ns,
						    csi, nsid);

	return -ENODEV;
}

