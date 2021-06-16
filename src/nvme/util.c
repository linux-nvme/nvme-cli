// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "filters.h"
#include "util.h"
#include "tree.h"
#include "log.h"

static inline __u8 nvme_generic_status_to_errno(__u16 status)
{
	switch (status) {
	case NVME_SC_INVALID_OPCODE:
	case NVME_SC_INVALID_FIELD:
	case NVME_SC_INVALID_NS:
	case NVME_SC_SGL_INVALID_LAST:
	case NVME_SC_SGL_INVALID_COUNT:
	case NVME_SC_SGL_INVALID_DATA:
	case NVME_SC_SGL_INVALID_METADATA:
	case NVME_SC_SGL_INVALID_TYPE:
	case NVME_SC_SGL_INVALID_OFFSET:
		return EINVAL;
	case NVME_SC_CMDID_CONFLICT:
		return EADDRINUSE;
	case NVME_SC_DATA_XFER_ERROR:
	case NVME_SC_INTERNAL:
	case NVME_SC_SANITIZE_FAILED:
		return EIO;
	case NVME_SC_POWER_LOSS:
	case NVME_SC_ABORT_REQ:
	case NVME_SC_ABORT_QUEUE:
	case NVME_SC_FUSED_FAIL:
	case NVME_SC_FUSED_MISSING:
		return EWOULDBLOCK;
	case NVME_SC_CMD_SEQ_ERROR:
		return EILSEQ;
	case NVME_SC_SANITIZE_IN_PROGRESS:
		return EINPROGRESS;
	case NVME_SC_NS_WRITE_PROTECTED:
	case NVME_SC_NS_NOT_READY:
	case NVME_SC_RESERVATION_CONFLICT:
		return EACCES;
	case NVME_SC_LBA_RANGE:
		return EREMOTEIO;
	case NVME_SC_CAP_EXCEEDED:
		return ENOSPC;
	}
	return EIO;
}

static inline __u8 nvme_cmd_specific_status_to_errno(__u16 status)
{
	switch (status) {
	case NVME_SC_CQ_INVALID:
	case NVME_SC_QID_INVALID:
	case NVME_SC_QUEUE_SIZE:
	case NVME_SC_FIRMWARE_SLOT:
	case NVME_SC_FIRMWARE_IMAGE:
	case NVME_SC_INVALID_VECTOR:
	case NVME_SC_INVALID_LOG_PAGE:
	case NVME_SC_INVALID_FORMAT:
	case NVME_SC_INVALID_QUEUE:
	case NVME_SC_NS_INSUFFICIENT_CAP:
	case NVME_SC_NS_ID_UNAVAILABLE:
	case NVME_SC_CTRL_LIST_INVALID:
	case NVME_SC_BAD_ATTRIBUTES:
	case NVME_SC_INVALID_PI:
		return EINVAL;
	case NVME_SC_ABORT_LIMIT:
	case NVME_SC_ASYNC_LIMIT:
		return EDQUOT;
	case NVME_SC_FW_NEEDS_CONV_RESET:
	case NVME_SC_FW_NEEDS_SUBSYS_RESET:
	case NVME_SC_FW_NEEDS_MAX_TIME:
		return ERESTART;
	case NVME_SC_FEATURE_NOT_SAVEABLE:
	case NVME_SC_FEATURE_NOT_CHANGEABLE:
	case NVME_SC_FEATURE_NOT_PER_NS:
	case NVME_SC_FW_ACTIVATE_PROHIBITED:
	case NVME_SC_NS_IS_PRIVATE:
	case NVME_SC_BP_WRITE_PROHIBITED:
	case NVME_SC_READ_ONLY:
	case NVME_SC_PMR_SAN_PROHIBITED:
		return EPERM;
	case NVME_SC_OVERLAPPING_RANGE:
	case NVME_SC_NS_NOT_ATTACHED:
		return ENOSPC;
	case NVME_SC_NS_ALREADY_ATTACHED:
		return EALREADY;
	case NVME_SC_THIN_PROV_NOT_SUPP:
		return EOPNOTSUPP;
	}

	return EIO;
}

static inline __u8 nvme_fabrics_status_to_errno(__u16 status)
{
	switch (status) {
	case NVME_SC_CONNECT_FORMAT:
	case NVME_SC_CONNECT_INVALID_PARAM:
		return EINVAL;
	case NVME_SC_CONNECT_CTRL_BUSY:
		return EBUSY;
	case NVME_SC_CONNECT_RESTART_DISC:
		return ERESTART;
	case NVME_SC_CONNECT_INVALID_HOST:
		return ECONNREFUSED;
	case NVME_SC_DISCOVERY_RESTART:
		return EAGAIN;
	case NVME_SC_AUTH_REQUIRED:
		return EPERM;
	}

	return EIO;
}

__u8 nvme_status_to_errno(int status, bool fabrics)
{
	__u16 sc;

	if (!status)
		return 0;
	if (status < 0)
		return errno;

	sc = nvme_status_code(status);
	switch (nvme_status_code_type(status)) {
	case NVME_SCT_GENERIC:
		return nvme_generic_status_to_errno(sc);
	case NVME_SCT_CMD_SPECIFIC:
		if  (fabrics)
			return nvme_fabrics_status_to_errno(sc);
		return nvme_cmd_specific_status_to_errno(sc);
	default:
		return EIO;
	}
}

static int __nvme_open(const char *name)
{
	char *path;
	int fd, ret;

	ret = asprintf(&path, "%s/%s", "/dev", name);
	if (ret < 0) {
		errno = ENOMEM;
		return -1;
	}

	fd = open(path, O_RDONLY);
	free(path);
	return fd;
}

int nvme_open(const char *name)
{
	int ret, fd, id, ns;
	struct stat stat;
	bool c;

	ret = sscanf(name, "nvme%dn%d", &id, &ns);
	if (ret != 1 && ret != 2) {
		errno = EINVAL;
		return -1;
	}
	c = ret == 1;

	fd = __nvme_open(name);
	if (fd < 0)
		return fd;

	ret = fstat(fd, &stat);
	if (ret < 0)
		goto close_fd;

	if (c) {
		if (!S_ISCHR(stat.st_mode)) {
			errno = EINVAL;
			goto close_fd;
		}
	} else if (!S_ISBLK(stat.st_mode)) {
		errno = EINVAL;
		goto close_fd;
	}

	return fd;

close_fd:
	close(fd);
	return -1;
}

int nvme_fw_download_seq(int fd, __u32 size, __u32 xfer, __u32 offset,
			 void *buf)
{
	int err = 0;

	while (size > 0) {
		xfer = MIN(xfer, size);
		err = nvme_fw_download(fd, offset, xfer, buf);
		if (err)
			break;

		buf += xfer;
		size -= xfer;
		offset += xfer;
	}

	return err;
}

int __nvme_get_log_page(int fd, __u32 nsid, __u8 log_id, bool rae,
			__u32 xfer_len, __u32 data_len, void *data)
{
	__u64 offset = 0, xfer;
	bool retain = true;
	void *ptr = data;
	int ret;

	/*
	 * 4k is the smallest possible transfer unit, so restricting to 4k
	 * avoids having to check the MDTS value of the controller.
	 */
	do {
		xfer = data_len - offset;
		if (xfer > xfer_len)
			xfer  = xfer_len;

		/*
		 * Always retain regardless of the RAE parameter until the very
		 * last portion of this log page so the data remains latched
		 * during the fetch sequence.
		 */
		if (offset + xfer == data_len)
			retain = rae;

		ret = nvme_get_log(fd, log_id, nsid, offset, NVME_LOG_LSP_NONE,
				   NVME_LOG_LSI_NONE, retain, NVME_UUID_NONE,
				   NVME_CSI_NVM, xfer, ptr);
		if (ret)
			return ret;

		offset += xfer;
		ptr += xfer;
	} while (offset < data_len);

	return 0;
}

int nvme_get_log_page(int fd, __u32 nsid, __u8 log_id, bool rae,
		      __u32 data_len, void *data)
{
	return __nvme_get_log_page(fd, nsid, log_id, rae, 4096, data_len, data);
}

static int nvme_get_telemetry_log(int fd, bool create, bool ctrl, bool rae,
				  struct nvme_telemetry_log **buf)
{
	static const __u32 xfer = NVME_LOG_TELEM_BLOCK_SIZE;

	struct nvme_telemetry_log *telem;
	enum nvme_cmd_get_log_lid lid;
	void *log, *tmp;
	__u32 size;
	int err;

	log = malloc(xfer);
	if (!log) {
		errno = ENOMEM;
		return -1;
	}

	if (ctrl) {
		err = nvme_get_log_telemetry_ctrl(fd, true, 0, xfer, log);
		lid = NVME_LOG_LID_TELEMETRY_CTRL;
	} else {
		lid = NVME_LOG_LID_TELEMETRY_HOST;
		if (create)
			err = nvme_get_log_create_telemetry_host(fd, log);
		else
			err = nvme_get_log_telemetry_host(fd, 0, xfer, log);
	}

	if (err)
		goto free;

	telem = log;
	if (ctrl && !telem->ctrlavail) {
		*buf = log;
		return 0;
	}

	/* dalb3 >= dalb2 >= dalb1 */
	size = (le16_to_cpu(telem->dalb3) + 1) * xfer;
	tmp = realloc(log, size);
	if (!tmp) {
		errno = ENOMEM;
		err = -1;
		goto free;
	}
	log = tmp;

	err = nvme_get_log_page(fd, NVME_NSID_NONE, lid, rae, size, (void *)log);
	if (!err) {
		*buf = log;
		return 0;
	}
free:
	free(log);
	return err;
}

int nvme_get_ctrl_telemetry(int fd, bool rae, struct nvme_telemetry_log **log)
{
	return nvme_get_telemetry_log(fd, false, true, rae, log);
}

int nvme_get_host_telemetry(int fd, struct nvme_telemetry_log **log)
{
	return nvme_get_telemetry_log(fd, false, false, false, log);
}

int nvme_get_new_host_telemetry(int fd, struct nvme_telemetry_log **log)
{
	return nvme_get_telemetry_log(fd, true, false, false, log);
}

int nvme_get_lba_status_log(int fd, bool rae, struct nvme_lba_status_log **log)
{
	__u32 size = sizeof(struct nvme_lba_status_log);
	void *buf, *tmp;
	int err;

	buf = malloc(size);
	if (!buf)
		return -1;

	*log = buf;
	err = nvme_get_log_lba_status(fd, true, 0, size, buf);
	if (err)
		goto free;

	size = le32_to_cpu((*log)->lslplen);
	if (!size)
		return 0;

	tmp = realloc(buf, size);
	if (!tmp) {
		err = -1;
		goto free;
	}
	buf = tmp;
	*log = buf;

	err = nvme_get_log_page(fd, NVME_NSID_NONE, NVME_LOG_LID_LBA_STATUS,
				rae, size, buf);
	if (!err)
		return 0;

free:
	*log = NULL;
	free(buf);
	return err;
}

void nvme_init_copy_range(struct nvme_copy_range *copy, __u16 *nlbs,
			  __u64 *slbas, __u32 *eilbrts, __u32 *elbatms,
			  __u32 *elbats, __u16 nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		copy[i].nlb = cpu_to_le16(nlbs[i]);
		copy[i].slba = cpu_to_le64(slbas[i]);
		copy[i].eilbrt = cpu_to_le32(eilbrts[i]);
		copy[i].elbatm = cpu_to_le16(elbatms[i]);
		copy[i].elbat = cpu_to_le16(elbats[i]);
	}
}

void nvme_init_dsm_range(struct nvme_dsm_range *dsm, __u32 *ctx_attrs,
			 __u32 *llbas, __u64 *slbas, __u16 nr_ranges)
{
	int i;

	for (i = 0; i < nr_ranges; i++) {
		dsm[i].cattr = cpu_to_le32(ctx_attrs[i]);
		dsm[i].nlb = cpu_to_le32(llbas[i]);
		dsm[i].slba = cpu_to_le64(slbas[i]);
	}
}

void nvme_init_id_ns(struct nvme_id_ns *ns, __u64 nsze, __u64 ncap, __u8 flbas,
		__u8 dps, __u8 nmic, __u32 anagrpid, __u16 nvmsetid)
{
	memset(ns, 0, sizeof(*ns));
	ns->nsze = cpu_to_le64(nsze);
	ns->ncap = cpu_to_le64(ncap);
	ns->flbas = flbas;
	ns->dps = dps;
	ns->nmic = nmic;
	ns->anagrpid = cpu_to_le32(anagrpid);
	ns->nvmsetid = cpu_to_le16(nvmsetid);
}

void nvme_init_ctrl_list(struct nvme_ctrl_list *cntlist, __u16 num_ctrls,
			  __u16 *ctrlist)
{
	int i;

	cntlist->num = cpu_to_le16(num_ctrls);
	for (i = 0; i < num_ctrls; i++)
		cntlist->identifier[i] = cpu_to_le16(ctrlist[i]);
}

static int nvme_ns_attachment(int fd, __u32 nsid, __u16 num_ctrls,
			      __u16 *ctrlist, bool attach)
{
	enum nvme_ns_attach_sel sel = NVME_NS_ATTACH_SEL_CTRL_DEATTACH;
	struct nvme_ctrl_list cntlist = { 0 };

	if (attach)
		sel = NVME_NS_ATTACH_SEL_CTRL_ATTACH;

	nvme_init_ctrl_list(&cntlist, num_ctrls, ctrlist);
	return nvme_ns_attach(fd, nsid, sel, &cntlist);
}

int nvme_namespace_attach_ctrls(int fd, __u32 nsid, __u16 num_ctrls,
				__u16 *ctrlist)
{
	return nvme_ns_attachment(fd, nsid, num_ctrls, ctrlist, true);
}

int nvme_namespace_detach_ctrls(int fd, __u32 nsid, __u16 num_ctrls,
				__u16 *ctrlist)
{
	return nvme_ns_attachment(fd, nsid, num_ctrls, ctrlist, false);
}

int nvme_get_ana_log_len(int fd, size_t *analen)
{
	struct nvme_id_ctrl ctrl;
	int ret;

	ret = nvme_identify_ctrl(fd, &ctrl);
	if (ret)
		return ret;

	*analen = sizeof(struct nvme_ana_log) +
		le32_to_cpu(ctrl.nanagrpid) * sizeof(struct nvme_ana_group_desc) +
		le32_to_cpu(ctrl.mnan) * sizeof(__le32);
	return 0;
}

int nvme_get_feature_length(int fid, __u32 cdw11, __u32 *len)
{
	switch (fid) {
	case NVME_FEAT_FID_LBA_RANGE:
		*len = sizeof(struct nvme_lba_range_type);
		break;
	case NVME_FEAT_FID_AUTO_PST:
		*len = sizeof(struct nvme_feat_auto_pst);
		break;
	case NVME_FEAT_FID_PLM_CONFIG:
		*len = sizeof(struct nvme_plm_config);
		break;
	case NVME_FEAT_FID_TIMESTAMP:
		*len = sizeof(struct nvme_timestamp);
		break;
	case NVME_FEAT_FID_HOST_BEHAVIOR:
		*len = sizeof(struct nvme_feat_host_behavior);
		break;
	case NVME_FEAT_FID_HOST_ID:
		*len = (cdw11 & 0x1) ? 16 : 8;
		break;
	case NVME_FEAT_FID_ARBITRATION:
	case NVME_FEAT_FID_POWER_MGMT:
	case NVME_FEAT_FID_TEMP_THRESH:
	case NVME_FEAT_FID_ERR_RECOVERY:
	case NVME_FEAT_FID_VOLATILE_WC:
	case NVME_FEAT_FID_NUM_QUEUES:
	case NVME_FEAT_FID_IRQ_COALESCE:
	case NVME_FEAT_FID_IRQ_CONFIG:
	case NVME_FEAT_FID_WRITE_ATOMIC:
	case NVME_FEAT_FID_ASYNC_EVENT:
	case NVME_FEAT_FID_HOST_MEM_BUF:
	case NVME_FEAT_FID_KATO:
	case NVME_FEAT_FID_HCTM:
	case NVME_FEAT_FID_NOPSC:
	case NVME_FEAT_FID_RRL:
	case NVME_FEAT_FID_PLM_WINDOW:
	case NVME_FEAT_FID_LBA_STS_INTERVAL:
	case NVME_FEAT_FID_SANITIZE:
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:
	case NVME_FEAT_FID_SW_PROGRESS:
	case NVME_FEAT_FID_RESV_MASK:
	case NVME_FEAT_FID_RESV_PERSIST:
	case NVME_FEAT_FID_WRITE_PROTECT:
		*len = 0;
		break;
	default:
		errno = EINVAL;
		return -1;
	}
	return 0;
}

int nvme_get_directive_receive_length(enum nvme_directive_dtype dtype,
		enum nvme_directive_receive_doper doper, __u32 *len)
{
	switch (dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
			*len = sizeof(struct nvme_id_directives);
			return 0;
		default:
			errno = EINVAL;
			return -1;
		}
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
			*len = sizeof(struct nvme_streams_directive_params);
			return 0;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
			*len = (128 * 1024) * sizeof(__le16);
			return 0;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
			*len = 0;
			return 0;
		default:
			return -EINVAL;
		}
	default:
		return -EINVAL;
	}
}

static int __nvme_set_attr(const char *path, const char *value)
{
	int ret, fd;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		nvme_msg(LOG_ERR, "Failed to open %s: %s\n", path,
			 strerror(errno));
		return -1;
	}
	ret = write(fd, value, strlen(value));
	close(fd);
	return ret;
}

int nvme_set_attr(const char *dir, const char *attr, const char *value)
{
	char *path;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return -1;

	ret = __nvme_set_attr(path, value);
	free(path);
	return ret;
}

static char *__nvme_get_attr(const char *path)
{
	char value[4096] = { 0 };
	int ret, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		nvme_msg(LOG_ERR, "Failed to open %s: %s\n", path,
			 strerror(errno));
		return NULL;
	}

	ret = read(fd, value, sizeof(value) - 1);
	if (ret < 0) {
		close(fd);
		return NULL;
	}

	if (value[strlen(value) - 1] == '\n')
		value[strlen(value) - 1] = '\0';
	while (strlen(value) > 0 && value[strlen(value) - 1] == ' ')
		value[strlen(value) - 1] = '\0';

	close(fd);
	return strdup(value);
}

char *nvme_get_attr(const char *dir, const char *attr)
{
	char *path, *value;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return NULL;

	value = __nvme_get_attr(path);
	free(path);
	return value;
}

char *nvme_get_subsys_attr(nvme_subsystem_t s, const char *attr)
{
	return nvme_get_attr(nvme_subsystem_get_sysfs_dir(s), attr);
}

char *nvme_get_ctrl_attr(nvme_ctrl_t c, const char *attr)
{
	return nvme_get_attr(nvme_ctrl_get_sysfs_dir(c), attr);
}

char *nvme_get_ns_attr(nvme_ns_t n, const char *attr)
{
	return nvme_get_attr(nvme_ns_get_sysfs_dir(n), attr);
}

char *nvme_get_path_attr(nvme_path_t p, const char *attr)
{
	return nvme_get_attr(nvme_path_get_sysfs_dir(p), attr);
}
