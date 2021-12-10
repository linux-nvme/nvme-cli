// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/stat.h>

#include <ccan/build_assert/build_assert.h>
#include <ccan/endian/endian.h>

#include "ioctl.h"
#include "util.h"

static int nvme_verify_chr(int fd)
{
	static struct stat nvme_stat;
	int err = fstat(fd, &nvme_stat);

	if (err < 0)
		return errno;

	if (!S_ISCHR(nvme_stat.st_mode)) {
		errno = ENOTBLK;
		return -1;
	}
	return 0;
}

int nvme_subsystem_reset(int fd)
{
	int ret;

	ret = nvme_verify_chr(fd);
	if (ret)
		return ret;
	return ioctl(fd, NVME_IOCTL_SUBSYS_RESET);
}

int nvme_ctrl_reset(int fd)
{
	int ret;

	ret = nvme_verify_chr(fd);
	if (ret)
		return ret;
	return ioctl(fd, NVME_IOCTL_RESET);
}

int nvme_ns_rescan(int fd)
{
	int ret;

	ret = nvme_verify_chr(fd);
	if (ret)
		return ret;
	return ioctl(fd, NVME_IOCTL_RESCAN);
}

int nvme_get_nsid(int fd, __u32 *nsid)
{
	errno = 0;
	*nsid = ioctl(fd, NVME_IOCTL_ID);
	return -1 * (errno != 0);
}

static int nvme_submit_passthru64(int fd, unsigned long ioctl_cmd,
				  struct nvme_passthru_cmd64 *cmd,
				  __u64 *result)
{
	int err = ioctl(fd, ioctl_cmd, cmd);

	if (err >= 0 && result)
		*result = cmd->result;
	return err;
}

static int nvme_submit_passthru(int fd, unsigned long ioctl_cmd,
				struct nvme_passthru_cmd *cmd, __u32 *result)
{
	int err = ioctl(fd, ioctl_cmd, cmd);

	if (err >= 0 && result)
		*result = cmd->result;
	return err;
}

static int nvme_passthru64(int fd, unsigned long ioctl_cmd, __u8 opcode,
			   __u8 flags, __u16 rsvd, __u32 nsid, __u32 cdw2,
			   __u32 cdw3, __u32 cdw10, __u32 cdw11, __u32 cdw12,
			   __u32 cdw13, __u32 cdw14, __u32 cdw15,
			   __u32 data_len, void *data, __u32 metadata_len,
			   void *metadata, __u32 timeout_ms, __u64 *result)
{
	struct nvme_passthru_cmd64 cmd = {
		.opcode		= opcode,
		.flags		= flags,
		.rsvd1		= rsvd,
		.nsid		= nsid,
		.cdw2		= cdw2,
		.cdw3		= cdw3,
		.metadata	= (__u64)(uintptr_t)metadata,
		.addr		= (__u64)(uintptr_t)data,
		.metadata_len	= metadata_len,
		.data_len	= data_len,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw13		= cdw13,
		.cdw14		= cdw14,
		.cdw15		= cdw15,
		.timeout_ms	= timeout_ms,
	};

	return nvme_submit_passthru64(fd, ioctl_cmd, &cmd, result);
}

static int nvme_passthru(int fd, unsigned long ioctl_cmd, __u8 opcode,
			 __u8 flags, __u16 rsvd, __u32 nsid, __u32 cdw2,
			 __u32 cdw3, __u32 cdw10, __u32 cdw11, __u32 cdw12,
			 __u32 cdw13, __u32 cdw14, __u32 cdw15, __u32 data_len,
			 void *data, __u32 metadata_len, void *metadata,
			 __u32 timeout_ms, __u32 *result)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= opcode,
		.flags		= flags,
		.rsvd1		= rsvd,
		.nsid		= nsid,
		.cdw2		= cdw2,
		.cdw3		= cdw3,
		.metadata	= (__u64)(uintptr_t)metadata,
		.addr		= (__u64)(uintptr_t)data,
		.metadata_len	= metadata_len,
		.data_len	= data_len,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw13		= cdw13,
		.cdw14		= cdw14,
		.cdw15		= cdw15,
		.timeout_ms	= timeout_ms,
	};

	return nvme_submit_passthru(fd, ioctl_cmd, &cmd, result);
}

int nvme_submit_admin_passthru64(int fd, struct nvme_passthru_cmd64 *cmd,
				 __u64 *result)
{
	return nvme_submit_passthru64(fd, NVME_IOCTL_ADMIN64_CMD, cmd, result);
}

int nvme_admin_passthru64(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
			 __u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10,
			 __u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14,
			 __u32 cdw15, __u32 data_len, void *data,
			 __u32 metadata_len, void *metadata, __u32 timeout_ms,
			 __u64 *result)
{
	return nvme_passthru64(fd, NVME_IOCTL_ADMIN64_CMD, opcode, flags, rsvd,
			       nsid, cdw2, cdw3, cdw10, cdw11, cdw12, cdw13,
			       cdw14, cdw15, data_len, data, metadata_len,
			       metadata, timeout_ms, result);
}

int nvme_submit_admin_passthru(int fd, struct nvme_passthru_cmd *cmd, __u32 *result)
{
	return nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, cmd, result);
}

int nvme_admin_passthru(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
			__u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10,
			__u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14,
			__u32 cdw15, __u32 data_len, void *data,
			__u32 metadata_len, void *metadata, __u32 timeout_ms,
			__u32 *result)
{
	return nvme_passthru(fd, NVME_IOCTL_ADMIN_CMD, opcode, flags, rsvd,
			     nsid, cdw2, cdw3, cdw10, cdw11, cdw12, cdw13,
			     cdw14, cdw15, data_len, data, metadata_len,
			     metadata, timeout_ms, result);
}

enum nvme_cmd_dword_fields {
	NVME_DEVICE_SELF_TEST_CDW10_STC_SHIFT			= 0,
	NVME_DEVICE_SELF_TEST_CDW10_STC_MASK			= 0x7,
	NVME_DIRECTIVE_CDW11_DOPER_SHIFT			= 0,
	NVME_DIRECTIVE_CDW11_DTYPE_SHIFT			= 8,
	NVME_DIRECTIVE_CDW11_DPSEC_SHIFT			= 16,
	NVME_DIRECTIVE_CDW11_DOPER_MASK				= 0xff,
	NVME_DIRECTIVE_CDW11_DTYPE_MASK				= 0xff,
	NVME_DIRECTIVE_CDW11_DPSEC_MASK				= 0xffff,
	NVME_DIRECTIVE_SEND_IDENTIFY_CDW12_ENDIR_SHIFT		= 0,
	NVME_DIRECTIVE_SEND_IDENTIFY_CDW12_DTYPE_SHIFT		= 1,
	NVME_DIRECTIVE_SEND_IDENTIFY_CDW12_ENDIR_MASK		= 0x1,
	NVME_DIRECTIVE_SEND_IDENTIFY_CDW12_DTYPE_MASK		= 0x1,
	NVME_FW_COMMIT_CDW10_FS_SHIFT				= 0,
	NVME_FW_COMMIT_CDW10_CA_SHIFT				= 3,
	NVME_FW_COMMIT_CDW10_BPID_SHIFT				= 31,
	NVME_FW_COMMIT_CDW10_FS_MASK				= 0x7,
	NVME_FW_COMMIT_CDW10_CA_MASK				= 0x7,
	NVME_FW_COMMIT_CDW10_BPID_MASK				= 0x1,
	NVME_GET_FEATURES_CDW10_SEL_SHIFT			= 8,
	NVME_GET_FEATURES_CDW10_SEL_MASK			= 0x7,
	NVME_SET_FEATURES_CDW10_SAVE_SHIFT			= 31,
	NVME_SET_FEATURES_CDW10_SAVE_MASK			= 0x1,
	NVME_FEATURES_CDW10_FID_SHIFT				= 0,
	NVME_FEATURES_CDW14_UUID_SHIFT				= 0,
	NVME_FEATURES_CDW10_FID_MASK				= 0xff,
	NVME_FEATURES_CDW14_UUID_MASK				= 0x7f,
	NVME_LOG_CDW10_LID_SHIFT				= 0,
	NVME_LOG_CDW10_LSP_SHIFT				= 8,
	NVME_LOG_CDW10_RAE_SHIFT				= 15,
	NVME_LOG_CDW10_NUMDL_SHIFT				= 16,
	NVME_LOG_CDW11_NUMDU_SHIFT				= 0,
	NVME_LOG_CDW11_LSI_SHIFT				= 16,
	NVME_LOG_CDW14_UUID_SHIFT				= 0,
	NVME_LOG_CDW14_CSI_SHIFT				= 24,
	NVME_LOG_CDW14_OT_SHIFT					= 23,
	NVME_LOG_CDW10_LID_MASK					= 0xff,
	NVME_LOG_CDW10_LSP_MASK					= 0xf,
	NVME_LOG_CDW10_RAE_MASK					= 0x1,
	NVME_LOG_CDW10_NUMDL_MASK				= 0xffff,
	NVME_LOG_CDW11_NUMDU_MASK				= 0xffff,
	NVME_LOG_CDW11_LSI_MASK					= 0xff,
	NVME_LOG_CDW14_UUID_MASK				= 0x7f,
	NVME_LOG_CDW14_CSI_MASK					= 0xff,
	NVME_LOG_CDW14_OT_MASK					= 0x1,
	NVME_IDENTIFY_CDW10_CNS_SHIFT				= 0,
	NVME_IDENTIFY_CDW10_CNTID_SHIFT				= 16,
	NVME_IDENTIFY_CDW11_NVMSETID_SHIFT			= 0,
	NVME_IDENTIFY_CDW11_DOMID_SHIFT				= 0,
	NVME_IDENTIFY_CDW14_UUID_SHIFT				= 0,
	NVME_IDENTIFY_CDW11_CSI_SHIFT				= 24,
	NVME_IDENTIFY_CDW10_CNS_MASK				= 0xff,
	NVME_IDENTIFY_CDW10_CNTID_MASK				= 0xffff,
	NVME_IDENTIFY_CDW11_NVMSETID_MASK			= 0xffff,
	NVME_IDENTIFY_CDW11_DOMID_MASK				= 0xffff,
	NVME_IDENTIFY_CDW14_UUID_MASK				= 0x7f,
	NVME_IDENTIFY_CDW11_CSI_MASK				= 0xff,
	NVME_NAMESPACE_ATTACH_CDW10_SEL_SHIFT			= 0,
	NVME_NAMESPACE_ATTACH_CDW10_SEL_MASK			= 0xf,
	NVME_NAMESPACE_MGMT_CDW10_SEL_SHIFT			= 0,
	NVME_NAMESPACE_MGMT_CDW10_SEL_MASK			= 0xf,
	NVME_NAMESPACE_MGMT_CDW11_CSI_SHIFT			= 24,
	NVME_NAMESPACE_MGMT_CDW11_CSI_MASK			= 0xff,
	NVME_VIRT_MGMT_CDW10_ACT_SHIFT				= 0,
	NVME_VIRT_MGMT_CDW10_RT_SHIFT				= 8,
	NVME_VIRT_MGMT_CDW10_CNTLID_SHIFT			= 16,
	NVME_VIRT_MGMT_CDW11_NR_SHIFT				= 0,
	NVME_VIRT_MGMT_CDW10_ACT_MASK				= 0xf,
	NVME_VIRT_MGMT_CDW10_RT_MASK				= 0x7,
	NVME_VIRT_MGMT_CDW10_CNTLID_MASK			= 0xffff,
	NVME_VIRT_MGMT_CDW11_NR_MASK				= 0xffff,
	NVME_FORMAT_CDW10_LBAF_SHIFT				= 0,
	NVME_FORMAT_CDW10_MSET_SHIFT				= 4,
	NVME_FORMAT_CDW10_PI_SHIFT				= 5,
	NVME_FORMAT_CDW10_PIL_SHIFT				= 8,
	NVME_FORMAT_CDW10_SES_SHIFT				= 9,
	NVME_FORMAT_CDW10_LBAF_MASK				= 0xf,
	NVME_FORMAT_CDW10_MSET_MASK				= 0x1,
	NVME_FORMAT_CDW10_PI_MASK				= 0x7,
	NVME_FORMAT_CDW10_PIL_MASK				= 0x1,
	NVME_FORMAT_CDW10_SES_MASK				= 0x7,
	NVME_SANITIZE_CDW10_SANACT_SHIFT			= 0,
	NVME_SANITIZE_CDW10_AUSE_SHIFT				= 3,
	NVME_SANITIZE_CDW10_OWPASS_SHIFT			= 4,
	NVME_SANITIZE_CDW10_OIPBP_SHIFT				= 8,
	NVME_SANITIZE_CDW10_NODAS_SHIFT				= 9,
	NVME_SANITIZE_CDW10_SANACT_MASK				= 0x7,
	NVME_SANITIZE_CDW10_AUSE_MASK				= 0x1,
	NVME_SANITIZE_CDW10_OWPASS_MASK				= 0xf,
	NVME_SANITIZE_CDW10_OIPBP_MASK				= 0x1,
	NVME_SANITIZE_CDW10_NODAS_MASK				= 0x1,
	NVME_SECURITY_NSSF_SHIFT				= 0,
	NVME_SECURITY_SPSP0_SHIFT				= 8,
	NVME_SECURITY_SPSP1_SHIFT				= 16,
	NVME_SECURITY_SECP_SHIFT				= 24,
	NVME_SECURITY_NSSF_MASK					= 0xff,
	NVME_SECURITY_SPSP0_MASK				= 0xff,
	NVME_SECURITY_SPSP1_MASK				= 0xff,
	NVME_SECURITY_SECP_MASK					= 0xffff,
	NVME_GET_LBA_STATUS_CDW13_RL_SHIFT			= 0,
	NVME_GET_LBA_STATUS_CDW13_ATYPE_SHIFT			= 24,
	NVME_GET_LBA_STATUS_CDW13_RL_MASK			= 0xffff,
	NVME_GET_LBA_STATUS_CDW13_ATYPE_MASK			= 0xff,
	NVME_ZNS_MGMT_SEND_ZSASO_SHIFT				= 9,
	NVME_ZNS_MGMT_SEND_ZSASO_MASK				= 0x1,
	NVME_ZNS_MGMT_SEND_SEL_SHIFT				= 8,
	NVME_ZNS_MGMT_SEND_SEL_MASK				= 0x1,
	NVME_ZNS_MGMT_SEND_ZSA_SHIFT				= 0,
	NVME_ZNS_MGMT_SEND_ZSA_MASK				= 0xff,
	NVME_ZNS_MGMT_RECV_ZRA_SHIFT				= 0,
	NVME_ZNS_MGMT_RECV_ZRA_MASK				= 0xff,
	NVME_ZNS_MGMT_RECV_ZRASF_SHIFT				= 8,
	NVME_ZNS_MGMT_RECV_ZRASF_MASK				= 0xff,
	NVME_ZNS_MGMT_RECV_ZRAS_FEAT_SHIFT			= 16,
	NVME_ZNS_MGMT_RECV_ZRAS_FEAT_MASK			= 0x1,
};

enum features {
	NVME_FEATURES_ARBITRATION_BURST_SHIFT			= 0,
	NVME_FEATURES_ARBITRATION_LPW_SHIFT			= 8,
	NVME_FEATURES_ARBITRATION_MPW_SHIFT			= 16,
	NVME_FEATURES_ARBITRATION_HPW_SHIFT			= 24,
	NVME_FEATURES_ARBITRATION_BURST_MASK			= 0x7,
	NVME_FEATURES_ARBITRATION_LPW_MASK			= 0xff,
	NVME_FEATURES_ARBITRATION_MPW_MASK			= 0xff,
	NVME_FEATURES_ARBITRATION_HPW_MASK			= 0xff,
	NVME_FEATURES_PWRMGMT_PS_SHIFT				= 0,
	NVME_FEATURES_PWRMGMT_WH_SHIFT				= 5,
	NVME_FEATURES_PWRMGMT_PS_MASK				= 0x1f,
	NVME_FEATURES_PWRMGMT_WH_MASK				= 0x7,
	NVME_FEATURES_TMPTH_SHIFT				= 0,
	NVME_FEATURES_TMPSEL_SHIFT				= 16,
	NVME_FEATURES_THSEL_SHIFT				= 20,
	NVME_FEATURES_TMPTH_MASK				= 0xff,
	NVME_FEATURES_TMPSEL_MASK				= 0xf,
	NVME_FEATURES_THSEL_MASK				= 0x3,
	NVME_FEATURES_ERROR_RECOVERY_TLER_SHIFT			= 0,
	NVME_FEATURES_ERROR_RECOVERY_DULBE_SHIFT		= 16,
	NVME_FEATURES_ERROR_RECOVERY_TLER_MASK			= 0xff,
	NVME_FEATURES_ERROR_RECOVERY_DULBE_MASK			= 0x1,
	NVME_FEATURES_VWC_WCE_SHIFT				= 0,
	NVME_FEATURES_VWC_WCE_MASK				= 0x1,
	NVME_FEATURES_IRQC_THR_SHIFT				= 0,
	NVME_FEATURES_IRQC_TIME_SHIFT				= 8,
	NVME_FEATURES_IRQC_THR_MASK				= 0xff,
	NVME_FEATURES_IRQC_TIME_MASK				= 0xff,
	NVME_FEATURES_IVC_IV_SHIFT				= 0,
	NVME_FEATURES_IVC_CD_SHIFT				= 16,
	NVME_FEATURES_IVC_IV_MASK				= 0xffff,
	NVME_FEATURES_IVC_CD_MASK				= 0x1,
	NVME_FEATURES_WAN_DN_SHIFT				= 0,
	NVME_FEATURES_WAN_DN_MASK				= 0x1,
	NVME_FEATURES_APST_APSTE_SHIFT				= 0,
	NVME_FEATURES_APST_APSTE_MASK				= 0x1,
	NVME_FEATURES_HCTM_TMT2_SHIFT				= 0,
	NVME_FEATURES_HCTM_TMT1_SHIFT				= 16,
	NVME_FEATURES_HCTM_TMT2_MASK				= 0xffff,
	NVME_FEATURES_HCTM_TMT1_MASK				= 0xffff,
	NVME_FEATURES_NOPS_NOPPME_SHIFT				= 0,
	NVME_FEATURES_NOPS_NOPPME_MASK				= 0x1,
	NVME_FEATURES_PLM_PLE_SHIFT				= 0,
	NVME_FEATURES_PLM_PLE_MASK				= 0x1,
	NVME_FEATURES_PLM_WINDOW_SELECT_SHIFT			= 0,
	NVME_FEATURES_PLM_WINDOW_SELECT_MASK			= 0xf,
	NVME_FEATURES_LBAS_LSIRI_SHIFT				= 0,
	NVME_FEATURES_LBAS_LSIPI_SHIFT				= 16,
	NVME_FEATURES_LBAS_LSIRI_MASK				= 0xffff,
	NVME_FEATURES_LBAS_LSIPI_MASK				= 0xffff,
	NVME_FEATURES_IOCSP_IOCSCI_SHIFT			= 0,
	NVME_FEATURES_IOCSP_IOCSCI_MASK				= 0xff,
};

int nvme_identify(int fd, enum nvme_identify_cns cns, __u32 nsid, __u16 cntid,
		  __u16 nvmsetid, __u16 domid, __u8 uuidx, __u8 csi,
		  void *data, __u32 timeout, __u32 *result)
{
	__u32 cdw10 = NVME_SET(cntid, IDENTIFY_CDW10_CNTID) |
			NVME_SET(cns, IDENTIFY_CDW10_CNS);
	__u32 cdw11 = NVME_SET(nvmsetid, IDENTIFY_CDW11_NVMSETID) |
			NVME_SET(domid, IDENTIFY_CDW11_DOMID) |
			NVME_SET(csi, IDENTIFY_CDW11_CSI);
	__u32 cdw14 = NVME_SET(uuidx, IDENTIFY_CDW14_UUID);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_identify,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t)data,
		.data_len	= NVME_IDENTIFY_DATA_SIZE,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw14		= cdw14,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

static int __nvme_identify(int fd, __u8 cns, __u32 nsid, void *data)
{
	return nvme_identify(fd, cns, nsid, NVME_CNTLID_NONE,
			     NVME_NVMSETID_NONE, NVME_DOMID_NONE,
			     NVME_UUID_NONE, NVME_CSI_NVM,
			     data, NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_identify_ctrl(int fd, struct nvme_id_ctrl *id)
{
	BUILD_ASSERT(sizeof(struct nvme_id_ctrl) == 4096);
	return __nvme_identify(fd, NVME_IDENTIFY_CNS_CTRL, NVME_NSID_NONE, id);
}

int nvme_identify_ns(int fd, __u32 nsid, struct nvme_id_ns *ns)
{
	BUILD_ASSERT(sizeof(struct nvme_id_ns) == 4096);
	return __nvme_identify(fd, NVME_IDENTIFY_CNS_NS, nsid, ns);
}

int nvme_identify_allocated_ns(int fd, __u32 nsid, struct nvme_id_ns *ns)
{
	return __nvme_identify(fd, NVME_IDENTIFY_CNS_ALLOCATED_NS, nsid, ns);
}

int nvme_identify_active_ns_list(int fd, __u32 nsid, struct nvme_ns_list *list)
{
	BUILD_ASSERT(sizeof(struct nvme_ns_list) == 4096);
	return __nvme_identify(fd, NVME_IDENTIFY_CNS_NS_ACTIVE_LIST, nsid,
			       list);
}

int nvme_identify_allocated_ns_list(int fd, __u32 nsid,
	struct nvme_ns_list *list)
{
	return __nvme_identify(fd, NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST, nsid,
			       list);
}

int nvme_identify_ctrl_list(int fd, __u16 cntid,
			    struct nvme_ctrl_list *ctrlist)
{
	BUILD_ASSERT(sizeof(struct nvme_ctrl_list) == 4096);
	return nvme_identify(fd, NVME_IDENTIFY_CNS_CTRL_LIST,
			     NVME_NSID_NONE, cntid, NVME_NVMSETID_NONE,
			     NVME_DOMID_NONE, NVME_UUID_NONE, NVME_CSI_NVM,
			     ctrlist, NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_identify_nsid_ctrl_list(int fd, __u32 nsid, __u16 cntid,
				 struct nvme_ctrl_list *ctrlist)
{
	return nvme_identify(fd, NVME_IDENTIFY_CNS_NS_CTRL_LIST, nsid,
			     cntid, NVME_NVMSETID_NONE, NVME_DOMID_NONE,
			     NVME_UUID_NONE, NVME_CSI_NVM, ctrlist,
			     NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_identify_ns_descs(int fd, __u32 nsid, struct nvme_ns_id_desc *descs)
{
	return __nvme_identify(fd, NVME_IDENTIFY_CNS_NS_DESC_LIST, nsid, descs);
}

int nvme_identify_nvmset_list(int fd, __u16 nvmsetid,
	struct nvme_id_nvmset_list *nvmset)
{
	BUILD_ASSERT(sizeof(struct nvme_id_nvmset_list) == 4096);
	return nvme_identify(fd, NVME_IDENTIFY_CNS_NVMSET_LIST,
			     NVME_NSID_NONE, NVME_CNTLID_NONE, nvmsetid,
			     NVME_DOMID_NONE, NVME_UUID_NONE, NVME_CSI_NVM,
			     nvmset, NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_identify_primary_ctrl(int fd, __u16 cntid,
	struct nvme_primary_ctrl_cap *cap)
{
	BUILD_ASSERT(sizeof(struct nvme_primary_ctrl_cap) == 4096);
	return nvme_identify(fd, NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP,
			     NVME_NSID_NONE, cntid, NVME_NVMSETID_NONE,
			     NVME_DOMID_NONE, NVME_UUID_NONE, NVME_CSI_NVM,
			     cap, NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_identify_secondary_ctrl_list(int fd, __u32 nsid, __u16 cntid,
	struct nvme_secondary_ctrl_list *list)
{
	BUILD_ASSERT(sizeof(struct nvme_secondary_ctrl_list) == 4096);
	return nvme_identify(fd, NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST,
			     nsid, cntid, NVME_NVMSETID_NONE,
			     NVME_DOMID_NONE, NVME_UUID_NONE, NVME_CSI_NVM,
			     list, NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_identify_ns_granularity(int fd,
	struct nvme_id_ns_granularity_list *list)
{
	BUILD_ASSERT(sizeof(struct nvme_id_ns_granularity_list) == 4096);
	return __nvme_identify(fd, NVME_IDENTIFY_CNS_NS_GRANULARITY,
			       NVME_NSID_NONE, list);
}

int nvme_identify_uuid(int fd, struct nvme_id_uuid_list *list)
{
	BUILD_ASSERT(sizeof(struct nvme_id_uuid_list) == 4096);
	return __nvme_identify(fd, NVME_IDENTIFY_CNS_UUID_LIST, NVME_NSID_NONE,
			       list);
}

int nvme_identify_ctrl_csi(int fd, __u8 csi, void *data)
{
	return nvme_identify(fd, NVME_IDENTIFY_CNS_CSI_CTRL, NVME_NSID_NONE,
			     NVME_CNTLID_NONE, NVME_NVMSETID_NONE,
			     NVME_DOMID_NONE, NVME_UUID_NONE, csi, data,
			     NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_identify_ns_csi(int fd, __u32 nsid, __u8 csi, void *data)
{
	return nvme_identify(fd, NVME_IDENTIFY_CNS_CSI_NS, nsid,
			     NVME_CNTLID_NONE, NVME_NVMSETID_NONE,
			     NVME_DOMID_NONE, NVME_UUID_NONE, csi, data,
			     NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_identify_active_ns_list_csi(int fd, __u32 nsid, __u8 csi,
				     struct nvme_ns_list *list)
{
	BUILD_ASSERT(sizeof(struct nvme_ns_list) == 4096);
	return nvme_identify(fd, NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST, nsid,
			     NVME_CNTLID_NONE, NVME_NVMSETID_NONE,
			     NVME_DOMID_NONE, NVME_UUID_NONE, csi, list,
			     NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_identify_allocated_ns_list_css(int fd, __u32 nsid, __u8 csi,
					struct nvme_ns_list *list)
{
	return nvme_identify(fd, NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST, nsid,
			     NVME_CNTLID_NONE, NVME_NVMSETID_NONE,
			     NVME_DOMID_NONE, NVME_UUID_NONE, csi, list,
			     NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_identify_domain_list(int fd, __u16 domid,
			      struct nvme_id_domain_list *list)
{
	BUILD_ASSERT(sizeof(struct nvme_id_domain_list) == 4096);
	return nvme_identify(fd, NVME_IDENTIFY_CNS_DOMAIN_LIST, NVME_NSID_NONE,
			     NVME_CNTLID_NONE, NVME_NVMSETID_NONE,
			     domid, NVME_UUID_NONE, NVME_CSI_NVM, list,
			     NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_identify_endurance_group_list(int fd, __u16 endgrp_id,
				struct nvme_id_endurance_group_list *list)
{
	BUILD_ASSERT(sizeof(struct nvme_id_endurance_group_list) == 4096);
	return nvme_identify(fd, NVME_IDENTIFY_CNS_ENDURANCE_GROUP_ID,
			     NVME_NSID_NONE, NVME_CNTLID_NONE,
			     NVME_NVMSETID_NONE, endgrp_id, NVME_UUID_NONE,
			     NVME_CSI_NVM, list, NVME_DEFAULT_IOCTL_TIMEOUT,
			     NULL);
}

int nvme_identify_independent_identify_ns(int fd, __u32 nsid,
					  struct nvme_id_independent_id_ns *ns)
{
	BUILD_ASSERT(sizeof(struct nvme_id_independent_id_ns) == 4096);
	return nvme_identify(fd, NVME_IDENTIFY_CNS_CSI_INDEPENDENT_ID_NS,
			     nsid, NVME_CNTLID_NONE, NVME_NVMSETID_NONE,
			     NVME_DOMID_NONE, NVME_UUID_NONE, NVME_CSI_NVM,
			     ns, NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_identify_iocs(int fd, __u16 cntlid, struct nvme_id_iocs *iocs)
{
	BUILD_ASSERT(sizeof(struct nvme_id_iocs) == 4096);
	return nvme_identify(fd, NVME_IDENTIFY_CNS_COMMAND_SET_STRUCTURE,
			     NVME_NSID_NONE, cntlid, NVME_NVMSETID_NONE,
			     NVME_DOMID_NONE, NVME_UUID_NONE, NVME_CSI_NVM,
			     iocs, NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_zns_identify_ns(int fd, __u32 nsid, struct nvme_zns_id_ns *data)
{
	BUILD_ASSERT(sizeof(struct nvme_zns_id_ns) == 4096);
	return nvme_identify(fd, NVME_IDENTIFY_CNS_CSI_NS, nsid,
			     NVME_CNTLID_NONE, NVME_NVMSETID_NONE,
			     NVME_DOMID_NONE, NVME_UUID_NONE, NVME_CSI_ZNS,
			     data, NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_zns_identify_ctrl(int fd, struct nvme_zns_id_ctrl *id)
{
	BUILD_ASSERT(sizeof(struct nvme_zns_id_ctrl) == 4096);
	return nvme_identify_ctrl_csi(fd, NVME_CSI_ZNS, id);
}

int nvme_nvm_identify_ctrl(int fd, struct nvme_id_ctrl_nvm *id) 
{
	BUILD_ASSERT(sizeof(struct nvme_id_ctrl_nvm ) == 4096);
	return nvme_identify_ctrl_csi(fd, NVME_CSI_NVM, id);
}

int nvme_get_log(int fd, enum nvme_cmd_get_log_lid lid, __u32 nsid, __u64 lpo,
		 __u8 lsp, __u16 lsi, bool rae, __u8 uuidx, enum nvme_csi csi,
		 bool ot, __u32 len, void *log, __u32 timeout, __u32 *result)
{
	__u32 numd = (len >> 2) - 1;
	__u16 numdu = numd >> 16, numdl = numd & 0xffff;

	__u32 cdw10 = NVME_SET(lid, LOG_CDW10_LID) |
			NVME_SET(lsp, LOG_CDW10_LSP) |
			NVME_SET(!!rae, LOG_CDW10_RAE) |
			NVME_SET(numdl, LOG_CDW10_NUMDL);
	__u32 cdw11 = NVME_SET(numdu, LOG_CDW11_NUMDU) |
			NVME_SET(lsi, LOG_CDW11_LSI);
	__u32 cdw12 = lpo & 0xffffffff;
	__u32 cdw13 = lpo >> 32;
	__u32 cdw14 = NVME_SET(uuidx, LOG_CDW14_UUID) |
			NVME_SET(csi, LOG_CDW14_CSI) |
			NVME_SET(!!ot, LOG_CDW14_OT);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_get_log_page,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t)log,
		.data_len	= len,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw13		= cdw13,
		.cdw14		= cdw14,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

static int __nvme_get_log(int fd, enum nvme_cmd_get_log_lid lid, bool rae,
			  __u32 len, void *log)
{
	return nvme_get_log(fd, lid, NVME_NSID_ALL, 0, NVME_LOG_LSP_NONE,
			    NVME_LOG_LSI_NONE, rae, NVME_UUID_NONE,
			    NVME_CSI_NVM, false, len, log,
			    NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_get_log_supported_log_pages(int fd, bool rae,
				     struct nvme_supported_log_pages *log)
{
	BUILD_ASSERT(sizeof(struct nvme_supported_log_pages) == 1024);
	return __nvme_get_log(fd, NVME_LOG_LID_SUPPORTED_LOG_PAGES, rae,
			      sizeof(*log), log);
}

int nvme_get_log_error(int fd, unsigned nr_entries, bool rae,
		       struct nvme_error_log_page *log)
{
	BUILD_ASSERT(sizeof(struct nvme_error_log_page) == 64);
	return __nvme_get_log(fd, NVME_LOG_LID_ERROR, rae,
			      sizeof(*log) * nr_entries, log);
}

int nvme_get_log_smart(int fd, __u32 nsid, bool rae, struct nvme_smart_log *log)
{
	BUILD_ASSERT(sizeof(struct nvme_smart_log) == 512);
	return nvme_get_log(fd, NVME_LOG_LID_SMART,  nsid, 0,
			    NVME_LOG_LSP_NONE, NVME_LOG_LSI_NONE, rae,
			    NVME_UUID_NONE, NVME_CSI_NVM, false,
			    sizeof(*log), log, NVME_DEFAULT_IOCTL_TIMEOUT,
			    NULL);
}

int nvme_get_log_fw_slot(int fd, bool rae, struct nvme_firmware_slot *log)
{
	BUILD_ASSERT(sizeof(struct nvme_firmware_slot) == 512);
	return __nvme_get_log(fd, NVME_LOG_LID_FW_SLOT, rae, sizeof(*log),
			      log);
}

int nvme_get_log_changed_ns_list(int fd, bool rae, struct nvme_ns_list *log)
{
	return __nvme_get_log(fd, NVME_LOG_LID_CHANGED_NS, rae,
			      sizeof(*log), log);
}

int nvme_get_log_cmd_effects(int fd, enum nvme_csi csi,
			     struct nvme_cmd_effects_log *log)
{
	BUILD_ASSERT(sizeof(struct nvme_cmd_effects_log) == 4096);
	return nvme_get_log(fd, NVME_LOG_LID_CMD_EFFECTS, NVME_NSID_ALL, 0,
			    NVME_LOG_LSP_NONE, NVME_LOG_LSI_NONE,
			    NVME_UUID_NONE, csi, false, false, sizeof(*log),
			    log, NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_get_log_device_self_test(int fd, struct nvme_self_test_log *log)
{
	BUILD_ASSERT(sizeof(struct nvme_self_test_log) == 564);
	return __nvme_get_log(fd, NVME_LOG_LID_DEVICE_SELF_TEST, false,
			      sizeof(*log), log);
}

enum nvme_cmd_get_log_telemetry_host_lsp {
	NVME_LOG_TELEM_HOST_LSP_RETAIN			= 0,
	NVME_LOG_TELEM_HOST_LSP_CREATE			= 1,
};

int nvme_get_log_create_telemetry_host(int fd, struct nvme_telemetry_log *log)
{
	BUILD_ASSERT(sizeof(struct nvme_telemetry_log) == 512);
	return nvme_get_log(fd, NVME_LOG_LID_TELEMETRY_HOST, NVME_NSID_NONE, 0,
			    NVME_LOG_TELEM_HOST_LSP_CREATE, NVME_LOG_LSI_NONE,
			    false, NVME_UUID_NONE, NVME_CSI_NVM, false,
			    sizeof(*log), log, NVME_DEFAULT_IOCTL_TIMEOUT,
			    NULL);
}

int nvme_get_log_telemetry_host(int fd, __u64 offset, __u32 len, void *log)
{
	return nvme_get_log(fd, NVME_LOG_LID_TELEMETRY_HOST, NVME_NSID_NONE,
			    offset, NVME_LOG_TELEM_HOST_LSP_RETAIN,
			    NVME_LOG_LSI_NONE, false, NVME_UUID_NONE,
			    NVME_CSI_NVM, false, len, log,
			    NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_get_log_telemetry_ctrl(int fd, bool rae, __u64 offset, __u32 len,
				void *log)
{
	return nvme_get_log(fd, NVME_LOG_LID_TELEMETRY_CTRL, NVME_NSID_NONE,
			    offset, NVME_LOG_LSP_NONE, NVME_LOG_LSI_NONE, rae,
			    NVME_UUID_NONE, NVME_CSI_NVM, false, len, log,
			    NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_get_log_endurance_group(int fd, __u16 endgid,
				 struct nvme_endurance_group_log *log)
{
	BUILD_ASSERT(sizeof(struct nvme_endurance_group_log) == 512);
	return nvme_get_log(fd, NVME_LOG_LID_ENDURANCE_GROUP, NVME_NSID_NONE,
			    0, NVME_LOG_LSP_NONE, endgid, false, NVME_UUID_NONE,
			    NVME_CSI_NVM, false, sizeof(*log), log,
			    NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_get_log_predictable_lat_nvmset(int fd, __u16 nvmsetid,
				struct nvme_nvmset_predictable_lat_log *log)
{
	BUILD_ASSERT(sizeof(struct nvme_nvmset_predictable_lat_log) == 512);
	return nvme_get_log(fd, NVME_LOG_LID_PREDICTABLE_LAT_NVMSET,
			    NVME_NSID_NONE, 0, NVME_LOG_LSP_NONE, nvmsetid,
			    false, NVME_UUID_NONE, NVME_CSI_NVM, false,
			    sizeof(*log),log, NVME_DEFAULT_IOCTL_TIMEOUT,
			    NULL);
}

int nvme_get_log_predictable_lat_event(int fd, bool rae, __u32 offset,
				       __u32 len, void *log)
{
	return nvme_get_log(fd, NVME_LOG_LID_PREDICTABLE_LAT_AGG,
			    NVME_NSID_NONE, offset, NVME_LOG_LSP_NONE,
			    NVME_LOG_LSI_NONE, rae, NVME_UUID_NONE,
			    NVME_CSI_NVM, false, len, log,
			    NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_get_log_ana(int fd, enum nvme_log_ana_lsp lsp, bool rae, __u64 offset,
		     __u32 len, void *log)
{
	return nvme_get_log(fd, NVME_LOG_LID_ANA, NVME_NSID_NONE, offset,
			    lsp, NVME_LOG_LSI_NONE, false, NVME_UUID_NONE,
			    NVME_CSI_NVM, false, len, log,
			    NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_get_log_ana_groups(int fd, bool rae, __u32 len,
			    struct nvme_ana_group_desc *log)
{
	return nvme_get_log_ana(fd, NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY, rae, 0,
				len, log);
}

int nvme_get_log_lba_status(int fd, bool rae, __u64 offset, __u32 len,
			    void *log)
{
	return nvme_get_log(fd, NVME_LOG_LID_LBA_STATUS, NVME_NSID_NONE,
			    offset, NVME_LOG_LSP_NONE, NVME_LOG_LSI_NONE, rae,
			    NVME_UUID_NONE, NVME_CSI_NVM, false, len, log,
			    NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_get_log_endurance_grp_evt(int fd, bool rae, __u32 offset, __u32 len,
				   void *log)
{
	return nvme_get_log(fd, NVME_LOG_LID_ENDURANCE_GRP_EVT,
			    NVME_NSID_NONE, offset, NVME_LOG_LSP_NONE,
			    NVME_LOG_LSI_NONE, rae, NVME_UUID_NONE,
			    NVME_CSI_NVM, false, len, log,
			    NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_get_log_fid_supported_effects(int fd, bool rae,
				       struct nvme_fid_supported_effects_log *log)
{
	BUILD_ASSERT(sizeof(struct nvme_fid_supported_effects_log) == 1024);
	return nvme_get_log(fd, NVME_LOG_LID_FID_SUPPORTED_EFFECTS,
			    NVME_NSID_NONE, 0, NVME_LOG_LSP_NONE,
			    NVME_LOG_LSI_NONE, rae, NVME_UUID_NONE,
			    NVME_CSI_NVM, false, sizeof(*log), log,
			    NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_get_log_boot_partition(int fd, bool rae, __u8 lsp, __u32 len,
			        struct nvme_boot_partition *part)
{
	BUILD_ASSERT(sizeof(struct nvme_boot_partition) == 16);
	return nvme_get_log(fd, NVME_LOG_LID_BOOT_PARTITION,
			    NVME_NSID_NONE, 0, NVME_LOG_LSP_NONE,
			    NVME_LOG_LSI_NONE, rae, NVME_UUID_NONE,
			    NVME_CSI_NVM, false, len, part,
			    NVME_DEFAULT_IOCTL_TIMEOUT, NULL);

}

int nvme_get_log_discovery(int fd, bool rae, __u32 offset, __u32 len, void *log)
{
	return nvme_get_log(fd, NVME_LOG_LID_DISCOVER, NVME_NSID_NONE, offset,
			    NVME_LOG_LSP_NONE, NVME_LOG_LSI_NONE, rae,
			    NVME_UUID_NONE, NVME_CSI_NVM, false, len, log,
			    NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_get_log_reservation(int fd, bool rae,
			     struct nvme_resv_notification_log *log)
{
	BUILD_ASSERT(sizeof(struct nvme_resv_notification_log) == 64);
	return __nvme_get_log(fd, NVME_LOG_LID_RESERVATION, rae,
			      sizeof(*log), log);
}

int nvme_get_log_sanitize(int fd, bool rae,
			  struct nvme_sanitize_log_page *log)
{
	BUILD_ASSERT(sizeof(struct nvme_sanitize_log_page) == 512);
	return __nvme_get_log(fd, NVME_LOG_LID_SANITIZE, rae, sizeof(*log),
			      log);
}

int nvme_get_log_persistent_event(int fd, enum nvme_pevent_log_action action,
				  __u32 size, void *pevent_log)
{
	return __nvme_get_log(fd, NVME_LOG_LID_PERSISTENT_EVENT, false, size,
			      pevent_log);
}

int nvme_get_log_zns_changed_zones(int fd, __u32 nsid, bool rae,
				   struct nvme_zns_changed_zone_log *log)
{
	BUILD_ASSERT(sizeof(struct nvme_zns_changed_zone_log) == 4096);
	return nvme_get_log(fd, NVME_LOG_LID_ZNS_CHANGED_ZONES, nsid, 0,
			    NVME_LOG_LSP_NONE, NVME_LOG_LSI_NONE, rae,
			    NVME_UUID_NONE, NVME_CSI_ZNS, false,
			    sizeof(*log), log, NVME_DEFAULT_IOCTL_TIMEOUT,
			    NULL);
}

int nvme_set_features(int fd, __u8 fid, __u32 nsid, __u32 cdw11, __u32 cdw12,
		      bool save, __u8 uuidx, __u32 cdw15, __u32 data_len,
		      void *data, __u32 timeout, __u32 *result)
{
	__u32 cdw10 = NVME_SET(fid, FEATURES_CDW10_FID) |
			NVME_SET(!!save, SET_FEATURES_CDW10_SAVE);
	__u32 cdw14 = NVME_SET(uuidx, FEATURES_CDW14_UUID);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_set_features,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t)data,
		.data_len	= data_len,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw14		= cdw14,
		.cdw15		= cdw15,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

static int __nvme_set_features(int fd, __u8 fid, __u32 cdw11, bool save,
	__u32 *result)
{
	return nvme_set_features(fd, fid, NVME_NSID_NONE, cdw11, 0, save,
				 NVME_UUID_NONE, 0, 0, NULL,
				 NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_set_features_arbitration(int fd, __u8 ab, __u8 lpw, __u8 mpw,
	__u8 hpw, bool save, __u32 *result)
{
	__u32 value = NVME_SET(ab, FEAT_ARBITRATION_BURST) |
			NVME_SET(lpw, FEAT_ARBITRATION_LPW) |
			NVME_SET(mpw, FEAT_ARBITRATION_MPW) |
			NVME_SET(hpw, FEAT_ARBITRATION_HPW);

	return __nvme_set_features(fd, NVME_FEAT_FID_ARBITRATION, value, save,
				   result);
}

int nvme_set_features_power_mgmt(int fd, __u8 ps, __u8 wh, bool save,
	__u32 *result)
{
	__u32 value = NVME_SET(ps, FEAT_PWRMGMT_PS) |
			NVME_SET(wh, FEAT_PWRMGMT_PS);

	return __nvme_set_features(fd, NVME_FEAT_FID_POWER_MGMT, value, save,
				   result);
}

int nvme_set_features_lba_range(int fd, __u32 nsid, __u32 nr_ranges, bool save,
				struct nvme_lba_range_type *data, __u32 *result)
{
	return -1;
}

int nvme_set_features_temp_thresh(int fd, __u16 tmpth, __u8 tmpsel,
	enum nvme_feat_tmpthresh_thsel thsel, bool save, __u32 *result)
{
	__u32 value = NVME_SET(tmpth, FEAT_TT_TMPTH) |
			NVME_SET(tmpsel, FEAT_TT_TMPSEL) |
			NVME_SET(thsel, FEAT_TT_THSEL);

	return __nvme_set_features(fd, NVME_FEAT_FID_TEMP_THRESH, value, save,
				   result);
}

int nvme_set_features_err_recovery(int fd, __u32 nsid, __u16 tler, bool dulbe,
	bool save, __u32 *result)
{
	__u32 value = NVME_SET(tler, FEAT_ERROR_RECOVERY_TLER) |
			NVME_SET(!!dulbe, FEAT_ERROR_RECOVERY_DULBE);

	return __nvme_set_features(fd, NVME_FEAT_FID_ERR_RECOVERY, value, save,
				   result);
}

int nvme_set_features_volatile_wc(int fd, bool wce, bool save, __u32 *result)
{
	__u32 value = NVME_SET(!!wce, FEAT_VWC_WCE);

	return __nvme_set_features(fd, NVME_FEAT_FID_VOLATILE_WC, value, save,
				   result);
}

int nvme_set_features_irq_coalesce(int fd, __u8 thr, __u8 time, bool save,
	__u32 *result)
{
	__u32 value = NVME_SET(thr, FEAT_IRQC_TIME) |
			NVME_SET(time, FEAT_IRQC_THR);

	return __nvme_set_features(fd, NVME_FEAT_FID_IRQ_COALESCE, value, save,
				   result);
}

int nvme_set_features_irq_config(int fd, __u16 iv, bool cd, bool save,
	__u32 *result)
{
	__u32 value = NVME_SET(iv, FEAT_ICFG_IV) |
			NVME_SET(!!cd, FEAT_ICFG_CD);

	return __nvme_set_features(fd, NVME_FEAT_FID_IRQ_CONFIG, value, save,
				   result);
}

int nvme_set_features_write_atomic(int fd, bool dn, bool save, __u32 *result)
{
	__u32 value = NVME_SET(!!dn, FEAT_WA_DN);

	return __nvme_set_features(fd, NVME_FEAT_FID_WRITE_ATOMIC, value, save,
				   result);
}

int nvme_set_features_async_event(int fd, __u32 events,
	bool save, __u32 *result)
{
	return __nvme_set_features(fd, NVME_FEAT_FID_ASYNC_EVENT, events, save,
				   result);
}

int nvme_set_features_auto_pst(int fd, bool apste, bool save,
	struct nvme_feat_auto_pst *apst, __u32 *result)
{
	__u32 value = NVME_SET(!!apste, FEAT_APST_APSTE);

	return __nvme_set_features(fd, NVME_FEAT_FID_AUTO_PST, value, save,
				   result);
}

int nvme_set_features_timestamp(int fd, bool save, __u64 timestamp)
{
	__le64 t = cpu_to_le64(timestamp);
	struct nvme_timestamp ts;

	memcpy(&t, ts.timestamp, sizeof(ts.timestamp));
	return nvme_set_features(fd, NVME_FEAT_FID_TIMESTAMP,
				 NVME_NSID_NONE, 0, 0, save, NVME_UUID_NONE, 0,
				 sizeof(ts), &ts,
				 NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_set_features_hctm(int fd, __u16 tmt2, __u16 tmt1,
	bool save, __u32 *result)
{
	__u32 value = NVME_SET(tmt2, FEAT_HCTM_TMT2) |
			NVME_SET(tmt1, FEAT_HCTM_TMT1);

	return __nvme_set_features(fd, NVME_FEAT_FID_HCTM, value, save,
				   result);
}

int nvme_set_features_nopsc(int fd, bool noppme, bool save, __u32 *result)
{
	__u32 value = NVME_SET(noppme, FEAT_NOPS_NOPPME);

	return __nvme_set_features(fd, NVME_FEAT_FID_NOPSC, value, save,
				   result);
}

int nvme_set_features_rrl(int fd, __u8 rrl, __u16 nvmsetid,
	bool save, __u32 *result)
{
	return nvme_set_features(fd, NVME_FEAT_FID_RRL, NVME_NSID_NONE,
				 nvmsetid, rrl, save, NVME_UUID_NONE, 0, 0,
				 NULL, NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_set_features_plm_config(int fd, bool plm, __u16 nvmsetid, bool save,
	struct nvme_plm_config *data, __u32 *result)
{
	return nvme_set_features(fd, NVME_FEAT_FID_PLM_CONFIG,
				 NVME_NSID_NONE, nvmsetid, !!plm, save,
				 NVME_UUID_NONE, 0, 0, NULL,
				 NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_set_features_plm_window(int fd, enum nvme_feat_plm_window_select sel,
	__u16 nvmsetid, bool save, __u32 *result)
{
	__u32 cdw12 = NVME_SET(sel, FEAT_PLMW_WS);

	return nvme_set_features(fd, NVME_FEAT_FID_PLM_WINDOW, NVME_NSID_NONE,
				 nvmsetid, cdw12, save, NVME_UUID_NONE, 0, 0,
				 NULL, NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_set_features_lba_sts_interval(int fd, __u16 lsiri, __u16 lsipi,
	bool save, __u32 *result)
{
	__u32 value = NVME_SET(lsiri, FEAT_LBAS_LSIRI) |
			NVME_SET(lsipi, FEAT_LBAS_LSIPI);

	return __nvme_set_features(fd, NVME_FEAT_FID_LBA_STS_INTERVAL, value,
				   save, result);
}

int nvme_set_features_host_behavior(int fd, bool save,
	struct nvme_feat_host_behavior *data)
{
	return nvme_set_features(fd, NVME_FEAT_FID_HOST_BEHAVIOR,
				 NVME_NSID_NONE, save, 0, 0, NVME_UUID_NONE, 0,
				 sizeof(*data), data,
				 NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_set_features_sanitize(int fd, bool nodrm, bool save, __u32 *result)
{
	return __nvme_set_features(fd, NVME_FEAT_FID_SANITIZE, !!nodrm, save,
				   result);
}

int nvme_set_features_endurance_evt_cfg(int fd, __u16 endgid, __u8 egwarn,
					bool save, __u32 *result)
{
	__u32 value = endgid | egwarn << 16;

	return __nvme_set_features(fd, NVME_FEAT_FID_ENDURANCE_EVT_CFG, value,
				   save, result);
}

int nvme_set_features_sw_progress(int fd, __u8 pbslc, bool save,
				  __u32 *result)
{
	return __nvme_set_features(fd, NVME_FEAT_FID_SW_PROGRESS, pbslc, save,
				   result);
}

int nvme_set_features_host_id(int fd, bool save, bool exhid, __u8 *hostid)
{
	__u32 len = exhid ? 16 : 8;
	__u32 value = !!exhid;

	return nvme_set_features(fd, NVME_FEAT_FID_HOST_ID, NVME_NSID_NONE,
				 save, value, 0, NVME_UUID_NONE, 0, len,
				 hostid, NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_set_features_resv_mask(int fd, __u32 mask, bool save, __u32 *result)
{
	return __nvme_set_features(fd, NVME_FEAT_FID_RESV_MASK, mask, save,
				   result);
}

int nvme_set_features_resv_persist(int fd, bool ptpl, bool save, __u32 *result)
{
	return __nvme_set_features(fd, NVME_FEAT_FID_RESV_PERSIST, !!ptpl, save,
				   result);
}

int nvme_set_features_write_protect(int fd, enum nvme_feat_nswpcfg_state state,
				    bool save, __u32 *result)
{
	return __nvme_set_features(fd, NVME_FEAT_FID_WRITE_PROTECT, state,
				   save, result);
}

int nvme_set_features_iocs_profile(int fd, __u8 iocsi, bool save)
{
	__u32 value = NVME_SET(iocsi, FEAT_IOCSP_IOCSCI);

	return __nvme_set_features(fd, NVME_FEAT_FID_IOCS_PROFILE, value,
				   save, NULL);
}

int nvme_get_features(int fd, enum nvme_features_id fid, __u32 nsid,
		      enum nvme_get_features_sel sel, __u32 cdw11, __u8 uuidx,
		      __u32 data_len, void *data, __u32 timeout, __u32 *result)
{
	__u32 cdw10 = NVME_SET(fid, FEATURES_CDW10_FID) |
			NVME_SET(sel, GET_FEATURES_CDW10_SEL);
	__u32 cdw14 = NVME_SET(uuidx, FEATURES_CDW14_UUID);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_get_features,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t)data,
		.data_len	= data_len,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw14		= cdw14,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

static int __nvme_get_features(int fd, enum nvme_features_id fid,
			       enum nvme_get_features_sel sel, __u32 *result)
{
	return nvme_get_features(fd, fid, NVME_NSID_NONE, sel, 0,
				 NVME_UUID_NONE, 0, NULL,
				 NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_get_features_arbitration(int fd, enum nvme_get_features_sel sel,
				  __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_ARBITRATION, sel, result);
}

int nvme_get_features_power_mgmt(int fd, enum nvme_get_features_sel sel,
				__u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_POWER_MGMT, sel, result);
}

int nvme_get_features_lba_range(int fd, enum nvme_get_features_sel sel,
				struct nvme_lba_range_type *data,
				__u32 *result)
{
	return nvme_get_features(fd, NVME_FEAT_FID_LBA_RANGE, NVME_NSID_NONE,
				 sel, 0, NVME_UUID_NONE, 0, NULL,
				 NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_get_features_temp_thresh(int fd, enum nvme_get_features_sel sel,
				  __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_TEMP_THRESH, sel, result);
}

int nvme_get_features_err_recovery(int fd, enum nvme_get_features_sel sel,
				   __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_ERR_RECOVERY, sel,
				   result);
}

int nvme_get_features_volatile_wc(int fd, enum nvme_get_features_sel sel,
				  __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_VOLATILE_WC, sel, result);
}

int nvme_get_features_num_queues(int fd, enum nvme_get_features_sel sel,
				 __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_NUM_QUEUES, sel, result);
}

int nvme_get_features_irq_coalesce(int fd, enum nvme_get_features_sel sel,
				   __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_IRQ_COALESCE, sel,
				   result);
}

int nvme_get_features_irq_config(int fd, enum nvme_get_features_sel sel,
				__u16 iv, __u32 *result)
{
	return nvme_get_features(fd, NVME_FEAT_FID_IRQ_CONFIG, NVME_NSID_NONE,
				 sel, iv, NVME_UUID_NONE, 0, NULL,
				 NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_get_features_write_atomic(int fd, enum nvme_get_features_sel sel,
				   __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_WRITE_ATOMIC, sel,
				   result);
}

int nvme_get_features_async_event(int fd, enum nvme_get_features_sel sel,
				  __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_ASYNC_EVENT, sel, result);
}

int nvme_get_features_auto_pst(int fd, enum nvme_get_features_sel sel,
			       struct nvme_feat_auto_pst *apst, __u32 *result)
{
	return nvme_get_features(fd, NVME_FEAT_FID_AUTO_PST, NVME_NSID_NONE,
				 sel, 0, NVME_UUID_NONE, 0, NULL,
				 NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_get_features_host_mem_buf(int fd, enum nvme_get_features_sel sel,
				   __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_HOST_MEM_BUF, sel, result);
}

int nvme_get_features_timestamp(int fd,
	enum nvme_get_features_sel sel, struct nvme_timestamp *ts)
{
	return nvme_get_features(fd, NVME_FEAT_FID_TIMESTAMP, NVME_NSID_NONE,
				 sel, 0, NVME_UUID_NONE, 0, NULL,
				 NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_get_features_kato(int fd, enum nvme_get_features_sel sel, __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_KATO, sel, result);
}

int nvme_get_features_hctm(int fd, enum nvme_get_features_sel sel, __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_HCTM, sel, result);
}

int nvme_get_features_nopsc(int fd, enum nvme_get_features_sel sel, __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_NOPSC, sel, result);
}

int nvme_get_features_rrl(int fd, enum nvme_get_features_sel sel, __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_RRL, sel, result);
}

int nvme_get_features_plm_config(int fd, enum nvme_get_features_sel sel,
	__u16 nvmsetid, struct nvme_plm_config *data, __u32 *result)
{
	return nvme_get_features(fd, NVME_FEAT_FID_PLM_CONFIG, NVME_NSID_NONE,
				 sel, nvmsetid, NVME_UUID_NONE, 0, NULL,
				 NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_get_features_plm_window(int fd, enum nvme_get_features_sel sel,
	__u16 nvmsetid, __u32 *result)
{
	return nvme_get_features(fd, NVME_FEAT_FID_PLM_WINDOW, NVME_NSID_NONE,
				 sel, nvmsetid, NVME_UUID_NONE, 0, NULL,
				 NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_get_features_lba_sts_interval(int fd, enum nvme_get_features_sel sel,
				       __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_LBA_STS_INTERVAL, sel,
				   result);
}

int nvme_get_features_host_behavior(int fd, enum nvme_get_features_sel sel,
				    struct nvme_feat_host_behavior *data,
				    __u32 *result)
{
	return nvme_get_features(fd, NVME_FEAT_FID_HOST_BEHAVIOR,
				 NVME_NSID_NONE, sel, 0, NVME_UUID_NONE, 0,
				 NULL, NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_get_features_sanitize(int fd, enum nvme_get_features_sel sel,
			       __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_SANITIZE, sel, result);
}

int nvme_get_features_endurance_event_cfg(int fd, enum nvme_get_features_sel sel,
					  __u16 endgid, __u32 *result)
{
	return nvme_get_features(fd, NVME_FEAT_FID_ENDURANCE_EVT_CFG,
				 NVME_NSID_NONE, sel, 0, NVME_UUID_NONE, 0,
				 NULL, NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_get_features_sw_progress(int fd, enum nvme_get_features_sel sel,
				  __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_SW_PROGRESS, sel, result);
}

int nvme_get_features_host_id(int fd, enum nvme_get_features_sel sel,
			      bool exhid, __u32 len, __u8 *hostid)
{
	return nvme_get_features(fd, NVME_FEAT_FID_HOST_ID, NVME_NSID_NONE, sel,
				 !!exhid, NVME_UUID_NONE, len, hostid,
				 NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_get_features_resv_mask(int fd, enum nvme_get_features_sel sel,
				__u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_RESV_MASK, sel, result);
}

int nvme_get_features_resv_persist(int fd, enum nvme_get_features_sel sel,
				   __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_RESV_PERSIST, sel, result);
}

int nvme_get_features_write_protect(int fd, __u32 nsid,
				    enum nvme_get_features_sel sel,
				    __u32 *result)
{
	return nvme_get_features(fd, NVME_FEAT_FID_WRITE_PROTECT, nsid, sel, 0,
				 NVME_UUID_NONE, 0, NULL,
				 NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_get_features_iocs_profile(int fd, enum nvme_get_features_sel sel,
				   __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_IOCS_PROFILE, sel, result);
}

int nvme_format_nvm(int fd, __u32 nsid, __u8 lbaf,
		    enum nvme_cmd_format_mset mset, enum nvme_cmd_format_pi pi,
		    enum nvme_cmd_format_pil pil, enum nvme_cmd_format_ses ses,
		    __u32 timeout, __u32 *result)
{
	__u32 cdw10 = NVME_SET(lbaf, FORMAT_CDW10_LBAF) |
			NVME_SET(mset, FORMAT_CDW10_MSET) |
			NVME_SET(pi, FORMAT_CDW10_PI) |
			NVME_SET(pil, FORMAT_CDW10_PIL) |
			NVME_SET(ses, FORMAT_CDW10_SES);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_format_nvm,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

int nvme_ns_mgmt(int fd, __u32 nsid, enum nvme_ns_mgmt_sel sel,
		 struct nvme_id_ns *ns, __u32 *result, __u32 timeout, __u8 csi)
{
	__u32 cdw10    = NVME_SET(sel, NAMESPACE_MGMT_CDW10_SEL);
	__u32 cdw11    = NVME_SET(csi, NAMESPACE_MGMT_CDW11_CSI);
	__u32 data_len = ns ? sizeof(*ns) : 0;

	struct nvme_passthru_cmd cmd = {
		.nsid	    = nsid,
		.opcode	    = nvme_admin_ns_mgmt,
		.cdw10	    = cdw10,
		.cdw11	    = cdw11,
		.timeout_ms = timeout,
		.data_len   = data_len,
		.addr	    = (__u64)(uintptr_t)ns,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

int nvme_ns_mgmt_create(int fd, struct nvme_id_ns *ns, __u32 *nsid,
			__u32 timeout, __u8 csi)
{
	return nvme_ns_mgmt(fd, NVME_NSID_NONE, NVME_NS_MGMT_SEL_CREATE, ns,
			    nsid, timeout, csi);
}

int nvme_ns_mgmt_delete(int fd, __u32 nsid)
{
	return nvme_ns_mgmt(fd, nsid, NVME_NS_MGMT_SEL_DELETE, NULL, NULL, 0,
			    0);
}

int nvme_ns_attach(int fd, __u32 nsid, enum nvme_ns_attach_sel sel,
		   struct nvme_ctrl_list *ctrlist, __u32 timeout)
{
	__u32 cdw10 = NVME_SET(sel, NAMESPACE_ATTACH_CDW10_SEL);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_ns_attach,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.data_len	= sizeof(*ctrlist),
		.addr		= (__u64)(uintptr_t)ctrlist,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd, NULL);
}

int nvme_ns_attach_ctrls(int fd, __u32 nsid, struct nvme_ctrl_list *ctrlist)
{
	return nvme_ns_attach(fd, nsid, NVME_NS_ATTACH_SEL_CTRL_ATTACH,
			      ctrlist, NVME_DEFAULT_IOCTL_TIMEOUT);
}

int nvme_ns_detach_ctrls(int fd, __u32 nsid, struct nvme_ctrl_list *ctrlist)
{
	return nvme_ns_attach(fd, nsid, NVME_NS_ATTACH_SEL_CTRL_DEATTACH,
			      ctrlist, NVME_DEFAULT_IOCTL_TIMEOUT);
}

int nvme_fw_download(int fd, __u32 offset, __u32 data_len, void *data,
		     __u32 timeout, __u32 *result)
{
	__u32 cdw10 = (data_len >> 2) - 1;
	__u32 cdw11 = offset >> 2;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_fw_download,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.data_len	= data_len,
		.addr		= (__u64)(uintptr_t)data,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

int nvme_fw_commit(int fd, __u8 slot, enum nvme_fw_commit_ca action, bool bpid,
		   __u32 *result)
{
	__u32 cdw10 = NVME_SET(slot, FW_COMMIT_CDW10_FS) |
			NVME_SET(action, FW_COMMIT_CDW10_CA) |
			NVME_SET(bpid, FW_COMMIT_CDW10_BPID);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_fw_commit,
		.cdw10		= cdw10,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

int nvme_security_send(int fd, __u32 nsid, __u8 nssf, __u8 spsp0, __u8 spsp1,
		       __u8 secp, __u32 tl, __u32 data_len, void *data,
		       __u32 timeout, __u32 *result)
{
	__u32 cdw10 = NVME_SET(secp, SECURITY_SECP) |
			NVME_SET(spsp0, SECURITY_SPSP0)  |
			NVME_SET(spsp1, SECURITY_SPSP1) |
			NVME_SET(nssf, SECURITY_NSSF);
	__u32 cdw11 = tl;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_security_send,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.data_len	= data_len,
		.addr		= (__u64)(uintptr_t)data,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

int nvme_security_receive(int fd, __u32 nsid, __u8 nssf, __u8 spsp0,
			  __u8 spsp1, __u8 secp, __u32 al, __u32 data_len,
			  void *data, __u32 timeout, __u32 *result)
{
	__u32 cdw10 = NVME_SET(secp, SECURITY_SECP) |
			NVME_SET(spsp0, SECURITY_SPSP0)  |
			NVME_SET(spsp1, SECURITY_SPSP1) |
			NVME_SET(nssf, SECURITY_NSSF);
	__u32 cdw11 = al;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_security_recv,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.data_len	= data_len,
		.addr		= (__u64)(uintptr_t)data,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

int nvme_get_lba_status(int fd, __u32 nsid, __u64 slba, __u32 mndw, __u16 rl,
			enum nvme_lba_status_atype atype, __u32 timeout,
			struct nvme_lba_status *lbas, __u32 *result)
{
	__u32 cdw10 = slba & 0xffffffff;
	__u32 cdw11 = slba >> 32;
	__u32 cdw12 = mndw;
	__u32 cdw13 = NVME_SET(rl, GET_LBA_STATUS_CDW13_RL) |
			NVME_SET(atype, GET_LBA_STATUS_CDW13_ATYPE);

	struct nvme_passthru_cmd cmd = {
		.opcode =  nvme_admin_get_lba_status,
		.nsid = nsid,
		.addr = (__u64)(uintptr_t)lbas,
		.cdw10 = cdw10,
		.cdw11 = cdw11,
		.cdw12 = cdw12,
		.cdw13 = cdw13,
		.timeout_ms = timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

int nvme_directive_send(int fd, __u32 nsid, __u16 dspec,
			enum nvme_directive_send_doper doper,
			enum nvme_directive_dtype dtype, __u32 cdw12,
			__u32 data_len, void *data, __u32 timeout,
			__u32 *result)
{
	__u32 cdw10 = data_len ? (data_len >> 2) - 1 : 0;
	__u32 cdw11 = NVME_SET(doper, DIRECTIVE_CDW11_DOPER) |
			NVME_SET(dtype, DIRECTIVE_CDW11_DTYPE) |
			NVME_SET(dspec, DIRECTIVE_CDW11_DPSEC);

        struct nvme_passthru_cmd cmd = {
                .opcode         = nvme_admin_directive_send,
                .nsid           = nsid,
                .cdw10          = cdw10,
                .cdw11          = cdw11,
                .cdw12          = cdw12,
                .data_len       = data_len,
                .addr           = (__u64)(uintptr_t)data,
		.timeout_ms	= timeout,
        };

        return nvme_submit_admin_passthru(fd, &cmd, result);
}

int nvme_directive_send_id_endir(int fd, __u32 nsid, bool endir,
				 enum nvme_directive_dtype dtype,
				 struct nvme_id_directives *id)
{
	__u32 cdw12 = NVME_SET(dtype, DIRECTIVE_SEND_IDENTIFY_CDW12_DTYPE) |
		NVME_SET(endir, DIRECTIVE_SEND_IDENTIFY_CDW12_ENDIR);

	return nvme_directive_send(fd, nsid, 0, NVME_DIRECTIVE_DTYPE_IDENTIFY,
				   NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR,
				   cdw12, sizeof(*id), id,
				   NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_directive_send_stream_release_identifier(int fd, __u32 nsid,
						  __u16 stream_id)
{
	enum nvme_directive_dtype dtype =
			NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER;

	return nvme_directive_send(fd, nsid, stream_id,
				   NVME_DIRECTIVE_DTYPE_STREAMS,
				   dtype, 0, 0, NULL,
				   NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_directive_send_stream_release_resource(int fd, __u32 nsid)
{
	enum nvme_directive_dtype dtype =
		NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE;

	return nvme_directive_send(fd, nsid, 0, NVME_DIRECTIVE_DTYPE_STREAMS,
				   dtype, 0, 0, NULL,
				   NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_directive_recv(int fd, __u32 nsid, __u16 dspec,
			enum nvme_directive_receive_doper doper,
			enum nvme_directive_dtype dtype, __u32 cdw12,
			__u32 data_len, void *data, __u32 timeout,
			__u32 *result)
{
	__u32 cdw10 = data_len ? (data_len >> 2) - 1 : 0;
	__u32 cdw11 = NVME_SET(doper, DIRECTIVE_CDW11_DOPER) |
			NVME_SET(dtype, DIRECTIVE_CDW11_DTYPE) |
			NVME_SET(dspec, DIRECTIVE_CDW11_DPSEC);

        struct nvme_passthru_cmd cmd = {
                .opcode         = nvme_admin_directive_recv,
                .nsid           = nsid,
                .cdw10          = cdw10,
                .cdw11          = cdw11,
                .cdw12          = cdw12,
                .data_len       = data_len,
                .addr           = (__u64)(uintptr_t)data,
		.timeout_ms	= timeout,
        };

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

int nvme_directive_recv_identify_parameters(int fd, __u32 nsid,
					    struct nvme_id_directives *id)
{
	enum nvme_directive_dtype dtype =
		NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM;

	return nvme_directive_recv(fd, nsid, 0, NVME_DIRECTIVE_DTYPE_IDENTIFY,
				   dtype, 0, sizeof(*id), id,
				   NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_directive_recv_stream_parameters(int fd, __u32 nsid,
					  struct nvme_streams_directive_params *parms)
{
	enum nvme_directive_dtype dtype =
		NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM;

	return nvme_directive_recv(fd, nsid, 0, NVME_DIRECTIVE_DTYPE_STREAMS,
				   dtype, 0, sizeof(*parms), parms,
				   NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_directive_recv_stream_status(int fd, __u32 nsid, unsigned nr_entries,
				      struct nvme_streams_directive_status *id)
{
	enum nvme_directive_dtype dtype =
		NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS;

	return nvme_directive_recv(fd, nsid, 0, NVME_DIRECTIVE_DTYPE_STREAMS,
				   dtype, 0, sizeof(*id), id,
				   NVME_DEFAULT_IOCTL_TIMEOUT, NULL);
}

int nvme_directive_recv_stream_allocate(int fd, __u32 nsid, __u16 nsr,
					__u32 *result)
{
	enum nvme_directive_dtype dtype =
		NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE;

	return nvme_directive_recv(fd, nsid, 0, NVME_DIRECTIVE_DTYPE_STREAMS,
				   dtype, nsr, 0, NULL,
				   NVME_DEFAULT_IOCTL_TIMEOUT, result);
}

int nvme_capacity_mgmt(int fd, __u8 op, __u16 element_id,
		       __u32 dw11, __u32 dw12,
		       __u32 timeout, __u32 *result)
{
	__u32 dw10 = op | element_id << 16;

        struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_capacity_mgmt,
		.cdw10		= dw10,
		.cdw11		= dw11,
		.cdw12		= dw12,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

int nvme_lockdown(int fd, __u8 scp, __u8 prhbt, __u8 ifc, __u8 ofi,
		  __u8 uuid)
{
	__u32 cdw10 =  ofi << 8 | (ifc & 0x3) << 5 | (prhbt & 0x1) << 4 | (scp & 0xF);

	struct nvme_passthru_cmd cmd = {
		.opcode         = nvme_admin_lockdown,
		.cdw10          = cdw10,
		.cdw14          = uuid & 0x3F,
	};

	return nvme_submit_admin_passthru(fd, &cmd, NULL);
}

int nvme_set_property(int fd, int offset, __u64 value,
		      __u32 timeout, __u32 *result)
{
	__u32 cdw10 = nvme_is_64bit_reg(offset);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_fabrics,
		.nsid		= nvme_fabrics_type_property_set,
		.cdw10		= cdw10,
		.cdw11		= offset,
		.cdw12		= value & 0xffffffff,
		.cdw13		= value >> 32,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

int nvme_get_property(int fd, int offset, __u64 *value, __u32 timeout)
{
	__u32 cdw10 = nvme_is_64bit_reg(offset);

	struct nvme_passthru_cmd64 cmd = {
		.opcode		= nvme_admin_fabrics,
		.nsid		= nvme_fabrics_type_property_get,
		.cdw10		= cdw10,
		.cdw11		= offset,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru64(fd, &cmd, value);
}

int nvme_sanitize_nvm(int fd, enum nvme_sanitize_sanact sanact, bool ause,
		      __u8 owpass, bool oipbp, bool nodas, __u32 ovrpat,
		      __u32 timeout, __u32 *result)
{
	__u32 cdw10 = NVME_SET(sanact, SANITIZE_CDW10_SANACT) |
			NVME_SET(!!ause, SANITIZE_CDW10_AUSE) |
			NVME_SET(owpass, SANITIZE_CDW10_OWPASS) |
			NVME_SET(!!oipbp, SANITIZE_CDW10_OIPBP) |
			NVME_SET(!!nodas, SANITIZE_CDW10_NODAS);
	__u32 cdw11 = ovrpat;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_sanitize_nvm,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

int nvme_dev_self_test(int fd, __u32 nsid, enum nvme_dst_stc stc)
{
	__u32 cdw10 = NVME_SET(stc, DEVICE_SELF_TEST_CDW10_STC);

	struct nvme_passthru_cmd cmd = {
		.opcode = nvme_admin_dev_self_test,
		.nsid = nsid,
		.cdw10 = cdw10,
	};

	return nvme_submit_admin_passthru(fd, &cmd, NULL);
}

int nvme_virtual_mgmt(int fd, enum nvme_virt_mgmt_act act,
		      enum nvme_virt_mgmt_rt rt, __u16 cntlid, __u16 nr,
		      __u32 *result)
{
	__u32 cdw10 = NVME_SET(act, VIRT_MGMT_CDW10_ACT) |
			NVME_SET(rt, VIRT_MGMT_CDW10_RT) |
			NVME_SET(cntlid, VIRT_MGMT_CDW10_CNTLID);
	__u32 cdw11 = NVME_SET(nr, VIRT_MGMT_CDW11_NR);

	struct nvme_passthru_cmd cmd = {
		.opcode = nvme_admin_virtual_mgmt,
		.cdw10  = cdw10,
		.cdw11  = cdw11,
	};

	return nvme_submit_admin_passthru(fd, &cmd, result);
}

int nvme_submit_io_passthru64(int fd, struct nvme_passthru_cmd64 *cmd,
			      __u64 *result)
{
	return nvme_submit_passthru64(fd, NVME_IOCTL_IO64_CMD, cmd, result);
}

int nvme_io_passthru64(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
		__u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11,
		__u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15,
		__u32 data_len, void *data, __u32 metadata_len, void *metadata,
		__u32 timeout_ms, __u64 *result)
{
	return nvme_passthru64(fd, NVME_IOCTL_IO64_CMD, opcode, flags, rsvd,
		nsid, cdw2, cdw3, cdw10, cdw11, cdw12, cdw13, cdw14, cdw15,
		data_len, data, metadata_len, metadata, timeout_ms, result);
}

int nvme_submit_io_passthru(int fd, struct nvme_passthru_cmd *cmd, __u32 *result)
{
	return nvme_submit_passthru(fd, NVME_IOCTL_IO_CMD, cmd, result);
}

int nvme_io_passthru(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
		__u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11,
		__u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15,
		__u32 data_len, void *data, __u32 metadata_len, void *metadata,
		__u32 timeout_ms, __u32 *result)
{
	return nvme_passthru(fd, NVME_IOCTL_IO_CMD, opcode, flags, rsvd, nsid,
		cdw2, cdw3, cdw10, cdw11, cdw12, cdw13, cdw14, cdw15, data_len,
		data, metadata_len, metadata, timeout_ms, result);
}

int nvme_flush(int fd, __u32 nsid)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_flush,
		.nsid		= nsid,
	};

	return nvme_submit_io_passthru(fd, &cmd, NULL);
}

static int nvme_io(int fd, __u8 opcode, __u32 nsid, __u64 slba, __u16 nlb,
	__u16 control, __u32 flags, __u32 reftag, __u16 apptag, __u16 appmask,
	__u64 storage_tag, __u32 data_len, void *data, __u32 metadata_len,
	void *metadata, __u32 timeout)
{
	__u32 cdw2  = storage_tag & 0xffffffff;
	__u32 cdw3  = (storage_tag >> 32) & 0xffff;
	__u32 cdw10 = slba & 0xffffffff;
	__u32 cdw11 = slba >> 32;
	__u32 cdw12 = nlb | (control << 16);
	__u32 cdw13 = flags;
	__u32 cdw14 = reftag;
	__u32 cdw15 = apptag | (appmask << 16);

	struct nvme_passthru_cmd cmd = {
		.opcode		= opcode,
		.nsid		= nsid,
		.cdw2		= cdw2,
		.cdw3		= cdw3,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw13		= cdw13,
		.cdw14		= cdw14,
		.cdw15		= cdw15,
		.data_len	= data_len,
		.metadata_len	= metadata_len,
		.addr		= (__u64)(uintptr_t)data,
		.metadata	= (__u64)(uintptr_t)metadata,
		.timeout_ms	= timeout,
	};

	return nvme_submit_io_passthru(fd, &cmd, NULL);
}

int nvme_read(int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control,
	      __u8 dsm, __u32 reftag, __u16 apptag, __u16 appmask,
	      __u64 storage_tag, __u32 data_len, void *data,
	      __u32 metadata_len, void *metadata, __u32 timeout)
{
	return nvme_io(fd, nvme_cmd_read, nsid, slba, nlb, control, dsm,
		       reftag, apptag, appmask, storage_tag, data_len, data,
		       metadata_len, metadata, timeout);
}

int nvme_write(int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control,
	       __u8 dsm, __u16 dspec, __u32 reftag, __u16 apptag,
	       __u16 appmask, __u64 storage_tag, __u32 data_len, void *data,
	       __u32 metadata_len, void *metadata, __u32 timeout)
{
	__u32 flags = dsm | dspec << 16;

	return nvme_io(fd, nvme_cmd_write, nsid, slba, nlb, control, flags,
		       reftag, apptag, appmask, storage_tag, data_len, data,
		       metadata_len, metadata, timeout);
}

int nvme_compare(int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control,
		 __u32 reftag, __u16 apptag, __u16 appmask, __u32 data_len,
		 void *data, __u32 metadata_len, void *metadata, __u32 timeout)
{
	return nvme_io(fd, nvme_cmd_compare, nsid, slba, nlb, control, 0,
		       reftag, apptag, appmask, 0, data_len, data, metadata_len,
		       metadata, timeout);
}

int nvme_write_zeros(int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control,
		     __u32 reftag, __u16 apptag, __u16 appmask,
		     __u64 storage_tag, __u32 timeout)
{
	return nvme_io(fd, nvme_cmd_write_zeroes, nsid, slba, nlb, control, 0,
		       reftag, apptag, appmask, storage_tag, 0, NULL, 0, NULL,
		       timeout);
}

int nvme_verify(int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control,
		__u32 reftag, __u16 apptag, __u16 appmask, __u64 storage_tag,
		__u32 timeout)
{
	return nvme_io(fd, nvme_cmd_verify, nsid, slba, nlb, control, 0,
		       reftag, apptag, appmask, 0, 0, NULL, 0, NULL, timeout);
}

int nvme_write_uncorrectable(int fd, __u32 nsid, __u64 slba, __u16 nlb,
			     __u32 timeout)
{
	return nvme_io(fd, nvme_cmd_write_uncor, nsid, slba, nlb, 0, 0, 0, 0,
		       0, 0, 0, NULL, 0, NULL, timeout);
}

int nvme_dsm(int fd, __u32 nsid, __u32 attrs, __u16 nr_ranges,
	     struct nvme_dsm_range *dsm, __u32 timeout, __u32 *result)
{
	__u32 cdw11 = attrs;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_dsm,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t)dsm,
		.data_len	= nr_ranges * sizeof(*dsm),
		.cdw10		= nr_ranges - 1,
		.cdw11		= cdw11,
		.timeout_ms	= timeout,
	};

	return nvme_submit_io_passthru(fd, &cmd, result);
}

int nvme_copy(int fd, __u32 nsid, struct nvme_copy_range *copy, __u64 sdlba,
	      __u16 nr, __u8 prinfor, __u8 prinfow, __u8 dtype, __u16 dspec,
	      __u8 format, int lr, int fua, __u32 ilbrt, __u16 lbatm,
	      __u16 lbat, __u32 timeout, __u32 *result)
{
	__u32 cdw12 = ((nr - 1) & 0xff) | ((format & 0xf) <<  8) |
		((prinfor & 0xf) << 12) | ((dtype & 0xf) << 20) |
		((prinfow & 0xf) << 26) | ((fua & 0x1) << 30) |
		((lr & 0x1) << 31);

	struct nvme_passthru_cmd cmd = {
		.opcode         = nvme_cmd_copy,
		.nsid           = nsid,
		.addr           = (__u64)(uintptr_t)copy,
		.data_len       = nr * sizeof(*copy),
		.cdw10          = sdlba & 0xffffffff,
		.cdw11          = sdlba >> 32,
		.cdw12          = cdw12,
		.cdw13		= (dspec & 0xffff) << 16,
		.cdw14		= ilbrt,
		.cdw15		= (lbatm << 16) | lbat,
		.timeout_ms	= timeout,
	};

	return nvme_submit_io_passthru(fd, &cmd, result);
}

int nvme_resv_acquire(int fd, __u32 nsid, enum nvme_resv_rtype rtype,
		      enum nvme_resv_racqa racqa, bool iekey,
		      __u64 crkey, __u64 nrkey, __u32 timeout, __u32 *result)
{
	__le64 payload[2] = { cpu_to_le64(crkey), cpu_to_le64(nrkey) };
	__u32 cdw10 = (racqa & 0x7) | (iekey ? 1 << 3 : 0) | rtype << 8;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_resv_acquire,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.data_len	= sizeof(payload),
		.addr		= (__u64)(uintptr_t)(payload),
		.timeout_ms	= timeout,
	};

	return nvme_submit_io_passthru(fd, &cmd, result);
}

int nvme_resv_register(int fd, __u32 nsid, enum nvme_resv_rrega rrega,
		       enum nvme_resv_cptpl cptpl, bool iekey,
		       __u64 crkey, __u64 nrkey, __u32 timeout, __u32 *result)
{
	__le64 payload[2] = { cpu_to_le64(crkey), cpu_to_le64(nrkey) };
	__u32 cdw10 = (rrega & 0x7) | (iekey ? 1 << 3 : 0) | cptpl << 30;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_resv_register,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.data_len	= sizeof(payload),
		.addr		= (__u64)(uintptr_t)(payload),
		.timeout_ms	= timeout,
	};

	return nvme_submit_io_passthru(fd, &cmd, result);
}

int nvme_resv_release(int fd, __u32 nsid, enum nvme_resv_rtype rtype,
		      enum nvme_resv_rrela rrela, bool iekey,
		      __u64 crkey, __u32 timeout, __u32 *result)
{
	__le64 payload[1] = { cpu_to_le64(crkey) };
	__u32 cdw10 = (rrela & 0x7) | (iekey ? 1 << 3 : 0) | rtype << 8;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_resv_release,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.addr		= (__u64)(uintptr_t)(payload),
		.data_len	= sizeof(payload),
		.timeout_ms	= timeout,
	};

	return nvme_submit_io_passthru(fd, &cmd, result);
}

int nvme_resv_report(int fd, __u32 nsid, bool eds, __u32 len,
		     struct nvme_resv_status *report, __u32 timeout,
		     __u32 *result)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_resv_report,
		.nsid		= nsid,
		.cdw10		= (len >> 2) - 1,
		.cdw11		= eds ? 1 : 0,
		.addr		= (__u64)(uintptr_t)report,
		.data_len	= len,
		.timeout_ms	= timeout,
	};

	return nvme_submit_io_passthru(fd, &cmd, result);
}

int nvme_zns_mgmt_send(int fd, __u32 nsid, __u64 slba,
		       enum nvme_zns_send_action zsa, bool select_all,
		       __u8 zsaso, __u32 data_len,
		       void *data, __u32 timeout, __u32 *result)
{
	__u32 cdw10 = slba & 0xffffffff;
	__u32 cdw11 = slba >> 32;
	__u32 cdw13 = NVME_SET(zsaso, ZNS_MGMT_SEND_ZSASO) |
			NVME_SET(!!select_all, ZNS_MGMT_SEND_SEL) |
			NVME_SET(zsa, ZNS_MGMT_SEND_ZSA);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_zns_cmd_mgmt_send,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw13		= cdw13,
		.addr		= (__u64)(uintptr_t)data,
		.data_len	= data_len,
		.timeout_ms	= timeout,
	};

	return nvme_submit_io_passthru(fd, &cmd, result);
}

int nvme_zns_mgmt_recv(int fd, __u32 nsid, __u64 slba,
		       enum nvme_zns_recv_action zra, __u16 zrasf,
		       bool zras_feat, __u32 data_len, void *data,
		       __u32 timeout, __u32 *result)
{
	__u32 cdw10 = slba & 0xffffffff;
	__u32 cdw11 = slba >> 32;
	__u32 cdw12 = (data_len >> 2) - 1;
	__u32 cdw13 = NVME_SET(zra, ZNS_MGMT_RECV_ZRA) |
			NVME_SET(zrasf, ZNS_MGMT_RECV_ZRASF) |
			NVME_SET(zras_feat, ZNS_MGMT_RECV_ZRAS_FEAT);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_zns_cmd_mgmt_recv,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw13		= cdw13,
		.addr		= (__u64)(uintptr_t)data,
		.data_len	= data_len,
		.timeout_ms	= timeout,
	};

	return nvme_submit_io_passthru(fd, &cmd, result);
}

int nvme_zns_report_zones(int fd, __u32 nsid, __u64 slba,
			  enum nvme_zns_report_options opts,
			  bool extended, bool partial,
			  __u32 data_len, void *data,
			  __u32 timeout, __u32 *result)
{
	BUILD_ASSERT(sizeof(struct nvme_zns_desc) == 64);
	enum nvme_zns_recv_action zra;

	if (extended)
		zra = NVME_ZNS_ZRA_EXTENDED_REPORT_ZONES;
	else
		zra = NVME_ZNS_ZRA_REPORT_ZONES;

	return nvme_zns_mgmt_recv(fd, nsid, slba, zra, opts, partial,
				  data_len, data, timeout, result);
}

int nvme_zns_append(int fd, __u32 nsid, __u64 zslba, __u16 nlb, __u16 control,
		    __u32 ilbrt, __u16 lbat, __u16 lbatm, __u32 data_len,
		    void *data, __u32 metadata_len, void *metadata,
		    __u32 timeout, __u64 *result)
{
	__u32 cdw10 = zslba & 0xffffffff;
	__u32 cdw11 = zslba >> 32;
	__u32 cdw12 = nlb | (control << 16);
	__u32 cdw14 = ilbrt;
	__u32 cdw15 = lbat | (lbatm << 16);

	struct nvme_passthru_cmd64 cmd = {
		.opcode		= nvme_zns_cmd_append,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw14		= cdw14,
		.cdw15		= cdw15,
		.metadata	= (__u64)(uintptr_t)metadata,
		.addr		= (__u64)(uintptr_t)data,
		.metadata_len	= metadata_len,
		.data_len	= data_len,
		.timeout_ms	= timeout,
	};

	return nvme_submit_io_passthru64(fd, &cmd, result);
}
