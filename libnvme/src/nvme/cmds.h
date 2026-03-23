/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *	    Daniel Wagner <dwagner@suse.de>
 */

#pragma once

#include <endian.h>
#include <errno.h>
#include <string.h>

#include <nvme/ioctl.h>
#include <nvme/types.h>

enum nvme_cmd_dword_fields {
	NVME_DEVICE_SELF_TEST_CDW10_STC_SHIFT			= 0,
	NVME_DEVICE_SELF_TEST_CDW10_STC_MASK			= 0xf,
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
	NVME_GET_FEATURES_CDW10_FID_SHIFT			= 0,
	NVME_GET_FEATURES_CDW10_FID_MASK			= 0xff,
	NVME_GET_FEATURES_CDW14_UUID_SHIFT			= 0,
	NVME_GET_FEATURES_CDW14_UUID_MASK			= 0x7f,
	NVME_SET_FEATURES_CDW10_SV_SHIFT			= 31,
	NVME_SET_FEATURES_CDW10_SV_MASK				= 0x1,
	NVME_SET_FEATURES_CDW10_FID_SHIFT			= 0,
	NVME_SET_FEATURES_CDW10_FID_MASK			= 0xff,
	NVME_SET_FEATURES_CDW11_NUM_SHIFT			= 0,
	NVME_SET_FEATURES_CDW11_NUM_MASK			= 0x3f,
	NVME_SET_FEATURES_CDW14_UUID_SHIFT			= 0,
	NVME_SET_FEATURES_CDW14_UUID_MASK			= 0x7f,
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
	NVME_LOG_CDW10_LSP_MASK					= 0x7f,
	NVME_LOG_CDW10_RAE_MASK					= 0x1,
	NVME_LOG_CDW10_NUMDL_MASK				= 0xffff,
	NVME_LOG_CDW11_NUMDU_MASK				= 0xffff,
	NVME_LOG_CDW11_LSI_MASK					= 0xffff,
	NVME_LOG_CDW14_UUID_MASK				= 0x7f,
	NVME_LOG_CDW14_CSI_MASK					= 0xff,
	NVME_LOG_CDW14_OT_MASK					= 0x1,
	NVME_IDENTIFY_CDW10_CNS_SHIFT				= 0,
	NVME_IDENTIFY_CDW10_CNTID_SHIFT				= 16,
	NVME_IDENTIFY_CDW11_CNSSPECID_SHIFT			= 0,
	NVME_IDENTIFY_CDW11_FIDX_SHIFT				= 0,
	NVME_IDENTIFY_CDW11_DOMID_SHIFT				= 0,
	NVME_IDENTIFY_CDW11_ENGGID_SHIFT			= 0,
	NVME_IDENTIFY_CDW14_UUID_SHIFT				= 0,
	NVME_IDENTIFY_CDW11_CSI_SHIFT				= 24,
	NVME_IDENTIFY_CDW10_CNS_MASK				= 0xff,
	NVME_IDENTIFY_CDW10_CNTID_MASK				= 0xffff,
	NVME_IDENTIFY_CDW11_CNSSPECID_MASK			= 0xffff,
	NVME_IDENTIFY_CDW11_FIDX_MASK				= 0xffff,
	NVME_IDENTIFY_CDW11_DOMID_MASK				= 0xffff,
	NVME_IDENTIFY_CDW11_ENGGID_MASK				= 0xffff,
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
	NVME_FORMAT_CDW10_LBAFL_SHIFT				= 0,
	NVME_FORMAT_CDW10_MSET_SHIFT				= 4,
	NVME_FORMAT_CDW10_PI_SHIFT				= 5,
	NVME_FORMAT_CDW10_PIL_SHIFT				= 8,
	NVME_FORMAT_CDW10_SES_SHIFT				= 9,
	NVME_FORMAT_CDW10_LBAFU_SHIFT				= 12,
	NVME_FORMAT_CDW10_LBAFL_MASK				= 0xf,
	NVME_FORMAT_CDW10_MSET_MASK				= 0x1,
	NVME_FORMAT_CDW10_PI_MASK				= 0x7,
	NVME_FORMAT_CDW10_PIL_MASK				= 0x1,
	NVME_FORMAT_CDW10_SES_MASK				= 0x7,
	NVME_FORMAT_CDW10_LBAFU_MASK				= 0x3,
	NVME_SANITIZE_CDW10_SANACT_SHIFT			= 0,
	NVME_SANITIZE_CDW10_AUSE_SHIFT				= 3,
	NVME_SANITIZE_CDW10_OWPASS_SHIFT			= 4,
	NVME_SANITIZE_CDW10_OIPBP_SHIFT				= 8,
	NVME_SANITIZE_CDW10_NDAS_SHIFT				= 9,
	NVME_SANITIZE_CDW10_EMVS_SHIFT				= 10,
	NVME_SANITIZE_CDW10_SANACT_MASK				= 0x7,
	NVME_SANITIZE_CDW10_AUSE_MASK				= 0x1,
	NVME_SANITIZE_CDW10_OWPASS_MASK				= 0xf,
	NVME_SANITIZE_CDW10_OIPBP_MASK				= 0x1,
	NVME_SANITIZE_CDW10_NDAS_MASK				= 0x1,
	NVME_SANITIZE_CDW10_EMVS_MASK				= 0x1,
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
	NVME_ZNS_MGMT_SEND_ZM_SHIFT				= 16,
	NVME_ZNS_MGMT_SEND_ZM_MASK				= 0xff,
	NVME_ZNS_MGMT_SEND_ZSASO_SHIFT				= 9,
	NVME_ZNS_MGMT_SEND_ZSASO_MASK				= 0x1,
	NVME_ZNS_MGMT_SEND_SEL_SHIFT				= 8,
	NVME_ZNS_MGMT_SEND_SEL_MASK				= 0x1,
	NVME_ZNS_MGMT_SEND_ZSA_SHIFT				= 0,
	NVME_ZNS_MGMT_SEND_ZSA_MASK				= 0xff,
	NVME_ZNS_MGMT_RECV_ZRASPF_SHIFT				= 16,
	NVME_ZNS_MGMT_RECV_ZRASPF_MASK				= 0x1,
	NVME_ZNS_MGMT_RECV_ZRAS_SHIFT				= 8,
	NVME_ZNS_MGMT_RECV_ZRAS_MASK				= 0xff,
	NVME_ZNS_MGMT_RECV_ZRA_SHIFT				= 0,
	NVME_ZNS_MGMT_RECV_ZRA_MASK				= 0xff,
	NVME_DIM_TAS_SHIFT					= 0,
	NVME_DIM_TAS_MASK					= 0xf,
	NVME_DSM_CDW10_NR_SHIFT					= 0,
	NVME_DSM_CDW10_NR_MASK					= 0xff,
	NVME_DSM_CDW11_IDR_SHIFT				= 0,
	NVME_DSM_CDW11_IDR_MASK					= 0x1,
	NVME_DSM_CDW11_IDW_SHIFT				= 1,
	NVME_DSM_CDW11_IDW_MASK					= 0x1,
	NVME_DSM_CDW11_AD_SHIFT					= 2,
	NVME_DSM_CDW11_AD_MASK					= 0x1,
	NVME_CAPACITY_MGMT_CDW10_OPER_SHIFT			= 0,
	NVME_CAPACITY_MGMT_CDW10_OPER_MASK			= 0xf,
	NVME_CAPACITY_MGMT_CDW10_ELID_SHIFT			= 16,
	NVME_CAPACITY_MGMT_CDW10_ELID_MASK			= 0xffff,
	NVME_CAPACITY_MGMT_CDW11_CAPL_SHIFT			= 0,
	NVME_CAPACITY_MGMT_CDW11_CAPL_MASK			= 0xffffffff,
	NVME_CAPACITY_MGMT_CDW12_CAPU_SHIFT			= 0,
	NVME_CAPACITY_MGMT_CDW12_CAPU_MASK			= 0xffffffff,
	NVME_LOCKDOWN_CDW10_SCP_SHIFT				= 0,
	NVME_LOCKDOWN_CDW10_SCP_MASK				= 0xf,
	NVME_LOCKDOWN_CDW10_PRHBT_SHIFT				= 4,
	NVME_LOCKDOWN_CDW10_PRHBT_MASK				= 0x1,
	NVME_LOCKDOWN_CDW10_IFC_SHIFT				= 5,
	NVME_LOCKDOWN_CDW10_IFC_MASK				= 0x3,
	NVME_LOCKDOWN_CDW10_OFI_SHIFT				= 8,
	NVME_LOCKDOWN_CDW10_OFI_MASK				= 0xff,
	NVME_LOCKDOWN_CDW14_UIDX_SHIFT				= 0,
	NVME_LOCKDOWN_CDW14_UIDX_MASK				= 0x3f,
	NVME_RESV_ACQUIRE_CDW10_RACQA_SHIFT			= 0,
	NVME_RESV_ACQUIRE_CDW10_RACQA_MASK			= 0x7,
	NVME_RESV_ACQUIRE_CDW10_IEKEY_SHIFT			= 3,
	NVME_RESV_ACQUIRE_CDW10_IEKEY_MASK			= 0x1,
	NVME_RESV_ACQUIRE_CDW10_DISNSRS_SHIFT			= 4,
	NVME_RESV_ACQUIRE_CDW10_DISNSRS_MASK			= 0x1,
	NVME_RESV_ACQUIRE_CDW10_RTYPE_SHIFT			= 8,
	NVME_RESV_ACQUIRE_CDW10_RTYPE_MASK			= 0xff,
	NVME_RESV_REGISTER_CDW10_RREGA_SHIFT			= 0,
	NVME_RESV_REGISTER_CDW10_RREGA_MASK			= 0x7,
	NVME_RESV_REGISTER_CDW10_IEKEY_SHIFT			= 3,
	NVME_RESV_REGISTER_CDW10_IEKEY_MASK			= 0x1,
	NVME_RESV_REGISTER_CDW10_DISNSRS_SHIFT			= 4,
	NVME_RESV_REGISTER_CDW10_DISNSRS_MASK			= 0x1,
	NVME_RESV_REGISTER_CDW10_CPTPL_SHIFT			= 30,
	NVME_RESV_REGISTER_CDW10_CPTPL_MASK			= 0x3,
	NVME_RESV_RELEASE_CDW10_RRELA_SHIFT			= 0,
	NVME_RESV_RELEASE_CDW10_RRELA_MASK			= 0x7,
	NVME_RESV_RELEASE_CDW10_IEKEY_SHIFT			= 3,
	NVME_RESV_RELEASE_CDW10_IEKEY_MASK			= 0x1,
	NVME_RESV_RELEASE_CDW10_DISNSRS_SHIFT			= 4,
	NVME_RESV_RELEASE_CDW10_DISNSRS_MASK			= 0x1,
	NVME_RESV_RELEASE_CDW10_RTYPE_SHIFT			= 8,
	NVME_RESV_RELEASE_CDW10_RTYPE_MASK			= 0xff,
	NVME_RESV_REPORT_CDW11_EDS_SHIFT			= 0,
	NVME_RESV_REPORT_CDW11_EDS_MASK				= 0x1,
	NVME_RESV_REPORT_CDW11_DISNSRS_SHIFT			= 1,
	NVME_RESV_REPORT_CDW11_DISNSRS_MASK			= 0x1,
	NVME_IO_MGMT_RECV_CDW10_MO_SHIFT			= 0,
	NVME_IO_MGMT_RECV_CDW10_MO_MASK				= 0xff,
	NVME_IO_MGMT_RECV_CDW10_MOS_SHIFT			= 16,
	NVME_IO_MGMT_RECV_CDW10_MOS_MASK			= 0xffff,
	NVME_IO_MGMT_SEND_CDW10_MO_SHIFT			= 0,
	NVME_IO_MGMT_SEND_CDW10_MO_MASK				= 0xff,
	NVME_IO_MGMT_SEND_CDW10_MOS_SHIFT			= 16,
	NVME_IO_MGMT_SEND_CDW10_MOS_MASK			= 0xffff,
	NVME_IOCS_COMMON_CDW2_ELBTU_SHIFT			= 0,
	NVME_IOCS_COMMON_CDW2_ELBTU_MASK			= 0xffff,
	NVME_IOCS_COMMON_CDW3_ELBTU_SHIFT			= 0,
	NVME_IOCS_COMMON_CDW3_ELBTU_MASK			= 0xffffffff,
	NVME_IOCS_COMMON_CDW10_SLBAL_SHIFT			= 0,
	NVME_IOCS_COMMON_CDW10_SLBAL_MASK			= 0xffffffff,
	NVME_IOCS_COMMON_CDW11_SLBAU_SHIFT			= 0,
	NVME_IOCS_COMMON_CDW11_SLBAU_MASK			= 0xffffffff,
	NVME_IOCS_COMMON_CDW12_NLB_SHIFT			= 0,
	NVME_IOCS_COMMON_CDW12_NLB_MASK				= 0xffff,
	NVME_IOCS_COMMON_CDW12_CETYPE_SHIFT			= 16,
	NVME_IOCS_COMMON_CDW12_CETYPE_MASK			= 0xf,
	NVME_IOCS_COMMON_CDW12_DTYPE_SHIFT			= 20,
	NVME_IOCS_COMMON_CDW12_DTYPE_MASK			= 0xf,
	NVME_IOCS_COMMON_CDW12_STC_SHIFT			= 24,
	NVME_IOCS_COMMON_CDW12_STC_MASK				= 0x1,
	NVME_IOCS_COMMON_CDW12_DEAC_SHIFT			= 25,
	NVME_IOCS_COMMON_CDW12_DEAC_MASK			= 0x1,
	NVME_IOCS_COMMON_CDW12_PIREMAP_SHIFT			= 25,
	NVME_IOCS_COMMON_CDW12_PIREMAP_MASK			= 0x1,
	NVME_IOCS_COMMON_CDW12_PRINFO_SHIFT			= 26,
	NVME_IOCS_COMMON_CDW12_PRINFO_MASK			= 0xf,
	NVME_IOCS_COMMON_CDW12_FUA_SHIFT			= 30,
	NVME_IOCS_COMMON_CDW12_FUA_MASK				= 0x1,
	NVME_IOCS_COMMON_CDW12_LR_SHIFT				= 31,
	NVME_IOCS_COMMON_CDW12_LR_MASK				= 0x1,
	NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT			=
		NVME_IOCS_COMMON_CDW12_CETYPE_SHIFT,
	NVME_IOCS_COMMON_CDW12_CONTROL_MASK			=
		(NVME_VAL(IOCS_COMMON_CDW12_CETYPE) |
		 NVME_VAL(IOCS_COMMON_CDW12_DTYPE) |
		 NVME_VAL(IOCS_COMMON_CDW12_STC) |
		 NVME_VAL(IOCS_COMMON_CDW12_DEAC) |
		 NVME_VAL(IOCS_COMMON_CDW12_PRINFO) |
		 NVME_VAL(IOCS_COMMON_CDW12_FUA) |
		 NVME_VAL(IOCS_COMMON_CDW12_LR)) >>
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
	NVME_IOCS_COMMON_CDW13_DSM_AF_SHIFT			= 0,
	NVME_IOCS_COMMON_CDW13_DSM_AF_MASK			= 0xf,
	NVME_IOCS_COMMON_CDW13_DSM_AL_SHIFT			= 4,
	NVME_IOCS_COMMON_CDW13_DSM_AL_MASK			= 0x3,
	NVME_IOCS_COMMON_CDW13_DSM_SEQREQ_SHIFT			= 6,
	NVME_IOCS_COMMON_CDW13_DSM_SEQREQ_MASK			= 0x1,
	NVME_IOCS_COMMON_CDW13_DSM_INCPRS_SHIFT			= 7,
	NVME_IOCS_COMMON_CDW13_DSM_INCPRS_MASK			= 0x1,
	NVME_IOCS_COMMON_CDW13_DSM_SHIFT			=
		NVME_IOCS_COMMON_CDW13_DSM_AF_SHIFT,
	NVME_IOCS_COMMON_CDW13_DSM_MASK				=
		 (NVME_VAL(IOCS_COMMON_CDW13_DSM_AF) |
		  NVME_VAL(IOCS_COMMON_CDW13_DSM_AL) |
		  NVME_VAL(IOCS_COMMON_CDW13_DSM_SEQREQ) |
		  NVME_VAL(IOCS_COMMON_CDW13_DSM_INCPRS)) >>
			NVME_IOCS_COMMON_CDW13_DSM_SHIFT,
	NVME_IOCS_COMMON_CDW13_CEV_SHIFT			= 0,
	NVME_IOCS_COMMON_CDW13_CEV_MASK				= 0xffff,
	NVME_IOCS_COMMON_CDW13_DSPEC_SHIFT			= 16,
	NVME_IOCS_COMMON_CDW13_DSPEC_MASK			= 0xffff,
	NVME_IOCS_COMMON_CDW14_ELBTL_SHIFT			= 0,
	NVME_IOCS_COMMON_CDW14_ELBTL_MASK			= 0xffffffff,
	NVME_IOCS_COMMON_CDW15_ELBAT_SHIFT			= 0,
	NVME_IOCS_COMMON_CDW15_ELBAT_MASK			= 0xffff,
	NVME_IOCS_COMMON_CDW15_ELBATM_SHIFT			= 16,
	NVME_IOCS_COMMON_CDW15_ELBATM_MASK			= 0xffff,
	NVME_COPY_CDW3_LBTU_SHIFT				= 0,
	NVME_COPY_CDW3_LBTU_MASK				= 0xffffffff,
	NVME_COPY_CDW10_SDLBAL_SHIFT				= 0,
	NVME_COPY_CDW10_SDLBAL_MASK				= 0xffffffff,
	NVME_COPY_CDW11_SDLBAU_SHIFT				= 0,
	NVME_COPY_CDW11_SDLBAU_MASK				= 0xffffffff,
	NVME_COPY_CDW12_NR_SHIFT				= 0,
	NVME_COPY_CDW12_NR_MASK					= 0xff,
	NVME_COPY_CDW12_DESFMT_SHIFT				= 8,
	NVME_COPY_CDW12_DESFMT_MASK				= 0xf,
	NVME_COPY_CDW12_PRINFOR_SHIFT				= 12,
	NVME_COPY_CDW12_PRINFOR_MASK				= 0xf,
	NVME_COPY_CDW12_CETYPE_SHIFT				= 16,
	NVME_COPY_CDW12_CETYPE_MASK				= 0xf,
	NVME_COPY_CDW12_DTYPE_SHIFT				= 20,
	NVME_COPY_CDW12_DTYPE_MASK				= 0xf,
	NVME_COPY_CDW12_STCW_SHIFT				= 24,
	NVME_COPY_CDW12_STCW_MASK				= 0x1,
	NVME_COPY_CDW12_STCR_SHIFT				= 25,
	NVME_COPY_CDW12_STCR_MASK				= 0x1,
	NVME_COPY_CDW12_PRINFOW_SHIFT				= 26,
	NVME_COPY_CDW12_PRINFOW_MASK				= 0xf,
	NVME_COPY_CDW12_FUA_SHIFT				= 30,
	NVME_COPY_CDW12_FUA_MASK				= 0x1,
	NVME_COPY_CDW12_LR_SHIFT				= 31,
	NVME_COPY_CDW12_LR_MASK					= 0x1,
	NVME_COPY_CDW14_LBTL_SHIFT				= 0,
	NVME_COPY_CDW14_LBTL_MASK				= 0xffffffff,
	NVME_COPY_CDW15_LBAT_SHIFT				= 0,
	NVME_COPY_CDW15_LBAT_MASK				= 0xffff,
	NVME_COPY_CDW15_LBATM_SHIFT				= 16,
	NVME_COPY_CDW15_LBATM_MASK				= 0xffff,
	NVME_MI_ADMIN_CFLAGS_ISH_SHIFT				= 2,
	NVME_MI_ADMIN_CFLAGS_ISH_MASK				= 0x1,
};

#define NVME_FIELD_ENCODE(value, shift, mask) \
	(((__u32)(value) & (mask)) << (shift))

#define NVME_FIELD_DECODE(value, shift, mask) \
	(((value) >> (shift)) & (mask))

/**
 * nvme_init_identify() - Initialize passthru command for
 * NVMe Identify
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace identifier
 * @csi:	Command Set Identifier
 * @cns:	The Controller or Namespace structure,
 *              see @enum nvme_identify_cns
 * @data:	User space destination address to transfer the data
 * @len:	Length of provided user buffer to hold the data in bytes
 *
 * Prepare the @cmd data structure for the NVMe Identify command.
 */
static inline void
nvme_init_identify(struct nvme_passthru_cmd *cmd,
		__u32 nsid, enum nvme_csi csi, enum nvme_identify_cns cns,
		void *data, __u32 len)
{
	__u32 cdw10 = NVME_FIELD_ENCODE(cns,
					NVME_IDENTIFY_CDW10_CNS_SHIFT,
					NVME_IDENTIFY_CDW10_CNS_MASK);
	__u32 cdw11 = NVME_FIELD_ENCODE(csi,
					NVME_IDENTIFY_CDW11_CSI_SHIFT,
					NVME_IDENTIFY_CDW11_CSI_MASK);

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode	= nvme_admin_identify;
	cmd->nsid	= nsid;
	cmd->cdw10	= cdw10;
	cmd->cdw11	= cdw11;
	cmd->data_len	= len;
	cmd->addr	= (__u64)(uintptr_t)data;
}

/**
 * nvme_init_identify_ns() - Initialize passthru command for
 * NVMe Identify Namespace data structure
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace identifier
 * @id:		User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_NS.
 */
static inline void
nvme_init_identify_ns(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_id_ns *id)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_NS,
			   id, sizeof(*id));
}

/**
 * nvme_init_identify_ctrl() - Initialize passthru command for
 * NVMe Identify Controller data structure
 * @cmd:	Command data structure to initialize
 * @id:		User space destination address to transfer the data,
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CTRL.
 */
static inline void
nvme_init_identify_ctrl(struct nvme_passthru_cmd *cmd, struct nvme_id_ctrl *id)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_CTRL,
			   id, sizeof(*id));
}

/**
 * nvme_init_identify_active_ns_list() - Initialize passthru command for
 * Active Namespaces ID list
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace identifier
 * @list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_NS_ACTIVE_LIST.
 */
static inline void
nvme_init_identify_active_ns_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_ns_list *list)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_NS_ACTIVE_LIST,
			   list, sizeof(*list));
}

/**
 * nvme_init_identify_ns_descs_list() - Initialize passthru command for
 * Namespace Descriptor list
 * @cmd:	Command data structure to initialize
 * @nsid:	The namespace id to retrieve descriptors
 * @descs:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_NS_DESC_LIST.
 */
static inline void
nvme_init_identify_ns_descs_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_ns_id_desc *descs)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_NS_DESC_LIST,
			   descs, NVME_IDENTIFY_DATA_SIZE);
}

/**
 * nvme_init_identify_nvmset_list() - Initialize passthru command for
 * NVM Set List data structure
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace identifier
 * @nvmsetid:	NVM Set Identifier
 * @nvmset:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_NS_ACTIVE_LIST.
 */
static inline void
nvme_init_identify_nvmset_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, __u16 nvmsetid, struct nvme_id_nvmset_list *nvmset)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_NVMSET_LIST,
			   nvmset, sizeof(*nvmset));
	cmd->cdw11 |= NVME_FIELD_ENCODE(nvmsetid,
					NVME_IDENTIFY_CDW11_CNSSPECID_SHIFT,
					NVME_IDENTIFY_CDW11_CNSSPECID_MASK);
}

/**
 * nvme_init_identify_csi_ns() - Initialize passthru command for
 * I/O Command Set specific Identify Namespace data structure
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace identifier
 * @csi:	Command Set Identifier
 * @uidx:	UUID Index for differentiating vendor specific encoding
 * @data:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_NS.
 */
static inline void
nvme_init_identify_csi_ns(struct nvme_passthru_cmd *cmd,
		__u32 nsid, enum nvme_csi csi, __u8 uidx, void *data)
{
	nvme_init_identify(cmd, nsid, csi,
			   NVME_IDENTIFY_CNS_CSI_NS,
			   data, NVME_IDENTIFY_DATA_SIZE);
	cmd->cdw14 |= NVME_FIELD_ENCODE(uidx,
					NVME_IDENTIFY_CDW14_UUID_SHIFT,
					NVME_IDENTIFY_CDW14_UUID_MASK);
}

/**
 * nvme_init_identify_csi_ctrl() - Initialize passthru command for
 * I/O Command Set specific Identify Controller data structure
 * @cmd:	Command data structure to initialize
 * @csi:	Command Set Identifier
 * @data:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_CTRL.
 */
static inline void
nvme_init_identify_csi_ctrl(struct nvme_passthru_cmd *cmd,
		enum nvme_csi csi, void *data)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, csi,
			   NVME_IDENTIFY_CNS_CSI_CTRL,
			   data, NVME_IDENTIFY_DATA_SIZE);
}

/**
 * nvme_init_identify_csi_active_ns_list() - Initialize passthru command
 * for Active namespace ID list
 * @cmd:	Command data structure to initialize
 * @nsid:	Return namespaces greater than this identifier
 * @csi:	Command Set Identifier
 * @ns_list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST.
 */
static inline void
nvme_init_identify_csi_active_ns_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, enum nvme_csi csi, struct nvme_ns_list *ns_list)
{
	nvme_init_identify(cmd, nsid, csi,
			   NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST,
			   ns_list, sizeof(*ns_list));
}

/**
 * nvme_init_identify_csi_independent_identify_id_ns() -Initialize passthru
 * command for I/O Command Set Independent Identify Namespace data structure
 * @cmd:	Command data structure to initialize
 * @nsid:	Return namespaces greater than this identifier
 * @ns:		I/O Command Set Independent Identify Namespace data
 *		structure
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_INDEPENDENT_ID_NS.
 */
static inline void
nvme_init_identify_csi_independent_identify_id_ns(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_id_independent_id_ns *ns)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_CSI_INDEPENDENT_ID_NS,
			   ns, sizeof(*ns));
}

/**
 * nvme_init_identify_ns_user_data_format() - Initialize passthru command
 * for Identify namespace user data format
 * @cmd:	Command data structure to initialize
 * @csi:	Command Set Identifier
 * @fidx:	Format Index
 * @uidx:	UUID selection, if supported
 * @data:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_NS_USER_DATA_FORMAT.
 */
static inline void
nvme_init_identify_ns_user_data_format(struct nvme_passthru_cmd *cmd,
		enum nvme_csi csi, __u16 fidx, __u8 uidx, void *data)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, csi,
			   NVME_IDENTIFY_CNS_NS_USER_DATA_FORMAT,
			   data, NVME_IDENTIFY_DATA_SIZE);
	cmd->cdw11 |= NVME_FIELD_ENCODE(fidx,
					NVME_IDENTIFY_CDW11_FIDX_SHIFT,
					NVME_IDENTIFY_CDW11_FIDX_MASK);
	cmd->cdw14 |= NVME_FIELD_ENCODE(uidx,
					NVME_IDENTIFY_CDW14_UUID_SHIFT,
					NVME_IDENTIFY_CDW14_UUID_MASK);
}

/**
 * nvme_init_identify_csi_ns_user_data_format() - Initialize passthru
 * command for Identify namespace user data format
 * @cmd:	Command data structure to initialize
 * @csi:	Command Set Identifier
 * @fidx:	Format Index
 * @uidx:	UUID selection, if supported
 * @data:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_NS_USER_DATA_FORMAT.
 */
static inline void
nvme_init_identify_csi_ns_user_data_format(struct nvme_passthru_cmd *cmd,
		enum nvme_csi csi, __u16 fidx, __u8 uidx, void *data)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, csi,
			   NVME_IDENTIFY_CNS_CSI_NS_USER_DATA_FORMAT,
			   data, NVME_IDENTIFY_DATA_SIZE);
	cmd->cdw11 |= NVME_FIELD_ENCODE(fidx,
					NVME_IDENTIFY_CDW11_FIDX_SHIFT,
					NVME_IDENTIFY_CDW11_FIDX_MASK);
	cmd->cdw14 |= NVME_FIELD_ENCODE(uidx,
					NVME_IDENTIFY_CDW14_UUID_SHIFT,
					NVME_IDENTIFY_CDW14_UUID_MASK);
}

/**
 * nvme_init_identify_allocated_ns_list() - Initialize passthru command
 * for Allocated namespace ID list
 * @cmd:	Command data structure to initialize
 * @nsid:	Return namespaces greater than this identifier
 * @ns_list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST.
 */
static inline void
nvme_init_identify_allocated_ns_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_ns_list *ns_list)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST,
			   ns_list, sizeof(*ns_list));
}

/**
 * nvme_init_identify_allocated_ns() - Initialize passthru command
 * for allocated Namespace ID list
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace to identify
 * @ns:		User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_ALLOCATED_NS.
 */
static inline void
nvme_init_identify_allocated_ns(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_id_ns *ns)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			  NVME_IDENTIFY_CNS_ALLOCATED_NS,
			  ns, sizeof(*ns));
}

/**
 * nvme_init_identify_ns_ctrl_list() - Initialize passhtru command
 * for Controller List
 * @cmd:	Command data structure to initialize
 * @nsid:	Return controllers that are attached to this nsid
 * @cntid:	Starting CNTLID to return in the list
 * @cntlist:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_NS_CTRL_LIST.
 */
static inline void
nvme_init_identify_ns_ctrl_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, __u16 cntid, struct nvme_ctrl_list *cntlist)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_NS_CTRL_LIST,
			   cntlist, sizeof(*cntlist));
	cmd->cdw10 |= NVME_FIELD_ENCODE(cntid,
					NVME_IDENTIFY_CDW10_CNTID_SHIFT,
					NVME_IDENTIFY_CDW10_CNTID_MASK);
}

/**
 * nvme_init_identify_ctrl_list() - Initialize passthru command for
 * Controller List of controllers
 * @cmd:	Command data structure to initialize
 * @cntid:	Starting CNTLID to return in the list
 * @cntlist:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CTRL_LIST.
 */
static inline void
nvme_init_identify_ctrl_list(struct nvme_passthru_cmd *cmd,
		__u16 cntid, struct nvme_ctrl_list *cntlist)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_CTRL_LIST,
			   cntlist, sizeof(*cntlist));
	cmd->cdw10 |= NVME_FIELD_ENCODE(cntid,
					NVME_IDENTIFY_CDW10_CNTID_SHIFT,
					NVME_IDENTIFY_CDW10_CNTID_MASK);
}

/**
 * nvme_init_identify_primary_ctrl_cap() - Initialize passthru command
 * for Primary Controller Capabilities data
 * @cmd:	Command data structure to initialize
 * @cntid:	Return controllers starting at this identifier
 * @cap:	User space destination buffer address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP.
 */
static inline void
nvme_init_identify_primary_ctrl_cap(struct nvme_passthru_cmd *cmd,
		__u16 cntid, struct nvme_primary_ctrl_cap *cap)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP,
			   cap, sizeof(*cap));
	cmd->cdw10 |= NVME_FIELD_ENCODE(cntid,
					NVME_IDENTIFY_CDW10_CNTID_SHIFT,
					NVME_IDENTIFY_CDW10_CNTID_MASK);
}

/**
 * nvme_init_identify_secondary_ctrl_list() - Initialize passhru command
 * for Secondary Controller list
 * @cmd:	Command data structure to initialize
 * @cntid:	Return controllers starting at this identifier
 * @sc_list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST.
 */
static inline void
nvme_init_identify_secondary_ctrl_list(struct nvme_passthru_cmd *cmd,
		__u16 cntid, struct nvme_secondary_ctrl_list *sc_list)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST,
			   sc_list, sizeof(*sc_list));
	cmd->cdw10 |= NVME_FIELD_ENCODE(cntid,
					NVME_IDENTIFY_CDW10_CNTID_SHIFT,
					NVME_IDENTIFY_CDW10_CNTID_MASK);
}


/**
 * nvme_init_identify_ns_granularity() - Initialize passthru command for
 * Namespace Granularity list
 * @cmd:	Command data structure to initialize
 * @gr_list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST.
 */
static inline void
nvme_init_identify_ns_granularity(struct nvme_passthru_cmd *cmd,
		struct nvme_id_ns_granularity_list *gr_list)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_NS_GRANULARITY,
			   gr_list, sizeof(*gr_list));
}

/**
 * nvme_init_identify_uuid_list() - Initialize passthru command for
 * UUID list
 * @cmd:	Command data structure to initialize
 * @uuid_list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_UUID_LIST.
 */
static inline void
nvme_init_identify_uuid_list(struct nvme_passthru_cmd *cmd,
		struct nvme_id_uuid_list *uuid_list)
{
	nvme_init_identify(cmd, NVME_UUID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_UUID_LIST,
			   uuid_list, sizeof(*uuid_list));
}

/**
 * nvme_init_identify_domain_list() - Initialize passthru command for
 * Domain list
 * @cmd:	Command data structure to initialize
 * @domid:	Domain ID
 * @list:	User space destination address to transfer data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_DOMAIN_LIST.
 */
static inline void
nvme_init_identify_domain_list(struct nvme_passthru_cmd *cmd,
		__u16 domid, struct nvme_id_domain_list *list)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			     NVME_IDENTIFY_CNS_DOMAIN_LIST,
			     list, sizeof(*list));
	cmd->cdw11 |= NVME_FIELD_ENCODE(domid,
					NVME_IDENTIFY_CDW11_DOMID_SHIFT,
					NVME_IDENTIFY_CDW11_DOMID_MASK);
}

/**
 * nvme_init_identify_endurance_group_id() - Initialize passthru command for
 * Endurance group list
 * @cmd:	Command data structure to initialize
 * @enggid:	Endurance group identifier
 * @list:	Array of endurance group identifiers
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline void
nvme_init_identify_endurance_group_id(struct nvme_passthru_cmd *cmd,
		__u16 enggid, struct nvme_id_endurance_group_list *list)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			     NVME_IDENTIFY_CNS_ENDURANCE_GROUP_ID,
			     list, sizeof(*list));
	cmd->cdw11 |= NVME_FIELD_ENCODE(enggid,
					NVME_IDENTIFY_CDW11_ENGGID_SHIFT,
					NVME_IDENTIFY_CDW11_ENGGID_MASK);
}

/**
 * nvme_init_identify_csi_allocated_ns_list() - Initialize passthru command for
 * I/O Command Set specific Allocated Namespace Id list
 * @cmd:	Command data structure to initialize
 * @nsid:	Return namespaces greater than this identifier
 * @csi:	Command Set Identifier
 * @ns_list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS_LIST.
 */
static inline void
nvme_init_identify_csi_allocated_ns_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, enum nvme_csi csi, struct nvme_ns_list *ns_list)
{
	nvme_init_identify(cmd, nsid, csi,
			   NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS_LIST,
			   ns_list, sizeof(*ns_list));
}

/**
 * nvme_init_identify_csi_id_ns_data_structure() - Initialize passthru command
 * for I/O Command Set specific Identify Namespace data structure
 * @cmd:	Command data structure to initialize
 * @nsid:	Return namespaces greater than this identifier
 * @csi:	Command Set Identifier
 * @data:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_ID_NS_DATA_STRUCTURE.
 */
static inline void
nvme_init_identify_csi_id_ns_data_structure(struct nvme_passthru_cmd *cmd,
		__u32 nsid, enum nvme_csi csi, void *data)
{
	nvme_init_identify(cmd, nsid, csi,
			   NVME_IDENTIFY_CNS_CSI_ID_NS_DATA_STRUCTURE,
			   data, NVME_IDENTIFY_DATA_SIZE);
}

/**
 * nvme_init_identify_command_set_structure() - Initialize passthru command for
 * I/O Command Set data structure
 * @cmd:	Command data structure to initialize
 * @cntid:	Controller ID
 * @iocs:	User space destination address to transfer the data
 *
 * Retrieves list of the controller's supported io command set vectors. See
 * &struct nvme_id_iocs.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline void
nvme_init_identify_command_set_structure(struct nvme_passthru_cmd *cmd,
		__u16 cntid, struct nvme_id_iocs *iocs)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_COMMAND_SET_STRUCTURE,
			   iocs, sizeof(*iocs));
	cmd->cdw10 |= NVME_FIELD_ENCODE(cntid,
					NVME_IDENTIFY_CDW10_CNTID_SHIFT,
					NVME_IDENTIFY_CDW10_CNTID_MASK);
}

/**
 * nvme_init_zns_identify_ns() - Initialize passthru command for
 * ZNS identify namespace data
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace to identify
 * @data:	User space destination address to transfer the data
 */
static inline void
nvme_init_zns_identify_ns(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_zns_id_ns *data)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_ZNS,
			   NVME_IDENTIFY_CNS_CSI_NS,
			   data, sizeof(*data));
}

/**
 * nvme_init_zns_identify_ctrl() - Initialize passthru command for
 * ZNS identify controller data
 * @cmd:	Command data structure to initialize
 * @id:	User space destination address to transfer the data
 */
static inline void
nvme_init_zns_identify_ctrl(struct nvme_passthru_cmd *cmd,
		struct nvme_zns_id_ctrl *id)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_ZNS,
			   NVME_IDENTIFY_CNS_CSI_CTRL,
			   id, sizeof(*id));
}

/**
 * nvme_init_get_log_lpo() - Initializes passthru command with a
 * Log Page Offset
 * @cmd:	Passthru command
 * @lpo:	Log Page Offset to set
 */
static inline void
nvme_init_get_log_lpo(struct nvme_passthru_cmd *cmd, __u64 lpo)
{
	cmd->cdw12 = lpo & 0xffffffff;
	cmd->cdw13 = lpo >> 32;
}

/**
 * nvme_init_get_log() - Initialize passthru command for
 * NVMe Admin Get Log
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier, if applicable
 * @lid:	Log Page Identifier, see &enum nvme_cmd_get_log_lid
 * @csi:	Command set identifier, see &enum nvme_csi for known values
 * @data:	User space destination address to transfer the data
 * @len:	Length of provided user buffer to hold the log data in bytes
 */
static inline void
nvme_init_get_log(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_cmd_get_log_lid lid, enum nvme_csi csi,
		void *data, __u32 len)
{
	__u32 numd = (len >> 2) - 1;
	__u16 numdu = numd >> 16;
	__u16 numdl = numd & 0xffff;
	__u32 cdw10 = NVME_FIELD_ENCODE(lid,
					NVME_LOG_CDW10_LID_SHIFT,
					NVME_LOG_CDW10_LID_MASK) |
		      NVME_FIELD_ENCODE(numdl,
					NVME_LOG_CDW10_NUMDL_SHIFT,
					NVME_LOG_CDW10_NUMDL_MASK);
	__u32 cdw11 = NVME_FIELD_ENCODE(numdu,
					NVME_LOG_CDW11_NUMDU_SHIFT,
					NVME_LOG_CDW11_NUMDU_MASK);
	__u32 cdw14 = NVME_FIELD_ENCODE(csi,
					NVME_LOG_CDW14_CSI_SHIFT,
					NVME_LOG_CDW14_CSI_MASK);

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode	= nvme_admin_get_log_page;
	cmd->nsid	= nsid;
	cmd->cdw10	= cdw10;
	cmd->cdw11	= cdw11;
	cmd->cdw14	= cdw14;
	cmd->data_len	= len;
	cmd->addr	= (__u64)(uintptr_t)data;
}

/**
 * nvme_init_get_log_supported_log_pages() -  Initialize passthru command for
 * Supported Log Pages
 * @cmd:	Passthru command to use
 * @csi:	Command set identifier, see &enum nvme_csi for known values
 * @log:	Array of LID supported and Effects data structures
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_SUPPORTED_LOG_PAGES.
 */
static inline void
nvme_init_get_log_supported_log_pages(struct nvme_passthru_cmd *cmd,
		enum nvme_csi csi, struct nvme_supported_log_pages *log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL, NVME_LOG_LID_SUPPORTED_LOG_PAGES,
		csi, log, sizeof(*log));
}

/**
 * nvme_init_get_log_error() - Initialize passthru command for Error Information
 * @cmd:	Passthru command to use
 * @nr_entries:	Number of error log entries allocated
 * @err_log:	Array of error logs of size 'entries'
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ERROR.
 */
static inline void
nvme_init_get_log_error(struct nvme_passthru_cmd *cmd, unsigned int nr_entries,
		struct nvme_error_log_page *err_log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL, NVME_LOG_LID_ERROR,
		NVME_CSI_NVM, err_log, sizeof(*err_log) * nr_entries);
}

/**
 * nvme_init_get_log_smart() - Initialize passthru command for
 * SMART / Health Information
 * @cmd:	Passthru command to use
 * @nsid:	Optional namespace identifier
 * @smart_log:	User address to store the smart log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_SMART.
 */
static inline void
nvme_init_get_log_smart(struct nvme_passthru_cmd *cmd, __u32 nsid,
		struct nvme_smart_log *smart_log)
{
	nvme_init_get_log(cmd, nsid, NVME_LOG_LID_SMART, NVME_CSI_NVM,
		smart_log, sizeof(*smart_log));
}

/**
 * nvme_init_get_log_fw_slot() - Initialize passthru command for
 * Firmware Slot Information
 * @cmd:	Passthru command to use
 * @fw_log:	User address to store the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_SMART.
 */
static inline void
nvme_init_get_log_fw_slot(struct nvme_passthru_cmd *cmd,
		struct nvme_firmware_slot *fw_log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL, NVME_LOG_LID_FW_SLOT,
		NVME_CSI_NVM, fw_log, sizeof(*fw_log));
}

/**
 * nvme_init_get_log_changed_ns() - Initialize passthru command for
 * Changed Attached Namespace List
 * @cmd:	Passthru command to use
 * @ns_log:	User address to store the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_CHANGED_NS.
 */
static inline void
nvme_init_get_log_changed_ns(struct nvme_passthru_cmd *cmd,
			struct nvme_ns_list *ns_log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL, NVME_LOG_LID_CHANGED_NS,
		NVME_CSI_NVM, ns_log, sizeof(*ns_log));
}


/**
 * nvme_init_get_log_cmd_effects() - Initialize passthru command for
 * Commands Supported and Effects
 * @cmd:	Passthru command to use
 * @csi:	Command Set Identifier
 * @effects_log:User address to store the effects log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_CMD_EFFECTS.
 */
static inline void
nvme_init_get_log_cmd_effects(struct nvme_passthru_cmd *cmd,
		enum nvme_csi csi, struct nvme_cmd_effects_log *effects_log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL, NVME_LOG_LID_CMD_EFFECTS, csi,
		 effects_log, sizeof(*effects_log));
}

/**
 * nvme_init_get_log_device_self_test() - Initialize passthru command for
 * Device Self-test
 * @cmd:	Passthru command to use
 * @log:	Userspace address of the log payload
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_DEVICE_SELF_TEST.
 */
static inline void
nvme_init_get_log_device_self_test(struct nvme_passthru_cmd *cmd,
		struct nvme_self_test_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL, NVME_LOG_LID_DEVICE_SELF_TEST,
		NVME_CSI_NVM, log, sizeof(*log));
}

/**
 * nvme_init_get_log_telemetry_host() - Initialize passthru command for
 * Telemetry Host-Initiated
 * @cmd:	Passthru command to use
 * @lpo:	Offset into the telemetry data
 * @log:	User address for log page data
 * @len:	Length of provided user buffer to hold the log data in bytes
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_TELEMETRY_HOST.
 */
static inline void
nvme_init_get_log_telemetry_host(struct nvme_passthru_cmd *cmd, __u64 lpo,
		void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE, NVME_LOG_LID_TELEMETRY_HOST,
		NVME_CSI_NVM, log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE(NVME_LOG_TELEM_HOST_LSP_RETAIN,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_create_telemetry_host_mcda() - Initialize passthru
 * command for Create Telemetry Host-Initiated
 * @cmd:	Passthru command to use
 * @mcda:	Maximum Created Data Area
 * @log:	Userspace address of the log payload
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_TELEMETRY_HOST and
 * LSP value %NVME_LOG_TELEM_HOST_LSP_CREATE.
 */
static inline void
nvme_init_get_log_create_telemetry_host_mcda(struct nvme_passthru_cmd *cmd,
		enum nvme_telemetry_da mcda, struct nvme_telemetry_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE, NVME_LOG_LID_TELEMETRY_HOST,
		NVME_CSI_NVM, log, sizeof(*log));
	cmd->cdw10 |= NVME_FIELD_ENCODE(
			mcda << 1 | NVME_LOG_TELEM_HOST_LSP_CREATE,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_create_telemetry_host() - Initialize passthru command for
 * Create Telemetry Host-Initiated
 * @cmd:	Passthru command to use
 * @log:	Userspace address of the log payload
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_TELEMETRY_HOST and
 * LSP value %NVME_LOG_TELEM_HOST_LSP_CREATE.
 */
static inline void
nvme_init_get_log_create_telemetry_host(struct nvme_passthru_cmd *cmd,
			struct nvme_telemetry_log *log)
{
	nvme_init_get_log_create_telemetry_host_mcda(cmd,
		NVME_TELEMETRY_DA_CTRL_DETERMINE, log);
}

/**
 * nvme_init_get_log_telemetry_ctrl() - Initialize passthru command for
 * Telemetry Controller-Initiated
 * @cmd:	Passthru command to use
 * @lpo:	Offset into the telemetry data
 * @log:	User address for log page data
 * @len:	Length of provided user buffer to hold the log data in bytes
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_TELEMETRY_CTRL.
 */
static inline void
nvme_init_get_log_telemetry_ctrl(struct nvme_passthru_cmd *cmd,
		__u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE, NVME_LOG_LID_TELEMETRY_CTRL,
		NVME_CSI_NVM, log, len);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_endurance_group() - Initialize passthru command for
 * Endurance Group Information
 * @cmd:	Passthru command to use
 * @endgid:	Starting group identifier to return in the list
 * @log:	User address to store the endurance log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ENDURANCE_GROUP.
 */
static inline void
nvme_init_get_log_endurance_group(struct nvme_passthru_cmd *cmd, __u16 endgid,
		struct nvme_endurance_group_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE, NVME_LOG_LID_ENDURANCE_GROUP,
		NVME_CSI_NVM, log, sizeof(*log));
	cmd->cdw11 |= NVME_FIELD_ENCODE(endgid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
}

/**
 * nvme_init_get_log_predictable_lat_nvmset() - Initialize passthru command for
 * Predictable Latency Per NVM Set
 * @cmd:	Passthru command to use
 * @nvmsetid:	NVM set id
 * @log:	User address to store the predictable latency log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_PREDICTABLE_LAT_NVMSET.
 */
static inline void
nvme_init_get_log_predictable_lat_nvmset(struct nvme_passthru_cmd *cmd,
		__u16 nvmsetid, struct nvme_nvmset_predictable_lat_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_PREDICTABLE_LAT_NVMSET, NVME_CSI_NVM,
		log, sizeof(*log));
	cmd->cdw11 |= NVME_FIELD_ENCODE(nvmsetid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
}

/**
 * nvme_init_get_log_predictable_lat_event() - Initialize passthru command for
 * Predictable Latency Event Aggregate
 * @cmd:	Passthru command to use
 * @lpo:	Offset into the predictable latency event
 * @log:	User address for log page data
 * @len:	Length of provided user buffer to hold the log data in bytes
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_PREDICTABLE_LAT_AGG.
 */
static inline void
nvme_init_get_log_predictable_lat_event(struct nvme_passthru_cmd *cmd,
		__u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_PREDICTABLE_LAT_AGG, NVME_CSI_NVM,
		log, len);
	cmd->cdw12 = lpo & 0xffffffff;
	cmd->cdw13 = lpo >> 32;
}

/**
 * nvme_init_get_log_ana() - Initialize passthru command for
 * Asymmetric Namespace Access
 * @cmd:	Passthru command to use
 * @lsp:	Log specific, see &enum nvme_get_log_ana_lsp
 * @lpo:	Offset to the start of the log page
 * @log:	User address to store the ana log
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ANA.
 */
static inline void
nvme_init_get_log_ana(struct nvme_passthru_cmd *cmd,
		enum nvme_log_ana_lsp lsp, __u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_ANA, NVME_CSI_NVM,
		log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE(lsp,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
	cmd->cdw12 = lpo & 0xffffffff;
	cmd->cdw13 = lpo >> 32;
}

/**
 * nvme_init_get_log_ana_groups() - Initialize passthru command for
 * Asymmetric Namespace Access groups
 * @cmd:	Passthru command to use
 * @log:	User address to store the ana group log
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ANA and LSP value %NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY
 */
static inline void
nvme_init_get_log_ana_groups(struct nvme_passthru_cmd *cmd,
		struct nvme_ana_log *log, __u32 len)
{
	nvme_init_get_log_ana(cmd, NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY,
		0, log, len);
}

/**
 * nvme_init_get_log_persistent_event() - Initialize passthru command for
 * Persistent Event Log
 * @cmd:	Passthru command to use
 * @action:	Action the controller should take during processing this command
 * @pevent_log:	User address to store the persistent event log
 * @len:	Size of @pevent_log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_PERSISTENT_EVENT
 */
static inline void
nvme_init_get_log_persistent_event(struct nvme_passthru_cmd *cmd,
		enum nvme_pevent_log_action action,
		void *pevent_log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_PERSISTENT_EVENT, NVME_CSI_NVM,
		pevent_log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE(action,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_lba_status() - Initialize passthru command for
 * Retrieve LBA Status
 * @cmd:	Passthru command to use
 * @lpo:	Offset to the start of the log page
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_LBA_STATUS
 */
static inline void
nvme_init_get_log_lba_status(struct nvme_passthru_cmd *cmd,
		__u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_LBA_STATUS, NVME_CSI_NVM,
		log, len);
	cmd->cdw12 = lpo & 0xffffffff;
	cmd->cdw13 = lpo >> 32;
}

/**
 * nvme_init_get_log_endurance_grp_evt() - Initialize passthru command for
 * Endurance Group Event Aggregate
 * @cmd:	Passthru command to use
 * @lpo:	Offset to the start of the log page
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ENDURANCE_GRP_EVT
 */
static inline void
nvme_init_get_log_endurance_grp_evt(struct nvme_passthru_cmd *cmd,
		__u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_ENDURANCE_GRP_EVT, NVME_CSI_NVM,
		log, len);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_media_unit_stat() - Initialize passthru command for
 * Media Unit Status
 * @cmd:	Passthru command to use
 * @domid:	Domain Identifier selection, if supported
 * @mus:	User address to store the Media Unit statistics log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_MEDIA_UNIT_STATUS
 */
static inline void
nvme_init_get_log_media_unit_stat(struct nvme_passthru_cmd *cmd,
		__u16 domid, struct nvme_media_unit_stat_log *mus)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_MEDIA_UNIT_STATUS, NVME_CSI_NVM,
		mus, sizeof(*mus));
	cmd->cdw11 |= NVME_FIELD_ENCODE(domid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
}

/**
 * nvme_init_get_log_support_cap_config_list() - Initialize passthru command for
 * Supported Capacity Configuration List
 * @cmd:	Passthru command to use
 * @domid:	Domain Identifier selection, if supported
 * @cap:	User address to store supported capabilities config list
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST
 */
static inline void
nvme_init_get_log_support_cap_config_list(struct nvme_passthru_cmd *cmd,
		__u16 domid, struct nvme_supported_cap_config_list_log *cap)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST, NVME_CSI_NVM,
		cap, sizeof(*cap));
	cmd->cdw11 |= NVME_FIELD_ENCODE(domid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
}

/**
 * nvme_init_get_log_fid_supported_effects() - Initialize passthru command for
 * Feature Identifiers Supported and Effects
 * @cmd:	Passthru command to use
 * @csi:	Command set identifier, see &enum nvme_csi for known values
 * @log:	FID Supported and Effects data structure
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_FID_SUPPORTED_EFFECTS
 */
static inline void
nvme_init_get_log_fid_supported_effects(struct nvme_passthru_cmd *cmd,
		enum nvme_csi csi, struct nvme_fid_supported_effects_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_FID_SUPPORTED_EFFECTS, csi,
		log, sizeof(*log));
}

/**
 * nvme_init_get_log_mi_cmd_supported_effects() - Initialize passthru command
 * for MI Commands Supported by the controller
 * @cmd:	Passthru command to use
 * @log:	MI Command Supported and Effects data structure
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS
 */
static inline void
nvme_init_get_log_mi_cmd_supported_effects(struct nvme_passthru_cmd *cmd,
		struct nvme_mi_cmd_supported_effects_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS, NVME_CSI_NVM,
		log, sizeof(*log));
}

/**
 * nvme_init_get_log_lockdown() - Initialize passthru command for
 * Command and Feature Lockdown
 * @cmd:		Passthru command to use
 * @cnscp:		Contents and Scope of Command and Feature Identifier
 *			Lists
 * @lockdown_log:	Buffer to store the lockdown log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN
 */
static inline void
nvme_init_get_log_lockdown(struct nvme_passthru_cmd *cmd,
		__u8 cnscp, struct nvme_lockdown_log *lockdown_log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN, NVME_CSI_NVM,
		lockdown_log, sizeof(*lockdown_log));
	cmd->cdw10 |= NVME_FIELD_ENCODE(cnscp,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_boot_partition() - Initialize passthru command for
 * Boot Partition
 * @cmd:	Passthru command to use
 * @lsp:	The log specified field of LID
 * @part:	User address to store the log page
 * @len:	The allocated size, minimum
 *		struct nvme_boot_partition
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_BOOT_PARTITION
 */
static inline void
nvme_init_get_log_boot_partition(struct nvme_passthru_cmd *cmd,
		__u8 lsp, struct nvme_boot_partition *part, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_BOOT_PARTITION, NVME_CSI_NVM,
		part, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE(lsp,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_rotational_media_info() - Initialize passthru command for
 * Rotational Media Information Log
 * @cmd:	Passthru command to use
 * @endgid:	Endurance Group Identifier
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ROTATIONAL_MEDIA_INFO
 */
static inline void
nvme_init_get_log_rotational_media_info(struct nvme_passthru_cmd *cmd,
		__u16 endgid, struct nvme_rotational_media_info_log *log,
		__u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_ROTATIONAL_MEDIA_INFO, NVME_CSI_NVM,
		log, len);
	cmd->cdw11 |= NVME_FIELD_ENCODE(endgid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
}

/**
 * nvme_init_get_log_dispersed_ns_participating_nss() - Initialize passthru
 * command for Dispersed Namespace Participating NVM Subsystems
 * @cmd:	Passthru command to use
 * @nsid:	Namespace Identifier
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS
 */
static inline void
nvme_init_get_log_dispersed_ns_participating_nss(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_dispersed_ns_participating_nss_log *log,
		__u32 len)
{
	nvme_init_get_log(cmd, nsid,
		NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS, NVME_CSI_NVM,
		log, len);
}

/**
 * nvme_init_get_log_mgmt_addr_list() - Initialize passthru command for
 * Management Address List
 * @cmd:	Passthru command to use
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_MGMT_ADDR_LIST
 */
static inline void
nvme_init_get_log_mgmt_addr_list(struct nvme_passthru_cmd *cmd,
		struct nvme_mgmt_addr_list_log *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_MGMT_ADDR_LIST, NVME_CSI_NVM,
		log, len);
}

/**
 * nvme_init_get_log_phy_rx_eom() - Initialize passthru command for
 * Physical Interface Receiver Eye Opening Measurement
 * @cmd:	Passthru command to use
 * @lsp:	Log specific, controls action and measurement quality
 * @controller:	Target controller ID
 * @log:	User address to store the log page
 * @len:	The allocated size, minimum
 *		struct nvme_phy_rx_eom_log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_PHY_RX_EOM
 */
static inline void
nvme_init_get_log_phy_rx_eom(struct nvme_passthru_cmd *cmd,
		__u8 lsp, __u16 controller, struct nvme_phy_rx_eom_log *log,
		__u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_PHY_RX_EOM, NVME_CSI_NVM,
		log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE(lsp,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
	cmd->cdw11 |= NVME_FIELD_ENCODE(controller,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
}

/**
 * nvme_init_get_log_reachability_groups() - Initialize passthru command for
 * Retrieve Reachability Groups
 * @cmd:	Passthru command to use
 * @rgo:	Return groups only
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_REACHABILITY_GROUPS
 */
static inline void
nvme_init_get_log_reachability_groups(struct nvme_passthru_cmd *cmd,
		bool rgo, struct nvme_reachability_groups_log *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_REACHABILITY_GROUPS, NVME_CSI_NVM,
		log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE((__u8)rgo,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_reachability_associations() - Initialize passthru command
 * for Reachability Associations Log
 * @cmd:	Passthru command to use
 * @rao:	Return associations only
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_REACHABILITY_ASSOCIATIONS
 */
static inline void
nvme_init_get_log_reachability_associations(struct nvme_passthru_cmd *cmd,
		bool rao, struct nvme_reachability_associations_log *log,
		__u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_REACHABILITY_ASSOCIATIONS, NVME_CSI_NVM,
		log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE((__u8)rao,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_changed_alloc_ns() - Initialize passthru command for
 * Changed Allocated Namespace List
 * @cmd:	Passthru command to use
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_CHANGED_ALLOC_NS
 */
static inline void
nvme_init_get_log_changed_alloc_ns(struct nvme_passthru_cmd *cmd,
		struct nvme_ns_list *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_CHANGED_ALLOC_NS, NVME_CSI_NVM,
		log, len);
}

/**
 * nvme_init_get_log_fdp_configurations() - Initialize passthru command for
 * Flexible Data Placement Configurations
 * @cmd:	Passthru command to use
 * @egid:	Endurance group identifier
 * @lpo:	Offset into log page
 * @log:	Log page data buffer
 * @len:	Length (in bytes) of provided user buffer to hold the log data
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_FDP_CONFIGS
 */
static inline void
nvme_init_get_log_fdp_configurations(struct nvme_passthru_cmd *cmd,
		__u16 egid, __u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_FDP_CONFIGS, NVME_CSI_NVM,
		log, len);
	cmd->cdw11 |= NVME_FIELD_ENCODE(egid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_reclaim_unit_handle_usage() - Initialize passthru
 * command for Reclaim Unit Handle Usage
 * @cmd:	Passthru command to use
 * @egid:	Endurance group identifier
 * @lpo:	Offset into log page
 * @log:	Log page data buffer
 * @len:	Length (in bytes) of provided user buffer to hold the log data
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_RUH_USAGE
 */
static inline void
nvme_init_get_log_reclaim_unit_handle_usage(struct nvme_passthru_cmd *cmd,
		__u16 egid, __u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_FDP_RUH_USAGE, NVME_CSI_NVM,
		log, len);
	cmd->cdw11 |= NVME_FIELD_ENCODE(egid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_fdp_stats() - Initialize passthru command for
 * Get Flexible Data Placement Statistics
 * @cmd:	Passthru command to use
 * @egid:	Endurance group identifier
 * @lpo:	Offset into log page
 * @log:	Log page data buffer
 * @len:	Length (in bytes) of provided user buffer to hold the log data
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_FDP_STATS
 */
static inline
void nvme_init_get_log_fdp_stats(struct nvme_passthru_cmd *cmd,
		__u16 egid, __u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_FDP_STATS, NVME_CSI_NVM,
		log, len);
	cmd->cdw11 |= NVME_FIELD_ENCODE(egid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_fdp_events() - Initialize passthru command for
 * Flexible Data Placement Events
 * @cmd:		Passthru command to use
 * @host_events:	Whether to report host or controller events
 * @egid:		Endurance group identifier
 * @lpo:		Offset into log page
 * @log:		Log page data buffer
 * @len:		Length (in bytes) of provided user buffer to hold
 *			the log data
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_FDP_EVENTS
 */
static inline void
nvme_init_get_log_fdp_events(struct nvme_passthru_cmd *cmd,
		bool host_events, __u16 egid, __u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_FDP_EVENTS, NVME_CSI_NVM,
		log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE((__u8)(host_events ? 0x1 : 0x0),
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
	cmd->cdw11 |= NVME_FIELD_ENCODE(egid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
	nvme_init_get_log_lpo(cmd, lpo);
}


/**
 * nvme_init_get_log_discovery() - Initialize passthru command for Discovery
 * @cmd:	Passthru command to use
 * @lpo:	Offset of this log to retrieve
 * @log:	User address to store the discovery log
 * @len:	The allocated size for this portion of the log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_DISCOVERY
 */
static inline void
nvme_init_get_log_discovery(struct nvme_passthru_cmd *cmd,
			__u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_DISCOVERY, NVME_CSI_NVM,
		log, len);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_host_discovery() - Initialize passthru command for
 * Host Discover
 * @cmd:	Passthru command to use
 * @allhoste:	All host entries
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_HOST_DISCOVERY
 */
static inline void
nvme_init_get_log_host_discovery(struct nvme_passthru_cmd *cmd,
		bool allhoste, struct nvme_host_discover_log *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_HOST_DISCOVERY, NVME_CSI_NVM,
		log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE((__u8)allhoste,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_ave_discovery() - Initialize passthru command for
 * AVE Discovery
 * @cmd:	Passthru command to use
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_AVE_DISCOVERY
 */
static inline void
nvme_init_get_log_ave_discovery(struct nvme_passthru_cmd *cmd,
		struct nvme_ave_discover_log *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_AVE_DISCOVERY, NVME_CSI_NVM,
		log, len);
}

/**
 * nvme_init_get_log_pull_model_ddc_req() - Initialize passthru command for
 * Pull Model DDC Request
 * @cmd:	Passthru command to use
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_PULL_MODEL_DDC_REQ
 */
static inline void
nvme_init_get_log_pull_model_ddc_req(struct nvme_passthru_cmd *cmd,
		struct nvme_pull_model_ddc_req_log *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_PULL_MODEL_DDC_REQ, NVME_CSI_NVM,
		log, len);
}

/**
 * nvme_init_get_log_reservation() - Initialize passthru command for
 * Reservation Notification
 * @cmd:	Passthru command to use
 * @log:	User address to store the reservation log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_RESERVATION
 */
static inline void
nvme_init_get_log_reservation(struct nvme_passthru_cmd *cmd,
			struct nvme_resv_notification_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_RESERVATION, NVME_CSI_NVM,
		log, sizeof(*log));
}

/**
 * nvme_init_get_log_sanitize() - Initialize passthru command for
 * Sanitize Status
 * @cmd:	Passthru command to use
 * @log:	User address to store the sanitize log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_SANITIZE
 */
static inline void
nvme_init_get_log_sanitize(struct nvme_passthru_cmd *cmd,
		struct nvme_sanitize_log_page *log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_SANITIZE, NVME_CSI_NVM,
		log, sizeof(*log));
}

/**
 * nvme_init_get_log_zns_changed_zones() - Initialize passthru command for
 * list of zones that have changed
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @log:	User address to store the changed zone log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ZNS_CHANGED_ZONES
 */
static inline void
nvme_init_get_log_zns_changed_zones(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_zns_changed_zone_log *log)
{
	nvme_init_get_log(cmd, nsid,
		NVME_LOG_LID_ZNS_CHANGED_ZONES, NVME_CSI_ZNS,
		log, sizeof(*log));
}

/**
 * nvme_init_set_features() - Initialize passthru command for
 * Set Features
 * @cmd:	Passthru command to use
 * @fid:	Feature identifier
 * @sv:		Save value across power states
 */
static inline void
nvme_init_set_features(struct nvme_passthru_cmd *cmd, __u8 fid, bool sv)
{
	__u32 cdw10 = NVME_FIELD_ENCODE(fid,
			NVME_SET_FEATURES_CDW10_FID_SHIFT,
			NVME_SET_FEATURES_CDW10_FID_MASK) |
		      NVME_FIELD_ENCODE(sv,
			NVME_SET_FEATURES_CDW10_SV_SHIFT,
			NVME_SET_FEATURES_CDW10_SV_MASK);

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode	= nvme_admin_set_features;
	cmd->cdw10	= cdw10;
}

/**
 * nvme_init_set_features_arbitration() -Initialize passthru command for
 * Arbitration Features
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @ab:		Arbitration Burst
 * @lpw:	Low Priority Weight
 * @mpw:	Medium Priority Weight
 * @hpw:	High Priority Weight
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_ARBRITARTION
 */
static inline void
nvme_init_set_features_arbitration(struct nvme_passthru_cmd *cmd,
		bool sv, __u8 ab, __u8 lpw, __u8 mpw, __u8 hpw)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_ARBITRATION, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(ab,
			NVME_FEAT_ARBITRATION_BURST_SHIFT,
			NVME_FEAT_ARBITRATION_BURST_MASK) |
		     NVME_FIELD_ENCODE(lpw,
			NVME_FEAT_ARBITRATION_LPW_SHIFT,
			NVME_FEAT_ARBITRATION_LPW_MASK) |
		     NVME_FIELD_ENCODE(mpw,
			NVME_FEAT_ARBITRATION_MPW_SHIFT,
			NVME_FEAT_ARBITRATION_MPW_MASK) |
		     NVME_FIELD_ENCODE(hpw,
			NVME_FEAT_ARBITRATION_HPW_SHIFT,
			NVME_FEAT_ARBITRATION_HPW_MASK);
}

/**
 * nvme_init_set_features_power_mgmt() - Initialize passthru command for
 * Power Management
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @ps:		Power State
 * @wh:		Workload Hint
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_PWRMGMT_PS
 */
static inline void
nvme_init_set_features_power_mgmt(struct nvme_passthru_cmd *cmd,
		bool sv, __u8 ps, __u8 wh)
{

	nvme_init_set_features(cmd, NVME_FEAT_FID_POWER_MGMT, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(ps,
			NVME_FEAT_PWRMGMT_PS_SHIFT,
			NVME_FEAT_PWRMGMT_PS_MASK) |
		     NVME_FIELD_ENCODE(wh,
			NVME_FEAT_PWRMGMT_WH_SHIFT,
			NVME_FEAT_PWRMGMT_WH_MASK);
}

/**
 * nvme_init_set_features_lba_range() - Initialize passthru command for
 * LBA Range
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sv:		Save value across power states
 * @num:	Number of ranges in @data
 * @data:	User address of feature data
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_LBA_RANGE
 */
static inline void
nvme_init_set_features_lba_range(struct nvme_passthru_cmd *cmd,
		__u32 nsid, bool sv, __u8 num,
		struct nvme_lba_range_type *data)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_LBA_RANGE, sv);
	cmd->nsid = nsid;
	cmd->cdw11 = NVME_FIELD_ENCODE(num - 1,
			NVME_SET_FEATURES_CDW11_NUM_SHIFT,
			NVME_SET_FEATURES_CDW11_NUM_MASK);
	cmd->data_len = sizeof(*data);
	cmd->addr = (__u64)(uintptr_t)data;
}

/**
 * nvme_init_set_features_temp_thresh() - Initialize passthru command for
 * Temperature Threshold
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @tmpth:	Temperature Threshold
 * @tmpsel:	Threshold Temperature Select
 * @thsel:	Threshold Type Select
 * @tmpthh:	Temperature Threshold Hysteresis
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_TEMP_THRESH
 */
static inline void
nvme_init_set_features_temp_thresh(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 tmpth, __u8 tmpsel,
		enum nvme_feat_tmpthresh_thsel thsel, __u8 tmpthh)
{

	nvme_init_set_features(cmd, NVME_FEAT_FID_TEMP_THRESH, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(tmpth,
			NVME_FEAT_TT_TMPTH_SHIFT,
			NVME_FEAT_TT_TMPTH_MASK) |
		     NVME_FIELD_ENCODE(tmpsel,
			NVME_FEAT_TT_TMPSEL_SHIFT,
			NVME_FEAT_TT_TMPSEL_MASK) |
		     NVME_FIELD_ENCODE(thsel,
			NVME_FEAT_TT_THSEL_SHIFT,
			NVME_FEAT_TT_THSEL_MASK) |
		     NVME_FIELD_ENCODE(tmpthh,
			NVME_FEAT_TT_TMPTHH_SHIFT,
			NVME_FEAT_TT_TMPTHH_MASK);
}

/**
 * nvme_init_set_features_err_recovery() - Initialize passthru command for
 * Error Recovery
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sv:		Save value across power states
 * @tler:	Time-limited error recovery value
 * @dulbe:	Deallocated or Unwritten Logical Block Error Enable
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_ERR_RECOVERY
 */
static inline void
nvme_init_set_features_err_recovery(struct nvme_passthru_cmd *cmd,
		__u32 nsid, bool sv, __u16 tler, bool dulbe)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_ERR_RECOVERY, sv);
	cmd->nsid = nsid;
	cmd->cdw11 = NVME_FIELD_ENCODE(tler,
			NVME_FEAT_ERROR_RECOVERY_TLER_SHIFT,
			NVME_FEAT_ERROR_RECOVERY_TLER_MASK) |
		     NVME_FIELD_ENCODE(dulbe,
			NVME_FEAT_ERROR_RECOVERY_DULBE_SHIFT,
			NVME_FEAT_ERROR_RECOVERY_DULBE_MASK);
}

/**
 * nvme_init_set_features_volatile_wc() - Initialize passthru command for
 * Volatile Write Cache
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @wce:	Write cache enable
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_VOLATILE_WC
 */
static inline void
nvme_init_set_features_volatile_wc(struct nvme_passthru_cmd *cmd,
		bool sv, bool wce)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_VOLATILE_WC, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(wce,
			NVME_FEAT_VWC_WCE_SHIFT,
			NVME_FEAT_VWC_WCE_MASK);
}

/**
 * nvme_init_set_features_irq_coalesce() - Initialize passthru command for
 * IRQ Coalescing
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @thr:	Aggregation Threshold
 * @time:	Aggregation Time
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_IRQ_COALESCE
 */
static inline void
nvme_init_set_features_irq_coalesce(struct nvme_passthru_cmd *cmd,
		bool sv, __u8 thr, __u8 time)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_IRQ_COALESCE, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(thr,
			NVME_FEAT_IRQC_THR_SHIFT,
			NVME_FEAT_IRQC_THR_MASK) |
		     NVME_FIELD_ENCODE(time,
			NVME_FEAT_IRQC_TIME_SHIFT,
			NVME_FEAT_IRQC_TIME_MASK);
}

/**
 * nvme_init_set_features_irq_config() - Initialize passthru command for
 * IRQ Config
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @iv:		Interrupt Vector
 * @cd:		Coalescing Disable
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_IRQ_CONFIG
 */
static inline void
nvme_init_set_features_irq_config(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 iv, bool cd)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_IRQ_CONFIG, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(iv,
			NVME_FEAT_ICFG_IV_SHIFT,
			NVME_FEAT_ICFG_IV_MASK) |
		     NVME_FIELD_ENCODE(cd,
			NVME_FEAT_ICFG_CD_SHIFT,
			NVME_FEAT_ICFG_CD_MASK);
}

/**
 * nvme_init_set_features_write_atomic() - Initialize passthru command for
 * Write Atomic
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @dn:		Disable Normal
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_WRITE_ATOMIC
 */
static inline void
nvme_init_set_features_write_atomic(struct nvme_passthru_cmd *cmd,
		bool sv, bool dn)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_WRITE_ATOMIC, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(dn,
			NVME_FEAT_WA_DN_SHIFT,
			NVME_FEAT_WA_DN_MASK);
}

/**
 * nvme_init_set_features_async_event() - Initialize passthru command for
 * Asynchronous Event Configuration
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @events:	Events to enable
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_ASYNC_EVENT
 */
static inline void
nvme_init_set_features_async_event(struct nvme_passthru_cmd *cmd,
		bool sv, __u32 events)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_ASYNC_EVENT, sv);
	cmd->cdw11 = events;
}

/**
 * nvme_init_set_features_auto_pst() - Initialize passthru command for
 * Autonomous Power State Transition
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @apste:	Autonomous Power State Transition Enable
 * @apst:	Autonomous Power State Transition data buffer
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_AUTO_PST
 */
static inline void
nvme_init_set_features_auto_pst(struct nvme_passthru_cmd *cmd,
		bool sv, bool apste, struct nvme_feat_auto_pst *apst)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_AUTO_PST, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(apste,
				       NVME_FEAT_APST_APSTE_SHIFT,
				       NVME_FEAT_APST_APSTE_MASK);
	cmd->data_len = sizeof(*apst);
	cmd->addr = (__u64)(uintptr_t)apst;
}

/**
 * nvme_init_set_features_timestamp() - Initialize passthru command for
 * Timestamp
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @tstmp:	The current timestamp value to assign to this feature
 * @ts:		Timestamp data buffer (populated by this function)
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_TIMESTAMP. The caller must provide a valid
 * buffer via @ts, which this function will populate.
 */
static inline void
nvme_init_set_features_timestamp(struct nvme_passthru_cmd *cmd,
		bool sv, __u64 tstmp, struct nvme_timestamp *ts)
{
	__le64 t = htole64(tstmp);

	memcpy(ts, &t, sizeof(__le64));

	nvme_init_set_features(cmd, NVME_FEAT_FID_TIMESTAMP, sv);
	cmd->data_len = sizeof(*ts);
	cmd->addr = (__u64)(uintptr_t)ts;
}

/**
 * nvme_init_set_features_hctm() - Initialize passthru command for
 * Host Controlled Thermal Management
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @tmt2:	Thermal Management Temperature 2
 * @tmt1:	Thermal Management Temperature 1
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_HCTM
 */
static inline void
nvme_init_set_features_hctm(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 tmt2, __u16 tmt1)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_HCTM, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(tmt2,
				       NVME_FEAT_HCTM_TMT2_SHIFT,
				       NVME_FEAT_HCTM_TMT2_MASK) |
		     NVME_FIELD_ENCODE(tmt1,
				       NVME_FEAT_HCTM_TMT1_SHIFT,
				       NVME_FEAT_HCTM_TMT1_MASK);
}

/**
 * nvme_init_set_features_nopsc() - Initialize passthru command for
 * Non-Operational Power State Config
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @noppme:	Non-Operational Power State Permissive Mode Enable
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_NOPSC
 */
static inline void
nvme_init_set_features_nopsc(struct nvme_passthru_cmd *cmd,
		bool sv, bool noppme)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_NOPSC, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(noppme,
			NVME_FEAT_NOPS_NOPPME_SHIFT,
			NVME_FEAT_NOPS_NOPPME_MASK);
}

/**
 * nvme_init_set_features_rrl() - Initialize passthru command for
 * Read Recovery Level
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @nvmsetid:	NVM set id
 * @rrl:	Read recovery level setting
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_RRL
 */
static inline void
nvme_init_set_features_rrl(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 nvmsetid, __u8 rrl)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_RRL, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(nvmsetid,
			NVME_FEAT_RRL_NVMSETID_SHIFT,
			NVME_FEAT_RRL_NVMSETID_MASK);
	cmd->cdw12 = NVME_FIELD_ENCODE(rrl,
			NVME_FEAT_RRL_RRL_SHIFT,
			NVME_FEAT_RRL_RRL_MASK);
}

/**
 * nvme_init_set_features_plm_config() - Initialize passthru command for
 * Predictable Latency Mode Config
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @nvmsetid:	NVM Set Identifier
 * @lpe:	Predictable Latency Enable
 * @data:	Pointer to structure nvme_plm_config
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_PLM_CONFIG
 */
static inline void
nvme_init_set_features_plm_config(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 nvmsetid, bool lpe, struct nvme_plm_config *data)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_PLM_CONFIG, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(nvmsetid,
			NVME_FEAT_PLM_NVMSETID_SHIFT,
			NVME_FEAT_PLM_NVMSETID_MASK);
	cmd->cdw12 = NVME_FIELD_ENCODE(lpe,
			NVME_FEAT_PLM_LPE_SHIFT,
			NVME_FEAT_PLM_LPE_MASK);
	cmd->data_len = sizeof(*data);
	cmd->addr = (__u64)(uintptr_t)data;
}

/**
 * nvme_init_set_features_plm_window() - Initialize passthru command for
 * Predictable Latency Mode Window
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @nvmsetid:	NVM Set Identifier
 * @wsel:	Window Select
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_PLM_WINDOW
 */
static inline void
nvme_init_set_features_plm_window(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 nvmsetid,
		enum nvme_feat_plm_window_select wsel)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_PLM_WINDOW, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(nvmsetid,
			NVME_FEAT_PLM_NVMSETID_SHIFT,
			NVME_FEAT_PLM_NVMSETID_MASK);
	cmd->cdw12 = NVME_FIELD_ENCODE(wsel,
			NVME_FEAT_PLMW_WS_SHIFT,
			NVME_FEAT_PLMW_WS_MASK);
}

/**
 * nvme_init_set_features_lba_sts_interval() - Initialize passthru command for
 * LBA Status Information Interval
 * @cmd:        Passthru command to use
 * @sv:         Save value across power states
 * @lsiri:      LBA Status Information Report Interval
 * @lsipi:      LBA Status Information Poll Interval
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_LBA_STS_INTERVAL
 */
static inline void
nvme_init_set_features_lba_sts_interval(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 lsiri, __u16 lsipi)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_LBA_STS_INTERVAL, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(lsiri,
			NVME_FEAT_LBAS_LSIRI_SHIFT,
			NVME_FEAT_LBAS_LSIRI_MASK) |
		     NVME_FIELD_ENCODE(lsipi,
			NVME_FEAT_LBAS_LSIPI_SHIFT,
			NVME_FEAT_LBAS_LSIPI_MASK);
}

/**
 * nvme_init_set_features_host_behavior() - Initialize passthru command for
 * Host Behavior
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @data:	Pointer to structure nvme_feat_host_behavior
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_HOST_BEHAVIOR
 */
static inline void
nvme_init_set_features_host_behavior(struct nvme_passthru_cmd *cmd,
		bool sv, struct nvme_feat_host_behavior *data)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_HOST_BEHAVIOR, sv);
	cmd->data_len = sizeof(*data);
	cmd->addr = (__u64)(uintptr_t)data;
}

/**
 * nvme_init_set_features_sanitize() - Initialize passthru command for
 * Sanitize
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @nodrm:	No-Deallocate Response Mode
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_SANITIZE
 */
static inline void
nvme_init_set_features_sanitize(struct nvme_passthru_cmd *cmd,
		bool sv, bool nodrm)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_SANITIZE, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(nodrm,
				       NVME_FEAT_SANITIZE_NODRM_SHIFT,
				       NVME_FEAT_SANITIZE_NODRM_MASK);
}

/**
 * nvme_init_set_features_endurance_evt_cfg() - Initialize passthru command for
 * Endurance Group Event Configuration
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @endgid:	Endurance Group Identifier
 * @egcw:	Flags to enable warning,
 *		see &enum nvme_eg_critical_warning_flags
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_ENDURANCE_EVT_CFG
 */
static inline void
nvme_init_set_features_endurance_evt_cfg(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 endgid, __u8 egcw)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_ENDURANCE_EVT_CFG, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(endgid,
				       NVME_FEAT_EG_ENDGID_SHIFT,
				       NVME_FEAT_EG_ENDGID_MASK) |
		     NVME_FIELD_ENCODE(egcw,
				       NVME_FEAT_EG_EGCW_SHIFT,
				       NVME_FEAT_EG_EGCW_MASK);
}

/**
 * nvme_init_set_features_sw_progress() - Initialize passthru command for
 * Software Pogress Marker
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @pbslc:	Pre-boot Software Load Count
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_SW_PROGRESS
 */
static inline void
nvme_init_set_features_sw_progress(struct nvme_passthru_cmd *cmd,
		bool sv, __u8 pbslc)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_SW_PROGRESS, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(pbslc,
				       NVME_FEAT_SPM_PBSLC_SHIFT,
				       NVME_FEAT_SPM_PBSLC_MASK);
}

/**
 * nvme_init_set_features_host_id() - Initialize passthru command for
 * Host Identifier
 * @cmd:        Passthru command to use
 * @sv:         Save value across power states
 * @exhid:      Enable Extended Host Identifier
 * @hostid:     Host ID buffer to set
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_HOST_ID.
 */
static inline void
nvme_init_set_features_host_id(struct nvme_passthru_cmd *cmd,
		bool sv, bool exhid, __u8 *hostid)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_HOST_ID, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(exhid,
				       NVME_FEAT_HOSTID_EXHID_SHIFT,
				       NVME_FEAT_HOSTID_EXHID_MASK);
	cmd->data_len = exhid ? 16 : 8;
	cmd->addr = (__u64)(uintptr_t)hostid;
}

/**
 * nvme_init_set_features_resv_mask() - Initialize passthru command for
 * Reservation Notification Mask
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sv:		Save value across power states
 * @mask:	Reservation Notification Mask Field
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_RESV_MASK
 */
static inline void
nvme_init_set_features_resv_mask(struct nvme_passthru_cmd *cmd, __u32 nsid,
		bool sv, __u32 mask)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_RESV_MASK, sv);
	cmd->nsid = nsid;
	cmd->cdw11 = mask;
}

/**
 * nvme_init_set_features_resv_persist() - Initialize passthru command for
 * Reservation Persistence
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sv:		Save value across power states
 * @ptpl:	Persist Through Power Loss
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_RESV_PERSIST
 */
static inline void
nvme_init_set_features_resv_persist(struct nvme_passthru_cmd *cmd, __u32 nsid,
		bool sv, bool ptpl)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_RESV_PERSIST, sv);
	cmd->nsid = nsid;
	cmd->cdw11 = NVME_FIELD_ENCODE(ptpl,
			NVME_FEAT_RESP_PTPL_SHIFT,
			NVME_FEAT_RESP_PTPL_MASK);
}

/**
 * nvme_init_set_features_write_protect() - Initialize passthru command for
 * Write Protect
 * @cmd:        Passthru command to use
 * @nsid:       Namespace ID
 * @sv:         Save value across power states
 * @wps:        Write Protection State
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_WRITE_PROTECT
 */
static inline void
nvme_init_set_features_write_protect(struct nvme_passthru_cmd *cmd, __u32 nsid,
		bool sv, enum nvme_feat_nswpcfg_state wps)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_WRITE_PROTECT, sv);
	cmd->nsid = nsid;
	cmd->cdw11 = NVME_FIELD_ENCODE(wps,
			NVME_FEAT_WP_WPS_SHIFT,
			NVME_FEAT_WP_WPS_MASK);
}

/**
 * nvme_init_set_features_iocs_profile() - Initialize passthru command for
 * I/O Command Set Profile
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @iocsci:	I/O Command Set Combination Index
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_IOCS_PROFILE
 */
static inline void
nvme_init_set_features_iocs_profile(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 iocsci)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_IOCS_PROFILE, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(iocsci,
			NVME_FEAT_IOCSP_IOCSCI_SHIFT,
			NVME_FEAT_IOCSP_IOCSCI_MASK);
}

/**
 * nvme_init_get_features() - Initialize passthru command for
 * Get Features
 * @cmd:	Passthru command to use
 * @fid:	Feature identifier, see &enum nvme_features_id
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 */
static inline void
nvme_init_get_features(struct nvme_passthru_cmd *cmd, __u8 fid,
		enum nvme_get_features_sel sel)
{
	__u32 cdw10 = NVME_FIELD_ENCODE(fid,
			NVME_GET_FEATURES_CDW10_FID_SHIFT,
			NVME_GET_FEATURES_CDW10_FID_MASK) |
		      NVME_FIELD_ENCODE(sel,
			NVME_GET_FEATURES_CDW10_SEL_SHIFT,
			NVME_GET_FEATURES_CDW10_SEL_MASK);

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode	= nvme_admin_get_features;
	cmd->cdw10	= cdw10;
}

/**
 * nvme_init_get_features_arbitration() - Initialize passthru command for
 * Get Features - Arbitration
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_ARBITRATION
 */
static inline void
nvme_init_get_features_arbitration(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_ARBITRATION, sel);
}

/**
 * nvme_init_get_features_power_mgmt() - Initialize passthru command for
 * Get Features - Power Management
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_POWER_MGMT
 */
static inline void
nvme_init_get_features_power_mgmt(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_POWER_MGMT, sel);
}

/**
 * nvme_init_get_features_lba_range() - Initialize passthru command for
 * Get Features - LBA Range
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @lrt:	Buffer to receive LBA Range Type data structure
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_LBA_RANGE
 */
static inline void
nvme_init_get_features_lba_range(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_get_features_sel sel, struct nvme_lba_range_type *lrt)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_LBA_RANGE, sel);
	cmd->nsid = nsid;
	cmd->data_len = sizeof(*lrt);
	cmd->addr = (__u64)(uintptr_t)lrt;
}

/**
 * nvme_init_get_features_temp_thresh() - Initialize passthru command for
 * Get Features - Temperature Threshold
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 * see &enum nvme_get_features_sel
 * @tmpsel:	Threshold Temperature Select
 * @thsel:	Threshold Type Select
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_TEMP_THRESH
 */
static inline void
nvme_init_get_features_temp_thresh(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel,
		__u8 tmpsel, enum nvme_feat_tmpthresh_thsel thsel)
{

	nvme_init_get_features(cmd, NVME_FEAT_FID_TEMP_THRESH, sel);
	cmd->cdw11 = NVME_FIELD_ENCODE(tmpsel,
			NVME_FEAT_TT_TMPSEL_SHIFT,
			NVME_FEAT_TT_TMPSEL_MASK) |
		     NVME_FIELD_ENCODE(thsel,
			NVME_FEAT_TT_THSEL_SHIFT,
			NVME_FEAT_TT_THSEL_MASK);
}

/**
 * nvme_init_get_features_err_recovery() - Initialize passthru command for
 * Get Features - Error Recovery
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_ERR_RECOVERY
 */
static inline void
nvme_init_get_features_err_recovery(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_ERR_RECOVERY, sel);
	cmd->nsid = nsid;
}

/**
 * nvme_init_get_features_volatile_wc() - Initialize passthru command for
 * Get Features - Volatile Write Cache
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 * see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_VOLATILE_WC
 */
static inline void
nvme_init_get_features_volatile_wc(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_VOLATILE_WC, sel);
}

/**
 * nvme_init_get_features_num_queues() - Initialize passthru command for
 * Get Features - Number of Queues
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 * see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_NUM_QUEUES
 */
static inline void
nvme_init_get_features_num_queues(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_NUM_QUEUES, sel);
}

/**
 * nvme_init_get_features_irq_coalesce() - Initialize passthru command for
 * Get Features - IRQ Coalesce
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_IRQ_COALESCE
 */
static inline void
nvme_init_get_features_irq_coalesce(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_IRQ_COALESCE, sel);
}

/**
 * nvme_init_get_features_irq_config() - Initialize passthru command for
 * Get Features - IRQ Config
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @iv:		Interrupt Vector
 * @cd:		Coalescing Disable
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_IRQ_CONFIG
 */
static inline void
nvme_init_get_features_irq_config(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel,
		__u16 iv, bool cd)
{
	__u32 cdw11 = NVME_FIELD_ENCODE(iv,
				       NVME_FEAT_ICFG_IV_SHIFT,
				       NVME_FEAT_ICFG_IV_MASK) |
		     NVME_FIELD_ENCODE(cd,
				       NVME_FEAT_ICFG_CD_SHIFT,
				       NVME_FEAT_ICFG_CD_MASK);

	nvme_init_get_features(cmd, NVME_FEAT_FID_IRQ_CONFIG, sel);
	cmd->cdw11 = cdw11;
}

/**
 * nvme_init_get_features_write_atomic() - Initialize passthru command for
 * Get Features - Write Atomic
 * @cmd:        Passthru command to use
 * @sel:        Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_WRITE_ATOMIC
 */
static inline void
nvme_init_get_features_write_atomic(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_WRITE_ATOMIC, sel);
}

/**
 * nvme_init_get_features_async_event() - Initialize passthru command for
 * Get Features - Asynchronous Event Configuration
 * @cmd:        Passthru command to use
 * @sel:        Select which type of attribute to return,
 * see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_ASYNC_EVENT
 */
static inline void
nvme_init_get_features_async_event(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_ASYNC_EVENT, sel);
}

/**
 * nvme_init_get_features_auto_pst() - Initialize passthru command for
 * Get Features - Autonomous Power State Transition
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @apst:	Autonomous Power State Transition data buffer
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_AUTO_PST
 */
static inline void
nvme_init_get_features_auto_pst(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel, struct nvme_feat_auto_pst *apst)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_AUTO_PST, sel);
	cmd->data_len = sizeof(*apst);
	cmd->addr = (__u64)(uintptr_t)apst;
}

/**
 * nvme_init_get_features_host_mem_buf() - Initialize passthru command for
 * Get Features - Host Memory Buffer
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @attrs:	Buffer for returned Host Memory Buffer Attributes
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_HOST_MEM_BUF
 */
static inline void
nvme_init_get_features_host_mem_buf(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel,
		struct nvme_host_mem_buf_attrs  *attrs)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_HOST_MEM_BUF, sel);
	cmd->data_len = sizeof(*attrs);
	cmd->addr = (__u64)(uintptr_t)attrs;
}

/**
 * nvme_init_get_features_timestamp() - Initialize passthru command for
 * Get Features - Timestamp
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @ts:		Current timestamp buffer
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_TIMESTAMP
 */
static inline void
nvme_init_get_features_timestamp(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel, struct nvme_timestamp *ts)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_TIMESTAMP, sel);
	cmd->data_len = sizeof(*ts);
	cmd->addr = (__u64)(uintptr_t)ts;
}

/**
 * nvme_init_get_features_kato() - Initialize passthru command for
 * Get Features - Keep Alive Timeout
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_KATO
 */
static inline void
nvme_init_get_features_kato(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_KATO, sel);
}

/**
 * nvme_init_get_features_hctm() - Initialize passthru command for
 * Get Features - Host Controlled Thermal Management
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_HCTM
 */
static inline void
nvme_init_get_features_hctm(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_HCTM, sel);
}

/**
 * nvme_init_get_features_nopsc() - Initialize passthru command for
 * Get Features - Non-Operational Power State Config
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_NOPSC
 */
static inline void
nvme_init_get_features_nopsc(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_NOPSC, sel);
}

/**
 * nvme_init_get_features_rrl() - Initialize passthru command for
 * Get Features - Read Recovery Level
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_RRL
 */
static inline void
nvme_init_get_features_rrl(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_RRL, sel);
}

/**
 * nvme_init_get_features_plm_config() - Initialize passthru command for
 * Get Features - Predictable Latency Mode Config
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @nvmsetid:   NVM set id
 * @plmc:       Buffer for returned Predictable Latency Mode Config
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_PLM_CONFIG
 */
static inline void
nvme_init_get_features_plm_config(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel, __u16 nvmsetid,
		struct nvme_plm_config *plmc)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_PLM_CONFIG, sel);
	cmd->cdw11 = NVME_FIELD_ENCODE(nvmsetid,
				       NVME_FEAT_PLM_NVMSETID_SHIFT,
				       NVME_FEAT_PLM_NVMSETID_MASK);
	cmd->data_len = sizeof(*plmc);
	cmd->addr = (__u64)(uintptr_t)plmc;
}

/**
 * nvme_init_get_features_plm_window() - Initialize passthru command for
 * Get Features - Predictable Latency Mode Window
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @nvmsetid:   NVM set id
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_PLM_WINDOW
 */
static inline void
nvme_init_get_features_plm_window(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel, __u16 nvmsetid)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_PLM_WINDOW, sel);
	cmd->cdw11 = NVME_FIELD_ENCODE(nvmsetid,
				       NVME_FEAT_PLM_NVMSETID_SHIFT,
				       NVME_FEAT_PLM_NVMSETID_MASK);
}

/**
 * nvme_init_get_features_lba_sts_interval() - Initialize passthru command for
 * Get Features - LBA Status Information Interval
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_LBA_STS_INTERVAL
 */
static inline void
nvme_init_get_features_lba_sts_interval(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_LBA_STS_INTERVAL, sel);
}

/**
 * nvme_init_get_features_host_behavior() - Initialize passthru command for
 * Get Features - Host Behavior
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @fhb:	Pointer to structure nvme_feat_host_behavior
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_HOST_BEHAVIOR
 */
static inline void
nvme_init_get_features_host_behavior(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel,
		struct nvme_feat_host_behavior *fhb)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_HOST_BEHAVIOR, sel);
	cmd->data_len = sizeof(*fhb);
	cmd->addr = (__u64)(uintptr_t)fhb;
}

/**
 * nvme_init_get_features_sanitize() - Initialize passthru command for
 * Get Features - Sanitize
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_SANITIZE
 */
static inline void
nvme_init_get_features_sanitize(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_SANITIZE, sel);
}

/**
 * nvme_init_get_features_endurance_event_cfg() - Initialize passthru command
 * for Get Features - Endurance Group Event Configuration
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @endgid:	Endurance Group Identifier
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_ENDURANCE_EVT_CFG
 */
static inline void
nvme_init_get_features_endurance_event_cfg(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel, __u16 endgid)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_ENDURANCE_EVT_CFG, sel);
	cmd->cdw11 = NVME_FIELD_ENCODE(endgid,
				       NVME_FEAT_EG_ENDGID_SHIFT,
				       NVME_FEAT_EG_ENDGID_MASK);
}

/**
 * nvme_init_get_features_sw_progress() - Initialize passthru command for
 * Get Features - Software Progress
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 * see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_SW_PROGRESS
 */
static inline void
nvme_init_get_features_sw_progress(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_SW_PROGRESS, sel);
}

/**
 * nvme_init_get_features_host_id() - Initialize passthru command for
 * Get Features - Host Identifier
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @exhid:	Enable Extended Host Identifier
 * @hostid:	Buffer for returned host ID
 * @len:	Length of @hostid
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_HOST_ID
 */
static inline void
nvme_init_get_features_host_id(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel, bool exhid,
		void *hostid, __u32 len)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_HOST_ID, sel);
	cmd->cdw11 = NVME_FIELD_ENCODE(exhid,
				       NVME_FEAT_HOSTID_EXHID_SHIFT,
				       NVME_FEAT_HOSTID_EXHID_MASK);
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)hostid;
}

/**
 * nvme_init_get_features_resv_mask() - Initialize passthru command for
 * Get Features - Reservation Notification Mask
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_RESV_MASK
 */
static inline void
nvme_init_get_features_resv_mask(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_RESV_MASK, sel);
	cmd->nsid = nsid;
}

/**
 * nvme_init_get_features_resv_persist() - Initialize passthru command for
 * Get Features - Reservation Persistence
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_RESV_PERSIST
 */
static inline void
nvme_init_get_features_resv_persist(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_RESV_PERSIST, sel);
	cmd->nsid = nsid;
}

/**
 * nvme_init_get_features_write_protect() - Initialize passthru command for
 * Get Features - Write Protect
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_WRITE_PROTECT
 */
static inline void
nvme_init_get_features_write_protect(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_WRITE_PROTECT, sel);
	cmd->nsid = nsid;
}

/**
 * nvme_init_get_features_iocs_profile() - Initialize passthru command for
 * Get Features - I/O Command Set Profile
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_IOCS_PROFILE
 */
static inline void
nvme_init_get_features_iocs_profile(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_IOCS_PROFILE, sel);
}

/**
 * nvme_init_format_nvm() - Initialize passthru command for Format NVM
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to format
 * @lbaf:	Logical block address format
 * @mset:	Metadata settings (extended or separated)
 * @pi:		Protection information type
 * @pil:	Protection information location (beginning or end)
 * @ses:	Secure erase settings
 *
 * Initializes the passthru command buffer for the Format NVM command.
 */
static inline void
nvme_init_format_nvm(struct nvme_passthru_cmd *cmd, __u32 nsid, __u8 lbaf,
		enum nvme_cmd_format_mset mset, enum nvme_cmd_format_pi pi,
		enum nvme_cmd_format_pil pil, enum nvme_cmd_format_ses ses)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_format_nvm;
	cmd->nsid = nsid;
	cmd->cdw10 = NVME_FIELD_ENCODE(lbaf,
			NVME_FORMAT_CDW10_LBAFL_SHIFT,
			NVME_FORMAT_CDW10_LBAFL_MASK) |
		      NVME_FIELD_ENCODE(mset,
			NVME_FORMAT_CDW10_MSET_SHIFT,
			NVME_FORMAT_CDW10_MSET_MASK) |
		      NVME_FIELD_ENCODE(pi,
			NVME_FORMAT_CDW10_PI_SHIFT,
			NVME_FORMAT_CDW10_PI_MASK) |
		      NVME_FIELD_ENCODE(pil,
			NVME_FORMAT_CDW10_PIL_SHIFT,
			NVME_FORMAT_CDW10_PIL_MASK) |
		      NVME_FIELD_ENCODE(ses,
			NVME_FORMAT_CDW10_SES_SHIFT,
			NVME_FORMAT_CDW10_SES_MASK) |
		      NVME_FIELD_ENCODE((lbaf >> 4),
			NVME_FORMAT_CDW10_LBAFU_SHIFT,
			NVME_FORMAT_CDW10_LBAFU_MASK);
}

/**
 * nvme_init_ns_mgmt() - Initialize passthru command for Namespace Management
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @sel:	Type of management operation to perform
 * @csi:	Command Set Identifier
 * @data:	Host Software Specified Fields buffer
 *
 * Initializes the passthru command buffer for the Namespace Management command.
 */
static inline void
nvme_init_ns_mgmt(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_ns_mgmt_sel sel, __u8 csi,
		struct nvme_ns_mgmt_host_sw_specified *data)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_ns_mgmt;
	cmd->nsid = nsid;
	cmd->data_len = data ? sizeof(*data) : 0;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(sel,
			NVME_NAMESPACE_MGMT_CDW10_SEL_SHIFT,
			NVME_NAMESPACE_MGMT_CDW10_SEL_MASK);
	cmd->cdw11 = NVME_FIELD_ENCODE(csi,
			NVME_NAMESPACE_MGMT_CDW11_CSI_SHIFT,
			NVME_NAMESPACE_MGMT_CDW11_CSI_MASK);
}

/**
 * nvme_init_ns_mgmt_create() - Initialize passthru command to create a
 * non attached namespace
 * @cmd:	Passthru command to use
 * @csi:	Command Set Identifier
 * @data:	Host Software Specified Fields buffer that defines NS
 *		creation parameters
 *
 * Initializes the passthru command buffer for the Namespace Management - Create
 * command. The command uses NVME_NSID_NONE as the target NSID.
 */
static inline void
nvme_init_ns_mgmt_create(struct nvme_passthru_cmd *cmd, __u8 csi,
		struct nvme_ns_mgmt_host_sw_specified *data)
{
	nvme_init_ns_mgmt(cmd, NVME_NSID_NONE, NVME_NS_MGMT_SEL_CREATE,
		csi, data);
}

/**
 * nvme_init_ns_mgmt_delete() - Initialize passthru command to delete a
 * non attached namespace
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier to delete
 *
 * Initializes the passthru command buffer for the Namespace Management - Delete
 * command (NVME_NS_MGMT_SEL_DELETE). The command uses the provided @nsid as
 * the target NSID.
 */
static inline void
nvme_init_ns_mgmt_delete(struct nvme_passthru_cmd *cmd, __u32 nsid)
{
	nvme_init_ns_mgmt(cmd, nsid, NVME_NS_MGMT_SEL_DELETE,
		NVME_CSI_NVM, NULL);
}

/**
 * nvme_init_ns_attach() - Initialize passthru command for
 * Namespace Attach/Detach
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to execute attach selection
 * @sel:	Attachment selection, see &enum nvme_ns_attach_sel
 * @ctrlist:	Controller list buffer to modify attachment state of nsid
 *
 * Initializes the passthru command buffer for the Namespace Attach/Detach
 * command.
 */
static inline void
nvme_init_ns_attach(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_ns_attach_sel sel, struct nvme_ctrl_list *ctrlist)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_ns_attach;
	cmd->nsid = nsid;
	cmd->data_len = sizeof(*ctrlist);
	cmd->addr = (__u64)(uintptr_t)ctrlist;
	cmd->cdw10 = NVME_FIELD_ENCODE(sel,
			NVME_NAMESPACE_ATTACH_CDW10_SEL_SHIFT,
			NVME_NAMESPACE_ATTACH_CDW10_SEL_MASK);
}

/**
 * nvme_init_ns_attach_ctrls() - Initialize passthru command to attach
 * namespace to controllers
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to attach
 * @ctrlist:	Controller list buffer to modify attachment state of nsid
 *
 * Initializes the passthru command buffer for the Namespace Attach command
 * (NVME_NS_ATTACH_SEL_CTRL_ATTACH).
 */
static inline void
nvme_init_ns_attach_ctrls(struct nvme_passthru_cmd *cmd, __u32 nsid,
		struct nvme_ctrl_list *ctrlist)
{
	nvme_init_ns_attach(cmd, nsid, NVME_NS_ATTACH_SEL_CTRL_ATTACH,
		ctrlist);
}

/**
 * nvme_init_ns_detach_ctrls() - Initialize passthru command to detach
 * namespace from controllers
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to detach
 * @ctrlist:	Controller list buffer to modify attachment state of nsid
 *
 * Initializes the passthru command buffer for the Namespace Detach command
 * (NVME_NS_ATTACH_SEL_CTRL_DEATTACH).
 */
static inline void
nvme_init_ns_detach_ctrls(struct nvme_passthru_cmd *cmd, __u32 nsid,
		struct nvme_ctrl_list *ctrlist)
{
	nvme_init_ns_attach(cmd, nsid, NVME_NS_ATTACH_SEL_CTRL_DEATTACH,
		ctrlist);
}

/**
 * nvme_init_fw_download() - Initialize passthru command to download part or
 * all of a firmware image to the controller
 * @cmd:	Passthru command to use
 * @data:	Userspace address of the firmware data buffer
 * @len:	Length of data in this command in bytes
 * @offset:	Offset in the firmware data
 *
 * Initializes the passthru command buffer for the Firmware Image
 * Download command.
 *
 * Note: Caller must ensure data_len and offset are DWord-aligned (0x4).
 *
 * Returns: 0 on success, or error code if arguments are invalid.
 */
static inline int
nvme_init_fw_download(struct nvme_passthru_cmd *cmd, void *data,
		__u32 len, __u32 offset)
{
	if (len & 0x3 || !len)
		return -EINVAL;

	if (offset & 0x3)
		return -EINVAL;

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_fw_download;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = (len >> 2) - 1;
	cmd->cdw11 = offset >> 2;

	return 0;
}

/**
 * nvme_init_fw_commit() - Initialize passthru command to commit firmware
 * using the specified action
 * @cmd:	Passthru command to use
 * @fs:		Firmware slot to commit the downloaded image
 * @ca:		Action to use for the firmware image,
 *		see &enum nvme_fw_commit_ca
 * @bpid:	Set to true to select the boot partition id
 *
 * Initializes the passthru command buffer for the Firmware Commit command.
 */
static inline void
nvme_init_fw_commit(struct nvme_passthru_cmd *cmd, __u8 fs,
		    enum nvme_fw_commit_ca ca, bool bpid)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_fw_commit;
	cmd->cdw10 = NVME_FIELD_ENCODE(fs,
			NVME_FW_COMMIT_CDW10_FS_SHIFT,
			NVME_FW_COMMIT_CDW10_FS_MASK) |
		      NVME_FIELD_ENCODE(ca,
			NVME_FW_COMMIT_CDW10_CA_SHIFT,
			NVME_FW_COMMIT_CDW10_CA_MASK) |
		      NVME_FIELD_ENCODE(bpid,
			NVME_FW_COMMIT_CDW10_BPID_SHIFT,
			NVME_FW_COMMIT_CDW10_BPID_MASK);
}

/**
 * nvme_init_security_send() - Initialize passthru command for Security Send
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to issue security command on
 * @nssf:	NVMe Security Specific field
 * @spsp:	Security Protocol Specific field
 * @secp:	Security Protocol
 * @tl:		Protocol specific transfer length
 * @data:	Security data payload buffer to send
 * @len:	Data length of the payload in bytes
 *
 * Initializes the passthru command buffer for the Security Send command.
 */
static inline void
nvme_init_security_send(struct nvme_passthru_cmd *cmd, __u32 nsid, __u8 nssf,
		__u16 spsp, __u8 secp, __u32 tl, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_security_send;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(secp,
			NVME_SECURITY_SECP_SHIFT,
			NVME_SECURITY_SECP_MASK) |
		      NVME_FIELD_ENCODE(spsp,
			NVME_SECURITY_SPSP0_SHIFT,
			NVME_SECURITY_SPSP0_MASK) |
		      NVME_FIELD_ENCODE(spsp >> 8,
			NVME_SECURITY_SPSP1_SHIFT,
			NVME_SECURITY_SPSP1_MASK) |
		      NVME_FIELD_ENCODE(nssf,
			NVME_SECURITY_NSSF_SHIFT,
			NVME_SECURITY_NSSF_MASK);
	cmd->cdw11 = tl;
}

/**
 * nvme_init_security_receive() - Initialize passthru command for
 * Security Receive
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to issue security command on
 * @nssf:	NVMe Security Specific field
 * @spsp:	Security Protocol Specific field
 * @secp:	Security Protocol
 * @al:		Protocol specific allocation length
 * @data:	Security data payload buffer to receive data into
 * @len:	Data length of the payload in bytes (must match @al)
 *
 * Initializes the passthru command buffer for the Security Receive command.
 */
static inline void
nvme_init_security_receive(struct nvme_passthru_cmd *cmd, __u32 nsid, __u8 nssf,
		__u16 spsp, __u8 secp, __u32 al, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_security_recv;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(secp,
			NVME_SECURITY_SECP_SHIFT,
			NVME_SECURITY_SECP_MASK) |
		     NVME_FIELD_ENCODE(spsp,
			NVME_SECURITY_SPSP0_SHIFT,
			NVME_SECURITY_SPSP0_MASK) |
		     NVME_FIELD_ENCODE(spsp >> 8,
			NVME_SECURITY_SPSP1_SHIFT,
			NVME_SECURITY_SPSP1_MASK) |
		     NVME_FIELD_ENCODE(nssf,
			NVME_SECURITY_NSSF_SHIFT,
			NVME_SECURITY_NSSF_MASK);
	cmd->cdw11 = al;
}

/**
 * nvme_init_get_lba_status() - Initialize passthru command to retrieve
 * information on possibly unrecoverable LBAs
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to retrieve LBA status
 * @slba:	Starting logical block address to check statuses
 * @mndw:	Maximum number of dwords to return
 * @atype:	Action type mechanism to determine LBA status descriptors to
 *		return, see &enum nvme_lba_status_atype
 * @rl:		Range length from slba to perform the action
 * @lbas:	Data payload buffer to return status descriptors
 *
 * Initializes the passthru command buffer for the Get LBA Status command.
 */
static inline void
nvme_init_get_lba_status(struct nvme_passthru_cmd *cmd, __u32 nsid, __u64 slba,
		__u32 mndw, enum nvme_lba_status_atype atype, __u16 rl,
		struct nvme_lba_status *lbas)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_get_lba_status;
	cmd->nsid = nsid;
	cmd->data_len = (mndw + 1) << 2;
	cmd->addr = (__u64)(uintptr_t)lbas;
	cmd->cdw10 = slba & 0xffffffff;
	cmd->cdw11 = slba >> 32;
	cmd->cdw12 = mndw;
	cmd->cdw13 = NVME_FIELD_ENCODE(rl,
			NVME_GET_LBA_STATUS_CDW13_RL_SHIFT,
			NVME_GET_LBA_STATUS_CDW13_RL_MASK) |
		     NVME_FIELD_ENCODE(atype,
			NVME_GET_LBA_STATUS_CDW13_ATYPE_SHIFT,
			NVME_GET_LBA_STATUS_CDW13_ATYPE_MASK);
}

/**
 * nvme_init_directive_send() - Initialize passthru command for Directive Send
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID, if applicable
 * @doper:	Directive send operation, see &enum nvme_directive_send_doper
 * @dtype:	Directive type, see &enum nvme_directive_dtype
 * @dspec:	Directive specific field
 * @data:	Data payload buffer to be send
 * @len:	Length of data payload in bytes
 *
 * Initializes the passthru command buffer for the Directive Send command.
 */
static inline void
nvme_init_directive_send(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_directive_send_doper doper,
		enum nvme_directive_dtype dtype, __u16 dspec,
		void *data, __u32 len)
{

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_directive_send;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = len ? (len >> 2) - 1 : 0;
	cmd->cdw11 = NVME_FIELD_ENCODE(doper,
			NVME_DIRECTIVE_CDW11_DOPER_SHIFT,
			NVME_DIRECTIVE_CDW11_DOPER_MASK) |
		      NVME_FIELD_ENCODE(dtype,
			NVME_DIRECTIVE_CDW11_DTYPE_SHIFT,
			NVME_DIRECTIVE_CDW11_DTYPE_MASK) |
		      NVME_FIELD_ENCODE(dspec,
			NVME_DIRECTIVE_CDW11_DPSEC_SHIFT,
			NVME_DIRECTIVE_CDW11_DPSEC_MASK);
}

/**
 * nvme_init_directive_send_id_endir() - Initialize passthru command for
 * Directive Send Enable Directive
 * @cmd:	Passthru command to use
 * @nsid:	Namespace Identifier
 * @endir:	Enable Directive
 * @dtype:	Directive Type
 * @id:		Pointer to structure nvme_id_directives
 *
 * Initializes the passthru command buffer for the Directive Send - Identify
 * (Enable Directive) command.
 */
static inline void
nvme_init_directive_send_id_endir(struct nvme_passthru_cmd *cmd, __u32 nsid,
		 bool endir, enum nvme_directive_dtype dtype,
		 struct nvme_id_directives *id)
{
	nvme_init_directive_send(cmd, nsid,
		NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR,
		NVME_DIRECTIVE_DTYPE_IDENTIFY, 0, id, sizeof(*id));
	cmd->cdw12 = NVME_FIELD_ENCODE(dtype,
			NVME_DIRECTIVE_SEND_IDENTIFY_CDW12_DTYPE_SHIFT,
			NVME_DIRECTIVE_SEND_IDENTIFY_CDW12_DTYPE_MASK) |
		     NVME_FIELD_ENCODE(endir,
			NVME_DIRECTIVE_SEND_IDENTIFY_CDW12_ENDIR_SHIFT,
			NVME_DIRECTIVE_SEND_IDENTIFY_CDW12_ENDIR_MASK);
}

/**
 * nvme_init_directive_send_stream_release_identifier() - Initialize passthru
 * command for Directive Send Stream release identifier
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @stream_id:	Stream identifier
 *
 * Initializes the passthru command buffer for the Directive Send - Stream
 * Release Identifier command.
 */
static inline void
nvme_init_directive_send_stream_release_identifier(
		struct nvme_passthru_cmd *cmd,
		__u32 nsid, __u16 stream_id)
{
	nvme_init_directive_send(cmd, nsid,
		NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER,
		NVME_DIRECTIVE_DTYPE_STREAMS, stream_id, NULL, 0);
}

/**
 * nvme_init_directive_send_stream_release_resource() - Initialize passthru
 * command for Directive Send Stream release resources
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 *
 * Initializes the passthru command buffer for the Directive Send - Stream
 * Release Resource command.
 */
static inline void
nvme_init_directive_send_stream_release_resource(struct nvme_passthru_cmd *cmd,
		__u32 nsid)
{
	nvme_init_directive_send(cmd, nsid,
		NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE,
		NVME_DIRECTIVE_DTYPE_STREAMS, 0, NULL, 0);
}

/**
 * nvme_init_directive_recv() - Initialize passthru command for
 * Directive Receive
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID, if applicable
 * @doper:	Directive receive operation,
 *		see &enum nvme_directive_receive_doper
 * @dtype:	Directive type, see &enum nvme_directive_dtype
 * @dspec:	Directive specific field
 * @data:	Userspace address of data payload buffer
 * @len:	Length of data payload in bytes
 *
 * Initializes the passthru command buffer for the Directive Receive command.
 */
static inline void
nvme_init_directive_recv(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_directive_receive_doper doper,
		enum nvme_directive_dtype dtype, __u16 dspec,
		void *data, __u32 len)
{

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_directive_recv;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = len ? (len >> 2) - 1 : 0;
	cmd->cdw11 = NVME_FIELD_ENCODE(doper,
			NVME_DIRECTIVE_CDW11_DOPER_SHIFT,
			NVME_DIRECTIVE_CDW11_DOPER_MASK) |
		      NVME_FIELD_ENCODE(dtype,
			NVME_DIRECTIVE_CDW11_DTYPE_SHIFT,
			NVME_DIRECTIVE_CDW11_DTYPE_MASK) |
		      NVME_FIELD_ENCODE(dspec,
			NVME_DIRECTIVE_CDW11_DPSEC_SHIFT,
			NVME_DIRECTIVE_CDW11_DPSEC_MASK);
}

/**
 * nvme_init_directive_recv_identify_parameters() - Initialize passthru command
 * for Directive Receive Identify Parameters
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @id:		Identify parameters buffer
 *
 * Initializes the passthru command buffer for the Directive Receive - Identify
 * Parameters command.
 */
static inline void
nvme_init_directive_recv_identify_parameters(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_id_directives *id)
{
	nvme_init_directive_recv(cmd, nsid,
		NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM,
		NVME_DIRECTIVE_DTYPE_IDENTIFY, 0, id, sizeof(*id));
}

/**
 * nvme_init_directive_recv_stream_parameters() - Initialize passthru command
 * for Directive Receive Stream Parameters
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @parms:	Streams directive parameters buffer
 *
 * Initializes the passthru command buffer for the Directive Receive - Stream
 * Parameters command.
 */
static inline void
nvme_init_directive_recv_stream_parameters(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_streams_directive_params *parms)
{
	nvme_init_directive_recv(cmd, nsid,
		NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM,
		NVME_DIRECTIVE_DTYPE_STREAMS, 0, parms, sizeof(*parms));
}

/**
 * nvme_init_directive_recv_stream_status() - Initialize passthru command for
 * Directive Receive Stream Status
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @nr_entries: Number of streams to receive
 * @id:		Stream status buffer
 *
 * Initializes the passthru command buffer for the Directive Receive - Stream
 * Status command.
 *
 * Return: 0 on success, or error code if arguments are invalid.
 */
static inline int
nvme_init_directive_recv_stream_status(struct nvme_passthru_cmd *cmd,
		__u32 nsid, unsigned int nr_entries,
		struct nvme_streams_directive_status *id)
{
	if (nr_entries > NVME_STREAM_ID_MAX)
		return -EINVAL;

	nvme_init_directive_recv(cmd, nsid,
		NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS,
		NVME_DIRECTIVE_DTYPE_STREAMS, 0, id,
		(__u32)(sizeof(*id) + nr_entries * sizeof(__le16)));

	return 0;
}

/**
 * nvme_init_directive_recv_stream_allocate() - Initialize passthru command for
 * Directive Receive Stream Allocate
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @nsr:	Namespace Streams Requested
 *
 * Initializes the passthru command buffer for the Directive Receive - Stream
 * Allocate command.
 */
static inline void
nvme_init_directive_recv_stream_allocate(struct nvme_passthru_cmd *cmd,
		__u32 nsid, __u16 nsr)
{
	nvme_init_directive_recv(cmd, nsid,
		NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE,
		NVME_DIRECTIVE_DTYPE_STREAMS, 0, NULL, 0);
	cmd->cdw12 = nsr;
}

/**
 * nvme_init_capacity_mgmt() - Initialize passthru command for
 * Capacity Management
 * @cmd:	Passthru command to use
 * @oper:	Operation to be performed by the controller
 * @elid:	Value specific to the value of the Operation field
 * @cap:	Capacity in bytes of the Endurance Group or NVM Set to
 *		be created
 *
 * Initializes the passthru command buffer for the Capacity Management command.
 */
static inline void
nvme_init_capacity_mgmt(struct nvme_passthru_cmd *cmd,
		__u8 oper, __u16 elid, __u64 cap)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_capacity_mgmt;
	cmd->cdw10 = NVME_FIELD_ENCODE(oper,
			NVME_CAPACITY_MGMT_CDW10_OPER_SHIFT,
			NVME_CAPACITY_MGMT_CDW10_OPER_MASK) |
		      NVME_FIELD_ENCODE(elid,
			NVME_CAPACITY_MGMT_CDW10_ELID_SHIFT,
			NVME_CAPACITY_MGMT_CDW10_ELID_MASK);
	cmd->cdw11 = NVME_FIELD_ENCODE(cap,
			NVME_CAPACITY_MGMT_CDW11_CAPL_SHIFT,
			NVME_CAPACITY_MGMT_CDW11_CAPL_MASK);
	cmd->cdw12 = NVME_FIELD_ENCODE(cap >> 32,
			NVME_CAPACITY_MGMT_CDW12_CAPU_SHIFT,
			NVME_CAPACITY_MGMT_CDW12_CAPU_MASK);
}

 /**
  * nvme_init_lockdown() - Initialize passthru command for Lockdown
  * @cmd:	Passthru command to use
  * @scp:	Scope of the command
  * @prhbt:	Prohibit or allow the command opcode or Set Features command
  * @ifc:	Affected interface
  * @ofi:	Opcode or Feature Identifier
  * @uidx:	UUID Index if controller supports this id selection method
  *
  * Initializes the passthru command buffer for the Lockdown command.
  */
static inline void
nvme_init_lockdown(struct nvme_passthru_cmd *cmd, __u8 scp, __u8 prhbt,
		__u8 ifc, __u8 ofi, __u8 uidx)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_lockdown;
	cmd->cdw10 = NVME_FIELD_ENCODE(ofi,
			NVME_LOCKDOWN_CDW10_OFI_SHIFT,
			NVME_LOCKDOWN_CDW10_OFI_MASK) |
		      NVME_FIELD_ENCODE(ifc,
			NVME_LOCKDOWN_CDW10_IFC_SHIFT,
			NVME_LOCKDOWN_CDW10_IFC_MASK) |
		      NVME_FIELD_ENCODE(prhbt,
			NVME_LOCKDOWN_CDW10_PRHBT_SHIFT,
			NVME_LOCKDOWN_CDW10_PRHBT_MASK) |
		      NVME_FIELD_ENCODE(scp,
			NVME_LOCKDOWN_CDW10_SCP_SHIFT,
			NVME_LOCKDOWN_CDW10_SCP_MASK);
	cmd->cdw14 = NVME_FIELD_ENCODE(uidx,
			NVME_LOCKDOWN_CDW14_UIDX_SHIFT,
			NVME_LOCKDOWN_CDW14_UIDX_MASK);
}

/**
 * nvme_init_set_property() - Initialize passthru command to set
 * controller property
 * @cmd:	Passthru command to use
 * @offset:	Property offset from the base to set
 * @value:	The value to set the property
 *
 * Initializes the passthru command buffer for the Fabrics Set Property command.
 * This is an NVMe-over-Fabrics specific command.
 */
static inline void
nvme_init_set_property(struct nvme_passthru_cmd *cmd, __u32 offset, __u64 value)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_fabrics;
	cmd->nsid = nvme_fabrics_type_property_set;
	cmd->cdw10 = nvme_is_64bit_reg(offset);
	cmd->cdw11 = (__u32)offset;
	cmd->cdw12 = (__u32)(value & 0xffffffff);
	cmd->cdw13 = (__u32)(value >> 32);
}

/**
 * nvme_init_get_property() - Initialize passthru command to get
 * a controller property
 * @cmd:	Passthru command to use
 * @offset:	Property offset from the base to retrieve
 *
 * Initializes the passthru command buffer for the Fabrics Get Property command.
 * This is an NVMe-over-Fabrics specific command.
 */
static inline void
nvme_init_get_property(struct nvme_passthru_cmd *cmd, __u32 offset)
{

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_fabrics;
	cmd->nsid = nvme_fabrics_type_property_get;
	cmd->cdw10 = nvme_is_64bit_reg(offset);
	cmd->cdw11 = (__u32)offset;
}

/**
 * nvme_init_sanitize_nvm() - Initialize passthru command to start a
 * sanitize operation
 * @cmd:	Passthru command to use
 * @sanact:	Sanitize action, see &enum nvme_sanitize_sanact
 * @ause:	Set to allow unrestricted sanitize exit
 * @owpass:	Overwrite pass count
 * @oipbp:	Set to overwrite invert pattern between passes
 * @ndas:	Set to not deallocate blocks after sanitizing
 * @emvs:	Set to enter media verification state
 * @ovrpat:	Overwrite pattern
 *
 * Initializes the passthru command buffer for the Sanitize NVM command.
 */
static inline void
nvme_init_sanitize_nvm(struct nvme_passthru_cmd *cmd,
		enum nvme_sanitize_sanact sanact, bool ause, __u8 owpass,
		bool oipbp, bool ndas, bool emvs, __u32 ovrpat)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_sanitize_nvm;
	cmd->cdw10 = NVME_FIELD_ENCODE(sanact,
			NVME_SANITIZE_CDW10_SANACT_SHIFT,
			NVME_SANITIZE_CDW10_SANACT_MASK) |
		      NVME_FIELD_ENCODE(ause,
			NVME_SANITIZE_CDW10_AUSE_SHIFT,
			NVME_SANITIZE_CDW10_AUSE_MASK) |
		      NVME_FIELD_ENCODE(owpass,
			NVME_SANITIZE_CDW10_OWPASS_SHIFT,
			NVME_SANITIZE_CDW10_OWPASS_MASK) |
		      NVME_FIELD_ENCODE(oipbp,
			NVME_SANITIZE_CDW10_OIPBP_SHIFT,
			NVME_SANITIZE_CDW10_OIPBP_MASK) |
		      NVME_FIELD_ENCODE(ndas,
			NVME_SANITIZE_CDW10_NDAS_SHIFT,
			NVME_SANITIZE_CDW10_NDAS_MASK) |
		      NVME_FIELD_ENCODE(emvs,
			NVME_SANITIZE_CDW10_EMVS_SHIFT,
			NVME_SANITIZE_CDW10_EMVS_MASK);
	cmd->cdw11 = ovrpat;
}

/**
 * nvme_init_sanitize_ns() - Initialize passthru command to start a
 * sanitize namespace operation
 * @cmd:	Passthru command to use
 * @sanact:	Sanitize action, see &enum nvme_sanitize_sanact
 * @ause:	Set to allow unrestricted sanitize exit
 * @emvs:	Set to enter media verification state
 *
 * Initializes the passthru command buffer for the Sanitize namespace command.
 */
static inline void
nvme_init_sanitize_ns(struct nvme_passthru_cmd *cmd,
		enum nvme_sanitize_sanact sanact, bool ause, bool emvs)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_sanitize_ns;
	cmd->cdw10 = NVME_FIELD_ENCODE(sanact,
			NVME_SANITIZE_CDW10_SANACT_SHIFT,
			NVME_SANITIZE_CDW10_SANACT_MASK) |
		      NVME_FIELD_ENCODE(ause,
			NVME_SANITIZE_CDW10_AUSE_SHIFT,
			NVME_SANITIZE_CDW10_AUSE_MASK) |
		      NVME_FIELD_ENCODE(emvs,
			NVME_SANITIZE_CDW10_EMVS_SHIFT,
			NVME_SANITIZE_CDW10_EMVS_MASK);
}

/**
 * nvme_init_dev_self_test() - Initialize passthru command to start or
 * abort a self test
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to test
 * @stc:	Self test code, see &enum nvme_dst_stc
 *
 * Initializes the passthru command buffer for the Device Self-test command.
 */
static inline void
nvme_init_dev_self_test(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_dst_stc stc)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_dev_self_test;
	cmd->nsid = nsid;
	cmd->cdw10 = NVME_FIELD_ENCODE(stc,
			NVME_DEVICE_SELF_TEST_CDW10_STC_SHIFT,
			NVME_DEVICE_SELF_TEST_CDW10_STC_MASK);
}

/**
 * nvme_init_virtual_mgmt() - Initialize passthru command for
 * Virtualization Resource Management
 * @cmd:	Passthru command to use
 * @act:	Virtual resource action, see &enum nvme_virt_mgmt_act
 * @rt:		Resource type to modify, see &enum nvme_virt_mgmt_rt
 * @cntlid:	Controller id for which resources are bing modified
 * @nr:		Number of resources being allocated or assigned
 *
 * Initializes the passthru command buffer for the Virtualization
 * Management command.
 */
static inline void
nvme_init_virtual_mgmt(struct nvme_passthru_cmd *cmd,
		enum nvme_virt_mgmt_act act, enum nvme_virt_mgmt_rt rt,
		__u16 cntlid, __u16 nr)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->opcode = nvme_admin_virtual_mgmt;
	cmd->cdw10 = NVME_FIELD_ENCODE(act,
			NVME_VIRT_MGMT_CDW10_ACT_SHIFT,
			NVME_VIRT_MGMT_CDW10_ACT_MASK) |
		     NVME_FIELD_ENCODE(rt,
			NVME_VIRT_MGMT_CDW10_RT_SHIFT,
			NVME_VIRT_MGMT_CDW10_RT_MASK) |
		     NVME_FIELD_ENCODE(cntlid,
			NVME_VIRT_MGMT_CDW10_CNTLID_SHIFT,
			NVME_VIRT_MGMT_CDW10_CNTLID_MASK);
	cmd->cdw11 = NVME_FIELD_ENCODE(nr,
			NVME_VIRT_MGMT_CDW11_NR_SHIFT,
			NVME_VIRT_MGMT_CDW11_NR_MASK);
}

/**
 * nvme_init_flush() - Initialize passthru command for Flush command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 *
 * The Flush command requests that the contents of volatile write cache be made
 * non-volatile.
 *
 * Initializes the passthru command buffer for the Flush command.
 */
static inline void
nvme_init_flush(struct nvme_passthru_cmd *cmd, __u32 nsid)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->opcode = nvme_cmd_flush;
	cmd->nsid = nsid;
}

/**
 * nvme_init_dsm() - Initialize passthru command for
 * NVMEe I/O Data Set Management
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @nr:		Number of block ranges in the data set management attributes
 * @idr:	DSM Integral Dataset for Read attribute
 * @idw:	DSM Integral Dataset for Write attribute
 * @ad:		DSM Deallocate attribute
 * @data:	User space destination address to transfer the data
 * @len:	Length of provided user buffer to hold the log data in bytes
 */
static inline void
nvme_init_dsm(struct nvme_passthru_cmd *cmd,
		__u32 nsid, __u16 nr, __u8 idr, __u8 idw, __u8 ad, void *data,
		__u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode	= nvme_cmd_dsm;
	cmd->nsid	= nsid;
	cmd->data_len	= len;
	cmd->addr	= (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(nr - 1,
			NVME_DSM_CDW10_NR_SHIFT,
			NVME_DSM_CDW10_NR_MASK);
	cmd->cdw11 = NVME_FIELD_ENCODE(idr,
			NVME_DSM_CDW11_IDR_SHIFT,
			NVME_DSM_CDW11_IDR_MASK) |
		      NVME_FIELD_ENCODE(idw,
			NVME_DSM_CDW11_IDW_SHIFT,
			NVME_DSM_CDW11_IDW_MASK) |
		      NVME_FIELD_ENCODE(ad,
			NVME_DSM_CDW11_AD_SHIFT,
			NVME_DSM_CDW11_AD_MASK);
}

/**
 * nvme_init_var_size_tags() - Initialize Command Dword fields
 * for Extended LBA based on Variable Sized Tags
 * @cmd:	Passthru command to use
 * @pif:	Protection information format, determines tag placement
 * @sts:	Storage tag size in bits
 * @reftag:	Expected Initial Logical Block Reference Tag (EILBRT)
 * @storage_tag: Expected Logical Block Storage Tag (ELBST)
 *
 * Initializes the passthru command buffer fields cdw2, cdw3, and cdw14
 * for commands supporting Extended LBA. This logic is usually called from
 * the command-specific init function (like nvme_init_zns_append).
 */
static inline int
nvme_init_var_size_tags(struct nvme_passthru_cmd *cmd,
		__u8 pif, __u8 sts, __u64 reftag, __u64 storage_tag)
{
	__u32 cdw2 = 0, cdw3 = 0, cdw14 = 0;

	switch (pif) {
	case NVME_NVM_PIF_16B_GUARD:
		cdw14 = NVME_FIELD_ENCODE(reftag,
				NVME_IOCS_COMMON_CDW14_ELBTL_SHIFT,
				NVME_IOCS_COMMON_CDW14_ELBTL_MASK);
		cdw14 |= NVME_FIELD_ENCODE(storage_tag << (32 - sts),
				NVME_IOCS_COMMON_CDW14_ELBTL_SHIFT,
				NVME_IOCS_COMMON_CDW14_ELBTL_MASK);
		break;
	case NVME_NVM_PIF_32B_GUARD:
		cdw14 = NVME_FIELD_ENCODE(reftag,
				NVME_IOCS_COMMON_CDW14_ELBTL_SHIFT,
				NVME_IOCS_COMMON_CDW14_ELBTL_MASK);
		cdw3 = NVME_FIELD_ENCODE(reftag >> 32,
				NVME_IOCS_COMMON_CDW3_ELBTU_SHIFT,
				NVME_IOCS_COMMON_CDW3_ELBTU_MASK);
		cdw14 |= NVME_FIELD_ENCODE(
				(storage_tag << (80 - sts)) & 0xffff0000,
				NVME_IOCS_COMMON_CDW14_ELBTL_SHIFT,
				NVME_IOCS_COMMON_CDW14_ELBTL_MASK);
		if (sts >= 48)
			cdw3 |= NVME_FIELD_ENCODE(storage_tag >> (sts - 48),
					NVME_IOCS_COMMON_CDW3_ELBTU_SHIFT,
					NVME_IOCS_COMMON_CDW3_ELBTU_MASK);
		else
			cdw3 |= NVME_FIELD_ENCODE(storage_tag << (48 - sts),
					NVME_IOCS_COMMON_CDW3_ELBTU_SHIFT,
					NVME_IOCS_COMMON_CDW3_ELBTU_MASK);
		cdw2 = NVME_FIELD_ENCODE(storage_tag >> (sts - 16),
			NVME_IOCS_COMMON_CDW2_ELBTU_SHIFT,
			NVME_IOCS_COMMON_CDW2_ELBTU_MASK);
		break;
	case NVME_NVM_PIF_64B_GUARD:
		cdw14 = NVME_FIELD_ENCODE(reftag,
				NVME_IOCS_COMMON_CDW14_ELBTL_SHIFT,
				NVME_IOCS_COMMON_CDW14_ELBTL_MASK);
		cdw3 = NVME_FIELD_ENCODE((reftag >> 32) & 0xffff,
				NVME_IOCS_COMMON_CDW3_ELBTU_SHIFT,
				NVME_IOCS_COMMON_CDW3_ELBTU_MASK);
		cdw14 |= NVME_FIELD_ENCODE(storage_tag << (48 - sts),
				NVME_IOCS_COMMON_CDW14_ELBTL_SHIFT,
				NVME_IOCS_COMMON_CDW14_ELBTL_MASK);
		if (sts >= 16)
			cdw3 |= NVME_FIELD_ENCODE(
					(storage_tag >> (sts - 16)) & 0xffff,
					NVME_IOCS_COMMON_CDW3_ELBTU_SHIFT,
					NVME_IOCS_COMMON_CDW3_ELBTU_MASK);
		else
			cdw3 |= NVME_FIELD_ENCODE(
					(storage_tag << (16 - sts)) & 0xffff,
					NVME_IOCS_COMMON_CDW3_ELBTU_SHIFT,
					NVME_IOCS_COMMON_CDW3_ELBTU_MASK);
		break;
	default:
		return -EINVAL;
	}

	cmd->cdw2 = cdw2;
	cmd->cdw3 = cdw3;
	cmd->cdw14 = cdw14;

	return 0;
}

/**
 * nvme_init_app_tag() - Initialize Command Dword fields for
 * Logical Block Application Tag/Mask
 * @cmd:	Passthru command to use
 * @lbat:	Logical block application tag
 * @lbatm:	Logical block application tag mask
 */
static inline void
nvme_init_app_tag(struct nvme_passthru_cmd *cmd,
	__u16 lbat, __u16 lbatm)
{
	cmd->cdw15 = NVME_FIELD_ENCODE(lbat,
			NVME_IOCS_COMMON_CDW15_ELBAT_SHIFT,
			NVME_IOCS_COMMON_CDW15_ELBAT_MASK) |
		     NVME_FIELD_ENCODE(lbatm,
			NVME_IOCS_COMMON_CDW15_ELBATM_SHIFT,
			NVME_IOCS_COMMON_CDW15_ELBATM_MASK);
}

/**
 * nvme_init_io() - Initialize passthru command for a generic user I/O command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @opcode:	Opcode to execute
 * @slba:	Starting logical block
 * @data:	Pointer to user address of the data buffer
 * @data_len:	Length of user buffer, @data, in bytes
 * @metadata:	Pointer to user address of the metadata buffer
 * @metadata_len:Length of user buffer, @metadata, in bytes
 *
 * Initializes the passthru command buffer for a generic NVM I/O command.
 * Note: If @elbas is true, the caller must ensure the definition/logic for
 * nvme_init_set_var_size_tags is available and that the return value from
 * that function is checked for error.
 */
static inline void
nvme_init_io(struct nvme_passthru_cmd *cmd, __u8 opcode, __u32 nsid, __u64 slba,
		void *data, __u32 data_len, void *metadata, __u32 metadata_len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = opcode;
	cmd->nsid = nsid;
	cmd->metadata = (__u64)(uintptr_t)metadata;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->metadata_len = metadata_len;
	cmd->data_len = data_len;
	cmd->cdw10 = NVME_FIELD_ENCODE(slba,
			NVME_IOCS_COMMON_CDW10_SLBAL_SHIFT,
			NVME_IOCS_COMMON_CDW10_SLBAL_MASK);
	cmd->cdw11 = NVME_FIELD_ENCODE(slba >> 32,
			NVME_IOCS_COMMON_CDW11_SLBAU_SHIFT,
			NVME_IOCS_COMMON_CDW11_SLBAU_MASK);
}

/**
 * nvme_init_read() - Initialize passthru command for a user read command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks (0-based)
 * @control:	Upper 16 bits of cdw12
 * @dsm:	Data set management attributes (CETYPE is zero),
 *		see &enum nvme_io_dsm_flags
 * @cev:	Command Extension Value (CETYPE is non-zero)
 * @data:	Pointer to user address of the data buffer
 * @data_len:	Length of user buffer, @data, in bytes
 * @metadata:	Pointer to user address of the metadata buffer
 * @metadata_len:Length of user buffer, @metadata, in bytes
 *
 * Initializes the passthru command buffer for the Read command.
 * Note: Assumes a macro or separate function exists to translate the combined
 * NLB/control/prinfo fields into cdw12/cdw13. This transformation assumes
 * the parameters are used for a generic nvme_init_io wrapper.
 */
static inline void
nvme_init_read(struct nvme_passthru_cmd *cmd, __u32 nsid, __u64 slba,
		__u16 nlb, __u16 control, __u8 dsm, __u16 cev,
		void *data, __u32 data_len, void *metadata, __u32 metadata_len)
{
	nvme_init_io(cmd, nvme_cmd_read, nsid, slba,
		data, data_len, metadata, metadata_len);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		      NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(dsm,
			NVME_IOCS_COMMON_CDW13_DSM_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSM_MASK) |
		     NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK);
}

/**
 * nvme_init_write() - Initialize passthru command for a user write command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks (0-based)
 * @control:	Upper 16 bits of cdw12
 * @dspec:	Directive specific value
 * @dsm:	Data set management attributes (CETYPE is zero),
 *		see &enum nvme_io_dsm_flags
 * @cev:	Command Extension Value (CETYPE is non-zero)
 * @data:	Pointer to user address of the data buffer
 * @data_len:	Length of user buffer, @data, in bytes
 * @metadata:	Pointer to user address of the metadata buffer
 * @metadata_len:Length of user buffer, @metadata, in bytes
 *
 * Initializes the passthru command buffer for the Write command.
 */
static inline void
nvme_init_write(struct nvme_passthru_cmd *cmd, __u32 nsid, __u64 slba,
		__u16 nlb, __u16 control, __u16 dspec, __u8 dsm, __u8 cev,
		void *data, __u32 data_len, void *metadata, __u32 metadata_len)
{
	nvme_init_io(cmd, nvme_cmd_write, nsid, slba,
		data, data_len, metadata, metadata_len);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		      NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(dspec,
			NVME_IOCS_COMMON_CDW13_DSPEC_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSPEC_MASK) |
		     NVME_FIELD_ENCODE(dsm,
			NVME_IOCS_COMMON_CDW13_DSM_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSM_MASK) |
		     NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK);
}
/**
 * nvme_init_compare() - Initialize passthru command for a user compare command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks (0-based)
 * @control:	Command control flags, see &enum nvme_io_control_flags.
 * @cev:	Command Extension Value (CETYPE is non-zero)
 * @data:	Pointer to user address of the data buffer
 * @data_len:	Length of user buffer, @data, in bytes
 * @metadata:	Pointer to user address of the metadata buffer
 * @metadata_len:Length of user buffer, @metadata, in bytes
 *
 * Initializes the passthru command buffer for the Compare command.
 */
static inline void
nvme_init_compare(struct nvme_passthru_cmd *cmd, __u32 nsid, __u64 slba,
		__u16 nlb, __u16 control, __u8 cev, void *data, __u32 data_len,
		void *metadata, __u32 metadata_len)
{
	nvme_init_io(cmd, nvme_cmd_compare, nsid, slba,
		data, data_len, metadata, metadata_len);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		     NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK);
}

/**
 * nvme_init_write_zeros() - Initialize passthru command for a
 * write zeroes command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks (0-based)
 * @control:	Upper 16 bits of cdw12
 * @dspec:	Directive specific value
 * @dsm:	Data set management attributes (CETYPE is zero),
 *		see &enum nvme_io_dsm_flags
 * @cev:	Command Extension Value (CETYPE is non-zero)
 *
 * Initializes the passthru command buffer for the Write Zeroes command.
 * Note: Write Zeroes command does not transfer data or metadata.
 */
static inline void
nvme_init_write_zeros(struct nvme_passthru_cmd *cmd, __u32 nsid, __u64 slba,
		__u16 nlb, __u16 control, __u16 dspec, __u8 dsm, __u8 cev)
{
	nvme_init_io(cmd, nvme_cmd_write_zeroes, nsid, slba, NULL, 0, NULL, 0);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		      NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(dspec,
			NVME_IOCS_COMMON_CDW13_DSPEC_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSPEC_MASK) |
		     NVME_FIELD_ENCODE(dsm,
			NVME_IOCS_COMMON_CDW13_DSM_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSM_MASK) |
		     NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK);
}

/**
 * nvme_init_write_uncorrectable() - Initialize passthru command for a
 * write uncorrectable command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks (0-based)
 * @control:	Upper 16 bits of cdw12
 * @dspec:	Directive specific value
 *
 * Initializes the passthru command buffer for the Write Uncorrectable command.
 * Note: This command transfers no data or metadata.
 */
static inline void
nvme_init_write_uncorrectable(struct nvme_passthru_cmd *cmd, __u32 nsid,
		__u64 slba, __u16 nlb, __u16 control, __u16 dspec)
{
	nvme_init_io(cmd, nvme_cmd_write_uncor, nsid, slba, NULL, 0, NULL, 0);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		      NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(dspec,
			NVME_IOCS_COMMON_CDW13_DSPEC_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSPEC_MASK);
}

/**
 * nvme_init_verify() - Initialize passthru command for a verify command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks (0-based)
 * @control:	Upper 16 bits of cdw12
 * @cev:	Command Extension Value (CETYPE is non-zero)
 * @data:	Pointer to user address of the data buffer
 * @data_len:	Length of user buffer, @data, in bytes
 * @metadata:	Pointer to user address of the metadata buffer
 * @metadata_len:Length of user buffer, @metadata, in bytes
 *
 * Initializes the passthru command buffer for the Verify command.
 * Note: Verify command transfers data or metadata to the controller to perform
 * the verification but not back to the host.
 */
static inline void
nvme_init_verify(struct nvme_passthru_cmd *cmd, __u32 nsid, __u64 slba,
		__u16 nlb, __u16 control, __u8 cev, void *data, __u32 data_len,
		void *metadata, __u32 metadata_len)
{
	nvme_init_io(cmd, nvme_cmd_verify, nsid, slba,
		data, data_len, metadata, metadata_len);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		     NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK);
}

/**
 * nvme_init_copy() - Initialize passthru command for Copy command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @sdlba:	Start destination LBA
 * @nr:		Number of ranges (1-based, 0-based in command)
 * @desfmt:	Descriptor format
 * @prinfor:	Protection information field for read
 * @prinfow:	Protection information field for write
 * @cetype:	Command Extension Type
 * @dtype:	Directive Type
 * @stcw:	Storage Tag Check Write
 * @stcr:	Storage Tag Check Read
 * @fua:	Force unit access
 * @lr:		Limited retry
 * @cev:	Command Extension Value
 * @dspec:	Directive specific value
 * @cpydsc:	Range description buffer
 *
 * Initializes the passthru command buffer for the Copy command by calculating
 * the data length and calling the generic I/O initializer.
 */
static inline void
nvme_init_copy(struct nvme_passthru_cmd *cmd, __u32 nsid, __u64 sdlba,
		__u16 nr, __u8 desfmt, __u8 prinfor, __u8 prinfow,
		__u8 cetype, __u8 dtype, bool stcw, bool stcr, bool fua,
		bool lr, __u16 cev, __u16 dspec, void *cpydsc)
{
	__u32 data_len;

	switch (desfmt) {
	case 1:
		data_len = nr * sizeof(struct nvme_copy_range_f1);
		break;
	case 2:
		data_len = nr * sizeof(struct nvme_copy_range_f2);
		break;
	case 3:
		data_len = nr * sizeof(struct nvme_copy_range_f3);
		break;
	default:
		data_len = nr * sizeof(struct nvme_copy_range_f0);
		break;
	}

	nvme_init_io(cmd, nvme_cmd_copy, nsid, sdlba, cpydsc,
		data_len, NULL, 0);
	cmd->cdw12 = NVME_FIELD_ENCODE(nr - 1,
			NVME_COPY_CDW12_NR_SHIFT,
			NVME_COPY_CDW12_NR_MASK) |
		     NVME_FIELD_ENCODE(desfmt,
			NVME_COPY_CDW12_DESFMT_SHIFT,
			NVME_COPY_CDW12_DESFMT_MASK) |
		     NVME_FIELD_ENCODE(prinfor,
			NVME_COPY_CDW12_PRINFOR_SHIFT,
			NVME_COPY_CDW12_PRINFOR_MASK) |
		     NVME_FIELD_ENCODE(cetype,
			NVME_COPY_CDW12_CETYPE_SHIFT,
			NVME_COPY_CDW12_CETYPE_MASK) |
		     NVME_FIELD_ENCODE(dtype,
			NVME_COPY_CDW12_DTYPE_SHIFT,
			NVME_COPY_CDW12_DTYPE_MASK) |
		     NVME_FIELD_ENCODE(stcw,
			NVME_COPY_CDW12_STCW_SHIFT,
			NVME_COPY_CDW12_STCW_MASK) |
		     NVME_FIELD_ENCODE(stcr,
			NVME_COPY_CDW12_STCR_SHIFT,
			NVME_COPY_CDW12_STCR_MASK) |
		     NVME_FIELD_ENCODE(prinfow,
			NVME_COPY_CDW12_PRINFOW_SHIFT,
			NVME_COPY_CDW12_PRINFOW_MASK) |
		     NVME_FIELD_ENCODE(fua,
			NVME_COPY_CDW12_FUA_SHIFT,
			NVME_COPY_CDW12_FUA_MASK) |
		     NVME_FIELD_ENCODE(lr,
			NVME_COPY_CDW12_LR_SHIFT,
			NVME_COPY_CDW12_LR_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK) |
		     NVME_FIELD_ENCODE(dspec,
			NVME_IOCS_COMMON_CDW13_DSPEC_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSPEC_MASK);
}

/**
 * nvme_init_resv_acquire() - Initialize passthru command for
 * Reservation Acquire
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @racqa:	The action that is performed by the command,
 *		see &enum nvme_resv_racqa
 * @iekey:	Set to ignore the existing key
 * @disnsrs:	Disperse Namespace Reservation Support
 * @rtype:	The type of reservation to be create, see &enum nvme_resv_rtype
 * @crkey:	The current reservation key associated with the host
 * @prkey:	Preempt Reservation Key
 * @payload:	Data payload buffer to hold crkey and prkey
 *
 * Initializes the passthru command buffer for the Reservation Acquire command.
 */
static inline void
nvme_init_resv_acquire(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_resv_racqa racqa, bool iekey, bool disnsrs,
		enum nvme_resv_rtype rtype, __u64 crkey, __u64 prkey,
		__le64 *payload)
{
	memset(cmd, 0, sizeof(*cmd));

	payload[0] = htole64(crkey);
	payload[1] = htole64(prkey);

	cmd->opcode = nvme_cmd_resv_acquire;
	cmd->nsid = nsid;
	cmd->data_len = 2 * sizeof(__le64);
	cmd->addr = (__u64)(uintptr_t)payload;
	cmd->cdw10 = NVME_FIELD_ENCODE(racqa,
			NVME_RESV_ACQUIRE_CDW10_RACQA_SHIFT,
			NVME_RESV_ACQUIRE_CDW10_RACQA_MASK) |
		     NVME_FIELD_ENCODE(iekey,
			NVME_RESV_ACQUIRE_CDW10_IEKEY_SHIFT,
			NVME_RESV_ACQUIRE_CDW10_IEKEY_MASK) |
		     NVME_FIELD_ENCODE(disnsrs,
			NVME_RESV_ACQUIRE_CDW10_DISNSRS_SHIFT,
			NVME_RESV_ACQUIRE_CDW10_DISNSRS_MASK) |
		     NVME_FIELD_ENCODE(rtype,
			NVME_RESV_ACQUIRE_CDW10_RTYPE_SHIFT,
			NVME_RESV_ACQUIRE_CDW10_RTYPE_MASK);
}

/**
 * nvme_init_resv_register() - Initialize passthru command for
 * Reservation Register
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @rrega:	The registration action, see &enum nvme_resv_rrega
 * @iekey:	Set to ignore the existing key
 * @disnsrs:	Disperse Namespace Reservation Support
 * @cptpl:	Change persist through power loss, see &enum nvme_resv_cptpl
 * @crkey:	The current reservation key associated with the host
 * @nrkey:	The new reservation key to be register if action is register or
 *		replace
 * @payload:	Data payload buffer to hold crkey and nrkey
 *
 * Initializes the passthru command buffer for the Reservation Register command.
 */
static inline void
nvme_init_resv_register(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_resv_rrega rrega, bool iekey, bool disnsrs,
		enum nvme_resv_cptpl cptpl, __u64 crkey, __u64 nrkey,
		__le64 *payload)
{
	memset(cmd, 0, sizeof(*cmd));

	payload[0] = htole64(crkey);
	payload[1] = htole64(nrkey);

	cmd->opcode = nvme_cmd_resv_register;
	cmd->nsid = nsid;
	cmd->data_len = 2 * sizeof(__le64);
	cmd->addr = (__u64)(uintptr_t)payload;
	cmd->cdw10 = NVME_FIELD_ENCODE(rrega,
			NVME_RESV_REGISTER_CDW10_RREGA_SHIFT,
			NVME_RESV_REGISTER_CDW10_RREGA_MASK) |
		     NVME_FIELD_ENCODE(iekey,
			NVME_RESV_REGISTER_CDW10_IEKEY_SHIFT,
			NVME_RESV_REGISTER_CDW10_IEKEY_MASK) |
		     NVME_FIELD_ENCODE(disnsrs,
			NVME_RESV_REGISTER_CDW10_DISNSRS_SHIFT,
			NVME_RESV_REGISTER_CDW10_DISNSRS_MASK) |
		     NVME_FIELD_ENCODE(cptpl,
			NVME_RESV_REGISTER_CDW10_CPTPL_SHIFT,
			NVME_RESV_REGISTER_CDW10_CPTPL_MASK);
}

/**
 * nvme_init_resv_release() - Initialize passthru command for
 * Reservation Release
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @rrela:	Reservation release action, see &enum nvme_resv_rrela
 * @iekey:	Set to ignore the existing key
 * @disnsrs:	Disperse Namespace Reservation Support
 * @rtype:	The type of reservation to be create, see &enum nvme_resv_rtype
 * @crkey:	The current reservation key to release
 * @payload:	Data payload buffer to hold crkey
 *
 * Initializes the passthru command buffer for the Reservation Release command.
 */
static inline void
nvme_init_resv_release(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_resv_rrela rrela, bool iekey, bool disnsrs,
		enum nvme_resv_rtype rtype, __u64 crkey, __le64 *payload)
{
	memset(cmd, 0, sizeof(*cmd));

	payload[0] = htole64(crkey);

	cmd->opcode = nvme_cmd_resv_release;
	cmd->nsid = nsid;
	cmd->data_len = sizeof(__le64);
	cmd->addr = (__u64)(uintptr_t)payload;
	cmd->cdw10 = NVME_FIELD_ENCODE(rrela,
			NVME_RESV_RELEASE_CDW10_RRELA_SHIFT,
			NVME_RESV_RELEASE_CDW10_RRELA_MASK) |
		     NVME_FIELD_ENCODE(iekey,
			NVME_RESV_RELEASE_CDW10_IEKEY_SHIFT,
			NVME_RESV_RELEASE_CDW10_IEKEY_MASK) |
		     NVME_FIELD_ENCODE(disnsrs,
			NVME_RESV_RELEASE_CDW10_DISNSRS_SHIFT,
			NVME_RESV_RELEASE_CDW10_DISNSRS_MASK) |
		     NVME_FIELD_ENCODE(rtype,
			NVME_RESV_RELEASE_CDW10_RTYPE_SHIFT,
			NVME_RESV_RELEASE_CDW10_RTYPE_MASK);
}

/**
 * nvme_init_resv_report() - Initialize passthru command for
 * Reservation Report
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @eds:	Request extended Data Structure
 * @disnsrs:	Disperse Namespace Reservation Support
 * @report:	The user space destination address to store the reservation
 *		report buffer
 * @len:	Number of bytes to request transferred with this command
 *
 * Initializes the passthru command buffer for the Reservation Report command.
 */
static inline void
nvme_init_resv_report(struct nvme_passthru_cmd *cmd, __u32 nsid,
		bool eds, bool disnsrs, struct nvme_resv_status *report,
		__u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_cmd_resv_report;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)report;
	cmd->cdw10 = (len >> 2) - 1;
	cmd->cdw11 = NVME_FIELD_ENCODE(eds,
			NVME_RESV_REPORT_CDW11_EDS_SHIFT,
			NVME_RESV_REPORT_CDW11_EDS_MASK) |
		     NVME_FIELD_ENCODE(disnsrs,
			NVME_RESV_REPORT_CDW11_DISNSRS_SHIFT,
			NVME_RESV_REPORT_CDW11_DISNSRS_MASK);
}

/**
 * nvme_init_io_mgmt_recv() - Initialize passthru command for
 * I/O Management Receive command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @mo:		Management Operation
 * @mos:	Management Operation Specific
 * @data:	Userspace address of the data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the I/O Management
 * Receive command.
 */
static inline void
nvme_init_io_mgmt_recv(struct nvme_passthru_cmd *cmd, __u32 nsid,
		__u8 mo, __u16 mos, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_cmd_io_mgmt_recv;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(mo,
			NVME_IO_MGMT_RECV_CDW10_MO_SHIFT,
			NVME_IO_MGMT_RECV_CDW10_MO_MASK) |
		     NVME_FIELD_ENCODE(mos,
			NVME_IO_MGMT_RECV_CDW10_MOS_SHIFT,
			NVME_IO_MGMT_RECV_CDW10_MOS_MASK);
	cmd->cdw11 = (len >> 2) - 1;
}

/**
 * nvme_init_fdp_reclaim_unit_handle_status() - Initialize passthru command
 * to get reclaim unit handle status
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @data:	Response buffer
 * @len:	Length of response buffer
 *
 * Initializes the passthru command buffer for the I/O Management Receive -
 * Reclaim Unit Handle Status command.
 */
static inline void
nvme_init_fdp_reclaim_unit_handle_status(struct nvme_passthru_cmd *cmd,
		__u32 nsid, void *data, __u32 len)
{
	nvme_init_io_mgmt_recv(cmd, nsid, NVME_IO_MGMT_RECV_RUH_STATUS, 0,
		data, len);
}

/**
 * nvme_init_io_mgmt_send() - Initialize passthru command for
 * I/O Management Send command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @mo:		Management Operation
 * @mos:	Management Operation Specific
 * @data:	Userspace address of the data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the I/O Management Send command.
 */
static inline void
nvme_init_io_mgmt_send(struct nvme_passthru_cmd *cmd, __u32 nsid,
		__u8 mo, __u16 mos, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_cmd_io_mgmt_send;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(mo,
			NVME_IO_MGMT_SEND_CDW10_MO_SHIFT,
			NVME_IO_MGMT_SEND_CDW10_MO_MASK) |
		     NVME_FIELD_ENCODE(mos,
			NVME_IO_MGMT_SEND_CDW10_MOS_SHIFT,
			NVME_IO_MGMT_SEND_CDW10_MOS_MASK);
}

/**
 * nvme_init_fdp_reclaim_unit_handle_update() - Initialize passthru command to
 * update a list of reclaim unit handles
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @pids:	List of placement identifiers buffer
 * @npids:	Number of placement identifiers
 *
 * Initializes the passthru command buffer for the I/O Management Send -
 * Reclaim Unit Handle Update command.
 */
static inline void
nvme_init_fdp_reclaim_unit_handle_update(struct nvme_passthru_cmd *cmd,
		__u32 nsid, void *pids, unsigned int npids)
{
	__u16 mos = npids - 1; /* MOS = NPI - 1 */
	__u32 len = npids * sizeof(__u16);

	nvme_init_io_mgmt_send(cmd, nsid, NVME_IO_MGMT_SEND_RUH_UPDATE,
		mos, pids, len);
}

/**
 * nvme_init_zns_mgmt_send() - Initialize passthru command for
 * ZNS management send command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block address
 * @zsa:	Zone send action
 * @selall:	Select all flag
 * @zsaso:	Zone Send Action Specific Option
 * @zm:		Zone Management
 * @data:	Userspace address of the data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the ZNS Management Send command.
 */
static inline void
nvme_init_zns_mgmt_send(struct nvme_passthru_cmd *cmd, __u32 nsid,
		__u64 slba, enum nvme_zns_send_action zsa, bool selall,
		__u8 zsaso, __u8 zm, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_zns_cmd_mgmt_send;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = slba & 0xffffffff;
	cmd->cdw11 = slba >> 32;
	cmd->cdw13 = NVME_FIELD_ENCODE(zsa,
			NVME_ZNS_MGMT_SEND_ZSA_SHIFT,
			NVME_ZNS_MGMT_SEND_ZSA_MASK) |
		      NVME_FIELD_ENCODE(selall,
			NVME_ZNS_MGMT_SEND_SEL_SHIFT,
			NVME_ZNS_MGMT_SEND_SEL_MASK) |
		      NVME_FIELD_ENCODE(zsaso,
			NVME_ZNS_MGMT_SEND_ZSASO_SHIFT,
			NVME_ZNS_MGMT_SEND_ZSASO_MASK) |
		      NVME_FIELD_ENCODE(zm,
			NVME_ZNS_MGMT_SEND_ZM_SHIFT,
			NVME_ZNS_MGMT_SEND_ZM_MASK);
}

/**
 * nvme_init_zns_mgmt_recv() - Initialize passthru command for
 * ZNS management receive command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block address
 * @zra:	zone receive action
 * @zras:	Zone receive action specific field
 * @zraspf:	Zone receive action specific features
 * @data:	Userspace address of the data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the ZNS Management
 * Receive command.
 */
static inline void
nvme_init_zns_mgmt_recv(struct nvme_passthru_cmd *cmd, __u32 nsid,
		__u64 slba, enum nvme_zns_recv_action zra, __u16 zras,
		bool zraspf, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_zns_cmd_mgmt_recv;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = slba & 0xffffffff;
	cmd->cdw11 = slba >> 32;
	cmd->cdw12 = (len >> 2) - 1;
	cmd->cdw13 = NVME_FIELD_ENCODE(zra,
			NVME_ZNS_MGMT_RECV_ZRA_SHIFT,
			NVME_ZNS_MGMT_RECV_ZRA_MASK) |
		     NVME_FIELD_ENCODE(zras,
			NVME_ZNS_MGMT_RECV_ZRAS_SHIFT,
			NVME_ZNS_MGMT_RECV_ZRAS_MASK) |
		     NVME_FIELD_ENCODE(zraspf,
			NVME_ZNS_MGMT_RECV_ZRASPF_SHIFT,
			NVME_ZNS_MGMT_RECV_ZRASPF_MASK);
}

/**
 * nvme_init_zns_report_zones() - Initialize passthru command to return
 * the list of zones
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting LBA
 * @opts:	Reporting options
 * @extended:	Extended report
 * @partial:	Partial report requested
 * @data:	Userspace address of the report zones data buffer
 * @len:	Length of the data buffer
 *
 * Initializes the passthru command buffer for the ZNS Management Receive -
 * Report Zones command.
 */
static inline void
nvme_init_zns_report_zones(struct nvme_passthru_cmd *cmd, __u32 nsid,
		__u64 slba, enum nvme_zns_report_options opts,
		bool extended, bool partial,
		void *data, __u32 len)
{
	enum nvme_zns_recv_action zra = extended ?
		NVME_ZNS_ZRA_EXTENDED_REPORT_ZONES : NVME_ZNS_ZRA_REPORT_ZONES;
	__u16 zras = (__u16)opts;
	bool zraspf = partial; /* ZRASPF is Partial Report Requested */

	nvme_init_zns_mgmt_recv(cmd, nsid, slba, zra, zras, zraspf, data, len);
}

/**
 * nvme_init_zns_append() - Initialize passthru command to append data to a zone
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @zslba:	Zone start logical block address
 * @nlb:	Number of logical blocks
 * @control:	Upper 16 bits of cdw12
 * @cev:	Command Extension Value
 * @dspec:	Directive Specific
 * @data:	Userspace address of the data buffer
 * @data_len:	Length of @data
 * @metadata:	Userspace address of the metadata buffer
 * @metadata_len: Length of @metadata
 *
 * Initializes the passthru command buffer for the ZNS Append command.
 */
static inline void
nvme_init_zns_append(struct nvme_passthru_cmd *cmd, __u32 nsid,
		__u64 zslba, __u16 nlb, __u16 control, __u16 cev, __u16 dspec,
		void *data, __u32 data_len, void *metadata, __u32 metadata_len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_zns_cmd_append;
	cmd->nsid = nsid;
	cmd->metadata = (__u64)(uintptr_t)metadata;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->metadata_len = metadata_len;
	cmd->data_len = data_len;
	cmd->cdw10 = NVME_FIELD_ENCODE(zslba,
			NVME_IOCS_COMMON_CDW10_SLBAL_SHIFT,
			NVME_IOCS_COMMON_CDW10_SLBAL_MASK);
	cmd->cdw11 = NVME_FIELD_ENCODE(zslba >> 32,
			NVME_IOCS_COMMON_CDW11_SLBAU_SHIFT,
			NVME_IOCS_COMMON_CDW11_SLBAU_MASK);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		     NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(dspec,
			NVME_IOCS_COMMON_CDW13_DSPEC_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSPEC_MASK);
	if (control & NVME_IOCS_COMMON_CDW12_CETYPE_MASK)
		cmd->cdw13 |= NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK);
}

/**
 * nvme_init_dim_send() - Initialize passthru command for
 * Discovery Information Management (DIM) Send
 * @cmd:	Passthru command to use
 * @tas:	Task field of the Command Dword 10 (cdw10)
 * @data:	Pointer to the DIM data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the Discovery Information
 * Management Send command.
 */
static inline void
nvme_init_dim_send(struct nvme_passthru_cmd *cmd,
		__u8 tas, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_discovery_info_mgmt;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(tas,
			NVME_DIM_TAS_SHIFT,
			NVME_DIM_TAS_MASK);

}

/**
 * nvme_init_lm_cdq_create() - Initialize passthru command for
 * Controller Data Queue create - Controller Data Queue command
 * @cmd:	Passthru command to use
 * @mos:	Management Operation Specific (MOS): This field is
 *		specific to the SEL type
 * @cntlid:	Controller ID: For Create CDQ, specifies the target
 *		migratable controller
 * @cdqsize:	For Create CDQ, specifies the size of CDQ, in dwords - 4 byte
 * @data:	Pointer to data buffer
 *
 * Initializes the passthru command buffer for the Controller Data Queue
 * command. Note: The result CDQID is returned in the CQE dword0, which the
 * submission function must handle.
 */
static inline void
nvme_init_lm_cdq_create(struct nvme_passthru_cmd *cmd,
		__u16 mos, __u16 cntlid, __u32 cdqsize, void *data)
{
	__u16 cqs;

	memset(cmd, 0, sizeof(*cmd));

	cqs = NVME_FIELD_ENCODE(cntlid,
		NVME_LM_CREATE_CDQ_CNTLID_SHIFT,
		NVME_LM_CREATE_CDQ_CNTLID_MASK);

	cmd->opcode = nvme_admin_ctrl_data_queue;
	cmd->data_len = cdqsize << 2;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(NVME_LM_SEL_CREATE_CDQ,
			NVME_LM_CDQ_SEL_SHIFT,
			NVME_LM_CDQ_SEL_MASK) |
		      NVME_FIELD_ENCODE(mos,
			NVME_LM_CDQ_MOS_SHIFT,
			NVME_LM_CDQ_MOS_MASK);
	cmd->cdw11 = NVME_FIELD_ENCODE(NVME_LM_CREATE_CDQ_PC,
			NVME_LM_CREATE_CDQ_PC_SHIFT,
			NVME_LM_CREATE_CDQ_PC_MASK) |
		     NVME_FIELD_ENCODE(cqs,
			NVME_LM_CQS_SHIFT,
			NVME_LM_CQS_MASK);
	cmd->cdw12 = cdqsize;
}

/**
 * nvme_init_lm_cdq_delete() - Initialize passthru command for
 * Controller Data Queue delete - Controller Data Queue command
 * @cmd:	Passthru command to use
 * @mos:	Management Operation Specific (MOS): This field is
 *		specific to the SEL type
 * @cdqid:	Controller Data Queue ID (CDQID): For Delete CDQ, this
 *		field is the CDQID to delete.
 *
 * Initializes the passthru command buffer for the Controller Data Queue delete
 * command.
 */
static inline void
nvme_init_lm_cdq_delete(struct nvme_passthru_cmd *cmd,
		__u16 mos, __u16 cdqid)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_ctrl_data_queue;
	cmd->cdw10 = NVME_FIELD_ENCODE(NVME_LM_SEL_DELETE_CDQ,
			NVME_LM_CDQ_SEL_SHIFT,
			NVME_LM_CDQ_SEL_MASK) |
		      NVME_FIELD_ENCODE(mos,
			NVME_LM_CDQ_MOS_SHIFT,
			NVME_LM_CDQ_MOS_MASK);
	cmd->cdw11 = NVME_FIELD_ENCODE(cdqid,
			NVME_LM_DELETE_CDQ_CDQID_SHIFT,
			NVME_LM_DELETE_CDQ_CDQID_MASK);
}

/**
 * nvme_init_lm_track_send() - Initialize passthru command for
 * Track Send command
 * @cmd:	Passthru command to use
 * @sel:	Select (SEL): This field specifies the type of
 *		management operation to perform
 * @mos:	Management Operation Specific (MOS): This field
 *		is specific to the SEL type
 * @cdqid:	Controller Data Queue ID (CDQID)
 *
 * Initializes the passthru command buffer for the Track Send command.
 */
static inline void
nvme_init_lm_track_send(struct nvme_passthru_cmd *cmd,
		__u8 sel, __u16 mos, __u16 cdqid)
{

	memset(cmd, 0, sizeof(*cmd));
	cmd->opcode = nvme_admin_track_send;
	cmd->cdw10 = NVME_FIELD_ENCODE(sel,
			NVME_LM_TRACK_SEND_SEL_SHIFT,
			NVME_LM_TRACK_SEND_SEL_MASK) |
		     NVME_FIELD_ENCODE(mos,
			NVME_LM_TRACK_SEND_MOS_SHIFT,
			NVME_LM_TRACK_SEND_MOS_MASK);
	cmd->cdw11 = cdqid;
}

/**
 * nvme_init_lm_migration_send() - Initialize passthru command for
 * Migration Send command
 * @cmd:	Passthru command to use
 * @sel:	Select (SEL): This field specifies the type of management
 *		operation to perform.
 * @mos:	Management Operation Specific (MOS): This field is specific
 *		to the SEL type
 * @cntlid:	Controller ID: This field specifies the identifier of the
 *		controller to which the operation is performed.
 * @stype:	Suspend Type (STYPE): This field specifies the type of suspend.
 * @dudmq:	Delete User Data Migration Queue (DUDMQ): If set, the migration
 *		queue is deleted is deleted as part of the Suspend operation.
 * @csvi:	Controller State Version Index (CSVI)
 * @csuuidi:	Controller State UUID Index (CSUUIDI)
 * @cso:	Offset: This field specifies the offset, in bytes, within
 *		the data available to be returned and specifies the starting
 *		point for that data for what is actually returned to the host.
 * @uidx:	UUID Index (UIDX)
 * @data:	Pointer to data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the Migration Send command.
 */
static inline void
nvme_init_lm_migration_send(struct nvme_passthru_cmd *cmd,
		__u16 sel, __u16 mos, __u16 cntlid, __u8 stype, bool dudmq,
		__u8 csvi, __u16 csuuidi, __u64 cso, __u8 uidx,
		void *data, __u32 len)
{
	__u32 cdw10 = NVME_FIELD_ENCODE(sel,
			NVME_LM_MIGRATION_SEND_SEL_SHIFT,
			NVME_LM_MIGRATION_SEND_SEL_MASK) |
		      NVME_FIELD_ENCODE(mos,
			NVME_LM_MIGRATION_SEND_MOS_SHIFT,
			NVME_LM_MIGRATION_SEND_MOS_MASK);
	__u32 cdw11 = 0;
	__u32 cdw14 = NVME_FIELD_ENCODE(uidx,
			NVME_LM_MIGRATION_SEND_UIDX_SHIFT,
			NVME_LM_MIGRATION_SEND_UIDX_MASK);

	if (sel == NVME_LM_SEL_SUSPEND) {
		cdw11 = NVME_FIELD_ENCODE(stype,
				NVME_LM_STYPE_SHIFT,
				NVME_LM_STYPE_MASK) |
			NVME_FIELD_ENCODE(cntlid,
				NVME_LM_SUSPEND_CNTLID_SHIFT,
				NVME_LM_SUSPEND_CNTLID_MASK);
		if (dudmq)
			cdw11 |= NVME_LM_DUDMQ;
	} else if (sel == NVME_LM_SEL_RESUME) {
		cdw11 = NVME_FIELD_ENCODE(cntlid,
				NVME_LM_RESUME_CNTLID_SHIFT,
				NVME_LM_RESUME_CNTLID_MASK);
	} else if (sel == NVME_LM_SEL_SET_CONTROLLER_STATE) {
		cdw11 = NVME_FIELD_ENCODE(csuuidi,
				NVME_LM_SET_CONTROLLER_STATE_CSUUIDI_SHIFT,
				NVME_LM_SET_CONTROLLER_STATE_CSUUIDI_MASK) |
			NVME_FIELD_ENCODE(csvi,
				NVME_LM_SET_CONTROLLER_STATE_CSVI_SHIFT,
				NVME_LM_SET_CONTROLLER_STATE_CSVI_MASK) |
			NVME_FIELD_ENCODE(cntlid,
				NVME_LM_SET_CONTROLLER_STATE_CNTLID_SHIFT,
				NVME_LM_SET_CONTROLLER_STATE_CNTLID_MASK);
	}

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_migration_send;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = cdw10;
	cmd->cdw11 = cdw11;
	cmd->cdw12 = (__u32)cso;
	cmd->cdw13 = (__u32)(cso >> 32);
	cmd->cdw14 = cdw14;
	cmd->cdw15 = len / sizeof(__u32);
}

/**
 * nvme_init_lm_migration_recv() - Initialize passthru command for
 * Migration Receive command
 * @cmd:	Passthru command to use
 * @offset:	Offset: This field specifies the offset, in bytes, within
 *		the data available to be returned and specifies the starting
 *		point for that data for what is actually returned to the host.
 * @mos:	Management Operation Specific (MOS): This field is specific to
 *		the SEL type
 * @cntlid:	Controller ID: This field specifies the identifier of the
 *		controller to which the operation is performed.
 * @csuuidi:	Controller State UUID Index (CSUUIDI)
 * @sel:	Select (SEL): This field specifies the type of management
 *		operation to perform
 * @uidx:	UUID Index (UIDX)
 * @csuidxp:	Controller State UUID Index Parameter (CSUIDXP)
 * @data:	Pointer to data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the Migration Receive command.
 */
static inline void
nvme_init_lm_migration_recv(struct nvme_passthru_cmd *cmd,
		__u64 offset, __u16 mos, __u16 cntlid, __u16 csuuidi, __u8 sel,
		__u8 uidx, __u8 csuidxp, void *data, __u32 len)
{
	__u32 cdw11 = 0;
	__u32 data_len = 0;

	if (sel == NVME_LM_SEL_GET_CONTROLLER_STATE) {
		cdw11 = NVME_FIELD_ENCODE(csuidxp,
				NVME_LM_GET_CONTROLLER_STATE_CSUIDXP_SHIFT,
				NVME_LM_GET_CONTROLLER_STATE_CSUIDXP_MASK) |
			NVME_FIELD_ENCODE(csuuidi,
				NVME_LM_GET_CONTROLLER_STATE_CSUUIDI_SHIFT,
				NVME_LM_GET_CONTROLLER_STATE_CSUUIDI_MASK) |
			NVME_FIELD_ENCODE(cntlid,
				NVME_LM_GET_CONTROLLER_STATE_CNTLID_SHIFT,
				NVME_LM_GET_CONTROLLER_STATE_CNTLID_MASK);
		data_len = len;
	}

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_migration_receive;
	cmd->data_len = data_len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(sel,
			NVME_LM_MIGRATION_RECV_SEL_SHIFT,
			NVME_LM_MIGRATION_RECV_SEL_MASK) |
		      NVME_FIELD_ENCODE(mos,
			NVME_LM_MIGRATION_RECV_MOS_SHIFT,
			NVME_LM_MIGRATION_RECV_MOS_MASK);
	cmd->cdw11 = cdw11;
	cmd->cdw12 = (__u32)offset;
	cmd->cdw13 = (__u32)(offset >> 32);
	cmd->cdw14 = NVME_FIELD_ENCODE(uidx,
			NVME_LM_MIGRATION_RECV_UIDX_SHIFT,
			NVME_LM_MIGRATION_RECV_UIDX_MASK);
	cmd->cdw15 = len ? (__u32)((len - 1) / sizeof(__u32)) : 0;
}

/**
 * nvme_init_lm_set_features_ctrl_data_queue() - Initialize passthru command for
 * Set Controller Data Queue feature
 * @cmd:	Passthru command to use
 * @cdqid:	Controller Data Queue ID (CDQID)
 * @hp:		Head Pointer (passed in cdw12)
 * @tpt:	Tail Pointer Trigger (passed in cdw13)
 * @etpt:	Enable Tail Pointer Trigger
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_CTRL_DATA_QUEUE.
 */
static inline void
nvme_init_lm_set_features_ctrl_data_queue(struct nvme_passthru_cmd *cmd,
	__u16 cdqid, __u32 hp, __u32 tpt, bool etpt)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_CTRL_DATA_QUEUE, false);
	cmd->cdw11 = cdqid |
		     NVME_FIELD_ENCODE(etpt,
			NVME_LM_CTRL_DATA_QUEUE_ETPT_SHIFT,
			NVME_LM_CTRL_DATA_QUEUE_ETPT_MASK);
	cmd->cdw12 = hp;
	cmd->cdw13 = tpt;
}

/**
 * nvme_init_lm_get_features_ctrl_data_queue() - Initialize passthru command for
 * Get Controller Data Queue feature
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @cdqid:	Controller Data Queue ID (CDQID)
 * @qfd:	Get Controller Data Queue feature data buffer
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_CTRL_DATA_QUEUE.
 */
static inline void
nvme_init_lm_get_features_ctrl_data_queue(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel, __u16 cdqid,
		struct nvme_lm_ctrl_data_queue_fid_data *qfd)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_CTRL_DATA_QUEUE, sel);
	cmd->data_len = sizeof(*qfd);
	cmd->addr = (__u64)(uintptr_t)qfd;
	cmd->cdw11 = cdqid;
}

/**
 * nvme_init_mi_cmd_flags() - Initialize command flags for NVMe-MI
 * @cmd:	Passthru command to use
 * @ish:	Ignore Shutdown (for NVMe-MI command)
 *
 * Initializes the passthru command flags
 */
static inline void
nvme_init_mi_cmd_flags(struct nvme_passthru_cmd *cmd, bool ish)
{
	cmd->flags = NVME_FIELD_ENCODE(ish,
			NVME_MI_ADMIN_CFLAGS_ISH_SHIFT,
			NVME_MI_ADMIN_CFLAGS_ISH_MASK);
}

/**
 * nvme_init_ctrl_list() - Initialize an nvme_ctrl_list structure from an array.
 * @cntlist:   The controller list structure to initialize
 * @num_ctrls: The number of controllers in the array, &ctrlist.
 * @ctrlist:   An array of controller identifiers in CPU native endian.
 *
 * This is intended to be used with any command that takes a controller list
 * argument. See nvme_ns_attach_ctrls() and nvme_ns_detach().
 */
static inline void
nvme_init_ctrl_list(struct nvme_ctrl_list *cntlist, __u16 num_ctrls,
		__u16 *ctrlist)
{
	int i;

	cntlist->num = htole16(num_ctrls);
	for (i = 0; i < num_ctrls; i++)
		cntlist->identifier[i] = htole16(ctrlist[i]);
}

/**
 * nvme_init_dsm_range() - Constructs a data set range structure
 * @dsm:	DSM range array
 * @ctx_attrs:	Array of context attributes
 * @llbas:	Array of length in logical blocks
 * @slbas:	Array of starting logical blocks
 * @nr_ranges:	The size of the dsm arrays
 *
 * Each array must be the same size of size 'nr_ranges'. This is intended to be
 * used with constructing a payload for nvme_dsm().
 *
 * Return: The nvme command status if a response was received or -errno
 * otherwise.
 */
static inline void
nvme_init_dsm_range(struct nvme_dsm_range *dsm, __u32 *ctx_attrs,
		__u32 *llbas, __u64 *slbas, __u16 nr_ranges)
{
	int i;

	for (i = 0; i < nr_ranges; i++) {
		dsm[i].cattr = htole32(ctx_attrs[i]);
		dsm[i].nlb = htole32(llbas[i]);
		dsm[i].slba = htole64(slbas[i]);
	}
}

/**
 * nvme_init_copy_range_elbt() - Constructs a copy range elbt structure
 * @elbt:
 * @eilbrts:	Expected initial logical block reference tag
 */
static inline void
nvme_init_copy_range_elbt(__u8 *elbt, __u64 eilbrt)
{
	int i;

	for (i = 0; i < 8; i++)
		elbt[9 - i] = (eilbrt >> (8 * i)) & 0xff;
	elbt[1] = 0;
	elbt[0] = 0;
}

/**
 * nvme_init_copy_range_f0() - Constructs a copy range structure
 * @copy:	Copy range array
 * @nlbs:	Number of logical blocks
 * @slbas:	Starting LBA
 * @elbts:	Expected initial logical block reference tag
 * @elbatms:	Expected logical block application tag mask
 * @elbats:	Expected logical block application tag
 * @nr:		Number of descriptors to construct
 */
static inline void
nvme_init_copy_range_f0(struct nvme_copy_range_f0 *copy, __u16 *nlbs,
		__u64 *slbas, __u32 *elbts, __u32 *elbatms,
		__u32 *elbats, __u16 nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		copy[i].nlb = htole16(nlbs[i]);
		copy[i].slba = htole64(slbas[i]);
		copy[i].elbt = htole32(elbts[i]);
		copy[i].elbatm = htole16(elbatms[i]);
		copy[i].elbat = htole16(elbats[i]);
	}
}

/**
 * nvme_init_copy_range_f1() - Constructs a copy range f1 structure
 * @copy:	Copy range array
 * @nlbs:	Number of logical blocks
 * @slbas:	Starting LBA
 * @eilbrts:	Expected initial logical block reference tag
 * @elbatms:	Expected logical block application tag mask
 * @elbats:	Expected logical block application tag
 * @nr:		Number of descriptors to construct
 */
static inline void
nvme_init_copy_range_f1(struct nvme_copy_range_f1 *copy, __u16 *nlbs,
		__u64 *slbas, __u64 *eilbrts, __u32 *elbatms,
		__u32 *elbats, __u16 nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		copy[i].nlb = htole16(nlbs[i]);
		copy[i].slba = htole64(slbas[i]);
		copy[i].elbatm = htole16(elbatms[i]);
		copy[i].elbat = htole16(elbats[i]);
		nvme_init_copy_range_elbt(copy[i].elbt, eilbrts[i]);
	}
}

/**
 * nvme_init_copy_range_f2() - Constructs a copy range f2 structure
 * @copy:	Copy range array
 * @snsids:	Source namespace identifier
 * @nlbs:	Number of logical blocks
 * @slbas:	Starting LBA
 * @sopts:	Source options
 * @eilbrts:	Expected initial logical block reference tag
 * @elbatms:	Expected logical block application tag mask
 * @elbats:	Expected logical block application tag
 * @nr:		Number of descriptors to construct
 */
static inline void
nvme_init_copy_range_f2(struct nvme_copy_range_f2 *copy,
		__u32 *snsids, __u16 *nlbs, __u64 *slbas, __u16 *sopts,
		__u32 *eilbrts, __u32 *elbatms, __u32 *elbats,
		__u16 nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		copy[i].snsid = htole32(snsids[i]);
		copy[i].nlb = htole16(nlbs[i]);
		copy[i].slba = htole64(slbas[i]);
		copy[i].sopt = htole16(sopts[i]);
		copy[i].eilbrt = htole32(eilbrts[i]);
		copy[i].elbatm = htole16(elbatms[i]);
		copy[i].elbat = htole16(elbats[i]);
	}
}

/**
 * nvme_init_copy_range_f3() - Constructs a copy range f3 structure
 * @copy:	Copy range array
 * @snsids:	Source namespace identifier
 * @nlbs:	Number of logical blocks
 * @slbas:	Starting LBA
 * @sopts:	Source options
 * @eilbrts:	Expected initial logical block reference tag
 * @elbatms:	Expected logical block application tag mask
 * @elbats:	Expected logical block application tag
 * @nr:		Number of descriptors to construct
 */
static inline void
nvme_init_copy_range_f3(struct nvme_copy_range_f3 *copy, __u32 *snsids,
		__u16 *nlbs, __u64 *slbas, __u16 *sopts,
		__u64 *eilbrts, __u32 *elbatms, __u32 *elbats,
		__u16 nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		copy[i].snsid = htole32(snsids[i]);
		copy[i].nlb = htole16(nlbs[i]);
		copy[i].slba = htole64(slbas[i]);
		copy[i].sopt = htole16(sopts[i]);
		copy[i].elbatm = htole16(elbatms[i]);
		copy[i].elbat = htole16(elbats[i]);
		nvme_init_copy_range_elbt(copy[i].elbt, eilbrts[i]);
	}
}

/**
 * nvme_get_log() - Get log page data
 * @hdl:	Transport handle
 * @cmd:	Passthru command
 * @rae:	Retain asynchronous events
 * @xfer_len:	Max log transfer size per request to split the total.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_log(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd, bool rae,
		 __u32 xfer_len);

/**
 * nvme_set_etdas() - Set the Extended Telemetry Data Area 4 Supported bit
 * @hdl:	Transport handle
 * @changed:	boolean to indicate whether or not the host
 *		behavior support feature had been changed
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_etdas(struct nvme_transport_handle *hdl, bool *changed);

/**
 * nvme_clear_etdas() - Clear the Extended Telemetry Data Area 4 Supported bit
 * @hdl:	Transport handle
 * @changed:	boolean to indicate whether or not the host
 *		behavior support feature had been changed
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_clear_etdas(struct nvme_transport_handle *hdl, bool *changed);

/**
 * nvme_get_uuid_list - Returns the uuid list (if supported)
 * @hdl:	Transport handle
 * @uuid_list:	UUID list returned by identify UUID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_uuid_list(struct nvme_transport_handle *hdl,
		struct nvme_id_uuid_list *uuid_list);

/**
 * nvme_get_telemetry_max() - Get telemetry limits
 * @hdl:	Transport handle
 * @da:		On success return max supported data area
 * @max_data_tx: On success set to max transfer chunk supported by
 *		the controller
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_telemetry_max(struct nvme_transport_handle *hdl,
		enum nvme_telemetry_da *da, size_t *max_data_tx);

/**
 * nvme_get_telemetry_log() - Get specified telemetry log
 * @hdl:	Transport handle
 * @create:	Generate new host initated telemetry capture
 * @ctrl:	Get controller Initiated log
 * @rae:	Retain asynchronous events
 * @max_data_tx: Set the max data transfer size to be used retrieving telemetry.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da.
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_telemetry_log(struct nvme_transport_handle *hdl, bool create,
		bool ctrl, bool rae, size_t max_data_tx,
		enum nvme_telemetry_da da, struct nvme_telemetry_log **log,
		size_t *size);

/**
 * nvme_get_ctrl_telemetry() - Get controller telemetry log
 * @hdl:	Transport handle
 * @rae:	Retain asynchronous events
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_ctrl_telemetry(struct nvme_transport_handle *hdl, bool rae,
		struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * nvme_get_host_telemetry() - Get host telemetry log
 * @hdl:	Transport handle
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_host_telemetry(struct nvme_transport_handle *hdl,
		struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * nvme_get_new_host_telemetry() - Get new host telemetry log
 * @hdl:	Transport handle
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_new_host_telemetry(struct nvme_transport_handle *hdl,
		struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * nvme_get_ana_log_len_from_id_ctrl() - Retrieve maximum possible ANA log size
 * @id_ctrl:	Controller identify data
 * @rgo:	If true, return maximum log page size without NSIDs
 *
 * Return: A byte limit on the size of the controller's ANA log page
 */
size_t nvme_get_ana_log_len_from_id_ctrl(const struct nvme_id_ctrl *id_ctrl,
		bool rgo);

/**
 * nvme_get_ana_log_atomic() - Retrieve Asymmetric Namespace Access
 * log page atomically
 * @hdl:	Transport handle
 * @rae:	Whether to retain asynchronous events
 * @rgo:	Whether to retrieve ANA groups only (no NSIDs)
 * @log:	Pointer to a buffer to receive the ANA log page
 * @len:	Input: the length of the log page buffer.
 *		Output: the actual length of the ANA log page.
 * @retries:	The maximum number of times to retry on log page changes
 *
 * See &struct nvme_ana_log for the definition of the returned structure.
 *
 * Return: If successful, returns 0 and sets *len to the actual log page length.
 * If unsuccessful, returns the nvme command status if a response was received
 * (see &enum nvme_status_field) or -1 with errno set otherwise.
 * Sets errno = EINVAL if retries == 0.
 * Sets errno = EAGAIN if unable to read the log page atomically
 * because chgcnt changed during each of the retries attempts.
 * Sets errno = ENOSPC if the full log page does not fit in the provided buffer.
 */
int
nvme_get_ana_log_atomic(struct nvme_transport_handle *hdl, bool rae, bool rgo,
		struct nvme_ana_log *log, __u32 *len, unsigned int retries);

/**
 * nvme_get_ana_log_len() - Retrieve size of the current ANA log
 * @hdl:	Transport handle
 * @analen:	Pointer to where the length will be set on success
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_ana_log_len(struct nvme_transport_handle *hdl, size_t *analen);

/**
 * nvme_get_logical_block_size() - Retrieve block size
 * @hdl:	Transport handle
 * @nsid:	Namespace id
 * @blksize:	Pointer to where the block size will be set on success
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_logical_block_size(struct nvme_transport_handle *hdl, __u32 nsid,
		int *blksize);

/**
 * nvme_get_lba_status_log() - Retrieve the LBA Status log page
 * @hdl:	Transport handle
 * @rae:	Retain asynchronous events
 * @log:	On success, set to the value of the allocated and retrieved log.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_lba_status_log(struct nvme_transport_handle *hdl, bool rae,
		struct nvme_lba_status_log **log);

/**
 * nvme_get_feature_length() - Retrieve the command payload length for a
 *			       specific feature identifier
 * @fid:   Feature identifier, see &enum nvme_features_id.
 * @cdw11: The cdw11 value may affect the transfer (only known fid is
 *	   %NVME_FEAT_FID_HOST_ID)
 * @dir:   Data transfer direction: false - host to controller, true -
 *	   controller to host may affect the transfer (only known fid is
 *	   %NVME_FEAT_FID_HOST_MEM_BUF).
 * @len:   On success, set to this features payload length in bytes.
 *
 * Return: 0 on success, -1 with errno set to EINVAL if the function did not
 * recognize &fid.
 */
int nvme_get_feature_length(int fid, __u32 cdw11, enum nvme_data_tfr dir,
			    __u32 *len);

/**
 * nvme_get_directive_receive_length() - Get directive receive length
 * @dtype: Directive type, see &enum nvme_directive_dtype
 * @doper: Directive receive operation, see &enum nvme_directive_receive_doper
 * @len:   On success, set to this directives payload length in bytes.
 *
 * Return: 0 on success, -1 with errno set to EINVAL if the function did not
 * recognize &dtype or &doper.
 */
int nvme_get_directive_receive_length(enum nvme_directive_dtype dtype,
		enum nvme_directive_receive_doper doper, __u32 *len);
