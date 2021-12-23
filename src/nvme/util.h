// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#ifndef _LIBNVME_UTIL_H
#define _LIBNVME_UTIL_H

#include "types.h"

/**
 * nvme_status_to_errno() - Converts nvme return status to errno
 * @status:  Return status from an nvme passthrough commmand
 * @fabrics: Set to true if &status is to a fabrics target.
 *
 * Return: An errno representing the nvme status if it is an nvme status field,
 * or unchanged status is < 0 since errno is already set.
 */
__u8 nvme_status_to_errno(int status, bool fabrics);

/**
 * nvme_status_to_string() - Returns string describing nvme return status.
 * @status:  Return status from an nvme passthrough commmand
 * @fabrics: Set to true if &status is to a fabrics target.
 *
 * Return: String representation of the nvme status if it is an nvme status field,
 * or a standard errno string if status is < 0.
 */
const char *nvme_status_to_string(int status, bool fabrics);

/**
 * nvme_init_id_ns() - Initialize an Identify Namepsace structure for creation.
 * @ns:	      Address of the Identify Namespace structure to initialize
 * @nsze:     Namespace size
 * @ncap:     namespace capacity
 * @flbas:    formatted logical block size settings
 * @dps:      Data protection settings
 * @nmic:     Namespace sharing capabilities
 * @anagrpid: ANA group identifier
 * @nvmsetid: NVM Set identifer
 *
 * This is intended to be used with a namespace management "create", see
 * &nvme_ns_mgmt_create().
 */
void nvme_init_id_ns(struct nvme_id_ns *ns, __u64 nsze, __u64 ncap, __u8 flbas,
		     __u8 dps, __u8 nmic, __u32 anagrpid, __u16 nvmsetid);

/**
 * nvme_init_ctrl_list() - Initialize an nvme_ctrl_list structure from an array.
 * @cntlist:   The controller list structure to initialize
 * @num_ctrls: The number of controllers in the array, &ctrlist.
 * @ctrlist:   An array of controller identifiers in CPU native endian.
 *
 * This is intended to be used with any command that takes a controller list
 * argument. See &nvme_ns_attach_ctrls() and &nvme_ns_detach().
 */
void nvme_init_ctrl_list(struct nvme_ctrl_list *cntlist, __u16 num_ctrls,
			 __u16 *ctrlist);

/**
 * nvme_init_dsm_range() - Constructs a data set range structure
 * @dsm:	DSM range array
 * @ctx_attrs:	Array of context attributes
 * @llbas:	Array of length in logical blocks
 * @slbas:	Array of starting logical blocks
 * @nr_ranges:	The size of the dsm arrays
 *
 * Each array must be the same size of size 'nr_ranges'. This is intended to be
 * used with constructing a payload for &nvme_dsm().
 *
 * Return: The nvme command status if a response was received or -errno
 * otherwise.
 */
void nvme_init_dsm_range(struct nvme_dsm_range *dsm, __u32 *ctx_attrs,
			  __u32 *llbas, __u64 *slbas, __u16 nr_ranges);

/**
 * nvme_init_copy_range() -
 */
void nvme_init_copy_range(struct nvme_copy_range *copy, __u16 *nlbs,
			  __u64 *slbas, __u32 *eilbrts, __u32 *elbatms,
			  __u32 *elbats, __u16 nr);

/**
 * nvme_get_feature_length() - Retreive the command payload length for a
 * 			       specific feature identifier
 * @fid:   Feature identifier, see &enum nvme_features_id.
 * @cdw11: The cdw11 value may affect the transfer (only known fid is
 * 	   %NVME_FEAT_FID_HOST_ID)
 * @len:   On success, set to this features payload length in bytes.
 *
 * Return: 0 on success, -1 with errno set to EINVAL if the function did not
 * recognize &fid.
 */
int nvme_get_feature_length(int fid, __u32 cdw11, __u32 *len);

/**
 * nvme_get_directive_receive_length() -
 * @dtype: Directive type, see &enum nvme_directive_dtype
 * @doper: Directive receive operation, see &enum nvme_directive_receive_doper
 * @len:   On success, set to this directives payload length in bytes.
 *
 * Return: 0 on success, -1 with errno set to EINVAL if the function did not
 * recognize &dtype or &doper.
 */
int nvme_get_directive_receive_length(enum nvme_directive_dtype dtype,
		enum nvme_directive_receive_doper doper, __u32 *len);

#define NVME_FEAT_ARB_BURST(v)		NVME_GET(v, FEAT_ARBITRATION_BURST)
#define NVME_FEAT_ARB_LPW(v)		NVME_GET(v, FEAT_ARBITRATION_LPW)
#define NVME_FEAT_ARB_MPW(v)		NVME_GET(v, FEAT_ARBITRATION_MPW)
#define NVME_FEAT_ARB_HPW(v)		NVME_GET(v, FEAT_ARBITRATION_HPW)

static inline void nvme_feature_decode_arbitration(__u32 value, __u8 *ab,
						   __u8 *lpw, __u8 *mpw,
						   __u8 *hpw)
{
	*ab  = NVME_FEAT_ARB_BURST(value);
	*lpw = NVME_FEAT_ARB_LPW(value);
	*mpw = NVME_FEAT_ARB_MPW(value);
	*hpw = NVME_FEAT_ARB_HPW(value);
};

#define NVME_FEAT_PM_PS(v)		NVME_GET(v, FEAT_PWRMGMT_PS)
#define NVME_FEAT_PM_WH(v)		NVME_GET(v, FEAT_PWRMGMT_WH)

static inline void nvme_feature_decode_power_mgmt(__u32 value, __u8 *ps,
						  __u8 *wh)
{
	*ps = NVME_FEAT_PM_PS(value);
	*wh = NVME_FEAT_PM_WH(value);
}

#define NVME_FEAT_LBAR_NR(v)		NVME_GET(v, FEAT_LBAR_NR)

static inline void nvme_feature_decode_lba_range(__u32 value, __u8 *num)
{
	*num = NVME_FEAT_LBAR_NR(value);
}

#define NVME_FEAT_TT_TMPTH(v)		NVME_GET(v, FEAT_TT_TMPTH)
#define NVME_FEAT_TT_TMPSEL(v)		NVME_GET(v, FEAT_TT_TMPSEL)
#define NVME_FEAT_TT_THSEL(v)		NVME_GET(v, FEAT_TT_THSEL)

static inline void nvme_feature_decode_temp_threshold(__u32 value, __u16 *tmpth,
						      __u8 *tmpsel, __u8 *thsel)
{
	*tmpth	= NVME_FEAT_TT_TMPTH(value);
	*tmpsel	= NVME_FEAT_TT_TMPSEL(value);
	*thsel	= NVME_FEAT_TT_THSEL(value);
}

#define NVME_FEAT_ER_TLER(v)		NVME_GET(v, FEAT_ERROR_RECOVERY_TLER)
#define NVME_FEAT_ER_DULBE(v)		NVME_GET(v, FEAT_ERROR_RECOVERY_DULBE)

static inline void nvme_feature_decode_error_recovery(__u32 value, __u16 *tler,
						      bool *dulbe)
{
	*tler	= NVME_FEAT_ER_TLER(value);
	*dulbe	= NVME_FEAT_ER_DULBE(value);
}

#define NVME_FEAT_VWC_WCE(v)		NVME_GET(v, FEAT_VWC_WCE)

static inline void nvme_feature_decode_volatile_write_cache(__u32 value,
							    bool *wce)
{
	*wce	= NVME_FEAT_VWC_WCE(value);
}

#define NVME_FEAT_NRQS_NSQR(v)		NVME_GET(v, FEAT_NRQS_NSQR)
#define NVME_FEAT_NRQS_NCQR(v)		NVME_GET(v, FEAT_NRQS_NCQR)

static inline void nvme_feature_decode_number_of_queues(__u32 value,
							__u16 *nsqr,
							__u16 *ncqr)
{
	*nsqr	= NVME_FEAT_NRQS_NSQR(value);
	*ncqr	= NVME_FEAT_NRQS_NCQR(value);
}

#define NVME_FEAT_IRQC_THR(v)		NVME_GET(v, FEAT_IRQC_THR)
#define NVME_FEAT_IRQC_TIME(v)		NVME_GET(v, FEAT_IRQC_TIME)

static inline void nvme_feature_decode_interrupt_coalescing(__u32 value,
							    __u8 *thr,
							    __u8 *time)
{
	*thr	= NVME_FEAT_IRQC_THR(value);
	*time	= NVME_FEAT_IRQC_TIME(value);
}

#define NVME_FEAT_ICFG_IV(v)		NVME_GET(v, FEAT_ICFG_IV)
#define NVME_FEAT_ICFG_CD(v)		NVME_GET(v, FEAT_ICFG_CD)

static inline void nvme_feature_decode_interrupt_config(__u32 value, __u16 *iv,
							bool *cd)
{
	*iv	= NVME_FEAT_ICFG_IV(value);
	*cd	= NVME_FEAT_ICFG_CD(value);
}

#define NVME_FEAT_WA_DN(v)		NVME_GET(v, FEAT_WA_DN)

static inline void nvme_feature_decode_write_atomicity(__u32 value, bool *dn)
{
	*dn	= NVME_FEAT_WA_DN(value);
}

#define NVME_FEAT_AE_SMART(v)		NVME_GET(v, FEAT_AE_SMART)
#define NVME_FEAT_AE_NAN(v)		NVME_GET(v, FEAT_AE_NAN)
#define NVME_FEAT_AE_FW(v)		NVME_GET(v, FEAT_AE_FW)
#define NVME_FEAT_AE_TELEM(v)		NVME_GET(v, FEAT_AE_TELEM)
#define NVME_FEAT_AE_ANA(v)		NVME_GET(v, FEAT_AE_ANA)
#define NVME_FEAT_AE_PLA(v)		NVME_GET(v, FEAT_AE_PLA)
#define NVME_FEAT_AE_LBAS(v)		NVME_GET(v, FEAT_AE_LBAS)
#define NVME_FEAT_AE_EGA(v)		NVME_GET(v, FEAT_AE_EGA)

static inline void nvme_feature_decode_async_event_config(__u32 value,
			  __u8 *smart, bool *nan, bool *fw, bool *telem,
			  bool *ana, bool *pla, bool *lbas, bool *ega)
{
	*smart	= NVME_FEAT_AE_SMART(value);
	*nan	= NVME_FEAT_AE_NAN(value);
	*fw	= NVME_FEAT_AE_FW(value);
	*telem	= NVME_FEAT_AE_TELEM(value);
	*ana	= NVME_FEAT_AE_ANA(value);
	*pla	= NVME_FEAT_AE_PLA(value);
	*lbas	= NVME_FEAT_AE_LBAS(value);
	*ega	= NVME_FEAT_AE_EGA(value);
}

#define NVME_FEAT_APST_APSTE(v)		NVME_GET(v, FEAT_APST_APSTE)

static inline void nvme_feature_decode_auto_power_state(__u32 value,
							bool *apste)
{
	*apste	= NVME_FEAT_APST_APSTE(value);
}

#define NVME_FEAT_HMEM_EHM(v)		NVME_GET(v, FEAT_HMEM_EHM)

static inline void nvme_feature_decode_host_memory_buffer(__u32 value, bool *ehm)
{
	*ehm	= NVME_FEAT_HMEM_EHM(value);
}

#define NVME_FEAT_HCTM_TMT2(v)		NVME_GET(v, FEAT_HCTM_TMT2)
#define NVME_FEAT_HCTM_TMT1(v)		NVME_GET(v, FEAT_HCTM_TMT1)

static inline void nvme_feature_decode_host_thermal_mgmt(__u32 value,
							 __u16 *tmt2,
							 __u16 *tmt1)
{
	*tmt2	= NVME_FEAT_HCTM_TMT2(value);
	*tmt1	= NVME_FEAT_HCTM_TMT1(value);
}

#define NVME_FEAT_NOPS_NOPPME(v)	NVME_GET(v, FEAT_NOPS_NOPPME)

static inline void nvme_feature_decode_non_op_power_config(__u32 value,
							   bool *noppme)
{
	*noppme	= NVME_FEAT_NOPS_NOPPME(value);
}

#define NVME_FEAT_RRL_RRL(v)		NVME_GET(v, FEAT_RRL_RRL)

static inline void nvme_feature_decode_read_recovery_level_config(__u32 value,
								  __u8 *rrl)
{
	*rrl	= NVME_FEAT_RRL_RRL(value);
}

#define NVME_FEAT_PLM_PLME(v)		NVME_GET(v, FEAT_PLM_PLME)

static inline void nvme_feature_decode_predictable_latency_mode_config(__u32 value,
								       bool *plme)
{
	*plme	= NVME_FEAT_PLM_PLME(value);
}

#define NVME_FEAT_PLMW_WS(v)		NVME_GET(v, FEAT_PLMW_WS)

static inline void nvme_feature_decode_predictable_latency_mode_window(__u32 value,
								       __u8 *ws)
{
	*ws	= NVME_FEAT_PLMW_WS(value);
}

#define NVME_FEAT_LBAS_LSIRI(v)		NVME_GET(v, FEAT_LBAS_LSIRI)
#define NVME_FEAT_LBAS_LSIPI(v)		NVME_GET(v, FEAT_LBAS_LSIPI)

static inline void nvme_feature_decode_lba_status_attributes(__u32 value,
							     __u16 *lsiri,
							     __u16 *lsipi)
{
	*lsiri	= NVME_FEAT_LBAS_LSIRI(value);
	*lsipi	= NVME_FEAT_LBAS_LSIPI(value);
}

#define NVME_FEAT_SC_NODRM(v)		NVME_GET(v, FEAT_SC_NODRM)

static inline void nvme_feature_decode_sanitize_config(__u32 value, bool *nodrm)
{
	*nodrm	= NVME_FEAT_SC_NODRM(value);
}

#define NVME_FEAT_EG_ENDGID(v)		NVME_GET(v, FEAT_EG_ENDGID)
#define NVME_FEAT_EG_EGCW(v)		NVME_GET(v, FEAT_EG_EGCW)

static inline void nvme_feature_decode_endurance_group_event_config(__u32 value,
	__u16 *endgid, __u8 *endgcw)
{
	*endgid	= NVME_FEAT_EG_ENDGID(value);
	*endgcw	= NVME_FEAT_EG_EGCW(value);
}

#define NVME_FEAT_SPM_PBSLC(v)		NVME_GET(v, FEAT_SPM_PBSLC)

static inline void nvme_feature_decode_software_progress_marker(__u32 value,
								__u8 *pbslc)
{
	*pbslc	= NVME_FEAT_SPM_PBSLC(value);
}

#define NVME_FEAT_HOSTID_EXHID(v)	NVME_GET(v, FEAT_HOSTID_EXHID)

static inline void nvme_feature_decode_host_identifier(__u32 value, bool *exhid)
{
	*exhid = NVME_FEAT_HOSTID_EXHID(value);
}

#define NVME_FEAT_RM_REGPRE(v)		NVME_GET(v, FEAT_RM_REGPRE)
#define NVME_FEAT_RM_RESREL(v)		NVME_GET(v, FEAT_RM_RESREL)
#define NVME_FEAT_RM_RESPRE(v)		NVME_GET(v, FEAT_RM_RESPRE)

static inline void nvme_feature_decode_reservation_notification(__u32 value,
								bool *regpre,
								bool *resrel,
								bool *respre)
{
	*regpre	= NVME_FEAT_RM_REGPRE(value);
	*resrel	= NVME_FEAT_RM_RESREL(value);
	*respre	= NVME_FEAT_RM_RESPRE(value);
}

#define NVME_FEAT_RP_PTPL(v)		NVME_GET(v, FEAT_RP_PTPL)

static inline void nvme_feature_decode_reservation_persistance(__u32 value,
							       bool *ptpl)
{
	*ptpl	= NVME_FEAT_RP_PTPL(value);
}

#define NVME_FEAT_WP_WPS(v)		NVME_GET(v, FEAT_WP_WPS)

static inline void nvme_feature_decode_namespace_write_protect(__u32 value,
							       __u8 *wps)
{
	*wps	= NVME_FEAT_WP_WPS(value);
}
#endif /* _LIBNVME_UTIL_H */
