// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#ifndef _LIBNVME_UTIL_H
#define _LIBNVME_UTIL_H

#include "types.h"

/**
 * DOC: util.h
 *
 * libnvme utility functions
 */

/**
 * enum nvme_connect_err - nvme connect error codes
 * @ENVME_CONNECT_RESOLVE:	failed to resolve host
 * @ENVME_CONNECT_ADDRFAM:	unrecognized address family
 * @ENVME_CONNECT_TRADDR:	failed to get traddr
 * @ENVME_CONNECT_TARG:		need a transport (-t) argument
 * @ENVME_CONNECT_AARG:		need a address (-a) argument
 * @ENVME_CONNECT_OPEN:		failed to open nvme-fabrics device
 * @ENVME_CONNECT_WRITE:	failed to write to nvme-fabrics device
 * @ENVME_CONNECT_READ:		failed to read from nvme-fabrics device
 * @ENVME_CONNECT_PARSE:	failed to parse ctrl info
 * @ENVME_CONNECT_INVAL_TR:	invalid transport type
 * @ENVME_CONNECT_LOOKUP_SUBSYS_NAME:	failed to lookup subsystem name
 * @ENVME_CONNECT_LOOKUP_SUBSYS: failed to lookup subsystem
 * @ENVME_CONNECT_ALREADY:	the connect attempt failed, already connected
 * @ENVME_CONNECT_INVAL:	invalid arguments/configuration
 * @ENVME_CONNECT_ADDRINUSE:	hostnqn already in use
 * @ENVME_CONNECT_NODEV:	invalid interface
 * @ENVME_CONNECT_OPNOTSUPP:	not supported
 * @ENVME_CONNECT_CONNREFUSED:      connection refused
 */
enum nvme_connect_err {
	ENVME_CONNECT_RESOLVE	= 1000,
	ENVME_CONNECT_ADDRFAM,
	ENVME_CONNECT_TRADDR,
	ENVME_CONNECT_TARG,
	ENVME_CONNECT_AARG,
	ENVME_CONNECT_OPEN,
	ENVME_CONNECT_WRITE,
	ENVME_CONNECT_READ,
	ENVME_CONNECT_PARSE,
	ENVME_CONNECT_INVAL_TR,
	ENVME_CONNECT_LOOKUP_SUBSYS_NAME,
	ENVME_CONNECT_LOOKUP_SUBSYS,
	ENVME_CONNECT_ALREADY,
	ENVME_CONNECT_INVAL,
	ENVME_CONNECT_ADDRINUSE,
	ENVME_CONNECT_NODEV,
	ENVME_CONNECT_OPNOTSUPP,
	ENVME_CONNECT_CONNREFUSED,
};

/**
 * nvme_status_to_errno() - Converts nvme return status to errno
 * @status:  Return status from an nvme passthrough command
 * @fabrics: Set to true if &status is to a fabrics target.
 *
 * Return: An errno representing the nvme status if it is an nvme status field,
 * or unchanged status is < 0 since errno is already set.
 */
__u8 nvme_status_to_errno(int status, bool fabrics);

/**
 * nvme_status_to_string() - Returns string describing nvme return status.
 * @status:  Return status from an nvme passthrough command
 * @fabrics: Set to true if &status is to a fabrics target.
 *
 * Return: String representation of the nvme status if it is an nvme status field,
 * or a standard errno string if status is < 0.
 */
const char *nvme_status_to_string(int status, bool fabrics);

/**
 * nvme_errno_to_string() - Returns string describing nvme connect failures
 * @err: Returned error code from nvme_add_ctrl()
 *
 * Return: String representation of the nvme connect error codes
 */
const char *nvme_errno_to_string(int err);

/**
 * nvme_init_ctrl_list() - Initialize an nvme_ctrl_list structure from an array.
 * @cntlist:   The controller list structure to initialize
 * @num_ctrls: The number of controllers in the array, &ctrlist.
 * @ctrlist:   An array of controller identifiers in CPU native endian.
 *
 * This is intended to be used with any command that takes a controller list
 * argument. See nvme_ns_attach_ctrls() and nvme_ns_detach().
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
 * used with constructing a payload for nvme_dsm().
 *
 * Return: The nvme command status if a response was received or -errno
 * otherwise.
 */
void nvme_init_dsm_range(struct nvme_dsm_range *dsm, __u32 *ctx_attrs,
			  __u32 *llbas, __u64 *slbas, __u16 nr_ranges);

/**
 * nvme_init_copy_range() - Constructs a copy range structure
 * @copy:	Copy range array
 * @nlbs:	Number of logical blocks
 * @slbas:	Starting LBA
 * @eilbrts:	Expected initial logical block reference tag
 * @elbatms:	Expected logical block application tag mask
 * @elbats:	Expected logical block application tag
 * @nr:		Number of descriptors to construct
 */
void nvme_init_copy_range(struct nvme_copy_range *copy, __u16 *nlbs,
			  __u64 *slbas, __u32 *eilbrts, __u32 *elbatms,
			  __u32 *elbats, __u16 nr);

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
void nvme_init_copy_range_f1(struct nvme_copy_range_f1 *copy, __u16 *nlbs,
			     __u64 *slbas, __u64 *eilbrts, __u32 *elbatms,
			     __u32 *elbats, __u16 nr);

/**
 * nvme_get_feature_length() - Retreive the command payload length for a
 *			       specific feature identifier
 * @fid:   Feature identifier, see &enum nvme_features_id.
 * @cdw11: The cdw11 value may affect the transfer (only known fid is
 *	   %NVME_FEAT_FID_HOST_ID)
 * @len:   On success, set to this features payload length in bytes.
 *
 * Return: 0 on success, -1 with errno set to EINVAL if the function did not
 * recognize &fid.
 */
int nvme_get_feature_length(int fid, __u32 cdw11, __u32 *len);

/**
 * nvme_get_feature_length2() - Retreive the command payload length for a
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
int nvme_get_feature_length2(int fid, __u32 cdw11, enum nvme_data_tfr dir,
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

static inline void nvme_id_ns_flbas_to_lbaf_inuse(__u8 flbas, __u8 *lbaf_inuse)
{
	*lbaf_inuse = (((flbas & NVME_NS_FLBAS_HIGHER_MASK) >> 1) |
			(flbas & NVME_NS_FLBAS_LOWER_MASK));
}

struct nvme_root;

char *hostname2traddr(struct nvme_root *r, const char *traddr);

/**
 * get_entity_name - Get Entity Name (ENAME).
 * @buffer: The buffer where the ENAME will be saved as an ASCII string.
 * @bufsz:  The size of @buffer.
 *
 * Per TP8010, ENAME is defined as the name associated with the host (i.e.
 * hostname).
 *
 * Return: Number of characters copied to @buffer.
 */
size_t get_entity_name(char *buffer, size_t bufsz);

/**
 * get_entity_version - Get Entity Version (EVER).
 * @buffer: The buffer where the EVER will be saved as an ASCII string.
 * @bufsz:  The size of @buffer.
 *
 * EVER is defined as the operating system name and version as an ASCII
 * string. This function reads different files from the file system and
 * builds a string as follows: [os type] [os release] [distro release]
 *
 *     E.g. "Linux 5.17.0-rc1 SLES 15.4"
 *
 * Return: Number of characters copied to @buffer.
 */
size_t get_entity_version(char *buffer, size_t bufsz);

/**
 * kv_strip - Strip blanks from key value string
 * @kv: The key-value string to strip
 *
 * Strip leading/trailing blanks as well as trailing comments from the
 * Key=Value string pointed to by @kv.
 *
 * Return: A pointer to the stripped string. Note that the original string,
 * @kv, gets modified.
 */
char *kv_strip(char *kv);

/**
 * kv_keymatch - Look for key in key value string
 * @kv:  The key=value string to search for the presence of @key
 * @key: The key to look for
 *
 * Look for @key in the Key=Value pair pointed to by @k and return a
 * pointer to the Value if @key is found.
 *
 * Check if @kv starts with @key. If it does then make sure that we
 * have a whole-word match on the @key, and if we do, return a pointer
 * to the first character of value (i.e. skip leading spaces, tabs,
 * and equal sign)
 *
 * Return: A pointer to the first character of "value" if a match is found.
 * NULL otherwise.
 */
char *kv_keymatch(const char *kv, const char *key);

/**
 * startswith - Checks that a string starts with a given prefix.
 * @s:      The string to check
 * @prefix: A string that @s could be starting with
 *
 * Return: If @s starts with @prefix, then return a pointer within @s at
 * the first character after the matched @prefix. NULL otherwise.
 */
char *startswith(const char *s, const char *prefix);

#define __round_mask(val, mult) ((__typeof__(val))((mult)-1))

/**
 * round_up - Round a value @val to the next multiple specified by @mult.
 * @val:  Value to round
 * @mult: Multiple to round to.
 *
 * usage: int x = round_up(13, sizeof(__u32)); // 13 -> 16
 */
#define round_up(val, mult)     ((((val)-1) | __round_mask((val), (mult)))+1)

/**
 * nvmf_exat_len() - Return length rounded up by 4
 * @val_len: Value length
 *
 * Return the size in bytes, rounded to a multiple of 4 (e.g., size of
 * __u32), of the buffer needed to hold the exat value of size
 * @val_len.
 *
 * Return: Length rounded up by 4
 */
static inline __u16 nvmf_exat_len(size_t val_len)
{
	return (__u16)round_up(val_len, sizeof(__u32));
}

/**
 * nvmf_exat_size - Return min aligned size to hold value
 * @val_len: This is the length of the data to be copied to the "exatval"
 *           field of a "struct nvmf_ext_attr".
 *
 * Return the size of the "struct nvmf_ext_attr" needed to hold
 * a value of size @val_len.
 *
 * Return: The size in bytes, rounded to a multiple of 4 (i.e. size of
 * __u32), of the "struct nvmf_ext_attr" required to hold a string of
 * length @val_len.
 */
static inline __u16 nvmf_exat_size(size_t val_len)
{
	return (__u16)(sizeof(struct nvmf_ext_attr) + nvmf_exat_len(val_len));
}

/**
 * nvmf_exat_ptr_next - Increment @p to the next element in the array.
 * @p: Pointer to an element of an array of "struct nvmf_ext_attr".
 *
 * Extended attributes are saved to an array of "struct nvmf_ext_attr"
 * where each element of the array is of variable size. In order to
 * move to the next element in the array one must increment the
 * pointer to the current element (@p) by the size of the current
 * element.
 *
 * Return: Pointer to the next element in the array.
 */
struct nvmf_ext_attr *nvmf_exat_ptr_next(struct nvmf_ext_attr *p);

/**
 * enum nvme_version - Selector for version to be returned by @nvme_get_version
 *
 * @NVME_VERSION_PROJECT:	Project release version
 * @NVME_VERSION_GIT:		Git reference
 */
enum nvme_version {
	NVME_VERSION_PROJECT	= 0,
	NVME_VERSION_GIT	= 1,
};

/**
 * nvme_get_version - Return version libnvme string
 * @type:	Selects which version type (see @struct nvme_version)
 *
 * Return: Returns version string for known types or else "n/a"
 */
const char *nvme_get_version(enum nvme_version type);

#define NVME_UUID_LEN_STRING	37  /* 1b4e28ba-2fa1-11d2-883f-0016d3cca427 + \0 */
#define NVME_UUID_LEN		16

/**
 * nvme_uuid_to_string - Return string represenation of encoded UUID
 * @uuid:	Binary encoded input UUID
 * @str:	Output string represenation of UUID
 *
 * Return: Returns error code if type conversion fails.
 */
int nvme_uuid_to_string(unsigned char uuid[NVME_UUID_LEN], char *str);

/**
 * nvme_uuid_from_string - Return encoded UUID represenation of string UUID
 * @uuid:	Binary encoded input UUID
 * @str:	Output string represenation of UUID
 *
 * Return: Returns error code if type conversion fails.
 */
int nvme_uuid_from_string(const char *str, unsigned char uuid[NVME_UUID_LEN]);

/**
 * nvme_uuid_random - Generate random UUID
 * @uuid:       Generated random UUID
 *
 * Generate random number according
 * https://www.rfc-editor.org/rfc/rfc4122#section-4.4
 *
 * Return: Returns error code if generating of random number fails.
 */
int nvme_uuid_random(unsigned char uuid[NVME_UUID_LEN]);

#endif /* _LIBNVME_UTIL_H */
