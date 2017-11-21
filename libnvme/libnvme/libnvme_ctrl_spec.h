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

#ifndef _LIBNVME_CTRL_SPEC_H_
#define _LIBNVME_CTRL_SPEC_H_

#include "libnvme_common.h"

#include <stdint.h>

struct _DLL_PUBLIC nvme_ctrl;
struct _DLL_PUBLIC nvme_psd;

/**
 * nvme_ctrl_vid_get() - Retrieve the VID property of specified NVMe controller.
 *
 * Retrieve the VID(Vendor ID) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_vid_get(struct nvme_ctrl *cnt);


/**
 * nvme_ctrl_ssvid_get() - Retrieve the SSVID property of specified NVMe
 * controller.
 *
 * Retrieve the SSVID(Subsystem Vendor ID) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_ssvid_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_sn_get() - Retrieve the SN property of specified NVMe
 * controller.
 *
 * Retrieve the SN(Serial Number) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	String. Please don't free this memory, it will be released by
 *	nvme_ctrls_free() or nvme_ctrl_free().
 */
_DLL_PUBLIC const char *nvme_ctrl_sn_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_mn_get() - Retrieve the MN property of specified NVMe
 * controller.
 *
 * Retrieve the MN(Model Number) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	String. Please don't free this memory, it will be released by
 *	nvme_ctrls_free() or nvme_ctrl_free().
 */
_DLL_PUBLIC const char *nvme_ctrl_mn_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_fr_get() - Retrieve the FR property of specified NVMe
 * controller.
 *
 * Retrieve the FR(Firmware Revision) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	String. Please don't free this memory, it will be released by
 *	nvme_ctrls_free() or nvme_ctrl_free().
 */
_DLL_PUBLIC const char *nvme_ctrl_fr_get(struct nvme_ctrl *cnt);


/**
 * nvme_ctrl_rab_get() - Retrieve the RAB property of specified NVMe controller.
 *
 * Retrieve the RAB(Recommended Arbitration Burst) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_rab_get(struct nvme_ctrl *cnt);


/**
 * nvme_ctrl_ieee_get() - Retrieve the IEEE property of specified NVMe
 * controller.
 *
 * Retrieve the IEEE(IEEE OUI Identifier) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint32_t nvme_ctrl_ieee_get(struct nvme_ctrl *cnt);


/**
 * nvme_ctrl_cmic_get() - Retrieve the CMIC property of specified NVMe
 * controller.
 *
 * Retrieve the CMIC(Controller Multi-Path I/O and Namespace Sharing
 * Capabilities) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_cmic_get(struct nvme_ctrl *cnt);


/**
 * nvme_ctrl_mdts_get() - Retrieve the MDTS property of specified NVMe
 * controller.
 *
 * Retrieve the MDTS(Maximum Data Transfer Size) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_mdts_get(struct nvme_ctrl *cnt);


/**
 * nvme_ctrl_cntlid_get() - Retrieve the CNTLID property of specified NVMe
 * controller.
 *
 * Retrieve the CNTLID(Controller ID) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_cntlid_get(struct nvme_ctrl *cnt);


/**
 * nvme_ctrl_ver_get() - Retrieve the VER property of specified NVMe
 * controller.
 *
 * Retrieve the VER(Version) property of specified NVMe controller.
 * Example of using this version number:
 *
 *	if (nvme_ctrl_ver_get(ctrl) >= NVME_SPEC_VERSION(1, 2, 0)) {
 *	    // Then we are facing 1.2.0+ NVMe implementation.
 *	}
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_ctrl_ver_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_rtd3r_get() - Retrieve the RTD3R property of specified NVMe
 * controller.
 *
 * Retrieve the RTD3R(RTD3 Resume Latency) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_ctrl_rtd3r_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_rtd3e_get() - Retrieve the RTD3E property of specified NVMe
 * controller.
 *
 * Retrieve the RTD3E(RTD3 Entry Latency) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_ctrl_rtd3e_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_oaes_get() - Retrieve the OAES property of specified NVMe
 * controller.
 *
 * Retrieve the OAES(Optional Asynchronous Events Supported) property of
 * specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_oaes_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_ctratt_get() - Retrieve the CTRATT property of specified NVMe
 * controller.
 *
 * Retrieve the CTRATT(Controller Attributes) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_ctrl_ctratt_get(struct nvme_ctrl *cnt);
/**
 * nvme_ctrl_fguid_get() - Retrieve the FGUID property of specified NVMe
 * controller.
 *
 * Retrieve the FGUID(FRU Globally Unique Identifier) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	String. Please don't free this memory, it will be released by
 *	nvme_ctrls_free() or nvme_ctrl_free().
 */

_DLL_PUBLIC const char *nvme_ctrl_fguid_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_oacs_get() - Retrieve the OACS property of specified NVMe
 * controller.
 *
 * Retrieve the OACS(Optional Admin Command Support) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_oacs_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_acl_get() - Retrieve the ACL property of specified NVMe
 * controller.
 *
 * Retrieve the ACL(Abort Command Limit) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_acl_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_aerl_get() - Retrieve the AERL property of specified NVMe
 * controller.
 *
 * Retrieve the AERL(Asynchronous Event Request Limit) property of specified
 * NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_aerl_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_frmw_get() - Retrieve the FRMW property of specified
 * NVMe controller.
 *
 * Retrieve the FRMW(Firmware Updates) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_frmw_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_ipa_get() - Retrieve the IPA property of specified
 * NVMe controller.
 *
 * Retrieve the IPA(Log Page Attributes) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_lpa_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_elpe_get() - Retrieve the ELPE property of specified
 * NVMe controller.
 *
 * Retrieve the ELPE(Error Log Page Entries) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_elpe_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_npss_get() - Retrieve the NPSS property of specified
 * NVMe controller.
 *
 * Retrieve the NPSS(Number of Power States Support) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_npss_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_avscc_get() - Retrieve the AVSCC property of specified
 * NVMe controller.
 *
 * Retrieve the AVSCC(Admin Vendor Specific Command Configuration) property of
 * specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_avscc_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_apsta_get() - Retrieve the APSTA property of specified
 * NVMe controller.
 *
 * Retrieve the APSTA(Autonomous Power State Transition Attributes) property of
 * specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_apsta_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_wctemp_get() - Retrieve the WCTEMP property of specified
 * NVMe controller.
 *
 * Retrieve the WCTEMP(Warning Composite Temperature Threshold) property of
 * specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_wctemp_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_cctemp_get() - Retrieve the CCTEMP property of specified
 * NVMe controller.
 *
 * Retrieve the CCTEMP(Critical Composite Temperature Threshold) property of
 * specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_cctemp_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_mtfa_get() - Retrieve the MTFA property of specified
 * NVMe controller.
 *
 * Retrieve the MTFA(Maximum Time for Firmware Activation) property of specified
 * NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_mtfa_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_hmpre_get() - Retrieve the HMPRE property of specified
 * NVMe controller.
 *
 * Retrieve the HMPRE(Host Memory Buffer Preferred Size) property of specified
 * NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_ctrl_hmpre_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_hmmin_get() - Retrieve the HMMIN property of specified
 * NVMe controller.
 *
 * Retrieve the HMMIN(Host Memory Buffer Minimum Size) property of specified
 * NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_ctrl_hmmin_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_tnvmcap_get() - Retrieve the TNVMCAP property of specified
 * NVMe controller.
 *
 * Retrieve the TNVMCAP(Total NVM Capacity) property of specified NVMe
 * controller.
 * You may use these lines to retrieve the least significant 64 bits of it:
 *
 *	le64toh(*((uint64_t *) nvme_ctrl_tnvmcap_get(cnt);
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t array with size of 16 representing a 128 bit integer in little
 *	endian.
 */
_DLL_PUBLIC const uint8_t *nvme_ctrl_tnvmcap_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_unvmcap_get() - Retrieve the UNVMCAP property of specified
 * NVMe controller.
 *
 * Retrieve the UNVMCAP(Unallocated NVM Capacity) property of specified NVMe
 * controller.
 * You may use these lines to retrieve the least significant 64 bits of it:
 *
 *	le64toh(*((uint64_t *) nvme_ctrl_unvmcap_get(cnt);
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t array with size of 16 representing a 128 bit integer in little
 *	endian.
 */
_DLL_PUBLIC const uint8_t *nvme_ctrl_unvmcap_get(struct nvme_ctrl *cnt);


/* TODO(Gris Ge): Expose bit field properties of RPMBS */

/**
 * nvme_ctrl_rpmbs_get() - Retrieve the RPMBS property of specified
 * NVMe controller.
 *
 * Retrieve the RPMBS(Replay Protected Memory Block Support) property of
 * specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_ctrl_rpmbs_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_edstt_get() - Retrieve the EDSTT property of specified
 * NVMe controller.
 *
 * Retrieve the EDSTT(Extended Device Self-test Time) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_edstt_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_esto_get() - Retrieve the ESTO property of specified
 * NVMe controller.
 *
 * Retrieve the ESTO(Device Self-test Options) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_esto_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_fwug_get() - Retrieve the FWUG property of specified
 * NVMe controller.
 *
 * Retrieve the FWUG(Firmware Update Granularity) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_fwug_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_kas_get() - Retrieve the KAS property of specified
 * NVMe controller.
 *
 * Retrieve the KAS(Keep Alive Support) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_kas_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_hctma_get() - Retrieve the HCTMA property of specified
 * NVMe controller.
 *
 * Retrieve the HCTMA(Host Controlled Thermal Management Attributes) property of
 * specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_hctma_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_mntmt_get() - Retrieve the MNTMT property of specified
 * NVMe controller.
 *
 * Retrieve the MNTMT(Minimum Thermal Management Temperature) property of
 * specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_mntmt_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_mxtmt_get() - Retrieve the MXTMT property of specified
 * NVMe controller.
 *
 * Retrieve the MXTMT(Maximum Thermal Management Temperature) property of
 * specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_mxtmt_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_sanicap_get() - Retrieve the SANICAP property of specified
 * NVMe controller.
 *
 * Retrieve the SANICAP(Sanitize Capabilities) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_ctrl_sanicap_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_sqes_get() - Retrieve the SQES property of specified
 * NVMe controller.
 *
 * Retrieve the SQES(Submission Queue Entry Size) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_sqes_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_cqes_get() - Retrieve the CQES property of specified
 * NVMe controller.
 *
 * Retrieve the CQES(Completion Queue Entry Size) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_cqes_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_maxcmd_get() - Retrieve the MAXCMD property of specified
 * NVMe controller.
 *
 * Retrieve the MAXCMD(Maximum Outstanding Commands) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_maxcmd_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_nn_get() - Retrieve the NN property of specified
 * NVMe controller.
 *
 * Retrieve the NN(Number of Namespaces) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_ctrl_nn_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_oncs_get() - Retrieve the ONCS property of specified
 * NVMe controller.
 *
 * Retrieve the ONCS(Optional NVM Command Support) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_oncs_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_fuses_get() - Retrieve the FUSES property of specified
 * NVMe controller.
 *
 * Retrieve the FUSES(Fused Operation Support) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_fuses_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_fna_get() - Retrieve the FNA property of specified
 * NVMe controller.
 *
 * Retrieve the FNA(Format NVM Attributes) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_fna_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_vwc_get() - Retrieve the VWC property of specified
 * NVMe controller.
 *
 * Retrieve the VWC(Volatile Write Cache) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_vwc_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_awun_get() - Retrieve the AWUN property of specified
 * NVMe controller.
 *
 * Retrieve the AWUN(Atomic Write Unit Normal) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_awun_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_awupf_get() - Retrieve the AWUPF property of specified
 * NVMe controller.
 *
 * Retrieve the AWUPF(Atomic Write Unit Power Fail) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_awupf_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_nvscc_get() - Retrieve the NVSCC property of specified
 * NVMe controller.
 *
 * Retrieve the NVSCC(NVM Vendor Specific Command Configuration) property of
 * specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_nvscc_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_acwu_get() - Retrieve the ACWU property of specified NVMe
 * controller.
 *
 * Retrieve the ACWU(Atomic Compare & Write Unit) property of specified NVMe
 * controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_acwu_get(struct nvme_ctrl *cnt);

/* TODO(Gris Ge): Expose bit field properties of SGLS */

/**
 * nvme_ctrl_sgls_get() - Retrieve the SGLS property of specified NVMe
 * controller.
 *
 * Retrieve the SGLS(SGL Support) property of specified NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_ctrl_sgls_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_subnqn_get() - Retrieve the SUBNQN property of
 * specified NVMe controller.
 *
 * Retrieve the SUBNQN(NVM Subsystem NVMe Qualified Name) property of specified
 * NVMe controller.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	String. Please don't free this memory, it will be released by
 *	nvme_ctrls_free() or nvme_ctrl_free().
 */
_DLL_PUBLIC const char *nvme_ctrl_subnqn_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_ioccsz_get() - Retrieve the IOCCSZ property of
 * specified NVMe controller.
 *
 * Retrieve the IOCCSZ(I/O Queue Command Capsule Supported Size) property of
 * specified NVMe controller. This property is only for NVMe over Fabrics.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_ctrl_ioccsz_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_iorcsz_get() - Retrieve the IORCSZ property of
 * specified NVMe controller.
 *
 * Retrieve the IORCSZ(I/O Queue Response Capsule Supported Size) property of
 * specified NVMe controller.  This property is only for NVMe over Fabrics.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_ctrl_iorcsz_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_icdoff_get() - Retrieve the ICDOFF property of
 * specified NVMe controller.
 *
 * Retrieve the ICDOFF(In Capsule Data Offset) property of specified NVMe
 * controller. This property is only for NVMe over Fabrics.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_ctrl_icdoff_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_ctrattr_get() - Retrieve the CTRATTR property of
 * specified NVMe controller.
 *
 * Retrieve the CTRATTR(Controller Attributes) property of specified NVMe
 * controller. This property is only for NVMe over Fabrics.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_ctrattr_get(struct nvme_ctrl *cnt);

/**
 * nvme_ctrl_msdbd_get() - Retrieve the MSDBD property of
 * specified NVMe controller.
 *
 * Retrieve the MSDBD(Maximum SGL Data Block Descriptors) property of specified
 * NVMe controller. This property is only for NVMe over Fabrics.
 *
 * @cnt:
 *	Pointer of 'struct nvme_ctrl'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_ctrl_msdbd_get(struct nvme_ctrl *cnt);

/**
 * nvme_psd_mp_get() - Retrieve the MP property of specified NVMe Power State
 * Descriptor.
 *
 * Retrieve the MP(Maximum Power) property of specified NVMe Power State
 * Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_psd_mp_get(struct nvme_psd *psd);

/**
 * nvme_psd_mxps_get() - Retrieve the MXPS property of specified NVMe Power
 * State Descriptor.
 *
 * Retrieve the MXPS(Max Power Scale) property of specified NVMe Power State
 * Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_psd_mxps_get(struct nvme_psd *psd);

/**
 * nvme_psd_nops_get() - Retrieve the NOPS property of specified NVMe Power
 * State Descriptor.
 *
 * Retrieve the NOPS(Non-Operational State) property of specified NVMe
 * Power State Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_psd_nops_get(struct nvme_psd *psd);

/**
 * nvme_psd_enlat_get() - Retrieve the ENLAT property of specified NVMe Power
 * State Descriptor.
 *
 * Retrieve the ENLAT(Entry Latency) property of specified NVMe
 * Power State Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_psd_enlat_get(struct nvme_psd *psd);

/**
 * nvme_psd_exlat_get() - Retrieve the EXLAT property of specified NVMe Power
 * State Descriptor.
 *
 * Retrieve the EXLAT(Exit Latency) property of specified NVMe
 * Power State Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint32_t.
 */
_DLL_PUBLIC uint32_t nvme_psd_exlat_get(struct nvme_psd *psd);

/**
 * nvme_psd_rrt_get() - Retrieve the RRT property of specified NVMe Power State
 * Descriptor.
 *
 * Retrieve the RRT(Relative Read Throughput) property of specified NVMe
 * Power State Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_psd_rrt_get(struct nvme_psd *psd);

/**
 * nvme_psd_rrl_get() - Retrieve the RRL property of specified NVMe Power State
 * Descriptor.
 *
 * Retrieve the RRL(Relative Read Latency) property of specified NVMe Power
 * State Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_psd_rrl_get(struct nvme_psd *psd);

/**
 * nvme_psd_rwt_get() - Retrieve the RWT property of specified NVMe Power State
 * Descriptor.
 *
 * Retrieve the RWT(Relative Write Throughput) property of specified NVMe
 * Power State Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_psd_rwt_get(struct nvme_psd *psd);

/**
 * nvme_psd_rwl_get() - Retrieve the RWL property of specified NVMe Power State
 * Descriptor.
 *
 * Retrieve the RWL(Relative Write Latency) property of specified NVMe
 * Power State Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_psd_rwl_get(struct nvme_psd *psd);

/**
 * nvme_psd_idlp_get() - Retrieve the IDLP property of specified NVMe Power
 * State Descriptor.
 *
 * Retrieve the IDLP(Idle Power) property of specified NVMe
 * Power State Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_psd_idlp_get(struct nvme_psd *psd);

/**
 * nvme_psd_ips_get() - Retrieve the IPS property of specified NVMe Power State
 * Descriptor.
 *
 * Retrieve the IPS(Idle Power Scale) property of specified NVMe
 * Power State Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_psd_ips_get(struct nvme_psd *psd);

/**
 * nvme_psd_actp_get() - Retrieve the ACTP property of specified NVMe Power
 * State Descriptor.
 *
 * Retrieve the ACTP(Active Power) property of specified NVMe
 * Power State Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint16_t.
 */
_DLL_PUBLIC uint16_t nvme_psd_actp_get(struct nvme_psd *psd);

/**
 * nvme_psd_apw_get() - Retrieve the APW property of specified NVMe Power State
 * Descriptor.
 *
 * Retrieve the APW(Active Power Workload) property of specified NVMe
 * Power State Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_psd_apw_get(struct nvme_psd *psd);

/**
 * nvme_psd_aps_get() - Retrieve the APS property of specified NVMe Power State
 * Descriptor.
 *
 * Retrieve the APS(Active Power Scale) property of specified NVMe
 * Power State Descriptor.
 *
 * @psd:
 *	Pointer of 'struct nvme_psd'.
 *	If this pointer is NULL, your program will be terminated by assert().
 *
 * Return:
 *	uint8_t.
 */
_DLL_PUBLIC uint8_t nvme_psd_aps_get(struct nvme_psd *psd);

#endif /* End of _LIBNVME_NS_SPEC_H_ */
