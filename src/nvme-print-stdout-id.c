// SPDX-License-Identifier: GPL-2.0-or-later
#include <ccan/array_size/array_size.h>
#include <shared/string-util.h>

#include "cleanup.h"
#include "nvme-print.h"
#include "nvme-print-stdout.h"

static const uint8_t zero_uuid[16] = { 0 };
static const uint8_t invalid_uuid[16] = {[0 ... 15] = 0xff };

static struct shr_table *stdout_id_ctrl_cmic_table(__u8 cmic)
{
	struct shr_table *t;
	__u8 rsvd = NVME_CMIC_MULTI_RSVD(cmic);
	__u8 ana = NVME_CMIC_MULTI_ANA(cmic);
	__u8 sriov = NVME_CMIC_MULTI_SRIOV(cmic);
	__u8 mctl = NVME_CMIC_MULTI_CTRL(cmic);
	__u8 mp = NVME_CMIC_MULTI_PORT(cmic);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:4]", rsvd, "Reserved");
	stdout_bits_add(t, "[3:3]", ana,
			 ana ? "ANA supported" : "ANA not supported");
	stdout_bits_add(t, "[2:2]", sriov, sriov ? "SR-IOV" : "PCI");
	stdout_bits_add(t, "[1:1]", mctl,
			 mctl ? "Multi Controller" : "Single Controller");
	stdout_bits_add(t, "[0:0]", mp, mp ? "Multi Port" : "Single Port");

	return t;
}

static struct shr_table *stdout_id_ctrl_oaes_table(__le32 ctrl_oaes)
{
	struct shr_table *t;
	__u32 oaes = le32_to_cpu(ctrl_oaes);
	__u32 dlpcn = NVME_CTRL_OAES_DLPCN(oaes);
	__u32 rsvd28 = (oaes & 0x70000000) >> 28;
	__u32 zdcn = NVME_CTRL_OAES_ZDCN(oaes);
	__u32 rsvd23 = (oaes >> 23) & 0xf;
	__u32 rlcc = NVME_CTRL_OAES_RLCC(oaes);
	__u32 rsvd20 = (oaes >> 20) & 0x3;
	__u32 ansan = NVME_CTRL_OAES_ANSAN(oaes);
	__u32 rsvd18 = (oaes >> 18) & 0x1;
	__u32 rgcns = NVME_CTRL_OAES_RGCNS(oaes);
	__u32 tthr = NVME_CTRL_OAES_TTHR(oaes);
	__u32 normal_shn = NVME_CTRL_OAES_NNVMSS(oaes);
	__u32 egealpcn = NVME_CTRL_OAES_EGEALPCN(oaes);
	__u32 lbasin = NVME_CTRL_OAES_LBASIAN(oaes);
	__u32 plealcn = NVME_CTRL_OAES_PLEALCN(oaes);
	__u32 anacn = NVME_CTRL_OAES_ANACN(oaes);
	__u32 rsvd10 = (oaes >> 10) & 0x1;
	__u32 fan = NVME_CTRL_OAES_FAN(oaes);
	__u32 nace = NVME_CTRL_OAES_NSAN(oaes);
	__u32 rsvd0 = oaes & 0xFF;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[31:31]", dlpcn,
			"Discovery Log Change Notice %sSupported",
			dlpcn ? "" : "Not ");
	if (rsvd28)
		stdout_bits_add(t, "[30:28]", rsvd28, "Reserved");
	stdout_bits_add(t, "[27:27]", zdcn,
			"Zone Descriptor Changed Notices %sSupported",
			zdcn ? "" : "Not ");
	if (rsvd23)
		stdout_bits_add(t, "[26:23]", rsvd23, "Reserved");
	stdout_bits_add(t, "[22:22]", rlcc,
			"Rate Limiting Configuration Change Notices %sSupported",
			rlcc ? "" : "Not ");
	if (rsvd20)
		stdout_bits_add(t, "[21:20]", rsvd20, "Reserved");
	stdout_bits_add(t, "[19:19]", ansan,
			"Allocated Namespace Attribute Notices %sSupported",
			ansan ? "" : "Not ");
	if (rsvd18)
		stdout_bits_add(t, "[18:18]", rsvd18, "Reserved");
	stdout_bits_add(t, "[17:17]", rgcns,
			"Reachability Groups Change Notices %sSupported",
			rgcns ? "" : "Not ");
	stdout_bits_add(t, "[16:16]", tthr,
			"Temperature Threshold Hysteresis Recovery %sSupported",
			tthr ? "" : "Not ");
	stdout_bits_add(t, "[15:15]", normal_shn,
			"Normal NSS Shutdown Event %sSupported",
			normal_shn ? "" : "Not ");
	stdout_bits_add(t, "[14:14]", egealpcn,
			"Endurance Group Event Aggregate Log Page Change Notice %sSupported",
			egealpcn ? "" : "Not ");
	stdout_bits_add(t, "[13:13]", lbasin,
			"LBA Status Information Notices %sSupported",
			lbasin ? "" : "Not ");
	stdout_bits_add(t, "[12:12]", plealcn,
			"Predictable Latency Event Aggregate Log Change Notices %sSupported",
			plealcn ? "" : "Not ");
	stdout_bits_add(t, "[11:11]", anacn,
			"Asymmetric Namespace Access Change Notices %sSupported",
			anacn ? "" : "Not ");
	if (rsvd10)
		stdout_bits_add(t, "[10:10]", rsvd10, "Reserved");
	stdout_bits_add(t, "[9:9]", fan,
			"Firmware Activation Notices %sSupported",
			fan ? "" : "Not ");
	stdout_bits_add(t, "[8:8]", nace,
			"Attached Namespace Attribute Changed Event %sSupported",
			nace ? "" : "Not ");
	if (rsvd0)
		stdout_bits_add(t, "[7:0]", rsvd0, "Reserved");

	return t;
}

static struct shr_table *stdout_id_ctrl_ctratt_table(__le32 ctrl_ctratt)
{
	struct shr_table *t;
	__u32 ctratt = le32_to_cpu(ctrl_ctratt);
	__u32 rsvd25 = (ctratt >> 25);
	__u32 iiellss = NVME_CTRL_CTRATT_IIELLSS(ctratt);
	__u32 vms = NVME_CTRL_CTRATT_VMS(ctratt);
	__u32 pms = NVME_CTRL_CTRATT_PMS(ctratt);
	__u32 pls = NVME_CTRL_CTRATT_PLS(ctratt);
	__u32 fdps = NVME_CTRL_CTRATT_FDPS(ctratt);
	__u32 rhii = NVME_CTRL_CTRATT_RHII(ctratt);
	__u32 hmbr = NVME_CTRL_CTRATT_HMBR(ctratt);
	__u32 mem = NVME_CTRL_CTRATT_MEM(ctratt);
	__u32 elbas = NVME_CTRL_CTRATT_ELBAS(ctratt);
	__u32 dnvms = NVME_CTRL_CTRATT_DNVMS(ctratt);
	__u32 deg = NVME_CTRL_CTRATT_DEG(ctratt);
	__u32 vcm = NVME_CTRL_CTRATT_VCM(ctratt);
	__u32 fcm = NVME_CTRL_CTRATT_FCM(ctratt);
	__u32 mds = NVME_CTRL_CTRATT_MDS(ctratt);
	__u32 ulist = NVME_CTRL_CTRATT_ULIST(ctratt);
	__u32 sqa = NVME_CTRL_CTRATT_SQA(ctratt);
	__u32 ng = NVME_CTRL_CTRATT_NG(ctratt);
	__u32 tbkas = NVME_CTRL_CTRATT_TBKAS(ctratt);
	__u32 plm = NVME_CTRL_CTRATT_PLM(ctratt);
	__u32 egs = NVME_CTRL_CTRATT_EGS(ctratt);
	__u32 rrlvls = NVME_CTRL_CTRATT_RRLVLS(ctratt);
	__u32 nsets = NVME_CTRL_CTRATT_NSETS(ctratt);
	__u32 nopspm = NVME_CTRL_CTRATT_NOPSPM(ctratt);
	__u32 hids = NVME_CTRL_CTRATT_HIDS(ctratt);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd25)
		stdout_bits_add(t, "[31:25]", rsvd25, "Reserved");
	stdout_bits_add(t, "[24:23]", iiellss, "Idle I/O Exit Latency Limit %s",
			 !iiellss ? "Not Supported" :
			 iiellss == NVME_CTRL_CTRATT_IIELLSS_POWER_STATE ?
			 "Supported (Power state)" :
			 iiellss == NVME_CTRL_CTRATT_IIELLSS_GLOBAL ?
			 "Supported (Global)" : "Reserved");
	stdout_bits_add(t, "[22:22]", vms, "Voltage Measurement %sSupported",
			 vms ? "" : "Not ");
	stdout_bits_add(t, "[21:21]", pms, "Power Measurement %sSupported",
			 pms ? "" : "Not ");
	stdout_bits_add(t, "[20:20]", pls, "Power Limit %sSupported",
			 pls ? "" : "Not ");
	stdout_bits_add(t, "[19:19]", fdps,
			 "Flexible Data Placement %sSupported",
			 fdps ? "" : "Not ");
	stdout_bits_add(t, "[18:18]", rhii,
			 "Reservations and Host Identifier Interaction %sSupported",
			 rhii ? "" : "Not ");
	stdout_bits_add(t, "[17:17]", hmbr,
			 "HMB Restrict Non-Operational Power State Access %sSupported",
			 hmbr ? "" : "Not ");
	stdout_bits_add(t, "[16:16]", mem,
			 "MDTS and Size Limits Exclude Metadata %sSupported",
			 mem ? "" : "Not ");
	stdout_bits_add(t, "[15:15]", elbas, "Extended LBA Formats %sSupported",
			 elbas ? "" : "Not ");
	stdout_bits_add(t, "[14:14]", dnvms, "Delete NVM Set %sSupported",
			 dnvms ? "" : "Not ");
	stdout_bits_add(t, "[13:13]", deg, "Delete Endurance Group %sSupported",
			 deg ? "" : "Not ");
	stdout_bits_add(t, "[12:12]", vcm,
			 "Variable Capacity Management %sSupported",
			 vcm ? "" : "Not ");
	stdout_bits_add(t, "[11:11]", fcm,
			 "Fixed Capacity Management %sSupported",
			 fcm ? "" : "Not ");
	stdout_bits_add(t, "[10:10]", mds, "Multi Domain Subsystem %sSupported",
			 mds ? "" : "Not ");
	stdout_bits_add(t, "[9:9]", ulist, "UUID List %sSupported",
			 ulist ? "" : "Not ");
	stdout_bits_add(t, "[8:8]", sqa, "SQ Associations %sSupported",
			 sqa ? "" : "Not ");
	stdout_bits_add(t, "[7:7]", ng, "Namespace Granularity %sSupported",
			 ng ? "" : "Not ");
	stdout_bits_add(t, "[6:6]", tbkas,
			 "Traffic Based Keep Alive %sSupported",
			 tbkas ? "" : "Not ");
	stdout_bits_add(t, "[5:5]", plm, "Predictable Latency Mode %sSupported",
			 plm ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", egs, "Endurance Groups %sSupported",
			 egs ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", rrlvls, "Read Recovery Levels %sSupported",
			 rrlvls ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", nsets, "NVM Sets %sSupported",
			 nsets ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", nopspm,
			 "Non-Operational Power State Permissive %sSupported",
			 nopspm ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", hids, "128-bit Host Identifier %sSupported",
			 hids ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_bpcap_table(__u8 ctrl_bpcap)
{
	struct shr_table *t;
	__u8 rsvd3 = (ctrl_bpcap >> 3);
	__u8 sfbpwps = NVME_GET(ctrl_bpcap, CTRL_BACAP_SFBPWPS);
	__u8 rpmbbpwps = NVME_GET(ctrl_bpcap, CTRL_BACAP_RPMBBPWPS);
	static const char * const rpmbbpwps_def[] = {
		"Support Not Specified",
		"Not Supported",
		"Supported"
	};

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd3)
		stdout_bits_add(t, "[7:3]", rsvd3, "Reserved");
	stdout_bits_add(t, "[2:2]", sfbpwps,
			 "Set Features Boot Partition Write Protection %sSupported",
			 sfbpwps ? "" : "Not ");
	stdout_bits_add(t, "[1:0]", rpmbbpwps,
			 "RPMB Boot Partition Write Protection %s",
			 rpmbbpwps_def[rpmbbpwps]);

	return t;
}

static struct shr_table *stdout_id_ctrl_chsi_table(__u8 ctrl_chsi)
{
	struct shr_table *t;
	__u8 rsvd1 = (ctrl_chsi >> 1);
	__u8 chs = NVME_CTRL_CHSI_CHS(ctrl_chsi);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd1)
		stdout_bits_add(t, "[7:1]", rsvd1, "Reserved");
	stdout_bits_add(t, "[0:0]", chs,
			 "CXL HDM %sSupported", chs ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_rmdca_table(__u8 ctrl_rmdca)
{
	struct shr_table *t;
	__u8 rsvd3 = (ctrl_rmdca >> 3);
	__u8 rdccs = NVME_CTRL_RMDCA_RDCCS(ctrl_rmdca);
	__u8 rdncs = NVME_CTRL_RMDCA_RDNCS(ctrl_rmdca);
	__u8 rdscs = NVME_CTRL_RMDCA_RDSCS(ctrl_rmdca);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd3)
		stdout_bits_add(t, "[7:3]", rsvd3, "Reserved");
	stdout_bits_add(t, "[2:2]", rdccs,
			 "Restore Default Capacity Management Configuration %sSupported",
			 rdccs ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", rdncs,
			 "Restore Default Namespace Configuration %sSupported",
			 rdncs ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", rdscs,
			 "Restore Default NVM Subsystem Configuration %sSupported",
			 rdscs ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_plsi_table(__u8 ctrl_plsi)
{
	struct shr_table *t;
	__u8 rsvd2 = (ctrl_plsi >> 2);
	__u8 plsfq = NVME_GET(ctrl_plsi, CTRL_PLSI_PLSFQ);
	__u8 plsepf = NVME_GET(ctrl_plsi, CTRL_PLSI_PLSEPF);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd2)
		stdout_bits_add(t, "[7:2]", rsvd2, "Reserved");
	stdout_bits_add(t, "[1:1]", plsfq,
			 "Power Loss Signaling with Forced Quiescence %sSupported",
			 plsfq ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", plsepf,
			 "Power Loss Signaling with Emergency Power Fail %sSupported",
			 plsepf ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_crcap_table(__u8 ctrl_crcap)
{
	struct shr_table *t;
	__u8 rsvd2 = (ctrl_crcap >> 2);
	__u8 rgidc = NVME_GET(ctrl_crcap, CTRL_CRCAP_RGIDC);
	__u8 rrsup = NVME_GET(ctrl_crcap, CTRL_CRCAP_RRSUP);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd2)
		stdout_bits_add(t, "[7:2]", rsvd2, "Reserved");
	stdout_bits_add(t, "[1:1]", rgidc,
			 "RGRPID %s while the namespace is attached to any controller.",
			 rgidc ? "does not change" : "may change");
	stdout_bits_add(t, "[0:0]", rrsup, "Reachability Reporting %sSupported",
			 rrsup ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_cntrltype_table(__u8 cntrltype)
{
	struct shr_table *t;
	__u8 rsvd = (cntrltype & 0xFC) >> 2;
	__u8 cntrl = cntrltype & 0x3;

	static const char * const type[] = {
		"Controller type not reported",
		"I/O Controller",
		"Discovery Controller",
		"Administrative Controller"
	};

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:0]", cntrltype, "%s", type[cntrl]);

	return t;
}

static struct shr_table *stdout_id_ctrl_nvmsr_table(__u8 nvmsr)
{
	struct shr_table *t;
	__u8 rsvd = (nvmsr >> 2) & 0xfc;
	__u8 nvmee = NVME_CTRL_NVMSR_NVMEE(nvmsr);
	__u8 nvmesd = NVME_CTRL_NVMSR_NVMESD(nvmsr);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", nvmee,
			 "NVM subsystem %spart of an Enclosure",
			 nvmee ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", nvmesd,
			 "NVM subsystem %spart of a Storage Device",
			 nvmesd ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_vwci_table(__u8 vwci)
{
	struct shr_table *t;
	__u8 vwcrv = NVME_CTRL_VWCI_VWCRV(vwci);
	__u8 vwcr = NVME_CTRL_VWCI_VWCR(vwci);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:7]", vwcrv,
			 "VPD Write Cycles Remaining field is %svalid.",
			 vwcrv ? "" : "Not ");
	stdout_bits_add(t, "[6:0]", vwcr, "VPD Write Cycles Remaining");

	return t;
}

static struct shr_table *stdout_id_ctrl_mec_table(__u8 mec)
{
	struct shr_table *t;
	__u8 rsvd = (mec >> 2) & 0xfc;
	__u8 pcieme = (mec >> 1) & 0x1;
	__u8 smbusme = mec & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", pcieme,
			 "NVM subsystem %scontains a Management Endpoint on a PCIe port",
			 pcieme ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", smbusme,
			 "NVM subsystem %scontains a Management Endpoint on an SMBus/I2C port",
			 smbusme ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_oacs_table(__le16 ctrl_oacs)
{
	struct shr_table *t;
	__u16 oacs = le16_to_cpu(ctrl_oacs);
	__u16 rsvd = (oacs & 0xC000) >> 14;
	__u16 rsvd12 = (oacs & 0x1000) >> 12;
	__u16 ccfls = NVME_CTRL_OACS_CCFLS(oacs);
	__u16 hmlms = NVME_CTRL_OACS_HMLMS(oacs);
	__u16 lock = NVME_CTRL_OACS_CFLS(oacs);
	__u16 glbas = NVME_CTRL_OACS_GLSS(oacs);
	__u16 dbc = NVME_CTRL_OACS_DBCS(oacs);
	__u16 vir = NVME_CTRL_OACS_VMS_M(oacs);
	__u16 nmi = NVME_CTRL_OACS_NSRS(oacs);
	__u16 dir = NVME_CTRL_OACS_DIRS(oacs);
	__u16 sft = NVME_CTRL_OACS_DSTS(oacs);
	__u16 nsm = NVME_CTRL_OACS_NMS_M(oacs);
	__u16 fwc = NVME_CTRL_OACS_FWDS(oacs);
	__u16 fmt = NVME_CTRL_OACS_FNVMS(oacs);
	__u16 sec = NVME_CTRL_OACS_SSRS(oacs);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:14]", rsvd, "Reserved");
	stdout_bits_add(t, "[13:13]", ccfls,
			 "Ctrl-scoped Command/Feature Lockdown %sSupported",
			 ccfls ? "" : "Not ");
	if (rsvd12)
		stdout_bits_add(t, "[12:12]", rsvd12, "Reserved");
	stdout_bits_add(t, "[11:11]", hmlms,
			 "Host Managed Live Migration %sSupported",
			 hmlms ? "" : "Not ");
	stdout_bits_add(t, "[10:10]", lock,
			 "Lockdown Command and Feature %sSupported",
			 lock ? "" : "Not ");
	stdout_bits_add(t, "[9:9]", glbas,
			 "Get LBA Status Capability %sSupported",
			 glbas ? "" : "Not ");
	stdout_bits_add(t, "[8:8]", dbc, "Doorbell Buffer Config %sSupported",
			 dbc ? "" : "Not ");
	stdout_bits_add(t, "[7:7]", vir,
			 "Virtualization Management %sSupported",
			 vir ? "" : "Not ");
	stdout_bits_add(t, "[6:6]", nmi, "NVMe-MI Send and Receive %sSupported",
			 nmi ? "" : "Not ");
	stdout_bits_add(t, "[5:5]", dir, "Directives %sSupported",
			 dir ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", sft, "Device Self-test %sSupported",
			 sft ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", nsm,
			 "NS Management and Attachment %sSupported",
			 nsm ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", fwc, "FW Commit and Download %sSupported",
			 fwc ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", fmt, "Format NVM %sSupported",
			 fmt ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", sec,
			 "Security Send and Receive %sSupported",
			 sec ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_frmw_table(__u8 frmw)
{
	struct shr_table *t;
	__u8 rsvd = (frmw & 0xC0) >> 6;
	__u8 smud = (frmw >> 5) & 0x1;
	__u8 fawr = (frmw & 0x10) >> 4;
	__u8 nfws = (frmw & 0xE) >> 1;
	__u8 s1ro = frmw & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:6]", rsvd, "Reserved");
	stdout_bits_add(t, "[5:5]", smud,
			 "Multiple FW or Boot Update Detection %sSupported",
			 smud ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", fawr,
			 "Firmware Activate Without Reset %sSupported",
			 fawr ? "" : "Not ");
	stdout_bits_add(t, "[3:1]", nfws, "Number of Firmware Slots");
	stdout_bits_add(t, "[0:0]", s1ro, "Firmware Slot 1 Read%s",
			 s1ro ? "-Only" : "/Write");

	return t;
}

static struct shr_table *stdout_id_ctrl_lpa_table(__u8 lpa)
{
	struct shr_table *t;
	__u8 rsvd = (lpa & 0x80) >> 7;
	__u8 tel = (lpa >> 6) & 0x1;
	__u8 lid_sup = (lpa >> 5) & 0x1;
	__u8 persevnt = (lpa & 0x10) >> 4;
	__u8 telem = (lpa & 0x8) >> 3;
	__u8 ed = (lpa & 0x4) >> 2;
	__u8 celp = (lpa & 0x2) >> 1;
	__u8 smlp = lpa & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:7]", rsvd, "Reserved");
	stdout_bits_add(t, "[6:6]", tel,
			 "Telemetry Log Data Area 4 %sSupported",
			 tel ? "" : "Not ");
	stdout_bits_add(t, "[5:5]", lid_sup,
			 "LID 0x0, Scope of each command in LID 0x5, 0x12, 0x13 %sSupported",
			 lid_sup ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", persevnt,
			 "Persistent Event log %sSupported",
			 persevnt ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", telem,
			 "Telemetry host/controller initiated log page %sSupported",
			 telem ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", ed,
			 "Extended data for Get Log Page %sSupported",
			 ed ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", celp,
			 "Command Effects Log Page %sSupported",
			 celp ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", smlp,
			 "SMART/Health Log Page per NS %sSupported",
			 smlp ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_elpe_table(__u8 elpe)
{
	struct shr_table *t;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:0]", elpe,
			 "Error Log Page Entries (ELPE), 0's based");

	return t;
}

static struct shr_table *stdout_id_ctrl_npss_table(__u8 npss)
{
	struct shr_table *t;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:0]", npss,
			 "Number of Power States Support (NPSS), 0's based");

	return t;
}

static struct shr_table *stdout_id_ctrl_avscc_table(__u8 avscc)
{
	struct shr_table *t;
	__u8 rsvd = (avscc & 0xFE) >> 1;
	__u8 fmt = avscc & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", fmt,
			 "Admin Vendor Specific Commands uses %s Format",
			 fmt ? "NVMe" : "Vendor Specific");

	return t;
}

static struct shr_table *stdout_id_ctrl_apsta_table(__u8 apsta)
{
	struct shr_table *t;
	__u8 rsvd = (apsta & 0xFE) >> 1;
	__u8 apst = apsta & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", apst,
			 "Autonomous Power State Transitions %sSupported",
			 apst ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_wctemp_table(__le16 wctemp)
{
	struct shr_table *t;
	__u16 val = le16_to_cpu(wctemp);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[15:0]", val,
			 "%s (%u K, %s) Warning Composite Temperature Threshold (WCTEMP)",
			 nvme_degrees_string(val), val,
			 nvme_degrees_fahrenheit_string(val));

	return t;
}

static struct shr_table *stdout_id_ctrl_cctemp_table(__le16 cctemp)
{
	struct shr_table *t;
	__u16 val = le16_to_cpu(cctemp);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[15:0]", val,
			 "%s (%u K, %s) Critical Composite Temperature Threshold (CCTEMP)",
			 nvme_degrees_string(val), val,
			 nvme_degrees_fahrenheit_string(val));

	return t;
}

static struct shr_table *stdout_id_ctrl_tnvmcap_table(__u8 *tnvmcap)
{
	struct shr_table *t;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add_str(t, "[127:0]",
			     uint128_t_to_l10n_string(le128_to_cpu(tnvmcap)),
			     "Total NVM Capacity (TNVMCAP)");

	return t;
}

static struct shr_table *stdout_id_ctrl_unvmcap_table(__u8 *unvmcap)
{
	struct shr_table *t;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add_str(t, "[127:0]",
			     uint128_t_to_l10n_string(le128_to_cpu(unvmcap)),
			     "Unallocated NVM Capacity (UNVMCAP)");

	return t;
}

static struct shr_table *stdout_id_ctrl_rpmbs_table(__le32 ctrl_rpmbs)
{
	struct shr_table *t;
	__u32 rpmbs = le32_to_cpu(ctrl_rpmbs);
	__u32 asz = (rpmbs & 0xFF000000) >> 24;
	__u32 tsz = (rpmbs & 0xFF0000) >> 16;
	__u32 rsvd = (rpmbs & 0xFFC0) >> 6;
	__u32 auth = (rpmbs & 0x38) >> 3;
	__u32 rpmb = rpmbs & 0x7;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[31:24]", asz, "Access Size");
	stdout_bits_add(t, "[23:16]", tsz, "Total Size");
	if (rsvd)
		stdout_bits_add(t, "[15:6]", rsvd, "Reserved");
	stdout_bits_add(t, "[5:3]", auth, "Authentication Method");
	stdout_bits_add(t, "[2:0]", rpmb, "Number of RPMB Units");

	return t;
}

void stdout_id_ctrl_rpmbs(__le32 ctrl_rpmbs)
{
	stdout_kv_table_finish(stdout_id_ctrl_rpmbs_table(ctrl_rpmbs),
				"id-ctrl-rpmbs");
	printf("\n");
}

static struct shr_table *stdout_id_ctrl_dsto_table(__u8 dsto)
{
	struct shr_table *t;
	__u8 rsvd2 = (dsto & 0xfc) >> 2;
	__u8 hirs = NVME_CTRL_DSTO_HIRS(dsto);
	__u8 sdso = NVME_CTRL_DSTO_SDSO(dsto);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd2)
		stdout_bits_add(t, "[7:2]", rsvd2, "Reserved");
	stdout_bits_add(t, "[1:1]", hirs,
			 "Host-Initiated Refresh capability %sSupported",
			 hirs ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", sdso, "NVM subsystem supports %s at a time",
			 sdso ?
			 "only one device self-test operation in progress" :
			 "one device self-test operation per controller");

	return t;
}

static struct shr_table *stdout_id_ctrl_hctma_table(__le16 ctrl_hctma)
{
	struct shr_table *t;
	__u16 hctma = le16_to_cpu(ctrl_hctma);
	__u16 rsvd = (hctma & 0xFFFE) >> 1;
	__u16 hctm = hctma & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", hctm,
			 "Host Controlled Thermal Management %sSupported",
			 hctm ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_mntmt_table(__le16 mntmt_le)
{
	struct shr_table *t;
	__u16 mntmt = le16_to_cpu(mntmt_le);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[15:0]", mntmt,
			 "%s (%u K, %s) Minimum Thermal Management Temperature (MNTMT)",
			 nvme_degrees_string(mntmt), mntmt,
			 nvme_degrees_fahrenheit_string(mntmt));

	return t;
}

static struct shr_table *stdout_id_ctrl_mxtmt_table(__le16 mxtmt_le)
{
	struct shr_table *t;
	__u16 mxtmt = le16_to_cpu(mxtmt_le);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[15:0]", mxtmt,
			 "%s (%u K, %s) Maximum Thermal Management Temperature (MXTMT)",
			 nvme_degrees_string(mxtmt), mxtmt,
			 nvme_degrees_fahrenheit_string(mxtmt));

	return t;
}

static struct shr_table *stdout_id_ctrl_sanicap_table(__le32 ctrl_sanicap)
{
	struct shr_table *t;
	__u32 sanicap = le32_to_cpu(ctrl_sanicap);
	__u32 rsvd6 = (sanicap & 0x1FFFFFC0) >> 6;
	__u32 sprrs = NVME_CTRL_SANICAP_SPRRS(sanicap);
	__u32 vers = NVME_CTRL_SANICAP_NVERS(sanicap);
	__u32 ows = NVME_CTRL_SANICAP_OWS(sanicap);
	__u32 bes = NVME_CTRL_SANICAP_BES(sanicap);
	__u32 ces = NVME_CTRL_SANICAP_CES(sanicap);
	__u32 ndi = NVME_CTRL_SANICAP_NDI(sanicap);
	__u32 nodmmas = NVME_CTRL_SANICAP_NODMMAS(sanicap);

	static const char * const modifies_media[] = {
		"Additional media modification after sanitize operation completes successfully is not defined",
		"Media is not additionally modified after sanitize operation completes successfully",
		"Media is additionally modified after sanitize operation completes successfully",
		"Reserved"
	};

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[31:30]", nodmmas, "%s", modifies_media[nodmmas]);
	stdout_bits_add(t, "[29:29]", ndi,
			 "No-Deallocate After Sanitize bit in Sanitize command %sSupported",
			 ndi ? "Not " : "");
	if (rsvd6)
		stdout_bits_add(t, "[28:6]", rsvd6, "Reserved");
	stdout_bits_add(t, "[5:5]", sprrs,
			 "Sanitize Purge Request and Reporting %sSupported",
			 sprrs ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", vers,
			 "Media Verification and Post-Verification Deallocation state %sSupported",
			 vers ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", ows,
			 "Overwrite Sanitize Operation %sSupported",
			 ows ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", bes,
			 "Block Erase Sanitize Operation %sSupported",
			 bes ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", ces,
			 "Crypto Erase Sanitize Operation %sSupported",
			 ces ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_anacap_table(__u8 anacap)
{
	struct shr_table *t;
	__u8 nz = (anacap & 0x80) >> 7;
	__u8 grpid_static = (anacap & 0x40) >> 6;
	__u8 rsvd = (anacap & 0x20) >> 5;
	__u8 ana_change = (anacap & 0x10) >> 4;
	__u8 ana_persist_loss = (anacap & 0x08) >> 3;
	__u8 ana_inaccessible = (anacap & 0x04) >> 2;
	__u8 ana_nonopt = (anacap & 0x02) >> 1;
	__u8 ana_opt = (anacap & 0x01);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:7]", nz, "Non-zero group ID %sSupported",
			 nz ? "" : "Not ");
	stdout_bits_add(t, "[6:6]", grpid_static, "Group ID does %schange",
			 grpid_static ? "not " : "");
	if (rsvd)
		stdout_bits_add(t, "[5:5]", rsvd, "Reserved");
	stdout_bits_add(t, "[4:4]", ana_change, "ANA Change state %sSupported",
			 ana_change ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", ana_persist_loss,
			 "ANA Persistent Loss state %sSupported",
			 ana_persist_loss ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", ana_inaccessible,
			 "ANA Inaccessible state %sSupported",
			 ana_inaccessible ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", ana_nonopt,
			 "ANA Non-optimized state %sSupported",
			 ana_nonopt ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", ana_opt, "ANA Optimized state %sSupported",
			 ana_opt ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_kpioc_table(__u8 ctrl_kpioc)
{
	struct shr_table *t;
	__u8 rsvd2 = (ctrl_kpioc >> 2);
	__u8 kpiosc = NVME_CTRL_KPIOC_KPIOSC(ctrl_kpioc);
	__u8 kpios = NVME_CTRL_KPIOC_KPIOS(ctrl_kpioc);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd2)
		stdout_bits_add(t, "[7:2]", rsvd2, "Reserved");
	stdout_bits_add(t, "[1:1]", kpiosc,
			 "Key Per I/O capability %s to all namespaces",
			 kpiosc ? "applies" : "Not apply");
	stdout_bits_add(t, "[0:0]", kpios, "Key Per I/O capability %sSupported",
			 kpios ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_tmpthha_table(__u8 tmpthha)
{
	struct shr_table *t;
	__u8 rsvd3 = (tmpthha & 0xf8) >> 3;
	__u8 tmpthmh = tmpthha & 0x7;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd3)
		stdout_bits_add(t, "[7:3]", rsvd3, "Reserved");
	stdout_bits_add(t, "[2:0]", tmpthmh,
			 "Temperature Threshold Maximum Hysteresis");

	return t;
}

static struct shr_table *stdout_id_ctrl_mupa_table(__u8 mupa)
{
	struct shr_table *t;
	__u8 mups = NVME_CTRL_MUPA_MUPS(mupa);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[1:0]", mups, "Maximum Unlimited Power Scale (%s)",
			 nvme_feature_power_limit_scale_to_string(mups));

	return t;
}

static struct shr_table *stdout_id_ctrl_cdpa_table(__le16 ctrl_cdpa)
{
	struct shr_table *t;
	__u16 cdpa = le16_to_cpu(ctrl_cdpa);
	__u16 rsvd1 = (cdpa >> 1);
	bool hmac_sha_384 = !!(cdpa & NVME_CTRL_CDPA_HMAC_SHA_384);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd1)
		stdout_bits_add(t, "[15:1]", rsvd1, "Reserved");
	stdout_bits_add(t, "[0:0]", hmac_sha_384, "HMAC-SHA-384 %sSupported",
			 hmac_sha_384 ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_ipmsr_table(__le16 ctrl_ipmsr)
{
	struct shr_table *t;
	__u16 ipmsr = le16_to_cpu(ctrl_ipmsr);
	__u16 srs = NVME_CTRL_IPMSR_SRS(ipmsr);
	__u16 srv = NVME_CTRL_IPMSR_SRV(ipmsr);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[15:8]", srs, "Sample Rate Scale (%s)",
			 nvme_ipmsr_srs_to_string(srs));
	stdout_bits_add(t, "[7:0]", srv, "Sample Rate Value");

	return t;
}

static struct shr_table *stdout_id_ctrl_ensa_table(__u8 ensa)
{
	struct shr_table *t;
	bool ensms = !!NVME_CTRL_ENSA_ENSMS(ensa);
	bool ensts = !!NVME_CTRL_ENSA_ENSTS(ensa);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[1:1]", ensms,
			 "Exported NVM Subsystem Support Migration %s",
			 nvme_support_str(ensms));
	stdout_bits_add(t, "[0:0]", ensts,
			 "Exported NVM Subsystem Template %s",
			 nvme_support_str(ensts));

	return t;
}

static struct shr_table *stdout_id_ctrl_endsfs_table(__u8 endsfs)
{
	struct shr_table *t;
	bool enf1 = !!NVME_CTRL_ENDSFS_ENF1(endsfs);
	bool enf0 = !!NVME_CTRL_ENDSFS_ENF0(endsfs);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[1:1]", enf1, "Exported Namespace Format 1 %s",
			 nvme_support_str(enf1));
	stdout_bits_add(t, "[0:0]", enf0, "Exported Namespace Format 0 %s",
			 nvme_support_str(enf0));

	return t;
}

static struct shr_table *stdout_id_ctrl_vsen_table(__le32 ctrl_vsen)
{
	struct shr_table *t;
	__u32 vsen = le32_to_cpu(ctrl_vsen);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (!vsen) {
		int row = shr_table_get_row_id(t);

		shr_table_set_value_str(t, 0, row, "", RIGHT);
		shr_table_set_value_str(t, 1, row, "", LEFT);
		shr_table_set_value_str(t, 2, row, "", RIGHT);
		shr_table_set_value_str(t, 3, row,
					 "Voltage sensor not supported", LEFT);
		shr_table_add_row(t, row);

		return t;
	}

	stdout_bits_add(t, "[31:24]", NVME_CTRL_VSEN_VSRS(vsen),
			 "Voltage Sample Rate Scale");
	stdout_bits_add(t, "[23:16]", NVME_CTRL_VSEN_VSRV(vsen),
			 "Voltage Sample Rate Value");
	stdout_bits_add(t, "[15:14]", NVME_CTRL_VSEN_VOLSS(vsen),
			 "Voltage Sample Scale");
	stdout_bits_add(t, "[13:12]", NVME_CTRL_VSEN_PISL(vsen),
			 "Power Input Supply Label");
	stdout_bits_add(t, "[11:0]", NVME_CTRL_VSEN_PISV(vsen),
			 "Power Input Supply Value (%g V)",
			 NVME_CTRL_VSEN_PISV(vsen) * 0.05);

	return t;
}

static struct shr_table *stdout_id_ctrl_sqes_table(__u8 sqes)
{
	struct shr_table *t;
	__u8 msqes = (sqes & 0xF0) >> 4;
	__u8 rsqes = sqes & 0xF;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:4]", msqes,
			 "Max SQ Entry Size (%d)", 1 << msqes);
	stdout_bits_add(t, "[3:0]", rsqes,
			 "Min SQ Entry Size (%d)", 1 << rsqes);

	return t;
}

static struct shr_table *stdout_id_ctrl_cqes_table(__u8 cqes)
{
	struct shr_table *t;
	__u8 mcqes = (cqes & 0xF0) >> 4;
	__u8 rcqes = cqes & 0xF;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:4]", mcqes,
			 "Max CQ Entry Size (%d)", 1 << mcqes);
	stdout_bits_add(t, "[3:0]", rcqes,
			 "Min CQ Entry Size (%d)", 1 << rcqes);

	return t;
}

static struct shr_table *stdout_id_ctrl_oncs_table(__le16 ctrl_oncs)
{
	struct shr_table *t;
	__u16 oncs = le16_to_cpu(ctrl_oncs);
	__u16 rsvd13 = oncs >> 13;
	bool nszs = !!(oncs & NVME_CTRL_ONCS_NAMESPACE_ZEROES);
	bool maxwzd = !!(oncs & NVME_CTRL_ONCS_WRITE_ZEROES_DEALLOCATE);
	bool nvmafc  = !!(oncs & NVME_CTRL_ONCS_ALL_FAST_COPY);
	bool nvmcsa  = !!(oncs & NVME_CTRL_ONCS_COPY_SINGLE_ATOMICITY);
	bool nvmcpys = !!(oncs & NVME_CTRL_ONCS_COPY);
	bool nvmvfys = !!(oncs & NVME_CTRL_ONCS_VERIFY);
	bool tss = !!(oncs & NVME_CTRL_ONCS_TIMESTAMP);
	bool reservs = !!(oncs & NVME_CTRL_ONCS_RESERVATIONS);
	bool ssfs = !!(oncs & NVME_CTRL_ONCS_SAVE_FEATURES);
	bool nvmwzsv = !!(oncs & NVME_CTRL_ONCS_WRITE_ZEROES);
	bool nvmdsmsv = !!(oncs & NVME_CTRL_ONCS_DSM);
	bool nvmwusv = !!(oncs & NVME_CTRL_ONCS_WRITE_UNCORRECTABLE);
	bool nvmcmps  = !!(oncs & NVME_CTRL_ONCS_COMPARE);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd13)
		stdout_bits_add(t, "[15:13]", rsvd13, "Reserved");
	stdout_bits_add(t, "[12:12]", nszs, "Namespace Zeroes %sSupported",
			 nszs ? "" : "Not ");
	stdout_bits_add(t, "[11:11]", maxwzd,
			 "Maximum Write Zeroes with Deallocate %sSupported",
			 maxwzd ? "" : "Not ");
	stdout_bits_add(t, "[10:10]", nvmafc, "All Fast Copy %sSupported",
			 nvmafc ? "" : "Not ");
	stdout_bits_add(t, "[9:9]", nvmcsa, "Copy Single Atomicity %sSupported",
			 nvmcsa ? "" : "Not ");
	stdout_bits_add(t, "[8:8]", nvmcpys, "Copy %sSupported",
			 nvmcpys ? "" : "Not ");
	stdout_bits_add(t, "[7:7]", nvmvfys, "Verify %sSupported",
			 nvmvfys ? "" : "Not ");
	stdout_bits_add(t, "[6:6]", tss, "Timestamp %sSupported",
			 tss ? "" : "Not ");
	stdout_bits_add(t, "[5:5]", reservs, "Reservations %sSupported",
			 reservs ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", ssfs, "Save and Select %sSupported",
			 ssfs ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", nvmwzsv, "Write Zeroes Support Variants");
	stdout_bits_add(t, "[2:2]", nvmdsmsv,
			 "Dataset Management Support Variants");
	stdout_bits_add(t, "[1:1]", nvmwusv,
			 "Write Uncorrectable Support Variants");
	stdout_bits_add(t, "[0:0]", nvmcmps, "Compare Command %sSupported",
			 nvmcmps ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_fuses_table(__le16 ctrl_fuses)
{
	struct shr_table *t;
	__u16 fuses = le16_to_cpu(ctrl_fuses);
	__u16 rsvd = (fuses & 0xFE) >> 1;
	__u16 cmpw = fuses & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", cmpw, "Fused Compare and Write %sSupported",
			 cmpw ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_fna_table(__u8 fna)
{
	struct shr_table *t;
	__u8 rsvd = (fna & 0xF0) >> 4;
	__u8 bcnsid = NVME_CTRL_FNA_NSID_ALL_F(fna);
	__u8 cese = NVME_CTRL_FNA_CES(fna);
	__u8 cens = NVME_CTRL_FNA_SEC_ALL_NS(fna);
	__u8 fmns = NVME_CTRL_FNA_FMT_ALL_NS(fna);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:4]", rsvd, "Reserved");
	stdout_bits_add(t, "[3:3]", bcnsid,
			 "Format NVM Broadcast NSID (FFFFFFFFh) %sSupported",
			 bcnsid ? "Not " : "");
	stdout_bits_add(t, "[2:2]", cese,
			 "Crypto Erase %sSupported as part of Secure Erase",
			 cese ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", cens,
			 "Crypto Erase Applies to %s Namespace(s)",
			 cens ? "All" : "Single");
	stdout_bits_add(t, "[0:0]", fmns, "Format Applies to %s Namespace(s)",
			 fmns ? "All" : "Single");

	return t;
}

static struct shr_table *stdout_id_ctrl_vwc_table(__u8 vwc)
{
	struct shr_table *t;
	__u8 rsvd = (vwc & 0xF8) >> 3;
	__u8 flush = (vwc & 0x6) >> 1;
	__u8 vwcp = vwc & 0x1;

	static const char * const flush_behavior[] = {
		"Support for the NSID field set to FFFFFFFFh is not indicated",
		"Reserved",
		"The Flush command does not support NSID set to FFFFFFFFh",
		"The Flush command supports NSID set to FFFFFFFFh"
	};

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:3]", rsvd, "Reserved");
	stdout_bits_add(t, "[2:1]", flush, "%s", flush_behavior[flush]);
	stdout_bits_add(t, "[0:0]", vwcp, "Volatile Write Cache %sPresent",
			 vwcp ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_icsvscc_table(__u8 icsvscc)
{
	struct shr_table *t;
	__u8 rsvd = (icsvscc & 0xFE) >> 1;
	__u8 fmt = icsvscc & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", fmt,
			 "NVM Vendor Specific Commands uses %s Format",
			 fmt ? "NVMe" : "Vendor Specific");

	return t;
}

static struct shr_table *stdout_id_ctrl_nwpc_table(__u8 nwpc)
{
	struct shr_table *t;
	__u8 no_wp_wp = (nwpc & 0x01);
	__u8 wp_power_cycle = (nwpc & 0x02) >> 1;
	__u8 wp_permanent = (nwpc & 0x04) >> 2;
	__u8 rsvd = (nwpc & 0xF8) >> 3;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:3]", rsvd, "Reserved");
	stdout_bits_add(t, "[2:2]", wp_permanent,
			 "Permanent Write Protect %sSupported",
			 wp_permanent ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", wp_power_cycle,
			 "Write Protect Until Power Supply %sSupported",
			 wp_power_cycle ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", no_wp_wp,
			 "No Write Protect and Write Protect Namespace %sSupported",
			 no_wp_wp ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_ocfs_table(__le16 ctrl_ocfs)
{
	struct shr_table *t;
	__u16 ocfs = le16_to_cpu(ctrl_ocfs);
	__u16 rsvd = ocfs >> 4;
	int copy_fmt;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:4]", rsvd, "Reserved");

	for (copy_fmt = 3; copy_fmt >= 0; copy_fmt--) {
		__cleanup_free char *bits = NULL;
		__cleanup_free char *desc = NULL;
		__u8 supported = ocfs >> copy_fmt & 1;

		if (asprintf(&bits, "[%d:%d]", copy_fmt, copy_fmt) < 0)
			bits = NULL;
		if (asprintf(&desc, "Controller Copy Format %xh %sSupported",
			     copy_fmt, supported ? "" : "Not ") < 0)
			desc = NULL;

		stdout_bits_add(t, bits ?: "", supported, desc ?: "");
	}

	return t;
}

static struct shr_table *stdout_id_ctrl_sgls_table(__le32 ctrl_sgls)
{
	struct shr_table *t;
	__u32 sgls = le32_to_cpu(ctrl_sgls);
	__u32 rsvd0 = (sgls & 0xFFC00000) >> 22;
	__u32 trsdbd = (sgls & 0x200000) >> 21;
	__u32 aofdsl = (sgls & 0x100000) >> 20;
	__u32 mpcsd = (sgls & 0x80000) >> 19;
	__u32 sglltb = (sgls & 0x40000) >> 18;
	__u32 bacmdb = (sgls & 0x20000) >> 17;
	__u32 bbs = (sgls & 0x10000) >> 16;
	__u32 sdt = (sgls >> 8) & 0xff;
	__u32 rsvd1 = (sgls & 0xF8) >> 3;
	__u32 key = (sgls & 0x4) >> 2;
	__u32 sglsp = sgls & 0x3;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd0)
		stdout_bits_add(t, "[31:22]", rsvd0, "Reserved");
	if (sglsp || (!sglsp && trsdbd))
		stdout_bits_add(t, "[21:21]", trsdbd,
				 "Transport SGL Data Block Descriptor %sSupported",
				 trsdbd ? "" : "Not ");
	if (sglsp || (!sglsp && aofdsl))
		stdout_bits_add(t, "[20:20]", aofdsl,
				 "Address Offsets %sSupported",
				 aofdsl ? "" : "Not ");
	if (sglsp || (!sglsp && mpcsd))
		stdout_bits_add(t, "[19:19]", mpcsd,
				 "Metadata Pointer Containing SGL Descriptor is %sSupported",
				 mpcsd ? "" : "Not ");
	if (sglsp || (!sglsp && sglltb))
		stdout_bits_add(t, "[18:18]", sglltb,
				 "SGL Length Larger than Buffer %sSupported",
				 sglltb ? "" : "Not ");
	if (sglsp || (!sglsp && bacmdb))
		stdout_bits_add(t, "[17:17]", bacmdb,
				 "Byte-Aligned Contig. MD Buffer %sSupported",
				 bacmdb ? "" : "Not ");
	if (sglsp || (!sglsp && bbs))
		stdout_bits_add(t, "[16:16]", bbs, "SGL Bit-Bucket %sSupported",
				 bbs ? "" : "Not ");
	stdout_bits_add(t, "[15:8]", sdt, "SGL Descriptor Threshold");
	if (rsvd1)
		stdout_bits_add(t, "[7:3]", rsvd1, "Reserved");
	if (sglsp || (!sglsp && key))
		stdout_bits_add(t, "[2:2]", key,
				 "Keyed SGL Data Block descriptor %sSupported",
				 key ? "" : "Not ");
	if (sglsp == 0x3)
		stdout_bits_add(t, "[1:0]", sglsp, "Reserved");
	else if (sglsp == 0x2)
		stdout_bits_add(t, "[1:0]", sglsp,
				 "Scatter-Gather Lists Supported. Dword alignment required.");
	else if (sglsp == 0x1)
		stdout_bits_add(t, "[1:0]", sglsp,
				 "Scatter-Gather Lists Supported. No Dword alignment required.");
	else
		stdout_bits_add(t, "[1:0]", sglsp,
				 "Scatter-Gather Lists Not Supported");

	return t;
}

static struct shr_table *stdout_id_ctrl_trattr_table(__u8 ctrl_trattr)
{
	struct shr_table *t;
	__u8 rsvd3 = (ctrl_trattr >> 3);
	__u8 mrtll = NVME_CTRL_TRATTR_MRTLL(ctrl_trattr);
	__u8 tudcs = NVME_CTRL_TRATTR_TUDCS(ctrl_trattr);
	__u8 thmcs = NVME_CTRL_TRATTR_THMCS(ctrl_trattr);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd3)
		stdout_bits_add(t, "[7:3]", rsvd3, "Reserved");
	stdout_bits_add(t, "[2:2]", mrtll,
			 "Memory Range Tracking Length Limit");
	stdout_bits_add(t, "[1:1]", tudcs,
			 "Tracking User Data Changes %sSupported",
			 tudcs ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", thmcs,
			 "Track Host Memory Changes %sSupported",
			 thmcs ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_fcatt_table(__u8 fcatt)
{
	struct shr_table *t;
	__u8 rsvd = (fcatt & 0xFE) >> 1;
	__u8 scm = fcatt & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", scm, "%s Controller Model",
			 scm ? "Static" : "Dynamic");

	return t;
}

static struct shr_table *stdout_id_ctrl_ofcs_table(__le16 ofcs_le)
{
	struct shr_table *t;
	__u16 ofcs = le16_to_cpu(ofcs_le);
	__u16 rsvd = (ofcs & 0xfffe) >> 1;
	__u8 disconn = ofcs & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", disconn, "Disconnect command %s Supported",
			 disconn ? "" : "Not");

	return t;
}

static struct shr_table *stdout_id_ctrl_dctype_table(__u8 dctype)
{
	struct shr_table *t;
	__u8 rsvd = (dctype & 0xFC) >> 2;
	__u8 dctype_val = dctype & 0x3;
	char *dctype_str;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:3]", rsvd, "Reserved");
	if (dctype_val == NVME_CTRL_DCTYPE_CDC)
		dctype_str = "CDC";
	else if (dctype_val == NVME_CTRL_DCTYPE_DDC)
		dctype_str = "DDC";
	else
		dctype_str = "not reported";

	stdout_bits_add(t, "[0:2]", dctype_val, "Discovery Controller Type: %s",
			 dctype_str);

	return t;
}

static struct shr_table *stdout_id_ns_nsfeat_table(__u8 nsfeat)
{
	struct shr_table *t;
	__u8 optrperf = (nsfeat & 0x80) >> 7;
	__u8 mam = (nsfeat & 0x40) >> 6;
	__u8 optperf = (nsfeat & 0x30) >> 4;
	__u8 uidreuse = (nsfeat & 0x8) >> 3;
	__u8 dulbe = (nsfeat & 0x4) >> 2;
	__u8 na = (nsfeat & 0x2) >> 1;
	__u8 thin = nsfeat & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:7]", optrperf,
			 "NPRG, NPRA and NORS are %sSupported",
			 optrperf ? "" : "Not ");
	stdout_bits_add(t, "[6:6]", mam,
			 "%s Atomicity Mode applies to write operations",
			 mam ? "Multiple" : "Single");
	stdout_bits_add(t, "[5:4]", optperf,
			 "NPWG, NPWA, %s%sNPDA, and NOWS are %sSupported",
			 ((optperf & 0x1) || (!optperf)) ? "NPDG, " : "",
			 ((optperf & 0x2) || (!optperf)) ? "NPDGL, " : "",
			 optperf ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", uidreuse,
			 "NGUID and EUI64 fields if non-zero, %sReused",
			 uidreuse ? "Never " : "");
	stdout_bits_add(t, "[2:2]", dulbe,
			 "Deallocated or Unwritten Logical Block error %sSupported",
			 dulbe ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", na, "Namespace uses %s",
			 na ? "NAWUN, NAWUPF, and NACWU" :
			 "AWUN, AWUPF, and ACWU");
	stdout_bits_add(t, "[0:0]", thin, "Thin Provisioning %sSupported",
			 thin ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ns_flbas_table(__u8 flbas)
{
	struct shr_table *t;
	__u8 rsvd = (flbas & 0x80) >> 7;
	__u8 msb2_lbaf = NVME_FLBAS_HIGHER(flbas);
	__u8 mdedata = NVME_FLBAS_META_EXT(flbas);
	__u8 lsb4_lbaf = NVME_FLBAS_LOWER(flbas);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:7]", rsvd, "Reserved");
	stdout_bits_add(t, "[6:5]", msb2_lbaf,
			 "Most significant 2 bits of Current LBA Format Selected");
	stdout_bits_add(t, "[4:4]", mdedata, "Metadata Transferred %s",
			 mdedata ? "at End of Data LBA" :
			 "in Separate Contiguous Buffer");
	stdout_bits_add(t, "[3:0]", lsb4_lbaf,
			 "Least significant 4 bits of Current LBA Format Selected");

	return t;
}

static struct shr_table *stdout_id_ns_mc_table(__u8 mc)
{
	struct shr_table *t;
	__u8 rsvd = (mc & 0xFC) >> 2;
	__u8 mdp = (mc & 0x2) >> 1;
	__u8 extdlba = mc & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", mdp, "Metadata Pointer %sSupported",
			 mdp ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", extdlba,
			 "Metadata as Part of Extended Data LBA %sSupported",
			 extdlba ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ns_dpc_table(__u8 dpc)
{
	struct shr_table *t;
	__u8 rsvd = (dpc & 0xE0) >> 5;
	__u8 pil8 = (dpc & 0x10) >> 4;
	__u8 pif8 = (dpc & 0x8) >> 3;
	__u8 pit3 = (dpc & 0x4) >> 2;
	__u8 pit2 = (dpc & 0x2) >> 1;
	__u8 pit1 = dpc & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:5]", rsvd, "Reserved");
	stdout_bits_add(t, "[4:4]", pil8,
			 "Protection Information Transferred as Last Bytes of Metadata %sSupported",
			 pil8 ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", pif8,
			 "Protection Information Transferred as First Bytes of Metadata %sSupported",
			 pif8 ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", pit3,
			 "Protection Information Type 3 %sSupported",
			 pit3 ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", pit2,
			 "Protection Information Type 2 %sSupported",
			 pit2 ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", pit1,
			 "Protection Information Type 1 %sSupported",
			 pit1 ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ns_dps_table(__u8 dps)
{
	struct shr_table *t;
	__u8 rsvd = (dps & 0xF0) >> 4;
	__u8 pif8 = NVME_NS_DPS_PI_FIRST(dps);
	__u8 pit = NVME_NS_DPS_PI(dps);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:4]", rsvd, "Reserved");
	stdout_bits_add(t, "[3:3]", pif8,
			 "Protection Information is Transferred as %s Bytes of Metadata",
			 pif8 ? "First" : "Last");
	stdout_bits_add(t, "[2:0]", pit, "Protection Information %s",
			 pit == 3 ? "Type 3 Enabled" :
			 pit == 2 ? "Type 2 Enabled" :
			 pit == 1 ? "Type 1 Enabled" :
			 pit == 0 ? "Disabled" : "Reserved Enabled");

	return t;
}

static struct shr_table *stdout_id_ns_nmic_table(__u8 nmic)
{
	struct shr_table *t;
	__u8 rsvd = (nmic & 0xfc) >> 2;
	__u8 disns = (nmic & 0x2) >> 1;
	__u8 shrns = nmic & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", disns,
			 "Namespace is %sa Dispersed Namespace",
			 disns ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", shrns, "Namespace Multipath %sCapable",
			 shrns ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ns_rescap_table(__u8 rescap)
{
	struct shr_table *t;
	__u8 iekr = (rescap & 0x80) >> 7;
	__u8 eaar = (rescap & 0x40) >> 6;
	__u8 wear = (rescap & 0x20) >> 5;
	__u8 earo = (rescap & 0x10) >> 4;
	__u8 wero = (rescap & 0x8) >> 3;
	__u8 ea = (rescap & 0x4) >> 2;
	__u8 we = (rescap & 0x2) >> 1;
	__u8 ptpl = rescap & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:7]", iekr,
			 "Ignore Existing Key - Used as defined in revision %s",
			 iekr ? "1.3 or later" : "1.2.1 or earlier");
	stdout_bits_add(t, "[6:6]", eaar,
			 "Exclusive Access - All Registrants %sSupported",
			 eaar ? "" : "Not ");
	stdout_bits_add(t, "[5:5]", wear,
			 "Write Exclusive - All Registrants %sSupported",
			 wear ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", earo,
			 "Exclusive Access - Registrants Only %sSupported",
			 earo ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", wero,
			 "Write Exclusive - Registrants Only %sSupported",
			 wero ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", ea, "Exclusive Access %sSupported",
			 ea ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", we, "Write Exclusive %sSupported",
			 we ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", ptpl,
			 "Persist Through Power Loss %sSupported",
			 ptpl ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ns_fpi_table(__u8 fpi)
{
	struct shr_table *t;
	__u8 fpis = (fpi & 0x80) >> 7;
	__u8 fpii = fpi & 0x7F;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:7]", fpis,
			 "Format Progress Indicator %sSupported",
			 fpis ? "" : "Not ");
	if (fpis || (!fpis && fpii))
		stdout_bits_add(t, "[6:0]", fpii,
				 "Format Progress Indicator (Remaining %d%%)",
				 fpii);

	return t;
}

static struct shr_table *stdout_id_ns_nsattr_table(__u8 nsattr)
{
	struct shr_table *t;
	__u8 rsvd = (nsattr & 0xFE) >> 1;
	__u8 write_protected = nsattr & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", write_protected,
			 "Namespace %sWrite Protected",
			 write_protected ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ns_dlfeat_table(__u8 dlfeat)
{
	struct shr_table *t;
	__u8 rsvd = (dlfeat & 0xE0) >> 5;
	__u8 guard = (dlfeat & 0x10) >> 4;
	__u8 dwz = (dlfeat & 0x8) >> 3;
	__u8 val = dlfeat & 0x7;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:5]", rsvd, "Reserved");
	stdout_bits_add(t, "[4:4]", guard,
			 "Guard Field of Deallocated Logical Blocks is set to %s",
			 guard ? "CRC of The Value Read" : "0xFFFF");
	stdout_bits_add(t, "[3:3]", dwz,
			 "Deallocate Bit in the Write Zeroes Command is %sSupported",
			 dwz ? "" : "Not ");
	stdout_bits_add(t, "[2:0]", val,
			 "Bytes Read From a Deallocated Logical Block and its Metadata are %s",
			 val == 2 ? "0xFF" :
			 val == 1 ? "0x00" :
			 val == 0 ? "Not Reported" : "Reserved Value");

	return t;
}

static struct shr_table *stdout_id_ns_kpios_table(__u8 kpios)
{
	struct shr_table *t;
	__u8 rsvd = (kpios & 0xfc) >> 2;
	__u8 kpiosns = (kpios & 0x2) >> 1;
	__u8 kpioens = kpios & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", kpiosns,
			 "Key Per I/O Capability %sSupported",
			 kpiosns ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", kpioens, "Key Per I/O Capability %s",
			 kpioens ? "Enabled" : "Disabled");

	return t;
}

struct stdout_id_ns_lbaf_table_support {
	bool verbose;
	bool cap_only;
};

static bool stdout_id_ns_lbaf_table_filter(const char *name, void *arg)
{
	const struct stdout_id_ns_lbaf_table_support *sup = arg;

	if (!sup->verbose &&
	    (!strcmp(name, "data_size") || !strcmp(name, "performance")))
		return false;
	if (sup->cap_only && !strcmp(name, "in_use"))
		return false;

	return true;
}

static const char *stdout_id_ns_lbaf_rp_str(__u8 rp)
{
	switch (rp) {
	case 3:
		return "Degraded";
	case 2:
		return "Good";
	case 1:
		return "Better";
	default:
		return "Best";
	}
}

static struct shr_table *stdout_id_ns_lbaf_table(struct nvme_id_ns *ns,
						 bool cap_only)
{
	/* no_widen on "lbaf" and "lbads", see stdout_id_ctrl_ps_table(). */
	struct shr_table_column columns[] = {
		{ "lbaf", RIGHT, AUTO_WIDTH, .no_widen = true },
		{ "ms", RIGHT, AUTO_WIDTH },
		{ "lbads", RIGHT, AUTO_WIDTH, .no_widen = true },
		{ "data_size", RIGHT, AUTO_WIDTH },
		{ "rp", RIGHT, AUTO_WIDTH },
		{ "performance", LEFT, AUTO_WIDTH },
		{ "in_use", LEFT, AUTO_WIDTH },
	};
	struct shr_table *t;
	struct stdout_id_ns_lbaf_table_support sup = {
		.verbose = stdout_print_ops.flags & VERBOSE,
		.cap_only = cap_only,
	};
	__u8 flbas;
	int i;

	t = shr_table_create();
	if (!t)
		return NULL;

	if (shr_table_add_columns_filter(t, columns, ARRAY_SIZE(columns),
			stdout_id_ns_lbaf_table_filter, &sup) < 0) {
		shr_table_free(t);
		return NULL;
	}

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &flbas);
	for (i = 0; i <= ns->nlbaf + ns->nulbaf; i++) {
		struct nvme_lbaf *lbaf = &ns->lbaf[i];
		int row = shr_table_get_row_id(t);
		int col = -1;

		shr_table_set_value_int(t, ++col, row, i, RIGHT);
		shr_table_set_value_unsigned(t, ++col, row,
				le16_to_cpu(lbaf->ms), RIGHT);
		shr_table_set_value_unsigned(t, ++col, row, lbaf->ds, RIGHT);
		if (sup.verbose)
			shr_table_set_value_unsigned(t, ++col, row,
					1U << lbaf->ds, RIGHT);
		shr_table_set_value_unsigned(t, ++col, row, lbaf->rp, RIGHT);
		if (sup.verbose)
			shr_table_set_value_str(t, ++col, row,
					stdout_id_ns_lbaf_rp_str(lbaf->rp),
					LEFT);
		if (!cap_only)
			shr_table_set_value_str(t, ++col, row,
					i == flbas ? "yes" : "", LEFT);

		shr_table_add_row(t, row);
	}

	return t;
}

void stdout_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
		  unsigned int lba_index, bool cap_only)
{
	bool verbose = stdout_print_ops.flags & VERBOSE;
	int vs = stdout_print_ops.flags & VS;
	struct shr_table *t;
	char nguid_buf[2 * sizeof(ns->nguid) + 1], *nguid = nguid_buf;
	char eui64_buf[2 * sizeof(ns->eui64) + 1], *eui64 = eui64_buf;
	int row, i;

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (!cap_only) {
		printf("NVME Identify Namespace %d:\n", nsid);

		if (verbose) {
			stdout_kv_add(t, "nsze",
				"%#"PRIx64"\tTotal size in logical blocks",
				le64_to_cpu(ns->nsze));
			stdout_kv_add(t, "ncap",
				"%#"PRIx64"\tMaximum size in logical blocks",
				le64_to_cpu(ns->ncap));
			stdout_kv_add(t, "nuse",
				"%#"PRIx64"\tCurrent size in logical blocks",
				le64_to_cpu(ns->nuse));
		} else {
			stdout_kv_add(t, "nsze", "%#"PRIx64,
				      le64_to_cpu(ns->nsze));
			stdout_kv_add(t, "ncap", "%#"PRIx64,
				      le64_to_cpu(ns->ncap));
			stdout_kv_add(t, "nuse", "%#"PRIx64,
				      le64_to_cpu(ns->nuse));
		}

		row = stdout_kv_add(t, "nsfeat", "%#x", ns->nsfeat);
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_nsfeat_table(ns->nsfeat));
	} else {
		printf("NVMe Identify Namespace for LBA format[%d]:\n",
		       lba_index);
	}

	stdout_kv_add(t, "nlbaf", "%d", ns->nlbaf);
	if (!cap_only) {
		row = stdout_kv_add(t, "flbas", "%#x", ns->flbas);
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_flbas_table(ns->flbas));
	}

	row = stdout_kv_add(t, "mc", "%#x", ns->mc);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_mc_table(ns->mc));

	row = stdout_kv_add(t, "dpc", "%#x", ns->dpc);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_dpc_table(ns->dpc));

	if (!cap_only) {
		row = stdout_kv_add(t, "dps", "%#x", ns->dps);
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_dps_table(ns->dps));

		row = stdout_kv_add(t, "nmic", "%#x", ns->nmic);
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_nmic_table(ns->nmic));

		row = stdout_kv_add(t, "rescap", "%#x", ns->rescap);
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_rescap_table(ns->rescap));

		row = stdout_kv_add(t, "fpi", "%#x", ns->fpi);
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_fpi_table(ns->fpi));

		row = stdout_kv_add(t, "dlfeat", "%d", ns->dlfeat);
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_dlfeat_table(ns->dlfeat));

		stdout_kv_add(t, "nawun", "%d", le16_to_cpu(ns->nawun));
		stdout_kv_add(t, "nawupf", "%d", le16_to_cpu(ns->nawupf));
		stdout_kv_add(t, "nacwu", "%d", le16_to_cpu(ns->nacwu));
		stdout_kv_add(t, "nabsn", "%d", le16_to_cpu(ns->nabsn));
		stdout_kv_add(t, "nabo", "%d", le16_to_cpu(ns->nabo));
		stdout_kv_add(t, "nabspf", "%d", le16_to_cpu(ns->nabspf));
		stdout_kv_add(t, "noiob", "%d", le16_to_cpu(ns->noiob));
		stdout_kv_add(t, "nvmcap", "%s",
			      uint128_t_to_l10n_string(
					      le128_to_cpu(ns->nvmcap)));
		if (ns->nsfeat & 0x30) {
			stdout_kv_add(t, "npwg", "%u", le16_to_cpu(ns->npwg));
			stdout_kv_add(t, "npwa", "%u", le16_to_cpu(ns->npwa));
			if (ns->nsfeat & 0x10)
				stdout_kv_add(t, "npdg", "%u",
					      le16_to_cpu(ns->npdg));
			stdout_kv_add(t, "npda", "%u", le16_to_cpu(ns->npda));
			stdout_kv_add(t, "nows", "%u", le16_to_cpu(ns->nows));
		}
		stdout_kv_add(t, "mssrl", "%u", le16_to_cpu(ns->mssrl));
		stdout_kv_add(t, "mcl", "%u", le32_to_cpu(ns->mcl));
		stdout_kv_add(t, "msrc", "%u", ns->msrc);

		row = stdout_kv_add(t, "kpios", "%u", ns->kpios);
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_kpios_table(ns->kpios));
	}

	stdout_kv_add(t, "nulbaf", "%u", ns->nulbaf);
	if (!cap_only) {
		stdout_kv_add(t, "kpiodaag", "%u", le32_to_cpu(ns->kpiodaag));
		stdout_kv_add(t, "anagrpid", "%u", le32_to_cpu(ns->anagrpid));

		row = stdout_kv_add(t, "nsattr", "%u", ns->nsattr);
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_nsattr_table(ns->nsattr));

		stdout_kv_add(t, "nvmsetid", "%d", le16_to_cpu(ns->nvmsetid));
		stdout_kv_add(t, "endgid", "%d", le16_to_cpu(ns->endgid));

		for (i = 0; i < (int)sizeof(ns->nguid); i++)
			nguid += sprintf(nguid, "%02x", ns->nguid[i]);
		stdout_kv_add(t, "nguid", "%s", nguid_buf);

		for (i = 0; i < (int)sizeof(ns->eui64); i++)
			eui64 += sprintf(eui64, "%02x", ns->eui64[i]);
		stdout_kv_add(t, "eui64", "%s", eui64_buf);
	}

	row = stdout_kv_add(t, "lbaf", "%d formats",
			    ns->nlbaf + ns->nulbaf + 1);
	shr_table_set_row_subtable(t, row,
				   stdout_id_ns_lbaf_table(ns, cap_only));

	stdout_kv_table_finish(t, "identify-namespace");

	if (vs && !cap_only) {
		printf("vs[]:\n");
		d(ns->vs, sizeof(ns->vs), 16, 1);
	}
}

static struct shr_table *
stdout_cmd_set_independent_id_ns_nsfeat_table(__u8 nsfeat)
{
	struct shr_table *t;
	__u8 rsvd6 = (nsfeat & 0xE0) >> 6;
	__u8 vwcnp = (nsfeat & 0x20) >> 5;
	__u8 rmedia = (nsfeat & 0x10) >> 4;
	__u8 uidreuse = (nsfeat & 0x8) >> 3;
	__u8 rsvd0 = (nsfeat & 0x7);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd6)
		stdout_bits_add(t, "[7:6]", rsvd6, "Reserved");
	stdout_bits_add(t, "[5:5]", vwcnp,
			 "Volatile Write Cache is %sPresent",
			 vwcnp ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", rmedia,
			 "Namespace %sstore data on rotational media",
			 rmedia ? "" : "does not ");
	stdout_bits_add(t, "[3:3]", uidreuse,
			 "NGUID and EUI64 fields if non-zero, %sReused",
			 uidreuse ? "Never " : "");
	if (rsvd0)
		stdout_bits_add(t, "[2:0]", rsvd0, "Reserved");

	return t;
}

static struct shr_table *
stdout_cmd_set_independent_id_ns_nstat_table(__u8 nstat)
{
	struct shr_table *t;
	__u8 rsvd3 = (nstat & 0xf8) >> 3;
	__u8 ioi = (nstat & 0x6) >> 1;
	__u8 nrdy = nstat & 0x1;

	static const char * const ioi_string[] = {
		"I/O performance degradation is not reported",
		"Reserved",
		"I/O performance is not currently degraded",
		"I/O performance is currently degraded"
	};

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd3)
		stdout_bits_add(t, "[7:3]", rsvd3, "Reserved");
	stdout_bits_add(t, "[2:1]", ioi, "%s", ioi_string[ioi]);
	stdout_bits_add(t, "[0:0]", nrdy, "Name space is %sready",
			 nrdy ? "" : "not ");

	return t;
}

void stdout_cmd_set_independent_id_ns(struct nvme_id_independent_id_ns *ns,
				      unsigned int nsid)
{
	bool verbose = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	int row;

	printf("NVME Identify Command Set Independent Namespace %d:\n", nsid);

	t = stdout_kv_table_create();
	if (!t)
		return;

	row = stdout_kv_add(t, "nsfeat", "%#x", ns->nsfeat);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_cmd_set_independent_id_ns_nsfeat_table(
						ns->nsfeat));

	row = stdout_kv_add(t, "nmic", "%#x", ns->nmic);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_nmic_table(ns->nmic));

	row = stdout_kv_add(t, "rescap", "%#x", ns->rescap);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_rescap_table(ns->rescap));

	row = stdout_kv_add(t, "fpi", "%#x", ns->fpi);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_fpi_table(ns->fpi));

	stdout_kv_add(t, "anagrpid", "%u", le32_to_cpu(ns->anagrpid));

	row = stdout_kv_add(t, "nsattr", "%u", ns->nsattr);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_nsattr_table(ns->nsattr));

	stdout_kv_add(t, "nvmsetid", "%d", le16_to_cpu(ns->nvmsetid));
	stdout_kv_add(t, "endgid", "%d", le16_to_cpu(ns->endgid));

	row = stdout_kv_add(t, "nstat", "%#x", ns->nstat);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_cmd_set_independent_id_ns_nstat_table(
						ns->nstat));

	row = stdout_kv_add(t, "kpios", "%#x", ns->kpios);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_kpios_table(ns->kpios));

	stdout_kv_add(t, "maxkt", "%#x", le16_to_cpu(ns->maxkt));
	stdout_kv_add(t, "rgrpid", "%#x", le32_to_cpu(ns->rgrpid));

	stdout_kv_table_finish(t, "id-independent-id-ns");
}

void stdout_id_ns_descs(void *data, unsigned int nsid)
{
	int pos, len = 0;
	int i, verbose = stdout_print_ops.flags & VERBOSE;
	__u8 uuid[NVME_UUID_LEN];
	char uuid_str[NVME_UUID_LEN_STRING];
	__u8 eui64[8];
	__u8 nguid[16];
	__u8 csi;
	struct shr_table *t;
	char hex[NVME_UUID_LEN * 2 + 1], *hp;

	printf("NVME Namespace Identification Descriptors NS %d:\n", nsid);

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (pos = 0; pos < NVME_IDENTIFY_DATA_SIZE; pos += len) {
		struct nvme_ns_id_desc *cur = data + pos;

		if (cur->nidl == 0)
			break;

		if (verbose) {
			stdout_kv_add(t, "loc", "%d", pos);
			stdout_kv_add(t, "nidt", "%d", (int)cur->nidt);
			stdout_kv_add(t, "nidl", "%d", (int)cur->nidl);
		}

		switch (cur->nidt) {
		case NVME_NIDT_EUI64:
			memcpy(eui64, data + pos + sizeof(*cur), sizeof(eui64));
			if (verbose)
				stdout_kv_add(t, "type", "%s", "eui64");
			hp = hex;
			for (i = 0; i < 8; i++)
				hp += sprintf(hp, "%02x", eui64[i]);
			stdout_kv_add(t, "eui64", "%s", hex);
			len = sizeof(eui64);
			break;
		case NVME_NIDT_NGUID:
			memcpy(nguid, data + pos + sizeof(*cur), sizeof(nguid));
			if (verbose)
				stdout_kv_add(t, "type", "%s", "nguid");
			hp = hex;
			for (i = 0; i < 16; i++)
				hp += sprintf(hp, "%02x", nguid[i]);
			stdout_kv_add(t, "nguid", "%s", hex);
			len = sizeof(nguid);
			break;
		case NVME_NIDT_UUID:
			memcpy(uuid, data + pos + sizeof(*cur), 16);
			libnvme_uuid_to_string(uuid, uuid_str);
			if (verbose)
				stdout_kv_add(t, "type", "%s", "uuid");
			stdout_kv_add(t, "uuid", "%s", uuid_str);
			len = sizeof(uuid);
			break;
		case NVME_NIDT_CSI:
			memcpy(&csi, data + pos + sizeof(*cur), 1);
			if (verbose)
				stdout_kv_add(t, "type", "%s", "csi");
			stdout_kv_add(t, "csi", "%#x", csi);
			len += sizeof(csi);
			break;
		default:
			/* Skip unknown types */
			len = cur->nidl;
			break;
		}

		len += sizeof(*cur);
	}

	stdout_kv_table_finish(t, "id-ns-descs");
}

/*
 * Only for &struct nvme_id_psd's idlp/actp: unlike
 * stdout_power_and_scale_str()'s other callers (Power Limit/Threshold
 * features, Interval Power Measurement, power-meas-log), the Power State
 * Descriptor spec text says a raw value of 0 means "not reported"
 * independent of the scale field.
 */
static char *stdout_psd_power_str(__u16 power, __u8 scale)
{
	char *s = NULL;

	if (!power) {
		if (asprintf(&s, "-") < 0)
			s = NULL;
		return s;
	}

	return stdout_power_and_scale_str(power, scale);
}

static char *stdout_bandwidth_and_scale_str(__u8 bw, __u8 scale)
{
	char *s = NULL;

	if (!bw) {
		if (asprintf(&s, "-") < 0)
			s = NULL;
		return s;
	}

	switch (scale & 0x7) {
	case NVME_PSD_MBWS_1_MIB_S:
		if (asprintf(&s, "%uMiB/s", bw) < 0)
			s = NULL;
		break;
	case NVME_PSD_MBWS_10_MIB_S:
		if (asprintf(&s, "%uMiB/s", bw * 10) < 0)
			s = NULL;
		break;
	case NVME_PSD_MBWS_100_MIB_S:
		if (asprintf(&s, "%uMiB/s", bw * 100) < 0)
			s = NULL;
		break;
	case NVME_PSD_MBWS_1_GIB_S:
		if (asprintf(&s, "%uGiB/s", bw) < 0)
			s = NULL;
		break;
	case NVME_PSD_MBWS_10_GIB_S:
		if (asprintf(&s, "%uGiB/s", bw * 10) < 0)
			s = NULL;
		break;
	case NVME_PSD_MBWS_100_GIB_S:
		if (asprintf(&s, "%uGiB/s", bw * 100) < 0)
			s = NULL;
		break;
	default:
		if (asprintf(&s, "reserved") < 0)
			s = NULL;
		break;
	}

	return s;
}

static char *stdout_psd_workload_str(__u8 apw)
{
	const char *s;

	switch (apw & 0x7) {
	case NVME_PSD_WORKLOAD_NP:
		s = "-";
		break;
	case 1:
		s = "1MiB 32 RW, 30s idle";
		break;
	case 2:
		s = "80K 128KiB SW";
		break;
	default:
		s = "reserved";
		break;
	}

	return strdup(s);
}

/*
 * Multiplies @time by @ts's scale up front -- e.g. "60us" (6 counts of 10
 * microseconds each) rather than leaving that math to the reader. @ts values
 * beyond the scale table are reserved.
 */
static char *stdout_psd_time_str(__u8 time, __u8 ts)
{
	static const struct {
		unsigned int mult;
		const char *unit;
	} scale[] = {
		{ 1, "us" }, { 10, "us" }, { 100, "us" },
		{ 1, "ms" }, { 10, "ms" }, { 100, "ms" },
		{ 1, "s" }, { 10, "s" }, { 100, "s" },
		{ 1000, "s" }, { 10000, "s" }, { 100000, "s" },
		{ 1000000, "s" },
	};
	char *s = NULL;

	switch (time) {
	case 0:
		if (asprintf(&s, "-") < 0)
			s = NULL;
		break;
	case 1 ... 99:
		if (ts >= ARRAY_SIZE(scale)) {
			if (asprintf(&s, "reserved") < 0)
				s = NULL;
		} else if (asprintf(&s, "%u%s", time * scale[ts].mult,
				    scale[ts].unit) < 0) {
			s = NULL;
		}
		break;
	default:
		if (asprintf(&s, "reserved") < 0)
			s = NULL;
		break;
	}

	return s;
}

/* @lat is in microseconds; a value of 0 means "not reported". */
static char *stdout_psd_latency_str(__u32 lat)
{
	char *s = NULL;

	if (!lat) {
		if (asprintf(&s, "-") < 0)
			s = NULL;
	} else if (asprintf(&s, "%uus", lat) < 0) {
		s = NULL;
	}

	return s;
}

struct stdout_id_ctrl_ps_table_support {
	bool iiellss;
	bool plsepf;
	bool plsfq;
	bool idle_power_used;
	bool active_power_used;
	bool workload_used;
	bool max_bandwidth_used;
	bool verbose;
};

static bool stdout_id_ctrl_ps_table_filter(const char *name, void *arg)
{
	const struct stdout_id_ctrl_ps_table_support *sup = arg;

	if (sup->verbose)
		return true;
	if (!sup->iiellss && !strcmp(name, "miiell"))
		return false;
	if (!sup->plsepf && (!strcmp(name, "epfrt") || !strcmp(name, "epfvt")))
		return false;
	if (!sup->plsfq && !strcmp(name, "fqvt"))
		return false;
	if (!sup->idle_power_used && !strcmp(name, "idle_power"))
		return false;
	if (!sup->active_power_used && !strcmp(name, "active_power"))
		return false;
	if (!sup->workload_used && !strcmp(name, "workload"))
		return false;
	if (!sup->max_bandwidth_used && !strcmp(name, "max_bandwidth"))
		return false;

	return true;
}

static bool stdout_id_ctrl_ps_idlp_used(struct nvme_id_ctrl *ctrl)
{
	int i;

	for (i = 0; i <= ctrl->npss; i++) {
		if (le16_to_cpu(ctrl->psd[i].idlp))
			return true;
	}

	return false;
}

static bool stdout_id_ctrl_ps_actp_used(struct nvme_id_ctrl *ctrl)
{
	int i;

	for (i = 0; i <= ctrl->npss; i++) {
		if (le16_to_cpu(ctrl->psd[i].actp))
			return true;
	}

	return false;
}

static bool stdout_id_ctrl_ps_apw_used(struct nvme_id_ctrl *ctrl)
{
	int i;

	for (i = 0; i <= ctrl->npss; i++) {
		if (ctrl->psd[i].apws & 0x7)
			return true;
	}

	return false;
}

static bool stdout_id_ctrl_ps_mbw_used(struct nvme_id_ctrl *ctrl)
{
	int i;

	for (i = 0; i <= ctrl->npss; i++) {
		if (ctrl->psd[i].mbw)
			return true;
	}

	return false;
}

/*
 * One row per power state, one column per sub-field -- unlike the bit-decode
 * subtables, which are one row per bit range -- since every power state
 * repeats the same fixed set of fields: a real table, not a "name : value"
 * list. Attached unconditionally, not just under -v.
 */
static struct shr_table *stdout_id_ctrl_ps_table(struct nvme_id_ctrl *ctrl)
{
	/*
	 * no_widen on "ps" and "state": columns 0 and 2 are what
	 * shr_table_align_column() widens to line up the outer table's
	 * "name :" and the bits subtables' "value" column, and this table
	 * happens to have its own columns at those same indices -- which do
	 * not mean the same thing, so they must opt out.
	 */
	struct shr_table_column columns[] = {
		{ "ps", RIGHT, AUTO_WIDTH, .no_widen = true },
		{ "mp", RIGHT, AUTO_WIDTH },
		{ "state", LEFT, AUTO_WIDTH, .no_widen = true },
		{ "enlat", RIGHT, AUTO_WIDTH },
		{ "exlat", RIGHT, AUTO_WIDTH },
		{ "rrt", RIGHT, AUTO_WIDTH },
		{ "rrl", RIGHT, AUTO_WIDTH },
		{ "rwt", RIGHT, AUTO_WIDTH },
		{ "rwl", RIGHT, AUTO_WIDTH },
		{ "idle_power", RIGHT, AUTO_WIDTH },
		{ "active_power", RIGHT, AUTO_WIDTH },
		{ "workload", LEFT, AUTO_WIDTH },
		{ "epfrt", LEFT, AUTO_WIDTH },
		{ "fqvt", LEFT, AUTO_WIDTH },
		{ "epfvt", LEFT, AUTO_WIDTH },
		{ "max_bandwidth", RIGHT, AUTO_WIDTH },
		{ "miiell", RIGHT, AUTO_WIDTH },
	};
	struct shr_table *t;
	struct stdout_id_ctrl_ps_table_support sup = {
		.iiellss = NVME_CTRL_CTRATT_IIELLSS(le32_to_cpu(ctrl->ctratt)),
		.plsepf = NVME_CTRL_PLSI_PLSEPF(ctrl->plsi),
		.plsfq = NVME_CTRL_PLSI_PLSFQ(ctrl->plsi),
		.idle_power_used = stdout_id_ctrl_ps_idlp_used(ctrl),
		.active_power_used = stdout_id_ctrl_ps_actp_used(ctrl),
		.workload_used = stdout_id_ctrl_ps_apw_used(ctrl),
		.max_bandwidth_used = stdout_id_ctrl_ps_mbw_used(ctrl),
		.verbose = stdout_print_ops.flags & VERBOSE,
	};
	int i;

	t = shr_table_create();
	if (!t)
		return NULL;

	if (shr_table_add_columns_filter(t, columns, ARRAY_SIZE(columns),
			stdout_id_ctrl_ps_table_filter, &sup) < 0) {
		shr_table_free(t);
		return NULL;
	}

	for (i = 0; i <= ctrl->npss; i++) {
		struct nvme_id_psd *psd = &ctrl->psd[i];
		__u16 max_power = le16_to_cpu(psd->mp);
		__cleanup_free char *mp = NULL;
		__cleanup_free char *enlat = NULL;
		__cleanup_free char *exlat = NULL;
		__cleanup_free char *idle_power = NULL;
		__cleanup_free char *active_power = NULL;
		__cleanup_free char *workload = NULL;
		__cleanup_free char *epfrt = NULL;
		__cleanup_free char *fqvt = NULL;
		__cleanup_free char *epfvt = NULL;
		__cleanup_free char *max_bandwidth = NULL;
		__cleanup_free char *miiell = NULL;
		int row = shr_table_get_row_id(t);
		int col = -1;

		if (!max_power) {
			if (asprintf(&mp, "-") < 0)
				mp = NULL;
		} else if (psd->flags & NVME_PSD_FLAGS_MXPS) {
			if (asprintf(&mp, "%01u.%04uW",
				     max_power / 10000, max_power % 10000) < 0)
				mp = NULL;
		} else {
			if (asprintf(&mp, "%01u.%02uW",
				     max_power / 100, max_power % 100) < 0)
				mp = NULL;
		}

		idle_power = stdout_psd_power_str(
				le16_to_cpu(psd->idlp),
				nvme_psd_power_scale(psd->ips));
		active_power = stdout_psd_power_str(
				le16_to_cpu(psd->actp),
				nvme_psd_power_scale(psd->apws));
		workload = stdout_psd_workload_str(psd->apws);
		if (sup.plsepf) {
			epfrt = stdout_psd_time_str(psd->epfrt,
						     psd->epfr_fqv_ts & 0xf);
			epfvt = stdout_psd_time_str(psd->epfvt,
						     psd->epfvts & 0xf);
		}
		if (sup.plsfq)
			fqvt = stdout_psd_time_str(psd->fqvt,
						    psd->epfr_fqv_ts >> 4);
		max_bandwidth = stdout_bandwidth_and_scale_str(psd->mbw,
								psd->mbws);
		enlat = stdout_psd_latency_str(le32_to_cpu(psd->enlat));
		exlat = stdout_psd_latency_str(le32_to_cpu(psd->exlat));

		if (sup.iiellss) {
			__u16 miiell_val = le16_to_cpu(psd->miiell);

			if (miiell_val) {
				if (asprintf(&miiell, "%uus",
					     miiell_val * 100) < 0)
					miiell = NULL;
			} else {
				if (asprintf(&miiell, "none") < 0)
					miiell = NULL;
			}
		}

		shr_table_set_value_int(t, ++col, row, i, RIGHT);
		shr_table_set_value_str(t, ++col, row, mp ?: "-", RIGHT);
		shr_table_set_value_str(t, ++col, row,
				psd->flags & NVME_PSD_FLAGS_NOPS ?
				"non-operational" : "operational",
				LEFT);
		shr_table_set_value_str(t, ++col, row, enlat ?: "-", RIGHT);
		shr_table_set_value_str(t, ++col, row, exlat ?: "-", RIGHT);
		shr_table_set_value_unsigned(t, ++col, row, psd->rrt, RIGHT);
		shr_table_set_value_unsigned(t, ++col, row, psd->rrl, RIGHT);
		shr_table_set_value_unsigned(t, ++col, row, psd->rwt, RIGHT);
		shr_table_set_value_unsigned(t, ++col, row, psd->rwl, RIGHT);
		if (sup.idle_power_used || sup.verbose)
			shr_table_set_value_str(t, ++col, row,
					idle_power ?: "-", RIGHT);
		if (sup.active_power_used || sup.verbose)
			shr_table_set_value_str(t, ++col, row,
					active_power ?: "-", RIGHT);
		if (sup.workload_used || sup.verbose)
			shr_table_set_value_str(t, ++col, row,
					workload ?: "-", LEFT);
		if (sup.plsepf || sup.verbose)
			shr_table_set_value_str(t, ++col, row,
					epfrt ?: "-", LEFT);
		if (sup.plsfq || sup.verbose)
			shr_table_set_value_str(t, ++col, row,
					fqvt ?: "-", LEFT);
		if (sup.plsepf || sup.verbose)
			shr_table_set_value_str(t, ++col, row,
					epfvt ?: "-", LEFT);
		if (sup.max_bandwidth_used || sup.verbose)
			shr_table_set_value_str(t, ++col, row,
					max_bandwidth ?: "-", RIGHT);
		if (sup.iiellss || sup.verbose)
			shr_table_set_value_str(t, ++col, row,
					miiell ?: "-", RIGHT);

		shr_table_add_row(t, row);
	}

	return t;
}

static void stdout_id_ctrl_cap_feat(struct nvme_id_ctrl *ctrl,
				    struct shr_table *t, bool verbose)
{
	char sn[sizeof(ctrl->sn) + 1];
	char mn[sizeof(ctrl->mn) + 1];
	char fr[sizeof(ctrl->fr) + 1];
	int row;

	snprintf(sn, sizeof(sn), "%-.*s", (int)sizeof(ctrl->sn), ctrl->sn);
	snprintf(mn, sizeof(mn), "%-.*s", (int)sizeof(ctrl->mn), ctrl->mn);
	snprintf(fr, sizeof(fr), "%-.*s", (int)sizeof(ctrl->fr), ctrl->fr);

	if (verbose)
		stdout_kv_add(t, "255:00",
			      "Controller Capabilities and Features");

	stdout_kv_add(t, "vid", "%#x", le16_to_cpu(ctrl->vid));
	stdout_kv_add(t, "ssvid", "%#x", le16_to_cpu(ctrl->ssvid));
	stdout_kv_add(t, "sn", "%s", shr_rtrim(sn));
	stdout_kv_add(t, "mn", "%s", shr_rtrim(mn));
	stdout_kv_add(t, "fr", "%s", shr_rtrim(fr));
	stdout_kv_add(t, "rab", "%d", ctrl->rab);
	stdout_kv_add(t, "ieee", "%02x%02x%02x",
		      ctrl->ieee[2], ctrl->ieee[1], ctrl->ieee[0]);

	row = stdout_kv_add(t, "cmic", "%#x", ctrl->cmic);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_cmic_table(ctrl->cmic));

	stdout_kv_add(t, "mdts", "%d", ctrl->mdts);
	stdout_kv_add(t, "cntlid", "%#x", le16_to_cpu(ctrl->cntlid));
	stdout_kv_add(t, "ver", "%#x", le32_to_cpu(ctrl->ver));
	stdout_kv_add(t, "rtd3r", "%#x", le32_to_cpu(ctrl->rtd3r));
	stdout_kv_add(t, "rtd3e", "%#x", le32_to_cpu(ctrl->rtd3e));

	row = stdout_kv_add(t, "oaes", "%#x", le32_to_cpu(ctrl->oaes));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_oaes_table(ctrl->oaes));

	row = stdout_kv_add(t, "ctratt", "%#x", le32_to_cpu(ctrl->ctratt));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_ctratt_table(ctrl->ctratt));

	stdout_kv_add(t, "rrls", "%#x", le16_to_cpu(ctrl->rrls));

	row = stdout_kv_add(t, "bpcap", "%#x", le16_to_cpu(ctrl->bpcap));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_bpcap_table(ctrl->bpcap));

	row = stdout_kv_add(t, "chsi", "%#x", ctrl->chsi);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_chsi_table(ctrl->chsi));

	stdout_kv_add(t, "nssl", "%#x", le32_to_cpu(ctrl->nssl));

	row = stdout_kv_add(t, "plsi", "%u", ctrl->plsi);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_plsi_table(ctrl->plsi));

	row = stdout_kv_add(t, "cntrltype", "%d", ctrl->cntrltype);
	if (verbose)
		shr_table_set_row_subtable(t, row,
			stdout_id_ctrl_cntrltype_table(ctrl->cntrltype));

	stdout_kv_add(t, "fguid", "%s", shr_uuid_to_string(ctrl->fguid));
	stdout_kv_add(t, "crdt1", "%u", le16_to_cpu(ctrl->crdt1));
	stdout_kv_add(t, "crdt2", "%u", le16_to_cpu(ctrl->crdt2));
	stdout_kv_add(t, "crdt3", "%u", le16_to_cpu(ctrl->crdt3));

	row = stdout_kv_add(t, "crcap", "%u", ctrl->crcap);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_crcap_table(ctrl->crcap));

	stdout_kv_add(t, "ciu", "%u", ctrl->ciu);
	stdout_kv_add(t, "cirn", "%"PRIu64,
		      le64_to_cpu(*(__le64 *)ctrl->cirn));

	row = stdout_kv_add(t, "nvmsr", "%u", ctrl->nvmsr);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_nvmsr_table(ctrl->nvmsr));

	row = stdout_kv_add(t, "vwci", "%u", ctrl->vwci);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_vwci_table(ctrl->vwci));

	row = stdout_kv_add(t, "mec", "%u", ctrl->mec);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_mec_table(ctrl->mec));
}

static void stdout_id_ctrl_admin_option(struct nvme_id_ctrl *ctrl,
					struct shr_table *t, bool verbose)
{
	int row;

	if (verbose)
		stdout_kv_add(t, "511:256",
		    "Admin Command Set Attributes & Optional Controller Capabilities");

	row = stdout_kv_add(t, "oacs", "%#x", le16_to_cpu(ctrl->oacs));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_oacs_table(ctrl->oacs));

	stdout_kv_add(t, "acl", "%d", ctrl->acl);
	stdout_kv_add(t, "aerl", "%d", ctrl->aerl);

	row = stdout_kv_add(t, "frmw", "%#x", ctrl->frmw);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_frmw_table(ctrl->frmw));

	row = stdout_kv_add(t, "lpa", "%#x", ctrl->lpa);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_lpa_table(ctrl->lpa));

	row = stdout_kv_add(t, "elpe", "%d", ctrl->elpe);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_elpe_table(ctrl->elpe));

	row = stdout_kv_add(t, "npss", "%d", ctrl->npss);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_npss_table(ctrl->npss));

	row = stdout_kv_add(t, "avscc", "%#x", ctrl->avscc);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_avscc_table(ctrl->avscc));

	row = stdout_kv_add(t, "apsta", "%#x", ctrl->apsta);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_apsta_table(ctrl->apsta));

	row = stdout_kv_add(t, "wctemp", "%d", le16_to_cpu(ctrl->wctemp));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_wctemp_table(ctrl->wctemp));

	row = stdout_kv_add(t, "cctemp", "%d", le16_to_cpu(ctrl->cctemp));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_cctemp_table(ctrl->cctemp));

	stdout_kv_add(t, "mtfa", "%d", le16_to_cpu(ctrl->mtfa));
	stdout_kv_add(t, "hmpre", "%u", le32_to_cpu(ctrl->hmpre));
	stdout_kv_add(t, "hmmin", "%u", le32_to_cpu(ctrl->hmmin));

	row = stdout_kv_add(t, "tnvmcap", "%s",
			     uint128_t_to_l10n_string(
					le128_to_cpu(ctrl->tnvmcap)));
	if (verbose)
		shr_table_set_row_subtable(t, row,
			stdout_id_ctrl_tnvmcap_table(ctrl->tnvmcap));

	row = stdout_kv_add(t, "unvmcap", "%s",
			     uint128_t_to_l10n_string(
					le128_to_cpu(ctrl->unvmcap)));
	if (verbose)
		shr_table_set_row_subtable(t, row,
			stdout_id_ctrl_unvmcap_table(ctrl->unvmcap));

	row = stdout_kv_add(t, "rpmbs", "%#x", le32_to_cpu(ctrl->rpmbs));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_rpmbs_table(ctrl->rpmbs));

	stdout_kv_add(t, "edstt", "%d", le16_to_cpu(ctrl->edstt));

	row = stdout_kv_add(t, "dsto", "%d", ctrl->dsto);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_dsto_table(ctrl->dsto));

	stdout_kv_add(t, "fwug", "%d", ctrl->fwug);
	stdout_kv_add(t, "kas", "%d", le16_to_cpu(ctrl->kas));

	row = stdout_kv_add(t, "hctma", "%#x", le16_to_cpu(ctrl->hctma));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_hctma_table(ctrl->hctma));

	row = stdout_kv_add(t, "mntmt", "%d", le16_to_cpu(ctrl->mntmt));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_mntmt_table(ctrl->mntmt));

	row = stdout_kv_add(t, "mxtmt", "%d", le16_to_cpu(ctrl->mxtmt));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_mxtmt_table(ctrl->mxtmt));

	row = stdout_kv_add(t, "sanicap", "%#x", le32_to_cpu(ctrl->sanicap));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_sanicap_table(ctrl->sanicap));

	stdout_kv_add(t, "hmminds", "%u", le32_to_cpu(ctrl->hmminds));
	stdout_kv_add(t, "hmmaxd", "%d", le16_to_cpu(ctrl->hmmaxd));
	stdout_kv_add(t, "nsetidmax", "%d", le16_to_cpu(ctrl->nsetidmax));
	stdout_kv_add(t, "endgidmax", "%d", le16_to_cpu(ctrl->endgidmax));
	stdout_kv_add(t, "anatt", "%d", ctrl->anatt);

	row = stdout_kv_add(t, "anacap", "%d", ctrl->anacap);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_anacap_table(ctrl->anacap));

	stdout_kv_add(t, "anagrpmax", "%u", ctrl->anagrpmax);
	stdout_kv_add(t, "nanagrpid", "%u", le32_to_cpu(ctrl->nanagrpid));
	stdout_kv_add(t, "pels", "%u", le32_to_cpu(ctrl->pels));
	stdout_kv_add(t, "domainid", "%d", le16_to_cpu(ctrl->domainid));

	row = stdout_kv_add(t, "kpioc", "%u", ctrl->kpioc);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_kpioc_table(ctrl->kpioc));

	stdout_kv_add(t, "mptfawr", "%d", le16_to_cpu(ctrl->mptfawr));

	row = stdout_kv_add(t, "rmdca", "%#x", ctrl->rmdca);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_rmdca_table(ctrl->rmdca));

	stdout_kv_add(t, "megcap", "%s",
		      uint128_t_to_l10n_string(le128_to_cpu(ctrl->megcap)));

	row = stdout_kv_add(t, "tmpthha", "%#x", ctrl->tmpthha);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_tmpthha_table(ctrl->tmpthha));

	row = stdout_kv_add(t, "mupa", "%#x", ctrl->mupa);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_mupa_table(ctrl->mupa));

	stdout_kv_add(t, "cqt", "%d", le16_to_cpu(ctrl->cqt));

	row = stdout_kv_add(t, "cdpa", "%d", le16_to_cpu(ctrl->cdpa));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_cdpa_table(ctrl->cdpa));

	stdout_kv_add(t, "mup", "%d", le16_to_cpu(ctrl->mup));

	row = stdout_kv_add(t, "ipmsr", "%#x", le16_to_cpu(ctrl->ipmsr));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_ipmsr_table(ctrl->ipmsr));

	stdout_kv_add(t, "msmt", "%#x", le16_to_cpu(ctrl->msmt));
	stdout_kv_add(t, "mnens", "%u", le16_to_cpu(ctrl->mnens));
	stdout_kv_add(t, "mnecpens", "%u", le16_to_cpu(ctrl->mnecpens));
	stdout_kv_add(t, "mensnn", "%u", le32_to_cpu(ctrl->mensnn));

	row = stdout_kv_add(t, "ensa", "%#x", ctrl->ensa);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_ensa_table(ctrl->ensa));

	row = stdout_kv_add(t, "endsfs", "%#x", ctrl->endsfs);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_endsfs_table(ctrl->endsfs));

	if (NVME_CTRL_CTRATT_VMS(le32_to_cpu(ctrl->ctratt))) {
		row = stdout_kv_add(t, "vsen1", "%#x",
				    le32_to_cpu(ctrl->vsen1));
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ctrl_vsen_table(ctrl->vsen1));

		row = stdout_kv_add(t, "vsen2", "%#x",
				    le32_to_cpu(ctrl->vsen2));
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ctrl_vsen_table(ctrl->vsen2));

		row = stdout_kv_add(t, "vsen3", "%#x",
				    le32_to_cpu(ctrl->vsen3));
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ctrl_vsen_table(ctrl->vsen3));

		row = stdout_kv_add(t, "vsen4", "%#x",
				    le32_to_cpu(ctrl->vsen4));
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ctrl_vsen_table(ctrl->vsen4));

		stdout_kv_add(t, "msvmt", "%u", le16_to_cpu(ctrl->msvmt));
	}
}

static void stdout_id_ctrl_nvm_attr(struct nvme_id_ctrl *ctrl,
			       struct shr_table *t, bool verbose)
{
	int row;

	if (verbose)
		stdout_kv_add(t, "1971:512", "NVM Command Set Attributes");

	row = stdout_kv_add(t, "sqes", "%#x", ctrl->sqes);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_sqes_table(ctrl->sqes));

	row = stdout_kv_add(t, "cqes", "%#x", ctrl->cqes);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_cqes_table(ctrl->cqes));

	stdout_kv_add(t, "maxcmd", "%d", le16_to_cpu(ctrl->maxcmd));
	stdout_kv_add(t, "nn", "%u", le32_to_cpu(ctrl->nn));

	row = stdout_kv_add(t, "oncs", "%#x", le16_to_cpu(ctrl->oncs));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_oncs_table(ctrl->oncs));

	row = stdout_kv_add(t, "fuses", "%#x", le16_to_cpu(ctrl->fuses));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_fuses_table(ctrl->fuses));

	row = stdout_kv_add(t, "fna", "%#x", ctrl->fna);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_fna_table(ctrl->fna));

	row = stdout_kv_add(t, "vwc", "%#x", ctrl->vwc);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_vwc_table(ctrl->vwc));

	stdout_kv_add(t, "awun", "%d", le16_to_cpu(ctrl->awun));
	stdout_kv_add(t, "awupf", "%d", le16_to_cpu(ctrl->awupf));

	row = stdout_kv_add(t, "icsvscc", "%d", ctrl->icsvscc);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_icsvscc_table(ctrl->icsvscc));

	row = stdout_kv_add(t, "nwpc", "%d", ctrl->nwpc);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_nwpc_table(ctrl->nwpc));

	stdout_kv_add(t, "acwu", "%d", le16_to_cpu(ctrl->acwu));

	row = stdout_kv_add(t, "ocfs", "%#x", le16_to_cpu(ctrl->ocfs));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_ocfs_table(ctrl->ocfs));

	row = stdout_kv_add(t, "sgls", "%#x", le32_to_cpu(ctrl->sgls));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_sgls_table(ctrl->sgls));

	stdout_kv_add(t, "mnan", "%u", le32_to_cpu(ctrl->mnan));
	stdout_kv_add(t, "maxdna", "%s",
		      uint128_t_to_l10n_string(le128_to_cpu(ctrl->maxdna)));
	stdout_kv_add(t, "maxcna", "%u", le32_to_cpu(ctrl->maxcna));
	stdout_kv_add(t, "oaqd", "%u", le32_to_cpu(ctrl->oaqd));
	stdout_kv_add(t, "rhiri", "%d", ctrl->rhiri);
	stdout_kv_add(t, "hirt", "%d", ctrl->hirt);
	stdout_kv_add(t, "cmmrtd", "%d", le16_to_cpu(ctrl->cmmrtd));
	stdout_kv_add(t, "nmmrtd", "%d", le16_to_cpu(ctrl->nmmrtd));
	stdout_kv_add(t, "minmrtg", "%d", ctrl->minmrtg);
	stdout_kv_add(t, "maxmrtg", "%d", ctrl->maxmrtg);

	row = stdout_kv_add(t, "trattr", "%d", ctrl->trattr);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_trattr_table(ctrl->trattr));

	stdout_kv_add(t, "mcudmq", "%d", le16_to_cpu(ctrl->mcudmq));
	stdout_kv_add(t, "mnsudmq", "%d", le16_to_cpu(ctrl->mnsudmq));
	stdout_kv_add(t, "mcmr", "%d", le16_to_cpu(ctrl->mcmr));
	stdout_kv_add(t, "nmcmr", "%d", le16_to_cpu(ctrl->nmcmr));
	stdout_kv_add(t, "mcdqpc", "%d", le16_to_cpu(ctrl->mcdqpc));
	stdout_kv_add(t, "subnqn", "%-.*s",
		      (int)sizeof(ctrl->subnqn), ctrl->subnqn);
}

static void stdout_id_ctrl_fabric(struct nvme_id_ctrl *ctrl,
				  struct shr_table *t, bool verbose)
{
	int row;

	if (verbose)
		stdout_kv_add(t, "2047:1972", "Fabric Specific");

	stdout_kv_add(t, "ioccsz", "%u", le32_to_cpu(ctrl->ioccsz));
	stdout_kv_add(t, "iorcsz", "%u", le32_to_cpu(ctrl->iorcsz));
	stdout_kv_add(t, "icdoff", "%d", le16_to_cpu(ctrl->icdoff));

	row = stdout_kv_add(t, "fcatt", "%#x", ctrl->fcatt);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_fcatt_table(ctrl->fcatt));

	stdout_kv_add(t, "msdbd", "%d", ctrl->msdbd);

	row = stdout_kv_add(t, "ofcs", "%d", le16_to_cpu(ctrl->ofcs));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_ofcs_table(ctrl->ofcs));

	row = stdout_kv_add(t, "dctype", "%d", ctrl->dctype);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_dctype_table(ctrl->dctype));

	stdout_kv_add(t, "ccrl", "%d", ctrl->ccrl);
}

void stdout_id_ctrl(struct nvme_id_ctrl *ctrl, const char *product_name,
	void (*vendor_show)(__u8 *vs, struct json_object *root))
{
	bool verbose = stdout_print_ops.flags & VERBOSE;
	bool vs = stdout_print_ops.flags & VS;
	struct shr_table *t;
	int row;

	if (verbose && product_name)
		printf("%s\n\n", product_name);
	printf("NVME Identify Controller:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_id_ctrl_cap_feat(ctrl, t, verbose);
	stdout_id_ctrl_admin_option(ctrl, t, verbose);
	stdout_id_ctrl_nvm_attr(ctrl, t, verbose);
	stdout_id_ctrl_fabric(ctrl, t, verbose);

	if (verbose)
		stdout_kv_add(t, "3071:2048", "Power State Descriptors");

	row = stdout_kv_add(t, "ps", "%d states", ctrl->npss + 1);
	/* Unlike the fields above, shown regardless of @verbose. */
	shr_table_set_row_subtable(t, row, stdout_id_ctrl_ps_table(ctrl));

	stdout_kv_table_finish(t, "identify-controller");

	if (verbose)
		printf("4095:3072 : Vendor Specific\n");

	if (vendor_show)
		vendor_show(ctrl->vs, NULL);
	else if (vs) {
		printf("vs[]:\n");
		d(ctrl->vs, sizeof(ctrl->vs), 16, 1);
	}
}

static struct shr_table *stdout_id_ctrl_nvm_kpiocap_table(__u8 kpiocap)
{
	struct shr_table *t;
	__u8 rsvd2 = (kpiocap & 0xfc) >> 2;
	__u8 kpiosc = NVME_CTRL_KPIOC_KPIOSC(kpiocap);
	__u8 kpios = NVME_CTRL_KPIOC_KPIOS(kpiocap);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd2)
		stdout_bits_add(t, "[7:2]", rsvd2, "Reserved");
	stdout_bits_add(t, "[1:1]", kpiosc,
			 "Key Per I/O capability enabled and disabled %s in the NVM subsystem",
			 kpiosc ? "all namespaces" : "each namespace");
	stdout_bits_add(t, "[0:0]", kpios, "Key Per I/O capability %sSupported",
			 kpios ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_nvm_aocs_table(__u16 aocs)
{
	struct shr_table *t;
	__u16 rsvd = (aocs & 0xfffe) >> 1;
	__u8 ralbas = aocs & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", ralbas,
			 "Reporting Allocated LBA %sSupported",
			 ralbas ? "" : "Not ");

	return t;
}

static const char *stdout_id_ctrl_nvm_lbamqf_str(__u8 lbamqf)
{
	switch (lbamqf) {
	case NVME_ID_CTRL_NVM_LBAMQF_TYPE_0:
		return "LBA Migration Queue Entry Type 0";
	case NVME_ID_CTRL_NVM_LBAMQF_VENDOR_MIN ... NVME_ID_CTRL_NVM_LBAMQF_VENDOR_MAX:
		return "Vendor Specific";
	default:
		return "Reserved";
	}
}

void stdout_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm)
{
	bool verbose = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	__u32 ver;
	int row;

	printf("NVMe Identify Controller NVM:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "vsl", "%u", ctrl_nvm->vsl);
	stdout_kv_add(t, "wzsl", "%u", ctrl_nvm->wzsl);
	stdout_kv_add(t, "wusl", "%u", ctrl_nvm->wusl);
	stdout_kv_add(t, "dmrl", "%u", ctrl_nvm->dmrl);
	stdout_kv_add(t, "dmrsl", "%u", le32_to_cpu(ctrl_nvm->dmrsl));
	stdout_kv_add(t, "dmsl", "%"PRIu64, le64_to_cpu(ctrl_nvm->dmsl));

	row = stdout_kv_add(t, "kpiocap", "%u", ctrl_nvm->kpiocap);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_nvm_kpiocap_table(
						ctrl_nvm->kpiocap));

	stdout_kv_add(t, "wzdsl", "%u", ctrl_nvm->wzdsl);

	row = stdout_kv_add(t, "aocs", "%u", le16_to_cpu(ctrl_nvm->aocs));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_nvm_aocs_table(
						le16_to_cpu(ctrl_nvm->aocs)));

	ver = le32_to_cpu(ctrl_nvm->ver);
	if (verbose)
		stdout_kv_add(t, "ver",
			      "0x%x\tNVM command set specification: %d.%d.%d",
			      ver, NVME_MAJOR(ver), NVME_MINOR(ver),
			      NVME_TERTIARY(ver));
	else
		stdout_kv_add(t, "ver", "0x%x", ver);

	if (verbose)
		stdout_kv_add(t, "lbamqf", "%u\t0x%x: %s", ctrl_nvm->lbamqf,
			      ctrl_nvm->lbamqf,
			      stdout_id_ctrl_nvm_lbamqf_str(ctrl_nvm->lbamqf));
	else
		stdout_kv_add(t, "lbamqf", "%u", ctrl_nvm->lbamqf);

	stdout_kv_table_finish(t, "id-ctrl-nvm");
}

static struct shr_table *stdout_nvm_id_ns_pic_table(__u8 pic)
{
	struct shr_table *t;
	__u8 rsvd = (pic & 0xF0) >> 4;
	__u8 qpifs = (pic & 0x8) >> 3;
	__u8 stcrs = (pic & 0x4) >> 2;
	__u8 pic_16bpistm = (pic & 0x2) >> 1;
	__u8 pic_16bpists = pic & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:4]", rsvd, "Reserved");
	stdout_bits_add(t, "[3:3]", qpifs,
			 "Qualified Protection Information Format %sSupported",
			 qpifs ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", stcrs,
			 "Storage Tag Check Read %sSupported",
			 stcrs ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", pic_16bpistm,
			 "16b Guard Protection Information Storage Tag Mask");
	stdout_bits_add(t, "[0:0]", pic_16bpists,
			 "16b Guard Protection Information Storage Tag %sSupported",
			 pic_16bpists ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_nvm_id_ns_pifa_table(__u8 pifa)
{
	struct shr_table *t;
	__u8 rsvd = (pifa & 0xF8) >> 3;
	__u8 stmla = pifa & 0x7;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:3]", rsvd, "Reserved");
	stdout_bits_add(t, "[2:0]", stmla,
			 "Storage Tag Masking Level Attribute : %s",
			 stmla == 0 ? "Bit Granularity Masking" :
			 stmla == 1 ? "Byte Granularity Masking" :
			 stmla == 2 ? "Masking Not Supported" : "Reserved");

	return t;
}

static char *pif_to_string(__u8 pif, bool qpifs, bool pif_field)
{
	switch (pif) {
	case NVME_NVM_PIF_16B_GUARD:
		return "16b Guard";
	case NVME_NVM_PIF_32B_GUARD:
		return "32b Guard";
	case NVME_NVM_PIF_64B_GUARD:
		return "64b Guard";
	case NVME_NVM_PIF_QTYPE:
		if (pif_field && qpifs)
			return "Qualified Type";
	default:
		return "Reserved";
	}
}

void stdout_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
		      struct nvme_id_ns *ns, unsigned int lba_index,
		      bool cap_only)
{
	bool verbose = stdout_print_ops.flags & VERBOSE;
	bool qpifs = (nvm_ns->pic & 0x8) >> 3;
	struct shr_table *t;
	__u32 elbaf;
	__u8 lbaf;
	int pif, sts, qpif;
	char *in_use = "(in use)";
	int i, row;

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &lbaf);

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (!cap_only) {
		printf("NVMe NVM Identify Namespace %d:\n", nsid);
		stdout_kv_add(t, "lbstm", "%#"PRIx64,
			      le64_to_cpu(nvm_ns->lbstm));
	} else {
		printf("NVMe NVM Identify Namespace for LBA format[%d]:\n",
		       lba_index);
		in_use = "";
	}

	row = stdout_kv_add(t, "pic", "%#x", nvm_ns->pic);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_nvm_id_ns_pic_table(nvm_ns->pic));

	row = stdout_kv_add(t, "pifa", "%#x", nvm_ns->pifa);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_nvm_id_ns_pifa_table(nvm_ns->pifa));

	stdout_kv_table_finish(t, "nvm-id-ns");

	for (i = 0; i <= ns->nlbaf + ns->nulbaf; i++) {
		elbaf = le32_to_cpu(nvm_ns->elbaf[i]);
		qpif = (elbaf >> 9) & 0xF;
		pif = (elbaf >> 7) & 0x3;
		sts = elbaf & 0x7f;
		if (verbose)
			printf("Extended LBA Format %2d : Qualified Protection "
				"Information Format: %s(%d) - Protection "
				"Information Format: %s(%d) - Storage Tag Size "
				"(MSB): %-2d %s\n", i,
				pif_to_string(qpif, qpifs, false), qpif,
				pif_to_string(pif, qpifs, true), pif, sts,
				i == lbaf ? in_use : "");
		else
			printf("elbaf %2d : qpif:%d pif:%d sts:%-2d %s\n", i,
				qpif, pif, sts, i == lbaf ? in_use : "");
	}

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (ns->nsfeat & 0x20)
		stdout_kv_add(t, "npdgl", "%#x", le32_to_cpu(nvm_ns->npdgl));

	stdout_kv_add(t, "nprg", "%#x", le32_to_cpu(nvm_ns->nprg));
	stdout_kv_add(t, "npra", "%#x", le32_to_cpu(nvm_ns->npra));
	stdout_kv_add(t, "nors", "%#x", le32_to_cpu(nvm_ns->nors));
	stdout_kv_add(t, "npdal", "%#x", le32_to_cpu(nvm_ns->npdal));
	stdout_kv_add(t, "lbapss", "%#x", le32_to_cpu(nvm_ns->lbapss));
	stdout_kv_add(t, "tlbaag", "%#x", le32_to_cpu(nvm_ns->tlbaag));

	stdout_kv_table_finish(t, "nvm-id-ns");
}

void stdout_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl)
{
	struct shr_table *t;

	printf("NVMe ZNS Identify Controller:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "zasl", "%u", ctrl->zasl);

	stdout_kv_table_finish(t, "zns-id-ctrl");
}

static struct shr_table *show_nvme_id_ns_zoned_zoc_table(__le16 ns_zoc)
{
	struct shr_table *t;
	__u16 zoc = le16_to_cpu(ns_zoc);
	__u8 rsvd = (zoc & 0xfffc) >> 2;
	__u8 ze = (zoc & 0x2) >> 1;
	__u8 vzc = zoc & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", ze, "Zone Active Excursions: %s",
			 ze ? "Yes (Host support required)" : "No");
	stdout_bits_add(t, "[0:0]", vzc, "Variable Zone Capacity: %s",
			 vzc ? "Yes (Host support required)" : "No");

	return t;
}

static struct shr_table *show_nvme_id_ns_zoned_ozcs_table(__le16 ns_ozcs)
{
	struct shr_table *t;
	__u16 ozcs = le16_to_cpu(ns_ozcs);
	__u8 rsvd = (ozcs & 0xfffc) >> 2;
	__u8 razb = ozcs & 0x1;
	__u8 zrwasup = (ozcs & 0x2) >> 1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", razb, "Read Across Zone Boundaries: %s",
			 razb ? "Yes" : "No");
	stdout_bits_add(t, "[1:1]", zrwasup, "Zone Random Write Area: %s",
			 zrwasup ? "Yes" : "No");

	return t;
}

static void stdout_zns_id_ns_recommended_limit(struct shr_table *t,
		const char *name, __le32 ns_rl, bool verbose)
{
	unsigned int recommended_limit = le32_to_cpu(ns_rl);

	if (!recommended_limit && verbose)
		stdout_kv_add(t, name, "%s", "Not Reported");
	else
		stdout_kv_add(t, name, "%u", recommended_limit);
}

static struct shr_table *stdout_zns_id_ns_zrwacap_table(__u8 zrwacap)
{
	struct shr_table *t;
	__u8 rsvd = (zrwacap & 0xfe) >> 1;
	__u8 expflushsup = zrwacap & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", expflushsup,
			 "Explicit ZRWA Flush Operations: %s",
			 expflushsup ? "Yes" : "No");

	return t;
}

void stdout_zns_id_ns(struct nvme_zns_id_ns *ns,
		      struct nvme_id_ns *id_ns)
{
	bool verbose = stdout_print_ops.flags & VERBOSE;
	bool vs = stdout_print_ops.flags & VS;
	struct shr_table *t;
	uint8_t lbaf;
	int i, row;

	nvme_id_ns_flbas_to_lbaf_inuse(id_ns->flbas, &lbaf);

	printf("ZNS Command Set Identify Namespace:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (verbose) {
		row = stdout_kv_add(t, "zoc",
				     "%u\tZone Operation Characteristics",
				     le16_to_cpu(ns->zoc));
		shr_table_set_row_subtable(t, row,
				show_nvme_id_ns_zoned_zoc_table(ns->zoc));
	} else {
		stdout_kv_add(t, "zoc", "%u", le16_to_cpu(ns->zoc));
	}

	if (verbose) {
		row = stdout_kv_add(t, "ozcs",
				     "%u\tOptional Zoned Command Support",
				     le16_to_cpu(ns->ozcs));
		shr_table_set_row_subtable(t, row,
				show_nvme_id_ns_zoned_ozcs_table(ns->ozcs));
	} else {
		stdout_kv_add(t, "ozcs", "%u", le16_to_cpu(ns->ozcs));
	}

	if (verbose) {
		if (ns->mar == 0xffffffff)
			stdout_kv_add(t, "mar", "%s",
				      "No Active Resource Limit");
		else
			stdout_kv_add(t, "mar", "%u\tActive Resources",
				      le32_to_cpu(ns->mar) + 1);
	} else {
		stdout_kv_add(t, "mar", "%#x", le32_to_cpu(ns->mar));
	}

	if (verbose) {
		if (ns->mor == 0xffffffff)
			stdout_kv_add(t, "mor", "%s",
				      "No Open Resource Limit");
		else
			stdout_kv_add(t, "mor", "%u\tOpen Resources",
				      le32_to_cpu(ns->mor) + 1);
	} else {
		stdout_kv_add(t, "mor", "%#x", le32_to_cpu(ns->mor));
	}

	stdout_zns_id_ns_recommended_limit(t, "rrl", ns->rrl, verbose);
	stdout_zns_id_ns_recommended_limit(t, "frl", ns->frl, verbose);
	stdout_zns_id_ns_recommended_limit(t, "rrl1", ns->rrl1, verbose);
	stdout_zns_id_ns_recommended_limit(t, "rrl2", ns->rrl2, verbose);
	stdout_zns_id_ns_recommended_limit(t, "rrl3", ns->rrl3, verbose);
	stdout_zns_id_ns_recommended_limit(t, "frl1", ns->frl1, verbose);
	stdout_zns_id_ns_recommended_limit(t, "frl2", ns->frl2, verbose);
	stdout_zns_id_ns_recommended_limit(t, "frl3", ns->frl3, verbose);

	stdout_kv_add(t, "numzrwa", "%#x", le32_to_cpu(ns->numzrwa));
	stdout_kv_add(t, "zrwafg", "%u", le16_to_cpu(ns->zrwafg));
	stdout_kv_add(t, "zrwasz", "%u", le16_to_cpu(ns->zrwasz));

	if (verbose) {
		row = stdout_kv_add(t, "zrwacap",
				     "%u\tZone Random Write Area Capability",
				     ns->zrwacap);
		shr_table_set_row_subtable(t, row,
				stdout_zns_id_ns_zrwacap_table(ns->zrwacap));
	} else {
		stdout_kv_add(t, "zrwacap", "%u", ns->zrwacap);
	}

	stdout_kv_table_finish(t, "zns-id-ns");

	for (i = 0; i <= id_ns->nlbaf; i++) {
		if (verbose)
			printf("LBA Format Extension %2d : Zone Size: %#"PRIx64
			       " LBAs - Zone Descriptor Extension Size: %-1d "
			       "bytes%s\n", i, le64_to_cpu(ns->lbafe[i].zsze),
			       ns->lbafe[i].zdes << 6,
			       i == lbaf ? " (in use)" : "");
		else
			printf("lbafe %2d: zsze:%#"PRIx64" zdes:%u%s\n", i,
			       (uint64_t)le64_to_cpu(ns->lbafe[i].zsze),
			       ns->lbafe[i].zdes, i == lbaf ? " (in use)" : "");
	}

	if (vs) {
		printf("vs[]    :\n");
		d(ns->vs, sizeof(ns->vs), 16, 1);
	}
}

void stdout_id_nvmset(struct nvme_id_nvmset_list *nvmset,
		      unsigned int nvmset_id)
{
	struct shr_table *t;
	int i;

	printf("NVME Identify NVM Set List %d:\n", nvmset_id);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "nid", "%d", nvmset->nid);

	stdout_kv_table_finish(t, "id-nvmset");

	printf(".................\n");
	for (i = 0; i < nvmset->nid; i++) {
		printf(" NVM Set Attribute Entry[%2d]\n", i);
		printf(".................\n");

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "nvmset_id", "%d",
			      le16_to_cpu(nvmset->ent[i].nvmsetid));
		stdout_kv_add(t, "endurance_group_id", "%d",
			      le16_to_cpu(nvmset->ent[i].endgid));
		stdout_kv_add(t, "random_4k_read_typical", "%u",
			      le32_to_cpu(nvmset->ent[i].rr4kt));
		stdout_kv_add(t, "optimal_write_size", "%u",
			      le32_to_cpu(nvmset->ent[i].ows));
		stdout_kv_add(t, "total_nvmset_cap", "%s",
			      uint128_t_to_l10n_string(le128_to_cpu(
					nvmset->ent[i].tnvmsetcap)));
		stdout_kv_add(t, "unalloc_nvmset_cap", "%s",
			      uint128_t_to_l10n_string(le128_to_cpu(
					nvmset->ent[i].unvmsetcap)));

		stdout_kv_table_finish(t, "nvm-set-attribute");

		printf(".................\n");
	}
}

void stdout_id_ns_granularity_list(
	const struct nvme_id_ns_granularity_list *glist)
{
	struct shr_table *t;
	int i;

	printf("Identify Namespace Granularity List:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Namespace Granularity Attributes (ATTR)",
		      "%#x", glist->attributes);
	stdout_kv_add(t, "Number of Descriptors (NUMD)",
		      "%d", glist->num_descriptors);

	stdout_kv_table_finish(t, "id-ns-granularity-list");

	/* Number of Descriptors is a 0's based value */
	for (i = 0; i <= glist->num_descriptors; i++) {
		printf("\n     Entry[%2d] :\n", i);
		printf("................\n");

		t = stdout_kv_table_create();
		if (!t)
			return;

		shr_table_set_indent(t, 2);

		stdout_kv_add(t, "Namespace Size Granularity (NSG)",
			      "%#"PRIx64,
			      le64_to_cpu(glist->entry[i].nszegran));
		stdout_kv_add(t, "Namespace Capacity Granularity (NCG)",
			      "%#"PRIx64,
			      le64_to_cpu(glist->entry[i].ncapgran));

		stdout_kv_table_finish(t, "id-ns-granularity-list");
	}
}

void stdout_id_uuid_list(const struct nvme_id_uuid_list *uuid_list)
{
	bool verbose = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	int i;

	printf("NVME Identify UUID:\n");

	for (i = 0; i < NVME_ID_UUID_LIST_MAX; i++) {
		__u8 uuid[NVME_UUID_LEN];
		char *association = "";
		uint8_t identifier_association =
		    uuid_list->entry[i].header & 0x3;

		/* The list is terminated by a zero UUID value */
		if (!memcmp(uuid_list->entry[i].uuid, zero_uuid, NVME_UUID_LEN))
			break;
		memcpy(&uuid, uuid_list->entry[i].uuid, NVME_UUID_LEN);
		if (verbose) {
			switch (identifier_association) {
			case 0x0:
				association = "No association reported";
				break;
			case 0x1:
				association = "associated with PCI Vendor ID";
				break;
			case 0x2:
				association =
				    "associated with PCI Subsystem Vendor ID";
				break;
			default:
				association = "Reserved";
				break;
			}
		}

		printf(" Entry[%3d]\n", i + 1);
		printf(".................\n");

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "association", "%#x %s",
			      identifier_association, association);

		if (memcmp(uuid_list->entry[i].uuid, invalid_uuid,
			   sizeof(zero_uuid)) == 0)
			stdout_kv_add(t, "UUID", "%s (Invalid UUID)",
				      shr_uuid_to_string(uuid));
		else
			stdout_kv_add(t, "UUID", "%s",
				      shr_uuid_to_string(uuid));

		stdout_kv_table_finish(t, "id-uuid-list");

		printf(".................\n");
	}
}

void stdout_id_domain_list(struct nvme_id_domain_list *id_dom)
{
	struct shr_table *t;
	int i;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Number of Domain Entries", "%u", id_dom->num);

	for (i = 0; i < id_dom->num; i++) {
		struct nvme_id_domain_attr *attr = &id_dom->domain_attr[i];
		char name[64];

		snprintf(name, sizeof(name), "Domain Id for Attr Entry[%u]", i);
		stdout_kv_add(t, name, "%u", le16_to_cpu(attr->dom_id));

		snprintf(name, sizeof(name),
			 "Domain Capacity for Attr Entry[%u]", i);
		stdout_kv_add(t, name, "%s", uint128_t_to_l10n_string(
			      le128_to_cpu(attr->dom_cap)));

		snprintf(name, sizeof(name),
			 "Unallocated Domain Capacity for Attr Entry[%u]", i);
		stdout_kv_add(t, name, "%s", uint128_t_to_l10n_string(
			      le128_to_cpu(attr->unalloc_dom_cap)));

		snprintf(name, sizeof(name),
			 "Max Endurance Group Domain Capacity for Attr Entry[%u]",
			 i);
		stdout_kv_add(t, name, "%s", uint128_t_to_l10n_string(
			      le128_to_cpu(attr->max_egrp_dom_cap)));
	}

	stdout_kv_table_finish(t, "id-domain-list");
}

static struct shr_table *stdout_id_iocs_iocsc_table(__u64 iocsc)
{
	struct shr_table *t;
	__u8 cpncs = NVME_GET(iocsc, IOCS_IOCSC_CPNCS);
	__u8 slmcs = NVME_GET(iocsc, IOCS_IOCSC_SLMCS);
	__u8 znscs = NVME_GET(iocsc, IOCS_IOCSC_ZNSCS);
	__u8 kvcs = NVME_GET(iocsc, IOCS_IOCSC_KVCS);
	__u8 nvmcs = NVME_GET(iocsc, IOCS_IOCSC_NVMCS);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[4:4]", cpncs,
			"Computational Programs Namespace Command Set %sSelected",
			cpncs ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", slmcs,
			"Subsystem Local Memory Command Set %sSelected",
			slmcs ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", znscs,
			"Zoned Namespace Command Set %sSelected",
			znscs ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", kvcs, "Key Value Command Set %sSelected",
			kvcs ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", nvmcs, "NVM Command Set %sSelected",
			nvmcs ? "" : "Not ");

	return t;
}

void stdout_id_iocs(struct nvme_id_iocs *iocs)
{
	bool verbose = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	int row;
	__u16 i;

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (i = 0; i < ARRAY_SIZE(iocs->iocsc); i++) {
		char name[48];
		__u64 iocsc;

		if (!iocs->iocsc[i])
			continue;

		iocsc = le64_to_cpu(iocs->iocsc[i]);
		snprintf(name, sizeof(name), "I/O Command Set Combination[%u]",
			 i);
		row = stdout_kv_add(t, name, "%"PRIx64, iocsc);
		if (verbose)
			shr_table_set_row_subtable(t, row,
				stdout_id_iocs_iocsc_table(iocsc));
	}

	stdout_kv_table_finish(t, "id-iocs");
}
