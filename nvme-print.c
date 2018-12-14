#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "nvme-print.h"
#include "json.h"
#include "nvme-models.h"
#include "suffix.h"

static const char *nvme_ana_state_to_string(enum nvme_ana_state state)
{
	switch (state) {
	case NVME_ANA_OPTIMIZED:
		return "optimized";
	case NVME_ANA_NONOPTIMIZED:
		return "non-optimized";
	case NVME_ANA_INACCESSIBLE:
		return "inaccessible";
	case NVME_ANA_PERSISTENT_LOSS:
		return "persistent-loss";
	case NVME_ANA_CHANGE:
		return "change";
	}
	return "invalid state";
}

static long double int128_to_double(__u8 *data)
{
	int i;
	long double result = 0;

	for (i = 0; i < 16; i++) {
		result *= 256;
		result += data[15 - i];
	}
	return result;
}

void d(unsigned char *buf, int len, int width, int group)
{
	int i, offset = 0, line_done = 0;
	char ascii[width + 1];

	printf("     ");
	for (i = 0; i <= 15; i++)
		printf("%3x", i);
	for (i = 0; i < len; i++) {
		line_done = 0;
		if (i % width == 0)
			printf( "\n%04x:", offset);
		if (i % group == 0)
			printf( " %02x", buf[i]);
		else
			printf( "%02x", buf[i]);
		ascii[i % width] = (buf[i] >= '!' && buf[i] <= '~') ? buf[i] : '.';
		if (((i + 1) % width) == 0) {
			ascii[i % width + 1] = '\0';
			printf( " \"%.*s\"", width, ascii);
			offset += width;
			line_done = 1;
		}
	}
	if (!line_done) {
		unsigned b = width - (i % width);
		ascii[i % width + 1] = '\0';
		printf( " %*s \"%.*s\"",
				2 * b + b / group + (b % group ? 1 : 0), "",
				width, ascii);
	}
	printf( "\n");
}

void d_raw(unsigned char *buf, unsigned len)
{
	unsigned i;
	for (i = 0; i < len; i++)
		putchar(*(buf+i));
}

static void format(char *formatter, size_t fmt_sz, char *tofmt, size_t tofmtsz)
{

	fmt_sz = snprintf(formatter,fmt_sz, "%-*.*s",
		 (int)tofmtsz, (int)tofmtsz, tofmt);
	/* trim() the obnoxious trailing white lines */
	while (fmt_sz) {
		if (formatter[fmt_sz - 1] != ' ' && formatter[fmt_sz - 1] != '\0') {
			formatter[fmt_sz] = '\0';
			break;
		}
		fmt_sz--;
	}
}

static void show_nvme_id_ctrl_cmic(__u8 cmic)
{
	__u8 rsvd = (cmic & 0xF0) >> 4;
	__u8 ana = (cmic & 0x8) >> 3;
	__u8 sriov = (cmic & 0x4) >> 2;
	__u8 mctl = (cmic & 0x2) >> 1;
	__u8 mp = cmic & 0x1;
	if (rsvd)
		printf("  [7:4] : %#x\tReserved\n", rsvd);
	printf("  [3:3] : %#x\tANA %ssupported\n", ana, ana ? "" : "not ");
	printf("  [2:2] : %#x\t%s\n", sriov, sriov ? "SR-IOV" : "PCI");
	printf("  [1:1] : %#x\t%s Controller\n",
		mctl, mctl ? "Multi" : "Single");
	printf("  [0:0] : %#x\t%s Port\n", mp, mp ? "Multi" : "Single");
	printf("\n");
}

static void show_nvme_id_ctrl_oaes(__le32 ctrl_oaes)
{
	__u32 oaes = le32_to_cpu(ctrl_oaes);
	__u32 rsvd0 = (oaes & 0xFFFFFC00) >> 10;
	__u32 nace = (oaes & 0x100) >> 8;
	__u32 fan = (oaes & 0x200) >> 9;
	__u32 rsvd1 = oaes & 0xFF;

	if (rsvd0)
		printf(" [31:10] : %#x\tReserved\n", rsvd0);
	printf("  [9:9] : %#x\tFirmware Activation Notices %sSupported\n",
		fan, fan ? "" : "Not ");
	printf("  [8:8] : %#x\tNamespace Attribute Changed Event %sSupported\n",
		nace, nace ? "" : "Not ");
	if (rsvd1)
		printf("  [7:0] : %#x\tReserved\n", rsvd1);
	printf("\n");
}

static void show_nvme_id_ctrl_ctratt(__le32 ctrl_ctratt)
{
	__u32 ctratt = le32_to_cpu(ctrl_ctratt);
	__u32 rsvd0 = ctratt >> 6;
	__u32 hostid128 = ctratt & NVME_CTRL_CTRATT_128_ID >> 0;
	__u32 psp = ctratt & NVME_CTRL_CTRATT_NON_OP_PSP >> 1;
	__u32 sets = ctratt & NVME_CTRL_CTRATT_NVM_SETS >> 2;
	__u32 rrl = ctratt & NVME_CTRL_CTRATT_READ_RECV_LVLS >> 3;
	__u32 eg = ctratt & NVME_CTRL_CTRATT_ENDURANCE_GROUPS >> 4;
	__u32 iod = ctratt & NVME_CTRL_CTRATT_PREDICTABLE_LAT >> 5;

	if (rsvd0)
		printf(" [31:6] : %#x\tReserved\n", rsvd0);
	printf("  [5:5] : %#x\tPredictable Latency Mode %sSupported\n",
		iod, iod ? "" : "Not ");
	printf("  [4:4] : %#x\tEndurance Groups %sSupported\n",
		eg, eg ? "" : "Not ");
	printf("  [3:3] : %#x\tRead Recovery Levels %sSupported\n",
		rrl, rrl ? "" : "Not ");
	printf("  [2:2] : %#x\tNVM Sets %sSupported\n",
		sets, sets ? "" : "Not ");
	printf("  [1:1] : %#x\tNon-Operational Power State Permissive %sSupported\n",
		psp, psp ? "" : "Not ");
	printf("  [0:0] : %#x\t128-bit Host Identifier %sSupported\n",
		hostid128, hostid128 ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_oacs(__le16 ctrl_oacs)
{
	__u16 oacs = le16_to_cpu(ctrl_oacs);
	__u16 rsvd = (oacs & 0xFE00) >> 9;
	__u16 dbc = (oacs & 0x100) >> 8;
	__u16 vir = (oacs & 0x80) >> 7;
	__u16 nmi = (oacs & 0x40) >> 6;
	__u16 dir = (oacs & 0x20) >> 5;
	__u16 sft = (oacs & 0x10) >> 4;
	__u16 nsm = (oacs & 0x8) >> 3;
	__u16 fwc = (oacs & 0x4) >> 2;
	__u16 fmt = (oacs & 0x2) >> 1;
	__u16 sec = oacs & 0x1;

	if (rsvd)
		printf(" [15:9] : %#x\tReserved\n", rsvd);
	printf("  [8:8] : %#x\tDoorbell Buffer Config %sSupported\n",
		dbc, dbc ? "" : "Not ");
	printf("  [7:7] : %#x\tVirtualization Management %sSupported\n",
		vir, vir ? "" : "Not ");
	printf("  [6:6] : %#x\tNVMe-MI Send and Receive %sSupported\n",
		nmi, nmi ? "" : "Not ");
	printf("  [5:5] : %#x\tDirectives %sSupported\n",
		dir, dir ? "" : "Not ");
	printf("  [4:4] : %#x\tDevice Self-test %sSupported\n",
		sft, sft ? "" : "Not ");
	printf("  [3:3] : %#x\tNS Management and Attachment %sSupported\n",
		nsm, nsm ? "" : "Not ");
	printf("  [2:2] : %#x\tFW Commit and Download %sSupported\n",
		fwc, fwc ? "" : "Not ");
	printf("  [1:1] : %#x\tFormat NVM %sSupported\n",
		fmt, fmt ? "" : "Not ");
	printf("  [0:0] : %#x\tSecurity Send and Receive %sSupported\n",
		sec, sec ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_frmw(__u8 frmw)
{
	__u8 rsvd = (frmw & 0xE0) >> 5;
	__u8 fawr = (frmw & 0x10) >> 4;
	__u8 nfws = (frmw & 0xE) >> 1;
	__u8 s1ro = frmw & 0x1;
	if (rsvd)
		printf("  [7:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tFirmware Activate Without Reset %sSupported\n",
		fawr, fawr ? "" : "Not ");
	printf("  [3:1] : %#x\tNumber of Firmware Slots\n", nfws);
	printf("  [0:0] : %#x\tFirmware Slot 1 Read%s\n",
		s1ro, s1ro ? "-Only" : "/Write");
	printf("\n");
}

static void show_nvme_id_ctrl_lpa(__u8 lpa)
{
	__u8 rsvd = (lpa & 0xF0) >> 4;
	__u8 telem = (lpa & 0x8) >> 3;
	__u8 ed = (lpa & 0x4) >> 2;
	__u8 celp = (lpa & 0x2) >> 1;
	__u8 smlp = lpa & 0x1;
	if (rsvd)
		printf("  [7:4] : %#x\tReserved\n", rsvd);
	printf("  [3:3] : %#x\tTelemetry host/controller initiated log page %sSuporrted\n",
	       telem, telem ? "" : "Not ");
	printf("  [2:2] : %#x\tExtended data for Get Log Page %sSupported\n",
		ed, ed ? "" : "Not ");
	printf("  [1:1] : %#x\tCommand Effects Log Page %sSupported\n",
		celp, celp ? "" : "Not ");
	printf("  [0:0] : %#x\tSMART/Health Log Page per NS %sSupported\n",
		smlp, smlp ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_avscc(__u8 avscc)
{
	__u8 rsvd = (avscc & 0xFE) >> 1;
	__u8 fmt = avscc & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tAdmin Vendor Specific Commands uses %s Format\n",
		fmt, fmt ? "NVMe" : "Vendor Specific");
	printf("\n");
}

static void show_nvme_id_ctrl_apsta(__u8 apsta)
{
	__u8 rsvd = (apsta & 0xFE) >> 1;
	__u8 apst = apsta & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tAutonomous Power State Transitions %sSupported\n",
		apst, apst ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_rpmbs(__le32 ctrl_rpmbs)
{
	__u32 rpmbs = le32_to_cpu(ctrl_rpmbs);
	__u32 asz = (rpmbs & 0xFF000000) >> 24;
	__u32 tsz = (rpmbs & 0xFF0000) >> 16;
	__u32 rsvd = (rpmbs & 0xFFC0) >> 6;
	__u32 auth = (rpmbs & 0x38) >> 3;
	__u32 rpmb = rpmbs & 0x7;

	printf(" [31:24]: %#x\tAccess Size\n", asz);
	printf(" [23:16]: %#x\tTotal Size\n", tsz);
	if (rsvd)
		printf(" [15:6] : %#x\tReserved\n", rsvd);
	printf("  [5:3] : %#x\tAuthentication Method\n", auth);
	printf("  [2:0] : %#x\tNumber of RPMB Units\n", rpmb);
	printf("\n");
}

static void show_nvme_id_ctrl_hctma(__le16 ctrl_hctma)
{
	__u16 hctma = le16_to_cpu(ctrl_hctma);
	__u16 rsvd = (hctma & 0xFFFE) >> 1;
	__u16 hctm = hctma & 0x1;

	if (rsvd)
		printf(" [15:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tHost Controlled Thermal Management %sSupported\n",
		hctm, hctm ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_sanicap(__le32 ctrl_sanicap)
{
	__u32 sanicap = le32_to_cpu(ctrl_sanicap);
	__u32 rsvd = (sanicap & 0xFFFFFFF8) >> 3;
	__u32 owr = (sanicap & 0x4) >> 2;
	__u32 ber = (sanicap & 0x2) >> 1;
	__u32 cer = sanicap & 0x1;

	if (rsvd)
		printf(" [31:3] : %#x\tReserved\n", rsvd);
	printf("  [2:2] : %#x\tOverwrite Sanitize Operation %sSupported\n",
		owr, owr ? "" : "Not ");
	printf("  [1:1] : %#x\tBlock Erase Sanitize Operation %sSupported\n",
		ber, ber ? "" : "Not ");
	printf("  [0:0] : %#x\tCrypto Erase Sanitize Operation %sSupported\n",
		cer, cer ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_anacap(__u8 anacap)
{
	__u8 nz = (anacap & 0x80) >> 7;
	__u8 grpid_change = (anacap & 0x40) >> 6;
	__u8 rsvd = (anacap & 0x20) >> 5;
	__u8 ana_change = (anacap & 0x10) >> 4;
	__u8 ana_persist_loss = (anacap & 0x08) >> 3;
	__u8 ana_inaccessible = (anacap & 0x04) >> 2;
	__u8 ana_nonopt = (anacap & 0x02) >> 1;
	__u8 ana_opt = (anacap & 0x01);

	printf("  [7:7] : %#x\tNon-zero group ID %sSupported\n",
			nz, nz ? "" : "Not ");
	printf("  [6:6] : %#x\tGroup ID does %schange\n",
			grpid_change, grpid_change ? "" : "not ");
	if (rsvd)
		printf(" [5:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tANA Change state %sSupported\n",
			ana_change, ana_change ? "" : "Not ");
	printf("  [3:3] : %#x\tANA Persistent Loss state %sSupported\n",
			ana_persist_loss, ana_persist_loss ? "" : "Not ");
	printf("  [2:2] : %#x\tANA Inaccessible state %sSupported\n",
			ana_inaccessible, ana_inaccessible ? "" : "Not ");
	printf("  [1:1] : %#x\tANA Non-optimized state %sSupported\n",
			ana_nonopt, ana_nonopt ? "" : "Not ");
	printf("  [0:0] : %#x\tANA Optimized state %sSupported\n",
			ana_opt, ana_opt ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_sqes(__u8 sqes)
{
	__u8 msqes = (sqes & 0xF0) >> 4;
	__u8 rsqes = sqes & 0xF;
	printf("  [7:4] : %#x\tMax SQ Entry Size (%d)\n", msqes, 1 << msqes);
	printf("  [3:0] : %#x\tMin SQ Entry Size (%d)\n", rsqes, 1 << rsqes);
	printf("\n");
}

static void show_nvme_id_ctrl_cqes(__u8 cqes)
{
	__u8 mcqes = (cqes & 0xF0) >> 4;
	__u8 rcqes = cqes & 0xF;
	printf("  [7:4] : %#x\tMax CQ Entry Size (%d)\n", mcqes, 1 << mcqes);
	printf("  [3:0] : %#x\tMin CQ Entry Size (%d)\n", rcqes, 1 << rcqes);
	printf("\n");
}

static void show_nvme_id_ctrl_oncs(__le16 ctrl_oncs)
{
	__u16 oncs = le16_to_cpu(ctrl_oncs);
	__u16 rsvd = (oncs & 0xFF80) >> 7;
	__u16 tmst = (oncs & 0x40) >> 6;
	__u16 resv = (oncs & 0x20) >> 5;
	__u16 save = (oncs & 0x10) >> 4;
	__u16 wzro = (oncs & 0x8) >> 3;
	__u16 dsms = (oncs & 0x4) >> 2;
	__u16 wunc = (oncs & 0x2) >> 1;
	__u16 cmp = oncs & 0x1;

	if (rsvd)
		printf(" [15:6] : %#x\tReserved\n", rsvd);
	printf("  [6:6] : %#x\tTimestamp %sSupported\n",
		tmst, tmst ? "" : "Not ");
	printf("  [5:5] : %#x\tReservations %sSupported\n",
		resv, resv ? "" : "Not ");
	printf("  [4:4] : %#x\tSave and Select %sSupported\n",
		save, save ? "" : "Not ");
	printf("  [3:3] : %#x\tWrite Zeroes %sSupported\n",
		wzro, wzro ? "" : "Not ");
	printf("  [2:2] : %#x\tData Set Management %sSupported\n",
		dsms, dsms ? "" : "Not ");
	printf("  [1:1] : %#x\tWrite Uncorrectable %sSupported\n",
		wunc, wunc ? "" : "Not ");
	printf("  [0:0] : %#x\tCompare %sSupported\n",
		cmp, cmp ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_fuses(__le16 ctrl_fuses)
{
	__u16 fuses = le16_to_cpu(ctrl_fuses);
	__u16 rsvd = (fuses & 0xFE) >> 1;
	__u16 cmpw = fuses & 0x1;

	if (rsvd)
		printf(" [15:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tFused Compare and Write %sSupported\n",
		cmpw, cmpw ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_fna(__u8 fna)
{
	__u8 rsvd = (fna & 0xF8) >> 3;
	__u8 cese = (fna & 0x4) >> 2;
	__u8 cens = (fna & 0x2) >> 1;
	__u8 fmns = fna & 0x1;
	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);
	printf("  [2:2] : %#x\tCrypto Erase %sSupported as part of Secure Erase\n",
		cese, cese ? "" : "Not ");
	printf("  [1:1] : %#x\tCrypto Erase Applies to %s Namespace(s)\n",
		cens, cens ? "All" : "Single");
	printf("  [0:0] : %#x\tFormat Applies to %s Namespace(s)\n",
		fmns, fmns ? "All" : "Single");
	printf("\n");
}

static void show_nvme_id_ctrl_vwc(__u8 vwc)
{
	__u8 rsvd = (vwc & 0xFE) >> 1;
	__u8 vwcp = vwc & 0x1;
	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tVolatile Write Cache %sPresent\n",
		vwcp, vwcp ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_nvscc(__u8 nvscc)
{
	__u8 rsvd = (nvscc & 0xFE) >> 1;
	__u8 fmt = nvscc & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tNVM Vendor Specific Commands uses %s Format\n",
		fmt, fmt ? "NVMe" : "Vendor Specific");
	printf("\n");
}

static void show_nvme_id_ctrl_nwpc(__u8 nwpc)
{
	__u8 no_wp_wp = (nwpc & 0x01);
	__u8 wp_power_cycle = (nwpc & 0x02) >> 1;
	__u8 wp_permanent = (nwpc & 0x04) >> 2;
	__u8 rsvd = (nwpc & 0xF8) >> 3;

	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);

	printf("  [2:2] : %#x\tPermanent Write Protect %sSupported\n",
		wp_permanent, wp_permanent ? "" : "Not ");
	printf("  [1:1] : %#x\tWrite Protect Until Power Supply %sSupported\n",
		wp_power_cycle, wp_power_cycle ? "" : "Not ");
	printf("  [0:0] : %#x\tNo Write Protect and Write Protect Namespace %sSupported\n",
		no_wp_wp, no_wp_wp ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ctrl_sgls(__le32 ctrl_sgls)
{
	__u32 sgls = le32_to_cpu(ctrl_sgls);
	__u32 rsvd0 = (sgls & 0xFF700000) >> 21;
	__u32 aofdsl = (sgls & 0x100000) >> 20;
	__u32 mpcsd = (sgls & 0x80000) >> 19;
	__u32 sglltb = (sgls & 0x40000) >> 18;
	__u32 bacmdb = (sgls & 0x20000) >> 17;
	__u32 bbs = (sgls & 0x10000) >> 16;
	__u32 rsvd1 = (sgls & 0xFFF8) >> 3;
	__u32 key = (sgls & 0x4) >> 2;
	__u32 sglsp = sgls & 0x3;

	if (rsvd0)
		printf(" [31:21]: %#x\tReserved\n", rsvd0);
	if (sglsp || (!sglsp && aofdsl))
		printf(" [20:20]: %#x\tAddress Offsets %sSupported\n",
			aofdsl, aofdsl ? "" : "Not ");
	if (sglsp || (!sglsp && mpcsd))
		printf(" [19:19]: %#x\tMetadata Pointer Containing "
			"SGL Descriptor is %sSupported\n",
			mpcsd, mpcsd ? "" : "Not ");
	if (sglsp || (!sglsp && sglltb))
		printf(" [18:18]: %#x\tSGL Length Larger than Buffer %sSupported\n",
			sglltb, sglltb ? "" : "Not ");
	if (sglsp || (!sglsp && bacmdb))
		printf(" [17:17]: %#x\tByte-Aligned Contig. MD Buffer %sSupported\n",
			bacmdb, bacmdb ? "" : "Not ");
	if (sglsp || (!sglsp && bbs))
		printf(" [16:16]: %#x\tSGL Bit-Bucket %sSupported\n",
			bbs, bbs ? "" : "Not ");
	if (rsvd1)
		printf(" [15:3] : %#x\tReserved\n", rsvd1);
	if (sglsp || (!sglsp && key))
		printf("  [2:2] : %#x\tKeyed SGL Data Block descriptor %sSupported\n",
			key, key ? "" : "Not ");
	if (sglsp == 0x3)
		printf("  [1:0] : %#x\tReserved\n", sglsp);
	else if (sglsp == 0x2)
		printf("  [1:0] : %#x\tScatter-Gather Lists Supported."
			" Dword alignment required.\n", sglsp);
	else if (sglsp == 0x1)
		printf("  [1:0] : %#x\tScatter-Gather Lists Supported."
			" No Dword alignment required.\n", sglsp);
	else
		printf(" [1:0]  : %#x\tScatter-Gather Lists Not Supported\n", sglsp);
	printf("\n");
}

static void show_nvme_id_ctrl_ctrattr(__u8 ctrattr)
{
	__u8 rsvd = (ctrattr & 0xFE) >> 1;
	__u8 scm = ctrattr & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\t%s Controller Model\n",
		scm, scm ? "Static" : "Dynamic");
	printf("\n");
}

static void show_nvme_id_ns_nsfeat(__u8 nsfeat)
{
	__u8 rsvd = (nsfeat & 0xF8) >> 3;
	__u8 dulbe = (nsfeat & 0x4) >> 2;
	__u8 na = (nsfeat & 0x2) >> 1;
	__u8 thin = nsfeat & 0x1;
	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);
	printf("  [2:2] : %#x\tDeallocated or Unwritten Logical Block error %sSupported\n",
		dulbe, dulbe ? "" : "Not ");
	printf("  [1:1] : %#x\tNamespace uses %s\n",
		na, na ? "NAWUN, NAWUPF, and NACWU" : "AWUN, AWUPF, and ACWU");
	printf("  [0:0] : %#x\tThin Provisioning %sSupported\n",
		thin, thin ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ns_flbas(__u8 flbas)
{
	__u8 rsvd = (flbas & 0xE0) >> 5;
	__u8 mdedata = (flbas & 0x10) >> 4;
	__u8 lbaf = flbas & 0xF;
	if (rsvd)
		printf("  [7:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tMetadata Transferred %s\n",
		mdedata, mdedata ? "at End of Data LBA" : "in Separate Contiguous Buffer");
	printf("  [3:0] : %#x\tCurrent LBA Format Selected\n", lbaf);
	printf("\n");
}

static void show_nvme_id_ns_mc(__u8 mc)
{
	__u8 rsvd = (mc & 0xFC) >> 2;
	__u8 mdp = (mc & 0x2) >> 1;
	__u8 extdlba = mc & 0x1;
	if (rsvd)
		printf("  [7:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] : %#x\tMetadata Pointer %sSupported\n",
		mdp, mdp ? "" : "Not ");
	printf("  [0:0] : %#x\tMetadata as Part of Extended Data LBA %sSupported\n",
		extdlba, extdlba ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ns_dpc(__u8 dpc)
{
	__u8 rsvd = (dpc & 0xE0) >> 5;
	__u8 pil8 = (dpc & 0x10) >> 4;
	__u8 pif8 = (dpc & 0x8) >> 3;
	__u8 pit3 = (dpc & 0x4) >> 2;
	__u8 pit2 = (dpc & 0x2) >> 1;
	__u8 pit1 = dpc & 0x1;
	if (rsvd)
		printf("  [7:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tProtection Information Transferred as Last 8 Bytes of Metadata %sSupported\n",
		pil8, pil8 ? "" : "Not ");
	printf("  [3:3] : %#x\tProtection Information Transferred as First 8 Bytes of Metadata %sSupported\n",
		pif8, pif8 ? "" : "Not ");
	printf("  [2:2] : %#x\tProtection Information Type 3 %sSupported\n",
		pit3, pit3 ? "" : "Not ");
	printf("  [1:1] : %#x\tProtection Information Type 2 %sSupported\n",
		pit2, pit2 ? "" : "Not ");
	printf("  [0:0] : %#x\tProtection Information Type 1 %sSupported\n",
		pit1, pit1 ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ns_dps(__u8 dps)
{
	__u8 rsvd = (dps & 0xF0) >> 4;
	__u8 pif8 = (dps & 0x8) >> 3;
	__u8 pit = dps & 0x7;
	if (rsvd)
		printf("  [7:4] : %#x\tReserved\n", rsvd);
	printf("  [3:3] : %#x\tProtection Information is Transferred as %s 8 Bytes of Metadata\n",
		pif8, pif8 ? "First" : "Last");
	printf("  [2:0] : %#x\tProtection Information %s\n", pit,
		pit == 3 ? "Type 3 Enabled" :
		pit == 2 ? "Type 2 Enabled" :
		pit == 1 ? "Type 1 Enabled" :
		pit == 0 ? "Disabled" : "Reserved Enabled");
	printf("\n");
}

static void show_nvme_id_ns_nmic(__u8 nmic)
{
	__u8 rsvd = (nmic & 0xFE) >> 1;
	__u8 mp = nmic & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tNamespace Multipath %sCapable\n",
		mp, mp ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ns_rescap(__u8 rescap)
{
	__u8 rsvd = (rescap & 0x80) >> 7;
	__u8 eaar = (rescap & 0x40) >> 6;
	__u8 wear = (rescap & 0x20) >> 5;
	__u8 earo = (rescap & 0x10) >> 4;
	__u8 wero = (rescap & 0x8) >> 3;
	__u8 ea = (rescap & 0x4) >> 2;
	__u8 we = (rescap & 0x2) >> 1;
	__u8 ptpl = rescap & 0x1;
	if (rsvd)
		printf("  [7:7] : %#x\tReserved\n", rsvd);
	printf("  [6:6] : %#x\tExclusive Access - All Registrants %sSupported\n",
		eaar, eaar ? "" : "Not ");
	printf("  [5:5] : %#x\tWrite Exclusive - All Registrants %sSupported\n",
		wear, wear ? "" : "Not ");
	printf("  [4:4] : %#x\tExclusive Access - Registrants Only %sSupported\n",
		earo, earo ? "" : "Not ");
	printf("  [3:3] : %#x\tWrite Exclusive - Registrants Only %sSupported\n",
		wero, wero ? "" : "Not ");
	printf("  [2:2] : %#x\tExclusive Access %sSupported\n",
		ea, ea ? "" : "Not ");
	printf("  [1:1] : %#x\tWrite Exclusive %sSupported\n",
		we, we ? "" : "Not ");
	printf("  [0:0] : %#x\tPersist Through Power Loss %sSupported\n",
		ptpl, ptpl ? "" : "Not ");
	printf("\n");
}

static void show_nvme_id_ns_fpi(__u8 fpi)
{
	__u8 fpis = (fpi & 0x80) >> 7;
	__u8 fpii = fpi & 0x7F;
	printf("  [7:7] : %#x\tFormat Progress Indicator %sSupported\n",
		fpis, fpis ? "" : "Not ");
	if (fpis || (!fpis && fpii))
		printf("  [6:0] : %#x\tFormat Progress Indicator (Remaining %d%%)\n",
		fpii, fpii);
	printf("\n");
}

static void show_nvme_id_ns_dlfeat(__u8 dlfeat)
{
	__u8 rsvd = (dlfeat & 0xE0) >> 5;
	__u8 guard = (dlfeat & 0x10) >> 4;
	__u8 dwz = (dlfeat & 0x8) >> 3;
	__u8 val = dlfeat & 0x7;
	if (rsvd)
		printf("  [7:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tGuard Field of Deallocated Logical Blocks is set to %s\n",
		guard, guard ? "CRC of The Value Read" : "0xFFFF");
	printf("  [3:3] : %#x\tDeallocate Bit in the Write Zeroes Command is %sSupported\n",
		dwz, dwz ? "" : "Not ");
	printf("  [2:0] : %#x\tBytes Read From a Deallocated Logical Block and its Metadata are %s\n", val,
		val == 2 ? "0xFF" :
		val == 1 ? "0x00" :
		val == 0 ? "Not Reported" : "Reserved Value");
	printf("\n");
}

void show_nvme_id_ns(struct nvme_id_ns *ns, unsigned int mode)
{
	int i;
	int human = mode & HUMAN,
		vs = mode & VS;

	printf("nsze    : %#"PRIx64"\n", (uint64_t)le64_to_cpu(ns->nsze));
	printf("ncap    : %#"PRIx64"\n", (uint64_t)le64_to_cpu(ns->ncap));
	printf("nuse    : %#"PRIx64"\n", (uint64_t)le64_to_cpu(ns->nuse));
	printf("nsfeat  : %#x\n", ns->nsfeat);
	if (human)
		show_nvme_id_ns_nsfeat(ns->nsfeat);
	printf("nlbaf   : %d\n", ns->nlbaf);
	printf("flbas   : %#x\n", ns->flbas);
	if (human)
		show_nvme_id_ns_flbas(ns->flbas);
	printf("mc      : %#x\n", ns->mc);
	if (human)
		show_nvme_id_ns_mc(ns->mc);
	printf("dpc     : %#x\n", ns->dpc);
	if (human)
		show_nvme_id_ns_dpc(ns->dpc);
	printf("dps     : %#x\n", ns->dps);
	if (human)
		show_nvme_id_ns_dps(ns->dps);
	printf("nmic    : %#x\n", ns->nmic);
	if (human)
		show_nvme_id_ns_nmic(ns->nmic);
	printf("rescap  : %#x\n", ns->rescap);
	if (human)
		show_nvme_id_ns_rescap(ns->rescap);
	printf("fpi     : %#x\n", ns->fpi);
	if (human)
		show_nvme_id_ns_fpi(ns->fpi);
	printf("dlfeat  : %d\n", le16_to_cpu(ns->dlfeat));
	if (human)
		show_nvme_id_ns_dlfeat(ns->dlfeat);
	printf("nawun   : %d\n", le16_to_cpu(ns->nawun));
	printf("nawupf  : %d\n", le16_to_cpu(ns->nawupf));
	printf("nacwu   : %d\n", le16_to_cpu(ns->nacwu));
	printf("nabsn   : %d\n", le16_to_cpu(ns->nabsn));
	printf("nabo    : %d\n", le16_to_cpu(ns->nabo));
	printf("nabspf  : %d\n", le16_to_cpu(ns->nabspf));
	printf("noiob   : %d\n", le16_to_cpu(ns->noiob));
	printf("nvmcap  : %.0Lf\n", int128_to_double(ns->nvmcap));
	printf("nsattr	: %u\n", ns->nsattr);
	printf("nvmsetid: %d\n", le16_to_cpu(ns->nvmsetid));
	printf("anagrpid: %u\n", le32_to_cpu(ns->anagrpid));
	printf("endgid  : %d\n", le16_to_cpu(ns->endgid));

	printf("nguid   : ");
	for (i = 0; i < 16; i++)
		printf("%02x", ns->nguid[i]);
	printf("\n");

	printf("eui64   : ");
	for (i = 0; i < 8; i++)
		printf("%02x", ns->eui64[i]);
	printf("\n");

	for (i = 0; i <= ns->nlbaf; i++) {
		if (human)
			printf("LBA Format %2d : Metadata Size: %-3d bytes - "
				"Data Size: %-2d bytes - Relative Performance: %#x %s %s\n", i,
				le16_to_cpu(ns->lbaf[i].ms), 1 << ns->lbaf[i].ds, ns->lbaf[i].rp,
				ns->lbaf[i].rp == 3 ? "Degraded" :
				ns->lbaf[i].rp == 2 ? "Good" :
				ns->lbaf[i].rp == 1 ? "Better" : "Best",
				i == (ns->flbas & 0xf) ? "(in use)" : "");
		else
			printf("lbaf %2d : ms:%-3d lbads:%-2d rp:%#x %s\n", i,
				le16_to_cpu(ns->lbaf[i].ms), ns->lbaf[i].ds, ns->lbaf[i].rp,
				i == (ns->flbas & 0xf) ? "(in use)" : "");
	}
	if (vs) {
		printf("vs[]:\n");
		d(ns->vs, sizeof(ns->vs), 16, 1);
	}
}


void json_nvme_id_ns_descs(void *data)
{
	/* large enough to hold uuid str (37) or nguid str (32) + zero byte */
	char json_str[40];
	char *json_str_p;

	union {
		__u8 eui64[NVME_NIDT_EUI64_LEN];
		__u8 nguid[NVME_NIDT_NGUID_LEN];

#ifdef LIBUUID
		uuid_t uuid;
#endif
	} desc;

	struct json_object *root;
	struct json_array *json_array = NULL;

	off_t off;
	int pos, len = 0;
	int i;

	for (pos = 0; pos < NVME_IDENTIFY_DATA_SIZE; pos += len) {
		struct nvme_ns_id_desc *cur = data + pos;
		const char *nidt_name = NULL;

		if (cur->nidl == 0)
			break;

		memset(json_str, 0, sizeof(json_str));
		json_str_p = json_str;
		off = pos + sizeof(*cur);

		switch (cur->nidt) {
		case NVME_NIDT_EUI64:
			memcpy(desc.eui64, data + off, sizeof(desc.eui64));
			for (i = 0; i < sizeof(desc.eui64); i++)
				json_str_p += sprintf(json_str_p, "%02x", desc.eui64[i]);
			len += sizeof(desc.eui64);
			nidt_name = "eui64";
			break;

		case NVME_NIDT_NGUID:
			memcpy(desc.nguid, data + off, sizeof(desc.nguid));
			for (i = 0; i < sizeof(desc.nguid); i++)
				json_str_p += sprintf(json_str_p, "%02x", desc.nguid[i]);
			len += sizeof(desc.nguid);
			nidt_name = "nguid";
			break;

#ifdef LIBUUID
		case NVME_NIDT_UUID:
			memcpy(desc.uuid, data + off, sizeof(desc.uuid));
			uuid_unparse_lower(desc.uuid, json_str);
			len += sizeof(desc.uuid);
			nidt_name = "uuid";
			break;
#endif
		default:
			/* Skip unnkown types */
			len = cur->nidl;
			break;
		}

		if (nidt_name) {
			struct json_object *elem = json_create_object();

			json_object_add_value_int(elem, "loc", pos);
			json_object_add_value_int(elem, "nidt", (int)cur->nidt);
			json_object_add_value_int(elem, "nidl", (int)cur->nidl);
			json_object_add_value_string(elem, "type", nidt_name);
			json_object_add_value_string(elem, nidt_name, json_str);

			if (!json_array) {
				json_array = json_create_array();
			}
			json_array_add_value_object(json_array, elem);
		}

		len += sizeof(*cur);
	}

	root = json_create_object();

	if (json_array)
		json_object_add_value_array(root, "ns-descs", json_array);

	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
}

void show_nvme_id_ns_descs(void *data)
{
	int pos, len = 0;
	int i;
#ifdef LIBUUID
	uuid_t uuid;
	char uuid_str[37];
#endif
	__u8 eui64[8];
	__u8 nguid[16];

	for (pos = 0; pos < NVME_IDENTIFY_DATA_SIZE; pos += len) {
		struct nvme_ns_id_desc *cur = data + pos;

		if (cur->nidl == 0)
			break;

		switch (cur->nidt) {
		case NVME_NIDT_EUI64:
			memcpy(eui64, data + pos + sizeof(*cur), sizeof(eui64));
			printf("eui64   : ");
			for (i = 0; i < 8; i++)
				printf("%02x", eui64[i]);
			printf("\n");
			len += sizeof(eui64);
			break;
		case NVME_NIDT_NGUID:
			memcpy(nguid, data + pos + sizeof(*cur), sizeof(nguid));
			printf("nguid   : ");
			for (i = 0; i < 16; i++)
				printf("%02x", nguid[i]);
			printf("\n");
			len += sizeof(nguid);
			break;
#ifdef LIBUUID
		case NVME_NIDT_UUID:
			memcpy(uuid, data + pos + sizeof(*cur), 16);
			uuid_unparse_lower(uuid, uuid_str);
			printf("uuid    : %s\n", uuid_str);
			len += sizeof(uuid);
			break;
#endif
		default:
			/* Skip unnkown types */
			len = cur->nidl;
			break;
		}

		len += sizeof(*cur);
	}
}

static void print_ps_power_and_scale(__le16 ctr_power, __u8 scale)
{
	__u16 power = le16_to_cpu(ctr_power);

	switch (scale & 0x3) {
	case 0:
		/* Not reported for this power state */
		printf("-");
		break;

	case 1:
		/* Units of 0.0001W */
		printf("%01u.%04uW", power / 10000, power % 10000);
		break;

	case 2:
		/* Units of 0.01W */
		printf("%01u.%02uW", power / 100, scale % 100);
		break;

	default:
		printf("reserved");
	}
}

static void show_nvme_id_ctrl_power(struct nvme_id_ctrl *ctrl)
{
	int i;


	for (i = 0; i <= ctrl->npss; i++) {
		__u16 max_power = le16_to_cpu(ctrl->psd[i].max_power);

		printf("ps %4d : mp:", i);

		if (ctrl->psd[i].flags & NVME_PS_FLAGS_MAX_POWER_SCALE)
			printf("%01u.%04uW ", max_power / 10000, max_power % 10000);
		else
			printf("%01u.%02uW ", max_power / 100, max_power % 100);

		if (ctrl->psd[i].flags & NVME_PS_FLAGS_NON_OP_STATE)
			printf("non-");

		printf("operational enlat:%d exlat:%d rrt:%d rrl:%d\n"
			"          rwt:%d rwl:%d idle_power:",
			le32_to_cpu(ctrl->psd[i].entry_lat), le32_to_cpu(ctrl->psd[i].exit_lat),
			ctrl->psd[i].read_tput, ctrl->psd[i].read_lat,
			ctrl->psd[i].write_tput, ctrl->psd[i].write_lat);
		print_ps_power_and_scale(ctrl->psd[i].idle_power,
					 POWER_SCALE(ctrl->psd[i].idle_scale));
		printf(" active_power:");
		print_ps_power_and_scale(ctrl->psd[i].active_power,
					 POWER_SCALE(ctrl->psd[i].active_work_scale));
		printf("\n");

	}
}

void __show_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode, void (*vendor_show)(__u8 *vs, struct json_object *root))
{
	int human = mode & HUMAN, vs = mode & VS;

	printf("vid       : %#x\n", le16_to_cpu(ctrl->vid));
	printf("ssvid     : %#x\n", le16_to_cpu(ctrl->ssvid));
	printf("sn        : %-.*s\n", (int)sizeof(ctrl->sn), ctrl->sn);
	printf("mn        : %-.*s\n", (int)sizeof(ctrl->mn), ctrl->mn);
	printf("fr        : %-.*s\n", (int)sizeof(ctrl->fr), ctrl->fr);
	printf("rab       : %d\n", ctrl->rab);
	printf("ieee      : %02x%02x%02x\n",
		ctrl->ieee[2], ctrl->ieee[1], ctrl->ieee[0]);
	printf("cmic      : %#x\n", ctrl->cmic);
	if (human)
		show_nvme_id_ctrl_cmic(ctrl->cmic);
	printf("mdts      : %d\n", ctrl->mdts);
	printf("cntlid    : %x\n", le16_to_cpu(ctrl->cntlid));
	printf("ver       : %x\n", le32_to_cpu(ctrl->ver));
	printf("rtd3r     : %x\n", le32_to_cpu(ctrl->rtd3r));
	printf("rtd3e     : %x\n", le32_to_cpu(ctrl->rtd3e));
	printf("oaes      : %#x\n", le32_to_cpu(ctrl->oaes));
	if (human)
		show_nvme_id_ctrl_oaes(ctrl->oaes);
	printf("ctratt    : %#x\n", le32_to_cpu(ctrl->ctratt));
	if (human)
		show_nvme_id_ctrl_ctratt(ctrl->ctratt);
	printf("rrls      : %#x\n", le16_to_cpu(ctrl->rrls));
	printf("oacs      : %#x\n", le16_to_cpu(ctrl->oacs));
	if (human)
		show_nvme_id_ctrl_oacs(ctrl->oacs);
	printf("acl       : %d\n", ctrl->acl);
	printf("aerl      : %d\n", ctrl->aerl);
	printf("frmw      : %#x\n", ctrl->frmw);
	if (human)
		show_nvme_id_ctrl_frmw(ctrl->frmw);
	printf("lpa       : %#x\n", ctrl->lpa);
	if (human)
		show_nvme_id_ctrl_lpa(ctrl->lpa);
	printf("elpe      : %d\n", ctrl->elpe);
	printf("npss      : %d\n", ctrl->npss);
	printf("avscc     : %#x\n", ctrl->avscc);
	if (human)
		show_nvme_id_ctrl_avscc(ctrl->avscc);
	printf("apsta     : %#x\n", ctrl->apsta);
	if (human)
		show_nvme_id_ctrl_apsta(ctrl->apsta);
	printf("wctemp    : %d\n", le16_to_cpu(ctrl->wctemp));
	printf("cctemp    : %d\n", le16_to_cpu(ctrl->cctemp));
	printf("mtfa      : %d\n", le16_to_cpu(ctrl->mtfa));
	printf("hmpre     : %d\n", le32_to_cpu(ctrl->hmpre));
	printf("hmmin     : %d\n", le32_to_cpu(ctrl->hmmin));
	printf("tnvmcap   : %.0Lf\n", int128_to_double(ctrl->tnvmcap));
	printf("unvmcap   : %.0Lf\n", int128_to_double(ctrl->unvmcap));
	printf("rpmbs     : %#x\n", le32_to_cpu(ctrl->rpmbs));
	if (human)
		show_nvme_id_ctrl_rpmbs(ctrl->rpmbs);
	printf("edstt     : %d\n", le16_to_cpu(ctrl->edstt));
	printf("dsto      : %d\n", ctrl->dsto);
	printf("fwug      : %d\n", ctrl->fwug);
	printf("kas       : %d\n", le16_to_cpu(ctrl->kas));
	printf("hctma     : %#x\n", le16_to_cpu(ctrl->hctma));
	if (human)
		show_nvme_id_ctrl_hctma(ctrl->hctma);
	printf("mntmt     : %d\n", le16_to_cpu(ctrl->mntmt));
	printf("mxtmt     : %d\n", le16_to_cpu(ctrl->mxtmt));
	printf("sanicap   : %#x\n", le32_to_cpu(ctrl->sanicap));
	if (human)
		show_nvme_id_ctrl_sanicap(ctrl->sanicap);
	printf("hmminds   : %d\n", le32_to_cpu(ctrl->hmminds));
	printf("hmmaxd    : %d\n", le16_to_cpu(ctrl->hmmaxd));
	printf("nsetidmax : %d\n", le16_to_cpu(ctrl->nsetidmax));
	printf("anatt     : %d\n", ctrl->anatt);
	printf("anacap    : %d\n", ctrl->anacap);
	if (human)
		show_nvme_id_ctrl_anacap(ctrl->anacap);
	printf("anagrpmax : %d\n", ctrl->anagrpmax);
	printf("nanagrpid : %d\n", le32_to_cpu(ctrl->nanagrpid));
	printf("sqes      : %#x\n", ctrl->sqes);
	if (human)
		show_nvme_id_ctrl_sqes(ctrl->sqes);
	printf("cqes      : %#x\n", ctrl->cqes);
	if (human)
		show_nvme_id_ctrl_cqes(ctrl->cqes);
	printf("maxcmd    : %d\n", le16_to_cpu(ctrl->maxcmd));
	printf("nn        : %d\n", le32_to_cpu(ctrl->nn));
	printf("oncs      : %#x\n", le16_to_cpu(ctrl->oncs));
	if (human)
		show_nvme_id_ctrl_oncs(ctrl->oncs);
	printf("fuses     : %#x\n", le16_to_cpu(ctrl->fuses));
	if (human)
		show_nvme_id_ctrl_fuses(ctrl->fuses);
	printf("fna       : %#x\n", ctrl->fna);
	if (human)
		show_nvme_id_ctrl_fna(ctrl->fna);
	printf("vwc       : %#x\n", ctrl->vwc);
	if (human)
		show_nvme_id_ctrl_vwc(ctrl->vwc);
	printf("awun      : %d\n", le16_to_cpu(ctrl->awun));
	printf("awupf     : %d\n", le16_to_cpu(ctrl->awupf));
	printf("nvscc     : %d\n", ctrl->nvscc);
	if (human)
		show_nvme_id_ctrl_nvscc(ctrl->nvscc);
	printf("nwpc      : %d\n", ctrl->nwpc);
	if (human)
		show_nvme_id_ctrl_nwpc(ctrl->nwpc);
	printf("acwu      : %d\n", le16_to_cpu(ctrl->acwu));
	printf("sgls      : %x\n", le32_to_cpu(ctrl->sgls));
	if (human)
		show_nvme_id_ctrl_sgls(ctrl->sgls);
	printf("mnan      : %d\n", le32_to_cpu(ctrl->mnan));
	printf("subnqn    : %-.*s\n", (int)sizeof(ctrl->subnqn), ctrl->subnqn);
	printf("ioccsz    : %d\n", le32_to_cpu(ctrl->ioccsz));
	printf("iorcsz    : %d\n", le32_to_cpu(ctrl->iorcsz));
	printf("icdoff    : %d\n", le16_to_cpu(ctrl->icdoff));
	printf("ctrattr   : %x\n", ctrl->ctrattr);
	if (human)
		show_nvme_id_ctrl_ctrattr(ctrl->ctrattr);
	printf("msdbd     : %d\n", ctrl->msdbd);

	show_nvme_id_ctrl_power(ctrl);
	if (vendor_show)
		vendor_show(ctrl->vs, NULL);
	else if (vs) {
		printf("vs[]:\n");
		d(ctrl->vs, sizeof(ctrl->vs), 16, 1);
	}
}

void show_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode)
{
	__show_nvme_id_ctrl(ctrl, mode, NULL);
}

void show_nvme_id_nvmset(struct nvme_id_nvmset *nvmset)
{
	int i;

	printf("nid     : %d\n", nvmset->nid);
	printf(".................\n");
	for (i = 0; i < nvmset->nid; i++) {
		printf(" NVM Set Attribute Entry[%2d]\n", i);
		printf(".................\n");
		printf("nvmset_id               : %d\n",
				le16_to_cpu(nvmset->ent[i].id));
		printf("enduracne_group_id      : %d\n",
				le16_to_cpu(nvmset->ent[i].endurance_group_id));
		printf("random_4k_read_typical  : %u\n",
				le32_to_cpu(nvmset->ent[i].random_4k_read_typical));
		printf("optimal_write_size      : %u\n",
				le32_to_cpu(nvmset->ent[i].opt_write_size));
		printf("total_nvmset_cap        : %.0Lf\n",
				int128_to_double(nvmset->ent[i].total_nvmset_cap));
		printf("unalloc_nvmset_cap      : %.0Lf\n",
				int128_to_double(nvmset->ent[i].unalloc_nvmset_cap));
		printf(".................\n");
	}
}

void json_nvme_id_nvmset(struct nvme_id_nvmset *nvmset, const char *devname)
{
	struct json_object *root;
	struct json_array *entries;
	__u32 nent = le32_to_cpu(nvmset->nid);
	int i;

	root = json_create_object();

	json_object_add_value_int(root, "nid", nent);

	entries = json_create_array();
	for (i = 0; i < nent; i++) {
		struct json_object *entry = json_create_object();

		json_object_add_value_int(entry, "nvmset_id", le16_to_cpu(nvmset->ent[i].id));
		json_object_add_value_int(entry, "endurance_group_id", le16_to_cpu(nvmset->ent[i].endurance_group_id));
		json_object_add_value_int(entry, "random_4k_read_typical", le32_to_cpu(nvmset->ent[i].random_4k_read_typical));
		json_object_add_value_int(entry, "optimal_write_size", le32_to_cpu(nvmset->ent[i].opt_write_size));
		json_object_add_value_float(entry, "total_nvmset_cap", int128_to_double(nvmset->ent[i].total_nvmset_cap));
		json_object_add_value_float(entry, "unalloc_nvmset_cap", int128_to_double(nvmset->ent[i].unalloc_nvmset_cap));

		json_array_add_value_object(entries, entry);
	}

	json_object_add_value_array(root, "NVMSet", entries);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void show_error_log(struct nvme_error_log_page *err_log, int entries, const char *devname)
{
	int i;

	printf("Error Log Entries for device:%s entries:%d\n", devname,
								entries);
	printf(".................\n");
	for (i = 0; i < entries; i++) {
		printf(" Entry[%2d]   \n", i);
		printf(".................\n");
		printf("error_count  : %"PRIu64"\n", (uint64_t)le64_to_cpu(err_log[i].error_count));
		printf("sqid         : %d\n", err_log[i].sqid);
		printf("cmdid        : %#x\n", err_log[i].cmdid);
		printf("status_field : %#x(%s)\n", err_log[i].status_field,
			nvme_status_to_string(err_log[i].status_field >> 1));
		printf("parm_err_loc : %#x\n", err_log[i].parm_error_location);
		printf("lba          : %#"PRIx64"\n",(uint64_t)le64_to_cpu(err_log[i].lba));
		printf("nsid         : %#x\n", err_log[i].nsid);
		printf("vs           : %d\n", err_log[i].vs);
		printf("cs           : %#"PRIx64"\n", (uint64_t) err_log[i].cs);
		printf(".................\n");
	}
}

void show_nvme_resv_report(struct nvme_reservation_status *status, int bytes, __u32 cdw11)
{
	int i, j, regctl, entries;

	regctl = status->regctl[0] | (status->regctl[1] << 8);

	printf("\nNVME Reservation status:\n\n");
	printf("gen       : %d\n", le32_to_cpu(status->gen));
	printf("rtype     : %d\n", status->rtype);
	printf("regctl    : %d\n", regctl);
	printf("ptpls     : %d\n", status->ptpls);

	/* check Extended Data Structure bit */
	if ((cdw11 & 0x1) == 0) {
		/* if status buffer was too small, don't loop past the end of the buffer */
		entries = (bytes - 24) / 24;
		if (entries < regctl)
			regctl = entries;

		for (i = 0; i < regctl; i++) {
			printf("regctl[%d] :\n", i);
			printf("  cntlid  : %x\n", le16_to_cpu(status->regctl_ds[i].cntlid));
			printf("  rcsts   : %x\n", status->regctl_ds[i].rcsts);
			printf("  hostid  : %"PRIx64"\n", (uint64_t)le64_to_cpu(status->regctl_ds[i].hostid));
			printf("  rkey    : %"PRIx64"\n", (uint64_t)le64_to_cpu(status->regctl_ds[i].rkey));
		}
	} else {
		struct nvme_reservation_status_ext *ext_status = (struct nvme_reservation_status_ext *)status;
		/* if status buffer was too small, don't loop past the end of the buffer */
		entries = (bytes - 64) / 64;
		if (entries < regctl)
			regctl = entries;

		for (i = 0; i < regctl; i++) {
			printf("regctlext[%d] :\n", i);
			printf("  cntlid     : %x\n", le16_to_cpu(ext_status->regctl_eds[i].cntlid));
			printf("  rcsts      : %x\n", ext_status->regctl_eds[i].rcsts);
			printf("  rkey       : %"PRIx64"\n", (uint64_t)le64_to_cpu(ext_status->regctl_eds[i].rkey));
			printf("  hostid     : ");
			for (j = 0; j < 16; j++)
				printf("%x", ext_status->regctl_eds[i].hostid[j]);
			printf("\n");
		}
	}
	printf("\n");
}

static char *fw_to_string(__u64 fw)
{
	static char ret[9];
	char *c = (char *)&fw;
	int i;

	for (i = 0; i < 8; i++)
		ret[i] = c[i] >= '!' && c[i] <= '~' ? c[i] : '.';
	ret[i] = '\0';
	return ret;
}

void show_fw_log(struct nvme_firmware_log_page *fw_log, const char *devname)
{
	int i;

	printf("Firmware Log for device:%s\n", devname);
	printf("afi  : %#x\n", fw_log->afi);
	for (i = 0; i < 7; i++)
		if (fw_log->frs[i])
			printf("frs%d : %#016"PRIx64" (%s)\n", i + 1, (uint64_t)fw_log->frs[i],
						fw_to_string(fw_log->frs[i]));
}

void show_changed_ns_list_log(struct nvme_changed_ns_list_log *log, const char *devname)
{
	int i;
	__u32 nsid;

	if (log->log[0] != cpu_to_le32(0XFFFFFFFF)) {
		for (i = 0; i < NVME_MAX_CHANGED_NAMESPACES; i++) {
			nsid = le32_to_cpu(log->log[i]);
			if (nsid == 0)
				break;

			printf("[%4u]:%#x\n", i, nsid);
		}
	} else
		printf("more than %d ns changed\n", NVME_MAX_CHANGED_NAMESPACES);
}

static void show_effects_log_human(__u32 effect)
{
	const char *set = "+";
	const char *clr = "-";

	printf("  CSUPP+");
	printf("  LBCC%s", (effect & NVME_CMD_EFFECTS_LBCC) ? set : clr);
	printf("  NCC%s", (effect & NVME_CMD_EFFECTS_NCC) ? set : clr);
	printf("  NIC%s", (effect & NVME_CMD_EFFECTS_NIC) ? set : clr);
	printf("  CCC%s", (effect & NVME_CMD_EFFECTS_CCC) ? set : clr);

	if ((effect & NVME_CMD_EFFECTS_CSE_MASK) >> 16 == 0)
		printf("  No command restriction\n");
	else if ((effect & NVME_CMD_EFFECTS_CSE_MASK) >> 16 == 1)
		printf("  No other command for same namespace\n");
	else if ((effect & NVME_CMD_EFFECTS_CSE_MASK) >> 16 == 2)
		printf("  No other command for any namespace\n");
	else
		printf("  Reserved CSE\n");
}

static char *nvme_cmd_to_string(int admin, __u8 opcode)
{
	if (admin) {
		switch (opcode) {
		case nvme_admin_delete_sq:	return "Delete I/O Submission Queue";
		case nvme_admin_create_sq:	return "Create I/O Submission Queue";
		case nvme_admin_get_log_page:	return "Get Log Page";
		case nvme_admin_delete_cq:	return "Delete I/O Completion Queue";
		case nvme_admin_create_cq:	return "Create I/O Completion Queue";
		case nvme_admin_identify:	return "Identify";
		case nvme_admin_abort_cmd:	return "Abort";
		case nvme_admin_set_features:	return "Set Features";
		case nvme_admin_get_features:	return "Get Features";
		case nvme_admin_async_event:	return "Asynchronous Event Request";
		case nvme_admin_ns_mgmt:	return "Namespace Management";
		case nvme_admin_activate_fw:	return "Firmware Commit";
		case nvme_admin_download_fw:	return "Firmware Image Download";
		case nvme_admin_dev_self_test:	return "Device Self-test";
		case nvme_admin_ns_attach:	return "Namespace Attachment";
		case nvme_admin_keep_alive:	return "Keep Alive";
		case nvme_admin_directive_send:	return "Directive Send";
		case nvme_admin_directive_recv:	return "Directive Receive";
		case nvme_admin_virtual_mgmt:	return "Virtualization Management";
		case nvme_admin_nvme_mi_send:	return "NVMEe-MI Send";
		case nvme_admin_nvme_mi_recv:	return "NVMEe-MI Receive";
		case nvme_admin_dbbuf:		return "Doorbell Buffer Config";
		case nvme_admin_format_nvm:	return "Format NVM";
		case nvme_admin_security_send:	return "Security Send";
		case nvme_admin_security_recv:	return "Security Receive";
		case nvme_admin_sanitize_nvm:	return "Sanitize";
		}
	} else {
		switch (opcode) {
		case nvme_cmd_flush:		return "Flush";
		case nvme_cmd_write:		return "Write";
		case nvme_cmd_read:		return "Read";
		case nvme_cmd_write_uncor:	return "Write Uncorrectable";
		case nvme_cmd_compare:		return "Compare";
		case nvme_cmd_write_zeroes:	return "Write Zeroes";
		case nvme_cmd_dsm:		return "Dataset Management";
		case nvme_cmd_resv_register:	return "Reservation Register";
		case nvme_cmd_resv_report:	return "Reservation Report";
		case nvme_cmd_resv_acquire:	return "Reservation Acquire";
		case nvme_cmd_resv_release:	return "Reservation Release";
		}
	}

	return "Unknown";
}

void show_effects_log(struct nvme_effects_log_page *effects, unsigned int flags)
{
	int i;
	int human = flags & HUMAN;
	__u32 effect;

	printf("Admin Command Set\n");
	for (i = 0; i < 256; i++) {
		effect = le32_to_cpu(effects->acs[i]);
		if (effect & NVME_CMD_EFFECTS_CSUPP) {
			printf("ACS%-6d[%-32s] %08x", i,
					nvme_cmd_to_string(1, i), effect);
			if (human)
				show_effects_log_human(effect);
			else
				printf("\n");
		}
	}
	printf("\nNVM Command Set\n");
	for (i = 0; i < 256; i++) {
		effect = le32_to_cpu(effects->iocs[i]);
		if (effect & NVME_CMD_EFFECTS_CSUPP) {
			printf("IOCS%-5d[%-32s] %08x", i,
					nvme_cmd_to_string(0, i), effect);
			if (human)
				show_effects_log_human(effect);
			else
				printf("\n");
		}
	}
}

uint64_t int48_to_long(__u8 *data)
{
	int i;
	uint64_t result = 0;

	for (i = 0; i < 6; i++) {
		result *= 256;
		result += data[5 - i];
	}
	return result;
}

void show_endurance_log(struct nvme_endurance_group_log *endurance_group,
			__u16 group_id, const char *devname)
{
	printf("Endurance Group Log for NVME device:%s Group ID:%x\n", devname, group_id);
	printf("avl_spare_threshold   : %u\n", endurance_group->avl_spare_threshold);
	printf("percent_used          : %u%%\n", endurance_group->percent_used);
	printf("endurance_estimate    : %'.0Lf\n",
		int128_to_double(endurance_group->endurance_estimate));
	printf("data_units_read       : %'.0Lf\n",
		int128_to_double(endurance_group->data_units_read));
	printf("data_units_written    : %'.0Lf\n",
		int128_to_double(endurance_group->data_units_written));
	printf("media_units_written   : %'.0Lf\n",
		int128_to_double(endurance_group->media_units_written));
}

void show_smart_log(struct nvme_smart_log *smart, unsigned int nsid, const char *devname)
{
	/* convert temperature from Kelvin to Celsius */
	int temperature = ((smart->temperature[1] << 8) |
		smart->temperature[0]) - 273;
	int i;

	printf("Smart Log for NVME device:%s namespace-id:%x\n", devname, nsid);
	printf("critical_warning                    : %#x\n", smart->critical_warning);
	printf("temperature                         : %d C\n", temperature);
	printf("available_spare                     : %u%%\n", smart->avail_spare);
	printf("available_spare_threshold           : %u%%\n", smart->spare_thresh);
	printf("percentage_used                     : %u%%\n", smart->percent_used);
	printf("data_units_read                     : %'.0Lf\n",
		int128_to_double(smart->data_units_read));
	printf("data_units_written                  : %'.0Lf\n",
		int128_to_double(smart->data_units_written));
	printf("host_read_commands                  : %'.0Lf\n",
		int128_to_double(smart->host_reads));
	printf("host_write_commands                 : %'.0Lf\n",
		int128_to_double(smart->host_writes));
	printf("controller_busy_time                : %'.0Lf\n",
		int128_to_double(smart->ctrl_busy_time));
	printf("power_cycles                        : %'.0Lf\n",
		int128_to_double(smart->power_cycles));
	printf("power_on_hours                      : %'.0Lf\n",
		int128_to_double(smart->power_on_hours));
	printf("unsafe_shutdowns                    : %'.0Lf\n",
		int128_to_double(smart->unsafe_shutdowns));
	printf("media_errors                        : %'.0Lf\n",
		int128_to_double(smart->media_errors));
	printf("num_err_log_entries                 : %'.0Lf\n",
		int128_to_double(smart->num_err_log_entries));
	printf("Warning Temperature Time            : %u\n", le32_to_cpu(smart->warning_temp_time));
	printf("Critical Composite Temperature Time : %u\n", le32_to_cpu(smart->critical_comp_time));
	for (i = 0; i < 8; i++) {
		__s32 temp = le16_to_cpu(smart->temp_sensor[i]);

		if (temp == 0)
			continue;
		printf("Temperature Sensor %d                : %d C\n", i + 1,
			temp - 273);
	}
	printf("Thermal Management T1 Trans Count   : %u\n", le32_to_cpu(smart->thm_temp1_trans_count));
	printf("Thermal Management T2 Trans Count   : %u\n", le32_to_cpu(smart->thm_temp2_trans_count));
	printf("Thermal Management T1 Total Time    : %u\n", le32_to_cpu(smart->thm_temp1_total_time));
	printf("Thermal Management T2 Total Time    : %u\n", le32_to_cpu(smart->thm_temp2_total_time));
}

void show_ana_log(struct nvme_ana_rsp_hdr *ana_log, const char *devname)
{
	int offset = sizeof(struct nvme_ana_rsp_hdr);
	struct nvme_ana_rsp_hdr *hdr = ana_log;
	struct nvme_ana_group_desc *desc;
	size_t nsid_buf_size;
	void *base = ana_log;
	__u32 nr_nsids;
	int i;
	int j;

	printf("Asynchronous Namespace Access Log for NVMe device: %s\n",
			devname);
	printf("ANA LOG HEADER :-\n");
	printf("chgcnt	:	%"PRIu64"\n",
			(uint64_t)le64_to_cpu(hdr->chgcnt));
	printf("ngrps	:	%u\n", le16_to_cpu(hdr->ngrps));
	printf("ANA Log Desc :-\n");

	for (i = 0; i < le16_to_cpu(ana_log->ngrps); i++) {
		desc = base + offset;
		nr_nsids = le32_to_cpu(desc->nnsids);
		nsid_buf_size = nr_nsids * sizeof(__le32);

		offset += sizeof(*desc);
		printf("grpid	:	%u\n", le32_to_cpu(desc->grpid));
		printf("nnsids	:	%u\n", le32_to_cpu(desc->nnsids));
		printf("chgcnt	:	%"PRIu64"\n",
		       (uint64_t)le64_to_cpu(desc->chgcnt));
		printf("state	:	%s\n",
				nvme_ana_state_to_string(desc->state));
		for (j = 0; j < le32_to_cpu(desc->nnsids); j++)
			printf("	nsid	:	%u\n",
					le32_to_cpu(desc->nsids[j]));
		printf("\n");
		offset += nsid_buf_size;
	}
}

void show_self_test_log(struct nvme_self_test_log *self_test, const char *devname)
{
	int i, temp;
	const char *test_code_res;
	const char *test_res[10] = {
		"Operation completed without error",
		"Operation was aborted by a Device Self-test command",
		"Operation was aborted by a Controller Level Reset",
		"Operation was aborted due to a removal of a namespace from the namespace inventory",
		"Operation was aborted due to the processing of a Format NVM command",
		"A fatal error or unknown test error occurred while the controller was executing the"\
		" device self-test operation and the operation did not complete",
		"Operation completed with a segment that failed and the segment that failed is not known",
		"Operation completed with one or more failed segments and the first segment that failed "\
		"is indicated in the SegmentNumber field",
		"Operation was aborted for unknown reason",
		"Reserved"
	};

	printf("Device Self Test Log for NVME device:%s\n", devname);
	printf("Current operation : %#x\n", self_test->crnt_dev_selftest_oprn);
	printf("Current Completion : %u%%\n", self_test->crnt_dev_selftest_compln);
	for (i = 0; i < NVME_SELF_TEST_REPORTS; i++) {
		temp = self_test->result[i].device_self_test_status & 0xf;
		if (temp == 0xf)
			continue;

		printf("Result[%d]:\n", i);
		printf("  Test Result                  : %#x %s\n", temp,
			test_res[temp > 9 ? 9 : temp]);

		temp = self_test->result[i].device_self_test_status >> 4;
		switch (temp) {
		case 1:
			test_code_res = "Short device self-test operation";
			break;
		case 2:
			test_code_res = "Extended device self-test operation";
			break;
		case 0xe:
			test_code_res = "Vendor specific";
			break;
		default :
			test_code_res = "Reserved";
			break;
		}
		printf("  Test Code                    : %#x %s\n", temp,
			test_code_res);
		if (temp == 7)
			printf("  Segment number               : %#x\n",
				self_test->result[i].segment_num);

		temp = self_test->result[i].valid_diagnostic_info;
		printf("  Valid Diagnostic Information : %#x\n", temp);
		printf("  Power on hours (POH)         : %#"PRIx64"\n",
			(uint64_t)le64_to_cpu(self_test->result[i].power_on_hours));

		if (temp & NVME_SELF_TEST_VALID_NSID)
			printf("  Namespace Identifier         : %#x\n",
				le32_to_cpu(self_test->result[i].nsid));
		if (temp & NVME_SELF_TEST_VALID_FLBA)
			printf("  Failing LBA                  : %#"PRIx64"\n",
				(uint64_t)le64_to_cpu(self_test->result[i].failing_lba));
		if (temp & NVME_SELF_TEST_VALID_SCT)
			printf("  Status Code Type             : %#x\n",
				self_test->result[i].status_code_type);
		if (temp & NVME_SELF_TEST_VALID_SC)
			printf("  Status Code                  : %#x\n",
				self_test->result[i].status_code);
		printf("  Vendor Specific                      : %x %x\n",
			self_test->result[i].vendor_specific[0],
			self_test->result[i].vendor_specific[0]);
	}
}

static void show_sanitize_log_sprog(__u32 sprog)
{
	double percent;

	percent = (((double)sprog * 100) / 0x10000);
	printf("\t(%f%%)\n", percent);
}

static const char *get_sanitize_log_sstat_status_str(__u16 status)
{
	const char *str;

	switch (status & NVME_SANITIZE_LOG_STATUS_MASK) {
	case NVME_SANITIZE_LOG_NEVER_SANITIZED:
		str = "NVM Subsystem has never been sanitized.";
		break;
	case NVME_SANITIZE_LOG_COMPLETED_SUCCESS:
		str = "Most Recent Sanitize Command Completed Successfully.";
		break;
	case NVME_SANITIZE_LOG_IN_PROGESS:
		str = "Sanitize in Progress.";
		break;
	case NVME_SANITIZE_LOG_COMPLETED_FAILED:
		str = "Most Recent Sanitize Command Failed.";
		break;
	default:
		str = "Unknown.";
	}

	return str;
}

static void show_sanitize_log_sstat(__u16 status)
{
	const char *str = get_sanitize_log_sstat_status_str(status);

	printf("\t[2:0]\t%s\n", str);
	str = "Number of completed passes if most recent operation was overwrite";
	printf("\t[7:3]\t%s:\t%u\n", str, (status & NVME_SANITIZE_LOG_NUM_CMPLTED_PASS_MASK) >> 3);

	printf("\t  [8]\t");
	if (status & NVME_SANITIZE_LOG_GLOBAL_DATA_ERASED)
		str = "Global Data Erased set: NVM storage has not been written";
	else
		str = "Global Data Erased cleared: NVM storage has been written";
	printf("%s\n", str);
}

void show_sanitize_log(struct nvme_sanitize_log_page *sanitize, unsigned int mode, const char *devname)
{
	int human = mode & HUMAN;
	__u16 status = le16_to_cpu(sanitize->status) & NVME_SANITIZE_LOG_STATUS_MASK;

	printf("Sanitize Progress                     (SPROG) :  %u", le32_to_cpu(sanitize->progress));
	if (human && status == NVME_SANITIZE_LOG_IN_PROGESS)
		show_sanitize_log_sprog(le32_to_cpu(sanitize->progress));
	else
		printf("\n");

	printf("Sanitize Status                       (SSTAT) :  %#x\n", le16_to_cpu(sanitize->status));
	if (human)
		show_sanitize_log_sstat(le16_to_cpu(sanitize->status));

	printf("Sanitize Command Dword 10 Information (SCDW10):  %#x\n", le32_to_cpu(sanitize->cdw10_info));
	printf("Estimated Time For Overwrite                  :  %u\n", le32_to_cpu(sanitize->est_ovrwrt_time));
	printf("Estimated Time For Block Erase                :  %u\n", le32_to_cpu(sanitize->est_blk_erase_time));
	printf("Estimated Time For Crypto Erase               :  %u\n", le32_to_cpu(sanitize->est_crypto_erase_time));
}

char *nvme_feature_to_string(int feature)
{
	switch (feature) {
	case NVME_FEAT_ARBITRATION:	return "Arbitration";
	case NVME_FEAT_POWER_MGMT:	return "Power Management";
	case NVME_FEAT_LBA_RANGE:	return "LBA Range Type";
	case NVME_FEAT_TEMP_THRESH:	return "Temperature Threshold";
	case NVME_FEAT_ERR_RECOVERY:	return "Error Recovery";
	case NVME_FEAT_VOLATILE_WC:	return "Volatile Write Cache";
	case NVME_FEAT_NUM_QUEUES:	return "Number of Queues";
	case NVME_FEAT_IRQ_COALESCE:	return "Interrupt Coalescing";
	case NVME_FEAT_IRQ_CONFIG: 	return "Interrupt Vector Configuration";
	case NVME_FEAT_WRITE_ATOMIC:	return "Write Atomicity Normal";
	case NVME_FEAT_ASYNC_EVENT:	return "Async Event Configuration";
	case NVME_FEAT_AUTO_PST:	return "Autonomous Power State Transition";
	case NVME_FEAT_HOST_MEM_BUF:	return "Host Memory Buffer";
	case NVME_FEAT_KATO:		return "Keep Alive Timer";
	case NVME_FEAT_NOPSC:		return "Non-Operational Power State Config";
	case NVME_FEAT_RRL:		return "Read Recovery Level";
	case NVME_FEAT_PLM_CONFIG:	return "Predicatable Latency Mode Config";
	case NVME_FEAT_PLM_WINDOW:	return "Predicatable Latency Mode Window";
	case NVME_FEAT_SW_PROGRESS:	return "Software Progress";
	case NVME_FEAT_HOST_ID:		return "Host Identifier";
	case NVME_FEAT_RESV_MASK:	return "Reservation Notification Mask";
	case NVME_FEAT_RESV_PERSIST:	return "Reservation Persistence";
	case NVME_FEAT_TIMESTAMP:	return "Timestamp";
	case NVME_FEAT_WRITE_PROTECT:	return "Namespce Write Protect";
	case NVME_FEAT_HCTM:		return "Host Controlled Thermal Management";
	default:			return "Unknown";
	}
}

char *nvme_register_to_string(int reg)
{
	switch (reg) {
	case NVME_REG_CAP:	return "Controller Capabilities";
	case NVME_REG_VS:	return "Version";
	case NVME_REG_INTMS:	return "Interrupt Vector Mask Set";
	case NVME_REG_INTMC:	return "Interrupt Vector Mask Clear";
	case NVME_REG_CC:	return "Controller Configuration";
	case NVME_REG_CSTS:	return "Controller Status";
	case NVME_REG_NSSR:	return "NVM Subsystem Reset";
	case NVME_REG_AQA:	return "Admin Queue Attributes";
	case NVME_REG_ASQ:	return "Admin Submission Queue Base Address";
	case NVME_REG_ACQ:	return "Admin Completion Queue Base Address";
	case NVME_REG_CMBLOC:	return "Controller Memory Buffer Location";
	case NVME_REG_CMBSZ:	return "Controller Memory Buffer Size";
	default:			return "Unknown";
	}
}

char* nvme_select_to_string(int sel)
{
	switch (sel) {
	case 0:  return "Current";
	case 1:  return "Default";
	case 2:  return "Saved";
	case 3:  return "Supported capabilities";
	default: return "Reserved";
	}
}

void nvme_show_select_result(__u32 result)
{
	if (result & 0x1)
		printf("  Feature is saveable\n");
	if (result & 0x2)
		printf("  Feature is per-namespace\n");
	if (result & 0x4)
		printf("  Feature is changeable\n");
}

char *nvme_status_to_string(__u32 status)
{
	switch (status & 0x3ff) {
	case NVME_SC_SUCCESS:			return "SUCCESS: The command completed successfully";
	case NVME_SC_INVALID_OPCODE:		return "INVALID_OPCODE: The associated command opcode field is not valid";
	case NVME_SC_INVALID_FIELD:		return "INVALID_FIELD: A reserved coded value or an unsupported value in a defined field";
	case NVME_SC_CMDID_CONFLICT:		return "CMDID_CONFLICT: The command identifier is already in use";
	case NVME_SC_DATA_XFER_ERROR:		return "DATA_XFER_ERROR: Error while trying to transfer the data or metadata";
	case NVME_SC_POWER_LOSS:		return "POWER_LOSS: Command aborted due to power loss notification";
	case NVME_SC_INTERNAL:			return "INTERNAL: The command was not completed successfully due to an internal error";
	case NVME_SC_ABORT_REQ:			return "ABORT_REQ: The command was aborted due to a Command Abort request";
	case NVME_SC_ABORT_QUEUE:		return "ABORT_QUEUE: The command was aborted due to a Delete I/O Submission Queue request";
	case NVME_SC_FUSED_FAIL:		return "FUSED_FAIL: The command was aborted due to the other command in a fused operation failing";
	case NVME_SC_FUSED_MISSING:		return "FUSED_MISSING: The command was aborted due to a Missing Fused Command";
	case NVME_SC_INVALID_NS:		return "INVALID_NS: The namespace or the format of that namespace is invalid";
	case NVME_SC_CMD_SEQ_ERROR:		return "CMD_SEQ_ERROR: The command was aborted due to a protocol violation in a multicommand sequence";
	case NVME_SC_SANITIZE_FAILED:		return "SANITIZE_FAILED: The most recent sanitize operation failed and no recovery actions has been successfully completed";
	case NVME_SC_SANITIZE_IN_PROGRESS:	return "SANITIZE_IN_PROGRESS: The requested function is prohibited while a sanitize operation is in progress";
	case NVME_SC_LBA_RANGE:			return "LBA_RANGE: The command references a LBA that exceeds the size of the namespace";
	case NVME_SC_NS_WRITE_PROTECTED:	return "NS_WRITE_PROTECTED: The command is prohibited while the namespace is write protected by the host.";
	case NVME_SC_CAP_EXCEEDED:		return "CAP_EXCEEDED: The execution of the command has caused the capacity of the namespace to be exceeded";
	case NVME_SC_NS_NOT_READY:		return "NS_NOT_READY: The namespace is not ready to be accessed as a result of a condition other than a condition that is reported as an Asymmetric Namespace Access condition";
	case NVME_SC_RESERVATION_CONFLICT:	return "RESERVATION_CONFLICT: The command was aborted due to a conflict with a reservation held on the accessed namespace";
	case NVME_SC_CQ_INVALID:		return "CQ_INVALID: The Completion Queue identifier specified in the command does not exist";
	case NVME_SC_QID_INVALID:		return "QID_INVALID: The creation of the I/O Completion Queue failed due to an invalid queue identifier specified as part of the command. An invalid queue identifier is one that is currently in use or one that is outside the range supported by the controller";
	case NVME_SC_QUEUE_SIZE:		return "QUEUE_SIZE: The host attempted to create an I/O Completion Queue with an invalid number of entries";
	case NVME_SC_ABORT_LIMIT:		return "ABORT_LIMIT: The number of concurrently outstanding Abort commands has exceeded the limit indicated in the Identify Controller data structure";
	case NVME_SC_ABORT_MISSING:		return "ABORT_MISSING: The abort command is missing";
	case NVME_SC_ASYNC_LIMIT:		return "ASYNC_LIMIT: The number of concurrently outstanding Asynchronous Event Request commands has been exceeded";
	case NVME_SC_FIRMWARE_SLOT:		return "FIRMWARE_SLOT: The firmware slot indicated is invalid or read only. This error is indicated if the firmware slot exceeds the number supported";
	case NVME_SC_FIRMWARE_IMAGE:		return "FIRMWARE_IMAGE: The firmware image specified for activation is invalid and not loaded by the controller";
	case NVME_SC_INVALID_VECTOR:		return "INVALID_VECTOR: The creation of the I/O Completion Queue failed due to an invalid interrupt vector specified as part of the command";
	case NVME_SC_INVALID_LOG_PAGE:		return "INVALID_LOG_PAGE: The log page indicated is invalid. This error condition is also returned if a reserved log page is requested";
	case NVME_SC_INVALID_FORMAT:		return "INVALID_FORMAT: The LBA Format specified is not supported. This may be due to various conditions";
	case NVME_SC_FW_NEEDS_CONV_RESET:	return "FW_NEEDS_CONVENTIONAL_RESET: The firmware commit was successful, however, activation of the firmware image requires a conventional reset";
	case NVME_SC_INVALID_QUEUE:		return "INVALID_QUEUE: This error indicates that it is invalid to delete the I/O Completion Queue specified. The typical reason for this error condition is that there is an associated I/O Submission Queue that has not been deleted.";
	case NVME_SC_FEATURE_NOT_SAVEABLE:	return "FEATURE_NOT_SAVEABLE: The Feature Identifier specified does not support a saveable value";
	case NVME_SC_FEATURE_NOT_CHANGEABLE:	return "FEATURE_NOT_CHANGEABLE: The Feature Identifier is not able to be changed";
	case NVME_SC_FEATURE_NOT_PER_NS:	return "FEATURE_NOT_PER_NS: The Feature Identifier specified is not namespace specific. The Feature Identifier settings apply across all namespaces";
	case NVME_SC_FW_NEEDS_SUBSYS_RESET:	return "FW_NEEDS_SUBSYSTEM_RESET: The firmware commit was successful, however, activation of the firmware image requires an NVM Subsystem";
	case NVME_SC_FW_NEEDS_RESET:		return "FW_NEEDS_RESET: The firmware commit was successful; however, the image specified does not support being activated without a reset";
	case NVME_SC_FW_NEEDS_MAX_TIME:		return "FW_NEEDS_MAX_TIME_VIOLATION: The image specified if activated immediately would exceed the Maximum Time for Firmware Activation (MTFA) value reported in Identify Controller. To activate the firmware, the Firmware Commit command needs to be re-issued and the image activated using a reset";
	case NVME_SC_FW_ACIVATE_PROHIBITED:	return "FW_ACTIVATION_PROHIBITED: The image specified is being prohibited from activation by the controller for vendor specific reasons";
	case NVME_SC_OVERLAPPING_RANGE:		return "OVERLAPPING_RANGE: This error is indicated if the firmware image has overlapping ranges";
	case NVME_SC_NS_INSUFFICENT_CAP:	return "NS_INSUFFICIENT_CAPACITY: Creating the namespace requires more free space than is currently available. The Command Specific Information field of the Error Information Log specifies the total amount of NVM capacity required to create the namespace in bytes";
	case NVME_SC_NS_ID_UNAVAILABLE:		return "NS_ID_UNAVAILABLE: The number of namespaces supported has been exceeded";
	case NVME_SC_NS_ALREADY_ATTACHED:	return "NS_ALREADY_ATTACHED: The controller is already attached to the namespace specified";
	case NVME_SC_NS_IS_PRIVATE:		return "NS_IS_PRIVATE: The namespace is private and is already attached to one controller";
	case NVME_SC_NS_NOT_ATTACHED:		return "NS_NOT_ATTACHED: The request to detach the controller could not be completed because the controller is not attached to the namespace";
	case NVME_SC_THIN_PROV_NOT_SUPP:	return "THIN_PROVISIONING_NOT_SUPPORTED: Thin provisioning is not supported by the controller";
	case NVME_SC_CTRL_LIST_INVALID:		return "CONTROLLER_LIST_INVALID: The controller list provided is invalid";
	case NVME_SC_BP_WRITE_PROHIBITED:	return "BOOT PARTITION WRITE PROHIBITED: The command is trying to modify a Boot Partition while it is locked";
	case NVME_SC_BAD_ATTRIBUTES:		return "BAD_ATTRIBUTES: Bad attributes were given";
	case NVME_SC_WRITE_FAULT:		return "WRITE_FAULT: The write data could not be committed to the media";
	case NVME_SC_READ_ERROR:		return "READ_ERROR: The read data could not be recovered from the media";
	case NVME_SC_GUARD_CHECK:		return "GUARD_CHECK: The command was aborted due to an end-to-end guard check failure";
	case NVME_SC_APPTAG_CHECK:		return "APPTAG_CHECK: The command was aborted due to an end-to-end application tag check failure";
	case NVME_SC_REFTAG_CHECK:		return "REFTAG_CHECK: The command was aborted due to an end-to-end reference tag check failure";
	case NVME_SC_COMPARE_FAILED:		return "COMPARE_FAILED: The command failed due to a miscompare during a Compare command";
	case NVME_SC_ACCESS_DENIED:		return "ACCESS_DENIED: Access to the namespace and/or LBA range is denied due to lack of access rights";
	case NVME_SC_UNWRITTEN_BLOCK:		return "UNWRITTEN_BLOCK: The command failed due to an attempt to read from an LBA range containing a deallocated or unwritten logical block";
	case NVME_SC_ANA_PERSISTENT_LOSS:	return "ASYMMETRIC_NAMESPACE_ACCESS_PERSISTENT_LOSS: The requested function (e.g., command) is not able to be performed as a result of the relationship between the controller and the namespace being in the ANA Persistent Loss state";
	case NVME_SC_ANA_INACCESSIBLE:		return "ASYMMETRIC_NAMESPACE_ACCESS_INACCESSIBLE: The requested function (e.g., command) is not able to be performed as a result of the relationship between the controller and the namespace being in the ANA Inaccessible state";
	case NVME_SC_ANA_TRANSITION:		return "ASYMMETRIC_NAMESPACE_ACCESS_TRANSITION: The requested function (e.g., command) is not able to be performed as a result of the relationship between the controller and the namespace transitioning between Asymmetric Namespace Access states";
	default:				return "Unknown";
	}
}

static char* nvme_feature_lba_type_to_string(__u8 type)
{
	switch (type) {
	case 0:	return "Reserved";
	case 1:	return "Filesystem";
	case 2:	return "RAID";
	case 3:	return "Cache";
	case 4:	return "Page / Swap file";
	default:
		if (type>=0x05 && type<=0x7f)
			return "Reserved";
		else
			return "Vendor Specific";
	}
}

void show_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges)
{
	int i, j;

	for (i = 0; i <= nr_ranges; i++) {
		printf("\ttype       : %#x - %s\n", lbrt[i].type, nvme_feature_lba_type_to_string(lbrt[i].type));
		printf("\tattributes : %#x - %s, %s\n", lbrt[i].attributes, (lbrt[i].attributes & 0x0001) ? "LBA range may be overwritten":"LBA range should not be overwritten",
			((lbrt[i].attributes & 0x0002) >> 1) ? "LBA range should be hidden from the OS/EFI/BIOS":"LBA range should be visible from the OS/EFI/BIOS");
		printf("\tslba       : %#"PRIx64"\n", (uint64_t)(lbrt[i].slba));
		printf("\tnlb        : %#"PRIx64"\n", (uint64_t)(lbrt[i].nlb));
		printf("\tguid       : ");
		for (j = 0; j < 16; j++)
			printf("%02x", lbrt[i].guid[j]);
		printf("\n");
	}
}


static char *nvme_feature_wl_hints_to_string(__u8 wh)
{
	switch (wh) {
	case 0:	return "No Workload";
	case 1:	return "Extended Idle Period with a Burst of Random Writes";
	case 2:	return "Heavy Sequential Writes";
	default:return "Reserved";
	}
}

static char *nvme_feature_temp_type_to_string(__u8 type)
{
	switch (type) {
	case 0:	return "Over Temperature Threshold";
	case 1:	return "Under Temperature Threshold";
	default:return "Reserved";
	}
}

static char *nvme_feature_temp_sel_to_string(__u8 sel)
{
	switch (sel)
	{
	case 0:	return "Composite Temperature";
	case 1:	return "Temperature Sensor 1";
	case 2:	return "Temperature Sensor 2";
	case 3:	return "Temperature Sensor 3";
	case 4:	return "Temperature Sensor 4";
	case 5:	return "Temperature Sensor 5";
	case 6:	return "Temperature Sensor 6";
	case 7:	return "Temperature Sensor 7";
	case 8:	return "Temperature Sensor 8";
	default:return "Reserved";
	}
}

static void show_auto_pst(struct nvme_auto_pst *apst)
{
	int i;

	printf( "\tAuto PST Entries");
	printf("\t.................\n");
	for (i = 0; i < 32; i++) {
		printf("\tEntry[%2d]   \n", i);
		printf("\t.................\n");
		printf("\tIdle Time Prior to Transition (ITPT): %u ms\n", (apst[i].data & 0xffffff00) >> 8);
		printf("\tIdle Transition Power State   (ITPS): %u\n", (apst[i].data & 0x000000f8) >> 3);
		printf("\t.................\n");
	}
}

static void show_timestamp(struct nvme_timestamp *ts)
{
	printf("\tThe timestamp is : %"PRIu64"\n", int48_to_long(ts->timestamp));
	printf("\t%s\n", (ts->attr & 2) ? "The Timestamp field was initialized with a "\
			"Timestamp value using a Set Features command." : "The Timestamp field was initialized "\
			"to ‘0’ by a Controller Level Reset.");
	printf("\t%s\n", (ts->attr & 1) ? "The controller may have stopped counting during vendor specific "\
			"intervals after the Timestamp value was initialized" : "The controller counted time in milliseconds "\
			"continuously since the Timestamp value was initialized.");
}

static void show_host_mem_buffer(struct nvme_host_mem_buffer *hmb)
{
	printf("\tHost Memory Descriptor List Entry Count (HMDLEC): %u\n", hmb->hmdlec);
	printf("\tHost Memory Descriptor List Address     (HMDLAU): 0x%x\n", hmb->hmdlau);
	printf("\tHost Memory Descriptor List Address     (HMDLAL): 0x%x\n", hmb->hmdlal);
	printf("\tHost Memory Buffer Size                  (HSIZE): %u\n", hmb->hsize);
}

void nvme_directive_show_fields(__u8 dtype, __u8 doper, unsigned int result, unsigned char *buf)
{
        __u8 *field = buf;
        int count, i;
        switch (dtype) {
        case NVME_DIR_IDENTIFY:
                switch (doper) {
                case NVME_DIR_RCV_ID_OP_PARAM:
                        printf("\tDirective support \n");
                        printf("\t\tIdentify Directive  : %s\n", (*field & 0x1) ? "supported":"not supported");
                        printf("\t\tStream Directive    : %s\n", (*field & 0x2) ? "supported":"not supported");
                        printf("\tDirective status \n");
                        printf("\t\tIdentify Directive  : %s\n", (*(field + 32) & 0x1) ? "enabled" : "disabled");
                        printf("\t\tStream Directive    : %s\n", (*(field + 32) & 0x2) ? "enabled" : "disabled");
                        break;
                default:
                        fprintf(stderr, "invalid directive operations for Identify Directives\n");
                }
                break;
        case NVME_DIR_STREAMS:
                switch (doper) {
                case NVME_DIR_RCV_ST_OP_PARAM:
                        printf("\tMax Streams Limit                          (MSL): %u\n", *(__u16 *) field);
                        printf("\tNVM Subsystem Streams Available           (NSSA): %u\n", *(__u16 *) (field + 2));
                        printf("\tNVM Subsystem Streams Open                (NSSO): %u\n", *(__u16 *) (field + 4));
                        printf("\tStream Write Size (in unit of LB size)     (SWS): %u\n", *(__u32 *) (field + 16));
                        printf("\tStream Granularity Size (in unit of SWS)   (SGS): %u\n", *(__u16 *) (field + 20));
                        printf("\tNamespece Streams Allocated                (NSA): %u\n", *(__u16 *) (field + 22));
                        printf("\tNamespace Streams Open                     (NSO): %u\n", *(__u16 *) (field + 24));
                        break;
                case NVME_DIR_RCV_ST_OP_STATUS:
                        count = *(__u16 *) field;
                        printf("\tOpen Stream Count  : %u\n", *(__u16 *) field);
                        for ( i = 0; i < count; i++ ) {
                                printf("\tStream Identifier %.6u : %u\n", i + 1, *(__u16 *) (field + ((i + 1) * 2)));
                        }
                        break;
                case NVME_DIR_RCV_ST_OP_RESOURCE:
                        printf("\tNamespace Streams Allocated (NSA): %u\n", result & 0xffff);
                        break;
                default:
                        fprintf(stderr, "invalid directive operations for Streams Directives\n");
                }
                break;
        default:
                fprintf(stderr, "invalid directive type\n");
                break;
        }
        return;
}

static char *nvme_plm_window(__u32 plm)
{
	switch (plm & 0x7) {
	case 1:
		return "Deterministic Window (DTWIN)";
	case 2:
		return "Non-deterministic Window (NDWIN)";
	default:
		return "Reserved";
	}
}

static void show_plm_config(struct nvme_plm_config *plmcfg)
{
	printf("\tEnable Event          :%04x\n", le16_to_cpu(plmcfg->enable_event));
	printf("\tDTWIN Reads Threshold :%"PRIu64"\n", (uint64_t)le64_to_cpu(plmcfg->dtwin_reads_thresh));
	printf("\tDTWIN Writes Threshold:%"PRIu64"\n", (uint64_t)le64_to_cpu(plmcfg->dtwin_writes_thresh));
	printf("\tDTWIN Time Threshold  :%"PRIu64"\n", (uint64_t)le64_to_cpu(plmcfg->dtwin_time_thresh));
}

void nvme_feature_show_fields(__u32 fid, unsigned int result, unsigned char *buf)
{
	__u8 field;
	uint64_t ull;

	switch (fid) {
	case NVME_FEAT_ARBITRATION:
		printf("\tHigh Priority Weight   (HPW): %u\n", ((result & 0xff000000) >> 24) + 1);
		printf("\tMedium Priority Weight (MPW): %u\n", ((result & 0x00ff0000) >> 16) + 1);
		printf("\tLow Priority Weight    (LPW): %u\n", ((result & 0x0000ff00) >> 8) + 1);
		printf("\tArbitration Burst       (AB): ");
		if ((result & 0x00000007) == 7)
			printf("No limit\n");
		else
			printf("%u\n",  1 << (result & 0x00000007));
		break;
	case NVME_FEAT_POWER_MGMT:
		field = (result & 0x000000E0) >> 5;
		printf("\tWorkload Hint (WH): %u - %s\n",  field, nvme_feature_wl_hints_to_string(field));
		printf("\tPower State   (PS): %u\n",  result & 0x0000001f);
		break;
	case NVME_FEAT_LBA_RANGE:
		field = result & 0x0000003f;
		printf("\tNumber of LBA Ranges (NUM): %u\n", field + 1);
		show_lba_range((struct nvme_lba_range_type *)buf, field);
		break;
	case NVME_FEAT_TEMP_THRESH:
		field = (result & 0x00300000) >> 20;
		printf("\tThreshold Type Select         (THSEL): %u - %s\n", field, nvme_feature_temp_type_to_string(field));
		field = (result & 0x000f0000) >> 16;
		printf("\tThreshold Temperature Select (TMPSEL): %u - %s\n", field, nvme_feature_temp_sel_to_string(field));
		printf("\tTemperature Threshold         (TMPTH): %d C\n", (result & 0x0000ffff) - 273);
		break;
	case NVME_FEAT_ERR_RECOVERY:
		printf("\tDeallocated or Unwritten Logical Block Error Enable (DULBE): %s\n", ((result & 0x00010000) >> 16) ? "Enabled":"Disabled");
		printf("\tTime Limited Error Recovery                          (TLER): %u ms\n", (result & 0x0000ffff) * 100);
		break;
	case NVME_FEAT_VOLATILE_WC:
		printf("\tVolatile Write Cache Enable (WCE): %s\n", (result & 0x00000001) ? "Enabled":"Disabled");
		break;
	case NVME_FEAT_NUM_QUEUES:
		printf("\tNumber of IO Completion Queues Allocated (NCQA): %u\n", ((result & 0xffff0000) >> 16) + 1);
		printf("\tNumber of IO Submission Queues Allocated (NSQA): %u\n",  (result & 0x0000ffff) + 1);
		break;
	case NVME_FEAT_IRQ_COALESCE:
		printf("\tAggregation Time     (TIME): %u usec\n", ((result & 0x0000ff00) >> 8) * 100);
		printf("\tAggregation Threshold (THR): %u\n",  (result & 0x000000ff) + 1);
		break;
	case NVME_FEAT_IRQ_CONFIG:
		printf("\tCoalescing Disable (CD): %s\n", ((result & 0x00010000) >> 16) ? "True":"False");
		printf("\tInterrupt Vector   (IV): %u\n",  result & 0x0000ffff);
		break;
	case NVME_FEAT_WRITE_ATOMIC:
		printf("\tDisable Normal (DN): %s\n", (result & 0x00000001) ? "True":"False");
		break;
	case NVME_FEAT_ASYNC_EVENT:
		printf("\tTelemetry Log Notices           : %s\n", ((result & 0x00000400) >> 10) ? "Send async event":"Do not send async event");
		printf("\tFirmware Activation Notices     : %s\n", ((result & 0x00000200) >> 9) ? "Send async event":"Do not send async event");
		printf("\tNamespace Attribute Notices     : %s\n", ((result & 0x00000100) >> 8) ? "Send async event":"Do not send async event");
		printf("\tSMART / Health Critical Warnings: %s\n", (result & 0x000000ff) ? "Send async event":"Do not send async event");
		break;
	case NVME_FEAT_AUTO_PST:
		printf("\tAutonomous Power State Transition Enable (APSTE): %s\n", (result & 0x00000001) ? "Enabled":"Disabled");
		show_auto_pst((struct nvme_auto_pst *)buf);
		break;
	case NVME_FEAT_HOST_MEM_BUF:
		printf("\tMemory Return       (MR): %s\n", ((result & 0x00000002) >> 1) ? "True":"False");
		printf("\tEnable Host Memory (EHM): %s\n", (result & 0x00000001) ? "Enabled":"Disabled");
		show_host_mem_buffer((struct nvme_host_mem_buffer *)buf);
		break;
	case NVME_FEAT_SW_PROGRESS:
		printf("\tPre-boot Software Load Count (PBSLC): %u\n", result & 0x000000ff);
		break;
	case NVME_FEAT_PLM_CONFIG:
		printf("\tPredictable Latency Window Enabled: %s\n", result & 0x1 ? "True":"False");
		show_plm_config((struct nvme_plm_config *)buf);
		break;
	case NVME_FEAT_PLM_WINDOW:
		printf("\tWindow Select: %s", nvme_plm_window(result));
		break;
	case NVME_FEAT_HOST_ID:
		ull =  buf[7]; ull <<= 8; ull |= buf[6]; ull <<= 8; ull |= buf[5]; ull <<= 8;
		ull |= buf[4]; ull <<= 8; ull |= buf[3]; ull <<= 8; ull |= buf[2]; ull <<= 8;
		ull |= buf[1]; ull <<= 8; ull |= buf[0];
		printf("\tHost Identifier (HOSTID):  %" PRIu64 "\n", ull);
		break;
	case NVME_FEAT_RESV_MASK:
		printf("\tMask Reservation Preempted Notification  (RESPRE): %s\n", ((result & 0x00000008) >> 3) ? "True":"False");
		printf("\tMask Reservation Released Notification   (RESREL): %s\n", ((result & 0x00000004) >> 2) ? "True":"False");
		printf("\tMask Registration Preempted Notification (REGPRE): %s\n", ((result & 0x00000002) >> 1) ? "True":"False");
		break;
	case NVME_FEAT_RESV_PERSIST:
		printf("\tPersist Through Power Loss (PTPL): %s\n", (result & 0x00000001) ? "True":"False");
		break;
	case NVME_FEAT_WRITE_PROTECT:
		printf("\tNamespace Write Protect: %s\n", result != NVME_NS_NO_WRITE_PROTECT ? "True" :  "False");
		break;
	case NVME_FEAT_TIMESTAMP:
		show_timestamp((struct nvme_timestamp *)buf);
		break;
	case NVME_FEAT_HCTM:
		printf("\tThermal Management Temperature 1 (TMT1) : %u Kelvin\n", (result >> 16));
		printf("\tThermal Management Temperature 2 (TMT2) : %u Kelvin\n", (result & 0x0000ffff));
		break;
	case NVME_FEAT_KATO:
		printf("\tKeep Alive Timeout (KATO) in milliseconds: %u\n", result);
		break;
	case NVME_FEAT_NOPSC:
		printf("\tNon-Operational Power State Permissive Mode Enable (NOPPME): %s\n", (result & 1) ? "True" : "False");
		break;
	}
}

static void show_list_item(struct list_item list_item)
{
	long long int lba = 1 << list_item.ns.lbaf[(list_item.ns.flbas & 0x0f)].ds;
	double nsze       = le64_to_cpu(list_item.ns.nsze) * lba;
	double nuse       = le64_to_cpu(list_item.ns.nuse) * lba;

	const char *s_suffix = suffix_si_get(&nsze);
	const char *u_suffix = suffix_si_get(&nuse);
	const char *l_suffix = suffix_binary_get(&lba);

	char usage[128];
	char format[128];

	sprintf(usage,"%6.2f %2sB / %6.2f %2sB", nuse, u_suffix,
		nsze, s_suffix);
	sprintf(format,"%3.0f %2sB + %2d B", (double)lba, l_suffix,
		le16_to_cpu(list_item.ns.lbaf[(list_item.ns.flbas & 0x0f)].ms));
	printf("%-16s %-*.*s %-*.*s %-9d %-26s %-16s %-.*s\n", list_item.node,
            (int)sizeof(list_item.ctrl.sn), (int)sizeof(list_item.ctrl.sn), list_item.ctrl.sn,
            (int)sizeof(list_item.ctrl.mn), (int)sizeof(list_item.ctrl.mn), list_item.ctrl.mn,
            list_item.nsid, usage, format, (int)sizeof(list_item.ctrl.fr), list_item.ctrl.fr);
}

void show_list_items(struct list_item *list_items, unsigned len)
{
	unsigned i;

	printf("%-16s %-20s %-40s %-9s %-26s %-16s %-8s\n",
	    "Node", "SN", "Model", "Namespace", "Usage", "Format", "FW Rev");
	printf("%-16s %-20s %-40s %-9s %-26s %-16s %-8s\n",
            "----------------", "--------------------", "----------------------------------------",
            "---------", "--------------------------", "----------------", "--------");
	for (i = 0 ; i < len ; i++)
		show_list_item(list_items[i]);

}

void json_print_list_items(struct list_item *list_items, unsigned len)
{
	struct json_object *root;
	struct json_array *devices;
	struct json_object *device_attrs;
	char formatter[41] = { 0 };
	int index, i = 0;
	char *product;
	long long int lba;
	double nsze;
	double nuse;

	root = json_create_object();
	devices = json_create_array();
	for (i = 0; i < len; i++) {
		device_attrs = json_create_object();

		json_object_add_value_string(device_attrs,
					     "DevicePath",
					     list_items[i].node);

		format(formatter, sizeof(formatter),
			   list_items[i].ctrl.fr,
			   sizeof(list_items[i].ctrl.fr));

		json_object_add_value_string(device_attrs,
					     "Firmware",
					     formatter);

		if (sscanf(list_items[i].node, "/dev/nvme%d", &index) == 1)
			json_object_add_value_int(device_attrs,
						  "Index",
						  index);

		format(formatter, sizeof(formatter),
		       list_items[i].ctrl.mn,
		       sizeof(list_items[i].ctrl.mn));

		json_object_add_value_string(device_attrs,
					     "ModelNumber",
					     formatter);

		product = nvme_product_name(index);

		json_object_add_value_string(device_attrs,
					     "ProductName",
					     product);

		format(formatter, sizeof(formatter),
		       list_items[i].ctrl.sn,
		       sizeof(list_items[i].ctrl.sn));

		json_object_add_value_string(device_attrs,
					     "SerialNumber",
					     formatter);

		json_array_add_value_object(devices, device_attrs);

		lba = 1 << list_items[i].ns.lbaf[(list_items[i].ns.flbas & 0x0f)].ds;
		nsze = le64_to_cpu(list_items[i].ns.nsze) * lba;
		nuse = le64_to_cpu(list_items[i].ns.nuse) * lba;
		json_object_add_value_uint(device_attrs,
					  "UsedBytes",
					  nuse);
		json_object_add_value_uint(device_attrs,
					  "MaximumLBA",
					  le64_to_cpu(list_items[i].ns.nsze));
		json_object_add_value_uint(device_attrs,
					  "PhysicalSize",
					  nsze);
		json_object_add_value_uint(device_attrs,
					  "SectorSize",
					  lba);

		free((void*)product);
	}
	if (i)
		json_object_add_value_array(root, "Devices", devices);
	json_print_object(root, NULL);
}

void json_nvme_id_ns(struct nvme_id_ns *ns, unsigned int mode)
{
	char nguid_buf[2 * sizeof(ns->nguid) + 1], eui64_buf[2 * sizeof(ns->eui64) + 1];
	char *nguid = nguid_buf, *eui64 = eui64_buf;
	struct json_object *root;
	struct json_array *lbafs;
	int i;

	long double nvmcap = int128_to_double(ns->nvmcap);

	root = json_create_object();

	json_object_add_value_uint(root, "nsze", le64_to_cpu(ns->nsze));
	json_object_add_value_uint(root, "ncap", le64_to_cpu(ns->ncap));
	json_object_add_value_uint(root, "nuse", le64_to_cpu(ns->nuse));
	json_object_add_value_int(root, "nsfeat", ns->nsfeat);
	json_object_add_value_int(root, "nlbaf", ns->nlbaf);
	json_object_add_value_int(root, "flbas", ns->flbas);
	json_object_add_value_int(root, "mc", ns->mc);
	json_object_add_value_int(root, "dpc", ns->dpc);
	json_object_add_value_int(root, "dps", ns->dps);
	json_object_add_value_int(root, "nmic", ns->nmic);
	json_object_add_value_int(root, "rescap", ns->rescap);
	json_object_add_value_int(root, "fpi", ns->fpi);
	json_object_add_value_int(root, "nawun", le16_to_cpu(ns->nawun));
	json_object_add_value_int(root, "nawupf", le16_to_cpu(ns->nawupf));
	json_object_add_value_int(root, "nacwu", le16_to_cpu(ns->nacwu));
	json_object_add_value_int(root, "nabsn", le16_to_cpu(ns->nabsn));
	json_object_add_value_int(root, "nabo", le16_to_cpu(ns->nabo));
	json_object_add_value_int(root, "nabspf", le16_to_cpu(ns->nabspf));
	json_object_add_value_int(root, "noiob", le16_to_cpu(ns->noiob));
	json_object_add_value_float(root, "nvmcap", nvmcap);
	json_object_add_value_int(root, "nsattr", ns->nsattr);
	json_object_add_value_int(root, "nvmsetid", le16_to_cpu(ns->nvmsetid));

	json_object_add_value_int(root, "anagrpid", le32_to_cpu(ns->anagrpid));
	json_object_add_value_int(root, "endgid", le16_to_cpu(ns->endgid));

	memset(eui64, 0, sizeof(eui64_buf));
	for (i = 0; i < sizeof(ns->eui64); i++)
		eui64 += sprintf(eui64, "%02x", ns->eui64[i]);

	memset(nguid, 0, sizeof(nguid_buf));
	for (i = 0; i < sizeof(ns->nguid); i++)
		nguid += sprintf(nguid, "%02x", ns->nguid[i]);

	json_object_add_value_string(root, "eui64", eui64_buf);
	json_object_add_value_string(root, "nguid", nguid_buf);

	lbafs = json_create_array();
	json_object_add_value_array(root, "lbafs", lbafs);

	for (i = 0; i <= ns->nlbaf; i++) {
		struct json_object *lbaf = json_create_object();

		json_object_add_value_int(lbaf, "ms", le16_to_cpu(ns->lbaf[i].ms));
		json_object_add_value_int(lbaf, "ds", le16_to_cpu(ns->lbaf[i].ds));
		json_object_add_value_int(lbaf, "rp", le16_to_cpu(ns->lbaf[i].rp));

		json_array_add_value_object(lbafs, lbaf);
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode, void (*vs)(__u8 *vs, struct json_object *root))
{
	struct json_object *root;
	struct json_array *psds;

	long double tnvmcap = int128_to_double(ctrl->tnvmcap);
	long double unvmcap = int128_to_double(ctrl->unvmcap);

	char sn[sizeof(ctrl->sn) + 1], mn[sizeof(ctrl->mn) + 1],
		fr[sizeof(ctrl->fr) + 1], subnqn[sizeof(ctrl->subnqn) + 1];
	__u32 ieee = ctrl->ieee[2] << 16 | ctrl->ieee[1] << 8 | ctrl->ieee[0];

	int i;

	snprintf(sn, sizeof(sn), "%-.*s", (int)sizeof(ctrl->sn), ctrl->sn);
	snprintf(mn, sizeof(mn), "%-.*s", (int)sizeof(ctrl->mn), ctrl->mn);
	snprintf(fr, sizeof(fr), "%-.*s", (int)sizeof(ctrl->fr), ctrl->fr);
	snprintf(subnqn, sizeof(subnqn), "%-.*s", (int)sizeof(ctrl->subnqn), ctrl->subnqn);

	root = json_create_object();

	json_object_add_value_int(root, "vid", le16_to_cpu(ctrl->vid));
	json_object_add_value_int(root, "ssvid", le16_to_cpu(ctrl->ssvid));
	json_object_add_value_string(root, "sn", sn);
	json_object_add_value_string(root, "mn", mn);
	json_object_add_value_string(root, "fr", fr);
	json_object_add_value_int(root, "rab", ctrl->rab);
	json_object_add_value_int(root, "ieee", ieee);
	json_object_add_value_int(root, "cmic", ctrl->cmic);
	json_object_add_value_int(root, "mdts", ctrl->mdts);
	json_object_add_value_int(root, "cntlid", le16_to_cpu(ctrl->cntlid));
	json_object_add_value_uint(root, "ver", le32_to_cpu(ctrl->ver));
	json_object_add_value_uint(root, "rtd3r", le32_to_cpu(ctrl->rtd3r));
	json_object_add_value_uint(root, "rtd3e", le32_to_cpu(ctrl->rtd3e));
	json_object_add_value_uint(root, "oaes", le32_to_cpu(ctrl->oaes));
	json_object_add_value_int(root, "ctratt", le32_to_cpu(ctrl->ctratt));
	json_object_add_value_int(root, "rrls", le16_to_cpu(ctrl->rrls));
	json_object_add_value_int(root, "oacs", le16_to_cpu(ctrl->oacs));
	json_object_add_value_int(root, "acl", ctrl->acl);
	json_object_add_value_int(root, "aerl", ctrl->aerl);
	json_object_add_value_int(root, "frmw", ctrl->frmw);
	json_object_add_value_int(root, "lpa", ctrl->lpa);
	json_object_add_value_int(root, "elpe", ctrl->elpe);
	json_object_add_value_int(root, "npss", ctrl->npss);
	json_object_add_value_int(root, "avscc", ctrl->avscc);
	json_object_add_value_int(root, "apsta", ctrl->apsta);
	json_object_add_value_int(root, "wctemp", le16_to_cpu(ctrl->wctemp));
	json_object_add_value_int(root, "cctemp", le16_to_cpu(ctrl->cctemp));
	json_object_add_value_int(root, "mtfa", le16_to_cpu(ctrl->mtfa));
	json_object_add_value_uint(root, "hmpre", le32_to_cpu(ctrl->hmpre));
	json_object_add_value_uint(root, "hmmin", le32_to_cpu(ctrl->hmmin));
	json_object_add_value_float(root, "tnvmcap", tnvmcap);
	json_object_add_value_float(root, "unvmcap", unvmcap);
	json_object_add_value_uint(root, "rpmbs", le32_to_cpu(ctrl->rpmbs));
	json_object_add_value_int(root, "edstt", le16_to_cpu(ctrl->edstt));
	json_object_add_value_int(root, "dsto", ctrl->dsto);
	json_object_add_value_int(root, "fwug", ctrl->fwug);
	json_object_add_value_int(root, "kas", le16_to_cpu(ctrl->kas));
	json_object_add_value_int(root, "hctma", le16_to_cpu(ctrl->hctma));
	json_object_add_value_int(root, "mntmt", le16_to_cpu(ctrl->mntmt));
	json_object_add_value_int(root, "mxtmt", le16_to_cpu(ctrl->mxtmt));
	json_object_add_value_int(root, "sanicap", le32_to_cpu(ctrl->sanicap));
	json_object_add_value_int(root, "hmminds", le32_to_cpu(ctrl->hmminds));
	json_object_add_value_int(root, "hmmaxd", le16_to_cpu(ctrl->hmmaxd));
	json_object_add_value_int(root, "nsetidmax", le16_to_cpu(ctrl->nsetidmax));

	json_object_add_value_int(root, "anatt",ctrl->anatt);
	json_object_add_value_int(root, "anacap", ctrl->anacap);
	json_object_add_value_int(root, "anagrpmax", le32_to_cpu(ctrl->anagrpmax));
	json_object_add_value_int(root, "nanagrpid", le32_to_cpu(ctrl->nanagrpid));
	json_object_add_value_int(root, "sqes", ctrl->sqes);
	json_object_add_value_int(root, "cqes", ctrl->cqes);
	json_object_add_value_int(root, "maxcmd", le16_to_cpu(ctrl->maxcmd));
	json_object_add_value_uint(root, "nn", le32_to_cpu(ctrl->nn));
	json_object_add_value_int(root, "oncs", le16_to_cpu(ctrl->oncs));
	json_object_add_value_int(root, "fuses", le16_to_cpu(ctrl->fuses));
	json_object_add_value_int(root, "fna", ctrl->fna);
	json_object_add_value_int(root, "vwc", ctrl->vwc);
	json_object_add_value_int(root, "awun", le16_to_cpu(ctrl->awun));
	json_object_add_value_int(root, "awupf", le16_to_cpu(ctrl->awupf));
	json_object_add_value_int(root, "nvscc", ctrl->nvscc);
	json_object_add_value_int(root, "nwpc", ctrl->nwpc);
	json_object_add_value_int(root, "acwu", le16_to_cpu(ctrl->acwu));
	json_object_add_value_int(root, "sgls", le32_to_cpu(ctrl->sgls));

	if (strlen(subnqn))
		json_object_add_value_string(root, "subnqn", subnqn);

	json_object_add_value_int(root, "ioccsz", le32_to_cpu(ctrl->ioccsz));
	json_object_add_value_int(root, "iorcsz", le32_to_cpu(ctrl->iorcsz));
	json_object_add_value_int(root, "icdoff", le16_to_cpu(ctrl->icdoff));
	json_object_add_value_int(root, "ctrattr", ctrl->ctrattr);
	json_object_add_value_int(root, "msdbd", ctrl->msdbd);

	psds = json_create_array();
	json_object_add_value_array(root, "psds", psds);

	for (i = 0; i <= ctrl->npss; i++) {
		struct json_object *psd = json_create_object();

		json_object_add_value_int(psd, "max_power",
			le16_to_cpu(ctrl->psd[i].max_power));
		json_object_add_value_int(psd, "flags", ctrl->psd[i].flags);
		json_object_add_value_uint(psd, "entry_lat",
			le32_to_cpu(ctrl->psd[i].entry_lat));
		json_object_add_value_uint(psd, "exit_lat",
			le32_to_cpu(ctrl->psd[i].exit_lat));
		json_object_add_value_int(psd, "read_tput", ctrl->psd[i].read_tput);
		json_object_add_value_int(psd, "read_lat", ctrl->psd[i].read_lat);
		json_object_add_value_int(psd, "write_tput", ctrl->psd[i].write_tput);
		json_object_add_value_int(psd, "write_lat", ctrl->psd[i].write_lat);
		json_object_add_value_int(psd, "idle_power",
			le16_to_cpu(ctrl->psd[i].idle_power));
		json_object_add_value_int(psd, "idle_scale", ctrl->psd[i].idle_scale);
		json_object_add_value_int(psd, "active_power",
			le16_to_cpu(ctrl->psd[i].active_power));
		json_object_add_value_int(psd, "active_work_scale", ctrl->psd[i].active_work_scale);

		json_array_add_value_object(psds, psd);
	}

	if(vs)
		vs(ctrl->vs, root);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_error_log(struct nvme_error_log_page *err_log, int entries, const char *devname)
{
	struct json_object *root;
	struct json_array *errors;

	int i;

	root = json_create_object();

	errors = json_create_array();
	json_object_add_value_array(root, "errors", errors);

	for (i = 0; i < entries; i++) {
		struct json_object *error = json_create_object();

		json_object_add_value_uint(error, "error_count", err_log[i].error_count);
		json_object_add_value_int(error, "sqid", err_log[i].sqid);
		json_object_add_value_int(error, "cmdid", err_log[i].cmdid);
		json_object_add_value_int(error, "status_field", err_log[i].status_field);
		json_object_add_value_int(error, "parm_error_location", err_log[i].parm_error_location);
		json_object_add_value_uint(error, "lba", err_log[i].lba);
		json_object_add_value_uint(error, "nsid", err_log[i].nsid);
		json_object_add_value_int(error, "vs", err_log[i].vs);
		json_object_add_value_uint(error, "cs", err_log[i].cs);

		json_array_add_value_object(errors, error);
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_nvme_resv_report(struct nvme_reservation_status *status, int bytes, __u32 cdw11)
{
	struct json_object *root;
	struct json_array *rcs;
	int i, j, regctl, entries;

	regctl = status->regctl[0] | (status->regctl[1] << 8);

	root = json_create_object();

	json_object_add_value_int(root, "gen", le32_to_cpu(status->gen));
	json_object_add_value_int(root, "rtype", status->rtype);
	json_object_add_value_int(root, "regctl", regctl);
	json_object_add_value_int(root, "ptpls", status->ptpls);

	rcs = json_create_array();
        /* check Extended Data Structure bit */
        if ((cdw11 & 0x1) == 0) {
                /* if status buffer was too small, don't loop past the end of the buffer */
                entries = (bytes - 24) / 24;
                if (entries < regctl)
                        regctl = entries;

		json_object_add_value_array(root, "regctls", rcs);
		for (i = 0; i < regctl; i++) {
			struct json_object *rc = json_create_object();

			json_object_add_value_int(rc, "cntlid", le16_to_cpu(status->regctl_ds[i].cntlid));
			json_object_add_value_int(rc, "rcsts", status->regctl_ds[i].rcsts);
			json_object_add_value_uint(rc, "hostid", (uint64_t)le64_to_cpu(status->regctl_ds[i].hostid));
			json_object_add_value_uint(rc, "rkey", (uint64_t)le64_to_cpu(status->regctl_ds[i].rkey));

			json_array_add_value_object(rcs, rc);
		}
	} else {
		struct nvme_reservation_status_ext *ext_status = (struct nvme_reservation_status_ext *)status;
		char	hostid[33];

                /* if status buffer was too small, don't loop past the end of the buffer */
                entries = (bytes - 64) / 64;
                if (entries < regctl)
                        regctl = entries;

		json_object_add_value_array(root, "regctlext", rcs);
		for (i = 0; i < regctl; i++) {
			struct json_object *rc = json_create_object();

			json_object_add_value_int(rc, "cntlid", le16_to_cpu(ext_status->regctl_eds[i].cntlid));
			json_object_add_value_int(rc, "rcsts", ext_status->regctl_eds[i].rcsts);
			json_object_add_value_uint(rc, "rkey", (uint64_t)le64_to_cpu(ext_status->regctl_eds[i].rkey));
			for (j = 0; j < 16; j++)
				sprintf(hostid + j * 2, "%02x", ext_status->regctl_eds[i].hostid[j]);

			json_object_add_value_string(rc, "hostid", hostid);

			json_array_add_value_object(rcs, rc);
		}
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_fw_log(struct nvme_firmware_log_page *fw_log, const char *devname)
{
	struct json_object *root;
	struct json_object *fwsi;
	char fmt[21];
	char str[32];
	int i;

	root = json_create_object();
	fwsi = json_create_object();

	json_object_add_value_int(fwsi, "Active Firmware Slot (afi)", fw_log->afi);

	for (i = 0; i < 7; i++) {
		if (fw_log->frs[i]) {
			snprintf(fmt, sizeof(fmt), "Firmware Rev Slot %d", i+1);
			snprintf(str, sizeof(str), "%"PRIu64" (%s)", (uint64_t)fw_log->frs[i],
			fw_to_string(fw_log->frs[i]));
			json_object_add_value_string(fwsi, fmt, str);
		}
	}
	json_object_add_value_object(root, devname, fwsi);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_changed_ns_list_log(struct nvme_changed_ns_list_log *log, const char *devname)
{
	struct json_object *root;
	struct json_object *nsi;
	char fmt[32];
	char str[32];
	__u32 nsid;
	int i;

	if (log->log[0] == cpu_to_le32(0XFFFFFFFF))
		return;

	root = json_create_object();
	nsi = json_create_object();

	json_object_add_value_string(root, "Changed Namespace List Log", devname);

	for (i = 0; i < NVME_MAX_CHANGED_NAMESPACES; i++) {
		nsid = le32_to_cpu(log->log[i]);

		if (nsid == 0)
			break;

		snprintf(fmt, sizeof(fmt), "[%4u]", i + 1);
		snprintf(str, sizeof(str), "%#x", nsid);
		json_object_add_value_string(nsi, fmt, str);
	}

	json_object_add_value_object(root, devname, nsi);
	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
}

void json_endurance_log(struct nvme_endurance_group_log *endurance_group,
			__u16 group_id, const char *devname)
{
	struct json_object *root;

	long double endurance_estimate= int128_to_double(endurance_group->endurance_estimate);
	long double data_units_read= int128_to_double(endurance_group->data_units_read);
	long double data_units_written= int128_to_double(endurance_group->data_units_written);
	long double media_units_written= int128_to_double(endurance_group->media_units_written);

	root = json_create_object();

	json_object_add_value_int(root, "avl_spare_threshold", endurance_group->avl_spare_threshold);
	json_object_add_value_int(root, "percent_used", endurance_group->percent_used);
	json_object_add_value_float(root, "endurance_estimate", endurance_estimate);
	json_object_add_value_float(root, "data_units_read", data_units_read);
	json_object_add_value_float(root, "data_units_written", data_units_written);
	json_object_add_value_float(root, "mediate_write_commands", media_units_written);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_smart_log(struct nvme_smart_log *smart, unsigned int nsid, const char *devname)
{
	struct json_object *root;
	int c;
	char key[21];

	unsigned int temperature = ((smart->temperature[1] << 8) |
		smart->temperature[0]);

	long double data_units_read = int128_to_double(smart->data_units_read);
	long double data_units_written = int128_to_double(smart->data_units_written);
	long double host_read_commands = int128_to_double(smart->host_reads);
	long double host_write_commands = int128_to_double(smart->host_writes);
	long double controller_busy_time = int128_to_double(smart->ctrl_busy_time);
	long double power_cycles = int128_to_double(smart->power_cycles);
	long double power_on_hours = int128_to_double(smart->power_on_hours);
	long double unsafe_shutdowns = int128_to_double(smart->unsafe_shutdowns);
	long double media_errors = int128_to_double(smart->media_errors);
	long double num_err_log_entries = int128_to_double(smart->num_err_log_entries);

	root = json_create_object();

	json_object_add_value_int(root, "critical_warning", smart->critical_warning);
	json_object_add_value_int(root, "temperature", temperature);
	json_object_add_value_int(root, "avail_spare", smart->avail_spare);
	json_object_add_value_int(root, "spare_thresh", smart->spare_thresh);
	json_object_add_value_int(root, "percent_used", smart->percent_used);
	json_object_add_value_float(root, "data_units_read", data_units_read);
	json_object_add_value_float(root, "data_units_written", data_units_written);
	json_object_add_value_float(root, "host_read_commands", host_read_commands);
	json_object_add_value_float(root, "host_write_commands", host_write_commands);
	json_object_add_value_float(root, "controller_busy_time", controller_busy_time);
	json_object_add_value_float(root, "power_cycles", power_cycles);
	json_object_add_value_float(root, "power_on_hours", power_on_hours);
	json_object_add_value_float(root, "unsafe_shutdowns", unsafe_shutdowns);
	json_object_add_value_float(root, "media_errors", media_errors);
	json_object_add_value_float(root, "num_err_log_entries", num_err_log_entries);
	json_object_add_value_uint(root, "warning_temp_time",
			le32_to_cpu(smart->warning_temp_time));
	json_object_add_value_uint(root, "critical_comp_time",
			le32_to_cpu(smart->critical_comp_time));

	for (c=0; c < 8; c++) {
		__s32 temp = le16_to_cpu(smart->temp_sensor[c]);

		if (temp == 0)
			continue;
		sprintf(key, "temperature_sensor_%d",c+1);
		json_object_add_value_int(root, key, temp);
	}

	json_object_add_value_uint(root, "thm_temp1_trans_count",
			le32_to_cpu(smart->thm_temp1_trans_count));
	json_object_add_value_uint(root, "thm_temp2_trans_count",
			le32_to_cpu(smart->thm_temp2_trans_count));
	json_object_add_value_uint(root, "thm_temp1_total_time",
			le32_to_cpu(smart->thm_temp1_total_time));
	json_object_add_value_uint(root, "thm_temp2_total_time",
			le32_to_cpu(smart->thm_temp2_total_time));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_ana_log(struct nvme_ana_rsp_hdr *ana_log, const char *devname)
{
	int offset = sizeof(struct nvme_ana_rsp_hdr);
	struct nvme_ana_rsp_hdr *hdr = ana_log;
	struct nvme_ana_group_desc *ana_desc;
	struct json_array *desc_list;
	struct json_array *ns_list;
	struct json_object *desc;
	struct json_object *nsid;
	struct json_object *root;
	size_t nsid_buf_size;
	void *base = ana_log;
	__u32 nr_nsids;
	int i;
	int j;

	root = json_create_object();
	json_object_add_value_string(root,
			"Asynchronous Namespace Access Log for NVMe device:",
			devname);
	json_object_add_value_uint(root, "chgcnt",
			(uint64_t)le64_to_cpu(hdr->chgcnt));
	json_object_add_value_uint(root, "ngrps", le16_to_cpu(hdr->ngrps));

	desc_list = json_create_array();
	for (i = 0; i < le16_to_cpu(ana_log->ngrps); i++) {
		desc = json_create_object();
		ana_desc = base + offset;
		nr_nsids = le32_to_cpu(ana_desc->nnsids);
		nsid_buf_size = nr_nsids * sizeof(__le32);

		offset += sizeof(*ana_desc);
		json_object_add_value_uint(desc, "grpid",
				le32_to_cpu(ana_desc->grpid));
		json_object_add_value_uint(desc, "nnsids",
				le32_to_cpu(ana_desc->nnsids));
		json_object_add_value_uint(desc, "chgcnt",
				le64_to_cpu(ana_desc->chgcnt));
		json_object_add_value_string(desc, "state",
				nvme_ana_state_to_string(ana_desc->state));

		ns_list = json_create_array();
		for (j = 0; j < le32_to_cpu(ana_desc->nnsids); j++) {
			nsid = json_create_object();
			json_object_add_value_uint(nsid, "nsid",
					le32_to_cpu(ana_desc->nsids[j]));
			json_array_add_value_object(ns_list, nsid);
		}
		json_object_add_value_array(desc, "NSIDS", ns_list);
		offset += nsid_buf_size;
		json_array_add_value_object(desc_list, desc);
	}

	json_object_add_value_array(root, "ANA DESC LIST ", desc_list);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_self_test_log(struct nvme_self_test_log *self_test, const char *devname)
{
	struct json_object *root;
	struct json_array *valid;
	struct json_object *valid_attrs;
	int i;

	root = json_create_object();
	json_object_add_value_int(root, "Current Device Self-Test Operation", self_test->crnt_dev_selftest_oprn);
	json_object_add_value_int(root, "Current Device Self-Test Completion", self_test->crnt_dev_selftest_compln);
	valid = json_create_array();

	for (i=0; i < NVME_SELF_TEST_REPORTS; i++) {
		if ((self_test->result[i].device_self_test_status & 0xf) == 0xf)
			continue;
		valid_attrs = json_create_object();
		json_object_add_value_int(valid_attrs, "Self test result", self_test->result[i].device_self_test_status & 0xf);
		json_object_add_value_int(valid_attrs, "Self test code", self_test->result[i].device_self_test_status >> 4);
		json_object_add_value_int(valid_attrs, "Segment number", self_test->result[i].segment_num);
		json_object_add_value_int(valid_attrs, "Valid Diagnostic Information", self_test->result[i].valid_diagnostic_info);
		json_object_add_value_uint(valid_attrs, "Power on hours (POH)",le64_to_cpu(self_test->result[i].power_on_hours));
		if (self_test->result[i].valid_diagnostic_info & NVME_SELF_TEST_VALID_NSID)
			json_object_add_value_int(valid_attrs, "Namespace Identifier (NSID)", le32_to_cpu(self_test->result[i].nsid));
		if (self_test->result[i].valid_diagnostic_info & NVME_SELF_TEST_VALID_FLBA)
			json_object_add_value_uint(valid_attrs, "Failing LBA",(uint64_t)le64_to_cpu(self_test->result[i].failing_lba));
		if (self_test->result[i].valid_diagnostic_info & NVME_SELF_TEST_VALID_SCT)
			json_object_add_value_int(valid_attrs, "Status Code Type",self_test->result[i].status_code_type);
		if(self_test->result[i].valid_diagnostic_info & NVME_SELF_TEST_VALID_SC)
			json_object_add_value_int(valid_attrs, "Status Code",self_test->result[i].status_code);
		json_object_add_value_int(valid_attrs, "Vendor Specific",(self_test->result[i].vendor_specific[1] << 8) |
			(self_test->result[i].vendor_specific[0]));
		json_array_add_value_object(valid, valid_attrs);
	}
	json_object_add_value_array(root, "List of Valid Reports", valid);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_effects_log(struct nvme_effects_log_page *effects_log, const char *devname)
{
	struct json_object *root;
	unsigned int opcode;
	char key[128];
	__u32 effect;

	root = json_create_object();

	for (opcode = 0; opcode < 256; opcode++) {
		sprintf(key, "ACS%d (%s)", opcode, nvme_cmd_to_string(1, opcode));
		effect = le32_to_cpu(effects_log->acs[opcode]);
		json_object_add_value_uint(root, key, effect);
	}

	for (opcode = 0; opcode < 256; opcode++) {
		sprintf(key, "IOCS%d (%s)", opcode, nvme_cmd_to_string(0, opcode));
		effect = le32_to_cpu(effects_log->iocs[opcode]);
		json_object_add_value_uint(root, key, effect);
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_sanitize_log(struct nvme_sanitize_log_page *sanitize_log, const char *devname)
{
	struct json_object *root;
	struct json_object *dev;
	struct json_object *sstat;
	const char *status_str;
	char str[128];
	__u16 status = le16_to_cpu(sanitize_log->status);

	root = json_create_object();
	dev = json_create_object();
	sstat = json_create_object();

	json_object_add_value_int(dev, "sprog", le16_to_cpu(sanitize_log->progress));
	json_object_add_value_int(sstat, "global_erased",
			(status & NVME_SANITIZE_LOG_GLOBAL_DATA_ERASED) >> 8);
	json_object_add_value_int(sstat, "no_cmplted_passes",
			(status & NVME_SANITIZE_LOG_NUM_CMPLTED_PASS_MASK) >> 3);

	status_str = get_sanitize_log_sstat_status_str(status);
	sprintf(str, "(%d) %s", status & NVME_SANITIZE_LOG_STATUS_MASK, status_str);
	json_object_add_value_string(sstat, "status", str);

	json_object_add_value_object(dev, "sstat", sstat);
	json_object_add_value_uint(dev, "cdw10_info", le32_to_cpu(sanitize_log->cdw10_info));
	json_object_add_value_uint(dev, "time_over_write", le32_to_cpu(sanitize_log->est_ovrwrt_time));
	json_object_add_value_uint(dev, "time_block_erase", le32_to_cpu(sanitize_log->est_blk_erase_time));
	json_object_add_value_uint(dev, "time_crypto_erase", le32_to_cpu(sanitize_log->est_crypto_erase_time));

	json_object_add_value_object(root, devname, dev);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void show_nvme_subsystem(struct subsys_list_item *item)
{
	int i;

	printf("%s - NQN=%s\n", item->name, item->subsysnqn);
	printf("\\\n");

	for (i = 0; i < item->nctrls; i++) {
		printf(" +- %s %s %s %s %s\n", item->ctrls[i].name,
				item->ctrls[i].transport,
				item->ctrls[i].address,
				item->ctrls[i].state,
				item->ctrls[i].ana_state ?
					item->ctrls[i].ana_state : "");
	}

}

void show_nvme_subsystem_list(struct subsys_list_item *slist, int n)
{
	int i;

	for (i = 0; i < n; i++)
		show_nvme_subsystem(&slist[i]);
}
void json_print_nvme_subsystem_list(struct subsys_list_item *slist, int n)
{
	struct json_object *root;
	struct json_array *subsystems;
	struct json_object *subsystem_attrs;
	struct json_array *paths;
	struct json_object *path_attrs;
	struct json_object *path_object;
	int i, j;

	root = json_create_object();
	subsystems = json_create_array();

	for (i = 0; i < n; i++) {
		subsystem_attrs = json_create_object();

		json_object_add_value_string(subsystem_attrs,
					     "Name", slist[i].name);
		json_object_add_value_string(subsystem_attrs,
					     "NQN", slist[i].subsysnqn);

		json_array_add_value_object(subsystems, subsystem_attrs);

		paths = json_create_array();
		path_object = json_create_object();

		for (j = 0; j < slist[i].nctrls; j++) {
			path_attrs = json_create_object();
			json_object_add_value_string(path_attrs, "Name",
					slist[i].ctrls[j].name);
			json_object_add_value_string(path_attrs, "Transport",
					slist[i].ctrls[j].transport);
			json_object_add_value_string(path_attrs, "Address",
					slist[i].ctrls[j].address);
			json_object_add_value_string(path_attrs, "State",
					slist[i].ctrls[j].state);
			if (slist[i].ctrls[j].ana_state)
				json_object_add_value_string(path_attrs,
						"ANAState",
						slist[i].ctrls[j].ana_state);
			json_array_add_value_object(paths, path_attrs);
		}
		if (j) {
			json_object_add_value_array(path_object, "Paths",
					paths);
			json_array_add_value_object(subsystems, path_object);
		}

	}

	if (i)
		json_object_add_value_array(root, "Subsystems", subsystems);
	json_print_object(root, NULL);
	printf("\n");
}

static void show_registers_cap(struct nvme_bar_cap *cap)
{
	printf("\tMemory Page Size Maximum      (MPSMAX): %u bytes\n", 1 <<  (12 + ((cap->mpsmax_mpsmin & 0xf0) >> 4)));
	printf("\tMemory Page Size Minimum      (MPSMIN): %u bytes\n", 1 <<  (12 + (cap->mpsmax_mpsmin & 0x0f)));
	printf("\tBoot Partition Support           (BPS): %s\n", (cap->bps_css_nssrs_dstrd & 0x2000) ? "Yes":"No");
	printf("\tCommand Sets Supported           (CSS): NVM command set is %s\n",
			(cap->bps_css_nssrs_dstrd & 0x0020) ? "supported":"not supported");
	printf("\tNVM Subsystem Reset Supported  (NSSRS): %s\n", (cap->bps_css_nssrs_dstrd & 0x0010) ? "Yes":"No");
	printf("\tDoorbell Stride                (DSTRD): %u bytes\n", 1 << (2 + (cap->bps_css_nssrs_dstrd & 0x000f)));
	printf("\tTimeout                           (TO): %u ms\n", cap->to * 500);
	printf("\tArbitration Mechanism Supported  (AMS): Weighted Round Robin with Urgent Priority Class is %s\n",
			(cap->ams_cqr & 0x02) ? "supported":"not supported");
	printf("\tContiguous Queues Required       (CQR): %s\n", (cap->ams_cqr & 0x01) ? "Yes":"No");
	printf("\tMaximum Queue Entries Supported (MQES): %u\n\n", cap->mqes + 1);
}

static void show_registers_version(__u32 vs)
{
	printf("\tNVMe specification %d.%d\n\n", (vs & 0xffff0000) >> 16,  (vs & 0x0000ff00) >> 8);
}

static void show_registers_cc_ams (__u8 ams)
{
	printf("\tArbitration Mechanism Selected     (AMS): ");
	switch (ams) {
	case 0:
		printf("Round Robin\n");
		break;
	case 1:
		printf("Weighted Round Robin with Urgent Priority Class\n");
		break;
	case 7:
		printf("Vendor Specific\n");
		break;
	default:
		printf("Reserved\n");
	}
}

static void show_registers_cc_shn (__u8 shn)
{
	printf("\tShutdown Notification              (SHN): ");
	switch (shn) {
	case 0:
		printf("No notification; no effect\n");
		break;
	case 1:
		printf("Normal shutdown notification\n");
		break;
	case 2:
		printf("Abrupt shutdown notification\n");
		break;
	default:
		printf("Reserved\n");
	}
}

static void show_registers_cc(__u32 cc)
{
	printf("\tI/O Completion Queue Entry Size (IOCQES): %u bytes\n", 1 << ((cc & 0x00f00000) >> NVME_CC_IOCQES_SHIFT));
	printf("\tI/O Submission Queue Entry Size (IOSQES): %u bytes\n", 1 << ((cc & 0x000f0000) >> NVME_CC_IOSQES_SHIFT));
	show_registers_cc_shn((cc & 0x0000c000) >> NVME_CC_SHN_SHIFT);
	show_registers_cc_ams((cc & 0x00003800) >> NVME_CC_AMS_SHIFT);
	printf("\tMemory Page Size                   (MPS): %u bytes\n", 1 << (12 + ((cc & 0x00000780) >> NVME_CC_MPS_SHIFT)));
	printf("\tI/O Command Sets Selected          (CSS): %s\n", (cc & 0x00000070) ? "Reserved":"NVM Command Set");
	printf("\tEnable                              (EN): %s\n\n", (cc & 0x00000001) ? "Yes":"No");
}

static void show_registers_csts_shst(__u8 shst)
{
	printf("\tShutdown Status               (SHST): ");
	switch (shst) {
	case 0:
		printf("Normal operation (no shutdown has been requested)\n");
		break;
	case 1:
		printf("Shutdown processing occurring\n");
		break;
	case 2:
		printf("Shutdown processing complete\n");
		break;
	default:
		printf("Reserved\n");
	}
}

static void show_registers_csts(__u32 csts)
{
	printf("\tProcessing Paused               (PP): %s\n", (csts & 0x00000020) ? "Yes":"No");
	printf("\tNVM Subsystem Reset Occurred (NSSRO): %s\n", (csts & 0x00000010) ? "Yes":"No");
	show_registers_csts_shst((csts & 0x0000000c) >> 2);
	printf("\tController Fatal Status        (CFS): %s\n", (csts & 0x00000002) ? "True":"False");
	printf("\tReady                          (RDY): %s\n\n", (csts & 0x00000001) ? "Yes":"No");

}

static void show_registers_aqa(__u32 aqa)
{
	printf("\tAdmin Completion Queue Size (ACQS): %u\n", ((aqa & 0x0fff0000) >> 16)+1);
	printf("\tAdmin Submission Queue Size (ASQS): %u\n\n", (aqa & 0x00000fff)+1);

}

static void show_registers_cmbloc(__u32 cmbloc, __u32 cmbsz)
{
	if (cmbsz == 0) {
		printf("\tController Memory Buffer feature is not supported\n\n");
	}
	else {
		printf("\tOffset                 (OFST): %x (See cmbsz.szu for granularity)\n",
			(cmbloc & 0xfffff000) >> 12);
		printf("\tBase Indicator Register (BIR): %x\n\n", cmbloc & 0x00000007 );
	}
}

static char *nvme_register_szu_to_string(__u8 szu)
{
	switch (szu) {
	case 0:	return "4 KB";
	case 1:	return "64 KB";
	case 2:	return "1 MB";
	case 3:	return "16 MB";
	case 4:	return "256 MB";
	case 5:	return "4 GB";
	case 6:	return "64 GB";
	default:	return "Reserved";
	}
}

static void show_registers_cmbsz(__u32 cmbsz)
{
	if (cmbsz == 0) {
		printf("\tController Memory Buffer feature is not supported\n\n");
		return;
	}
	printf("\tSize                      (SZ): %u\n", (cmbsz & 0xfffff000) >> 12);
	printf("\tSize Units               (SZU): %s\n", nvme_register_szu_to_string((cmbsz & 0x00000f00) >> 8));
	printf("\tWrite Data Support       (WDS): Write Data and metadata transfer in Controller Memory Buffer is %s\n",
			(cmbsz & 0x00000010) ? "Supported":"Not supported");
	printf("\tRead Data Support        (RDS): Read Data and metadata transfer in Controller Memory Buffer is %s\n",
			(cmbsz & 0x00000008) ? "Supported":"Not supported");
	printf("\tPRP SGL List Support   (LISTS): PRP/SG Lists in Controller Memory Buffer is %s\n",
			(cmbsz & 0x00000004) ? "Supported":"Not supported");
	printf("\tCompletion Queue Support (CQS): Admin and I/O Completion Queues in Controller Memory Buffer is %s\n",
			(cmbsz & 0x00000002) ? "Supported":"Not supported");
	printf("\tSubmission Queue Support (SQS): Admin and I/O Submission Queues in Controller Memory Buffer is %s\n\n",
			(cmbsz & 0x00000001) ? "Supported":"Not supported");
}

static void show_registers_bpinfo_brs(__u8 brs)
{
	printf("\tBoot Read Status                (BRS): ");
	switch (brs) {
	case 0:
		printf("No Boot Partition read operation requested\n");
		break;
	case 1:
		printf("Boot Partition read in progress\n");
		break;
	case 2:
		printf("Boot Partition read completed successfully\n");
		break;
	case 3:
		printf("Error completing Boot Partition read\n");
		break;
	default:
		printf("Invalid\n");
	}
}

static void show_registers_bpinfo(__u32 bpinfo)
{
	if (bpinfo == 0) {
		printf("\tBoot Partition feature is not supported\n\n");
		return;
	}

	printf("\tActive Boot Partition ID      (ABPID): %u\n", (bpinfo & 0x80000000) >> 31);
	show_registers_bpinfo_brs((bpinfo & 0x03000000) >> 24);
	printf("\tBoot Partition Size            (BPSZ): %u\n", bpinfo & 0x00007fff);
}

static void show_registers_bprsel(__u32 bprsel)
{
	if (bprsel == 0) {
		printf("\tBoot Partition feature is not supported\n\n");
		return;
	}

	printf("\tBoot Partition Identifier      (BPID): %u\n", (bprsel & 0x80000000) >> 31);
	printf("\tBoot Partition Read Offset    (BPROF): %x\n", (bprsel & 0x3ffffc00) >> 10);
	printf("\tBoot Partition Read Size      (BPRSZ): %x\n", bprsel & 0x000003ff);
}

static void show_registers_bpmbl(uint64_t bpmbl)
{
	if (bpmbl == 0) {
		printf("\tBoot Partition feature is not supported\n\n");
		return;
	}

	printf("\tBoot Partition Memory Buffer Base Address (BMBBA): %"PRIx64"\n", bpmbl);
}

static inline uint32_t mmio_read32(void *addr)
{
	__le32 *p = addr;

	return le32_to_cpu(*p);
}

/* Access 64-bit registers as 2 32-bit; Some devices fail 64-bit MMIO. */
static inline __u64 mmio_read64(void *addr)
{
	__le32 *p = addr;

	return le32_to_cpu(*p) | ((uint64_t)le32_to_cpu(*(p + 1)) << 32);
}

void show_ctrl_registers(void *bar, unsigned int mode, bool fabrics)
{
	uint64_t cap, asq, acq, bpmbl;
	uint32_t vs, intms, intmc, cc, csts, nssr, aqa, cmbsz, cmbloc, bpinfo, bprsel;

	int human = mode & HUMAN;

	cap = mmio_read64(bar + NVME_REG_CAP);
	vs = mmio_read32(bar + NVME_REG_VS);
	intms = mmio_read32(bar + NVME_REG_INTMS);
	intmc = mmio_read32(bar + NVME_REG_INTMC);
	cc = mmio_read32(bar + NVME_REG_CC);
	csts = mmio_read32(bar + NVME_REG_CSTS);
	nssr = mmio_read32(bar + NVME_REG_NSSR);
	aqa = mmio_read32(bar + NVME_REG_AQA);
	asq = mmio_read64(bar + NVME_REG_ASQ);
	acq = mmio_read64(bar + NVME_REG_ACQ);
	cmbloc = mmio_read32(bar + NVME_REG_CMBLOC);
	cmbsz = mmio_read32(bar + NVME_REG_CMBSZ);
	bpinfo = mmio_read32(bar + NVME_REG_BPINFO);
	bprsel = mmio_read32(bar + NVME_REG_BPRSEL);
	bpmbl = mmio_read64(bar + NVME_REG_BPMBL);

	if (human) {
		if (cap != 0xffffffff) {
			printf("cap     : %"PRIx64"\n", cap);
			show_registers_cap((struct nvme_bar_cap *)&cap);
		}
		if (vs != 0xffffffff) {
			printf("version : %x\n", vs);
			show_registers_version(vs);
		}
		if (cc != 0xffffffff) {
			printf("cc      : %x\n", cc);
			show_registers_cc(cc);
		}
		if (csts != 0xffffffff) {
			printf("csts    : %x\n", csts);
			show_registers_csts(csts);
		}
		if (nssr != 0xffffffff) {
			printf("nssr    : %x\n", nssr);
			printf("\tNVM Subsystem Reset Control (NSSRC): %u\n\n", nssr);
		}
		if (!fabrics) {
			printf("intms   : %x\n", intms);
			printf("\tInterrupt Vector Mask Set (IVMS): %x\n\n",
					intms);

			printf("intmc   : %x\n", intmc);
			printf("\tInterrupt Vector Mask Clear (IVMC): %x\n\n",
					intmc);
			printf("aqa     : %x\n", aqa);
			show_registers_aqa(aqa);

			printf("asq     : %"PRIx64"\n", asq);
			printf("\tAdmin Submission Queue Base (ASQB): %"PRIx64"\n\n",
					asq);

			printf("acq     : %"PRIx64"\n", acq);
			printf("\tAdmin Completion Queue Base (ACQB): %"PRIx64"\n\n",
					acq);

			printf("cmbloc  : %x\n", cmbloc);
			show_registers_cmbloc(cmbloc, cmbsz);

			printf("cmbsz   : %x\n", cmbsz);
			show_registers_cmbsz(cmbsz);

			printf("bpinfo  : %x\n", bpinfo);
			show_registers_bpinfo(bpinfo);

			printf("bprsel  : %x\n", bprsel);
			show_registers_bprsel(bprsel);

			printf("bpmbl   : %"PRIx64"\n", bpmbl);
			show_registers_bpmbl(bpmbl);
		}
	} else {
		if (cap != 0xffffffff)
			printf("cap     : %"PRIx64"\n", cap);
		if (vs != 0xffffffff)
			printf("version : %x\n", vs);
		if (cc != 0xffffffff)
			printf("cc      : %x\n", cc);
		if (csts != 0xffffffff)
			printf("csts    : %x\n", csts);
		if (nssr != 0xffffffff)
			printf("nssr    : %x\n", nssr);
		if (!fabrics) {
			printf("intms   : %x\n", intms);
			printf("intmc   : %x\n", intmc);
			printf("aqa     : %x\n", aqa);
			printf("asq     : %"PRIx64"\n", asq);
			printf("acq     : %"PRIx64"\n", acq);
			printf("cmbloc  : %x\n", cmbloc);
			printf("cmbsz   : %x\n", cmbsz);
			printf("bpinfo  : %x\n", bpinfo);
			printf("bprsel  : %x\n", bprsel);
			printf("bpmbl   : %"PRIx64"\n", bpmbl);
		}
	}
}

void show_single_property(int offset, uint64_t value64, int human)
{
	uint32_t value32;

	if (!human) {
		printf("property: 0x%02x (%s), value: %"PRIx64"\n", offset,
			   nvme_register_to_string(offset), value64);
		return;
	}

	value32 = (uint32_t) value64;

	switch (offset) {
	case NVME_REG_CAP:
		printf("cap : %"PRIx64"\n", value64);
		show_registers_cap((struct nvme_bar_cap *)&value64);
		break;

	case NVME_REG_VS:
		printf("version : %x\n", value32);
		show_registers_version(value32);
		break;

	case NVME_REG_CC:
		printf("cc : %x\n", value32);
		show_registers_cc(value32);
		break;

	case NVME_REG_CSTS:
		printf("csts : %x\n", value32);
		show_registers_csts(value32);
		break;

	case NVME_REG_NSSR:
		printf("nssr : %x\n", value32);
		printf("\tNVM Subsystem Reset Control (NSSRC): %u\n\n", value32);
		break;

	default:
		printf("unknown property: 0x%02x (%s), value: %"PRIx64"\n", offset,
			   nvme_register_to_string(offset), value64);
		break;
	}
}
