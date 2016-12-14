#include <endian.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "nvme-print.h"
#include "json.h"
#include "nvme-models.h"

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
	__u8 rsvd = (cmic & 0xF8) >> 3;
	__u8 sriov = (cmic & 0x4) >> 2;
	__u8 mctl = (cmic & 0x2) >> 1;
	__u8 mp = cmic & 0x1;
	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);
	printf("  [2:2] : %#x\t%s\n", sriov, sriov ? "SR-IOV" : "PCI");
	printf("  [1:1] : %#x\t%s Controller\n",
		mctl, mctl ? "Multi" : "Single");
	printf("  [0:0] : %#x\t%s Port\n", mp, mp ? "Multi" : "Single");
	printf("\n");
}

static void show_nvme_id_ctrl_oaes(__le32 ctrl_oaes)
{
	__u32 oaes = le32_to_cpu(ctrl_oaes);
	__u32 rsvd0 = (oaes & 0xFFFFFE00) >> 9;
	__u32 nace = (oaes & 0x100) >> 8;
	__u32 rsvd1 = oaes & 0xFF;

	if (rsvd0)
		printf(" [31:9] : %#x\tReserved\n", rsvd0);
	printf("  [8:8] : %#x\tNamespace Attribute Changed Event %sSupported\n",
		nace, nace ? "" : "Not ");
	if (rsvd1)
		printf("  [7:0] : %#x\tReserved\n", rsvd1);
	printf("\n");
}

static void show_nvme_id_ctrl_oacs(__le16 ctrl_oacs)
{
	__u16 oacs = le16_to_cpu(ctrl_oacs);
	__u16 rsvd = (oacs & 0xFFF0) >> 4;
	__u16 nsm = (oacs & 0x8) >> 3;
	__u16 fwc = (oacs & 0x4) >> 2;
	__u16 fmt = (oacs & 0x2) >> 1;
	__u16 sec = oacs & 0x1;

	if (rsvd)
		printf(" [15:4] : %#x\tReserved\n", rsvd);
	printf("  [3:3] : %#x\tNS Management and Attachment %sSupported\n",
		nsm, nsm ? "" : "Not ");
	printf("  [2:2] : %#x\tFW Commit and Download %sSupported\n",
		fwc, fwc ? "" : "Not ");
	printf("  [1:1] : %#x\tFormat NVM %sSupported\n",
		fmt, fmt ? "" : "Not ");
	printf("  [0:0] : %#x\tSec. Send and Receive %sSupported\n",
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
	__u8 rsvd = (lpa & 0xFC) >> 2;
	__u8 celp = (lpa & 0x2) >> 1;
	__u8 smlp = lpa & 0x1;
	if (rsvd)
		printf("  [7:2] : %#x\tReserved\n", rsvd);
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
	__u32 rpmb = rpmbs & 0x3;

	printf(" [31:24]: %#x\tAccess Size\n", asz);
	printf(" [23:16]: %#x\tTotal Size\n", tsz);
	if (rsvd)
		printf(" [15:6] : %#x\tReserved\n", rsvd);
	printf("  [5:3] : %#x\tAuthentication Method\n", auth);
	printf("  [2:0] : %#x\tNumber of RPMB Units\n", rpmb);
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
	__u16 rsvd = (oncs & 0xFFC0) >> 6;
	__u16 resv = (oncs & 0x20) >> 5;
	__u16 save = (oncs & 0x10) >> 4;
	__u16 wzro = (oncs & 0x8) >> 3;
	__u16 dsms = (oncs & 0x4) >> 2;
	__u16 wunc = (oncs & 0x2) >> 1;
	__u16 cmp = oncs & 0x1;

	if (rsvd)
		printf(" [15:6] : %#x\tReserved\n", rsvd);
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

static void show_nvme_id_ctrl_sgls(__le32 ctrl_sgls)
{
	__u32 sgls = le32_to_cpu(ctrl_sgls);
	__u32 rsvd0 = (sgls & 0xFFF80000) >> 19;
	__u32 sglltb = (sgls & 0x40000) >> 18;
	__u32 bacmdb = (sgls & 0x20000) >> 17;
	__u32 bbs = (sgls & 0x10000) >> 16;
	__u32 rsvd1 = (sgls & 0xFFFE) >> 1;
	__u32 sglsp = sgls & 0x1;

	if (rsvd0)
		printf(" [31:19]: %#x\tReserved\n", rsvd0);
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
		printf(" [15:1] : %#x\tReserved\n", rsvd1);
	printf("  [0:0] : %#x\tScatter-Gather Lists %sSupported\n",
		sglsp, sglsp ? "" : "Not ");
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
		fpii, 100 - fpii);
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
	printf("nawun   : %d\n", le16_to_cpu(ns->nawun));
	printf("nawupf  : %d\n", le16_to_cpu(ns->nawupf));
	printf("nacwu   : %d\n", le16_to_cpu(ns->nacwu));
	printf("nabsn   : %d\n", le16_to_cpu(ns->nabsn));
	printf("nabo    : %d\n", le16_to_cpu(ns->nabo));
	printf("nabspf  : %d\n", le16_to_cpu(ns->nabspf));
	printf("nvmcap  : %.0Lf\n", int128_to_double(ns->nvmcap));

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
		printf("vs[]:");
		d(ns->vs, sizeof(ns->vs), 16, 1);
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

void __show_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode, void (*vendor_show)(__u8 *vs))
{
	int human = mode & HUMAN, vs = mode & VS;

	printf("vid     : %#x\n", le16_to_cpu(ctrl->vid));
	printf("ssvid   : %#x\n", le16_to_cpu(ctrl->ssvid));
	printf("sn      : %-.*s\n", (int)sizeof(ctrl->sn), ctrl->sn);
	printf("mn      : %-.*s\n", (int)sizeof(ctrl->mn), ctrl->mn);
	printf("fr      : %-.*s\n", (int)sizeof(ctrl->fr), ctrl->fr);
	printf("rab     : %d\n", ctrl->rab);
	printf("ieee    : %02x%02x%02x\n",
		ctrl->ieee[2], ctrl->ieee[1], ctrl->ieee[0]);
	printf("cmic    : %#x\n", ctrl->cmic);
	if (human)
		show_nvme_id_ctrl_cmic(ctrl->cmic);
	printf("mdts    : %d\n", ctrl->mdts);
	printf("cntlid  : %x\n", le16_to_cpu(ctrl->cntlid));
	printf("ver     : %x\n", le32_to_cpu(ctrl->ver));
	printf("rtd3r   : %x\n", le32_to_cpu(ctrl->rtd3r));
	printf("rtd3e   : %x\n", le32_to_cpu(ctrl->rtd3e));
	printf("oaes    : %#x\n", le32_to_cpu(ctrl->oaes));
	if (human)
		show_nvme_id_ctrl_oaes(ctrl->oaes);
	printf("oacs    : %#x\n", le16_to_cpu(ctrl->oacs));
	if (human)
		show_nvme_id_ctrl_oacs(ctrl->oacs);
	printf("acl     : %d\n", ctrl->acl);
	printf("aerl    : %d\n", ctrl->aerl);
	printf("frmw    : %#x\n", ctrl->frmw);
	if (human)
		show_nvme_id_ctrl_frmw(ctrl->frmw);
	printf("lpa     : %#x\n", ctrl->lpa);
	if (human)
		show_nvme_id_ctrl_lpa(ctrl->lpa);
	printf("elpe    : %d\n", ctrl->elpe);
	printf("npss    : %d\n", ctrl->npss);
	printf("avscc   : %#x\n", ctrl->avscc);
	if (human)
		show_nvme_id_ctrl_avscc(ctrl->avscc);
	printf("apsta   : %#x\n", ctrl->apsta);
	if (human)
		show_nvme_id_ctrl_apsta(ctrl->apsta);
	printf("wctemp  : %d\n", le16_to_cpu(ctrl->wctemp));
	printf("cctemp  : %d\n", le16_to_cpu(ctrl->cctemp));
	printf("mtfa    : %d\n", le16_to_cpu(ctrl->mtfa));
	printf("hmpre   : %d\n", le32_to_cpu(ctrl->hmpre));
	printf("hmmin   : %d\n", le32_to_cpu(ctrl->hmmin));
	printf("tnvmcap : %.0Lf\n", int128_to_double(ctrl->tnvmcap));
	printf("unvmcap : %.0Lf\n", int128_to_double(ctrl->unvmcap));
	printf("rpmbs   : %#x\n", le32_to_cpu(ctrl->rpmbs));
	if (human)
		show_nvme_id_ctrl_rpmbs(ctrl->rpmbs);
	printf("sqes    : %#x\n", ctrl->sqes);
	if (human)
		show_nvme_id_ctrl_sqes(ctrl->sqes);
	printf("cqes    : %#x\n", ctrl->cqes);
	if (human)
		show_nvme_id_ctrl_cqes(ctrl->cqes);
	printf("nn      : %d\n", le32_to_cpu(ctrl->nn));
	printf("oncs    : %#x\n", le16_to_cpu(ctrl->oncs));
	if (human)
		show_nvme_id_ctrl_oncs(ctrl->oncs);
	printf("fuses   : %#x\n", le16_to_cpu(ctrl->fuses));
	if (human)
		show_nvme_id_ctrl_fuses(ctrl->fuses);
	printf("fna     : %#x\n", ctrl->fna);
	if (human)
		show_nvme_id_ctrl_fna(ctrl->fna);
	printf("vwc     : %#x\n", ctrl->vwc);
	if (human)
		show_nvme_id_ctrl_vwc(ctrl->vwc);
	printf("awun    : %d\n", le16_to_cpu(ctrl->awun));
	printf("awupf   : %d\n", le16_to_cpu(ctrl->awupf));
	printf("nvscc   : %d\n", ctrl->nvscc);
	if (human)
		show_nvme_id_ctrl_nvscc(ctrl->nvscc);
	printf("acwu    : %d\n", le16_to_cpu(ctrl->acwu));
	printf("sgls    : %x\n", le32_to_cpu(ctrl->sgls));
	if (human)
		show_nvme_id_ctrl_sgls(ctrl->sgls);

	printf("subnqn  : %-.*s\n", (int)sizeof(ctrl->subnqn), ctrl->subnqn);

	show_nvme_id_ctrl_power(ctrl);
	if (vendor_show)
		vendor_show(ctrl->vs);
	else if (vs) {
		printf("vs[]:\n");
		d(ctrl->vs, sizeof(ctrl->vs), 16, 1);
	}
}

void show_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode)
{
	__show_nvme_id_ctrl(ctrl, mode, NULL);
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
		printf(".................\n");
	}
}

void show_nvme_resv_report(struct nvme_reservation_status *status)
{
	int i, regctl;

	regctl = status->regctl[0] | (status->regctl[1] << 8);

	printf("\nNVME Reservation status:\n\n");
	printf("gen       : %d\n", le32_to_cpu(status->gen));
	printf("regctl    : %d\n", regctl);
	printf("rtype     : %d\n", status->rtype);
	printf("ptpls     : %d\n", status->ptpls);

	for (i = 0; i < regctl; i++) {
		printf("regctl[%d] :\n", i);
		printf("  cntlid  : %x\n", le16_to_cpu(status->regctl_ds[i].cntlid));
		printf("  rcsts   : %x\n", status->regctl_ds[i].rcsts);
		printf("  hostid  : %"PRIx64"\n", (uint64_t)le64_to_cpu(status->regctl_ds[i].hostid));
		printf("  rkey    : %"PRIx64"\n", (uint64_t)le64_to_cpu(status->regctl_ds[i].rkey));
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

void show_smart_log(struct nvme_smart_log *smart, unsigned int nsid, const char *devname)
{
	/* convert temperature from Kelvin to Celsius */
	int c;
	int temperature = ((smart->temperature[1] << 8) |
		smart->temperature[0]) - 273;

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
	for (c=0; c < 8; c++) {
		__u16 temp = le16_to_cpu(smart->temp_sensor[c]);
		printf("Temperature Sensor %d                : %u C\n", c + 1,
			temp ? temp - 273 : 0);
	}
}

void show_intel_smart_log(struct nvme_additional_smart_log *smart, unsigned int nsid, const char *devname)
{
	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n", devname, nsid);
	printf("key                               normalized raw\n");
	printf("program_fail_count              : %3d%%       %"PRIu64"\n",
		smart->program_fail_cnt.norm,
		int48_to_long(smart->program_fail_cnt.raw));
	printf("erase_fail_count                : %3d%%       %"PRIu64"\n",
		smart->erase_fail_cnt.norm,
		int48_to_long(smart->erase_fail_cnt.raw));
	printf("wear_leveling                   : %3d%%       min: %u, max: %u, avg: %u\n",
		smart->wear_leveling_cnt.norm,
		le16_to_cpu(smart->wear_leveling_cnt.wear_level.min),
		le16_to_cpu(smart->wear_leveling_cnt.wear_level.max),
		le16_to_cpu(smart->wear_leveling_cnt.wear_level.avg));
	printf("end_to_end_error_detection_count: %3d%%       %"PRIu64"\n",
		smart->e2e_err_cnt.norm,
		int48_to_long(smart->e2e_err_cnt.raw));
	printf("crc_error_count                 : %3d%%       %"PRIu64"\n",
		smart->crc_err_cnt.norm,
		int48_to_long(smart->crc_err_cnt.raw));
	printf("timed_workload_media_wear       : %3d%%       %.3f%%\n",
		smart->timed_workload_media_wear.norm,
		((float)int48_to_long(smart->timed_workload_media_wear.raw)) / 1024);
	printf("timed_workload_host_reads       : %3d%%       %"PRIu64"%%\n",
		smart->timed_workload_host_reads.norm,
		int48_to_long(smart->timed_workload_host_reads.raw));
	printf("timed_workload_timer            : %3d%%       %"PRIu64" min\n",
		smart->timed_workload_timer.norm,
		int48_to_long(smart->timed_workload_timer.raw));
	printf("thermal_throttle_status         : %3d%%       %u%%, cnt: %u\n",
		smart->thermal_throttle_status.norm,
		smart->thermal_throttle_status.thermal_throttle.pct,
		smart->thermal_throttle_status.thermal_throttle.count);
	printf("retry_buffer_overflow_count     : %3d%%       %"PRIu64"\n",
		smart->retry_buffer_overflow_cnt.norm,
		int48_to_long(smart->retry_buffer_overflow_cnt.raw));
	printf("pll_lock_loss_count             : %3d%%       %"PRIu64"\n",
		smart->pll_lock_loss_cnt.norm,
		int48_to_long(smart->pll_lock_loss_cnt.raw));
	printf("nand_bytes_written              : %3d%%       sectors: %"PRIu64"\n",
		smart->nand_bytes_written.norm,
		int48_to_long(smart->nand_bytes_written.raw));
	printf("host_bytes_written              : %3d%%       sectors: %"PRIu64"\n",
		smart->host_bytes_written.norm,
		int48_to_long(smart->host_bytes_written.raw));
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
	case NVME_FEAT_SW_PROGRESS:	return "Software Progress";
	case NVME_FEAT_HOST_ID:		return "Host Identifier";
	case NVME_FEAT_RESV_MASK:	return "Reservation Notification Mask";
	case NVME_FEAT_RESV_PERSIST:	return "Reservation Persistence";
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


char *nvme_status_to_string(__u32 status)
{
	switch (status & 0x3ff) {
	case NVME_SC_SUCCESS:			return "SUCCESS";
	case NVME_SC_INVALID_OPCODE:		return "INVALID_OPCODE";
	case NVME_SC_INVALID_FIELD:		return "INVALID_FIELD";
	case NVME_SC_CMDID_CONFLICT:		return "CMDID_CONFLICT";
	case NVME_SC_DATA_XFER_ERROR:		return "DATA_XFER_ERROR";
	case NVME_SC_POWER_LOSS:		return "POWER_LOSS";
	case NVME_SC_INTERNAL:			return "INTERNAL";
	case NVME_SC_ABORT_REQ:			return "ABORT_REQ";
	case NVME_SC_ABORT_QUEUE:		return "ABORT_QUEUE";
	case NVME_SC_FUSED_FAIL:		return "FUSED_FAIL";
	case NVME_SC_FUSED_MISSING:		return "FUSED_MISSING";
	case NVME_SC_INVALID_NS:		return "INVALID_NS";
	case NVME_SC_CMD_SEQ_ERROR:		return "CMD_SEQ_ERROR";
	case NVME_SC_LBA_RANGE:			return "LBA_RANGE";
	case NVME_SC_CAP_EXCEEDED:		return "CAP_EXCEEDED";
	case NVME_SC_NS_NOT_READY:		return "NS_NOT_READY";
	case NVME_SC_RESERVATION_CONFLICT:	return "RESERVATION_CONFLICT";
	case NVME_SC_CQ_INVALID:		return "CQ_INVALID";
	case NVME_SC_QID_INVALID:		return "QID_INVALID";
	case NVME_SC_QUEUE_SIZE:		return "QUEUE_SIZE";
	case NVME_SC_ABORT_LIMIT:		return "ABORT_LIMIT";
	case NVME_SC_ABORT_MISSING:		return "ABORT_MISSING";
	case NVME_SC_ASYNC_LIMIT:		return "ASYNC_LIMIT";
	case NVME_SC_FIRMWARE_SLOT:		return "FIRMWARE_SLOT";
	case NVME_SC_FIRMWARE_IMAGE:		return "FIRMWARE_IMAGE";
	case NVME_SC_INVALID_VECTOR:		return "INVALID_VECTOR";
	case NVME_SC_INVALID_LOG_PAGE:		return "INVALID_LOG_PAGE";
	case NVME_SC_INVALID_FORMAT:		return "INVALID_FORMAT";
	case NVME_SC_FW_NEEDS_CONV_RESET:	return "FW_NEEDS_CONVENTIONAL_RESET";
	case NVME_SC_INVALID_QUEUE:		return "INVALID_QUEUE";
	case NVME_SC_FEATURE_NOT_SAVEABLE:	return "FEATURE_NOT_SAVEABLE";
	case NVME_SC_FEATURE_NOT_CHANGEABLE:	return "FEATURE_NOT_CHANGEABLE";
	case NVME_SC_FEATURE_NOT_PER_NS:	return "FEATURE_NOT_PER_NS";
	case NVME_SC_FW_NEEDS_SUBSYS_RESET:	return "FW_NEEDS_SUBSYSTEM_RESET";
	case NVME_SC_FW_NEEDS_RESET:		return "FW_NEEDS_RESET";
	case NVME_SC_FW_NEEDS_MAX_TIME:		return "FW_NEEDS_MAX_TIME_VIOLATION";
	case NVME_SC_FW_ACIVATE_PROHIBITED:	return "FW_ACTIVATION_PROHIBITED";
	case NVME_SC_OVERLAPPING_RANGE:		return "OVERLAPPING_RANGE";
	case NVME_SC_NS_INSUFFICENT_CAP:	return "NS_INSUFFICIENT_CAPACITY";
	case NVME_SC_NS_ID_UNAVAILABLE:		return "NS_ID_UNAVAILABLE";
	case NVME_SC_NS_ALREADY_ATTACHED:	return "NS_ALREADY_ATTACHED";
	case NVME_SC_NS_IS_PRIVATE:		return "NS_IS_PRIVATE";
	case NVME_SC_NS_NOT_ATTACHED:		return "NS_NOT_ATTACHED";
	case NVME_SC_THIN_PROV_NOT_SUPP:	return "THIN_PROVISIONING_NOT_SUPPORTED";
	case NVME_SC_CTRL_LIST_INVALID:		return "CONTROLLER_LIST_INVALID";
	case NVME_SC_BAD_ATTRIBUTES:		return "BAD_ATTRIBUTES";
	case NVME_SC_WRITE_FAULT:		return "WRITE_FAULT";
	case NVME_SC_READ_ERROR:		return "READ_ERROR";
	case NVME_SC_GUARD_CHECK:		return "GUARD_CHECK";
	case NVME_SC_APPTAG_CHECK:		return "APPTAG_CHECK";
	case NVME_SC_REFTAG_CHECK:		return "REFTAG_CHECK";
	case NVME_SC_COMPARE_FAILED:		return "COMPARE_FAILED";
	case NVME_SC_ACCESS_DENIED:		return "ACCESS_DENIED";
	case NVME_SC_UNWRITTEN_BLOCK:		return "UNWRITTEN_BLOCK";
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

static void show_host_mem_buffer(struct nvme_host_mem_buffer *hmb)
{
	printf("\tHost Memory Descriptor List Entry Count (HMDLEC): %u\n", hmb->hmdlec);
	printf("\tHost Memory Descriptor List Address     (HMDLAU): %u\n", hmb->hmdlau);
	printf("\tHost Memory Descriptor List Address     (HMDLAL): %u\n", hmb->hmdlal);
	printf("\tHost Memory Buffer Size                  (HSIZE): %u\n", hmb->hsize);
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
		printf("\tTemperature Threshold         (TMPTH): %u C\n", (result & 0x0000ffff) - 273);
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
		printf("\tAggregation Time     (TIME): %u ms\n", ((result & 0x0000ff00) >> 8) * 100);
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
		printf("\tFirmware Activation Notices     : %s\n", ((result & 0x00000200) >> 9) ? "Send async event":"Do not send async event");
		printf("\tNamespace Attribute Notices     : %s\n", ((result & 0x00000100) >> 8) ? "Send NameSpace Attribute Changed event":"Do not send NameSpace Attribute Changed event");
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
	}
}

void json_print_list_items(struct list_item *list_items, unsigned len)
{
	struct json_object *root;
	struct json_array *devices;
	struct json_object *device_attrs;
	char formatter[41] = { 0 };
	int index, i = 0;
	char *product;

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
		free((void*)product);
	}
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

	json_object_add_value_int(root, "nsze", le64_to_cpu(ns->nsze));
	json_object_add_value_int(root, "ncap", le64_to_cpu(ns->ncap));
	json_object_add_value_int(root, "nuse", le64_to_cpu(ns->nuse));
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
	json_object_add_value_float(root, "nvmcap", nvmcap);

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
}

void json_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode)
{
	struct json_object *root;
	struct json_array *psds;

	long double tnvmcap = int128_to_double(ctrl->tnvmcap);
	long double unvmcap = int128_to_double(ctrl->unvmcap);

	char sn[sizeof(ctrl->sn) + 1], mn[sizeof(ctrl->mn) + 1], fr[sizeof(ctrl->fr) + 1];
	char subnqn[sizeof(ctrl->subnqn) + 1];
	__u32 ieee = ctrl->ieee[2] << 16 | ctrl->ieee[1] << 8 | ctrl->ieee[0];

	int i;

	snprintf(sn, sizeof(sn), "%-.*s\n", (int)sizeof(ctrl->sn), ctrl->sn);
	snprintf(mn, sizeof(mn), "%-.*s\n", (int)sizeof(ctrl->mn), ctrl->mn);
	snprintf(fr, sizeof(fr), "%-.*s\n", (int)sizeof(ctrl->fr), ctrl->fr);
	snprintf(subnqn, sizeof(subnqn), "%-.*s\n", (int)sizeof(ctrl->subnqn), ctrl->subnqn);


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
	json_object_add_value_int(root, "ver", le32_to_cpu(ctrl->ver));
	json_object_add_value_int(root, "rtd3r", le32_to_cpu(ctrl->rtd3r));
	json_object_add_value_int(root, "rtd3e", le32_to_cpu(ctrl->rtd3e));
	json_object_add_value_int(root, "oaes", le32_to_cpu(ctrl->oaes));
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
	json_object_add_value_int(root, "hmpre", le32_to_cpu(ctrl->hmpre));
	json_object_add_value_int(root, "hmmin", le32_to_cpu(ctrl->hmmin));
	json_object_add_value_float(root, "tnvmcap", tnvmcap);
	json_object_add_value_float(root, "unvmcap", unvmcap);
	json_object_add_value_int(root, "rpmbs", le32_to_cpu(ctrl->rpmbs));
	json_object_add_value_int(root, "sqes", ctrl->sqes);
	json_object_add_value_int(root, "cqes", ctrl->cqes);
	json_object_add_value_int(root, "nn", le32_to_cpu(ctrl->nn));
	json_object_add_value_int(root, "oncs", le16_to_cpu(ctrl->oncs));
	json_object_add_value_int(root, "fuses", le16_to_cpu(ctrl->fuses));
	json_object_add_value_int(root, "fna", ctrl->fna);
	json_object_add_value_int(root, "vwc", ctrl->vwc);
	json_object_add_value_int(root, "awun", le16_to_cpu(ctrl->awun));
	json_object_add_value_int(root, "awupf", le16_to_cpu(ctrl->awupf));
	json_object_add_value_int(root, "nvscc", ctrl->nvscc);
	json_object_add_value_int(root, "acwu", le16_to_cpu(ctrl->acwu));
	json_object_add_value_int(root, "sgls", le32_to_cpu(ctrl->sgls));
	json_object_add_value_string(root, "subnqn", subnqn);

	psds = json_create_array();
	json_object_add_value_array(root, "psds", psds);

	for (i = 0; i <= ctrl->npss; i++) {
		struct json_object *psd = json_create_object();

		json_object_add_value_int(psd, "max_power",
			le16_to_cpu(ctrl->psd[i].max_power));
		json_object_add_value_int(psd, "flags", ctrl->psd[i].flags);
		json_object_add_value_int(psd, "entry_lat",
			le32_to_cpu(ctrl->psd[i].entry_lat));
		json_object_add_value_int(psd, "exit_lat",
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

	json_print_object(root, NULL);
	printf("\n");
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

		json_object_add_value_int(error, "error_count", err_log[i].error_count);
		json_object_add_value_int(error, "sqid", err_log[i].sqid);
		json_object_add_value_int(error, "cmdid", err_log[i].cmdid);
		json_object_add_value_int(error, "status_field", err_log[i].status_field);
		json_object_add_value_int(error, "parm_error_location", err_log[i].parm_error_location);
		json_object_add_value_int(error, "lba", err_log[i].lba);
		json_object_add_value_int(error, "nsid", err_log[i].nsid);
		json_object_add_value_int(error, "vs", err_log[i].vs);

		json_array_add_value_object(errors, error);
	}

	json_print_object(root, NULL);
	printf("\n");
}

void json_nvme_resv_report(struct nvme_reservation_status *status)
{
	struct json_object *root;
	struct json_array *rcs;
	int i, regctl;

	regctl = status->regctl[0] | (status->regctl[1] << 8);

	root = json_create_object();

	json_object_add_value_int(root, "gen", le32_to_cpu(status->gen));
	json_object_add_value_int(root, "regctl", regctl);
	json_object_add_value_int(root, "rtype", status->rtype);
	json_object_add_value_int(root, "ptpls", status->ptpls);

	rcs = json_create_array();
	json_object_add_value_array(root, "regctls", rcs);

	for (i = 0; i < regctl; i++) {
		struct json_object *rc = json_create_object();

		json_object_add_value_int(rc, "cntlid", le16_to_cpu(status->regctl_ds[i].cntlid));
		json_object_add_value_int(rc, "rcsts", status->regctl_ds[i].rcsts);
		json_object_add_value_int(rc, "hostid", (uint64_t)le64_to_cpu(status->regctl_ds[i].hostid));
		json_object_add_value_int(rc, "rkey", (uint64_t)le64_to_cpu(status->regctl_ds[i].rkey));

		json_array_add_value_object(rcs, rc);
	}

	json_print_object(root, NULL);
	printf("\n");
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
		snprintf(fmt, sizeof(fmt), "Firmware Rev Slot %d", i);
		snprintf(str, sizeof(str), "%"PRIu64" (%s)", (uint64_t)fw_log->frs[i],
			 fw_to_string(fw_log->frs[i]));
		json_object_add_value_string(fwsi, fmt, str);
	}
	json_object_add_value_object(root, devname, fwsi);

	json_print_object(root, NULL);
	printf("\n");
}

void json_add_smart_log(struct nvme_additional_smart_log *smart,
			unsigned int nsid, const char *devname)
{
	struct json_object *root;
	struct json_object *data;
	char fmt[128];

	root = json_create_object();
	data = json_create_object();

	json_object_add_value_int(data, "Program Fail Count",
				  int48_to_long(smart->program_fail_cnt.raw));
	json_object_add_value_int(data, "Erase Fail Count",
				  int48_to_long(smart->erase_fail_cnt.raw));
	json_object_add_value_int(data, "Wear Leveling Min",
				  le16toh(smart->wear_leveling_cnt.wear_level.min));
	json_object_add_value_int(data, "Wear Leveling Max",
				  le16toh(smart->wear_leveling_cnt.wear_level.max));
	json_object_add_value_int(data, "Wear Leveling Avg",
				  le16toh(smart->wear_leveling_cnt.wear_level.avg));
	json_object_add_value_int(data, "End-to-end Error Detection Count",
				  int48_to_long(smart->e2e_err_cnt.raw));
	json_object_add_value_int(data, "CRC Error Count",
				  int48_to_long(smart->crc_err_cnt.raw));
	json_object_add_value_float(data, "Timed Workload Media Wear",
				    ((long double)int48_to_long(smart->timed_workload_media_wear.raw)) / 1024);

	json_object_add_value_int(data, "Timed Workload Host Reads",
				  int48_to_long(smart->timed_workload_host_reads.raw));
	json_object_add_value_int(data, "Timed Workload Timer",
				  int48_to_long(smart->timed_workload_timer.raw));
	snprintf(fmt, sizeof(fmt), "%u%%",
		 smart->thermal_throttle_status.thermal_throttle.pct);
	json_object_add_value_string(data, "Thermal Throttle status Percentage",
				     fmt);
	json_object_add_value_int(data, "Thermal Throttle Status Count",
				  smart->thermal_throttle_status.thermal_throttle.count);
	json_object_add_value_int(data, "Retry Buffer Overflow Count",
				  int48_to_long(smart->retry_buffer_overflow_cnt.raw));
	json_object_add_value_int(data, "PLL Lock Loss Count",
				  int48_to_long(smart->pll_lock_loss_cnt.raw));
	json_object_add_value_int(data, "Nand Bytes Written",
				  int48_to_long(smart->nand_bytes_written.raw));
	json_object_add_value_int(data, "Host Bytes Written",
				  int48_to_long(smart->host_bytes_written.raw));

	snprintf(fmt, sizeof(fmt), "Additional Smart Log for %s", devname);
	json_object_add_value_object(root, fmt, data);
	json_print_object(root, NULL);
}

void json_smart_log(struct nvme_smart_log *smart, unsigned int nsid, const char *devname)
{
	struct json_object *root;

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
	json_object_add_value_int(root, "warning_temp_time",
			le32_to_cpu(smart->warning_temp_time));
	json_object_add_value_int(root, "critical_comp_time",
			le32_to_cpu(smart->critical_comp_time));

	json_print_object(root, NULL);
	printf("\n");
}

void show_registers_cap(struct nvme_bar_cap *cap)
{
	printf("\tMemory Page Size Maximum      (MPSMAX): %u bytes\n", 1 <<  (12 + ((cap->mpsmax_mpsmin & 0xf0) >> 4)));
	printf("\tMemory Page Size Minimum      (MPSMIN): %u bytes\n", 1 <<  (12 + (cap->mpsmax_mpsmin & 0x0f)));
	printf("\tCommand Sets Supported           (CSS): NVM command set is %s\n",
			(cap->css_nssrs_dstrd & 0x0020) ? "supported":"not supported");
	printf("\tNVM Subsystem Reset Supported  (NSSRS): %s\n", (cap->css_nssrs_dstrd & 0x0010) ? "Yes":"No");
	printf("\tDoorbell Stride                (DSTRD): %u bytes\n", 1 << (2 + (cap->css_nssrs_dstrd & 0x000f)));
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
	printf("\tI/O Completion Queue Entry Size (IOSQES): %u bytes\n", 1 <<   ((cc & 0x00f00000) >> 20));
	printf("\tI/O Submission Queue Entry Size (IOSQES): %u bytes\n", 1 <<   ((cc & 0x000f0000) >> 16));
	show_registers_cc_shn((cc & 0x0000c000) >> 14);
	show_registers_cc_ams((cc & 0x00003800) >> 11);
	printf("\tMemory Page Size                   (MPS): %u bytes\n", 1 <<  (12 + ((cc & 0x00000780) >> 7)));
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
	printf("\tAdmin Completion Queue Size (ACQS): %u bytes\n", ((aqa & 0x0fff0000) >> 16)+1);
	printf("\tAdmin Submission Queue Size (ASQS): %u bytes\n\n", (aqa & 0x00000fff)+1);

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

void show_ctrl_registers(void *bar, unsigned int mode)
{
	uint64_t cap, asq, acq;
	uint32_t vs, intms, intmc, cc, csts, nssr, aqa, cmbsz, cmbloc;

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

	if (human) {
		printf("cap     : %"PRIx64"\n", cap);
		show_registers_cap((struct nvme_bar_cap *)&cap);

		printf("version : %x\n", vs);
		show_registers_version(vs);

		printf("intms   : %x\n", intms);
		printf("\tInterrupt Vector Mask Set (IVMS): %x\n\n", intms);

		printf("intmc   : %x\n", intmc);
		printf("\tInterrupt Vector Mask Clear (IVMC): %x\n\n", intmc);

		printf("cc      : %x\n", cc);
		show_registers_cc(cc);

		printf("csts    : %x\n", csts);
		show_registers_csts(csts);

		printf("nssr    : %x\n", nssr);
		printf("\tNVM Subsystem Reset Control (NSSRC): %u\n\n", nssr);

		printf("aqa     : %x\n", aqa);
		show_registers_aqa(aqa);

		printf("asq     : %"PRIx64"\n", asq);
		printf("\tAdmin Submission Queue Base (ASQB): %"PRIx64"\n",
				asq);

		printf("acq     : %"PRIx64"\n", acq);
		printf("\tAdmin Completion Queue Base (ACQB): %"PRIx64"\n",
				acq);

		printf("cmbloc  : %x\n", cmbloc);
		show_registers_cmbloc(cmbloc, cmbsz);

		printf("cmbsz   : %x\n", cmbsz);
		show_registers_cmbsz(cmbsz);
	} else {
		printf("cap     : %"PRIx64"\n", cap);
		printf("version : %x\n", vs);
		printf("intms   : %x\n", intms);
		printf("intmc   : %x\n", intmc);
		printf("cc      : %x\n", cc);
		printf("csts    : %x\n", csts);
		printf("nssr    : %x\n", nssr);
		printf("aqa     : %x\n", aqa);
		printf("asq     : %"PRIx64"\n", asq);
		printf("acq     : %"PRIx64"\n", acq);
		printf("cmbloc  : %x\n", cmbloc);
		printf("cmbsz   : %x\n", cmbsz);
	}
}
