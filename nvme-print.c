#include <endian.h>
#include <inttypes.h>
#include <stdio.h>

#include "nvme-print.h"

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
			fprintf(stdout, "\n%04x:", offset);
		if (i % group == 0)
			fprintf(stdout, " %02x", buf[i]);
		else
			fprintf(stdout, "%02x", buf[i]);
		ascii[i % width] = (buf[i] >= '!' && buf[i] <= '~') ? buf[i] : '.';
		if (((i + 1) % width) == 0) {
			ascii[i % width + 1] = '\0';
			fprintf(stdout, " \"%.*s\"", width, ascii);
			offset += width;
			line_done = 1;
		}
	}
	if (!line_done) {
		unsigned b = width - (i % width);
		ascii[i % width + 1] = '\0';
		fprintf(stdout, " %*s \"%.*s\"",
				2 * b + b / group + (b % group ? 1 : 0), "",
				width, ascii);
	}
	fprintf(stdout, "\n");
}

void d_raw(unsigned char *buf, unsigned len)
{
	unsigned i;
	for (i = 0; i < len; i++)
		putchar(*(buf+i));
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

static void show_nvme_id_ctrl_oaes(__le32 oaes)
{
	__le32 rsvd0 = (oaes & 0xFFFFFE00) >> 9;
	__le32 nace = (oaes & 0x100) >> 8;
	__le32 rsvd1 = oaes & 0xFF;
	if (rsvd0)
		printf(" [31:9] : %#x\tReserved\n", rsvd0);
	printf("  [8:8] : %#x\tNamespace Attribute Changed Event %sSupported\n",
		nace, nace ? "" : "Not ");
	if (rsvd1)
		printf("  [7:0] : %#x\tReserved\n", rsvd1);
	printf("\n");
}

static void show_nvme_id_ctrl_oacs(__le16 oacs)
{
	__le16 rsvd = (oacs & 0xFFF0) >> 4;
	__le16 nsm = (oacs & 0x8) >> 3;
	__le16 fwc = (oacs & 0x4) >> 2;
	__le16 fmt = (oacs & 0x2) >> 1;
	__le16 sec = oacs & 0x1;
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

static void show_nvme_id_ctrl_rpmbs(__le32 rpmbs)
{
	__le32 asz = (rpmbs & 0xFF000000) >> 24;
	__le32 tsz = (rpmbs & 0xFF0000) >> 16;
	__le32 rsvd = (rpmbs & 0xFFC0) >> 6;
	__le32 auth = (rpmbs & 0x38) >> 3;
	__le32 rpmb = rpmbs & 0x3;
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

static void show_nvme_id_ctrl_oncs(__le16 oncs)
{
	__le16 rsvd = (oncs & 0xFFC0) >> 6;
	__le16 resv = (oncs & 0x20) >> 5;
	__le16 save = (oncs & 0x10) >> 4;
	__le16 wzro = (oncs & 0x8) >> 3;
	__le16 dsms = (oncs & 0x4) >> 2;
	__le16 wunc = (oncs & 0x2) >> 1;
	__le16 cmp = oncs & 0x1;
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

static void show_nvme_id_ctrl_fuses(__le16 fuses)
{
	__le16 rsvd = (fuses & 0xFE) >> 1;
	__le16 cmpw = fuses & 0x1;
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

static void show_nvme_id_ctrl_sgls(__le32 sgls)
{
	__le32 rsvd0 = (sgls & 0xFFF80000) >> 19;
	__le32 sglltb = (sgls & 0x40000) >> 18;
	__le32 bacmdb = (sgls & 0x20000) >> 17;
	__le32 bbs = (sgls & 0x10000) >> 16;
	__le32 rsvd1 = (sgls & 0xFFFE) >> 1;
	__le32 sglsp = sgls & 0x1;
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
	int human = mode&HUMAN,
		vs = mode&VS;

	printf("nsze    : %#"PRIx64"\n", (uint64_t)le64toh(ns->nsze));
	printf("ncap    : %#"PRIx64"\n", (uint64_t)le64toh(ns->ncap));
	printf("nuse    : %#"PRIx64"\n", (uint64_t)le64toh(ns->nuse));
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
	printf("nawun   : %d\n", ns->nawun);
	printf("nawupf  : %d\n", ns->nawupf);
	printf("nacwu   : %d\n", ns->nacwu);
	printf("nabsn   : %d\n", ns->nabsn);
	printf("nabo    : %d\n", ns->nabo);
	printf("nabspf  : %d\n", ns->nabspf);
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
				ns->lbaf[i].ms, 1 << ns->lbaf[i].ds, ns->lbaf[i].rp,
				ns->lbaf[i].rp == 3 ? "Degraded" :
				ns->lbaf[i].rp == 2 ? "Good" :
				ns->lbaf[i].rp == 1 ? "Better" : "Best",
				i == (ns->flbas & 0xf) ? "(in use)" : "");
		else
			printf("lbaf %2d : ms:%-3d ds:%-2d rp:%#x %s\n", i,
				ns->lbaf[i].ms, ns->lbaf[i].ds, ns->lbaf[i].rp,
				i == (ns->flbas & 0xf) ? "(in use)" : "");
	}
	if (vs) {
		printf("vs[]:");
		d(ns->vs, sizeof(ns->vs), 16, 1);
	}
}

static void print_ps_power_and_scale(__le16 power, __u8 scale)
{
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

void show_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode)
{
	int i;
	int human = mode & HUMAN,
		vs = mode & VS;

	printf("vid     : %#x\n", ctrl->vid);
	printf("ssvid   : %#x\n", ctrl->ssvid);
	printf("sn      : %-20.20s\n", ctrl->sn);
	printf("mn      : %-20.20s\n", ctrl->mn);
	printf("fr      : %-.8s\n", ctrl->fr);
	printf("rab     : %d\n", ctrl->rab);
	printf("ieee    : %02x%02x%02x\n",
		ctrl->ieee[2], ctrl->ieee[1], ctrl->ieee[0]);
	printf("cmic    : %#x\n", ctrl->cmic);
	if (human)
		show_nvme_id_ctrl_cmic(ctrl->cmic);
	printf("mdts    : %d\n", ctrl->mdts);
	printf("cntlid  : %x\n", ctrl->cntlid);
	printf("ver     : %x\n", ctrl->ver);
	printf("rtd3r   : %x\n", ctrl->rtd3r);
	printf("rtd3e   : %x\n", ctrl->rtd3e);
	printf("oaes    : %#x\n", ctrl->oaes);
	if (human)
		show_nvme_id_ctrl_oaes(ctrl->oaes);
	printf("oacs    : %#x\n", ctrl->oacs);
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
	printf("wctemp  : %d\n", ctrl->wctemp);
	printf("cctemp  : %d\n", ctrl->cctemp);
	printf("mtfa    : %d\n", ctrl->mtfa);
	printf("hmmin   : %d\n", ctrl->hmmin);
	printf("tnvmcap : %.0Lf\n", int128_to_double(ctrl->tnvmcap));
	printf("unvmcap : %.0Lf\n", int128_to_double(ctrl->unvmcap));
	printf("rpmbs   : %#x\n", ctrl->rpmbs);
	if (human)
		show_nvme_id_ctrl_rpmbs(ctrl->rpmbs);
	printf("sqes    : %#x\n", ctrl->sqes);
	if (human)
		show_nvme_id_ctrl_sqes(ctrl->sqes);
	printf("cqes    : %#x\n", ctrl->cqes);
	if (human)
		show_nvme_id_ctrl_cqes(ctrl->cqes);
	printf("nn      : %d\n", ctrl->nn);
	printf("oncs    : %#x\n", ctrl->oncs);
	if (human)
		show_nvme_id_ctrl_oncs(ctrl->oncs);
	printf("fuses   : %#x\n", ctrl->fuses);
	if (human)
		show_nvme_id_ctrl_fuses(ctrl->fuses);
	printf("fna     : %#x\n", ctrl->fna);
	if (human)
		show_nvme_id_ctrl_fna(ctrl->fna);
	printf("vwc     : %#x\n", ctrl->vwc);
	if (human)
		show_nvme_id_ctrl_vwc(ctrl->vwc);
	printf("awun    : %d\n", ctrl->awun);
	printf("awupf   : %d\n", ctrl->awupf);
	printf("nvscc   : %d\n", ctrl->nvscc);
	if (human)
		show_nvme_id_ctrl_nvscc(ctrl->nvscc);
	printf("acwu    : %d\n", ctrl->acwu);
	printf("sgls    : %x\n", ctrl->sgls);
	if (human)
		show_nvme_id_ctrl_sgls(ctrl->sgls);

	for (i = 0; i <= ctrl->npss; i++) {
		printf("ps %4d : mp:", i);

		if (ctrl->psd[i].flags & NVME_PS_FLAGS_MAX_POWER_SCALE)
			printf("%01u.%04uW ", ctrl->psd[i].max_power / 10000, ctrl->psd[i].max_power % 10000);
		else
			printf("%01u.%02uW ", ctrl->psd[i].max_power / 100, ctrl->psd[i].max_power % 100);

		if (ctrl->psd[i].flags & NVME_PS_FLAGS_NON_OP_STATE)
			printf("non-");
		printf("operational enlat:%d exlat:%d rrt:%d rrl:%d\n"
			"          rwt:%d rwl:%d idle_power:",
			ctrl->psd[i].entry_lat, ctrl->psd[i].exit_lat,
			ctrl->psd[i].read_tput, ctrl->psd[i].read_lat,
			ctrl->psd[i].write_tput, ctrl->psd[i].write_lat);
		print_ps_power_and_scale(ctrl->psd[i].idle_power,
					 ctrl->psd[i].idle_scale);
		printf(" active_power:");
		print_ps_power_and_scale(ctrl->psd[i].active_power,
					 ctrl->psd[i].active_work_scale);
		printf("\n");

	}
	if (vs) {
		printf("vs[]:\n");
		d(ctrl->vs, sizeof(ctrl->vs), 16, 1);
	}
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
		printf("error_count  : %"PRIu64"\n", (uint64_t)le64toh(err_log[i].error_count));
		printf("sqid         : %d\n", err_log[i].sqid);
		printf("cmdid        : %#x\n", err_log[i].cmdid);
		printf("status_field : %#x\n", err_log[i].status_field);
		printf("parm_err_loc : %#x\n", err_log[i].parm_error_location);
		printf("lba          : %#"PRIx64"\n",(uint64_t)le64toh(err_log[i].lba));
		printf("nsid         : %d\n", err_log[i].nsid);
		printf("vs           : %d\n", err_log[i].vs);
		printf(".................\n");
	}
}

void show_nvme_resv_report(struct nvme_reservation_status *status)
{
	int i, regctl;

	regctl = status->regctl[0] | (status->regctl[1] << 8);

	printf("\nNVME Reservation status:\n\n");
	printf("gen       : %d\n", le32toh(status->gen));
	printf("regctl    : %d\n", regctl);
	printf("rtype     : %d\n", status->rtype);
	printf("ptpls     : %d\n", status->ptpls);

	for (i = 0; i < regctl; i++) {
		printf("regctl[%d] :\n", i);
		printf("  cntlid  : %x\n", le16toh(status->regctl_ds[i].cntlid));
		printf("  rcsts   : %x\n", status->regctl_ds[i].rcsts);
		printf("  hostid  : %"PRIx64"\n", (uint64_t)le64toh(status->regctl_ds[i].hostid));
		printf("  rkey    : %"PRIx64"\n", (uint64_t)le64toh(status->regctl_ds[i].rkey));
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

static unsigned long int48_to_long(__u8 *data)
{
	int i;
	long result = 0;

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
	unsigned int temperature = ((smart->temperature[1] << 8) |
		smart->temperature[0]) - 273;

	printf("Smart Log for NVME device:%s namespace-id:%x\n", devname, nsid);
	printf("critical_warning                    : %#x\n", smart->critical_warning);
	printf("temperature                         : %u C\n", temperature);
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
	printf("Critical Composite Temperature Time : %u\n", smart->warning_temp_time);
	for (c=0; c < 8; c++) {
	    printf("Temperature Sensor %d                : %u C\n", c + 1,
			smart->temp_sensor[c] ? smart->temp_sensor[c] - 273 : 0);
	}
}

void show_intel_smart_log(struct nvme_additional_smart_log *smart, unsigned int nsid, const char *devname)
{
	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n", devname, nsid);
	printf("key                               normalized raw\n");
	printf("program_fail_count              : %3d%%       %lu\n",
		smart->program_fail_cnt.norm,
		int48_to_long(smart->program_fail_cnt.raw));
	printf("erase_fail_count                : %3d%%       %lu\n",
		smart->erase_fail_cnt.norm,
		int48_to_long(smart->erase_fail_cnt.raw));
	printf("wear_leveling                   : %3d%%       min: %u, max: %u, avg: %u\n",
		smart->wear_leveling_cnt.norm,
		smart->wear_leveling_cnt.wear_level.min,
		smart->wear_leveling_cnt.wear_level.max,
		smart->wear_leveling_cnt.wear_level.avg);
	printf("end_to_end_error_detection_count: %3d%%       %lu\n",
		smart->e2e_err_cnt.norm,
		int48_to_long(smart->e2e_err_cnt.raw));
	printf("crc_error_count                 : %3d%%       %lu\n",
		smart->crc_err_cnt.norm,
		int48_to_long(smart->crc_err_cnt.raw));
	printf("timed_workload_media_wear       : %3d%%       %.3f%%\n",
		smart->timed_workload_media_wear.norm,
		((float)int48_to_long(smart->timed_workload_media_wear.raw)) / 1024);
	printf("timed_workload_host_reads       : %3d%%       %lu%%\n",
		smart->timed_workload_host_reads.norm,
		int48_to_long(smart->timed_workload_host_reads.raw));
	printf("timed_workload_timer            : %3d%%       %lu min\n",
		smart->timed_workload_timer.norm,
		int48_to_long(smart->timed_workload_timer.raw));
	printf("thermal_throttle_status         : %3d%%       %u%%, cnt: %u\n",
		smart->thermal_throttle_status.norm,
		smart->thermal_throttle_status.thermal_throttle.pct,
		smart->thermal_throttle_status.thermal_throttle.count);
	printf("retry_buffer_overflow_count     : %3d%%       %lu\n",
		smart->retry_buffer_overflow_cnt.norm,
		int48_to_long(smart->retry_buffer_overflow_cnt.raw));
	printf("pll_lock_loss_count             : %3d%%       %lu\n",
		smart->pll_lock_loss_cnt.norm,
		int48_to_long(smart->pll_lock_loss_cnt.raw));
	printf("nand_bytes_written              : %3d%%       sectors: %lu\n",
		smart->nand_bytes_written.norm,
		int48_to_long(smart->nand_bytes_written.raw));
	printf("host_bytes_written              : %3d%%       sectors: %lu\n",
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
	case NVME_SC_SUCCESS:		return "SUCCESS";
	case NVME_SC_INVALID_OPCODE:	return "INVALID_OPCODE";
	case NVME_SC_INVALID_FIELD:	return "INVALID_FIELD";
	case NVME_SC_CMDID_CONFLICT:	return "CMDID_CONFLICT";
	case NVME_SC_DATA_XFER_ERROR:	return "DATA_XFER_ERROR";
	case NVME_SC_POWER_LOSS:	return "POWER_LOSS";
	case NVME_SC_INTERNAL:		return "INTERNAL";
	case NVME_SC_ABORT_REQ:		return "ABORT_REQ";
	case NVME_SC_ABORT_QUEUE:	return "ABORT_QUEUE";
	case NVME_SC_FUSED_FAIL:	return "FUSED_FAIL";
	case NVME_SC_FUSED_MISSING:	return "FUSED_MISSING";
	case NVME_SC_INVALID_NS:	return "INVALID_NS";
	case NVME_SC_CMD_SEQ_ERROR:	return "CMD_SEQ_ERROR";
	case NVME_SC_LBA_RANGE:		return "LBA_RANGE";
	case NVME_SC_CAP_EXCEEDED:	return "CAP_EXCEEDED";
	case NVME_SC_NS_NOT_READY:	return "NS_NOT_READY";
	case NVME_SC_CQ_INVALID:	return "CQ_INVALID";
	case NVME_SC_QID_INVALID:	return "QID_INVALID";
	case NVME_SC_QUEUE_SIZE:	return "QUEUE_SIZE";
	case NVME_SC_ABORT_LIMIT:	return "ABORT_LIMIT";
	case NVME_SC_ABORT_MISSING:	return "ABORT_MISSING";
	case NVME_SC_ASYNC_LIMIT:	return "ASYNC_LIMIT";
	case NVME_SC_FIRMWARE_SLOT:	return "FIRMWARE_SLOT";
	case NVME_SC_FIRMWARE_IMAGE:	return "FIRMWARE_IMAGE";
	case NVME_SC_INVALID_VECTOR:	return "INVALID_VECTOR";
	case NVME_SC_INVALID_LOG_PAGE:	return "INVALID_LOG_PAGE";
	case NVME_SC_INVALID_FORMAT:	return "INVALID_FORMAT";
	case NVME_SC_BAD_ATTRIBUTES:	return "BAD_ATTRIBUTES";
	case NVME_SC_WRITE_FAULT:	return "WRITE_FAULT";
	case NVME_SC_READ_ERROR:	return "READ_ERROR";
	case NVME_SC_GUARD_CHECK:	return "GUARD_CHECK";
	case NVME_SC_APPTAG_CHECK:	return "APPTAG_CHECK";
	case NVME_SC_REFTAG_CHECK:	return "REFTAG_CHECK";
	case NVME_SC_COMPARE_FAILED:	return "COMPARE_FAILED";
	case NVME_SC_ACCESS_DENIED:	return "ACCESS_DENIED";
	default:			return "Unknown";
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

	fprintf(stdout, "\tAuto PST Entries");
	fprintf(stdout,"\t.................\n");
	for (i = 0; i < 32; i++) {
		fprintf(stdout,"\tEntry[%2d]   \n", i);
		fprintf(stdout,"\t.................\n");
		fprintf(stdout,"\tIdle Time Prior to Transition (ITPT): %u ms\n", (apst[i].data & 0xffffff00) >> 8);
		fprintf(stdout,"\tIdle Transition Power State   (ITPS): %u\n", (apst[i].data & 0x000000f8) >> 3);
		fprintf(stdout,"\t.................\n");
	}
}

static void show_host_mem_buffer(struct nvme_host_mem_buffer *hmb)
{
	fprintf(stdout,"\tHost Memory Descriptor List Entry Count (HMDLEC): %u\n", hmb->hmdlec);
	fprintf(stdout,"\tHost Memory Descriptor List Address     (HMDLAU): %u\n", hmb->hmdlau);
	fprintf(stdout,"\tHost Memory Descriptor List Address     (HMDLAL): %u\n", hmb->hmdlal);
	fprintf(stdout,"\tHost Memory Buffer Size                  (HSIZE): %u\n", hmb->hsize);
}

void nvme_feature_show_fields(__u32 fid, unsigned int result, unsigned char *buf)
{
	__u8 field;
	uint64_t ull;

	switch (fid) {
	case NVME_FEAT_ARBITRATION:
		fprintf(stdout,"\tHigh Priority Weight   (HPW): %u\n", ((result & 0xff000000) >> 24) + 1);
		fprintf(stdout,"\tMedium Priority Weight (MPW): %u\n", ((result & 0x00ff0000) >> 16) + 1);
		fprintf(stdout,"\tLow Priority Weight    (LPW): %u\n", ((result & 0x0000ff00) >> 8) + 1);
		fprintf(stdout,"\tArbitration Burst       (AB): %u\n",  1 << (result & 0x00000007));
		break;
	case NVME_FEAT_POWER_MGMT:
		field =  (result & 0x000000E0) >> 5;
		fprintf(stdout,"\tWorkload Hint (WH): %u - %s\n",  field, nvme_feature_wl_hints_to_string(field));
		fprintf(stdout,"\tPower State   (PS): %u\n",  result & 0x0000001f);
		break;
	case NVME_FEAT_LBA_RANGE:
		field =  result & 0x0000003f;
		fprintf(stdout,"\tNumber of LBA Ranges (NUM): %u\n",  field+1);
		show_lba_range((struct nvme_lba_range_type *)buf, field);
		break;
	case NVME_FEAT_TEMP_THRESH:
		field = (result & 0x00300000) >> 20;
		fprintf(stdout,"\tThreshold Type Select         (THSEL): %u - %s\n", field, nvme_feature_temp_type_to_string(field));
		field = (result & 0x000f0000) >> 16;
		fprintf(stdout,"\tThreshold Temperature Select (TMPSEL): %u - %s\n", field, nvme_feature_temp_sel_to_string(field));
		fprintf(stdout,"\tTemperature Threshold         (TMPTH): %u C\n", (result & 0x0000ffff) - 273);
		break;
	case NVME_FEAT_ERR_RECOVERY:
		fprintf(stdout,"\tDeallocated or Unwritten Logical Block Error Enable (DULBE): %s\n", ((result & 0x00010000) >> 16) ? "Enabled":"Disabled");
		fprintf(stdout,"\tTime Limited Error Recovery                          (TLER): %u ms\n", (result & 0x0000ffff) * 100);
		break;
	case NVME_FEAT_VOLATILE_WC:
		fprintf(stdout,"\tVolatile Write Cache Enable (WCE): %s\n", (result & 0x00000001) ? "Enabled":"Disabled");
		break;
	case NVME_FEAT_NUM_QUEUES:
		fprintf(stdout,"\tNumber of IO Completion Queues Allocated (NCQA): %u\n", ((result & 0xffff0000) >> 16) + 1);
		fprintf(stdout,"\tNumber of IO Submission Queues Allocated (NSQA): %u\n",  (result & 0x0000ffff) + 1);
		break;
	case NVME_FEAT_IRQ_COALESCE:
		fprintf(stdout,"\tAggregation Time     (TIME): %u ms\n", ((result & 0x0000ff00) >> 8) * 100);
		fprintf(stdout,"\tAggregation Threshold (THR): %u\n",  (result & 0x000000ff) + 1);
		break;
	case NVME_FEAT_IRQ_CONFIG:
		fprintf(stdout,"\tCoalescing Disable (CD): %s\n", ((result & 0x00010000) >> 16) ? "True":"False");
		fprintf(stdout,"\tInterrupt Vector   (IV): %u\n",  result & 0x0000ffff);
		break;
	case NVME_FEAT_WRITE_ATOMIC:
		fprintf(stdout,"\tDisable Normal (DN): %s\n", (result & 0x00000001) ? "True":"False");
		break;
	case NVME_FEAT_ASYNC_EVENT:
		fprintf(stdout,"\tFirmware Activation Notices     : %s\n", ((result & 0x00000200) >> 9) ? "Send async event":"Do not send async event");
	    fprintf(stdout,"\tNamespace Attribute Notices     : %s\n", ((result & 0x00000100) >> 8) ? "Send NameSpace Attribute Changed event":"Do not send NameSpace Attribute Changed event");
		fprintf(stdout,"\tSMART / Health Critical Warnings: %s\n", (result & 0x000000ff) ? "Send async event":"Do not send async event");
		break;
	case NVME_FEAT_AUTO_PST:
		fprintf(stdout,"\tAutonomous Power State Transition Enable (APSTE): %s\n", (result & 0x00000001) ? "Enabled":"Disabled");
		show_auto_pst((struct nvme_auto_pst *)buf);
		break;
	case NVME_FEAT_HOST_MEM_BUF:
		fprintf(stdout,"\tMemory Return       (MR): %s\n", ((result & 0x00000002) >> 1) ? "True":"False");
		fprintf(stdout,"\tEnable Host Memory (EHM): %s\n", (result & 0x00000001) ? "Enabled":"Disabled");
		show_host_mem_buffer((struct nvme_host_mem_buffer *)buf);
		break;
	case NVME_FEAT_SW_PROGRESS:
		fprintf(stdout,"\tPre-boot Software Load Count (PBSLC): %u\n", result & 0x000000ff);
		break;
	case NVME_FEAT_HOST_ID:
		ull =  buf[7]; ull <<= 8; ull |= buf[6]; ull <<= 8; ull |= buf[5]; ull <<= 8;
		ull |= buf[4]; ull <<= 8; ull |= buf[3]; ull <<= 8; ull |= buf[2]; ull <<= 8;
		ull |= buf[1]; ull <<= 8; ull |= buf[0];
		fprintf(stdout,"\tHost Identifier (HOSTID):  %" PRIu64 "\n", ull);
		break;
	case NVME_FEAT_RESV_MASK:
		fprintf(stdout,"\tMask Reservation Preempted Notification  (RESPRE): %s\n", ((result & 0x00000008) >> 3) ? "True":"False");
		fprintf(stdout,"\tMask Reservation Released Notification   (RESREL): %s\n", ((result & 0x00000004) >> 2) ? "True":"False");
		fprintf(stdout,"\tMask Registration Preempted Notification (REGPRE): %s\n", ((result & 0x00000002) >> 1) ? "True":"False");
		break;
	case NVME_FEAT_RESV_PERSIST:
		fprintf(stdout,"\tPersist Through Power Loss (PTPL): %s\n", (result & 0x00000001) ? "True":"False");
		break;
	}
}
