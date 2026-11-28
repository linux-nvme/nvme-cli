// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>
#include <shared/hex-util.h>
#include <shared/string-util.h>
#include <shared/uuid-util.h>

#include "id-print.h"
#include "nvme-print.h"
#include "nvme-print-json.h"

static const uint8_t zero_uuid[16] = { 0 };

static void json_id_iocs_iocsc(struct json_object *obj_iocsc, __u64 iocsc)
{
	__u8 cpncs = NVME_GET(iocsc, IOCS_IOCSC_CPNCS);
	__u8 slmcs = NVME_GET(iocsc, IOCS_IOCSC_SLMCS);
	__u8 znscs = NVME_GET(iocsc, IOCS_IOCSC_ZNSCS);
	__u8 kvcs = NVME_GET(iocsc, IOCS_IOCSC_KVCS);
	__u8 nvmcs = NVME_GET(iocsc, IOCS_IOCSC_NVMCS);

	obj_add_str(obj_iocsc, "Computational Programs Namespace Command Set",
		    cpncs ? "Selected" : "Not selected");
	obj_add_str(obj_iocsc, "Subsystem Local Memory Command Set", slmcs ?
		    "Selected" : "Not selected");
	obj_add_str(obj_iocsc, "Zoned Namespace Command Set",
		    znscs ? "Selected" : "Not selected");
	obj_add_str(obj_iocsc, "Key Value Command Set",
		    kvcs ? "Selected" : "Not selected");
	obj_add_str(obj_iocsc, "NVM Command Set",
		    nvmcs ? "Selected" : "Not selected");
}

static void json_id_iocs(struct nvme_id_iocs *iocs)
{
	struct json_object *r = json_root();
	struct json_object *obj_iocsc;
	char json_str[STR_LEN];
	__u16 i;

	for (i = 0; i < ARRAY_SIZE(iocs->iocsc); i++) {
		if (iocs->iocsc[i]) {
			sprintf(json_str, "I/O Command Set Combination[%u]", i);
			obj_add_uint64(r, json_str,
				       le64_to_cpu(iocs->iocsc[i]));

			obj_iocsc = json_create_object();
			sprintf(json_str, "IOCSC%u", i);
			json_id_iocs_iocsc(obj_iocsc,
					   le64_to_cpu(iocs->iocsc[i]));
			obj_add_obj(r, json_str, obj_iocsc);
		}
	}
}

static void json_nvme_id_ns_lbaf(struct nvme_id_ns *ns, int i,
				 struct json_object *lbafs)
{
	struct json_object *lbaf = json_create_object();
	__u8 flbas;

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &flbas);

	if (json_verbose_mode()) {
		obj_add_int(lbaf, "LBA Format", i);
		json_object_add_string(lbaf, "Metadata Size", "%d bytes",
				       le16_to_cpu(ns->lbaf[i].ms));
		json_object_add_string(lbaf, "Data Size", "%u bytes",
				       nvme_lbaf_data_size(ns->lbaf[i].ds));
		json_object_add_string(lbaf, "Relative Performance", "0x%x %s",
				       ns->lbaf[i].rp,
				       ns->lbaf[i].rp == 3 ? "Degraded" :
				       ns->lbaf[i].rp == 2 ? "Good" :
				       ns->lbaf[i].rp == 1 ? "Better" : "Best");
		obj_add_str(lbaf, "in use", i == flbas ? "yes" : "no");
	} else {
		obj_add_int(lbaf, "lbaf", i);
		obj_add_int(lbaf, "ms", le16_to_cpu(ns->lbaf[i].ms));
		obj_add_int(lbaf, "ds", ns->lbaf[i].ds);
		obj_add_int(lbaf, "rp", ns->lbaf[i].rp);
		obj_add_int(lbaf, "in_use", i == flbas);
	}

	array_add_obj(lbafs, lbaf);
}

static void json_nvme_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
			    unsigned int lba_index, bool cap_only)
{
	char nguid[2 * sizeof(ns->nguid) + 1];
	char eui64[2 * sizeof(ns->eui64) + 1];
	struct json_object *r = json_root();
	struct json_object *lbafs = json_create_array();
	int i;
	shr_uint128_t nvmcap = le128_to_cpu(ns->nvmcap);

	if (!cap_only) {
		obj_add_uint64(r, "nsze", le64_to_cpu(ns->nsze));
		obj_add_uint64(r, "ncap", le64_to_cpu(ns->ncap));
		obj_add_uint64(r, "nuse", le64_to_cpu(ns->nuse));
		obj_add_int(r, "nsfeat", ns->nsfeat);
	}

	obj_add_int(r, "nlbaf", ns->nlbaf);

	if (!cap_only)
		obj_add_int(r, "flbas", ns->flbas);

	obj_add_int(r, "mc", ns->mc);
	obj_add_int(r, "dpc", ns->dpc);

	if (!cap_only) {
		obj_add_int(r, "dps", ns->dps);
		obj_add_int(r, "nmic", ns->nmic);
		obj_add_int(r, "rescap", ns->rescap);
		obj_add_int(r, "fpi", ns->fpi);
		obj_add_int(r, "dlfeat", ns->dlfeat);
		obj_add_int(r, "nawun", le16_to_cpu(ns->nawun));
		obj_add_int(r, "nawupf", le16_to_cpu(ns->nawupf));
		obj_add_int(r, "nacwu", le16_to_cpu(ns->nacwu));
		obj_add_int(r, "nabsn", le16_to_cpu(ns->nabsn));
		obj_add_int(r, "nabo", le16_to_cpu(ns->nabo));
		obj_add_int(r, "nabspf", le16_to_cpu(ns->nabspf));
		obj_add_int(r, "noiob", le16_to_cpu(ns->noiob));
		obj_add_uint128(r, "nvmcap", nvmcap);

		if (ns->nsfeat & 0x30) {
			obj_add_int(r, "npwg", le16_to_cpu(ns->npwg));
			obj_add_int(r, "npwa", le16_to_cpu(ns->npwa));
			if (ns->nsfeat & 0x10)
				obj_add_int(r, "npdg", le16_to_cpu(ns->npdg));
			obj_add_int(r, "npda", le16_to_cpu(ns->npda));
			obj_add_int(r, "nows", le16_to_cpu(ns->nows));
		}

		obj_add_int(r, "mssrl", le16_to_cpu(ns->mssrl));
		obj_add_uint(r, "mcl", le32_to_cpu(ns->mcl));
		obj_add_int(r, "msrc", ns->msrc);
		obj_add_uint(r, "kpios", ns->kpios);
	}

	obj_add_int(r, "nulbaf", ns->nulbaf);

	if (!cap_only) {
		obj_add_uint(r, "kpiodaag", le32_to_cpu(ns->kpiodaag));
		obj_add_uint(r, "anagrpid", le32_to_cpu(ns->anagrpid));
		obj_add_int(r, "nsattr", ns->nsattr);
		obj_add_int(r, "nvmsetid", le16_to_cpu(ns->nvmsetid));
		obj_add_int(r, "endgid", le16_to_cpu(ns->endgid));

		shr_bin_to_hex(eui64, sizeof(eui64), ns->eui64,
			       sizeof(ns->eui64), 0);
		shr_bin_to_hex(nguid, sizeof(nguid), ns->nguid,
			       sizeof(ns->nguid), 0);

		obj_add_str(r, "nguid", nguid);
		obj_add_str(r, "eui64", eui64);
	}

	obj_add_array(r, "lbafs", lbafs);

	for (i = 0; i < nvme_id_ns_nr_lbaf(ns); i++)
		json_nvme_id_ns_lbaf(ns, i, lbafs);

	obj_d(r, "vs", ns->vs, strnlen((const char *)ns->vs, sizeof(ns->vs)),
	      16, 1);
}

static void json_nvme_id_ctrl(struct nvme_id_ctrl *ctrl,
			      const char *product_name,
			      void (*vs)(__u8 *vs, struct json_object *r))
{
	struct json_object *r = json_root();
	struct json_object *psds = json_create_array();
	shr_uint128_t tnvmcap = le128_to_cpu(ctrl->tnvmcap);
	shr_uint128_t unvmcap = le128_to_cpu(ctrl->unvmcap);
	shr_uint128_t megcap = le128_to_cpu(ctrl->megcap);
	shr_uint128_t maxdna = le128_to_cpu(ctrl->maxdna);
	char sn[sizeof(ctrl->sn) + 1], mn[sizeof(ctrl->mn) + 1],
		fr[sizeof(ctrl->fr) + 1], subnqn[sizeof(ctrl->subnqn) + 1];
	__u32 ieee = ctrl->ieee[2] << 16 | ctrl->ieee[1] << 8 | ctrl->ieee[0];
	int i;

	snprintf(sn, sizeof(sn), "%-.*s", (int)sizeof(ctrl->sn), ctrl->sn);
	snprintf(mn, sizeof(mn), "%-.*s", (int)sizeof(ctrl->mn), ctrl->mn);
	snprintf(fr, sizeof(fr), "%-.*s", (int)sizeof(ctrl->fr), ctrl->fr);
	snprintf(subnqn, sizeof(subnqn), "%-.*s", (int)sizeof(ctrl->subnqn),
		 ctrl->subnqn);

	if (product_name)
		obj_add_str(r, "product_name", product_name);

	obj_add_int(r, "vid", le16_to_cpu(ctrl->vid));
	obj_add_int(r, "ssvid", le16_to_cpu(ctrl->ssvid));
	obj_add_str(r, "sn", shr_rtrim(sn));
	obj_add_str(r, "mn", shr_rtrim(mn));
	obj_add_str(r, "fr", shr_rtrim(fr));
	obj_add_int(r, "rab", ctrl->rab);
	obj_add_int(r, "ieee", ieee);
	obj_add_int(r, "cmic", ctrl->cmic);
	obj_add_int(r, "mdts", ctrl->mdts);
	obj_add_int(r, "cntlid", le16_to_cpu(ctrl->cntlid));
	obj_add_uint(r, "ver", le32_to_cpu(ctrl->ver));
	obj_add_uint(r, "rtd3r", le32_to_cpu(ctrl->rtd3r));
	obj_add_uint(r, "rtd3e", le32_to_cpu(ctrl->rtd3e));
	obj_add_uint(r, "oaes", le32_to_cpu(ctrl->oaes));
	obj_add_uint(r, "ctratt", le32_to_cpu(ctrl->ctratt));
	obj_add_int(r, "rrls", le16_to_cpu(ctrl->rrls));
	obj_add_int(r, "bpcap", ctrl->bpcap);
	obj_add_uint(r, "nssl", le32_to_cpu(ctrl->nssl));
	obj_add_int(r, "plsi", ctrl->plsi);
	obj_add_int(r, "cntrltype", ctrl->cntrltype);
	obj_add_str(r, "fguid", shr_uuid_to_string(ctrl->fguid));
	obj_add_int(r, "crdt1", le16_to_cpu(ctrl->crdt1));
	obj_add_int(r, "crdt2", le16_to_cpu(ctrl->crdt2));
	obj_add_int(r, "crdt3", le16_to_cpu(ctrl->crdt3));
	obj_add_int(r, "crcap", ctrl->crcap);
	obj_add_int(r, "ciu", ctrl->ciu);
	obj_add_uint64(r, "cirn", le64_to_cpu(*(__le64 *)ctrl->cirn));
	obj_add_int(r, "nvmsr", ctrl->nvmsr);
	obj_add_int(r, "vwci", ctrl->vwci);
	obj_add_int(r, "mec", ctrl->mec);
	obj_add_int(r, "oacs", le16_to_cpu(ctrl->oacs));
	obj_add_int(r, "acl", ctrl->acl);
	obj_add_int(r, "aerl", ctrl->aerl);
	obj_add_int(r, "frmw", ctrl->frmw);
	obj_add_int(r, "lpa", ctrl->lpa);
	obj_add_int(r, "elpe", ctrl->elpe);
	obj_add_int(r, "npss", ctrl->npss);
	obj_add_int(r, "avscc", ctrl->avscc);
	obj_add_int(r, "apsta", ctrl->apsta);
	obj_add_int(r, "wctemp", le16_to_cpu(ctrl->wctemp));
	obj_add_int(r, "cctemp", le16_to_cpu(ctrl->cctemp));
	obj_add_int(r, "mtfa", le16_to_cpu(ctrl->mtfa));
	obj_add_uint(r, "hmpre", le32_to_cpu(ctrl->hmpre));
	obj_add_uint(r, "hmmin", le32_to_cpu(ctrl->hmmin));
	obj_add_uint128(r, "tnvmcap", tnvmcap);
	obj_add_uint128(r, "unvmcap", unvmcap);
	obj_add_uint(r, "rpmbs", le32_to_cpu(ctrl->rpmbs));
	obj_add_int(r, "edstt", le16_to_cpu(ctrl->edstt));
	obj_add_int(r, "dsto", ctrl->dsto);
	obj_add_int(r, "fwug", ctrl->fwug);
	obj_add_int(r, "kas", le16_to_cpu(ctrl->kas));
	obj_add_int(r, "hctma", le16_to_cpu(ctrl->hctma));
	obj_add_int(r, "mntmt", le16_to_cpu(ctrl->mntmt));
	obj_add_int(r, "mxtmt", le16_to_cpu(ctrl->mxtmt));
	obj_add_uint(r, "sanicap", le32_to_cpu(ctrl->sanicap));
	obj_add_uint(r, "hmminds", le32_to_cpu(ctrl->hmminds));
	obj_add_int(r, "hmmaxd", le16_to_cpu(ctrl->hmmaxd));
	obj_add_int(r, "nsetidmax", le16_to_cpu(ctrl->nsetidmax));
	obj_add_int(r, "endgidmax", le16_to_cpu(ctrl->endgidmax));
	obj_add_int(r, "anatt", ctrl->anatt);
	obj_add_int(r, "anacap", ctrl->anacap);
	obj_add_uint(r, "anagrpmax", le32_to_cpu(ctrl->anagrpmax));
	obj_add_uint(r, "nanagrpid", le32_to_cpu(ctrl->nanagrpid));
	obj_add_uint(r, "pels", le32_to_cpu(ctrl->pels));
	obj_add_int(r, "domainid", le16_to_cpu(ctrl->domainid));
	obj_add_int(r, "kpioc", ctrl->kpioc);
	obj_add_int(r, "mptfawr", le16_to_cpu(ctrl->mptfawr));
	obj_add_uint128(r, "megcap", megcap);
	obj_add_int(r, "tmpthha", ctrl->tmpthha);
	obj_add_int(r, "mupa", ctrl->mupa);
	obj_add_int(r, "cqt", le16_to_cpu(ctrl->cqt));
	obj_add_int(r, "cdpa", le16_to_cpu(ctrl->cdpa));
	obj_add_int(r, "mup", le16_to_cpu(ctrl->mup));
	obj_add_int(r, "ipmsr", le16_to_cpu(ctrl->ipmsr));
	obj_add_int(r, "msmt", le16_to_cpu(ctrl->msmt));
	obj_add_int(r, "mnens", le16_to_cpu(ctrl->mnens));
	obj_add_int(r, "mnecpens", le16_to_cpu(ctrl->mnecpens));
	obj_add_uint(r, "mensnn", le32_to_cpu(ctrl->mensnn));
	obj_add_int(r, "ensa", le16_to_cpu(ctrl->ensa));
	obj_add_int(r, "endsfs", le16_to_cpu(ctrl->endsfs));
	obj_add_uint(r, "vsen1", le32_to_cpu(ctrl->vsen1));
	obj_add_uint(r, "vsen2", le32_to_cpu(ctrl->vsen2));
	obj_add_uint(r, "vsen3", le32_to_cpu(ctrl->vsen3));
	obj_add_uint(r, "vsen4", le32_to_cpu(ctrl->vsen4));
	obj_add_int(r, "msvmt", le16_to_cpu(ctrl->msvmt));
	obj_add_int(r, "sqes", ctrl->sqes);
	obj_add_int(r, "cqes", ctrl->cqes);
	obj_add_int(r, "maxcmd", le16_to_cpu(ctrl->maxcmd));
	obj_add_uint(r, "nn", le32_to_cpu(ctrl->nn));
	obj_add_int(r, "oncs", le16_to_cpu(ctrl->oncs));
	obj_add_int(r, "fuses", le16_to_cpu(ctrl->fuses));
	obj_add_int(r, "fna", ctrl->fna);
	obj_add_int(r, "vwc", ctrl->vwc);
	obj_add_int(r, "awun", le16_to_cpu(ctrl->awun));
	obj_add_int(r, "awupf", le16_to_cpu(ctrl->awupf));
	obj_add_int(r, "icsvscc", ctrl->icsvscc);
	obj_add_int(r, "nwpc", ctrl->nwpc);
	obj_add_int(r, "acwu", le16_to_cpu(ctrl->acwu));
	obj_add_int(r, "cdfs", le16_to_cpu(ctrl->cdfs));
	obj_add_uint(r, "sgls", le32_to_cpu(ctrl->sgls));
	obj_add_uint(r, "mnan", le32_to_cpu(ctrl->mnan));
	obj_add_uint128(r, "maxdna", maxdna);
	obj_add_uint(r, "maxcna", le32_to_cpu(ctrl->maxcna));
	obj_add_uint(r, "oaqd", le32_to_cpu(ctrl->oaqd));
	obj_add_int(r, "rhiri", ctrl->rhiri);
	obj_add_int(r, "hirt", ctrl->hirt);
	obj_add_int(r, "cmmrtd", le16_to_cpu(ctrl->cmmrtd));
	obj_add_int(r, "nmmrtd", le16_to_cpu(ctrl->nmmrtd));
	obj_add_int(r, "minmrtg", ctrl->minmrtg);
	obj_add_int(r, "maxmrtg", ctrl->maxmrtg);
	obj_add_int(r, "trattr", ctrl->trattr);
	obj_add_int(r, "mcudmq", le16_to_cpu(ctrl->mcudmq));
	obj_add_int(r, "mnsudmq", le16_to_cpu(ctrl->mnsudmq));
	obj_add_int(r, "mcmr", le16_to_cpu(ctrl->mcmr));
	obj_add_int(r, "nmcmr", le16_to_cpu(ctrl->nmcmr));
	obj_add_int(r, "mcdqpc", le16_to_cpu(ctrl->mcdqpc));

	if (strlen(subnqn))
		obj_add_str(r, "subnqn", subnqn);

	obj_add_uint(r, "ioccsz", le32_to_cpu(ctrl->ioccsz));
	obj_add_uint(r, "iorcsz", le32_to_cpu(ctrl->iorcsz));
	obj_add_int(r, "icdoff", le16_to_cpu(ctrl->icdoff));
	obj_add_int(r, "fcatt", ctrl->fcatt);
	obj_add_int(r, "msdbd", ctrl->msdbd);
	obj_add_int(r, "ofcs", le16_to_cpu(ctrl->ofcs));
	obj_add_int(r, "dctype", ctrl->dctype);
	obj_add_int(r, "ccrl", ctrl->ccrl);

	obj_add_array(r, "psds", psds);

	for (i = 0; i < nvme_id_ctrl_nr_psd(ctrl); i++) {
		struct json_object *psd = json_create_object();

		obj_add_int(psd, "max_power", le16_to_cpu(ctrl->psd[i].mp));
		obj_add_int(psd, "max_power_scale",
			    ctrl->psd[i].flags & NVME_PSD_FLAGS_MXPS);
		obj_add_int(psd, "non-operational_state",
			    !!(ctrl->psd[i].flags & NVME_PSD_FLAGS_NOPS));
		obj_add_uint(psd, "entry_lat", le32_to_cpu(ctrl->psd[i].enlat));
		obj_add_uint(psd, "exit_lat", le32_to_cpu(ctrl->psd[i].exlat));
		obj_add_int(psd, "read_tput", ctrl->psd[i].rrt);
		obj_add_int(psd, "read_lat", ctrl->psd[i].rrl);
		obj_add_int(psd, "write_tput", ctrl->psd[i].rwt);
		obj_add_int(psd, "write_lat", ctrl->psd[i].rwl);
		obj_add_int(psd, "idle_power", le16_to_cpu(ctrl->psd[i].idlp));
		obj_add_int(psd, "idle_scale",
			    nvme_psd_power_scale(ctrl->psd[i].ips));
		obj_add_int(psd, "active_power",
			    le16_to_cpu(ctrl->psd[i].actp));
		obj_add_int(psd, "active_power_work", ctrl->psd[i].apws & 7);
		obj_add_int(psd, "active_scale",
			    nvme_psd_power_scale(ctrl->psd[i].apws));
		obj_add_int(psd, "emerg_power_fail_recover_time",
			    ctrl->psd[i].epfrt);
		obj_add_int(psd, "emerg_power_fail_recover_scale",
			    ctrl->psd[i].epfr_fqv_ts & 0xf);
		obj_add_int(psd, "force_quiesce_vault_time", ctrl->psd[i].fqvt);
		obj_add_int(psd, "force_quiesce_vault_scale",
			    ctrl->psd[i].epfr_fqv_ts >> 4);
		obj_add_int(psd, "emerg_power_fail_vault_time",
			    ctrl->psd[i].epfvt);
		obj_add_int(psd, "emerg_power_fail_vault_scale",
			    ctrl->psd[i].epfvts & 0xf);
		obj_add_int(psd, "max_bandwidth", ctrl->psd[i].mbw);
		obj_add_int(psd, "max_bandwidth_scale",
			    ctrl->psd[i].mbws & 0x7);
		obj_add_int(psd, "min_idle_io_exit_lat_limit",
			    le16_to_cpu(ctrl->psd[i].miiell));

		array_add_obj(psds, psd);
	}

	if (vs)
		vs(ctrl->vs, r);
}

static void json_nvme_cmd_set_independent_id_ns(
		struct nvme_id_independent_id_ns *ns, unsigned int nsid)
{
	struct json_object *r = json_root();

	obj_add_int(r, "nsfeat", ns->nsfeat);
	obj_add_int(r, "nmic", ns->nmic);
	obj_add_int(r, "rescap", ns->rescap);
	obj_add_int(r, "fpi", ns->fpi);
	obj_add_uint(r, "anagrpid", le32_to_cpu(ns->anagrpid));
	obj_add_int(r, "nsattr", ns->nsattr);
	obj_add_int(r, "nvmsetid", le16_to_cpu(ns->nvmsetid));
	obj_add_int(r, "endgid", le16_to_cpu(ns->endgid));
	obj_add_int(r, "nstat", ns->nstat);
	obj_add_int(r, "kpios", ns->kpios);
	obj_add_int(r, "maxkt", le16_to_cpu(ns->maxkt));
	obj_add_int(r, "rgrpid", le32_to_cpu(ns->rgrpid));
}

static void json_nvme_id_ns_descs(void *data, unsigned int nsid)
{
	/* large enough to hold uuid str (37) or nguid str (32) + zero byte */
	char json_str[STR_LEN];
	union {
		__u8 eui64[NVME_NIDT_EUI64_LEN];
		__u8 nguid[NVME_NIDT_NGUID_LEN];
		__u8 uuid[NVME_UUID_LEN];
		__u8 csi;
	} desc;
	struct json_object *r = json_root();
	struct json_object *json_array = NULL;
	struct nvme_ns_id_desc *cur;
	size_t pos, off;

	for (pos = 0; (cur = nvme_ns_id_desc(data, pos));
	     pos += sizeof(*cur) + cur->nidl) {
		const char *nidt_name = NULL;

		memset(json_str, 0, sizeof(json_str));
		off = pos + sizeof(*cur);

		switch (nvme_ns_id_desc_type(cur)) {
		case NVME_NIDT_EUI64:
			memcpy(desc.eui64, data + off, sizeof(desc.eui64));
			shr_bin_to_hex(json_str, sizeof(json_str), desc.eui64,
				       sizeof(desc.eui64), 0);
			nidt_name = "eui64";
			break;
		case NVME_NIDT_NGUID:
			memcpy(desc.nguid, data + off, sizeof(desc.nguid));
			shr_bin_to_hex(json_str, sizeof(json_str), desc.nguid,
				       sizeof(desc.nguid), 0);
			nidt_name = "nguid";
			break;
		case NVME_NIDT_UUID:
			memcpy(desc.uuid, data + off, sizeof(desc.uuid));
			libnvme_uuid_to_string(desc.uuid, json_str);
			nidt_name = "uuid";
			break;
		case NVME_NIDT_CSI:
			memcpy(&desc.csi, data + off, sizeof(desc.csi));
			sprintf(json_str, "%#x", desc.csi);
			nidt_name = "csi";
			break;
		default:
			/* Skip unknown types */
			break;
		}

		if (nidt_name) {
			struct json_object *elem = json_create_object();

			obj_add_int(elem, "loc", pos);
			obj_add_int(elem, "nidt", (int)cur->nidt);
			obj_add_int(elem, "nidl", (int)cur->nidl);
			obj_add_str(elem, "Type", nidt_name);
			obj_add_str(elem, nidt_name, json_str);

			if (!json_array)
				json_array = json_create_array();
			array_add_obj(json_array, elem);
		}
	}

	if (json_array)
		obj_add_array(r, "ns-descs", json_array);
}

static void json_id_ctrl_rpmbs(__le32 ctrl_rpmbs)
{
	struct json_object *r = json_root();
	__u32 rpmbs = le32_to_cpu(ctrl_rpmbs);
	__u32 asz = (rpmbs & 0xFF000000) >> 24;
	__u32 tsz = (rpmbs & 0xFF0000) >> 16;
	__u32 rsvd = (rpmbs & 0xFFC0) >> 6;
	__u32 auth = (rpmbs & 0x38) >> 3;
	__u32 rpmb = rpmbs & 7;

	obj_add_uint_nx(r, "[31:24]: Access Size", asz);
	obj_add_uint_nx(r, "[23:16]: Total Size", tsz);

	if (rsvd)
		obj_add_uint_nx(r, "[15:6]: Reserved", rsvd);

	obj_add_uint_nx(r, "[5:3]: Authentication Method", auth);
	obj_add_uint_nx(r, "[2:0]: Number of RPMB Units", rpmb);
}

static void json_nvme_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm)
{
	struct json_object *r = json_root();

	obj_add_uint(r, "vsl", ctrl_nvm->vsl);
	obj_add_uint(r, "wzsl", ctrl_nvm->wzsl);
	obj_add_uint(r, "wusl", ctrl_nvm->wusl);
	obj_add_uint(r, "dmrl", ctrl_nvm->dmrl);
	obj_add_uint(r, "dmrsl", le32_to_cpu(ctrl_nvm->dmrsl));
	obj_add_uint64(r, "dmsl", le64_to_cpu(ctrl_nvm->dmsl));
	obj_add_uint(r, "kpiocap", ctrl_nvm->kpiocap);
	obj_add_uint(r, "wzdsl", ctrl_nvm->wzdsl);
	obj_add_uint(r, "aocs", le16_to_cpu(ctrl_nvm->aocs));

	if (json_verbose_mode()) {
		__u16 rsvd = (ctrl_nvm->aocs & 0xfffe) >> 1;
		__u8 ralbas = ctrl_nvm->aocs & 0x1;

		if (rsvd)
			obj_add_uint(r, "[15:1]: Reserved", rsvd);
		obj_add_uint(r, "[0:0]: Reporting Allocated LBA Supported",
			     ralbas);
	}

	obj_add_uint(r, "ver", le32_to_cpu(ctrl_nvm->ver));
	obj_add_uint(r, "lbamqf", ctrl_nvm->lbamqf);
}

static void json_nvme_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns,
				unsigned int nsid, struct nvme_id_ns *ns,
				unsigned int lba_index, bool cap_only)

{
	struct json_object *r = json_root();
	struct json_object *elbafs = json_create_array();
	int i;

	if (!cap_only)
		obj_add_uint64(r, "lbstm", le64_to_cpu(nvm_ns->lbstm));

	obj_add_int(r, "pic", nvm_ns->pic);
	obj_add_int(r, "pifa", nvm_ns->pifa);

	obj_add_array(r, "elbafs", elbafs);

	for (i = 0; i < nvme_id_ns_nr_lbaf(ns); i++) {
		struct json_object *elbaf = json_create_object();
		unsigned int elbaf_val = le32_to_cpu(nvm_ns->elbaf[i]);

		obj_add_uint(elbaf, "sts", elbaf_val & 0x7F);
		obj_add_uint(elbaf, "pif", (elbaf_val >> 7) & 0x3);
		obj_add_uint(elbaf, "qpif", (elbaf_val >> 9) & 0xF);

		array_add_obj(elbafs, elbaf);
	}
	if (ns->nsfeat & 0x20)
		obj_add_int(r, "npdgl", le32_to_cpu(nvm_ns->npdgl));

	obj_add_uint(r, "nprg", le32_to_cpu(nvm_ns->nprg));
	obj_add_uint(r, "npra", le32_to_cpu(nvm_ns->npra));
	obj_add_uint(r, "nors", le32_to_cpu(nvm_ns->nors));
	obj_add_uint(r, "npdal", le32_to_cpu(nvm_ns->npdal));
	obj_add_uint(r, "lbapss", le32_to_cpu(nvm_ns->lbapss));
	obj_add_uint(r, "tlbaag", le32_to_cpu(nvm_ns->tlbaag));
}

static void json_nvme_list_ns(struct nvme_ns_list *ns_list)
{
	struct json_object *r = json_root();
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();
	int i;

	for (i = 0; i < 1024; i++) {
		if (ns_list->ns[i]) {
			valid_attrs = json_create_object();
			obj_add_uint(valid_attrs, "nsid",
				     le32_to_cpu(ns_list->ns[i]));
			array_add_obj(valid, valid_attrs);
		}
	}

	obj_add_array(r, "nsid_list", valid);
}

static void json_nvme_list_ctrl(struct nvme_ctrl_list *ctrl_list)
{
	__u16 num = le16_to_cpu(ctrl_list->num);
	struct json_object *r = json_root();
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();
	int i;

	obj_add_uint(r, "num_ctrl", le16_to_cpu(ctrl_list->num));

	for (i = 0; i < min(num, 2047); i++) {
		valid_attrs = json_create_object();
		obj_add_uint(valid_attrs, "ctrl_id",
			     le16_to_cpu(ctrl_list->identifier[i]));
		array_add_obj(valid, valid_attrs);
	}

	obj_add_array(r, "ctrl_list", valid);
}

static void json_nvme_id_nvmset(struct nvme_id_nvmset_list *nvmset,
				unsigned int nvmeset_id)
{
	__u32 nent = nvmset->nid;
	struct json_object *entries = json_create_array();
	struct json_object *r = json_root();
	int i;

	obj_add_int(r, "nid", nent);

	for (i = 0; i < nent && i < ARRAY_SIZE(nvmset->ent); i++) {
		struct json_object *entry = json_create_object();

		obj_add_int(entry, "nvmset_id",
			    le16_to_cpu(nvmset->ent[i].nvmsetid));
		obj_add_int(entry, "endurance_group_id",
			    le16_to_cpu(nvmset->ent[i].endgid));
		obj_add_uint(entry, "random_4k_read_typical",
			     le32_to_cpu(nvmset->ent[i].rr4kt));
		obj_add_uint(entry, "optimal_write_size",
			     le32_to_cpu(nvmset->ent[i].ows));
		obj_add_uint128(entry, "total_nvmset_cap",
				le128_to_cpu(nvmset->ent[i].tnvmsetcap));
		obj_add_uint128(entry, "unalloc_nvmset_cap",
				le128_to_cpu(nvmset->ent[i].unvmsetcap));
		array_add_obj(entries, entry);
	}

	obj_add_array(r, "NVMSet", entries);
}

static void json_nvme_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *caps)
{
	struct json_object *r = json_root();

	obj_add_uint(r, "cntlid", le16_to_cpu(caps->cntlid));
	obj_add_uint(r, "portid", le16_to_cpu(caps->portid));
	obj_add_uint(r, "crt", caps->crt);

	obj_add_uint(r, "vqfrt", le32_to_cpu(caps->vqfrt));
	obj_add_uint(r, "vqrfa", le32_to_cpu(caps->vqrfa));
	obj_add_int(r, "vqrfap", le16_to_cpu(caps->vqrfap));
	obj_add_int(r, "vqprt", le16_to_cpu(caps->vqprt));
	obj_add_int(r, "vqfrsm", le16_to_cpu(caps->vqfrsm));
	obj_add_int(r, "vqgran", le16_to_cpu(caps->vqgran));

	obj_add_uint(r, "vifrt", le32_to_cpu(caps->vifrt));
	obj_add_uint(r, "virfa", le32_to_cpu(caps->virfa));
	obj_add_int(r, "virfap", le16_to_cpu(caps->virfap));
	obj_add_int(r, "viprt",  le16_to_cpu(caps->viprt));
	obj_add_int(r, "vifrsm", le16_to_cpu(caps->vifrsm));
	obj_add_int(r, "vigran", le16_to_cpu(caps->vigran));
}

static void json_nvme_list_secondary_ctrl(
		const struct nvme_secondary_ctrl_list *sc_list, __u32 count)
{
	const struct nvme_secondary_ctrl *sc_entry = &sc_list->sc_entry[0];
	__u32 nent = min(sc_list->num, count);
	struct json_object *entries = json_create_array();
	struct json_object *r = json_root();
	int i;

	obj_add_int(r, "num", nent);

	for (i = 0; i < nent; i++) {
		struct json_object *entry = json_create_object();

		obj_add_int(entry, "secondary-controller-identifier",
			    le16_to_cpu(sc_entry[i].scid));
		obj_add_int(entry, "primary-controller-identifier",
			    le16_to_cpu(sc_entry[i].pcid));
		obj_add_int(entry, "secondary-controller-state",
			    sc_entry[i].scs);
		obj_add_int(entry, "virtual-function-number",
			    le16_to_cpu(sc_entry[i].vfn));
		obj_add_int(entry, "num-virtual-queues",
			    le16_to_cpu(sc_entry[i].nvq));
		obj_add_int(entry, "num-virtual-interrupts",
			    le16_to_cpu(sc_entry[i].nvi));
		array_add_obj(entries, entry);
	}

	obj_add_array(r, "secondary-controllers", entries);
}

static void json_nvme_id_ns_granularity_list(
		const struct nvme_id_ns_granularity_list *glist)
{
	int i;
	struct json_object *r = json_root();
	struct json_object *entries = json_create_array();

	obj_add_int(r, "attributes", glist->attributes);
	obj_add_int(r, "num-descriptors", glist->num_descriptors);

	for (i = 0; i <= glist->num_descriptors && i < ARRAY_SIZE(glist->entry);
	     i++) {
		struct json_object *entry = json_create_object();

		obj_add_uint64(entry, "namespace-size-granularity",
			       le64_to_cpu(glist->entry[i].nszegran));
		obj_add_uint64(entry, "namespace-capacity-granularity",
			       le64_to_cpu(glist->entry[i].ncapgran));
		array_add_obj(entries, entry);
	}

	obj_add_array(r, "namespace-granularity-list", entries);
}

static void json_nvme_id_uuid_list(const struct nvme_id_uuid_list *uuid_list)
{
	struct json_object *r = json_root();
	struct json_object *entries = json_create_array();
	int i;

	for (i = 0; i < NVME_ID_UUID_LIST_MAX; i++) {
		__u8 uuid[NVME_UUID_LEN];
		struct json_object *entry;

		/* The list is terminated by a zero UUID value */
		if (memcmp(uuid_list->entry[i].uuid, zero_uuid,
			   sizeof(zero_uuid)) == 0)
			break;
		entry = json_create_object();
		memcpy(&uuid, uuid_list->entry[i].uuid, sizeof(uuid));
		obj_add_int(entry, "association",
			uuid_list->entry[i].header & 0x3);
		obj_add_str(entry, "uuid",
			shr_uuid_to_string(uuid));
		array_add_obj(entries, entry);
	}

	obj_add_array(r, "UUID-list", entries);
}

static void json_id_domain_list(struct nvme_id_domain_list *id_dom)
{
	struct json_object *r = json_root();
	struct json_object *entries = json_create_array();
	struct json_object *entry;
	int i;
	shr_uint128_t dom_cap, unalloc_dom_cap, max_egrp_dom_cap;

	obj_add_uint(r, "num_dom_entries", id_dom->num);

	for (i = 0; i < id_dom->num && i < ARRAY_SIZE(id_dom->domain_attr);
	     i++) {
		entry = json_create_object();
		dom_cap = le128_to_cpu(id_dom->domain_attr[i].dom_cap);
		unalloc_dom_cap =
			le128_to_cpu(id_dom->domain_attr[i].unalloc_dom_cap);
		max_egrp_dom_cap =
			le128_to_cpu(id_dom->domain_attr[i].max_egrp_dom_cap);

		obj_add_uint(entry, "dom_id",
			     le16_to_cpu(id_dom->domain_attr[i].dom_id));
		obj_add_uint128(entry, "dom_cap", dom_cap);
		obj_add_uint128(entry, "unalloc_dom_cap", unalloc_dom_cap);
		obj_add_uint128(entry, "max_egrp_dom_cap", max_egrp_dom_cap);

		array_add_obj(entries, entry);
	}

	obj_add_array(r, "domain_list", entries);
}

static void json_nvme_endurance_group_list(
		struct nvme_id_endurance_group_list *endgrp_list)
{
	struct json_object *r = json_root();
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();
	int i;

	obj_add_uint(r, "num_endgrp_id", le16_to_cpu(endgrp_list->num));

	for (i = 0; i < min(le16_to_cpu(endgrp_list->num), 2047); i++) {
		valid_attrs = json_create_object();
		obj_add_uint(valid_attrs, "endgrp_id",
			     le16_to_cpu(endgrp_list->identifier[i]));
		array_add_obj(valid, valid_attrs);
	}

	obj_add_array(r, "endgrp_list", valid);
}

static struct id_print_ops id_json_print_ops = {
	.ctrl_list			= json_nvme_list_ctrl,
	.endurance_group_list		= json_nvme_endurance_group_list,
	.id_ctrl			= json_nvme_id_ctrl,
	.id_ctrl_nvm			= json_nvme_id_ctrl_nvm,
	.id_ctrl_rpmbs			= json_id_ctrl_rpmbs,
	.id_domain_list			= json_id_domain_list,
	.id_independent_id_ns		= json_nvme_cmd_set_independent_id_ns,
	.id_iocs			= json_id_iocs,
	.id_ns				= json_nvme_id_ns,
	.id_ns_descs			= json_nvme_id_ns_descs,
	.id_ns_granularity_list		= json_nvme_id_ns_granularity_list,
	.id_nvmset_list			= json_nvme_id_nvmset,
	.id_uuid_list			= json_nvme_id_uuid_list,
	.ns_list			= json_nvme_list_ns,
	.nvm_id_ns			= json_nvme_nvm_id_ns,
	.primary_ctrl_cap		= json_nvme_primary_ctrl_cap,
	.secondary_ctrl_list		= json_nvme_list_secondary_ctrl,
};

struct id_print_ops *id_get_json_print_ops(nvme_print_flags_t flags)
{
	id_json_print_ops.flags = flags;
	return &id_json_print_ops;
}
