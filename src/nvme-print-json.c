// SPDX-License-Identifier: GPL-2.0-or-later

#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef CONFIG_FABRICS
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include <libnvme-mi.h>
#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/compiler/compiler.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>
#include <ccan/str/str.h>
#include <shared/compiler-attributes-util.h>
#include <shared/hex-util.h>
#include <shared/mmio-util.h>
#include <shared/string-util.h>
#include <shared/unaligned-util.h>

#include "cleanup.h"
#include "global-ctx.h"
#include "nvme-iostat.h"
#include "nvme-json.h"
#include "nvme-print.h"
#include "nvme-print-json.h"

#define ERROR_MSG_LEN 100
#define NAME_LEN 128
#define BUF_LEN 320
#define VAL_LEN 4096

static const uint8_t zero_uuid[16] = { 0 };
static struct print_ops json_print_ops;
static struct json_object *json_r;
static bool json_init;

static void d_json(unsigned char *buf, int len, int width, int group, struct json_object *array)
{
	int i;
	char ascii[32 + 1] = { 0 };

	assert(width < sizeof(ascii));

	for (i = 0; i < len; i++) {
		ascii[i % width] = (buf[i] >= '!' && buf[i] <= '~') ? buf[i] : '.';
		if (!((i + 1) % width)) {
			array_add_str(array, ascii);
			memset(ascii, 0, sizeof(ascii));
		}
	}

	if (strlen(ascii)) {
		ascii[i % width + 1] = '\0';
		array_add_str(array, ascii);
	}
}

void obj_d(struct json_object *o, const char *k, unsigned char *buf, int len,
	   int width, int group)
{
	struct json_object *data = json_create_array();

	d_json(buf, len, width, group, data);
	obj_add_array(o, k, data);
}


void obj_add_uint_nx(struct json_object *o, const char *k, __u32 v)
{
	char str[STR_LEN];

	sprintf(str, "%#x", v);
	obj_add_str(o, k, str);
}


static void obj_add_ctrl_address(struct json_object *o, struct libnvme_ctrl *c)
{
	const char *address = libnvme_ctrl_get_address(c);

	/* controllers without an address, e.g. loop, don't report one */
	obj_add_str(o, "Address", address ? address : "");
}

static void obj_add_ctrl_address_details(struct json_object *o, const char *k,
					 struct libnvme_ctrl *c)
{
	struct json_object *address_details = json_create_object();
	const char *value;
	bool has_value = false;

	value = libnvme_ctrl_get_traddr(c);
	if (value) {
		obj_add_str(address_details, "traddr", value);
		has_value = true;
	}

	value = libnvme_ctrl_get_host_traddr(c);
	if (value) {
		obj_add_str(address_details, "host_traddr", value);
		has_value = true;
	}

	value = libnvme_ctrl_get_host_iface(c);
	if (value) {
		obj_add_str(address_details, "host_iface", value);
		has_value = true;
	}

	value = libnvme_ctrl_get_trsvcid(c);
	if (value) {
		obj_add_str(address_details, "trsvcid", value);
		has_value = true;
	}

	if (!has_value) {
		json_free_object(address_details);
		return;
	}

	obj_add_obj(o, k, address_details);
}


void obj_add_result(struct json_object *o, const char *v, ...)
{
	va_list ap;

	__cleanup_free char *value = NULL;

	va_start(ap, v);

	if (vasprintf(&value, v, ap) < 0)
		value = NULL;

	obj_add_str(o, "Result", value ? value : alloc_error);

	va_end(ap);
}

void obj_add_key(struct json_object *o, const char *k, const char *v, ...)
{
	va_list ap;

	__cleanup_free char *value = NULL;

	va_start(ap, v);

	if (vasprintf(&value, v, ap) < 0)
		value = NULL;

	obj_add_str(o, k, value ? value : alloc_error);

	va_end(ap);
}

struct json_object *obj_create_array_obj(struct json_object *o, const char *k)
{
	struct json_object *array = json_create_array();
	struct json_object *obj = json_create_object();

	obj_add_array(o, k, array);
	array_add_obj(array, obj);

	return obj;
}

struct json_object *obj_create(const char *k)
{
	struct json_object *array;
	struct json_object *obj = json_create_object();

	if (json_r) {
		array = json_create_array();
		obj_add_array(json_r, k, array);
		array_add_obj(array, obj);
	}

	return obj;
}

void json_print(struct json_object *r)
{
	json_print_object(r, NULL);
	printf("\n");
	json_free_object(r);
}

void obj_print(struct json_object *o)
{
	if (!json_r)
		json_print(o);
}

static void json_id_iocs_iocsc(struct json_object *obj_iocsc, __u64 iocsc)
{
	__u8 cpncs = NVME_GET(iocsc, IOCS_IOCSC_CPNCS);
	__u8 slmcs = NVME_GET(iocsc, IOCS_IOCSC_SLMCS);
	__u8 znscs = NVME_GET(iocsc, IOCS_IOCSC_ZNSCS);
	__u8 kvcs = NVME_GET(iocsc, IOCS_IOCSC_KVCS);
	__u8 nvmcs = NVME_GET(iocsc, IOCS_IOCSC_NVMCS);

	obj_add_str(obj_iocsc, "Computational Programs Namespace Command Set", cpncs ?
		    "Selected" : "Not selected");
	obj_add_str(obj_iocsc, "Subsystem Local Memory Command Set", slmcs ?
		    "Selected" : "Not selected");
	obj_add_str(obj_iocsc, "Zoned Namespace Command Set", znscs ? "Selected" : "Not selected");
	obj_add_str(obj_iocsc, "Key Value Command Set", kvcs ? "Selected" : "Not selected");
	obj_add_str(obj_iocsc, "NVM Command Set", nvmcs ? "Selected" : "Not selected");
}

static bool verbose_mode(void)
{
	return json_print_ops.flags & VERBOSE;
}

bool json_verbose_mode(void)
{
	return verbose_mode();
}

struct json_object *json_root(void)
{
	return json_r;
}

static void json_id_iocs(struct nvme_id_iocs *iocs)
{
	struct json_object *r = json_r;
	struct json_object *obj_iocsc;
	char json_str[STR_LEN];
	__u16 i;

	for (i = 0; i < ARRAY_SIZE(iocs->iocsc); i++) {
		if (iocs->iocsc[i]) {
			sprintf(json_str, "I/O Command Set Combination[%u]", i);
			obj_add_uint64(r, json_str, le64_to_cpu(iocs->iocsc[i]));

			obj_iocsc = json_create_object();
			sprintf(json_str, "IOCSC%u", i);
			json_id_iocs_iocsc(obj_iocsc, le64_to_cpu(iocs->iocsc[i]));
			obj_add_obj(r, json_str, obj_iocsc);
		}
	}
}

static void json_nvme_id_ns_lbaf(struct nvme_id_ns *ns, int i, struct json_object *lbafs)
{
	struct json_object *lbaf = json_create_object();
	__u8 flbas;

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &flbas);

	if (verbose_mode()) {
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
	struct json_object *r = json_r;
	struct json_object *lbafs = json_create_array();
	struct json_object *vs = json_create_array();
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

	d_json(ns->vs, strnlen((const char *)ns->vs, sizeof(ns->vs)), 16, 1, vs);
	obj_add_array(r, "vs", vs);
}

void json_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, const char *product_name,
		       void (*vs)(__u8 *vs, struct json_object *r))
{
	struct json_object *r = json_r;
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
	snprintf(subnqn, sizeof(subnqn), "%-.*s", (int)sizeof(ctrl->subnqn), ctrl->subnqn);

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
	obj_add_int(r, "ocfs", le16_to_cpu(ctrl->ocfs));
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
		obj_add_int(psd, "max_power_scale", ctrl->psd[i].flags & NVME_PSD_FLAGS_MXPS);
		obj_add_int(psd, "non-operational_state",
			    !!(ctrl->psd[i].flags & NVME_PSD_FLAGS_NOPS));
		obj_add_uint(psd, "entry_lat", le32_to_cpu(ctrl->psd[i].enlat));
		obj_add_uint(psd, "exit_lat", le32_to_cpu(ctrl->psd[i].exlat));
		obj_add_int(psd, "read_tput", ctrl->psd[i].rrt);
		obj_add_int(psd, "read_lat", ctrl->psd[i].rrl);
		obj_add_int(psd, "write_tput", ctrl->psd[i].rwt);
		obj_add_int(psd, "write_lat", ctrl->psd[i].rwl);
		obj_add_int(psd, "idle_power", le16_to_cpu(ctrl->psd[i].idlp));
		obj_add_int(psd, "idle_scale", nvme_psd_power_scale(ctrl->psd[i].ips));
		obj_add_int(psd, "active_power", le16_to_cpu(ctrl->psd[i].actp));
		obj_add_int(psd, "active_power_work", ctrl->psd[i].apws & 7);
		obj_add_int(psd, "active_scale", nvme_psd_power_scale(ctrl->psd[i].apws));
		obj_add_int(psd, "emerg_power_fail_recover_time", ctrl->psd[i].epfrt);
		obj_add_int(psd, "emerg_power_fail_recover_scale", ctrl->psd[i].epfr_fqv_ts & 0xf);
		obj_add_int(psd, "force_quiesce_vault_time", ctrl->psd[i].fqvt);
		obj_add_int(psd, "force_quiesce_vault_scale", ctrl->psd[i].epfr_fqv_ts >> 4);
		obj_add_int(psd, "emerg_power_fail_vault_time", ctrl->psd[i].epfvt);
		obj_add_int(psd, "emerg_power_fail_vault_scale", ctrl->psd[i].epfvts & 0xf);
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

void json_nvme_resv_report(struct nvme_resv_status *status,
			   int bytes, bool eds)
{
	struct json_object *r = json_r;
	struct json_object *rcs = json_create_array();
	int i, entries;
	int regstrnt = status->regstrnt[0] | (status->regstrnt[1] << 8);

	obj_add_uint(r, "gen", le32_to_cpu(status->gen));
	obj_add_int(r, "rtype", status->rtype);
	obj_add_int(r, "regstrnt", regstrnt);
	obj_add_int(r, "ptpls", status->ptpls);

	/* check Extended Data Structure bit */
	if (!eds) {
		/*
		 * if status buffer was too small, don't loop past the end of
		 * the buffer
		 */
		entries = (bytes - 24) / 24;
		if (entries < regstrnt)
			regstrnt = entries;

		obj_add_array(r, "registrants", rcs);
		for (i = 0; i < regstrnt; i++) {
			struct json_object *rc = json_create_object();

			obj_add_int(rc, "cntlid", le16_to_cpu(status->registrant_ds[i].cntlid));
			obj_add_int(rc, "rcsts", status->registrant_ds[i].rcsts);
			obj_add_uint64(rc, "hostid", le64_to_cpu(status->registrant_ds[i].hostid));
			obj_add_uint64(rc, "rkey", le64_to_cpu(status->registrant_ds[i].rkey));

			array_add_obj(rcs, rc);
		}
	} else {
		char hostid[33];

		/* if status buffer was too small, don't loop past the end of the buffer */
		entries = (bytes - 64) / 64;

		if (entries < regstrnt)
			regstrnt = entries;

		obj_add_array(r, "registrantext", rcs);

		for (i = 0; i < regstrnt; i++) {
			struct json_object *rc = json_create_object();

			obj_add_int(rc, "cntlid", le16_to_cpu(status->registrant_eds[i].cntlid));
			obj_add_int(rc, "rcsts", status->registrant_eds[i].rcsts);
			obj_add_uint64(rc, "rkey", le64_to_cpu(status->registrant_eds[i].rkey));

			shr_bin_to_hex(hostid, sizeof(hostid),
				       status->registrant_eds[i].hostid,
				       sizeof(status->registrant_eds[i].hostid),
				       0);

			obj_add_str(rc, "hostid", hostid);
			array_add_obj(rcs, rc);
		}
	}
}

static void json_select_result(enum nvme_features_id fid, __u64 result)
{
	struct json_object *r = json_r;
	char json_str[STR_LEN];
	struct json_object *feature = json_create_array();

	if (result & 0x1)
		array_add_str(feature, "saveable");
	if (result & 0x2)
		array_add_str(feature, "per-namespace");
	if (result & 0x4)
		array_add_str(feature, "changeable");

	sprintf(json_str, "Feature: %#0*x: select", fid ? 4 : 2, fid);
	obj_add_array(r, json_str, feature);
}

static void json_lba_status(struct nvme_lba_status *list,
			      unsigned long len)
{
	struct json_object *r = json_r;
	__u32 nlsd = le32_to_cpu(list->nlsd);
	size_t nr = nvme_log_nr_entries(nlsd, len, sizeof(*list),
					sizeof(list->descs[0]));
	size_t idx;
	struct nvme_lba_status_desc *e;
	struct json_object *lsde;
	char json_str[STR_LEN];

	obj_add_uint(r, "Number of LBA Status Descriptors (NLSD)", nlsd);
	obj_add_uint(r, "Completion Condition (CMPC)", list->cmpc);

	switch (list->cmpc) {
	case NVME_LBA_STATUS_CMPC_NO_CMPC:
		obj_add_str(r, "cmpc-definition", "No indication of the completion condition");
		break;
	case NVME_LBA_STATUS_CMPC_INCOMPLETE:
		obj_add_str(r, "cmpc-definition",
			"Completed transferring the amount of data specified in the"\
			"MNDW field. But, additional LBA Status Descriptor Entries are"\
			"available to transfer or scan did not complete (if ATYPE = 10h)");
		break;
	case NVME_LBA_STATUS_CMPC_COMPLETE:
		obj_add_str(r, "cmpc-definition",
			"Completed the specified action over the number of LBAs specified"\
			"in the Range Length field and transferred all available LBA Status"\
			"Descriptor Entries");
		break;
	default:
		break;
	}

	for (idx = 0; idx < nr; idx++) {
		lsde = json_create_object();
		sprintf(json_str, "LSD entry %zu", idx);
		obj_add_obj(r, json_str, lsde);
		e = &list->descs[idx];
		sprintf(json_str, "0x%016"PRIx64"", le64_to_cpu(e->dslba));
		obj_add_str(lsde, "DSLBA", json_str);
		sprintf(json_str, "0x%08x", le32_to_cpu(e->nlb));
		obj_add_str(lsde, "NLB", json_str);
		sprintf(json_str, "0x%02x", e->status);
		obj_add_str(lsde, "status", json_str);
	}
}

static void json_nvme_fdp_configs(struct nvme_fdp_config_log *log, size_t len)
{
	struct json_object *r, *obj_configs;
	unsigned char *p, *end;
	uint16_t n;

	r = json_r;
	obj_configs = json_create_array();

	if (len < sizeof(*log)) {
		obj_add_array(r, "configs", obj_configs);
		return;
	}

	p = (unsigned char *)log->configs;
	end = (unsigned char *)log + len;
	n = le16_to_cpu(log->n);

	obj_add_uint(r, "n", n);

	for (int i = 0; i < n + 1; i++) {
		struct nvme_fdp_config_desc config;
		struct nvme_fdp_ruh_desc *ruhs;
		uint16_t nruh, size, max_nruh;
		struct json_object *obj_config, *obj_ruhs;

		if (!shr_buf_has_room(p, end, sizeof(config)))
			break;

		/* descriptors are only 4 byte aligned */
		memcpy(&config, p, sizeof(config));
		ruhs = (struct nvme_fdp_ruh_desc *)(p + sizeof(config));

		size = le16_to_cpu(config.size);
		if (size < sizeof(config) || !shr_buf_has_room(p, end, size))
			break;

		nruh = le16_to_cpu(config.nruh);
		max_nruh = (size - sizeof(config)) / sizeof(*ruhs);
		if (nruh > max_nruh)
			nruh = max_nruh;

		obj_config = json_create_object();
		obj_ruhs = json_create_array();

		obj_add_uint(obj_config, "fdpa", config.fdpa);
		obj_add_uint(obj_config, "vss", config.vss);
		obj_add_uint(obj_config, "nrg", le32_to_cpu(config.nrg));
		obj_add_uint(obj_config, "nruh", nruh);
		obj_add_uint(obj_config, "nnss", le32_to_cpu(config.nnss));
		obj_add_uint64(obj_config, "runs", le64_to_cpu(config.runs));
		obj_add_uint(obj_config, "erutl", le32_to_cpu(config.erutl));

		for (int j = 0; j < nruh; j++) {
			struct nvme_fdp_ruh_desc *ruh = &ruhs[j];

			struct json_object *obj_ruh = json_create_object();

			obj_add_uint(obj_ruh, "ruht", ruh->ruht);

			array_add_obj(obj_ruhs, obj_ruh);
		}

		obj_add_array(obj_config, "ruhs", obj_ruhs);
		array_add_obj(obj_configs, obj_config);

		p += size;
	}

	obj_add_array(r, "configs", obj_configs);
}

static void json_nvme_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len)
{
	struct json_object *r, *obj_ruhus;
	uint16_t nruh;

	r = json_r;
	obj_ruhus = json_create_array();

	nruh = le16_to_cpu(log->nruh);

	obj_add_uint(r, "nruh", nruh);

	nruh = nvme_log_nr_entries(nruh, len, sizeof(*log),
				   sizeof(log->ruhus[0]));
	for (int i = 0; i < nruh; i++) {
		struct nvme_fdp_ruhu_desc *ruhu = &log->ruhus[i];

		struct json_object *obj_ruhu = json_create_object();

		obj_add_uint(obj_ruhu, "ruha", ruhu->ruha);

		array_add_obj(obj_ruhus, obj_ruhu);
	}

	obj_add_array(r, "ruhus", obj_ruhus);
}

static void json_nvme_fdp_stats(struct nvme_fdp_stats_log *log)
{
	struct json_object *r = json_r;

	obj_add_uint128(r, "hbmw", le128_to_cpu(log->hbmw));
	obj_add_uint128(r, "mbmw", le128_to_cpu(log->mbmw));
	obj_add_uint128(r, "mbe", le128_to_cpu(log->mbe));
}

static void json_nvme_fdp_events(struct nvme_fdp_events_log *log)
{
	struct json_object *r, *obj_events;
	uint32_t n;

	r = json_r;
	obj_events = json_create_array();

	n = le32_to_cpu(log->n);

	obj_add_uint(r, "n", n);

	for (unsigned int i = 0; i < n && i < ARRAY_SIZE(log->events); i++) {
		struct nvme_fdp_event *event = &log->events[i];

		struct json_object *obj_event = json_create_object();

		obj_add_uint(obj_event, "type", event->type);
		obj_add_uint(obj_event, "fdpef", event->flags);
		obj_add_uint(obj_event, "pid", le16_to_cpu(event->pid));
		obj_add_uint64(obj_event, "timestamp",
			       int48_to_long(event->ts.timestamp));
		obj_add_uint(obj_event, "nsid", le32_to_cpu(event->nsid));

		if (event->type == NVME_FDP_EVENT_REALLOC) {
			struct nvme_fdp_event_realloc *mr;

			mr = (struct nvme_fdp_event_realloc *)&event->type_specific;

			obj_add_uint(obj_event, "nlbam", le16_to_cpu(mr->nlbam));

			if (mr->flags & NVME_FDP_EVENT_REALLOC_F_LBAV)
				obj_add_uint64(obj_event, "lba", le64_to_cpu(mr->lba));
		}

		array_add_obj(obj_events, obj_event);
	}

	obj_add_array(r, "events", obj_events);
}

static void json_nvme_fdp_ruh_status(struct nvme_fdp_ruh_status *status, size_t len)
{
	struct json_object *r, *obj_ruhss;
	uint16_t nruhsd;

	r = json_r;
	obj_ruhss = json_create_array();

	nruhsd = le16_to_cpu(status->nruhsd);

	obj_add_uint(r, "nruhsd", nruhsd);

	nruhsd = nvme_log_nr_entries(nruhsd, len, sizeof(*status),
				     sizeof(status->ruhss[0]));
	for (unsigned int i = 0; i < nruhsd; i++) {
		struct nvme_fdp_ruh_status_desc *ruhs = &status->ruhss[i];

		struct json_object *obj_ruhs = json_create_object();

		obj_add_uint(obj_ruhs, "pid", le16_to_cpu(ruhs->pid));
		obj_add_uint(obj_ruhs, "ruhid", le16_to_cpu(ruhs->ruhid));
		obj_add_uint(obj_ruhs, "earutr", le32_to_cpu(ruhs->earutr));
		obj_add_uint64(obj_ruhs, "ruamw", le64_to_cpu(ruhs->ruamw));

		array_add_obj(obj_ruhss, obj_ruhs);
	}

	obj_add_array(r, "ruhss", obj_ruhss);
}

static unsigned int json_print_nvme_subsystem_multipath(struct libnvme_subsystem *s, json_object *paths)
{
	struct libnvme_ns *n;
	struct libnvme_path *p;
	unsigned int i = 0;

	n = libnvme_subsystem_first_ns(s);
	if (!n)
		return 0;

	libnvme_namespace_for_each_path(n, p) {
		struct json_object *path_attrs;
		struct libnvme_ctrl *c = libnvme_path_get_ctrl(p);
		const char *ana_state;

		libnvme_path_get_ana_state(p, &ana_state, "");
		path_attrs = json_create_object();
		obj_add_str(path_attrs, "Name", libnvme_ctrl_get_name(c));
		obj_add_str(path_attrs, "Transport", libnvme_ctrl_get_transport(c));
		obj_add_ctrl_address(path_attrs, c);
		obj_add_ctrl_address_details(path_attrs, "AddressDetails", c);
		obj_add_str(path_attrs, "State", libnvme_ctrl_get_state(c));
		obj_add_str(path_attrs, "ANAState", ana_state);
		array_add_obj(paths, path_attrs);
		i++;
	}

	return i;
}

static void json_print_nvme_subsystem_ctrls(struct libnvme_subsystem *s,
					    json_object *paths)
{
	struct libnvme_ctrl *c;

	libnvme_subsystem_for_each_ctrl(s, c) {
		struct json_object *path_attrs;

		path_attrs = json_create_object();
		obj_add_str(path_attrs, "Name", libnvme_ctrl_get_name(c));
		obj_add_str(path_attrs, "Transport", libnvme_ctrl_get_transport(c));
		obj_add_ctrl_address(path_attrs, c);
		obj_add_ctrl_address_details(path_attrs, "AddressDetails", c);
		obj_add_str(path_attrs, "State", libnvme_ctrl_get_state(c));
		array_add_obj(paths, path_attrs);
	}
}

static void json_print_nvme_subsystem_list(struct libnvme_global_ctx *ctx,
					   bool show_ana)
{
	struct json_object *host_attrs, *subsystem_attrs;
	struct json_object *subsystems, *paths;
	struct json_object *a = json_create_array();
	struct libnvme_host *h;

	libnvme_for_each_host(ctx, h) {
		struct libnvme_subsystem *s;
		const char *hostid;

		host_attrs = json_create_object();
		obj_add_str(host_attrs, "HostNQN", libnvme_host_get_hostnqn(h));
		hostid = libnvme_host_get_hostid(h);
		if (hostid)
			obj_add_str(host_attrs, "HostID", hostid);
		subsystems = json_create_array();
		libnvme_for_each_subsystem(h, s) {
			struct libnvme_ctrl *c;
			bool no_ctrl = true;

			libnvme_subsystem_for_each_ctrl(s, c)
				no_ctrl = false;
			if (no_ctrl)
				continue;

			subsystem_attrs = json_create_object();
			obj_add_str(subsystem_attrs, "Name", libnvme_subsystem_get_name(s));
			obj_add_str(subsystem_attrs, "NQN", libnvme_subsystem_get_subsysnqn(s));

			if (verbose_mode()) {
				const char *model;
				const char *serial;
				const char *firmware;
				const char *iopolicy;

				libnvme_subsystem_get_model(s, &model, "");
				libnvme_subsystem_get_serial(s, &serial, "");
				libnvme_subsystem_get_firmware(s, &firmware,
								"");
				libnvme_subsystem_get_iopolicy(s, &iopolicy,
								"");

				obj_add_str(subsystem_attrs, "Model", model);
				obj_add_str(subsystem_attrs, "Serial", serial);
				obj_add_str(subsystem_attrs, "Firmware",
						firmware);
				obj_add_str(subsystem_attrs, "IOPolicy",
						iopolicy);
				obj_add_str(subsystem_attrs, "Type",
						libnvme_subsystem_get_subsystype(s));
			}

			array_add_obj(subsystems, subsystem_attrs);
			paths = json_create_array();

			if (!show_ana || !json_print_nvme_subsystem_multipath(s, paths))
				json_print_nvme_subsystem_ctrls(s, paths);

			obj_add_array(subsystem_attrs, "Paths", paths);
		}
		obj_add_array(host_attrs, "Subsystems", subsystems);
		array_add_obj(a, host_attrs);
	}

	json_print(a);
}

/* Adds the fields @fields of @value to @o, decoded, under their names */
void json_bitfields(struct json_object *o, const struct bitfield *fields,
		    unsigned int nr, uint64_t value)
{
	char buf[128];
	unsigned int i;

	for (i = 0; i < nr; i++) {
		bitfield_str(&fields[i], value, buf, sizeof(buf));
		obj_add_str(o, fields[i].name, buf);
	}
}

/*
 * The same for each style: the value of each register under its symbol,
 * with -v an object of the value and its fields.
 */
static void json_ctrl_registers(const struct nvme_reg_val *vals,
				unsigned int nr,
				enum nvme_regs_style style __shr_unused)
{
	struct json_object *r = json_r;
	struct json_object *o;
	unsigned int i;

	for (i = 0; i < nr; i++) {
		const struct nvme_reg *reg = vals[i].reg;

		if (!verbose_mode()) {
			obj_add_uint64(r, reg->sym, vals[i].value);
			continue;
		}

		o = json_create_object();
		obj_add_uint64(o, "value", vals[i].value);
		json_bitfields(o, reg->fields, reg->nr_fields, vals[i].value);
		obj_add_obj(r, reg->sym, o);
	}
}

static void json_nvme_cmd_set_independent_id_ns(struct nvme_id_independent_id_ns *ns,
						unsigned int nsid)
{
	struct json_object *r = json_r;

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
	struct json_object *r = json_r;
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

static void json_nvme_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm)
{
	struct json_object *r = json_r;

	obj_add_uint(r, "vsl", ctrl_nvm->vsl);
	obj_add_uint(r, "wzsl", ctrl_nvm->wzsl);
	obj_add_uint(r, "wusl", ctrl_nvm->wusl);
	obj_add_uint(r, "dmrl", ctrl_nvm->dmrl);
	obj_add_uint(r, "dmrsl", le32_to_cpu(ctrl_nvm->dmrsl));
	obj_add_uint64(r, "dmsl", le64_to_cpu(ctrl_nvm->dmsl));
	obj_add_uint(r, "kpiocap", ctrl_nvm->kpiocap);
	obj_add_uint(r, "wzdsl", ctrl_nvm->wzdsl);
	obj_add_uint(r, "aocs", le16_to_cpu(ctrl_nvm->aocs));

	if (verbose_mode()) {
		__u16 rsvd = (ctrl_nvm->aocs & 0xfffe) >> 1;
		__u8 ralbas = ctrl_nvm->aocs & 0x1;

		if (rsvd)
			obj_add_uint(r, "[15:1]: Reserved", rsvd);
		obj_add_uint(r, "[0:0]: Reporting Allocated LBA Supported", ralbas);
	}

	obj_add_uint(r, "ver", le32_to_cpu(ctrl_nvm->ver));
	obj_add_uint(r, "lbamqf", ctrl_nvm->lbamqf);
}

static void json_nvme_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns,
				unsigned int nsid, struct nvme_id_ns *ns,
				unsigned int lba_index, bool cap_only)

{
	struct json_object *r = json_r;
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
	struct json_object *r = json_r;
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();
	int i;

	for (i = 0; i < 1024; i++) {
		if (ns_list->ns[i]) {
			valid_attrs = json_create_object();
			obj_add_uint(valid_attrs, "nsid", le32_to_cpu(ns_list->ns[i]));
			array_add_obj(valid, valid_attrs);
		}
	}

	obj_add_array(r, "nsid_list", valid);
}

static void json_feature_show_fields_arbitration(struct json_object *r, unsigned int result)
{
	char json_str[STR_LEN];

	obj_add_uint(r, "High Priority Weight (HPW)", ((result & 0xff000000) >> 24) + 1);
	obj_add_uint(r, "Medium Priority Weight (MPW)", ((result & 0xff0000) >> 16) + 1);
	obj_add_uint(r, "Low Priority Weight (LPW)", ((result & 0xff00) >> 8) + 1);

	if ((result & 7) == 7)
		sprintf(json_str, "No limit");
	else
		sprintf(json_str, "%u", 1 << (result & 7));

	obj_add_str(r, "Arbitration Burst (AB)", json_str);
}

static void json_feature_show_fields_power_mgmt(struct json_object *r, unsigned int result)
{
	__u8 field = (result & 0xe0) >> 5;

	obj_add_uint(r, "Workload Hint (WH)", field);
	obj_add_str(r, "WH description", nvme_feature_wl_hints_to_string(field));
	obj_add_uint(r, "Power State (PS)", result & 0x1f);
	obj_add_uint(r, "Idle I/O Exit Latency Limit (IIELL)",
		     NVME_FEAT_PM_IIELL(result));
}

static void json_lba_range_entry(struct nvme_lba_range_type *lbrt, int nr_ranges,
				 struct json_object *r)
{
	char json_str[STR_LEN];
	struct json_object *lbare;
	int i;
	struct json_object *lbara = json_create_array();

	obj_add_array(r, "LBA Ranges", lbara);

	for (i = 0; i <= nr_ranges; i++) {
		lbare = json_create_object();
		array_add_obj(lbara, lbare);

		obj_add_int(lbare, "LBA range", i);

		obj_add_uint_nx(lbare, "type", lbrt->entry[i].type);

		obj_add_str(lbare, "type description",
			    nvme_feature_lba_type_to_string(lbrt->entry[i].type));

		obj_add_uint_nx(lbare, "attributes", lbrt->entry[i].attributes);

		obj_add_str(lbare, "attribute[0]", lbrt->entry[i].attributes & 1 ?
			    "LBA range may be overwritten" : "LBA range should not be overwritten");

		obj_add_str(lbare, "attribute[1]", lbrt->entry[i].attributes & 2 ?
			    "LBA range should be hidden from the OS/EFI/BIOS" :
			    "LBA range should be visible from the OS/EFI/BIOS");

		obj_add_nprix64(lbare, "slba", le64_to_cpu(lbrt->entry[i].slba));

		obj_add_nprix64(lbare, "nlb", le64_to_cpu(lbrt->entry[i].nlb));

		shr_bin_to_hex(json_str, sizeof(json_str), lbrt->entry[i].guid,
			       sizeof(lbrt->entry[i].guid), 0);

		obj_add_str(lbare, "guid", json_str);
	}
}

static void json_feature_show_fields_lba_range(struct json_object *r, __u8 field,
					       unsigned char *buf)
{
	obj_add_uint(r, "Number of LBA Ranges (NUM)", field + 1);

	if (buf)
		json_lba_range_entry((struct nvme_lba_range_type *)buf, field, r);
}

static void json_feature_show_fields_temp_thresh(struct json_object *r, unsigned int result)
{
	char json_str[STR_LEN];
	__u8 field;

	field = (result & 0x1c00000) >> 22;
	sprintf(json_str, "%s", nvme_degrees_string(field));
	obj_add_str(r, "Temperature Threshold Hysteresis (TMPTHH)", json_str);

	sprintf(json_str, "%u K", field);
	obj_add_str(r, "TMPTHH kelvin", json_str);

	field = (result & 0x300000) >> 20;
	obj_add_uint(r, "Threshold Type Select (THSEL)", field);
	obj_add_str(r, "THSEL description", nvme_feature_temp_type_to_string(field));

	field = (result & 0xf0000) >> 16;

	obj_add_uint(r, "Threshold Temperature Select (TMPSEL)", field);
	obj_add_str(r, "TMPSEL description", nvme_feature_temp_sel_to_string(field));

	sprintf(json_str, "%s", nvme_degrees_string(result & 0xffff));
	obj_add_str(r, "Temperature Threshold (TMPTH)", json_str);

	sprintf(json_str, "%u K", result & 0xffff);
	obj_add_str(r, "TMPTH kelvin", json_str);
}

static void json_feature_show_fields_err_recovery(struct json_object *r, unsigned int result)
{
	char json_str[STR_LEN];

	obj_add_str(r, "Deallocated or Unwritten Logical Block Error Enable (DULBE)",
		     (result & 0x10000) >> 16 ? "Enabled" : "Disabled");

	sprintf(json_str, "%u ms", (result & 0xffff) * 100);
	obj_add_str(r, "Time Limited Error Recovery (TLER)", json_str);
}

static void json_feature_show_fields_volatile_wc(struct json_object *r, unsigned int result)
{
	obj_add_str(r, "Volatile Write Cache Enable (WCE)", result & 1 ? "Enabled" : "Disabled");
}

static void json_feature_show_fields_num_queues(struct json_object *r, unsigned int result)
{
	obj_add_uint(r, "Number of IO Completion Queues Allocated (NCQA)",
		     ((result & 0xffff0000) >> 16) + 1);
	obj_add_uint(r, "Number of IO Submission Queues Allocated (NSQA)", (result & 0xffff) + 1);
}

static void json_feature_show_fields_irq_coalesce(struct json_object *r, unsigned int result)
{
	char json_str[STR_LEN];

	sprintf(json_str, "%u usec", ((result & 0xff00) >> 8) * 100);
	obj_add_str(r, "Aggregation Time (TIME)", json_str);

	obj_add_uint(r, "Aggregation Threshold (THR)", (result & 0xff) + 1);
}

static void json_feature_show_fields_irq_config(struct json_object *r, unsigned int result)
{
	obj_add_str(r, "Coalescing Disable (CD)", (result & 0x10000) >> 16 ? "True" : "False");
	obj_add_uint(r, "Interrupt Vector (IV)", result & 0xffff);
}

static void json_feature_show_fields_write_atomic(struct json_object *r, unsigned int result)
{
	obj_add_str(r, "Disable Normal (DN)", result & 1 ? "True" : "False");
}

static void json_feature_show_fields_async_event(struct json_object *r, unsigned int result)
{
	const char *async = "Send async event";
	const char *no_async = "Do not send async event";

	obj_add_str(r, feat_ae_dlpcn,
		    NVME_FEAT_AE_DLPCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_hdlpcn,
		    NVME_FEAT_AE_HDLPCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_adlpcn,
		    NVME_FEAT_AE_ADLPCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_pmdrlpcn,
		    NVME_FEAT_AE_PMDRLPCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_zdcn,
		    NVME_FEAT_AE_ZDCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_tthry,
		    NVME_FEAT_AE_TTHRY(result) ? async : no_async);
	obj_add_str(r, feat_ae_rlccn,
		    NVME_FEAT_AE_RLCCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_lhcn,
		    NVME_FEAT_AE_LHCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_ccrcn,
		    NVME_FEAT_AE_CCRCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_ansan,
		    NVME_FEAT_AE_ANSAN(result) ? async : no_async);
	obj_add_str(r, feat_ae_rgrp0,
		    NVME_FEAT_AE_RGRP0(result) ? async : no_async);
	obj_add_str(r, feat_ae_rassn,
		    NVME_FEAT_AE_RASSN(result) ? async : no_async);
	obj_add_str(r, feat_ae_nnsshdn,
		    NVME_FEAT_AE_NNSSHDN(result) ? async : no_async);
	obj_add_str(r, feat_ae_ega,
		    NVME_FEAT_AE_EGA(result) ? async : no_async);
	obj_add_str(r, feat_ae_lbas,
		    NVME_FEAT_AE_LBAS(result) ? async : no_async);
	obj_add_str(r, feat_ae_pla,
		    NVME_FEAT_AE_PLA(result) ? async : no_async);
	obj_add_str(r, feat_ae_ana,
		    NVME_FEAT_AE_ANA(result) ? async : no_async);
	obj_add_str(r, feat_ae_telem,
		    NVME_FEAT_AE_TELEM(result) ? async : no_async);
	obj_add_str(r, feat_ae_fw, NVME_FEAT_AE_FW(result) ? async : no_async);
	obj_add_str(r, feat_ae_nan,
		    NVME_FEAT_AE_NAN(result) ? async : no_async);
	obj_add_str(r, feat_ae_smart,
		    NVME_FEAT_AE_SMART(result) ? async : no_async);
}

static void json_auto_pst(struct nvme_feat_auto_pst *apst, struct json_object *r)
{
	int i;
	__u64 value;
	char json_str[STR_LEN];
	struct json_object *apsta = json_create_array();
	struct json_object *apste;

	obj_add_array(r, "Auto PST Entries", apsta);

	for (i = 0; i < ARRAY_SIZE(apst->apst_entry); i++) {
		apste = json_create_object();
		array_add_obj(apsta, apste);
		sprintf(json_str, "%2d", i);
		obj_add_str(apste, "entry", json_str);
		value = le64_to_cpu(apst->apst_entry[i]);
		sprintf(json_str, "%u ms", (__u32)NVME_GET(value, APST_ENTRY_ITPT));
		obj_add_str(apste, "Idle Time Prior to Transition (ITPT)", json_str);
		obj_add_uint(apste, "Idle Transition Power State (ITPS)",
			     (__u32)NVME_GET(value, APST_ENTRY_ITPS));
	}
}

static void json_feature_show_fields_auto_pst(struct json_object *r, unsigned int result,
					      unsigned char *buf)
{
	obj_add_str(r, "Autonomous Power State Transition Enable (APSTE)", result & 1 ? "Enabled" :
		     "Disabled");

	if (buf)
		json_auto_pst((struct nvme_feat_auto_pst *)buf, r);
}

static void json_host_mem_buffer(struct nvme_host_mem_buf_attrs *hmb, struct json_object *r)
{
	char json_str[STR_LEN];

	obj_add_uint(r, "Host Memory Descriptor List Entry Count (HMDLEC)", le32_to_cpu(hmb->hmdlec));

	sprintf(json_str, "0x%x", le32_to_cpu(hmb->hmdlau));
	obj_add_str(r, "Host Memory Descriptor List Address (HMDLAU)", json_str);

	sprintf(json_str, "0x%x", le32_to_cpu(hmb->hmdlal));
	obj_add_str(r, "Host Memory Descriptor List Address (HMDLAL)", json_str);

	obj_add_uint(r, "Host Memory Buffer Size (HSIZE)", le32_to_cpu(hmb->hsize));
}

static void json_feature_show_fields_host_mem_buf(struct json_object *r, unsigned int result,
						  unsigned char *buf)
{
	obj_add_str(r, "Enable Host Memory (EHM)", result & 1 ? "Enabled" : "Disabled");
	obj_add_str(r, "Host Memory Non-operational Access Restriction Enable (HMNARE)",
			(result & 0x00000004) ? "True" : "False");
	obj_add_str(r, "Host Memory Non-operational Access Restricted (HMNAR)",
			(result & 0x00000008) ? "True" : "False");

	if (buf)
		json_host_mem_buffer((struct nvme_host_mem_buf_attrs *)buf, r);
}

void json_timestamp(struct json_object *r, struct nvme_timestamp *ts)
{
	obj_add_uint64(r, "timestamp", int48_to_long(ts->timestamp));
	obj_add_str(r, "timestamp string", nvme_format_timestamp(ts->timestamp));
	obj_add_str(r, "timestamp origin", nvme_format_timestamp_origin(ts->attr));
	obj_add_str(r, "synch", nvme_format_timestamp_sync(ts->attr));
}

static void json_feature_show_fields_timestamp(struct json_object *r, unsigned char *buf)
{
	if (buf)
		json_timestamp(r, (struct nvme_timestamp *)buf);
}

static void json_feature_show_fields_kato(struct json_object *r, unsigned int result)
{
	obj_add_uint(r, "Keep Alive Timeout (KATO) in milliseconds", result);
}

static void json_feature_show_fields_hctm(struct json_object *r, unsigned int result)
{
	char json_str[STR_LEN];

	sprintf(json_str, "%u K", result >> 16);
	obj_add_str(r, "Thermal Management Temperature 1 (TMT1)", json_str);

	sprintf(json_str, "%s", nvme_degrees_string(result >> 16));
	obj_add_str(r, "TMT1 celsius", json_str);

	sprintf(json_str, "%u K", result & 0xffff);
	obj_add_str(r, "Thermal Management Temperature 2", json_str);

	sprintf(json_str, "%s", nvme_degrees_string(result & 0xffff));
	obj_add_str(r, "TMT2 celsius", json_str);
}

static void json_feature_show_fields_nopsc(struct json_object *r, unsigned int result)
{
	obj_add_str(r, "Non-Operational Power State Permissive Mode Enable (NOPPME)", result & 1 ?
		    "True" : "False");
}

static void json_feature_show_fields_rrl(struct json_object *r, unsigned int result)
{
	obj_add_uint(r, "Read Recovery Level (RRL)", result & 0xf);
}

static void json_plm_config(struct nvme_plm_config *plmcfg, struct json_object *r)
{
	char json_str[STR_LEN];

	sprintf(json_str, "%04x", le16_to_cpu(plmcfg->ee));
	obj_add_str(r, "Enable Event", json_str);

	obj_add_uint64(r, "DTWIN Reads Threshold", le64_to_cpu(plmcfg->dtwinrt));
	obj_add_uint64(r, "DTWIN Writes Threshold", le64_to_cpu(plmcfg->dtwinwt));
	obj_add_uint64(r, "DTWIN Time Threshold", le64_to_cpu(plmcfg->dtwintt));
}

static void json_feature_show_fields_plm_config(struct json_object *r, unsigned int result,
						unsigned char *buf)
{
	obj_add_str(r, "Predictable Latency Window Enabled", result & 1 ? "True" : "False");

	if (buf)
		json_plm_config((struct nvme_plm_config *)buf, r);
}

static void json_feature_show_fields_plm_window(struct json_object *r, unsigned int result)
{
	obj_add_str(r, "Window Select", nvme_plm_window_to_string(result));
}

static void json_feature_show_fields_lba_sts_interval(struct json_object *r, unsigned int result)
{
	obj_add_uint(r, "LBA Status Information Poll Interval (LSIPI)", result >> 16);
	obj_add_uint(r, "LBA Status Information Report Interval (LSIRI)", result & 0xffff);
}

static void json_feature_show_fields_host_behavior(struct json_object *r, unsigned char *buf)
{
	if (buf) {
		struct nvme_feat_host_behavior *host = (struct nvme_feat_host_behavior *)buf;

		obj_add_str(r, "Host Behavior Support", buf[0] & 0x1 ? "True" : "False");
		obj_add_str(r, "Advanced Command Retry Enable (ACRE)", host->acre ?
			    "True" : "False");
		obj_add_str(r, "Extended Telemetry Data Area 4 Supported (ETDAS)", host->etdas ?
			    "True" : "False");
		obj_add_str(r, "LBA Format Extension Enable (LBAFEE)", host->lbafee ?
			    "True" : "False");
		obj_add_str(r, "Host Dispersed Namespace Support (HDISNS)", host->hdisns ?
			    "Enabled" : "Disabled");
		obj_add_str(r, "Copy Descriptor Format 2h Enable (CDF2E)", host->cdfe & (1 << 2) ?
			    "True" : "False");
		obj_add_str(r, "Copy Descriptor Format 3h Enable (CDF3E)", host->cdfe & (1 << 3) ?
			    "True" : "False");
		obj_add_str(r, "Copy Descriptor Format 4h Enable (CDF4E)", host->cdfe & (1 << 4) ?
			    "True" : "False");
	}
}

static void json_feature_show_fields_sanitize(struct json_object *r, unsigned int result)
{
	obj_add_uint(r, "No-Deallocate Response Mode (NODRM)", result & 1);
}

static void json_feature_show_fields_endurance_evt_cfg(struct json_object *r, unsigned int result)
{
	obj_add_uint(r, "Endurance Group Identifier (ENDGID)", result & 0xffff);
	obj_add_uint(r, "Endurance Group Critical Warnings", result >> 16 & 0xff);
}

static void json_feature_show_fields_iocs_profile(struct json_object *r, unsigned int result)
{
	obj_add_str(r, "I/O Command Set Profile", result & 0x1 ? "True" : "False");
}

static void json_feature_show_fields_spinup_control(struct json_object *r, unsigned int result)
{
	obj_add_str(r, "Spinup control feature Enabled", result & 1 ? "True" : "False");
}

static void json_feature_show_fields_power_loss_signal(struct json_object *r, unsigned int result)
{
	obj_add_str(r, "Power Loss Signaling Mode (PLSM)",
		    nvme_pls_mode_to_string(NVME_GET(result, FEAT_PLS_MODE)));
}

static void json_feat_perfc_std(struct json_object *r, struct nvme_std_perf_attr *data)
{
	obj_add_str(r, "random 4 kib average read latency",
		    nvme_feature_perfc_r4karl_to_string(data->r4karl));
	obj_add_uint_02x(r, "R4KARL", data->r4karl);
}

static void json_feat_perfc_id_list(struct json_object *r, struct nvme_perf_attr_id_list *data)
{
	int i;
	int attri_vs;
	char json_str[STR_LEN];
	struct json_object *paida = json_create_array();
	struct json_object *paide;

	obj_add_str(r, "attribute type", nvme_feature_perfc_attrtyp_to_string(data->attrtyp));
	obj_add_uint_02x(r, "ATTRTYP", data->attrtyp);
	obj_add_int(r, "maximum saveable vendor specific performance attributes (MSVSPA)",
		    data->msvspa);
	obj_add_int(r, "unused saveable vendor specific performance attributes (USVSPA)",
		    data->usvspa);

	obj_add_array(r, "performance attribute identifier list", paida);
	for (i = 0; i < ARRAY_SIZE(data->id_list); i++) {
		paide = json_create_object();
		array_add_obj(paida, paide);
		attri_vs = i + NVME_FEAT_PERFC_ATTRI_VS_MIN;
		sprintf(json_str, "performance attribute %02xh identifier (PA%02XHI)", attri_vs,
			attri_vs);
		obj_add_str(paide, json_str, shr_uuid_to_string(data->id_list[i].id));
	}
}

static void json_feat_perfc_vs(struct json_object *r, struct nvme_vs_perf_attr *data)
{
	__u16 attrl = le16_to_cpu(data->attrl);

	obj_add_str(r, "performance attribute identifier (PAID)", shr_uuid_to_string(data->paid));
	obj_add_uint(r, "attribute length (ATTRL)", attrl);
	obj_d(r, "vendor specific (VS)", (unsigned char *)data->vs,
	      min_t(size_t, attrl, sizeof(data->vs)), 16, 1);
}

static void json_feat_perfc(struct json_object *r, enum nvme_features_id fid, unsigned int result,
			    struct nvme_perf_characteristics *data)
{
	__u8 attri;
	bool rvspa;

	nvme_feature_decode_perf_characteristics(result, &attri, &rvspa);

	obj_add_str(r, "attribute index", nvme_feature_perfc_attri_to_string(attri));
	obj_add_uint_02x(r, "ATTRI", attri);

	switch (attri) {
	case NVME_FEAT_PERFC_ATTRI_STD:
		json_feat_perfc_std(r, data->std_perf);
		break;
	case NVME_FEAT_PERFC_ATTRI_ID_LIST:
		json_feat_perfc_id_list(r, data->id_list);
		break;
	case NVME_FEAT_PERFC_ATTRI_VS_MIN ... NVME_FEAT_PERFC_ATTRI_VS_MAX:
		json_feat_perfc_vs(r, data->vs_perf);
		break;
	default:
		break;
	}
}

static void json_host_metadata(struct json_object *r, enum nvme_features_id fid,
			       struct nvme_host_metadata *data)
{
	struct nvme_metadata_element_desc desc;
	const __u8 *v;
	size_t off = 0;
	int i;
	char val[VAL_LEN];
	__u16 len;
	char json_str[STR_LEN];
	struct json_object *desca = json_create_array();
	struct json_object *desce;

	obj_add_int(r, "Num Metadata Element Descriptors", data->ndesc);

	obj_add_array(r, "Metadata Element Descriptors", desca);

	for (i = 0; i < data->ndesc; i++) {
		v = nvme_host_metadata_element(data, &off, &desc, &len);
		if (!v)
			break;

		desce = json_create_object();
		array_add_obj(desca, desce);

		obj_add_int(desce, "Element", i);

		snprintf(json_str, sizeof(json_str), "0x%02x", desc.type);
		obj_add_str(desce, "Type", json_str);

		obj_add_str(desce, "Type definition",
			    nvme_host_metadata_type_to_string(fid, desc.type));

		obj_add_int(desce, "Revision", desc.rev);

		obj_add_int(desce, "Length", le16_to_cpu(desc.len));

		snprintf(val, sizeof(val), "%.*s", len, (const char *)v);
		obj_add_str(desce, "Value", val);
	}
}

static void json_feature_show_fields_ns_metadata(struct json_object *r, enum nvme_features_id fid,
						 unsigned char *buf)
{
	if (buf)
		json_host_metadata(r, fid, (struct nvme_host_metadata *)buf);
}

static void json_feature_show_fields_sw_progress(struct json_object *r, unsigned int result)
{
	obj_add_uint(r, "Pre-boot Software Load Count (PBSLC)", result & 0xff);
}

static void json_feature_show_fields_host_id(struct json_object *r,
		unsigned int result, unsigned char *hostid)
{
	bool exhid;

	if (!hostid)
		return;

	nvme_feature_decode_host_id(result, &exhid);

	if (exhid)
		obj_add_str(r, "Host Identifier (HOSTID)",
			    uint128_t_to_l10n_string(le128_to_cpu(hostid)));
	else
		obj_add_uint64(r, "Host Identifier (HOSTID)",
			       le64_to_cpu(*(__le64 *)hostid));
}

static void json_feature_show_fields_resv_nf_mask(struct json_object *r, unsigned int result)
{
	obj_add_str(r, "Mask Reservation Preempted Notification (RESPRE)", (result & 8) >> 3 ?
		     "True" : "False");
	obj_add_str(r, "Mask Reservation Released Notification (RESREL)", (result & 4) >> 2 ?
		     "True" : "False");
	obj_add_str(r, "Mask Registration Preempted Notification (REGPRE)", (result & 2) >> 1 ?
		     "True" : "False");
}

static void json_feature_show_fields_resv_persist(struct json_object *r, unsigned int result)
{
	obj_add_str(r, "Persist Through Power Loss (PTPL)", result & 1 ? "True" : "False");
}

static void json_feature_show_fields_write_protect(struct json_object *r, unsigned int result)
{
	obj_add_str(r, "Namespace Write Protect", nvme_ns_wp_cfg_to_string(result));
}

static void json_feature_show_fields_fdp(struct json_object *r, unsigned int result)
{
	obj_add_str(r, "Flexible Direct Placement Enable (FDPE)", result & 1 ? "Yes" : "No");
	obj_add_uint(r, "Flexible Direct Placement Configuration Index", result >> 8 & 0xf);
}

static void json_feature_show_fields_fdp_events(struct json_object *r, unsigned int result,
						unsigned char *buf)
{
	unsigned int i;
	struct nvme_fdp_supported_event_desc *d;
	char json_str[STR_LEN];

	// NOET is in bits 7:0; bits 31:8 are reserved.
	for (i = 0; i < (result & 0xff); i++) {
		d = &((struct nvme_fdp_supported_event_desc *)buf)[i];
		sprintf(json_str, "%s", d->evta & 0x1 ? "Enabled" : "Not enabled");
		obj_add_str(r, nvme_fdp_event_to_string(d->evt), json_str);
	}
}

static void json_feature_show_fields_bpwp(struct json_object *r, unsigned int result)
{
	__u8 field;

	field = NVME_FEAT_BPWPC_BP0WPS(result);
	obj_add_str(r, "Boot Partition 0 Write Protection State", nvme_bpwps_to_string(field));
	field = NVME_FEAT_BPWPC_BP1WPS(result);
	obj_add_str(r, "Boot Partition 1 Write Protection State", nvme_bpwps_to_string(field));
}

static char *get_power_and_scale(__u16 power, __u8 scale)
{
	char *str;
	int ret;

	switch (scale) {
	case NVME_PSD_PS_NOT_REPORTED:
		/* Not reported for this power state */
		ret = asprintf(&str, "-");
		break;
	case NVME_PSD_PS_100_MICRO_WATT:
		/* Units of 0.0001W */
		ret = asprintf(&str, "%01u.%04uW", power / 10000,
			       power % 10000);
		break;
	case NVME_PSD_PS_10_MILLI_WATT:
		/* Units of 0.01W */
		ret = asprintf(&str, "%01u.%02uW", power / 100, power % 100);
		break;
	default:
		ret = asprintf(&str, "reserved");
		break;
	}

	if (ret > 0)
		return str;

	return NULL;
}

static void json_feature_show_fields_power_limit(struct json_object *r,
						 unsigned int result)
{
	__u8 field = NVME_FEAT_POWER_LIMIT_PLS(result);

	__cleanup_free char *k =
	    get_power_and_scale(NVME_FEAT_POWER_LIMIT_PLV(result), field);

	obj_add_str(r, "Power Limit Scale (PLS)",
		    nvme_feature_power_limit_scale_to_string(field));
	obj_add_uint(r, "Power Limit Value (PLV)",
		     NVME_FEAT_POWER_LIMIT_PLV(result));
	obj_add_str(r, "Power Limit", k);
}

static void json_feature_show_fields_power_thresh(struct json_object *r,
						  unsigned int result)
{
	__u8 field;
	__u16 ptv;
	__cleanup_free char *k = NULL;

	field = NVME_FEAT_POWER_THRESH_EPT(result);

	obj_add_str(r, "Enable Power Threshold (EPT)",
		    field ? "Enabled" : "Disabled");

	field = NVME_FEAT_POWER_THRESH_PMTS(result);
	obj_add_str(r, "Power Measurement Type Select (PMTS)",
		    nvme_power_measurement_type_to_string(field));

	field = NVME_FEAT_POWER_THRESH_PTS(result);
	obj_add_str(r, "Power Threshold Scale (PTS)",
		    nvme_feature_power_limit_scale_to_string(field));

	ptv = NVME_FEAT_POWER_THRESH_PTV(result);

	obj_add_uint(r, "Power Threshold Value (PTV)", ptv);

	k = get_power_and_scale(ptv, NVME_FEAT_POWER_THRESH_PTS(result));
	obj_add_str(r, "Power Threshold", k);
}

static void json_feature_show_fields_power_meas(struct json_object *r,
						unsigned int result)
{
	__u8 field;
	__u16 smt;

	field = NVME_FEAT_POWER_MEAS_ACT(result);
	obj_add_str(r, "Action (ACT)",
		nvme_power_measurement_action_to_string(field));

	field = NVME_FEAT_POWER_MEAS_PMTS(result);
	obj_add_str(r, "Power Measurement Type Select (PMTS)",
		nvme_power_measurement_type_to_string(field));

	smt = NVME_FEAT_POWER_MEAS_SMT(result);

	obj_add_uint(r, "Stop Measurement Time (SMT)", smt);
}

static void json_feature_show_fields_voltage_threshold(struct json_object *r,
							unsigned int result)
{
	obj_add_uint(r, "Voltage Sensor Select (VSENS)",
		     NVME_FEAT_VOLTAGE_THRESHOLD_VSENS(result));
	obj_add_str(r, "Enable Voltage Threshold (EVT)",
		    result & NVME_FEAT_VOLTAGE_THRESHOLD_EVT ? "Enabled" : "Disabled");
	obj_add_uint(r, "Overvoltage Threshold (OVT)",
		     NVME_FEAT_VOLTAGE_THRESHOLD_OVT(result));
	obj_add_uint(r, "Undervoltage Threshold (UVT)",
		     NVME_FEAT_VOLTAGE_THRESHOLD_UVT(result));
}

static void json_feature_show_fields_voltage_measurement(struct json_object *r,
							  unsigned int result)
{
	obj_add_uint(r, "Action (ACT)", NVME_FEAT_VOLTAGE_MEASUREMENT_ACT(result));
}

static void json_rate_limiting_data(struct json_object *r, struct nvme_rate_limiting_data *rld)
{
	__u16 rlc = le16_to_cpu(rld->rlc);
	__u16 rlm = NVME_RATE_LIMITING_RLC_RLM(rlc);

	obj_add_str(r, "Rate Limiting Enable (RLE)",
		    NVME_RATE_LIMITING_RLC_RLE(rlc) ? "Enabled" : "Disabled");
	obj_add_uint(r, "Rate Limiting Mode (RLM)", rlm);
	obj_add_str(r, "RLM description",
		    rlm == NVME_RATE_LIMITING_MODE_SOFT_LIMIT ? "Soft Limit" :
		    rlm == NVME_RATE_LIMITING_MODE_HARD_LIMIT ? "Hard Limit" : "Reserved");
	obj_add_uint(r, "Bandwidth Scale Factor (BWSF)", rld->bwsf);
	obj_add_uint64(r, "Total Bandwidth Value (TBWV)", le64_to_cpu(rld->tbwv));
	obj_add_uint64(r, "Write Bandwidth Value (WBWV)", le64_to_cpu(rld->wbwv));
	obj_add_uint(r, "Total IOPS (TIOPS)", le32_to_cpu(rld->tiops));
	obj_add_uint(r, "Write IOPS (WIOPS)", le32_to_cpu(rld->wiops));
	obj_add_uint(r, "Read IOPS Ratio (RIOPSR)", rld->riopsr);
	obj_add_uint(r, "Write IOPS Ratio (WIOPSR)", rld->wiopsr);
	obj_add_uint(r, "Read Bandwidth Ratio (RBWR)", rld->rbwr);
	obj_add_uint(r, "Write Bandwidth Ratio (WBWR)", rld->wbwr);
}

static void json_feature_show_fields_rate_limiting(struct json_object *r, unsigned char *buf)
{
	if (buf)
		json_rate_limiting_data(r, (struct nvme_rate_limiting_data *)buf);
}

static void json_feature_show(enum nvme_features_id fid, int sel,
			      unsigned int result, void *buf, __u32 data_len)
{
	struct json_object *r;
	char json_str[STR_LEN];

	sprintf(json_str, "feature: %#0*x", fid ? 4 : 2, fid);
	r = obj_create(json_str);

	obj_add_str(r, "name", nvme_feature_to_string(fid));

	sprintf(json_str, "%#0*x", result ? 10 : 8, result);
	obj_add_str(r, nvme_select_to_string(sel), json_str);

	obj_print(r);

	if (NVME_CHECK(sel, GET_FEATURES_SEL, SUPPORTED))
		json_select_result(fid, result);
	else
		json_feature_show_fields(fid, result, buf);
}

void json_feature_show_fields(enum nvme_features_id fid, unsigned int result,
			      unsigned char *buf)
{
	struct json_object *r;
	char json_str[STR_LEN];

	sprintf(json_str, "Feature: %#0*x", fid ? 4 : 2, fid);
	r = obj_create(json_str);

	switch (fid) {
	case NVME_FEAT_FID_ARBITRATION:
		json_feature_show_fields_arbitration(r, result);
		break;
	case NVME_FEAT_FID_POWER_MGMT:
		json_feature_show_fields_power_mgmt(r, result);
		break;
	case NVME_FEAT_FID_LBA_RANGE:
		json_feature_show_fields_lba_range(r, result & 0x3f, buf);
		break;
	case NVME_FEAT_FID_TEMP_THRESH:
		json_feature_show_fields_temp_thresh(r, result);
		break;
	case NVME_FEAT_FID_ERR_RECOVERY:
		json_feature_show_fields_err_recovery(r, result);
		break;
	case NVME_FEAT_FID_VOLATILE_WC:
		json_feature_show_fields_volatile_wc(r, result);
		break;
	case NVME_FEAT_FID_NUM_QUEUES:
		json_feature_show_fields_num_queues(r, result);
		break;
	case NVME_FEAT_FID_IRQ_COALESCE:
		json_feature_show_fields_irq_coalesce(r, result);
		break;
	case NVME_FEAT_FID_IRQ_CONFIG:
		json_feature_show_fields_irq_config(r, result);
		break;
	case NVME_FEAT_FID_WRITE_ATOMIC:
		json_feature_show_fields_write_atomic(r, result);
		break;
	case NVME_FEAT_FID_ASYNC_EVENT:
		json_feature_show_fields_async_event(r, result);
		break;
	case NVME_FEAT_FID_AUTO_PST:
		json_feature_show_fields_auto_pst(r, result, buf);
		break;
	case NVME_FEAT_FID_HOST_MEM_BUF:
		json_feature_show_fields_host_mem_buf(r, result, buf);
		break;
	case NVME_FEAT_FID_TIMESTAMP:
		json_feature_show_fields_timestamp(r, buf);
		break;
	case NVME_FEAT_FID_KATO:
		json_feature_show_fields_kato(r, result);
		break;
	case NVME_FEAT_FID_HCTM:
		json_feature_show_fields_hctm(r, result);
		break;
	case NVME_FEAT_FID_NOPSC:
		json_feature_show_fields_nopsc(r, result);
		break;
	case NVME_FEAT_FID_RRL:
		json_feature_show_fields_rrl(r, result);
		break;
	case NVME_FEAT_FID_PLM_CONFIG:
		json_feature_show_fields_plm_config(r, result, buf);
		break;
	case NVME_FEAT_FID_PLM_WINDOW:
		json_feature_show_fields_plm_window(r, result);
		break;
	case NVME_FEAT_FID_LBA_STS_INTERVAL:
		json_feature_show_fields_lba_sts_interval(r, result);
		break;
	case NVME_FEAT_FID_HOST_BEHAVIOR:
		json_feature_show_fields_host_behavior(r, buf);
		break;
	case NVME_FEAT_FID_SANITIZE:
		json_feature_show_fields_sanitize(r, result);
		break;
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:
		json_feature_show_fields_endurance_evt_cfg(r, result);
		break;
	case NVME_FEAT_FID_IOCS_PROFILE:
		json_feature_show_fields_iocs_profile(r, result);
		break;
	case NVME_FEAT_FID_SPINUP_CONTROL:
		json_feature_show_fields_spinup_control(r, result);
		break;
	case NVME_FEAT_FID_POWER_LOSS_SIGNAL:
		json_feature_show_fields_power_loss_signal(r, result);
		break;
	case NVME_FEAT_FID_PERF_CHARACTERISTICS:
		json_feat_perfc(r, fid, result, (struct nvme_perf_characteristics *)buf);
		break;
	case NVME_FEAT_FID_ENH_CTRL_METADATA:
	case NVME_FEAT_FID_CTRL_METADATA:
	case NVME_FEAT_FID_NS_METADATA:
		json_feature_show_fields_ns_metadata(r, fid, buf);
		break;
	case NVME_FEAT_FID_SW_PROGRESS:
		json_feature_show_fields_sw_progress(r, result);
		break;
	case NVME_FEAT_FID_HOST_ID:
		json_feature_show_fields_host_id(r, result, buf);
		break;
	case NVME_FEAT_FID_RESV_NF_MASK:
		json_feature_show_fields_resv_nf_mask(r, result);
		break;
	case NVME_FEAT_FID_RESV_PERSIST:
		json_feature_show_fields_resv_persist(r, result);
		break;
	case NVME_FEAT_FID_WRITE_PROTECT:
		json_feature_show_fields_write_protect(r, result);
		break;
	case NVME_FEAT_FID_FDP:
		json_feature_show_fields_fdp(r, result);
		break;
	case NVME_FEAT_FID_FDP_EVENTS:
		json_feature_show_fields_fdp_events(r, result, buf);
		break;
	case NVME_FEAT_FID_BP_WRITE_PROTECT:
		json_feature_show_fields_bpwp(r, result);
		break;
	case NVME_FEAT_FID_POWER_LIMIT:
		json_feature_show_fields_power_limit(r, result);
		break;
	case NVME_FEAT_FID_POWER_THRESH:
		json_feature_show_fields_power_thresh(r, result);
		break;
	case NVME_FEAT_FID_POWER_MEASUREMENT:
		json_feature_show_fields_power_meas(r, result);
		break;
	case NVME_FEAT_FID_VOLTAGE_THRESHOLD:
		json_feature_show_fields_voltage_threshold(r, result);
		break;
	case NVME_FEAT_FID_VOLTAGE_MEASUREMENT:
		json_feature_show_fields_voltage_measurement(r, result);
		break;
	case NVME_FEAT_FID_RATE_LIMITING:
		json_feature_show_fields_rate_limiting(r, buf);
		break;
	default:
		break;
	}

	obj_print(r);
}

void json_id_ctrl_rpmbs(__le32 ctrl_rpmbs)
{
	struct json_object *r = json_r;
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

static void json_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges)
{
	struct json_object *r = json_r;

	json_lba_range_entry(lbrt, nr_ranges, r);
}

static void json_lba_status_info(__u64 result)
{
	struct json_object *r = json_r;

	obj_add_uint(r, "LBA Status Information Poll Interval (LSIPI)", (result >> 16) & 0xffff);
	obj_add_uint(r, "LBA Status Information Report Interval (LSIRI)", result & 0xffff);
}

void json_d(unsigned char *buf, int len, int width, int group)
{
	struct json_object *r = json_r;
	char json_str[STR_LEN];

	sprintf(json_str, "data: buf=%p len=%d width=%d group=%d", buf, len, width, group);
	obj_d(r, json_str, buf, len, width, group);
}

static void json_nvme_list_ctrl(struct nvme_ctrl_list *ctrl_list)
{
	__u16 num = le16_to_cpu(ctrl_list->num);
	struct json_object *r = json_r;
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();
	int i;

	obj_add_uint(r, "num_ctrl", le16_to_cpu(ctrl_list->num));

	for (i = 0; i < min(num, 2047); i++) {
		valid_attrs = json_create_object();
		obj_add_uint(valid_attrs, "ctrl_id", le16_to_cpu(ctrl_list->identifier[i]));
		array_add_obj(valid, valid_attrs);
	}

	obj_add_array(r, "ctrl_list", valid);
}

static void json_nvme_id_nvmset(struct nvme_id_nvmset_list *nvmset,
				unsigned int nvmeset_id)
{
	__u32 nent = nvmset->nid;
	struct json_object *entries = json_create_array();
	struct json_object *r = json_r;
	int i;

	obj_add_int(r, "nid", nent);

	for (i = 0; i < nent && i < ARRAY_SIZE(nvmset->ent); i++) {
		struct json_object *entry = json_create_object();

		obj_add_int(entry, "nvmset_id", le16_to_cpu(nvmset->ent[i].nvmsetid));
		obj_add_int(entry, "endurance_group_id", le16_to_cpu(nvmset->ent[i].endgid));
		obj_add_uint(entry, "random_4k_read_typical", le32_to_cpu(nvmset->ent[i].rr4kt));
		obj_add_uint(entry, "optimal_write_size", le32_to_cpu(nvmset->ent[i].ows));
		obj_add_uint128(entry, "total_nvmset_cap", le128_to_cpu(nvmset->ent[i].tnvmsetcap));
		obj_add_uint128(entry, "unalloc_nvmset_cap",
				le128_to_cpu(nvmset->ent[i].unvmsetcap));
		array_add_obj(entries, entry);
	}

	obj_add_array(r, "NVMSet", entries);
}

static void json_nvme_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *caps)
{
	struct json_object *r = json_r;

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

static void json_nvme_list_secondary_ctrl(const struct nvme_secondary_ctrl_list *sc_list,
					  __u32 count)
{
	const struct nvme_secondary_ctrl *sc_entry = &sc_list->sc_entry[0];
	__u32 nent = min(sc_list->num, count);
	struct json_object *entries = json_create_array();
	struct json_object *r = json_r;
	int i;

	obj_add_int(r, "num", nent);

	for (i = 0; i < nent; i++) {
		struct json_object *entry = json_create_object();

		obj_add_int(entry, "secondary-controller-identifier",
			    le16_to_cpu(sc_entry[i].scid));
		obj_add_int(entry, "primary-controller-identifier", le16_to_cpu(sc_entry[i].pcid));
		obj_add_int(entry, "secondary-controller-state", sc_entry[i].scs);
		obj_add_int(entry, "virtual-function-number", le16_to_cpu(sc_entry[i].vfn));
		obj_add_int(entry, "num-virtual-queues", le16_to_cpu(sc_entry[i].nvq));
		obj_add_int(entry, "num-virtual-interrupts", le16_to_cpu(sc_entry[i].nvi));
		array_add_obj(entries, entry);
	}

	obj_add_array(r, "secondary-controllers", entries);
}

static void json_nvme_id_ns_granularity_list(
		const struct nvme_id_ns_granularity_list *glist)
{
	int i;
	struct json_object *r = json_r;
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
	struct json_object *r = json_r;
	struct json_object *entries = json_create_array();
	int i;

	for (i = 0; i < NVME_ID_UUID_LIST_MAX; i++) {
		__u8 uuid[NVME_UUID_LEN];
		struct json_object *entry;

		/* The list is terminated by a zero UUID value */
		if (memcmp(uuid_list->entry[i].uuid, zero_uuid, sizeof(zero_uuid)) == 0)
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
	struct json_object *r = json_r;
	struct json_object *entries = json_create_array();
	struct json_object *entry;
	int i;
	shr_uint128_t dom_cap, unalloc_dom_cap, max_egrp_dom_cap;

	obj_add_uint(r, "num_dom_entries", id_dom->num);

	for (i = 0; i < id_dom->num && i < ARRAY_SIZE(id_dom->domain_attr);
	     i++) {
		entry = json_create_object();
		dom_cap = le128_to_cpu(id_dom->domain_attr[i].dom_cap);
		unalloc_dom_cap = le128_to_cpu(id_dom->domain_attr[i].unalloc_dom_cap);
		max_egrp_dom_cap = le128_to_cpu(id_dom->domain_attr[i].max_egrp_dom_cap);

		obj_add_uint(entry, "dom_id", le16_to_cpu(id_dom->domain_attr[i].dom_id));
		obj_add_uint128(entry, "dom_cap", dom_cap);
		obj_add_uint128(entry, "unalloc_dom_cap", unalloc_dom_cap);
		obj_add_uint128(entry, "max_egrp_dom_cap", max_egrp_dom_cap);

		array_add_obj(entries, entry);
	}

	obj_add_array(r, "domain_list", entries);
}

static void json_nvme_endurance_group_list(struct nvme_id_endurance_group_list *endgrp_list)
{
	struct json_object *r = json_r;
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();
	int i;

	obj_add_uint(r, "num_endgrp_id", le16_to_cpu(endgrp_list->num));

	for (i = 0; i < min(le16_to_cpu(endgrp_list->num), 2047); i++) {
		valid_attrs = json_create_object();
		obj_add_uint(valid_attrs, "endgrp_id", le16_to_cpu(endgrp_list->identifier[i]));
		array_add_obj(valid, valid_attrs);
	}

	obj_add_array(r, "endgrp_list", valid);
}

static void json_print_detail_list_multipath(struct libnvme_subsystem *s,
		struct json_object *jss)
{
	struct libnvme_ns *n;
	struct libnvme_path *p;
	struct json_object *jnss = json_create_array();

	libnvme_subsystem_for_each_ns(s, n) {
		struct json_object *jns = json_create_object();
		struct json_object *jpaths = json_create_array();
		int lba;
		uint64_t lba_count, nsze, nuse;

		libnvme_ns_get_lba_size(n, &lba, 0);
		libnvme_ns_get_lba_count(n, &lba_count, 0);
		nsze = lba_count * lba;
		libnvme_ns_get_lba_util(n, &nuse, 0);
		nuse *= lba;

		obj_add_str(jns, "NameSpace", libnvme_ns_get_name(n));
		obj_add_str(jns, "Generic", libnvme_ns_get_generic_name(n));
		obj_add_int(jns, "NSID", libnvme_ns_get_nsid(n));
		obj_add_uint64(jns, "UsedBytes", nuse);
		obj_add_uint64(jns, "MaximumLBA", lba_count);
		obj_add_uint64(jns, "PhysicalSize", nsze);
		obj_add_int(jns, "SectorSize", lba);

		libnvme_namespace_for_each_path(n, p) {
			struct libnvme_ctrl *c;
			struct json_object *jpath = json_create_object();
			const char *slot;
			const char *cntlid;
			const char *serial;
			const char *model;
			const char *firmware;
			const char *ana_state;

			libnvme_path_get_ana_state(p, &ana_state, "");
			obj_add_str(jpath, "Path", libnvme_path_get_name(p));
			obj_add_str(jpath, "ANAState", ana_state);

			/*
			 * For multipath, each path maps to one controller.
			 * So get the controller from the path and then add
			 * controller  attributes.
			 */
			c = libnvme_path_get_ctrl(p);
			libnvme_ctrl_get_phy_slot(c, &slot, "");
			libnvme_ctrl_get_cntlid(c, &cntlid, "");
			libnvme_ctrl_get_serial(c, &serial, "");
			libnvme_ctrl_get_model(c, &model, "");
			libnvme_ctrl_get_firmware(c, &firmware, "");
			obj_add_str(jpath, "Controller", libnvme_ctrl_get_name(c));
			obj_add_str(jpath, "Cntlid", cntlid);
			obj_add_str(jpath, "SerialNumber", serial);
			obj_add_str(jpath, "ModelNumber", model);
			obj_add_str(jpath, "Firmware", firmware);
			obj_add_str(jpath, "Transport", libnvme_ctrl_get_transport(c));
			obj_add_ctrl_address(jpath, c);
			obj_add_ctrl_address_details(jpath, "AddressDetails", c);
			obj_add_str(jpath, "Slot", slot ? slot : "");

			array_add_obj(jpaths, jpath);
		}

		obj_add_obj(jns, "Paths", jpaths);
		array_add_obj(jnss, jns);
	}
	obj_add_obj(jss, "Namespaces", jnss);
}

static void json_print_detail_list(struct libnvme_subsystem *s, struct json_object *jss)
{
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;
	struct json_object *jctrls = json_create_array();

	libnvme_subsystem_for_each_ctrl(s, c) {
		struct json_object *jctrl = json_create_object();
		struct json_object *jnss = json_create_array();
		const char *slot;
		const char *cntlid;
		const char *serial;
		const char *model;
		const char *firmware;

		libnvme_ctrl_get_phy_slot(c, &slot, "");
		libnvme_ctrl_get_cntlid(c, &cntlid, "");
		libnvme_ctrl_get_serial(c, &serial, "");
		libnvme_ctrl_get_model(c, &model, "");
		libnvme_ctrl_get_firmware(c, &firmware, "");

		obj_add_str(jctrl, "Controller", libnvme_ctrl_get_name(c));
		obj_add_str(jctrl, "Cntlid", cntlid);
		obj_add_str(jctrl, "SerialNumber", serial);
		obj_add_str(jctrl, "ModelNumber", model);
		obj_add_str(jctrl, "Firmware", firmware);
		obj_add_str(jctrl, "Transport", libnvme_ctrl_get_transport(c));
		obj_add_ctrl_address(jctrl, c);
		obj_add_ctrl_address_details(jctrl, "AddressDetails", c);
		obj_add_str(jctrl, "Slot", slot ? slot : "");

		libnvme_ctrl_for_each_ns(c, n) {
			struct json_object *jns = json_create_object();
			int lba;
			uint64_t lba_count, nsze, nuse;

			libnvme_ns_get_lba_size(n, &lba, 0);
			libnvme_ns_get_lba_count(n, &lba_count, 0);
			nsze = lba_count * lba;
			libnvme_ns_get_lba_util(n, &nuse, 0);
			nuse *= lba;

			obj_add_str(jns, "NameSpace", libnvme_ns_get_name(n));
			obj_add_str(jns, "Generic", libnvme_ns_get_generic_name(n));
			obj_add_int(jns, "NSID", libnvme_ns_get_nsid(n));
			obj_add_uint64(jns, "UsedBytes", nuse);
			obj_add_uint64(jns, "MaximumLBA", lba_count);
			obj_add_uint64(jns, "PhysicalSize", nsze);
			obj_add_int(jns, "SectorSize", lba);

			array_add_obj(jnss, jns);
		}

		obj_add_obj(jctrl, "Namespaces", jnss);
		array_add_obj(jctrls, jctrl);
	}

	obj_add_obj(jss, "Controllers", jctrls);
}

static void json_detail_list_v2(struct libnvme_global_ctx *ctx)
{
	struct json_object *r = json_r;
	struct json_object *jdev = json_create_array();

	struct libnvme_host *h;
	struct libnvme_subsystem *s;

	libnvme_for_each_host(ctx, h) {
		struct json_object *hss = json_create_object();
		struct json_object *jsslist = json_create_array();
		const char *hostid;

		obj_add_str(hss, "HostNQN", libnvme_host_get_hostnqn(h));
		hostid = libnvme_host_get_hostid(h);
		if (hostid)
			obj_add_str(hss, "HostID", hostid);

		libnvme_for_each_subsystem(h, s) {
			struct json_object *jss = json_create_object();

			obj_add_str(jss, "Subsystem", libnvme_subsystem_get_name(s));
			obj_add_str(jss, "SubsystemNQN", libnvme_subsystem_get_subsysnqn(s));

			if (nvme_is_multipath(s))
				json_print_detail_list_multipath(s, jss);
			else
				json_print_detail_list(s, jss);

			array_add_obj(jsslist, jss);
		}

		obj_add_obj(hss, "Subsystems", jsslist);
		array_add_obj(jdev, hss);
	}

	obj_add_array(r, "Devices", jdev);
}

static void json_detail_list(struct libnvme_global_ctx *ctx)
{
	struct json_object *r = json_r;
	struct json_object *jdev = json_create_array();

	struct libnvme_host *h;
	struct libnvme_subsystem *s;
	struct libnvme_ctrl *c;
	struct libnvme_path *p;
	struct libnvme_ns *n;

	libnvme_for_each_host(ctx, h) {
		struct json_object *hss = json_create_object();
		struct json_object *jsslist = json_create_array();
		const char *hostid;

		obj_add_str(hss, "HostNQN", libnvme_host_get_hostnqn(h));
		hostid = libnvme_host_get_hostid(h);
		if (hostid)
			obj_add_str(hss, "HostID", hostid);

		libnvme_for_each_subsystem(h, s) {
			struct json_object *jss = json_create_object();
			struct json_object *jctrls = json_create_array();
			struct json_object *jnss = json_create_array();

			obj_add_str(jss, "Subsystem", libnvme_subsystem_get_name(s));
			obj_add_str(jss, "SubsystemNQN", libnvme_subsystem_get_subsysnqn(s));

			libnvme_subsystem_for_each_ctrl(s, c) {
				struct json_object *jctrl = json_create_object();
				struct json_object *jnss = json_create_array();
				struct json_object *jpaths = json_create_array();
				const char *cntlid;
				const char *serial;
				const char *model;
				const char *firmware;
				const char *slot;

				libnvme_ctrl_get_cntlid(c, &cntlid, "");
				libnvme_ctrl_get_serial(c, &serial, "");
				libnvme_ctrl_get_model(c, &model, "");
				libnvme_ctrl_get_firmware(c, &firmware, "");
				libnvme_ctrl_get_phy_slot(c, &slot, "");

				obj_add_str(jctrl, "Controller", libnvme_ctrl_get_name(c));
				obj_add_str(jctrl, "Cntlid", cntlid);
				obj_add_str(jctrl, "SerialNumber", serial);
				obj_add_str(jctrl, "ModelNumber", model);
				obj_add_str(jctrl, "Firmware", firmware);
				obj_add_str(jctrl, "Transport", libnvme_ctrl_get_transport(c));
				obj_add_ctrl_address(jctrl, c);
				obj_add_ctrl_address_details(jctrl, "AddressDetails", c);
				obj_add_str(jctrl, "Slot", slot);

				libnvme_ctrl_for_each_ns(c, n) {
					struct json_object *jns = json_create_object();
					int lba;
					uint64_t lba_count, nsze, nuse;

					libnvme_ns_get_lba_size(n, &lba, 0);
					libnvme_ns_get_lba_count(n,
							&lba_count, 0);
					nsze = lba_count * lba;
					libnvme_ns_get_lba_util(n, &nuse, 0);
					nuse *= lba;

					obj_add_str(jns, "NameSpace", libnvme_ns_get_name(n));
					obj_add_str(jns, "Generic", libnvme_ns_get_generic_name(n));
					obj_add_int(jns, "NSID", libnvme_ns_get_nsid(n));
					obj_add_uint64(jns, "UsedBytes", nuse);
					obj_add_uint64(jns, "MaximumLBA",
							lba_count);
					obj_add_uint64(jns, "PhysicalSize", nsze);
					obj_add_int(jns, "SectorSize", lba);

					array_add_obj(jnss, jns);
				}
				obj_add_obj(jctrl, "Namespaces", jnss);

				libnvme_ctrl_for_each_path(c, p) {
					struct json_object *jpath = json_create_object();
					const char *ana_state;

					libnvme_path_get_ana_state(p,
							&ana_state, "");
					obj_add_str(jpath, "Path", libnvme_path_get_name(p));
					obj_add_str(jpath, "ANAState",
							ana_state);

					array_add_obj(jpaths, jpath);
				}
				obj_add_obj(jctrl, "Paths", jpaths);

				array_add_obj(jctrls, jctrl);
			}
			obj_add_obj(jss, "Controllers", jctrls);

			libnvme_subsystem_for_each_ns(s, n) {
				struct json_object *jns = json_create_object();
				int lba;
				uint64_t lba_count, nsze, nuse;

				libnvme_ns_get_lba_size(n, &lba, 0);
				libnvme_ns_get_lba_count(n, &lba_count, 0);
				nsze = lba_count * lba;
				libnvme_ns_get_lba_util(n, &nuse, 0);
				nuse *= lba;

				obj_add_str(jns, "NameSpace", libnvme_ns_get_name(n));
				obj_add_str(jns, "Generic", libnvme_ns_get_generic_name(n));
				obj_add_int(jns, "NSID", libnvme_ns_get_nsid(n));
				obj_add_uint64(jns, "UsedBytes", nuse);
				obj_add_uint64(jns, "MaximumLBA", lba_count);
				obj_add_uint64(jns, "PhysicalSize", nsze);
				obj_add_int(jns, "SectorSize", lba);

				array_add_obj(jnss, jns);
			}
			obj_add_obj(jss, "Namespaces", jnss);

			array_add_obj(jsslist, jss);
		}

		obj_add_obj(hss, "Subsystems", jsslist);
		array_add_obj(jdev, hss);
	}

	obj_add_array(r, "Devices", jdev);
}

static struct json_object *json_list_item_obj(struct libnvme_ns *n)
{
	struct json_object *r = json_create_object();
	char devname[NAME_LEN] = { 0 };
	char genname[NAME_LEN] = { 0 };
	int lba;
	uint64_t lba_count, nsze, nuse;

	libnvme_ns_get_lba_size(n, &lba, 0);
	libnvme_ns_get_lba_count(n, &lba_count, 0);
	nsze = lba_count * lba;
	libnvme_ns_get_lba_util(n, &nuse, 0);
	nuse *= lba;

	nvme_dev_full_path(n, devname, sizeof(devname));
	nvme_generic_full_path(n, genname, sizeof(genname));

	obj_add_int(r, "NameSpace", libnvme_ns_get_nsid(n));
	obj_add_str(r, "DevicePath", devname);
	obj_add_str(r, "GenericPath", genname);
	obj_add_str(r, "Firmware", libnvme_ns_get_firmware(n));
	obj_add_str(r, "ModelNumber", libnvme_ns_get_model(n));
	obj_add_str(r, "SerialNumber", libnvme_ns_get_serial(n));
	obj_add_uint64(r, "UsedBytes", nuse);
	obj_add_uint64(r, "MaximumLBA", lba_count);
	obj_add_uint64(r, "PhysicalSize", nsze);
	obj_add_int(r, "SectorSize", lba);

	return r;
}

static void json_simple_list(struct libnvme_global_ctx *ctx)
{
	struct json_object *r = json_r;
	struct json_object *jdevices = json_create_array();

	struct libnvme_host *h;
	struct libnvme_subsystem *s;
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			libnvme_subsystem_for_each_ns(s, n)
				array_add_obj(jdevices, json_list_item_obj(n));

			libnvme_subsystem_for_each_ctrl(s, c) {
				libnvme_ctrl_for_each_ns(c, n)
					array_add_obj(jdevices, json_list_item_obj(n));
			}
		}
	}

	obj_add_array(r, "Devices", jdevices);
}

static void json_list_item(struct libnvme_ns *n, struct shr_table *t)
{
	struct json_object *r = json_list_item_obj(n);

	json_print(r);
}

static void json_print_list_items(struct libnvme_global_ctx *ctx)
{
	if (json_print_ops.flags & VERBOSE) {
		if (nvme_args.output_format_ver == 2)
			json_detail_list_v2(ctx);
		else
			json_detail_list(ctx);
	} else
		json_simple_list(ctx);
}

static unsigned int json_subsystem_topology_multipath(struct libnvme_subsystem *s,
						      json_object *namespaces)
{
	struct libnvme_ns *n;
	struct libnvme_path *p;
	unsigned int i = 0;
	const char *iopolicy;

	libnvme_subsystem_get_iopolicy(s, &iopolicy, "");

	libnvme_subsystem_for_each_ns(s, n) {
		struct json_object *ns_attrs;
		struct json_object *paths;

		ns_attrs = json_create_object();
		obj_add_int(ns_attrs, "NSID", libnvme_ns_get_nsid(n));
		obj_add_str(ns_attrs, "Name", libnvme_ns_get_name(n));

		paths = json_create_array();
		libnvme_namespace_for_each_path(n, p) {
			struct json_object *path_attrs;
			struct json_object *ctrls, *ctrl_attrs;
			struct libnvme_ctrl *c;
			const char *ana_state;

			libnvme_path_get_ana_state(p, &ana_state, "");
			path_attrs = json_create_object();
			obj_add_str(path_attrs, "Path", libnvme_path_get_name(p));
			obj_add_str(path_attrs, "ANAState", ana_state);

			/*
			 * For iopolicy numa exclude "Qdepth", for iopolicy
			 * queue-depth exclude "NUMANodes" and for iopolicy
			 * round-robin exclude both "Qdepth" and "NUMANodes".
			 */
			if (streq(iopolicy, "numa")) {
				const char *numa_nodes;

				libnvme_path_get_numa_nodes(p, &numa_nodes,
							     "");
				obj_add_str(path_attrs, "NUMANodes",
						numa_nodes);
			} else if (streq(iopolicy, "queue-depth")) {
				int queue_depth;

				libnvme_path_get_queue_depth(p, &queue_depth,
							      0);
				obj_add_int(path_attrs, "Qdepth", queue_depth);
			}

			c = libnvme_path_get_ctrl(p);
			ctrls = json_create_array();
			ctrl_attrs = json_create_object();
			obj_add_str(ctrl_attrs, "Name", libnvme_ctrl_get_name(c));
			obj_add_str(ctrl_attrs, "Transport", libnvme_ctrl_get_transport(c));
			obj_add_ctrl_address(ctrl_attrs, c);
			obj_add_ctrl_address_details(ctrl_attrs, "AddressDetails", c);
			obj_add_str(ctrl_attrs, "State", libnvme_ctrl_get_state(c));
			array_add_obj(ctrls, ctrl_attrs);
			obj_add_array(path_attrs, "Controller", ctrls);

			array_add_obj(paths, path_attrs);
		}
		obj_add_array(ns_attrs, "Paths", paths);
		array_add_obj(namespaces, ns_attrs);
		i++;
	}

	return i;
}

static void json_print_nvme_subsystem_topology(struct libnvme_subsystem *s,
					       json_object *namespaces)
{
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;

	libnvme_subsystem_for_each_ctrl(s, c) {
		libnvme_ctrl_for_each_ns(c, n) {
			struct json_object *ctrl_attrs;
			struct json_object *ns_attrs;
			struct json_object *ctrl;

			ns_attrs = json_create_object();
			obj_add_int(ns_attrs, "NSID", libnvme_ns_get_nsid(n));
			obj_add_str(ns_attrs, "Name", libnvme_ns_get_name(n));

			ctrl = json_create_array();
			ctrl_attrs = json_create_object();
			obj_add_str(ctrl_attrs, "Name",
						     libnvme_ctrl_get_name(c));
			obj_add_str(ctrl_attrs, "Transport",
						     libnvme_ctrl_get_transport(c));
			obj_add_ctrl_address(ctrl_attrs, c);
			obj_add_ctrl_address_details(ctrl_attrs, "AddressDetails", c);
			obj_add_str(ctrl_attrs, "State",
						     libnvme_ctrl_get_state(c));

			array_add_obj(ctrl, ctrl_attrs);
			obj_add_array(ns_attrs, "Controller", ctrl);
			array_add_obj(namespaces, ns_attrs);
		}
	}
}

static void json_simple_topology(struct libnvme_global_ctx *ctx)
{
	struct json_object *host_attrs, *subsystem_attrs;
	struct json_object *subsystems, *namespaces;
	struct json_object *a = json_create_array();
	struct libnvme_host *h;

	libnvme_for_each_host(ctx, h) {
		struct libnvme_subsystem *s;
		const char *hostid;

		host_attrs = json_create_object();
		obj_add_str(host_attrs, "HostNQN", libnvme_host_get_hostnqn(h));
		hostid = libnvme_host_get_hostid(h);
		if (hostid)
			obj_add_str(host_attrs, "HostID", hostid);
		subsystems = json_create_array();
		libnvme_for_each_subsystem(h, s) {
			const char *iopolicy;

			subsystem_attrs = json_create_object();
			obj_add_str(subsystem_attrs, "Name", libnvme_subsystem_get_name(s));
			obj_add_str(subsystem_attrs, "NQN", libnvme_subsystem_get_subsysnqn(s));
			libnvme_subsystem_get_iopolicy(s, &iopolicy, "");
			obj_add_str(subsystem_attrs, "IOPolicy", iopolicy);

			if (verbose_mode()) {
				const char *model;
				const char *serial;
				const char *firmware;

				libnvme_subsystem_get_model(s, &model, "");
				libnvme_subsystem_get_serial(s, &serial, "");
				libnvme_subsystem_get_firmware(s, &firmware,
								"");

				obj_add_str(subsystem_attrs, "Model", model);
				obj_add_str(subsystem_attrs, "Serial", serial);
				obj_add_str(subsystem_attrs, "Firmware",
						firmware);
				obj_add_str(subsystem_attrs, "Type",
						libnvme_subsystem_get_subsystype(s));
			}

			array_add_obj(subsystems, subsystem_attrs);
			namespaces = json_create_array();

			if (!json_subsystem_topology_multipath(s, namespaces))
				json_print_nvme_subsystem_topology(s, namespaces);

			obj_add_array(subsystem_attrs, "Namespaces", namespaces);
		}
		obj_add_array(host_attrs, "Subsystems", subsystems);
		array_add_obj(a, host_attrs);
	}

	json_print(a);
}

#ifdef CONFIG_TOP
/* A rate with two decimals, as nvme top shows it */
static void obj_add_rate(struct json_object *o, const char *k, double v)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%.2f", v);
	json_object_object_add(o, k, json_object_new_double_s(v, buf));
}

/* An attribute of a kernel which may not have it is left out */
static void obj_add_count(struct json_object *o, const char *k, int ret,
			  long v)
{
	if (!ret)
		json_object_object_add(o, k, json_object_new_int64(v));
}

static void obj_add_iostat(struct json_object *o, const struct nvme_iostat *st)
{
	struct json_object *r = json_create_object();

	obj_add_rate(r, "ReadIOPS", st->r_iops);
	obj_add_rate(r, "WriteIOPS", st->w_iops);
	obj_add_rate(r, "ReadLatencyMs", st->r_lat);
	obj_add_rate(r, "WriteLatencyMs", st->w_lat);
	obj_add_rate(r, "ReadBytesPerSec", st->r_bw);
	obj_add_rate(r, "WriteBytesPerSec", st->w_bw);
	obj_add_uint(r, "Inflights", st->inflights);
	obj_add_rate(r, "UtilPercent", st->util);

	obj_add_obj(o, "Stats", r);
}

/* The sum of the rates, and the highest latencies and utilization */
static void obj_add_iostat_aggr(struct json_object *o,
				const struct nvme_iostat *st)
{
	struct json_object *r = json_create_object();

	obj_add_rate(r, "ReadIOPS", st->r_iops);
	obj_add_rate(r, "WriteIOPS", st->w_iops);
	obj_add_rate(r, "MaxReadLatencyMs", st->r_lat);
	obj_add_rate(r, "MaxWriteLatencyMs", st->w_lat);
	obj_add_rate(r, "ReadBytesPerSec", st->r_bw);
	obj_add_rate(r, "WriteBytesPerSec", st->w_bw);
	obj_add_rate(r, "MaxUtilPercent", st->util);

	obj_add_obj(o, "Stats", r);
}

static struct json_object *json_top_path(struct libnvme_path *p)
{
	struct json_object *r = json_create_object();
	struct nvme_iostat st;
	const char *str;
	int qdepth, ret;
	long v;

	obj_add_str(r, "Name", libnvme_path_get_name(p));
	obj_add_str(r, "Controller",
		    libnvme_ctrl_get_name(libnvme_path_get_ctrl(p)));
	if (!libnvme_path_get_ana_state(p, &str, NULL))
		obj_add_str(r, "ANAState", str);
	if (!libnvme_path_get_numa_nodes(p, &str, NULL))
		obj_add_str(r, "NUMANodes", str);
	if (!libnvme_path_get_queue_depth(p, &qdepth, 0))
		obj_add_int(r, "Qdepth", qdepth);
	ret = libnvme_path_get_command_retry_count(p, &v, 0);
	obj_add_count(r, "Retries", ret, v);
	ret = libnvme_path_get_multipath_failover_count(p, &v, 0);
	obj_add_count(r, "Failovers", ret, v);
	ret = libnvme_path_get_command_error_count(p, &v, 0);
	obj_add_count(r, "Errors", ret, v);

	nvme_iostat_path(p, &st);
	obj_add_iostat(r, &st);

	return r;
}

static struct json_object *json_top_nshead(struct libnvme_ns *n,
					   struct nvme_iostat *aggr)
{
	struct json_object *r = json_create_object();
	struct json_object *paths = json_create_array();
	struct libnvme_path *p;
	struct nvme_iostat st;
	int ret;
	long v;

	obj_add_str(r, "Name", libnvme_ns_get_name(n));
	obj_add_uint(r, "NSID", libnvme_ns_get_nsid(n));
	ret = libnvme_ns_get_io_requeue_no_usable_path_count(n, &v, 0);
	obj_add_count(r, "RequeueIO", ret, v);
	ret = libnvme_ns_get_io_fail_no_available_path_count(n, &v, 0);
	obj_add_count(r, "FailIO", ret, v);

	nvme_iostat_ns(n, &st);
	nvme_iostat_aggr(aggr, &st);
	obj_add_iostat(r, &st);

	libnvme_namespace_for_each_path(n, p)
		array_add_obj(paths, json_top_path(p));
	obj_add_array(r, "Paths", paths);

	return r;
}

static struct json_object *json_top_ns(struct libnvme_ns *n,
				       struct libnvme_ctrl *c,
				       struct nvme_iostat *aggr)
{
	struct json_object *r = json_create_object();
	struct nvme_iostat st;
	int ret;
	long v;

	obj_add_str(r, "Name", libnvme_ns_get_name(n));
	obj_add_uint(r, "NSID", libnvme_ns_get_nsid(n));
	obj_add_str(r, "Controller", libnvme_ctrl_get_name(c));
	ret = libnvme_ns_get_command_retry_count(n, &v, 0);
	obj_add_count(r, "Retries", ret, v);
	ret = libnvme_ns_get_command_error_count(n, &v, 0);
	obj_add_count(r, "Errors", ret, v);

	nvme_iostat_ns(n, &st);
	nvme_iostat_aggr(aggr, &st);
	obj_add_iostat(r, &st);

	return r;
}

static struct json_object *json_top_ctrl(struct libnvme_ctrl *c,
					 bool multipath)
{
	struct json_object *r = json_create_object();
	struct nvme_iostat aggr = { 0 }, st;
	struct libnvme_path *p;
	struct libnvme_ns *n;
	const char *node;
	int npaths = 0, ret;
	long v;

	obj_add_str(r, "Name", libnvme_ctrl_get_name(c));
	obj_add_str(r, "Transport", libnvme_ctrl_get_transport(c));
	obj_add_ctrl_address(r, c);
	obj_add_str(r, "State", libnvme_ctrl_get_state(c));
	if (!libnvme_ctrl_get_numa_node(c, &node, NULL))
		obj_add_int(r, "NUMANode", atoi(node));
	ret = libnvme_ctrl_get_reset_count(c, &v, 0);
	obj_add_count(r, "Resets", ret, v);
	ret = libnvme_ctrl_get_reconnect_count(c, &v, 0);
	obj_add_count(r, "Reconnects", ret, v);
	ret = libnvme_ctrl_get_command_error_count(c, &v, 0);
	obj_add_count(r, "Errors", ret, v);

	if (multipath) {
		libnvme_ctrl_for_each_path(c, p) {
			npaths++;
			nvme_iostat_path(p, &st);
			nvme_iostat_aggr(&aggr, &st);
		}
		obj_add_int(r, "Paths", npaths);
	} else {
		libnvme_ctrl_for_each_ns(c, n) {
			nvme_iostat_ns(n, &st);
			nvme_iostat_aggr(&aggr, &st);
		}
	}
	obj_add_iostat_aggr(r, &aggr);

	return r;
}

static struct json_object *json_top_subsys(struct libnvme_subsystem *s)
{
	struct json_object *r = json_create_object();
	struct json_object *namespaces = json_create_array();
	struct json_object *ctrls = json_create_array();
	bool multipath = nvme_is_multipath(s);
	struct nvme_iostat aggr = { 0 };
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;
	const char *str;

	obj_add_str(r, "Name", libnvme_subsystem_get_name(s));
	obj_add_str(r, "NQN", libnvme_subsystem_get_subsysnqn(s));
	obj_add_str(r, "HostNQN",
		    libnvme_host_get_hostnqn(libnvme_subsystem_get_host(s)));
	if (!libnvme_subsystem_get_iopolicy(s, &str, NULL))
		obj_add_str(r, "IOPolicy", str);
	if (!libnvme_subsystem_get_model(s, &str, NULL))
		obj_add_str(r, "Model", str);
	if (!libnvme_subsystem_get_serial(s, &str, NULL))
		obj_add_str(r, "Serial", str);
	if (!libnvme_subsystem_get_firmware(s, &str, NULL))
		obj_add_str(r, "Firmware", str);
	obj_add_str(r, "Type", libnvme_subsystem_get_subsystype(s));

	if (multipath) {
		libnvme_subsystem_for_each_ns(s, n)
			array_add_obj(namespaces, json_top_nshead(n, &aggr));
	} else {
		libnvme_subsystem_for_each_ctrl(s, c)
			libnvme_ctrl_for_each_ns(c, n)
				array_add_obj(namespaces,
					      json_top_ns(n, c, &aggr));
	}
	obj_add_iostat_aggr(r, &aggr);
	obj_add_array(r, "Namespaces", namespaces);

	libnvme_subsystem_for_each_ctrl(s, c)
		array_add_obj(ctrls, json_top_ctrl(c, multipath));
	obj_add_array(r, "Controllers", ctrls);

	return r;
}

static void json_top_update(struct libnvme_global_ctx *ctx)
{
	struct libnvme_subsystem *s;
	struct libnvme_host *h;

	libnvme_for_each_host(ctx, h)
		libnvme_for_each_subsystem(h, s)
			nvme_iostat_update_subsys(s, nvme_is_multipath(s));
}

/* Takes two samples @interval seconds apart and prints the rates */
static void json_top(int interval)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct json_object *r, *subsystems;
	struct libnvme_subsystem *s;
	struct libnvme_host *h;
	int err;

	err = nvme_create_global_ctx(&ctx);
	if (err)
		return;

	if (libnvme_scan_topology(ctx, NULL, NULL)) {
		nvme_show_error("Failed to scan topology");
		return;
	}

	json_top_update(ctx);
	sleep(interval);
	json_top_update(ctx);

	r = json_create_object();
	obj_add_int(r, "Interval", interval);
	subsystems = json_create_array();
	libnvme_for_each_host(ctx, h)
		libnvme_for_each_subsystem(h, s)
			array_add_obj(subsystems, json_top_subsys(s));
	obj_add_array(r, "Subsystems", subsystems);

	json_print(r);
}
#endif /* CONFIG_TOP */

static void json_directive_show_fields_identify(__u8 doper, __u8 *field,
						__u32 len,
						struct json_object *r)
{
	struct json_object *support;
	struct json_object *enabled;
	struct json_object *persistent;

	switch (doper) {
	case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
		if (len < NVME_DIRECTIVE_IDENTIFY_PARAM_LEN) {
			obj_add_str(r, "Error", "directive data too short");
			break;
		}
		support = json_create_object();
		obj_add_obj(r, "Directive support", support);
		obj_add_str(support, "Identify Directive",
			    *field & 0x1 ? "Supported" : "Not supported");
		obj_add_str(support, "Stream Directive",
			    *field & 0x2 ? "Supported" : "Not supported");
		obj_add_str(support, "Data Placement Directive",
			    *field & 0x4 ? "Supported" : "Not supported");
		enabled = json_create_object();
		obj_add_obj(r, "Directive enabled", enabled);
		obj_add_str(enabled, "Identify Directive",
			    *(field + 32) & 0x1 ? "Enabled" : "Disabled");
		obj_add_str(enabled, "Stream Directive",
			    *(field + 32) & 0x2 ? "Enabled" : "Disabled");
		obj_add_str(enabled, "Data Placement Directive",
			    *(field + 32) & 0x4 ? "Enabled" : "Disabled");
		persistent = json_create_object();
		obj_add_obj(r,
			    "Directive Persistent Across Controller Level Resets",
			    persistent);
		obj_add_str(persistent, "Identify Directive",
			    *(field + 64) & 0x1 ? "Enabled" : "Disabled");
		obj_add_str(persistent, "Stream Directive",
			    *(field + 64) & 0x2 ? "Enabled" : "Disabled");
		obj_add_str(persistent, "Data Placement Directive",
			    *(field + 64) & 0x4 ? "Enabled" : "Disabled");
		break;
	default:
		obj_add_str(r, "Error", "invalid directive operations for Identify Directives");
		break;
	}
}

static void json_directive_show_fields_streams(__u8 doper,
					       unsigned int result, __u8 *field,
					       __u32 len, struct json_object *r)
{
	struct nvme_streams_directive_params *params = (void *)field;
	struct nvme_streams_directive_status *status = (void *)field;
	int count;
	int i;
	char json_str[STR_LEN];

	switch (doper) {
	case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
		if (len < sizeof(*params)) {
			obj_add_str(r, "Error", "directive data too short");
			break;
		}
		obj_add_uint(r, "Max Streams Limit (MSL)",
			     le16_to_cpu(params->msl));
		obj_add_uint(r, "NVM Subsystem Streams Available (NSSA)",
			     le16_to_cpu(params->nssa));
		obj_add_uint(r, "NVM Subsystem Streams Open (NSSO)",
			     le16_to_cpu(params->nsso));
		obj_add_uint(r, "NVM Subsystem Stream Capability (NSSC)",
			     params->nssc);
		obj_add_uint(r, "Stream Write Size (in unit of LB size) (SWS)",
			     le32_to_cpu(params->sws));
		obj_add_uint(r, "Stream Granularity Size (in unit of SWS) (SGS)",
			     le16_to_cpu(params->sgs));
		obj_add_uint(r, "Namespace Streams Allocated (NSA)",
			     le16_to_cpu(params->nsa));
		obj_add_uint(r, "Namespace Streams Open (NSO)",
			     le16_to_cpu(params->nso));
		break;
	case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
		if (len < sizeof(*status)) {
			obj_add_str(r, "Error", "directive data too short");
			break;
		}
		count = nvme_streams_status_nr_sid(status, len);
		obj_add_uint(r, "Open Stream Count", le16_to_cpu(status->osc));
		for (i = 0; i < count; i++) {
			sprintf(json_str, "Stream Identifier %.6u", i + 1);
			obj_add_uint(r, json_str, le16_to_cpu(status->sid[i]));
		}
		break;
	case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
		obj_add_uint(r, "Namespace Streams Allocated (NSA)", result & 0xffff);
		break;
	default:
		obj_add_str(r, "Error",
					     "invalid directive operations for Streams Directives");
		break;
	}
}

static void json_directive_show_fields(__u8 dtype, __u8 doper, unsigned int result,
				       __u8 *field, __u32 len,
				       struct json_object *r)
{
	switch (dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		json_directive_show_fields_identify(doper, field, len, r);
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		json_directive_show_fields_streams(doper, result, field, len,
						   r);
		break;
	default:
		obj_add_str(r, "Error", "invalid directive type");
		break;
	}
}

static void json_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u64 result,
				void *buf, __u32 len)
{
	struct json_object *r = json_r;
	struct json_object *data;
	char json_str[STR_LEN];

	sprintf(json_str, "%#x", type);
	obj_add_str(r, "Type", json_str);
	sprintf(json_str, "%#x", oper);
	obj_add_str(r, "Operation", json_str);
	sprintf(json_str, "%#x", spec);
	obj_add_str(r, "spec", json_str);
	sprintf(json_str, "%#x", nsid);
	obj_add_str(r, "NSID", json_str);
	sprintf(json_str, "%#"PRIx64, (uint64_t)result);
	obj_add_result(r, "%s", json_str);

	if (verbose_mode()) {
		json_directive_show_fields(type, oper, result, buf, len, r);
	} else if (buf) {
		data = json_create_array();
		d_json((unsigned char *)buf, len, 16, 1, data);
		obj_add_array(r, "data", data);
	}
}

#ifdef CONFIG_FABRICS
static void json_discovery_log(const struct nvmf_discovery_log *log, int numrec)
{
	struct json_object *r = json_r;
	struct json_object *entries = json_create_array();
	int i;

	obj_add_uint64(r, "genctr", le64_to_cpu(log->genctr));
	obj_add_array(r, "records", entries);

	for (i = 0; i < numrec; i++) {
		const struct nvmf_disc_log_entry *e = &log->entries[i];
		struct json_object *entry = json_create_object();
		/*
		 * e->trsvcid/subnqn/traddr are fixed-width fields off the wire,
		 * not guaranteed NUL-terminated. json_object_new_string()
		 * needs a NUL-terminated C string, so make NUL-terminated
		 * copies and trim trailing spaces (if any). Members of e
		 * cannot be modified directly (we do not own that data).
		 */
		__cleanup_free char *trsvcid = NULL;
		__cleanup_free char *traddr = NULL;
		__cleanup_free char *subnqn = NULL;

		trsvcid = shr_buf2str(e->trsvcid, sizeof(e->trsvcid));
		traddr = shr_buf2str(e->traddr, sizeof(e->traddr));
		subnqn = shr_buf2str(e->subnqn, sizeof(e->subnqn));

		obj_add_str(entry, "trtype", libnvmf_trtype_str(e->trtype));
		obj_add_str(entry, "adrfam", libnvmf_adrfam_str(e->adrfam));
		obj_add_str(entry, "subtype", libnvmf_subtype_str(e->subtype));
		obj_add_str(entry, "treq", libnvmf_treq_str(e->treq));
		obj_add_uint(entry, "portid", le16_to_cpu(e->portid));
		obj_add_str(entry, "trsvcid", trsvcid);
		obj_add_str(entry, "subnqn", subnqn);
		obj_add_str(entry, "traddr", traddr);
		obj_add_str(entry, "eflags", libnvmf_eflags_str(le16_to_cpu(e->eflags)));

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			obj_add_str(entry, "rdma_prtype", libnvmf_prtype_str(e->tsas.rdma.prtype));
			obj_add_str(entry, "rdma_qptype", libnvmf_qptype_str(e->tsas.rdma.qptype));
			obj_add_str(entry, "rdma_cms", libnvmf_cms_str(e->tsas.rdma.cms));
			obj_add_uint(entry, "rdma_pkey", le16_to_cpu(e->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			obj_add_str(entry, "sectype", libnvmf_sectype_str(e->tsas.tcp.sectype));
			break;
		default:
			break;
		}
		array_add_obj(entries, entry);
	}
}
#else
static void json_discovery_log(const struct nvmf_discovery_log *log,
				int numrec)
{
}
#endif

#ifdef CONFIG_FABRICS
static void json_add_param(const char *key, const char *value, void *user_data)
{
	obj_add_str(user_data, key, value);
}

/*
 * libnvmf_config_conn_for_each() callback for "nvme config show -o json".
 * Reports fields as configured, not canonicalized through a TID (which has
 * no per-field accessors). hostnqn/hostid are null when a persona falls
 * back to the system default, not the value it would resolve to.
 */
static void json_add_conn(const struct libnvmf_config_conn *c, void *user_data)
{
	struct json_object *entries = user_data;
	struct json_object *entry = json_create_object();
	struct json_object *params_obj = json_create_object();
	const struct libnvmf_params *params = libnvmf_config_conn_get_params(c);

	obj_add_str(entry, "source", libnvmf_config_conn_get_source(c));
	obj_add_bool(entry, "is_dc", libnvmf_config_conn_is_dc(c));
	obj_add_str(entry, "transport", libnvmf_config_conn_get_transport(c));
	obj_add_str(entry, "traddr", libnvmf_config_conn_get_traddr(c));
	obj_add_str(entry, "trsvcid", libnvmf_config_conn_get_trsvcid(c));
	obj_add_str(entry, "nqn", libnvmf_config_conn_get_subsysnqn(c));
	obj_add_str(entry, "host-traddr",
		    libnvmf_config_conn_get_host_traddr(c));
	obj_add_str(entry, "host-iface", libnvmf_config_conn_get_host_iface(c));
	obj_add_str(entry, "hostnqn", libnvmf_config_conn_get_hostnqn(c));
	obj_add_str(entry, "hostid", libnvmf_config_conn_get_hostid(c));

	libnvmf_params_for_each(params, json_add_param, params_obj);
	obj_add_obj(entry, "params", params_obj);

	array_add_obj(entries, entry);
}

static void json_config_conn_list(struct libnvmf_config *config)
{
	struct json_object *r = json_r;
	struct json_object *entries = json_create_array();

	obj_add_array(r, "connections", entries);
	libnvmf_config_conn_for_each(config, json_add_conn, entries);
}
#else
static void json_config_conn_list(struct libnvmf_config *config) {}
#endif

static void json_connect_msg(struct libnvme_ctrl *c)
{
	struct json_object *r = json_r;

	obj_add_str(r, "device", libnvme_ctrl_get_name(c));
}

static void json_output_object(struct json_object *r)
{
	json_print(r);
}

static void json_output_status(int status)
{
	struct json_object *r;
	char json_str[STR_LEN];
	int val;
	int type;

	sprintf(json_str, "status: %d", status);
	r = obj_create(json_str);

	if (status < 0) {
		obj_add_str(r, "error", libnvme_strerror(-status));
		obj_print(r);
		return;
	}

	val = nvme_status_get_value(status);
	type = nvme_status_get_type(status);

	switch (type) {
	case NVME_STATUS_TYPE_NVME:
		obj_add_str(r, "error", libnvme_status_to_string(val, false));
		obj_add_str(r, "type", "nvme");
		break;
#ifdef CONFIG_MI
	case NVME_STATUS_TYPE_MI:
		obj_add_str(r, "error", libnvme_mi_status_to_string(val));
		obj_add_str(r, "type", "nvme-mi");
		break;
#endif
	default:
		obj_add_str(r, "type", "Unknown");
		break;
	}

	obj_print(r);
}

static void json_output_opcode_status(int status, bool admin, __u8 opcode)
{
	struct json_object *r;
	char json_str[STR_LEN];
	int val = nvme_status_get_value(status);
	int type = nvme_status_get_type(status);

	if (status >= 0 && type == NVME_STATUS_TYPE_NVME) {
		sprintf(json_str, "status: %d", status);
		r = obj_create(json_str);
		obj_add_str(r, "error",
			    libnvme_opcode_status_to_string(val, admin, opcode));
		obj_add_str(r, "type", "nvme");
		obj_print(r);
		return;
	}

	json_output_status(status);
}

static void json_output_error_status(int status, const char *msg, va_list ap)
{
	struct json_object *r;
	char json_str[STR_LEN];
	int val;
	int type;

	__cleanup_free char *value = NULL;

	if (vasprintf(&value, msg, ap) < 0)
		value = NULL;

	sprintf(json_str, "Error: %s", value ? value : alloc_error);
	r = obj_create(json_str);

	if (status < 0) {
		obj_add_str(r, "error", libnvme_strerror(-status));
		obj_print(r);
		return;
	}

	val = nvme_status_get_value(status);
	type = nvme_status_get_type(status);

	switch (type) {
	case NVME_STATUS_TYPE_NVME:
		obj_add_str(r, "status", libnvme_status_to_string(val, false));
		obj_add_str(r, "type", "nvme");
		break;
#ifdef CONFIG_MI
	case NVME_STATUS_TYPE_MI:
		obj_add_str(r, "status", libnvme_mi_status_to_string(val));
		obj_add_str(r, "type", "nvme-mi");
		break;
#endif
	default:
		obj_add_str(r, "type", "Unknown");
		break;
	}

	obj_add_int(r, "value", val);

	obj_print(r);
}

static void json_output_message(bool error, const char *msg, va_list ap)
{
	struct json_object *r = json_r;

	__cleanup_free char *value = NULL;

	if (vasprintf(&value, msg, ap) < 0)
		value = NULL;

	obj_add_str(r, error ? "error" : "result", value ? value : alloc_error);
}

static void json_output_perror(const char *msg, va_list ap)
{
	struct json_object *r = json_r;
	int err = errno;

	__cleanup_free char *error = NULL;

	if (vasprintf(&error, msg, ap) < 0)
		error = NULL;

	obj_add_key(r, "error", "%s: %s", error ? error : alloc_error,
		    libnvme_strerror(err));
}

static void json_output_key_value(const char *key, const char *val, va_list ap)
{
	struct json_object *r = json_r;

	__cleanup_free char *value = NULL;
	__cleanup_free char *key_dup = strdup(key);
	char *key_trim = key_dup ? shr_trim(key_dup) : NULL;

	if (vasprintf(&value, val, ap) < 0)
		value = NULL;

	obj_add_str(r, key_trim ? key_trim : key, value ? value : "Could not allocate string");
}

void json_show_init(void)
{
	json_init = true;

	if (!json_r)
		json_r = json_create_object();
}

bool json_empty(struct json_object *obj)
{
	if (!obj)
		return true;

	switch (json_object_get_type(obj)) {
	case json_type_object:
		return json_object_object_length(obj) == 0;
	case json_type_array:
		return json_object_array_length(obj) == 0;
	default:
		return false; /* scalars always have something to print */
	}
}

void json_show_finish(void)
{
	/* nvme_main() finishes even if no command started a document */
	if (!json_init)
		return;
	json_init = false;

	if (!json_empty(json_r))
		json_output_object(json_r);
	else
		json_free_object(json_r);

	json_r = NULL;
}

/*
 * A sandboxed printer: the child inherits the document as it was at the
 * fork. Let the printer write to an object of its own instead, whose
 * members the caller adds to its document.
 */
static int json_capture_begin(void)
{
	if (!json_init)
		return 0;

	json_r = json_create_object();
	return json_r ? 0 : -ENOMEM;
}

static int json_member_put(struct printbuf *pb, const char *s, size_t len)
{
	uint32_t n = len;

	if (len > UINT32_MAX)
		return -EOVERFLOW;
	printbuf_memappend(pb, (const char *)&n, sizeof(n));
	printbuf_memappend(pb, s, len);

	return 0;
}

/*
 * The members the printer added, serialized as pairs of a length and the
 * key, a length and the value. @buf is to free().
 */
static int json_capture_end(void **buf, size_t *len)
{
	struct printbuf *pb;
	const char *v;
	int err = 0;

	*buf = NULL;
	*len = 0;
	if (!json_init)
		return 0;

	pb = printbuf_new();
	if (!pb)
		return -ENOMEM;
	json_object_object_foreach(json_r, key, val) {
		v = json_object_to_json_string_ext(val,
				JSON_C_TO_STRING_PRETTY |
				JSON_C_TO_STRING_NOSLASHESCAPE);
		if (!v || json_member_put(pb, key, strlen(key)) ||
		    json_member_put(pb, v, strlen(v))) {
			err = -ENOMEM;
			break;
		}
	}
	if (!err && printbuf_length(pb)) {
		*buf = malloc(printbuf_length(pb));
		if (*buf) {
			memcpy(*buf, pb->buf, printbuf_length(pb));
			*len = printbuf_length(pb);
		} else {
			err = -ENOMEM;
		}
	}
	printbuf_free(pb);

	return err;
}

/* Writes a serialized value as it is, indented to @level */
static int json_member_serialize(struct json_object *jso,
				 struct printbuf *pb, int level, int flags)
{
	const char *s = json_object_get_string(jso);
	size_t len = json_object_get_string_len(jso), i, start = 0;
	int j;

	for (i = 0; i < len; i++) {
		if (s[i] != '\n')
			continue;
		printbuf_memappend(pb, s + start, i - start + 1);
		start = i + 1;
		if (flags & JSON_C_TO_STRING_PRETTY)
			for (j = 0; j < level; j++)
				printbuf_strappend(pb, "  ");
	}
	printbuf_memappend(pb, s + start, len - start);

	return 0;
}

static bool json_member_get(const char **p, const char *end,
			    const char **s, uint32_t *n)
{
	if ((size_t)(end - *p) < sizeof(*n))
		return false;
	memcpy(n, *p, sizeof(*n));
	*p += sizeof(*n);
	if ((size_t)(end - *p) < *n)
		return false;
	*s = *p;
	*p += *n;

	return true;
}

/*
 * Adds the members of a sandboxed printer to the document. They are added
 * as the child serialized them, not parsed again: a parse would turn 128
 * bit numbers into doubles. A member replaces one of the same key, as when
 * the printer runs in process. The child may have been taken over: check
 * the framing, the values are only copied to the output.
 */
static int json_capture_add(const void *buf, size_t len)
{
	const char *p = buf, *end = p + len, *k, *v;
	struct json_object *val;
	__cleanup_free char *key = NULL;
	uint32_t klen, vlen;

	if (!len)
		return 0;
	if (!json_init || !json_r)
		return -EPROTO;

	while (p < end) {
		if (!json_member_get(&p, end, &k, &klen) ||
		    !json_member_get(&p, end, &v, &vlen) ||
		    memchr(k, '\0', klen))
			return -EPROTO;
		free(key);
		key = strndup(k, klen);
		if (!key)
			return -ENOMEM;
		val = json_object_new_string_len(v, vlen);
		if (!val)
			return -ENOMEM;
		json_object_set_serializer(val, json_member_serialize,
					   NULL, NULL);
		json_object_object_add(json_r, key, val);
	}

	return 0;
}

static struct print_ops json_print_ops = {
	/* libnvme types.h print functions */
	.ctrl_list			= json_nvme_list_ctrl,
	.ctrl_registers			= json_ctrl_registers,
	.directive			= json_directive_show,
	.discovery_log			= json_discovery_log,
	.endurance_group_list		= json_nvme_endurance_group_list,
	.fdp_config_log			= json_nvme_fdp_configs,
	.fdp_event_log			= json_nvme_fdp_events,
	.fdp_ruh_status			= json_nvme_fdp_ruh_status,
	.fdp_stats_log			= json_nvme_fdp_stats,
	.fdp_usage_log			= json_nvme_fdp_usage,
	.id_ctrl			= json_nvme_id_ctrl,
	.id_ctrl_nvm			= json_nvme_id_ctrl_nvm,
	.id_domain_list			= json_id_domain_list,
	.id_independent_id_ns		= json_nvme_cmd_set_independent_id_ns,
	.id_iocs			= json_id_iocs,
	.id_ns				= json_nvme_id_ns,
	.id_ns_descs			= json_nvme_id_ns_descs,
	.id_ns_granularity_list		= json_nvme_id_ns_granularity_list,
	.id_nvmset_list			= json_nvme_id_nvmset,
	.id_uuid_list			= json_nvme_id_uuid_list,
	.lba_status			= json_lba_status,
	.ns_list			= json_nvme_list_ns,
	.nvm_id_ns			= json_nvme_nvm_id_ns,
	.primary_ctrl_cap		= json_nvme_primary_ctrl_cap,
	.resv_report			= json_nvme_resv_report,
	.secondary_ctrl_list		= json_nvme_list_secondary_ctrl,
	.select_result			= json_select_result,
	.show_feature			= json_feature_show,
	.show_feature_fields		= json_feature_show_fields,
	.id_ctrl_rpmbs			= json_id_ctrl_rpmbs,
	.lba_range			= json_lba_range,
	.lba_status_info		= json_lba_status_info,
	.d				= json_d,
	.show_init			= json_show_init,
	.show_finish			= json_show_finish,

	/* libnvme tree print functions */
	.list_item			= json_list_item,
	.list_items			= json_print_list_items,
	.print_nvme_subsystem_list	= json_print_nvme_subsystem_list,
	.topology_ctrl			= json_simple_topology,
	.topology_namespace		= json_simple_topology,
	.topology_multipath		= json_simple_topology,

	/* nvme top */
#ifdef CONFIG_TOP
	.top				= json_top,
#endif

	/* config show */
	.config_conn_list		= json_config_conn_list,

	/* status and error messages */
	.connect_msg			= json_connect_msg,
	.show_message			= json_output_message,
	.show_perror			= json_output_perror,
	.show_status			= json_output_status,
	.show_opcode_status		= json_output_opcode_status,
	.show_error_status		= json_output_error_status,
	.show_key_value			= json_output_key_value,
	.capture_begin			= json_capture_begin,
	.capture_end			= json_capture_end,
	.capture_add			= json_capture_add,
};

/*
 * json-c seeds its string hash on the first lookup. Built without
 * getrandom(), as the meson subproject is, it reads /dev/urandom then,
 * which a printer in the sandbox cannot open.
 */
static void json_seed_hash(void)
{
	struct json_object *o = json_create_object();

	json_object_object_get_ex(o, "", NULL);
	json_free_object(o);
}

struct print_ops *nvme_get_json_print_ops(nvme_print_flags_t flags)
{
	json_seed_hash();
	json_print_ops.flags = flags;
	return &json_print_ops;
}
