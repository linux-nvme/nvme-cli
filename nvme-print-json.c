// SPDX-License-Identifier: GPL-2.0-or-later

#include <assert.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ccan/ccan/compiler/compiler.h>

#include "nvme-print.h"

#include "util/json.h"
#include "logging.h"
#include "nvme.h"
#include "common.h"
#include "libnvme.h"

#define ERROR_MSG_LEN 100
#define NAME_LEN 128
#define BUF_LEN 320
#define VAL_LEN 4096
#define BYTE_TO_BIT(byte) ((byte) * 8)
#define MS_TO_SEC(time) ((time) / 1000)
#define MS500_TO_MS(time) ((time) * 500)
#define MS500_TO_SEC(time) (MS_TO_SEC(MS500_TO_MS(time)))

#define array_add_obj json_array_add_value_object
#define array_add_str json_array_add_value_string

#define obj_add_array json_object_add_value_array
#define obj_add_int json_object_add_value_int
#define obj_add_obj json_object_add_value_object
#define obj_add_uint json_object_add_value_uint
#define obj_add_uint128 json_object_add_value_uint128
#define obj_add_uint64 json_object_add_value_uint64
#define obj_add_str json_object_add_value_string
#define obj_add_uint_02x json_object_add_uint_02x
#define obj_add_uint_0x json_object_add_uint_0x
#define obj_add_byte_array json_object_add_byte_array
#define obj_add_nprix64 json_object_add_nprix64
#define obj_add_uint_0nx json_object_add_uint_0nx
#define obj_add_0nprix64 json_object_add_0nprix64
#define obj_add_string json_object_add_string

static const uint8_t zero_uuid[16] = { 0 };
static struct print_ops json_print_ops;
static struct json_object *json_r;
static int json_init;

static void json_feature_show_fields(enum nvme_features_id fid, unsigned int result,
				     unsigned char *buf);

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

static void obj_d(struct json_object *o, const char *k, unsigned char *buf, int len, int width,
		  int group)
{
	struct json_object *data = json_create_array();

	d_json(buf, len, width, group, data);
	obj_add_array(o, k, data);
}

static void obj_add_uint_x(struct json_object *o, const char *k, __u32 v)
{
	char str[STR_LEN];

	sprintf(str, "%x", v);
	obj_add_str(o, k, str);
}

static void obj_add_uint_nx(struct json_object *o, const char *k, __u32 v)
{
	char str[STR_LEN];

	sprintf(str, "%#x", v);
	obj_add_str(o, k, str);
}

static void obj_add_prix64(struct json_object *o, const char *k, uint64_t v)
{
	char str[STR_LEN];

	sprintf(str, "%"PRIx64"", v);
	obj_add_str(o, k, str);
}

static void obj_add_int_secs(struct json_object *o, const char *k, int v)
{
	char str[STR_LEN];

	sprintf(str, "%d secs", v);
	obj_add_str(o, k, str);
}

static void obj_add_result(struct json_object *o, const char *v, ...)
{
	va_list ap;

	_cleanup_free_ char *value = NULL;

	va_start(ap, v);

	if (vasprintf(&value, v, ap) < 0)
		value = alloc_error;

	obj_add_str(o, "Result", value);

	va_end(ap);
}

static void obj_add_key(struct json_object *o, const char *k, const char *v, ...)
{
	va_list ap;

	_cleanup_free_ char *value = NULL;

	va_start(ap, v);

	if (vasprintf(&value, v, ap) < 0)
		value = alloc_error;

	obj_add_str(o, k, value);

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

static struct json_object *obj_create(const char *k)
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

static void obj_print(struct json_object *o)
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
	return json_print_ops.flags & VERBOSE || nvme_cfg.output_format_ver == 2;
}

static void json_id_iocs(struct nvme_id_iocs *iocs)
{
	struct json_object *r = json_create_object();
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

	json_print(r);
}

static void json_nvme_id_ns_lbaf(struct nvme_id_ns *ns, int i, struct json_object *lbafs)
{
	struct json_object *lbaf = json_create_object();
	__u8 flbas;

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &flbas);

	if (verbose_mode()) {
		obj_add_int(lbaf, "LBA Format", i);
		obj_add_string(lbaf, "Metadata Size", "%d bytes", le16_to_cpu(ns->lbaf[i].ms));
		obj_add_string(lbaf, "Data Size", "%d bytes", 1 << ns->lbaf[i].ds);
		obj_add_string(lbaf, "Relative Performance", "0x%x %s", ns->lbaf[i].rp,
			       ns->lbaf[i].rp == 3 ? "Degraded" : ns->lbaf[i].rp == 2 ? "Good" :
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
	char nguid_buf[2 * sizeof(ns->nguid) + 1],
		eui64_buf[2 * sizeof(ns->eui64) + 1];
	char *nguid = nguid_buf, *eui64 = eui64_buf;
	struct json_object *r = json_create_object();
	struct json_object *lbafs = json_create_array();
	struct json_object *vs = json_create_array();
	int i;
	nvme_uint128_t nvmcap = le128_to_cpu(ns->nvmcap);

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

		memset(eui64, 0, sizeof(eui64_buf));

		for (i = 0; i < sizeof(ns->eui64); i++)
			eui64 += sprintf(eui64, "%02x", ns->eui64[i]);

		memset(nguid, 0, sizeof(nguid_buf));

		for (i = 0; i < sizeof(ns->nguid); i++)
			nguid += sprintf(nguid, "%02x", ns->nguid[i]);

		obj_add_str(r, "nguid", nguid_buf);
		obj_add_str(r, "eui64", eui64_buf);
	}

	obj_add_array(r, "lbafs", lbafs);

	for (i = 0; i <= ns->nlbaf; i++)
		json_nvme_id_ns_lbaf(ns, i, lbafs);

	d_json(ns->vs, strnlen((const char *)ns->vs, sizeof(ns->vs)), 16, 1, vs);
	obj_add_array(r, "vs", vs);

	json_print(r);
}

void json_nvme_id_ctrl(struct nvme_id_ctrl *ctrl,
			void (*vs)(__u8 *vs, struct json_object *r))
{
	struct json_object *r = json_create_object();
	struct json_object *psds = json_create_array();
	nvme_uint128_t tnvmcap = le128_to_cpu(ctrl->tnvmcap);
	nvme_uint128_t unvmcap = le128_to_cpu(ctrl->unvmcap);
	nvme_uint128_t megcap = le128_to_cpu(ctrl->megcap);
	nvme_uint128_t maxdna = le128_to_cpu(ctrl->maxdna);
	char sn[sizeof(ctrl->sn) + 1], mn[sizeof(ctrl->mn) + 1],
		fr[sizeof(ctrl->fr) + 1], subnqn[sizeof(ctrl->subnqn) + 1];
	__u32 ieee = ctrl->ieee[2] << 16 | ctrl->ieee[1] << 8 | ctrl->ieee[0];
	int i;

	snprintf(sn, sizeof(sn), "%-.*s", (int)sizeof(ctrl->sn), ctrl->sn);
	snprintf(mn, sizeof(mn), "%-.*s", (int)sizeof(ctrl->mn), ctrl->mn);
	snprintf(fr, sizeof(fr), "%-.*s", (int)sizeof(ctrl->fr), ctrl->fr);
	snprintf(subnqn, sizeof(subnqn), "%-.*s", (int)sizeof(ctrl->subnqn), ctrl->subnqn);

	obj_add_int(r, "vid", le16_to_cpu(ctrl->vid));
	obj_add_int(r, "ssvid", le16_to_cpu(ctrl->ssvid));
	obj_add_str(r, "sn", sn);
	obj_add_str(r, "mn", mn);
	obj_add_str(r, "fr", fr);
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
	obj_add_str(r, "fguid", util_uuid_to_string(ctrl->fguid));
	obj_add_int(r, "crdt1", le16_to_cpu(ctrl->crdt1));
	obj_add_int(r, "crdt2", le16_to_cpu(ctrl->crdt2));
	obj_add_int(r, "crdt3", le16_to_cpu(ctrl->crdt3));
	obj_add_int(r, "crcap", ctrl->crcap);
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
	obj_add_int(r, "cqt", le16_to_cpu(ctrl->cqt));
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

	obj_add_array(r, "psds", psds);

	for (i = 0; i <= ctrl->npss; i++) {
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

		array_add_obj(psds, psd);
	}

	if (vs)
		vs(ctrl->vs, r);

	json_print(r);
}

static void json_error_log(struct nvme_error_log_page *err_log, int entries,
			   const char *devname)
{
	struct json_object *r = json_create_object();
	struct json_object *errors = json_create_array();
	int i;

	obj_add_array(r, "errors", errors);

	for (i = 0; i < entries; i++) {
		struct json_object *error = json_create_object();

		obj_add_uint64(error, "error_count", le64_to_cpu(err_log[i].error_count));
		obj_add_int(error, "sqid", le16_to_cpu(err_log[i].sqid));
		obj_add_int(error, "cmdid", le16_to_cpu(err_log[i].cmdid));
		obj_add_int(error, "status_field", le16_to_cpu(err_log[i].status_field) >> 0x1);
		obj_add_int(error, "phase_tag", le16_to_cpu(err_log[i].status_field) & 0x1);
		obj_add_int(error, "parm_error_location",
			    le16_to_cpu(err_log[i].parm_error_location));
		obj_add_uint64(error, "lba", le64_to_cpu(err_log[i].lba));
		obj_add_uint(error, "nsid", le32_to_cpu(err_log[i].nsid));
		obj_add_int(error, "vs", err_log[i].vs);
		obj_add_int(error, "trtype", err_log[i].trtype);
		obj_add_uint64(error, "cs", le64_to_cpu(err_log[i].cs));
		obj_add_int(error, "trtype_spec_info", le16_to_cpu(err_log[i].trtype_spec_info));

		array_add_obj(errors, error);
	}

	json_print(r);
}

void json_nvme_resv_report(struct nvme_resv_status *status,
			   int bytes, bool eds)
{
	struct json_object *r = json_create_object();
	struct json_object *rcs = json_create_array();
	int i, j, entries;
	int regctl = status->regctl[0] | (status->regctl[1] << 8);

	obj_add_uint(r, "gen", le32_to_cpu(status->gen));
	obj_add_int(r, "rtype", status->rtype);
	obj_add_int(r, "regctl", regctl);
	obj_add_int(r, "ptpls", status->ptpls);

	/* check Extended Data Structure bit */
	if (!eds) {
		/*
		 * if status buffer was too small, don't loop past the end of
		 * the buffer
		 */
		entries = (bytes - 24) / 24;
		if (entries < regctl)
			regctl = entries;

		obj_add_array(r, "regctls", rcs);
		for (i = 0; i < regctl; i++) {
			struct json_object *rc = json_create_object();

			obj_add_int(rc, "cntlid", le16_to_cpu(status->regctl_ds[i].cntlid));
			obj_add_int(rc, "rcsts", status->regctl_ds[i].rcsts);
			obj_add_uint64(rc, "hostid", le64_to_cpu(status->regctl_ds[i].hostid));
			obj_add_uint64(rc, "rkey", le64_to_cpu(status->regctl_ds[i].rkey));

			array_add_obj(rcs, rc);
		}
	} else {
		char hostid[33];

		/* if status buffer was too small, don't loop past the end of the buffer */
		entries = (bytes - 64) / 64;

		if (entries < regctl)
			regctl = entries;

		obj_add_array(r, "regctlext", rcs);

		for (i = 0; i < regctl; i++) {
			struct json_object *rc = json_create_object();

			obj_add_int(rc, "cntlid", le16_to_cpu(status->regctl_eds[i].cntlid));
			obj_add_int(rc, "rcsts", status->regctl_eds[i].rcsts);
			obj_add_uint64(rc, "rkey", le64_to_cpu(status->regctl_eds[i].rkey));

			for (j = 0; j < 16; j++)
				sprintf(hostid + j * 2, "%02x", status->regctl_eds[i].hostid[j]);

			obj_add_str(rc, "hostid", hostid);
			array_add_obj(rcs, rc);
		}
	}

	json_print(r);
}

void json_fw_log(struct nvme_firmware_slot *fw_log, const char *devname)
{
	struct json_object *r = json_create_object();
	struct json_object *fwsi = json_create_object();
	char fmt[21];
	char str[32];
	int i;
	__le64 *frs;

	obj_add_int(fwsi, "Active Firmware Slot (afi)", fw_log->afi);

	for (i = 0; i < 7; i++) {
		if (fw_log->frs[i][0]) {
			snprintf(fmt, sizeof(fmt), "Firmware Rev Slot %d",
				i + 1);
			frs = (__le64 *)&fw_log->frs[i];
			snprintf(str, sizeof(str), "%"PRIu64" (%s)",
				le64_to_cpu(*frs),
			util_fw_to_string(fw_log->frs[i]));
			obj_add_str(fwsi, fmt, str);
		}
	}

	obj_add_obj(r, devname, fwsi);

	json_print(r);
}

void json_changed_ns_list_log(struct nvme_ns_list *log, const char *devname, bool alloc)
{
	struct json_object *r = json_create_object();
	struct json_object *nsi = json_create_object();
	char fmt[32];
	char str[32];
	__u32 nsid;
	int i;

	_cleanup_free_ char *k = NULL;

	if (log->ns[0] == cpu_to_le32(0xffffffff))
		return;

	if (asprintf(&k, "Changed %s Namespace List Log", alloc ? "Allocated" : "Attached") > 0)
		obj_add_str(r, k, devname);

	for (i = 0; i < NVME_ID_NS_LIST_MAX; i++) {
		nsid = le32_to_cpu(log->ns[i]);

		if (nsid == 0)
			break;

		snprintf(fmt, sizeof(fmt), "[%4u]", i + 1);
		snprintf(str, sizeof(str), "%#x", nsid);
		obj_add_str(nsi, fmt, str);
	}

	obj_add_obj(r, devname, nsi);

	json_print(r);
}

static void json_endurance_log(struct nvme_endurance_group_log *endurance_group, __u16 group_id,
			       const char *devname)
{
	struct json_object *r = json_create_object();
	nvme_uint128_t endurance_estimate = le128_to_cpu(endurance_group->endurance_estimate);
	nvme_uint128_t data_units_read = le128_to_cpu(endurance_group->data_units_read);
	nvme_uint128_t data_units_written = le128_to_cpu(endurance_group->data_units_written);
	nvme_uint128_t media_units_written = le128_to_cpu(endurance_group->media_units_written);
	nvme_uint128_t host_read_cmds = le128_to_cpu(endurance_group->host_read_cmds);
	nvme_uint128_t host_write_cmds = le128_to_cpu(endurance_group->host_write_cmds);
	nvme_uint128_t media_data_integrity_err =
	    le128_to_cpu(endurance_group->media_data_integrity_err);
	nvme_uint128_t num_err_info_log_entries =
	    le128_to_cpu(endurance_group->num_err_info_log_entries);
	nvme_uint128_t total_end_grp_cap = le128_to_cpu(endurance_group->total_end_grp_cap);
	nvme_uint128_t unalloc_end_grp_cap = le128_to_cpu(endurance_group->unalloc_end_grp_cap);

	obj_add_int(r, "critical_warning", endurance_group->critical_warning);
	obj_add_int(r, "endurance_group_features", endurance_group->endurance_group_features);
	obj_add_int(r, "avl_spare", endurance_group->avl_spare);
	obj_add_int(r, "avl_spare_threshold", endurance_group->avl_spare_threshold);
	obj_add_int(r, "percent_used", endurance_group->percent_used);
	obj_add_int(r, "domain_identifier", endurance_group->domain_identifier);
	obj_add_uint128(r, "endurance_estimate", endurance_estimate);
	obj_add_uint128(r, "data_units_read", data_units_read);
	obj_add_uint128(r, "data_units_written", data_units_written);
	obj_add_uint128(r, "media_units_written", media_units_written);
	obj_add_uint128(r, "host_read_cmds", host_read_cmds);
	obj_add_uint128(r, "host_write_cmds", host_write_cmds);
	obj_add_uint128(r, "media_data_integrity_err", media_data_integrity_err);
	obj_add_uint128(r, "num_err_info_log_entries", num_err_info_log_entries);
	obj_add_uint128(r, "total_end_grp_cap", total_end_grp_cap);
	obj_add_uint128(r, "unalloc_end_grp_cap", unalloc_end_grp_cap);

	json_print(r);
}

static void json_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
			   const char *devname)
{
	struct json_object *r = json_create_object();
	int c;
	char key[21];
	unsigned int temperature = ((smart->temperature[1] << 8) |
		smart->temperature[0]);
	nvme_uint128_t data_units_read = le128_to_cpu(smart->data_units_read);
	nvme_uint128_t data_units_written = le128_to_cpu(smart->data_units_written);
	nvme_uint128_t host_read_commands = le128_to_cpu(smart->host_reads);
	nvme_uint128_t host_write_commands = le128_to_cpu(smart->host_writes);
	nvme_uint128_t controller_busy_time = le128_to_cpu(smart->ctrl_busy_time);
	nvme_uint128_t power_cycles = le128_to_cpu(smart->power_cycles);
	nvme_uint128_t power_on_hours = le128_to_cpu(smart->power_on_hours);
	nvme_uint128_t unsafe_shutdowns = le128_to_cpu(smart->unsafe_shutdowns);
	nvme_uint128_t media_errors = le128_to_cpu(smart->media_errors);
	nvme_uint128_t num_err_log_entries = le128_to_cpu(smart->num_err_log_entries);

	if (verbose_mode()) {
		struct json_object *crt = json_create_object();

		obj_add_int(crt, "value", smart->critical_warning);
		obj_add_int(crt, "available_spare", smart->critical_warning & 1);
		obj_add_int(crt, "temp_threshold", (smart->critical_warning & 2) >> 1);
		obj_add_int(crt, "reliability_degraded", (smart->critical_warning & 4) >> 2);
		obj_add_int(crt, "ro", (smart->critical_warning & 8) >> 3);
		obj_add_int(crt, "vmbu_failed", (smart->critical_warning & 0x10) >> 4);
		obj_add_int(crt, "pmr_ro", (smart->critical_warning & 0x20) >> 5);

		obj_add_obj(r, "critical_warning", crt);
	} else {
		obj_add_int(r, "critical_warning", smart->critical_warning);
	}

	obj_add_int(r, "temperature", temperature);
	obj_add_int(r, "avail_spare", smart->avail_spare);
	obj_add_int(r, "spare_thresh", smart->spare_thresh);
	obj_add_int(r, "percent_used", smart->percent_used);
	obj_add_int(r, "endurance_grp_critical_warning_summary", smart->endu_grp_crit_warn_sumry);
	obj_add_uint128(r, "data_units_read", data_units_read);
	obj_add_uint128(r, "data_units_written", data_units_written);
	obj_add_uint128(r, "host_read_commands", host_read_commands);
	obj_add_uint128(r, "host_write_commands", host_write_commands);
	obj_add_uint128(r, "controller_busy_time", controller_busy_time);
	obj_add_uint128(r, "power_cycles", power_cycles);
	obj_add_uint128(r, "power_on_hours", power_on_hours);
	obj_add_uint128(r, "unsafe_shutdowns", unsafe_shutdowns);
	obj_add_uint128(r, "media_errors", media_errors);
	obj_add_uint128(r, "num_err_log_entries", num_err_log_entries);
	obj_add_uint(r, "warning_temp_time", le32_to_cpu(smart->warning_temp_time));
	obj_add_uint(r, "critical_comp_time", le32_to_cpu(smart->critical_comp_time));

	for (c = 0; c < 8; c++) {
		__s32 temp = le16_to_cpu(smart->temp_sensor[c]);

		if (temp == 0)
			continue;

		sprintf(key, "temperature_sensor_%d", c + 1);
		obj_add_int(r, key, temp);
	}

	obj_add_uint(r, "thm_temp1_trans_count", le32_to_cpu(smart->thm_temp1_trans_count));
	obj_add_uint(r, "thm_temp2_trans_count", le32_to_cpu(smart->thm_temp2_trans_count));
	obj_add_uint(r, "thm_temp1_total_time", le32_to_cpu(smart->thm_temp1_total_time));
	obj_add_uint(r, "thm_temp2_total_time", le32_to_cpu(smart->thm_temp2_total_time));

	json_print(r);
}

static void json_ana_log(struct nvme_ana_log *ana_log, const char *devname,
			 size_t len)
{
	int offset = sizeof(struct nvme_ana_log);
	struct nvme_ana_log *hdr = ana_log;
	struct nvme_ana_group_desc *ana_desc;
	struct json_object *desc_list = json_create_array();
	struct json_object *ns_list;
	struct json_object *desc;
	struct json_object *nsid;
	struct json_object *r = json_create_object();
	size_t nsid_buf_size;
	void *base = ana_log;
	__u32 nr_nsids;
	int i, j;

	obj_add_str(r, "Asymmetric Namespace Access Log for NVMe device", devname);
	obj_add_uint64(r, "chgcnt", le64_to_cpu(hdr->chgcnt));
	obj_add_uint(r, "ngrps", le16_to_cpu(hdr->ngrps));

	for (i = 0; i < le16_to_cpu(ana_log->ngrps); i++) {
		desc = json_create_object();
		ana_desc = base + offset;
		nr_nsids = le32_to_cpu(ana_desc->nnsids);
		nsid_buf_size = nr_nsids * sizeof(__le32);

		offset += sizeof(*ana_desc);
		obj_add_uint(desc, "grpid", le32_to_cpu(ana_desc->grpid));
		obj_add_uint(desc, "nnsids", le32_to_cpu(ana_desc->nnsids));
		obj_add_uint64(desc, "chgcnt", le64_to_cpu(ana_desc->chgcnt));
		obj_add_str(desc, "state", nvme_ana_state_to_string(ana_desc->state));

		ns_list = json_create_array();
		for (j = 0; j < le32_to_cpu(ana_desc->nnsids); j++) {
			nsid = json_create_object();
			obj_add_uint(nsid, "nsid", le32_to_cpu(ana_desc->nsids[j]));
			array_add_obj(ns_list, nsid);
		}
		obj_add_array(desc, "NSIDS", ns_list);
		offset += nsid_buf_size;
		array_add_obj(desc_list, desc);
	}

	obj_add_array(r, "ANA DESC LIST ", desc_list);

	json_print(r);
}

static void json_select_result(enum nvme_features_id fid, __u32 result)
{
	struct json_object *r = json_r ? json_r : json_create_object();
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

	obj_print(r);
}

static void json_self_test_log(struct nvme_self_test_log *self_test, __u8 dst_entries,
			       __u32 size, const char *devname)
{
	struct json_object *valid_attrs;
	struct json_object *r = json_create_object();
	struct json_object *valid = json_create_array();
	int i;
	__u32 num_entries = min(dst_entries, NVME_LOG_ST_MAX_RESULTS);

	obj_add_int(r, "Current Device Self-Test Operation", self_test->current_operation);
	obj_add_int(r, "Current Device Self-Test Completion", self_test->completion);

	for (i = 0; i < num_entries; i++) {
		valid_attrs = json_create_object();
		obj_add_int(valid_attrs, "Self test result", self_test->result[i].dsts & 0xf);

		if ((self_test->result[i].dsts & 0xf) == 0xf)
			goto add;

		obj_add_int(valid_attrs, "Self test code",
			self_test->result[i].dsts >> 4);
		obj_add_int(valid_attrs, "Segment number",
			self_test->result[i].seg);
		obj_add_int(valid_attrs, "Valid Diagnostic Information",
			self_test->result[i].vdi);
		obj_add_uint64(valid_attrs, "Power on hours",
			       le64_to_cpu(self_test->result[i].poh));

		if (self_test->result[i].vdi & NVME_ST_VALID_DIAG_INFO_NSID)
			obj_add_uint(valid_attrs, "Namespace Identifier",
				     le32_to_cpu(self_test->result[i].nsid));

		if (self_test->result[i].vdi & NVME_ST_VALID_DIAG_INFO_FLBA)
			obj_add_uint64(valid_attrs, "Failing LBA",
				       le64_to_cpu(self_test->result[i].flba));

		if (self_test->result[i].vdi & NVME_ST_VALID_DIAG_INFO_SCT)
			obj_add_int(valid_attrs, "Status Code Type", self_test->result[i].sct);

		if (self_test->result[i].vdi & NVME_ST_VALID_DIAG_INFO_SC)
			obj_add_int(valid_attrs, "Status Code", self_test->result[i].sc);

		obj_add_int(valid_attrs, "Vendor Specific",
			    self_test->result[i].vs[1] << 8 | self_test->result[i].vs[0]);

add:
		array_add_obj(valid, valid_attrs);
	}

	obj_add_array(r, "List of Valid Reports", valid);

	json_print(r);
}

static void json_registers_cap(struct nvme_bar_cap *cap, struct json_object *r)
{
	char json_str[STR_LEN];
	struct json_object *cssa = json_create_array();
	struct json_object *csso = json_create_object();
	struct json_object *amsa = json_create_array();
	struct json_object *amso = json_create_object();

	sprintf(json_str, "%"PRIx64"", *(uint64_t *)cap);
	obj_add_str(r, "cap", json_str);

	obj_add_str(r, "NVM Subsystem Shutdown Enhancements Supported (NSSES)",
			cap->nsses ? "Supported" : "Not supported");
	obj_add_str(r, "Controller Ready With Media Support (CRWMS)",
		     cap->crwms ? "Supported" : "Not supported");
	obj_add_str(r, "Controller Ready Independent of Media Support (CRIMS)",
		     cap->crims ? "Supported" : "Not supported");
	obj_add_str(r, "NVM Subsystem Shutdown Supported (NSSS)",
		     cap->nsss ? "Supported" : "Not supported");
	obj_add_str(r, "Controller Memory Buffer Supported (CMBS):",
		     cap->cmbs ? "Supported" : "Not supported");
	obj_add_str(r, "Persistent Memory Region Supported (PMRS)",
		     cap->pmrs ? "Supported" : "Not supported");

	sprintf(json_str, "%u bytes", 1 << (12 + cap->mpsmax));
	obj_add_str(r, "Memory Page Size Maximum (MPSMAX)", json_str);

	sprintf(json_str, "%u bytes", 1 << (12 + cap->mpsmin));
	obj_add_str(r, "Memory Page Size Minimum (MPSMIN)", json_str);

	obj_add_str(r, "Controller Power Scope (CPS)", !cap->cps ? "Not Reported" : cap->cps == 1 ?
		     "Controller scope" : cap->cps == 2 ? "Domain scope" : "NVM subsystem scope");
	obj_add_str(r, "Boot Partition Support (BPS)", cap->bps ? "Yes" : "No");

	obj_add_array(r, "Command Sets Supported (CSS)", cssa);
	obj_add_str(csso, "NVM command set", cap->css & 1 ? "Supported" : "Not supported");
	obj_add_str(csso, "One or more I/O Command Sets",
		    cap->css & 0x40 ? "Supported" : "Not supported");
	obj_add_str(csso, cap->css & 0x80 ? "Only Admin Command Set" : "I/O Command Set",
		    "Supported");
	array_add_obj(cssa, csso);

	obj_add_str(r, "NVM Subsystem Reset Supported (NSSRS)", cap->nssrs ? "Yes" : "No");

	sprintf(json_str, "%u bytes", 1 << (2 + cap->dstrd));
	obj_add_str(r, "Doorbell Stride (DSTRD)", json_str);

	sprintf(json_str, "%u ms", MS500_TO_MS(cap->to));
	obj_add_str(r, "Timeout (TO)", json_str);

	obj_add_array(r, "Arbitration Mechanism Supported (AMS)", amsa);
	obj_add_str(amso, "Weighted Round Robin with Urgent Priority Class",
		    cap->ams & 2 ? "Supported" : "Not supported");
	array_add_obj(amsa, amso);

	obj_add_str(r, "Contiguous Queues Required (CQR)", cap->cqr ? "Yes" : "No");
	obj_add_uint(r, "Maximum Queue Entries Supported (MQES)", cap->mqes + 1);
}

static void json_registers_version(__u32 vs, struct json_object *r)
{
	char json_str[STR_LEN];

	sprintf(json_str, "%x", vs);
	obj_add_str(r, "Version", json_str);

	sprintf(json_str, "%d.%d.%d", NVME_MAJOR(vs), NVME_MINOR(vs), NVME_TERTIARY(vs));
	obj_add_str(r, "NVMe specification", json_str);
}

static void json_registers_intms(__u32 intms, struct json_object *r)
{
	obj_add_uint_x(r, "intms", intms);

	obj_add_uint_x(r, "Interrupt Vector Mask Set (IVMS)", intms);
}

static void json_registers_intmc(__u32 intmc, struct json_object *r)
{
	obj_add_uint_x(r, "intmc", intmc);

	obj_add_uint_x(r, "Interrupt Vector Mask Set (IVMC)", intmc);
}

static void json_registers_cc_ams(__u8 ams, struct json_object *r)
{
	char json_str[STR_LEN];

	switch (ams) {
	case NVME_CC_AMS_RR:
		sprintf(json_str, "Round Robin");
		break;
	case NVME_CC_AMS_WRRU:
		sprintf(json_str, "Weighted Round Robin with Urgent Priority Class");
		break;
	case NVME_CC_AMS_VS:
		sprintf(json_str, "Vendor Specific");
		break;
	default:
		sprintf(json_str, "%s", "Reserved");
		break;
	}

	obj_add_str(r, "Arbitration Mechanism Selected (AMS)", json_str);
}

static void json_registers_cc_shn(__u8 shn, struct json_object *r)
{
	char json_str[STR_LEN];

	switch (shn) {
	case NVME_CC_SHN_NONE:
		sprintf(json_str, "No notification; no effect");
		break;
	case NVME_CC_SHN_NORMAL:
		sprintf(json_str, "Normal shutdown notification");
		break;
	case NVME_CC_SHN_ABRUPT:
		sprintf(json_str, "Abrupt shutdown notification");
		break;
	default:
		sprintf(json_str, "%s", "Reserved");
		break;
	}

	obj_add_str(r, "Shutdown Notification (SHN)", json_str);
}

static void json_registers_cc(__u32 cc, struct json_object *r)
{
	char json_str[STR_LEN];

	sprintf(json_str, "%x", cc);
	obj_add_str(r, "cc", json_str);

	obj_add_str(r, "Controller Ready Independent of Media Enable (CRIME)",
		     NVME_CC_CRIME(cc) ? "Enabled" : "Disabled");

	sprintf(json_str, "%u bytes", POWER_OF_TWO(NVME_CC_IOCQES(cc)));
	obj_add_str(r, "I/O Completion Queue Entry Size (IOCQES): ", json_str);

	sprintf(json_str, "%u bytes", POWER_OF_TWO(NVME_CC_IOSQES(cc)));
	obj_add_str(r, "I/O Submission Queue Entry Size (IOSQES)", json_str);

	json_registers_cc_shn(NVME_CC_SHN(cc), r);
	json_registers_cc_ams(NVME_CC_AMS(cc), r);

	sprintf(json_str, "%u bytes", POWER_OF_TWO(12 + NVME_CC_MPS(cc)));
	obj_add_str(r, "Memory Page Size (MPS)", json_str);

	obj_add_str(r, "I/O Command Set Selected (CSS)",
		    NVME_CC_CSS(cc) == NVME_CC_CSS_NVM ? "NVM Command Set" :
		    NVME_CC_CSS(cc) == NVME_CC_CSS_CSI ? "All supported I/O Command Sets" :
		    NVME_CC_CSS(cc) == NVME_CC_CSS_ADMIN ? "Admin Command Set only" : "Reserved");
	obj_add_str(r, "Enable (EN)", NVME_CC_EN(cc) ? "Yes" : "No");
}

static void json_registers_csts_shst(__u8 shst, struct json_object *r)
{
	char json_str[STR_LEN];

	switch (shst) {
	case NVME_CSTS_SHST_NORMAL:
		sprintf(json_str, "Normal operation (no shutdown has been requested)");
		break;
	case NVME_CSTS_SHST_OCCUR:
		sprintf(json_str, "Shutdown processing occurring");
		break;
	case NVME_CSTS_SHST_CMPLT:
		sprintf(json_str, "Shutdown processing complete");
		break;
	default:
		sprintf(json_str, "%s", "Reserved");
		break;
	}

	obj_add_str(r, "Shutdown Status (SHST)", json_str);
}

static void json_registers_csts(__u32 csts, struct json_object *r)
{
	obj_add_uint_x(r, "csts", csts);

	obj_add_str(r, "Shutdown Type (ST)", NVME_CSTS_ST(csts) ? "Subsystem" : "Controller");
	obj_add_str(r, "Processing Paused (PP)", NVME_CSTS_PP(csts) ? "Yes" : "No");
	obj_add_str(r, "NVM Subsystem Reset Occurred (NSSRO)",
		    NVME_CSTS_NSSRO(csts) ? "Yes" : "No");

	json_registers_csts_shst(NVME_CSTS_SHST(csts), r);

	obj_add_str(r, "Controller Fatal Status (CFS)", NVME_CSTS_CFS(csts) ? "True" : "False");
	obj_add_str(r, "Ready (RDY)", NVME_CSTS_RDY(csts) ? "Yes" : "No");
}

static void json_registers_nssr(__u32 nssr, struct json_object *r)
{
	obj_add_uint_x(r, "nssr", nssr);
	obj_add_uint(r, "NVM Subsystem Reset Control (NSSRC)", nssr);
}

static void json_registers_nssd(__u32 nssd, struct json_object *r)
{
	obj_add_uint_nx(r, "NVM Subsystem Shutdown Control (NSSC)", nssd);
}

static void json_registers_crto(__u32 crto, struct json_object *r)
{
	obj_add_uint_x(r, "crto", crto);

	obj_add_int_secs(r, "CRIMT", MS500_TO_SEC(NVME_CRTO_CRIMT(crto)));
	obj_add_int_secs(r, "CRWMT", MS500_TO_SEC(NVME_CRTO_CRWMT(crto)));
}

static void json_registers_aqa(uint32_t aqa, struct json_object *r)
{
	obj_add_uint_x(r, "aqa", aqa);
	obj_add_uint(r, "Admin Completion Queue Size (ACQS)", NVME_AQA_ACQS(aqa) + 1);
	obj_add_uint(r, "Admin Submission Queue Size (ASQS)", NVME_AQA_ASQS(aqa) + 1);
}

static void json_registers_asq(uint64_t asq, struct json_object *r)
{
	obj_add_prix64(r, "asq", asq);
	obj_add_prix64(r, "Admin Submission Queue Base (ASQB)", asq);
}

static void json_registers_acq(uint64_t acq, struct json_object *r)
{
	obj_add_prix64(r, "acq", acq);
	obj_add_prix64(r, "Admin Completion Queue Base (ACQB)", acq);
}

static void json_registers_cmbloc(uint32_t cmbloc, bool support, struct json_object *r)
{
	obj_add_uint_x(r, "cmbloc", cmbloc);

	if (!support) {
		obj_add_result(r, "Controller Memory Buffer feature is not supported");
		return;
	}

	obj_add_uint_0x(r, "Offset (OFST) (See cmbsz.szu for granularity)",
			 (cmbloc & 0xfffff000) >> 12);
	obj_add_int(r, "CMB Queue Dword Alignment (CQDA)", (cmbloc & 0x100) >> 8);
	obj_add_str(r, "CMB Data Metadata Mixed Memory Support (CDMMMS)",
		     (cmbloc & 0x00000080) >> 7 ? "Not enforced" : "Enforced");
	obj_add_str(r, "CMB Data Pointer and Command Independent Locations Support (CDPCILS)",
		     (cmbloc & 0x00000040) >> 6 ? "Not enforced" : "Enforced");
	obj_add_str(r, "CMB Data Pointer Mixed Locations Support (CDPMLS)",
		     (cmbloc & 0x00000020) >> 5 ? "Not enforced" : "Enforced");
	obj_add_str(r, "CMB Queue Physically Discontiguous Support (CQPDS)",
		     (cmbloc & 0x00000010) >> 4 ? "Not enforced" : "Enforced");
	obj_add_str(r, "CMB Queue Mixed Memory Support (CQMMS)",
		     (cmbloc & 0x00000008) >> 3 ? "Not enforced" : "Enforced");
	obj_add_uint_0x(r, "Base Indicator Register (BIR)", (cmbloc & 0x00000007));
}

static void json_registers_cmbsz(uint32_t cmbsz, struct json_object *r)
{
	obj_add_uint_x(r, "cmbsz", cmbsz);

	if (!cmbsz) {
		obj_add_result(r, "Controller Memory Buffer feature is not supported");
		return;
	}

	obj_add_uint(r, "Size (SZ)", (cmbsz & 0xfffff000) >> 12);
	obj_add_str(r, "Size Units (SZU)", nvme_register_szu_to_string((cmbsz & 0xf00) >> 8));
	obj_add_str(r, "Write Data Support (WDS)", cmbsz & 0x10 ? "Supported" : "Not supported");
	obj_add_str(r, "Read Data Support (RDS)", cmbsz & 8 ? "Supported" : "Not supported");
	obj_add_str(r, "PRP SGL List Support (LISTS)", cmbsz & 4 ? "Supported" : "Not supported");
	obj_add_str(r, "Completion Queue Support (CQS)", cmbsz & 2 ? "Supported" : "Not supported");
	obj_add_str(r, "Submission Queue Support (SQS)", cmbsz & 1 ? "Supported" : "Not supported");
}

static void json_registers_bpinfo_brs(__u8 brs, struct json_object *r)
{
	char json_str[STR_LEN];

	switch (brs) {
	case 0:
		sprintf(json_str, "No Boot Partition read operation requested");
		break;
	case 1:
		sprintf(json_str, "Boot Partition read in progress");
		break;
	case 2:
		sprintf(json_str, "Boot Partition read completed successfully");
		break;
	case 3:
		sprintf(json_str, "Error completing Boot Partition read");
		break;
	default:
		sprintf(json_str, "%s", "Invalid");
		break;
	}

	obj_add_str(r, "Boot Read Status (BRS)", json_str);
}

static void json_registers_bpinfo(uint32_t bpinfo, struct json_object *r)
{
	obj_add_uint_x(r, "bpinfo", bpinfo);

	obj_add_uint(r, "Active Boot Partition ID (ABPID)", NVME_BPINFO_ABPID(bpinfo));
	json_registers_bpinfo_brs(NVME_BPINFO_BRS(bpinfo), r);
	obj_add_uint(r, "Boot Partition Size (BPSZ)", NVME_BPINFO_BPSZ(bpinfo));
}

static void json_registers_bprsel(uint32_t bprsel, struct json_object *r)
{
	obj_add_uint_x(r, "bprsel", bprsel);

	obj_add_uint(r, "Boot Partition Identifier (BPID)", NVME_BPRSEL_BPID(bprsel));
	obj_add_uint_x(r, "Boot Partition Read Offset (BPROF)", NVME_BPRSEL_BPROF(bprsel));
	obj_add_uint_x(r, "Boot Partition Read Size (BPRSZ)", NVME_BPRSEL_BPRSZ(bprsel));
}

static void json_registers_bpmbl(uint64_t bpmbl, struct json_object *r)
{
	obj_add_prix64(r, "bpmbl", bpmbl);

	obj_add_prix64(r, "Boot Partition Memory Buffer Base Address (BMBBA)",
		       (uint64_t)NVME_BPMBL_BMBBA(bpmbl));
}

static void json_registers_cmbmsc(uint64_t cmbmsc, struct json_object *r)
{
	obj_add_prix64(r, "cmbmsc", cmbmsc);

	obj_add_prix64(r, "Controller Base Address (CBA)", (uint64_t)NVME_CMBMSC_CBA(cmbmsc));
	obj_add_prix64(r, "Controller Memory Space Enable (CMSE)", NVME_CMBMSC_CMSE(cmbmsc));
	obj_add_str(r, "Capabilities Registers Enabled (CRE)",
		    NVME_CMBMSC_CRE(cmbmsc) ? "Enabled" : "Not enabled");
}

static void json_registers_cmbsts(uint32_t cmbsts, struct json_object *r)
{
	obj_add_uint_x(r, "cmbsts", cmbsts);

	obj_add_uint_x(r, "Controller Base Address Invalid (CBAI)", NVME_CMBSTS_CBAI(cmbsts));
}

static void json_registers_cmbebs(uint32_t cmbebs, struct json_object *r)
{
	char buffer[BUF_LEN];

	obj_add_uint_nx(r, "cmbebs", cmbebs);

	obj_add_uint_nx(r, "CMB Elasticity Buffer Size Base (CMBWBZ)", NVME_CMBEBS_CMBWBZ(cmbebs));
	sprintf(buffer, "%s", NVME_CMBEBS_RBB(cmbebs) ? "shall" : "may");
	obj_add_str(r, "CMB Read Bypass Behavior (CMBRBB)", buffer);
	obj_add_str(r, "CMB Elasticity Buffer Size Units (CMBSZU)",
		    nvme_register_unit_to_string(NVME_CMBEBS_CMBSZU(cmbebs)));
}

static void json_registers_cmbswtp(uint32_t cmbswtp, struct json_object *r)
{
	char str[STR_LEN];

	obj_add_uint_nx(r, "cmbswtp", cmbswtp);

	obj_add_uint_nx(r, "CMB Sustained Write Throughput (CMBSWTV)",
			NVME_CMBSWTP_CMBSWTV(cmbswtp));
	sprintf(str, "%s/second", nvme_register_unit_to_string(NVME_CMBSWTP_CMBSWTU(cmbswtp)));
	obj_add_str(r, "CMB Sustained Write Throughput Units (CMBSWTU)", str);
}

static void json_registers_pmrcap(uint32_t pmrcap, struct json_object *r)
{
	obj_add_uint_x(r, "pmrcap", pmrcap);

	obj_add_str(r, "Controller Memory Space Supported (CMSS)",
		    NVME_PMRCAP_CMSS(pmrcap) ? "Supported" : "Not supported");
	obj_add_uint_x(r, "Persistent Memory Region Timeout (PMRTO)", NVME_PMRCAP_PMRTO(pmrcap));
	obj_add_uint_x(r, "Persistent Memory Region Write Barrier Mechanisms (PMRWBM)",
		       NVME_PMRCAP_PMRWBM(pmrcap));
	obj_add_str(r, "Persistent Memory Region Time Units (PMRTU)",
		    NVME_PMRCAP_PMRTU(pmrcap) ? "minutes" : "500 milliseconds");
	obj_add_uint_x(r, "Base Indicator Register (BIR)", NVME_PMRCAP_BIR(pmrcap));
	obj_add_str(r, "Write Data Support (WDS)",
		    NVME_PMRCAP_WDS(pmrcap) ? "Supported" : "Not supported");
	obj_add_str(r, "Read Data Support (RDS)",
		    NVME_PMRCAP_RDS(pmrcap) ? "Supported" : "Not supported");
}

static void json_registers_pmrctl(uint32_t pmrctl, struct json_object *r)
{
	obj_add_uint_x(r, "pmrctl", pmrctl);

	obj_add_str(r, "Enable (EN)", NVME_PMRCTL_EN(pmrctl) ? "Ready" : "Disabled");
}

static void json_registers_pmrsts(uint32_t pmrsts, bool ready, struct json_object *r)
{
	obj_add_uint_x(r, "pmrsts", pmrsts);

	obj_add_uint_x(r, "Controller Base Address Invalid (CBAI)", NVME_PMRSTS_CBAI(pmrsts));
	obj_add_str(r, "Health Status (HSTS)",
		    nvme_register_pmr_hsts_to_string(NVME_PMRSTS_HSTS(pmrsts)));
	obj_add_str(r, "Not Ready (NRDY)",
		    !NVME_PMRSTS_NRDY(pmrsts) && ready ? "Ready" : "Not ready");
	obj_add_uint_x(r, "Error (ERR)", NVME_PMRSTS_ERR(pmrsts));
}

static void json_registers_pmrebs(uint32_t pmrebs, struct json_object *r)
{
	obj_add_uint_x(r, "pmrebs", pmrebs);

	obj_add_uint_x(r, "PMR Elasticity Buffer Size Base (PMRWBZ)", NVME_PMREBS_PMRWBZ(pmrebs));
	obj_add_str(r, "Read Bypass Behavior", NVME_PMREBS_RBB(pmrebs) ? "Shall" : "May");
	obj_add_str(r, "PMR Elasticity Buffer Size Units (PMRSZU)",
		    nvme_register_unit_to_string(NVME_PMREBS_PMRSZU(pmrebs)));
}

static void json_registers_pmrswtp(uint32_t pmrswtp, struct json_object *r)
{
	obj_add_uint_x(r, "pmrswtp", pmrswtp);

	obj_add_uint_x(r, "PMR Sustained Write Throughput (PMRSWTV)",
		       NVME_PMRSWTP_PMRSWTV(pmrswtp));
	obj_add_key(r, "PMR Sustained Write Throughput Units (PMRSWTU)", "%s/second",
		    nvme_register_unit_to_string(NVME_PMRSWTP_PMRSWTU(pmrswtp)));
}

static void json_registers_pmrmscl(uint32_t pmrmscl, struct json_object *r)
{
	obj_add_uint_nx(r, "pmrmscl", pmrmscl);

	obj_add_uint_nx(r, "Controller Base Address (CBA)", (uint32_t)NVME_PMRMSC_CBA(pmrmscl));
	obj_add_uint_nx(r, "Controller Memory Space Enable (CMSE)", NVME_PMRMSC_CMSE(pmrmscl));
}

static void json_registers_pmrmscu(uint32_t pmrmscu, struct json_object *r)
{
	obj_add_uint_nx(r, "pmrmscu", pmrmscu);

	obj_add_uint_nx(r, "Controller Base Address (CBA)", pmrmscu);
}

static void json_registers_unknown(int offset, uint64_t value64, struct json_object *r)
{
	obj_add_uint_02x(r, "unknown property", offset);
	obj_add_str(r, "name", nvme_register_to_string(offset));
	obj_add_prix64(r, "value", value64);
}

static void json_single_property_human(int offset, uint64_t value64, struct json_object *r)
{
	uint32_t value32 = (uint32_t)value64;

	switch (offset) {
	case NVME_REG_CAP:
		json_registers_cap((struct nvme_bar_cap *)&value64, r);
		break;
	case NVME_REG_VS:
		json_registers_version(value32, r);
		break;
	case NVME_REG_CC:
		json_registers_cc(value32, r);
		break;
	case NVME_REG_CSTS:
		json_registers_csts(value32, r);
		break;
	case NVME_REG_NSSR:
		json_registers_nssr(value32, r);
		break;
	case NVME_REG_NSSD:
		json_registers_nssd(value32, r);
		break;
	case NVME_REG_CRTO:
		json_registers_crto(value32, r);
		break;
	default:
		json_registers_unknown(offset, value64, r);
		break;
	}
}

static void json_single_property(int offset, uint64_t value64)
{
	struct json_object *r = json_create_object();
	char json_str[STR_LEN];
	uint32_t value32 = (uint32_t)value64;

	if (verbose_mode()) {
		json_single_property_human(offset, value64, r);
	} else {
		sprintf(json_str, "0x%02x", offset);
		obj_add_str(r, "property", json_str);

		obj_add_str(r, "name", nvme_register_to_string(offset));

		if (nvme_is_64bit_reg(offset))
			sprintf(json_str, "%"PRIx64"", value64);
		else
			sprintf(json_str, "%x", value32);

		obj_add_str(r, "value", json_str);
	}

	json_print(r);
}

struct json_object *json_effects_log(enum nvme_csi csi,
				     struct nvme_cmd_effects_log *effects_log)
{
	struct json_object *r = json_create_object();
	struct json_object *acs = json_create_object();
	struct json_object *iocs = json_create_object();
	unsigned int opcode;
	char key[128];
	__u32 effect;

	obj_add_uint(r, "command_set_identifier", csi);

	for (opcode = 0; opcode < 256; opcode++) {
		effect = le32_to_cpu(effects_log->acs[opcode]);
		if (effect & NVME_CMD_EFFECTS_CSUPP) {
			sprintf(key, "ACS_%u (%s)", opcode,
				nvme_cmd_to_string(1, opcode));
			obj_add_uint(acs, key, effect);
		}
	}

	obj_add_obj(r, "admin_cmd_set", acs);

	for (opcode = 0; opcode < 256; opcode++) {
		effect = le32_to_cpu(effects_log->iocs[opcode]);
		if (effect & NVME_CMD_EFFECTS_CSUPP) {
			sprintf(key, "IOCS_%u (%s)", opcode,
				nvme_cmd_to_string(0, opcode));
			obj_add_uint(iocs, key, effect);
		}
	}

	obj_add_obj(r, "io_cmd_set", iocs);
	return r;
}

static void json_effects_log_list(struct list_head *list)
{
	struct json_object *r = json_create_array();
	nvme_effects_log_node_t *node = NULL;

	list_for_each(list, node, node) {
		struct json_object *json_page =
			json_effects_log(node->csi, &node->effects);
		array_add_obj(r, json_page);
	}

	json_print(r);
}

static void json_sanitize_log(struct nvme_sanitize_log_page *sanitize_log,
			      const char *devname)
{
	struct json_object *r = json_create_object();
	struct json_object *dev = json_create_object();
	struct json_object *sstat = json_create_object();
	struct json_object *ssi = json_create_object();
	const char *status_str;
	__u16 status, sos;
	__u8 fails, sans;
	char str[128];

	status = le16_to_cpu(sanitize_log->sstat);

	obj_add_int(dev, "sprog", le16_to_cpu(sanitize_log->sprog));
	obj_add_int(sstat, "media_verification_canceled", NVME_GET(status, SANITIZE_SSTAT_MVCNCLD));
	obj_add_int(sstat, "global_erased", NVME_GET(status, SANITIZE_SSTAT_GLOBAL_DATA_ERASED));
	obj_add_int(sstat, "no_cmplted_passes", NVME_GET(status, SANITIZE_SSTAT_COMPLETED_PASSES));

	sos = NVME_GET(status, SANITIZE_SSTAT_STATUS);
	status_str = nvme_sstat_status_to_string(status);
	sprintf(str, "(%d) %s", sos, status_str);
	obj_add_str(sstat, "status", str);

	obj_add_obj(dev, "sstat", sstat);
	obj_add_uint(dev, "cdw10_info", le32_to_cpu(sanitize_log->scdw10));
	obj_add_uint(dev, "time_over_write", le32_to_cpu(sanitize_log->eto));
	obj_add_uint(dev, "time_block_erase", le32_to_cpu(sanitize_log->etbe));
	obj_add_uint(dev, "time_crypto_erase", le32_to_cpu(sanitize_log->etce));
	obj_add_uint(dev, "time_over_write_no_dealloc", le32_to_cpu(sanitize_log->etond));
	obj_add_uint(dev, "time_block_erase_no_dealloc", le32_to_cpu(sanitize_log->etbend));
	obj_add_uint(dev, "time_crypto_erase_no_dealloc", le32_to_cpu(sanitize_log->etcend));
	obj_add_uint(dev, "time_post_verification_dealloc", le32_to_cpu(sanitize_log->etpvds));

	sans = NVME_GET(sanitize_log->ssi, SANITIZE_SSI_SANS);
	status_str = nvme_ssi_state_to_string(sans);
	sprintf(str, "(%d) %s", sans, status_str);
	obj_add_str(ssi, "sanitize_state", str);

	if (sos == NVME_SANITIZE_SSTAT_STATUS_COMPLETED_FAILED) {
		fails = NVME_GET(sanitize_log->ssi, SANITIZE_SSI_FAILS);
		status_str = nvme_ssi_state_to_string(fails);
		sprintf(str, "(%d) %s", fails, status_str);
		obj_add_str(ssi, "failure_state", str);
	}

	obj_add_obj(dev, "sanitize_state_information", ssi);
	obj_add_obj(r, devname, dev);

	json_print(r);
}

static void json_predictable_latency_per_nvmset(
		struct nvme_nvmset_predictable_lat_log *plpns_log,
		__u16 nvmset_id, const char *devname)
{
	struct json_object *r = json_create_object();

	obj_add_uint(r, "nvmset_id", le16_to_cpu(nvmset_id));
	obj_add_uint(r, "status", plpns_log->status);
	obj_add_uint(r, "event_type", le16_to_cpu(plpns_log->event_type));
	obj_add_uint64(r, "dtwin_reads_typical", le64_to_cpu(plpns_log->dtwin_rt));
	obj_add_uint64(r, "dtwin_writes_typical", le64_to_cpu(plpns_log->dtwin_wt));
	obj_add_uint64(r, "dtwin_time_maximum", le64_to_cpu(plpns_log->dtwin_tmax));
	obj_add_uint64(r, "ndwin_time_minimum_high", le64_to_cpu(plpns_log->ndwin_tmin_hi));
	obj_add_uint64(r, "ndwin_time_minimum_low", le64_to_cpu(plpns_log->ndwin_tmin_lo));
	obj_add_uint64(r, "dtwin_reads_estimate", le64_to_cpu(plpns_log->dtwin_re));
	obj_add_uint64(r, "dtwin_writes_estimate", le64_to_cpu(plpns_log->dtwin_we));
	obj_add_uint64(r, "dtwin_time_estimate", le64_to_cpu(plpns_log->dtwin_te));

	json_print(r);
}

static void json_predictable_latency_event_agg_log(
		struct nvme_aggregate_predictable_lat_event *pea_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	struct json_object *r = json_create_object();
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();
	__u64 num_entries = le64_to_cpu(pea_log->num_entries);
	__u64 num_iter = min(num_entries, log_entries);

	obj_add_uint64(r, "num_entries_avail", num_entries);

	for (int i = 0; i < num_iter; i++) {
		valid_attrs = json_create_object();
		obj_add_uint(valid_attrs, "entry", le16_to_cpu(pea_log->entries[i]));
		array_add_obj(valid, valid_attrs);
	}

	obj_add_array(r, "list_of_entries", valid);

	json_print(r);
}

static void json_add_bitmap(int i, __u8 seb, struct json_object *r)
{
	char evt_str[50];
	char key[128];

	for (int bit = 0; bit < CHAR_BIT; bit++) {
		if (nvme_pel_event_to_string(bit + i * CHAR_BIT)) {
			sprintf(key, "bitmap_%x", (bit + i * CHAR_BIT));
			if ((seb >> bit) & 0x1)
				snprintf(evt_str, sizeof(evt_str), "Support %s",
					 nvme_pel_event_to_string(bit + i * CHAR_BIT));
			obj_add_str(r, key, evt_str);
		}
	}
}

static void json_pevent_log_head(struct nvme_persistent_event_log *pevent_log_head,
				 struct json_object *r)
{
	int i;
	char sn[sizeof(pevent_log_head->sn) + 1];
	char mn[sizeof(pevent_log_head->mn) + 1];
	char subnqn[sizeof(pevent_log_head->subnqn) + 1];

	snprintf(sn, sizeof(sn), "%-.*s", (int)sizeof(pevent_log_head->sn), pevent_log_head->sn);
	snprintf(mn, sizeof(mn), "%-.*s", (int)sizeof(pevent_log_head->mn), pevent_log_head->mn);
	snprintf(subnqn, sizeof(subnqn), "%-.*s", (int)sizeof(pevent_log_head->subnqn),
		 pevent_log_head->subnqn);

	obj_add_uint(r, "log_id", pevent_log_head->lid);
	obj_add_uint(r, "total_num_of_events", le32_to_cpu(pevent_log_head->tnev));
	obj_add_uint64(r, "total_log_len", le64_to_cpu(pevent_log_head->tll));
	obj_add_uint(r, "log_revision", pevent_log_head->rv);
	obj_add_uint(r, "log_header_len", le16_to_cpu(pevent_log_head->lhl));
	obj_add_uint64(r, "timestamp", le64_to_cpu(pevent_log_head->ts));
	obj_add_uint128(r, "power_on_hours", le128_to_cpu(pevent_log_head->poh));
	obj_add_uint64(r, "power_cycle_count", le64_to_cpu(pevent_log_head->pcc));
	obj_add_uint(r, "pci_vid", le16_to_cpu(pevent_log_head->vid));
	obj_add_uint(r, "pci_ssvid", le16_to_cpu(pevent_log_head->ssvid));
	obj_add_str(r, "sn", sn);
	obj_add_str(r, "mn", mn);
	obj_add_str(r, "subnqn", subnqn);
	obj_add_uint(r, "gen_number", le16_to_cpu(pevent_log_head->gen_number));
	obj_add_uint(r, "rci", le32_to_cpu(pevent_log_head->rci));

	for (i = 0; i < ARRAY_SIZE(pevent_log_head->seb); i++) {
		if (!pevent_log_head->seb[i])
			continue;
		json_add_bitmap(i, pevent_log_head->seb[i], r);
	}
}

static void json_pel_smart_health(void *pevent_log_info, __u32 offset,
				  struct json_object *valid_attrs)
{
	char key[128];
	struct nvme_smart_log *smart_event = pevent_log_info + offset;
	unsigned int temperature = (smart_event->temperature[1] << 8) | smart_event->temperature[0];
	nvme_uint128_t data_units_read = le128_to_cpu(smart_event->data_units_read);
	nvme_uint128_t data_units_written = le128_to_cpu(smart_event->data_units_written);
	nvme_uint128_t host_read_commands = le128_to_cpu(smart_event->host_reads);
	nvme_uint128_t host_write_commands = le128_to_cpu(smart_event->host_writes);
	nvme_uint128_t controller_busy_time = le128_to_cpu(smart_event->ctrl_busy_time);
	nvme_uint128_t power_cycles = le128_to_cpu(smart_event->power_cycles);
	nvme_uint128_t power_on_hours = le128_to_cpu(smart_event->power_on_hours);
	nvme_uint128_t unsafe_shutdowns = le128_to_cpu(smart_event->unsafe_shutdowns);
	nvme_uint128_t media_errors = le128_to_cpu(smart_event->media_errors);
	nvme_uint128_t num_err_log_entries = le128_to_cpu(smart_event->num_err_log_entries);
	int c;
	__s32 temp;

	obj_add_int(valid_attrs, "critical_warning", smart_event->critical_warning);
	obj_add_int(valid_attrs, "temperature", temperature);
	obj_add_int(valid_attrs, "avail_spare", smart_event->avail_spare);
	obj_add_int(valid_attrs, "spare_thresh", smart_event->spare_thresh);
	obj_add_int(valid_attrs, "percent_used", smart_event->percent_used);
	obj_add_int(valid_attrs, "endurance_grp_critical_warning_summary",
		    smart_event->endu_grp_crit_warn_sumry);
	obj_add_uint128(valid_attrs, "data_units_read", data_units_read);
	obj_add_uint128(valid_attrs, "data_units_written", data_units_written);
	obj_add_uint128(valid_attrs, "host_read_commands", host_read_commands);
	obj_add_uint128(valid_attrs, "host_write_commands", host_write_commands);
	obj_add_uint128(valid_attrs, "controller_busy_time", controller_busy_time);
	obj_add_uint128(valid_attrs, "power_cycles", power_cycles);
	obj_add_uint128(valid_attrs, "power_on_hours", power_on_hours);
	obj_add_uint128(valid_attrs, "unsafe_shutdowns", unsafe_shutdowns);
	obj_add_uint128(valid_attrs, "media_errors", media_errors);
	obj_add_uint128(valid_attrs, "num_err_log_entries", num_err_log_entries);
	obj_add_uint(valid_attrs, "warning_temp_time", le32_to_cpu(smart_event->warning_temp_time));
	obj_add_uint(valid_attrs, "critical_comp_time",
		     le32_to_cpu(smart_event->critical_comp_time));

	for (c = 0; c < 8; c++) {
		temp = le16_to_cpu(smart_event->temp_sensor[c]);
		if (!temp)
			continue;
		sprintf(key, "temperature_sensor_%d", c + 1);
		obj_add_int(valid_attrs, key, temp);
	}

	obj_add_uint(valid_attrs, "thm_temp1_trans_count",
		     le32_to_cpu(smart_event->thm_temp1_trans_count));
	obj_add_uint(valid_attrs, "thm_temp2_trans_count",
		     le32_to_cpu(smart_event->thm_temp2_trans_count));
	obj_add_uint(valid_attrs, "thm_temp1_total_time",
		     le32_to_cpu(smart_event->thm_temp1_total_time));
	obj_add_uint(valid_attrs, "thm_temp2_total_time",
		     le32_to_cpu(smart_event->thm_temp2_total_time));
}

static void json_pel_fw_commit(void *pevent_log_info, __u32 offset, struct json_object *valid_attrs)
{
	char fw_str[50];
	struct nvme_fw_commit_event *fw_commit_event = pevent_log_info + offset;

	snprintf(fw_str, sizeof(fw_str), "%"PRIu64" (%s)", le64_to_cpu(fw_commit_event->old_fw_rev),
		 util_fw_to_string((char *)&fw_commit_event->old_fw_rev));
	obj_add_str(valid_attrs, "old_fw_rev", fw_str);
	snprintf(fw_str, sizeof(fw_str), "%"PRIu64" (%s)", le64_to_cpu(fw_commit_event->new_fw_rev),
		 util_fw_to_string((char *)&fw_commit_event->new_fw_rev));
	obj_add_str(valid_attrs, "new_fw_rev", fw_str);
	obj_add_uint(valid_attrs, "fw_commit_action", fw_commit_event->fw_commit_action);
	obj_add_uint(valid_attrs, "fw_slot", fw_commit_event->fw_slot);
	obj_add_uint(valid_attrs, "sct_fw", fw_commit_event->sct_fw);
	obj_add_uint(valid_attrs, "sc_fw", fw_commit_event->sc_fw);
	obj_add_uint(valid_attrs, "vu_assign_fw_commit_rc",
		     le16_to_cpu(fw_commit_event->vndr_assign_fw_commit_rc));
}

static void json_pel_timestamp(void *pevent_log_info, __u32 offset, struct json_object *valid_attrs)
{
	struct nvme_time_stamp_change_event *ts_change_event = pevent_log_info + offset;

	obj_add_uint64(valid_attrs, "prev_ts", le64_to_cpu(ts_change_event->previous_timestamp));
	obj_add_uint64(valid_attrs, "ml_secs_since_reset",
		       le64_to_cpu(ts_change_event->ml_secs_since_reset));
}

static void json_pel_power_on_reset(void *pevent_log_info, __u32 offset,
				    struct json_object *valid_attrs, __le16 vsil, __le16 el)
{
	__u64 *fw_rev;
	char fw_str[50];
	struct nvme_power_on_reset_info_list *por_event;
	__u32 por_info_len = le16_to_cpu(el) - le16_to_cpu(vsil) - sizeof(*fw_rev);
	__u32 por_info_list = por_info_len / sizeof(*por_event);
	int i;

	fw_rev = pevent_log_info + offset;
	snprintf(fw_str, sizeof(fw_str), "%"PRIu64" (%s)", le64_to_cpu(*fw_rev),
		 util_fw_to_string((char *)fw_rev));
	obj_add_str(valid_attrs, "fw_rev", fw_str);

	for (i = 0; i < por_info_list; i++) {
		por_event = pevent_log_info + offset + sizeof(*fw_rev) + i * sizeof(*por_event);
		obj_add_uint(valid_attrs, "ctrl_id", le16_to_cpu(por_event->cid));
		obj_add_uint(valid_attrs, "fw_act", por_event->fw_act);
		obj_add_uint(valid_attrs, "op_in_prog", por_event->op_in_prog);
		obj_add_uint(valid_attrs, "ctrl_power_cycle",
			     le32_to_cpu(por_event->ctrl_power_cycle));
		obj_add_uint64(valid_attrs, "power_on_ml_secs",
			       le64_to_cpu(por_event->power_on_ml_seconds));
		obj_add_uint64(valid_attrs, "ctrl_time_stamp",
			       le64_to_cpu(por_event->ctrl_time_stamp));
	}
}

static void json_pel_nss_hw_error(void *pevent_log_info, __u32 offset,
				  struct json_object *valid_attrs)
{
	struct nvme_nss_hw_err_event *nss_hw_err_event = pevent_log_info + offset;

	obj_add_uint(valid_attrs, "nss_hw_err_code",
		     le16_to_cpu(nss_hw_err_event->nss_hw_err_event_code));
}

static void json_pel_change_ns(void *pevent_log_info, __u32 offset, struct json_object *valid_attrs)
{
	struct nvme_change_ns_event *ns_event = pevent_log_info + offset;

	obj_add_uint(valid_attrs, "nsmgt_cdw10", le32_to_cpu(ns_event->nsmgt_cdw10));
	obj_add_uint64(valid_attrs, "nsze", le64_to_cpu(ns_event->nsze));
	obj_add_uint64(valid_attrs, "nscap", le64_to_cpu(ns_event->nscap));
	obj_add_uint(valid_attrs, "flbas", ns_event->flbas);
	obj_add_uint(valid_attrs, "dps", ns_event->dps);
	obj_add_uint(valid_attrs, "nmic", ns_event->nmic);
	obj_add_uint(valid_attrs, "ana_grp_id", le32_to_cpu(ns_event->ana_grp_id));
	obj_add_uint(valid_attrs, "nvmset_id", le16_to_cpu(ns_event->nvmset_id));
	obj_add_uint(valid_attrs, "nsid", le32_to_cpu(ns_event->nsid));
}

static void json_pel_format_start(void *pevent_log_info, __u32 offset,
				  struct json_object *valid_attrs)
{
	struct nvme_format_nvm_start_event *format_start_event = pevent_log_info + offset;

	obj_add_uint(valid_attrs, "nsid", le32_to_cpu(format_start_event->nsid));
	obj_add_uint(valid_attrs, "fna", format_start_event->fna);
	obj_add_uint(valid_attrs, "format_nvm_cdw10",
		     le32_to_cpu(format_start_event->format_nvm_cdw10));
}

static void json_pel_format_completion(void *pevent_log_info, __u32 offset,
				       struct json_object *valid_attrs)
{
	struct nvme_format_nvm_compln_event *format_cmpln_event = pevent_log_info + offset;

	obj_add_uint(valid_attrs, "nsid", le32_to_cpu(format_cmpln_event->nsid));
	obj_add_uint(valid_attrs, "smallest_fpi", format_cmpln_event->smallest_fpi);
	obj_add_uint(valid_attrs, "format_nvm_status", format_cmpln_event->format_nvm_status);
	obj_add_uint(valid_attrs, "compln_info", le16_to_cpu(format_cmpln_event->compln_info));
	obj_add_uint(valid_attrs, "status_field", le32_to_cpu(format_cmpln_event->status_field));
}
static void json_pel_sanitize_start(void *pevent_log_info, __u32 offset,
				    struct json_object *valid_attrs)
{
	struct nvme_sanitize_start_event *sanitize_start_event = pevent_log_info + offset;

	obj_add_uint(valid_attrs, "SANICAP", le32_to_cpu(sanitize_start_event->sani_cap));
	obj_add_uint(valid_attrs, "sani_cdw10", le32_to_cpu(sanitize_start_event->sani_cdw10));
	obj_add_uint(valid_attrs, "sani_cdw11", le32_to_cpu(sanitize_start_event->sani_cdw11));
}

static void json_pel_sanitize_completion(void *pevent_log_info, __u32 offset,
					 struct json_object *valid_attrs)
{
	struct nvme_sanitize_compln_event *sanitize_cmpln_event = pevent_log_info + offset;

	obj_add_uint(valid_attrs, "sani_prog", le16_to_cpu(sanitize_cmpln_event->sani_prog));
	obj_add_uint(valid_attrs, "sani_status", le16_to_cpu(sanitize_cmpln_event->sani_status));
	obj_add_uint(valid_attrs, "cmpln_info", le16_to_cpu(sanitize_cmpln_event->cmpln_info));
}

static void json_pel_set_feature(void *pevent_log_info, __u32 offset,
				 struct json_object *valid_attrs)
{
	struct nvme_set_feature_event *set_feat_event = pevent_log_info + offset;
	int fid = NVME_GET(le32_to_cpu(set_feat_event->cdw_mem[0]), FEATURES_CDW10_FID);
	int cdw11 = le32_to_cpu(set_feat_event->cdw_mem[1]);
	int dword_cnt = NVME_SET_FEAT_EVENT_DW_COUNT(set_feat_event->layout);
	unsigned char *mem_buf;

	obj_add_uint_02x(valid_attrs, "feature", fid);
	obj_add_str(valid_attrs, "name", nvme_feature_to_string(fid));
	obj_add_uint_0nx(valid_attrs, "value", cdw11, 8);

	if (NVME_SET_FEAT_EVENT_MB_COUNT(set_feat_event->layout)) {
		mem_buf = (unsigned char *)(set_feat_event + 4 + dword_cnt * 4);
		json_feature_show_fields(fid, cdw11, mem_buf);
	}
}

static void json_pel_telemetry_crt(void *pevent_log_info, __u32 offset,
				   struct json_object *valid_attrs)
{
	obj_d(valid_attrs, "create", pevent_log_info + offset, 512, 16, 1);
}

static void json_pel_thermal_excursion(void *pevent_log_info, __u32 offset,
				       struct json_object *valid_attrs)
{
	struct nvme_thermal_exc_event *thermal_exc_event = pevent_log_info + offset;

	obj_add_uint(valid_attrs, "over_temp", thermal_exc_event->over_temp);
	obj_add_uint(valid_attrs, "threshold", thermal_exc_event->threshold);
}

static void json_pevent_entry(void *pevent_log_info, __u8 action, __u32 size, const char *devname,
			      __u32 offset, struct json_object *valid)
{
	int i;
	struct nvme_persistent_event_log *pevent_log_head = pevent_log_info;
	struct nvme_persistent_event_entry *pevent_entry_head;
	struct json_object *valid_attrs;

	for (i = 0; i < le32_to_cpu(pevent_log_head->tnev); i++) {
		if (offset + sizeof(*pevent_entry_head) >= size)
			break;

		pevent_entry_head = pevent_log_info + offset;

		if (offset + pevent_entry_head->ehl + 3 + le16_to_cpu(pevent_entry_head->el) >=
		    size)
			break;

		valid_attrs = json_create_object();

		obj_add_uint(valid_attrs, "event_number", i);
		obj_add_str(valid_attrs, "event_type",
			    nvme_pel_event_to_string(pevent_entry_head->etype));
		obj_add_uint(valid_attrs, "event_type_rev", pevent_entry_head->etype_rev);
		obj_add_uint(valid_attrs, "event_header_len", pevent_entry_head->ehl);
		obj_add_uint(valid_attrs, "event_header_additional_info", pevent_entry_head->ehai);
		obj_add_uint(valid_attrs, "ctrl_id", le16_to_cpu(pevent_entry_head->cntlid));
		obj_add_uint64(valid_attrs, "event_time_stamp",
			       le64_to_cpu(pevent_entry_head->ets));
		obj_add_uint(valid_attrs, "port_id", le16_to_cpu(pevent_entry_head->pelpid));
		obj_add_uint(valid_attrs, "vu_info_len", le16_to_cpu(pevent_entry_head->vsil));
		obj_add_uint(valid_attrs, "event_len", le16_to_cpu(pevent_entry_head->el));

		offset += pevent_entry_head->ehl + 3;

		switch (pevent_entry_head->etype) {
		case NVME_PEL_SMART_HEALTH_EVENT:
			json_pel_smart_health(pevent_log_info, offset, valid_attrs);
			break;
		case NVME_PEL_FW_COMMIT_EVENT:
			json_pel_fw_commit(pevent_log_info, offset, valid_attrs);
			break;
		case NVME_PEL_TIMESTAMP_EVENT:
			json_pel_timestamp(pevent_log_info, offset, valid_attrs);
			break;
		case NVME_PEL_POWER_ON_RESET_EVENT:
			json_pel_power_on_reset(pevent_log_info, offset, valid_attrs,
						pevent_entry_head->vsil, pevent_entry_head->el);
			break;
		case NVME_PEL_NSS_HW_ERROR_EVENT:
			json_pel_nss_hw_error(pevent_log_info, offset, valid_attrs);
			break;
		case NVME_PEL_CHANGE_NS_EVENT:
			json_pel_change_ns(pevent_log_info, offset, valid_attrs);
			break;
		case NVME_PEL_FORMAT_START_EVENT:
			json_pel_format_start(pevent_log_info, offset, valid_attrs);
			break;
		case NVME_PEL_FORMAT_COMPLETION_EVENT:
			json_pel_format_completion(pevent_log_info, offset, valid_attrs);
			break;
		case NVME_PEL_SANITIZE_START_EVENT:
			json_pel_sanitize_start(pevent_log_info, offset, valid_attrs);
			break;
		case NVME_PEL_SANITIZE_COMPLETION_EVENT:
			json_pel_sanitize_completion(pevent_log_info, offset, valid_attrs);
			break;
		case NVME_PEL_SET_FEATURE_EVENT:
			json_pel_set_feature(pevent_log_info, offset, valid_attrs);
			break;
		case NVME_PEL_TELEMETRY_CRT:
			json_pel_telemetry_crt(pevent_log_info, offset, valid_attrs);
			break;
		case NVME_PEL_THERMAL_EXCURSION_EVENT:
			json_pel_thermal_excursion(pevent_log_info, offset, valid_attrs);
			break;
		default:
			break;
		}

		array_add_obj(valid, valid_attrs);
		offset += le16_to_cpu(pevent_entry_head->el);
	}
}

static void json_persistent_event_log(void *pevent_log_info, __u8 action,
				      __u32 size, const char *devname)
{
	struct json_object *r = json_create_object();
	struct json_object *valid = json_create_array();
	__u32 offset = sizeof(struct nvme_persistent_event_log);

	if (size >= offset) {
		json_pevent_log_head(pevent_log_info, r);
		json_pevent_entry(pevent_log_info, action, size, devname, offset, valid);
		obj_add_array(r, "list_of_event_entries", valid);
	} else {
		obj_add_result(r, "No log data can be shown with this log len at least " \
				"512 bytes is required or can be 0 to read the complete "\
				"log page after context established");
	}

	json_print(r);
}

static void json_endurance_group_event_agg_log(
		struct nvme_aggregate_endurance_group_event *endurance_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	struct json_object *r = json_create_object();
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();

	obj_add_uint64(r, "num_entries_avail", le64_to_cpu(endurance_log->num_entries));

	for (int i = 0; i < log_entries; i++) {
		valid_attrs = json_create_object();
		obj_add_uint(valid_attrs, "entry", le16_to_cpu(endurance_log->entries[i]));
		array_add_obj(valid, valid_attrs);
	}

	obj_add_array(r, "list_of_entries", valid);

	json_print(r);
}

static void json_lba_status(struct nvme_lba_status *list,
			      unsigned long len)
{
	struct json_object *r = json_create_object();
	int idx;
	struct nvme_lba_status_desc *e;
	struct json_object *lsde;
	char json_str[STR_LEN];

	obj_add_uint(r, "Number of LBA Status Descriptors (NLSD)", le32_to_cpu(list->nlsd));
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

	for (idx = 0; idx < list->nlsd; idx++) {
		lsde = json_create_array();
		sprintf(json_str, "LSD entry %d", idx);
		obj_add_array(r, json_str, lsde);
		e = &list->descs[idx];
		sprintf(json_str, "0x%016"PRIx64"", le64_to_cpu(e->dslba));
		obj_add_str(lsde, "DSLBA", json_str);
		sprintf(json_str, "0x%08x", le32_to_cpu(e->nlb));
		obj_add_str(lsde, "NLB", json_str);
		sprintf(json_str, "0x%02x", e->status);
		obj_add_str(lsde, "status", json_str);
	}

	json_print(r);
}

static void json_lba_status_log(void *lba_status, __u32 size, const char *devname)
{
	struct json_object *r = json_create_object();
	struct json_object *desc;
	struct json_object *element;
	struct json_object *desc_list;
	struct json_object *elements_list = json_create_array();
	struct nvme_lba_status_log *hdr = lba_status;
	struct nvme_lbas_ns_element *ns_element;
	struct nvme_lba_rd *range_desc;
	int offset = sizeof(*hdr);
	__u32 num_lba_desc;
	__u32 num_elements = le32_to_cpu(hdr->nlslne);
	int ele;
	int i;

	obj_add_uint(r, "lslplen", le32_to_cpu(hdr->lslplen));
	obj_add_uint(r, "nlslne", num_elements);
	obj_add_uint(r, "estulb", le32_to_cpu(hdr->estulb));
	obj_add_uint(r, "lsgc", le16_to_cpu(hdr->lsgc));

	for (ele = 0; ele < num_elements; ele++) {
		ns_element = lba_status + offset;
		element = json_create_object();
		obj_add_uint(element, "neid", le32_to_cpu(ns_element->neid));
		num_lba_desc = le32_to_cpu(ns_element->nlrd);
		obj_add_uint(element, "nlrd", num_lba_desc);
		obj_add_uint(element, "ratype", ns_element->ratype);

		offset += sizeof(*ns_element);
		desc_list = json_create_array();

		if (num_lba_desc != 0xffffffff) {
			for (i = 0; i < num_lba_desc; i++) {
				range_desc = lba_status + offset;
				desc = json_create_object();
				obj_add_uint64(desc, "rslba", le64_to_cpu(range_desc->rslba));
				obj_add_uint(desc, "rnlb", le32_to_cpu(range_desc->rnlb));

				offset += sizeof(*range_desc);
				array_add_obj(desc_list, desc);
			}
		} else {
			obj_add_result(r, "Number of LBA Range Descriptors (NLRD) set to %#x for NS element %d",
					num_lba_desc, ele);
		}

		obj_add_array(element, "descs", desc_list);
		array_add_obj(elements_list, element);
	}

	obj_add_array(r, "ns_elements", elements_list);

	json_print(r);
}

static void json_resv_notif_log(struct nvme_resv_notification_log *resv,
				const char *devname)
{
	struct json_object *r = json_create_object();

	obj_add_uint64(r, "count", le64_to_cpu(resv->lpc));
	obj_add_uint(r, "rn_log_type", resv->rnlpt);
	obj_add_uint(r, "num_logs", resv->nalp);
	obj_add_uint(r, "NSID", le32_to_cpu(resv->nsid));

	json_print(r);
}

static void json_fid_support_effects_log(
		struct nvme_fid_supported_effects_log *fid_log,
		const char *devname)
{
	struct json_object *r = json_create_object();
	struct json_object *fids;
	struct json_object *fids_list = json_create_array();
	unsigned int fid;
	char key[128];
	__u32 fid_support;

	for (fid = 0; fid < NVME_LOG_FID_SUPPORTED_EFFECTS_MAX; fid++) {
		fid_support = le32_to_cpu(fid_log->fid_support[fid]);
		if (fid_support & NVME_FID_SUPPORTED_EFFECTS_FSUPP) {
			fids = json_create_object();
			sprintf(key, "fid_%u", fid);
			obj_add_uint(fids, key, fid_support);
			array_add_obj(fids_list, fids);
		}
	}

	obj_add_obj(r, "fid_support", fids_list);

	json_print(r);
}

static void json_mi_cmd_support_effects_log(
		struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
		const char *devname)
{
	struct json_object *r = json_create_object();
	struct json_object *mi_cmds;
	struct json_object *mi_cmds_list = json_create_array();
	unsigned int mi_cmd;
	char key[128];
	__u32 mi_cmd_support;

	for (mi_cmd = 0; mi_cmd < NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_MAX; mi_cmd++) {
		mi_cmd_support = le32_to_cpu(mi_cmd_log->mi_cmd_support[mi_cmd]);
		if (mi_cmd_support & NVME_MI_CMD_SUPPORTED_EFFECTS_CSUPP) {
			mi_cmds = json_create_object();
			sprintf(key, "mi_cmd_%u", mi_cmd);
			obj_add_uint(mi_cmds, key, mi_cmd_support);
			array_add_obj(mi_cmds_list, mi_cmds);
		}
	}

	obj_add_obj(r, "mi_command_support", mi_cmds_list);

	json_print(r);
}

static void json_boot_part_log(void *bp_log, const char *devname,
			       __u32 size)
{
	struct nvme_boot_partition *hdr = bp_log;
	struct json_object *r = json_create_object();

	obj_add_uint(r, "count", hdr->lid);
	obj_add_uint(r, "abpid", NVME_BOOT_PARTITION_INFO_ABPID(le32_to_cpu(hdr->bpinfo)));
	obj_add_uint(r, "bpsz", NVME_BOOT_PARTITION_INFO_BPSZ(le32_to_cpu(hdr->bpinfo)));

	json_print(r);
}

/* Printable Eye string is allocated and returned, caller must free */
static char *json_eom_printable_eye(struct nvme_eom_lane_desc *lane,
				    struct json_object *r)
{
	char *eye = (char *)lane->eye_desc;
	uint16_t nrows = le16_to_cpu(lane->nrows);
	uint16_t ncols = le16_to_cpu(lane->ncols);
	struct json_object *eye_array = NULL;
	char *printable_start = NULL;
	char *printable = NULL;

	if (nrows == 0 || ncols == 0)
		return NULL;

	eye_array = json_create_array();
	if (!eye_array)
		return NULL;

	/*
	 * Allocate buffer for full printable string (with newlines)
	 * +1 for null terminator
	 */
	printable = malloc(nrows * ncols + nrows + 1);
	printable_start = printable;

	if (!printable)
		goto fail_free_eye_array;

	for (int i = 0; i < nrows; i++) {
		char *row = malloc(ncols + 1);

		if (!row)
			goto fail_free_eye_printable;

		for (int j = 0; j < ncols; j++) {
			char ch = eye[i * ncols + j];
			*printable++ = ch;
			row[j] = ch;
		}

		*printable++ = '\n';
		row[ncols] = '\0';

		array_add_str(eye_array, row);
		free(row);
	}

	*printable = '\0';

	obj_add_array(r, "printable_eye", eye_array);

	return printable_start;

fail_free_eye_printable:
	free(printable);
fail_free_eye_array:
	json_free_object(eye_array);

	return NULL;
}

static void json_phy_rx_eom_descs(struct nvme_phy_rx_eom_log *log,
			struct json_object *r, char **allocated_eyes)
{
	void *p = log->descs;
	uint16_t num_descs = le16_to_cpu(log->nd);
	int i;
	struct json_object *descs = json_create_array();

	obj_add_array(r, "descs", descs);

	for (i = 0; i < num_descs; i++) {
		struct nvme_eom_lane_desc *desc = p;
		_cleanup_free_ char *hexstr = NULL;
		unsigned char *vsdata = NULL;
		unsigned int vsdataoffset = 0;
		uint16_t nrows, ncols, edlen;
		struct json_object *jdesc;
		char *hexdata;

		jdesc = json_create_object();
		if (!desc)
			return;

		nrows = le16_to_cpu(desc->nrows);
		ncols = le16_to_cpu(desc->ncols);
		edlen = le16_to_cpu(desc->edlen);

		obj_add_uint(jdesc, "lid", desc->mstatus);
		obj_add_uint(jdesc, "lane", desc->lane);
		obj_add_uint(jdesc, "eye", desc->eye);
		obj_add_uint(jdesc, "top", le16_to_cpu(desc->top));
		obj_add_uint(jdesc, "bottom", le16_to_cpu(desc->bottom));
		obj_add_uint(jdesc, "left", le16_to_cpu(desc->left));
		obj_add_uint(jdesc, "right", le16_to_cpu(desc->right));
		obj_add_uint(jdesc, "nrows", nrows);
		obj_add_uint(jdesc, "ncols", ncols);
		obj_add_uint(jdesc, "edlen", edlen);

		if (NVME_EOM_ODP_PEFP(log->odp))
			allocated_eyes[i] = json_eom_printable_eye(desc, jdesc);

		if (edlen == 0)
			continue;

		/* 2 hex chars + space per byte */
		hexstr = malloc(edlen * 3 + 1);

		if (!hexstr) {
			json_free_object(jdesc);
			return;
		}

		/* Hex dump Vendor Specific Eye Data */
		vsdataoffset = (nrows * ncols) + sizeof(struct nvme_eom_lane_desc);
		vsdata = (unsigned char *)((unsigned char *)desc + vsdataoffset);

		hexdata = hexstr;

		for (int offset = 0; offset < edlen; offset++)
			hexdata += sprintf(hexdata, "%02X ", vsdata[offset]);
		/* remove trailing space */
		*(hexdata - 1) = '\0';

		obj_add_str(jdesc, "vsdata_hex", hexstr);

		array_add_obj(descs, jdesc);

		p += log->dsize;
	}
}

static void json_phy_rx_eom_log(struct nvme_phy_rx_eom_log *log, __u16 controller)
{
	int i;
	struct json_object *r = json_create_object();

	_cleanup_free_ char **allocated_eyes = NULL;

	obj_add_uint(r, "lid", log->lid);
	obj_add_uint(r, "eomip", log->eomip);
	obj_add_uint(r, "hsize", le16_to_cpu(log->hsize));
	obj_add_uint(r, "rsize", le32_to_cpu(log->rsize));
	obj_add_uint(r, "eomdgn", log->eomdgn);
	obj_add_uint(r, "lr", log->lr);
	obj_add_uint(r, "lanes", log->lanes);
	obj_add_uint(r, "epl", log->epl);
	obj_add_uint(r, "lspfc", log->lspfc);
	obj_add_uint(r, "li", log->li);
	obj_add_uint(r, "lsic", le16_to_cpu(log->lsic));
	obj_add_uint(r, "dsize", le32_to_cpu(log->dsize));
	obj_add_uint(r, "nd", le16_to_cpu(log->nd));
	obj_add_uint(r, "maxtb", le16_to_cpu(log->maxtb));
	obj_add_uint(r, "maxlr", le16_to_cpu(log->maxlr));
	obj_add_uint(r, "etgood", le16_to_cpu(log->etgood));
	obj_add_uint(r, "etbetter", le16_to_cpu(log->etbetter));
	obj_add_uint(r, "etbest", le16_to_cpu(log->etbest));

	if (log->eomip == NVME_PHY_RX_EOM_COMPLETED) {
		/* Save Printable Eye strings allocated to free later */
		allocated_eyes = malloc(log->nd * sizeof(char *));
		if (allocated_eyes)
			json_phy_rx_eom_descs(log, r, allocated_eyes);
	}

	if (allocated_eyes) {
		for (i = 0; i < log->nd; i++) {
			/* Free any Printable Eye strings allocated */
			if (allocated_eyes[i])
				free(allocated_eyes[i]);
		}
	}

	json_print(r);
}

static void json_media_unit_stat_log(struct nvme_media_unit_stat_log *mus)
{
	struct json_object *r = json_create_object();
	struct json_object *entries = json_create_array();
	struct json_object *entry;
	int i;

	obj_add_uint(r, "nmu", le16_to_cpu(mus->nmu));
	obj_add_uint(r, "cchans", le16_to_cpu(mus->cchans));
	obj_add_uint(r, "sel_config", le16_to_cpu(mus->sel_config));

	for (i = 0; i < mus->nmu; i++) {
		entry = json_create_object();
		obj_add_uint(entry, "muid", le16_to_cpu(mus->mus_desc[i].muid));
		obj_add_uint(entry, "domainid", le16_to_cpu(mus->mus_desc[i].domainid));
		obj_add_uint(entry, "endgid", le16_to_cpu(mus->mus_desc[i].endgid));
		obj_add_uint(entry, "nvmsetid", le16_to_cpu(mus->mus_desc[i].nvmsetid));
		obj_add_uint(entry, "cap_adj_fctr", le16_to_cpu(mus->mus_desc[i].cap_adj_fctr));
		obj_add_uint(entry, "avl_spare", mus->mus_desc[i].avl_spare);
		obj_add_uint(entry, "percent_used", mus->mus_desc[i].percent_used);
		obj_add_uint(entry, "mucs", mus->mus_desc[i].mucs);
		obj_add_uint(entry, "cio", mus->mus_desc[i].cio);
		array_add_obj(entries, entry);
	}

	obj_add_array(r, "mus_list", entries);

	json_print(r);
}

static void json_supported_cap_config_log(
		struct nvme_supported_cap_config_list_log *cap_log)
{
	struct json_object *r = json_create_object();
	struct json_object *cap_list = json_create_array();
	struct json_object *capacity;
	struct json_object *end_list;
	struct json_object *set_list;
	struct json_object *set;
	struct json_object *chan_list;
	struct json_object *channel;
	struct json_object *media_list;
	struct json_object *media;
	struct json_object *endurance;
	struct nvme_end_grp_chan_desc *chan_desc;
	int i, j, k, l, m, egcn, egsets, egchans, chmus;
	int sccn = cap_log->sccn;

	obj_add_uint(r, "sccn", cap_log->sccn);
	for (i = 0; i < sccn; i++) {
		capacity = json_create_object();
		obj_add_uint(capacity, "cap_config_id",
			     le16_to_cpu(cap_log->cap_config_desc[i].cap_config_id));
		obj_add_uint(capacity, "domainid",
			     le16_to_cpu(cap_log->cap_config_desc[i].domainid));
		obj_add_uint(capacity, "egcn", le16_to_cpu(cap_log->cap_config_desc[i].egcn));
		end_list = json_create_array();
		egcn = le16_to_cpu(cap_log->cap_config_desc[i].egcn);
		for (j = 0; j < egcn; j++) {
			endurance = json_create_object();
			obj_add_uint(endurance, "endgid",
				     le16_to_cpu(cap_log->cap_config_desc[i].egcd[j].endgid));
			obj_add_uint(endurance, "cap_adj_factor",
				     le16_to_cpu(cap_log->cap_config_desc[i].egcd[j].cap_adj_factor));
			obj_add_uint128(endurance, "tegcap",
					le128_to_cpu(cap_log->cap_config_desc[i].egcd[j].tegcap));
			obj_add_uint128(endurance, "segcap",
					le128_to_cpu(cap_log->cap_config_desc[i].egcd[j].segcap));
			obj_add_uint(endurance, "egsets",
				     le16_to_cpu(cap_log->cap_config_desc[i].egcd[j].egsets));
			egsets = le16_to_cpu(cap_log->cap_config_desc[i].egcd[j].egsets);
			set_list = json_create_array();
			for (k = 0; k < egsets; k++) {
				set = json_create_object();
				obj_add_uint(set, "nvmsetid",
				    le16_to_cpu(cap_log->cap_config_desc[i].egcd[j].nvmsetid[k]));
				array_add_obj(set_list, set);
			}
			chan_desc = (struct nvme_end_grp_chan_desc *)
			    &cap_log->cap_config_desc[i].egcd[j].nvmsetid[egsets];
			egchans = le16_to_cpu(chan_desc->egchans);
			obj_add_uint(endurance, "egchans", le16_to_cpu(chan_desc->egchans));
			chan_list = json_create_array();
			for (l = 0; l < egchans; l++) {
				channel = json_create_object();
				obj_add_uint(channel, "chanid",
					     le16_to_cpu(chan_desc->chan_config_desc[l].chanid));
				obj_add_uint(channel, "chmus",
					     le16_to_cpu(chan_desc->chan_config_desc[l].chmus));
				chmus = le16_to_cpu(chan_desc->chan_config_desc[l].chmus);
				media_list = json_create_array();
				for (m = 0; m < chmus; m++) {
					media = json_create_object();
					obj_add_uint(media, "chanid",
					    le16_to_cpu(chan_desc->chan_config_desc[l].mu_config_desc[m].muid));
					obj_add_uint(media, "chmus",
					    le16_to_cpu(chan_desc->chan_config_desc[l].mu_config_desc[m].mudl));
					array_add_obj(media_list, media);
				}
				obj_add_array(channel, "Media Descriptor", media_list);
				array_add_obj(chan_list, channel);
			}
			obj_add_array(endurance, "Channel Descriptor", chan_list);
			obj_add_array(endurance, "NVM Set IDs", set_list);
			array_add_obj(end_list, endurance);
		}
		obj_add_array(capacity, "Endurance Descriptor", end_list);
		array_add_obj(cap_list, capacity);
	}

	obj_add_array(r, "Capacity Descriptor", cap_list);

	json_print(r);
}

static void json_nvme_fdp_configs(struct nvme_fdp_config_log *log, size_t len)
{
	struct json_object *r, *obj_configs;
	uint16_t n;

	void *p = log->configs;

	r = json_create_object();
	obj_configs = json_create_array();

	n = le16_to_cpu(log->n);

	obj_add_uint(r, "n", n);

	for (int i = 0; i < n + 1; i++) {
		struct nvme_fdp_config_desc *config = p;

		struct json_object *obj_config = json_create_object();
		struct json_object *obj_ruhs = json_create_array();

		obj_add_uint(obj_config, "fdpa", config->fdpa);
		obj_add_uint(obj_config, "vss", config->vss);
		obj_add_uint(obj_config, "nrg", le32_to_cpu(config->nrg));
		obj_add_uint(obj_config, "nruh", le16_to_cpu(config->nruh));
		obj_add_uint(obj_config, "nnss", le32_to_cpu(config->nnss));
		obj_add_uint64(obj_config, "runs", le64_to_cpu(config->runs));
		obj_add_uint(obj_config, "erutl", le32_to_cpu(config->erutl));

		for (int j = 0; j < le16_to_cpu(config->nruh); j++) {
			struct nvme_fdp_ruh_desc *ruh = &config->ruhs[j];

			struct json_object *obj_ruh = json_create_object();

			obj_add_uint(obj_ruh, "ruht", ruh->ruht);

			array_add_obj(obj_ruhs, obj_ruh);
		}

		array_add_obj(obj_configs, obj_config);

		p += config->size;
	}

	obj_add_array(r, "configs", obj_configs);

	json_print(r);
}

static void json_nvme_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len)
{
	struct json_object *r, *obj_ruhus;
	uint16_t nruh;

	r = json_create_object();
	obj_ruhus = json_create_array();

	nruh = le16_to_cpu(log->nruh);

	obj_add_uint(r, "nruh", nruh);

	for (int i = 0; i < nruh; i++) {
		struct nvme_fdp_ruhu_desc *ruhu = &log->ruhus[i];

		struct json_object *obj_ruhu = json_create_object();

		obj_add_uint(obj_ruhu, "ruha", ruhu->ruha);

		array_add_obj(obj_ruhus, obj_ruhu);
	}

	obj_add_array(r, "ruhus", obj_ruhus);

	json_print(r);
}

static void json_nvme_fdp_stats(struct nvme_fdp_stats_log *log)
{
	struct json_object *r = json_create_object();

	obj_add_uint128(r, "hbmw", le128_to_cpu(log->hbmw));
	obj_add_uint128(r, "mbmw", le128_to_cpu(log->mbmw));
	obj_add_uint128(r, "mbe", le128_to_cpu(log->mbe));

	json_print(r);
}

static void json_nvme_fdp_events(struct nvme_fdp_events_log *log)
{
	struct json_object *r, *obj_events;
	uint32_t n;

	r = json_create_object();
	obj_events = json_create_array();

	n = le32_to_cpu(log->n);

	obj_add_uint(r, "n", n);

	for (unsigned int i = 0; i < n; i++) {
		struct nvme_fdp_event *event = &log->events[i];

		struct json_object *obj_event = json_create_object();

		obj_add_uint(obj_event, "type", event->type);
		obj_add_uint(obj_event, "fdpef", event->flags);
		obj_add_uint(obj_event, "pid", le16_to_cpu(event->pid));
		obj_add_uint64(obj_event, "timestamp", le64_to_cpu(*(uint64_t *)&event->ts));
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

	json_print(r);
}

static void json_nvme_fdp_ruh_status(struct nvme_fdp_ruh_status *status, size_t len)
{
	struct json_object *r, *obj_ruhss;
	uint16_t nruhsd;

	r = json_create_object();
	obj_ruhss = json_create_array();

	nruhsd = le16_to_cpu(status->nruhsd);

	obj_add_uint(r, "nruhsd", nruhsd);

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

	json_print(r);
}

static unsigned int json_print_nvme_subsystem_multipath(nvme_subsystem_t s, json_object *paths)
{
	nvme_ns_t n;
	nvme_path_t p;
	unsigned int i = 0;

	n = nvme_subsystem_first_ns(s);
	if (!n)
		return 0;

	nvme_namespace_for_each_path(n, p) {
		struct json_object *path_attrs;
		nvme_ctrl_t c = nvme_path_get_ctrl(p);

		path_attrs = json_create_object();
		obj_add_str(path_attrs, "Name", nvme_ctrl_get_name(c));
		obj_add_str(path_attrs, "Transport", nvme_ctrl_get_transport(c));
		obj_add_str(path_attrs, "Address", nvme_ctrl_get_address(c));
		obj_add_str(path_attrs, "State", nvme_ctrl_get_state(c));
		obj_add_str(path_attrs, "ANAState", nvme_path_get_ana_state(p));
		array_add_obj(paths, path_attrs);
		i++;
	}

	return i;
}

static void json_print_nvme_subsystem_ctrls(nvme_subsystem_t s,
					    json_object *paths)
{
	nvme_ctrl_t c;

	nvme_subsystem_for_each_ctrl(s, c) {
		struct json_object *path_attrs;

		path_attrs = json_create_object();
		obj_add_str(path_attrs, "Name", nvme_ctrl_get_name(c));
		obj_add_str(path_attrs, "Transport", nvme_ctrl_get_transport(c));
		obj_add_str(path_attrs, "Address", nvme_ctrl_get_address(c));
		obj_add_str(path_attrs, "State", nvme_ctrl_get_state(c));
		array_add_obj(paths, path_attrs);
	}
}

static void json_print_nvme_subsystem_list(nvme_root_t r, bool show_ana)
{
	struct json_object *host_attrs, *subsystem_attrs;
	struct json_object *subsystems, *paths;
	struct json_object *a = json_create_array();
	nvme_host_t h;

	nvme_for_each_host(r, h) {
		nvme_subsystem_t s;
		const char *hostid;

		host_attrs = json_create_object();
		obj_add_str(host_attrs, "HostNQN", nvme_host_get_hostnqn(h));
		hostid = nvme_host_get_hostid(h);
		if (hostid)
			obj_add_str(host_attrs, "HostID", hostid);
		subsystems = json_create_array();
		nvme_for_each_subsystem(h, s) {
			nvme_ctrl_t c;
			bool no_ctrl = true;

			nvme_subsystem_for_each_ctrl(s, c)
				no_ctrl = false;
			if (no_ctrl)
				continue;

			subsystem_attrs = json_create_object();
			obj_add_str(subsystem_attrs, "Name", nvme_subsystem_get_name(s));
			obj_add_str(subsystem_attrs, "NQN", nvme_subsystem_get_nqn(s));

			if (verbose_mode()) {
				obj_add_str(subsystem_attrs, "Model",
						nvme_subsystem_get_model(s));
				obj_add_str(subsystem_attrs, "Serial",
						nvme_subsystem_get_serial(s));
				obj_add_str(subsystem_attrs, "Firmware",
						nvme_subsystem_get_fw_rev(s));
				obj_add_str(subsystem_attrs, "IOPolicy",
						nvme_subsystem_get_iopolicy(s));
				obj_add_str(subsystem_attrs, "Type",
						nvme_subsystem_get_type(s));
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

static void json_ctrl_registers_cap(void *bar, struct json_object *r)
{
	uint64_t cap = mmio_read64(bar + NVME_REG_CAP);

	if (verbose_mode())
		json_registers_cap((struct nvme_bar_cap *)&cap, obj_create_array_obj(r, "cap"));
	else
		obj_add_uint64(r, "cap", cap);
}

static void json_ctrl_registers_vs(void *bar, struct json_object *r)
{
	uint32_t vs = mmio_read32(bar + NVME_REG_VS);

	if (verbose_mode())
		json_registers_version(vs, obj_create_array_obj(r, "vs"));
	else
		obj_add_int(r, "vs", vs);
}

static void json_ctrl_registers_intms(void *bar, struct json_object *r)
{
	uint32_t intms = mmio_read32(bar + NVME_REG_INTMS);

	if (verbose_mode())
		json_registers_intms(intms, obj_create_array_obj(r, "intms"));
	else
		obj_add_int(r, "intms", intms);
}

static void json_ctrl_registers_intmc(void *bar, struct json_object *r)
{
	uint32_t intmc = mmio_read32(bar + NVME_REG_INTMC);

	if (verbose_mode())
		json_registers_intmc(intmc, obj_create_array_obj(r, "intmc"));
	else
		obj_add_int(r, "intmc", intmc);
}

static void json_ctrl_registers_cc(void *bar, struct json_object *r)
{
	uint32_t cc = mmio_read32(bar + NVME_REG_CC);

	if (verbose_mode())
		json_registers_cc(cc, obj_create_array_obj(r, "cc"));
	else
		obj_add_int(r, "cc", cc);
}

static void json_ctrl_registers_csts(void *bar, struct json_object *r)
{
	uint32_t csts = mmio_read32(bar + NVME_REG_CSTS);

	if (verbose_mode())
		json_registers_csts(csts, obj_create_array_obj(r, "csts"));
	else
		obj_add_int(r, "csts", csts);
}

static void json_ctrl_registers_nssr(void *bar, struct json_object *r)
{
	uint32_t nssr = mmio_read32(bar + NVME_REG_NSSR);

	if (verbose_mode())
		json_registers_nssr(nssr, obj_create_array_obj(r, "nssr"));
	else
		obj_add_int(r, "nssr", nssr);
}

static void json_ctrl_registers_nssd(void *bar, struct json_object *r)
{
	uint32_t nssd = mmio_read32(bar + NVME_REG_NSSD);

	if (verbose_mode())
		json_registers_nssd(nssd, obj_create_array_obj(r, "nssd"));
	else
		obj_add_int(r, "nssd", nssd);
}

static void json_ctrl_registers_crto(void *bar, struct json_object *r)
{
	uint32_t crto = mmio_read32(bar + NVME_REG_CRTO);

	if (verbose_mode())
		json_registers_crto(crto, obj_create_array_obj(r, "crto"));
	else
		obj_add_int(r, "crto", crto);
}

static void json_ctrl_registers_aqa(void *bar, struct json_object *r)
{
	uint32_t aqa = mmio_read32(bar + NVME_REG_AQA);

	if (verbose_mode())
		json_registers_aqa(aqa, obj_create_array_obj(r, "aqa"));
	else
		obj_add_int(r, "aqa", aqa);
}

static void json_ctrl_registers_asq(void *bar, struct json_object *r)
{
	uint64_t asq = mmio_read64(bar + NVME_REG_ASQ);

	if (verbose_mode())
		json_registers_asq(asq, obj_create_array_obj(r, "asq"));
	else
		obj_add_uint64(r, "asq", asq);
}

static void json_ctrl_registers_acq(void *bar, struct json_object *r)
{
	uint64_t acq = mmio_read64(bar + NVME_REG_ACQ);

	if (verbose_mode())
		json_registers_acq(acq, obj_create_array_obj(r, "acq"));
	else
		obj_add_uint64(r, "acq", acq);
}

static void json_ctrl_registers_cmbloc(void *bar, struct json_object *r)
{
	uint32_t cmbloc = mmio_read32(bar + NVME_REG_CMBLOC);
	uint32_t cmbsz;
	bool support;

	if (verbose_mode()) {
		cmbsz = mmio_read32(bar + NVME_REG_CMBSZ);
		support = nvme_registers_cmbloc_support(cmbsz);
		json_registers_cmbloc(cmbloc, support, obj_create_array_obj(r, "cmbloc"));
	} else {
		obj_add_int(r, "cmbloc", cmbloc);
	}
}

static void json_ctrl_registers_cmbsz(void *bar, struct json_object *r)
{
	uint32_t cmbsz = mmio_read32(bar + NVME_REG_CMBSZ);

	if (verbose_mode())
		json_registers_cmbsz(cmbsz, obj_create_array_obj(r, "cmbsz"));
	else
		obj_add_int(r, "cmbsz", cmbsz);
}

static void json_ctrl_registers_bpinfo(void *bar, struct json_object *r)
{
	uint32_t bpinfo = mmio_read32(bar + NVME_REG_BPINFO);

	if (verbose_mode())
		json_registers_bpinfo(bpinfo, obj_create_array_obj(r, "bpinfo"));
	else
		obj_add_int(r, "bpinfo", bpinfo);
}

static void json_ctrl_registers_bprsel(void *bar, struct json_object *r)
{
	uint32_t bprsel = mmio_read32(bar + NVME_REG_BPRSEL);

	if (verbose_mode())
		json_registers_bprsel(bprsel, obj_create_array_obj(r, "bprsel"));
	else
		obj_add_int(r, "bprsel", bprsel);
}

static void json_ctrl_registers_bpmbl(void *bar, struct json_object *r)
{
	uint64_t bpmbl = mmio_read64(bar + NVME_REG_BPMBL);

	if (verbose_mode())
		json_registers_bpmbl(bpmbl, obj_create_array_obj(r, "bpmbl"));
	else
		obj_add_uint64(r, "bpmbl", bpmbl);
}

static void json_ctrl_registers_cmbmsc(void *bar, struct json_object *r)
{
	uint64_t cmbmsc = mmio_read64(bar + NVME_REG_CMBMSC);

	if (verbose_mode())
		json_registers_cmbmsc(cmbmsc, obj_create_array_obj(r, "cmbmsc"));
	else
		obj_add_uint64(r, "cmbmsc", cmbmsc);
}

static void json_ctrl_registers_cmbsts(void *bar, struct json_object *r)
{
	uint32_t cmbsts = mmio_read32(bar + NVME_REG_CMBSTS);

	if (verbose_mode())
		json_registers_cmbsts(cmbsts, obj_create_array_obj(r, "cmbsts"));
	else
		obj_add_int(r, "cmbsts", cmbsts);
}

static void json_ctrl_registers_cmbebs(void *bar, struct json_object *r)
{
	uint32_t cmbebs = mmio_read32(bar + NVME_REG_CMBEBS);

	if (verbose_mode())
		json_registers_cmbebs(cmbebs, obj_create_array_obj(r, "cmbebs"));
	else
		obj_add_int(r, "cmbebs", cmbebs);
}

static void json_ctrl_registers_cmbswtp(void *bar, struct json_object *r)
{
	uint32_t cmbswtp = mmio_read32(bar + NVME_REG_CMBSWTP);

	if (verbose_mode())
		json_registers_cmbswtp(cmbswtp, obj_create_array_obj(r, "cmbswtp"));
	else
		obj_add_int(r, "cmbswtp", cmbswtp);
}

static void json_ctrl_registers_pmrcap(void *bar, struct json_object *r)
{
	uint32_t pmrcap = mmio_read32(bar + NVME_REG_PMRCAP);

	if (verbose_mode())
		json_registers_pmrcap(pmrcap, obj_create_array_obj(r, "pmrcap"));
	else
		obj_add_int(r, "pmrcap", pmrcap);
}

static void json_ctrl_registers_pmrctl(void *bar, struct json_object *r)
{
	uint32_t pmrctl = mmio_read32(bar + NVME_REG_PMRCTL);

	if (verbose_mode())
		json_registers_pmrctl(pmrctl, obj_create_array_obj(r, "pmrctl"));
	else
		obj_add_int(r, "pmrctl", pmrctl);
}

static void json_ctrl_registers_pmrsts(void *bar, struct json_object *r)
{
	uint32_t pmrsts = mmio_read32(bar + NVME_REG_PMRSTS);
	uint32_t pmrctl;
	bool ready;

	if (verbose_mode()) {
		pmrctl = mmio_read32(bar + NVME_REG_PMRCTL);
		ready = nvme_registers_pmrctl_ready(pmrctl);
		json_registers_pmrsts(pmrsts, ready, obj_create_array_obj(r, "pmrsts"));
	} else {
		obj_add_int(r, "pmrsts", pmrsts);
	}
}

static void json_ctrl_registers_pmrebs(void *bar, struct json_object *r)
{
	uint32_t pmrebs = mmio_read32(bar + NVME_REG_PMREBS);

	if (verbose_mode())
		json_registers_pmrebs(pmrebs, obj_create_array_obj(r, "pmrebs"));
	else
		obj_add_int(r, "pmrebs", pmrebs);
}

static void json_ctrl_registers_pmrswtp(void *bar, struct json_object *r)
{
	uint32_t pmrswtp = mmio_read32(bar + NVME_REG_PMRSWTP);

	if (verbose_mode())
		json_registers_pmrswtp(pmrswtp, obj_create_array_obj(r, "pmrswtp"));
	else
		obj_add_int(r, "pmrswtp", pmrswtp);
}

static void json_ctrl_registers_pmrmscl(void *bar, struct json_object *r)
{
	uint32_t pmrmscl = mmio_read32(bar + NVME_REG_PMRMSCL);

	if (verbose_mode())
		json_registers_pmrmscl(pmrmscl, obj_create_array_obj(r, "pmrmscl"));
	else
		obj_add_uint(r, "pmrmscl", pmrmscl);
}

static void json_ctrl_registers_pmrmscu(void *bar, struct json_object *r)
{
	uint32_t pmrmscu = mmio_read32(bar + NVME_REG_PMRMSCU);

	if (verbose_mode())
		json_registers_pmrmscu(pmrmscu, obj_create_array_obj(r, "pmrmscu"));
	else
		obj_add_uint(r, "pmrmscu", pmrmscu);
}

static void json_ctrl_registers(void *bar, bool fabrics)
{
	struct json_object *r = json_create_object();

	json_ctrl_registers_cap(bar, r);
	json_ctrl_registers_vs(bar, r);
	json_ctrl_registers_intms(bar, r);
	json_ctrl_registers_intmc(bar, r);
	json_ctrl_registers_cc(bar, r);
	json_ctrl_registers_csts(bar, r);
	json_ctrl_registers_nssr(bar, r);
	json_ctrl_registers_aqa(bar, r);
	json_ctrl_registers_asq(bar, r);
	json_ctrl_registers_acq(bar, r);
	json_ctrl_registers_cmbloc(bar, r);
	json_ctrl_registers_cmbsz(bar, r);
	json_ctrl_registers_bpinfo(bar, r);
	json_ctrl_registers_bprsel(bar, r);
	json_ctrl_registers_bpmbl(bar, r);
	json_ctrl_registers_cmbmsc(bar, r);
	json_ctrl_registers_cmbsts(bar, r);
	json_ctrl_registers_cmbebs(bar, r);
	json_ctrl_registers_cmbswtp(bar, r);
	json_ctrl_registers_nssd(bar, r);
	json_ctrl_registers_crto(bar, r);
	json_ctrl_registers_pmrcap(bar, r);
	json_ctrl_registers_pmrctl(bar, r);
	json_ctrl_registers_pmrsts(bar, r);
	json_ctrl_registers_pmrebs(bar, r);
	json_ctrl_registers_pmrswtp(bar, r);
	json_ctrl_registers_pmrmscl(bar, r);
	json_ctrl_registers_pmrmscu(bar, r);

	json_print(r);
}

static void json_ctrl_register_human(int offset, uint64_t value, struct json_object *r)
{
	char buffer[BUF_LEN];
	struct json_object *array_obj = NULL;

	switch (offset) {
	case NVME_REG_CAP:
		array_obj = obj_create_array_obj(r, "cap");
		break;
	case NVME_REG_VS:
		array_obj = obj_create_array_obj(r, "vs");
		break;
	case NVME_REG_INTMS:
		obj_add_nprix64(r, "Interrupt Vector Mask Set (IVMS)", value);
		break;
	case NVME_REG_INTMC:
		obj_add_nprix64(r, "Interrupt Vector Mask Clear (IVMC)", value);
		break;
	case NVME_REG_CC:
		array_obj = obj_create_array_obj(r, "cc");
		break;
	case NVME_REG_CSTS:
		array_obj = obj_create_array_obj(r, "csts");
		break;
	case NVME_REG_NSSR:
		obj_add_uint64(r, "NVM Subsystem Reset Control (NSSRC)", value);
		break;
	case NVME_REG_AQA:
		json_registers_aqa(value, obj_create_array_obj(r, "aqa"));
		break;
	case NVME_REG_ASQ:
		obj_add_nprix64(r, "Admin Submission Queue Base (ASQB)", value);
		break;
	case NVME_REG_ACQ:
		obj_add_nprix64(r, "Admin Completion Queue Base (ACQB)", value);
		break;
	case NVME_REG_CMBLOC:
		json_registers_cmbloc(value, true, obj_create_array_obj(r, "cmbloc"));
		break;
	case NVME_REG_CMBSZ:
		json_registers_cmbsz(value, obj_create_array_obj(r, "cmbsz"));
		break;
	case NVME_REG_BPINFO:
		json_registers_bpinfo(value, obj_create_array_obj(r, "bpinfo"));
		break;
	case NVME_REG_BPRSEL:
		json_registers_bprsel(value, obj_create_array_obj(r, "bprsel"));
		break;
	case NVME_REG_BPMBL:
		json_registers_bpmbl(value, obj_create_array_obj(r, "bpmbl"));
		break;
	case NVME_REG_CMBMSC:
		json_registers_cmbmsc(value, obj_create_array_obj(r, "cmbmsc"));
		break;
	case NVME_REG_CMBSTS:
		json_registers_cmbsts(value, obj_create_array_obj(r, "cmbsts"));
		break;
	case NVME_REG_CMBEBS:
		json_registers_cmbebs(value, obj_create_array_obj(r, "cmbebs"));
		break;
	case NVME_REG_CMBSWTP:
		json_registers_cmbswtp(value, obj_create_array_obj(r, "cmbswtp"));
		break;
	case NVME_REG_NSSD:
		json_registers_nssd(value, obj_create_array_obj(r, "nssd"));
		break;
	case NVME_REG_CRTO:
		array_obj = obj_create_array_obj(r, "crto");
		break;
	case NVME_REG_PMRCAP:
		json_registers_pmrcap(value, obj_create_array_obj(r, "pmrcap"));
		break;
	case NVME_REG_PMRCTL:
		json_registers_pmrctl(value, obj_create_array_obj(r, "pmrctl"));
		break;
	case NVME_REG_PMRSTS:
		json_registers_pmrsts(value, true, obj_create_array_obj(r, "pmrsts"));
		break;
	case NVME_REG_PMREBS:
		json_registers_pmrebs(value, obj_create_array_obj(r, "pmrebs"));
		break;
	case NVME_REG_PMRSWTP:
		json_registers_pmrswtp(value, obj_create_array_obj(r, "pmrswtp"));
		break;
	case NVME_REG_PMRMSCL:
		json_registers_pmrmscl(value, obj_create_array_obj(r, "pmrmscl"));
		break;
	case NVME_REG_PMRMSCU:
		json_registers_pmrmscu(value, obj_create_array_obj(r, "pmrmscu"));
		break;
	default:
		sprintf(buffer, "%#04x (%s)", offset, nvme_register_to_string(offset));
		obj_add_str(r, "register", buffer);
		obj_add_nprix64(r, "value", value);
		break;
	}

	if (array_obj)
		json_single_property_human(offset, value, array_obj);
}

static void json_ctrl_register(int offset, uint64_t value)
{
	struct json_object *r;
	char json_str[STR_LEN];

	sprintf(json_str, "register: %#04x", offset);
	r = obj_create(json_str);

	if (verbose_mode()) {
		obj_add_uint64(r, nvme_register_to_string(offset), value);
		json_ctrl_register_human(offset, value, r);
	} else {
		obj_add_str(r, "name", nvme_register_symbol_to_string(offset));
		obj_add_uint64(r, "value", value);
	}
}

static void json_nvme_cmd_set_independent_id_ns(struct nvme_id_independent_id_ns *ns,
						unsigned int nsid)
{
	struct json_object *r = json_create_object();

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

	json_print(r);
}

static void json_nvme_id_ns_descs(void *data, unsigned int nsid)
{
	/* large enough to hold uuid str (37) or nguid str (32) + zero byte */
	char json_str[STR_LEN];
	char *json_str_p;
	union {
		__u8 eui64[NVME_NIDT_EUI64_LEN];
		__u8 nguid[NVME_NIDT_NGUID_LEN];
		__u8 uuid[NVME_UUID_LEN];
		__u8 csi;
	} desc;
	struct json_object *r = json_create_object();
	struct json_object *json_array = NULL;
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
			len = sizeof(desc.eui64);
			nidt_name = "eui64";
			break;
		case NVME_NIDT_NGUID:
			memcpy(desc.nguid, data + off, sizeof(desc.nguid));
			for (i = 0; i < sizeof(desc.nguid); i++)
				json_str_p += sprintf(json_str_p, "%02x", desc.nguid[i]);
			len = sizeof(desc.nguid);
			nidt_name = "nguid";
			break;
		case NVME_NIDT_UUID:
			memcpy(desc.uuid, data + off, sizeof(desc.uuid));
			nvme_uuid_to_string(desc.uuid, json_str);
			len = sizeof(desc.uuid);
			nidt_name = "uuid";
			break;
		case NVME_NIDT_CSI:
			memcpy(&desc.csi, data + off, sizeof(desc.csi));
			sprintf(json_str_p, "%#x", desc.csi);
			len += sizeof(desc.csi);
			nidt_name = "csi";
			break;
		default:
			/* Skip unknown types */
			len = cur->nidl;
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

		len += sizeof(*cur);
	}

	if (json_array)
		obj_add_array(r, "ns-descs", json_array);

	json_print(r);
}

static void json_nvme_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm)
{
	struct json_object *r = json_create_object();

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

	json_print(r);
}

static void json_nvme_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns,
				unsigned int nsid, struct nvme_id_ns *ns,
				unsigned int lba_index, bool cap_only)

{
	struct json_object *r = json_create_object();
	struct json_object *elbafs = json_create_array();
	int i;

	if (!cap_only)
		obj_add_uint64(r, "lbstm", le64_to_cpu(nvm_ns->lbstm));

	obj_add_int(r, "pic", nvm_ns->pic);
	obj_add_int(r, "pifa", nvm_ns->pifa);

	obj_add_array(r, "elbafs", elbafs);

	for (i = 0; i <= ns->nlbaf + ns->nulbaf; i++) {
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

	json_print(r);
}

static void json_nvme_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl)
{
	struct json_object *r = json_create_object();

	obj_add_int(r, "zasl", ctrl->zasl);

	json_print(r);
}

static void json_nvme_zns_id_ns(struct nvme_zns_id_ns *ns,
				struct nvme_id_ns *id_ns)
{
	struct json_object *r = json_create_object();
	struct json_object *lbafs = json_create_array();
	int i;

	obj_add_int(r, "zoc", le16_to_cpu(ns->zoc));
	obj_add_int(r, "ozcs", le16_to_cpu(ns->ozcs));
	obj_add_uint(r, "mar", le32_to_cpu(ns->mar));
	obj_add_uint(r, "mor", le32_to_cpu(ns->mor));
	obj_add_uint(r, "rrl", le32_to_cpu(ns->rrl));
	obj_add_uint(r, "frl", le32_to_cpu(ns->frl));
	obj_add_uint(r, "rrl1", le32_to_cpu(ns->rrl1));
	obj_add_uint(r, "rrl2", le32_to_cpu(ns->rrl2));
	obj_add_uint(r, "rrl3", le32_to_cpu(ns->rrl3));
	obj_add_uint(r, "frl1", le32_to_cpu(ns->frl1));
	obj_add_uint(r, "frl2", le32_to_cpu(ns->frl2));
	obj_add_uint(r, "frl3", le32_to_cpu(ns->frl3));
	obj_add_uint(r, "numzrwa", le32_to_cpu(ns->numzrwa));
	obj_add_int(r, "zrwafg", le16_to_cpu(ns->zrwafg));
	obj_add_int(r, "zrwasz", le16_to_cpu(ns->zrwasz));
	obj_add_int(r, "zrwacap", ns->zrwacap);

	obj_add_array(r, "lbafe", lbafs);

	for (i = 0; i <= id_ns->nlbaf; i++) {
		struct json_object *lbaf = json_create_object();

		obj_add_uint64(lbaf, "zsze", le64_to_cpu(ns->lbafe[i].zsze));
		obj_add_int(lbaf, "zdes", ns->lbafe[i].zdes);

		array_add_obj(lbafs, lbaf);
	}

	json_print(r);
}

static void json_nvme_list_ns(struct nvme_ns_list *ns_list)
{
	struct json_object *r = json_create_object();
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

	json_print(r);
}

static void json_zns_start_zone_list(__u64 nr_zones, struct json_object **zone_list)
{
	*zone_list = json_create_array();
}

static void json_zns_changed(struct nvme_zns_changed_zone_log *log)
{
	struct json_object *r = json_create_object();
	char json_str[STR_LEN];
	uint16_t nrzid = le16_to_cpu(log->nrzid);
	int i;

	if (nrzid == 0xFFFF) {
		obj_add_result(r, "Too many zones have changed to fit into the log. Use report zones for changes.");
	} else {
		obj_add_uint(r, "nrzid", nrzid);
		for (i = 0; i < nrzid; i++) {
			sprintf(json_str, "zid %03d", i);
			obj_add_uint64(r, json_str, (uint64_t)le64_to_cpu(log->zid[i]));
		}
	}

	json_print(r);
}

static void json_zns_finish_zone_list(__u64 nr_zones,
				      struct json_object *zone_list)
{
	struct json_object *r = json_create_object();

	obj_add_uint(r, "nr_zones", nr_zones);
	obj_add_array(r, "zone_list", zone_list);

	json_print(r);
}

static void json_nvme_zns_report_zones(void *report, __u32 descs,
				       __u8 ext_size, __u32 report_size,
				       struct json_object *zone_list)
{
	struct json_object *zone;
	struct json_object *ext_data;
	struct nvme_zone_report *r = report;
	struct nvme_zns_desc *desc;
	int i;

	for (i = 0; i < descs; i++) {
		desc = (struct nvme_zns_desc *)
			(report + sizeof(*r) + i * (sizeof(*desc) + ext_size));
		zone = json_create_object();

		obj_add_uint64(zone, "slba", le64_to_cpu(desc->zslba));
		obj_add_uint64(zone, "wp", le64_to_cpu(desc->wp));
		obj_add_uint64(zone, "cap", le64_to_cpu(desc->zcap));
		obj_add_str(zone, "state", nvme_zone_state_to_string(desc->zs >> 4));
		obj_add_str(zone, "type", nvme_zone_type_to_string(desc->zt));
		obj_add_uint(zone, "attrs", desc->za);
		obj_add_uint(zone, "attrs_info", desc->zai);

		if (ext_size) {
			if (desc->za & NVME_ZNS_ZA_ZDEV) {
				ext_data = json_create_array();
				d_json((unsigned char *)desc + sizeof(*desc),
					ext_size, 16, 1, ext_data);
				obj_add_array(zone, "ext_data", ext_data);
			} else {
				obj_add_str(zone, "ext_data", "Not valid");
			}
		}

		array_add_obj(zone_list, zone);
	}
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
}

static void json_lba_range_entry(struct nvme_lba_range_type *lbrt, int nr_ranges,
				 struct json_object *r)
{
	char json_str[STR_LEN];
	struct json_object *lbare;
	int i;
	int j;
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

		for (j = 0; j < ARRAY_SIZE(lbrt->entry[i].guid); j++)
			sprintf(&json_str[j * 2], "%02x", lbrt->entry[i].guid[j]);

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

	obj_add_str(r, "Discovery Log Page Change Notices", NVME_FEAT_AE_DLPCN(result) ?
			async : no_async);
	obj_add_str(r, "Host Discovery Log Page Change Notification", NVME_FEAT_AE_HDLPCN(result) ?
			async : no_async);
	obj_add_str(r, "AVE Discovery Log Page Change Notification", NVME_FEAT_AE_ADLPCN(result) ?
			async : no_async);
	obj_add_str(r, "Pull Model DDC Request Log Page Change Notification",
			NVME_FEAT_AE_PMDRLPCN(result) ? async : no_async);
	obj_add_str(r, "Zone Descriptor Changed Notices", NVME_FEAT_AE_ZDCN(result) ?
			async : no_async);
	obj_add_str(r, "Reachability Group", NVME_FEAT_AE_RGRP0(result) ? async : no_async);
	obj_add_str(r, "Reachability Association", NVME_FEAT_AE_RASSN(result) ? async : no_async);
	obj_add_str(r, "Normal NVM Subsystem Shutdown", NVME_FEAT_AE_NNSSHDN(result) ?
			async : no_async);
	obj_add_str(r, "Endurance Group Event Aggregate Log Change Notices",
			NVME_FEAT_AE_EGA(result) ? async : no_async);
	obj_add_str(r, "LBA Status Information Notices", NVME_FEAT_AE_LBAS(result) ?
			async : no_async);
	obj_add_str(r, "Predictable Latency Event Aggregate Log Change Notices",
			NVME_FEAT_AE_PLA(result) ? async : no_async);
	obj_add_str(r, "Asymmetric Namespace Access Change Notices", NVME_FEAT_AE_ANA(result) ?
			async : no_async);
	obj_add_str(r, "Telemetry Log Notices", NVME_FEAT_AE_TELEM(result) ? async : no_async);
	obj_add_str(r, "Firmware Activation Notices", NVME_FEAT_AE_FW(result) ? async : no_async);
	obj_add_str(r, "Namespace Attribute Notices", NVME_FEAT_AE_NAN(result) ? async : no_async);
	obj_add_str(r, "SMART / Health Critical Warnings", NVME_FEAT_AE_SMART(result) ?
			async : no_async);
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

static void json_timestamp(struct json_object *r, struct nvme_timestamp *ts)
{
	char buffer[BUF_LEN];
	time_t timestamp = int48_to_long(ts->timestamp) / 1000;
	struct tm *tm = localtime(&timestamp);

	obj_add_uint64(r, "timestamp", int48_to_long(ts->timestamp));

	if (!strftime(buffer, sizeof(buffer), "%c %Z", tm))
		sprintf(buffer, "%s", "-");

	obj_add_str(r, "timestamp string", buffer);

	obj_add_str(r, "timestamp origin", ts->attr & 2 ?
	    "The Timestamp field was initialized with a Timestamp value using a Set Features command." :
	    "The Timestamp field was initialized to 0h by a Controller Level Reset.");

	obj_add_str(r, "synch", ts->attr & 1 ?
	    "The controller may have stopped counting during vendor specific intervals after the Timestamp value was initialized." :
	    "The controller counted time in milliseconds continuously since the Timestamp value was initialized.");
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
		obj_add_str(paide, json_str, util_uuid_to_string(data->id_list[i].id));
	}
}

static void json_feat_perfc_vs(struct json_object *r, struct nvme_vs_perf_attr *data)
{
	obj_add_str(r, "performance attribute identifier (PAID)", util_uuid_to_string(data->paid));
	obj_add_uint(r, "attribute length (ATTRL)", data->attrl);
	obj_d(r, "vendor specific (VS)", (unsigned char *)data->vs, data->attrl, 16, 1);
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
	struct nvme_metadata_element_desc *desc = &data->descs[0];
	int i;
	char val[VAL_LEN];
	__u16 len;
	char json_str[STR_LEN];
	struct json_object *desca = json_create_array();
	struct json_object *desce;

	obj_add_int(r, "Num Metadata Element Descriptors", data->ndesc);

	obj_add_array(r, "Metadata Element Descriptors", desca);

	for (i = 0; i < data->ndesc; i++) {
		desce = json_create_object();
		array_add_obj(desca, desce);

		obj_add_int(desce, "Element", i);

		sprintf(json_str, "0x%02x", desc->type);
		obj_add_str(desce, "Type", json_str);

		obj_add_str(desce, "Type definition",
			    nvme_host_metadata_type_to_string(fid, desc->type));

		obj_add_int(desce, "Revision", desc->rev);

		len = le16_to_cpu(desc->len);
		obj_add_int(desce, "Length", len);

		strncpy(val, (char *)desc->val, min(sizeof(val) - 1, len));
		obj_add_str(desce, "Value", val);

		desc = (struct nvme_metadata_element_desc *)&desc->val[desc->len];
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

static void json_feature_show_fields_host_id(struct json_object *r, unsigned char *buf)
{
	uint64_t ull = 0;
	int i;

	if (buf) {
		for (i = sizeof(ull) / sizeof(*buf); i; i--) {
			ull |=  buf[i - 1];
			if (i - 1)
				ull <<= BYTE_TO_BIT(sizeof(buf[i]));
		}
		obj_add_uint64(r, "Host Identifier (HOSTID)", ull);
	}
}

static void json_feature_show_fields_resv_mask(struct json_object *r, unsigned int result)
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

	for (i = 0; i < result; i++) {
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

static void json_feature_show(enum nvme_features_id fid, int sel, unsigned int result)
{
	struct json_object *r;
	char json_str[STR_LEN];

	sprintf(json_str, "feature: %#0*x", fid ? 4 : 2, fid);
	r = obj_create(json_str);

	obj_add_str(r, "name", nvme_feature_to_string(fid));

	sprintf(json_str, "%#0*x", result ? 10 : 8, result);
	obj_add_str(r, nvme_select_to_string(sel), json_str);

	obj_print(r);
}

static void json_feature_show_fields(enum nvme_features_id fid, unsigned int result,
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
		json_feature_show_fields_host_id(r, buf);
		break;
	case NVME_FEAT_FID_RESV_MASK:
		json_feature_show_fields_resv_mask(r, result);
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
	default:
		break;
	}

	obj_print(r);
}

void json_id_ctrl_rpmbs(__le32 ctrl_rpmbs)
{
	struct json_object *r = json_create_object();
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

	json_print(r);
}

static void json_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges)
{
	struct json_object *r = json_create_object();

	json_lba_range_entry(lbrt, nr_ranges, r);

	json_print(r);
}

static void json_lba_status_info(__u32 result)
{
	struct json_object *r = json_create_object();

	obj_add_uint(r, "LBA Status Information Poll Interval (LSIPI)", (result >> 16) & 0xffff);
	obj_add_uint(r, "LBA Status Information Report Interval (LSIRI)", result & 0xffff);

	json_print(r);
}

void json_d(unsigned char *buf, int len, int width, int group)
{
	struct json_object *r = json_r ? json_r : json_create_object();
	char json_str[STR_LEN];

	sprintf(json_str, "data: buf=%p len=%d width=%d group=%d", buf, len, width, group);
	obj_d(r, json_str, buf, len, width, group);

	obj_print(r);
}

static void json_nvme_list_ctrl(struct nvme_ctrl_list *ctrl_list)
{
	__u16 num = le16_to_cpu(ctrl_list->num);
	struct json_object *r = json_create_object();
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

	json_print(r);
}

static void json_nvme_id_nvmset(struct nvme_id_nvmset_list *nvmset,
				unsigned int nvmeset_id)
{
	__u32 nent = nvmset->nid;
	struct json_object *entries = json_create_array();
	struct json_object *r = json_create_object();
	int i;

	obj_add_int(r, "nid", nent);

	for (i = 0; i < nent; i++) {
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

	json_print(r);
}

static void json_nvme_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *caps)
{
	struct json_object *r = json_create_object();

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

	json_print(r);
}

static void json_nvme_list_secondary_ctrl(const struct nvme_secondary_ctrl_list *sc_list,
					  __u32 count)
{
	const struct nvme_secondary_ctrl *sc_entry = &sc_list->sc_entry[0];
	__u32 nent = min(sc_list->num, count);
	struct json_object *entries = json_create_array();
	struct json_object *r = json_create_object();
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

	json_print(r);
}

static void json_nvme_id_ns_granularity_list(
		const struct nvme_id_ns_granularity_list *glist)
{
	int i;
	struct json_object *r = json_create_object();
	struct json_object *entries = json_create_array();

	obj_add_int(r, "attributes", glist->attributes);
	obj_add_int(r, "num-descriptors", glist->num_descriptors);

	for (i = 0; i <= glist->num_descriptors; i++) {
		struct json_object *entry = json_create_object();

		obj_add_uint64(entry, "namespace-size-granularity",
			       le64_to_cpu(glist->entry[i].nszegran));
		obj_add_uint64(entry, "namespace-capacity-granularity",
			       le64_to_cpu(glist->entry[i].ncapgran));
		array_add_obj(entries, entry);
	}

	obj_add_array(r, "namespace-granularity-list", entries);

	json_print(r);
}

static void json_nvme_id_uuid_list(const struct nvme_id_uuid_list *uuid_list)
{
	struct json_object *r = json_create_object();
	struct json_object *entries = json_create_array();
	int i;

	for (i = 0; i < NVME_ID_UUID_LIST_MAX; i++) {
		__u8 uuid[NVME_UUID_LEN];
		struct json_object *entry = json_create_object();

		/* The list is terminated by a zero UUID value */
		if (memcmp(uuid_list->entry[i].uuid, zero_uuid, sizeof(zero_uuid)) == 0)
			break;
		memcpy(&uuid, uuid_list->entry[i].uuid, sizeof(uuid));
		obj_add_int(entry, "association",
			uuid_list->entry[i].header & 0x3);
		obj_add_str(entry, "uuid",
			util_uuid_to_string(uuid));
		array_add_obj(entries, entry);
	}

	obj_add_array(r, "UUID-list", entries);

	json_print(r);
}

static void json_id_domain_list(struct nvme_id_domain_list *id_dom)
{
	struct json_object *r = json_create_object();
	struct json_object *entries = json_create_array();
	struct json_object *entry;
	int i;
	nvme_uint128_t dom_cap, unalloc_dom_cap, max_egrp_dom_cap;

	obj_add_uint(r, "num_dom_entries", id_dom->num);

	for (i = 0; i < id_dom->num; i++) {
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

	json_print(r);
}

static void json_nvme_endurance_group_list(struct nvme_id_endurance_group_list *endgrp_list)
{
	struct json_object *r = json_create_object();
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

	json_print(r);
}

static void json_support_log(struct nvme_supported_log_pages *support_log,
			     const char *devname)
{
	struct json_object *r = json_create_object();
	struct json_object *valid = json_create_array();
	struct json_object *valid_attrs;
	unsigned int lid;
	char key[128];
	__u32 support;

	for (lid = 0; lid < 256; lid++) {
		support = le32_to_cpu(support_log->lid_support[lid]);
		if (support & 0x1) {
			valid_attrs = json_create_object();
			sprintf(key, "lid_0x%x ", lid);
			obj_add_uint(valid_attrs, key, support);
			array_add_obj(valid, valid_attrs);
		}
	}

	obj_add_array(r, "supported_logs", valid);

	json_print(r);
}

static void json_detail_list(nvme_root_t t)
{
	struct json_object *r = json_create_object();
	struct json_object *jdev = json_create_array();

	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	nvme_path_t p;
	nvme_ns_t n;

	nvme_for_each_host(t, h) {
		struct json_object *hss = json_create_object();
		struct json_object *jsslist = json_create_array();
		const char *hostid;

		obj_add_str(hss, "HostNQN", nvme_host_get_hostnqn(h));
		hostid = nvme_host_get_hostid(h);
		if (hostid)
			obj_add_str(hss, "HostID", hostid);

		nvme_for_each_subsystem(h, s) {
			struct json_object *jss = json_create_object();
			struct json_object *jctrls = json_create_array();
			struct json_object *jnss = json_create_array();

			obj_add_str(jss, "Subsystem", nvme_subsystem_get_name(s));
			obj_add_str(jss, "SubsystemNQN", nvme_subsystem_get_nqn(s));

			nvme_subsystem_for_each_ctrl(s, c) {
				struct json_object *jctrl = json_create_object();
				struct json_object *jnss = json_create_array();
				struct json_object *jpaths = json_create_array();

				obj_add_str(jctrl, "Controller", nvme_ctrl_get_name(c));
				obj_add_str(jctrl, "Cntlid", nvme_ctrl_get_cntlid(c));
				obj_add_str(jctrl, "SerialNumber", nvme_ctrl_get_serial(c));
				obj_add_str(jctrl, "ModelNumber", nvme_ctrl_get_model(c));
				obj_add_str(jctrl, "Firmware", nvme_ctrl_get_firmware(c));
				obj_add_str(jctrl, "Transport", nvme_ctrl_get_transport(c));
				obj_add_str(jctrl, "Address", nvme_ctrl_get_address(c));
				obj_add_str(jctrl, "Slot", nvme_ctrl_get_phy_slot(c));

				nvme_ctrl_for_each_ns(c, n) {
					struct json_object *jns = json_create_object();
					int lba = nvme_ns_get_lba_size(n);
					uint64_t nsze = nvme_ns_get_lba_count(n) * lba;
					uint64_t nuse = nvme_ns_get_lba_util(n) * lba;

					obj_add_str(jns, "NameSpace", nvme_ns_get_name(n));
					obj_add_str(jns, "Generic", nvme_ns_get_generic_name(n));
					obj_add_int(jns, "NSID", nvme_ns_get_nsid(n));
					obj_add_uint64(jns, "UsedBytes", nuse);
					obj_add_uint64(jns, "MaximumLBA", nvme_ns_get_lba_count(n));
					obj_add_uint64(jns, "PhysicalSize", nsze);
					obj_add_int(jns, "SectorSize", lba);

					array_add_obj(jnss, jns);
				}
				obj_add_obj(jctrl, "Namespaces", jnss);

				nvme_ctrl_for_each_path(c, p) {
					struct json_object *jpath = json_create_object();

					obj_add_str(jpath, "Path", nvme_path_get_name(p));
					obj_add_str(jpath, "ANAState", nvme_path_get_ana_state(p));

					array_add_obj(jpaths, jpath);
				}
				obj_add_obj(jctrl, "Paths", jpaths);

				array_add_obj(jctrls, jctrl);
			}
			obj_add_obj(jss, "Controllers", jctrls);

			nvme_subsystem_for_each_ns(s, n) {
				struct json_object *jns = json_create_object();

				int lba = nvme_ns_get_lba_size(n);
				uint64_t nsze = nvme_ns_get_lba_count(n) * lba;
				uint64_t nuse = nvme_ns_get_lba_util(n) * lba;

				obj_add_str(jns, "NameSpace", nvme_ns_get_name(n));
				obj_add_str(jns, "Generic", nvme_ns_get_generic_name(n));
				obj_add_int(jns, "NSID", nvme_ns_get_nsid(n));
				obj_add_uint64(jns, "UsedBytes", nuse);
				obj_add_uint64(jns, "MaximumLBA", nvme_ns_get_lba_count(n));
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

	json_print(r);
}

static struct json_object *json_list_item_obj(nvme_ns_t n)
{
	struct json_object *r = json_create_object();
	char devname[NAME_LEN] = { 0 };
	char genname[NAME_LEN] = { 0 };
	int lba = nvme_ns_get_lba_size(n);
	uint64_t nsze = nvme_ns_get_lba_count(n) * lba;
	uint64_t nuse = nvme_ns_get_lba_util(n) * lba;

	nvme_dev_full_path(n, devname, sizeof(devname));
	nvme_generic_full_path(n, genname, sizeof(genname));

	obj_add_int(r, "NameSpace", nvme_ns_get_nsid(n));
	obj_add_str(r, "DevicePath", devname);
	obj_add_str(r, "GenericPath", genname);
	obj_add_str(r, "Firmware", nvme_ns_get_firmware(n));
	obj_add_str(r, "ModelNumber", nvme_ns_get_model(n));
	obj_add_str(r, "SerialNumber", nvme_ns_get_serial(n));
	obj_add_uint64(r, "UsedBytes", nuse);
	obj_add_uint64(r, "MaximumLBA", nvme_ns_get_lba_count(n));
	obj_add_uint64(r, "PhysicalSize", nsze);
	obj_add_int(r, "SectorSize", lba);

	return r;
}

static void json_simple_list(nvme_root_t t)
{
	struct json_object *r = json_create_object();
	struct json_object *jdevices = json_create_array();

	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	nvme_ns_t n;

	nvme_for_each_host(t, h) {
		nvme_for_each_subsystem(h, s) {
			nvme_subsystem_for_each_ns(s, n)
				array_add_obj(jdevices, json_list_item_obj(n));

			nvme_subsystem_for_each_ctrl(s, c) {
				nvme_ctrl_for_each_ns(c, n)
					array_add_obj(jdevices, json_list_item_obj(n));
			}
		}
	}

	obj_add_array(r, "Devices", jdevices);

	json_print(r);
}

static void json_list_item(nvme_ns_t n)
{
	struct json_object *r = json_list_item_obj(n);

	json_print(r);
}

static void json_print_list_items(nvme_root_t t)
{
	if (verbose_mode())
		json_detail_list(t);
	else
		json_simple_list(t);
}

static unsigned int json_subsystem_topology_multipath(nvme_subsystem_t s,
						      json_object *namespaces)
{
	nvme_ns_t n;
	nvme_path_t p;
	unsigned int i = 0;

	nvme_subsystem_for_each_ns(s, n) {
		struct json_object *ns_attrs;
		struct json_object *paths;

		ns_attrs = json_create_object();
		obj_add_int(ns_attrs, "NSID", nvme_ns_get_nsid(n));

		paths = json_create_array();
		nvme_namespace_for_each_path(n, p) {
			struct json_object *path_attrs;

			nvme_ctrl_t c = nvme_path_get_ctrl(p);

			path_attrs = json_create_object();
			obj_add_str(path_attrs, "Name", nvme_ctrl_get_name(c));
			obj_add_str(path_attrs, "Transport", nvme_ctrl_get_transport(c));
			obj_add_str(path_attrs, "Address", nvme_ctrl_get_address(c));
			obj_add_str(path_attrs, "State", nvme_ctrl_get_state(c));
			obj_add_str(path_attrs, "ANAState", nvme_path_get_ana_state(p));
			array_add_obj(paths, path_attrs);
		}
		obj_add_array(ns_attrs, "Paths", paths);
		array_add_obj(namespaces, ns_attrs);
		i++;
	}

	return i;
}

static void json_print_nvme_subsystem_topology(nvme_subsystem_t s,
					       json_object *namespaces)
{
	nvme_ctrl_t c;
	nvme_ns_t n;

	nvme_subsystem_for_each_ctrl(s, c) {
		nvme_ctrl_for_each_ns(c, n) {
			struct json_object *ctrl_attrs;
			struct json_object *ns_attrs;
			struct json_object *ctrl;

			ns_attrs = json_create_object();
			obj_add_int(ns_attrs, "NSID", nvme_ns_get_nsid(n));

			ctrl = json_create_array();
			ctrl_attrs = json_create_object();
			obj_add_str(ctrl_attrs, "Name",
						     nvme_ctrl_get_name(c));
			obj_add_str(ctrl_attrs, "Transport",
						     nvme_ctrl_get_transport(c));
			obj_add_str(ctrl_attrs, "Address",
						     nvme_ctrl_get_address(c));
			obj_add_str(ctrl_attrs, "State",
						     nvme_ctrl_get_state(c));

			array_add_obj(ctrl, ctrl_attrs);
			obj_add_array(ns_attrs, "Controller", ctrl);
			array_add_obj(namespaces, ns_attrs);
		}
	}
}

static void json_simple_topology(nvme_root_t r)
{
	struct json_object *host_attrs, *subsystem_attrs;
	struct json_object *subsystems, *namespaces;
	struct json_object *a = json_create_array();
	nvme_host_t h;

	nvme_for_each_host(r, h) {
		nvme_subsystem_t s;
		const char *hostid;

		host_attrs = json_create_object();
		obj_add_str(host_attrs, "HostNQN", nvme_host_get_hostnqn(h));
		hostid = nvme_host_get_hostid(h);
		if (hostid)
			obj_add_str(host_attrs, "HostID", hostid);
		subsystems = json_create_array();
		nvme_for_each_subsystem(h, s) {
			subsystem_attrs = json_create_object();
			obj_add_str(subsystem_attrs, "Name", nvme_subsystem_get_name(s));
			obj_add_str(subsystem_attrs, "NQN", nvme_subsystem_get_nqn(s));

			if (verbose_mode()) {
				obj_add_str(subsystem_attrs, "Model",
						nvme_subsystem_get_model(s));
				obj_add_str(subsystem_attrs, "Serial",
						nvme_subsystem_get_serial(s));
				obj_add_str(subsystem_attrs, "Firmware",
						nvme_subsystem_get_fw_rev(s));
				obj_add_str(subsystem_attrs, "IOPolicy",
						nvme_subsystem_get_iopolicy(s));
				obj_add_str(subsystem_attrs, "Type",
						nvme_subsystem_get_type(s));
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

static void json_directive_show_fields_identify(__u8 doper, __u8 *field, struct json_object *r)
{
	struct json_object *support;
	struct json_object *enabled;
	struct json_object *persistent;

	switch (doper) {
	case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
		support = json_create_array();
		obj_add_array(r, "Directive support", support);
		obj_add_str(support, "Identify Directive",
			    *field & 0x1 ? "Supported" : "Not supported");
		obj_add_str(support, "Stream Directive",
			    *field & 0x2 ? "Supported" : "Not supported");
		obj_add_str(support, "Data Placement Directive",
			    *field & 0x4 ? "Supported" : "Not supported");
		enabled = json_create_array();
		obj_add_array(r, "Directive enabled", enabled);
		obj_add_str(enabled, "Identify Directive",
			    *(field + 32) & 0x1 ? "Enabled" : "Disabled");
		obj_add_str(enabled, "Stream Directive",
			    *(field + 32) & 0x2 ? "Enabled" : "Disabled");
		obj_add_str(enabled, "Data Placement Directive",
			    *(field + 32) & 0x4 ? "Enabled" : "Disabled");
		persistent = json_create_array();
		obj_add_array(r, "Directive Persistent Across Controller Level Resets",
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

static void json_directive_show_fields_streams(__u8 doper,  unsigned int result, __u16 *field,
					       struct json_object *r)
{
	int count;
	int i;
	char json_str[STR_LEN];

	switch (doper) {
	case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
		obj_add_uint(r, "Max Streams Limit (MSL)", le16_to_cpu(*field));
		obj_add_uint(r, "NVM Subsystem Streams Available (NSSA)", le16_to_cpu(*(field + 2)));
		obj_add_uint(r, "NVM Subsystem Streams Open (NSSO)", le16_to_cpu(*(field + 4)));
		obj_add_uint(r, "NVM Subsystem Stream Capability (NSSC)", le16_to_cpu(*(field + 6)));
		obj_add_uint(r, "Stream Write Size (in unit of LB size) (SWS)",
			     le16_to_cpu(*(__u32 *)(field + 16)));
		obj_add_uint(r, "Stream Granularity Size (in unit of SWS) (SGS)",
			     le16_to_cpu(*(field + 20)));
		obj_add_uint(r, "Namespace Streams Allocated (NSA)", le16_to_cpu(*(field + 22)));
		obj_add_uint(r, "Namespace Streams Open (NSO)", le16_to_cpu(*(field + 24)));
		break;
	case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
		count = *field;
		obj_add_uint(r, "Open Stream Count", le16_to_cpu(*field));
		for (i = 0; i < count; i++) {
			sprintf(json_str, "Stream Identifier %.6u", i + 1);
			obj_add_uint(r, json_str, le16_to_cpu(*(field + (i + 1) * 2)));
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
				       __u8 *field, struct json_object *r)
{
	switch (dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		json_directive_show_fields_identify(doper, field, r);
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		json_directive_show_fields_streams(doper, result, (__u16 *)field, r);
		break;
	default:
		obj_add_str(r, "Error", "invalid directive type");
		break;
	}
}

static void json_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u32 result,
				void *buf, __u32 len)
{
	struct json_object *r = json_create_object();
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
	sprintf(json_str, "%#x", result);
	obj_add_result(r, json_str);

	if (verbose_mode()) {
		json_directive_show_fields(type, oper, result, buf, r);
	} else if (buf) {
		data = json_create_array();
		d_json((unsigned char *)buf, len, 16, 1, data);
		obj_add_array(r, "data", data);
	}

	json_print(r);
}

static void json_discovery_log(struct nvmf_discovery_log *log, int numrec)
{
	struct json_object *r = json_create_object();
	struct json_object *entries = json_create_array();
	int i;

	obj_add_uint64(r, "genctr", le64_to_cpu(log->genctr));
	obj_add_array(r, "records", entries);

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_log_entry *e = &log->entries[i];
		struct json_object *entry = json_create_object();

		obj_add_str(entry, "trtype", nvmf_trtype_str(e->trtype));
		obj_add_str(entry, "adrfam", nvmf_adrfam_str(e->adrfam));
		obj_add_str(entry, "subtype", nvmf_subtype_str(e->subtype));
		obj_add_str(entry, "treq", nvmf_treq_str(e->treq));
		obj_add_uint(entry, "portid", le16_to_cpu(e->portid));
		obj_add_str(entry, "trsvcid", e->trsvcid);
		obj_add_str(entry, "subnqn", e->subnqn);
		obj_add_str(entry, "traddr", e->traddr);
		obj_add_str(entry, "eflags", nvmf_eflags_str(le16_to_cpu(e->eflags)));

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			obj_add_str(entry, "rdma_prtype", nvmf_prtype_str(e->tsas.rdma.prtype));
			obj_add_str(entry, "rdma_qptype", nvmf_qptype_str(e->tsas.rdma.qptype));
			obj_add_str(entry, "rdma_cms", nvmf_cms_str(e->tsas.rdma.cms));
			obj_add_uint(entry, "rdma_pkey", le16_to_cpu(e->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			obj_add_str(entry, "sectype", nvmf_sectype_str(e->tsas.tcp.sectype));
			break;
		default:
			break;
		}
		array_add_obj(entries, entry);
	}

	json_print(r);
}

static void json_connect_msg(nvme_ctrl_t c)
{
	struct json_object *r = json_create_object();

	obj_add_str(r, "device", nvme_ctrl_get_name(c));

	json_print(r);
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
		obj_add_str(r, "error", nvme_strerror(errno));
		obj_print(r);
		return;
	}

	val = nvme_status_get_value(status);
	type = nvme_status_get_type(status);

	switch (type) {
	case NVME_STATUS_TYPE_NVME:
		obj_add_str(r, "error", nvme_status_to_string(val, false));
		obj_add_str(r, "type", "nvme");
		break;
	case NVME_STATUS_TYPE_MI:
		obj_add_str(r, "error", nvme_mi_status_to_string(val));
		obj_add_str(r, "type", "nvme-mi");
		break;
	default:
		obj_add_str(r, "type", "Unknown");
		break;
	}

	obj_print(r);
}

static void json_output_error_status(int status, const char *msg, va_list ap)
{
	struct json_object *r;
	char json_str[STR_LEN];
	int val;
	int type;

	_cleanup_free_ char *value = NULL;

	if (vasprintf(&value, msg, ap) < 0)
		value = alloc_error;

	sprintf(json_str, "Error: %s", value);
	r = obj_create(json_str);

	if (status < 0) {
		obj_add_str(r, "error", nvme_strerror(errno));
		obj_print(r);
		return;
	}

	val = nvme_status_get_value(status);
	type = nvme_status_get_type(status);

	switch (type) {
	case NVME_STATUS_TYPE_NVME:
		obj_add_str(r, "status", nvme_status_to_string(val, false));
		obj_add_str(r, "type", "nvme");
		break;
	case NVME_STATUS_TYPE_MI:
		obj_add_str(r, "status", nvme_mi_status_to_string(val));
		obj_add_str(r, "type", "nvme-mi");
		break;
	default:
		obj_add_str(r, "type", "Unknown");
		break;
	}

	obj_add_int(r, "value", val);

	obj_print(r);
}

static void json_output_message(bool error, const char *msg, va_list ap)
{
	struct json_object *r = json_r ? json_r : json_create_object();

	_cleanup_free_ char *value = NULL;

	if (vasprintf(&value, msg, ap) < 0)
		value = alloc_error;

	obj_add_str(r, error ? "error" : "result", value);

	obj_print(r);
}

static void json_output_perror(const char *msg, va_list ap)
{
	struct json_object *r = json_create_object();

	_cleanup_free_ char *error = NULL;

	if (vasprintf(&error, msg, ap) < 0)
		error = alloc_error;

	obj_add_key(r, "error", "%s: %s", error, strerror(errno));

	json_output_object(r);
}

static char *trim_white_space(char *str)
{
	char *end;

	if (!str)
		return NULL;

	/* Trim leading space */
	while (isspace((unsigned char)*str))
		str++;

	/* All spaces */
	if (!*str)
		return str;

	/* Trim trailing space */
	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end))
		end--;

	/* Write new null terminator character */
	end[1] = '\0';

	return str;
}

static void json_output_key_value(const char *key, const char *val, va_list ap)
{
	struct json_object *r = json_r ? json_r : json_create_object();

	_cleanup_free_ char *value = NULL;
	_cleanup_free_ char *key_trim = trim_white_space(strdup(key));

	if (vasprintf(&value, val, ap) < 0)
		value = NULL;

	obj_add_str(r, key_trim ? key_trim : key, value ? value : "Could not allocate string");

	obj_print(r);
}

void json_show_init(void)
{
	json_init++;

	if (!json_r)
		json_r = json_create_object();
}

void json_show_finish(void)
{
	if (--json_init)
		return;

	if (json_r)
		json_output_object(json_r);

	json_r = NULL;
}

static void json_mgmt_addr_list_log(struct nvme_mgmt_addr_list_log *ma_list)
{
	int i;
	bool reserved = true;
	struct json_object *r = json_create_object();
	struct json_object *mad;
	struct json_object *mat;
	char json_str[STR_LEN];

	for (i = 0; i < ARRAY_SIZE(ma_list->mad); i++) {
		switch (ma_list->mad[i].mat) {
		case 1:
		case 2:
			mad = json_create_object();
			mat = json_create_object();
			obj_add_str(mat, "definition", ma_list->mad[i].mat == 1 ?
				    "NVM subsystem management agent" : "fabric interface manager");
			snprintf(json_str, sizeof(json_str), "type: %d", ma_list->mad[i].mat);
			obj_add_obj(mad, json_str, mat);
			obj_add_str(mad, "address", (const char *)ma_list->mad[i].madrs);
			snprintf(json_str, sizeof(json_str), "descriptor: %d", i);
			obj_add_obj(r, json_str, mad);
			reserved = false;
			break;
		case 0xff:
			goto out;
		default:
			break;
		}
	}

out:
	if (reserved)
		obj_add_str(r, "list", "All management address descriptors reserved");

	json_print(r);
}

static void json_rotational_media_info_log(struct nvme_rotational_media_info_log *info)
{
	struct json_object *r = json_create_object();

	obj_add_uint(r, "endgid", le16_to_cpu(info->endgid));
	obj_add_uint(r, "numa", le16_to_cpu(info->numa));
	obj_add_uint(r, "nrs", le16_to_cpu(info->nrs));
	obj_add_uint(r, "spinc", le32_to_cpu(info->spinc));
	obj_add_uint(r, "fspinc", le32_to_cpu(info->fspinc));
	obj_add_uint(r, "ldc", le32_to_cpu(info->ldc));
	obj_add_uint(r, "fldc", le32_to_cpu(info->fldc));

	json_print(r);
}

static void json_dispersed_ns_psub_log(struct nvme_dispersed_ns_participating_nss_log *log)
{
	struct json_object *r = json_create_object();
	__u64 numpsub = le64_to_cpu(log->numpsub);
	__u64 i;
	char json_str[STR_LEN];
	char psub[NVME_NQN_LENGTH + 1];

	obj_add_uint64(r, "genctr", le64_to_cpu(log->genctr));
	obj_add_uint64(r, "numpsub", numpsub);
	for (i = 0; i < numpsub; i++) {
		snprintf(json_str, sizeof(json_str), "participating_nss %"PRIu64"", (uint64_t)i);
		snprintf(psub, sizeof(psub), "%-.*s", NVME_NQN_LENGTH,
			 &log->participating_nss[i * NVME_NQN_LENGTH]);
		obj_add_str(r, json_str, psub);
	}

	json_print(r);
}

static void json_reachability_groups_log(struct nvme_reachability_groups_log *log, __u64 len UNUSED)
{
	struct json_object *r = json_create_object();
	__u16 i;
	__u32 j;
	char json_str[STR_LEN];
	struct json_object *rgd;

	obj_add_uint64(r, "chngc", le64_to_cpu(log->chngc));
	obj_add_uint(r, "nrgd", le16_to_cpu(log->nrgd));

	for (i = 0; i < le16_to_cpu(log->nrgd); i++) {
		snprintf(json_str, sizeof(json_str), "rgid: %u", le32_to_cpu(log->rgd[i].rgid));
		rgd = json_create_object();
		obj_add_uint(rgd, "nnid", le32_to_cpu(log->rgd[i].nnid));
		obj_add_uint64(rgd, "chngc", le64_to_cpu(log->rgd[i].chngc));
		for (j = 0; j < le32_to_cpu(log->rgd[i].nnid); j++)
			obj_add_uint(rgd, "nnid", le32_to_cpu(log->rgd[i].nsid[j]));
		obj_add_obj(r, json_str, rgd);
	}

	json_print(r);
}

static void json_reachability_associations_log(struct nvme_reachability_associations_log *log,
					       __u64 len UNUSED)
{
	struct json_object *r = json_create_object();
	__u16 i;
	__u32 j;
	char json_str[STR_LEN];
	struct json_object *rad;

	obj_add_uint64(r, "chngc", le64_to_cpu(log->chngc));
	obj_add_uint(r, "nrad", le16_to_cpu(log->nrad));

	for (i = 0; i < le16_to_cpu(log->nrad); i++) {
		snprintf(json_str, sizeof(json_str), "rasid: %u", le32_to_cpu(log->rad[i].rasid));
		rad = json_create_object();
		obj_add_uint(rad, "nrid", le32_to_cpu(log->rad[i].nrid));
		obj_add_uint64(rad, "chngc", le64_to_cpu(log->rad[i].chngc));
		obj_add_uint(rad, "rac", log->rad[i].rac);
		for (j = 0; j < le32_to_cpu(log->rad[i].nrid); j++)
			obj_add_uint(rad, "rgid", le32_to_cpu(log->rad[i].rgid[j]));
		obj_add_obj(r, json_str, rad);
	}

	json_print(r);
}

static void json_host_discovery_log(struct nvme_host_discover_log *log)
{
	struct json_object *r = json_create_object();
	__u32 i;
	__u16 j;
	struct nvme_host_ext_discover_log *hedlpe;
	struct nvmf_ext_attr *exat;
	__u32 thdlpl = le32_to_cpu(log->thdlpl);
	__u32 tel;
	__u16 numexat;
	char json_str[STR_LEN];
	struct json_object *hedlpe_o;
	struct json_object *tsas_o;
	struct json_object *exat_o;
	int n = 0;

	obj_add_uint64(r, "genctr", le64_to_cpu(log->genctr));
	obj_add_uint64(r, "numrec", le64_to_cpu(log->numrec));
	obj_add_uint(r, "recfmt", le16_to_cpu(log->recfmt));
	obj_add_uint_02x(r, "hdlpf", log->hdlpf);
	obj_add_uint(r, "thdlpl", thdlpl);

	for (i = sizeof(*log); i < le32_to_cpu(log->thdlpl); i += tel) {
		hedlpe_o = json_create_object();
		hedlpe = (void *)log + i;
		tel = le32_to_cpu(hedlpe->tel);
		numexat = le16_to_cpu(hedlpe->numexat);
		obj_add_str(hedlpe_o, "trtype", nvmf_trtype_str(hedlpe->trtype));
		obj_add_str(hedlpe_o, "adrfam",
			    strlen(hedlpe->traddr) ? nvmf_adrfam_str(hedlpe->adrfam) : "");
		obj_add_str(hedlpe_o, "eflags", nvmf_eflags_str(le16_to_cpu(hedlpe->eflags)));
		obj_add_str(hedlpe_o, "hostnqn", hedlpe->hostnqn);
		obj_add_str(hedlpe_o, "traddr", hedlpe->traddr);
		tsas_o = json_create_object();
		switch (hedlpe->trtype) {
		case NVMF_TRTYPE_RDMA:
			obj_add_str(tsas_o, "prtype", nvmf_prtype_str(hedlpe->tsas.rdma.prtype));
			obj_add_str(tsas_o, "qptype", nvmf_qptype_str(hedlpe->tsas.rdma.qptype));
			obj_add_str(tsas_o, "cms", nvmf_cms_str(hedlpe->tsas.rdma.cms));
			obj_add_uint_0nx(tsas_o, "pkey", le16_to_cpu(hedlpe->tsas.rdma.pkey), 4);
			break;
		case NVMF_TRTYPE_TCP:
			obj_add_str(tsas_o, "sectype", nvmf_sectype_str(hedlpe->tsas.tcp.sectype));
			break;
		default:
			obj_d(tsas_o, "common", (unsigned char *)hedlpe->tsas.common,
			      sizeof(hedlpe->tsas.common), 16, 1);
			break;
		}
		obj_add_obj(hedlpe_o, "tsas", tsas_o);
		obj_add_uint(hedlpe_o, "tel", tel);
		obj_add_uint(hedlpe_o, "numexat", numexat);

		exat = hedlpe->exat;
		for (j = 0; j < numexat; j++) {
			exat_o = json_create_object();
			snprintf(json_str, sizeof(json_str), "exat: %d", j);
			obj_add_uint(exat_o, "exattype", le16_to_cpu(exat->exattype));
			obj_add_uint(exat_o, "exatlen", le16_to_cpu(exat->exatlen));
			obj_d(exat_o, "exatval", (unsigned char *)exat->exatval,
			      le16_to_cpu(exat->exatlen), 16, 1);
			obj_add_obj(hedlpe_o, json_str, exat_o);
			exat = nvmf_exat_ptr_next(exat);
		}
		snprintf(json_str, sizeof(json_str), "hedlpe: %d", n++);
		obj_add_obj(r, json_str, hedlpe_o);
	}
}

static void obj_add_traddr(struct json_object *o, const char *k, __u8 adrfam, __u8 *traddr)
{
	int af = AF_INET;
	socklen_t size = INET_ADDRSTRLEN;
	char dst[INET6_ADDRSTRLEN];

	if (adrfam == NVMF_ADDR_FAMILY_IP6) {
		af = AF_INET6;
		size = INET6_ADDRSTRLEN;
	}

	if (inet_ntop(af, nvmf_adrfam_str(adrfam), dst, size))
		obj_add_str(o, k, dst);
}

static void json_ave_discovery_log(struct nvme_ave_discover_log *log)
{
	struct json_object *r = json_create_object();
	__u32 i;
	__u8 j;
	struct nvme_ave_discover_log_entry *adlpe;
	struct nvme_ave_tr_record *atr;
	__u32 tadlpl = le32_to_cpu(log->tadlpl);
	__u32 tel;
	__u8 numatr;
	int n = 0;
	char json_str[STR_LEN];
	struct json_object *adlpe_o;
	struct json_object *atr_o;

	obj_add_uint64(r, "genctr", le64_to_cpu(log->genctr));
	obj_add_uint64(r, "numrec", le64_to_cpu(log->numrec));
	obj_add_uint(r, "recfmt", le16_to_cpu(log->recfmt));
	obj_add_uint(r, "thdlpl", tadlpl);

	for (i = sizeof(*log); i < le32_to_cpu(log->tadlpl); i += tel) {
		adlpe_o = json_create_object();
		adlpe = (void *)log + i;
		tel = le32_to_cpu(adlpe->tel);
		numatr = adlpe->numatr;
		obj_add_uint(adlpe_o, "tel", tel);
		obj_add_str(adlpe_o, "avenqn", adlpe->avenqn);
		obj_add_uint(adlpe_o, "numatr", numatr);

		atr = adlpe->atr;
		for (j = 0; j < numatr; j++) {
			atr_o = json_create_object();
			snprintf(json_str, sizeof(json_str), "atr: %d", j);
			obj_add_str(atr_o, "aveadrfam", nvmf_adrfam_str(atr->aveadrfam));
			obj_add_uint(atr_o, "avetrsvcid", le16_to_cpu(atr->avetrsvcid));
			obj_add_traddr(atr_o, "avetraddr", atr->aveadrfam, atr->avetraddr);
			obj_add_obj(adlpe_o, json_str, atr_o);
			atr++;
		}
		snprintf(json_str, sizeof(json_str), "adlpe: %d", n++);
		obj_add_obj(r, json_str, adlpe_o);
	}
}

static void json_pull_model_ddc_req_log(struct nvme_pull_model_ddc_req_log *log)
{
	struct json_object *r = json_create_object();
	__u32 tpdrpl = le32_to_cpu(log->tpdrpl);
	__u32 osp_len = tpdrpl - offsetof(struct nvme_pull_model_ddc_req_log, osp);

	obj_add_uint(r, "ori", log->ori);
	printf("tpdrpl: %u\n", tpdrpl);
	obj_d(r, "osp", (unsigned char *)log->osp, osp_len, 16, 1);
}

static struct print_ops json_print_ops = {
	/* libnvme types.h print functions */
	.ana_log			= json_ana_log,
	.boot_part_log			= json_boot_part_log,
	.phy_rx_eom_log			= json_phy_rx_eom_log,
	.ctrl_list			= json_nvme_list_ctrl,
	.ctrl_registers			= json_ctrl_registers,
	.ctrl_register			= json_ctrl_register,
	.directive			= json_directive_show,
	.discovery_log			= json_discovery_log,
	.effects_log_list		= json_effects_log_list,
	.endurance_group_event_agg_log	= json_endurance_group_event_agg_log,
	.endurance_group_list		= json_nvme_endurance_group_list,
	.endurance_log			= json_endurance_log,
	.error_log			= json_error_log,
	.fdp_config_log			= json_nvme_fdp_configs,
	.fdp_event_log			= json_nvme_fdp_events,
	.fdp_ruh_status			= json_nvme_fdp_ruh_status,
	.fdp_stats_log			= json_nvme_fdp_stats,
	.fdp_usage_log			= json_nvme_fdp_usage,
	.fid_supported_effects_log	= json_fid_support_effects_log,
	.fw_log				= json_fw_log,
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
	.lba_status_log			= json_lba_status_log,
	.media_unit_stat_log		= json_media_unit_stat_log,
	.mi_cmd_support_effects_log	= json_mi_cmd_support_effects_log,
	.ns_list			= json_nvme_list_ns,
	.ns_list_log			= json_changed_ns_list_log,
	.nvm_id_ns			= json_nvme_nvm_id_ns,
	.persistent_event_log		= json_persistent_event_log,
	.predictable_latency_event_agg_log = json_predictable_latency_event_agg_log,
	.predictable_latency_per_nvmset	= json_predictable_latency_per_nvmset,
	.primary_ctrl_cap		= json_nvme_primary_ctrl_cap,
	.resv_notification_log		= json_resv_notif_log,
	.resv_report			= json_nvme_resv_report,
	.sanitize_log_page		= json_sanitize_log,
	.secondary_ctrl_list		= json_nvme_list_secondary_ctrl,
	.select_result			= json_select_result,
	.self_test_log			= json_self_test_log,
	.single_property		= json_single_property,
	.smart_log			= json_smart_log,
	.supported_cap_config_list_log	= json_supported_cap_config_log,
	.supported_log_pages		= json_support_log,
	.zns_start_zone_list		= json_zns_start_zone_list,
	.zns_changed_zone_log		= json_zns_changed,
	.zns_finish_zone_list		= json_zns_finish_zone_list,
	.zns_id_ctrl			= json_nvme_zns_id_ctrl,
	.zns_id_ns			= json_nvme_zns_id_ns,
	.zns_report_zones		= json_nvme_zns_report_zones,
	.show_feature			= json_feature_show,
	.show_feature_fields		= json_feature_show_fields,
	.id_ctrl_rpmbs			= json_id_ctrl_rpmbs,
	.lba_range			= json_lba_range,
	.lba_status_info		= json_lba_status_info,
	.d				= json_d,
	.show_init			= json_show_init,
	.show_finish			= json_show_finish,
	.mgmt_addr_list_log		= json_mgmt_addr_list_log,
	.rotational_media_info_log	= json_rotational_media_info_log,
	.dispersed_ns_psub_log		= json_dispersed_ns_psub_log,
	.reachability_groups_log	= json_reachability_groups_log,
	.reachability_associations_log	= json_reachability_associations_log,
	.host_discovery_log		= json_host_discovery_log,
	.ave_discovery_log		= json_ave_discovery_log,
	.pull_model_ddc_req_log		= json_pull_model_ddc_req_log,

	/* libnvme tree print functions */
	.list_item			= json_list_item,
	.list_items			= json_print_list_items,
	.print_nvme_subsystem_list	= json_print_nvme_subsystem_list,
	.topology_ctrl			= json_simple_topology,
	.topology_namespace		= json_simple_topology,

	/* status and error messages */
	.connect_msg			= json_connect_msg,
	.show_message			= json_output_message,
	.show_perror			= json_output_perror,
	.show_status			= json_output_status,
	.show_error_status		= json_output_error_status,
	.show_key_value			= json_output_key_value,
};

struct print_ops *nvme_get_json_print_ops(nvme_print_flags_t flags)
{
	json_print_ops.flags = flags;
	return &json_print_ops;
}
