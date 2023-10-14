// SPDX-License-Identifier: GPL-2.0-or-later

#include <assert.h>
#include <errno.h>
#include <time.h>

#include "nvme-print.h"

#include "util/json.h"
#include "nvme.h"
#include "common.h"

#define ERROR_MSG_LEN 100
#define STR_LEN 100
#define NAME_LEN 128
#define BUF_LEN 320
#define VAL_LEN 4096
#define BYTE_TO_BIT(byte) ((byte) * 8)
#define POWER_OF_TWO(exponent) (1 << (exponent))
#define MS500_TO_SEC(time) ((time) / 2)

#define array_add_obj json_array_add_value_object
#define obj_add_array json_object_add_value_array
#define obj_add_int json_object_add_value_int
#define obj_add_str json_object_add_value_string
#define obj_add_uint json_object_add_value_uint
#define obj_add_uint64 json_object_add_value_uint64

#define root_add_array(k, v) obj_add_array(root, k, v)
#define root_add_int(k, v) obj_add_int(root, k, v)
#define root_add_int_secs(k, v) obj_add_int_secs(root, k, v)
#define root_add_prix64(k, v) obj_add_prix64(root, k, v)
#define root_add_result(v, ...) obj_add_result(root, v, ##__VA_ARGS__)
#define root_add_str(k, v) json_object_add_value_string(root, k, v)
#define root_add_uint(k, v) obj_add_uint(root, k, v)
#define root_add_uint64(k, v) obj_add_uint64(root, k, v)
#define root_add_uint_0x(k, v) obj_add_uint_0x(root, k, v)
#define root_add_uint_nx(k, v) obj_add_uint_nx(root, k, v)
#define root_add_uint_x(k, v) obj_add_uint_x(root, k, v)

static const uint8_t zero_uuid[16] = { 0 };
static struct print_ops json_print_ops;

static const char *supported = "Supported";
static const char *not_supported = "Not Supported";
static const char *yes = "Yes";
static const char *no = "No";
static const char *enabled = "Enabled";
static const char *disabled = "Disabled";
static const char *reserved = "Reserved";
static const char *true_str = "True";
static const char *false_str = "False";
static const char *result_str = "result";
static const char *error_str = "error";

static void obj_add_uint_x(struct json_object *o, const char *k, __u32 v)
{
	char str[STR_LEN];

	sprintf(str, "%x", v);
	obj_add_str(o, k, str);
}

static void obj_add_uint_0x(struct json_object *o, const char *k, __u32 v)
{
	char str[STR_LEN];

	sprintf(str, "0x%02x", v);
	obj_add_str(o, k, str);
}

static void obj_add_uint_nx(struct json_object *o, const char *k, __u32 v)
{
	char str[STR_LEN];

	sprintf(str, "%#x", v);
	obj_add_str(o, k, str);
}

static void obj_add_nprix64(struct json_object *o, const char *k, uint64_t v)
{
	char str[STR_LEN];

	sprintf(str, "%#"PRIx64"", v);
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
	va_start(ap, v);
	char *value;

	if (vasprintf(&value, v, ap) < 0)
		value = NULL;

	if (value)
		obj_add_str(o, result_str, value);
	else
		obj_add_str(o, result_str, "Could not allocate string");

	free(value);
}

static void json_print(struct json_object *root)
{
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_id_iocs(struct nvme_id_iocs *iocs)
{
	struct json_object *root = json_create_object();
	char json_str[STR_LEN];
	__u16 i;

	for (i = 0; i < ARRAY_SIZE(iocs->iocsc); i++) {
		if (iocs->iocsc[i]) {
			sprintf(json_str, "I/O Command Set Combination[%u]", i);
			root_add_uint64(json_str, le64_to_cpu(iocs->iocsc[i]));
		}
	}

	json_print(root);
}

static void json_nvme_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
			    unsigned int lba_index, bool cap_only)
{
	char nguid_buf[2 * sizeof(ns->nguid) + 1],
		eui64_buf[2 * sizeof(ns->eui64) + 1];
	char *nguid = nguid_buf, *eui64 = eui64_buf;
	struct json_object *root = json_create_object();
	struct json_object *lbafs = json_create_array();
	int i;
	nvme_uint128_t nvmcap = le128_to_cpu(ns->nvmcap);

	if (!cap_only) {
		root_add_uint64("nsze", le64_to_cpu(ns->nsze));
		root_add_uint64("ncap", le64_to_cpu(ns->ncap));
		root_add_uint64("nuse", le64_to_cpu(ns->nuse));
		root_add_int("nsfeat", ns->nsfeat);
	}

	root_add_int("nlbaf", ns->nlbaf);

	if (!cap_only)
		root_add_int("flbas", ns->flbas);

	root_add_int("mc", ns->mc);
	root_add_int("dpc", ns->dpc);

	if (!cap_only) {
		root_add_int("dps", ns->dps);
		root_add_int("nmic", ns->nmic);
		root_add_int("rescap", ns->rescap);
		root_add_int("fpi", ns->fpi);
		root_add_int("dlfeat", ns->dlfeat);
		root_add_int("nawun", le16_to_cpu(ns->nawun));
		root_add_int("nawupf", le16_to_cpu(ns->nawupf));
		root_add_int("nacwu", le16_to_cpu(ns->nacwu));
		root_add_int("nabsn", le16_to_cpu(ns->nabsn));
		root_add_int("nabo", le16_to_cpu(ns->nabo));
		root_add_int("nabspf", le16_to_cpu(ns->nabspf));
		root_add_int("noiob", le16_to_cpu(ns->noiob));
		json_object_add_value_uint128(root, "nvmcap", nvmcap);
		root_add_int("nsattr", ns->nsattr);
		root_add_int("nvmsetid", le16_to_cpu(ns->nvmsetid));

		if (ns->nsfeat & 0x10) {
			root_add_int("npwg", le16_to_cpu(ns->npwg));
			root_add_int("npwa", le16_to_cpu(ns->npwa));
			root_add_int("npdg", le16_to_cpu(ns->npdg));
			root_add_int("npda", le16_to_cpu(ns->npda));
			root_add_int("nows", le16_to_cpu(ns->nows));
		}

		root_add_int("mssrl", le16_to_cpu(ns->mssrl));
		json_object_add_value_uint(root, "mcl", le32_to_cpu(ns->mcl));
		root_add_int("msrc", ns->msrc);
	}

	root_add_int("nulbaf", ns->nulbaf);

	if (!cap_only) {
		json_object_add_value_uint(root, "anagrpid", le32_to_cpu(ns->anagrpid));
		root_add_int("endgid", le16_to_cpu(ns->endgid));

		memset(eui64, 0, sizeof(eui64_buf));

		for (i = 0; i < sizeof(ns->eui64); i++)
			eui64 += sprintf(eui64, "%02x", ns->eui64[i]);

		memset(nguid, 0, sizeof(nguid_buf));

		for (i = 0; i < sizeof(ns->nguid); i++)
			nguid += sprintf(nguid, "%02x", ns->nguid[i]);

		root_add_str("eui64", eui64_buf);
		root_add_str("nguid", nguid_buf);
	}

	json_object_add_value_array(root, "lbafs", lbafs);

	for (i = 0; i <= ns->nlbaf; i++) {
		struct json_object *lbaf = json_create_object();

		obj_add_int(lbaf, "ms", le16_to_cpu(ns->lbaf[i].ms));
		obj_add_int(lbaf, "ds", ns->lbaf[i].ds);
		obj_add_int(lbaf, "rp", ns->lbaf[i].rp);

		json_array_add_value_object(lbafs, lbaf);
	}

	json_print(root);
}

 void json_nvme_id_ctrl(struct nvme_id_ctrl *ctrl,
			void (*vs)(__u8 *vs, struct json_object *root))
{
	struct json_object *root = json_create_object();
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

	root_add_int("vid", le16_to_cpu(ctrl->vid));
	root_add_int("ssvid", le16_to_cpu(ctrl->ssvid));
	root_add_str("sn", sn);
	root_add_str("mn", mn);
	root_add_str("fr", fr);
	root_add_int("rab", ctrl->rab);
	root_add_int("ieee", ieee);
	root_add_int("cmic", ctrl->cmic);
	root_add_int("mdts", ctrl->mdts);
	root_add_int("cntlid", le16_to_cpu(ctrl->cntlid));
	json_object_add_value_uint(root, "ver", le32_to_cpu(ctrl->ver));
	json_object_add_value_uint(root, "rtd3r", le32_to_cpu(ctrl->rtd3r));
	json_object_add_value_uint(root, "rtd3e", le32_to_cpu(ctrl->rtd3e));
	json_object_add_value_uint(root, "oaes", le32_to_cpu(ctrl->oaes));
	json_object_add_value_uint(root, "ctratt", le32_to_cpu(ctrl->ctratt));
	root_add_int("rrls", le16_to_cpu(ctrl->rrls));
	root_add_int("cntrltype", ctrl->cntrltype);
	root_add_str("fguid", util_uuid_to_string(ctrl->fguid));
	root_add_int("crdt1", le16_to_cpu(ctrl->crdt1));
	root_add_int("crdt2", le16_to_cpu(ctrl->crdt2));
	root_add_int("crdt3", le16_to_cpu(ctrl->crdt3));
	root_add_int("nvmsr", ctrl->nvmsr);
	root_add_int("vwci", ctrl->vwci);
	root_add_int("mec", ctrl->mec);
	root_add_int("oacs", le16_to_cpu(ctrl->oacs));
	root_add_int("acl", ctrl->acl);
	root_add_int("aerl", ctrl->aerl);
	root_add_int("frmw", ctrl->frmw);
	root_add_int("lpa", ctrl->lpa);
	root_add_int("elpe", ctrl->elpe);
	root_add_int("npss", ctrl->npss);
	root_add_int("avscc", ctrl->avscc);
	root_add_int("apsta", ctrl->apsta);
	root_add_int("wctemp", le16_to_cpu(ctrl->wctemp));
	root_add_int("cctemp", le16_to_cpu(ctrl->cctemp));
	root_add_int("mtfa", le16_to_cpu(ctrl->mtfa));
	json_object_add_value_uint(root, "hmpre", le32_to_cpu(ctrl->hmpre));
	json_object_add_value_uint(root, "hmmin", le32_to_cpu(ctrl->hmmin));
	json_object_add_value_uint128(root, "tnvmcap", tnvmcap);
	json_object_add_value_uint128(root, "unvmcap", unvmcap);
	json_object_add_value_uint(root, "rpmbs", le32_to_cpu(ctrl->rpmbs));
	root_add_int("edstt", le16_to_cpu(ctrl->edstt));
	root_add_int("dsto", ctrl->dsto);
	root_add_int("fwug", ctrl->fwug);
	root_add_int("kas", le16_to_cpu(ctrl->kas));
	root_add_int("hctma", le16_to_cpu(ctrl->hctma));
	root_add_int("mntmt", le16_to_cpu(ctrl->mntmt));
	root_add_int("mxtmt", le16_to_cpu(ctrl->mxtmt));
	json_object_add_value_uint(root, "sanicap", le32_to_cpu(ctrl->sanicap));
	json_object_add_value_uint(root, "hmminds", le32_to_cpu(ctrl->hmminds));
	root_add_int("hmmaxd", le16_to_cpu(ctrl->hmmaxd));
	root_add_int("nsetidmax",
		le16_to_cpu(ctrl->nsetidmax));
	root_add_int("endgidmax", le16_to_cpu(ctrl->endgidmax));
	root_add_int("anatt",ctrl->anatt);
	root_add_int("anacap", ctrl->anacap);
	json_object_add_value_uint(root, "anagrpmax",
		le32_to_cpu(ctrl->anagrpmax));
	json_object_add_value_uint(root, "nanagrpid",
		le32_to_cpu(ctrl->nanagrpid));
	json_object_add_value_uint(root, "pels", le32_to_cpu(ctrl->pels));
	root_add_int("domainid", le16_to_cpu(ctrl->domainid));
	json_object_add_value_uint128(root, "megcap", megcap);
	root_add_int("sqes", ctrl->sqes);
	root_add_int("cqes", ctrl->cqes);
	root_add_int("maxcmd", le16_to_cpu(ctrl->maxcmd));
	json_object_add_value_uint(root, "nn", le32_to_cpu(ctrl->nn));
	root_add_int("oncs", le16_to_cpu(ctrl->oncs));
	root_add_int("fuses", le16_to_cpu(ctrl->fuses));
	root_add_int("fna", ctrl->fna);
	root_add_int("vwc", ctrl->vwc);
	root_add_int("awun", le16_to_cpu(ctrl->awun));
	root_add_int("awupf", le16_to_cpu(ctrl->awupf));
	root_add_int("icsvscc", ctrl->icsvscc);
	root_add_int("nwpc", ctrl->nwpc);
	root_add_int("acwu", le16_to_cpu(ctrl->acwu));
	root_add_int("ocfs", le16_to_cpu(ctrl->ocfs));
	json_object_add_value_uint(root, "sgls", le32_to_cpu(ctrl->sgls));
	json_object_add_value_uint(root, "mnan", le32_to_cpu(ctrl->mnan));
	json_object_add_value_uint128(root, "maxdna", maxdna);
	json_object_add_value_uint(root, "maxcna", le32_to_cpu(ctrl->maxcna));
	json_object_add_value_uint(root, "oaqd", le32_to_cpu(ctrl->oaqd));

	if (strlen(subnqn))
		root_add_str("subnqn", subnqn);

	json_object_add_value_uint(root, "ioccsz", le32_to_cpu(ctrl->ioccsz));
	json_object_add_value_uint(root, "iorcsz", le32_to_cpu(ctrl->iorcsz));
	root_add_int("icdoff", le16_to_cpu(ctrl->icdoff));
	root_add_int("fcatt", ctrl->fcatt);
	root_add_int("msdbd", ctrl->msdbd);
	root_add_int("ofcs", le16_to_cpu(ctrl->ofcs));

	json_object_add_value_array(root, "psds", psds);

	for (i = 0; i <= ctrl->npss; i++) {
		struct json_object *psd = json_create_object();

		obj_add_int(psd, "max_power", le16_to_cpu(ctrl->psd[i].mp));
		obj_add_int(psd, "max_power_scale", ctrl->psd[i].flags & 0x1);
		obj_add_int(psd, "non-operational_state", (ctrl->psd[i].flags & 2) >> 1);
		json_object_add_value_uint(psd, "entry_lat",
			le32_to_cpu(ctrl->psd[i].enlat));
		json_object_add_value_uint(psd, "exit_lat",
			le32_to_cpu(ctrl->psd[i].exlat));
		obj_add_int(psd, "read_tput", ctrl->psd[i].rrt);
		obj_add_int(psd, "read_lat", ctrl->psd[i].rrl);
		obj_add_int(psd, "write_tput", ctrl->psd[i].rwt);
		obj_add_int(psd, "write_lat", ctrl->psd[i].rwl);
		obj_add_int(psd, "idle_power", le16_to_cpu(ctrl->psd[i].idlp));
		obj_add_int(psd, "idle_scale", nvme_psd_power_scale(ctrl->psd[i].ips));
		obj_add_int(psd, "active_power", le16_to_cpu(ctrl->psd[i].actp));
		obj_add_int(psd, "active_power_work", ctrl->psd[i].apws & 7);
		obj_add_int(psd, "active_scale", nvme_psd_power_scale(ctrl->psd[i].apws));

		json_array_add_value_object(psds, psd);
	}

	if(vs)
		vs(ctrl->vs, root);

	json_print(root);
}

static void json_error_log(struct nvme_error_log_page *err_log, int entries,
			   const char *devname)
{
	struct json_object *root = json_create_object();
	struct json_object *errors = json_create_array();
	int i;

	json_object_add_value_array(root, "errors", errors);

	for (i = 0; i < entries; i++) {
		struct json_object *error = json_create_object();

		obj_add_uint64(error, "error_count", le64_to_cpu(err_log[i].error_count));
		obj_add_int(error, "sqid", le16_to_cpu(err_log[i].sqid));
		obj_add_int(error, "cmdid", le16_to_cpu(err_log[i].cmdid));
		obj_add_int(error, "status_field", le16_to_cpu(err_log[i].status_field >> 0x1));
		obj_add_int(error, "phase_tag", le16_to_cpu(err_log[i].status_field & 0x1));
		obj_add_int(error, "parm_error_location",
			    le16_to_cpu(err_log[i].parm_error_location));
		obj_add_uint64(error, "lba", le64_to_cpu(err_log[i].lba));
		json_object_add_value_uint(error, "nsid", le32_to_cpu(err_log[i].nsid));
		obj_add_int(error, "vs", err_log[i].vs);
		obj_add_int(error, "trtype", err_log[i].trtype);
		obj_add_uint64(error, "cs", le64_to_cpu(err_log[i].cs));
		obj_add_int(error, "trtype_spec_info", le16_to_cpu(err_log[i].trtype_spec_info));

		json_array_add_value_object(errors, error);
	}

	json_print(root);
}

void json_nvme_resv_report(struct nvme_resv_status *status,
			   int bytes, bool eds)
{
	struct json_object *root = json_create_object();
	struct json_object *rcs = json_create_array();
	int i, j, entries;
	int regctl = status->regctl[0] | (status->regctl[1] << 8);

	json_object_add_value_uint(root, "gen", le32_to_cpu(status->gen));
	root_add_int("rtype", status->rtype);
	root_add_int("regctl", regctl);
	root_add_int("ptpls", status->ptpls);

	/* check Extended Data Structure bit */
	if (!eds) {
		/*
		 * if status buffer was too small, don't loop past the end of
		 * the buffer
		 */
		entries = (bytes - 24) / 24;
		if (entries < regctl)
			regctl = entries;

		json_object_add_value_array(root, "regctls", rcs);
		for (i = 0; i < regctl; i++) {
			struct json_object *rc = json_create_object();

			obj_add_int(rc, "cntlid", le16_to_cpu(status->regctl_ds[i].cntlid));
			obj_add_int(rc, "rcsts", status->regctl_ds[i].rcsts);
			obj_add_uint64(rc, "hostid", le64_to_cpu(status->regctl_ds[i].hostid));
			obj_add_uint64(rc, "rkey", le64_to_cpu(status->regctl_ds[i].rkey));

			json_array_add_value_object(rcs, rc);
		}
	} else {
		char hostid[33];

		/* if status buffer was too small, don't loop past the end of the buffer */
		entries = (bytes - 64) / 64;

		if (entries < regctl)
			regctl = entries;

		json_object_add_value_array(root, "regctlext", rcs);

		for (i = 0; i < regctl; i++) {
			struct json_object *rc = json_create_object();

			obj_add_int(rc, "cntlid", le16_to_cpu(status->regctl_eds[i].cntlid));
			obj_add_int(rc, "rcsts", status->regctl_eds[i].rcsts);
			obj_add_uint64(rc, "rkey", le64_to_cpu(status->regctl_eds[i].rkey));

			for (j = 0; j < 16; j++)
				sprintf(hostid + j * 2, "%02x", status->regctl_eds[i].hostid[j]);

			obj_add_str(rc, "hostid", hostid);
			json_array_add_value_object(rcs, rc);
		}
	}

	json_print(root);
}

void json_fw_log(struct nvme_firmware_slot *fw_log, const char *devname)
{
	struct json_object *root = json_create_object();
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

	json_object_add_value_object(root, devname, fwsi);

	json_print(root);
}

void json_changed_ns_list_log(struct nvme_ns_list *log,
			      const char *devname)
{
	struct json_object *root = json_create_object();
	struct json_object *nsi = json_create_object();
	char fmt[32];
	char str[32];
	__u32 nsid;
	int i;

	if (log->ns[0] == cpu_to_le32(0xffffffff))
		return;

	root_add_str("Changed Namespace List Log", devname);

	for (i = 0; i < NVME_ID_NS_LIST_MAX; i++) {
		nsid = le32_to_cpu(log->ns[i]);

		if (nsid == 0)
			break;

		snprintf(fmt, sizeof(fmt), "[%4u]", i + 1);
		snprintf(str, sizeof(str), "%#x", nsid);
		obj_add_str(nsi, fmt, str);
	}

	json_object_add_value_object(root, devname, nsi);

	json_print(root);
}

static void json_endurance_log(struct nvme_endurance_group_log *endurance_group, __u16 group_id,
			       const char *devname)
{
	struct json_object *root = json_create_object();
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

	root_add_int("critical_warning", endurance_group->critical_warning);
	root_add_int("endurance_group_features", endurance_group->endurance_group_features);
	root_add_int("avl_spare", endurance_group->avl_spare);
	root_add_int("avl_spare_threshold", endurance_group->avl_spare_threshold);
	root_add_int("percent_used", endurance_group->percent_used);
	root_add_int("domain_identifier", endurance_group->domain_identifier);
	json_object_add_value_uint128(root, "endurance_estimate", endurance_estimate);
	json_object_add_value_uint128(root, "data_units_read", data_units_read);
	json_object_add_value_uint128(root, "data_units_written", data_units_written);
	json_object_add_value_uint128(root, "media_units_written", media_units_written);
	json_object_add_value_uint128(root, "host_read_cmds", host_read_cmds);
	json_object_add_value_uint128(root, "host_write_cmds", host_write_cmds);
	json_object_add_value_uint128(root, "media_data_integrity_err", media_data_integrity_err);
	json_object_add_value_uint128(root, "num_err_info_log_entries", num_err_info_log_entries);
	json_object_add_value_uint128(root, "total_end_grp_cap", total_end_grp_cap);
	json_object_add_value_uint128(root, "unalloc_end_grp_cap", unalloc_end_grp_cap);

	json_print(root);
}

static void json_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
			   const char *devname)
{
	int c, human = json_print_ops.flags  & VERBOSE;
	struct json_object *root = json_create_object();
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

	if (human) {
		struct json_object *crt = json_create_object();

		obj_add_int(crt, "value", smart->critical_warning);
		obj_add_int(crt, "available_spare", smart->critical_warning & 1);
		obj_add_int(crt, "temp_threshold", (smart->critical_warning & 2) >> 1);
		obj_add_int(crt, "reliability_degraded", (smart->critical_warning & 4) >> 2);
		obj_add_int(crt, "ro", (smart->critical_warning & 8) >> 3);
		obj_add_int(crt, "vmbu_failed", (smart->critical_warning & 0x10) >> 4);
		obj_add_int(crt, "pmr_ro", (smart->critical_warning & 0x20) >> 5);

		json_object_add_value_object(root, "critical_warning", crt);
	} else {
		root_add_int("critical_warning", smart->critical_warning);
	}

	root_add_int("temperature", temperature);
	root_add_int("avail_spare", smart->avail_spare);
	root_add_int("spare_thresh", smart->spare_thresh);
	root_add_int("percent_used", smart->percent_used);
	root_add_int("endurance_grp_critical_warning_summary", smart->endu_grp_crit_warn_sumry);
	json_object_add_value_uint128(root, "data_units_read", data_units_read);
	json_object_add_value_uint128(root, "data_units_written",
		data_units_written);
	json_object_add_value_uint128(root, "host_read_commands",
		host_read_commands);
	json_object_add_value_uint128(root, "host_write_commands",
		host_write_commands);
	json_object_add_value_uint128(root, "controller_busy_time",
		controller_busy_time);
	json_object_add_value_uint128(root, "power_cycles", power_cycles);
	json_object_add_value_uint128(root, "power_on_hours", power_on_hours);
	json_object_add_value_uint128(root, "unsafe_shutdowns", unsafe_shutdowns);
	json_object_add_value_uint128(root, "media_errors", media_errors);
	json_object_add_value_uint128(root, "num_err_log_entries",
		num_err_log_entries);
	json_object_add_value_uint(root, "warning_temp_time",
			le32_to_cpu(smart->warning_temp_time));
	json_object_add_value_uint(root, "critical_comp_time",
			le32_to_cpu(smart->critical_comp_time));

	for (c = 0; c < 8; c++) {
		__s32 temp = le16_to_cpu(smart->temp_sensor[c]);

		if (temp == 0)
			continue;

		sprintf(key, "temperature_sensor_%d",c+1);
		root_add_int(key, temp);
	}

	json_object_add_value_uint(root, "thm_temp1_trans_count",
			le32_to_cpu(smart->thm_temp1_trans_count));
	json_object_add_value_uint(root, "thm_temp2_trans_count",
			le32_to_cpu(smart->thm_temp2_trans_count));
	json_object_add_value_uint(root, "thm_temp1_total_time",
			le32_to_cpu(smart->thm_temp1_total_time));
	json_object_add_value_uint(root, "thm_temp2_total_time",
			le32_to_cpu(smart->thm_temp2_total_time));

	json_print(root);
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
	struct json_object *root = json_create_object();
	size_t nsid_buf_size;
	void *base = ana_log;
	__u32 nr_nsids;
	int i, j;

	root_add_str("Asymmetric Namespace Access Log for NVMe device", devname);
	root_add_uint64("chgcnt", le64_to_cpu(hdr->chgcnt));
	json_object_add_value_uint(root, "ngrps", le16_to_cpu(hdr->ngrps));

	for (i = 0; i < le16_to_cpu(ana_log->ngrps); i++) {
		desc = json_create_object();
		ana_desc = base + offset;
		nr_nsids = le32_to_cpu(ana_desc->nnsids);
		nsid_buf_size = nr_nsids * sizeof(__le32);

		offset += sizeof(*ana_desc);
		json_object_add_value_uint(desc, "grpid", le32_to_cpu(ana_desc->grpid));
		json_object_add_value_uint(desc, "nnsids", le32_to_cpu(ana_desc->nnsids));
		obj_add_uint64(desc, "chgcnt", le64_to_cpu(ana_desc->chgcnt));
		obj_add_str(desc, "state", nvme_ana_state_to_string(ana_desc->state));

		ns_list = json_create_array();
		for (j = 0; j < le32_to_cpu(ana_desc->nnsids); j++) {
			nsid = json_create_object();
			json_object_add_value_uint(nsid, "nsid", le32_to_cpu(ana_desc->nsids[j]));
			json_array_add_value_object(ns_list, nsid);
		}
		json_object_add_value_array(desc, "NSIDS", ns_list);
		offset += nsid_buf_size;
		json_array_add_value_object(desc_list, desc);
	}

	json_object_add_value_array(root, "ANA DESC LIST ", desc_list);

	json_print(root);
}

static void json_select_result(__u32 result)
{
	struct json_object *root = json_create_object();
	struct json_object *feature = json_create_array();

	if (result & 0x1)
		json_array_add_value_string(feature, "saveable");
	if (result & 0x2)
		json_array_add_value_string(feature, "per-namespace");
	if (result & 0x4)
		json_array_add_value_string(feature, "changeable");

	json_object_add_value_array(root, "Feature", feature);

	json_print(root);
}

static void json_self_test_log(struct nvme_self_test_log *self_test, __u8 dst_entries,
			       __u32 size, const char *devname)
{
	struct json_object *valid_attrs;
	struct json_object *root = json_create_object();
	struct json_object *valid = json_create_array();
	int i;
	__u32 num_entries = min(dst_entries, NVME_LOG_ST_MAX_RESULTS);

	root_add_int("Current Device Self-Test Operation", self_test->current_operation);
	root_add_int("Current Device Self-Test Completion", self_test->completion);

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
			json_object_add_value_uint(valid_attrs, "Namespace Identifier",
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
		json_array_add_value_object(valid, valid_attrs);
	}

	json_object_add_value_array(root, "List of Valid Reports", valid);

	json_print(root);
}

static void json_registers_cap(struct nvme_bar_cap *cap, struct json_object *root)
{
	char json_str[STR_LEN];
	struct json_object *cssa = json_create_array();
	struct json_object *csso = json_create_object();
	struct json_object *amsa = json_create_array();
	struct json_object *amso = json_create_object();

	sprintf(json_str, "%"PRIx64"", *(uint64_t *)cap);
	root_add_str("cap", json_str);

	root_add_str("Controller Ready With Media Support (CRWMS)",
		     cap->crwms ? supported : not_supported);
	root_add_str("Controller Ready Independent of Media Support (CRIMS)",
		     cap->crims ? supported : not_supported);
	root_add_str("NVM Subsystem Shutdown Supported (NSSS)",
		     cap->nsss ? supported : not_supported);
	root_add_str("Controller Memory Buffer Supported (CMBS):",
		     cap->cmbs ? supported : not_supported);
	root_add_str("Persistent Memory Region Supported (PMRS)",
		     cap->pmrs ? supported : not_supported);

	sprintf(json_str, "%u bytes", 1 << (12 + cap->mpsmax));
	root_add_str("Memory Page Size Maximum (MPSMAX)", json_str);

	sprintf(json_str, "%u bytes", 1 << (12 + cap->mpsmin));
	root_add_str("Memory Page Size Minimum (MPSMIN)", json_str);

	root_add_str("Controller Power Scope (CPS)", !cap->cps ? "Not Reported" : cap->cps == 1 ?
		     "Controller scope" : cap->cps == 2 ? "Domain scope" : "NVM subsystem scope");
	root_add_str("Boot Partition Support (BPS)", cap->bps ? yes : no);

	root_add_array("Command Sets Supported (CSS)", cssa);
	obj_add_str(csso, "NVM command set is %s", cap->css & 1 ? supported : not_supported);
	obj_add_str(csso, "One or more I/O Command Sets are %s",
		    cap->css & 0x40 ? supported : not_supported);
	obj_add_str(csso, cap->css & 0x80 ? "Only Admin Command Set" : "I/O Command Set",
		    supported);
	array_add_obj(cssa, csso);

	root_add_str("NVM Subsystem Reset Supported (NSSRS): %s", cap->nssrs ? yes : no);

	sprintf(json_str, "%u bytes", 1 << (2 + cap->dstrd));
	root_add_str("Doorbell Stride (DSTRD)", json_str);

	root_add_uint("Timeout (TO): %u ms", cap->to * 500);

	root_add_array("Arbitration Mechanism Supported (AMS)", amsa);
	obj_add_str(amso, "Weighted Round Robin with Urgent Priority Class",
		    cap->ams & 2 ? supported : not_supported);
	array_add_obj(amsa, amso);

	root_add_str("Contiguous Queues Required (CQR)", cap->cqr ? yes : no);
	root_add_uint("Maximum Queue Entries Supported (MQES)", cap->mqes + 1);
}

static void json_registers_version(__u32 vs, struct json_object *root)
{
	char json_str[STR_LEN];

	sprintf(json_str, "%x", vs);
	root_add_str("version", json_str);

	sprintf(json_str, "%d.%d", (vs & 0xffff0000) >> 16, (vs & 0x0000ff00) >> 8);
	root_add_str("NVMe specification", json_str);
}

static void json_registers_cc_ams (__u8 ams, struct json_object *root)
{
	char json_str[STR_LEN];

	switch (ams) {
	case 0:
		sprintf(json_str, "Round Robin");
		break;
	case 1:
		sprintf(json_str, "Weighted Round Robin with Urgent Priority Class");
		break;
	case 7:
		sprintf(json_str, "Vendor Specific");
		break;
	default:
		sprintf(json_str, "Reserved");
		break;
	}

	root_add_str("Arbitration Mechanism Selected (AMS)", json_str);
}

static void json_registers_cc_shn (__u8 shn, struct json_object *root)
{
	char json_str[STR_LEN];

	switch (shn) {
	case 0:
		sprintf(json_str, "No notification; no effect");
		break;
	case 1:
		sprintf(json_str, "Normal shutdown notification");
		break;
	case 2:
		sprintf(json_str, "Abrupt shutdown notification");
		break;
	default:
		sprintf(json_str, "Reserved");
		break;
	}

	root_add_str("Shutdown Notification (SHN)", json_str);
}

static void json_registers_cc(__u32 cc, struct json_object *root)
{
	char json_str[STR_LEN];

	sprintf(json_str, "%x", cc);
	root_add_str("cc", json_str);

	root_add_str("Controller Ready Independent of Media Enable (CRIME)",
		     NVME_CC_CRIME(cc) ? enabled : disabled);

	sprintf(json_str, "%u bytes", POWER_OF_TWO(NVME_GET(cc, CC_IOCQES)));
	root_add_str("I/O Completion Queue Entry Size (IOCQES): ", json_str);

	sprintf(json_str, "%u bytes", POWER_OF_TWO(NVME_GET(cc, CC_IOSQES)));
	root_add_str("I/O Submission Queue Entry Size (IOSQES)", json_str);

	json_registers_cc_shn((cc & 0xc000) >> NVME_CC_SHN_SHIFT, root);
	json_registers_cc_ams((cc & 0x3800) >> NVME_CC_AMS_SHIFT, root);

	sprintf(json_str, "%u bytes", POWER_OF_TWO(12 + NVME_GET(cc, CC_MPS)));
	root_add_str("Memory Page Size (MPS)", json_str);

	root_add_str("I/O Command Set Selected (CSS)", (cc & 0x70) == 0x00 ? "NVM Command Set" :
		     (cc & 0x70) == 0x60 ? "All supported I/O Command Sets" :
		     (cc & 0x70) == 0x70 ? "Admin Command Set only" : reserved);
	root_add_str("Enable (EN)", cc & 1 ? yes : no);
}

static void json_registers_csts_shst(__u8 shst, struct json_object *root)
{
	char json_str[STR_LEN];

	switch (shst) {
	case 0:
		sprintf(json_str, "Normal operation (no shutdown has been requested)");
		break;
	case 1:
		sprintf(json_str, "Shutdown processing occurring");
		break;
	case 2:
		sprintf(json_str, "Shutdown processing complete");
		break;
	default:
		sprintf(json_str, "Reserved");
		break;
	}
	root_add_str("Shutdown Status (SHST)", json_str);
}

static void json_registers_csts(__u32 csts, struct json_object *root)
{
	root_add_uint_x("csts", csts);

	root_add_str("Processing Paused (PP)", csts & 0x20 ? yes : no);
	root_add_str("NVM Subsystem Reset Occurred (NSSRO)", csts & 0x10 ? yes : no);

	json_registers_csts_shst((csts & 0xc) >> 2, root);

	root_add_str("Controller Fatal Status (CFS)", csts & 2 ? true_str : false_str);
	root_add_str("Ready (RDY)", csts & 1 ? yes : no);
}

static void json_registers_nssr(__u32 nssr, struct json_object *root)
{
	root_add_uint_x("nssr", nssr);
	root_add_uint("NVM Subsystem Reset Control (NSSRC)", nssr);
}

static void json_registers_crto(__u32 crto, struct json_object *root)
{
	root_add_uint_x("crto", crto);

	root_add_int_secs("CRIMT", MS500_TO_SEC(NVME_CRTO_CRIMT(crto)));
	root_add_int_secs("CRWMT", MS500_TO_SEC(NVME_CRTO_CRWMT(crto)));
}

static void json_registers_unknown(int offset, uint64_t value64, struct json_object *root)
{
	root_add_uint_0x("unknown property", offset);
	root_add_str("name", nvme_register_to_string(offset));
	root_add_prix64("value", value64);
}

static void json_single_property_human(int offset, uint64_t value64, struct json_object *root)
{
	uint32_t value32 = (uint32_t)value64;

	switch (offset) {
	case NVME_REG_CAP:
		json_registers_cap((struct nvme_bar_cap *)&value64, root);
		break;
	case NVME_REG_VS:
		json_registers_version(value32, root);
		break;
	case NVME_REG_CC:
		json_registers_cc(value32, root);
		break;
	case NVME_REG_CSTS:
		json_registers_csts(value32, root);
		break;
	case NVME_REG_NSSR:
		json_registers_nssr(value32, root);
		break;
	case NVME_REG_CRTO:
		json_registers_crto(value32, root);
		break;
	default:
		json_registers_unknown(offset, value64, root);
		break;
	}
}

static void json_single_property(int offset, uint64_t value64)
{
	struct json_object *root = json_create_object();
	char json_str[STR_LEN];
	int human = json_print_ops.flags & VERBOSE;
	uint32_t value32 = (uint32_t)value64;

	if (human) {
		json_single_property_human(offset, value64, root);
	} else {
		sprintf(json_str, "0x%02x", offset);
		root_add_str("property", json_str);

		root_add_str("name", nvme_register_to_string(offset));

		if (nvme_is_64bit_reg(offset))
			sprintf(json_str, "%"PRIx64"", value64);
		else
			sprintf(json_str, "%x", value32);

		root_add_str("value", json_str);
	}

	json_print(root);
}

struct json_object* json_effects_log(enum nvme_csi csi,
			     struct nvme_cmd_effects_log *effects_log)
{
	struct json_object *root = json_create_object();
	struct json_object *acs = json_create_object();
	struct json_object *iocs = json_create_object();
	unsigned int opcode;
	char key[128];
	__u32 effect;

	json_object_add_value_uint(root, "command_set_identifier", csi);

	for (opcode = 0; opcode < 256; opcode++) {
		effect = le32_to_cpu(effects_log->acs[opcode]);
		if (effect & NVME_CMD_EFFECTS_CSUPP) {
			sprintf(key, "ACS_%u (%s)", opcode,
				nvme_cmd_to_string(1, opcode));
			json_object_add_value_uint(acs, key, effect);
		}
	}

	json_object_add_value_object(root, "admin_cmd_set", acs);

	for (opcode = 0; opcode < 256; opcode++) {
		effect = le32_to_cpu(effects_log->iocs[opcode]);
		if (effect & NVME_CMD_EFFECTS_CSUPP) {
			sprintf(key, "IOCS_%u (%s)", opcode,
				nvme_cmd_to_string(0, opcode));
			json_object_add_value_uint(iocs, key, effect);
		}
	}

	json_object_add_value_object(root, "io_cmd_set", iocs);
	return root;
}

static void json_effects_log_list(struct list_head *list)
{
	struct json_object *root = json_create_array();
	nvme_effects_log_node_t *node;

	list_for_each(list, node, node) {
		struct json_object *json_page =
			json_effects_log(node->csi, &node->effects);
		json_array_add_value_object(root, json_page);
	}

	json_print(root);
}

static void json_sanitize_log(struct nvme_sanitize_log_page *sanitize_log,
			      const char *devname)
{
	struct json_object *root = json_create_object();
	struct json_object *dev = json_create_object();
	struct json_object *sstat = json_create_object();
	const char *status_str;
	char str[128];
	__u16 status = le16_to_cpu(sanitize_log->sstat);

	obj_add_int(dev, "sprog", le16_to_cpu(sanitize_log->sprog));
	obj_add_int(sstat, "global_erased", (status & NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED) >> 8);
	obj_add_int(sstat, "no_cmplted_passes",
		    (status >> NVME_SANITIZE_SSTAT_COMPLETED_PASSES_SHIFT) &
		    NVME_SANITIZE_SSTAT_COMPLETED_PASSES_MASK);

	status_str = nvme_sstat_status_to_string(status);
	sprintf(str, "(%d) %s", status & NVME_SANITIZE_SSTAT_STATUS_MASK,
		status_str);
	obj_add_str(sstat, "status", str);

	json_object_add_value_object(dev, "sstat", sstat);
	json_object_add_value_uint(dev, "cdw10_info",
		le32_to_cpu(sanitize_log->scdw10));
	json_object_add_value_uint(dev, "time_over_write",
		le32_to_cpu(sanitize_log->eto));
	json_object_add_value_uint(dev, "time_block_erase",
		le32_to_cpu(sanitize_log->etbe));
	json_object_add_value_uint(dev, "time_crypto_erase",
		le32_to_cpu(sanitize_log->etce));

	json_object_add_value_uint(dev, "time_over_write_no_dealloc",
		le32_to_cpu(sanitize_log->etond));
	json_object_add_value_uint(dev, "time_block_erase_no_dealloc",
		le32_to_cpu(sanitize_log->etbend));
	json_object_add_value_uint(dev, "time_crypto_erase_no_dealloc",
		le32_to_cpu(sanitize_log->etcend));

	json_object_add_value_object(root, devname, dev);

	json_print(root);
}

static void json_predictable_latency_per_nvmset(
		struct nvme_nvmset_predictable_lat_log *plpns_log,
		__u16 nvmset_id, const char *devname)
{
	struct json_object *root = json_create_object();

	json_object_add_value_uint(root, "nvmset_id",
		le16_to_cpu(nvmset_id));
	json_object_add_value_uint(root, "status",
		plpns_log->status);
	json_object_add_value_uint(root, "event_type",
		le16_to_cpu(plpns_log->event_type));
	root_add_uint64("dtwin_reads_typical",
		le64_to_cpu(plpns_log->dtwin_rt));
	root_add_uint64("dtwin_writes_typical",
		le64_to_cpu(plpns_log->dtwin_wt));
	root_add_uint64("dtwin_time_maximum",
		le64_to_cpu(plpns_log->dtwin_tmax));
	root_add_uint64("ndwin_time_minimum_high",
		le64_to_cpu(plpns_log->ndwin_tmin_hi));
	root_add_uint64("ndwin_time_minimum_low",
		le64_to_cpu(plpns_log->ndwin_tmin_lo));
	root_add_uint64("dtwin_reads_estimate",
		le64_to_cpu(plpns_log->dtwin_re));
	root_add_uint64("dtwin_writes_estimate",
		le64_to_cpu(plpns_log->dtwin_we));
	root_add_uint64("dtwin_time_estimate",
		le64_to_cpu(plpns_log->dtwin_te));

	json_print(root);
}

static void json_predictable_latency_event_agg_log(
		struct nvme_aggregate_predictable_lat_event *pea_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	struct json_object *root = json_create_object();
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();
	__u64 num_entries = le64_to_cpu(pea_log->num_entries);
	__u64 num_iter = min(num_entries, log_entries);

	root_add_uint64("num_entries_avail", num_entries);

	for (int i = 0; i < num_iter; i++) {
		valid_attrs = json_create_object();
		json_object_add_value_uint(valid_attrs, "entry",
			le16_to_cpu(pea_log->entries[i]));
		json_array_add_value_object(valid, valid_attrs);
	}

	json_object_add_value_array(root, "list_of_entries", valid);

	json_print(root);
}

static void json_add_bitmap(int i, __u8 seb, struct json_object *root)
{
	char evt_str[50];
	char key[128];

	for (int bit = 0; bit < 8; bit++) {
		if (nvme_pel_event_to_string(bit + i * 8)) {
			sprintf(key, "bitmap_%x", (bit + i * 8));
			if ((seb >> bit) & 0x1)
				snprintf(evt_str, sizeof(evt_str), "Support %s",
					 nvme_pel_event_to_string(bit + i * 8));
			root_add_str(key, evt_str);
		}
	}
}

static void json_pevent_log_head(struct nvme_persistent_event_log *pevent_log_head,
				 struct json_object *root)
{
	int i;
	char sn[sizeof(pevent_log_head->sn) + 1];
	char mn[sizeof(pevent_log_head->mn) + 1];
	char subnqn[sizeof(pevent_log_head->subnqn) + 1];

	snprintf(sn, sizeof(sn), "%-.*s", (int)sizeof(pevent_log_head->sn), pevent_log_head->sn);
	snprintf(mn, sizeof(mn), "%-.*s", (int)sizeof(pevent_log_head->mn), pevent_log_head->mn);
	snprintf(subnqn, sizeof(subnqn), "%-.*s", (int)sizeof(pevent_log_head->subnqn),
		 pevent_log_head->subnqn);

	json_object_add_value_uint(root, "log_id", pevent_log_head->lid);
	json_object_add_value_uint(root, "total_num_of_events", le32_to_cpu(pevent_log_head->tnev));
	root_add_uint64("total_log_len", le64_to_cpu(pevent_log_head->tll));
	json_object_add_value_uint(root, "log_revision", pevent_log_head->rv);
	json_object_add_value_uint(root, "log_header_len", le16_to_cpu(pevent_log_head->lhl));
	root_add_uint64("timestamp", le64_to_cpu(pevent_log_head->ts));
	json_object_add_value_uint128(root, "power_on_hours", le128_to_cpu(pevent_log_head->poh));
	root_add_uint64("power_cycle_count", le64_to_cpu(pevent_log_head->pcc));
	json_object_add_value_uint(root, "pci_vid", le16_to_cpu(pevent_log_head->vid));
	json_object_add_value_uint(root, "pci_ssvid", le16_to_cpu(pevent_log_head->ssvid));
	root_add_str("sn", sn);
	root_add_str("mn", mn);
	root_add_str("subnqn", subnqn);
	json_object_add_value_uint(root, "gen_number", le16_to_cpu(pevent_log_head->gen_number));
	json_object_add_value_uint(root, "rci", le32_to_cpu(pevent_log_head->rci));

	for (i = 0; i < ARRAY_SIZE(pevent_log_head->seb); i++) {
		if (!pevent_log_head->seb[i])
			continue;
		json_add_bitmap(i, pevent_log_head->seb[i], root);
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
	json_object_add_value_uint128(valid_attrs, "data_units_read", data_units_read);
	json_object_add_value_uint128(valid_attrs, "data_units_written", data_units_written);
	json_object_add_value_uint128(valid_attrs, "host_read_commands", host_read_commands);
	json_object_add_value_uint128(valid_attrs, "host_write_commands", host_write_commands);
	json_object_add_value_uint128(valid_attrs, "controller_busy_time", controller_busy_time);
	json_object_add_value_uint128(valid_attrs, "power_cycles", power_cycles);
	json_object_add_value_uint128(valid_attrs, "power_on_hours", power_on_hours);
	json_object_add_value_uint128(valid_attrs, "unsafe_shutdowns", unsafe_shutdowns);
	json_object_add_value_uint128(valid_attrs, "media_errors", media_errors);
	json_object_add_value_uint128(valid_attrs, "num_err_log_entries", num_err_log_entries);
	json_object_add_value_uint(valid_attrs, "warning_temp_time",
				   le32_to_cpu(smart_event->warning_temp_time));
	json_object_add_value_uint(valid_attrs, "critical_comp_time",
				   le32_to_cpu(smart_event->critical_comp_time));

	for (c = 0; c < 8; c++) {
		temp = le16_to_cpu(smart_event->temp_sensor[c]);
		if (!temp)
			continue;
		sprintf(key, "temperature_sensor_%d",c + 1);
		obj_add_int(valid_attrs, key, temp);
	}

	json_object_add_value_uint(valid_attrs, "thm_temp1_trans_count",
				   le32_to_cpu(smart_event->thm_temp1_trans_count));
	json_object_add_value_uint(valid_attrs, "thm_temp2_trans_count",
				   le32_to_cpu(smart_event->thm_temp2_trans_count));
	json_object_add_value_uint(valid_attrs, "thm_temp1_total_time",
				   le32_to_cpu(smart_event->thm_temp1_total_time));
	json_object_add_value_uint(valid_attrs, "thm_temp2_total_time",
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
	json_object_add_value_uint(valid_attrs, "fw_commit_action",
				   fw_commit_event->fw_commit_action);
	json_object_add_value_uint(valid_attrs, "fw_slot", fw_commit_event->fw_slot);
	json_object_add_value_uint(valid_attrs, "sct_fw", fw_commit_event->sct_fw);
	json_object_add_value_uint(valid_attrs, "sc_fw", fw_commit_event->sc_fw);
	json_object_add_value_uint(valid_attrs, "vu_assign_fw_commit_rc",
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
		json_object_add_value_uint(valid_attrs, "ctrl_id", le16_to_cpu(por_event->cid));
		json_object_add_value_uint(valid_attrs, "fw_act", por_event->fw_act);
		json_object_add_value_uint(valid_attrs, "op_in_prog", por_event->op_in_prog);
		json_object_add_value_uint(valid_attrs, "ctrl_power_cycle",
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

	json_object_add_value_uint(valid_attrs, "nss_hw_err_code",
				   le16_to_cpu(nss_hw_err_event->nss_hw_err_event_code));
}

static void json_pel_change_ns(void *pevent_log_info, __u32 offset, struct json_object *valid_attrs)
{
	struct nvme_change_ns_event *ns_event = pevent_log_info + offset;

	json_object_add_value_uint(valid_attrs, "nsmgt_cdw10", le32_to_cpu(ns_event->nsmgt_cdw10));
	obj_add_uint64(valid_attrs, "nsze", le64_to_cpu(ns_event->nsze));
	obj_add_uint64(valid_attrs, "nscap", le64_to_cpu(ns_event->nscap));
	json_object_add_value_uint(valid_attrs, "flbas", ns_event->flbas);
	json_object_add_value_uint(valid_attrs, "dps", ns_event->dps);
	json_object_add_value_uint(valid_attrs, "nmic", ns_event->nmic);
	json_object_add_value_uint(valid_attrs, "ana_grp_id", le32_to_cpu(ns_event->ana_grp_id));
	json_object_add_value_uint(valid_attrs, "nvmset_id", le16_to_cpu(ns_event->nvmset_id));
	json_object_add_value_uint(valid_attrs, "nsid", le32_to_cpu(ns_event->nsid));
}

static void json_pel_format_start(void *pevent_log_info, __u32 offset,
				  struct json_object *valid_attrs)
{
	struct nvme_format_nvm_start_event *format_start_event = pevent_log_info + offset;

	json_object_add_value_uint(valid_attrs, "nsid", le32_to_cpu(format_start_event->nsid));
	json_object_add_value_uint(valid_attrs, "fna", format_start_event->fna);
	json_object_add_value_uint(valid_attrs, "format_nvm_cdw10",
				   le32_to_cpu(format_start_event->format_nvm_cdw10));
}

static void json_pel_format_completion(void *pevent_log_info, __u32 offset,
				       struct json_object *valid_attrs)
{
	struct nvme_format_nvm_compln_event *format_cmpln_event = pevent_log_info + offset;

	json_object_add_value_uint(valid_attrs, "nsid", le32_to_cpu(format_cmpln_event->nsid));
	json_object_add_value_uint(valid_attrs, "smallest_fpi", format_cmpln_event->smallest_fpi);
	json_object_add_value_uint(valid_attrs, "format_nvm_status",
				   format_cmpln_event->format_nvm_status);
	json_object_add_value_uint(valid_attrs, "compln_info",
				   le16_to_cpu(format_cmpln_event->compln_info));
	json_object_add_value_uint(valid_attrs, "status_field",
				   le32_to_cpu(format_cmpln_event->status_field));
}
static void json_pel_sanitize_start(void *pevent_log_info, __u32 offset,
				    struct json_object *valid_attrs)
{
	struct nvme_sanitize_start_event *sanitize_start_event = pevent_log_info + offset;

	json_object_add_value_uint(valid_attrs, "SANICAP",
				   le32_to_cpu(sanitize_start_event->sani_cap));
	json_object_add_value_uint(valid_attrs, "sani_cdw10",
				   le32_to_cpu(sanitize_start_event->sani_cdw10));
	json_object_add_value_uint(valid_attrs, "sani_cdw11",
				   le32_to_cpu(sanitize_start_event->sani_cdw11));
}

static void json_pel_sanitize_completion(void *pevent_log_info, __u32 offset,
					 struct json_object *valid_attrs)
{
	struct nvme_sanitize_compln_event *sanitize_cmpln_event = pevent_log_info + offset;

	json_object_add_value_uint(valid_attrs, "sani_prog",
				   le16_to_cpu(sanitize_cmpln_event->sani_prog));
	json_object_add_value_uint(valid_attrs, "sani_status",
				   le16_to_cpu(sanitize_cmpln_event->sani_status));
	json_object_add_value_uint(valid_attrs, "cmpln_info",
				   le16_to_cpu(sanitize_cmpln_event->cmpln_info));
}

static void json_pel_thermal_excursion(void *pevent_log_info, __u32 offset,
				       struct json_object *valid_attrs)
{
	struct nvme_thermal_exc_event *thermal_exc_event = pevent_log_info + offset;

	json_object_add_value_uint(valid_attrs, "over_temp", thermal_exc_event->over_temp);
	json_object_add_value_uint(valid_attrs, "threshold", thermal_exc_event->threshold);
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

		json_object_add_value_uint(valid_attrs, "event_number", i);
		obj_add_str(valid_attrs, "event_type",
			    nvme_pel_event_to_string(pevent_entry_head->etype));
		json_object_add_value_uint(valid_attrs, "event_type_rev",
					   pevent_entry_head->etype_rev);
		json_object_add_value_uint(valid_attrs, "event_header_len", pevent_entry_head->ehl);
		json_object_add_value_uint(valid_attrs, "event_header_additional_info",
					   pevent_entry_head->ehai);
		json_object_add_value_uint(valid_attrs, "ctrl_id",
					   le16_to_cpu(pevent_entry_head->cntlid));
		obj_add_uint64(valid_attrs, "event_time_stamp",
			       le64_to_cpu(pevent_entry_head->ets));
		json_object_add_value_uint(valid_attrs, "port_id",
					   le16_to_cpu(pevent_entry_head->pelpid));
		json_object_add_value_uint(valid_attrs, "vu_info_len",
					   le16_to_cpu(pevent_entry_head->vsil));
		json_object_add_value_uint(valid_attrs, "event_len",
					   le16_to_cpu(pevent_entry_head->el));

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
						pevent_entry_head->el, pevent_entry_head->vsil);
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
		case NVME_PEL_THERMAL_EXCURSION_EVENT:
			json_pel_thermal_excursion(pevent_log_info, offset, valid_attrs);
			break;
		default:
			break;
		}

		json_array_add_value_object(valid, valid_attrs);
		offset += le16_to_cpu(pevent_entry_head->el);
	}
}

static void json_persistent_event_log(void *pevent_log_info, __u8 action,
				      __u32 size, const char *devname)
{
	struct json_object *root = json_create_object();
	struct json_object *valid = json_create_array();
	__u32 offset = sizeof(struct nvme_persistent_event_log);

	if (size >= offset) {
		json_pevent_log_head(pevent_log_info, root);
		json_pevent_entry(pevent_log_info, action, size, devname, offset, valid);
		json_object_add_value_array(root, "list_of_event_entries", valid);
	} else {
		root_add_result("No log data can be shown with this log len at least " \
				"512 bytes is required or can be 0 to read the complete "\
				"log page after context established");
	}

	json_print(root);
}

static void json_endurance_group_event_agg_log(
		struct nvme_aggregate_predictable_lat_event *endurance_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	struct json_object *root = json_create_object();
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();

	root_add_uint64("num_entries_avail", le64_to_cpu(endurance_log->num_entries));

	for (int i = 0; i < log_entries; i++) {
		valid_attrs = json_create_object();
		json_object_add_value_uint(valid_attrs, "entry",
			le16_to_cpu(endurance_log->entries[i]));
		json_array_add_value_object(valid, valid_attrs);
	}

	json_object_add_value_array(root, "list_of_entries", valid);

	json_print(root);
}

static void json_lba_status(struct nvme_lba_status *list,
			      unsigned long len)
{
	struct json_object *root = json_create_object();
	int idx;
	struct nvme_lba_status_desc *e;
	struct json_object *lsde;
	char json_str[STR_LEN];

	json_object_add_value_uint(root, "Number of LBA Status Descriptors (NLSD)",
				   le32_to_cpu(list->nlsd));
	json_object_add_value_uint(root, "Completion Condition (CMPC)", list->cmpc);

	switch (list->cmpc) {
	case 1:
		root_add_str("cmpc-definition",
		    "Completed due to transferring the amount of data specified in the MNDW field");
		break;
	case 2:
		root_add_str("cmpc-definition",
		    "Completed due to having performed the action specified in the Action Type field over the number of logical blocks specified in the Range Length field");
		break;
	default:
		break;
	}

	for (idx = 0; idx < list->nlsd; idx++) {
		lsde = json_create_array();
		sprintf(json_str, "LSD entry %d", idx);
		json_object_add_value_array(root, json_str, lsde);
		e = &list->descs[idx];
		sprintf(json_str, "0x%016"PRIu64"", le64_to_cpu(e->dslba));
		obj_add_str(lsde, "DSLBA", json_str);
		sprintf(json_str, "0x%08x", le32_to_cpu(e->nlb));
		obj_add_str(lsde, "NLB", json_str);
		sprintf(json_str, "0x%02x", e->status);
		obj_add_str(lsde, "Status", json_str);
	}

	json_print(root);
}

static void json_lba_status_log(void *lba_status, __u32 size, const char *devname)
{
	struct json_object *root = json_create_object();
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

	root_add_uint("lslplen", le32_to_cpu(hdr->lslplen));
	root_add_uint("nlslne", num_elements);
	root_add_uint("estulb", le32_to_cpu(hdr->estulb));
	root_add_uint("lsgc", le16_to_cpu(hdr->lsgc));

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
			root_add_result("Number of LBA Range Descriptors (NLRD) set to %#x for NS element %d",
					num_lba_desc, ele);
		}

		obj_add_array(element, "descs", desc_list);
		array_add_obj(elements_list, element);
	}

	root_add_array("ns_elements", elements_list);

	json_print(root);
}

static void json_resv_notif_log(struct nvme_resv_notification_log *resv,
				const char *devname)
{
	struct json_object *root = json_create_object();

	root_add_uint64("count", le64_to_cpu(resv->lpc));
	json_object_add_value_uint(root, "rn_log_type",
		resv->rnlpt);
	json_object_add_value_uint(root, "num_logs",
		resv->nalp);
	json_object_add_value_uint(root, "nsid",
		le32_to_cpu(resv->nsid));

	json_print(root);
}

static void json_fid_support_effects_log(
		struct nvme_fid_supported_effects_log *fid_log,
		const char *devname)
{
	struct json_object *root = json_create_object();
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
			json_object_add_value_uint(fids, key, fid_support);
			json_array_add_value_object(fids_list, fids);
		}
	}

	json_object_add_value_object(root, "fid_support", fids_list);

	json_print(root);
}

static void json_mi_cmd_support_effects_log(
		struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
		const char *devname)
{
	struct json_object *root = json_create_object();
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
			json_object_add_value_uint(mi_cmds, key, mi_cmd_support);
			json_array_add_value_object(mi_cmds_list, mi_cmds);
		}
	}

	json_object_add_value_object(root, "mi_command_support", mi_cmds_list);

	json_print(root);
}

static void json_boot_part_log(void *bp_log, const char *devname,
			       __u32 size)
{
	struct nvme_boot_partition *hdr = bp_log;
	struct json_object *root = json_create_object();

	json_object_add_value_uint(root, "count", hdr->lid);
	json_object_add_value_uint(root, "abpid",
		(le32_to_cpu(hdr->bpinfo) >> 31) & 0x1);
	json_object_add_value_uint(root, "bpsz",
		le32_to_cpu(hdr->bpinfo) & 0x7fff);

	json_print(root);
}

/* Printable Eye string is allocated and returned, caller must free */
static char *json_eom_printable_eye(struct nvme_eom_lane_desc *lane,
				    struct json_object *root)
{
	char *eye = (char *)lane->eye_desc;
	char *printable = malloc(lane->nrows * lane->ncols + lane->ncols);
	char *printable_start = printable;
	int i, j;

	if (!printable)
		goto exit;

	for (i = 0; i < lane->nrows; i++) {
		for (j = 0; j < lane->ncols; j++, printable++)
			sprintf(printable, "%c", eye[i * lane->ncols + j]);
		sprintf(printable++, "\n");
	}

	root_add_str("printable_eye", printable_start);

exit:
	return printable_start;
}

static void json_phy_rx_eom_descs(struct nvme_phy_rx_eom_log *log,
			struct json_object *root, char **allocated_eyes)
{
	void *p = log->descs;
	uint16_t num_descs = le16_to_cpu(log->nd);
	int i;
	struct json_object *descs = json_create_array();

	json_object_add_value_array(root, "descs", descs);

	for (i = 0; i < num_descs; i++) {
		struct nvme_eom_lane_desc *desc = p;
		struct json_object *jdesc = json_create_object();

		json_object_add_value_uint(jdesc, "lid", desc->mstatus);
		json_object_add_value_uint(jdesc, "lane", desc->lane);
		json_object_add_value_uint(jdesc, "eye", desc->eye);
		json_object_add_value_uint(jdesc, "top", le16_to_cpu(desc->top));
		json_object_add_value_uint(jdesc, "bottom", le16_to_cpu(desc->bottom));
		json_object_add_value_uint(jdesc, "left", le16_to_cpu(desc->left));
		json_object_add_value_uint(jdesc, "right", le16_to_cpu(desc->right));
		json_object_add_value_uint(jdesc, "nrows", le16_to_cpu(desc->nrows));
		json_object_add_value_uint(jdesc, "ncols", le16_to_cpu(desc->ncols));
		json_object_add_value_uint(jdesc, "edlen", le16_to_cpu(desc->edlen));

		if (log->odp & NVME_EOM_PRINTABLE_EYE_PRESENT)
			allocated_eyes[i] = json_eom_printable_eye(desc, root);

		/* Eye Data field is vendor specific, doesn't map to JSON */

		json_array_add_value_object(descs, jdesc);

		p += log->dsize;
	}
}

static void json_phy_rx_eom_log(struct nvme_phy_rx_eom_log *log, __u16 controller)
{
	char **allocated_eyes = NULL;
	int i;
	struct json_object *root = json_create_object();

	json_object_add_value_uint(root, "lid", log->lid);
	json_object_add_value_uint(root, "eomip", log->eomip);
	json_object_add_value_uint(root, "hsize", le16_to_cpu(log->hsize));
	json_object_add_value_uint(root, "rsize", le32_to_cpu(log->rsize));
	json_object_add_value_uint(root, "eomdgn", log->eomdgn);
	json_object_add_value_uint(root, "lr", log->lr);
	json_object_add_value_uint(root, "lanes", log->lanes);
	json_object_add_value_uint(root, "epl", log->epl);
	json_object_add_value_uint(root, "lspfc", log->lspfc);
	json_object_add_value_uint(root, "li", log->li);
	json_object_add_value_uint(root, "lsic", le16_to_cpu(log->lsic));
	json_object_add_value_uint(root, "dsize", le32_to_cpu(log->dsize));
	json_object_add_value_uint(root, "nd", le16_to_cpu(log->nd));
	json_object_add_value_uint(root, "maxtb", le16_to_cpu(log->maxtb));
	json_object_add_value_uint(root, "maxlr", le16_to_cpu(log->maxlr));
	json_object_add_value_uint(root, "etgood", le16_to_cpu(log->etgood));
	json_object_add_value_uint(root, "etbetter", le16_to_cpu(log->etbetter));
	json_object_add_value_uint(root, "etbest", le16_to_cpu(log->etbest));

	if (log->eomip == NVME_PHY_RX_EOM_COMPLETED) {
		/* Save Printable Eye strings allocated to free later */
		allocated_eyes = malloc(log->nd * sizeof(char *));
		if (allocated_eyes)
			json_phy_rx_eom_descs(log, root, allocated_eyes);
	}

	if (allocated_eyes) {
		for (i = 0; i < log->nd; i++) {
			/* Free any Printable Eye strings allocated */
			if (allocated_eyes[i])
				free(allocated_eyes[i]);
		}
		free(allocated_eyes);
	}

	json_print(root);
}

static void json_media_unit_stat_log(struct nvme_media_unit_stat_log *mus)
{

	struct json_object *root = json_create_object();
	struct json_object *entries = json_create_array();
	struct json_object *entry;
	int i;

	json_object_add_value_uint(root, "nmu", le16_to_cpu(mus->nmu));
	json_object_add_value_uint(root, "cchans", le16_to_cpu(mus->cchans));
	json_object_add_value_uint(root, "sel_config", le16_to_cpu(mus->sel_config));

	for (i = 0; i < mus->nmu; i++) {
		entry = json_create_object();
		json_object_add_value_uint(entry, "muid", le16_to_cpu(mus->mus_desc[i].muid));
		json_object_add_value_uint(entry, "domainid", le16_to_cpu(mus->mus_desc[i].domainid));
		json_object_add_value_uint(entry, "endgid", le16_to_cpu(mus->mus_desc[i].endgid));
		json_object_add_value_uint(entry, "nvmsetid", le16_to_cpu(mus->mus_desc[i].nvmsetid));
		json_object_add_value_uint(entry, "cap_adj_fctr", le16_to_cpu(mus->mus_desc[i].cap_adj_fctr));
		json_object_add_value_uint(entry, "avl_spare", mus->mus_desc[i].avl_spare);
		json_object_add_value_uint(entry, "percent_used", mus->mus_desc[i].percent_used);
		json_object_add_value_uint(entry, "mucs", mus->mus_desc[i].mucs);
		json_object_add_value_uint(entry, "cio", mus->mus_desc[i].cio);
		json_array_add_value_object(entries, entry);
	}

	json_object_add_value_array(root, "mus_list", entries);

	json_print(root);
}

static void json_supported_cap_config_log(
		struct nvme_supported_cap_config_list_log *cap_log)
{
	struct json_object *root = json_create_object();
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

	json_object_add_value_uint(root, "sccn", cap_log->sccn);
	for (i = 0; i < sccn; i++) {
		capacity = json_create_object();
		json_object_add_value_uint(capacity, "cap_config_id",
			le16_to_cpu(cap_log->cap_config_desc[i].cap_config_id));
		json_object_add_value_uint(capacity, "domainid",
			le16_to_cpu(cap_log->cap_config_desc[i].domainid));
		json_object_add_value_uint(capacity, "egcn",
			le16_to_cpu(cap_log->cap_config_desc[i].egcn));
		end_list = json_create_array();
		egcn = le16_to_cpu(cap_log->cap_config_desc[i].egcn);
		for (j = 0; j < egcn; j++) {
			endurance = json_create_object();
			json_object_add_value_uint(endurance, "endgid",
				le16_to_cpu(cap_log->cap_config_desc[i].egcd[j].endgid));
			json_object_add_value_uint(endurance, "cap_adj_factor",
				le16_to_cpu(cap_log->cap_config_desc[i].egcd[j].cap_adj_factor));
			json_object_add_value_uint128(endurance, "tegcap",
				le128_to_cpu(cap_log->cap_config_desc[i].egcd[j].tegcap));
			json_object_add_value_uint128(endurance, "segcap",
				le128_to_cpu(cap_log->cap_config_desc[i].egcd[j].segcap));
			json_object_add_value_uint(endurance, "egsets",
				le16_to_cpu(cap_log->cap_config_desc[i].egcd[j].egsets));
			egsets = le16_to_cpu(cap_log->cap_config_desc[i].egcd[j].egsets);
			set_list = json_create_array();
			for (k = 0; k < egsets; k++) {
				set = json_create_object();
				json_object_add_value_uint(set, "nvmsetid",
					le16_to_cpu(cap_log->cap_config_desc[i].egcd[j].nvmsetid[k]));
				json_array_add_value_object(set_list, set);
			}
			chan_desc = (struct nvme_end_grp_chan_desc *) \
					((cap_log->cap_config_desc[i].egcd[j].nvmsetid[0]) * (sizeof(__u16)*egsets));
			egchans = le16_to_cpu(chan_desc->egchans);
			json_object_add_value_uint(endurance, "egchans",
				le16_to_cpu(chan_desc->egchans));
			chan_list = json_create_array();
			for (l = 0; l < egchans; l++) {
				channel = json_create_object();
				json_object_add_value_uint(channel, "chanid",
					le16_to_cpu(chan_desc->chan_config_desc[l].chanid));
				json_object_add_value_uint(channel, "chmus",
					le16_to_cpu(chan_desc->chan_config_desc[l].chmus));
				chmus = le16_to_cpu(chan_desc->chan_config_desc[l].chmus);
				media_list = json_create_array();
				for (m = 0; m < chmus; m++) {
					media = json_create_object();
					json_object_add_value_uint(media, "chanid",
						le16_to_cpu(chan_desc->chan_config_desc[l].mu_config_desc[m].muid));
					json_object_add_value_uint(media, "chmus",
						le16_to_cpu(chan_desc->chan_config_desc[l].mu_config_desc[m].mudl));
					json_array_add_value_object(media_list, media);
				}
				json_object_add_value_array(channel, "Media Descriptor", media_list);
				json_array_add_value_object(chan_list, channel);
			}
			json_object_add_value_array(endurance, "Channel Descriptor", chan_list);
			json_object_add_value_array(endurance, "NVM Set IDs", set_list);
			json_array_add_value_object(end_list, endurance);
		}
		json_object_add_value_array(capacity, "Endurance Descriptor", end_list);
		json_array_add_value_object(cap_list, capacity);
	}

	json_object_add_value_array(root, "Capacity Descriptor", cap_list);

	json_print(root);
}

static void json_nvme_fdp_configs(struct nvme_fdp_config_log *log, size_t len)
{
	struct json_object *root, *obj_configs;
	uint16_t n;

	void *p = log->configs;

	root = json_create_object();
	obj_configs = json_create_array();

	n = le16_to_cpu(log->n);

	json_object_add_value_uint(root, "n", n);

	for (int i = 0; i < n + 1; i++) {
		struct nvme_fdp_config_desc *config = p;

		struct json_object *obj_config = json_create_object();
		struct json_object *obj_ruhs = json_create_array();

		json_object_add_value_uint(obj_config, "fdpa", config->fdpa);
		json_object_add_value_uint(obj_config, "vss", config->vss);
		json_object_add_value_uint(obj_config, "nrg", le32_to_cpu(config->nrg));
		json_object_add_value_uint(obj_config, "nruh", le16_to_cpu(config->nruh));
		json_object_add_value_uint(obj_config, "nnss", le32_to_cpu(config->nnss));
		obj_add_uint64(obj_config, "runs", le64_to_cpu(config->runs));
		json_object_add_value_uint(obj_config, "erutl", le32_to_cpu(config->erutl));

		for (int j = 0; j < le16_to_cpu(config->nruh); j++) {
			struct nvme_fdp_ruh_desc *ruh = &config->ruhs[j];

			struct json_object *obj_ruh = json_create_object();

			json_object_add_value_uint(obj_ruh, "ruht", ruh->ruht);

			json_array_add_value_object(obj_ruhs, obj_ruh);
		}

		json_array_add_value_object(obj_configs, obj_config);

		p += config->size;
	}

	json_object_add_value_array(root, "configs", obj_configs);

	json_print(root);
}

static void json_nvme_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len)
{
	struct json_object *root, *obj_ruhus;
	uint16_t nruh;

	root = json_create_object();
	obj_ruhus = json_create_array();

	nruh = le16_to_cpu(log->nruh);

	json_object_add_value_uint(root, "nruh", nruh);

	for (int i = 0; i < nruh; i++) {
		struct nvme_fdp_ruhu_desc *ruhu = &log->ruhus[i];

		struct json_object *obj_ruhu = json_create_object();

		json_object_add_value_uint(obj_ruhu, "ruha", ruhu->ruha);

		json_array_add_value_object(obj_ruhus, obj_ruhu);
	}

	json_object_add_value_array(root, "ruhus", obj_ruhus);

	json_print(root);
}

static void json_nvme_fdp_stats(struct nvme_fdp_stats_log *log)
{
	struct json_object *root = json_create_object();

	json_object_add_value_uint128(root, "hbmw", le128_to_cpu(log->hbmw));
	json_object_add_value_uint128(root, "mbmw", le128_to_cpu(log->mbmw));
	json_object_add_value_uint128(root, "mbe", le128_to_cpu(log->mbe));

	json_print(root);
}

static void json_nvme_fdp_events(struct nvme_fdp_events_log *log)
{
	struct json_object *root, *obj_events;
	uint32_t n;

	root = json_create_object();
	obj_events = json_create_array();

	n = le32_to_cpu(log->n);

	json_object_add_value_uint(root, "n", n);

	for (unsigned int i = 0; i < n; i++) {
		struct nvme_fdp_event *event = &log->events[i];

		struct json_object *obj_event = json_create_object();

		json_object_add_value_uint(obj_event, "type", event->type);
		json_object_add_value_uint(obj_event, "fdpef", event->flags);
		json_object_add_value_uint(obj_event, "pid", le16_to_cpu(event->pid));
		obj_add_uint64(obj_event, "timestamp", le64_to_cpu(*(uint64_t *)&event->ts));
		json_object_add_value_uint(obj_event, "nsid", le32_to_cpu(event->nsid));

		if (event->type == NVME_FDP_EVENT_REALLOC) {
			struct nvme_fdp_event_realloc *mr;
			mr = (struct nvme_fdp_event_realloc *)&event->type_specific;

			json_object_add_value_uint(obj_event, "nlbam", le16_to_cpu(mr->nlbam));

			if (mr->flags & NVME_FDP_EVENT_REALLOC_F_LBAV)
				obj_add_uint64(obj_event, "lba", le64_to_cpu(mr->lba));
		}

		json_array_add_value_object(obj_events, obj_event);
	}

	json_object_add_value_array(root, "events", obj_events);

	json_print(root);
}

static void json_nvme_fdp_ruh_status(struct nvme_fdp_ruh_status *status, size_t len)
{
	struct json_object *root, *obj_ruhss;
	uint16_t nruhsd;

	root = json_create_object();
	obj_ruhss = json_create_array();

	nruhsd = le16_to_cpu(status->nruhsd);

	json_object_add_value_uint(root, "nruhsd", nruhsd);

	for (unsigned int i = 0; i < nruhsd; i++) {
		struct nvme_fdp_ruh_status_desc *ruhs = &status->ruhss[i];

		struct json_object *obj_ruhs = json_create_object();

		json_object_add_value_uint(obj_ruhs, "pid", le16_to_cpu(ruhs->pid));
		json_object_add_value_uint(obj_ruhs, "ruhid", le16_to_cpu(ruhs->ruhid));
		json_object_add_value_uint(obj_ruhs, "earutr", le32_to_cpu(ruhs->earutr));
		obj_add_uint64(obj_ruhs, "ruamw", le64_to_cpu(ruhs->ruamw));

		json_array_add_value_object(obj_ruhss, obj_ruhs);
	}

	json_object_add_value_array(root, "ruhss", obj_ruhss);

	json_print(root);
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
		json_array_add_value_object(paths, path_attrs);
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
		json_array_add_value_object(paths, path_attrs);
	}
}

static void json_print_nvme_subsystem_list(nvme_root_t r, bool show_ana)

{
	struct json_object *host_attrs, *subsystem_attrs;
	struct json_object *subsystems, *paths;
	struct json_object *root = json_create_array();
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
			obj_add_str(subsystem_attrs, "IOPolicy", nvme_subsystem_get_iopolicy(s));

			json_array_add_value_object(subsystems, subsystem_attrs);
			paths = json_create_array();

			if (!show_ana || !json_print_nvme_subsystem_multipath(s, paths))
				json_print_nvme_subsystem_ctrls(s, paths);

			json_object_add_value_array(subsystem_attrs, "Paths",
						    paths);
		}
		json_object_add_value_array(host_attrs, "Subsystems", subsystems);
		json_array_add_value_object(root, host_attrs);
	}

	json_print(root);
}

static void json_ctrl_registers(void *bar, bool fabrics)
{
	struct json_object *root = json_create_object();
	uint64_t cap = mmio_read64(bar + NVME_REG_CAP);
	uint32_t vs = mmio_read32(bar + NVME_REG_VS);
	uint32_t intms = mmio_read32(bar + NVME_REG_INTMS);
	uint32_t intmc = mmio_read32(bar + NVME_REG_INTMC);
	uint32_t cc = mmio_read32(bar + NVME_REG_CC);
	uint32_t csts = mmio_read32(bar + NVME_REG_CSTS);
	uint32_t nssr = mmio_read32(bar + NVME_REG_NSSR);
	uint32_t crto = mmio_read32(bar + NVME_REG_CRTO);
	uint32_t aqa = mmio_read32(bar + NVME_REG_AQA);
	uint64_t asq = mmio_read64(bar + NVME_REG_ASQ);
	uint64_t acq = mmio_read64(bar + NVME_REG_ACQ);
	uint32_t cmbloc = mmio_read32(bar + NVME_REG_CMBLOC);
	uint32_t cmbsz = mmio_read32(bar + NVME_REG_CMBSZ);
	uint32_t bpinfo = mmio_read32(bar + NVME_REG_BPINFO);
	uint32_t bprsel = mmio_read32(bar + NVME_REG_BPRSEL);
	uint64_t bpmbl = mmio_read64(bar + NVME_REG_BPMBL);
	uint64_t cmbmsc = mmio_read64(bar + NVME_REG_CMBMSC);
	uint32_t cmbsts = mmio_read32(bar + NVME_REG_CMBSTS);
	uint32_t pmrcap = mmio_read32(bar + NVME_REG_PMRCAP);
	uint32_t pmrctl = mmio_read32(bar + NVME_REG_PMRCTL);
	uint32_t pmrsts = mmio_read32(bar + NVME_REG_PMRSTS);
	uint32_t pmrebs = mmio_read32(bar + NVME_REG_PMREBS);
	uint32_t pmrswtp = mmio_read32(bar + NVME_REG_PMRSWTP);
	uint32_t pmrmscl = mmio_read32(bar + NVME_REG_PMRMSCL);
	uint32_t pmrmscu = mmio_read32(bar + NVME_REG_PMRMSCU);

	root_add_uint64("cap", cap);
	root_add_int("vs", vs);
	root_add_int("intms", intms);
	root_add_int("intmc", intmc);
	root_add_int("cc", cc);
	root_add_int("csts", csts);
	root_add_int("nssr", nssr);
	root_add_int("crto", crto);
	root_add_int("aqa", aqa);
	root_add_uint64("asq", asq);
	root_add_uint64("acq", acq);
	root_add_int("cmbloc", cmbloc);
	root_add_int("cmbsz", cmbsz);
	root_add_int("bpinfo", bpinfo);
	root_add_int("bprsel", bprsel);
	root_add_uint64("bpmbl", bpmbl);
	root_add_uint64("cmbmsc", cmbmsc);
	root_add_int("cmbsts", cmbsts);
	root_add_int("pmrcap", pmrcap);
	root_add_int("pmrctl", pmrctl);
	root_add_int("pmrsts", pmrsts);
	root_add_int("pmrebs", pmrebs);
	root_add_int("pmrswtp", pmrswtp);
	json_object_add_value_uint(root, "pmrmscl", pmrmscl);
	json_object_add_value_uint(root, "pmrmscu", pmrmscu);

	json_print(root);
}

static void d_json(unsigned char *buf, int len, int width, int group, struct json_object *array)
{
	int i;
	char ascii[32 + 1] = { 0 };

	assert(width < sizeof(ascii));

	for (i = 0; i < len; i++) {
		ascii[i % width] = (buf[i] >= '!' && buf[i] <= '~') ? buf[i] : '.';
		if (!((i + 1) % width)) {
			json_array_add_value_string(array, ascii);
			memset(ascii, 0, sizeof(ascii));
		}
	}

	if (strlen(ascii)) {
		ascii[i % width + 1] = '\0';
		json_array_add_value_string(array, ascii);
	}
}

static void json_nvme_cmd_set_independent_id_ns(
		struct nvme_id_independent_id_ns *ns,
		unsigned int nsid)
{
	struct json_object *root = json_create_object();

	root_add_int("nsfeat", ns->nsfeat);
	root_add_int("nmic", ns->nmic);
	root_add_int("rescap", ns->rescap);
	root_add_int("fpi", ns->fpi);
	json_object_add_value_uint(root, "anagrpid", le32_to_cpu(ns->anagrpid));
	root_add_int("nsattr", ns->nsattr);
	root_add_int("nvmsetid", le16_to_cpu(ns->nvmsetid));
	root_add_int("endgid", le16_to_cpu(ns->endgid));
	root_add_int("nstat", ns->nstat);

	json_print(root);
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
	struct json_object *root = json_create_object();
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
			obj_add_str(elem, "type", nidt_name);
			obj_add_str(elem, nidt_name, json_str);

			if (!json_array)
				json_array = json_create_array();
			json_array_add_value_object(json_array, elem);
		}

		len += sizeof(*cur);
	}

	if (json_array)
		json_object_add_value_array(root, "ns-descs", json_array);

	json_print(root);
}

static void json_nvme_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm)
{
	struct json_object *root = json_create_object();

	json_object_add_value_uint(root, "vsl", ctrl_nvm->vsl);
	json_object_add_value_uint(root, "wzsl", ctrl_nvm->wzsl);
	json_object_add_value_uint(root, "wusl", ctrl_nvm->wusl);
	json_object_add_value_uint(root, "dmrl", ctrl_nvm->dmrl);
	json_object_add_value_uint(root, "dmrsl", le32_to_cpu(ctrl_nvm->dmrsl));
	root_add_uint64("dmsl", le64_to_cpu(ctrl_nvm->dmsl));

	json_print(root);
}

static void json_nvme_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns,
				unsigned int nsid, struct nvme_id_ns *ns,
				unsigned int lba_index, bool cap_only)

{
	struct json_object *root = json_create_object();
	struct json_object *elbafs = json_create_array();
	int i;

	if (!cap_only)
		root_add_uint64("lbstm", le64_to_cpu(nvm_ns->lbstm));

	root_add_int("pic", nvm_ns->pic);

	json_object_add_value_array(root, "elbafs", elbafs);

	for (i = 0; i <= ns->nlbaf; i++) {
		struct json_object *elbaf = json_create_object();
		unsigned int elbaf_val = le32_to_cpu(nvm_ns->elbaf[i]);

		json_object_add_value_uint(elbaf, "sts", elbaf_val & 0x7F);
		json_object_add_value_uint(elbaf, "pif", (elbaf_val >> 7) & 0x3);

		json_array_add_value_object(elbafs, elbaf);
	}

	json_print(root);
}

static void json_nvme_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl)
{
	struct json_object *root = json_create_object();

	root_add_int("zasl", ctrl->zasl);

	json_print(root);
}

static void json_nvme_zns_id_ns(struct nvme_zns_id_ns *ns,
				struct nvme_id_ns *id_ns)
{
	struct json_object *root = json_create_object();
	struct json_object *lbafs = json_create_array();
	int i;

	root_add_int("zoc", le16_to_cpu(ns->zoc));
	root_add_int("ozcs", le16_to_cpu(ns->ozcs));
	json_object_add_value_uint(root, "mar", le32_to_cpu(ns->mar));
	json_object_add_value_uint(root, "mor", le32_to_cpu(ns->mor));
	json_object_add_value_uint(root, "rrl", le32_to_cpu(ns->rrl));
	json_object_add_value_uint(root, "frl", le32_to_cpu(ns->frl));
	json_object_add_value_uint(root, "rrl1", le32_to_cpu(ns->rrl1));
	json_object_add_value_uint(root, "rrl2", le32_to_cpu(ns->rrl2));
	json_object_add_value_uint(root, "rrl3", le32_to_cpu(ns->rrl3));
	json_object_add_value_uint(root, "frl1", le32_to_cpu(ns->frl1));
	json_object_add_value_uint(root, "frl2", le32_to_cpu(ns->frl2));
	json_object_add_value_uint(root, "frl3", le32_to_cpu(ns->frl3));
	json_object_add_value_uint(root, "numzrwa", le32_to_cpu(ns->numzrwa));
	root_add_int("zrwafg", le16_to_cpu(ns->zrwafg));
	root_add_int("zrwasz", le16_to_cpu(ns->zrwasz));
	root_add_int("zrwacap", ns->zrwacap);

	json_object_add_value_array(root, "lbafe", lbafs);

	for (i = 0; i <= id_ns->nlbaf; i++) {
		struct json_object *lbaf = json_create_object();

		obj_add_uint64(lbaf, "zsze", le64_to_cpu(ns->lbafe[i].zsze));
		obj_add_int(lbaf, "zdes", ns->lbafe[i].zdes);

		json_array_add_value_object(lbafs, lbaf);
	}

	json_print(root);
}

static void json_nvme_list_ns(struct nvme_ns_list *ns_list)
{
	struct json_object *root = json_create_object();
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();
	int i;

	for (i = 0; i < 1024; i++) {
		if (ns_list->ns[i]) {
			valid_attrs = json_create_object();
			json_object_add_value_uint(valid_attrs, "nsid",
				le32_to_cpu(ns_list->ns[i]));
			json_array_add_value_object(valid, valid_attrs);
		}
	}

	json_object_add_value_array(root, "nsid_list", valid);

	json_print(root);
}

static void json_zns_start_zone_list(__u64 nr_zones, struct json_object **zone_list)
{
	*zone_list = json_create_array();
}

static void json_zns_changed(struct nvme_zns_changed_zone_log *log)
{
	struct json_object *root = json_create_object();
	char json_str[STR_LEN];
	uint16_t nrzid = le16_to_cpu(log->nrzid);
	int i;

	if (nrzid == 0xFFFF) {
		root_add_result("Too many zones have changed to fit into the log. Use report zones for changes.");
	} else {
		root_add_uint("nrzid", nrzid);
		for (i = 0; i < nrzid; i++) {
			sprintf(json_str, "zid %03d", i);
			root_add_uint64(json_str, (uint64_t)le64_to_cpu(log->zid[i]));
		}
	}

	json_print(root);
}

static void json_zns_finish_zone_list(__u64 nr_zones,
				      struct json_object *zone_list)
{
	struct json_object *root = json_create_object();

	json_object_add_value_uint(root, "nr_zones", nr_zones);
	json_object_add_value_array(root, "zone_list", zone_list);

	json_print(root);
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
		json_object_add_value_uint(zone, "attrs", desc->za);
		json_object_add_value_uint(zone, "attrs_info", desc->zai);

		if (ext_size) {
			if (desc->za & NVME_ZNS_ZA_ZDEV) {
				ext_data = json_create_array();
				d_json((unsigned char *)desc + sizeof(*desc),
					ext_size, 16, 1, ext_data);
				json_object_add_value_array(zone, "ext_data",
					ext_data);
			} else {
				obj_add_str(zone, "ext_data", "Not valid");
			}
		}

		json_array_add_value_object(zone_list, zone);
	}
}

static void json_feature_show_fields_arbitration(unsigned int result)
{
	struct json_object *root = json_create_object();
	char json_str[STR_LEN];

	root_add_uint("High Priority Weight (HPW)", ((result & 0xff000000) >> 24) + 1);
	root_add_uint("Medium Priority Weight (MPW)", ((result & 0xff0000) >> 16) + 1);
	root_add_uint("Low Priority Weight (LPW)", ((result & 0xff00) >> 8) + 1);

	if ((result & 7) == 7)
		sprintf(json_str, "No limit");
	else
		sprintf(json_str, "%u", 1 << (result & 7));

	root_add_str("Arbitration Burst (AB)", json_str);

	json_print(root);
}

static void json_feature_show_fields_power_mgmt(unsigned int result)
{
	struct json_object *root = json_create_object();
	__u8 field = (result & 0xe0) >> 5;

	root_add_uint("Workload Hint (WH)", field);
	root_add_str("WH description", nvme_feature_wl_hints_to_string(field));
	root_add_uint("Power State (PS)", result & 0x1f);

	json_print(root);
}

static void json_lba_range_entry(struct nvme_lba_range_type *lbrt, int nr_ranges,
				 struct json_object *root)
{
	char json_str[STR_LEN];
	struct json_object *lbare;
	int i;
	int j;
	struct json_object *lbara = json_create_array();

	root_add_array("LBA Ranges", lbara);

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

static void json_feature_show_fields_lba_range(__u8 field, unsigned char *buf)
{
	struct json_object *root = json_create_object();

	root_add_uint("Number of LBA Ranges (NUM)", field + 1);

	if (buf)
		json_lba_range_entry((struct nvme_lba_range_type *)buf, field, root);

	json_print(root);
}

static void json_feature_show_fields_temp_thresh(unsigned int result)
{
	struct json_object *root = json_create_object();
	__u8 field = (result & 0x300000) >> 20;
	char json_str[STR_LEN];

	root_add_uint("Threshold Type Select (THSEL)", field);
	root_add_str("THSEL description", nvme_feature_temp_type_to_string(field));

	field = (result & 0xf0000) >> 16;

	root_add_uint("Threshold Temperature Select (TMPSEL)", field);
	root_add_str("TMPSEL description", nvme_feature_temp_sel_to_string(field));

	sprintf(json_str, "%ld Celsius", kelvin_to_celsius(result & 0xffff));
	root_add_str("Temperature Threshold (TMPTH)", json_str);

	sprintf(json_str, "%u K", result & 0xffff);
	root_add_str("TMPTH kelvin", json_str);

	json_print(root);
}

static void json_feature_show_fields_err_recovery(unsigned int result)
{
	struct json_object *root = json_create_object();
	char json_str[STR_LEN];

	root_add_str("Deallocated or Unwritten Logical Block Error Enable (DULBE)",
		     (result & 0x10000) >> 16 ? enabled : disabled);

	sprintf(json_str, "%u ms", (result & 0xffff) * 100);
	root_add_str("Time Limited Error Recovery (TLER)", json_str);

	json_print(root);
}

static void json_feature_show_fields_volatile_wc(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_str("Volatile Write Cache Enable (WCE)", result & 1 ? enabled : disabled);

	json_print(root);
}

static void json_feature_show_fields_num_queues(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_uint("Number of IO Completion Queues Allocated (NCQA)",
		      ((result & 0xffff0000) >> 16) + 1);

	root_add_uint("Number of IO Submission Queues Allocated (NSQA)", (result & 0xffff) + 1);

	json_print(root);
}

static void json_feature_show_fields_irq_coalesce(unsigned int result)
{
	struct json_object *root = json_create_object();
	char json_str[STR_LEN];

	sprintf(json_str, "%u usec", ((result & 0xff00) >> 8) * 100);
	root_add_str("Aggregation Time (TIME)", json_str);

	root_add_uint("Aggregation Threshold (THR)", (result & 0xff) + 1);

	json_print(root);
}

static void json_feature_show_fields_irq_config(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_str("Coalescing Disable (CD)", (result & 0x10000) >> 16 ? true_str : false_str);

	root_add_uint("Interrupt Vector (IV)", result & 0xffff);

	json_print(root);
}

static void json_feature_show_fields_write_atomic(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_str("Disable Normal (DN)", result & 1 ? true_str : false_str);

	json_print(root);
}

static void json_feature_show_fields_async_event(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_str("Discovery Log Page Change Notices", (result & 0x80000000) >> 31 ?
		     "Send async event" : "Do not send async event");
	root_add_str("Endurance Group Event Aggregate Log Change Notices", (result & 0x4000) >> 14 ?
		     "Send async event" : "Do not send async event");
	root_add_str("LBA Status Information Notices", (result & 0x2000) >> 13 ?
		     "Send async event" : "Do not send async event");
	root_add_str("Predictable Latency Event Aggregate Log Change Notices",
		     (result & 0x1000) >> 12 ? "Send async event" : "Do not send async event");
	root_add_str("Asymmetric Namespace Access Change Notices", (result & 0x800) >> 11 ?
		     "Send async event" : "Do not send async event");
	root_add_str("Telemetry Log Notices", (result & 0x400) >> 10 ? "Send async event" :
		     "Do not send async event");
	root_add_str("Firmware Activation Notices", (result & 0x200) >> 9 ? "Send async event" :
		     "Do not send async event");
	root_add_str("Namespace Attribute Notices", (result & 0x100) >> 8 ? "Send async event" :
		     "Do not send async event");
	root_add_str("SMART / Health Critical Warnings", result & 0xff ? "Send async event" :
		     "Do not send async event");

	json_print(root);
}

static void json_auto_pst(struct nvme_feat_auto_pst *apst, struct json_object *root)
{
	int i;
	__u64 value;
	char json_str[STR_LEN];
	struct json_object *apsta = json_create_array();
	struct json_object *apste;

	root_add_array("Auto PST Entries", apsta);

	for (i = 0; i < ARRAY_SIZE(apst->apst_entry); i++) {
		apste = json_create_object();
		array_add_obj(apsta, apste);
		sprintf(json_str, "%2d", i);
		obj_add_str(apste, "Entry", json_str);
		value = le64_to_cpu(apst->apst_entry[i]);
		sprintf(json_str, "%u ms", (__u32)NVME_GET(value, APST_ENTRY_ITPT));
		obj_add_str(apste, "Idle Time Prior to Transition (ITPT)", json_str);
		obj_add_uint(apste, "Idle Transition Power State (ITPS)",
			     (__u32)NVME_GET(value, APST_ENTRY_ITPS));
	}
}

static void json_feature_show_fields_auto_pst(unsigned int result, unsigned char *buf)
{
	struct json_object *root = json_create_object();

	root_add_str("Autonomous Power State Transition Enable (APSTE)", result & 1 ? enabled :
		     disabled);

	if (buf)
		json_auto_pst((struct nvme_feat_auto_pst *)buf, root);

	json_print(root);
}

static void json_host_mem_buffer(struct nvme_host_mem_buf_attrs *hmb, struct json_object *root)
{
	char json_str[STR_LEN];

	root_add_uint("Host Memory Descriptor List Entry Count (HMDLEC)", le32_to_cpu(hmb->hmdlec));

	sprintf(json_str, "0x%x", le32_to_cpu(hmb->hmdlau));
	root_add_str("Host Memory Descriptor List Address (HMDLAU)", json_str);

	sprintf(json_str, "0x%x", le32_to_cpu(hmb->hmdlal));
	root_add_str("Host Memory Descriptor List Address (HMDLAL)", json_str);

	root_add_uint("Host Memory Buffer Size (HSIZE)", le32_to_cpu(hmb->hsize));
}

static void json_feature_show_fields_host_mem_buf(unsigned int result, unsigned char *buf)
{
	struct json_object *root = json_create_object();

	root_add_str("Enable Host Memory (EHM)", result & 1 ? enabled : disabled);

	if (buf)
		json_host_mem_buffer((struct nvme_host_mem_buf_attrs *)buf, root);

	json_print(root);
}

static void json_timestamp(struct nvme_timestamp *ts)
{
	struct json_object *root = json_create_object();
	char buffer[BUF_LEN];
	time_t timestamp = int48_to_long(ts->timestamp) / 1000;
	struct tm *tm = localtime(&timestamp);

	root_add_uint64("timestamp", int48_to_long(ts->timestamp));

	if(!strftime(buffer, sizeof(buffer), "%c %Z", tm))
		sprintf(buffer, "%s", "-");

	root_add_str("timestamp string", buffer);

	root_add_str("timestamp origin", ts->attr & 2 ?
	    "The Timestamp field was initialized with a Timestamp value using a Set Features command." :
	    "The Timestamp field was initialized to 0h by a Controller Level Reset.");

	root_add_str("synch", ts->attr & 1 ?
	    "The controller may have stopped counting during vendor specific intervals after the Timestamp value was initialized." :
	    "The controller counted time in milliseconds continuously since the Timestamp value was initialized.");

	json_print(root);
}

static void json_feature_show_fields_timestamp(unsigned char *buf)
{
	if (buf)
		json_timestamp((struct nvme_timestamp *)buf);
}

static void json_feature_show_fields_kato(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_uint("Keep Alive Timeout (KATO) in milliseconds", result);

	json_print(root);
}

static void json_feature_show_fields_hctm(unsigned int result)
{
	struct json_object *root = json_create_object();
	char json_str[STR_LEN];

	sprintf(json_str, "%u K", result >> 16);
	root_add_str("Thermal Management Temperature 1 (TMT1)", json_str);

	sprintf(json_str, "%ld Celsius", kelvin_to_celsius(result >> 16));
	root_add_str("TMT1 celsius", json_str);

	sprintf(json_str, "%u K", result & 0xffff);
	root_add_str("Thermal Management Temperature 2", json_str);

	sprintf(json_str, "%ld Celsius", kelvin_to_celsius(result & 0xffff));
	root_add_str("TMT2 celsius", json_str);

	json_print(root);
}

static void json_feature_show_fields_nopsc(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_str("Non-Operational Power State Permissive Mode Enable (NOPPME)", result & 1 ?
		     true_str : false_str);

	json_print(root);
}

static void json_feature_show_fields_rrl(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_uint("Read Recovery Level (RRL)", result & 0xf);

	json_print(root);
}

static void json_plm_config(struct nvme_plm_config *plmcfg, struct json_object *root)
{
	char json_str[STR_LEN];

	sprintf(json_str, "%04x", le16_to_cpu(plmcfg->ee));
	root_add_str("Enable Event", json_str);

	root_add_uint64("DTWIN Reads Threshold", le64_to_cpu(plmcfg->dtwinrt));
	root_add_uint64("DTWIN Writes Threshold", le64_to_cpu(plmcfg->dtwinwt));
	root_add_uint64("DTWIN Time Threshold", le64_to_cpu(plmcfg->dtwintt));
}

static void json_feature_show_fields_plm_config(unsigned int result, unsigned char *buf)
{
	struct json_object *root = json_create_object();

	root_add_str("Predictable Latency Window Enabled", result & 1 ? true_str : false_str);

	if (buf)
		json_plm_config((struct nvme_plm_config *)buf, root);

	json_print(root);
}

static void json_feature_show_fields_plm_window(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_str("Window Select", nvme_plm_window_to_string(result));

	json_print(root);
}

static void json_feature_show_fields_lba_sts_interval(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_uint("LBA Status Information Poll Interval (LSIPI)", result >> 16);
	root_add_uint("LBA Status Information Report Interval (LSIRI)", result & 0xffff);

	json_print(root);
}

static void json_feature_show_fields_host_behavior(unsigned char *buf)
{
	struct json_object *root = json_create_object();

	if (buf)
		root_add_str("Host Behavior Support", buf[0] & 0x1 ? true_str : false_str);

	json_print(root);
}

static void json_feature_show_fields_sanitize(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_uint("No-Deallocate Response Mode (NODRM)", result & 1);

	json_print(root);
}

static void json_feature_show_fields_endurance_evt_cfg(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_uint("Endurance Group Identifier (ENDGID)", result & 0xffff);
	root_add_uint("Endurance Group Critical Warnings", result >> 16 & 0xff);

	json_print(root);
}

static void json_feature_show_fields_iocs_profile(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_str("I/O Command Set Profile", result & 0x1 ? true_str : false_str);

	json_print(root);
}

static void json_feature_show_fields_spinup_control(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_str("Spinup control feature Enabled", result & 1 ? true_str : false_str);

	json_print(root);
}

static void json_host_metadata(enum nvme_features_id fid, struct nvme_host_metadata *data)
{
	struct json_object *root = json_create_object();
	struct nvme_metadata_element_desc *desc = &data->descs[0];
	int i;
	char val[VAL_LEN];
	__u16 len;
	char json_str[STR_LEN];
	struct json_object *desca = json_create_array();
	struct json_object *desce;

	root_add_int("Num Metadata Element Descriptors", data->ndesc);

	root_add_array("Metadata Element Descriptors", desca);

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

	json_print(root);
}

static void json_feature_show_fields_ns_metadata(enum nvme_features_id fid, unsigned char *buf)
{
	if (buf)
		json_host_metadata(fid, (struct nvme_host_metadata *)buf);
}

static void json_feature_show_fields_sw_progress(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_uint("Pre-boot Software Load Count (PBSLC)", result & 0xff);

	json_print(root);
}

static void json_feature_show_fields_host_id(unsigned char *buf)
{
	struct json_object *root = json_create_object();
	uint64_t ull = 0;
	int i;

	if (buf) {
		for (i = sizeof(ull) / sizeof(*buf); i; i--) {
			ull |=  buf[i - 1];
			if (i - 1)
				ull <<= BYTE_TO_BIT(sizeof(buf[i]));
		}
		root_add_uint64("Host Identifier (HOSTID)", ull);
	}

	json_print(root);
}

static void json_feature_show_fields_resv_mask(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_str("Mask Reservation Preempted Notification (RESPRE)", (result & 8) >> 3 ?
		     true_str : false_str);
	root_add_str("Mask Reservation Released Notification (RESREL)", (result & 4) >> 2 ?
		     true_str : false_str);
	root_add_str("Mask Registration Preempted Notification (REGPRE)", (result & 2) >> 1 ?
		     true_str : false_str);

	json_print(root);
}

static void json_feature_show_fields_resv_persist(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_str("Persist Through Power Loss (PTPL)", result & 1 ? true_str : false_str);

	json_print(root);
}

static void json_feature_show_fields_write_protect(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_str("Namespace Write Protect", nvme_ns_wp_cfg_to_string(result));

	json_print(root);
}

static void json_feature_show_fields_fdp(unsigned int result)
{
	struct json_object *root = json_create_object();

	root_add_str("Flexible Direct Placement Enable (FDPE)", result & 1 ? yes : no);
	root_add_uint("Flexible Direct Placement Configuration Index", result >> 8 & 0xf);

	json_print(root);
}

static void json_feature_show_fields_fdp_events(unsigned int result, unsigned char *buf)
{
	struct json_object *root = json_create_object();
	unsigned int i;
	struct nvme_fdp_supported_event_desc *d;
	char json_str[STR_LEN];

	for (i = 0; i < result; i++) {
		d = &((struct nvme_fdp_supported_event_desc *)buf)[i];
		sprintf(json_str, "%sEnabled", d->evta & 0x1 ? "" : "Not ");
		root_add_str(nvme_fdp_event_to_string(d->evt), json_str);
	}

	json_print(root);
}

static void json_feature_show(enum nvme_features_id fid, int sel, unsigned int result)
{
	struct json_object *root = json_create_object();
	char json_str[STR_LEN];

	sprintf(json_str, "%#0*x", fid ? 4 : 2, fid);
	root_add_str("feature", json_str);

	root_add_str("name", nvme_feature_to_string(fid));

	sprintf(json_str, "%#0*x", result ? 10 : 8, result);
	root_add_str(nvme_select_to_string(sel), json_str);

	json_print(root);
}

static void json_feature_show_fields(enum nvme_features_id fid, unsigned int result,
				     unsigned char *buf)
{
	switch (fid) {
	case NVME_FEAT_FID_ARBITRATION:
		json_feature_show_fields_arbitration(result);
		break;
	case NVME_FEAT_FID_POWER_MGMT:
		json_feature_show_fields_power_mgmt(result);
		break;
	case NVME_FEAT_FID_LBA_RANGE:
		json_feature_show_fields_lba_range(result & 0x3f, buf);
		break;
	case NVME_FEAT_FID_TEMP_THRESH:
		json_feature_show_fields_temp_thresh(result);
		break;
	case NVME_FEAT_FID_ERR_RECOVERY:
		json_feature_show_fields_err_recovery(result);
		break;
	case NVME_FEAT_FID_VOLATILE_WC:
		json_feature_show_fields_volatile_wc(result);
		break;
	case NVME_FEAT_FID_NUM_QUEUES:
		json_feature_show_fields_num_queues(result);
		break;
	case NVME_FEAT_FID_IRQ_COALESCE:
		json_feature_show_fields_irq_coalesce(result);
		break;
	case NVME_FEAT_FID_IRQ_CONFIG:
		json_feature_show_fields_irq_config(result);
		break;
	case NVME_FEAT_FID_WRITE_ATOMIC:
		json_feature_show_fields_write_atomic(result);
		break;
	case NVME_FEAT_FID_ASYNC_EVENT:
		json_feature_show_fields_async_event(result);
		break;
	case NVME_FEAT_FID_AUTO_PST:
		json_feature_show_fields_auto_pst(result, buf);
		break;
	case NVME_FEAT_FID_HOST_MEM_BUF:
		json_feature_show_fields_host_mem_buf(result, buf);
		break;
	case NVME_FEAT_FID_TIMESTAMP:
		json_feature_show_fields_timestamp(buf);
		break;
	case NVME_FEAT_FID_KATO:
		json_feature_show_fields_kato(result);
		break;
	case NVME_FEAT_FID_HCTM:
		json_feature_show_fields_hctm(result);
		break;
	case NVME_FEAT_FID_NOPSC:
		json_feature_show_fields_nopsc(result);
		break;
	case NVME_FEAT_FID_RRL:
		json_feature_show_fields_rrl(result);
		break;
	case NVME_FEAT_FID_PLM_CONFIG:
		json_feature_show_fields_plm_config(result, buf);
		break;
	case NVME_FEAT_FID_PLM_WINDOW:
		json_feature_show_fields_plm_window(result);
		break;
	case NVME_FEAT_FID_LBA_STS_INTERVAL:
		json_feature_show_fields_lba_sts_interval(result);
		break;
	case NVME_FEAT_FID_HOST_BEHAVIOR:
		json_feature_show_fields_host_behavior(buf);
		break;
	case NVME_FEAT_FID_SANITIZE:
		json_feature_show_fields_sanitize(result);
		break;
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:
		json_feature_show_fields_endurance_evt_cfg(result);
		break;
	case NVME_FEAT_FID_IOCS_PROFILE:
		json_feature_show_fields_iocs_profile(result);
		break;
	case NVME_FEAT_FID_SPINUP_CONTROL:
		json_feature_show_fields_spinup_control(result);
		break;
	case NVME_FEAT_FID_ENH_CTRL_METADATA:
		fallthrough;
	case NVME_FEAT_FID_CTRL_METADATA:
		fallthrough;
	case NVME_FEAT_FID_NS_METADATA:
		json_feature_show_fields_ns_metadata(fid, buf);
		break;
	case NVME_FEAT_FID_SW_PROGRESS:
		json_feature_show_fields_sw_progress(result);
		break;
	case NVME_FEAT_FID_HOST_ID:
		json_feature_show_fields_host_id(buf);
		break;
	case NVME_FEAT_FID_RESV_MASK:
		json_feature_show_fields_resv_mask(result);
		break;
	case NVME_FEAT_FID_RESV_PERSIST:
		json_feature_show_fields_resv_persist(result);
		break;
	case NVME_FEAT_FID_WRITE_PROTECT:
		json_feature_show_fields_write_protect(result);
		break;
	case NVME_FEAT_FID_FDP:
		json_feature_show_fields_fdp(result);
		break;
	case NVME_FEAT_FID_FDP_EVENTS:
		json_feature_show_fields_fdp_events(result, buf);
		break;
	default:
		break;
	}
}

void json_id_ctrl_rpmbs(__le32 ctrl_rpmbs)
{
	struct json_object *root = json_create_object();
	__u32 rpmbs = le32_to_cpu(ctrl_rpmbs);
	__u32 asz = (rpmbs & 0xFF000000) >> 24;
	__u32 tsz = (rpmbs & 0xFF0000) >> 16;
	__u32 rsvd = (rpmbs & 0xFFC0) >> 6;
	__u32 auth = (rpmbs & 0x38) >> 3;
	__u32 rpmb = rpmbs & 7;

	root_add_uint_nx("[31:24]: Access Size", asz);
	root_add_uint_nx("[23:16]: Total Size", tsz);

	if (rsvd)
		root_add_uint_nx("[15:6]: Reserved", rsvd);

	root_add_uint_nx("[5:3]: Authentication Method", auth);
	root_add_uint_nx("[2:0]: Number of RPMB Units", rpmb);

	json_print(root);
}

static void json_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges)
{
	struct json_object *root = json_create_object();

	json_lba_range_entry(lbrt, nr_ranges, root);

	json_print(root);
}

static void json_lba_status_info(__u32 result)
{
	struct json_object *root = json_create_object();

	root_add_uint("LBA Status Information Poll Interval (LSIPI)", (result >> 16) & 0xffff);
	root_add_uint("LBA Status Information Report Interval (LSIRI)", result & 0xffff);

	json_print(root);
}

void json_d(unsigned char *buf, int len, int width, int group)
{
	struct json_object *root = json_create_object();
	struct json_object *data = json_create_array();

	d_json(buf, len, width, group, data);
	json_object_add_value_array(root, "data", data);

	json_print(root);
}

static void json_nvme_list_ctrl(struct nvme_ctrl_list *ctrl_list)
{
	__u16 num = le16_to_cpu(ctrl_list->num);
	struct json_object *root = json_create_object();
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();
	int i;

	json_object_add_value_uint(root, "num_ctrl",
		le16_to_cpu(ctrl_list->num));

	for (i = 0; i < min(num, 2047); i++) {

		valid_attrs = json_create_object();
		json_object_add_value_uint(valid_attrs, "ctrl_id",
			le16_to_cpu(ctrl_list->identifier[i]));
		json_array_add_value_object(valid, valid_attrs);
	}

	json_object_add_value_array(root, "ctrl_list", valid);

	json_print(root);
}

static void json_nvme_id_nvmset(struct nvme_id_nvmset_list *nvmset,
				unsigned int nvmeset_id)
{
	__u32 nent = nvmset->nid;
	struct json_object *entries = json_create_array();
	struct json_object *root = json_create_object();
	int i;

	root_add_int("nid", nent);

	for (i = 0; i < nent; i++) {
		struct json_object *entry = json_create_object();

		obj_add_int(entry, "nvmset_id", le16_to_cpu(nvmset->ent[i].nvmsetid));
		obj_add_int(entry, "endurance_group_id", le16_to_cpu(nvmset->ent[i].endgid));
		json_object_add_value_uint(entry, "random_4k_read_typical",
			  le32_to_cpu(nvmset->ent[i].rr4kt));
		json_object_add_value_uint(entry, "optimal_write_size",
			  le32_to_cpu(nvmset->ent[i].ows));
		json_object_add_value_uint128(entry, "total_nvmset_cap",
			    le128_to_cpu(nvmset->ent[i].tnvmsetcap));
		json_object_add_value_uint128(entry, "unalloc_nvmset_cap",
			    le128_to_cpu(nvmset->ent[i].unvmsetcap));
		json_array_add_value_object(entries, entry);
	}

	json_object_add_value_array(root, "NVMSet", entries);

	json_print(root);
}

static void json_nvme_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *caps)
{
	struct json_object *root = json_create_object();

	json_object_add_value_uint(root, "cntlid", le16_to_cpu(caps->cntlid));
	json_object_add_value_uint(root, "portid", le16_to_cpu(caps->portid));
	json_object_add_value_uint(root, "crt",    caps->crt);

	json_object_add_value_uint(root, "vqfrt",  le32_to_cpu(caps->vqfrt));
	json_object_add_value_uint(root, "vqrfa",  le32_to_cpu(caps->vqrfa));
	root_add_int("vqrfap", le16_to_cpu(caps->vqrfap));
	root_add_int("vqprt",  le16_to_cpu(caps->vqprt));
	root_add_int("vqfrsm", le16_to_cpu(caps->vqfrsm));
	root_add_int("vqgran", le16_to_cpu(caps->vqgran));

	json_object_add_value_uint(root, "vifrt",  le32_to_cpu(caps->vifrt));
	json_object_add_value_uint(root, "virfa",  le32_to_cpu(caps->virfa));
	root_add_int("virfap", le16_to_cpu(caps->virfap));
	root_add_int("viprt",  le16_to_cpu(caps->viprt));
	root_add_int("vifrsm", le16_to_cpu(caps->vifrsm));
	root_add_int("vigran", le16_to_cpu(caps->vigran));

	json_print(root);
}

static void json_nvme_list_secondary_ctrl(const struct nvme_secondary_ctrl_list *sc_list,
					  __u32 count)
{
	const struct nvme_secondary_ctrl *sc_entry = &sc_list->sc_entry[0];
	__u32 nent = min(sc_list->num, count);
	struct json_object *entries = json_create_array();
	struct json_object *root = json_create_object();
	int i;

	root_add_int("num", nent);

	for (i = 0; i < nent; i++) {
		struct json_object *entry = json_create_object();

		obj_add_int(entry, "secondary-controller-identifier",
			    le16_to_cpu(sc_entry[i].scid));
		obj_add_int(entry, "primary-controller-identifier", le16_to_cpu(sc_entry[i].pcid));
		obj_add_int(entry, "secondary-controller-state", sc_entry[i].scs);
		obj_add_int(entry, "virtual-function-number", le16_to_cpu(sc_entry[i].vfn));
		obj_add_int(entry, "num-virtual-queues", le16_to_cpu(sc_entry[i].nvq));
		obj_add_int(entry, "num-virtual-interrupts", le16_to_cpu(sc_entry[i].nvi));
		json_array_add_value_object(entries, entry);
	}

	json_object_add_value_array(root, "secondary-controllers", entries);

	json_print(root);
}

static void json_nvme_id_ns_granularity_list(
		const struct nvme_id_ns_granularity_list *glist)
{
	int i;
	struct json_object *root = json_create_object();
	struct json_object *entries = json_create_array();

	root_add_int("attributes", glist->attributes);
	root_add_int("num-descriptors", glist->num_descriptors);

	for (i = 0; i <= glist->num_descriptors; i++) {
		struct json_object *entry = json_create_object();

		obj_add_uint64(entry, "namespace-size-granularity",
			       le64_to_cpu(glist->entry[i].nszegran));
		obj_add_uint64(entry, "namespace-capacity-granularity",
			       le64_to_cpu(glist->entry[i].ncapgran));
		json_array_add_value_object(entries, entry);
	}

	json_object_add_value_array(root, "namespace-granularity-list", entries);

	json_print(root);
}

static void json_nvme_id_uuid_list(const struct nvme_id_uuid_list *uuid_list)
{
	struct json_object *root = json_create_object();
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
		json_array_add_value_object(entries, entry);
	}

	json_object_add_value_array(root, "UUID-list", entries);

	json_print(root);
}

static void json_id_domain_list(struct nvme_id_domain_list *id_dom)
{
	struct json_object *root = json_create_object();
	struct json_object *entries = json_create_array();
	struct json_object *entry;
	int i;
	nvme_uint128_t dom_cap, unalloc_dom_cap, max_egrp_dom_cap;

	json_object_add_value_uint(root, "num_dom_entries", id_dom->num);

	for (i = 0; i < id_dom->num; i++) {
		entry = json_create_object();
		dom_cap = le128_to_cpu(id_dom->domain_attr[i].dom_cap);
		unalloc_dom_cap = le128_to_cpu(id_dom->domain_attr[i].unalloc_dom_cap);
		max_egrp_dom_cap = le128_to_cpu(id_dom->domain_attr[i].max_egrp_dom_cap);

		json_object_add_value_uint(entry, "dom_id", le16_to_cpu(id_dom->domain_attr[i].dom_id));
		json_object_add_value_uint128(entry, "dom_cap", dom_cap);
		json_object_add_value_uint128(entry, "unalloc_dom_cap", unalloc_dom_cap);
		json_object_add_value_uint128(entry, "max_egrp_dom_cap", max_egrp_dom_cap);

		json_array_add_value_object(entries, entry);
	}

	json_object_add_value_array(root, "domain_list", entries);

	json_print(root);
}

static void json_nvme_endurance_group_list(struct nvme_id_endurance_group_list *endgrp_list)
{
	struct json_object *root = json_create_object();
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();
	int i;

	json_object_add_value_uint(root, "num_endgrp_id",
		le16_to_cpu(endgrp_list->num));

	for (i = 0; i < min(le16_to_cpu(endgrp_list->num), 2047); i++) {
		valid_attrs = json_create_object();
		json_object_add_value_uint(valid_attrs, "endgrp_id",
			le16_to_cpu(endgrp_list->identifier[i]));
		json_array_add_value_object(valid, valid_attrs);
	}

	json_object_add_value_array(root, "endgrp_list", valid);

	json_print(root);
}

static void json_support_log(struct nvme_supported_log_pages *support_log,
			     const char *devname)
{
	struct json_object *root = json_create_object();
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
			json_object_add_value_uint(valid_attrs, key, support);
			json_array_add_value_object(valid, valid_attrs);
		}
	}

	json_object_add_value_object(root, "supported_logs", valid);

	json_print(root);
}

static void json_detail_list(nvme_root_t r)
{
	struct json_object *root = json_create_object();
	struct json_object *jdev = json_create_array();

	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	nvme_path_t p;
	nvme_ns_t n;

	nvme_for_each_host(r, h) {
		struct json_object *hss = json_create_object();
		struct json_object *jsslist = json_create_array();
		const char *hostid;

		obj_add_str(hss, "HostNQN", nvme_host_get_hostnqn(h));
		hostid = nvme_host_get_hostid(h);
		if (hostid)
			obj_add_str(hss, "HostID", hostid);

		nvme_for_each_subsystem(h , s) {
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

					json_array_add_value_object(jnss, jns);
				}
				json_object_add_value_object(jctrl, "Namespaces", jnss);

				nvme_ctrl_for_each_path(c, p) {
					struct json_object *jpath = json_create_object();

					obj_add_str(jpath, "Path", nvme_path_get_name(p));
					obj_add_str(jpath, "ANAState", nvme_path_get_ana_state(p));

					json_array_add_value_object(jpaths, jpath);
				}
				json_object_add_value_object(jctrl, "Paths", jpaths);

				json_array_add_value_object(jctrls, jctrl);
			}
			json_object_add_value_object(jss, "Controllers", jctrls);

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

				json_array_add_value_object(jnss, jns);
			}
			json_object_add_value_object(jss, "Namespaces", jnss);

			json_array_add_value_object(jsslist, jss);
		}

		json_object_add_value_object(hss, "Subsystems", jsslist);
		json_array_add_value_object(jdev, hss);
	}

	json_object_add_value_array(root, "Devices", jdev);

	json_print(root);
}

static struct json_object *json_list_item_obj(nvme_ns_t n)
{
	struct json_object *root = json_create_object();
	char devname[NAME_LEN] = { 0 };
	char genname[NAME_LEN] = { 0 };
	int lba = nvme_ns_get_lba_size(n);
	uint64_t nsze = nvme_ns_get_lba_count(n) * lba;
	uint64_t nuse = nvme_ns_get_lba_util(n) * lba;

	nvme_dev_full_path(n, devname, sizeof(devname));
	nvme_generic_full_path(n, genname, sizeof(genname));

	root_add_int("NameSpace", nvme_ns_get_nsid(n));
	root_add_str("DevicePath", devname);
	root_add_str("GenericPath", genname);
	root_add_str("Firmware", nvme_ns_get_firmware(n));
	root_add_str("ModelNumber", nvme_ns_get_model(n));
	root_add_str("SerialNumber", nvme_ns_get_serial(n));
	root_add_uint64("UsedBytes", nuse);
	root_add_uint64("MaximumLBA", nvme_ns_get_lba_count(n));
	root_add_uint64("PhysicalSize", nsze);
	root_add_int("SectorSize", lba);

	return root;
}

static void json_simple_list(nvme_root_t r)
{
	struct json_object *root = json_create_object();
	struct json_object *jdevices = json_create_array();

	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	nvme_ns_t n;

	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			nvme_subsystem_for_each_ns(s, n)
				json_array_add_value_object(jdevices, json_list_item_obj(n));

			nvme_subsystem_for_each_ctrl(s, c)
				nvme_ctrl_for_each_ns(c, n)
				json_array_add_value_object(jdevices, json_list_item_obj(n));
		}
	}

	json_object_add_value_array(root, "Devices", jdevices);

	json_print(root);
}

static void json_list_item(nvme_ns_t n)
{
	struct json_object *root = json_list_item_obj(n);

	json_print(root);
}

static void json_print_list_items(nvme_root_t r)
{
	if (json_print_ops.flags & VERBOSE)
		json_detail_list(r);
	else
		json_simple_list(r);
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
			json_array_add_value_object(paths, path_attrs);
		}
		json_object_add_value_array(ns_attrs, "Paths", paths);
		json_array_add_value_object(namespaces, ns_attrs);
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

			json_array_add_value_object(ctrl, ctrl_attrs);
			json_object_add_value_array(ns_attrs, "Controller", ctrl);
			json_array_add_value_object(namespaces, ns_attrs);
		}
	}
}

static void json_simple_topology(nvme_root_t r)
{
	struct json_object *host_attrs, *subsystem_attrs;
	struct json_object *subsystems, *namespaces;
	struct json_object *root = json_create_array();
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
			obj_add_str(subsystem_attrs, "IOPolicy", nvme_subsystem_get_iopolicy(s));

			json_array_add_value_object(subsystems, subsystem_attrs);
			namespaces = json_create_array();

			if (!json_subsystem_topology_multipath(s, namespaces))
				json_print_nvme_subsystem_topology(s, namespaces);

			json_object_add_value_array(subsystem_attrs, "Namespaces",
						    namespaces);
		}
		json_object_add_value_array(host_attrs, "Subsystems", subsystems);
		json_array_add_value_object(root, host_attrs);
	}

	json_print(root);
}

static void json_directive_show_fields_identify(__u8 doper, __u8 *field, struct json_object *root)
{
	struct json_object *support;
	struct json_object *enabled;
	struct json_object *persistent;

	switch (doper) {
	case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
		support = json_create_array();
		json_object_add_value_array(root, "Directive support", support);
		obj_add_str(support, "Identify Directive",
			    *field & 0x1 ? "supported" : "not supported");
		obj_add_str(support, "Stream Directive",
			    *field & 0x2 ? "supported" : "not supported");
		obj_add_str(support, "Data Placement Directive",
			    *field & 0x4 ? "supported" : "not supported");
		enabled = json_create_array();
		json_object_add_value_array(root, "Directive enabled", enabled);
		obj_add_str(enabled, "Identify Directive",
			    *(field + 32) & 0x1 ? "enabled" : "disabled");
		obj_add_str(enabled, "Stream Directive",
			    *(field + 32) & 0x2 ? "enabled" : "disabled");
		obj_add_str(enabled, "Data Placement Directive",
			    *(field + 32) & 0x4 ? "enabled" : "disabled");
		persistent = json_create_array();
		json_object_add_value_array(root,
					    "Directive Persistent Across Controller Level Resets",
					    persistent);
		obj_add_str(persistent, "Identify Directive",
			    *(field + 32) & 0x1 ? "enabled" : "disabled");
		obj_add_str(persistent, "Stream Directive",
			    *(field + 32) & 0x2 ? "enabled" : "disabled");
		obj_add_str(persistent, "Data Placement Directive",
			    *(field + 32) & 0x4 ? "enabled" : "disabled");
		break;
	default:
		root_add_str(error_str, "invalid directive operations for Identify Directives");
		break;
	}
}

static void json_directive_show_fields_streams(__u8 doper,  unsigned int result, __u16 *field,
					       struct json_object *root)
{
	int count;
	int i;
	char json_str[STR_LEN];

	switch (doper) {
	case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
		json_object_add_value_uint(root, "Max Streams Limit (MSL)",
					   le16_to_cpu(*field));
		json_object_add_value_uint(root, "NVM Subsystem Streams Available (NSSA)",
					   le16_to_cpu(*(field + 2)));
		json_object_add_value_uint(root, "NVM Subsystem Streams Open (NSSO)",
					   le16_to_cpu(*(field + 4)));
		json_object_add_value_uint(root, "NVM Subsystem Stream Capability (NSSC)",
					   le16_to_cpu(*(field + 6)));
		json_object_add_value_uint(root,
					   "Stream Write Size (in unit of LB size) (SWS)",
					   le16_to_cpu(*(__u32 *)(field + 16)));
		json_object_add_value_uint(root,
					   "Stream Granularity Size (in unit of SWS) (SGS)",
					   le16_to_cpu(*(field + 20)));
		json_object_add_value_uint(root, "Namespace Streams Allocated (NSA)",
					   le16_to_cpu(*(field + 22)));
		json_object_add_value_uint(root, "Namespace Streams Open (NSO)",
					   le16_to_cpu(*(field + 24)));
		break;
	case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
		count = *field;
		json_object_add_value_uint(root, "Open Stream Count",
					   le16_to_cpu(*field));
		for (i = 0; i < count; i++) {
			sprintf(json_str, "Stream Identifier %.6u", i + 1);
			json_object_add_value_uint(root, json_str,
						   le16_to_cpu(*(field + (i + 1) * 2)));
		}
		break;
	case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
		json_object_add_value_uint(root, "Namespace Streams Allocated (NSA)",
					   result & 0xffff);
		break;
	default:
		root_add_str(error_str,
					     "invalid directive operations for Streams Directives");
		break;
	}
}

static void json_directive_show_fields(__u8 dtype, __u8 doper, unsigned int result,
				       __u8 *field, struct json_object *root)
{
	switch (dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		json_directive_show_fields_identify(doper, field, root);
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		json_directive_show_fields_streams(doper, result, (__u16 *)field, root);
		break;
	default:
		root_add_str(error_str, "invalid directive type");
		break;
	}
}

static void json_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u32 result,
				void *buf, __u32 len)
{
	struct json_object *root = json_create_object();
	struct json_object *data;
	char json_str[STR_LEN];

	sprintf(json_str, "%#x", type);
	root_add_str("type", json_str);
	sprintf(json_str, "%#x", oper);
	root_add_str("operation", json_str);
	sprintf(json_str, "%#x", spec);
	root_add_str("spec", json_str);
	sprintf(json_str, "%#x", nsid);
	root_add_str("nsid", json_str);
	sprintf(json_str, "%#x", result);
	root_add_result(json_str);

	if (json_print_ops.flags & VERBOSE) {
		json_directive_show_fields(type, oper, result, buf, root);
	} else if (buf) {
		data = json_create_array();
		d_json((unsigned char *)buf, len, 16, 1, data);
		json_object_add_value_array(root, "data", data);
	}

	json_print(root);
}

static void json_discovery_log(struct nvmf_discovery_log *log, int numrec)
{
	struct json_object *root = json_create_object();
	struct json_object *entries = json_create_array();
	int i;

	root_add_uint64("genctr", le64_to_cpu(log->genctr));
	json_object_add_value_array(root, "records", entries);

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_log_entry *e = &log->entries[i];
		struct json_object *entry = json_create_object();

		obj_add_str(entry, "trtype", nvmf_trtype_str(e->trtype));
		obj_add_str(entry, "adrfam", nvmf_adrfam_str(e->adrfam));
		obj_add_str(entry, "subtype", nvmf_subtype_str(e->subtype));
		obj_add_str(entry,"treq", nvmf_treq_str(e->treq));
		json_object_add_value_uint(entry, "portid",
					   le16_to_cpu(e->portid));
		obj_add_str(entry, "trsvcid", e->trsvcid);
		obj_add_str(entry, "subnqn", e->subnqn);
		obj_add_str(entry, "traddr", e->traddr);
		obj_add_str(entry, "eflags", nvmf_eflags_str(le16_to_cpu(e->eflags)));

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			obj_add_str(entry, "rdma_prtype", nvmf_prtype_str(e->tsas.rdma.prtype));
			obj_add_str(entry, "rdma_qptype", nvmf_qptype_str(e->tsas.rdma.qptype));
			obj_add_str(entry, "rdma_cms", nvmf_cms_str(e->tsas.rdma.cms));
			json_object_add_value_uint(entry, "rdma_pkey",
				le16_to_cpu(e->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			obj_add_str(entry, "sectype", nvmf_sectype_str(e->tsas.tcp.sectype));
			break;
		default:
			break;
		}
		json_array_add_value_object(entries, entry);
	}

	json_print(root);
}

static void json_connect_msg(nvme_ctrl_t c)
{
	struct json_object *root = json_create_object();

	root_add_str("device", nvme_ctrl_get_name(c));

	json_print(root);
}

static void json_output_object(struct json_object *root)
{
	json_print(root);
}

static void json_output_status(int status)
{
	struct json_object *root = json_create_object();
	int val;
	int type;

	if (status < 0) {
		root_add_str(error_str, nvme_strerror(errno));
		return json_output_object(root);
	}

	val = nvme_status_get_value(status);
	type = nvme_status_get_type(status);

	switch (type) {
	case NVME_STATUS_TYPE_NVME:
		root_add_str(error_str, nvme_status_to_string(val, false));
		root_add_str("type", "nvme");
		break;
	case NVME_STATUS_TYPE_MI:
		root_add_str(error_str, nvme_mi_status_to_string(val));
		root_add_str("type", "nvme-mi");
		break;
	default:
		root_add_str("type", "unknown");
		break;
	}

	root_add_int("value", val);

	json_output_object(root);
}

static void json_output_message(bool error, const char *msg, va_list ap)
{
	struct json_object *root = json_create_object();
	char *value;
	const char *key = error ? error_str : result_str;

	if (vasprintf(&value, msg, ap) < 0)
		value = NULL;

	if (value)
		root_add_str(key, value);
	else
		root_add_str(key, "Could not allocate string");

	free(value);

	json_output_object(root);
}

static void json_output_perror(const char *msg)
{
	struct json_object *root = json_create_object();
	char *error;

	if (asprintf(&error, "%s: %s", msg, strerror(errno)) < 0)
		error = NULL;

	if (error)
		root_add_str(error_str, error);
	else
		root_add_str(error_str, "Could not allocate string");

	json_output_object(root);

	free(error);
}

static struct print_ops json_print_ops = {
	/* libnvme types.h print functions */
	.ana_log			= json_ana_log,
	.boot_part_log			= json_boot_part_log,
	.phy_rx_eom_log			= json_phy_rx_eom_log,
	.ctrl_list			= json_nvme_list_ctrl,
	.ctrl_registers			= json_ctrl_registers,
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
	.self_test_log 			= json_self_test_log,
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
};

struct print_ops *nvme_get_json_print_ops(enum nvme_print_flags flags)
{
	json_print_ops.flags = flags;
	return &json_print_ops;
}
