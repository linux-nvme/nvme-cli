// SPDX-License-Identifier: GPL-2.0-or-later

#include <assert.h>
#include <errno.h>

#include "nvme-print.h"

#include "util/json.h"
#include "nvme.h"
#include "common.h"

#define ERROR_MSG_LEN 100

static const uint8_t zero_uuid[16] = { 0 };
static struct print_ops json_print_ops;

static void json_nvme_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
			    unsigned int lba_index, bool cap_only)
{
	char nguid_buf[2 * sizeof(ns->nguid) + 1],
		eui64_buf[2 * sizeof(ns->eui64) + 1];
	char *nguid = nguid_buf, *eui64 = eui64_buf;
	struct json_object *root;
	struct json_object *lbafs;
	int i;

	nvme_uint128_t nvmcap = le128_to_cpu(ns->nvmcap);

	root = json_create_object();

	if (!cap_only) {
		json_object_add_value_uint64(root, "nsze", le64_to_cpu(ns->nsze));
		json_object_add_value_uint64(root, "ncap", le64_to_cpu(ns->ncap));
		json_object_add_value_uint64(root, "nuse", le64_to_cpu(ns->nuse));
		json_object_add_value_int(root, "nsfeat", ns->nsfeat);
	}
	json_object_add_value_int(root, "nlbaf", ns->nlbaf);
	if (!cap_only)
		json_object_add_value_int(root, "flbas", ns->flbas);
	json_object_add_value_int(root, "mc", ns->mc);
	json_object_add_value_int(root, "dpc", ns->dpc);
	if (!cap_only) {
		json_object_add_value_int(root, "dps", ns->dps);
		json_object_add_value_int(root, "nmic", ns->nmic);
		json_object_add_value_int(root, "rescap", ns->rescap);
		json_object_add_value_int(root, "fpi", ns->fpi);
		json_object_add_value_int(root, "dlfeat", ns->dlfeat);
		json_object_add_value_int(root, "nawun", le16_to_cpu(ns->nawun));
		json_object_add_value_int(root, "nawupf", le16_to_cpu(ns->nawupf));
		json_object_add_value_int(root, "nacwu", le16_to_cpu(ns->nacwu));
		json_object_add_value_int(root, "nabsn", le16_to_cpu(ns->nabsn));
		json_object_add_value_int(root, "nabo", le16_to_cpu(ns->nabo));
		json_object_add_value_int(root, "nabspf", le16_to_cpu(ns->nabspf));
		json_object_add_value_int(root, "noiob", le16_to_cpu(ns->noiob));
		json_object_add_value_uint128(root, "nvmcap", nvmcap);
		json_object_add_value_int(root, "nsattr", ns->nsattr);
		json_object_add_value_int(root, "nvmsetid", le16_to_cpu(ns->nvmsetid));

		if (ns->nsfeat & 0x10) {
			json_object_add_value_int(root, "npwg", le16_to_cpu(ns->npwg));
			json_object_add_value_int(root, "npwa", le16_to_cpu(ns->npwa));
			json_object_add_value_int(root, "npdg", le16_to_cpu(ns->npdg));
			json_object_add_value_int(root, "npda", le16_to_cpu(ns->npda));
			json_object_add_value_int(root, "nows", le16_to_cpu(ns->nows));
		}

		json_object_add_value_int(root, "mssrl", le16_to_cpu(ns->mssrl));
		json_object_add_value_uint(root, "mcl", le32_to_cpu(ns->mcl));
		json_object_add_value_int(root, "msrc", ns->msrc);
	}
	json_object_add_value_int(root, "nulbaf", ns->nulbaf);

	if (!cap_only) {
		json_object_add_value_uint(root, "anagrpid", le32_to_cpu(ns->anagrpid));
		json_object_add_value_int(root, "endgid", le16_to_cpu(ns->endgid));

		memset(eui64, 0, sizeof(eui64_buf));
		for (i = 0; i < sizeof(ns->eui64); i++)
			eui64 += sprintf(eui64, "%02x", ns->eui64[i]);

		memset(nguid, 0, sizeof(nguid_buf));
		for (i = 0; i < sizeof(ns->nguid); i++)
			nguid += sprintf(nguid, "%02x", ns->nguid[i]);

		json_object_add_value_string(root, "eui64", eui64_buf);
		json_object_add_value_string(root, "nguid", nguid_buf);
	}

	lbafs = json_create_array();
	json_object_add_value_array(root, "lbafs", lbafs);

	for (i = 0; i <= ns->nlbaf; i++) {
		struct json_object *lbaf = json_create_object();

		json_object_add_value_int(lbaf, "ms",
			le16_to_cpu(ns->lbaf[i].ms));
		json_object_add_value_int(lbaf, "ds", ns->lbaf[i].ds);
		json_object_add_value_int(lbaf, "rp", ns->lbaf[i].rp);

		json_array_add_value_object(lbafs, lbaf);
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

 void json_nvme_id_ctrl(struct nvme_id_ctrl *ctrl,
			void (*vs)(__u8 *vs, struct json_object *root))
{
	struct json_object *root;
	struct json_object *psds;

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
	json_object_add_value_uint(root, "ctratt", le32_to_cpu(ctrl->ctratt));
	json_object_add_value_int(root, "rrls", le16_to_cpu(ctrl->rrls));
	json_object_add_value_int(root, "cntrltype", ctrl->cntrltype);
	json_object_add_value_string(root, "fguid", util_uuid_to_string(ctrl->fguid));
	json_object_add_value_int(root, "crdt1", le16_to_cpu(ctrl->crdt1));
	json_object_add_value_int(root, "crdt2", le16_to_cpu(ctrl->crdt2));
	json_object_add_value_int(root, "crdt3", le16_to_cpu(ctrl->crdt3));
	json_object_add_value_int(root, "nvmsr", ctrl->nvmsr);
	json_object_add_value_int(root, "vwci", ctrl->vwci);
	json_object_add_value_int(root, "mec", ctrl->mec);
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
	json_object_add_value_uint128(root, "tnvmcap", tnvmcap);
	json_object_add_value_uint128(root, "unvmcap", unvmcap);
	json_object_add_value_uint(root, "rpmbs", le32_to_cpu(ctrl->rpmbs));
	json_object_add_value_int(root, "edstt", le16_to_cpu(ctrl->edstt));
	json_object_add_value_int(root, "dsto", ctrl->dsto);
	json_object_add_value_int(root, "fwug", ctrl->fwug);
	json_object_add_value_int(root, "kas", le16_to_cpu(ctrl->kas));
	json_object_add_value_int(root, "hctma", le16_to_cpu(ctrl->hctma));
	json_object_add_value_int(root, "mntmt", le16_to_cpu(ctrl->mntmt));
	json_object_add_value_int(root, "mxtmt", le16_to_cpu(ctrl->mxtmt));
	json_object_add_value_uint(root, "sanicap", le32_to_cpu(ctrl->sanicap));
	json_object_add_value_uint(root, "hmminds", le32_to_cpu(ctrl->hmminds));
	json_object_add_value_int(root, "hmmaxd", le16_to_cpu(ctrl->hmmaxd));
	json_object_add_value_int(root, "nsetidmax",
		le16_to_cpu(ctrl->nsetidmax));
	json_object_add_value_int(root, "endgidmax", le16_to_cpu(ctrl->endgidmax));
	json_object_add_value_int(root, "anatt",ctrl->anatt);
	json_object_add_value_int(root, "anacap", ctrl->anacap);
	json_object_add_value_uint(root, "anagrpmax",
		le32_to_cpu(ctrl->anagrpmax));
	json_object_add_value_uint(root, "nanagrpid",
		le32_to_cpu(ctrl->nanagrpid));
	json_object_add_value_uint(root, "pels", le32_to_cpu(ctrl->pels));
	json_object_add_value_int(root, "domainid", le16_to_cpu(ctrl->domainid));
	json_object_add_value_uint128(root, "megcap", megcap);
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
	json_object_add_value_int(root, "icsvscc", ctrl->icsvscc);
	json_object_add_value_int(root, "nwpc", ctrl->nwpc);
	json_object_add_value_int(root, "acwu", le16_to_cpu(ctrl->acwu));
	json_object_add_value_int(root, "ocfs", le16_to_cpu(ctrl->ocfs));
	json_object_add_value_uint(root, "sgls", le32_to_cpu(ctrl->sgls));
	json_object_add_value_uint(root, "mnan", le32_to_cpu(ctrl->mnan));
	json_object_add_value_uint128(root, "maxdna", maxdna);
	json_object_add_value_uint(root, "maxcna", le32_to_cpu(ctrl->maxcna));

	if (strlen(subnqn))
		json_object_add_value_string(root, "subnqn", subnqn);

	json_object_add_value_uint(root, "ioccsz", le32_to_cpu(ctrl->ioccsz));
	json_object_add_value_uint(root, "iorcsz", le32_to_cpu(ctrl->iorcsz));
	json_object_add_value_int(root, "icdoff", le16_to_cpu(ctrl->icdoff));
	json_object_add_value_int(root, "fcatt", ctrl->fcatt);
	json_object_add_value_int(root, "msdbd", ctrl->msdbd);
	json_object_add_value_int(root, "ofcs", le16_to_cpu(ctrl->ofcs));

	psds = json_create_array();
	json_object_add_value_array(root, "psds", psds);

	for (i = 0; i <= ctrl->npss; i++) {
		struct json_object *psd = json_create_object();

		json_object_add_value_int(psd, "max_power",
			le16_to_cpu(ctrl->psd[i].mp));
		json_object_add_value_int(psd, "max_power_scale",
			ctrl->psd[i].flags & 0x1);
		json_object_add_value_int(psd, "non-operational_state",
			(ctrl->psd[i].flags & 0x2) >> 1);
		json_object_add_value_uint(psd, "entry_lat",
			le32_to_cpu(ctrl->psd[i].enlat));
		json_object_add_value_uint(psd, "exit_lat",
			le32_to_cpu(ctrl->psd[i].exlat));
		json_object_add_value_int(psd, "read_tput",
			ctrl->psd[i].rrt);
		json_object_add_value_int(psd, "read_lat",
			ctrl->psd[i].rrl);
		json_object_add_value_int(psd, "write_tput",
			ctrl->psd[i].rwt);
		json_object_add_value_int(psd, "write_lat",
			ctrl->psd[i].rwl);
		json_object_add_value_int(psd, "idle_power",
			le16_to_cpu(ctrl->psd[i].idlp));
		json_object_add_value_int(psd, "idle_scale",
			nvme_psd_power_scale(ctrl->psd[i].ips));
		json_object_add_value_int(psd, "active_power",
			le16_to_cpu(ctrl->psd[i].actp));
		json_object_add_value_int(psd, "active_power_work",
			ctrl->psd[i].apws & 0x7);
		json_object_add_value_int(psd, "active_scale",
			nvme_psd_power_scale(ctrl->psd[i].apws));

		json_array_add_value_object(psds, psd);
	}

	if(vs)
		vs(ctrl->vs, root);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_error_log(struct nvme_error_log_page *err_log, int entries,
			   const char *devname)
{
	struct json_object *root;
	struct json_object *errors;
	int i;

	root = json_create_object();
	errors = json_create_array();
	json_object_add_value_array(root, "errors", errors);

	for (i = 0; i < entries; i++) {
		struct json_object *error = json_create_object();

		json_object_add_value_uint64(error, "error_count",
			le64_to_cpu(err_log[i].error_count));
		json_object_add_value_int(error, "sqid",
			le16_to_cpu(err_log[i].sqid));
		json_object_add_value_int(error, "cmdid",
			le16_to_cpu(err_log[i].cmdid));
		json_object_add_value_int(error, "status_field",
			le16_to_cpu(err_log[i].status_field >> 0x1));
		json_object_add_value_int(error, "phase_tag",
			le16_to_cpu(err_log[i].status_field & 0x1));
		json_object_add_value_int(error, "parm_error_location",
			le16_to_cpu(err_log[i].parm_error_location));
		json_object_add_value_uint64(error, "lba",
			le64_to_cpu(err_log[i].lba));
		json_object_add_value_uint(error, "nsid",
			le32_to_cpu(err_log[i].nsid));
		json_object_add_value_int(error, "vs", err_log[i].vs);
		json_object_add_value_int(error, "trtype", err_log[i].trtype);
		json_object_add_value_uint64(error, "cs",
			le64_to_cpu(err_log[i].cs));
		json_object_add_value_int(error, "trtype_spec_info",
			le16_to_cpu(err_log[i].trtype_spec_info));

		json_array_add_value_object(errors, error);
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_nvme_resv_report(struct nvme_resv_status *status,
			   int bytes, bool eds)
{
	struct json_object *root;
	struct json_object *rcs;
	int i, j, regctl, entries;

	regctl = status->regctl[0] | (status->regctl[1] << 8);

	root = json_create_object();

	json_object_add_value_uint(root, "gen", le32_to_cpu(status->gen));
	json_object_add_value_int(root, "rtype", status->rtype);
	json_object_add_value_int(root, "regctl", regctl);
	json_object_add_value_int(root, "ptpls", status->ptpls);

	rcs = json_create_array();
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

			json_object_add_value_int(rc, "cntlid",
				le16_to_cpu(status->regctl_ds[i].cntlid));
			json_object_add_value_int(rc, "rcsts",
				status->regctl_ds[i].rcsts);
			json_object_add_value_uint64(rc, "hostid",
				le64_to_cpu(status->regctl_ds[i].hostid));
			json_object_add_value_uint64(rc, "rkey",
				le64_to_cpu(status->regctl_ds[i].rkey));

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

			json_object_add_value_int(rc, "cntlid",
				le16_to_cpu(status->regctl_eds[i].cntlid));
			json_object_add_value_int(rc, "rcsts",
				status->regctl_eds[i].rcsts);
			json_object_add_value_uint64(rc, "rkey",
				le64_to_cpu(status->regctl_eds[i].rkey));
			for (j = 0; j < 16; j++)
				sprintf(hostid + j * 2, "%02x",
					status->regctl_eds[i].hostid[j]);

			json_object_add_value_string(rc, "hostid", hostid);
			json_array_add_value_object(rcs, rc);
		}
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_fw_log(struct nvme_firmware_slot *fw_log, const char *devname)
{
	struct json_object *root;
	struct json_object *fwsi;
	char fmt[21];
	char str[32];
	int i;
	__le64 *frs;

	root = json_create_object();
	fwsi = json_create_object();

	json_object_add_value_int(fwsi, "Active Firmware Slot (afi)",
		fw_log->afi);
	for (i = 0; i < 7; i++) {
		if (fw_log->frs[i][0]) {
			snprintf(fmt, sizeof(fmt), "Firmware Rev Slot %d",
				i + 1);
			frs = (__le64 *)&fw_log->frs[i];
			snprintf(str, sizeof(str), "%"PRIu64" (%s)",
				le64_to_cpu(*frs),
			util_fw_to_string(fw_log->frs[i]));
			json_object_add_value_string(fwsi, fmt, str);
		}
	}
	json_object_add_value_object(root, devname, fwsi);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_changed_ns_list_log(struct nvme_ns_list *log,
			      const char *devname)
{
	struct json_object *root;
	struct json_object *nsi;
	char fmt[32];
	char str[32];
	__u32 nsid;
	int i;

	if (log->ns[0] == cpu_to_le32(0xffffffff))
		return;

	root = json_create_object();
	nsi = json_create_object();

	json_object_add_value_string(root, "Changed Namespace List Log",
		devname);

	for (i = 0; i < NVME_ID_NS_LIST_MAX; i++) {
		nsid = le32_to_cpu(log->ns[i]);

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

static void json_endurance_log(struct nvme_endurance_group_log *endurance_group, __u16 group_id,
			       const char *devname)
{
	struct json_object *root;
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

	root = json_create_object();

	json_object_add_value_int(root, "critical_warning", endurance_group->critical_warning);
	json_object_add_value_int(root, "endurance_group_features",
				  endurance_group->endurance_group_features);
	json_object_add_value_int(root, "avl_spare", endurance_group->avl_spare);
	json_object_add_value_int(root, "avl_spare_threshold",
				  endurance_group->avl_spare_threshold);
	json_object_add_value_int(root, "percent_used", endurance_group->percent_used);
	json_object_add_value_int(root, "domain_identifier", endurance_group->domain_identifier);
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

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
			   const char *devname)
{
	int c, human = json_print_ops.flags  & VERBOSE;
	struct json_object *root;
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

	root = json_create_object();

	if (human) {
		struct json_object *crt = json_create_object();

		json_object_add_value_int(crt, "value", smart->critical_warning);
		json_object_add_value_int(crt, "available_spare", smart->critical_warning & 0x01);
		json_object_add_value_int(crt, "temp_threshold", (smart->critical_warning & 0x02) >> 1);
		json_object_add_value_int(crt, "reliability_degraded", (smart->critical_warning & 0x04) >> 2);
		json_object_add_value_int(crt, "ro", (smart->critical_warning & 0x08) >> 3);
		json_object_add_value_int(crt, "vmbu_failed", (smart->critical_warning & 0x10) >> 4);
		json_object_add_value_int(crt, "pmr_ro", (smart->critical_warning & 0x20) >> 5);

		json_object_add_value_object(root, "critical_warning", crt);
	} else
		json_object_add_value_int(root, "critical_warning",
			smart->critical_warning);

	json_object_add_value_int(root, "temperature", temperature);
	json_object_add_value_int(root, "avail_spare", smart->avail_spare);
	json_object_add_value_int(root, "spare_thresh", smart->spare_thresh);
	json_object_add_value_int(root, "percent_used", smart->percent_used);
	json_object_add_value_int(root, "endurance_grp_critical_warning_summary",
		smart->endu_grp_crit_warn_sumry);
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

static void json_ana_log(struct nvme_ana_log *ana_log, const char *devname,
			 size_t len)
{
	int offset = sizeof(struct nvme_ana_log);
	struct nvme_ana_log *hdr = ana_log;
	struct nvme_ana_group_desc *ana_desc;
	struct json_object *desc_list;
	struct json_object *ns_list;
	struct json_object *desc;
	struct json_object *nsid;
	struct json_object *root;
	size_t nsid_buf_size;
	void *base = ana_log;
	__u32 nr_nsids;
	int i, j;

	root = json_create_object();
	json_object_add_value_string(root,
			"Asymmetric Namespace Access Log for NVMe device",
			devname);
	json_object_add_value_uint64(root, "chgcnt",
			le64_to_cpu(hdr->chgcnt));
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

static void json_self_test_log(struct nvme_self_test_log *self_test, __u8 dst_entries,
			       __u32 size, const char *devname)
{
	struct json_object *valid_attrs;
	struct json_object *root;
	struct json_object *valid;
	int i;
	__u32 num_entries;

	root = json_create_object();
	json_object_add_value_int(root, "Current Device Self-Test Operation",
		self_test->current_operation);
	json_object_add_value_int(root, "Current Device Self-Test Completion",
		self_test->completion);
	valid = json_create_array();

	num_entries = min(dst_entries, NVME_LOG_ST_MAX_RESULTS);
	for (i = 0; i < num_entries; i++) {
		valid_attrs = json_create_object();
		json_object_add_value_int(valid_attrs, "Self test result",
			self_test->result[i].dsts & 0xf);
		if ((self_test->result[i].dsts & 0xf) == 0xf)
			goto add;
		json_object_add_value_int(valid_attrs, "Self test code",
			self_test->result[i].dsts >> 4);
		json_object_add_value_int(valid_attrs, "Segment number",
			self_test->result[i].seg);
		json_object_add_value_int(valid_attrs, "Valid Diagnostic Information",
			self_test->result[i].vdi);
		json_object_add_value_uint64(valid_attrs, "Power on hours",
			le64_to_cpu(self_test->result[i].poh));
		if (self_test->result[i].vdi & NVME_ST_VALID_DIAG_INFO_NSID)
			json_object_add_value_uint(valid_attrs, "Namespace Identifier",
				le32_to_cpu(self_test->result[i].nsid));
		if (self_test->result[i].vdi & NVME_ST_VALID_DIAG_INFO_FLBA) {
			json_object_add_value_uint64(valid_attrs, "Failing LBA",
				le64_to_cpu(self_test->result[i].flba));
		}
		if (self_test->result[i].vdi & NVME_ST_VALID_DIAG_INFO_SCT)
			json_object_add_value_int(valid_attrs, "Status Code Type",
				self_test->result[i].sct);
		if (self_test->result[i].vdi & NVME_ST_VALID_DIAG_INFO_SC)
			json_object_add_value_int(valid_attrs, "Status Code",
				self_test->result[i].sc);
		json_object_add_value_int(valid_attrs, "Vendor Specific",
			(self_test->result[i].vs[1] << 8) |
			(self_test->result[i].vs[0]));
add:
		json_array_add_value_object(valid, valid_attrs);
	}
	json_object_add_value_array(root, "List of Valid Reports", valid);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

struct json_object* json_effects_log(enum nvme_csi csi,
			     struct nvme_cmd_effects_log *effects_log)
{
	struct json_object *root;
	struct json_object *acs;
	struct json_object *iocs;
	unsigned int opcode;
	char key[128];
	__u32 effect;

	root = json_create_object();
	json_object_add_value_uint(root, "command_set_identifier", csi);

	acs = json_create_object();
	for (opcode = 0; opcode < 256; opcode++) {
		effect = le32_to_cpu(effects_log->acs[opcode]);
		if (effect & NVME_CMD_EFFECTS_CSUPP) {
			sprintf(key, "ACS_%u (%s)", opcode,
				nvme_cmd_to_string(1, opcode));
			json_object_add_value_uint(acs, key, effect);
		}
	}

	json_object_add_value_object(root, "admin_cmd_set", acs);

	iocs = json_create_object();
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
	struct json_object *json_list;
	nvme_effects_log_node_t *node;

	json_list = json_create_array();

	list_for_each(list, node, node) {
		struct json_object *json_page =
			json_effects_log(node->csi, &node->effects);
		json_array_add_value_object(json_list, json_page);
	}

	json_print_object(json_list, NULL);
	printf("\n");
	json_free_object(json_list);
}

static void json_sanitize_log(struct nvme_sanitize_log_page *sanitize_log,
			      const char *devname)
{
	struct json_object *root;
	struct json_object *dev;
	struct json_object *sstat;
	const char *status_str;
	char str[128];
	__u16 status = le16_to_cpu(sanitize_log->sstat);

	root = json_create_object();
	dev = json_create_object();
	sstat = json_create_object();

	json_object_add_value_int(dev, "sprog",
		le16_to_cpu(sanitize_log->sprog));
	json_object_add_value_int(sstat, "global_erased",
		(status & NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED) >> 8);
	json_object_add_value_int(sstat, "no_cmplted_passes",
		(status >> NVME_SANITIZE_SSTAT_COMPLETED_PASSES_SHIFT) &
			NVME_SANITIZE_SSTAT_COMPLETED_PASSES_MASK);

	status_str = nvme_sstat_status_to_string(status);
	sprintf(str, "(%d) %s", status & NVME_SANITIZE_SSTAT_STATUS_MASK,
		status_str);
	json_object_add_value_string(sstat, "status", str);

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
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_predictable_latency_per_nvmset(
		struct nvme_nvmset_predictable_lat_log *plpns_log,
		__u16 nvmset_id, const char *devname)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_uint(root, "nvmset_id",
		le16_to_cpu(nvmset_id));
	json_object_add_value_uint(root, "status",
		plpns_log->status);
	json_object_add_value_uint(root, "event_type",
		le16_to_cpu(plpns_log->event_type));
	json_object_add_value_uint64(root, "dtwin_reads_typical",
		le64_to_cpu(plpns_log->dtwin_rt));
	json_object_add_value_uint64(root, "dtwin_writes_typical",
		le64_to_cpu(plpns_log->dtwin_wt));
	json_object_add_value_uint64(root, "dtwin_time_maximum",
		le64_to_cpu(plpns_log->dtwin_tmax));
	json_object_add_value_uint64(root, "ndwin_time_minimum_high",
		le64_to_cpu(plpns_log->ndwin_tmin_hi));
	json_object_add_value_uint64(root, "ndwin_time_minimum_low",
		le64_to_cpu(plpns_log->ndwin_tmin_lo));
	json_object_add_value_uint64(root, "dtwin_reads_estimate",
		le64_to_cpu(plpns_log->dtwin_re));
	json_object_add_value_uint64(root, "dtwin_writes_estimate",
		le64_to_cpu(plpns_log->dtwin_we));
	json_object_add_value_uint64(root, "dtwin_time_estimate",
		le64_to_cpu(plpns_log->dtwin_te));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_predictable_latency_event_agg_log(
		struct nvme_aggregate_predictable_lat_event *pea_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	struct json_object *root;
	struct json_object *valid_attrs;
	struct json_object *valid;
	__u64 num_iter;
	__u64 num_entries;

	root = json_create_object();
	num_entries = le64_to_cpu(pea_log->num_entries);
	json_object_add_value_uint64(root, "num_entries_avail",
		num_entries);
	valid = json_create_array();

	num_iter = min(num_entries, log_entries);
	for (int i = 0; i < num_iter; i++) {
		valid_attrs = json_create_object();
		json_object_add_value_uint(valid_attrs, "entry",
			le16_to_cpu(pea_log->entries[i]));
		json_array_add_value_object(valid, valid_attrs);
	}
	json_object_add_value_array(root, "list_of_entries", valid);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
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
			json_object_add_value_string(root, key, evt_str);
		}
	}
}


static void json_persistent_event_log(void *pevent_log_info, __u8 action,
				      __u32 size, const char *devname)

{
	struct json_object *root;
	struct json_object *valid_attrs;
	struct json_object *valid;
	__u32 offset, por_info_len, por_info_list;
	__u64 *fw_rev;
	char key[128];
	char fw_str[50];

	struct nvme_smart_log *smart_event;
	struct nvme_fw_commit_event *fw_commit_event;
	struct nvme_time_stamp_change_event *ts_change_event;
	struct nvme_power_on_reset_info_list *por_event;
	struct nvme_nss_hw_err_event *nss_hw_err_event;
	struct nvme_change_ns_event *ns_event;
	struct nvme_format_nvm_start_event *format_start_event;
	struct nvme_format_nvm_compln_event *format_cmpln_event;
	struct nvme_sanitize_start_event *sanitize_start_event;
	struct nvme_sanitize_compln_event *sanitize_cmpln_event;
	struct nvme_thermal_exc_event *thermal_exc_event;
	struct nvme_persistent_event_log *pevent_log_head;
	struct nvme_persistent_event_entry *pevent_entry_head;

	root = json_create_object();
	valid = json_create_array();

	offset = sizeof(*pevent_log_head);
	if (size >= offset) {
		pevent_log_head = pevent_log_info;
		char sn[sizeof(pevent_log_head->sn) + 1],
			mn[sizeof(pevent_log_head->mn) + 1],
			subnqn[sizeof(pevent_log_head->subnqn) + 1];

		snprintf(sn, sizeof(sn), "%-.*s",
			(int)sizeof(pevent_log_head->sn), pevent_log_head->sn);
		snprintf(mn, sizeof(mn), "%-.*s",
			(int)sizeof(pevent_log_head->mn), pevent_log_head->mn);
		snprintf(subnqn, sizeof(subnqn), "%-.*s",
			(int)sizeof(pevent_log_head->subnqn), pevent_log_head->subnqn);

		json_object_add_value_uint(root, "log_id",
			pevent_log_head->lid);
		json_object_add_value_uint(root, "total_num_of_events",
			le32_to_cpu(pevent_log_head->tnev));
		json_object_add_value_uint64(root, "total_log_len",
			le64_to_cpu(pevent_log_head->tll));
		json_object_add_value_uint(root, "log_revision",
			pevent_log_head->rv);
		json_object_add_value_uint(root, "log_header_len",
			le16_to_cpu(pevent_log_head->lhl));
		json_object_add_value_uint64(root, "timestamp",
			le64_to_cpu(pevent_log_head->ts));
		json_object_add_value_uint128(root, "power_on_hours",
			le128_to_cpu(pevent_log_head->poh));
		json_object_add_value_uint64(root, "power_cycle_count",
			le64_to_cpu(pevent_log_head->pcc));
		json_object_add_value_uint(root, "pci_vid",
			le16_to_cpu(pevent_log_head->vid));
		json_object_add_value_uint(root, "pci_ssvid",
			le16_to_cpu(pevent_log_head->ssvid));
		json_object_add_value_string(root, "sn", sn);
		json_object_add_value_string(root, "mn", mn);
		json_object_add_value_string(root, "subnqn", subnqn);
		json_object_add_value_uint(root, "gen_number",
			le16_to_cpu(pevent_log_head->gen_number));
		json_object_add_value_uint(root, "rci",
			le32_to_cpu(pevent_log_head->rci));
		for (int i = 0; i < 32; i++) {
			if (pevent_log_head->seb[i] == 0)
				continue;
			json_add_bitmap(i, pevent_log_head->seb[i], root);
		}
	} else {
		printf("No log data can be shown with this log len at least " \
			"512 bytes is required or can be 0 to read the complete "\
			"log page after context established\n");
		return;
	}
	for (int i = 0; i < le32_to_cpu(pevent_log_head->tnev); i++) {
		if (offset + sizeof(*pevent_entry_head) >= size)
			break;

		pevent_entry_head = pevent_log_info + offset;

		if ((offset + pevent_entry_head->ehl + 3 +
			le16_to_cpu(pevent_entry_head->el)) >= size)
			break;
		valid_attrs = json_create_object();

		json_object_add_value_uint(valid_attrs, "event_number", i);
		json_object_add_value_string(valid_attrs, "event_type",
			nvme_pel_event_to_string(pevent_entry_head->etype));
		json_object_add_value_uint(valid_attrs, "event_type_rev",
			pevent_entry_head->etype_rev);
		json_object_add_value_uint(valid_attrs, "event_header_len",
			pevent_entry_head->ehl);
		json_object_add_value_uint(valid_attrs, "event_header_additional_info",
			pevent_entry_head->ehai);
		json_object_add_value_uint(valid_attrs, "ctrl_id",
			le16_to_cpu(pevent_entry_head->cntlid));
		json_object_add_value_uint64(valid_attrs, "event_time_stamp",
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
			smart_event = pevent_log_info + offset;
			unsigned int temperature = ((smart_event->temperature[1] << 8) |
				smart_event->temperature[0]);

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
			json_object_add_value_int(valid_attrs, "critical_warning",
				smart_event->critical_warning);

			json_object_add_value_int(valid_attrs, "temperature",
				temperature);
			json_object_add_value_int(valid_attrs, "avail_spare",
				smart_event->avail_spare);
			json_object_add_value_int(valid_attrs, "spare_thresh",
				smart_event->spare_thresh);
			json_object_add_value_int(valid_attrs, "percent_used",
				smart_event->percent_used);
			json_object_add_value_int(valid_attrs,
				"endurance_grp_critical_warning_summary",
				smart_event->endu_grp_crit_warn_sumry);
			json_object_add_value_uint128(valid_attrs, "data_units_read",
				data_units_read);
			json_object_add_value_uint128(valid_attrs, "data_units_written",
				data_units_written);
			json_object_add_value_uint128(valid_attrs, "host_read_commands",
				host_read_commands);
			json_object_add_value_uint128(valid_attrs, "host_write_commands",
				host_write_commands);
			json_object_add_value_uint128(valid_attrs, "controller_busy_time",
				controller_busy_time);
			json_object_add_value_uint128(valid_attrs, "power_cycles",
				power_cycles);
			json_object_add_value_uint128(valid_attrs, "power_on_hours",
				power_on_hours);
			json_object_add_value_uint128(valid_attrs, "unsafe_shutdowns",
				unsafe_shutdowns);
			json_object_add_value_uint128(valid_attrs, "media_errors",
				media_errors);
			json_object_add_value_uint128(valid_attrs, "num_err_log_entries",
				num_err_log_entries);
			json_object_add_value_uint(valid_attrs, "warning_temp_time",
					le32_to_cpu(smart_event->warning_temp_time));
			json_object_add_value_uint(valid_attrs, "critical_comp_time",
					le32_to_cpu(smart_event->critical_comp_time));

			for (int c = 0; c < 8; c++) {
				__s32 temp = le16_to_cpu(smart_event->temp_sensor[c]);
				if (temp == 0)
					continue;
				sprintf(key, "temperature_sensor_%d",c + 1);
				json_object_add_value_int(valid_attrs, key, temp);
			}

			json_object_add_value_uint(valid_attrs, "thm_temp1_trans_count",
					le32_to_cpu(smart_event->thm_temp1_trans_count));
			json_object_add_value_uint(valid_attrs, "thm_temp2_trans_count",
					le32_to_cpu(smart_event->thm_temp2_trans_count));
			json_object_add_value_uint(valid_attrs, "thm_temp1_total_time",
					le32_to_cpu(smart_event->thm_temp1_total_time));
			json_object_add_value_uint(valid_attrs, "thm_temp2_total_time",
					le32_to_cpu(smart_event->thm_temp2_total_time));
			break;
		case NVME_PEL_FW_COMMIT_EVENT:
			fw_commit_event = pevent_log_info + offset;
			snprintf(fw_str, sizeof(fw_str), "%"PRIu64" (%s)",
				le64_to_cpu(fw_commit_event->old_fw_rev),
				util_fw_to_string((char *)&fw_commit_event->old_fw_rev));
			json_object_add_value_string(valid_attrs, "old_fw_rev", fw_str);
			snprintf(fw_str, sizeof(fw_str), "%"PRIu64" (%s)",
				le64_to_cpu(fw_commit_event->new_fw_rev),
				util_fw_to_string((char *)&fw_commit_event->new_fw_rev));
			json_object_add_value_string(valid_attrs, "new_fw_rev", fw_str);
			json_object_add_value_uint(valid_attrs, "fw_commit_action",
				fw_commit_event->fw_commit_action);
			json_object_add_value_uint(valid_attrs, "fw_slot",
				fw_commit_event->fw_slot);
			json_object_add_value_uint(valid_attrs, "sct_fw",
				fw_commit_event->sct_fw);
			json_object_add_value_uint(valid_attrs, "sc_fw",
				fw_commit_event->sc_fw);
			json_object_add_value_uint(valid_attrs,
				"vu_assign_fw_commit_rc",
				le16_to_cpu(fw_commit_event->vndr_assign_fw_commit_rc));
			break;
		case NVME_PEL_TIMESTAMP_EVENT:
			ts_change_event = pevent_log_info + offset;
			json_object_add_value_uint64(valid_attrs, "prev_ts",
				le64_to_cpu(ts_change_event->previous_timestamp));
			json_object_add_value_uint64(valid_attrs,
				"ml_secs_since_reset",
				le64_to_cpu(ts_change_event->ml_secs_since_reset));
			break;
		case NVME_PEL_POWER_ON_RESET_EVENT:
			por_info_len = (le16_to_cpu(pevent_entry_head->el) -
				le16_to_cpu(pevent_entry_head->vsil) - sizeof(*fw_rev));

			por_info_list = por_info_len / sizeof(*por_event);

			fw_rev = pevent_log_info + offset;
			snprintf(fw_str, sizeof(fw_str), "%"PRIu64" (%s)",
				le64_to_cpu(*fw_rev),
				util_fw_to_string((char *)fw_rev));
			json_object_add_value_string(valid_attrs, "fw_rev", fw_str);
			for (int i = 0; i < por_info_list; i++) {
				por_event = pevent_log_info + offset +
					sizeof(*fw_rev) + i * sizeof(*por_event);
				json_object_add_value_uint(valid_attrs, "ctrl_id",
					le16_to_cpu(por_event->cid));
				json_object_add_value_uint(valid_attrs, "fw_act",
					por_event->fw_act);
				json_object_add_value_uint(valid_attrs, "op_in_prog",
					por_event->op_in_prog);
				json_object_add_value_uint(valid_attrs, "ctrl_power_cycle",
					le32_to_cpu(por_event->ctrl_power_cycle));
				json_object_add_value_uint64(valid_attrs, "power_on_ml_secs",
					le64_to_cpu(por_event->power_on_ml_seconds));
				json_object_add_value_uint64(valid_attrs, "ctrl_time_stamp",
					le64_to_cpu(por_event->ctrl_time_stamp));
			}
			break;
		case NVME_PEL_NSS_HW_ERROR_EVENT:
			nss_hw_err_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "nss_hw_err_code",
				le16_to_cpu(nss_hw_err_event->nss_hw_err_event_code));
			break;
		case NVME_PEL_CHANGE_NS_EVENT:
			ns_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "nsmgt_cdw10",
				le32_to_cpu(ns_event->nsmgt_cdw10));
			json_object_add_value_uint64(valid_attrs, "nsze",
				le64_to_cpu(ns_event->nsze));
			json_object_add_value_uint64(valid_attrs, "nscap",
				le64_to_cpu(ns_event->nscap));
			json_object_add_value_uint(valid_attrs, "flbas",
				ns_event->flbas);
			json_object_add_value_uint(valid_attrs, "dps",
				ns_event->dps);
			json_object_add_value_uint(valid_attrs, "nmic",
				ns_event->nmic);
			json_object_add_value_uint(valid_attrs, "ana_grp_id",
				le32_to_cpu(ns_event->ana_grp_id));
			json_object_add_value_uint(valid_attrs, "nvmset_id",
				le16_to_cpu(ns_event->nvmset_id));
			json_object_add_value_uint(valid_attrs, "nsid",
				le32_to_cpu(ns_event->nsid));
			break;
		case NVME_PEL_FORMAT_START_EVENT:
			format_start_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "nsid",
				le32_to_cpu(format_start_event->nsid));
			json_object_add_value_uint(valid_attrs, "fna",
				format_start_event->fna);
			json_object_add_value_uint(valid_attrs, "format_nvm_cdw10",
				le32_to_cpu(format_start_event->format_nvm_cdw10));
			break;
		case NVME_PEL_FORMAT_COMPLETION_EVENT:
			format_cmpln_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "nsid",
				le32_to_cpu(format_cmpln_event->nsid));
			json_object_add_value_uint(valid_attrs, "smallest_fpi",
				format_cmpln_event->smallest_fpi);
			json_object_add_value_uint(valid_attrs, "format_nvm_status",
				format_cmpln_event->format_nvm_status);
			json_object_add_value_uint(valid_attrs, "compln_info",
				le16_to_cpu(format_cmpln_event->compln_info));
			json_object_add_value_uint(valid_attrs, "status_field",
				le32_to_cpu(format_cmpln_event->status_field));
			break;
		case NVME_PEL_SANITIZE_START_EVENT:
			sanitize_start_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "SANICAP",
				le32_to_cpu(sanitize_start_event->sani_cap));
			json_object_add_value_uint(valid_attrs, "sani_cdw10",
				le32_to_cpu(sanitize_start_event->sani_cdw10));
			json_object_add_value_uint(valid_attrs, "sani_cdw11",
				le32_to_cpu(sanitize_start_event->sani_cdw11));
			break;
		case NVME_PEL_SANITIZE_COMPLETION_EVENT:
			sanitize_cmpln_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "sani_prog",
				le16_to_cpu(sanitize_cmpln_event->sani_prog));
			json_object_add_value_uint(valid_attrs, "sani_status",
				le16_to_cpu(sanitize_cmpln_event->sani_status));
			json_object_add_value_uint(valid_attrs, "cmpln_info",
				le16_to_cpu(sanitize_cmpln_event->cmpln_info));
			break;
		case NVME_PEL_THERMAL_EXCURSION_EVENT:
			thermal_exc_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "over_temp",
				thermal_exc_event->over_temp);
			json_object_add_value_uint(valid_attrs, "threshold",
				thermal_exc_event->threshold);
			break;
		}

		json_array_add_value_object(valid, valid_attrs);
		offset += le16_to_cpu(pevent_entry_head->el);
	}

	json_object_add_value_array(root, "list_of_event_entries", valid);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}


static void json_endurance_group_event_agg_log(
		struct nvme_aggregate_predictable_lat_event *endurance_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	struct json_object *root;
	struct json_object *valid_attrs;
	struct json_object *valid;

	root = json_create_object();
	json_object_add_value_uint64(root, "num_entries_avail",
		le64_to_cpu(endurance_log->num_entries));
	valid = json_create_array();

	for (int i = 0; i < log_entries; i++) {
		valid_attrs = json_create_object();
		json_object_add_value_uint(valid_attrs, "entry",
			le16_to_cpu(endurance_log->entries[i]));
		json_array_add_value_object(valid, valid_attrs);
	}
	json_object_add_value_array(root, "list_of_entries", valid);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}


static void json_lba_status_log(void *lba_status, __u32 size,
				const char *devname)
{
	struct json_object *root;
	struct json_object *desc;
	struct json_object *element;
	struct json_object *desc_list;
	struct json_object *elements_list;
	struct nvme_lba_status_log *hdr;
	struct nvme_lbas_ns_element *ns_element;
	struct nvme_lba_rd *range_desc;
	int offset = sizeof(*hdr);
	__u32 num_lba_desc, num_elements;

	root = json_create_object();
	hdr = lba_status;
	json_object_add_value_uint(root, "lslplen", le32_to_cpu(hdr->lslplen));
	num_elements = le32_to_cpu(hdr->nlslne);
	json_object_add_value_uint(root, "nlslne", num_elements);
	json_object_add_value_uint(root, "estulb", le32_to_cpu(hdr->estulb));
	json_object_add_value_uint(root, "lsgc", le16_to_cpu(hdr->lsgc));

	elements_list = json_create_array();
	for (int ele = 0; ele < num_elements; ele++) {
		ns_element = lba_status + offset;
		element = json_create_object();
		json_object_add_value_uint(element, "neid",
			le32_to_cpu(ns_element->neid));
		num_lba_desc = le32_to_cpu(ns_element->nlrd);
		json_object_add_value_uint(element, "nlrd", num_lba_desc);
		json_object_add_value_uint(element, "ratype", ns_element->ratype);

		offset += sizeof(*ns_element);
		desc_list = json_create_array();
		if (num_lba_desc != 0xffffffff) {
			for (int i = 0; i < num_lba_desc; i++) {
				range_desc = lba_status + offset;
				desc = json_create_object();
				json_object_add_value_uint64(desc, "rslba",
					le64_to_cpu(range_desc->rslba));
				json_object_add_value_uint(desc, "rnlb",
					le32_to_cpu(range_desc->rnlb));

				offset += sizeof(*range_desc);
				json_array_add_value_object(desc_list, desc);
			}
		} else {
			printf("Number of LBA Range Descriptors (NLRD) set to %#x for " \
				"NS element %d", num_lba_desc, ele);
		}

		json_object_add_value_array(element, "descs", desc_list);
		json_array_add_value_object(elements_list, element);
	}

	json_object_add_value_array(root, "ns_elements", elements_list);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}


static void json_resv_notif_log(struct nvme_resv_notification_log *resv,
				const char *devname)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_uint64(root, "count",
		le64_to_cpu(resv->lpc));
	json_object_add_value_uint(root, "rn_log_type",
		resv->rnlpt);
	json_object_add_value_uint(root, "num_logs",
		resv->nalp);
	json_object_add_value_uint(root, "nsid",
		le32_to_cpu(resv->nsid));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}


static void json_fid_support_effects_log(
		struct nvme_fid_supported_effects_log *fid_log,
		const char *devname)
{
	struct json_object *root;
	struct json_object *fids;
	struct json_object *fids_list;
	unsigned int fid;
	char key[128];
	__u32 fid_support;

	root = json_create_object();
	fids_list = json_create_array();
	for (fid = 0; fid < 256; fid++) {
		fid_support = le32_to_cpu(fid_log->fid_support[fid]);
		if (fid_support & NVME_FID_SUPPORTED_EFFECTS_FSUPP) {
			fids = json_create_object();
			sprintf(key, "fid_%u", fid);
			json_object_add_value_uint(fids, key, fid_support);
			json_array_add_value_object(fids_list, fids);
		}
	}

	json_object_add_value_object(root, "fid_support", fids_list);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}


static void json_mi_cmd_support_effects_log(
		struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
		const char *devname)
{
	struct json_object *root;
	struct json_object *mi_cmds;
	struct json_object *mi_cmds_list;
	unsigned int mi_cmd;
	char key[128];
	__u32 mi_cmd_support;

	root = json_create_object();
	mi_cmds_list = json_create_array();
	for (mi_cmd = 0; mi_cmd < 256; mi_cmd++) {
		mi_cmd_support = le32_to_cpu(mi_cmd_log->mi_cmd_support[mi_cmd]);
		if (mi_cmd_support & NVME_MI_CMD_SUPPORTED_EFFECTS_CSUPP) {
			mi_cmds = json_create_object();
			sprintf(key, "mi_cmd_%u", mi_cmd);
			json_object_add_value_uint(mi_cmds, key, mi_cmd_support);
			json_array_add_value_object(mi_cmds_list, mi_cmds);
		}
	}

	json_object_add_value_object(root, "mi_command_support", mi_cmds_list);
	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
}


static void json_boot_part_log(void *bp_log, const char *devname,
			       __u32 size)
{
	struct nvme_boot_partition *hdr;
	struct json_object *root;

	hdr = bp_log;
	root = json_create_object();

	json_object_add_value_uint(root, "count", hdr->lid);
	json_object_add_value_uint(root, "abpid",
		(le32_to_cpu(hdr->bpinfo) >> 31) & 0x1);
	json_object_add_value_uint(root, "bpsz",
		le32_to_cpu(hdr->bpinfo) & 0x7fff);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_media_unit_stat_log(struct nvme_media_unit_stat_log *mus)
{

	struct json_object *root;
	struct json_object *entries;
	struct json_object *entry;
	int i;

	root = json_create_object();
	entries = json_create_array();

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
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}


static void json_supported_cap_config_log(
		struct nvme_supported_cap_config_list_log *cap_log)
{
	struct json_object *root;
	struct json_object *cap_list;
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
	int i, j, k, l, m, sccn, egcn, egsets, egchans, chmus;

	root = json_create_object();

	json_object_add_value_uint(root, "sccn", cap_log->sccn);
	cap_list = json_create_array();
	sccn = cap_log->sccn;
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
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
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
		json_object_add_value_uint64(obj_config, "runs", le64_to_cpu(config->runs));
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

	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
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

	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
}


static void json_nvme_fdp_stats(struct nvme_fdp_stats_log *log)
{
	struct json_object *root = json_create_object();

	json_object_add_value_uint128(root, "hbmw", le128_to_cpu(log->hbmw));
	json_object_add_value_uint128(root, "mbmw", le128_to_cpu(log->mbmw));
	json_object_add_value_uint128(root, "mbe", le128_to_cpu(log->mbe));

	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
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
		json_object_add_value_uint64(obj_event, "timestamp", le64_to_cpu(*(uint64_t *)&event->ts));
		json_object_add_value_uint(obj_event, "nsid", le32_to_cpu(event->nsid));

		if (event->type == NVME_FDP_EVENT_REALLOC) {
			struct nvme_fdp_event_realloc *mr;
			mr = (struct nvme_fdp_event_realloc *)&event->type_specific;

			json_object_add_value_uint(obj_event, "nlbam", le16_to_cpu(mr->nlbam));

			if (mr->flags & NVME_FDP_EVENT_REALLOC_F_LBAV)
				json_object_add_value_uint64(obj_event, "lba", le64_to_cpu(mr->lba));
		}

		json_array_add_value_object(obj_events, obj_event);
	}

	json_object_add_value_array(root, "events", obj_events);

	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
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
		json_object_add_value_uint64(obj_ruhs, "ruamw", le64_to_cpu(ruhs->ruamw));

		json_array_add_value_object(obj_ruhss, obj_ruhs);
	}

	json_object_add_value_array(root, "ruhss", obj_ruhss);

	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
}

static unsigned int json_print_nvme_subsystem_multipath(nvme_subsystem_t s,
						        json_object *paths)
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
		json_object_add_value_string(path_attrs, "Name",
					     nvme_ctrl_get_name(c));
		json_object_add_value_string(path_attrs, "Transport",
					     nvme_ctrl_get_transport(c));
		json_object_add_value_string(path_attrs, "Address",
					     nvme_ctrl_get_address(c));
		json_object_add_value_string(path_attrs, "State",
					     nvme_ctrl_get_state(c));
		json_object_add_value_string(path_attrs, "ANAState",
					     nvme_path_get_ana_state(p));
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
		json_object_add_value_string(path_attrs, "Name",
					     nvme_ctrl_get_name(c));
		json_object_add_value_string(path_attrs, "Transport",
					     nvme_ctrl_get_transport(c));
		json_object_add_value_string(path_attrs, "Address",
					     nvme_ctrl_get_address(c));
		json_object_add_value_string(path_attrs, "State",
					     nvme_ctrl_get_state(c));
		json_array_add_value_object(paths, path_attrs);
	}
}

static void json_print_nvme_subsystem_list(nvme_root_t r, bool show_ana)

{
	struct json_object *host_attrs, *subsystem_attrs;
	struct json_object *subsystems, *paths;
	struct json_object *root;
	nvme_host_t h;

	root = json_create_array();

	nvme_for_each_host(r, h) {
		nvme_subsystem_t s;
		const char *hostid;

		host_attrs = json_create_object();
		json_object_add_value_string(host_attrs, "HostNQN",
					     nvme_host_get_hostnqn(h));
		hostid = nvme_host_get_hostid(h);
		if (hostid)
			json_object_add_value_string(host_attrs, "HostID", hostid);
		subsystems = json_create_array();
		nvme_for_each_subsystem(h, s) {
			subsystem_attrs = json_create_object();
			json_object_add_value_string(subsystem_attrs, "Name",
						     nvme_subsystem_get_name(s));
			json_object_add_value_string(subsystem_attrs, "NQN",
						     nvme_subsystem_get_nqn(s));
			json_object_add_value_string(subsystem_attrs, "IOPolicy",
						     nvme_subsystem_get_iopolicy(s));

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
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_ctrl_registers(void *bar, bool fabrics)
{
	uint64_t cap, asq, acq, bpmbl, cmbmsc;
	uint32_t vs, intms, intmc, cc, csts, nssr, crto, aqa, cmbsz, cmbloc,
		bpinfo, bprsel, cmbsts, pmrcap, pmrctl, pmrsts, pmrebs, pmrswtp,
		pmrmscl, pmrmscu;
	struct json_object *root;

	cap = mmio_read64(bar + NVME_REG_CAP);
	vs = mmio_read32(bar + NVME_REG_VS);
	intms = mmio_read32(bar + NVME_REG_INTMS);
	intmc = mmio_read32(bar + NVME_REG_INTMC);
	cc = mmio_read32(bar + NVME_REG_CC);
	csts = mmio_read32(bar + NVME_REG_CSTS);
	nssr = mmio_read32(bar + NVME_REG_NSSR);
	crto = mmio_read32(bar + NVME_REG_CRTO);
	aqa = mmio_read32(bar + NVME_REG_AQA);
	asq = mmio_read64(bar + NVME_REG_ASQ);
	acq = mmio_read64(bar + NVME_REG_ACQ);
	cmbloc = mmio_read32(bar + NVME_REG_CMBLOC);
	cmbsz = mmio_read32(bar + NVME_REG_CMBSZ);
	bpinfo = mmio_read32(bar + NVME_REG_BPINFO);
	bprsel = mmio_read32(bar + NVME_REG_BPRSEL);
	bpmbl = mmio_read64(bar + NVME_REG_BPMBL);
	cmbmsc = mmio_read64(bar + NVME_REG_CMBMSC);
	cmbsts = mmio_read32(bar + NVME_REG_CMBSTS);
	pmrcap = mmio_read32(bar + NVME_REG_PMRCAP);
	pmrctl = mmio_read32(bar + NVME_REG_PMRCTL);
	pmrsts = mmio_read32(bar + NVME_REG_PMRSTS);
	pmrebs = mmio_read32(bar + NVME_REG_PMREBS);
	pmrswtp = mmio_read32(bar + NVME_REG_PMRSWTP);
	pmrmscl = mmio_read32(bar + NVME_REG_PMRMSCL);
	pmrmscu = mmio_read32(bar + NVME_REG_PMRMSCU);

	root = json_create_object();
	json_object_add_value_uint64(root, "cap", cap);
	json_object_add_value_int(root, "vs", vs);
	json_object_add_value_int(root, "intms", intms);
	json_object_add_value_int(root, "intmc", intmc);
	json_object_add_value_int(root, "cc", cc);
	json_object_add_value_int(root, "csts", csts);
	json_object_add_value_int(root, "nssr", nssr);
	json_object_add_value_int(root, "crto", crto);
	json_object_add_value_int(root, "aqa", aqa);
	json_object_add_value_uint64(root, "asq", asq);
	json_object_add_value_uint64(root, "acq", acq);
	json_object_add_value_int(root, "cmbloc", cmbloc);
	json_object_add_value_int(root, "cmbsz", cmbsz);
	json_object_add_value_int(root, "bpinfo", bpinfo);
	json_object_add_value_int(root, "bprsel", bprsel);
	json_object_add_value_uint64(root, "bpmbl", bpmbl);
	json_object_add_value_uint64(root, "cmbmsc", cmbmsc);
	json_object_add_value_int(root, "cmbsts", cmbsts);
	json_object_add_value_int(root, "pmrcap", pmrcap);
	json_object_add_value_int(root, "pmrctl", pmrctl);
	json_object_add_value_int(root, "pmrsts", pmrsts);
	json_object_add_value_int(root, "pmrebs", pmrebs);
	json_object_add_value_int(root, "pmrswtp", pmrswtp);
	json_object_add_value_uint(root, "pmrmscl", pmrmscl);
	json_object_add_value_uint(root, "pmrmscu", pmrmscu);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void d_json(unsigned char *buf, int len, int width, int group,
	    struct json_object *array)
{
	int i, line_done = 0;
	char ascii[32 + 1];
	assert(width < sizeof(ascii));

	for (i = 0; i < len; i++) {
		line_done = 0;
		ascii[i % width] = (buf[i] >= '!' && buf[i] <= '~') ? buf[i] : '.';
		if (((i + 1) % width) == 0) {
			ascii[i % width + 1] = '\0';
			json_array_add_value_string(array, ascii);
			line_done = 1;
		}
	}
	if (!line_done) {
		ascii[i % width + 1] = '\0';
		json_array_add_value_string(array, ascii);
	}
}

static void json_nvme_cmd_set_independent_id_ns(
		struct nvme_id_independent_id_ns *ns,
		unsigned int nsid)
{
	struct json_object *root;
	root = json_create_object();

	json_object_add_value_int(root, "nsfeat", ns->nsfeat);
	json_object_add_value_int(root, "nmic", ns->nmic);
	json_object_add_value_int(root, "rescap", ns->rescap);
	json_object_add_value_int(root, "fpi", ns->fpi);
	json_object_add_value_uint(root, "anagrpid", le32_to_cpu(ns->anagrpid));
	json_object_add_value_int(root, "nsattr", ns->nsattr);
	json_object_add_value_int(root, "nvmsetid", le16_to_cpu(ns->nvmsetid));
	json_object_add_value_int(root, "endgid", le16_to_cpu(ns->endgid));
	json_object_add_value_int(root, "nstat", ns->nstat);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_nvme_id_ns_descs(void *data, unsigned int nsid)
{
	/* large enough to hold uuid str (37) or nguid str (32) + zero byte */
	char json_str[40];
	char *json_str_p;

	union {
		__u8 eui64[NVME_NIDT_EUI64_LEN];
		__u8 nguid[NVME_NIDT_NGUID_LEN];
		__u8 uuid[NVME_UUID_LEN];
		__u8 csi;
	} desc;

	struct json_object *root;
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

static void json_nvme_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_uint(root, "vsl", ctrl_nvm->vsl);
	json_object_add_value_uint(root, "wzsl", ctrl_nvm->wzsl);
	json_object_add_value_uint(root, "wusl", ctrl_nvm->wusl);
	json_object_add_value_uint(root, "dmrl", ctrl_nvm->dmrl);
	json_object_add_value_uint(root, "dmrsl", le32_to_cpu(ctrl_nvm->dmrsl));
	json_object_add_value_uint64(root, "dmsl", le64_to_cpu(ctrl_nvm->dmsl));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_nvme_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns,
				unsigned int nsid, struct nvme_id_ns *ns,
				unsigned int lba_index, bool cap_only)

{
	struct json_object *root;
	struct json_object *elbafs;
	int i;

	root = json_create_object();

	if (!cap_only) {
		json_object_add_value_uint64(root, "lbstm", le64_to_cpu(nvm_ns->lbstm));
	}
	json_object_add_value_int(root, "pic", nvm_ns->pic);

	elbafs = json_create_array();
	json_object_add_value_array(root, "elbafs", elbafs);

	for (i = 0; i <= ns->nlbaf; i++) {
		struct json_object *elbaf = json_create_object();
		unsigned int elbaf_val = le32_to_cpu(nvm_ns->elbaf[i]);

		json_object_add_value_uint(elbaf, "sts", elbaf_val & 0x7F);
		json_object_add_value_uint(elbaf, "pif", (elbaf_val >> 7) & 0x3);

		json_array_add_value_object(elbafs, elbaf);
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_nvme_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_int(root, "zasl", ctrl->zasl);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_nvme_zns_id_ns(struct nvme_zns_id_ns *ns,
				struct nvme_id_ns *id_ns)
{
	struct json_object *root;
	struct json_object *lbafs;
	int i;

	root = json_create_object();
	json_object_add_value_int(root, "zoc", le16_to_cpu(ns->zoc));
	json_object_add_value_int(root, "ozcs", le16_to_cpu(ns->ozcs));
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
	json_object_add_value_int(root, "zrwafg", le16_to_cpu(ns->zrwafg));
	json_object_add_value_int(root, "zrwasz", le16_to_cpu(ns->zrwasz));
	json_object_add_value_int(root, "zrwacap", ns->zrwacap);

	lbafs = json_create_array();
	json_object_add_value_array(root, "lbafe", lbafs);

	for (i = 0; i <= id_ns->nlbaf; i++) {
		struct json_object *lbaf = json_create_object();

		json_object_add_value_int(lbaf, "zsze",
			le64_to_cpu(ns->lbafe[i].zsze));
		json_object_add_value_int(lbaf, "zdes", ns->lbafe[i].zdes);

		json_array_add_value_object(lbafs, lbaf);
	}
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_nvme_list_ns(struct nvme_ns_list *ns_list)
{
	struct json_object *root;
	struct json_object *valid_attrs;
	struct json_object *valid;
	int i;

	root = json_create_object();
	valid = json_create_array();

	for (i = 0; i < 1024; i++) {
		if (ns_list->ns[i]) {
			valid_attrs = json_create_object();
			json_object_add_value_uint(valid_attrs, "nsid",
				le32_to_cpu(ns_list->ns[i]));
			json_array_add_value_object(valid, valid_attrs);
		}
	}
	json_object_add_value_array(root, "nsid_list", valid);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_zns_finish_zone_list(__u64 nr_zones,
				      struct json_object *zone_list)
{
	struct json_object *root = json_create_object();
	json_object_add_value_uint(root, "nr_zones", nr_zones);
	json_object_add_value_array(root, "zone_list", zone_list);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
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

		json_object_add_value_uint64(zone, "slba",
					     le64_to_cpu(desc->zslba));
		json_object_add_value_uint64(zone, "wp",
					     le64_to_cpu(desc->wp));
		json_object_add_value_uint64(zone, "cap",
					     le64_to_cpu(desc->zcap));
		json_object_add_value_string(zone, "state",
			nvme_zone_state_to_string(desc->zs >> 4));
		json_object_add_value_string(zone, "type",
			nvme_zone_type_to_string(desc->zt));
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
				json_object_add_value_string(zone, "ext_data", "Not valid");
			}
		}

		json_array_add_value_object(zone_list, zone);
	}
}

static void json_nvme_list_ctrl(struct nvme_ctrl_list *ctrl_list)
{
	__u16 num = le16_to_cpu(ctrl_list->num);
	struct json_object *root;
	struct json_object *valid_attrs;
	struct json_object *valid;
	int i;

	root = json_create_object();
	valid = json_create_array();

	json_object_add_value_uint(root, "num_ctrl",
		le16_to_cpu(ctrl_list->num));

	for (i = 0; i < min(num, 2047); i++) {

		valid_attrs = json_create_object();
		json_object_add_value_uint(valid_attrs, "ctrl_id",
			le16_to_cpu(ctrl_list->identifier[i]));
		json_array_add_value_object(valid, valid_attrs);
	}

	json_object_add_value_array(root, "ctrl_list", valid);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_nvme_id_nvmset(struct nvme_id_nvmset_list *nvmset,
				unsigned int nvmeset_id)
{
	__u32 nent = nvmset->nid;
	struct json_object *entries;
	struct json_object *root;
	int i;

	root = json_create_object();

	json_object_add_value_int(root, "nid", nent);

	entries = json_create_array();
	for (i = 0; i < nent; i++) {
		struct json_object *entry = json_create_object();

		json_object_add_value_int(entry, "nvmset_id",
			  le16_to_cpu(nvmset->ent[i].nvmsetid));
		json_object_add_value_int(entry, "endurance_group_id",
			  le16_to_cpu(nvmset->ent[i].endgid));
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
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_nvme_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *caps)
{
	struct json_object *root;

	root = json_create_object();

	json_object_add_value_uint(root, "cntlid", le16_to_cpu(caps->cntlid));
	json_object_add_value_uint(root, "portid", le16_to_cpu(caps->portid));
	json_object_add_value_uint(root, "crt",    caps->crt);

	json_object_add_value_uint(root, "vqfrt",  le32_to_cpu(caps->vqfrt));
	json_object_add_value_uint(root, "vqrfa",  le32_to_cpu(caps->vqrfa));
	json_object_add_value_int(root, "vqrfap", le16_to_cpu(caps->vqrfap));
	json_object_add_value_int(root, "vqprt",  le16_to_cpu(caps->vqprt));
	json_object_add_value_int(root, "vqfrsm", le16_to_cpu(caps->vqfrsm));
	json_object_add_value_int(root, "vqgran", le16_to_cpu(caps->vqgran));

	json_object_add_value_uint(root, "vifrt",  le32_to_cpu(caps->vifrt));
	json_object_add_value_uint(root, "virfa",  le32_to_cpu(caps->virfa));
	json_object_add_value_int(root, "virfap", le16_to_cpu(caps->virfap));
	json_object_add_value_int(root, "viprt",  le16_to_cpu(caps->viprt));
	json_object_add_value_int(root, "vifrsm", le16_to_cpu(caps->vifrsm));
	json_object_add_value_int(root, "vigran", le16_to_cpu(caps->vigran));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_nvme_list_secondary_ctrl(const struct nvme_secondary_ctrl_list *sc_list,
					  __u32 count)
{
	const struct nvme_secondary_ctrl *sc_entry = &sc_list->sc_entry[0];
	__u32 nent = min(sc_list->num, count);
	struct json_object *entries;
	struct json_object *root;
	int i;

	root = json_create_object();

	json_object_add_value_int(root, "num", nent);

	entries = json_create_array();
	for (i = 0; i < nent; i++) {
		struct json_object *entry = json_create_object();

		json_object_add_value_int(entry,
			"secondary-controller-identifier",
			le16_to_cpu(sc_entry[i].scid));
		json_object_add_value_int(entry,
			"primary-controller-identifier",
			le16_to_cpu(sc_entry[i].pcid));
		json_object_add_value_int(entry, "secondary-controller-state",
					  sc_entry[i].scs);
		json_object_add_value_int(entry, "virtual-function-number",
			le16_to_cpu(sc_entry[i].vfn));
		json_object_add_value_int(entry, "num-virtual-queues",
			le16_to_cpu(sc_entry[i].nvq));
		json_object_add_value_int(entry, "num-virtual-interrupts",
			le16_to_cpu(sc_entry[i].nvi));
		json_array_add_value_object(entries, entry);
	}

	json_object_add_value_array(root, "secondary-controllers", entries);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_nvme_id_ns_granularity_list(
		const struct nvme_id_ns_granularity_list *glist)
{
	int i;
	struct json_object *root;
	struct json_object *entries;

	root = json_create_object();

	json_object_add_value_int(root, "attributes", glist->attributes);
	json_object_add_value_int(root, "num-descriptors",
		glist->num_descriptors);

	entries = json_create_array();
	for (i = 0; i <= glist->num_descriptors; i++) {
		struct json_object *entry = json_create_object();

		json_object_add_value_uint64(entry, "namespace-size-granularity",
			le64_to_cpu(glist->entry[i].nszegran));
		json_object_add_value_uint64(entry, "namespace-capacity-granularity",
			le64_to_cpu(glist->entry[i].ncapgran));
		json_array_add_value_object(entries, entry);
	}

	json_object_add_value_array(root, "namespace-granularity-list", entries);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_nvme_id_uuid_list(const struct nvme_id_uuid_list *uuid_list)
{
	struct json_object *root;
	struct json_object *entries;
	int i;

	root = json_create_object();
	entries = json_create_array();

	for (i = 0; i < NVME_ID_UUID_LIST_MAX; i++) {
		__u8 uuid[NVME_UUID_LEN];
		struct json_object *entry = json_create_object();

		/* The list is terminated by a zero UUID value */
		if (memcmp(uuid_list->entry[i].uuid, zero_uuid, sizeof(zero_uuid)) == 0)
			break;
		memcpy(&uuid, uuid_list->entry[i].uuid, sizeof(uuid));
		json_object_add_value_int(entry, "association",
			uuid_list->entry[i].header & 0x3);
		json_object_add_value_string(entry, "uuid",
			util_uuid_to_string(uuid));
		json_array_add_value_object(entries, entry);
	}
	json_object_add_value_array(root, "UUID-list", entries);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_id_domain_list(struct nvme_id_domain_list *id_dom)
{
	struct json_object *root;
	struct json_object *entries;
	struct json_object *entry;
	int i;
	nvme_uint128_t dom_cap, unalloc_dom_cap, max_egrp_dom_cap;

	root = json_create_object();
	entries = json_create_array();

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
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_nvme_endurance_group_list(struct nvme_id_endurance_group_list *endgrp_list)
{
	struct json_object *root;
	struct json_object *valid_attrs;
	struct json_object *valid;
	int i;

	root = json_create_object();
	valid = json_create_array();

	json_object_add_value_uint(root, "num_endgrp_id",
		le16_to_cpu(endgrp_list->num));

	for (i = 0; i < min(le16_to_cpu(endgrp_list->num), 2047); i++) {
		valid_attrs = json_create_object();
		json_object_add_value_uint(valid_attrs, "endgrp_id",
			le16_to_cpu(endgrp_list->identifier[i]));
		json_array_add_value_object(valid, valid_attrs);
	}

	json_object_add_value_array(root, "endgrp_list", valid);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_support_log(struct nvme_supported_log_pages *support_log,
			     const char *devname)
{
	struct json_object *root;
	struct json_object *valid;
	struct json_object *valid_attrs;
	unsigned int lid;
	char key[128];
	__u32 support;

	root = json_create_object();
	valid = json_create_array();

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
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_detail_list(nvme_root_t r)
{
	struct json_object *jroot = json_create_object();
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

		json_object_add_value_string(hss, "HostNQN", nvme_host_get_hostnqn(h));
		hostid = nvme_host_get_hostid(h);
		if (hostid)
			json_object_add_value_string(hss, "HostID", hostid);

		nvme_for_each_subsystem(h , s) {
			struct json_object *jss = json_create_object();
			struct json_object *jctrls = json_create_array();
			struct json_object *jnss = json_create_array();

			json_object_add_value_string(jss, "Subsystem", nvme_subsystem_get_name(s));
			json_object_add_value_string(jss, "SubsystemNQN", nvme_subsystem_get_nqn(s));

			nvme_subsystem_for_each_ctrl(s, c) {
				struct json_object *jctrl = json_create_object();
				struct json_object *jnss = json_create_array();
				struct json_object *jpaths = json_create_array();

				json_object_add_value_string(jctrl, "Controller", nvme_ctrl_get_name(c));
				json_object_add_value_string(jctrl, "SerialNumber", nvme_ctrl_get_serial(c));
				json_object_add_value_string(jctrl, "ModelNumber", nvme_ctrl_get_model(c));
				json_object_add_value_string(jctrl, "Firmware", nvme_ctrl_get_firmware(c));
				json_object_add_value_string(jctrl, "Transport", nvme_ctrl_get_transport(c));
				json_object_add_value_string(jctrl, "Address", nvme_ctrl_get_address(c));
				json_object_add_value_string(jctrl, "Slot", nvme_ctrl_get_phy_slot(c));

				nvme_ctrl_for_each_ns(c, n) {
					struct json_object *jns = json_create_object();
					int lba = nvme_ns_get_lba_size(n);
					uint64_t nsze = nvme_ns_get_lba_count(n) * lba;
					uint64_t nuse = nvme_ns_get_lba_util(n) * lba;

					json_object_add_value_string(jns, "NameSpace", nvme_ns_get_name(n));
					json_object_add_value_string(jns, "Generic", nvme_ns_get_generic_name(n));
					json_object_add_value_int(jns, "NSID", nvme_ns_get_nsid(n));
					json_object_add_value_uint64(jns, "UsedBytes", nuse);
					json_object_add_value_uint64(jns, "MaximumLBA", nvme_ns_get_lba_count(n));
					json_object_add_value_uint64(jns, "PhysicalSize", nsze);
					json_object_add_value_int(jns, "SectorSize", lba);

					json_array_add_value_object(jnss, jns);
				}
				json_object_add_value_object(jctrl, "Namespaces", jnss);

				nvme_ctrl_for_each_path(c, p) {
					struct json_object *jpath = json_create_object();

					json_object_add_value_string(jpath, "Path", nvme_path_get_name(p));
					json_object_add_value_string(jpath, "ANAState", nvme_path_get_ana_state(p));

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

				json_object_add_value_string(jns, "NameSpace", nvme_ns_get_name(n));
				json_object_add_value_string(jns, "Generic", nvme_ns_get_generic_name(n));
				json_object_add_value_int(jns, "NSID", nvme_ns_get_nsid(n));
				json_object_add_value_uint64(jns, "UsedBytes", nuse);
				json_object_add_value_uint64(jns, "MaximumLBA", nvme_ns_get_lba_count(n));
				json_object_add_value_uint64(jns, "PhysicalSize", nsze);
				json_object_add_value_int(jns, "SectorSize", lba);

				json_array_add_value_object(jnss, jns);
			}
			json_object_add_value_object(jss, "Namespaces", jnss);

			json_array_add_value_object(jsslist, jss);
		}

		json_object_add_value_object(hss, "Subsystems", jsslist);
		json_array_add_value_object(jdev, hss);
	}
	json_object_add_value_array(jroot, "Devices", jdev);
	json_print_object(jroot, NULL);
	printf("\n");
	json_free_object(jroot);
}

static struct json_object *json_list_item(nvme_ns_t n)
{
	struct json_object *jdevice = json_create_object();
	char devname[128] = { 0 };
	char genname[128] = { 0 };

	int lba = nvme_ns_get_lba_size(n);
	uint64_t nsze = nvme_ns_get_lba_count(n) * lba;
	uint64_t nuse = nvme_ns_get_lba_util(n) * lba;

	nvme_dev_full_path(n, devname, sizeof(devname));
	nvme_generic_full_path(n, genname, sizeof(genname));

	json_object_add_value_int(jdevice, "NameSpace", nvme_ns_get_nsid(n));
	json_object_add_value_string(jdevice, "DevicePath", devname);
	json_object_add_value_string(jdevice, "GenericPath", genname);
	json_object_add_value_string(jdevice, "Firmware", nvme_ns_get_firmware(n));
	json_object_add_value_string(jdevice, "ModelNumber", nvme_ns_get_model(n));
	json_object_add_value_string(jdevice, "SerialNumber", nvme_ns_get_serial(n));
	json_object_add_value_uint64(jdevice, "UsedBytes", nuse);
	json_object_add_value_uint64(jdevice, "MaximumLBA", nvme_ns_get_lba_count(n));
	json_object_add_value_uint64(jdevice, "PhysicalSize", nsze);
	json_object_add_value_int(jdevice, "SectorSize", lba);

	return jdevice;
}

static void json_simple_list(nvme_root_t r)
{
	struct json_object *jroot = json_create_object();
	struct json_object *jdevices = json_create_array();

	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	nvme_ns_t n;

	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			nvme_subsystem_for_each_ns(s, n)
				json_array_add_value_object(jdevices,
							    json_list_item(n));

			nvme_subsystem_for_each_ctrl(s, c)
				nvme_ctrl_for_each_ns(c, n)
				json_array_add_value_object(jdevices,
							    json_list_item(n));
		}
	}
	json_object_add_value_array(jroot, "Devices", jdevices);
	json_print_object(jroot, NULL);
	printf("\n");
	json_free_object(jroot);
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
	        json_object_add_value_int(ns_attrs, "NSID",
					  nvme_ns_get_nsid(n));

		paths = json_create_array();
		nvme_namespace_for_each_path(n, p) {
			struct json_object *path_attrs;

			nvme_ctrl_t c = nvme_path_get_ctrl(p);

			path_attrs = json_create_object();
			json_object_add_value_string(path_attrs, "Name",
						     nvme_ctrl_get_name(c));
			json_object_add_value_string(path_attrs, "Transport",
						     nvme_ctrl_get_transport(c));
			json_object_add_value_string(path_attrs, "Address",
						     nvme_ctrl_get_address(c));
			json_object_add_value_string(path_attrs, "State",
						     nvme_ctrl_get_state(c));
			json_object_add_value_string(path_attrs, "ANAState",
						     nvme_path_get_ana_state(p));
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
		        json_object_add_value_int(ns_attrs, "NSID",
						  nvme_ns_get_nsid(n));

		        ctrl = json_create_array();
			ctrl_attrs = json_create_object();
			json_object_add_value_string(ctrl_attrs, "Name",
						     nvme_ctrl_get_name(c));
			json_object_add_value_string(ctrl_attrs, "Transport",
						     nvme_ctrl_get_transport(c));
			json_object_add_value_string(ctrl_attrs, "Address",
						     nvme_ctrl_get_address(c));
			json_object_add_value_string(ctrl_attrs, "State",
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
	struct json_object *root;
	nvme_host_t h;

	root = json_create_array();

	nvme_for_each_host(r, h) {
		nvme_subsystem_t s;
		const char *hostid;

		host_attrs = json_create_object();
		json_object_add_value_string(host_attrs, "HostNQN",
					     nvme_host_get_hostnqn(h));
		hostid = nvme_host_get_hostid(h);
		if (hostid)
			json_object_add_value_string(host_attrs, "HostID", hostid);
		subsystems = json_create_array();
		nvme_for_each_subsystem(h, s) {
			subsystem_attrs = json_create_object();
			json_object_add_value_string(subsystem_attrs, "Name",
						     nvme_subsystem_get_name(s));
			json_object_add_value_string(subsystem_attrs, "NQN",
						     nvme_subsystem_get_nqn(s));
			json_object_add_value_string(subsystem_attrs, "IOPolicy",
						     nvme_subsystem_get_iopolicy(s));

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
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_discovery_log(struct nvmf_discovery_log *log, int numrec)
{
	struct json_object *root;
	struct json_object *entries;
	int i;

	root = json_create_object();
	entries = json_create_array();
	json_object_add_value_uint64(root, "genctr", le64_to_cpu(log->genctr));
	json_object_add_value_array(root, "records", entries);

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_log_entry *e = &log->entries[i];
		struct json_object *entry = json_create_object();

		json_object_add_value_string(entry, "trtype",
					     nvmf_trtype_str(e->trtype));
		json_object_add_value_string(entry, "adrfam",
					     nvmf_adrfam_str(e->adrfam));
		json_object_add_value_string(entry, "subtype",
					     nvmf_subtype_str(e->subtype));
		json_object_add_value_string(entry,"treq",
					     nvmf_treq_str(e->treq));
		json_object_add_value_uint(entry, "portid",
					   le16_to_cpu(e->portid));
		json_object_add_value_string(entry, "trsvcid", e->trsvcid);
		json_object_add_value_string(entry, "subnqn", e->subnqn);
		json_object_add_value_string(entry, "traddr", e->traddr);
		json_object_add_value_string(entry, "eflags",
					     nvmf_eflags_str(le16_to_cpu(e->eflags)));

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			json_object_add_value_string(entry, "rdma_prtype",
				nvmf_prtype_str(e->tsas.rdma.prtype));
			json_object_add_value_string(entry, "rdma_qptype",
				nvmf_qptype_str(e->tsas.rdma.qptype));
			json_object_add_value_string(entry, "rdma_cms",
				nvmf_cms_str(e->tsas.rdma.cms));
			json_object_add_value_uint(entry, "rdma_pkey",
				le16_to_cpu(e->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			json_object_add_value_string(entry, "sectype",
				nvmf_sectype_str(e->tsas.tcp.sectype));
			break;
		}
		json_array_add_value_object(entries, entry);
	}
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_connect_msg(nvme_ctrl_t c)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_string(root, "device", nvme_ctrl_get_name(c));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_output_object(struct json_object *root)
{
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_output_status(int status)
{
	struct json_object *root = json_create_object();
	int val;
	int type;

	if (status < 0) {
		json_object_add_value_string(root, "error", nvme_strerror(errno));
		return json_output_object(root);
	}

	val = nvme_status_get_value(status);
	type = nvme_status_get_type(status);

	switch (type) {
	case NVME_STATUS_TYPE_NVME:
		json_object_add_value_string(root, "error", nvme_status_to_string(val, false));
		json_object_add_value_string(root, "type", "nvme");
		break;
	case NVME_STATUS_TYPE_MI:
		json_object_add_value_string(root, "error", nvme_mi_status_to_string(val));
		json_object_add_value_string(root, "type", "nvme-mi");
		break;
	default:
		json_object_add_value_string(root, "type", "unknow");
		break;
	}

	json_object_add_value_int(root, "value", val);

	json_output_object(root);
}

static void json_output_message(bool error, const char *msg, va_list ap)
{
	struct json_object *root = json_create_object();
	char *value;
	const char *key = error ? "error" : "result";

	if (vasprintf(&value, msg, ap) < 0)
		value = NULL;

	if (value)
		json_object_add_value_string(root, key, value);
	else
		json_object_add_value_string(root, key, "Could not allocate string");

	json_output_object(root);

	free(value);
}

static void json_output_perror(const char *msg)
{
	struct json_object *root = json_create_object();
	char *error;

	if (asprintf(&error, "%s: %s", msg, strerror(errno)) < 0)
		error = NULL;

	if (error)
		json_object_add_value_string(root, "error", error);
	else
		json_object_add_value_string(root, "error", "Could not allocate string");

	json_output_object(root);

	free(error);
}

static struct print_ops json_print_ops = {
	.ana_log			= json_ana_log,
	.boot_part_log			= json_boot_part_log,
	.ctrl_list			= json_nvme_list_ctrl,
	.ctrl_registers			= json_ctrl_registers,
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
	.ns_list			= json_nvme_list_ns,
	.nvm_id_ns			= json_nvme_nvm_id_ns,
	.id_ctrl_nvm			= json_nvme_id_ctrl_nvm,
	.id_domain_list			= json_id_domain_list,
	.id_independent_id_ns		= json_nvme_cmd_set_independent_id_ns,
	.id_ns				= json_nvme_id_ns,
	.id_ns_descs			= json_nvme_id_ns_descs,
	.id_ns_granularity_list		= json_nvme_id_ns_granularity_list,
	.id_nvmset_list			= json_nvme_id_nvmset,
	.id_uuid_list			= json_nvme_id_uuid_list,
	.lba_status_log			= json_lba_status_log,
	.media_unit_stat_log		= json_media_unit_stat_log,
	.mi_cmd_support_effects_log	= json_mi_cmd_support_effects_log,
	.ns_list_log			= json_changed_ns_list_log,
	.persistent_event_log		= json_persistent_event_log,
	.predictable_latency_event_agg_log = json_predictable_latency_event_agg_log,
	.predictable_latency_per_nvmset	= json_predictable_latency_per_nvmset,
	.primary_ctrl_cap		= json_nvme_primary_ctrl_cap,
	.resv_notification_log		= json_resv_notif_log,
	.resv_report			= json_nvme_resv_report,
	.sanitize_log_page		= json_sanitize_log,
	.secondary_ctrl_list		= json_nvme_list_secondary_ctrl,
	.self_test_log 			= json_self_test_log,
	.smart_log			= json_smart_log,
	.supported_cap_config_list_log	= json_supported_cap_config_log,
	.supported_log_pages		= json_support_log,
	.zns_changed_zone_log		= NULL,
	.zns_report_zones		= json_nvme_zns_report_zones,
	.zns_finish_zone_list		= json_zns_finish_zone_list,
	.zns_id_ctrl			= json_nvme_zns_id_ctrl,
	.zns_id_ns			= json_nvme_zns_id_ns,

	.list_items			= json_print_list_items,
	.print_nvme_subsystem_list	= json_print_nvme_subsystem_list,
	.topology_ctrl			= json_simple_topology,
	.topology_namespace		= json_simple_topology,

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
