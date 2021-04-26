#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>

#include "nvme.h"
#include "nvme-print.h"
#include "nvme-models.h"
#include "util/suffix.h"
#include "common.h"

static const uint8_t zero_uuid[16] = { 0 };
static const uint8_t invalid_uuid[16] = {[0 ... 15] = 0xff };
static const char dash[100] = {[0 ... 99] = '-'};

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

const char *nvme_cmd_to_string(int admin, __u8 opcode)
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
		case nvme_admin_get_lba_status:	return "Get LBA Status";
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
		case nvme_cmd_verify:		return "Verify";
		case nvme_cmd_copy:		return "Copy";
		}
	}

	return "Unknown";
}

static const char *fw_to_string(__u64 fw)
{
	static char ret[9];
	char *c = (char *)&fw;
	int i;

	for (i = 0; i < 8; i++)
		ret[i] = c[i] >= '!' && c[i] <= '~' ? c[i] : '.';
	ret[i] = '\0';
	return ret;
}

static const char *get_sanitize_log_sstat_status_str(__u16 status)
{
	switch (status & NVME_SANITIZE_LOG_STATUS_MASK) {
	case NVME_SANITIZE_LOG_NEVER_SANITIZED:
		return "NVM Subsystem has never been sanitized.";
	case NVME_SANITIZE_LOG_COMPLETED_SUCCESS:
		return "Most Recent Sanitize Command Completed Successfully.";
	case NVME_SANITIZE_LOG_IN_PROGESS:
		return "Sanitize in Progress.";
	case NVME_SANITIZE_LOG_COMPLETED_FAILED:
		return "Most Recent Sanitize Command Failed.";
	case NVME_SANITIZE_LOG_ND_COMPLETED_SUCCESS:
		return "Most Recent Sanitize Command (No-Deallocate After Sanitize) Completed Successfully.";
	default:
		return "Unknown";
	}
}

static void json_nvme_id_ns(struct nvme_id_ns *ns)
{
	char nguid_buf[2 * sizeof(ns->nguid) + 1],
		eui64_buf[2 * sizeof(ns->eui64) + 1];
	char *nguid = nguid_buf, *eui64 = eui64_buf;
	struct json_object *root;
	struct json_object *lbafs;
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

	if (ns->nsfeat & 0x10) {
		json_object_add_value_int(root, "npwg", le16_to_cpu(ns->npwg));
		json_object_add_value_int(root, "npwa", le16_to_cpu(ns->npwa));
		json_object_add_value_int(root, "npdg", le16_to_cpu(ns->npdg));
		json_object_add_value_int(root, "npda", le16_to_cpu(ns->npda));
		json_object_add_value_int(root, "nows", le16_to_cpu(ns->nows));
	}

	json_object_add_value_int(root, "mssrl", le16_to_cpu(ns->mssrl));
	json_object_add_value_int(root, "mcl", le32_to_cpu(ns->mcl));
	json_object_add_value_int(root, "msrc", ns->msrc);

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

static void json_nvme_id_ctrl(struct nvme_id_ctrl *ctrl,
			void (*vs)(__u8 *vs, struct json_object *root))
{
	struct json_object *root;
	struct json_object *psds;

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
	json_object_add_value_int(root, "crdt1", le16_to_cpu(ctrl->crdt1));
	json_object_add_value_int(root, "crdt2", le16_to_cpu(ctrl->crdt2));
	json_object_add_value_int(root, "crdt3", le16_to_cpu(ctrl->crdt3));
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
	json_object_add_value_int(root, "nsetidmax",
		le16_to_cpu(ctrl->nsetidmax));

	json_object_add_value_int(root, "anatt",ctrl->anatt);
	json_object_add_value_int(root, "anacap", ctrl->anacap);
	json_object_add_value_int(root, "anagrpmax",
		le32_to_cpu(ctrl->anagrpmax));
	json_object_add_value_int(root, "nanagrpid",
		le32_to_cpu(ctrl->nanagrpid));
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
	json_object_add_value_int(root, "sgls", le32_to_cpu(ctrl->sgls));

	if (strlen(subnqn))
		json_object_add_value_string(root, "subnqn", subnqn);

	json_object_add_value_int(root, "ioccsz", le32_to_cpu(ctrl->ioccsz));
	json_object_add_value_int(root, "iorcsz", le32_to_cpu(ctrl->iorcsz));
	json_object_add_value_int(root, "icdoff", le16_to_cpu(ctrl->icdoff));
	json_object_add_value_int(root, "fcatt", ctrl->fcatt);
	json_object_add_value_int(root, "msdbd", ctrl->msdbd);
	json_object_add_value_int(root, "ofcs", le16_to_cpu(ctrl->ofcs));

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
		json_object_add_value_int(psd, "read_tput",
			ctrl->psd[i].read_tput);
		json_object_add_value_int(psd, "read_lat",
			ctrl->psd[i].read_lat);
		json_object_add_value_int(psd, "write_tput",
			ctrl->psd[i].write_tput);
		json_object_add_value_int(psd, "write_lat",
			ctrl->psd[i].write_lat);
		json_object_add_value_int(psd, "idle_power",
			le16_to_cpu(ctrl->psd[i].idle_power));
		json_object_add_value_int(psd, "idle_scale",
			ctrl->psd[i].idle_scale);
		json_object_add_value_int(psd, "active_power",
			le16_to_cpu(ctrl->psd[i].active_power));
		json_object_add_value_int(psd, "active_work_scale",
			ctrl->psd[i].active_work_scale);

		json_array_add_value_object(psds, psd);
	}

	if(vs)
		vs(ctrl->vs, root);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_error_log(struct nvme_error_log_page *err_log, int entries)
{
	struct json_object *root;
	struct json_object *errors;
	int i;

	root = json_create_object();
	errors = json_create_array();
	json_object_add_value_array(root, "errors", errors);

	for (i = 0; i < entries; i++) {
		struct json_object *error = json_create_object();

		json_object_add_value_uint(error, "error_count",
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
		json_object_add_value_uint(error, "lba",
			le64_to_cpu(err_log[i].lba));
		json_object_add_value_uint(error, "nsid",
			le32_to_cpu(err_log[i].nsid));
		json_object_add_value_int(error, "vs", err_log[i].vs);
		json_object_add_value_int(error, "trtype", err_log[i].trtype);
		json_object_add_value_uint(error, "cs",
			le64_to_cpu(err_log[i].cs));
		json_object_add_value_int(error, "trtype_spec_info",
			le16_to_cpu(err_log[i].trtype_spec_info));

		json_array_add_value_object(errors, error);
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_nvme_resv_report(struct nvme_reservation_status *status,
				  int bytes, __u32 cdw11)
{
	struct json_object *root;
	struct json_object *rcs;
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
			json_object_add_value_uint(rc, "hostid",
				le64_to_cpu(status->regctl_ds[i].hostid));
			json_object_add_value_uint(rc, "rkey",
				le64_to_cpu(status->regctl_ds[i].rkey));

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

			json_object_add_value_int(rc, "cntlid",
				le16_to_cpu(ext_status->regctl_eds[i].cntlid));
			json_object_add_value_int(rc, "rcsts",
				ext_status->regctl_eds[i].rcsts);
			json_object_add_value_uint(rc, "rkey",
				le64_to_cpu(ext_status->regctl_eds[i].rkey));
			for (j = 0; j < 16; j++)
				sprintf(hostid + j * 2, "%02x",
					ext_status->regctl_eds[i].hostid[j]);

			json_object_add_value_string(rc, "hostid", hostid);
			json_array_add_value_object(rcs, rc);
		}
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_fw_log(struct nvme_firmware_log_page *fw_log, const char *devname)
{
	struct json_object *root;
	struct json_object *fwsi;
	char fmt[21];
	char str[32];
	int i;

	root = json_create_object();
	fwsi = json_create_object();

	json_object_add_value_int(fwsi, "Active Firmware Slot (afi)",
		fw_log->afi);
	for (i = 0; i < 7; i++) {
		if (fw_log->frs[i]) {
			snprintf(fmt, sizeof(fmt), "Firmware Rev Slot %d",
				i + 1);
			snprintf(str, sizeof(str), "%"PRIu64" (%s)",
				(uint64_t)fw_log->frs[i],
			fw_to_string(fw_log->frs[i]));
			json_object_add_value_string(fwsi, fmt, str);
		}
	}
	json_object_add_value_object(root, devname, fwsi);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_changed_ns_list_log(struct nvme_changed_ns_list_log *log,
				     const char *devname)
{
	struct json_object *root;
	struct json_object *nsi;
	char fmt[32];
	char str[32];
	__u32 nsid;
	int i;

	if (log->log[0] == cpu_to_le32(0xffffffff))
		return;

	root = json_create_object();
	nsi = json_create_object();

	json_object_add_value_string(root, "Changed Namespace List Log",
		devname);

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

static void json_endurance_log(struct nvme_endurance_group_log *endurance_group,
			__u16 group_id)
{
	struct json_object *root;

	long double endurance_estimate =
		int128_to_double(endurance_group->endurance_estimate);
	long double data_units_read =
		int128_to_double(endurance_group->data_units_read);
	long double data_units_written =
		int128_to_double(endurance_group->data_units_written);
	long double media_units_written =
		int128_to_double(endurance_group->media_units_written);
	long double host_read_cmds =
		int128_to_double(endurance_group->host_read_cmds);
	long double host_write_cmds =
		int128_to_double(endurance_group->host_write_cmds);
	long double media_data_integrity_err =
		int128_to_double(endurance_group->media_data_integrity_err);
	long double num_err_info_log_entries =
		int128_to_double(endurance_group->num_err_info_log_entries);

	root = json_create_object();

	json_object_add_value_int(root, "critical_warning",
		endurance_group->critical_warning);
	json_object_add_value_int(root, "avl_spare",
		endurance_group->avl_spare);
	json_object_add_value_int(root, "avl_spare_threshold",
		endurance_group->avl_spare_threshold);
	json_object_add_value_int(root, "percent_used",
		endurance_group->percent_used);
	json_object_add_value_float(root, "endurance_estimate",
		endurance_estimate);
	json_object_add_value_float(root, "data_units_read", data_units_read);
	json_object_add_value_float(root, "data_units_written",
		data_units_written);
	json_object_add_value_float(root, "mediate_write_commands",
		media_units_written);
	json_object_add_value_float(root, "host_read_cmds", host_read_cmds);
	json_object_add_value_float(root, "host_write_cmds", host_write_cmds);
	json_object_add_value_float(root, "media_data_integrity_err",
		media_data_integrity_err);
	json_object_add_value_float(root, "num_err_info_log_entries",
		num_err_info_log_entries);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
	enum nvme_print_flags flags)
{
	int c, human = flags & VERBOSE;
	struct json_object *root;
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
	json_object_add_value_float(root, "data_units_read", data_units_read);
	json_object_add_value_float(root, "data_units_written",
		data_units_written);
	json_object_add_value_float(root, "host_read_commands",
		host_read_commands);
	json_object_add_value_float(root, "host_write_commands",
		host_write_commands);
	json_object_add_value_float(root, "controller_busy_time",
		controller_busy_time);
	json_object_add_value_float(root, "power_cycles", power_cycles);
	json_object_add_value_float(root, "power_on_hours", power_on_hours);
	json_object_add_value_float(root, "unsafe_shutdowns", unsafe_shutdowns);
	json_object_add_value_float(root, "media_errors", media_errors);
	json_object_add_value_float(root, "num_err_log_entries",
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

static void json_ana_log(struct nvme_ana_rsp_hdr *ana_log, const char *devname)
{
	int offset = sizeof(struct nvme_ana_rsp_hdr);
	struct nvme_ana_rsp_hdr *hdr = ana_log;
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
	json_object_add_value_uint(root, "chgcnt",
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

static void json_self_test_log(struct nvme_self_test_log *self_test, __u8 dst_entries)
{
	struct json_object *valid_attrs;
	struct json_object *root;
	struct json_object *valid;
	int i;
	__u32 num_entries;

	root = json_create_object();
	json_object_add_value_int(root, "Current Device Self-Test Operation",
		self_test->crnt_dev_selftest_oprn);
	json_object_add_value_int(root, "Current Device Self-Test Completion",
		self_test->crnt_dev_selftest_compln);
	valid = json_create_array();

	num_entries = min(dst_entries, NVME_ST_REPORTS);
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
		json_object_add_value_uint(valid_attrs, "Power on hours",
			le64_to_cpu(self_test->result[i].poh));
		if (self_test->result[i].vdi & NVME_ST_VALID_NSID)
			json_object_add_value_int(valid_attrs, "Namespace Identifier",
				le32_to_cpu(self_test->result[i].nsid));
		if (self_test->result[i].vdi & NVME_ST_VALID_FLBA)
			json_object_add_value_uint(valid_attrs, "Failing LBA",
				le64_to_cpu(self_test->result[i].flba));
		if (self_test->result[i].vdi & NVME_ST_VALID_SCT)
			json_object_add_value_int(valid_attrs, "Status Code Type",
				self_test->result[i].sct);
		if (self_test->result[i].vdi & NVME_ST_VALID_SC)
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

static void json_effects_log(struct nvme_effects_log_page *effects_log)
{
	struct json_object *root;
	struct json_object *acs;
	struct json_object *iocs;
	unsigned int opcode;
	char key[128];
	__u32 effect;

	root = json_create_object();
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
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_sanitize_log(struct nvme_sanitize_log_page *sanitize_log,
			      const char *devname)
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

	json_object_add_value_int(dev, "sprog",
		le16_to_cpu(sanitize_log->progress));
	json_object_add_value_int(sstat, "global_erased",
		(status & NVME_SANITIZE_LOG_GLOBAL_DATA_ERASED) >> 8);
	json_object_add_value_int(sstat, "no_cmplted_passes",
		(status & NVME_SANITIZE_LOG_NUM_CMPLTED_PASS_MASK) >> 3);

	status_str = get_sanitize_log_sstat_status_str(status);
	sprintf(str, "(%d) %s", status & NVME_SANITIZE_LOG_STATUS_MASK,
		status_str);
	json_object_add_value_string(sstat, "status", str);

	json_object_add_value_object(dev, "sstat", sstat);
	json_object_add_value_uint(dev, "cdw10_info",
		le32_to_cpu(sanitize_log->cdw10_info));
	json_object_add_value_uint(dev, "time_over_write",
		le32_to_cpu(sanitize_log->est_ovrwrt_time));
	json_object_add_value_uint(dev, "time_block_erase",
		le32_to_cpu(sanitize_log->est_blk_erase_time));
	json_object_add_value_uint(dev, "time_crypto_erase",
		le32_to_cpu(sanitize_log->est_crypto_erase_time));

	json_object_add_value_uint(dev, "time_over_write_no_dealloc",
		le32_to_cpu(sanitize_log->est_ovrwrt_time_with_no_deallocate));
	json_object_add_value_uint(dev, "time_block_erase_no_dealloc",
		le32_to_cpu(sanitize_log->est_blk_erase_time_with_no_deallocate));
	json_object_add_value_uint(dev, "time_crypto_erase_no_dealloc",
		le32_to_cpu(sanitize_log->est_crypto_erase_time_with_no_deallocate));

	json_object_add_value_object(root, devname, dev);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void json_predictable_latency_per_nvmset(
	struct nvme_predlat_per_nvmset_log_page *plpns_log,
	__u16 nvmset_id)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_uint(root, "nvmset_id",
		le16_to_cpu(nvmset_id));
	json_object_add_value_uint(root, "status",
		plpns_log->status);
	json_object_add_value_uint(root, "event_type",
		le16_to_cpu(plpns_log->event_type));
	json_object_add_value_uint(root, "dtwin_reads_typical",
		le64_to_cpu(plpns_log->dtwin_rtyp));
	json_object_add_value_uint(root, "dtwin_writes_typical",
		le64_to_cpu(plpns_log->dtwin_wtyp));
	json_object_add_value_uint(root, "dtwin_time_maximum",
		le64_to_cpu(plpns_log->dtwin_timemax));
	json_object_add_value_uint(root, "ndwin_time_minimum_high",
		le64_to_cpu(plpns_log->ndwin_timemin_high));
	json_object_add_value_uint(root, "ndwin_time_minimum_low",
		le64_to_cpu(plpns_log->ndwin_timemin_low));
	json_object_add_value_uint(root, "dtwin_reads_estimate",
		le64_to_cpu(plpns_log->dtwin_restimate));
	json_object_add_value_uint(root, "dtwin_writes_estimate",
		le64_to_cpu(plpns_log->dtwin_westimate));
	json_object_add_value_uint(root, "dtwin_time_estimate",
		le64_to_cpu(plpns_log->dtwin_testimate));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void nvme_show_predictable_latency_per_nvmset(
	struct nvme_predlat_per_nvmset_log_page *plpns_log,
	__u16 nvmset_id, const char *devname,
	enum nvme_print_flags flags)
{
	if (flags & BINARY)
		return d_raw((unsigned char *)plpns_log,
			sizeof(*plpns_log));
	if (flags & JSON)
		return json_predictable_latency_per_nvmset(plpns_log,
			nvmset_id);

	printf("Predictable Latency Per NVM Set Log for device: %s\n",
		devname);
	printf("Predictable Latency Per NVM Set Log for NVM Set ID: %u\n",
		le16_to_cpu(nvmset_id));
	printf("Status: %u\n", plpns_log->status);
	printf("Event Type: %u\n",
		le16_to_cpu(plpns_log->event_type));
	printf("DTWIN Reads Typical: %"PRIu64"\n",
		le64_to_cpu(plpns_log->dtwin_rtyp));
	printf("DTWIN Writes Typical: %"PRIu64"\n",
		le64_to_cpu(plpns_log->dtwin_wtyp));
	printf("DTWIN Time Maximum: %"PRIu64"\n",
		le64_to_cpu(plpns_log->dtwin_timemax));
	printf("NDWIN Time Minimum High: %"PRIu64" \n",
		le64_to_cpu(plpns_log->ndwin_timemin_high));
	printf("NDWIN Time Minimum Low: %"PRIu64"\n",
		le64_to_cpu(plpns_log->ndwin_timemin_low));
	printf("DTWIN Reads Estimate: %"PRIu64"\n",
		le64_to_cpu(plpns_log->dtwin_restimate));
	printf("DTWIN Writes Estimate: %"PRIu64"\n",
		le64_to_cpu(plpns_log->dtwin_westimate));
	printf("DTWIN Time Estimate: %"PRIu64"\n\n\n",
		le64_to_cpu(plpns_log->dtwin_testimate));
}

void json_predictable_latency_event_agg_log(
	struct nvme_event_agg_log_page *pea_log,
	__u64 log_entries)
{
	struct json_object *root;
	struct json_object *valid_attrs;
	struct json_object *valid;
	__u64 num_iter;
	__u64 num_entries;

	root = json_create_object();
	num_entries = le64_to_cpu(pea_log->num_entries);
	json_object_add_value_uint(root, "num_entries_avail",
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

void nvme_show_predictable_latency_event_agg_log(
	struct nvme_event_agg_log_page *pea_log,
	__u64 log_entries, __u32 size, const char *devname,
	enum nvme_print_flags flags)
{
	__u64 num_iter;
	__u64 num_entries;

	if (flags & BINARY)
		return d_raw((unsigned char *)pea_log, size);
	if (flags & JSON)
		return json_predictable_latency_event_agg_log(pea_log,
			log_entries);

	num_entries = le64_to_cpu(pea_log->num_entries);
	printf("Predictable Latency Event Aggregate Log for"\
		" device: %s\n", devname);

	printf("Number of Entries Available: %"PRIu64"\n",
		(uint64_t)num_entries);

	num_iter = min(num_entries, log_entries);
	for (int i = 0; i < num_iter; i++) {
		printf("Entry[%d]: %u\n", i + 1,
			le16_to_cpu(pea_log->entries[i]));
	}
}

static const char *nvme_show_nss_hw_error(__u16 error_code)
{
	switch (error_code) {
	case 0x01:
		return "PCIe Correctable Error";
	case 0x02:
		return "PCIe Uncorrectable Non fatal Error";
	case 0x03:
		return "PCIe Uncorrectable Fatal Error";
	case 0x04:
		return "PCIe Link Status Change";
	case 0x05:
		return "PCIe Link Not Active";
	case 0x06:
		return "Critical Warning Condition";
	case 0x07:
		return "Endurance Group Critical Warning Condition";
	case 0x08:
		return "Unsafe Shutdown";
	case 0x09:
		return "Controller Fatal Status";
	case 0xA:
		return "Media and Data Integrity Status";
	default:
		return "Reserved";
	}
}

void json_persistent_event_log(void *pevent_log_info, __u32 size)
{
	struct json_object *root;
	struct json_object *valid_attrs;
	struct json_object *valid;
	__u32 offset, por_info_len, por_info_list;
	__u64 *fw_rev;
	char key[128];
	struct nvme_smart_log *smart_event;
	struct nvme_fw_commit_event *fw_commit_event;
	struct nvme_time_stamp_change_event *ts_change_event;
	struct nvme_power_on_reset_info_list *por_event;
	struct nvme_nss_hw_err_event *nss_hw_err_event;
	struct nvme_change_ns_event	*ns_event;
	struct nvme_format_nvm_start_event *format_start_event;
	struct nvme_format_nvm_compln_event *format_cmpln_event;
	struct nvme_sanitize_start_event *sanitize_start_event;
	struct nvme_sanitize_compln_event *sanitize_cmpln_event;
	struct nvme_thermal_exc_event *thermal_exc_event;
	struct nvme_persistent_event_log_head *pevent_log_head;
	struct nvme_persistent_event_entry_head *pevent_entry_head;

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
			pevent_log_head->log_id);
		json_object_add_value_uint(root, "total_num_of_events",
			le32_to_cpu(pevent_log_head->tnev));
		json_object_add_value_uint(root, "total_log_len",
			le64_to_cpu(pevent_log_head->tll));
		json_object_add_value_uint(root, "log_revision",
			pevent_log_head->log_rev);
		json_object_add_value_uint(root, "log_header_len",
			le16_to_cpu(pevent_log_head->head_len));
		json_object_add_value_uint(root, "timestamp",
			le64_to_cpu(pevent_log_head->timestamp));
		json_object_add_value_float(root, "power_on_hours",
			int128_to_double(pevent_log_head->poh));
		json_object_add_value_uint(root, "power_cycle_count",
			le64_to_cpu(pevent_log_head->pcc));
		json_object_add_value_uint(root, "pci_vid",
			le16_to_cpu(pevent_log_head->vid));
		json_object_add_value_uint(root, "pci_ssvid",
			le16_to_cpu(pevent_log_head->ssvid));
		json_object_add_value_string(root, "sn", sn);
		json_object_add_value_string(root, "mn", mn);
		json_object_add_value_string(root, "subnqn", subnqn);
		for (int i = 0; i < 32; i++) {
			if (pevent_log_head->supp_event_bm[i] == 0)
				continue;
			sprintf(key, "bitmap_%d", i);
			json_object_add_value_uint(root, key,
				pevent_log_head->supp_event_bm[i]);
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

		json_object_add_value_uint(valid_attrs, "event_type",
			pevent_entry_head->etype);
		json_object_add_value_uint(valid_attrs, "event_type_rev",
			pevent_entry_head->etype_rev);
		json_object_add_value_uint(valid_attrs, "event_header_len",
			pevent_entry_head->ehl);
		json_object_add_value_uint(valid_attrs, "ctrl_id",
			le16_to_cpu(pevent_entry_head->ctrl_id));
		json_object_add_value_uint(valid_attrs, "event_time_stamp",
			le64_to_cpu(pevent_entry_head->etimestamp));
		json_object_add_value_uint(valid_attrs, "vu_info_len",
			le16_to_cpu(pevent_entry_head->vsil));
		json_object_add_value_uint(valid_attrs, "event_len",
			le16_to_cpu(pevent_entry_head->el));

		offset += pevent_entry_head->ehl + 3;

		switch (pevent_entry_head->etype) {
		case NVME_SMART_HEALTH_EVENT:
			smart_event = pevent_log_info + offset;
			unsigned int temperature = ((smart_event->temperature[1] << 8) |
				smart_event->temperature[0]);

			long double data_units_read = int128_to_double(smart_event->data_units_read);
			long double data_units_written = int128_to_double(smart_event->data_units_written);
			long double host_read_commands = int128_to_double(smart_event->host_reads);
			long double host_write_commands = int128_to_double(smart_event->host_writes);
			long double controller_busy_time = int128_to_double(smart_event->ctrl_busy_time);
			long double power_cycles = int128_to_double(smart_event->power_cycles);
			long double power_on_hours = int128_to_double(smart_event->power_on_hours);
			long double unsafe_shutdowns = int128_to_double(smart_event->unsafe_shutdowns);
			long double media_errors = int128_to_double(smart_event->media_errors);
			long double num_err_log_entries = int128_to_double(smart_event->num_err_log_entries);
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
			json_object_add_value_float(valid_attrs, "data_units_read",
				data_units_read);
			json_object_add_value_float(valid_attrs, "data_units_written",
				data_units_written);
			json_object_add_value_float(valid_attrs, "host_read_commands",
				host_read_commands);
			json_object_add_value_float(valid_attrs, "host_write_commands",
				host_write_commands);
			json_object_add_value_float(valid_attrs, "controller_busy_time",
				controller_busy_time);
			json_object_add_value_float(valid_attrs, "power_cycles",
				power_cycles);
			json_object_add_value_float(valid_attrs, "power_on_hours",
				power_on_hours);
			json_object_add_value_float(valid_attrs, "unsafe_shutdowns",
				unsafe_shutdowns);
			json_object_add_value_float(valid_attrs, "media_errors",
				media_errors);
			json_object_add_value_float(valid_attrs, "num_err_log_entries",
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
		case NVME_FW_COMMIT_EVENT:
			fw_commit_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "old_fw_rev",
				le64_to_cpu(fw_commit_event->old_fw_rev));
			json_object_add_value_uint(valid_attrs, "new_fw_rev",
				le64_to_cpu(fw_commit_event->new_fw_rev));
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
		case NVME_TIMESTAMP_EVENT:
			ts_change_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "prev_ts",
				le64_to_cpu(ts_change_event->previous_timestamp));
			json_object_add_value_uint(valid_attrs,
				"ml_secs_since_reset",
				le64_to_cpu(ts_change_event->ml_secs_since_reset));
			break;
		case NVME_POWER_ON_RESET_EVENT:
			por_info_len = (le16_to_cpu(pevent_entry_head->el) -
				le16_to_cpu(pevent_entry_head->vsil) - sizeof(*fw_rev));

			por_info_list = por_info_len / sizeof(*por_event);

			fw_rev = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "fw_rev",
				le64_to_cpu(*fw_rev));
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
				json_object_add_value_uint(valid_attrs, "power_on_ml_secs",
					le64_to_cpu(por_event->power_on_ml_seconds));
				json_object_add_value_uint(valid_attrs, "ctrl_time_stamp",
					le64_to_cpu(por_event->ctrl_time_stamp));
			}
			break;
		case NVME_NSS_HW_ERROR_EVENT:
			nss_hw_err_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "nss_hw_err_code",
				le16_to_cpu(nss_hw_err_event->nss_hw_err_event_code));
			break;
		case NVME_CHANGE_NS_EVENT:
			ns_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "nsmgt_cdw10",
				le32_to_cpu(ns_event->nsmgt_cdw10));
			json_object_add_value_uint(valid_attrs, "nsze",
				le64_to_cpu(ns_event->nsze));
			json_object_add_value_uint(valid_attrs, "nscap",
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
		case NVME_FORMAT_START_EVENT:
			format_start_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "nsid",
				le32_to_cpu(format_start_event->nsid));
			json_object_add_value_uint(valid_attrs, "fna",
				format_start_event->fna);
			json_object_add_value_uint(valid_attrs, "format_nvm_cdw10",
				le32_to_cpu(format_start_event->format_nvm_cdw10));
			break;
		case NVME_FORMAT_COMPLETION_EVENT:
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
		case NVME_SANITIZE_START_EVENT:
			sanitize_start_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "SANICAP",
				le32_to_cpu(sanitize_start_event->sani_cap));
			json_object_add_value_uint(valid_attrs, "sani_cdw10",
				le32_to_cpu(sanitize_start_event->sani_cdw10));
			json_object_add_value_uint(valid_attrs, "sani_cdw11",
				le32_to_cpu(sanitize_start_event->sani_cdw11));
			break;
		case NVME_SANITIZE_COMPLETION_EVENT:
			sanitize_cmpln_event = pevent_log_info + offset;
			json_object_add_value_uint(valid_attrs, "sani_prog",
				le16_to_cpu(sanitize_cmpln_event->sani_prog));
			json_object_add_value_uint(valid_attrs, "sani_status",
				le16_to_cpu(sanitize_cmpln_event->sani_status));
			json_object_add_value_uint(valid_attrs, "cmpln_info",
				le16_to_cpu(sanitize_cmpln_event->cmpln_info));
			break;
		case NVME_THERMAL_EXCURSION_EVENT:
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

void nvme_show_persistent_event_log(void *pevent_log_info,
	__u8 action, __u32 size, const char *devname,
	enum nvme_print_flags flags)
{
	__u32 offset, por_info_len, por_info_list;
	__u64 *fw_rev;
	struct nvme_smart_log *smart_event;
	struct nvme_fw_commit_event *fw_commit_event;
	struct nvme_time_stamp_change_event *ts_change_event;
	struct nvme_power_on_reset_info_list *por_event;
	struct nvme_nss_hw_err_event *nss_hw_err_event;
	struct nvme_change_ns_event	*ns_event;
	struct nvme_format_nvm_start_event *format_start_event;
	struct nvme_format_nvm_compln_event *format_cmpln_event;
	struct nvme_sanitize_start_event *sanitize_start_event;
	struct nvme_sanitize_compln_event *sanitize_cmpln_event;
	struct nvme_thermal_exc_event *thermal_exc_event;
	struct nvme_persistent_event_log_head *pevent_log_head;
	struct nvme_persistent_event_entry_head *pevent_entry_head;

	if (flags & BINARY)
		return d_raw((unsigned char *)pevent_log_info, size);
	if (flags & JSON)
		return json_persistent_event_log(pevent_log_info, size);

	offset = sizeof(*pevent_log_head);

	printf("Persistent Event Log for device: %s\n", devname);
	printf("Action for Persistent Event Log: %u\n", action);
	if (size >= offset) {
		pevent_log_head = pevent_log_info;
		printf("Log Identifier: %u\n", pevent_log_head->log_id);
		printf("Total Number of Events: %u\n",
			le32_to_cpu(pevent_log_head->tnev));
		printf("Total Log Length : %"PRIu64"\n",
			le64_to_cpu(pevent_log_head->tll));
		printf("Log Revision: %u\n", pevent_log_head->log_rev);
		printf("Log Header Length: %u\n", pevent_log_head->head_len);
		printf("Timestamp: %"PRIu64"\n",
			le64_to_cpu(pevent_log_head->timestamp));
		printf("Power On Hours (POH): %'.0Lf\n",
			int128_to_double(pevent_log_head->poh));
		printf("Power Cycle Count: %"PRIu64"\n",
			le64_to_cpu(pevent_log_head->pcc));
		printf("PCI Vendor ID (VID): %u\n",
			le16_to_cpu(pevent_log_head->vid));
		printf("PCI Subsystem Vendor ID (SSVID): %u\n",
			le16_to_cpu(pevent_log_head->ssvid));
		printf("Serial Number (SN): %-.*s\n",
			(int)sizeof(pevent_log_head->sn), pevent_log_head->sn);
		printf("Model Number (MN): %-.*s\n",
			(int)sizeof(pevent_log_head->mn), pevent_log_head->mn);
		printf("NVM Subsystem NVMe Qualified Name (SUBNQN): %-.*s\n",
			(int)sizeof(pevent_log_head->subnqn),
			pevent_log_head->subnqn);
		printf("Supported Events Bitmap: ");
		for (int i = 0; i < 32; i++) {
			if (pevent_log_head->supp_event_bm[i] == 0)
				continue;
			printf("BitMap[%d] is 0x%x\n", i,
				pevent_log_head->supp_event_bm[i]);
		}
	} else {
		printf("No log data can be shown with this log len at least " \
			"512 bytes is required or can be 0 to read the complete "\
			"log page after context established\n");
		return;
	}
	printf("\n");
	printf("\nPersistent Event Entries:\n");
	for (int i = 0; i < le32_to_cpu(pevent_log_head->tnev); i++) {
		if (offset + sizeof(*pevent_entry_head) >= size)
			break;

		pevent_entry_head = pevent_log_info + offset;

		if ((offset + pevent_entry_head->ehl + 3 +
			le16_to_cpu(pevent_entry_head->el)) >= size)
			break;

		printf("Event Type: %u\n", pevent_entry_head->etype);
		printf("Event Type Revision: %u\n", pevent_entry_head->etype_rev);
		printf("Event Header Length: %u\n", pevent_entry_head->ehl);
		printf("Controller Identifier: %u\n",
			le16_to_cpu(pevent_entry_head->ctrl_id));
		printf("Event Timestamp: %"PRIu64"\n",
			le64_to_cpu(pevent_entry_head->etimestamp));
		printf("Vendor Specific Information Length: %u\n",
			le16_to_cpu(pevent_entry_head->vsil));
		printf("Event Length: %u\n", le16_to_cpu(pevent_entry_head->el));

		offset += pevent_entry_head->ehl + 3;

		switch (pevent_entry_head->etype) {
		case NVME_SMART_HEALTH_EVENT:
			smart_event = pevent_log_info + offset;
			printf("Smart Health Event: \n");
			nvme_show_smart_log(smart_event, NVME_NSID_ALL, devname, flags);
			break;
		case NVME_FW_COMMIT_EVENT:
			fw_commit_event = pevent_log_info + offset;
			printf("FW Commit Event: \n");
			printf("Old Firmware Revision: %"PRIu64"\n",
				le64_to_cpu(fw_commit_event->old_fw_rev));
			printf("New Firmware Revision: %"PRIu64"\n",
				le64_to_cpu(fw_commit_event->new_fw_rev));
			printf("FW Commit Action: %u\n",
				fw_commit_event->fw_commit_action);
			printf("FW Slot: %u\n", fw_commit_event->fw_slot);
			printf("Status Code Type for Firmware Commit Command: %u\n",
				fw_commit_event->sct_fw);
			printf("Status Returned for Firmware Commit Command: %u\n",
				fw_commit_event->sc_fw);
			printf("Vendor Assigned Firmware Commit Result Code: %u\n",
				le16_to_cpu(fw_commit_event->vndr_assign_fw_commit_rc));
			break;
		case NVME_TIMESTAMP_EVENT:
			ts_change_event = pevent_log_info + offset;
			printf("Time Stamp Change Event: \n");
			printf("Previous Timestamp: %"PRIu64"\n",
				le64_to_cpu(ts_change_event->previous_timestamp));
			printf("Milliseconds Since Reset: %"PRIu64"\n",
				le64_to_cpu(ts_change_event->ml_secs_since_reset));
			break;
		case NVME_POWER_ON_RESET_EVENT:
			por_info_len = (le16_to_cpu(pevent_entry_head->el) -
				le16_to_cpu(pevent_entry_head->vsil) - sizeof(*fw_rev));

			por_info_list = por_info_len / sizeof(*por_event);

			printf("Power On Reset Event: \n");
			fw_rev = pevent_log_info + offset;
			printf("Firmware Revision: %"PRIu64"\n", le64_to_cpu(*fw_rev));
			printf("Reset Information List: \n");

			for (int i = 0; i < por_info_list; i++) {
				por_event = pevent_log_info + offset +
					sizeof(*fw_rev) + i * sizeof(*por_event);
				printf("Controller ID: %u\n", le16_to_cpu(por_event->cid));
				printf("Firmware Activation: %u\n",
					por_event->fw_act);
				printf("Operation in Progress: %u\n",
					por_event->op_in_prog);
				printf("Controller Power Cycle: %u\n",
					le32_to_cpu(por_event->ctrl_power_cycle));
				printf("Power on milliseconds: %"PRIu64"\n",
					le64_to_cpu(por_event->power_on_ml_seconds));
				printf("Controller Timestamp: %"PRIu64"\n",
					le64_to_cpu(por_event->ctrl_time_stamp));
			}
			break;
		case NVME_NSS_HW_ERROR_EVENT:
			nss_hw_err_event = pevent_log_info + offset;
			printf("NVM Subsystem Hardware Error Event Code: %u, %s\n",
				le16_to_cpu(nss_hw_err_event->nss_hw_err_event_code),
				nvme_show_nss_hw_error(nss_hw_err_event->nss_hw_err_event_code));
			break;
		case NVME_CHANGE_NS_EVENT:
			ns_event = pevent_log_info + offset;
			printf("Change Namespace Event: \n");
			printf("Namespace Management CDW10: %u\n",
				le32_to_cpu(ns_event->nsmgt_cdw10));
			printf("Namespace Size: %"PRIu64"\n",
				le64_to_cpu(ns_event->nsze));
			printf("Namespace Capacity: %"PRIu64"\n",
				le64_to_cpu(ns_event->nscap));
			printf("Formatted LBA Size: %u\n", ns_event->flbas);
			printf("End-to-end Data Protection Type Settings: %u\n",
				ns_event->dps);
			printf("Namespace Multi-path I/O and Namespace Sharing" \
				" Capabilities: %u\n", ns_event->nmic);
			printf("ANA Group Identifier: %u\n",
				le32_to_cpu(ns_event->ana_grp_id));
			printf("NVM Set Identifier: %u\n", le16_to_cpu(ns_event->nvmset_id));
			printf("Namespace ID: %u\n", le32_to_cpu(ns_event->nsid));
			break;
		case NVME_FORMAT_START_EVENT:
			format_start_event = pevent_log_info + offset;
			printf("Format NVM Start Event: \n");
			printf("Namespace Identifier: %u\n",
				le32_to_cpu(format_start_event->nsid));
			printf("Format NVM Attributes: %u\n",
				format_start_event->fna);
			printf("Format NVM CDW10: %u\n",
				le32_to_cpu(format_start_event->format_nvm_cdw10));
			break;
		case NVME_FORMAT_COMPLETION_EVENT:
			format_cmpln_event = pevent_log_info + offset;
			printf("Format NVM Completion Event: \n");
			printf("Namespace Identifier: %u\n",
				le32_to_cpu(format_cmpln_event->nsid));
			printf("Smallest Format Progress Indicator: %u\n",
				format_cmpln_event->smallest_fpi);
			printf("Format NVM Status: %u\n",
				format_cmpln_event->format_nvm_status);
			printf("Completion Information: %u\n",
				le16_to_cpu(format_cmpln_event->compln_info));
			printf("Status Field: %u\n",
				le32_to_cpu(format_cmpln_event->status_field));
			break;
		case NVME_SANITIZE_START_EVENT:
			sanitize_start_event = pevent_log_info + offset;
			printf("Sanitize Start Event: \n");
			printf("SANICAP: %u\n", sanitize_start_event->sani_cap);
			printf("Sanitize CDW10: %u\n",
				le32_to_cpu(sanitize_start_event->sani_cdw10));
			printf("Sanitize CDW11: %u\n",
				le32_to_cpu(sanitize_start_event->sani_cdw11));
			break;
		case NVME_SANITIZE_COMPLETION_EVENT:
			sanitize_cmpln_event = pevent_log_info + offset;
			printf("Sanitize Completion Event: \n");
			printf("Sanitize Progress: %u\n",
				le16_to_cpu(sanitize_cmpln_event->sani_prog));
			printf("Sanitize Status: %u\n",
				le16_to_cpu(sanitize_cmpln_event->sani_status));
			printf("Completion Information: %u\n",
				le16_to_cpu(sanitize_cmpln_event->cmpln_info));
			break;
		case NVME_THERMAL_EXCURSION_EVENT:
			thermal_exc_event = pevent_log_info + offset;
			printf("Thermal Excursion Event: \n");
			printf("Over Temperature: %u\n", thermal_exc_event->over_temp);
			printf("Threshold: %u\n", thermal_exc_event->threshold);
			break;
		default:
			printf("Reserved Event\n\n");
		}
		offset += le16_to_cpu(pevent_entry_head->el);
		printf("\n");
	}
}

void json_endurance_group_event_agg_log(
	struct nvme_event_agg_log_page *endurance_log,
	__u64 log_entries)
{
	struct json_object *root;
	struct json_object *valid_attrs;
	struct json_object *valid;

	root = json_create_object();
	json_object_add_value_uint(root, "num_entries_avail",
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

void nvme_show_endurance_group_event_agg_log(
	struct nvme_event_agg_log_page *endurance_log,
	__u64 log_entries, __u32 size, const char *devname,
	enum nvme_print_flags flags)
{

	if (flags & BINARY)
		return d_raw((unsigned char *)endurance_log, size);
	if (flags & JSON)
		return json_endurance_group_event_agg_log(endurance_log,
			log_entries);

	printf("Endurance Group Event Aggregate Log for"\
		" device: %s\n", devname);

	printf("Number of Entries Available: %"PRIu64"\n",
		le64_to_cpu(endurance_log->num_entries));

	for (int i = 0; i < log_entries; i++) {
		printf("Entry[%d]: %u\n", i + 1,
			le16_to_cpu(endurance_log->entries[i]));
	}
}

void json_lba_status_log(void *lba_status)
{
	struct json_object *root;
	struct json_object *desc;
	struct json_object *element;
	struct json_object *desc_list;
	struct json_object *elements_list;
	struct nvme_lba_status_hdr *hdr;
	struct nvme_lba_status_ns_element *ns_element;
	struct nvme_lba_status_range_desc *range_desc;
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
				json_object_add_value_uint(desc, "rslba",
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

void nvme_show_lba_status_log(void *lba_status, __u32 size,
	const char *devname, enum nvme_print_flags flags)
{
	struct nvme_lba_status_hdr *hdr;
	struct nvme_lba_status_ns_element *ns_element;
	struct nvme_lba_status_range_desc *range_desc;
	int offset = sizeof(*hdr);
	__u32 num_lba_desc, num_elements;

	if (flags & BINARY)
		return d_raw((unsigned char *)lba_status, size);
	if (flags & JSON)
		return json_lba_status_log(lba_status);

	hdr = lba_status;
	printf("LBA Status Log for device: %s\n", devname);
	printf("LBA Status Log Page Length: %"PRIu32"\n",
		le32_to_cpu(hdr->lslplen));
	num_elements = le32_to_cpu(hdr->nlslne);
	printf("Number of LBA Status Log Namespace Elements: %"PRIu32"\n",
		num_elements);
	printf("Estimate of Unrecoverable Logical Blocks: %"PRIu32"\n",
		le32_to_cpu(hdr->estulb));
	printf("LBA Status Generation Counter: %"PRIu16"\n", le16_to_cpu(hdr->lsgc));
	for (int ele = 0; ele < num_elements; ele++) {
		ns_element = lba_status + offset;
		printf("Namespace Element Identifier: %"PRIu32"\n",
			le32_to_cpu(ns_element->neid));
		num_lba_desc = le32_to_cpu(ns_element->nlrd);
		printf("Number of LBA Range Descriptors: %"PRIu32"\n", num_lba_desc);
		printf("Recommended Action Type: %u\n", ns_element->ratype);

		offset += sizeof(*ns_element);
		if (num_lba_desc != 0xffffffff) {
			for (int i = 0; i < num_lba_desc; i++) {
				range_desc = lba_status + offset;
				printf("RSLBA[%d]: %"PRIu64"\n", i,
					le64_to_cpu(range_desc->rslba));
				printf("RNLB[%d]: %"PRIu32"\n", i,
					le32_to_cpu(range_desc->rnlb));
				offset += sizeof(*range_desc);
			}
		} else {
			printf("Number of LBA Range Descriptors (NLRD) set to %#x for "\
				"NS element %d\n", num_lba_desc, ele);
		}
	}
}

static const char *resv_notif_to_string(__u8 type)
{
	switch (type) {
	case 0x1: return "Empty Log Page";
	case 0x2: return "Registration Preempted";
	case 0x3: return "Reservation Released";
	case 0x4: return "Reservation Preempted";
	default:  return "Reserved";
	}
}

static void json_resv_notif_log(struct nvme_resv_notif_log *resv)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_uint(root, "count",
		le64_to_cpu(resv->log_page_count));
	json_object_add_value_uint(root, "rn_log_type",
		resv->resv_notif_log_type);
	json_object_add_value_uint(root, "num_logs",
		resv->num_logs);
	json_object_add_value_uint(root, "nsid",
		le32_to_cpu(resv->nsid));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void nvme_show_resv_notif_log(struct nvme_resv_notif_log *resv,
	const char *devname, enum nvme_print_flags flags)
{
	if (flags & BINARY)
		return d_raw((unsigned char *)resv, sizeof(*resv));
	if (flags & JSON)
		return json_resv_notif_log(resv);

	printf("Reservation Notif Log for device: %s\n", devname);
	printf("Log Page Count				: %"PRIx64"\n",
		le64_to_cpu(resv->log_page_count));
	printf("Resv Notif Log Page Type	: %u (%s)\n",
		resv->resv_notif_log_type,
		resv_notif_to_string(resv->resv_notif_log_type));
	printf("Num of Available Log Pages	: %u\n", resv->num_logs);
	printf("Namespace ID:				: %"PRIx32"\n",
		le32_to_cpu(resv->nsid));
}

static void nvme_show_subsystem(struct nvme_subsystem *s)
{
	int i;

	printf("%s - NQN=%s\n", s->name, s->subsysnqn);
	printf("\\\n");

	for (i = 0; i < s->nr_ctrls; i++) {
		printf(" +- %s %s %s %s %s\n", s->ctrls[i].name,
				s->ctrls[i].transport ? : "",
				s->ctrls[i].address ? : "",
				s->ctrls[i].state ? : "",
				s->ctrls[i].ana_state ? : "");
	}
}

static void json_print_nvme_subsystem_list(struct nvme_topology *t)
{
	struct json_object *subsystem_attrs, *path_attrs;
	struct json_object *subsystems, *paths;
	struct json_object *root;
	int i, j;

	root = json_create_object();
	subsystems = json_create_array();

	for (i = 0; i < t->nr_subsystems; i++) {
		struct nvme_subsystem *s = &t->subsystems[i];

		subsystem_attrs = json_create_object();
		json_object_add_value_string(subsystem_attrs,
					     "Name", s->name);
		json_object_add_value_string(subsystem_attrs,
					     "NQN", s->subsysnqn);

		json_array_add_value_object(subsystems, subsystem_attrs);

		paths = json_create_array();
		for (j = 0; j < s->nr_ctrls; j++) {
			struct nvme_ctrl *c = &s->ctrls[j];

			path_attrs = json_create_object();
			json_object_add_value_string(path_attrs, "Name",
					c->name);
			if (c->transport)
				json_object_add_value_string(path_attrs,
						"Transport", c->transport);
			if (c->address)
				json_object_add_value_string(path_attrs,
						"Address", c->address);
			if (c->state)
				json_object_add_value_string(path_attrs,
						"State", c->state);
			if (c->ana_state)
				json_object_add_value_string(path_attrs,
						"ANAState", c->ana_state);
			json_array_add_value_object(paths, path_attrs);
		}
		if (j)
			json_object_add_value_array(subsystem_attrs, "Paths",
				paths);
	}

	if (i)
		json_object_add_value_array(root, "Subsystems", subsystems);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void nvme_show_subsystem_list(struct nvme_topology *t,
			      enum nvme_print_flags flags)
{
	int i;

	if (flags & JSON)
		return json_print_nvme_subsystem_list(t);

	for (i = 0; i < t->nr_subsystems; i++)
		nvme_show_subsystem(&t->subsystems[i]);
}

static void nvme_show_registers_cap(struct nvme_bar_cap *cap)
{
	printf("\tController Memory Buffer Supported (CMBS): The Controller Memory Buffer is %s\n",
		((cap->rsvd_cmbs_pmrs & 0x02) >> 1) ? "Supported" :
			"Not Supported");
	printf("\tPersistent Memory Region Supported (PMRS): The Persistent Memory Region is %s\n",
		(cap->rsvd_cmbs_pmrs & 0x01) ? "Supported" : "Not Supported");
	printf("\tMemory Page Size Maximum         (MPSMAX): %u bytes\n",
		1 <<  (12 + ((cap->mpsmax_mpsmin & 0xf0) >> 4)));
	printf("\tMemory Page Size Minimum         (MPSMIN): %u bytes\n",
		1 <<  (12 + (cap->mpsmax_mpsmin & 0x0f)));
	printf("\tBoot Partition Support              (BPS): %s\n",
		(cap->bps_css_nssrs_dstrd & 0x2000) ? "Yes":"No");
	printf("\tCommand Sets Supported              (CSS): NVM command set is %s\n",
		(cap->bps_css_nssrs_dstrd & 0x0020) ? "Supported" : "Not Supported");
	printf("\t                                           One or more I/O Command Sets are %s\n",
		(cap->bps_css_nssrs_dstrd & 0x0800) ? "Supported" : "Not Supported");
	printf("\tNVM Subsystem Reset Supported     (NSSRS): %s\n",
		(cap->bps_css_nssrs_dstrd & 0x0010) ? "Yes":"No");
	printf("\tDoorbell Stride                   (DSTRD): %u bytes\n",
		1 << (2 + (cap->bps_css_nssrs_dstrd & 0x000f)));
	printf("\tTimeout                              (TO): %u ms\n",
		cap->to * 500);
	printf("\tArbitration Mechanism Supported     (AMS): Weighted Round Robin with Urgent Priority Class is %s\n",
		(cap->ams_cqr & 0x02) ? "supported":"not supported");
	printf("\tContiguous Queues Required          (CQR): %s\n",
		(cap->ams_cqr & 0x01) ? "Yes":"No");
	printf("\tMaximum Queue Entries Supported    (MQES): %u\n\n",
		cap->mqes + 1);
}

static void nvme_show_registers_version(__u32 vs)
{
	printf("\tNVMe specification %d.%d\n\n", (vs & 0xffff0000) >> 16,
		(vs & 0x0000ff00) >> 8);
}

static void nvme_show_registers_cc_ams (__u8 ams)
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

static void nvme_show_registers_cc_shn (__u8 shn)
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

static void nvme_show_registers_cc(__u32 cc)
{
	printf("\tI/O Completion Queue Entry Size (IOCQES): %u bytes\n",
		1 << ((cc & 0x00f00000) >> NVME_CC_IOCQES_SHIFT));
	printf("\tI/O Submission Queue Entry Size (IOSQES): %u bytes\n",
		1 << ((cc & 0x000f0000) >> NVME_CC_IOSQES_SHIFT));
	nvme_show_registers_cc_shn((cc & 0x0000c000) >> NVME_CC_SHN_SHIFT);
	nvme_show_registers_cc_ams((cc & 0x00003800) >> NVME_CC_AMS_SHIFT);
	printf("\tMemory Page Size                   (MPS): %u bytes\n",
		1 << (12 + ((cc & 0x00000780) >> NVME_CC_MPS_SHIFT)));
	printf("\tI/O Command Set Selected           (CSS): %s\n",
		(cc & 0x00000070) == 0x00 ? "NVM Command Set" :
		(cc & 0x00000070) == 0x60 ? "All supported I/O Command Sets" :
		(cc & 0x00000070) == 0x70 ? "Admin Command Set only" : "Reserved");
	printf("\tEnable                              (EN): %s\n\n",
		(cc & 0x00000001) ? "Yes":"No");
}

static void nvme_show_registers_csts_shst(__u8 shst)
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

static void nvme_show_registers_csts(__u32 csts)
{
	printf("\tProcessing Paused               (PP): %s\n",
		(csts & 0x00000020) ? "Yes":"No");
	printf("\tNVM Subsystem Reset Occurred (NSSRO): %s\n",
		(csts & 0x00000010) ? "Yes":"No");
	nvme_show_registers_csts_shst((csts & 0x0000000c) >> 2);
	printf("\tController Fatal Status        (CFS): %s\n",
		(csts & 0x00000002) ? "True":"False");
	printf("\tReady                          (RDY): %s\n\n",
		(csts & 0x00000001) ? "Yes":"No");

}

static void nvme_show_registers_aqa(__u32 aqa)
{
	printf("\tAdmin Completion Queue Size (ACQS): %u\n",
		((aqa & 0x0fff0000) >> 16) + 1);
	printf("\tAdmin Submission Queue Size (ASQS): %u\n\n",
		(aqa & 0x00000fff) + 1);

}

static void nvme_show_registers_cmbloc(__u32 cmbloc, __u32 cmbsz)
{
	static const char *enforced[] = { "Enforced", "Not Enforced" };

	if (cmbsz == 0) {
		printf("\tController Memory Buffer feature is not supported\n\n");
		return;
	}
	printf("\tOffset                                                        (OFST): 0x%x (See cmbsz.szu for granularity)\n",
			(cmbloc & 0xfffff000) >> 12);

	printf("\tCMB Queue Dword Alignment                                     (CQDA): %d\n",
			(cmbloc & 0x00000100) >> 8);

	printf("\tCMB Data Metadata Mixed Memory Support                      (CDMMMS): %s\n",
			enforced[(cmbloc & 0x00000080) >> 7]);

	printf("\tCMB Data Pointer and Command Independent Locations Support (CDPCILS): %s\n",
			enforced[(cmbloc & 0x00000040) >> 6]);

	printf("\tCMB Data Pointer Mixed Locations Support                    (CDPMLS): %s\n",
			enforced[(cmbloc & 0x00000020) >> 5]);

	printf("\tCMB Queue Physically Discontiguous Support                   (CQPDS): %s\n",
			enforced[(cmbloc & 0x00000010) >> 4]);

	printf("\tCMB Queue Mixed Memory Support                               (CQMMS): %s\n",
			enforced[(cmbloc & 0x00000008) >> 3]);

	printf("\tBase Indicator Register                                        (BIR): 0x%x\n\n",
			(cmbloc & 0x00000007));
}

static const char *nvme_register_szu_to_string(__u8 szu)
{
	switch (szu) {
	case 0:	return "4 KB";
	case 1:	return "64 KB";
	case 2:	return "1 MB";
	case 3:	return "16 MB";
	case 4:	return "256 MB";
	case 5:	return "4 GB";
	case 6:	return "64 GB";
	default:return "Reserved";
	}
}

static void nvme_show_registers_cmbsz(__u32 cmbsz)
{
	if (cmbsz == 0) {
		printf("\tController Memory Buffer feature is not supported\n\n");
		return;
	}
	printf("\tSize                      (SZ): %u\n",
		(cmbsz & 0xfffff000) >> 12);
	printf("\tSize Units               (SZU): %s\n",
		nvme_register_szu_to_string((cmbsz & 0x00000f00) >> 8));
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

static void nvme_show_registers_bpinfo_brs(__u8 brs)
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

static void nvme_show_registers_bpinfo(__u32 bpinfo)
{
	if (bpinfo == 0) {
		printf("\tBoot Partition feature is not supported\n\n");
		return;
	}

	printf("\tActive Boot Partition ID      (ABPID): %u\n",
		(bpinfo & 0x80000000) >> 31);
	nvme_show_registers_bpinfo_brs((bpinfo & 0x03000000) >> 24);
	printf("\tBoot Partition Size            (BPSZ): %u\n",
		bpinfo & 0x00007fff);
}

static void nvme_show_registers_bprsel(__u32 bprsel)
{
	if (bprsel == 0) {
		printf("\tBoot Partition feature is not supported\n\n");
		return;
	}

	printf("\tBoot Partition Identifier      (BPID): %u\n",
		(bprsel & 0x80000000) >> 31);
	printf("\tBoot Partition Read Offset    (BPROF): %x\n",
		(bprsel & 0x3ffffc00) >> 10);
	printf("\tBoot Partition Read Size      (BPRSZ): %x\n",
		bprsel & 0x000003ff);
}

static void nvme_show_registers_bpmbl(uint64_t bpmbl)
{
	if (bpmbl == 0) {
		printf("\tBoot Partition feature is not supported\n\n");
		return;
	}

	printf("\tBoot Partition Memory Buffer Base Address (BMBBA): %"PRIx64"\n",
		bpmbl);
}

static void nvme_show_registers_cmbmsc(uint64_t cmbmsc)
{
	printf("\tController Base Address         (CBA): %" PRIx64 "\n",
			(cmbmsc & 0xfffffffffffff000) >> 12);
	printf("\tController Memory Space Enable (CMSE): %" PRIx64 "\n",
			(cmbmsc & 0x0000000000000002) >> 1);
	printf("\tCapabilities Registers Enabled  (CRE): CMBLOC and "\
	       "CMBSZ registers are%senabled\n\n",
		(cmbmsc & 0x0000000000000001) ? " " : " NOT ");
}

static void nvme_show_registers_cmbsts(__u32 cmbsts)
{
	printf("\tController Base Address Invalid (CBAI): %x\n\n",
		(cmbsts & 0x00000001));
}

static void nvme_show_registers_pmrcap(__u32 pmrcap)
{
	printf("\tController Memory Space Supported                   (CMSS): "\
	       "Referencing PMR with host supplied addresses is %s\n",
	       ((pmrcap & 0x01000000) >> 24) ? "Supported" : "Not Supported");
	printf("\tPersistent Memory Region Timeout                   (PMRTO): %x\n",
		(pmrcap & 0x00ff0000) >> 16);
	printf("\tPersistent Memory Region Write Barrier Mechanisms (PMRWBM): %x\n",
		(pmrcap & 0x00003c00) >> 10);
	printf("\tPersistent Memory Region Time Units                (PMRTU): PMR time unit is %s\n",
		(pmrcap & 0x00000300) >> 8 ? "minutes":"500 milliseconds");
	printf("\tBase Indicator Register                              (BIR): %x\n",
		(pmrcap & 0x000000e0) >> 5);
	printf("\tWrite Data Support                                   (WDS): Write data to the PMR is %s\n",
		(pmrcap & 0x00000010) ? "supported":"not supported");
	printf("\tRead Data Support                                    (RDS): Read data from the PMR is %s\n",
		(pmrcap & 0x00000008) ? "supported":"not supported");
}

static void nvme_show_registers_pmrctl(__u32 pmrctl)
{
	printf("\tEnable (EN): PMR is %s\n", (pmrctl & 0x00000001) ?
		"READY" : "Disabled");
}

static const char *nvme_register_pmr_hsts_to_string(__u8 hsts)
{
	switch (hsts) {
	case 0: return "Normal Operation";
	case 1: return "Restore Error";
	case 2: return "Read Only";
	case 3: return "Unreliable";
	default: return "Reserved";
	}
}

static void nvme_show_registers_pmrsts(__u32 pmrsts, __u32 pmrctl)
{
	printf("\tController Base Address Invalid (CBAI): %x\n",
		(pmrsts & 0x00001000) >> 12);
	printf("\tHealth Status                   (HSTS): %s\n",
		nvme_register_pmr_hsts_to_string((pmrsts & 0x00000e00) >> 9));
	printf("\tNot Ready                       (NRDY): "\
		"The Persistent Memory Region is %s to process "\
		"PCI Express memory read and write requests\n",
			(pmrsts & 0x00000100) == 0 && (pmrctl & 0x00000001) ?
				"READY":"Not Ready");
	printf("\tError                            (ERR): %x\n", (pmrsts & 0x000000ff));
}

static const char *nvme_register_pmr_pmrszu_to_string(__u8 pmrszu)
{
	switch (pmrszu) {
	case 0: return "Bytes";
	case 1: return "One KB";
	case 2: return "One MB";
	case 3: return "One GB";
	default: return "Reserved";
	}
}

static void nvme_show_registers_pmrebs(__u32 pmrebs)
{
	printf("\tPMR Elasticity Buffer Size Base  (PMRWBZ): %x\n", (pmrebs & 0xffffff00) >> 8);
	printf("\tRead Bypass Behavior                     : memory reads not conflicting with memory writes "\
	       "in the PMR Elasticity Buffer %s bypass those memory writes\n",
	       (pmrebs & 0x00000010) ? "SHALL":"MAY");
	printf("\tPMR Elasticity Buffer Size Units (PMRSZU): %s\n",
		nvme_register_pmr_pmrszu_to_string(pmrebs & 0x0000000f));
}

static void nvme_show_registers_pmrswtp(__u32 pmrswtp)
{
	printf("\tPMR Sustained Write Throughput       (PMRSWTV): %x\n",
		(pmrswtp & 0xffffff00) >> 8);
	printf("\tPMR Sustained Write Throughput Units (PMRSWTU): %s/second\n",
		nvme_register_pmr_pmrszu_to_string(pmrswtp & 0x0000000f));
}

static void nvme_show_registers_pmrmscl(uint32_t pmrmscl)
{
	printf("\tController Base Address         (CBA): %#x\n",
		(pmrmscl & 0xfffff000) >> 12);
	printf("\tController Memory Space Enable (CMSE): %#x\n\n",
		(pmrmscl & 0x00000002) >> 1);
}

static void nvme_show_registers_pmrmscu(uint32_t pmrmscu)
{
	printf("\tController Base Address         (CBA): %#x\n",
		pmrmscu);
}

static inline uint32_t mmio_read32(void *addr)
{
	__le32 *p = addr;

	return le32_to_cpu(*p);
}

/* Access 64-bit registers as 2 32-bit; Some devices fail 64-bit MMIO. */
static inline __u64 mmio_read64(void *addr)
{
	const volatile __u32 *p = addr;
	__u32 low, high;

	low = le32_to_cpu(*p);
	high = le32_to_cpu(*(p + 1));

	return ((__u64) high << 32) | low;
}

static void json_ctrl_registers(void *bar)
{
	uint64_t cap, asq, acq, bpmbl, cmbmsc;
	uint32_t vs, intms, intmc, cc, csts, nssr, aqa, cmbsz, cmbloc,
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
	json_object_add_value_uint(root, "cap", cap);
	json_object_add_value_int(root, "vs", vs);
	json_object_add_value_int(root, "intms", intms);
	json_object_add_value_int(root, "intmc", intmc);
	json_object_add_value_int(root, "cc", cc);
	json_object_add_value_int(root, "csts", csts);
	json_object_add_value_int(root, "nssr", nssr);
	json_object_add_value_int(root, "aqa", aqa);
	json_object_add_value_uint(root, "asq", asq);
	json_object_add_value_uint(root, "acq", acq);
	json_object_add_value_int(root, "cmbloc", cmbloc);
	json_object_add_value_int(root, "cmbsz", cmbsz);
	json_object_add_value_int(root, "bpinfo", bpinfo);
	json_object_add_value_int(root, "bprsel", bprsel);
	json_object_add_value_uint(root, "bpmbl", bpmbl);
	json_object_add_value_uint(root, "cmbmsc", cmbmsc);
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

void nvme_show_ctrl_registers(void *bar, bool fabrics, enum nvme_print_flags flags)
{
	const unsigned int reg_size = 0x0e1c;  /* 0x0000 to 0x0e1b */
	uint64_t cap, asq, acq, bpmbl, cmbmsc;
	uint32_t vs, intms, intmc, cc, csts, nssr, aqa, cmbsz, cmbloc, bpinfo,
		 bprsel, cmbsts, pmrcap, pmrctl, pmrsts, pmrebs, pmrswtp,
		 pmrmscl, pmrmscu;
	int human = flags & VERBOSE;

	if (flags & BINARY)
		return d_raw((unsigned char *)bar, reg_size);
	if (flags & JSON)
		return json_ctrl_registers(bar);

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
	cmbmsc = mmio_read64(bar + NVME_REG_CMBMSC);
	cmbsts = mmio_read32(bar + NVME_REG_CMBSTS);
	pmrcap = mmio_read32(bar + NVME_REG_PMRCAP);
	pmrctl = mmio_read32(bar + NVME_REG_PMRCTL);
	pmrsts = mmio_read32(bar + NVME_REG_PMRSTS);
	pmrebs = mmio_read32(bar + NVME_REG_PMREBS);
	pmrswtp = mmio_read32(bar + NVME_REG_PMRSWTP);
	pmrmscl = mmio_read32(bar + NVME_REG_PMRMSCL);
	pmrmscu = mmio_read32(bar + NVME_REG_PMRMSCU);

	if (human) {
		if (cap != 0xffffffff) {
			printf("cap     : %"PRIx64"\n", cap);
			nvme_show_registers_cap((struct nvme_bar_cap *)&cap);
		}
		if (vs != 0xffffffff) {
			printf("version : %x\n", vs);
			nvme_show_registers_version(vs);
		}
		if (cc != 0xffffffff) {
			printf("cc      : %x\n", cc);
			nvme_show_registers_cc(cc);
		}
		if (csts != 0xffffffff) {
			printf("csts    : %x\n", csts);
			nvme_show_registers_csts(csts);
		}
		if (nssr != 0xffffffff) {
			printf("nssr    : %x\n", nssr);
			printf("\tNVM Subsystem Reset Control (NSSRC): %u\n\n",
				nssr);
		}
		if (!fabrics) {
			printf("intms   : %x\n", intms);
			printf("\tInterrupt Vector Mask Set (IVMS): %x\n\n",
					intms);

			printf("intmc   : %x\n", intmc);
			printf("\tInterrupt Vector Mask Clear (IVMC): %x\n\n",
					intmc);
			printf("aqa     : %x\n", aqa);
			nvme_show_registers_aqa(aqa);

			printf("asq     : %"PRIx64"\n", asq);
			printf("\tAdmin Submission Queue Base (ASQB): %"PRIx64"\n\n",
					asq);

			printf("acq     : %"PRIx64"\n", acq);
			printf("\tAdmin Completion Queue Base (ACQB): %"PRIx64"\n\n",
					acq);

			printf("cmbloc  : %x\n", cmbloc);
			nvme_show_registers_cmbloc(cmbloc, cmbsz);

			printf("cmbsz   : %x\n", cmbsz);
			nvme_show_registers_cmbsz(cmbsz);

			printf("bpinfo  : %x\n", bpinfo);
			nvme_show_registers_bpinfo(bpinfo);

			printf("bprsel  : %x\n", bprsel);
			nvme_show_registers_bprsel(bprsel);

			printf("bpmbl   : %"PRIx64"\n", bpmbl);
			nvme_show_registers_bpmbl(bpmbl);

			printf("cmbmsc	: %"PRIx64"\n", cmbmsc);
			nvme_show_registers_cmbmsc(cmbmsc);

			printf("cmbsts	: %x\n", cmbsts);
			nvme_show_registers_cmbsts(cmbsts);

			printf("pmrcap  : %x\n", pmrcap);
			nvme_show_registers_pmrcap(pmrcap);

			printf("pmrctl  : %x\n", pmrctl);
			nvme_show_registers_pmrctl(pmrctl);

			printf("pmrsts  : %x\n", pmrsts);
			nvme_show_registers_pmrsts(pmrsts, pmrctl);

			printf("pmrebs  : %x\n", pmrebs);
			nvme_show_registers_pmrebs(pmrebs);

			printf("pmrswtp : %x\n", pmrswtp);
			nvme_show_registers_pmrswtp(pmrswtp);

			printf("pmrmscl	: %#x\n", pmrmscl);
			nvme_show_registers_pmrmscl(pmrmscl);

			printf("pmrmscu	: %#x\n", pmrmscu);
			nvme_show_registers_pmrmscu(pmrmscu);
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
			printf("cmbmsc	: %"PRIx64"\n", cmbmsc);
			printf("cmbsts	: %x\n", cmbsts);
			printf("pmrcap  : %x\n", pmrcap);
			printf("pmrctl  : %x\n", pmrctl);
			printf("pmrsts  : %x\n", pmrsts);
			printf("pmrebs  : %x\n", pmrebs);
			printf("pmrswtp : %x\n", pmrswtp);
			printf("pmrmscl	: %#x\n", pmrmscl);
			printf("pmrmscu	: %#x\n", pmrmscu);
		}
	}
}

void nvme_show_single_property(int offset, uint64_t value64, int human)
{
	uint32_t value32;

	if (!human) {
		if (is_64bit_reg(offset))
			printf("property: 0x%02x (%s), value: %"PRIx64"\n",
				offset, nvme_register_to_string(offset),
				value64);
		else
			printf("property: 0x%02x (%s), value: %x\n", offset,
				   nvme_register_to_string(offset),
				   (uint32_t) value64);

		return;
	}

	value32 = (uint32_t) value64;

	switch (offset) {
	case NVME_REG_CAP:
		printf("cap : %"PRIx64"\n", value64);
		nvme_show_registers_cap((struct nvme_bar_cap *)&value64);
		break;

	case NVME_REG_VS:
		printf("version : %x\n", value32);
		nvme_show_registers_version(value32);
		break;

	case NVME_REG_CC:
		printf("cc : %x\n", value32);
		nvme_show_registers_cc(value32);
		break;

	case NVME_REG_CSTS:
		printf("csts : %x\n", value32);
		nvme_show_registers_csts(value32);
		break;

	case NVME_REG_NSSR:
		printf("nssr : %x\n", value32);
		printf("\tNVM Subsystem Reset Control (NSSRC): %u\n\n",
			value32);
		break;

	default:
		printf("unknown property: 0x%02x (%s), value: %"PRIx64"\n",
			offset, nvme_register_to_string(offset), value64);
		break;
	}
}

void nvme_show_relatives(const char *name)
{
	unsigned id, i, nsid = NVME_NSID_ALL;
	char *path = NULL;
	bool block = true;
	int ret;

	ret = sscanf(name, "nvme%dn%d", &id, &nsid);
	switch (ret) {
	case 1:
		if (asprintf(&path, "/sys/class/nvme/%s", name) < 0)
			path = NULL;
		block = false;
		break;
	case 2:
		if (asprintf(&path, "/sys/block/%s/device", name) < 0)
			path = NULL;
		break;
	default:
		return;
	}

	if (!path)
		return;

	if (block) {
		struct nvme_topology t = { };
		char *subsysnqn;
		int err;

		subsysnqn = get_nvme_subsnqn(path);
		if (!subsysnqn) {
			free(path);
			return;
		}
		err = scan_subsystems(&t, subsysnqn, 0, 0, NULL);
		if (err || t.nr_subsystems != 1) {
			free(subsysnqn);
			free(path);
			return;
		}

		fprintf(stderr, "Namespace %s has parent controller(s):", name);
		for (i = 0; i < t.subsystems[0].nr_ctrls; i++)
			fprintf(stderr, "%s%s", i ? ", " : "",
				t.subsystems[0].ctrls[i].name);
		fprintf(stderr, "\n\n");
		free(subsysnqn);
		free_topology(&t);
	} else {
		struct dirent **paths;
		bool comma = false;
		int n, ns, cntlid;

		n = scandir(path, &paths, scan_ctrl_paths_filter, alphasort);
		if (n < 0) {
			free(path);
			return;
		}

		fprintf(stderr, "Controller %s has child namespace(s):", name);
		for (i = 0; i < n; i++) {
			if (sscanf(paths[i]->d_name, "nvme%dc%dn%d",
				   &id, &cntlid, &ns) != 3) {
				if (sscanf(paths[i]->d_name, "nvme%dn%d",
					   &id, &ns) != 2) {
					continue;
				}
			}
			fprintf(stderr, "%snvme%dn%d", comma ? ", " : "", id,
				ns);
			comma = true;
		}
		fprintf(stderr, "\n\n");
		free(paths);
	}
	free(path);
}

void d(unsigned char *buf, int len, int width, int group)
{
	int i, offset = 0, line_done = 0;
	char ascii[32 + 1];

	assert(width < sizeof(ascii));
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
		putchar(*(buf + i));
}

void nvme_show_status(__u16 status)
{
	fprintf(stderr, "NVMe status: %s(%#x)\n", nvme_status_to_string(status),
		status);
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

static const char *nvme_uuid_to_string(uuid_t uuid)
{
	/* large enough to hold uuid str (37) + null-termination byte */
	static char uuid_str[40];
#ifdef LIBUUID
	uuid_unparse_lower(uuid, uuid_str);
#else
	static const char *hex_digits = "0123456789abcdef";
	char *p = &uuid_str[0];
	int i;

	for (i = 0; i < 16; i++) {
		*p++ = hex_digits[(uuid.b[i] & 0xf0) >> 4];
		*p++ = hex_digits[uuid.b[i] & 0x0f];
		if (i == 3 || i == 5 || i == 7 || i == 9)
			*p++ = '-';
	}
	*p = '\0';
#endif
	return uuid_str;
}

static void nvme_show_id_ctrl_cmic(__u8 cmic)
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

static void nvme_show_id_ctrl_oaes(__le32 ctrl_oaes)
{
	__u32 oaes = le32_to_cpu(ctrl_oaes);
	__u32 rsvd0 = (oaes & 0xF0000000) >> 28;
	__u32 zicn = (oaes & 0x08000000) >> 27;
	__u32 rsvd1 = (oaes & 0x07FF8000) >> 15;
	__u32 nace = (oaes & 0x100) >> 8;
	__u32 fan = (oaes & 0x200) >> 9;
	__u32 anacn = (oaes & 0x800) >> 11;
	__u32 plealcn = (oaes & 0x1000) >> 12;
	__u32 lbasin = (oaes & 0x2000) >> 13;
	__u32 egealpcn = (oaes & 0x4000) >> 14;
	__u32 rsvd2 = oaes & 0xFF;

	if (rsvd0)
		printf(" [31:28] : %#x\tReserved\n", rsvd0);
	printf("[27:27] : %#x\tZone Descriptor Changed Notices %sSupported\n",
			zicn, zicn ? "" : "Not ");
	if (rsvd1)
		printf(" [26:15] : %#x\tReserved\n", rsvd1);
	printf("[14:14] : %#x\tEndurance Group Event Aggregate Log Page"\
			" Change Notice %sSupported\n",
			egealpcn, egealpcn ? "" : "Not ");
	printf("[13:13] : %#x\tLBA Status Information Notices %sSupported\n",
			lbasin, lbasin ? "" : "Not ");
	printf("[12:12] : %#x\tPredictable Latency Event Aggregate Log Change"\
			" Notices %sSupported\n",
			plealcn, plealcn ? "" : "Not ");
	printf("[11:11] : %#x\tAsymmetric Namespace Access Change Notices"\
			" %sSupported\n", anacn, anacn ? "" : "Not ");
	printf("  [9:9] : %#x\tFirmware Activation Notices %sSupported\n",
		fan, fan ? "" : "Not ");
	printf("  [8:8] : %#x\tNamespace Attribute Changed Event %sSupported\n",
		nace, nace ? "" : "Not ");
	if (rsvd2)
		printf("  [7:0] : %#x\tReserved\n", rsvd1);
	printf("\n");
}

static void nvme_show_id_ctrl_ctratt(__le32 ctrl_ctratt)
{
	__u32 ctratt = le32_to_cpu(ctrl_ctratt);
	__u32 rsvd = ctratt >> 10;
	__u32 hostid128 = (ctratt & NVME_CTRL_CTRATT_128_ID) >> 0;
	__u32 psp = (ctratt & NVME_CTRL_CTRATT_NON_OP_PSP) >> 1;
	__u32 sets = (ctratt & NVME_CTRL_CTRATT_NVM_SETS) >> 2;
	__u32 rrl = (ctratt & NVME_CTRL_CTRATT_READ_RECV_LVLS) >> 3;
	__u32 eg = (ctratt & NVME_CTRL_CTRATT_ENDURANCE_GROUPS) >> 4;
	__u32 iod = (ctratt & NVME_CTRL_CTRATT_PREDICTABLE_LAT) >> 5;
	__u32 ng = (ctratt & NVME_CTRL_CTRATT_NAMESPACE_GRANULARITY) >> 7;
	__u32 uuidlist = (ctratt & NVME_CTRL_CTRATT_UUID_LIST) >> 9;
	__u32 rsvd6 = (ctratt & 0x00000040) >> 6;
	__u32 rsvd8 = (ctratt & 0x00000100) >> 8;

	if (rsvd)
		printf(" [31:10] : %#x\tReserved\n", rsvd);

	printf("  [9:9] : %#x\tUUID List %sSupported\n",
		uuidlist, uuidlist ? "" : "Not ");
	if (rsvd8)
		printf(" [8:8] : %#x\tReserved\n", rsvd8);
	printf("  [7:7] : %#x\tNamespace Granularity %sSupported\n",
		ng, ng ? "" : "Not ");
	if (rsvd6)
		printf(" [6:6] : %#x\tReserved\n", rsvd6);
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

static void nvme_show_id_ctrl_cntrltype(__u8 cntrltype)
{
	__u8 rsvd = (cntrltype & 0xFC) >> 2;
	__u8 cntrl = cntrltype & 0x3;

	static const char *type[] = {
		"Controller type not reported",
		"I/O Controller",
		"Discovery Controller",
		"Administrative Controller"
	};

	printf("  [7:2] : %#x\tReserved\n", rsvd);
	printf("  [1:0] : %#x\t%s\n", cntrltype, type[cntrl]);
}

static void nvme_show_id_ctrl_oacs(__le16 ctrl_oacs)
{
	__u16 oacs = le16_to_cpu(ctrl_oacs);
	__u16 rsvd = (oacs & 0xFC00) >> 10;
	__u16 glbas = (oacs & 0x200) >> 9;
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
	printf("  [9:9] : %#x\tGet LBA Status Capability %sSupported\n",
		glbas, glbas ? "" : "Not ");
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

static void nvme_show_id_ctrl_frmw(__u8 frmw)
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

static void nvme_show_id_ctrl_lpa(__u8 lpa)
{
	__u8 rsvd = (lpa & 0xE0) >> 5;
	__u8 persevnt = (lpa & 0x10) >> 4;
	__u8 telem = (lpa & 0x8) >> 3;
	__u8 ed = (lpa & 0x4) >> 2;
	__u8 celp = (lpa & 0x2) >> 1;
	__u8 smlp = lpa & 0x1;

	if (rsvd)
		printf("  [7:4] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tPersistent Event log %sSupported\n",
			persevnt, persevnt ? "" : "Not ");
	printf("  [3:3] : %#x\tTelemetry host/controller initiated log page %sSupported\n",
	       telem, telem ? "" : "Not ");
	printf("  [2:2] : %#x\tExtended data for Get Log Page %sSupported\n",
		ed, ed ? "" : "Not ");
	printf("  [1:1] : %#x\tCommand Effects Log Page %sSupported\n",
		celp, celp ? "" : "Not ");
	printf("  [0:0] : %#x\tSMART/Health Log Page per NS %sSupported\n",
		smlp, smlp ? "" : "Not ");
	printf("\n");
}

static void nvme_show_id_ctrl_avscc(__u8 avscc)
{
	__u8 rsvd = (avscc & 0xFE) >> 1;
	__u8 fmt = avscc & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tAdmin Vendor Specific Commands uses %s Format\n",
		fmt, fmt ? "NVMe" : "Vendor Specific");
	printf("\n");
}

static void nvme_show_id_ctrl_apsta(__u8 apsta)
{
	__u8 rsvd = (apsta & 0xFE) >> 1;
	__u8 apst = apsta & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tAutonomous Power State Transitions %sSupported\n",
		apst, apst ? "" : "Not ");
	printf("\n");
}

void nvme_show_id_ctrl_rpmbs(__le32 ctrl_rpmbs)
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

static void nvme_show_id_ctrl_hctma(__le16 ctrl_hctma)
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

static void nvme_show_id_ctrl_sanicap(__le32 ctrl_sanicap)
{
	__u32 sanicap = le32_to_cpu(ctrl_sanicap);
	__u32 rsvd = (sanicap & 0x1FFFFFF8) >> 3;
	__u32 owr = (sanicap & 0x4) >> 2;
	__u32 ber = (sanicap & 0x2) >> 1;
	__u32 cer = sanicap & 0x1;
	__u32 ndi = (sanicap & 0x20000000) >> 29;
	__u32 nodmmas = (sanicap & 0xC0000000) >> 30;

	static const char *modifies_media[] = {
		"Additional media modification after sanitize operation completes successfully is not defined",
		"Media is not additionally modified after sanitize operation completes successfully",
		"Media is additionally modified after sanitize operation completes successfully",
		"Reserved"
	};

	printf("  [31:30] : %#x\t%s\n", nodmmas, modifies_media[nodmmas]);
	printf("  [29:29] : %#x\tNo-Deallocate After Sanitize bit in Sanitize command %sSupported\n",
		ndi, ndi ? "Not " : "");
	if (rsvd)
		printf("  [28:3] : %#x\tReserved\n", rsvd);
	printf("    [2:2] : %#x\tOverwrite Sanitize Operation %sSupported\n",
		owr, owr ? "" : "Not ");
	printf("    [1:1] : %#x\tBlock Erase Sanitize Operation %sSupported\n",
		ber, ber ? "" : "Not ");
	printf("    [0:0] : %#x\tCrypto Erase Sanitize Operation %sSupported\n",
		cer, cer ? "" : "Not ");
	printf("\n");
}

static void nvme_show_id_ctrl_anacap(__u8 anacap)
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

static void nvme_show_id_ctrl_sqes(__u8 sqes)
{
	__u8 msqes = (sqes & 0xF0) >> 4;
	__u8 rsqes = sqes & 0xF;
	printf("  [7:4] : %#x\tMax SQ Entry Size (%d)\n", msqes, 1 << msqes);
	printf("  [3:0] : %#x\tMin SQ Entry Size (%d)\n", rsqes, 1 << rsqes);
	printf("\n");
}

static void nvme_show_id_ctrl_cqes(__u8 cqes)
{
	__u8 mcqes = (cqes & 0xF0) >> 4;
	__u8 rcqes = cqes & 0xF;
	printf("  [7:4] : %#x\tMax CQ Entry Size (%d)\n", mcqes, 1 << mcqes);
	printf("  [3:0] : %#x\tMin CQ Entry Size (%d)\n", rcqes, 1 << rcqes);
	printf("\n");
}

static void nvme_show_id_ctrl_oncs(__le16 ctrl_oncs)
{
	__u16 oncs = le16_to_cpu(ctrl_oncs);
	__u16 rsvd = (oncs & 0xFE00) >> 9;
	__u16 copy = (oncs & 0x100) >> 8;
	__u16 vrfy = (oncs & 0x80) >> 7;
	__u16 tmst = (oncs & 0x40) >> 6;
	__u16 resv = (oncs & 0x20) >> 5;
	__u16 save = (oncs & 0x10) >> 4;
	__u16 wzro = (oncs & 0x8) >> 3;
	__u16 dsms = (oncs & 0x4) >> 2;
	__u16 wunc = (oncs & 0x2) >> 1;
	__u16 cmp = oncs & 0x1;

	if (rsvd)
		printf(" [15:9] : %#x\tReserved\n", rsvd);
	printf("  [8:8] : %#x\tCopy %sSupported\n",
		copy, copy ? "" : "Not ");
	printf("  [7:7] : %#x\tVerify %sSupported\n",
		vrfy, vrfy ? "" : "Not ");
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

static void nvme_show_id_ctrl_fuses(__le16 ctrl_fuses)
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

static void nvme_show_id_ctrl_fna(__u8 fna)
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

static void nvme_show_id_ctrl_vwc(__u8 vwc)
{
	__u8 rsvd = (vwc & 0xF8) >> 3;
	__u8 flush = (vwc & 0x6) >> 1;
	__u8 vwcp = vwc & 0x1;

	static const char *flush_behavior[] = {
		"Support for the NSID field set to FFFFFFFFh is not indicated",
		"Reserved",
		"The Flush command does not support NSID set to FFFFFFFFh",
		"The Flush command supports NSID set to FFFFFFFFh"
	};

	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);
	printf("  [2:1] : %#x\t%s\n", flush, flush_behavior[flush]);
	printf("  [0:0] : %#x\tVolatile Write Cache %sPresent\n",
		vwcp, vwcp ? "" : "Not ");
	printf("\n");
}

static void nvme_show_id_ctrl_icsvscc(__u8 icsvscc)
{
	__u8 rsvd = (icsvscc & 0xFE) >> 1;
	__u8 fmt = icsvscc & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tNVM Vendor Specific Commands uses %s Format\n",
		fmt, fmt ? "NVMe" : "Vendor Specific");
	printf("\n");
}

static void nvme_show_id_ctrl_nwpc(__u8 nwpc)
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

static void nvme_show_id_ctrl_sgls(__le32 ctrl_sgls)
{
	__u32 sgls = le32_to_cpu(ctrl_sgls);
	__u32 rsvd0 = (sgls & 0xFFC00000) >> 22;
	__u32 trsdbd = (sgls & 0x200000) >> 21;
	__u32 aofdsl = (sgls & 0x100000) >> 20;
	__u32 mpcsd = (sgls & 0x80000) >> 19;
	__u32 sglltb = (sgls & 0x40000) >> 18;
	__u32 bacmdb = (sgls & 0x20000) >> 17;
	__u32 bbs = (sgls & 0x10000) >> 16;
	__u32 rsvd1 = (sgls & 0xFFF8) >> 3;
	__u32 key = (sgls & 0x4) >> 2;
	__u32 sglsp = sgls & 0x3;

	if (rsvd0)
		printf(" [31:22]: %#x\tReserved\n", rsvd0);
	if (sglsp || (!sglsp && trsdbd))
		printf(" [21:21]: %#x\tTransport SGL Data Block Descriptor %sSupported\n",
			trsdbd, trsdbd ? "" : "Not ");
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

static void nvme_show_id_ctrl_fcatt(__u8 fcatt)
{
	__u8 rsvd = (fcatt & 0xFE) >> 1;
	__u8 scm = fcatt & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\t%s Controller Model\n",
		scm, scm ? "Static" : "Dynamic");
	printf("\n");
}

static void nvme_show_id_ctrl_ofcs(__le16 ofcs)
{
	__u16 rsvd = (ofcs & 0xfffe) >> 1;
	__u8 disconn = ofcs & 0x1;
	if (rsvd)
		printf("  [15:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tDisconnect command %s Supported\n",
		disconn, disconn ? "" : "Not");
	printf("\n");

}

static void nvme_show_id_ns_nsfeat(__u8 nsfeat)
{
	__u8 rsvd = (nsfeat & 0xE0) >> 5;
	__u8 ioopt = (nsfeat & 0x10) >> 4;
	__u8 uidreuse = (nsfeat & 0x8) >> 3;
	__u8 dulbe = (nsfeat & 0x4) >> 2;
	__u8 na = (nsfeat & 0x2) >> 1;
	__u8 thin = nsfeat & 0x1;
	if (rsvd)
		printf("  [7:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tNPWG, NPWA, NPDG, NPDA, and NOWS are %sSupported\n",
		ioopt, ioopt ? "" : "Not ");
	printf("  [3:3] : %#x\tNGUID and EUI64 fields if non-zero, %sReused\n",
		uidreuse, uidreuse ? "Never " : "");
	printf("  [2:2] : %#x\tDeallocated or Unwritten Logical Block error %sSupported\n",
		dulbe, dulbe ? "" : "Not ");
	printf("  [1:1] : %#x\tNamespace uses %s\n",
		na, na ? "NAWUN, NAWUPF, and NACWU" : "AWUN, AWUPF, and ACWU");
	printf("  [0:0] : %#x\tThin Provisioning %sSupported\n",
		thin, thin ? "" : "Not ");
	printf("\n");
}

static void nvme_show_id_ns_flbas(__u8 flbas)
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

static void nvme_show_id_ns_mc(__u8 mc)
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

static void nvme_show_id_ns_dpc(__u8 dpc)
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

static void nvme_show_id_ns_dps(__u8 dps)
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

static void nvme_show_id_ns_nmic(__u8 nmic)
{
	__u8 rsvd = (nmic & 0xFE) >> 1;
	__u8 mp = nmic & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tNamespace Multipath %sCapable\n",
		mp, mp ? "" : "Not ");
	printf("\n");
}

static void nvme_show_id_ns_rescap(__u8 rescap)
{
	__u8 iekr = (rescap & 0x80) >> 7;
	__u8 eaar = (rescap & 0x40) >> 6;
	__u8 wear = (rescap & 0x20) >> 5;
	__u8 earo = (rescap & 0x10) >> 4;
	__u8 wero = (rescap & 0x8) >> 3;
	__u8 ea = (rescap & 0x4) >> 2;
	__u8 we = (rescap & 0x2) >> 1;
	__u8 ptpl = rescap & 0x1;

	printf("  [7:7] : %#x\tIgnore Existing Key - Used as defined in revision %s\n",
		iekr, iekr ? "1.3 or later" : "1.2.1 or earlier");
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

static void nvme_show_id_ns_fpi(__u8 fpi)
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

static void nvme_show_id_ns_dlfeat(__u8 dlfeat)
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
	printf("  [2:0] : %#x\tBytes Read From a Deallocated Logical Block and its Metadata are %s\n",
		val, val == 2 ? "0xFF" :
			val == 1 ? "0x00" :
			val == 0 ? "Not Reported" : "Reserved Value");
	printf("\n");
}

void nvme_show_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
		enum nvme_print_flags flags)
{
	int human = flags & VERBOSE;
	int vs = flags & VS;
	int i;

	if (flags & BINARY)
		return d_raw((unsigned char *)ns, sizeof(*ns));
	if (flags & JSON)
		return json_nvme_id_ns(ns);

	printf("NVME Identify Namespace %d:\n", nsid);
	printf("nsze    : %#"PRIx64"\n", le64_to_cpu(ns->nsze));
	printf("ncap    : %#"PRIx64"\n", le64_to_cpu(ns->ncap));
	printf("nuse    : %#"PRIx64"\n", le64_to_cpu(ns->nuse));
	printf("nsfeat  : %#x\n", ns->nsfeat);
	if (human)
		nvme_show_id_ns_nsfeat(ns->nsfeat);
	printf("nlbaf   : %d\n", ns->nlbaf);
	printf("flbas   : %#x\n", ns->flbas);
	if (human)
		nvme_show_id_ns_flbas(ns->flbas);
	printf("mc      : %#x\n", ns->mc);
	if (human)
		nvme_show_id_ns_mc(ns->mc);
	printf("dpc     : %#x\n", ns->dpc);
	if (human)
		nvme_show_id_ns_dpc(ns->dpc);
	printf("dps     : %#x\n", ns->dps);
	if (human)
		nvme_show_id_ns_dps(ns->dps);
	printf("nmic    : %#x\n", ns->nmic);
	if (human)
		nvme_show_id_ns_nmic(ns->nmic);
	printf("rescap  : %#x\n", ns->rescap);
	if (human)
		nvme_show_id_ns_rescap(ns->rescap);
	printf("fpi     : %#x\n", ns->fpi);
	if (human)
		nvme_show_id_ns_fpi(ns->fpi);
	printf("dlfeat  : %d\n", ns->dlfeat);
	if (human)
		nvme_show_id_ns_dlfeat(ns->dlfeat);
	printf("nawun   : %d\n", le16_to_cpu(ns->nawun));
	printf("nawupf  : %d\n", le16_to_cpu(ns->nawupf));
	printf("nacwu   : %d\n", le16_to_cpu(ns->nacwu));
	printf("nabsn   : %d\n", le16_to_cpu(ns->nabsn));
	printf("nabo    : %d\n", le16_to_cpu(ns->nabo));
	printf("nabspf  : %d\n", le16_to_cpu(ns->nabspf));
	printf("noiob   : %d\n", le16_to_cpu(ns->noiob));
	printf("nvmcap  : %.0Lf\n", int128_to_double(ns->nvmcap));
	if (ns->nsfeat & 0x10) {
		printf("npwg    : %u\n", le16_to_cpu(ns->npwg));
		printf("npwa    : %u\n", le16_to_cpu(ns->npwa));
		printf("npdg    : %u\n", le16_to_cpu(ns->npdg));
		printf("npda    : %u\n", le16_to_cpu(ns->npda));
		printf("nows    : %u\n", le16_to_cpu(ns->nows));
	}
	printf("mssrl   : %u\n", le16_to_cpu(ns->mssrl));
	printf("mcl     : %d\n", le32_to_cpu(ns->mcl));
	printf("msrc    : %u\n", ns->msrc);
	printf("anagrpid: %u\n", le32_to_cpu(ns->anagrpid));
	printf("nsattr	: %u\n", ns->nsattr);
	printf("nvmsetid: %d\n", le16_to_cpu(ns->nvmsetid));
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
				"Data Size: %-2d bytes - Relative Performance: %#x %s %s\n",
				i, le16_to_cpu(ns->lbaf[i].ms),
				1 << ns->lbaf[i].ds, ns->lbaf[i].rp,
				ns->lbaf[i].rp == 3 ? "Degraded" :
					ns->lbaf[i].rp == 2 ? "Good" :
					ns->lbaf[i].rp == 1 ? "Better" : "Best",
				i == (ns->flbas & 0xf) ? "(in use)" : "");
		else
			printf("lbaf %2d : ms:%-3d lbads:%-2d rp:%#x %s\n", i,
				le16_to_cpu(ns->lbaf[i].ms), ns->lbaf[i].ds,
				ns->lbaf[i].rp,
				i == (ns->flbas & 0xf) ? "(in use)" : "");
	}

	if (vs) {
		printf("vs[]:\n");
		d(ns->vs, sizeof(ns->vs), 16, 1);
	}
}


static void json_nvme_id_ns_descs(void *data)
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

#ifdef LIBUUID
		case NVME_NIDT_UUID:
			memcpy(desc.uuid, data + off, sizeof(desc.uuid));
			uuid_unparse_lower(desc.uuid, json_str);
			len = sizeof(desc.uuid);
			nidt_name = "uuid";
			break;
#endif
		case NVME_NIDT_CSI:
			memcpy(&desc.csi, data + off, sizeof(desc.csi));
			json_str_p += sprintf(json_str_p, "%#x", desc.csi);
			len += sizeof(desc.csi);
			nidt_name = "csi";
			break;
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

void nvme_show_id_ns_descs(void *data, unsigned nsid, enum nvme_print_flags flags)
{
	int pos, len = 0;
	int i;
#ifdef LIBUUID
	uuid_t uuid;
	char uuid_str[37];
#endif
	__u8 eui64[8];
	__u8 nguid[16];
	__u8 csi;

	if (flags & BINARY)
		return  d_raw((unsigned char *)data, 0x1000);
	if (flags & JSON)
		return json_nvme_id_ns_descs(data);

	printf("NVME Namespace Identification Descriptors NS %d:\n", nsid);
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
			len = sizeof(eui64);
			break;
		case NVME_NIDT_NGUID:
			memcpy(nguid, data + pos + sizeof(*cur), sizeof(nguid));
			printf("nguid   : ");
			for (i = 0; i < 16; i++)
				printf("%02x", nguid[i]);
			printf("\n");
			len = sizeof(nguid);
			break;
#ifdef LIBUUID
		case NVME_NIDT_UUID:
			memcpy(uuid, data + pos + sizeof(*cur), 16);
			uuid_unparse_lower(uuid, uuid_str);
			printf("uuid    : %s\n", uuid_str);
			len = sizeof(uuid);
			break;
#endif
		case NVME_NIDT_CSI:
			memcpy(&csi, data + pos + sizeof(*cur), 1);
			printf("csi     : %#x\n", csi);
			len += sizeof(csi);
			break;
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
		printf("%01u.%02uW", power / 100, power % 100);
		break;

	default:
		printf("reserved");
	}
}

static void nvme_show_id_ctrl_power(struct nvme_id_ctrl *ctrl)
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
			le32_to_cpu(ctrl->psd[i].entry_lat),
			le32_to_cpu(ctrl->psd[i].exit_lat),
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

void __nvme_show_id_ctrl(struct nvme_id_ctrl *ctrl, enum nvme_print_flags flags,
			void (*vendor_show)(__u8 *vs, struct json_object *root))
{
	int human = flags & VERBOSE, vs = flags & VS;

	if (flags & BINARY)
		return d_raw((unsigned char *)ctrl, sizeof(*ctrl));
	else if (flags & JSON)
		return json_nvme_id_ctrl(ctrl, vendor_show);

	printf("NVME Identify Controller:\n");
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
		nvme_show_id_ctrl_cmic(ctrl->cmic);
	printf("mdts      : %d\n", ctrl->mdts);
	printf("cntlid    : %#x\n", le16_to_cpu(ctrl->cntlid));
	printf("ver       : %#x\n", le32_to_cpu(ctrl->ver));
	printf("rtd3r     : %#x\n", le32_to_cpu(ctrl->rtd3r));
	printf("rtd3e     : %#x\n", le32_to_cpu(ctrl->rtd3e));
	printf("oaes      : %#x\n", le32_to_cpu(ctrl->oaes));
	if (human)
		nvme_show_id_ctrl_oaes(ctrl->oaes);
	printf("ctratt    : %#x\n", le32_to_cpu(ctrl->ctratt));
	if (human)
		nvme_show_id_ctrl_ctratt(ctrl->ctratt);
	printf("rrls      : %#x\n", le16_to_cpu(ctrl->rrls));
	printf("cntrltype : %d\n", ctrl->cntrltype);
	if (human)
		nvme_show_id_ctrl_cntrltype(ctrl->cntrltype);
	printf("fguid     : %-.*s\n", (int)sizeof(ctrl->fguid), ctrl->fguid);
	printf("crdt1     : %u\n", le16_to_cpu(ctrl->crdt1));
	printf("crdt2     : %u\n", le16_to_cpu(ctrl->crdt2));
	printf("crdt3     : %u\n", le16_to_cpu(ctrl->crdt3));

	printf("oacs      : %#x\n", le16_to_cpu(ctrl->oacs));
	if (human)
		nvme_show_id_ctrl_oacs(ctrl->oacs);
	printf("acl       : %d\n", ctrl->acl);
	printf("aerl      : %d\n", ctrl->aerl);
	printf("frmw      : %#x\n", ctrl->frmw);
	if (human)
		nvme_show_id_ctrl_frmw(ctrl->frmw);
	printf("lpa       : %#x\n", ctrl->lpa);
	if (human)
		nvme_show_id_ctrl_lpa(ctrl->lpa);
	printf("elpe      : %d\n", ctrl->elpe);
	printf("npss      : %d\n", ctrl->npss);
	printf("avscc     : %#x\n", ctrl->avscc);
	if (human)
		nvme_show_id_ctrl_avscc(ctrl->avscc);
	printf("apsta     : %#x\n", ctrl->apsta);
	if (human)
		nvme_show_id_ctrl_apsta(ctrl->apsta);
	printf("wctemp    : %d\n", le16_to_cpu(ctrl->wctemp));
	printf("cctemp    : %d\n", le16_to_cpu(ctrl->cctemp));
	printf("mtfa      : %d\n", le16_to_cpu(ctrl->mtfa));
	printf("hmpre     : %d\n", le32_to_cpu(ctrl->hmpre));
	printf("hmmin     : %d\n", le32_to_cpu(ctrl->hmmin));
	printf("tnvmcap   : %.0Lf\n", int128_to_double(ctrl->tnvmcap));
	printf("unvmcap   : %.0Lf\n", int128_to_double(ctrl->unvmcap));
	printf("rpmbs     : %#x\n", le32_to_cpu(ctrl->rpmbs));
	if (human)
		nvme_show_id_ctrl_rpmbs(ctrl->rpmbs);
	printf("edstt     : %d\n", le16_to_cpu(ctrl->edstt));
	printf("dsto      : %d\n", ctrl->dsto);
	printf("fwug      : %d\n", ctrl->fwug);
	printf("kas       : %d\n", le16_to_cpu(ctrl->kas));
	printf("hctma     : %#x\n", le16_to_cpu(ctrl->hctma));
	if (human)
		nvme_show_id_ctrl_hctma(ctrl->hctma);
	printf("mntmt     : %d\n", le16_to_cpu(ctrl->mntmt));
	printf("mxtmt     : %d\n", le16_to_cpu(ctrl->mxtmt));
	printf("sanicap   : %#x\n", le32_to_cpu(ctrl->sanicap));
	if (human)
		nvme_show_id_ctrl_sanicap(ctrl->sanicap);
	printf("hmminds   : %d\n", le32_to_cpu(ctrl->hmminds));
	printf("hmmaxd    : %d\n", le16_to_cpu(ctrl->hmmaxd));
	printf("nsetidmax : %d\n", le16_to_cpu(ctrl->nsetidmax));
	printf("endgidmax : %d\n", le16_to_cpu(ctrl->endgidmax));
	printf("anatt     : %d\n", ctrl->anatt);
	printf("anacap    : %d\n", ctrl->anacap);
	if (human)
		nvme_show_id_ctrl_anacap(ctrl->anacap);
	printf("anagrpmax : %d\n", ctrl->anagrpmax);
	printf("nanagrpid : %d\n", le32_to_cpu(ctrl->nanagrpid));
	printf("pels      : %d\n", le32_to_cpu(ctrl->pels));
	printf("sqes      : %#x\n", ctrl->sqes);
	if (human)
		nvme_show_id_ctrl_sqes(ctrl->sqes);
	printf("cqes      : %#x\n", ctrl->cqes);
	if (human)
		nvme_show_id_ctrl_cqes(ctrl->cqes);
	printf("maxcmd    : %d\n", le16_to_cpu(ctrl->maxcmd));
	printf("nn        : %d\n", le32_to_cpu(ctrl->nn));
	printf("oncs      : %#x\n", le16_to_cpu(ctrl->oncs));
	if (human)
		nvme_show_id_ctrl_oncs(ctrl->oncs);
	printf("fuses     : %#x\n", le16_to_cpu(ctrl->fuses));
	if (human)
		nvme_show_id_ctrl_fuses(ctrl->fuses);
	printf("fna       : %#x\n", ctrl->fna);
	if (human)
		nvme_show_id_ctrl_fna(ctrl->fna);
	printf("vwc       : %#x\n", ctrl->vwc);
	if (human)
		nvme_show_id_ctrl_vwc(ctrl->vwc);
	printf("awun      : %d\n", le16_to_cpu(ctrl->awun));
	printf("awupf     : %d\n", le16_to_cpu(ctrl->awupf));
	printf("icsvscc     : %d\n", ctrl->icsvscc);
	if (human)
		nvme_show_id_ctrl_icsvscc(ctrl->icsvscc);
	printf("nwpc      : %d\n", ctrl->nwpc);
	if (human)
		nvme_show_id_ctrl_nwpc(ctrl->nwpc);
	printf("acwu      : %d\n", le16_to_cpu(ctrl->acwu));
	printf("sgls      : %#x\n", le32_to_cpu(ctrl->sgls));
	if (human)
		nvme_show_id_ctrl_sgls(ctrl->sgls);
	printf("mnan      : %d\n", le32_to_cpu(ctrl->mnan));
	printf("subnqn    : %-.*s\n", (int)sizeof(ctrl->subnqn), ctrl->subnqn);
	printf("ioccsz    : %d\n", le32_to_cpu(ctrl->ioccsz));
	printf("iorcsz    : %d\n", le32_to_cpu(ctrl->iorcsz));
	printf("icdoff    : %d\n", le16_to_cpu(ctrl->icdoff));
	printf("fcatt     : %#x\n", ctrl->fcatt);
	if (human)
		nvme_show_id_ctrl_fcatt(ctrl->fcatt);
	printf("msdbd     : %d\n", ctrl->msdbd);
	printf("ofcs      : %d\n", le16_to_cpu(ctrl->ofcs));
	if (human)
		nvme_show_id_ctrl_ofcs(ctrl->ofcs);

	nvme_show_id_ctrl_power(ctrl);
	if (vendor_show)
		vendor_show(ctrl->vs, NULL);
	else if (vs) {
		printf("vs[]:\n");
		d(ctrl->vs, sizeof(ctrl->vs), 16, 1);
	}
}

void nvme_show_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode)
{
	__nvme_show_id_ctrl(ctrl, mode, NULL);
}

static void json_nvme_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_uint(root, "vsl", ctrl_nvm->vsl);
	json_object_add_value_uint(root, "wzsl", ctrl_nvm->wzsl);
	json_object_add_value_uint(root, "wusl", ctrl_nvm->wusl);
	json_object_add_value_uint(root, "dmrl", ctrl_nvm->dmrl);
	json_object_add_value_uint(root, "dmrsl", ctrl_nvm->dmrsl);
	json_object_add_value_uint(root, "dmsl", ctrl_nvm->dmsl);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void nvme_show_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm,
	enum nvme_print_flags flags)
{
	if (flags & BINARY)
		return d_raw((unsigned char *)ctrl_nvm, sizeof(*ctrl_nvm));
	else if (flags & JSON)
		return json_nvme_id_ctrl_nvm(ctrl_nvm);

	printf("NVMe Identify Controller NVM:\n");
	printf("vsl    : %u\n", ctrl_nvm->vsl);
	printf("wzsl   : %u\n", ctrl_nvm->wzsl);
	printf("wusl   : %u\n", ctrl_nvm->wusl);
	printf("dmrl   : %u\n", ctrl_nvm->dmrl);
	printf("dmrsl  : %u\n", le32_to_cpu(ctrl_nvm->dmrsl));
	printf("dmsl   : %"PRIu64"\n", le64_to_cpu(ctrl_nvm->dmsl));
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

void nvme_show_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl, unsigned int mode)
{
	if (mode & BINARY)
		return d_raw((unsigned char *)ctrl, sizeof(*ctrl));
	else if (mode & JSON)
		return json_nvme_zns_id_ctrl(ctrl);

	printf("NVMe ZNS Identify Controller:\n");
	printf("zasl    : %u\n", ctrl->zasl);
}

void json_nvme_zns_id_ns(struct nvme_zns_id_ns *ns,
	struct nvme_id_ns *id_ns)
{
	struct json_object *root;
	struct json_object *lbafs;
	int i;

	root = json_create_object();
	json_object_add_value_int(root, "zoc", le16_to_cpu(ns->zoc));
	json_object_add_value_int(root, "ozcs", le16_to_cpu(ns->ozcs));
	json_object_add_value_int(root, "mar", le32_to_cpu(ns->mar));
	json_object_add_value_int(root, "mor", le32_to_cpu(ns->mor));
	json_object_add_value_int(root, "rrl", le32_to_cpu(ns->rrl));
	json_object_add_value_int(root, "frl", le32_to_cpu(ns->frl));

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

static void show_nvme_id_ns_zoned_zoc(__le16 ns_zoc)
{
	__u16 zoc = le16_to_cpu(ns_zoc);
	__u8 rsvd = (zoc & 0xfffc) >> 2;
	__u8 ze = (zoc & 0x2) >> 1;
	__u8 vzc = zoc & 0x1;
	if (rsvd)
		printf(" [15:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] : %#x\t  Zone Active Excursions: %s\n",
		ze, ze ? "Yes (Host support required)" : "No");
	printf("  [0:0] : %#x\t  Variable Zone Capacity: %s\n",
		vzc, vzc ? "Yes (Host support required)" : "No");
	printf("\n");
}

static void show_nvme_id_ns_zoned_ozcs(__le16 ns_ozcs)
{
	__u16 ozcs = le16_to_cpu(ns_ozcs);
	__u8 rsvd = (ozcs & 0xfffe) >> 1;
	__u8 razb = ozcs & 0x1;

	if (rsvd)
		printf(" [15:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\t  Read Across Zone Boundaries: %s\n",
		razb, razb ? "Yes" : "No");
}

void nvme_show_zns_id_ns(struct nvme_zns_id_ns *ns,
	struct nvme_id_ns *id_ns, unsigned long flags)
{
	int human = flags & VERBOSE, vs = flags & VS;
	uint8_t lbaf = id_ns->flbas & NVME_NS_FLBAS_LBA_MASK;
	int i;

	if (flags & BINARY)
		return d_raw((unsigned char *)ns, sizeof(*ns));
	else if (flags & JSON)
		return json_nvme_zns_id_ns(ns, id_ns);

	printf("ZNS Command Set Identify Namespace:\n");

	if (human) {
		printf("zoc     : %u\tZone Operation Characteristics\n", le16_to_cpu(ns->zoc));
		show_nvme_id_ns_zoned_zoc(ns->zoc);
	} else {
		printf("zoc     : %u\n", le16_to_cpu(ns->zoc));
	}

	if (human) {
		printf("ozcs    : %u\tOptional Zoned Command Support\n", le16_to_cpu(ns->ozcs));
		show_nvme_id_ns_zoned_ozcs(ns->ozcs);
	} else {
		printf("ozcs    : %u\n", le16_to_cpu(ns->ozcs));
	}

	if (human) {
		if (ns->mar == 0xffffffff) {
			printf("mar     : No Active Resource Limit\n");
		} else {
			printf("mar     : %u\tActive Resources\n", le32_to_cpu(ns->mar) + 1);
		}
	} else {
		printf("mar     : %#x\n", le32_to_cpu(ns->mar));
	}

	if (human) {
		if (ns->mor == 0xffffffff) {
			printf("mor     : No Open Resource Limit\n");
		} else {
			printf("mor     : %u\tOpen Resources\n", le32_to_cpu(ns->mor) + 1);
		}
	} else {
		printf("mor     : %#x\n", le32_to_cpu(ns->mor));
	}

	if (!le32_to_cpu(ns->rrl) && human)
		printf("rrl     : Not Reported\n");
	else
		printf("rrl     : %d\n", le32_to_cpu(ns->rrl));

	if (!le32_to_cpu(ns->frl) && human)
		printf("frl     : Not Reported\n");
	else
		printf("frl     : %d\n", le32_to_cpu(ns->frl));

	for (i = 0; i <= id_ns->nlbaf; i++){
		if (human)
			printf("LBA Format Extension %2d : Zone Size: 0x%"PRIx64" LBAs - "
					"Zone Descriptor Extension Size: %-1d bytes%s\n",
				i, le64_to_cpu(ns->lbafe[i].zsze), ns->lbafe[i].zdes << 6,
				i == lbaf ? " (in use)" : "");
		else
			printf("lbafe %2d: zsze:0x%"PRIx64" zdes:%u%s\n", i,
				(uint64_t)le64_to_cpu(ns->lbafe[i].zsze),
				ns->lbafe[i].zdes, i == lbaf ? " (in use)" : "");
	}

	if (vs) {
		printf("vs[]    :\n");
		d(ns->vs, sizeof(ns->vs), 16, 1);
	}
}

void nvme_show_zns_changed(struct nvme_zns_changed_zone_log *log,
	unsigned long flags)
{
	uint16_t nrzid;
	int i;

	if (flags & BINARY)
		return d_raw((unsigned char *)log, sizeof(*log));

	nrzid = le16_to_cpu(log->nrzid);
	printf("NVMe Changed Zone List:\n");

	if (nrzid == 0xFFFF) {
		printf("Too many zones have changed to fit into the log. Use report zones for changes.\n");
		return;
	}

	printf("nrzid:  %u\n", nrzid);
	for (i = 0; i < nrzid; i++)
		printf("zid %03d: %"PRIu64"\n", i, (uint64_t)le64_to_cpu(log->zid[i]));
}

char *zone_type_to_string(__u8 cond)
{
	switch (cond) {
	case NVME_ZONE_TYPE_SEQWRITE_REQ:
		return "SEQWRITE_REQ";
	default:
		return "Unknown";
	}
}

char *zone_state_to_string(__u8 state)
{
	switch (state) {
	case NVME_ZNS_ZS_EMPTY:
		return "EMPTY";
	case NVME_ZNS_ZS_IMPL_OPEN:
		return "IMP_OPENED";
	case NVME_ZNS_ZS_EXPL_OPEN:
		return "EXP_OPENED";
	case NVME_ZNS_ZS_CLOSED:
		return "CLOSED";
	case NVME_ZNS_ZS_READ_ONLY:
		return "READONLY";
	case NVME_ZNS_ZS_FULL:
		return "FULL";
	case NVME_ZNS_ZS_OFFLINE:
		return "OFFLINE";
	default:
		return "Unknown State";
	}
}

void nvme_show_zns_report_zones(void *report, __u32 descs,
	__u8 ext_size, __u32 report_size, unsigned long flags)
{
	struct nvme_zone_report *r = report;
	struct nvme_zns_desc *desc;
	int i;

	__u64 nr_zones = le64_to_cpu(r->nr_zones);

	if (nr_zones < descs)
		descs = nr_zones;

	if (flags & BINARY)
		return d_raw((unsigned char *)report, report_size);

	printf("nr_zones: %"PRIu64"\n", (uint64_t)le64_to_cpu(r->nr_zones));
	for (i = 0; i < descs; i++) {
		desc = (struct nvme_zns_desc *)
			(report + sizeof(*r) + i * (sizeof(*desc) + ext_size));
		printf("SLBA: 0x%-8"PRIx64" WP: 0x%-8"PRIx64" Cap: 0x%-8"PRIx64" State: %-12s Type: %-14s Attrs: 0x%-x\n",
		(uint64_t)le64_to_cpu(desc->zslba), (uint64_t)le64_to_cpu(desc->wp),
		(uint64_t)le64_to_cpu(desc->zcap), zone_state_to_string(desc->zs >> 4),
		zone_type_to_string(desc->zt), desc->za);

		if (ext_size) {
			printf("Extension Data: ");
			if (desc->za & NVME_ZNS_ZA_ZDEV) {
				d((unsigned char *)desc + sizeof(*desc), ext_size, 16, 1);
				printf("..\n");
			} else {
				printf(" Not valid\n");
			}
		}
	}
}

static void json_nvme_id_nvmset(struct nvme_id_nvmset *nvmset)
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
			  le16_to_cpu(nvmset->ent[i].id));
		json_object_add_value_int(entry, "endurance_group_id",
			  le16_to_cpu(nvmset->ent[i].endurance_group_id));
		json_object_add_value_int(entry, "random_4k_read_typical",
			  le32_to_cpu(nvmset->ent[i].random_4k_read_typical));
		json_object_add_value_int(entry, "optimal_write_size",
			  le32_to_cpu(nvmset->ent[i].opt_write_size));
		json_object_add_value_float(entry, "total_nvmset_cap",
			    int128_to_double(nvmset->ent[i].total_nvmset_cap));
		json_object_add_value_float(entry, "unalloc_nvmset_cap",
			    int128_to_double(nvmset->ent[i].unalloc_nvmset_cap));
		json_array_add_value_object(entries, entry);
	}

	json_object_add_value_array(root, "NVMSet", entries);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void nvme_show_id_nvmset(struct nvme_id_nvmset *nvmset, unsigned nvmset_id,
	enum nvme_print_flags flags)
{
	int i;

	if (flags & BINARY)
		return d_raw((unsigned char *)nvmset, sizeof(*nvmset));
	if (flags & JSON)
		return json_nvme_id_nvmset(nvmset);

	printf("NVME Identify NVM Set List %d:\n", nvmset_id);
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

static void json_nvme_primary_ctrl_caps(const struct nvme_primary_ctrl_caps *caps)
{
	struct json_object *root;

	root = json_create_object();

	json_object_add_value_uint(root, "cntlid", le16_to_cpu(caps->cntlid));
	json_object_add_value_uint(root, "portid", le16_to_cpu(caps->portid));
	json_object_add_value_uint(root, "crt",    caps->crt);

	json_object_add_value_int(root, "vqfrt",  le32_to_cpu(caps->vqfrt));
	json_object_add_value_int(root, "vqrfa",  le32_to_cpu(caps->vqrfa));
	json_object_add_value_int(root, "vqrfap", le16_to_cpu(caps->vqrfap));
	json_object_add_value_int(root, "vqprt",  le16_to_cpu(caps->vqprt));
	json_object_add_value_int(root, "vqfrsm", le16_to_cpu(caps->vqfrsm));
	json_object_add_value_int(root, "vqgran", le16_to_cpu(caps->vqgran));

	json_object_add_value_int(root, "vifrt",  le32_to_cpu(caps->vifrt));
	json_object_add_value_int(root, "virfa",  le32_to_cpu(caps->virfa));
	json_object_add_value_int(root, "virfap", le16_to_cpu(caps->virfap));
	json_object_add_value_int(root, "viprt",  le16_to_cpu(caps->viprt));
	json_object_add_value_int(root, "vifrsm", le16_to_cpu(caps->vifrsm));
	json_object_add_value_int(root, "vigran", le16_to_cpu(caps->vigran));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void nvme_show_primary_ctrl_caps_crt(__u8 crt)
{
	__u8 rsvd = (crt & 0xFC) >> 2;
	__u8 vi = (crt & 0x2) >> 1;
	__u8 vq = crt & 0x1;

	if (rsvd)
		printf("  [7:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] %#x\tVI Resources are %ssupported\n", vi, vi ? "" : "not ");
	printf("  [0:0] %#x\tVQ Resources are %ssupported\n", vq, vq ? "" : "not ");
}

void nvme_show_primary_ctrl_caps(const struct nvme_primary_ctrl_caps *caps,
				 enum nvme_print_flags flags)
{
	int human = flags & VERBOSE;

	if (flags & BINARY)
		return d_raw((unsigned char *)caps, sizeof(*caps));
	else if (flags & JSON)
		return json_nvme_primary_ctrl_caps(caps);

	printf("NVME Identify Primary Controller Capabilities:\n");
	printf("cntlid    : %#x\n", le16_to_cpu(caps->cntlid));
	printf("portid    : %#x\n", le16_to_cpu(caps->portid));
	printf("crt       : %#x\n", caps->crt);
	if (human)
		nvme_show_primary_ctrl_caps_crt(caps->crt);
	printf("vqfrt     : %d\n", le32_to_cpu(caps->vqfrt));
	printf("vqrfa     : %d\n", le32_to_cpu(caps->vqrfa));
	printf("vqrfap    : %d\n", le16_to_cpu(caps->vqrfap));
	printf("vqprt     : %d\n", le16_to_cpu(caps->vqprt));
	printf("vqfrsm    : %d\n", le16_to_cpu(caps->vqfrsm));
	printf("vqgran    : %d\n", le16_to_cpu(caps->vqgran));
	printf("vifrt     : %d\n", le32_to_cpu(caps->vifrt));
	printf("virfa     : %d\n", le32_to_cpu(caps->virfa));
	printf("virfap    : %d\n", le16_to_cpu(caps->virfap));
	printf("viprt     : %d\n", le16_to_cpu(caps->viprt));
	printf("vifrsm    : %d\n", le16_to_cpu(caps->vifrsm));
	printf("vigran    : %d\n", le16_to_cpu(caps->vigran));
}

static void json_nvme_list_secondary_ctrl(const struct nvme_secondary_controllers_list *sc_list,
					  __u32 count)
{
	const struct nvme_secondary_controller_entry *sc_entry = &sc_list->sc_entry[0];
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

void nvme_show_list_secondary_ctrl(
	const struct nvme_secondary_controllers_list *sc_list,
	__u32 count, enum nvme_print_flags flags)
{
	const struct nvme_secondary_controller_entry *sc_entry =
		&sc_list->sc_entry[0];
	static const char * const state_desc[] = { "Offline", "Online" };

	__u16 num = sc_list->num;
	__u32 entries = min(num, count);
	int i;

	if (flags & BINARY)
		return d_raw((unsigned char *)sc_list, sizeof(*sc_list));
	if (flags & JSON)
		return json_nvme_list_secondary_ctrl(sc_list, entries);

	printf("Identify Secondary Controller List:\n");
	printf("   NUMID       : Number of Identifiers           : %d\n", num);

	for (i = 0; i < entries; i++) {
		printf("   SCEntry[%-3d]:\n", i);
		printf("................\n");
		printf("     SCID      : Secondary Controller Identifier : 0x%.04x\n",
				le16_to_cpu(sc_entry[i].scid));
		printf("     PCID      : Primary Controller Identifier   : 0x%.04x\n",
				le16_to_cpu(sc_entry[i].pcid));
		printf("     SCS       : Secondary Controller State      : 0x%.04x (%s)\n",
				sc_entry[i].scs,
				state_desc[sc_entry[i].scs & 0x1]);
		printf("     VFN       : Virtual Function Number         : 0x%.04x\n",
				le16_to_cpu(sc_entry[i].vfn));
		printf("     NVQ       : Num VQ Flex Resources Assigned  : 0x%.04x\n",
				le16_to_cpu(sc_entry[i].nvq));
		printf("     NVI       : Num VI Flex Resources Assigned  : 0x%.04x\n",
				le16_to_cpu(sc_entry[i].nvi));
	}
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

		json_object_add_value_uint(entry, "namespace-size-granularity",
			le64_to_cpu(glist->entry[i].namespace_size_granularity));
		json_object_add_value_uint(entry, "namespace-capacity-granularity",
			le64_to_cpu(glist->entry[i].namespace_capacity_granularity));
		json_array_add_value_object(entries, entry);
	}

	json_object_add_value_array(root, "namespace-granularity-list", entries);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void nvme_show_id_ns_granularity_list(const struct nvme_id_ns_granularity_list *glist,
	enum nvme_print_flags flags)
{
	int i;

	if (flags & BINARY)
		return d_raw((unsigned char *)glist, sizeof(*glist));
	if (flags & JSON)
		return json_nvme_id_ns_granularity_list(glist);

	printf("Identify Namespace Granularity List:\n");
	printf("   ATTR        : Namespace Granularity Attributes: 0x%x\n",
		glist->attributes);
	printf("   NUMD        : Number of Descriptors           : %d\n",
		glist->num_descriptors);

	/* Number of Descriptors is a 0's based value */
	for (i = 0; i <= glist->num_descriptors; i++) {
		printf("\n     Entry[%2d] :\n", i);
		printf("................\n");
		printf("     NSG       : Namespace Size Granularity     : 0x%"PRIx64"\n",
			le64_to_cpu(glist->entry[i].namespace_size_granularity));
		printf("     NCG       : Namespace Capacity Granularity : 0x%"PRIx64"\n",
			le64_to_cpu(glist->entry[i].namespace_capacity_granularity));
	}
}

static void json_nvme_id_uuid_list(const struct nvme_id_uuid_list *uuid_list)
{
	struct json_object *root;
	struct json_object *entries;
	int i;

	root = json_create_object();
	entries = json_create_array();
	/* The 0th entry is reserved */
	for (i = 1; i < NVME_MAX_UUID_ENTRIES; i++) {
		uuid_t uuid;
		struct json_object *entry = json_create_object();

		/* The list is terminated by a zero UUID value */
		if (memcmp(uuid_list->entry[i].uuid, zero_uuid, sizeof(zero_uuid)) == 0)
			break;
		memcpy(&uuid, uuid_list->entry[i].uuid, sizeof(uuid));
		json_object_add_value_int(entry, "association",
			uuid_list->entry[i].header & 0x3);
		json_object_add_value_string(entry, "uuid",
			nvme_uuid_to_string(uuid));
		json_array_add_value_object(entries, entry);
	}
	json_object_add_value_array(root, "UUID-list", entries);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

void nvme_show_id_uuid_list(const struct nvme_id_uuid_list *uuid_list,
				enum nvme_print_flags flags)
{
	int i, human = flags & VERBOSE;

	if (flags & BINARY)
		return d_raw((unsigned char *)uuid_list, sizeof(*uuid_list));
	if (flags & JSON)
		return json_nvme_id_uuid_list(uuid_list);

	/* The 0th entry is reserved */
	printf("NVME Identify UUID:\n");
	for (i = 1; i < NVME_MAX_UUID_ENTRIES; i++) {
		uuid_t uuid;
		char *association = "";
		uint8_t identifier_association = uuid_list->entry[i].header & 0x3;
		/* The list is terminated by a zero UUID value */
		if (memcmp(uuid_list->entry[i].uuid, zero_uuid, sizeof(zero_uuid)) == 0)
			break;
		memcpy(&uuid, uuid_list->entry[i].uuid, sizeof(uuid));
		if (human) {
			switch (identifier_association) {
			case 0x0:
				association = "No association reported";
				break;
			case 0x1:
				association = "associated with PCI Vendor ID";
				break;
			case 0x2:
				association = "associated with PCI Subsystem Vendor ID";
				break;
			default:
				association = "Reserved";
				break;
			}
		}
		printf(" Entry[%3d]\n", i);
		printf(".................\n");
		printf("association  : 0x%x %s\n", identifier_association, association);
		printf("UUID         : %s", nvme_uuid_to_string(uuid));
		if (memcmp(uuid_list->entry[i].uuid, invalid_uuid,
			   sizeof(zero_uuid)) == 0)
			printf(" (Invalid UUID)");
		printf("\n.................\n");
	}
}

void nvme_show_id_iocs(struct nvme_id_iocs *iocs)
{
	__u16 i;

	for (i = 0; i < 512; i++)
		if (iocs->iocs[i])
			printf("I/O Command Set Combination[%u]:%"PRIx64"\n", i,
				(uint64_t)le64_to_cpu(iocs->iocs[i]));
}

static const char *nvme_trtype_to_string(__u8 trtype)
{
	switch (trtype) {
	case 0: return "The transport type is not indicated or the error "\
		"is not transport related.";
	case 1: return "RDMA Transport error.";
	case 2: return "Fibre Channel Transport error.";
	case 3: return "TCP Transport error.";
	case 254: return "Intra-host Transport error.";
	default: return "Reserved";
	};
}

void nvme_show_error_log(struct nvme_error_log_page *err_log, int entries,
			const char *devname, enum nvme_print_flags flags)
{
	int i;

	if (flags & BINARY)
		return d_raw((unsigned char *)err_log,
			     entries * sizeof(*err_log));
	else if (flags & JSON)
		return json_error_log(err_log, entries);

	printf("Error Log Entries for device:%s entries:%d\n", devname,
								entries);
	printf(".................\n");
	for (i = 0; i < entries; i++) {
		printf(" Entry[%2d]   \n", i);
		printf(".................\n");
		printf("error_count	: %"PRIu64"\n",
			le64_to_cpu(err_log[i].error_count));
		printf("sqid		: %d\n", err_log[i].sqid);
		printf("cmdid		: %#x\n", err_log[i].cmdid);
		printf("status_field	: %#x(%s)\n", err_log[i].status_field >> 0x1,
			nvme_status_to_string(
				le16_to_cpu(err_log[i].status_field) >> 1));
		printf("phase_tag	: %#x\n",
			le16_to_cpu(err_log[i].status_field & 0x1));
		printf("parm_err_loc	: %#x\n",
			err_log[i].parm_error_location);
		printf("lba		: %#"PRIx64"\n",
			le64_to_cpu(err_log[i].lba));
		printf("nsid		: %#x\n", err_log[i].nsid);
		printf("vs		: %d\n", err_log[i].vs);
		printf("trtype		: %s\n",
			nvme_trtype_to_string(err_log[i].trtype));
		printf("cs		: %#"PRIx64"\n",
		       le64_to_cpu(err_log[i].cs));
		printf("trtype_spec_info: %#x\n", err_log[i].trtype_spec_info);
		printf(".................\n");
	}
}

void nvme_show_resv_report(struct nvme_reservation_status *status, int bytes,
	__u32 cdw11, enum nvme_print_flags flags)
{
	int i, j, regctl, entries;

	if (flags & BINARY)
		return d_raw((unsigned char *)status, bytes);
	else if (flags & JSON)
		return json_nvme_resv_report(status, bytes, cdw11);

	regctl = status->regctl[0] | (status->regctl[1] << 8);

	printf("\nNVME Reservation status:\n\n");
	printf("gen       : %d\n", le32_to_cpu(status->gen));
	printf("rtype     : %d\n", status->rtype);
	printf("regctl    : %d\n", regctl);
	printf("ptpls     : %d\n", status->ptpls);

	/* check Extended Data Structure bit */
	if ((cdw11 & 0x1) == 0) {
		/*
		 * if status buffer was too small, don't loop past the end of
		 * the buffer
		 */
		entries = (bytes - 24) / 24;
		if (entries < regctl)
			regctl = entries;

		for (i = 0; i < regctl; i++) {
			printf("regctl[%d] :\n", i);
			printf("  cntlid  : %x\n",
				le16_to_cpu(status->regctl_ds[i].cntlid));
			printf("  rcsts   : %x\n",
				status->regctl_ds[i].rcsts);
			printf("  hostid  : %"PRIx64"\n",
				le64_to_cpu(status->regctl_ds[i].hostid));
			printf("  rkey    : %"PRIx64"\n",
				le64_to_cpu(status->regctl_ds[i].rkey));
		}
	} else {
		struct nvme_reservation_status_ext *ext_status =
			(struct nvme_reservation_status_ext *)status;
		/* if status buffer was too small, don't loop past the end of the buffer */
		entries = (bytes - 64) / 64;
		if (entries < regctl)
			regctl = entries;

		for (i = 0; i < regctl; i++) {
			printf("regctlext[%d] :\n", i);
			printf("  cntlid     : %x\n",
				le16_to_cpu(ext_status->regctl_eds[i].cntlid));
			printf("  rcsts      : %x\n",
				ext_status->regctl_eds[i].rcsts);
			printf("  rkey       : %"PRIx64"\n",
				le64_to_cpu(ext_status->regctl_eds[i].rkey));
			printf("  hostid     : ");
			for (j = 0; j < 16; j++)
				printf("%x",
					ext_status->regctl_eds[i].hostid[j]);
			printf("\n");
		}
	}
	printf("\n");
}

void nvme_show_fw_log(struct nvme_firmware_log_page *fw_log,
	const char *devname, enum nvme_print_flags flags)
{
	int i;

	if (flags & BINARY)
		return d_raw((unsigned char *)fw_log, sizeof(*fw_log));
	if (flags & JSON)
		return json_fw_log(fw_log, devname);

	printf("Firmware Log for device:%s\n", devname);
	printf("afi  : %#x\n", fw_log->afi);
	for (i = 0; i < 7; i++) {
		if (fw_log->frs[i])
			printf("frs%d : %#016"PRIx64" (%s)\n", i + 1,
				(uint64_t)fw_log->frs[i],
				fw_to_string(fw_log->frs[i]));
	}
}

void nvme_show_changed_ns_list_log(struct nvme_changed_ns_list_log *log,
				   const char *devname,
				   enum nvme_print_flags flags)
{
	__u32 nsid;
	int i;

	if (flags & BINARY)
		return d_raw((unsigned char *)log, sizeof(*log));
	else if (flags & JSON)
		return json_changed_ns_list_log(log, devname);

	if (log->log[0] != cpu_to_le32(0XFFFFFFFF)) {
		for (i = 0; i < NVME_MAX_CHANGED_NAMESPACES; i++) {
			nsid = le32_to_cpu(log->log[i]);
			if (nsid == 0)
				break;

			printf("[%4u]:%#x\n", i, nsid);
		}
	} else
		printf("more than %d ns changed\n",
			NVME_MAX_CHANGED_NAMESPACES);
}

static void nvme_show_effects_log_human(__u32 effect)
{
	const char *set = "+";
	const char *clr = "-";

	printf("  CSUPP+");
	printf("  LBCC%s", (effect & NVME_CMD_EFFECTS_LBCC) ? set : clr);
	printf("  NCC%s", (effect & NVME_CMD_EFFECTS_NCC) ? set : clr);
	printf("  NIC%s", (effect & NVME_CMD_EFFECTS_NIC) ? set : clr);
	printf("  CCC%s", (effect & NVME_CMD_EFFECTS_CCC) ? set : clr);
	printf("  USS%s", (effect & NVME_CMD_EFFECTS_UUID_SEL) ? set : clr);

	if ((effect & NVME_CMD_EFFECTS_CSE_MASK) >> 16 == 0)
		printf("  No command restriction\n");
	else if ((effect & NVME_CMD_EFFECTS_CSE_MASK) >> 16 == 1)
		printf("  No other command for same namespace\n");
	else if ((effect & NVME_CMD_EFFECTS_CSE_MASK) >> 16 == 2)
		printf("  No other command for any namespace\n");
	else
		printf("  Reserved CSE\n");
}

void nvme_show_effects_log(struct nvme_effects_log_page *effects,
			   unsigned int flags)
{
	int i, human = flags & VERBOSE;
	__u32 effect;

	if (flags & BINARY)
		return d_raw((unsigned char *)effects, sizeof(*effects));
	else if (flags & JSON)
		return json_effects_log(effects);

	printf("Admin Command Set\n");
	for (i = 0; i < 256; i++) {
		effect = le32_to_cpu(effects->acs[i]);
		if (effect & NVME_CMD_EFFECTS_CSUPP) {
			printf("ACS%-6d[%-32s] %08x", i,
					nvme_cmd_to_string(1, i), effect);
			if (human)
				nvme_show_effects_log_human(effect);
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
				nvme_show_effects_log_human(effect);
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

void nvme_show_endurance_log(struct nvme_endurance_group_log *endurance_log,
			     __u16 group_id, const char *devname,
			     enum nvme_print_flags flags)
{
	if (flags & BINARY)
		return d_raw((unsigned char *)endurance_log,
			sizeof(*endurance_log));
	else if (flags & JSON)
		return json_endurance_log(endurance_log, group_id);

	printf("Endurance Group Log for NVME device:%s Group ID:%x\n", devname,
		group_id);
	printf("critical warning	: %u\n",
		endurance_log->critical_warning);
	printf("avl_spare		: %u\n", endurance_log->avl_spare);
	printf("avl_spare_threshold	: %u\n",
		endurance_log->avl_spare_threshold);
	printf("percent_used		: %u%%\n", endurance_log->percent_used);
	printf("endurance_estimate	: %'.0Lf\n",
		int128_to_double(endurance_log->endurance_estimate));
	printf("data_units_read		: %'.0Lf\n",
		int128_to_double(endurance_log->data_units_read));
	printf("data_units_written	: %'.0Lf\n",
		int128_to_double(endurance_log->data_units_written));
	printf("media_units_written	: %'.0Lf\n",
		int128_to_double(endurance_log->media_units_written));
	printf("host_read_cmds		: %'.0Lf\n",
		int128_to_double(endurance_log->host_read_cmds));
	printf("host_write_cmds		: %'.0Lf\n",
		int128_to_double(endurance_log->host_write_cmds));
	printf("media_data_integrity_err: %'.0Lf\n",
		int128_to_double(endurance_log->media_data_integrity_err));
	printf("num_err_info_log_entries: %'.0Lf\n",
		int128_to_double(endurance_log->num_err_info_log_entries));
}

void nvme_show_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
			 const char *devname, enum nvme_print_flags flags)
{
	/* convert temperature from Kelvin to Celsius */
	int temperature = ((smart->temperature[1] << 8) |
			    smart->temperature[0]) - 273;
	int i, human = flags & VERBOSE;

	if (flags & BINARY)
		return d_raw((unsigned char *)smart, sizeof(*smart));
	else if (flags & JSON)
		return json_smart_log(smart, nsid, flags);

	printf("Smart Log for NVME device:%s namespace-id:%x\n", devname, nsid);
	printf("critical_warning			: %#x\n",
		smart->critical_warning);

	if (human) {
		printf("      Available Spare[0]             : %d\n", smart->critical_warning & 0x01);
		printf("      Temp. Threshold[1]             : %d\n", (smart->critical_warning & 0x02) >> 1);
		printf("      NVM subsystem Reliability[2]   : %d\n", (smart->critical_warning & 0x04) >> 2);
		printf("      Read-only[3]                   : %d\n", (smart->critical_warning & 0x08) >> 3);
		printf("      Volatile mem. backup failed[4] : %d\n", (smart->critical_warning & 0x10) >> 4);
		printf("      Persistent Mem. RO[5]          : %d\n", (smart->critical_warning & 0x20) >> 5);
	}

	printf("temperature				: %d C\n",
		temperature);
	printf("available_spare				: %u%%\n",
		smart->avail_spare);
	printf("available_spare_threshold		: %u%%\n",
		smart->spare_thresh);
	printf("percentage_used				: %u%%\n",
		smart->percent_used);
	printf("endurance group critical warning summary: %#x\n",
		smart->endu_grp_crit_warn_sumry);
	printf("data_units_read				: %'.0Lf\n",
		int128_to_double(smart->data_units_read));
	printf("data_units_written			: %'.0Lf\n",
		int128_to_double(smart->data_units_written));
	printf("host_read_commands			: %'.0Lf\n",
		int128_to_double(smart->host_reads));
	printf("host_write_commands			: %'.0Lf\n",
		int128_to_double(smart->host_writes));
	printf("controller_busy_time			: %'.0Lf\n",
		int128_to_double(smart->ctrl_busy_time));
	printf("power_cycles				: %'.0Lf\n",
		int128_to_double(smart->power_cycles));
	printf("power_on_hours				: %'.0Lf\n",
		int128_to_double(smart->power_on_hours));
	printf("unsafe_shutdowns			: %'.0Lf\n",
		int128_to_double(smart->unsafe_shutdowns));
	printf("media_errors				: %'.0Lf\n",
		int128_to_double(smart->media_errors));
	printf("num_err_log_entries			: %'.0Lf\n",
		int128_to_double(smart->num_err_log_entries));
	printf("Warning Temperature Time		: %u\n",
		le32_to_cpu(smart->warning_temp_time));
	printf("Critical Composite Temperature Time	: %u\n",
		le32_to_cpu(smart->critical_comp_time));
	for (i = 0; i < 8; i++) {
		__s32 temp = le16_to_cpu(smart->temp_sensor[i]);

		if (temp == 0)
			continue;
		printf("Temperature Sensor %d           : %d C\n", i + 1,
			temp - 273);
	}
	printf("Thermal Management T1 Trans Count	: %u\n",
		le32_to_cpu(smart->thm_temp1_trans_count));
	printf("Thermal Management T2 Trans Count	: %u\n",
		le32_to_cpu(smart->thm_temp2_trans_count));
	printf("Thermal Management T1 Total Time	: %u\n",
		le32_to_cpu(smart->thm_temp1_total_time));
	printf("Thermal Management T2 Total Time	: %u\n",
		le32_to_cpu(smart->thm_temp2_total_time));
}

void nvme_show_ana_log(struct nvme_ana_rsp_hdr *ana_log, const char *devname,
			enum nvme_print_flags flags, size_t len)
{
	int offset = sizeof(struct nvme_ana_rsp_hdr);
	struct nvme_ana_rsp_hdr *hdr = ana_log;
	struct nvme_ana_group_desc *desc;
	size_t nsid_buf_size;
	void *base = ana_log;
	__u32 nr_nsids;
	int i, j;

	if (flags & BINARY)
		return d_raw((unsigned char *)ana_log, len);
	else if (flags & JSON)
		return json_ana_log(ana_log, devname);

	printf("Asymmetric Namespace Access Log for NVMe device: %s\n",
			devname);
	printf("ANA LOG HEADER :-\n");
	printf("chgcnt	:	%"PRIu64"\n",
			le64_to_cpu(hdr->chgcnt));
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
		       le64_to_cpu(desc->chgcnt));
		printf("state	:	%s\n",
				nvme_ana_state_to_string(desc->state));
		for (j = 0; j < le32_to_cpu(desc->nnsids); j++)
			printf("	nsid	:	%u\n",
					le32_to_cpu(desc->nsids[j]));
		printf("\n");
		offset += nsid_buf_size;
	}
}

static void nvme_show_self_test_result(struct nvme_self_test_res *res,
			     enum nvme_print_flags flags)
{
	static const char *const test_res[] = {
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
		"Operation was aborted due to a sanitize operation",
		"Reserved",
		[NVME_ST_RES_NOT_USED] = "Entry not used (does not contain a result)",
	};
	__u8 op, code;

	op = res->dsts & NVME_ST_RES_MASK;
	printf("  Operation Result             : %#x", op);
	if (flags & VERBOSE)
		printf(" %s", (op < ARRAY_SIZE(test_res) && test_res[op]) ?
			test_res[op] : test_res[ARRAY_SIZE(test_res) - 1]);
	printf("\n");
	if (op == NVME_ST_RES_NOT_USED)
		return;

	code = res->dsts >> NVME_ST_CODE_SHIFT;
	printf("  Self Test Code               : %x", code);

	if (flags & VERBOSE) {
		switch (code) {
		case NVME_ST_CODE_SHORT_OP:
			printf(" Short device self-test operation");
			break;
		case NVME_ST_CODE_EXT_OP:
			printf(" Extended device self-test operation");
			break;
		case NVME_ST_CODE_VS:
			printf(" Vendor specific");
			break;
		default:
			printf(" Reserved");
			break;
		}
	}
	printf("\n");

	if (op == NVME_ST_RES_KNOWN_SEG_FAIL)
		printf("  Segment Number               : %#x\n", res->seg);

	printf("  Valid Diagnostic Information : %#x\n", res->vdi);
	printf("  Power on hours (POH)         : %#"PRIx64"\n",
		(uint64_t)le64_to_cpu(res->poh));

	if (res->vdi & NVME_ST_VALID_NSID)
		printf("  Namespace Identifier         : %#x\n",
			le32_to_cpu(res->nsid));
	if (res->vdi & NVME_ST_VALID_FLBA)
		printf("  Failing LBA                  : %#"PRIx64"\n",
			(uint64_t)le64_to_cpu(res->flba));
	if (res->vdi & NVME_ST_VALID_SCT)
		printf("  Status Code Type             : %#x\n", res->sct);
	if (res->vdi & NVME_ST_VALID_SC) {
		printf("  Status Code                  : %#x", res->sc);
		if (flags & VERBOSE)
			printf(" %s", nvme_status_to_string(
				(res->sct & 7) << 8 | res->sc));
		printf("\n");
	}
	printf("  Vendor Specific              : %#x %#x\n",
		res->vs[0], res->vs[1]);
}

void nvme_show_self_test_log(struct nvme_self_test_log *self_test, __u8 dst_entries,
				__u32 size, const char *devname, enum nvme_print_flags flags)
{
	int i;
	__u8 num_entries;

	if (flags & BINARY)
		return d_raw((unsigned char *)self_test, size);
	if (flags & JSON)
		return json_self_test_log(self_test, dst_entries);

	printf("Device Self Test Log for NVME device:%s\n", devname);
	printf("Current operation  : %#x\n", self_test->crnt_dev_selftest_oprn);
	printf("Current Completion : %u%%\n", self_test->crnt_dev_selftest_compln);
	num_entries = min(dst_entries, NVME_ST_REPORTS);
	for (i = 0; i < num_entries; i++) {
		printf("Self Test Result[%d]:\n", i);
		nvme_show_self_test_result(&self_test->result[i], flags);
	}
}

static void nvme_show_sanitize_log_sprog(__u32 sprog)
{
	double percent;

	percent = (((double)sprog * 100) / 0x10000);
	printf("\t(%f%%)\n", percent);
}

static void nvme_show_sanitize_log_sstat(__u16 status)
{
	const char *str = get_sanitize_log_sstat_status_str(status);

	printf("\t[2:0]\t%s\n", str);
	str = "Number of completed passes if most recent operation was overwrite";
	printf("\t[7:3]\t%s:\t%u\n", str,
		(status & NVME_SANITIZE_LOG_NUM_CMPLTED_PASS_MASK) >> 3);

	printf("\t  [8]\t");
	if (status & NVME_SANITIZE_LOG_GLOBAL_DATA_ERASED)
		str = "Global Data Erased set: no NS LB in the NVM subsystem "\
			"has been written to and no PMR in the NVM subsystem "\
			"has been enabled";
	else
		str = "Global Data Erased cleared: a NS LB in the NVM "\
			"subsystem has been written to or a PMR in the NVM "\
			"subsystem has been enabled";
	printf("%s\n", str);
}

static void nvme_show_estimate_sanitize_time(const char *text, uint32_t value)
{
	printf("%s:  %u%s\n", text, value,
		value == 0xffffffff ? " (No time period reported)" : "");
}

void nvme_show_sanitize_log(struct nvme_sanitize_log_page *sanitize,
			    const char *devname, enum nvme_print_flags flags)
{
	int human = flags & VERBOSE;
	__u16 status = le16_to_cpu(sanitize->status) & NVME_SANITIZE_LOG_STATUS_MASK;

	if (flags & BINARY)
		d_raw((unsigned char *)sanitize, sizeof(*sanitize));
	else if (flags & JSON) {
		json_sanitize_log(sanitize, devname);
		return;
	}

	printf("Sanitize Progress                      (SPROG) :  %u",
	       le16_to_cpu(sanitize->progress));

	if (human && status == NVME_SANITIZE_LOG_IN_PROGESS)
		nvme_show_sanitize_log_sprog(le16_to_cpu(sanitize->progress));
	else
		printf("\n");

	printf("Sanitize Status                        (SSTAT) :  %#x\n",
		le16_to_cpu(sanitize->status));
	if (human)
		nvme_show_sanitize_log_sstat(le16_to_cpu(sanitize->status));

	printf("Sanitize Command Dword 10 Information (SCDW10) :  %#x\n",
		le32_to_cpu(sanitize->cdw10_info));
	nvme_show_estimate_sanitize_time("Estimated Time For Overwrite                   ",
		le32_to_cpu(sanitize->est_ovrwrt_time));
	nvme_show_estimate_sanitize_time("Estimated Time For Block Erase                 ",
		le32_to_cpu(sanitize->est_blk_erase_time));
	nvme_show_estimate_sanitize_time("Estimated Time For Crypto Erase                ",
		le32_to_cpu(sanitize->est_crypto_erase_time));
	nvme_show_estimate_sanitize_time("Estimated Time For Overwrite (No-Deallocate)   ",
		le32_to_cpu(sanitize->est_ovrwrt_time_with_no_deallocate));
	nvme_show_estimate_sanitize_time("Estimated Time For Block Erase (No-Deallocate) ",
		le32_to_cpu(sanitize->est_blk_erase_time_with_no_deallocate));
	nvme_show_estimate_sanitize_time("Estimated Time For Crypto Erase (No-Deallocate)",
		le32_to_cpu(sanitize->est_crypto_erase_time_with_no_deallocate));
}

const char *nvme_feature_to_string(enum nvme_feat feature)
{
	switch (feature) {
	case NVME_FEAT_NONE:		return "Reserved";
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
	case NVME_LBA_STATUS_INFO:	return "LBA Status Infomation Attributes";
      case NVME_FEAT_ENDURANCE:       return "Enduarance Event Group Configuration";
	case NVME_FEAT_IOCS_PROFILE:	return "I/O Command Set Profile";
	case NVME_FEAT_SW_PROGRESS:	return "Software Progress";
	case NVME_FEAT_HOST_ID:		return "Host Identifier";
	case NVME_FEAT_RESV_MASK:	return "Reservation Notification Mask";
	case NVME_FEAT_RESV_PERSIST:	return "Reservation Persistence";
	case NVME_FEAT_TIMESTAMP:	return "Timestamp";
	case NVME_FEAT_WRITE_PROTECT:	return "Namespce Write Protect";
	case NVME_FEAT_HCTM:		return "Host Controlled Thermal Management";
	case NVME_FEAT_HOST_BEHAVIOR:   return "Host Behavior";
	case NVME_FEAT_SANITIZE:	return "Sanitize";
	}
	/*
	 * We don't use the "default:" statement to let the compiler warning if
	 * some values of the enum nvme_feat are missing in the switch().
	 * The following return is acting as the default: statement.
	 */
	return "Unknown";
}

const char *nvme_register_to_string(int reg)
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
	default:		return "Unknown";
	}
}

const char *nvme_select_to_string(int sel)
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

const char *nvme_status_to_string(__u16 status)
{
	switch (status & 0x7ff) {
	case NVME_SC_SUCCESS:
		return "SUCCESS: The command completed successfully";
	case NVME_SC_INVALID_OPCODE:
		return "INVALID_OPCODE: The associated command opcode field is not valid";
	case NVME_SC_INVALID_FIELD:
		return "INVALID_FIELD: A reserved coded value or an unsupported value in a defined field";
	case NVME_SC_CMDID_CONFLICT:
		return "CMDID_CONFLICT: The command identifier is already in use";
	case NVME_SC_DATA_XFER_ERROR:
		return "DATA_XFER_ERROR: Error while trying to transfer the data or metadata";
	case NVME_SC_POWER_LOSS:
		return "POWER_LOSS: Command aborted due to power loss notification";
	case NVME_SC_INTERNAL:
		return "INTERNAL: The command was not completed successfully due to an internal error";
	case NVME_SC_ABORT_REQ:
		return "ABORT_REQ: The command was aborted due to a Command Abort request";
	case NVME_SC_ABORT_QUEUE:
		return "ABORT_QUEUE: The command was aborted due to a Delete I/O Submission Queue request";
	case NVME_SC_FUSED_FAIL:
		return "FUSED_FAIL: The command was aborted due to the other command in a fused operation failing";
	case NVME_SC_FUSED_MISSING:
		return "FUSED_MISSING: The command was aborted due to a Missing Fused Command";
	case NVME_SC_INVALID_NS:
		return "INVALID_NS: The namespace or the format of that namespace is invalid";
	case NVME_SC_CMD_SEQ_ERROR:
		return "CMD_SEQ_ERROR: The command was aborted due to a protocol violation in a multicommand sequence";
	case NVME_SC_SGL_INVALID_LAST:
		return "SGL_INVALID_LAST: The command includes an invalid SGL Last Segment or SGL Segment descriptor.";
	case NVME_SC_SGL_INVALID_COUNT:
		return "SGL_INVALID_COUNT: There is an SGL Last Segment descriptor or an SGL Segment descriptor in a location other than the last descriptor of a segment based on the length indicated.";
	case NVME_SC_SGL_INVALID_DATA:
		return "SGL_INVALID_DATA: This may occur if the length of a Data SGL is too short.";
	case NVME_SC_SGL_INVALID_METADATA:
		return "SGL_INVALID_METADATA: This may occur if the length of a Metadata SGL is too short";
	case NVME_SC_SGL_INVALID_TYPE:
		return "SGL_INVALID_TYPE: The type of an SGL Descriptor is a type that is not supported by the controller.";
	case NVME_SC_CMB_INVALID_USE:
		return "CMB_INVALID_USE: The attempted use of the Controller Memory Buffer is not supported by the controller.";
	case NVME_SC_PRP_INVALID_OFFSET:
		return "PRP_INVALID_OFFSET: The Offset field for a PRP entry is invalid.";
	case NVME_SC_ATOMIC_WRITE_UNIT_EXCEEDED:
		return "ATOMIC_WRITE_UNIT_EXCEEDED: The length specified exceeds the atomic write unit size.";
	case NVME_SC_OPERATION_DENIED:
		return "OPERATION_DENIED: The command was denied due to lack of access rights.";
	case NVME_SC_SGL_INVALID_OFFSET:
		return "SGL_INVALID_OFFSET: The offset specified in a descriptor is invalid.";
	case NVME_SC_INCONSISTENT_HOST_ID:
		return "INCONSISTENT_HOST_ID: The NVM subsystem detected the simultaneous use of 64-bit and 128-bit Host Identifier values on different controllers.";
	case NVME_SC_KEEP_ALIVE_EXPIRED:
		return "KEEP_ALIVE_EXPIRED: The Keep Alive Timer expired.";
	case NVME_SC_KEEP_ALIVE_INVALID:
		return "KEEP_ALIVE_INVALID: The Keep Alive Timeout value specified is invalid.";
	case NVME_SC_PREEMPT_ABORT:
		return "PREEMPT_ABORT: The command was aborted due to a Reservation Acquire command with the Reservation Acquire Action (RACQA) set to 010b (Preempt and Abort).";
	case NVME_SC_SANITIZE_FAILED:
		return "SANITIZE_FAILED: The most recent sanitize operation failed and no recovery actions has been successfully completed";
	case NVME_SC_SANITIZE_IN_PROGRESS:
		return "SANITIZE_IN_PROGRESS: The requested function is prohibited while a sanitize operation is in progress";
	case NVME_SC_IOCS_NOT_SUPPORTED:
		return "IOCS_NOT_SUPPORTED: The I/O command set is not supported";
	case NVME_SC_IOCS_NOT_ENABLED:
		return "IOCS_NOT_ENABLED: The I/O command set is not enabled";
	case NVME_SC_IOCS_COMBINATION_REJECTED:
		return "IOCS_COMBINATION_REJECTED: The I/O command set combination is rejected";
	case NVME_SC_INVALID_IOCS:
		return "INVALID_IOCS: the I/O command set is invalid";
	case NVME_SC_LBA_RANGE:
		return "LBA_RANGE: The command references a LBA that exceeds the size of the namespace";
	case NVME_SC_NS_WRITE_PROTECTED:
		return "NS_WRITE_PROTECTED: The command is prohibited while the namespace is write protected by the host.";
	case NVME_SC_TRANSIENT_TRANSPORT:
		return "TRANSIENT_TRANSPORT: A transient transport error was detected.";
	case NVME_SC_CAP_EXCEEDED:
		return "CAP_EXCEEDED: The execution of the command has caused the capacity of the namespace to be exceeded";
	case NVME_SC_NS_NOT_READY:
		return "NS_NOT_READY: The namespace is not ready to be accessed as a result of a condition other than a condition that is reported as an Asymmetric Namespace Access condition";
	case NVME_SC_RESERVATION_CONFLICT:
		return "RESERVATION_CONFLICT: The command was aborted due to a conflict with a reservation held on the accessed namespace";
	case NVME_SC_FORMAT_IN_PROGRESS:
		return "FORMAT_IN_PROGRESS: A Format NVM command is in progress on the namespace.";
	case NVME_SC_ZONE_BOUNDARY_ERROR:
		return "ZONE_BOUNDARY_ERROR: Invalid Zone Boundary crossing";
	case NVME_SC_ZONE_IS_FULL:
		return "ZONE_IS_FULL: The accessed zone is in ZSF:Full state";
	case NVME_SC_ZONE_IS_READ_ONLY:
		return "ZONE_IS_READ_ONLY: The accessed zone is in ZSRO:Read Only state";
	case NVME_SC_ZONE_IS_OFFLINE:
		return "ZONE_IS_OFFLINE: The access zone is in ZSO:Offline state";
	case NVME_SC_ZONE_INVALID_WRITE:
		return "ZONE_INVALID_WRITE: The write to zone was not at the write pointer offset";
	case NVME_SC_TOO_MANY_ACTIVE_ZONES:
		return "TOO_MANY_ACTIVE_ZONES: The controller does not allow additional active zones";
	case NVME_SC_TOO_MANY_OPEN_ZONES:
		return "TOO_MANY_OPEN_ZONES: The controller does not allow additional open zones";
	case NVME_SC_ZONE_INVALID_STATE_TRANSITION:
		return "INVALID_ZONE_STATE_TRANSITION: The zone state change was invalid";
	case NVME_SC_CQ_INVALID:
		return "CQ_INVALID: The Completion Queue identifier specified in the command does not exist";
	case NVME_SC_QID_INVALID:
		return "QID_INVALID: The creation of the I/O Completion Queue failed due to an invalid queue identifier specified as part of the command. An invalid queue identifier is one that is currently in use or one that is outside the range supported by the controller";
	case NVME_SC_QUEUE_SIZE:
		return "QUEUE_SIZE: The host attempted to create an I/O Completion Queue with an invalid number of entries";
	case NVME_SC_ABORT_LIMIT:
		return "ABORT_LIMIT: The number of concurrently outstanding Abort commands has exceeded the limit indicated in the Identify Controller data structure";
	case NVME_SC_ABORT_MISSING:
		return "ABORT_MISSING: The abort command is missing";
	case NVME_SC_ASYNC_LIMIT:
		return "ASYNC_LIMIT: The number of concurrently outstanding Asynchronous Event Request commands has been exceeded";
	case NVME_SC_FIRMWARE_SLOT:
		return "FIRMWARE_SLOT: The firmware slot indicated is invalid or read only. This error is indicated if the firmware slot exceeds the number supported";
	case NVME_SC_FIRMWARE_IMAGE:
		return "FIRMWARE_IMAGE: The firmware image specified for activation is invalid and not loaded by the controller";
	case NVME_SC_INVALID_VECTOR:
		return "INVALID_VECTOR: The creation of the I/O Completion Queue failed due to an invalid interrupt vector specified as part of the command";
	case NVME_SC_INVALID_LOG_PAGE:
		return "INVALID_LOG_PAGE: The log page indicated is invalid. This error condition is also returned if a reserved log page is requested";
	case NVME_SC_INVALID_FORMAT:
		return "INVALID_FORMAT: The LBA Format specified is not supported. This may be due to various conditions";
	case NVME_SC_FW_NEEDS_CONV_RESET:
		return "FW_NEEDS_CONVENTIONAL_RESET: The firmware commit was successful, however, activation of the firmware image requires a conventional reset";
	case NVME_SC_INVALID_QUEUE:
		return "INVALID_QUEUE: This error indicates that it is invalid to delete the I/O Completion Queue specified. The typical reason for this error condition is that there is an associated I/O Submission Queue that has not been deleted.";
	case NVME_SC_FEATURE_NOT_SAVEABLE:
		return "FEATURE_NOT_SAVEABLE: The Feature Identifier specified does not support a saveable value";
	case NVME_SC_FEATURE_NOT_CHANGEABLE:
		return "FEATURE_NOT_CHANGEABLE: The Feature Identifier is not able to be changed";
	case NVME_SC_FEATURE_NOT_PER_NS:
		return "FEATURE_NOT_PER_NS: The Feature Identifier specified is not namespace specific. The Feature Identifier settings apply across all namespaces";
	case NVME_SC_FW_NEEDS_SUBSYS_RESET:
		return "FW_NEEDS_SUBSYSTEM_RESET: The firmware commit was successful, however, activation of the firmware image requires an NVM Subsystem";
	case NVME_SC_FW_NEEDS_RESET:
		return "FW_NEEDS_RESET: The firmware commit was successful; however, the image specified does not support being activated without a reset";
	case NVME_SC_FW_NEEDS_MAX_TIME:
		return "FW_NEEDS_MAX_TIME_VIOLATION: The image specified if activated immediately would exceed the Maximum Time for Firmware Activation (MTFA) value reported in Identify Controller. To activate the firmware, the Firmware Commit command needs to be re-issued and the image activated using a reset";
	case NVME_SC_FW_ACTIVATE_PROHIBITED:
		return "FW_ACTIVATION_PROHIBITED: The image specified is being prohibited from activation by the controller for vendor specific reasons";
	case NVME_SC_OVERLAPPING_RANGE:
		return "OVERLAPPING_RANGE: This error is indicated if the firmware image has overlapping ranges";
	case NVME_SC_NS_INSUFFICIENT_CAP:
		return "NS_INSUFFICIENT_CAPACITY: Creating the namespace requires more free space than is currently available. The Command Specific Information field of the Error Information Log specifies the total amount of NVM capacity required to create the namespace in bytes";
	case NVME_SC_NS_ID_UNAVAILABLE:
		return "NS_ID_UNAVAILABLE: The number of namespaces supported has been exceeded";
	case NVME_SC_NS_ALREADY_ATTACHED:
		return "NS_ALREADY_ATTACHED: The controller is already attached to the namespace specified";
	case NVME_SC_NS_IS_PRIVATE:
		return "NS_IS_PRIVATE: The namespace is private and is already attached to one controller";
	case NVME_SC_NS_NOT_ATTACHED:
		return "NS_NOT_ATTACHED: The request to detach the controller could not be completed because the controller is not attached to the namespace";
	case NVME_SC_THIN_PROV_NOT_SUPP:
		return "THIN_PROVISIONING_NOT_SUPPORTED: Thin provisioning is not supported by the controller";
	case NVME_SC_CTRL_LIST_INVALID:
		return "CONTROLLER_LIST_INVALID: The controller list provided is invalid";
	case NVME_SC_DEVICE_SELF_TEST_IN_PROGRESS:
		return "DEVICE_SELF_TEST_IN_PROGRESS: The controller or NVM subsystem already has a device self-test operation in process.";
	case NVME_SC_BP_WRITE_PROHIBITED:
		return "BOOT PARTITION WRITE PROHIBITED: The command is trying to modify a Boot Partition while it is locked";
	case NVME_SC_INVALID_CTRL_ID:
		return "INVALID_CTRL_ID: An invalid Controller Identifier was specified.";
	case NVME_SC_INVALID_SECONDARY_CTRL_STATE:
		return "INVALID_SECONDARY_CTRL_STATE: The action requested for the secondary controller is invalid based on the current state of the secondary controller and its primary controller.";
	case NVME_SC_INVALID_NUM_CTRL_RESOURCE:
		return "INVALID_NUM_CTRL_RESOURCE: The specified number of Flexible Resources is invalid";
	case NVME_SC_INVALID_RESOURCE_ID:
		return "INVALID_RESOURCE_ID: At least one of the specified resource identifiers was invalid";
	case NVME_SC_ANA_INVALID_GROUP_ID:
		return "ANA_INVALID_GROUP_ID: The specified ANA Group Identifier (ANAGRPID) is not supported in the submitted command.";
	case NVME_SC_ANA_ATTACH_FAIL:
		return "ANA_ATTACH_FAIL: The controller is not attached to the namespace as a result of an ANA condition";
	case NVME_SC_BAD_ATTRIBUTES:
		return "BAD_ATTRIBUTES: Bad attributes were given";
	case NVME_SC_INVALID_PI:
		return "INVALID_PROTECION_INFO: The Protection Information Field settings specified in the command are invalid";
	case NVME_SC_READ_ONLY:
		return "WRITE_ATTEMPT_READ_ONLY_RANGE: The LBA range specified contains read-only blocks";
	case NVME_SC_CMD_SIZE_LIMIT_EXCEEDED:
		return "CMD_SIZE_LIMIT_EXCEEDED: Command size limit exceeded";
	case NVME_SC_WRITE_FAULT:
		return "WRITE_FAULT: The write data could not be committed to the media";
	case NVME_SC_READ_ERROR:
		return "READ_ERROR: The read data could not be recovered from the media";
	case NVME_SC_GUARD_CHECK:
		return "GUARD_CHECK: The command was aborted due to an end-to-end guard check failure";
	case NVME_SC_APPTAG_CHECK:
		return "APPTAG_CHECK: The command was aborted due to an end-to-end application tag check failure";
	case NVME_SC_REFTAG_CHECK:
		return "REFTAG_CHECK: The command was aborted due to an end-to-end reference tag check failure";
	case NVME_SC_COMPARE_FAILED:
		return "COMPARE_FAILED: The command failed due to a miscompare during a Compare command";
	case NVME_SC_ACCESS_DENIED:
		return "ACCESS_DENIED: Access to the namespace and/or LBA range is denied due to lack of access rights";
	case NVME_SC_UNWRITTEN_BLOCK:
		return "UNWRITTEN_BLOCK: The command failed due to an attempt to read from an LBA range containing a deallocated or unwritten logical block";
	case NVME_SC_INTERNAL_PATH_ERROR:
		return "INTERNAL_PATH_ERROT: The command was not completed as the result of a controller internal error";
	case NVME_SC_ANA_PERSISTENT_LOSS:
		return "ASYMMETRIC_NAMESPACE_ACCESS_PERSISTENT_LOSS: The requested function (e.g., command) is not able to be performed as a result of the relationship between the controller and the namespace being in the ANA Persistent Loss state";
	case NVME_SC_ANA_INACCESSIBLE:
		return "ASYMMETRIC_NAMESPACE_ACCESS_INACCESSIBLE: The requested function (e.g., command) is not able to be performed as a result of the relationship between the controller and the namespace being in the ANA Inaccessible state";
	case NVME_SC_ANA_TRANSITION:
		return "ASYMMETRIC_NAMESPACE_ACCESS_TRANSITION: The requested function (e.g., command) is not able to be performed as a result of the relationship between the controller and the namespace transitioning between Asymmetric Namespace Access states";
	case NVME_SC_CTRL_PATHING_ERROR:
		return "CONTROLLER_PATHING_ERROR: A pathing error was detected by the controller";
	case NVME_SC_HOST_PATHING_ERROR:
		return "HOST_PATHING_ERROR: A pathing error was detected by the host";
	case NVME_SC_HOST_CMD_ABORT:
		return "HOST_COMMAND_ABORT: The command was aborted as a result of host action";
	case NVME_SC_CMD_INTERRUPTED:
		return "CMD_INTERRUPTED: Command processing was interrupted and the controller is unable to successfully complete the command. The host should retry the command.";
	case NVME_SC_PMR_SAN_PROHIBITED:
		return "Sanitize Prohibited While Persistent Memory Region is Enabled: A sanitize operation is prohibited while the Persistent Memory Region is enabled.";
	default:
		return "Unknown";
	}
}

static const char *nvme_feature_lba_type_to_string(__u8 type)
{
	switch (type) {
	case 0:	return "Reserved";
	case 1:	return "Filesystem";
	case 2:	return "RAID";
	case 3:	return "Cache";
	case 4:	return "Page / Swap file";
	default:
		if (type >= 0x05 && type <= 0x7f)
			return "Reserved";
		else
			return "Vendor Specific";
	}
}

void nvme_show_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges)
{
	int i, j;

	for (i = 0; i <= nr_ranges; i++) {
		printf("\ttype       : %#x - %s\n", lbrt[i].type,
			nvme_feature_lba_type_to_string(lbrt[i].type));
		printf("\tattributes : %#x - %s, %s\n", lbrt[i].attributes,
			(lbrt[i].attributes & 0x0001) ?
				"LBA range may be overwritten" :
				"LBA range should not be overwritten",
			((lbrt[i].attributes & 0x0002) >> 1) ?
				"LBA range should be hidden from the OS/EFI/BIOS" :
				"LBA range should be visible from the OS/EFI/BIOS");
		printf("\tslba       : %#"PRIx64"\n", (uint64_t)(lbrt[i].slba));
		printf("\tnlb        : %#"PRIx64"\n", (uint64_t)(lbrt[i].nlb));
		printf("\tguid       : ");
		for (j = 0; j < 16; j++)
			printf("%02x", lbrt[i].guid[j]);
		printf("\n");
	}
}


static const char *nvme_feature_wl_hints_to_string(__u8 wh)
{
	switch (wh) {
	case 0:	return "No Workload";
	case 1:	return "Extended Idle Period with a Burst of Random Writes";
	case 2:	return "Heavy Sequential Writes";
	default:return "Reserved";
	}
}

static const char *nvme_feature_temp_type_to_string(__u8 type)
{
	switch (type) {
	case 0:	return "Over Temperature Threshold";
	case 1:	return "Under Temperature Threshold";
	default:return "Reserved";
	}
}

static const char *nvme_feature_temp_sel_to_string(__u8 sel)
{
	switch (sel) {
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

static void nvme_show_auto_pst(struct nvme_auto_pst *apst)
{
	int i;

	printf( "\tAuto PST Entries");
	printf("\t.................\n");
	for (i = 0; i < 32; i++) {
		printf("\tEntry[%2d]   \n", i);
		printf("\t.................\n");
		printf("\tIdle Time Prior to Transition (ITPT): %u ms\n",
			(apst[i].data & 0xffffff00) >> 8);
		printf("\tIdle Transition Power State   (ITPS): %u\n",
			(apst[i].data & 0x000000f8) >> 3);
		printf("\t.................\n");
	}
}

static void nvme_show_timestamp(struct nvme_timestamp *ts)
{
	struct tm *tm;
	char buffer[32];
	time_t timestamp = int48_to_long(ts->timestamp) / 1000;

	tm = localtime(&timestamp);
	strftime(buffer, sizeof(buffer), "%c %Z", tm);

	printf("\tThe timestamp is : %"PRIu64" (%s)\n",
		int48_to_long(ts->timestamp), buffer);
	printf("\t%s\n", (ts->attr & 2) ?
		"The Timestamp field was initialized with a "\
			"Timestamp value using a Set Features command." :
		"The Timestamp field was initialized "\
			"to ‘0’ by a Controller Level Reset.");
	printf("\t%s\n", (ts->attr & 1) ?
		"The controller may have stopped counting during vendor specific "\
			"intervals after the Timestamp value was initialized" :
		"The controller counted time in milliseconds "\
			"continuously since the Timestamp value was initialized.");
}

static void nvme_show_host_mem_buffer(struct nvme_host_mem_buffer *hmb)
{
	printf("\tHost Memory Descriptor List Entry Count (HMDLEC): %u\n",
		le32_to_cpu(hmb->hmdlec));
	printf("\tHost Memory Descriptor List Address     (HMDLAU): 0x%x\n",
		le32_to_cpu(hmb->hmdlau));
	printf("\tHost Memory Descriptor List Address     (HMDLAL): 0x%x\n",
		le32_to_cpu(hmb->hmdlal));
	printf("\tHost Memory Buffer Size                  (HSIZE): %u\n",
		le32_to_cpu(hmb->hsize));
}

static void nvme_directive_show_fields(__u8 dtype, __u8 doper,
				       unsigned int result, unsigned char *buf)
{
	__u8 *field = buf;
	int count, i;

	switch (dtype) {
	case NVME_DIR_IDENTIFY:
		switch (doper) {
		case NVME_DIR_RCV_ID_OP_PARAM:
			printf("\tDirective support \n");
			printf("\t\tIdentify Directive  : %s\n",
				(*field & 0x1) ? "supported":"not supported");
			printf("\t\tStream Directive    : %s\n",
				(*field & 0x2) ? "supported":"not supported");
			printf("\tDirective status \n");
			printf("\t\tIdentify Directive  : %s\n",
				(*(field + 32) & 0x1) ? "enabled" : "disabled");
			printf("\t\tStream Directive    : %s\n",
				(*(field + 32) & 0x2) ? "enabled" : "disabled");
			break;
		default:
			fprintf(stderr,
				"invalid directive operations for Identify Directives\n");
		}
		break;
	case NVME_DIR_STREAMS:
		switch (doper) {
		case NVME_DIR_RCV_ST_OP_PARAM:
			printf("\tMax Streams Limit                          (MSL): %u\n",
				*(__u16 *) field);
			printf("\tNVM Subsystem Streams Available           (NSSA): %u\n",
				*(__u16 *) (field + 2));
			printf("\tNVM Subsystem Streams Open                (NSSO): %u\n",
				*(__u16 *) (field + 4));
			printf("\tNVM Subsystem Stream Capability           (NSSC): %u\n",
				*(__u16 *) (field + 6));
			printf("\tStream Write Size (in unit of LB size)     (SWS): %u\n",
				*(__u32 *) (field + 16));
			printf("\tStream Granularity Size (in unit of SWS)   (SGS): %u\n",
				*(__u16 *) (field + 20));
			printf("\tNamespece Streams Allocated                (NSA): %u\n",
				*(__u16 *) (field + 22));
			printf("\tNamespace Streams Open                     (NSO): %u\n",
				*(__u16 *) (field + 24));
			break;
		case NVME_DIR_RCV_ST_OP_STATUS:
			count = *(__u16 *) field;
			printf("\tOpen Stream Count  : %u\n", *(__u16 *) field);
			for ( i = 0; i < count; i++ ) {
				printf("\tStream Identifier %.6u : %u\n", i + 1,
					*(__u16 *) (field + ((i + 1) * 2)));
			}
			break;
		case NVME_DIR_RCV_ST_OP_RESOURCE:
			printf("\tNamespace Streams Allocated (NSA): %u\n",
				result & 0xffff);
			break;
		default:
			fprintf(stderr,
				"invalid directive operations for Streams Directives\n");
		}
		break;
	default:
		fprintf(stderr, "invalid directive type\n");
		break;
	}
	return;
}

void nvme_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u32 result,
	void *buf, __u32 len, enum nvme_print_flags flags)
{
	if (flags & BINARY) {
		if (buf)
			return d_raw(buf, len);
		return;
	}

	printf("dir-receive: type:%#x operation:%#x spec:%#x nsid:%#x result:%#x\n",
		type, oper, spec, nsid, result);
	if (flags & VERBOSE)
		nvme_directive_show_fields(type, oper, result, buf);
	else if (buf)
		d(buf, len, 16, 1);
}

static const char *nvme_plm_window(__u32 plm)
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

void nvme_show_lba_status_info(__u32 result) {
	printf("\tLBA Status Information Poll Interval (LSIPI)	: %u\n", (result >> 16) & 0xffff);
	printf("\tLBA Status Information Report Interval (LSIRI): %u\n", result & 0xffff);
}

static void nvme_show_plm_config(struct nvme_plm_config *plmcfg)
{
	printf("\tEnable Event          :%04x\n", le16_to_cpu(plmcfg->enable_event));
	printf("\tDTWIN Reads Threshold :%"PRIu64"\n", le64_to_cpu(plmcfg->dtwin_reads_thresh));
	printf("\tDTWIN Writes Threshold:%"PRIu64"\n", le64_to_cpu(plmcfg->dtwin_writes_thresh));
	printf("\tDTWIN Time Threshold  :%"PRIu64"\n", le64_to_cpu(plmcfg->dtwin_time_thresh));
}

void nvme_feature_show_fields(enum nvme_feat fid, unsigned int result, unsigned char *buf)
{
	__u8 field;
	uint64_t ull;

	switch (fid) {
      case NVME_FEAT_NONE:
              printf("\tFeature Identifier Reserved\n");
              break;
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
		nvme_show_lba_range((struct nvme_lba_range_type *)buf, field);
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
		printf("\tEndurance Group Event Aggregate Log Change Notices: %s\n", ((result & 0x00004000) >> 14) ? "Send async event":"Do not send async event");
		printf("\tLBA Status Information Notices  : %s\n", ((result & 0x00002000) >> 13) ? "Send async event":"Do not send async event");
		printf("\tPredictable Latency Event Aggregate Log Change Notices: %s\n", ((result & 0x00001000) >> 12) ? "Send async event":"Do not send async event");
		printf("\tAsymmetric Namespace Access Change Notices: %s\n", ((result & 0x00000800) >> 11) ? "Send async event":"Do not send async event");
		printf("\tTelemetry Log Notices           : %s\n", ((result & 0x00000400) >> 10) ? "Send async event":"Do not send async event");
		printf("\tFirmware Activation Notices     : %s\n", ((result & 0x00000200) >> 9) ? "Send async event":"Do not send async event");
		printf("\tNamespace Attribute Notices     : %s\n", ((result & 0x00000100) >> 8) ? "Send async event":"Do not send async event");
		printf("\tSMART / Health Critical Warnings: %s\n", (result & 0x000000ff) ? "Send async event":"Do not send async event");
		break;
	case NVME_FEAT_AUTO_PST:
		printf("\tAutonomous Power State Transition Enable (APSTE): %s\n", (result & 0x00000001) ? "Enabled":"Disabled");
		nvme_show_auto_pst((struct nvme_auto_pst *)buf);
		break;
	case NVME_FEAT_HOST_MEM_BUF:
		printf("\tEnable Host Memory (EHM): %s\n", (result & 0x00000001) ? "Enabled":"Disabled");
		nvme_show_host_mem_buffer((struct nvme_host_mem_buffer *)buf);
		break;
	case NVME_FEAT_SW_PROGRESS:
		printf("\tPre-boot Software Load Count (PBSLC): %u\n", result & 0x000000ff);
		break;
	case NVME_FEAT_PLM_CONFIG:
		printf("\tPredictable Latency Window Enabled: %s\n", result & 0x1 ? "True":"False");
		nvme_show_plm_config((struct nvme_plm_config *)buf);
		break;
	case NVME_FEAT_PLM_WINDOW:
		printf("\tWindow Select: %s", nvme_plm_window(result));
		break;
	case NVME_LBA_STATUS_INFO:
		nvme_show_lba_status_info(result);
		break;
      case NVME_FEAT_ENDURANCE:
              printf("\tEndurance Group Identifier (ENDGID): %u\n", result & 0xffff);
              printf("\tEndurance Group Critical Warnings  : %u\n", (result >> 16) & 0xff);
              break;
	case NVME_FEAT_IOCS_PROFILE:
		printf("\tI/O Command Set Comination Index(IOCSCI): %u\n", result & 0x1ff);
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
		nvme_show_timestamp((struct nvme_timestamp *)buf);
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
	case NVME_FEAT_HOST_BEHAVIOR:
		printf("\tHost Behavior Support: %s\n", (buf[0] & 0x1) ? "True" : "False");
		break;
	case NVME_FEAT_SANITIZE:
                printf("\tNo-Deallocate Response Mode (NODRM) : %u\n", result & 0x1);
                break;
	case NVME_FEAT_RRL:
		printf("\tRead Recovery Level (RRL): %u\n", result & 0xf);
		break;
	}
}

void nvme_show_lba_status(struct nvme_lba_status *list, unsigned long len,
			enum nvme_print_flags flags)
{
	int idx;

	if (flags & BINARY)
		return  d_raw((unsigned char *)list, len);

	printf("Number of LBA Status Descriptors(NLSD): %" PRIu64 "\n",
		le64_to_cpu(list->nlsd));
	printf("Completion Condition(CMPC): %u\n", list->cmpc);

	switch (list->cmpc) {
	case 1:
		printf("\tCompleted due to transferring the amount of data"\
			" specified in the MNDW field\n");
		break;
	case 2:
		printf("\tCompleted due to having performed the action\n"\
			"\tspecified in the Action Type field over the\n"\
			"\tnumber of logical blocks specified in the\n"\
			"\tRange Length field\n");
		break;
	}

	for (idx = 0; idx < list->nlsd; idx++) {
		struct nvme_lba_status_desc *e = &list->descs[idx];
		printf("{ DSLBA: 0x%016"PRIu64", NLB: 0x%08x, Status: 0x%02x }\n",
				le64_to_cpu(e->dslba), le32_to_cpu(e->nlb),
				e->status);
	}
}

static void nvme_show_list_item(struct nvme_namespace *n)
{
	long long lba	= 1 << n->ns.lbaf[(n->ns.flbas & 0x0f)].ds;
	double nsze	= le64_to_cpu(n->ns.nsze) * lba;
	double nuse	= le64_to_cpu(n->ns.nuse) * lba;

	const char *s_suffix = suffix_si_get(&nsze);
	const char *u_suffix = suffix_si_get(&nuse);
	const char *l_suffix = suffix_binary_get(&lba);

	char usage[128];
	char format[128], path[256];
	struct stat st;
	int ret;

	sprintf(path, "%s%s", n->ctrl->path, n->name);
	ret = stat(path, &st);
	if (ret < 0)
		return;

	sprintf(usage,"%6.2f %2sB / %6.2f %2sB", nuse, u_suffix,
		nsze, s_suffix);
	sprintf(format,"%3.0f %2sB + %2d B", (double)lba, l_suffix,
		le16_to_cpu(n->ns.lbaf[(n->ns.flbas & 0x0f)].ms));
	printf("%-21s %-*.*s %-*.*s %-9d %-26s %-16s %-.*s\n", path,
		(int)sizeof(n->ctrl->id.sn), (int)sizeof(n->ctrl->id.sn), n->ctrl->id.sn,
		(int)sizeof(n->ctrl->id.mn), (int)sizeof(n->ctrl->id.mn), n->ctrl->id.mn,
		n->nsid, usage, format, (int)sizeof(n->ctrl->id.fr), n->ctrl->id.fr);
}

static void nvme_show_simple_list(struct nvme_topology *t)
{
	int i, j, k;

	printf("%-21s %-20s %-40s %-9s %-26s %-16s %-8s\n",
	    "Node", "SN", "Model", "Namespace", "Usage", "Format", "FW Rev");
	printf("%-.21s %-.20s %-.40s %-.9s %-.26s %-.16s %-.8s\n", dash, dash,
		dash, dash, dash, dash, dash);

	for (i = 0; i < t->nr_subsystems; i++) {
		struct nvme_subsystem *s = &t->subsystems[i];

		for (j = 0; j < s->nr_ctrls; j++) {
			struct nvme_ctrl *c = &s->ctrls[j];

			for (k = 0; k < c->nr_namespaces; k++) {
				struct nvme_namespace *n = &c->namespaces[k];
				nvme_show_list_item(n);
			}
		}

		for (j = 0; j < s->nr_namespaces; j++) {
			struct nvme_namespace *n = &s->namespaces[j];
			nvme_show_list_item(n);
		}
	}
}

static void nvme_show_details_ns(struct nvme_namespace *n, bool ctrl)
{
	long long lba	= 1 << n->ns.lbaf[(n->ns.flbas & 0x0f)].ds;
	double nsze	= le64_to_cpu(n->ns.nsze) * lba;
	double nuse	= le64_to_cpu(n->ns.nuse) * lba;

	const char *s_suffix = suffix_si_get(&nsze);
	const char *u_suffix = suffix_si_get(&nuse);
	const char *l_suffix = suffix_binary_get(&lba);

	char usage[128];
	char format[128];

	sprintf(usage,"%6.2f %2sB / %6.2f %2sB", nuse, u_suffix,
		nsze, s_suffix);
	sprintf(format,"%3.0f %2sB + %2d B", (double)lba, l_suffix,
		le16_to_cpu(n->ns.lbaf[(n->ns.flbas & 0x0f)].ms));

	printf("%-12s %-8d %-26s %-16s ", n->name, n->nsid, usage, format);

	if (ctrl)
		printf("%s", n->ctrl->name);
	else {
		struct nvme_subsystem *s = n->ctrl->subsys;
		int i, j;
		bool comma = false;

		for (i = 0; i < s->nr_ctrls; i++) {
			struct nvme_ctrl *c = &s->ctrls[i];

			for (j = 0; j < c->nr_namespaces; j++) {
				struct nvme_namespace *ns = &c->namespaces[j];

				if (ns->nsid == n->nsid) {
					printf("%s%s", comma ? ", " : "",
					       c->name);
					comma = true;
				}
			}
		}
	}
	printf("\n");
}

static void nvme_show_detailed_list(struct nvme_topology *t)
{
	int i, j, k;

	printf("NVM Express Subsystems\n\n");
	printf("%-16s %-96s %-.16s\n", "Subsystem", "Subsystem-NQN", "Controllers");
	printf("%-.16s %-.96s %-.16s\n", dash, dash, dash);
	for (i = 0; i < t->nr_subsystems; i++) {
		struct nvme_subsystem *s = &t->subsystems[i];

		printf("%-16s %-96s ", s->name, s->subsysnqn);
		for (j = 0; j < s->nr_ctrls; j++) {
			struct nvme_ctrl *c = &s->ctrls[j];

			printf("%s%s", j ? ", " : "", c->name);
		}
		printf("\n");
	};

	printf("\nNVM Express Controllers\n\n");
	printf("%-8s %-20s %-40s %-8s %-6s %-14s %-12s %-16s\n", "Device",
		"SN", "MN", "FR", "TxPort", "Address", "Subsystem", "Namespaces");
	printf("%-.8s %-.20s %-.40s %-.8s %-.6s %-.14s %-.12s %-.16s\n", dash, dash,
		dash, dash, dash, dash, dash, dash);
	for (i = 0; i < t->nr_subsystems; i++) {
		struct nvme_subsystem *s = &t->subsystems[i];

		for (j = 0; j < s->nr_ctrls; j++) {
			bool comma = false;
			struct nvme_ctrl *c = &s->ctrls[j];

			printf("%-8s %-.20s %-.40s %-.8s %-6s %-14s %-12s ",
				c->name, c->id.sn, c->id.mn, c->id.fr,
				c->transport ? : "", c->address ? : "", s->name);

			for (k = 0; k < c->nr_namespaces; k++) {
				struct nvme_namespace *n = &c->namespaces[k];

				printf("%s%s", comma ? ", " : "", n->name);
				comma = true;
			}
			printf("\n");
		}
	}

	printf("\nNVM Express Namespaces\n\n");
	printf("%-12s %-8s %-26s %-16s %-16s\n", "Device", "NSID", "Usage", "Format", "Controllers");
	printf("%-.12s %-.8s %-.26s %-.16s %-.16s\n", dash, dash, dash, dash, dash);

	for (i = 0; i < t->nr_subsystems; i++) {
		struct nvme_subsystem *s = &t->subsystems[i];

		if (s->nr_namespaces) {
			for (j = 0; j < s->nr_namespaces; j++) {
				struct nvme_namespace *n = &s->namespaces[j];
				nvme_show_details_ns(n, false);
			}
		} else {
			for (j = 0; j < s->nr_ctrls; j++) {
				struct nvme_ctrl *c = &s->ctrls[j];

				for (k = 0; k < c->nr_namespaces; k++) {
					struct nvme_namespace *n = &c->namespaces[k];
					nvme_show_details_ns(n, true);
				}
			}
		}
	}
}

static void json_detail_ns(struct nvme_namespace *n, struct json_object *ns_attrs)
{
	long long lba;
	double nsze, nuse;

	lba = 1 << n->ns.lbaf[(n->ns.flbas & 0x0f)].ds;
	nsze = le64_to_cpu(n->ns.nsze) * lba;
	nuse = le64_to_cpu(n->ns.nuse) * lba;

	json_object_add_value_string(ns_attrs, "NameSpace", n->name);
	json_object_add_value_uint(ns_attrs, "NSID", n->nsid);

	json_object_add_value_uint(ns_attrs, "UsedBytes", nuse);
	json_object_add_value_uint(ns_attrs, "MaximumLBA",
		le64_to_cpu(n->ns.nsze));
	json_object_add_value_uint(ns_attrs, "PhysicalSize", nsze);
	json_object_add_value_uint(ns_attrs, "SectorSize", lba);
}

static void json_detail_list(struct nvme_topology *t)
{
	int i, j, k;
	struct json_object *root;
	struct json_object *devices;
	char formatter[41] = { 0 };

	root = json_create_object();
	devices = json_create_array();

	for (i = 0; i < t->nr_subsystems; i++) {
		struct nvme_subsystem *s = &t->subsystems[i];
		struct json_object *subsys_attrs;
		struct json_object *namespaces, *ctrls;

		subsys_attrs = json_create_object();
		json_object_add_value_string(subsys_attrs, "Subsystem", s->name);
		json_object_add_value_string(subsys_attrs, "SubsystemNQN", s->subsysnqn);

		ctrls = json_create_array();
		json_object_add_value_array(subsys_attrs, "Controllers", ctrls);
		for (j = 0; j < s->nr_ctrls; j++) {
			struct json_object *ctrl_attrs = json_create_object();
			struct nvme_ctrl *c = &s->ctrls[j];
			struct json_object *namespaces;

			json_object_add_value_string(ctrl_attrs, "Controller", c->name);
			if (c->transport)
				json_object_add_value_string(ctrl_attrs, "Transport", c->transport);
			if (c->address)
				json_object_add_value_string(ctrl_attrs, "Address", c->address);
			if (c->state)
				json_object_add_value_string(ctrl_attrs, "State", c->state);
			if (c->hostnqn)
				json_object_add_value_string(ctrl_attrs, "HostNQN", c->hostnqn);
			if (c->hostid)
				json_object_add_value_string(ctrl_attrs, "HostID", c->hostid);

			format(formatter, sizeof(formatter), c->id.fr, sizeof(c->id.fr));
			json_object_add_value_string(ctrl_attrs, "Firmware", formatter);

			format(formatter, sizeof(formatter), c->id.mn, sizeof(c->id.mn));
			json_object_add_value_string(ctrl_attrs, "ModelNumber", formatter);

			format(formatter, sizeof(formatter), c->id.sn, sizeof(c->id.sn));
			json_object_add_value_string(ctrl_attrs, "SerialNumber", formatter);

			namespaces = json_create_array();

			for (k = 0; k < c->nr_namespaces; k++) {
				struct json_object *ns_attrs = json_create_object();
				struct nvme_namespace *n = &c->namespaces[k];

				json_detail_ns(n, ns_attrs);
				json_array_add_value_object(namespaces, ns_attrs);
			}
			if (k)
				json_object_add_value_array(ctrl_attrs, "Namespaces", namespaces);
			else
				json_free_array(namespaces);

			json_array_add_value_object(ctrls, ctrl_attrs);
		}

		namespaces = json_create_array();
		for (k = 0; k < s->nr_namespaces; k++) {
			struct json_object *ns_attrs = json_create_object();
			struct nvme_namespace *n = &s->namespaces[k];

			json_detail_ns(n, ns_attrs);
			json_array_add_value_object(namespaces, ns_attrs);
		}
		if (k)
			json_object_add_value_array(subsys_attrs, "Namespaces", namespaces);
		else
			json_free_array(namespaces);

		json_array_add_value_object(devices, subsys_attrs);
	}

	json_object_add_value_array(root, "Devices", devices);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_simple_ns(struct nvme_namespace *n, struct json_object *devices)
{
	struct json_object *device_attrs;
	char formatter[41] = { 0 };
	double nsze, nuse;
	int ret, index = -1;
	long long lba;
	char *devnode;
	struct stat st;

	if (asprintf(&devnode, "%s%s", n->ctrl->path, n->name) < 0)
		return;

	ret = stat(devnode, &st);
	if (ret < 0)
		return;

	device_attrs = json_create_object();
	json_object_add_value_int(device_attrs, "NameSpace", n->nsid);

	json_object_add_value_string(device_attrs, "DevicePath", devnode);
	free(devnode);

	format(formatter, sizeof(formatter),
			   n->ctrl->id.fr,
			   sizeof(n->ctrl->id.fr));

	json_object_add_value_string(device_attrs, "Firmware", formatter);

	if (sscanf(n->ctrl->name, "nvme%d", &index) == 1)
		json_object_add_value_int(device_attrs, "Index", index);

	format(formatter, sizeof(formatter),
		       n->ctrl->id.mn,
		       sizeof(n->ctrl->id.mn));

	json_object_add_value_string(device_attrs, "ModelNumber", formatter);

	if (index >= 0 && n->ctrl->transport && !strcmp(n->ctrl->transport, "pcie")) {
		char *product = nvme_product_name(index);

		json_object_add_value_string(device_attrs, "ProductName", product);
		free((void*)product);
	}

	format(formatter, sizeof(formatter),
	       n->ctrl->id.sn,
	       sizeof(n->ctrl->id.sn));

	json_object_add_value_string(device_attrs, "SerialNumber", formatter);

	lba = 1 << n->ns.lbaf[(n->ns.flbas & 0x0f)].ds;
	nsze = le64_to_cpu(n->ns.nsze) * lba;
	nuse = le64_to_cpu(n->ns.nuse) * lba;

	json_object_add_value_uint(device_attrs, "UsedBytes", nuse);
	json_object_add_value_uint(device_attrs, "MaximumLBA",
				  le64_to_cpu(n->ns.nsze));
	json_object_add_value_uint(device_attrs, "PhysicalSize", nsze);
	json_object_add_value_uint(device_attrs, "SectorSize", lba);

	json_array_add_value_object(devices, device_attrs);
}

static void json_simple_list(struct nvme_topology *t)
{
	struct json_object *root;
	struct json_object *devices;
	int i, j, k;

	root = json_create_object();
	devices = json_create_array();
	for (i = 0; i < t->nr_subsystems; i++) {
		struct nvme_subsystem *s = &t->subsystems[i];

		for (j = 0; j < s->nr_ctrls; j++) {
			struct nvme_ctrl *c = &s->ctrls[j];

			for (k = 0; k < c->nr_namespaces; k++) {
				struct nvme_namespace *n = &c->namespaces[k];
				json_simple_ns(n, devices);
			}
		}

		for (j = 0; j < s->nr_namespaces; j++) {
			struct nvme_namespace *n = &s->namespaces[j];
			json_simple_ns(n, devices);
		}
	}
	json_object_add_value_array(root, "Devices", devices);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void json_print_list_items(struct nvme_topology *t,
				  enum nvme_print_flags flags)
{
	if (flags & VERBOSE)
		json_detail_list(t);
	else
		json_simple_list(t);
}

void nvme_show_list_items(struct nvme_topology *t, enum nvme_print_flags flags)
{
	if (flags & JSON)
		json_print_list_items(t, flags);
	else if (flags & VERBOSE)
		nvme_show_detailed_list(t);
	else
		nvme_show_simple_list(t);
}
