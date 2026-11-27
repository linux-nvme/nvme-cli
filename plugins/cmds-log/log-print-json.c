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
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>
#include <shared/hex-util.h>
#include <shared/string-util.h>
#include <shared/unaligned-util.h>

#include "cleanup.h"
#include "log-print.h"
#include "nvme-json.h"
#include "nvme-print.h"
#include "plugins/cmds-feat/feat-print.h"
#include "nvme-print-json.h"

static void json_error_log(struct nvme_error_log_page *err_log, int entries,
			   const char *devname,
			   struct nvme_error_log_filter *flt)
{
	struct json_object *r = json_root();
	struct json_object *errors = json_create_array();
	struct json_object *error;
	__u16 sts;
	int i;

	obj_add_array(r, "errors", errors);

	for (i = 0; i < entries; i++) {
		if (nvme_is_error_log_filter(&err_log[i], flt))
			continue;

		error = json_create_object();
		sts = le16_to_cpu(err_log[i].status_field);

		obj_add_uint64(error, "error_count",
			       le64_to_cpu(err_log[i].error_count));
		obj_add_int(error, "sqid", le16_to_cpu(err_log[i].sqid));
		obj_add_int(error, "cmdid", le16_to_cpu(err_log[i].cmdid));
		obj_add_int(error, "status_field",
			    NVME_ERR_SF_STATUS_FIELD(sts));
		obj_add_int(error, "phase_tag", NVME_ERR_SF_PHASE_TAG(sts));
		obj_add_int(error, "parm_error_location",
			    le16_to_cpu(err_log[i].parm_error_location));
		obj_add_uint64(error, "lba", le64_to_cpu(err_log[i].lba));
		obj_add_uint(error, "nsid", le32_to_cpu(err_log[i].nsid));
		obj_add_int(error, "vs", err_log[i].vs);
		obj_add_int(error, "trtype", err_log[i].trtype);
		obj_add_int(error, "csi", err_log[i].csi);
		obj_add_int(error, "opcode", err_log[i].opcode);
		obj_add_uint64(error, "cs", le64_to_cpu(err_log[i].cs));
		obj_add_int(error, "trtype_spec_info",
			    le16_to_cpu(err_log[i].trtype_spec_info));
		obj_add_int(error, "log_page_version",
			    err_log[i].log_page_version);

		array_add_obj(errors, error);
	}
}

static void json_fw_log(struct nvme_firmware_slot *fw_log, const char *devname)
{
	struct json_object *r = json_root();
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
			shr_fw_to_string(fw_log->frs[i]));
			obj_add_str(fwsi, fmt, str);
		}
	}

	obj_add_obj(r, devname, fwsi);
}

static void json_changed_ns_list_log(struct nvme_ns_list *log,
				     const char *devname, bool alloc)
{
	struct json_object *r = json_root();
	struct json_object *nsi;
	char fmt[32];
	char str[32];
	__u32 nsid;
	int i;

	__cleanup_free char *k = NULL;

	if (log->ns[0] == cpu_to_le32(0xffffffff))
		return;

	nsi = json_create_object();

	if (asprintf(&k, "Changed %s Namespace List Log",
		     alloc ? "Allocated" : "Attached") > 0)
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
}

static void json_endurance_log(struct nvme_endurance_group_log *endurance_group,
			       __u16 group_id, const char *devname)
{
	struct json_object *r = json_root();
	shr_uint128_t endurance_estimate =
		le128_to_cpu(endurance_group->endurance_estimate);
	shr_uint128_t data_units_read =
		le128_to_cpu(endurance_group->data_units_read);
	shr_uint128_t data_units_written =
		le128_to_cpu(endurance_group->data_units_written);
	shr_uint128_t media_units_written =
		le128_to_cpu(endurance_group->media_units_written);
	shr_uint128_t host_read_cmds =
		le128_to_cpu(endurance_group->host_read_cmds);
	shr_uint128_t host_write_cmds =
		le128_to_cpu(endurance_group->host_write_cmds);
	shr_uint128_t media_data_integrity_err =
	    le128_to_cpu(endurance_group->media_data_integrity_err);
	shr_uint128_t num_err_info_log_entries =
	    le128_to_cpu(endurance_group->num_err_info_log_entries);
	shr_uint128_t total_end_grp_cap =
		le128_to_cpu(endurance_group->total_end_grp_cap);
	shr_uint128_t unalloc_end_grp_cap =
		le128_to_cpu(endurance_group->unalloc_end_grp_cap);

	obj_add_int(r, "critical_warning", endurance_group->critical_warning);
	obj_add_int(r, "endurance_group_features",
		    endurance_group->endurance_group_features);
	obj_add_int(r, "avl_spare", endurance_group->avl_spare);
	obj_add_int(r, "avl_spare_threshold",
		    endurance_group->avl_spare_threshold);
	obj_add_int(r, "percent_used", endurance_group->percent_used);
	obj_add_int(r, "domain_identifier", endurance_group->domain_identifier);
	obj_add_uint128(r, "endurance_estimate", endurance_estimate);
	obj_add_uint128(r, "data_units_read", data_units_read);
	obj_add_uint128(r, "data_units_written", data_units_written);
	obj_add_uint128(r, "media_units_written", media_units_written);
	obj_add_uint128(r, "host_read_cmds", host_read_cmds);
	obj_add_uint128(r, "host_write_cmds", host_write_cmds);
	obj_add_uint128(r, "media_data_integrity_err",
			media_data_integrity_err);
	obj_add_uint128(r, "num_err_info_log_entries",
			num_err_info_log_entries);
	obj_add_uint128(r, "total_end_grp_cap", total_end_grp_cap);
	obj_add_uint128(r, "unalloc_end_grp_cap", unalloc_end_grp_cap);
}

static void json_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
			   const char *devname)
{
	struct json_object *r = json_root();
	int c;
	char key[21];
	unsigned int temperature = ((smart->temperature[1] << 8) |
		smart->temperature[0]);
	shr_uint128_t data_units_read = le128_to_cpu(smart->data_units_read);
	shr_uint128_t data_units_written =
		le128_to_cpu(smart->data_units_written);
	shr_uint128_t host_read_commands = le128_to_cpu(smart->host_reads);
	shr_uint128_t host_write_commands = le128_to_cpu(smart->host_writes);
	shr_uint128_t controller_busy_time =
		le128_to_cpu(smart->ctrl_busy_time);
	shr_uint128_t power_cycles = le128_to_cpu(smart->power_cycles);
	shr_uint128_t power_on_hours = le128_to_cpu(smart->power_on_hours);
	shr_uint128_t unsafe_shutdowns = le128_to_cpu(smart->unsafe_shutdowns);
	shr_uint128_t media_errors = le128_to_cpu(smart->media_errors);
	shr_uint128_t num_err_log_entries =
		le128_to_cpu(smart->num_err_log_entries);

	if (json_verbose_mode()) {
		struct json_object *crt = json_create_object();

		obj_add_int(crt, "value", smart->critical_warning);
		obj_add_int(crt, "available_spare",
			    smart->critical_warning & 1);
		obj_add_int(crt, "temp_threshold",
			    (smart->critical_warning & 2) >> 1);
		obj_add_int(crt, "reliability_degraded",
			    (smart->critical_warning & 4) >> 2);
		obj_add_int(crt, "ro", (smart->critical_warning & 8) >> 3);
		obj_add_int(crt, "vmbu_failed",
			    (smart->critical_warning & 0x10) >> 4);
		obj_add_int(crt, "pmr_ro",
			    (smart->critical_warning & 0x20) >> 5);
		obj_add_int(crt, "indeterminate_personality",
			    (smart->critical_warning & 0x40) >> 6);

		obj_add_obj(r, "critical_warning", crt);
	} else {
		obj_add_int(r, "critical_warning", smart->critical_warning);
	}

	obj_add_int(r, "temperature", temperature);
	obj_add_int(r, "avail_spare", smart->avail_spare);
	obj_add_int(r, "spare_thresh", smart->spare_thresh);
	obj_add_int(r, "percent_used", smart->percent_used);
	obj_add_int(r, "endurance_grp_critical_warning_summary",
		    smart->endu_grp_crit_warn_sumry);
	obj_add_int(r, "informative_warning", smart->informative_warning);
	obj_add_int(r, "voltage_log_threshold_warning",
		    smart->informative_warning & 0x1);
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
	obj_add_uint(r, "warning_temp_time",
		     le32_to_cpu(smart->warning_temp_time));
	obj_add_uint(r, "critical_comp_time",
		     le32_to_cpu(smart->critical_comp_time));

	for (c = 0; c < 8; c++) {
		__s32 temp = le16_to_cpu(smart->temp_sensor[c]);

		if (temp == 0)
			continue;

		sprintf(key, "temperature_sensor_%d", c + 1);
		obj_add_int(r, key, temp);
	}

	obj_add_uint(r, "thm_temp1_trans_count",
		     le32_to_cpu(smart->thm_temp1_trans_count));
	obj_add_uint(r, "thm_temp2_trans_count",
		     le32_to_cpu(smart->thm_temp2_trans_count));
	obj_add_uint(r, "thm_temp1_total_time",
		     le32_to_cpu(smart->thm_temp1_total_time));
	obj_add_uint(r, "thm_temp2_total_time",
		     le32_to_cpu(smart->thm_temp2_total_time));
	obj_add_uint64(r, "op_lifetime_energy_consumed",
		       le64_to_cpu(smart->op_lifetime_energy_consumed));
	obj_add_uint(r, "interval_power_measurement",
		     le32_to_cpu(smart->interval_power_measurement));
}

static void json_ana_log(struct nvme_ana_log *ana_log, const char *devname,
			 size_t len)
{
	size_t offset = sizeof(struct nvme_ana_log);
	struct nvme_ana_log *hdr = ana_log;
	struct nvme_ana_group_desc ana_desc;
	struct json_object *desc_list = json_create_array();
	struct json_object *ns_list;
	struct json_object *desc;
	struct json_object *nsid;
	struct json_object *r = json_root();
	size_t nsid_buf_size;
	void *base = ana_log;
	__le32 *nsids;
	__u32 nr_nsids;
	int i, j;

	obj_add_str(r, "Asymmetric Namespace Access Log for NVMe device",
		    devname);
	obj_add_uint64(r, "chgcnt", le64_to_cpu(hdr->chgcnt));
	obj_add_uint(r, "ngrps", le16_to_cpu(hdr->ngrps));

	for (i = 0; i < le16_to_cpu(ana_log->ngrps); i++) {
		if (offset > len || len - offset < sizeof(ana_desc))
			break;
		/* descriptors are only 4 byte aligned */
		memcpy(&ana_desc, base + offset, sizeof(ana_desc));
		nr_nsids = le32_to_cpu(ana_desc.nnsids);
		nsid_buf_size = (size_t)nr_nsids * sizeof(__le32);
		if (len - offset - sizeof(ana_desc) < nsid_buf_size)
			break;

		desc = json_create_object();
		offset += sizeof(ana_desc);
		nsids = base + offset;
		obj_add_uint(desc, "grpid", le32_to_cpu(ana_desc.grpid));
		obj_add_uint(desc, "nnsids", le32_to_cpu(ana_desc.nnsids));
		obj_add_uint64(desc, "chgcnt", le64_to_cpu(ana_desc.chgcnt));
		obj_add_str(desc, "state",
			    nvme_ana_state_to_string(ana_desc.state));

		ns_list = json_create_array();
		for (j = 0; j < nr_nsids; j++) {
			nsid = json_create_object();
			obj_add_uint(nsid, "nsid", le32_to_cpu(nsids[j]));
			array_add_obj(ns_list, nsid);
		}
		obj_add_array(desc, "NSIDS", ns_list);
		offset += nsid_buf_size;
		array_add_obj(desc_list, desc);
	}

	obj_add_array(r, "ANA DESC LIST ", desc_list);
}

static void json_self_test_log(struct nvme_self_test_log *self_test,
			       __u8 dst_entries, __u32 size,
			       const char *devname)
{
	struct json_object *valid_attrs;
	struct json_object *r = json_root();
	struct json_object *valid = json_create_array();
	int i;
	__u32 num_entries = min(dst_entries, NVME_LOG_ST_MAX_RESULTS);

	obj_add_int(r, "Current Device Self-Test Operation",
		    self_test->current_operation);
	obj_add_int(r, "Current Device Self-Test Completion",
		    self_test->completion);

	for (i = 0; i < num_entries; i++) {
		valid_attrs = json_create_object();
		obj_add_int(valid_attrs, "Self test result",
			    self_test->result[i].dsts & 0xf);

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
			obj_add_int(valid_attrs, "Status Code Type",
				    self_test->result[i].sct);

		if (self_test->result[i].vdi & NVME_ST_VALID_DIAG_INFO_SC)
			obj_add_int(valid_attrs, "Status Code",
				    self_test->result[i].sc);

		obj_add_int(valid_attrs, "Vendor Specific",
			    self_test->result[i].vs[1] << 8 |
				    self_test->result[i].vs[0]);

add:
		array_add_obj(valid, valid_attrs);
	}

	obj_add_array(r, "List of Valid Reports", valid);
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
	struct json_object *r = json_root();
	struct json_object *dev = json_create_object();
	struct json_object *sstat = json_create_object();
	struct json_object *ssi = json_create_object();
	const char *status_str;
	__u16 status, sos;
	__u8 fails, sans;
	char str[128];

	status = le16_to_cpu(sanitize_log->sstat);

	obj_add_int(dev, "sprog", le16_to_cpu(sanitize_log->sprog));
	obj_add_int(sstat, "media_verification_canceled",
		    NVME_GET(status, SANITIZE_SSTAT_MVCNCLD));
	obj_add_int(sstat, "global_erased",
		    NVME_GET(status, SANITIZE_SSTAT_GLOBAL_DATA_ERASED));
	obj_add_int(sstat, "no_cmplted_passes",
		    NVME_GET(status, SANITIZE_SSTAT_COMPLETED_PASSES));
	obj_add_int(sstat, "purged", NVME_GET(status, SANITIZE_SSTAT_PRGD));

	sos = NVME_GET(status, SANITIZE_SSTAT_STATUS);
	status_str = nvme_sstat_status_to_string(status);
	sprintf(str, "(%d) %s", sos, status_str);
	obj_add_str(sstat, "status", str);

	obj_add_obj(dev, "sstat", sstat);
	obj_add_uint(dev, "cdw10_info", le32_to_cpu(sanitize_log->scdw10));
	obj_add_uint(dev, "time_over_write", le32_to_cpu(sanitize_log->eto));
	obj_add_uint(dev, "time_block_erase", le32_to_cpu(sanitize_log->etbe));
	obj_add_uint(dev, "time_crypto_erase", le32_to_cpu(sanitize_log->etce));
	obj_add_uint(dev, "time_over_write_no_dealloc",
		     le32_to_cpu(sanitize_log->etond));
	obj_add_uint(dev, "time_block_erase_no_dealloc",
		     le32_to_cpu(sanitize_log->etbend));
	obj_add_uint(dev, "time_crypto_erase_no_dealloc",
		     le32_to_cpu(sanitize_log->etcend));
	obj_add_uint(dev, "time_post_verification_dealloc",
		     le32_to_cpu(sanitize_log->etpvds));

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
}

static void json_predictable_latency_per_nvmset(
		struct nvme_nvmset_predictable_lat_log *plpns_log,
		__u16 nvmset_id, const char *devname)
{
	struct json_object *r = json_root();

	obj_add_uint(r, "nvmset_id", le16_to_cpu(nvmset_id));
	obj_add_uint(r, "status", plpns_log->status);
	obj_add_uint(r, "event_type", le16_to_cpu(plpns_log->event_type));
	obj_add_uint64(r, "dtwin_reads_typical",
		       le64_to_cpu(plpns_log->dtwin_rt));
	obj_add_uint64(r, "dtwin_writes_typical",
		       le64_to_cpu(plpns_log->dtwin_wt));
	obj_add_uint64(r, "dtwin_time_maximum",
		       le64_to_cpu(plpns_log->dtwin_tmax));
	obj_add_uint64(r, "ndwin_time_minimum_high",
		       le64_to_cpu(plpns_log->ndwin_tmin_hi));
	obj_add_uint64(r, "ndwin_time_minimum_low",
		       le64_to_cpu(plpns_log->ndwin_tmin_lo));
	obj_add_uint64(r, "dtwin_reads_estimate",
		       le64_to_cpu(plpns_log->dtwin_re));
	obj_add_uint64(r, "dtwin_writes_estimate",
		       le64_to_cpu(plpns_log->dtwin_we));
	obj_add_uint64(r, "dtwin_time_estimate",
		       le64_to_cpu(plpns_log->dtwin_te));
}

static void json_predictable_latency_event_agg_log(
		struct nvme_aggregate_predictable_lat_event *pea_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	struct json_object *r = json_root();
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();
	__u64 num_entries = le64_to_cpu(pea_log->num_entries);
	__u64 num_iter = min(num_entries, log_entries);

	obj_add_uint64(r, "num_entries_avail", num_entries);

	for (int i = 0; i < num_iter; i++) {
		valid_attrs = json_create_object();
		obj_add_uint(valid_attrs, "entry",
			     le16_to_cpu(pea_log->entries[i]));
		array_add_obj(valid, valid_attrs);
	}

	obj_add_array(r, "list_of_entries", valid);
}

static void json_add_bitmap(int i, __u8 seb, struct json_object *r)
{
	char evt_str[50];
	char key[128];

	for (int bit = 0; bit < CHAR_BIT; bit++) {
		if (!((seb >> bit) & 0x1))
			continue;
		sprintf(key, "bitmap_%x", (bit + i * CHAR_BIT));
		snprintf(evt_str, sizeof(evt_str), "Support %s",
			 nvme_pel_event_to_string(bit + i * CHAR_BIT));
		obj_add_str(r, key, evt_str);
	}
}

void nvme_json_pevent_log_head(
	struct nvme_persistent_event_log *pevent_log_head,
	struct json_object *r)
{
	int i;
	char sn[sizeof(pevent_log_head->sn) + 1];
	char mn[sizeof(pevent_log_head->mn) + 1];
	char subnqn[sizeof(pevent_log_head->subnqn) + 1];

	snprintf(sn, sizeof(sn), "%-.*s", (int)sizeof(pevent_log_head->sn),
		 pevent_log_head->sn);
	snprintf(mn, sizeof(mn), "%-.*s", (int)sizeof(pevent_log_head->mn),
		 pevent_log_head->mn);
	snprintf(subnqn, sizeof(subnqn), "%-.*s",
		 (int)sizeof(pevent_log_head->subnqn), pevent_log_head->subnqn);

	obj_add_uint(r, "log_id", pevent_log_head->lid);
	obj_add_uint(r, "total_num_of_events",
		     le32_to_cpu(pevent_log_head->tnev));
	obj_add_uint64(r, "total_log_len", le64_to_cpu(pevent_log_head->tll));
	obj_add_uint(r, "log_revision", pevent_log_head->rv);
	obj_add_uint(r, "log_header_len", le16_to_cpu(pevent_log_head->lhl));
	obj_add_uint64(r, "timestamp", le64_to_cpu(pevent_log_head->ts));
	obj_add_uint128(r, "power_on_hours",
			le128_to_cpu(pevent_log_head->poh));
	obj_add_uint64(r, "power_cycle_count",
		       le64_to_cpu(pevent_log_head->pcc));
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

void nvme_json_pel_smart_health(void *pevent_log_info, __u32 offset,
				struct json_object *valid_attrs)
{
	char key[128];
	struct nvme_smart_log *smart_event = pevent_log_info + offset;
	unsigned int temperature = (smart_event->temperature[1] << 8) |
				   smart_event->temperature[0];
	shr_uint128_t data_units_read =
		le128_to_cpu(smart_event->data_units_read);
	shr_uint128_t data_units_written =
		le128_to_cpu(smart_event->data_units_written);
	shr_uint128_t host_read_commands =
		le128_to_cpu(smart_event->host_reads);
	shr_uint128_t host_write_commands =
		le128_to_cpu(smart_event->host_writes);
	shr_uint128_t controller_busy_time =
		le128_to_cpu(smart_event->ctrl_busy_time);
	shr_uint128_t power_cycles = le128_to_cpu(smart_event->power_cycles);
	shr_uint128_t power_on_hours =
		le128_to_cpu(smart_event->power_on_hours);
	shr_uint128_t unsafe_shutdowns =
		le128_to_cpu(smart_event->unsafe_shutdowns);
	shr_uint128_t media_errors = le128_to_cpu(smart_event->media_errors);
	shr_uint128_t num_err_log_entries =
		le128_to_cpu(smart_event->num_err_log_entries);
	int c;
	__s32 temp;

	obj_add_int(valid_attrs, "critical_warning",
		    smart_event->critical_warning);
	obj_add_int(valid_attrs, "temperature", temperature);
	obj_add_int(valid_attrs, "avail_spare", smart_event->avail_spare);
	obj_add_int(valid_attrs, "spare_thresh", smart_event->spare_thresh);
	obj_add_int(valid_attrs, "percent_used", smart_event->percent_used);
	obj_add_int(valid_attrs, "endurance_grp_critical_warning_summary",
		    smart_event->endu_grp_crit_warn_sumry);
	obj_add_uint128(valid_attrs, "data_units_read", data_units_read);
	obj_add_uint128(valid_attrs, "data_units_written", data_units_written);
	obj_add_uint128(valid_attrs, "host_read_commands", host_read_commands);
	obj_add_uint128(valid_attrs, "host_write_commands",
			host_write_commands);
	obj_add_uint128(valid_attrs, "controller_busy_time",
			controller_busy_time);
	obj_add_uint128(valid_attrs, "power_cycles", power_cycles);
	obj_add_uint128(valid_attrs, "power_on_hours", power_on_hours);
	obj_add_uint128(valid_attrs, "unsafe_shutdowns", unsafe_shutdowns);
	obj_add_uint128(valid_attrs, "media_errors", media_errors);
	obj_add_uint128(valid_attrs, "num_err_log_entries",
			num_err_log_entries);
	obj_add_uint(valid_attrs, "warning_temp_time",
		     le32_to_cpu(smart_event->warning_temp_time));
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

void nvme_json_pel_fw_commit(void *pevent_log_info, __u32 offset,
			     struct json_object *valid_attrs)
{
	char fw_str[50];
	struct nvme_fw_commit_event *fw_commit_event = pevent_log_info + offset;

	snprintf(fw_str, sizeof(fw_str), "%" PRIu64 " (%s)",
		 le64_to_cpu(fw_commit_event->old_fw_rev),
		 shr_fw_to_string((char *)&fw_commit_event->old_fw_rev));
	obj_add_str(valid_attrs, "old_fw_rev", fw_str);
	snprintf(fw_str, sizeof(fw_str), "%" PRIu64 " (%s)",
		 le64_to_cpu(fw_commit_event->new_fw_rev),
		 shr_fw_to_string((char *)&fw_commit_event->new_fw_rev));
	obj_add_str(valid_attrs, "new_fw_rev", fw_str);
	obj_add_uint(valid_attrs, "fw_commit_action",
		     fw_commit_event->fw_commit_action);
	obj_add_uint(valid_attrs, "fw_slot", fw_commit_event->fw_slot);
	obj_add_uint(valid_attrs, "sct_fw", fw_commit_event->sct_fw);
	obj_add_uint(valid_attrs, "sc_fw", fw_commit_event->sc_fw);
	obj_add_uint(valid_attrs, "vu_assign_fw_commit_rc",
		     le16_to_cpu(fw_commit_event->vndr_assign_fw_commit_rc));
}

void nvme_json_pel_timestamp(void *pevent_log_info, __u32 offset,
			     struct json_object *valid_attrs)
{
	struct nvme_time_stamp_change_event *ts_change_event =
		pevent_log_info + offset;

	obj_add_uint64(valid_attrs, "prev_ts",
		       le64_to_cpu(ts_change_event->previous_timestamp));
	obj_add_uint64(valid_attrs, "ml_secs_since_reset",
		       le64_to_cpu(ts_change_event->ml_secs_since_reset));
}

void nvme_json_pel_power_on_reset(void *pevent_log_info, __u32 offset,
				  struct json_object *valid_attrs,
				  __le16 vsil, __le16 el,
				  __u32 size)
{
	__u64 *fw_rev;
	char fw_str[50];
	struct nvme_power_on_reset_info_list *por_event;
	__u32 ev_len = le16_to_cpu(el);
	__u32 vlen = le16_to_cpu(vsil);
	__u32 por_info_len, por_info_list;
	int i;

	if (ev_len < vlen + sizeof(*fw_rev) ||
	    offset > size - sizeof(*fw_rev))
		return;

	por_info_len = ev_len - vlen - sizeof(*fw_rev);
	por_info_list = por_info_len / sizeof(*por_event);

	fw_rev = pevent_log_info + offset;
	snprintf(fw_str, sizeof(fw_str), "%"PRIu64" (%s)", le64_to_cpu(*fw_rev),
		 shr_fw_to_string((char *)fw_rev));
	obj_add_str(valid_attrs, "fw_rev", fw_str);

	for (i = 0; i < por_info_list; i++) {
		__u32 poff = offset + sizeof(*fw_rev) +
			     i * sizeof(*por_event);

		if (poff > size - sizeof(*por_event))
			break;
		por_event = pevent_log_info + poff;
		obj_add_uint(valid_attrs, "ctrl_id",
			     le16_to_cpu(por_event->cid));
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

void nvme_json_pel_nss_hw_error(void *pevent_log_info, __u32 offset,
				struct json_object *valid_attrs)
{
	struct nvme_nss_hw_err_event *nss_hw_err_event =
		pevent_log_info + offset;

	obj_add_uint(valid_attrs, "nss_hw_err_code",
		     le16_to_cpu(nss_hw_err_event->nss_hw_err_event_code));
}

void nvme_json_pel_change_ns(void *pevent_log_info, __u32 offset,
			     struct json_object *valid_attrs)
{
	struct nvme_change_ns_event *ns_event = pevent_log_info + offset;

	obj_add_uint(valid_attrs, "nsmgt_cdw10",
		     le32_to_cpu(ns_event->nsmgt_cdw10));
	obj_add_uint64(valid_attrs, "nsze", le64_to_cpu(ns_event->nsze));
	obj_add_uint64(valid_attrs, "nscap", le64_to_cpu(ns_event->nscap));
	obj_add_uint(valid_attrs, "flbas", ns_event->flbas);
	obj_add_uint(valid_attrs, "dps", ns_event->dps);
	obj_add_uint(valid_attrs, "nmic", ns_event->nmic);
	obj_add_uint(valid_attrs, "ana_grp_id",
		     le32_to_cpu(ns_event->ana_grp_id));
	obj_add_uint(valid_attrs, "nvmset_id",
		     le16_to_cpu(ns_event->nvmset_id));
	obj_add_uint(valid_attrs, "nsid", le32_to_cpu(ns_event->nsid));
}

void nvme_json_pel_format_start(void *pevent_log_info, __u32 offset,
				struct json_object *valid_attrs)
{
	struct nvme_format_nvm_start_event *format_start_event =
		pevent_log_info + offset;

	obj_add_uint(valid_attrs, "nsid",
		     le32_to_cpu(format_start_event->nsid));
	obj_add_uint(valid_attrs, "fna", format_start_event->fna);
	obj_add_uint(valid_attrs, "format_nvm_cdw10",
		     le32_to_cpu(format_start_event->format_nvm_cdw10));
}

void nvme_json_pel_format_completion(void *pevent_log_info, __u32 offset,
				     struct json_object *valid_attrs)
{
	struct nvme_format_nvm_compln_event *format_cmpln_event =
		pevent_log_info + offset;

	obj_add_uint(valid_attrs, "nsid",
		     le32_to_cpu(format_cmpln_event->nsid));
	obj_add_uint(valid_attrs, "smallest_fpi",
		     format_cmpln_event->smallest_fpi);
	obj_add_uint(valid_attrs, "format_nvm_status",
		     format_cmpln_event->format_nvm_status);
	obj_add_uint(valid_attrs, "compln_info",
		     le16_to_cpu(format_cmpln_event->compln_info));
	obj_add_uint(valid_attrs, "status_field",
		     le32_to_cpu(format_cmpln_event->status_field));
}

void nvme_json_pel_sanitize_start(void *pevent_log_info, __u32 offset,
				  struct json_object *valid_attrs)
{
	struct nvme_sanitize_start_event *sanitize_start_event =
		pevent_log_info + offset;

	obj_add_uint(valid_attrs, "SANICAP",
		     le32_to_cpu(sanitize_start_event->sani_cap));
	obj_add_uint(valid_attrs, "sani_cdw10",
		     le32_to_cpu(sanitize_start_event->sani_cdw10));
	obj_add_uint(valid_attrs, "sani_cdw11",
		     le32_to_cpu(sanitize_start_event->sani_cdw11));
}

void nvme_json_pel_sanitize_completion(void *pevent_log_info, __u32 offset,
				       struct json_object *valid_attrs)
{
	struct nvme_sanitize_compln_event *sanitize_cmpln_event =
		pevent_log_info + offset;

	obj_add_uint(valid_attrs, "sani_prog",
		     le16_to_cpu(sanitize_cmpln_event->sani_prog));
	obj_add_uint(valid_attrs, "sani_status",
		     le16_to_cpu(sanitize_cmpln_event->sani_status));
	obj_add_uint(valid_attrs, "cmpln_info",
		     le16_to_cpu(sanitize_cmpln_event->cmpln_info));
}

void nvme_json_pel_set_feature(void *data, __u32 len,
			       struct json_object *valid_attrs)
{
	struct nvme_set_feature_event *set_feat_event = data;
	int fid = NVME_GET(le32_to_cpu(set_feat_event->cdw_mem[0]),
			   SET_FEATURES_CDW10_FID);
	int cdw11 = le32_to_cpu(set_feat_event->cdw_mem[1]);
	__cleanup_free unsigned char *mem_buf = NULL;

	obj_add_uint_02x(valid_attrs, "feature", fid);
	obj_add_str(valid_attrs, "name", nvme_feature_to_string(fid));
	obj_add_uint_0nx(valid_attrs, "value", cdw11, 8);

	mem_buf = nvme_pel_set_feature_data(data, len);
	if (mem_buf)
		json_feature_show_fields(fid, cdw11, mem_buf);
}

void nvme_json_pel_telemetry_crt(void *pevent_log_info, __u32 offset,
				 struct json_object *valid_attrs,
				 __u32 len, __u32 size)
{
	if (len < 512 || offset > size - 512)
		return;
	obj_d(valid_attrs, "create", pevent_log_info + offset, 512, 16, 1);
}

void nvme_json_pel_thermal_excursion(void *pevent_log_info, __u32 offset,
				     struct json_object *valid_attrs)
{
	struct nvme_thermal_exc_event *thermal_exc_event =
		pevent_log_info + offset;

	obj_add_uint(valid_attrs, "over_temp", thermal_exc_event->over_temp);
	obj_add_uint(valid_attrs, "threshold", thermal_exc_event->threshold);
}

static void json_pel_vs_event_data(struct json_object *valid_attrs, void *vsed,
				   __u8 vsedt, __u16 vsedl)
{
	struct json_object *vs_data = json_create_object();
	char *str;

	switch (vsedt) {
	case NVME_PEL_VSEDT_EVENT_NAME:
		str = malloc(vsedl + 1);
		if (str) {
			memcpy(str, vsed, vsedl);
			str[vsedl] = '\0';
			obj_add_str(vs_data, "event_name", str);
			free(str);
		}
		break;
	case NVME_PEL_VSEDT_ASCII_STRING:
		str = malloc(vsedl + 1);
		if (str) {
			memcpy(str, vsed, vsedl);
			str[vsedl] = '\0';
			obj_add_str(vs_data, "ascii_string_data", str);
			free(str);
		}
		break;
	case NVME_PEL_VSEDT_BINARY:
		obj_d(vs_data, "binary_data", (unsigned char *)vsed, vsedl, 16,
		      1);
		break;
	case NVME_PEL_VSEDT_SIGNED_INT:
		if (vsedl < sizeof(__le64)) {
			obj_d(vs_data, "binary_data", (unsigned char *)vsed,
			      vsedl, 16, 1);
			break;
		}
		obj_add_int(vs_data, "signed_integer_data",
			    (int64_t)shr_get_unaligned_le64(vsed));
		break;
	default:
		obj_d(vs_data, "reserved_data_type_bin", (unsigned char *)vsed,
		      vsedl, 16, 1);
		break;
	}

	obj_add_obj(valid_attrs, "vs_event_data", vs_data);
}

void nvme_json_pel_vendor_specific_event(void *pevent_log_info, __u32 offset,
					 __u32 event_data_len,
					 struct json_object *valid_attrs)
{
	__u32 progress = 0;
	__u16 vsedl;
	__u32 i;
	struct nvme_vs_event_desc vs_desc;
	struct json_object *vs_events = json_create_array();

	for (i = 0; progress + sizeof(vs_desc) <= event_data_len; i++) {
		void *p = pevent_log_info + offset + progress;
		struct json_object *vs_event;

		/* The descriptors are not aligned. */
		memcpy(&vs_desc, p, sizeof(vs_desc));
		vsedl = le16_to_cpu(vs_desc.vsedl);
		if (vsedl > event_data_len - progress - sizeof(vs_desc))
			break;

		vs_event = json_create_object();

		obj_add_uint(vs_event, "vs_event_descriptor_number", i);
		obj_add_uint(vs_event, "vs_event_code",
			     le16_to_cpu(vs_desc.vsec));
		obj_add_uint(vs_event, "vs_event_data_type", vs_desc.vsedt);
		obj_add_uint(vs_event, "vs_event_uuid_index", vs_desc.uidx);
		obj_add_uint(vs_event, "vs_event_data_len", vsedl);

		if (vsedl)
			json_pel_vs_event_data(vs_event, p + sizeof(vs_desc),
					       vs_desc.vsedt, vsedl);

		array_add_obj(vs_events, vs_event);
		progress += sizeof(vs_desc) + vsedl;
	}

	obj_add_array(valid_attrs, "vs_event_entry", vs_events);
}

static void json_pevent_entry(void *pevent_log_info, __u8 action, __u32 size,
			      const char *devname, __u32 offset,
			      struct json_object *valid)
{
	int i;
	__u16 vsil, el;
	__u32 data_len;
	struct nvme_persistent_event_log *pevent_log_head = pevent_log_info;
	struct nvme_persistent_event_entry *pevent_entry_head;
	struct json_object *valid_attrs;

	for (i = 0; i < le32_to_cpu(pevent_log_head->tnev); i++) {
		pevent_entry_head = nvme_pel_event(pevent_log_info, size,
						   offset);
		if (!pevent_entry_head)
			break;

		vsil = le16_to_cpu(pevent_entry_head->vsil);
		el = le16_to_cpu(pevent_entry_head->el);

		valid_attrs = json_create_object();

		obj_add_uint(valid_attrs, "event_number", i);
		obj_add_str(valid_attrs, "event_type",
			    nvme_pel_event_to_string(pevent_entry_head->etype));
		obj_add_uint(valid_attrs, "event_type_rev",
			     pevent_entry_head->etype_rev);
		obj_add_uint(valid_attrs, "event_header_len",
			     pevent_entry_head->ehl);
		obj_add_uint(valid_attrs, "event_header_additional_info",
			     pevent_entry_head->ehai);
		obj_add_uint(valid_attrs, "ctrl_id",
			     le16_to_cpu(pevent_entry_head->cntlid));
		obj_add_uint64(valid_attrs, "event_time_stamp",
			       le64_to_cpu(pevent_entry_head->ets));
		obj_add_uint(valid_attrs, "port_id",
			     le16_to_cpu(pevent_entry_head->pelpid));
		obj_add_uint(valid_attrs, "vu_info_len", vsil);
		obj_add_uint(valid_attrs, "event_len", el);

		if (vsil)
			obj_d(valid_attrs, "vs_info_bin",
			      (void *)pevent_entry_head +
			      pevent_entry_head->ehl + 3, vsil, 16, 1);

		offset += pevent_entry_head->ehl + vsil + 3;

		__cleanup_free void *data =
			nvme_pel_event_data(pevent_log_info, offset,
					    el - vsil, &data_len);

		if (!data) {
			array_add_obj(valid, valid_attrs);
			break;
		}

		switch (pevent_entry_head->etype) {
		case NVME_PEL_SMART_HEALTH_EVENT:
			nvme_json_pel_smart_health(data, 0, valid_attrs);
			break;
		case NVME_PEL_FW_COMMIT_EVENT:
			nvme_json_pel_fw_commit(data, 0, valid_attrs);
			break;
		case NVME_PEL_TIMESTAMP_EVENT:
			nvme_json_pel_timestamp(data, 0, valid_attrs);
			break;
		case NVME_PEL_POWER_ON_RESET_EVENT:
			nvme_json_pel_power_on_reset(data, 0, valid_attrs,
						     pevent_entry_head->vsil,
						     pevent_entry_head->el,
						     data_len);
			break;
		case NVME_PEL_NSS_HW_ERROR_EVENT:
			nvme_json_pel_nss_hw_error(data, 0, valid_attrs);
			break;
		case NVME_PEL_CHANGE_NS_EVENT:
			nvme_json_pel_change_ns(data, 0, valid_attrs);
			break;
		case NVME_PEL_FORMAT_START_EVENT:
			nvme_json_pel_format_start(data, 0, valid_attrs);
			break;
		case NVME_PEL_FORMAT_COMPLETION_EVENT:
			nvme_json_pel_format_completion(data, 0, valid_attrs);
			break;
		case NVME_PEL_SANITIZE_START_EVENT:
			nvme_json_pel_sanitize_start(data, 0, valid_attrs);
			break;
		case NVME_PEL_SANITIZE_COMPLETION_EVENT:
			nvme_json_pel_sanitize_completion(data, 0, valid_attrs);
			break;
		case NVME_PEL_SET_FEATURE_EVENT:
			nvme_json_pel_set_feature(data, el - vsil,
						  valid_attrs);
			break;
		case NVME_PEL_TELEMETRY_CRT:
			nvme_json_pel_telemetry_crt(data, 0, valid_attrs,
						    el - vsil, data_len);
			break;
		case NVME_PEL_THERMAL_EXCURSION_EVENT:
			nvme_json_pel_thermal_excursion(data, 0, valid_attrs);
			break;
		case NVME_PEL_VENDOR_SPECIFIC_EVENT:
			nvme_json_pel_vendor_specific_event(data, 0, el - vsil,
							    valid_attrs);
			break;
		default:
			break;
		}

		array_add_obj(valid, valid_attrs);
		offset += el - vsil;
	}
}

static void json_persistent_event_log(void *pevent_log_info, __u8 action,
				      __u32 size, const char *devname)
{
	struct json_object *r = json_root();
	struct json_object *valid;
	__u32 offset = sizeof(struct nvme_persistent_event_log);

	if (size >= offset) {
		valid = json_create_array();
		nvme_json_pevent_log_head(pevent_log_info, r);
		json_pevent_entry(pevent_log_info, action, size, devname,
				  offset, valid);
		obj_add_array(r, "list_of_event_entries", valid);
	} else {
		obj_add_result(r,
			"No log data can be shown with this log len at least 512 bytes is required or can be 0 to read the complete log page after context established");
	}
}

static void json_endurance_group_event_agg_log(
		struct nvme_aggregate_endurance_group_event *endurance_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	struct json_object *r = json_root();
	struct json_object *valid_attrs;
	struct json_object *valid = json_create_array();

	obj_add_uint64(r, "num_entries_avail",
		       le64_to_cpu(endurance_log->num_entries));

	for (int i = 0; i < log_entries; i++) {
		valid_attrs = json_create_object();
		obj_add_uint(valid_attrs, "entry",
			     le16_to_cpu(endurance_log->entries[i]));
		array_add_obj(valid, valid_attrs);
	}

	obj_add_array(r, "list_of_entries", valid);
}

static void json_lba_status_log(void *lba_status, __u32 size,
				const char *devname)
{
	struct json_object *r = json_root();
	struct json_object *desc;
	struct json_object *element;
	struct json_object *desc_list;
	struct json_object *elements_list;
	struct nvme_lba_status_log *hdr = lba_status;
	struct nvme_lbas_ns_element *ns_element;
	struct nvme_lba_rd *range_desc;
	size_t offset = sizeof(*hdr);
	__u32 num_lba_desc;
	__u32 num_elements;
	int ele;
	int i;

	if (size < sizeof(*hdr))
		return;

	elements_list = json_create_array();
	num_elements = le32_to_cpu(hdr->nlslne);

	obj_add_uint(r, "lslplen", le32_to_cpu(hdr->lslplen));
	obj_add_uint(r, "nlslne", num_elements);
	obj_add_uint(r, "estulb", le32_to_cpu(hdr->estulb));
	obj_add_uint(r, "lsgc", le16_to_cpu(hdr->lsgc));

	for (ele = 0; ele < num_elements; ele++) {
		if (offset + sizeof(*ns_element) > size)
			break;
		ns_element = lba_status + offset;
		element = json_create_object();
		obj_add_uint(element, "neid", le32_to_cpu(ns_element->neid));
		num_lba_desc = le32_to_cpu(ns_element->nlrd);
		obj_add_uint(element, "nlrd", num_lba_desc);
		obj_add_uint(element, "ratype", ns_element->ratype);

		offset += sizeof(*ns_element);
		desc_list = json_create_array();

		if (num_lba_desc != 0xffffffff) {
			if (num_lba_desc >
			    (size - offset) / sizeof(*range_desc)) {
				json_free_object(desc_list);
				json_free_object(element);
				break;
			}
			for (i = 0; i < num_lba_desc; i++) {
				range_desc = lba_status + offset;
				desc = json_create_object();
				obj_add_uint64(desc, "rslba",
					       le64_to_cpu(range_desc->rslba));
				obj_add_uint(desc, "rnlb",
					     le32_to_cpu(range_desc->rnlb));

				offset += sizeof(*range_desc);
				array_add_obj(desc_list, desc);
			}
		} else {
			obj_add_result(
				r,
				"Number of LBA Range Descriptors (NLRD) set to %#x for NS element %d",
				num_lba_desc, ele);
		}

		obj_add_array(element, "descs", desc_list);
		array_add_obj(elements_list, element);
	}

	obj_add_array(r, "ns_elements", elements_list);
}

static void json_resv_notif_log(struct nvme_resv_notification_log *resv,
				const char *devname)
{
	struct json_object *r = json_root();

	obj_add_uint64(r, "count", le64_to_cpu(resv->lpc));
	obj_add_uint(r, "rn_log_type", resv->rnlpt);
	obj_add_uint(r, "num_logs", resv->nalp);
	obj_add_uint(r, "NSID", le32_to_cpu(resv->nsid));
}

static void json_fid_support_effects_log(
		struct nvme_fid_supported_effects_log *fid_log,
		const char *devname)
{
	struct json_object *r = json_root();
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
}

static void json_mi_cmd_support_effects_log(
		struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
		const char *devname)
{
	struct json_object *r = json_root();
	struct json_object *mi_cmds;
	struct json_object *mi_cmds_list = json_create_array();
	unsigned int mi_cmd;
	char key[128];
	__u32 mi_cmd_support;

	for (mi_cmd = 0; mi_cmd < NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_MAX;
	     mi_cmd++) {
		mi_cmd_support =
			le32_to_cpu(mi_cmd_log->mi_cmd_support[mi_cmd]);
		if (mi_cmd_support & NVME_MI_CMD_SUPPORTED_EFFECTS_CSUPP) {
			mi_cmds = json_create_object();
			sprintf(key, "mi_cmd_%u", mi_cmd);
			obj_add_uint(mi_cmds, key, mi_cmd_support);
			array_add_obj(mi_cmds_list, mi_cmds);
		}
	}

	obj_add_obj(r, "mi_command_support", mi_cmds_list);
}

static void json_boot_part_log(void *bp_log, const char *devname,
			       __u32 size)
{
	struct nvme_boot_partition *hdr = bp_log;
	struct json_object *r = json_root();

	obj_add_uint(r, "count", hdr->lid);
	obj_add_uint(r, "abpid",
		     NVME_BOOT_PARTITION_INFO_ABPID(le32_to_cpu(hdr->bpinfo)));
	obj_add_uint(r, "bpsz",
		     NVME_BOOT_PARTITION_INFO_BPSZ(le32_to_cpu(hdr->bpinfo)));
}

/* Printable Eye string is allocated and returned, caller must free */
static char *json_eom_printable_eye(const struct nvme_eom_lane_desc *lane,
				    const unsigned char *eye,
				    struct json_object *r)
{
	size_t nrows = le16_to_cpu(lane->nrows);
	size_t ncols = le16_to_cpu(lane->ncols);
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
	printable = malloc((size_t)nrows * ncols + nrows + 1);
	printable_start = printable;

	if (!printable)
		goto fail_free_eye_array;

	for (size_t i = 0; i < nrows; i++) {
		char *row = malloc(ncols + 1);

		if (!row)
			goto fail_free_eye_printable;

		for (size_t j = 0; j < ncols; j++) {
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
	free(printable_start);
fail_free_eye_array:
	json_free_object(eye_array);

	return NULL;
}

static void json_phy_rx_eom_descs(struct nvme_phy_rx_eom_log *log,
				  struct json_object *r, char **allocated_eyes,
				  size_t len)
{
	struct eom_desc_iter it;
	struct nvme_eom_lane_desc desc;
	struct json_object *descs = json_create_array();
	int i = 0;

	obj_add_array(r, "descs", descs);

	eom_desc_iter_init(&it, log, len);

	while (eom_desc_iter_next(&it, &desc)) {
		int idx = i++;
		__cleanup_free char *hexstr = NULL;
		unsigned char *vsdata;
		uint32_t vsdatalen;
		struct json_object *jdesc;
		char *hexdata;

		jdesc = json_create_object();
		if (!jdesc)
			return;

		obj_add_uint(jdesc, "lid", desc.mstatus);
		obj_add_uint(jdesc, "lane", desc.lane);
		obj_add_uint(jdesc, "eye", desc.eye);
		obj_add_uint(jdesc, "top", le16_to_cpu(desc.top));
		obj_add_uint(jdesc, "bottom", le16_to_cpu(desc.bottom));
		obj_add_uint(jdesc, "left", le16_to_cpu(desc.left));
		obj_add_uint(jdesc, "right", le16_to_cpu(desc.right));
		obj_add_uint(jdesc, "nrows", le16_to_cpu(desc.nrows));
		obj_add_uint(jdesc, "ncols", le16_to_cpu(desc.ncols));
		obj_add_uint(jdesc, "edlen", le32_to_cpu(desc.edlen));

		vsdata = eom_desc_iter_vsdata(&it, &desc, &vsdatalen);
		if (!vsdata) {
			json_free_object(jdesc);
			continue;
		}

		if (NVME_EOM_ODP_PEFP(log->odp))
			allocated_eyes[idx] = json_eom_printable_eye(&desc,
					eom_desc_iter_eye(&it), jdesc);

		if (vsdatalen == 0) {
			json_free_object(jdesc);
			continue;
		}

		/* 2 hex chars + space per byte */
		hexstr = malloc((size_t)vsdatalen * 3 + 1);

		if (!hexstr) {
			json_free_object(jdesc);
			return;
		}

		/* Hex dump Vendor Specific Eye Data */
		hexdata = hexstr;

		for (uint32_t offset = 0; offset < vsdatalen; offset++)
			hexdata += sprintf(hexdata, "%02X ", vsdata[offset]);
		/* remove trailing space */
		*(hexdata - 1) = '\0';

		obj_add_str(jdesc, "vsdata_hex", hexstr);

		array_add_obj(descs, jdesc);
	}
}

static void json_phy_rx_eom_log(struct nvme_phy_rx_eom_log *log,
				__u16 controller, size_t len)
{
	int i;
	uint16_t num_descs;
	struct json_object *r = json_root();

	__cleanup_free char **allocated_eyes = NULL;

	if (len < sizeof(*log))
		return;

	num_descs = le16_to_cpu(log->nd);
	if (num_descs >
	    (len - sizeof(*log)) / sizeof(struct nvme_eom_lane_desc))
		num_descs = (len - sizeof(*log)) /
			    sizeof(struct nvme_eom_lane_desc);

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
		allocated_eyes = calloc(num_descs, sizeof(char *));
		if (allocated_eyes)
			json_phy_rx_eom_descs(log, r, allocated_eyes, len);
	}

	if (allocated_eyes) {
		for (i = 0; i < num_descs; i++) {
			/* Free any Printable Eye strings allocated */
			free(allocated_eyes[i]);
		}
	}
}

static void json_media_unit_stat_log(struct nvme_media_unit_stat_log *mus,
		size_t len)
{
	struct json_object *r = json_root();
	struct json_object *entries = json_create_array();
	struct nvme_media_unit_stat_desc desc;
	struct mus_desc_iter it;

	if (len < sizeof(*mus)) {
		obj_add_array(r, "mus_list", entries);
		return;
	}

	obj_add_uint(r, "nmu", le16_to_cpu(mus->nmu));
	obj_add_uint(r, "cchans", le16_to_cpu(mus->cchans));
	obj_add_uint(r, "sel_config", le16_to_cpu(mus->sel_config));

	mus_desc_iter_init(&it, mus, len);
	while (mus_desc_iter_next(&it, &desc)) {
		struct json_object *entry = json_create_object();
		struct json_object *chans = json_create_array();

		obj_add_uint(entry, "muid", le16_to_cpu(desc.muid));
		obj_add_uint(entry, "domainid", le16_to_cpu(desc.domainid));
		obj_add_uint(entry, "endgid", le16_to_cpu(desc.endgid));
		obj_add_uint(entry, "nvmsetid", le16_to_cpu(desc.nvmsetid));
		obj_add_uint(entry, "cap_adj_fctr",
			     le16_to_cpu(desc.cap_adj_fctr));
		obj_add_uint(entry, "avl_spare", desc.avl_spare);
		obj_add_uint(entry, "percent_used", desc.percent_used);
		obj_add_uint(entry, "mucs", desc.mucs);
		obj_add_uint(entry, "cio", desc.cio);

		for (int k = 0; k < desc.mucs; k++) {
			struct json_object *chan = json_create_object();

			obj_add_uint(chan, "chanid",
				     mus_desc_iter_chan(&it, k));
			array_add_obj(chans, chan);
		}
		obj_add_array(entry, "chanids", chans);
		array_add_obj(entries, entry);
	}

	obj_add_array(r, "mus_list", entries);
}

/*
 * An odd Media Unit Descriptor Length leaves the next descriptors
 * unaligned, so they are copied before they are read.
 */
static bool json_cap_config_chan(struct json_object *chan_list,
		unsigned char **p, unsigned char *end)
{
	struct nvme_channel_config_desc chd;
	struct json_object *channel, *media_list;
	int chmus;

	if (!shr_buf_has_room(*p, end, sizeof(chd)))
		return false;

	memcpy(&chd, *p, sizeof(chd));
	chmus = le16_to_cpu(chd.chmus);
	*p += sizeof(chd);

	channel = json_create_object();
	obj_add_uint(channel, "chanid", le16_to_cpu(chd.chanid));
	obj_add_uint(channel, "chmus", chmus);
	media_list = json_create_array();
	obj_add_array(channel, "Media Descriptor", media_list);
	array_add_obj(chan_list, channel);

	for (int m = 0; m < chmus; m++) {
		struct nvme_media_unit_config_desc mu;
		struct json_object *media;
		size_t size;

		if (!shr_buf_has_room(*p, end, sizeof(mu)))
			return false;

		memcpy(&mu, *p, sizeof(mu));
		size = sizeof(mu) + le16_to_cpu(mu.mudl);
		if (!shr_buf_has_room(*p, end, size))
			return false;

		media = json_create_object();
		obj_add_uint(media, "muid", le16_to_cpu(mu.muid));
		obj_add_uint(media, "mudl", le16_to_cpu(mu.mudl));
		array_add_obj(media_list, media);
		*p += size;
	}

	return true;
}

static bool json_cap_config_egcd(struct json_object *end_list,
		unsigned char **p, unsigned char *end)
{
	struct nvme_end_grp_config_desc egcd;
	struct nvme_end_grp_chan_desc chan_desc;
	struct json_object *endurance, *set_list, *chan_list;
	unsigned char *sets;
	int egsets, egchans;

	if (!shr_buf_has_room(*p, end, sizeof(egcd)))
		return false;

	memcpy(&egcd, *p, sizeof(egcd));
	egsets = le16_to_cpu(egcd.egsets);
	sets = *p + sizeof(egcd);
	*p = sets + egsets * sizeof(__le16);
	if (!shr_buf_has_room(sets, end, egsets * sizeof(__le16) +
			      sizeof(chan_desc)))
		return false;

	memcpy(&chan_desc, *p, sizeof(chan_desc));
	egchans = le16_to_cpu(chan_desc.egchans);
	*p += sizeof(chan_desc);

	endurance = json_create_object();
	obj_add_uint(endurance, "endgid", le16_to_cpu(egcd.endgid));
	obj_add_uint(endurance, "cap_adj_factor",
		     le16_to_cpu(egcd.cap_adj_factor));
	obj_add_uint128(endurance, "tegcap", le128_to_cpu(egcd.tegcap));
	obj_add_uint128(endurance, "segcap", le128_to_cpu(egcd.segcap));
	obj_add_uint(endurance, "egsets", egsets);
	obj_add_uint(endurance, "egchans", egchans);

	set_list = json_create_array();
	for (int k = 0; k < egsets; k++) {
		struct json_object *set = json_create_object();
		__le16 id;

		memcpy(&id, sets + k * sizeof(id), sizeof(id));
		obj_add_uint(set, "nvmsetid", le16_to_cpu(id));
		array_add_obj(set_list, set);
	}

	chan_list = json_create_array();
	obj_add_array(endurance, "Channel Descriptor", chan_list);
	obj_add_array(endurance, "NVM Set IDs", set_list);
	array_add_obj(end_list, endurance);

	for (int l = 0; l < egchans; l++) {
		if (!json_cap_config_chan(chan_list, p, end))
			return false;
	}

	return true;
}

static void json_supported_cap_config_log(
		struct nvme_supported_cap_config_list_log *cap_log, size_t len)
{
	struct json_object *r = json_root();
	struct json_object *cap_list = json_create_array();
	unsigned char *p = (unsigned char *)cap_log->cap_config_desc;
	unsigned char *end = (unsigned char *)cap_log + len;
	bool more = true;

	obj_add_array(r, "Capacity Descriptor", cap_list);
	if (len < sizeof(*cap_log))
		return;

	obj_add_uint(r, "sccn", cap_log->sccn);
	for (int i = 0; more && i < cap_log->sccn; i++) {
		struct nvme_capacity_config_desc desc;
		struct json_object *capacity, *end_list;
		int egcn;

		if (!shr_buf_has_room(p, end, sizeof(desc)))
			break;

		memcpy(&desc, p, sizeof(desc));
		egcn = le16_to_cpu(desc.egcn);
		p += sizeof(desc);

		capacity = json_create_object();
		obj_add_uint(capacity, "cap_config_id",
			     le16_to_cpu(desc.cap_config_id));
		obj_add_uint(capacity, "domainid", le16_to_cpu(desc.domainid));
		obj_add_uint(capacity, "egcn", egcn);
		end_list = json_create_array();
		obj_add_array(capacity, "Endurance Descriptor", end_list);
		array_add_obj(cap_list, capacity);

		for (int j = 0; more && j < egcn; j++)
			more = json_cap_config_egcd(end_list, &p, end);
	}
}

static void json_support_log(struct nvme_supported_log_pages *support_log,
			     const char *devname)
{
	struct json_object *r = json_root();
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
}

static void json_mgmt_addr_list_log(struct nvme_mgmt_addr_list_log *ma_list)
{
	int i;
	bool reserved = true;
	struct json_object *r = json_root();
	struct json_object *mad;
	struct json_object *mat;
	char json_str[STR_LEN];
	char madrs[sizeof(ma_list->mad[0].madrs) + 1];

	for (i = 0; i < ARRAY_SIZE(ma_list->mad); i++) {
		switch (ma_list->mad[i].mat) {
		case 1:
		case 2:
			mad = json_create_object();
			mat = json_create_object();
			obj_add_str(mat, "definition",
				    ma_list->mad[i].mat == 1 ?
					    "NVM subsystem management agent" :
					    "fabric interface manager");
			snprintf(json_str, sizeof(json_str), "type: %d",
				 ma_list->mad[i].mat);
			obj_add_obj(mad, json_str, mat);
			snprintf(madrs, sizeof(madrs), "%-.*s",
				 (int)sizeof(ma_list->mad[i].madrs),
				 ma_list->mad[i].madrs);
			obj_add_str(mad, "address", madrs);
			snprintf(json_str, sizeof(json_str), "descriptor: %d",
				 i);
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
		obj_add_str(r, "list",
			    "All management address descriptors reserved");
}

static void
json_rotational_media_info_log(struct nvme_rotational_media_info_log *info)
{
	struct json_object *r = json_root();

	obj_add_uint(r, "endgid", le16_to_cpu(info->endgid));
	obj_add_uint(r, "numa", le16_to_cpu(info->numa));
	obj_add_uint(r, "nrs", le16_to_cpu(info->nrs));
	obj_add_uint(r, "spinc", le32_to_cpu(info->spinc));
	obj_add_uint(r, "fspinc", le32_to_cpu(info->fspinc));
	obj_add_uint(r, "ldc", le32_to_cpu(info->ldc));
	obj_add_uint(r, "fldc", le32_to_cpu(info->fldc));
}

static void json_dispersed_ns_psub_log(
		struct nvme_dispersed_ns_participating_nss_log *log, __u64 len)
{
	struct json_object *r = json_root();
	__u64 numpsub = le64_to_cpu(log->numpsub);
	__u64 i, n;
	char json_str[STR_LEN];
	char psub[NVME_NQN_LENGTH + 1];

	obj_add_uint64(r, "genctr", le64_to_cpu(log->genctr));
	obj_add_uint64(r, "numpsub", numpsub);
	n = nvme_log_nr_entries(numpsub, len, sizeof(*log), NVME_NQN_LENGTH);
	for (i = 0; i < n; i++) {
		snprintf(json_str, sizeof(json_str),
			 "participating_nss %" PRIu64 "", (uint64_t)i);
		snprintf(psub, sizeof(psub), "%-.*s", NVME_NQN_LENGTH,
			 &log->participating_nss[i * NVME_NQN_LENGTH]);
		obj_add_str(r, json_str, psub);
	}
}

static void json_reachability_groups_log(
		struct nvme_reachability_groups_log *log, __u64 len)
{
	struct json_object *r = json_root();
	struct nvme_reachability_group_desc desc;
	__u64 off = sizeof(*log);
	__le32 *nsid;
	__u16 i;
	__u32 j;
	char json_str[STR_LEN];
	struct json_object *rgd, *nsids;

	obj_add_uint64(r, "chngc", le64_to_cpu(log->chngc));
	obj_add_uint(r, "nrgd", le16_to_cpu(log->nrgd));

	for (i = 0; i < le16_to_cpu(log->nrgd) &&
	     nvme_reachability_group(log, len, off, &desc); i++) {
		snprintf(json_str, sizeof(json_str), "rgid: %u",
			 le32_to_cpu(desc.rgid));
		rgd = json_create_object();
		obj_add_uint(rgd, "nnid", le32_to_cpu(desc.nnid));
		obj_add_uint64(rgd, "chngc", le64_to_cpu(desc.chngc));
		nsids = json_create_array();
		nsid = nvme_reachability_ids(log, off, sizeof(desc));
		for (j = 0; j < le32_to_cpu(desc.nnid); j++)
			json_object_array_add(nsids,
				json_object_new_uint64(le32_to_cpu(nsid[j])));
		obj_add_array(rgd, "nsid", nsids);
		obj_add_obj(r, json_str, rgd);
		off = nvme_reachability_group_next(&desc, off);
	}
}

static void json_reachability_associations_log(
	struct nvme_reachability_associations_log *log, __u64 len)
{
	struct json_object *r = json_root();
	struct nvme_reachability_association_desc desc;
	__u64 off = sizeof(*log);
	__le32 *rgid;
	__u16 i;
	__u32 j;
	char json_str[STR_LEN];
	struct json_object *rad, *rgids;

	obj_add_uint64(r, "chngc", le64_to_cpu(log->chngc));
	obj_add_uint(r, "nrad", le16_to_cpu(log->nrad));

	for (i = 0; i < le16_to_cpu(log->nrad) &&
	     nvme_reachability_association(log, len, off, &desc); i++) {
		snprintf(json_str, sizeof(json_str), "rasid: %u",
			 le32_to_cpu(desc.rasid));
		rad = json_create_object();
		obj_add_uint(rad, "nrid", le32_to_cpu(desc.nrid));
		obj_add_uint64(rad, "chngc", le64_to_cpu(desc.chngc));
		obj_add_uint(rad, "rac", desc.rac);
		rgids = json_create_array();
		rgid = nvme_reachability_ids(log, off, sizeof(desc));
		for (j = 0; j < le32_to_cpu(desc.nrid); j++)
			json_object_array_add(rgids,
				json_object_new_uint64(le32_to_cpu(rgid[j])));
		obj_add_array(rad, "rgid", rgids);
		obj_add_obj(r, json_str, rad);
		off = nvme_reachability_association_next(&desc, off);
	}
}

#ifdef CONFIG_FABRICS
static void json_host_discovery_log(struct nvme_host_discovery_log *log,
				    __u64 len)
{
	struct json_object *r = json_root();
	__u64 i;
	__u16 j;
	struct nvme_host_ext_discovery_log hedlpe;
	struct nvmf_ext_attr exat;
	void *rec, *p;
	char hostnqn[sizeof(hedlpe.hostnqn) + 1];
	char traddr[sizeof(hedlpe.traddr) + 1];
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

	for (i = sizeof(*log);
	     (rec = nvme_host_discovery_record(log, len, i)); i += tel) {
		memcpy(&hedlpe, rec, sizeof(hedlpe));
		hedlpe_o = json_create_object();
		tel = le32_to_cpu(hedlpe.tel);
		numexat = le16_to_cpu(hedlpe.numexat);
		snprintf(hostnqn, sizeof(hostnqn), "%-.*s",
			 (int)sizeof(hedlpe.hostnqn), hedlpe.hostnqn);
		snprintf(traddr, sizeof(traddr), "%-.*s",
			 (int)sizeof(hedlpe.traddr), hedlpe.traddr);
		obj_add_str(hedlpe_o, "trtype",
			    libnvmf_trtype_str(hedlpe.trtype));
		obj_add_str(hedlpe_o, "adrfam", traddr[0] ?
			    libnvmf_adrfam_str(hedlpe.adrfam) : "");
		obj_add_str(hedlpe_o, "eflags",
			    libnvmf_eflags_str(le16_to_cpu(hedlpe.eflags)));
		obj_add_str(hedlpe_o, "hostnqn", hostnqn);
		obj_add_str(hedlpe_o, "traddr", traddr);
		tsas_o = json_create_object();
		switch (hedlpe.trtype) {
		case NVMF_TRTYPE_RDMA:
			obj_add_str(tsas_o, "prtype",
				libnvmf_prtype_str(hedlpe.tsas.rdma.prtype));
			obj_add_str(tsas_o, "qptype",
				libnvmf_qptype_str(hedlpe.tsas.rdma.qptype));
			obj_add_str(tsas_o, "cms",
				    libnvmf_cms_str(hedlpe.tsas.rdma.cms));
			obj_add_uint_0nx(tsas_o, "pkey",
					 le16_to_cpu(hedlpe.tsas.rdma.pkey), 4);
			break;
		case NVMF_TRTYPE_TCP:
			obj_add_str(tsas_o, "sectype",
				libnvmf_sectype_str(hedlpe.tsas.tcp.sectype));
			break;
		default:
			obj_d(tsas_o, "common",
			      (unsigned char *)hedlpe.tsas.common,
			      sizeof(hedlpe.tsas.common), 16, 1);
			break;
		}
		obj_add_obj(hedlpe_o, "tsas", tsas_o);
		obj_add_uint(hedlpe_o, "tel", tel);
		obj_add_uint(hedlpe_o, "numexat", numexat);

		p = rec + sizeof(hedlpe);
		for (j = 0; j < numexat &&
		     (p = nvme_host_discovery_exat(rec, tel, p, &exat)); j++) {
			exat_o = json_create_object();
			snprintf(json_str, sizeof(json_str), "exat: %d", j);
			obj_add_uint(exat_o, "exattype",
				     le16_to_cpu(exat.exattype));
			obj_add_uint(exat_o, "exatlen",
				     le16_to_cpu(exat.exatlen));
			obj_d(exat_o, "exatval",
			      (unsigned char *)p + sizeof(exat),
			      le16_to_cpu(exat.exatlen), 16, 1);
			obj_add_obj(hedlpe_o, json_str, exat_o);
			p = nvme_host_discovery_exat_next(p, &exat);
		}
		snprintf(json_str, sizeof(json_str), "hedlpe: %d", n++);
		obj_add_obj(r, json_str, hedlpe_o);
	}
}

static void obj_add_traddr(struct json_object *o, const char *k, __u8 adrfam,
			   __u8 *traddr)
{
	char dst[INET6_ADDRSTRLEN];
	socklen_t size;
	int af;

	if (adrfam == NVMF_ADDR_FAMILY_IP4) {
		af = AF_INET;
		size = INET_ADDRSTRLEN;
	} else if (adrfam == NVMF_ADDR_FAMILY_IP6) {
		af = AF_INET6;
		size = INET6_ADDRSTRLEN;
	} else {
		obj_add_str(o, k, "<invalid>");
		return;
	}

	if (inet_ntop(af, traddr, dst, size))
		obj_add_str(o, k, dst);
}

static void json_ave_discovery_log(struct nvme_ave_discovery_log *log,
				   __u64 len)
{
	struct json_object *r = json_root();
	__u64 i;
	__u8 j;
	struct nvme_ave_discovery_log_entry adlpe;
	char avenqn[sizeof(adlpe.avenqn) + 1];
	struct nvme_ave_tr_record atr;
	void *rec;
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

	for (i = sizeof(*log);
	     (rec = nvme_ave_discovery_record(log, len, i)); i += tel) {
		memcpy(&adlpe, rec, sizeof(adlpe));
		adlpe_o = json_create_object();
		tel = le32_to_cpu(adlpe.tel);
		numatr = adlpe.numatr;
		snprintf(avenqn, sizeof(avenqn), "%-.*s",
			 (int)sizeof(adlpe.avenqn), adlpe.avenqn);
		obj_add_uint(adlpe_o, "tel", tel);
		obj_add_str(adlpe_o, "avenqn", avenqn);
		obj_add_uint(adlpe_o, "numatr", numatr);

		/* the transport records must fit the record */
		numatr = nvme_log_nr_entries(numatr, tel, sizeof(adlpe),
					     sizeof(atr));
		for (j = 0; j < numatr; j++) {
			memcpy(&atr, rec + sizeof(adlpe) + j * sizeof(atr),
			       sizeof(atr));
			atr_o = json_create_object();
			snprintf(json_str, sizeof(json_str), "atr: %d", j);
			obj_add_str(atr_o, "aveadrfam",
				    libnvmf_adrfam_str(atr.aveadrfam));
			obj_add_uint(atr_o, "avetrsvcid",
				     le16_to_cpu(atr.avetrsvcid));
			obj_add_traddr(atr_o, "avetraddr", atr.aveadrfam,
				       atr.avetraddr);
			obj_add_obj(adlpe_o, json_str, atr_o);
		}
		snprintf(json_str, sizeof(json_str), "adlpe: %d", n++);
		obj_add_obj(r, json_str, adlpe_o);
	}
}
#else
static void json_host_discovery_log(struct nvme_host_discovery_log *log,
				    __u64 len)
{
}

static void json_ave_discovery_log(struct nvme_ave_discovery_log *log,
				   __u64 len)
{
}
#endif

static void json_pull_model_ddc_req_log(struct nvme_pull_model_ddc_req_log *log,
					__u64 len)
{
	struct json_object *r = json_root();
	__u32 tpdrpl = le32_to_cpu(log->tpdrpl);
	__u32 osp_len = nvme_pull_model_ddc_req_osp_len(log, len);

	obj_add_uint(r, "ori", log->ori);
	obj_add_uint(r, "tpdrpl", tpdrpl);
	obj_d(r, "osp", (unsigned char *)log->osp, osp_len, 16, 1);
}

static void json_power_meas_log(struct nvme_power_meas_log *log, __u32 size)
{
	struct json_object *r = json_root();
	struct json_object *descs;
	struct json_object *smts_obj;
	struct json_object *mipwrt_obj;
	__u16 nphd = le16_to_cpu(log->nphd);
	__u16 pma = le16_to_cpu(log->pma);
	__u8 pmt = NVME_GET(pma, PMA_PMT);
	__u16 i;

	obj_add_uint(r, "ver", log->ver);
	obj_add_uint(r, "pmgn", log->pmgn);
	obj_add_uint(r, "pma", pma);
	obj_add_uint(r, "pme", NVME_GET(pma, PMA_PME));
	obj_add_uint(r, "ncpdf", NVME_GET(pma, PMA_NCPDF));
	obj_add_uint(r, "epf", NVME_GET(pma, PMA_EPF));
	obj_add_uint(r, "mipwrts", NVME_GET(pma, PMA_MIPWRTS));
	obj_add_uint(r, "phdo", NVME_GET(pma, PMA_PHDO));
	obj_add_uint(r, "pmt", pmt);
	obj_add_str(r, "pmt_str", nvme_power_measurement_type_to_string(pmt));
	obj_add_uint(r, "sze", le32_to_cpu(log->sze));
	obj_add_uint(r, "pmc", le32_to_cpu(log->pmc));
	obj_add_uint(r, "nphd", nphd);
	obj_add_uint(r, "smtr", le16_to_cpu(log->smtr));

	smts_obj = json_create_object();
	json_timestamp(smts_obj, &log->smts);
	obj_add_obj(r, "smts", smts_obj);

	obj_add_uint(r, "phds", le16_to_cpu(log->phds));
	obj_add_uint(r, "phbs", le16_to_cpu(log->phbs));
	obj_add_uint(r, "nphds", le16_to_cpu(log->nphds));
	obj_add_uint(r, "vss", le16_to_cpu(log->vss));
	obj_add_uint(r, "phdoc", le32_to_cpu(log->phdoc));
	obj_add_uint(r, "aipwr", le32_to_cpu(log->aipwr));
	obj_add_uint(r, "mipwr", le32_to_cpu(log->mipwr));

	mipwrt_obj = json_create_object();
	json_timestamp(mipwrt_obj, &log->mipwrt);
	obj_add_obj(r, "mipwrt", mipwrt_obj);

	obj_add_uint(r, "ipwrpe", log->ipwrpe);

	/* the descriptors the buffer holds */
	nphd = nvme_log_nr_entries(nphd, size, sizeof(*log),
				   sizeof(log->descs[0]));
	descs = json_create_array();
	for (i = 0; i < nphd; i++) {
		struct json_object *desc = json_create_object();

		obj_add_uint(desc, "phbc", le32_to_cpu(log->descs[i].phbc));
		obj_add_uint(desc, "phblt", le32_to_cpu(log->descs[i].phblt));
		json_object_array_add(descs, desc);
	}
	obj_add_obj(r, "descs", descs);
}

static void json_voltage_meas_log(struct nvme_voltage_measurement_log *log,
				  __u32 size)
{
	struct json_object *r = json_root();
	struct json_object *ivmds;
	struct json_object *ts_obj;
	__u8 vma = log->vma;
	__u16 vsi = le16_to_cpu(log->vsi);
	__u16 nvmde = le16_to_cpu(log->nvmde);
	__u16 ovol = le16_to_cpu(log->ovol);
	__u16 uvol = le16_to_cpu(log->uvol);
	__u16 i;

	obj_add_uint(r, "vmgn", log->vmgn);
	obj_add_uint(r, "vma", vma);
	obj_add_uint(r, "vme", !!(vma & NVME_VOLTAGE_MEASUREMENT_VMA_VME));
	obj_add_uint(r, "ivolts",
		     !!(vma & NVME_VOLTAGE_MEASUREMENT_VMA_IVOLTS));
	obj_add_uint(r, "vsm", NVME_VOLTAGE_MEASUREMENT_VMA_VSM(vma));
	obj_add_uint(r, "vmc", !!(vma & NVME_VOLTAGE_MEASUREMENT_VMA_VMC));
	obj_add_uint(r, "vsi", vsi);
	obj_add_uint(r, "vssv", NVME_VOLTAGE_MEASUREMENT_VSI_VSSV(vsi));
	obj_add_uint(r, "vssl", NVME_VOLTAGE_MEASUREMENT_VSI_VSSL(vsi));
	obj_add_uint(r, "vsss", NVME_VOLTAGE_MEASUREMENT_VSI_VSSS(vsi));
	obj_add_uint(r, "vmlsz", le32_to_cpu(log->vmlsz));
	obj_add_uint(r, "nvmds", le16_to_cpu(log->nvmds));
	obj_add_uint(r, "nvmde", nvmde);
	obj_add_uint(r, "svmtr", le16_to_cpu(log->svmtr));

	ts_obj = json_create_object();
	json_timestamp(ts_obj, &log->svmts);
	obj_add_obj(r, "svmts", ts_obj);

	obj_add_uint(r, "cntlid", le16_to_cpu(log->cntlid));
	obj_add_uint(r, "vlvss", le16_to_cpu(log->vlvss));

	obj_add_uint(r, "ovol", ovol);
	obj_add_uint(r, "movv", NVME_VOLTAGE_MEASUREMENT_OVOL_MOVV(ovol));
	obj_add_uint(r, "ovv", !!(ovol & NVME_VOLTAGE_MEASUREMENT_OVOL_OVV));
	obj_add_uint(r, "ovc", le16_to_cpu(log->ovc));
	obj_add_uint(r, "ovlt", le16_to_cpu(log->ovlt));

	ts_obj = json_create_object();
	json_timestamp(ts_obj, &log->ovts);
	obj_add_obj(r, "ovts", ts_obj);

	obj_add_uint(r, "iovpe", log->iovpe);

	obj_add_uint(r, "uvol", uvol);
	obj_add_uint(r, "muvv", NVME_VOLTAGE_MEASUREMENT_UVOL_MUVV(uvol));
	obj_add_uint(r, "uvv", !!(uvol & NVME_VOLTAGE_MEASUREMENT_UVOL_UVV));
	obj_add_uint(r, "uvc", le16_to_cpu(log->uvc));
	obj_add_uint(r, "uvlt", le16_to_cpu(log->uvlt));

	ts_obj = json_create_object();
	json_timestamp(ts_obj, &log->uvts);
	obj_add_obj(r, "uvts", ts_obj);

	obj_add_uint(r, "iuvpe", log->iuvpe);

	/* the descriptors the buffer holds */
	nvmde = nvme_log_nr_entries(nvmde, size, sizeof(*log),
				    sizeof(log->ivmd[0]));
	ivmds = json_create_array();
	for (i = 0; i < nvmde; i++) {
		struct json_object *ivmd = json_create_object();
		__u16 v = le16_to_cpu(log->ivmd[i]);

		obj_add_uint(ivmd, "volv",
			     NVME_VOLTAGE_MEASUREMENT_IVMD_VOLV(v));
		obj_add_uint(ivmd, "ncvm",
			     !!(v & NVME_VOLTAGE_MEASUREMENT_IVMD_NCVM));
		json_object_array_add(ivmds, ivmd);
	}
	obj_add_obj(r, "ivmd", ivmds);
}

static struct log_print_ops json_log_print_ops = {
	.ana_log = json_ana_log,
	.boot_part_log = json_boot_part_log,
	.phy_rx_eom_log = json_phy_rx_eom_log,
	.effects_log_list = json_effects_log_list,
	.endurance_group_event_agg_log = json_endurance_group_event_agg_log,
	.endurance_log = json_endurance_log,
	.error_log = json_error_log,
	.fid_supported_effects_log = json_fid_support_effects_log,
	.fw_log = json_fw_log,
	.lba_status_log = json_lba_status_log,
	.media_unit_stat_log = json_media_unit_stat_log,
	.mi_cmd_support_effects_log = json_mi_cmd_support_effects_log,
	.ns_list_log = json_changed_ns_list_log,
	.persistent_event_log = json_persistent_event_log,
	.predictable_latency_event_agg_log =
		json_predictable_latency_event_agg_log,
	.predictable_latency_per_nvmset = json_predictable_latency_per_nvmset,
	.resv_notification_log = json_resv_notif_log,
	.sanitize_log_page = json_sanitize_log,
	.self_test_log = json_self_test_log,
	.smart_log = json_smart_log,
	.supported_cap_config_list_log = json_supported_cap_config_log,
	.supported_log_pages = json_support_log,
	.voltage_meas_log = json_voltage_meas_log,
	.mgmt_addr_list_log = json_mgmt_addr_list_log,
	.rotational_media_info_log = json_rotational_media_info_log,
	.dispersed_ns_psub_log = json_dispersed_ns_psub_log,
	.reachability_groups_log = json_reachability_groups_log,
	.reachability_associations_log = json_reachability_associations_log,
	.host_discovery_log = json_host_discovery_log,
	.ave_discovery_log = json_ave_discovery_log,
	.pull_model_ddc_req_log = json_pull_model_ddc_req_log,
	.power_meas_log = json_power_meas_log,
};

struct log_print_ops *log_get_json_print_ops(void)
{
	return &json_log_print_ops;
}
