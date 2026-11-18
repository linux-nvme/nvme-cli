// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <shared/int-util.h>
#include <shared/mem-util.h>
#include <shared/table-util.h>
#include <shared/uint128-util.h>

#include "fdp-print.h"
#include "nvme-print.h"
#include "nvme-print-stdout.h"

static struct fdp_print_ops stdout_fdp_print_ops;

static struct shr_table *stdout_fdp_config_fdpa_table(uint8_t fdpa)
{
	struct shr_table *t;
	__u8 valid = NVME_GET(fdpa, FDP_CONFIG_FDPA_VALID);
	__u8 rsvd = (fdpa >> 5) & 0x3;
	__u8 fdpvwc = NVME_GET(fdpa, FDP_CONFIG_FDPA_FDPVWC);
	__u8 rgif = NVME_GET(fdpa, FDP_CONFIG_FDPA_RGIF);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:7]", valid, "FDP Configuration %sValid",
			valid ? "" : "Not ");
	if (rsvd)
		stdout_bits_add(t, "[6:5]", rsvd, "Reserved");
	stdout_bits_add(t, "[4:4]", fdpvwc,
			"FDP Volatile Write Cache %sPresent",
			fdpvwc ? "" : "Not ");
	stdout_bits_add(t, "[3:0]", rgif, "Reclaim Group Identifier Format");

	return t;
}

static struct shr_table *stdout_fdp_config_ruh_list_table(
		struct nvme_fdp_ruh_desc *ruhs, uint16_t nruh)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	shr_table_set_indent(t, 2);

	for (int j = 0; j < nruh; j++) {
		struct nvme_fdp_ruh_desc *ruh = &ruhs[j];
		const char *ruht_str;
		char name[16];

		if (ruh->ruht == NVME_FDP_RUHT_INITIALLY_ISOLATED)
			ruht_str = "Initially Isolated";
		else
			ruht_str = "Persistently Isolated";

		snprintf(name, sizeof(name), "[%d]", j);
		stdout_kv_add(t, name, "%s", ruht_str);
	}

	return t;
}

static void stdout_fdp_configs(struct nvme_fdp_config_log *log, size_t len)
{
	unsigned char *p, *end;
	int verbose = stdout_fdp_print_ops.flags & VERBOSE;
	uint16_t n;
	struct shr_table *t;
	int row;

	if (len < sizeof(*log))
		return;

	p = (unsigned char *)log->configs;
	end = (unsigned char *)log + len;
	n = le16_to_cpu(log->n) + 1;

	for (int i = 0; i < n; i++) {
		struct nvme_fdp_config_desc config;
		struct nvme_fdp_ruh_desc *ruhs;
		uint16_t size, nruh, max_nruh;

		if (!shr_buf_has_room(p, end, sizeof(config)))
			break;

		/* descriptors are only 4 byte aligned */
		memcpy(&config, p, sizeof(config));
		ruhs = (struct nvme_fdp_ruh_desc *)(p + sizeof(config));

		t = stdout_kv_table_create();
		if (!t)
			return;

		row = stdout_kv_add(t, "FDP Attributes", "%#x", config.fdpa);
		if (verbose)
			shr_table_set_row_subtable(t, row,
				stdout_fdp_config_fdpa_table(config.fdpa));

		stdout_kv_add(t, "Vendor Specific Size", "%u", config.vss);
		stdout_kv_add(t, "Number of Reclaim Groups", "%"PRIu32,
			      le32_to_cpu(config.nrg));
		stdout_kv_add(t, "Number of Reclaim Unit Handles", "%"PRIu16,
			      le16_to_cpu(config.nruh));
		stdout_kv_add(t, "Number of Namespaces Supported", "%"PRIu32,
			      le32_to_cpu(config.nnss));
		stdout_kv_add(t, "Reclaim Unit Nominal Size", "%"PRIu64,
			      le64_to_cpu(config.runs));
		stdout_kv_add(t, "Estimated Reclaim Unit Time Limit", "%"PRIu32,
			      le32_to_cpu(config.erutl));

		size = le16_to_cpu(config.size);
		if (size < sizeof(config) || !shr_buf_has_room(p, end, size)) {
			stdout_kv_table_finish(t, "fdp-configs");
			break;
		}

		nruh = le16_to_cpu(config.nruh);
		max_nruh = (size - sizeof(config)) / sizeof(*ruhs);
		if (nruh > max_nruh)
			nruh = max_nruh;

		if (nruh) {
			row = stdout_kv_add(t, "Reclaim Unit Handle List", "");
			shr_table_set_row_subtable(t, row,
				stdout_fdp_config_ruh_list_table(ruhs, nruh));
		}

		stdout_kv_table_finish(t, "fdp-configs");

		p += size;
	}
}

static void stdout_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len)
{
	uint16_t nruh = nvme_log_nr_entries(le16_to_cpu(log->nruh), len,
					    sizeof(*log),
					    sizeof(log->ruhus[0]));
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (int i = 0; i < nruh; i++) {
		struct nvme_fdp_ruhu_desc *ruhu = &log->ruhus[i];
		const char *ruha_str;
		char name[48];

		switch (ruhu->ruha) {
		case 0x0:
			ruha_str = "Unused";
			break;
		case 0x1:
			ruha_str = "Host Specified";
			break;
		case 0x2:
			ruha_str = "Controller Specified";
			break;
		default:
			ruha_str = "Unknown";
			break;
		}

		snprintf(name, sizeof(name),
			 "Reclaim Unit Handle %d Attributes", i);
		stdout_kv_add(t, name, "%#"PRIx8" (%s)", ruhu->ruha, ruha_str);
	}

	stdout_kv_table_finish(t, "fdp-usage");
}

static void stdout_fdp_stats(struct nvme_fdp_stats_log *log)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Host Bytes with Metadata Written (HBMW)", "%s",
		      uint128_t_to_l10n_string(le128_to_cpu(log->hbmw)));
	stdout_kv_add(t, "Media Bytes with Metadata Written (MBMW)", "%s",
		      uint128_t_to_l10n_string(le128_to_cpu(log->mbmw)));
	stdout_kv_add(t, "Media Bytes Erased (MBE)", "%s",
		      uint128_t_to_l10n_string(le128_to_cpu(log->mbe)));

	stdout_kv_table_finish(t, "fdp-stats");
}

static void stdout_fdp_events(struct nvme_fdp_events_log *log)
{
	struct tm *tm;
	char buffer[320];
	time_t ts;
	uint32_t n = le32_to_cpu(log->n);
	struct shr_table *t;

	for (unsigned int i = 0; i < n && i < ARRAY_SIZE(log->events); i++) {
		struct nvme_fdp_event *event = &log->events[i];

		ts = int48_to_long(event->ts.timestamp) / 1000;
		tm = localtime(&ts);

		printf("Event[%u]\n", i);

		t = stdout_kv_table_create();
		if (!t)
			return;

		shr_table_set_indent(t, 2);

		stdout_kv_add(t, "Event Type", "%#"PRIx8" (%s)", event->type,
			      nvme_fdp_event_to_string(event->type));
		stdout_kv_add(t, "Event Timestamp", "%"PRIu64" (%s)",
			      int48_to_long(event->ts.timestamp),
			      strftime(buffer, sizeof(buffer), "%c %Z", tm) ?
			      buffer : "-");

		if (event->flags & NVME_FDP_EVENT_F_PIV)
			stdout_kv_add(t, "Placement Identifier (PID)",
				      "%#"PRIx16, le16_to_cpu(event->pid));

		if (event->flags & NVME_FDP_EVENT_F_NSIDV)
			stdout_kv_add(t, "Namespace Identifier (NSID)",
				      "%"PRIu32, le32_to_cpu(event->nsid));

		if (event->type == NVME_FDP_EVENT_REALLOC) {
			struct nvme_fdp_event_realloc *mr;

			mr = (struct nvme_fdp_event_realloc *)
			     &event->type_specific;

			stdout_kv_add(t, "Number of LBAs Moved (NLBAM)",
				      "%"PRIu16, le16_to_cpu(mr->nlbam));

			if (mr->flags & NVME_FDP_EVENT_REALLOC_F_LBAV)
				stdout_kv_add(t, "Logical Block Address (LBA)",
					      "%#"PRIx64,
					      le64_to_cpu(mr->lba));
		}

		if (event->flags & NVME_FDP_EVENT_F_LV) {
			stdout_kv_add(t, "Reclaim Group Identifier", "%"PRIu16,
				      le16_to_cpu(event->rgid));
			stdout_kv_add(t, "Reclaim Unit Handle Identifier",
				      "%"PRIu8, event->ruhid);
		}

		stdout_kv_table_finish(t, "fdp-events");

		printf("\n");
	}
}

static void stdout_fdp_ruh_status(struct nvme_fdp_ruh_status *status,
				  size_t len)
{
	uint16_t nruhsd = nvme_log_nr_entries(le16_to_cpu(status->nruhsd),
					      len, sizeof(*status),
					      sizeof(status->ruhss[0]));
	struct shr_table *t;

	for (unsigned int i = 0; i < nruhsd; i++) {
		struct nvme_fdp_ruh_status_desc *ruhs = &status->ruhss[i];

		t = stdout_kv_table_create();
		if (!t)
			return;

		shr_table_set_indent(t, 2);

		stdout_kv_add(t, "Placement Identifier (PID)", "%"PRIu16,
			      le16_to_cpu(ruhs->pid));
		stdout_kv_add(t, "Reclaim Unit Handle Identifier", "%"PRIu16,
			      le16_to_cpu(ruhs->ruhid));
		stdout_kv_add(t,
			      "Estimated Active Reclaim Unit Time Remaining (EARUTR)",
			      "%"PRIu32, le32_to_cpu(ruhs->earutr));
		stdout_kv_add(t, "Reclaim Unit Available Media Writes (RUAMW)",
			      "%"PRIu64, le64_to_cpu(ruhs->ruamw));

		stdout_kv_table_finish(t, "fdp-ruh-status");

		printf("\n");
	}
}

static struct fdp_print_ops stdout_fdp_print_ops = {
	.config_log	= stdout_fdp_configs,
	.event_log	= stdout_fdp_events,
	.ruh_status	= stdout_fdp_ruh_status,
	.stats_log	= stdout_fdp_stats,
	.usage_log	= stdout_fdp_usage,
};

struct fdp_print_ops *fdp_get_stdout_print_ops(nvme_print_flags_t flags)
{
	stdout_fdp_print_ops.flags = flags;
	return &stdout_fdp_print_ops;
}
