// SPDX-License-Identifier: GPL-2.0-or-later
#include <time.h>

#ifdef CONFIG_FABRICS
#include <arpa/inet.h>
#endif /* CONFIG_FABRICS */

#include <ccan/array_size/array_size.h>
#include <ccan/minmax/minmax.h>
#include <shared/string-util.h>
#include <shared/unaligned-util.h>

#include "cleanup.h"
#include "logging.h"
#include "nvme-print.h"
#include "nvme-print-stdout.h"

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

void stdout_fdp_configs(struct nvme_fdp_config_log *log, size_t len)
{
	unsigned char *p, *end;
	int verbose = stdout_print_ops.flags & VERBOSE;
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

void stdout_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len)
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

void stdout_fdp_stats(struct nvme_fdp_stats_log *log)
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

void stdout_fdp_events(struct nvme_fdp_events_log *log)
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

#ifdef CONFIG_FABRICS
void stdout_discovery_log(const struct nvmf_discovery_log *log, int numrec)
{
	int i;

	printf("\nDiscovery Log Number of Records %d, Generation counter %"
	       PRIu64"\n", numrec, le64_to_cpu(log->genctr));

	for (i = 0; i < numrec; i++) {
		const struct nvmf_disc_log_entry *e = &log->entries[i];

		/*
		 * e->trsvcid/subnqn/traddr are fixed-width fields off the
		 * wire, space-padded per the spec, and not guaranteed
		 * NUL-terminated by a non-compliant DC. shr_buf2str() bounds
		 * the read to the field's own size and strips the padding.
		 */
		__cleanup_free char *trsvcid = NULL;
		__cleanup_free char *subnqn = NULL;
		__cleanup_free char *traddr = NULL;
		struct shr_table *t;

		trsvcid = shr_buf2str(e->trsvcid, sizeof(e->trsvcid));
		subnqn = shr_buf2str(e->subnqn, sizeof(e->subnqn));
		traddr = shr_buf2str(e->traddr, sizeof(e->traddr));

		printf("=====Discovery Log Entry %d======\n", i);

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "trtype", "%s", libnvmf_trtype_str(e->trtype));
		stdout_kv_add(t, "adrfam", "%s",
			      e->traddr[0] ?
			      libnvmf_adrfam_str(e->adrfam) : "");
		stdout_kv_add(t, "subtype", "%s",
			      libnvmf_subtype_str(e->subtype));
		stdout_kv_add(t, "treq", "%s", libnvmf_treq_str(e->treq));
		stdout_kv_add(t, "portid", "%d", le16_to_cpu(e->portid));
		stdout_kv_add(t, "trsvcid", "%s", trsvcid);
		stdout_kv_add(t, "subnqn", "%s", subnqn);
		stdout_kv_add(t, "traddr", "%s", traddr);
		stdout_kv_add(t, "eflags", "%s",
			      libnvmf_eflags_str(le16_to_cpu(e->eflags)));

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			stdout_kv_add(t, "rdma_prtype", "%s",
				      libnvmf_prtype_str(e->tsas.rdma.prtype));
			stdout_kv_add(t, "rdma_qptype", "%s",
				      libnvmf_qptype_str(e->tsas.rdma.qptype));
			stdout_kv_add(t, "rdma_cms", "%s",
				      libnvmf_cms_str(e->tsas.rdma.cms));
			stdout_kv_add(t, "rdma_pkey", "%#04x",
				      le16_to_cpu(e->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			stdout_kv_add(t, "sectype", "%s",
				      libnvmf_sectype_str(e->tsas.tcp.sectype));
			break;
		}

		stdout_kv_table_finish(t, "discovery-log");
	}
}

#endif /* CONFIG_FABRICS */
