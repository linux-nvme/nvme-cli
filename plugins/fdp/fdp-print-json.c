// SPDX-License-Identifier: GPL-2.0-or-later

#include <string.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <shared/int-util.h>
#include <shared/mem-util.h>
#include <shared/uint128-util.h>

#include "fdp-print.h"
#include "nvme-print.h"
#include "nvme-print-json.h"

static void json_nvme_fdp_configs(struct nvme_fdp_config_log *log, size_t len)
{
	struct json_object *r, *obj_configs;
	unsigned char *p, *end;
	uint16_t n;

	r = json_root();
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

	r = json_root();
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
	struct json_object *r = json_root();

	obj_add_uint128(r, "hbmw", le128_to_cpu(log->hbmw));
	obj_add_uint128(r, "mbmw", le128_to_cpu(log->mbmw));
	obj_add_uint128(r, "mbe", le128_to_cpu(log->mbe));
}

static void json_nvme_fdp_events(struct nvme_fdp_events_log *log)
{
	struct json_object *r, *obj_events;
	uint32_t n;

	r = json_root();
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

			mr = (struct nvme_fdp_event_realloc *)
			     &event->type_specific;

			obj_add_uint(obj_event, "nlbam",
				     le16_to_cpu(mr->nlbam));

			if (mr->flags & NVME_FDP_EVENT_REALLOC_F_LBAV)
				obj_add_uint64(obj_event, "lba",
					       le64_to_cpu(mr->lba));
		}

		array_add_obj(obj_events, obj_event);
	}

	obj_add_array(r, "events", obj_events);
}

static void json_nvme_fdp_ruh_status(struct nvme_fdp_ruh_status *status,
				     size_t len)
{
	struct json_object *r, *obj_ruhss;
	uint16_t nruhsd;

	r = json_root();
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

static struct fdp_print_ops json_fdp_print_ops = {
	.config_log	= json_nvme_fdp_configs,
	.event_log	= json_nvme_fdp_events,
	.ruh_status	= json_nvme_fdp_ruh_status,
	.stats_log	= json_nvme_fdp_stats,
	.usage_log	= json_nvme_fdp_usage,
};

struct fdp_print_ops *fdp_get_json_print_ops(nvme_print_flags_t flags)
{
	json_fdp_print_ops.flags = flags;
	return &json_fdp_print_ops;
}
