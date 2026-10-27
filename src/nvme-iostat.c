// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * I/O statistics of NVMe namespaces and paths
 *
 * Copyright (c) 2026 Nilay Shroff, IBM
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Nilay Shroff <nilay@linux.ibm.com>
 *          Daniel Wagner <dwagner@suse.de>
 */

#include <stdio.h>

#include <libnvme.h>

#include "nvme-iostat.h"

#define IOPS_UNIT_NONE		""
#define IOPS_UNIT_KB		"k"

#define BW_UNIT_BYTES_PER_SEC	"B/s"
#define BW_UNIT_KIB_PER_SEC	"KiB/s"
#define BW_UNIT_MIB_PER_SEC	"MiB/s"

#define BW_KIB	1024
#define BW_MIB	(BW_KIB * 1024)

static double nvme_calc_util_percent(unsigned int ticks, double interval_ms)
{
	if (!interval_ms)
		return 0;

	return (ticks / interval_ms) * 100;
}

static double nvme_calc_iops(unsigned long ios, double interval_ms)
{
	double interval_sec;

	if (interval_ms < 1000)
		return 0;

	interval_sec = interval_ms / 1000;
	return (ios / interval_sec);
}

static double nvme_calc_latency(unsigned long ticks, unsigned long ios)
{
	if (!ios)
		return 0;

	return ((double)ticks/ios);
}

static double nvme_calc_bandwidth(unsigned long long sectors,
			double interval_ms)
{
	double bytes;
	double sec;

	if (interval_ms < 1000)
		return 0;

	sec = interval_ms / 1000;
	bytes = (double)sectors * 512;
	return (bytes / sec);
}

void nvme_iostat_calc(const struct nvme_iostat_sample *s,
		struct nvme_iostat *st)
{
	*st = (struct nvme_iostat){ 0 };

	if (!s->interval_ms)
		return;

	st->r_iops = nvme_calc_iops(s->r_ios, s->interval_ms);
	st->w_iops = nvme_calc_iops(s->w_ios, s->interval_ms);

	st->r_lat = nvme_calc_latency(s->r_ticks, s->r_ios);
	st->w_lat = nvme_calc_latency(s->w_ticks, s->w_ios);

	st->r_bw = nvme_calc_bandwidth(s->r_sectors, s->interval_ms);
	st->w_bw = nvme_calc_bandwidth(s->w_sectors, s->interval_ms);

	st->inflights = s->inflights;
	st->util = nvme_calc_util_percent(s->io_ticks, s->interval_ms);
}

void nvme_iostat_ns(struct libnvme_ns *n, struct nvme_iostat *st)
{
	struct nvme_iostat_sample s = {
		.interval_ms = libnvme_ns_get_stat_interval(n),
		.r_ios = libnvme_ns_get_read_ios(n),
		.w_ios = libnvme_ns_get_write_ios(n),
		.r_sectors = libnvme_ns_get_read_sectors(n),
		.w_sectors = libnvme_ns_get_write_sectors(n),
		.r_ticks = libnvme_ns_get_read_ticks(n),
		.w_ticks = libnvme_ns_get_write_ticks(n),
		.io_ticks = libnvme_ns_get_io_ticks(n),
		.inflights = libnvme_ns_get_inflights(n),
	};

	nvme_iostat_calc(&s, st);
}

void nvme_iostat_path(struct libnvme_path *p, struct nvme_iostat *st)
{
	struct nvme_iostat_sample s = {
		.interval_ms = libnvme_path_get_stat_interval(p),
		.r_ios = libnvme_path_get_read_ios(p),
		.w_ios = libnvme_path_get_write_ios(p),
		.r_sectors = libnvme_path_get_read_sectors(p),
		.w_sectors = libnvme_path_get_write_sectors(p),
		.r_ticks = libnvme_path_get_read_ticks(p),
		.w_ticks = libnvme_path_get_write_ticks(p),
		.io_ticks = libnvme_path_get_io_ticks(p),
		.inflights = libnvme_path_get_inflights(p),
	};

	nvme_iostat_calc(&s, st);
}

void nvme_iostat_aggr(struct nvme_iostat *aggr, const struct nvme_iostat *st)
{
	aggr->r_iops += st->r_iops;
	aggr->w_iops += st->w_iops;

	aggr->r_bw += st->r_bw;
	aggr->w_bw += st->w_bw;

	if (st->r_lat > aggr->r_lat)
		aggr->r_lat = st->r_lat;
	if (st->w_lat > aggr->w_lat)
		aggr->w_lat = st->w_lat;
	if (st->util > aggr->util)
		aggr->util = st->util;
}

void nvme_iostat_update_subsys(struct libnvme_subsystem *s, bool multipath)
{
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;
	struct libnvme_path *p;

	if (multipath) {
		libnvme_subsystem_for_each_ns(s, n) {
			libnvme_ns_update_stat(n, true);

			libnvme_namespace_for_each_path(n, p)
				libnvme_path_update_stat(p, true);
		}
	} else {
		libnvme_subsystem_for_each_ctrl(s, c) {
			libnvme_ctrl_for_each_ns(c, n)
				libnvme_ns_update_stat(n, true);
		}
	}
}

void nvme_iostat_reset_subsys(struct libnvme_subsystem *s, bool multipath)
{
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;
	struct libnvme_path *p;

	if (multipath) {
		libnvme_subsystem_for_each_ns(s, n) {
			libnvme_ns_reset_stat(n);

			libnvme_namespace_for_each_path(n, p)
				libnvme_path_reset_stat(p);
		}
	} else {
		libnvme_subsystem_for_each_ctrl(s, c) {
			libnvme_ctrl_for_each_ns(c, n)
				libnvme_ns_reset_stat(n);
		}
	}
}

int nvme_iostat_format_iops(double iops, char *buf, size_t size)
{
	char *unit;

	if (iops < 1000)
		unit = IOPS_UNIT_NONE;
	else {
		iops /= 1000;
		unit = IOPS_UNIT_KB;
	}

	return snprintf(buf, size, "%.2f%s", iops, unit);
}

int nvme_iostat_format_bw(double bw, char *buf, size_t size)
{
	char *unit = "";

	if (!bw)
		goto out;

	if (bw < BW_KIB)
		unit = BW_UNIT_BYTES_PER_SEC;
	else if (bw < BW_MIB) {
		bw /= BW_KIB;
		unit = BW_UNIT_KIB_PER_SEC;
	} else {
		bw /= BW_MIB;
		unit = BW_UNIT_MIB_PER_SEC;
	}

out:
	return snprintf(buf, size, "%.2f%s", bw, unit);
}

int nvme_iostat_format_lat(double lat, char *buf, size_t size)
{
	return snprintf(buf, size, "%.2f", lat);
}
