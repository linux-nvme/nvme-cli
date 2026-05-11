// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Helpers for nvme top dashboard
 *
 * Copyright (c) 2026 Nilay Shroff, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define IOPS_UNIT_NONE		""
#define IOPS_UNIT_KB		"k"

#define BW_UNIT_BYTES_PER_SEC	"B/s"
#define BW_UNIT_KIB_PER_SEC	"KiB/s"
#define BW_UNIT_MIB_PER_SEC	"MiB/s"

#define BW_KIB	1024
#define BW_MIB	(BW_KIB * 1024)

#include <libnvme.h>
#include "nvme-top.h"

static double nvme_calc_util_percent(unsigned int ticks, double interval_ms)
{
	if (!interval_ms)
		return 0;

	return (ticks / interval_ms) * 100;
}

static double nvme_path_calc_util_percent(libnvme_path_t p, double interval_ms)
{
	unsigned int ticks;

	ticks = libnvme_path_get_io_ticks(p);
	return nvme_calc_util_percent(ticks, interval_ms);
}

static double nvme_ns_calc_util_percent(libnvme_ns_t n, double interval_ms)
{
	unsigned int ticks;

	ticks = libnvme_ns_get_io_ticks(n);
	return nvme_calc_util_percent(ticks, interval_ms);
}

static double nvme_calc_iops(unsigned long ios, double interval_ms)
{
	double interval_sec;

	if (interval_ms < 1000)
		return 0;

	interval_sec = interval_ms / 1000;
	return (ios / interval_sec);
}

static double nvme_path_calc_read_iops(libnvme_path_t p, double interval_ms)
{
	unsigned long read_ios;

	read_ios = libnvme_path_get_read_ios(p);
	return nvme_calc_iops(read_ios, interval_ms);
}

static double nvme_path_calc_write_iops(libnvme_path_t p, double interval_ms)
{
	unsigned long write_ios;

	write_ios = libnvme_path_get_write_ios(p);
	return nvme_calc_iops(write_ios, interval_ms);
}

static double nvme_ns_calc_read_iops(libnvme_ns_t n, double interval_ms)
{
	unsigned long read_ios;

	read_ios = libnvme_ns_get_read_ios(n);
	return nvme_calc_iops(read_ios, interval_ms);
}

static double nvme_ns_calc_write_iops(libnvme_ns_t n, double interval_ms)
{
	unsigned long write_ios;

	write_ios = libnvme_ns_get_write_ios(n);
	return nvme_calc_iops(write_ios, interval_ms);
}

static double nvme_calc_latency(unsigned long ticks, unsigned long ios)
{
	if (!ios)
		return 0;

	return ((double)ticks/ios);
}

static double nvme_path_calc_read_latency(libnvme_path_t p)
{
	unsigned int ticks;
	unsigned long ios;

	ticks = libnvme_path_get_read_ticks(p);
	ios = libnvme_path_get_read_ios(p);

	return nvme_calc_latency(ticks, ios);
}

static double nvme_path_calc_write_latency(libnvme_path_t p)
{
	unsigned int ticks;
	unsigned long ios;

	ticks = libnvme_path_get_write_ticks(p);
	ios = libnvme_path_get_write_ios(p);

	return nvme_calc_latency(ticks, ios);
}

static double nvme_ns_calc_read_latency(libnvme_ns_t n)
{
	unsigned int ticks;
	unsigned long ios;

	ticks = libnvme_ns_get_read_ticks(n);
	ios = libnvme_ns_get_read_ios(n);

	return nvme_calc_latency(ticks, ios);
}

static double nvme_ns_calc_write_latency(libnvme_ns_t n)
{
	unsigned int ticks;
	unsigned long ios;

	ticks = libnvme_ns_get_write_ticks(n);
	ios = libnvme_ns_get_write_ios(n);

	return nvme_calc_latency(ticks, ios);
}

static double nvme_calc_bandwidth(unsigned long long sectors,
			double interval_ms)
{
	double bytes;
	double sec;

	if (interval_ms < 1000)
		return 0;

	sec = interval_ms / 1000;
	bytes = sectors * 512;
	return (bytes / sec);
}

static double nvme_path_calc_read_bw(libnvme_path_t p, double interval_ms)
{
	unsigned long long sectors;

	sectors = libnvme_path_get_read_sectors(p);
	return nvme_calc_bandwidth(sectors, interval_ms);
}

static double nvme_path_calc_write_bw(libnvme_path_t p, double interval_ms)
{
	unsigned long long sectors;

	sectors = libnvme_path_get_write_sectors(p);
	return nvme_calc_bandwidth(sectors, interval_ms);
}

static double nvme_ns_calc_read_bw(libnvme_ns_t n, double interval_ms)
{
	unsigned long long sectors;

	sectors = libnvme_ns_get_read_sectors(n);
	return nvme_calc_bandwidth(sectors, interval_ms);
}

static double nvme_ns_calc_write_bw(libnvme_ns_t n, double interval_ms)
{
	unsigned long long sectors;

	sectors = libnvme_ns_get_write_sectors(n);
	return nvme_calc_bandwidth(sectors, interval_ms);
}

int nvme_format_iops(double iops, char *buf, size_t size)
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

int nvme_format_bw(double bw, char *buf, size_t size)
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

void nvme_ns_calc_aggr_stat(libnvme_ns_t n, double *r_iops, double *w_iops,
		double *r_bw, double *w_bw, double *max_rlat, double *max_wlat,
		double *max_util)
{
	double interval_ms, rlat, wlat, util;

	interval_ms = libnvme_ns_get_stat_interval(n);
	if (!interval_ms)
		return;

	*r_iops += nvme_ns_calc_read_iops(n, interval_ms);
	*w_iops += nvme_ns_calc_write_iops(n, interval_ms);

	*r_bw += nvme_ns_calc_read_bw(n, interval_ms);
	*w_bw += nvme_ns_calc_write_bw(n, interval_ms);

	rlat = nvme_ns_calc_read_latency(n);
	if (rlat > *max_rlat)
		*max_rlat = rlat;

	wlat = nvme_ns_calc_write_latency(n);
	if (wlat > *max_wlat)
		*max_wlat = wlat;

	util = nvme_ns_calc_util_percent(n, interval_ms);
	if (util > *max_util)
		*max_util = util;
}

void nvme_path_calc_aggr_stat(libnvme_path_t p, double *r_iops, double *w_iops,
		double *r_bw, double *w_bw, double *max_rlat, double *max_wlat,
		double *max_util)
{
	double interval_ms, rlat, wlat, util;

	interval_ms = libnvme_path_get_stat_interval(p);
	if (!interval_ms)
		return;

	*r_iops += nvme_path_calc_read_iops(p, interval_ms);
	*w_iops += nvme_path_calc_write_iops(p, interval_ms);

	*r_bw += nvme_path_calc_read_bw(p, interval_ms);
	*w_bw += nvme_path_calc_write_bw(p, interval_ms);

	rlat = nvme_path_calc_read_latency(p);
	if (rlat > *max_rlat)
		*max_rlat = rlat;

	wlat = nvme_path_calc_write_latency(p);
	if (wlat > *max_wlat)
		*max_wlat = wlat;

	util = nvme_path_calc_util_percent(p, interval_ms);
	if (util > *max_util)
		*max_util = util;
}

void nvme_ns_calc_stat(libnvme_ns_t n, double *r_iops, double *w_iops,
		double *r_lat, double *w_lat, double *r_bw, double *w_bw,
		double *util, unsigned int *inflights)
{
	double interval_ms;

	interval_ms = libnvme_ns_get_stat_interval(n);
	if (!interval_ms)
		return;

	/* calculate R/W IOPS */
	*r_iops = nvme_ns_calc_read_iops(n, interval_ms);
	*w_iops = nvme_ns_calc_write_iops(n, interval_ms);

	/* calculate R/W latency */
	*r_lat = nvme_ns_calc_read_latency(n);
	*w_lat = nvme_ns_calc_write_latency(n);

	/* calculate R/W bandwidth */
	*r_bw = nvme_ns_calc_read_bw(n, interval_ms);
	*w_bw = nvme_ns_calc_write_bw(n, interval_ms);

	/* get inflights counter */
	*inflights = libnvme_ns_get_inflights(n);

	/* calculate util percent */
	*util = nvme_ns_calc_util_percent(n, interval_ms);
}

void nvme_path_calc_stat(libnvme_path_t p, double *r_iops, double *w_iops,
		double *r_lat, double *w_lat, double *r_bw, double *w_bw,
		double *util, unsigned int *inflights)
{
	double interval_ms;

	interval_ms = libnvme_path_get_stat_interval(p);
	if (!interval_ms)
		return;

	/* calculate R/W IOPS */
	*r_iops = nvme_path_calc_read_iops(p, interval_ms);
	*w_iops = nvme_path_calc_write_iops(p, interval_ms);

	/* calculate R/W latency */
	*r_lat = nvme_path_calc_read_latency(p);
	*w_lat = nvme_path_calc_write_latency(p);

	/* calculate R/W bandwidth */
	*r_bw = nvme_path_calc_read_bw(p, interval_ms);
	*w_bw = nvme_path_calc_write_bw(p, interval_ms);

	/* get inflights counter */
	*inflights = libnvme_path_get_inflights(p);

	/* calculate util percent */
	*util = nvme_path_calc_util_percent(p, interval_ms);
}
