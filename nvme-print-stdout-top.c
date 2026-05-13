// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Implements nvme top dashboard
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

#include <stdio.h>
#include <stddef.h>
#include <libnvme.h>

#include "nvme.h"
#include "nvme-print.h"
#include "common.h"
#include "logging.h"
#include "util/dashboard.h"
#include "util/table.h"

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
	bytes = (double)sectors * 512;
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

static int nvme_format_iops(double iops, char *buf, size_t size)
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

static int nvme_format_bw(double bw, char *buf, size_t size)
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

static int nvme_format_lat(double lat, char *buf, size_t size)
{
	return snprintf(buf, size, "%.2f", lat);
}

static void nvme_ns_calc_aggr_stat(libnvme_ns_t n,
			double *r_iops, double *w_iops,
			double *r_bw, double *w_bw,
			double *max_rlat, double *max_wlat,
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

static void nvme_path_calc_aggr_stat(libnvme_path_t p,
			double *r_iops, double *w_iops,
			double *r_bw, double *w_bw,
			double *max_rlat, double *max_wlat,
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

static void nvme_ns_calc_stat(libnvme_ns_t n,
			double *r_iops, double *w_iops,
			double *r_lat, double *w_lat,
			double *r_bw, double *w_bw,
			double *util,
			unsigned int *inflights)
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

static void nvme_path_calc_stat(libnvme_path_t p,
			double *r_iops, double *w_iops,
			double *r_lat, double *w_lat,
			double *r_bw, double *w_bw,
			double *util,
			unsigned int *inflights)
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

static bool stdout_top_nvme_ctrl_is_fabric(libnvme_ctrl_t c)
{
	if (strcmp(libnvme_ctrl_get_transport(c), "pcie"))
		return true;
	else
		return false;
}

static bool stdout_top_print_ctrl_summary_tbl_filter(const char *name,
		void *arg)
{
	libnvme_ctrl_t c;
	libnvme_subsystem_t s = arg;
	bool multipath = nvme_is_multipath(s);

	if (!strcmp(name, "Paths")) {
		if (!multipath)
			return false;
	}

	if (!strcmp(name, "Reconnects")) {
		c = libnvme_subsystem_first_ctrl(s);
		if (c) {
			if (stdout_top_nvme_ctrl_is_fabric(c))
				return true;
			else
				return false;
		}
	}

	return true;
}

static int stdout_top_print_path_health(FILE *stream, libnvme_subsystem_t s)
{
	int ret = 0;
	int col, row;
	libnvme_ns_t n;
	libnvme_path_t p;
	struct table *t;
	struct table_column columns[] = {
		{"NSPath", LEFT},
		{"ANAState", LEFT},
		{"Retries", LEFT},
		{"Failovers", LEFT},
		{"Errors", LEFT}
	};

	t = table_create();
	if (!t) {
		nvme_show_error("Failed to init path health table\n");
		return 1;
	}

	if (table_add_columns(t, columns, ARRAY_SIZE(columns)) < 0) {
		nvme_show_error("Failed to add columns to path health table\n");
		ret = 1;
		goto free_tbl;
	}

	fprintf(stream, "\n------------ Path Health -------------\n\n");
	libnvme_subsystem_for_each_ns(s, n) {
		libnvme_namespace_for_each_path(n, p) {

			row = table_get_row_id(t);
			if (row < 0) {
				nvme_show_error("Failed to add row to path health table\n");
				goto free_tbl;
			}

			col = -1;

			table_set_value_str(t, ++col, row,
			    libnvme_path_get_name(p), LEFT);
			table_set_value_str(t, ++col, row,
			    libnvme_path_get_ana_state(p), LEFT);
			table_set_value_long(t, ++col, row,
			    libnvme_path_get_command_retry_count(p), LEFT);
			table_set_value_long(t, ++col, row,
			    libnvme_path_get_multipath_failover_count(p), LEFT);
			table_set_value_int(t, ++col, row,
			    libnvme_path_get_command_error_count(p), LEFT);

			table_add_row(t, row);
		}
	}

	table_print_stream(stream, t);
free_tbl:
	table_free(t);
	return ret;
}

static int stdout_top_print_ctrl_summary(FILE *stream,
		libnvme_subsystem_t s, bool multipath)
{
	int ret = 0;
	int row, col, npaths;
	libnvme_ctrl_t c;
	libnvme_path_t p;
	libnvme_ns_t n;
	double max_util, max_rlat, max_wlat;
	double r_iops, w_iops, r_bw, w_bw;
	char r_bw_str[16], w_bw_str[16];
	char r_iops_str[16], w_iops_str[16];
	char r_clat_str[16], w_clat_str[16];
	const char *node;
	struct table *t;
	bool is_fabric = false;
	struct table_column columns[] = {
		{"Ctrl", LEFT},
		{"Paths", LEFT},
		{"Node", LEFT},
		{"Trtype", LEFT},
		{"Address", LEFT},
		{"State", LEFT},
		{"Resets", LEFT},
		{"Reconnects", LEFT},
		{"Errors", LEFT},
		{"r_IOPS", LEFT},
		{"w_IOPS", LEFT},
		{"r_clat", LEFT},
		{"w_clat", LEFT},
		{"r_bw", LEFT},
		{"w_bw", LEFT},
		{"Util%", LEFT},
	};

	t = table_create();
	if (!t) {
		nvme_show_error("Failed to init ctrl summary table");
		return 1;
	}

	if (table_add_columns_filter(t, columns, ARRAY_SIZE(columns),
		stdout_top_print_ctrl_summary_tbl_filter, (void *)s) < 0) {
		nvme_show_error("Failed to add columns to ctrl summary table");
		ret = 1;
		goto free_tbl;
	}

	c = libnvme_subsystem_first_ctrl(s);
	if (c)
		is_fabric = stdout_top_nvme_ctrl_is_fabric(c);

	fprintf(stream, "\n---------- Controller Summary --------\n\n");
	libnvme_subsystem_for_each_ctrl(s, c) {
		npaths = 0;
		r_iops = w_iops = 0;
		r_bw = w_bw = 0;
		max_util = max_rlat = max_wlat = 0;

		row = table_get_row_id(t);
		if (row < 0) {
			nvme_show_error("Failed to add row to ctrl summary table");
			ret = 1;
			goto free_tbl;
		}

		if (multipath) {
			libnvme_ctrl_for_each_path(c, p) {

				/* count num of paths per controller */
				npaths++;

				nvme_path_calc_aggr_stat(p,
						&r_iops, &w_iops,
						&r_bw, &w_bw,
						&max_rlat, &max_wlat,
						&max_util);
			}
		} else {
			libnvme_ctrl_for_each_ns(c, n) {
				nvme_ns_calc_aggr_stat(n,
						&r_iops, &w_iops,
						&r_bw, &w_bw,
						&max_rlat, &max_wlat,
						&max_util);
			}
		}

		nvme_format_iops(r_iops, r_iops_str, sizeof(r_iops_str));
		nvme_format_iops(w_iops, w_iops_str, sizeof(w_iops_str));

		nvme_format_bw(r_bw, r_bw_str, sizeof(r_bw_str));
		nvme_format_bw(w_bw, w_bw_str, sizeof(w_bw_str));

		nvme_format_lat(max_rlat, r_clat_str, sizeof(r_clat_str));
		nvme_format_lat(max_wlat, w_clat_str, sizeof(w_clat_str));

		node = libnvme_ctrl_get_numa_node(c);
		if (!strcmp(node, "-1"))
			node = "NUMA_NO_NODE";

		col = -1;

		table_set_value_str(t, ++col, row,
				libnvme_ctrl_get_name(c), LEFT);
		if (multipath)
			table_set_value_int(t, ++col, row, npaths, LEFT);

		table_set_value_str(t, ++col, row, node, LEFT);
		table_set_value_str(t, ++col, row,
				libnvme_ctrl_get_transport(c), LEFT);
		table_set_value_str(t, ++col, row,
				libnvme_ctrl_get_traddr(c), LEFT);
		table_set_value_str(t, ++col, row,
				libnvme_ctrl_get_state(c), LEFT);
		table_set_value_long(t, ++col, row,
				libnvme_ctrl_get_reset_count(c), LEFT);
		if (is_fabric)
			table_set_value_long(t, ++col, row,
				libnvme_ctrl_get_reconnect_count(c), LEFT);

		table_set_value_long(t, ++col, row,
				libnvme_ctrl_get_command_error_count(c), LEFT);
		table_set_value_str(t, ++col, row, r_iops_str, LEFT);
		table_set_value_str(t, ++col, row, w_iops_str, LEFT);
		table_set_value_str(t, ++col, row, r_clat_str, LEFT);
		table_set_value_str(t, ++col, row, w_clat_str, LEFT);
		table_set_value_str(t, ++col, row, r_bw_str, LEFT);
		table_set_value_str(t, ++col, row, w_bw_str, LEFT);
		table_set_value_double(t, ++col, row, max_util, LEFT);

		table_add_row(t, row);
	}

	table_print_stream(stream, t);
free_tbl:
	table_free(t);
	return ret;
}

static int stdout_top_print_ns_stat(FILE *stream, libnvme_subsystem_t s)
{
	int ret = 0;
	libnvme_ns_t n;
	libnvme_ctrl_t c;
	int col, row;
	unsigned int inflights;
	double r_iops, w_iops, r_lat, w_lat, r_bw, w_bw, util;
	char r_bw_str[16], w_bw_str[16];
	char r_iops_str[16], w_iops_str[16];
	char r_clat_str[16], w_clat_str[16];
	struct table *t;
	struct table_column columns[] = {
		{"Namespace", LEFT},
		{"NSID", LEFT},
		{"Ctrl", LEFT},
		{"Retries", LEFT},
		{"Errors", LEFT},
		{"r_IOPS", LEFT},
		{"w_IOPS", LEFT},
		{"r_clat", LEFT},
		{"w_clat", LEFT},
		{"r_bw", LEFT},
		{"w_bw", LEFT},
		{"Inflights", LEFT},
		{"Util%", LEFT},
	};

	t = table_create();
	if (!t) {
		nvme_show_error("Failed to init ns stat table\n");
		return 1;
	}

	if (table_add_columns(t, columns, ARRAY_SIZE(columns)) < 0) {
		nvme_show_error("Failed to add columns to ns stat table\n");
		ret = 1;
		goto free_tbl;
	}

	fprintf(stream, "----------- Namespace Stat -----------\n\n");
	libnvme_subsystem_for_each_ctrl(s, c) {
		libnvme_ctrl_for_each_ns(c, n) {
			r_iops = r_lat = r_bw = 0;
			w_iops = w_lat = w_bw = 0;
			util = inflights = 0;

			nvme_ns_calc_stat(n,
					&r_iops, &w_iops,
					&r_lat, &w_lat,
					&r_bw, &w_bw,
					&util, &inflights);

			nvme_format_iops(r_iops, r_iops_str,
					sizeof(r_iops_str));
			nvme_format_iops(w_iops, w_iops_str,
					sizeof(w_iops_str));

			nvme_format_bw(r_bw, r_bw_str, sizeof(r_bw_str));
			nvme_format_bw(w_bw, w_bw_str, sizeof(w_bw_str));

			nvme_format_lat(r_lat, r_clat_str, sizeof(r_clat_str));
			nvme_format_lat(w_lat, w_clat_str, sizeof(w_clat_str));

			row = table_get_row_id(t);
			if (row < 0) {
				nvme_show_error("Failed to add row to ns stat table\n");
				ret = 1;
				goto free_tbl;
			}

			col = -1;

			table_set_value_str(t, ++col, row,
					libnvme_ns_get_name(n), LEFT);
			table_set_value_int(t, ++col, row,
					libnvme_ns_get_nsid(n), LEFT);
			table_set_value_str(t, ++col, row,
					libnvme_ctrl_get_name(c), LEFT);
			table_set_value_long(t, ++col, row,
				libnvme_ns_get_command_retry_count(n), LEFT);
			table_set_value_long(t, ++col, row,
				libnvme_ns_get_command_error_count(n), LEFT);
			table_set_value_str(t, ++col, row, r_iops_str, LEFT);
			table_set_value_str(t, ++col, row, w_iops_str, LEFT);
			table_set_value_str(t, ++col, row, r_clat_str, LEFT);
			table_set_value_str(t, ++col, row, w_clat_str, LEFT);
			table_set_value_str(t, ++col, row, r_bw_str, LEFT);
			table_set_value_str(t, ++col, row, w_bw_str, LEFT);
			table_set_value_unsigned(t, ++col, row, inflights,
					LEFT);
			table_set_value_double(t, ++col, row, util, LEFT);

			table_add_row(t, row);
		}
	}

	table_print_stream(stream, t);
free_tbl:
	table_free(t);
	return ret;
}

static int stdout_top_print_nshead_stat(FILE *stream, libnvme_subsystem_t s)
{
	int ret = 0;
	libnvme_ns_t n;
	libnvme_path_t p;
	double r_iops, w_iops, r_lat, w_lat, r_bw, w_bw, util;
	unsigned int inflights;
	int col, row, npaths;
	char r_iops_str[16], w_iops_str[16];
	char r_clat_str[16], w_clat_str[16];
	char r_bw_str[16], w_bw_str[16];
	struct table *t;
	struct table_column columns[] = {
			{"NSHead", LEFT},
			{"NSID", LEFT},
			{"Paths", LEFT},
			{"Requeue-IO", LEFT},
			{"Fail-IO", LEFT},
			{"r_IOPS", LEFT},
			{"w_IOPS", LEFT},
			{"r_clat", LEFT},
			{"w_clat", LEFT},
			{"r_bw", LEFT},
			{"w_bw", LEFT},
			{"Inflights", LEFT},
			{"Util%", LEFT},
	};

	t = table_create();
	if (!t) {
		nvme_show_error("Failed to init nshead stat table\n");
		return 1;
	}

	if (table_add_columns(t, columns, ARRAY_SIZE(columns)) < 0) {
		nvme_show_error("Failed to add columns to shead stat table\n");
		ret = 1;
		goto free_tbl;
	}

	fprintf(stream, "------------ NSHead Stat -------------\n\n");
	libnvme_subsystem_for_each_ns(s, n) {
		npaths = 0;
		r_iops = r_lat = r_bw = 0;
		w_iops = w_lat = w_bw = 0;
		util = inflights = 0;

		nvme_ns_calc_stat(n,
				&r_iops, &w_iops,
				&r_lat, &w_lat,
				&r_bw, &w_bw,
				&util, &inflights);

		nvme_format_iops(r_iops, r_iops_str, sizeof(r_iops_str));
		nvme_format_iops(w_iops, w_iops_str, sizeof(w_iops_str));

		nvme_format_bw(r_bw, r_bw_str, sizeof(r_bw_str));
		nvme_format_bw(w_bw, w_bw_str, sizeof(w_bw_str));

		nvme_format_lat(r_lat, r_clat_str, sizeof(r_clat_str));
		nvme_format_lat(w_lat, w_clat_str, sizeof(w_clat_str));

		libnvme_namespace_for_each_path(n, p)
			npaths++;

		row = table_get_row_id(t);
		if (row < 0) {
			nvme_show_error("Failed to add row to nshead stat table\n");
			ret = 1;
			goto free_tbl;
		}

		col = -1;

		table_set_value_str(t, ++col, row, libnvme_ns_get_name(n),
				LEFT);
		table_set_value_int(t, ++col, row, libnvme_ns_get_nsid(n),
				LEFT);
		table_set_value_int(t, ++col, row, npaths, LEFT);
		table_set_value_long(t, ++col, row,
			libnvme_ns_get_requeue_no_usable_path_count(n), LEFT);
		table_set_value_long(t, ++col, row,
			libnvme_ns_get_fail_no_available_path_count(n), LEFT);
		table_set_value_str(t, ++col, row, r_iops_str, LEFT);
		table_set_value_str(t, ++col, row, w_iops_str, LEFT);
		table_set_value_str(t, ++col, row, r_clat_str, LEFT);
		table_set_value_str(t, ++col, row, w_clat_str, LEFT);
		table_set_value_str(t, ++col, row, r_bw_str, LEFT);
		table_set_value_str(t, ++col, row, w_bw_str, LEFT);
		table_set_value_unsigned(t, ++col, row, inflights, LEFT);
		table_set_value_double(t, ++col, row, util, LEFT);

		table_add_row(t, row);
	}

	table_print_stream(stream, t);
free_tbl:
	table_free(t);
	return ret;
}

static int stdout_top_print_path_perf(FILE *stream, libnvme_subsystem_t s)
{
	int ret = 0;
	libnvme_ns_t n;
	libnvme_path_t p;
	libnvme_ctrl_t c;
	unsigned int inflights;
	int row, col;
	double util, r_iops, w_iops, r_lat, w_lat, r_bw, w_bw;
	char r_iops_str[16], w_iops_str[16];
	char r_clat_str[16], w_clat_str[16];
	char r_bw_str[16], w_bw_str[16];
	bool first;
	struct table *t;
	const char *iopolicy = libnvme_subsystem_get_iopolicy(s);
	struct table_column columns[] = {
		{"NSHead", LEFT},
		{"NSID", LEFT},
		{"NSPath", LEFT},
		{"Nodes", LEFT},
		{"Qdepth", LEFT},
		{"Ctrl", LEFT},
		{"r_IOPS", LEFT},
		{"w_IOPS", LEFT},
		{"r_clat", LEFT},
		{"w_clat", LEFT},
		{"r_bw", LEFT},
		{"w_bw", LEFT},
		{"Inflights", LEFT},
		{"Util%", LEFT},
	};

	t = table_create();
	if (!t) {
		nvme_show_error("Failed to init path perf table");
		return 1;
	}

	if (table_add_columns_filter(t, columns, ARRAY_SIZE(columns),
			subsystem_iopolicy_filter, (void *)s) < 0) {
		nvme_show_error("Failed to add columns to path perf table");
		ret = 1;
		goto free_tbl;
	}

	fprintf(stream, "\n---------- Path Performance ----------\n\n");
	libnvme_subsystem_for_each_ns(s, n) {
		first = true;
		libnvme_namespace_for_each_path(n, p) {
			r_iops = r_lat = r_bw = 0;
			w_iops = w_lat = w_bw = 0;
			util = inflights = 0;

			nvme_path_calc_stat(p,
					&r_iops, &w_iops,
					&r_lat, &w_lat,
					&r_bw, &w_bw,
					&util, &inflights);

			nvme_format_iops(r_iops, r_iops_str,
					sizeof(r_iops_str));
			nvme_format_iops(w_iops, w_iops_str,
					sizeof(w_iops_str));

			nvme_format_bw(r_bw, r_bw_str, sizeof(r_bw_str));
			nvme_format_bw(w_bw, w_bw_str, sizeof(w_bw_str));

			nvme_format_lat(r_lat, r_clat_str, sizeof(r_clat_str));
			nvme_format_lat(w_lat, w_clat_str, sizeof(w_clat_str));

			/* get controller associated with the path */
			c = libnvme_path_get_ctrl(p);

			row = table_get_row_id(t);
			if (row < 0) {
				nvme_show_error("Failed to add row to path perf table");
				ret = 1;
				goto free_tbl;
			}

			/*
			 * For the first row we print actual NSHead name,
			 * however, for the subsequent rows we print "arrow"
			 * ("-->") symbol for NSHead. This "arrow" style makes
			 * it visually obvious that subsequent entries (if
			 * present) are a path under the first NSHead.
			 */
			col = -1;

			if (first) {
				table_set_value_str(t, ++col, row,
						libnvme_ns_get_name(n), LEFT);
				first = false;
			} else
				table_set_value_str(t, ++col, row,
						"-->", CENTERED);

			table_set_value_int(t, ++col, row,
					libnvme_ns_get_nsid(n), CENTERED);
			table_set_value_str(t, ++col, row,
					libnvme_path_get_name(p), LEFT);

			if (!strcmp(iopolicy, "numa"))
				table_set_value_str(t, ++col, row,
				    libnvme_path_get_numa_nodes(p), CENTERED);
			else if (!strcmp(iopolicy, "queue-depth"))
				table_set_value_int(t, ++col, row,
				    libnvme_path_get_queue_depth(p), CENTERED);

			table_set_value_str(t, ++col, row,
					libnvme_ctrl_get_name(c), LEFT);
			table_set_value_str(t, ++col, row, r_iops_str, LEFT);
			table_set_value_str(t, ++col, row, w_iops_str, LEFT);
			table_set_value_str(t, ++col, row, r_clat_str, LEFT);
			table_set_value_str(t, ++col, row, w_clat_str, LEFT);
			table_set_value_str(t, ++col, row, r_bw_str, LEFT);
			table_set_value_str(t, ++col, row, w_bw_str, LEFT);
			table_set_value_unsigned(t, ++col, row,
					inflights, LEFT);
			table_set_value_double(t, ++col, row, util, LEFT);

			table_add_row(t, row);
		}
	}
	table_print_stream(stream, t);
free_tbl:
	table_free(t);
	return ret;
}

static void  stdout_top_print_subsys_topology_config(FILE *stream,
		libnvme_subsystem_t s)
{
	int len = strlen(libnvme_subsystem_get_name(s));

	fprintf(stream, "%s - NQN=%s\n", libnvme_subsystem_get_name(s),
		libnvme_subsystem_get_subsysnqn(s));
	fprintf(stream, "%*s   hostnqn=%s\n", len, " ",
		libnvme_host_get_hostnqn(libnvme_subsystem_get_host(s)));
	fprintf(stream, "%*s   iopolicy=%s\n", len, " ",
		libnvme_subsystem_get_iopolicy(s));

	fprintf(stream, "%*s   model=%s\n", len, " ",
		libnvme_subsystem_get_model(s));
	fprintf(stream, "%*s   serial=%s\n", len, " ",
		libnvme_subsystem_get_serial(s));
	fprintf(stream, "%*s   firmware=%s\n", len, " ",
		libnvme_subsystem_get_firmware(s));
	fprintf(stream, "%*s   type=%s\n", len, " ",
		libnvme_subsystem_get_subsystype(s));

	fprintf(stream, "\n");
}

static int stdout_top_update_stat(libnvme_subsystem_t s)
{
	libnvme_ctrl_t c;
	libnvme_ns_t n;
	libnvme_path_t p;
	int ret;

	if (nvme_is_multipath(s)) {
		libnvme_subsystem_for_each_ns(s, n) {
			ret = libnvme_ns_update_stat(n, true);
			if (ret < 0) {
				nvme_show_error("Failed to update namespace stat");
				return ret;
			}

			libnvme_namespace_for_each_path(n, p) {
				ret = libnvme_path_update_stat(p, true);
				if (ret < 0) {
					nvme_show_error("Failed to update path stat");
					return ret;
				}
			}
		}
	} else {
		libnvme_subsystem_for_each_ctrl(s, c) {
			libnvme_ctrl_for_each_ns(c, n) {
				ret = libnvme_ns_update_stat(n, true);
				if (ret < 0) {
					nvme_show_error("Failed to update namespace stat");
					return ret;
				}
			}
		}
	}

	return 0;
}

static void stdout_top_reset_stat(libnvme_subsystem_t s)
{
	libnvme_ctrl_t c;
	libnvme_ns_t n;
	libnvme_path_t p;

	if (nvme_is_multipath(s)) {
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

static int stdout_top_print_subsys_topology(struct dashboard_ctx *db_ctx,
		FILE *stream, libnvme_subsystem_t s)
{
	int ret = 0;
	bool multipath = nvme_is_multipath(s);

	ret = stdout_top_update_stat(s);
	if (ret)
		return ret;

	stdout_top_print_subsys_topology_config(stream, s);

	if (multipath) {
		ret = stdout_top_print_nshead_stat(stream, s);
		if (ret)
			return ret;

		ret = stdout_top_print_path_perf(stream, s);
		if (ret)
			return ret;

		ret = stdout_top_print_path_health(stream, s);
		if (ret)
			return ret;
	} else {
		ret = stdout_top_print_ns_stat(stream, s);
		if (ret)
			return ret;
	}

	ret = stdout_top_print_ctrl_summary(stream, s, multipath);

	return ret;
}

static void stdout_top_print_subsys_topology_header(
		struct dashboard_ctx *db_ctx, FILE *stream)
{
	fprintf(stream, "---- nvme-top - Refresh: %d Second ----\n",
			dashboard_get_interval(db_ctx));

	dashboard_set_header_rows(db_ctx, 1);

	/* highlight the header row */
	dashboard_set_header_row_reverse(db_ctx, 0);
}

static void stdout_top_print_subsys_topology_footer(
		struct dashboard_ctx *db_ctx, FILE *stream)
{
	fprintf(stream, "\n--------------------------------------\n");
	fprintf(stream, "[ESC to go back to the previous screen, q to quit]\n");

	dashboard_set_footer_rows(db_ctx, 3);

	/* hightligh the last footer row */
	dashboard_set_footer_row_reverse(db_ctx, 2);
}

static struct libnvme_global_ctx *stdout_top_rescan_topology(void)
{
	struct libnvme_global_ctx *ctx;

	ctx = libnvme_create_global_ctx(stdout, log_level);
	if (!ctx) {
		nvme_show_error("Failed to create global context");
		return NULL;
	}

	if (libnvme_scan_topology(ctx, NULL, NULL)) {
		libnvme_free_global_ctx(ctx);
		nvme_show_error("Failed to scan topology");
		return NULL;
	}

	return ctx;
}

static libnvme_subsystem_t stdout_top_search_subsystem(
		struct libnvme_global_ctx *ctx, const char *subsys_name)
{
	libnvme_host_t h;
	libnvme_subsystem_t s;

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			if (!strcmp(libnvme_subsystem_get_name(s), subsys_name))
				return s;
		}
	}

	return NULL;
}

static libnvme_subsystem_t *stdout_top_build_subsys_arr(
		struct libnvme_global_ctx *ctx, int *num_subsys)
{
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_subsystem_t *subsys_arr;
	int subsys_idx = 0;
	int n = 0;

	libnvme_for_each_host(ctx, h)
		libnvme_for_each_subsystem(h, s)
			n++;
	if (!n) {
		nvme_show_error("Can't find any NVMe subsystem on the host\n");
		return NULL;
	}

	subsys_arr = calloc(n, sizeof(libnvme_subsystem_t));
	if (!subsys_arr) {
		nvme_show_error("Failed to allocate memory for subsys array\n");
		return NULL;
	}

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s)
			subsys_arr[subsys_idx++] = s;
	}

	*num_subsys = n;
	return subsys_arr;
}

/*
 * Draws subsys topology screen of susbystem @s
 * Returns: 0 if ESC key is pressed or needs to draw subsystem selection screen
 *          1 if 'q' is pressed or in case of error
 */
static int stdout_top_draw_subsys_topology_screen(struct dashboard_ctx *db_ctx,
			FILE *stream, libnvme_subsystem_t _s)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	enum event_type event;
	int ret, scroll = 0;
	int data_start, data_rows;
	libnvme_subsystem_t s = NULL;

	ctx = stdout_top_rescan_topology();
	if (!ctx)
		return 1; /* force quit */

	s = stdout_top_search_subsystem(ctx, libnvme_subsystem_get_name(_s));
	if (!s)
		return 0; /* draw subsys selection screen */

	while (1) {
		stdout_top_print_subsys_topology_header(db_ctx, stream);
		ret = stdout_top_print_subsys_topology(db_ctx, stream, s);
		if (ret)
			break;
		stdout_top_print_subsys_topology_footer(db_ctx, stream);

draw:
		ret = dashboard_draw_frame(db_ctx, scroll);
		if (ret)
			break;
wait_for_event:
		event = dashboard_wait_for_event(db_ctx);
		if (event == EVENT_TYPE_KEY_ESC) {
			ret = 0;
			dashboard_reset(db_ctx);
			break;
		} else if (event == EVENT_TYPE_KEY_UP) {
			data_start = dashboard_get_data_start(db_ctx);
			/*
			 * If we don't move past the first data row by shifting
			 * one data row up then do so, otherwise ignore the key
			 * press.
			 */
			if (data_start - 1 >= 0) {
				dashboard_set_data_start(db_ctx,
						data_start - 1);
				scroll = 1;
				goto draw;
			}
			goto wait_for_event;
		} else if (event == EVENT_TYPE_KEY_DOWN) {
			data_start = dashboard_get_data_start(db_ctx);
			data_rows = dashboard_get_data_rows(db_ctx);
			/*
			 * If we don't move past the max data rows shifting one
			 * row down then do so, otherwise ignore the key press.
			 */
			if (data_start + 1 < data_rows) {
				dashboard_set_data_start(db_ctx,
						data_start + 1);
				scroll = 1;
				goto draw;
			}
			goto wait_for_event;
		} else if (event == EVENT_TYPE_TIMEOUT) { /* screen timed out */
			scroll = 0;
		} else if (event == EVENT_TYPE_KEY_QUIT ||
				event == EVENT_TYPE_ERROR) {
			ret = 1;
			break;
		} else if (event == EVENT_TYPE_NVME_UEVENT) {
			/* free old ctx */
			libnvme_free_global_ctx(ctx);
			ctx = stdout_top_rescan_topology();
			if (!ctx) {
				ret = 1; /* force quit */
				break;
			}

			s = stdout_top_search_subsystem(ctx,
					libnvme_subsystem_get_name(_s));
			if (!s) {
				ret = 0; /* draw subsys selection screen */
				break;
			}
			scroll = 0;
		} else if (event == EVENT_TYPE_SIGWINCH) {
			/*
			 * Window size would have changed so re-draw the subsys
			 * topology screen.
			 */
			scroll = 0;
		} /* else unknown event, ignore */
	}

	return ret;
}

static int stdout_top_draw_subsys_screen(struct dashboard_ctx *db_ctx,
		FILE *stream, libnvme_subsystem_t *subsys_arr, int num_subsys)
{
	int ret = 0;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;
	libnvme_ns_t n;
	libnvme_path_t p;
	int i, row, col, num_ns, num_path, num_ctrl;
	double r_iops, w_iops;
	double r_bw, w_bw;
	double max_rlat, max_wlat, max_util;
	char r_bw_str[16], w_bw_str[16];
	char r_iops_str[16], w_iops_str[16];
	char r_clat_str[16], w_clat_str[16];
	struct table *t;
	struct table_column columns[] = {
		{"Subsystem", LEFT},
		{"Namespaces", LEFT},
		{"Paths", LEFT},
		{"Ctrls", LEFT},
		{"IOPolicy", LEFT},
		{"r_IOPS", LEFT},
		{"w_IOPS", LEFT},
		{"r_clat", LEFT},
		{"w_clat", LEFT},
		{"r_bw", LEFT},
		{"w_bw", LEFT},
		{"Util%", LEFT},
	};

	fprintf(stream, "---- nvme-top - Refresh: %d Second ----\n",
			dashboard_get_interval(db_ctx));
	fprintf(stream, "\n--------- Subsystem Summary ----------\n\n");

	t = table_create();
	if (!t) {
		nvme_show_error("Failed to init subsys screen table\n");
		return -1;
	}

	if (table_add_columns(t, columns, ARRAY_SIZE(columns)) < 0) {
		nvme_show_error("Failed to add columns to subsys screen table\n");
		ret = -1;
		goto free_tbl;
	}
	/*
	 * Header row count is calculated manually. The first row displays the
	 * refresh interval, followed by an empty row. The third row displays
	 * the heading followed by another empty row. The fifth row is for
	 * displaying table columns and then another row for dashes underneath
	 * the table columns.
	 */
	dashboard_set_header_rows(db_ctx, 6);

	/* highlight the first header row */
	dashboard_set_header_row_reverse(db_ctx, 0);

	for (i = 0; i < num_subsys; i++) {
		s = subsys_arr[i];
		num_ctrl = num_ns = num_path = 0;
		r_iops = w_iops = 0;
		r_bw = w_bw = 0;
		max_rlat = max_wlat = 0;
		max_util = 0;

		libnvme_subsystem_for_each_ctrl(s, c)
			num_ctrl++;

		ret = stdout_top_update_stat(s);
		if (ret)
			goto free_tbl;

		if (nvme_is_multipath(s)) {
			libnvme_subsystem_for_each_ns(s, n) {
				num_ns++;

				libnvme_namespace_for_each_path(n, p)
					num_path++;

				nvme_ns_calc_aggr_stat(n,
						&r_iops, &w_iops,
						&r_bw, &w_bw,
						&max_rlat, &max_wlat,
						&max_util);
			}
		} else {
			libnvme_subsystem_for_each_ctrl(s, c) {
				libnvme_ctrl_for_each_ns(c, n) {
					num_ns++;

					nvme_ns_calc_aggr_stat(n,
							&r_iops, &w_iops,
							&r_bw, &w_bw,
							&max_rlat, &max_wlat,
							&max_util);
				}
			}
		}

		nvme_format_iops(r_iops, r_iops_str, sizeof(r_iops_str));
		nvme_format_iops(w_iops, w_iops_str, sizeof(w_iops_str));

		nvme_format_bw(r_bw, r_bw_str, sizeof(r_bw_str));
		nvme_format_bw(w_bw, w_bw_str, sizeof(w_bw_str));

		nvme_format_lat(max_rlat, r_clat_str, sizeof(r_clat_str));
		nvme_format_lat(max_wlat, w_clat_str, sizeof(w_clat_str));

		row = table_get_row_id(t);
		if (row < 0) {
			nvme_show_error("Failed to add row to subsys screen table\n");
			ret = -1;
			goto free_tbl;
		}

		col = -1;

		table_set_value_str(t, ++col, row,
				libnvme_subsystem_get_name(s), LEFT);
		table_set_value_int(t, ++col, row, num_ns, LEFT);
		table_set_value_int(t, ++col, row, num_path, LEFT);
		table_set_value_int(t, ++col, row, num_ctrl, LEFT);
		table_set_value_str(t, ++col, row,
				libnvme_subsystem_get_iopolicy(s), LEFT);
		table_set_value_str(t, ++col, row, r_iops_str, LEFT);
		table_set_value_str(t, ++col, row, w_iops_str, LEFT);
		table_set_value_str(t, ++col, row, r_clat_str, LEFT);
		table_set_value_str(t, ++col, row, w_clat_str, LEFT);
		table_set_value_str(t, ++col, row, r_bw_str, LEFT);
		table_set_value_str(t, ++col, row, w_bw_str, LEFT);
		table_set_value_double(t, ++col, row, max_util, LEFT);

		table_add_row(t, row);
	}

	table_print_stream(stream, t);

	fprintf(stream, "\n--------------------------------------\n");
	fprintf(stream, "[up/down arrow keys to navigate, Enter to view, q to quit]\n");

	/*
	 * Footer rows are calculated manually.
	 * The first row is empty (adds spaces) followed by another row for
	 * dashes and the last row adds footer string.
	 */
	dashboard_set_footer_rows(db_ctx, 3);

	/* highlight the last footer row */
	dashboard_set_footer_row_reverse(db_ctx, 2);

free_tbl:
	table_free(t);
	return ret;
}

void stdout_top(int refresh_interval)
{
	FILE *stream;
	enum event_type event;
	struct dashboard_ctx *db_ctx;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_free libnvme_subsystem_t *subsys_arr = NULL;
	int data_start, frame_rows, quit = 0, scroll = 0;
	int num_subsys = 0, subsys_idx = 0;

	ctx = stdout_top_rescan_topology();
	if (!ctx)
		return;
	subsys_arr = stdout_top_build_subsys_arr(ctx, &num_subsys);
	if (!subsys_arr)
		return;

	stream = dashboard_init(&db_ctx, refresh_interval);
	if (!stream)
		return;

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s)
			stdout_top_reset_stat(s);
	}

	/*
	 * We start with first subsystem highlited, so set subsystem index to 0.
	 */
	subsys_idx = 0;
	while (!quit) {
		if (stdout_top_draw_subsys_screen(db_ctx, stream, subsys_arr,
				num_subsys) < 0)
			break;
draw:
		/* highlight the selected @subsys_idx row */
		dashboard_set_data_row_reverse(db_ctx, subsys_idx);
		if (dashboard_draw_frame(db_ctx, scroll) < 0)
			break;
wait_for_event:
		event = dashboard_wait_for_event(db_ctx);
		switch (event) {
		case EVENT_TYPE_KEY_QUIT:
		case EVENT_TYPE_ERROR:
			quit = 1;
			break;
		case EVENT_TYPE_KEY_RETURN:
			dashboard_reset(db_ctx);

			s = subsys_arr[subsys_idx];
			quit = stdout_top_draw_subsys_topology_screen(db_ctx,
					stream, s);
			scroll = 0;
			if (quit)
				break;
			fallthrough;
		case EVENT_TYPE_NVME_UEVENT:
			libnvme_free_global_ctx(ctx);
			free(subsys_arr);
			subsys_arr = NULL;
			ctx = stdout_top_rescan_topology();
			if (!ctx) {
				quit = 1;
				break;
			}
			subsys_arr = stdout_top_build_subsys_arr(ctx,
					&num_subsys);
			if (!subsys_arr)
				quit = 1;
			else
				subsys_idx = 0;
			break;
		case EVENT_TYPE_KEY_DOWN:
			/*
			 * The @num_subsys should be equal to @data_rows, so we
			 * evaluate here that we don't move pass the last data
			 * row (or the last subsys) if we were to shift (focus)
			 * one row down. In case it's not possible to shift
			 * because we are already down to the last row then
			 * ignore key press.
			 */
			if (subsys_idx + 1 < num_subsys) {
				subsys_idx++; /* we'll highlight this row */

				data_start = dashboard_get_data_start(db_ctx);
				frame_rows = dashboard_get_frame_data_rows(
						db_ctx);
				/*
				 * If moving to next row requires shifting the
				 * window frame buffer by one position down then
				 * do so.
				 */
				if (subsys_idx >= data_start + frame_rows) {
					dashboard_set_data_start(db_ctx,
							data_start + 1);
				}
				/*
				 * As we are scrolling one row down, we need to
				 * re-draw the frame.
				 */
				scroll = 1;
				goto draw;
			}
			goto wait_for_event;
		case EVENT_TYPE_KEY_UP:
			/*
			 * If it's possible to move one row above the current
			 * subsys (higlighted) row then decrease the subsys_idx
			 * by one.
			 */
			if (subsys_idx - 1 >= 0) {
				subsys_idx--;
				/*
				 * If moving one row up requires us to shift
				 * the window frame buffer by one position up
				 * then do so.
				 */
				data_start = dashboard_get_data_start(db_ctx);
				if (subsys_idx < data_start) {
					dashboard_set_data_start(db_ctx,
						data_start - 1);
				}
				/*
				 * As we are scrolling one row up, we need to
				 * re-draw the frame.
				 */
				scroll = 1;
				goto draw;
			}
			goto wait_for_event;
		case EVENT_TYPE_TIMEOUT:
			/* subsys screen timed out */
			scroll = 0;
			break;
		case EVENT_TYPE_SIGWINCH:
			/*
			 * Window size would have changed so re-draw the subsys
			 * selection screen.
			 */
			scroll = 0;
			break;
		default: /* unknown event, ignore */
			continue;
		}
	}

	dashboard_exit(db_ctx);
}
