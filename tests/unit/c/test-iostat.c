// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * Unit tests for nvme-iostat.c: the rates nvme top derives from two
 * block layer stat samples. The block layer counts sectors in 512-byte
 * units and ticks in milliseconds (Linux Documentation/block/stat.rst).
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "nvme-iostat.h"

static bool report(const char *what, bool pass)
{
	printf(" - %s [%s]\n", what, pass ? "PASS" : "FAIL");
	return pass;
}

static bool eq(double a, double b)
{
	return a - b < 1e-9 && b - a < 1e-9;
}

static bool test_calc(void)
{
	struct nvme_iostat_sample s = {
		.interval_ms = 2000,
		.r_ios = 1000, .w_ios = 10,
		.r_sectors = 2048, .w_sectors = 8,
		.r_ticks = 3000, .w_ticks = 5,
		.io_ticks = 500,
		.inflights = 7,
	};
	struct nvme_iostat st;
	bool pass = true;

	printf("rates over a 2 s interval\n");
	nvme_iostat_calc(&s, &st);
	pass &= report("read IOPS", eq(st.r_iops, 500));
	pass &= report("write IOPS", eq(st.w_iops, 5));
	pass &= report("read latency", eq(st.r_lat, 3));
	pass &= report("write latency", eq(st.w_lat, 0.5));
	pass &= report("read bandwidth", eq(st.r_bw, 2048 * 512 / 2));
	pass &= report("write bandwidth", eq(st.w_bw, 8 * 512 / 2));
	pass &= report("utilization", eq(st.util, 25));
	pass &= report("inflights", st.inflights == 7);

	return pass;
}

static bool test_calc_edges(void)
{
	struct nvme_iostat_sample s = {
		.interval_ms = 0,
		.r_ios = 10, .r_ticks = 20, .io_ticks = 5, .inflights = 3,
	};
	struct nvme_iostat st;
	bool pass = true;

	printf("edge cases\n");
	nvme_iostat_calc(&s, &st);
	pass &= report("no interval gives no stats",
		       !st.r_iops && !st.r_lat && !st.util && !st.inflights);

	/* rates need a full second, latency and utilization do not */
	s.interval_ms = 500;
	nvme_iostat_calc(&s, &st);
	pass &= report("short interval: no rates",
		       !st.r_iops && !st.r_bw);
	pass &= report("short interval: latency", eq(st.r_lat, 2));
	pass &= report("short interval: utilization", eq(st.util, 1));

	s = (struct nvme_iostat_sample){ .interval_ms = 1000, .r_ticks = 9 };
	nvme_iostat_calc(&s, &st);
	pass &= report("no I/O: no latency", !st.r_lat && !st.w_lat);

	return pass;
}

static bool test_aggr(void)
{
	struct nvme_iostat aggr = { 0 };
	struct nvme_iostat a = {
		.r_iops = 1, .w_iops = 2, .r_bw = 3, .w_bw = 4,
		.r_lat = 5, .w_lat = 1, .util = 10, .inflights = 1,
	};
	struct nvme_iostat b = {
		.r_iops = 10, .w_iops = 20, .r_bw = 30, .w_bw = 40,
		.r_lat = 2, .w_lat = 6, .util = 50, .inflights = 1,
	};
	bool pass = true;

	printf("aggregation\n");
	nvme_iostat_aggr(&aggr, &a);
	nvme_iostat_aggr(&aggr, &b);
	pass &= report("rates add up",
		       eq(aggr.r_iops, 11) && eq(aggr.w_iops, 22) &&
		       eq(aggr.r_bw, 33) && eq(aggr.w_bw, 44));
	pass &= report("latencies keep the maximum",
		       eq(aggr.r_lat, 5) && eq(aggr.w_lat, 6));
	pass &= report("utilization keeps the maximum", eq(aggr.util, 50));
	pass &= report("inflights untouched", !aggr.inflights);

	return pass;
}

static bool check_fmt(const char *what,
		int (*fmt)(double, char *, size_t), double v, const char *exp)
{
	char buf[16];

	fmt(v, buf, sizeof(buf));
	if (strcmp(buf, exp))
		printf("   %g: \"%s\", expected \"%s\"\n", v, buf, exp);
	return report(what, !strcmp(buf, exp));
}

static bool test_format(void)
{
	bool pass = true;

	printf("formatting\n");
	pass &= check_fmt("IOPS below 1000", nvme_iostat_format_iops,
			  999, "999.00");
	pass &= check_fmt("IOPS in thousands", nvme_iostat_format_iops,
			  1500, "1.50k");
	pass &= check_fmt("no bandwidth", nvme_iostat_format_bw, 0, "0.00");
	pass &= check_fmt("bandwidth in B/s", nvme_iostat_format_bw,
			  512, "512.00B/s");
	pass &= check_fmt("bandwidth in KiB/s", nvme_iostat_format_bw,
			  2048, "2.00KiB/s");
	pass &= check_fmt("bandwidth in MiB/s", nvme_iostat_format_bw,
			  3 * 1024 * 1024, "3.00MiB/s");
	pass &= check_fmt("latency", nvme_iostat_format_lat, 1.234, "1.23");

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_calc();
	pass &= test_calc_edges();
	pass &= test_aggr();
	pass &= test_format();

	return pass ? 0 : 1;
}
