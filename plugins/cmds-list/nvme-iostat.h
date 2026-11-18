/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * I/O statistics of NVMe namespaces and paths
 *
 * libnvme keeps two samples of the block layer statistics per namespace
 * and path. The functions here turn the difference of the two samples
 * into rates, which nvme top shows.
 *
 * Copyright (c) 2026 Nilay Shroff, IBM
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Nilay Shroff <nilay@linux.ibm.com>
 *          Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

struct libnvme_ns;
struct libnvme_path;
struct libnvme_subsystem;

/* The difference of two block layer stat samples. */
struct nvme_iostat_sample {
	double interval_ms;		/* time between the samples */
	unsigned long r_ios, w_ios;
	unsigned long long r_sectors, w_sectors;	/* 512-byte units */
	unsigned int r_ticks, w_ticks;	/* ms spent on reads/writes */
	unsigned int io_ticks;		/* ms the device was busy */
	unsigned int inflights;		/* current, not a difference */
};

struct nvme_iostat {
	double r_iops, w_iops;		/* I/Os per second */
	double r_lat, w_lat;		/* average ms per I/O */
	double r_bw, w_bw;		/* bytes per second */
	double util;			/* percent of the interval busy */
	unsigned int inflights;
};

void nvme_iostat_calc(const struct nvme_iostat_sample *s,
		struct nvme_iostat *st);
void nvme_iostat_ns(struct libnvme_ns *n, struct nvme_iostat *st);
void nvme_iostat_path(struct libnvme_path *p, struct nvme_iostat *st);

/*
 * Adds @st to @aggr: the rates add up, the latencies and the utilization
 * keep the maximum. The inflights are left alone.
 */
void nvme_iostat_aggr(struct nvme_iostat *aggr, const struct nvme_iostat *st);

/*
 * Takes a new sample of every namespace of @s, and of every path too if
 * @multipath. A namespace or a path may go away meanwhile, e.g. at a
 * failover: libnvme gives no rates for a sample which failed, so its
 * stats are zero until the topology is refreshed.
 */
void nvme_iostat_update_subsys(struct libnvme_subsystem *s, bool multipath);
void nvme_iostat_reset_subsys(struct libnvme_subsystem *s, bool multipath);

int nvme_iostat_format_iops(double iops, char *buf, size_t size);
int nvme_iostat_format_bw(double bw, char *buf, size_t size);
int nvme_iostat_format_lat(double lat, char *buf, size_t size);
