/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NVME_TOP_H
#define NVME_TOP_H

#include <stdio.h>
#include <stddef.h>
#include <libnvme.h>

int nvme_format_iops(double iops, char *buf, size_t size);
int nvme_format_bw(double bw, char *buf, size_t size);

void nvme_ns_calc_aggr_stat(libnvme_ns_t n, double *r_iops, double *w_iops,
		double *r_bw, double *w_bw, double *max_rlat, double *max_wlat,
		double *max_util);
void nvme_path_calc_aggr_stat(libnvme_path_t p, double *r_iops, double *w_iops,
		double *r_bw, double *w_bw, double *max_rlat, double *max_wlat,
		double *max_util);
void nvme_ns_calc_stat(libnvme_ns_t n, double *r_iops, double *w_iops,
		double *r_lat, double *w_lat, double *r_bw, double *w_bw,
		double *util, unsigned int *inflights);
void nvme_path_calc_stat(libnvme_path_t p, double *r_iops, double *w_iops,
		double *r_lat, double *w_lat, double *r_bw, double *w_bw,
		double *util, unsigned int *inflights);

static inline int nvme_format_lat(double lat, char *buf, size_t size)
{
	return snprintf(buf, size, "%.2f", lat);
}

#endif /* NVME_TOP_H */
