// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 */

/**
 * Open all nvme controller's uevent and listen for changes. If NVME_AEN event
 * is observed with controller telemetry data, read the log and save it to a
 * file in /var/log/ with the device's unique name and epoch timestamp.
 */
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <libnvme.h>

#include <ccan/endian/endian.h>

struct events {
	nvme_ctrl_t c;
	int uevent_fd;
};

static int open_uevent(nvme_ctrl_t c)
{
	char buf[0x1000];
	if (snprintf(buf, sizeof(buf), "%s/uevent", nvme_ctrl_get_sysfs_dir(c)) < 0)
		return -1;
	return open(buf, O_RDONLY);
}

static void save_telemetry(nvme_ctrl_t c)
{
	char buf[0x1000];
	size_t log_size;
	int ret, fd;
	struct nvme_telemetry_log *log;
	time_t s;

	/* Clear the log (rae == false) at the end to see new telemetry events later */
	ret = nvme_get_ctrl_telemetry(nvme_ctrl_get_fd(c), false, &log, NVME_TELEMETRY_DA_3, &log_size);
	if (ret)
		return;

	s = time(NULL);
	ret = snprintf(buf, sizeof(buf), "/var/log/%s-telemetry-%ld",
		nvme_ctrl_get_subsysnqn(c), s);
	if (ret < 0) {
		free(log);
		return;
	}

	fd = open(buf, O_CREAT|O_WRONLY, S_IRUSR|S_IRGRP);
	if (fd < 0) {
		free(log);
		return;
	}

	ret = write(fd, log, log_size);
	if (ret < 0)
		printf("failed to write telemetry log\n");
	else
		printf("telemetry log save as %s, wrote:%d size:%zd\n", buf,
			ret, log_size);
	close(fd);
	free(log);
}

static void check_telemetry(nvme_ctrl_t c, int ufd)
{
	char buf[0x1000] = { 0 };
	char *p, *ptr;
	int len;

	len = read(ufd, buf, sizeof(buf) - 1);
	if (len < 0)
		return;

	ptr = buf;
	while ((p = strsep(&ptr, "\n")) != NULL) {
		__u32 aen, type, info, lid;

		if (sscanf(p, "NVME_AEN=0x%08x", &aen) != 1)
			continue;

		type = aen & 0x07;
		info = (aen >> 8) & 0xff;
		lid = (aen >> 16) & 0xff;

		printf("%s: aen type:%x info:%x lid:%d\n",
			nvme_ctrl_get_name(c), type, info, lid);
		if (type == NVME_AER_NOTICE &&
		    info == NVME_AER_NOTICE_TELEMETRY)
			save_telemetry(c);
	}
}

static void wait_events(fd_set *fds, struct events *e, int nr)
{
	int ret, i;

	for (i = 0; i < nr; i++)
		check_telemetry(e[i].c, e[i].uevent_fd);

	while (1) {
		ret = select(nr, fds, NULL, NULL, NULL);
		if (ret < 0)
			return;

		for (i = 0; i < nr; i++) {
			if (!FD_ISSET(e[i].uevent_fd, fds))
				continue;
			check_telemetry(e[i].c, e[i].uevent_fd);
		}
	}
}

int main()
{
	struct events *e;
	fd_set fds;
	int i = 0;

	nvme_subsystem_t s;
	nvme_ctrl_t c;
	nvme_host_t h;
	nvme_root_t r;

	r = nvme_scan(NULL);
	if (!r)
		return EXIT_FAILURE;

	nvme_for_each_host(r, h)
		nvme_for_each_subsystem(h, s)
			nvme_subsystem_for_each_ctrl(s, c)
				i++;

	e = calloc(i, sizeof(struct events));
	FD_ZERO(&fds);
	i = 0;

	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			nvme_subsystem_for_each_ctrl(s, c) {
				int fd = open_uevent(c);

				if (fd < 0)
					continue;
				FD_SET(fd, &fds);
				e[i].uevent_fd = fd;
				e[i].c = c;
				i++;
			}
		}
	}

	wait_events(&fds, e, i);
	nvme_free_tree(r);
	free(e);

	return EXIT_SUCCESS;
}
