/*
 * Copyright (C) 2021 SUSE LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This file implements a simple monitor for NVMe-related uevents.
 */

#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <libudev.h>
#include <signal.h>
#include <time.h>
#include <syslog.h>
#include <sys/epoll.h>

#include "nvme-status.h"
#include "util/argconfig.h"
#include "util/cleanup.h"
#include "common.h"
#include "monitor.h"
#define LOG_FUNCNAME 1
#include "util/log.h"
#include "event/event.h"

static struct monitor_config {
	bool autoconnect;
} mon_cfg = {
	.autoconnect = true,
};

static struct dispatcher *mon_dsp;

static DEFINE_CLEANUP_FUNC(cleanup_monitorp, struct udev_monitor *, udev_monitor_unref);

static int create_udev_monitor(struct udev *udev, struct udev_monitor **pmon)
{
	struct udev_monitor *mon __cleanup__(cleanup_monitorp) = NULL;
	int ret;
	bool use_udev;
	static const char *const monitor_name[] = {
		[false] = "kernel",
		[true]  = "udev",
	};

	/* Check if udevd is running, same test that libudev uses */
	use_udev = access("/run/udev/control", F_OK) >= 0;
	msg(LOG_DEBUG, "using %s monitor for uevents\n", monitor_name[use_udev]);

	mon = udev_monitor_new_from_netlink(udev, monitor_name[use_udev]);
	if (!mon)
		return errno ? -errno : -ENOMEM;

	/* Add match for NVMe controller devices */
	ret = udev_monitor_filter_add_match_subsystem_devtype(mon, "nvme", NULL);
	/* Add match for fc_udev_device */
	ret = udev_monitor_filter_add_match_subsystem_devtype(mon, "fc", NULL);

	/*
	 * If we use the "udev" monitor, the kernel filters out the interesting
	 * uevents for us using BPF. A single event is normally well below 1kB,
	 * so 1MiB is sufficient for queueing more than 1000 uevents, which
	 * should be plenty for just nvme.
	 *
	 * For "kernel" monitors, the filtering is done by libudev in user space,
	 * thus every device is received in the first place, and a larger
	 * receive buffer is needed. Use the same value as udevd.
	 */
	udev_monitor_set_receive_buffer_size(mon, (use_udev ? 1 : 128) * 1024 * 1024);
	ret = udev_monitor_enable_receiving(mon);
	if (ret < 0)
		return ret;
	*pmon = mon;
	mon = NULL;
	return 0;
}

static sig_atomic_t must_exit;

static void monitor_int_handler(int sig)
{
	must_exit = 1;
}

static int monitor_init_signals(sigset_t *wait_mask)
{
	sigset_t mask;
	struct sigaction sa = { .sa_handler = monitor_int_handler, };

	/*
	 * Block all signals. They will be unblocked when we wait
	 * for events.
	 */
	sigfillset(&mask);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
		return -errno;
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		return -errno;
	if (sigaction(SIGINT, &sa, NULL) == -1)
		return -errno;

	/* signal mask to be used in epoll_pwait() */
	sigfillset(wait_mask);
	sigdelset(wait_mask, SIGTERM);
	sigdelset(wait_mask, SIGINT);

	return 0;
}

static void monitor_handle_udevice(struct udev_device *ud)
{
	msg(LOG_INFO, "uevent: %s %s\n",
		udev_device_get_action(ud),
		udev_device_get_sysname(ud));
}

struct udev_monitor_event {
	struct event e;
	struct udev_monitor *monitor;
};

static int monitor_handle_uevents(struct event *ev,
				  uint32_t __attribute__((unused)) ep_events)
{
	struct udev_monitor_event *udev_event =
		container_of(ev, struct udev_monitor_event, e);
	struct udev_monitor *monitor = udev_event->monitor;
	struct udev_device *ud;

	for (ud = udev_monitor_receive_device(monitor);
	     ud;
	     ud = udev_monitor_receive_device(monitor)) {
		monitor_handle_udevice(ud);
		udev_device_unref(ud);
	}
	return EVENTCB_CONTINUE;
}

static int monitor_parse_opts(const char *desc, int argc, char **argv)
{
	bool quiet = false;
	bool verbose = false;
	bool debug = false;
	bool noauto = false;
	int ret;
	OPT_ARGS(opts) = {
		OPT_FLAG("no-connect",     'N', &noauto,              "dry run, do not autoconnect to discovered controllers"),
		OPT_FLAG("silent",         'S', &quiet,               "log level: silent"),
		OPT_FLAG("verbose",        'v', &verbose,             "log level: verbose"),
		OPT_FLAG("debug",          'D', &debug,               "log level: debug"),
		OPT_FLAG("timestamps",     't', &log_timestamp,       "print log timestamps"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;
	if (quiet)
		log_level = LOG_WARNING;
	if (verbose)
		log_level = LOG_INFO;
	if (debug)
		log_level = LOG_DEBUG;
	if (noauto)
		mon_cfg.autoconnect = false;

	return ret;
}

static DEFINE_CLEANUP_FUNC(cleanup_udevp, struct udev *, udev_unref);

static void cleanup_udev_event(struct event *evt)
{
	struct udev_monitor_event *ue;

	ue = container_of(evt, struct udev_monitor_event, e);
	if (ue->monitor)
		ue->monitor = udev_monitor_unref(ue->monitor);
}

int aen_monitor(const char *desc, int argc, char **argv)
{
	int ret;
	struct udev *udev __cleanup__(cleanup_udevp) = NULL;
	struct udev_monitor *monitor __cleanup__(cleanup_monitorp) = NULL;
	struct udev_monitor_event udev_event = { .e.fd = -1, };
	sigset_t wait_mask;

	ret = monitor_parse_opts(desc, argc, argv);
	if (ret)
		goto out;

	ret = monitor_init_signals(&wait_mask);
	if (ret != 0) {
		msg(LOG_ERR, "monitor: failed to initialize signals: %m\n");
		goto out;
	}

	mon_dsp = new_dispatcher(CLOCK_REALTIME);
	if (!mon_dsp) {
		ret = errno ? -errno : -EIO;
		goto out;
	}

	udev = udev_new();
	if (!udev) {
		msg(LOG_ERR, "failed to create udev object: %m\n");
		ret = errno ? -errno : -ENOMEM;
		goto out;
	}

	ret = create_udev_monitor(udev, &monitor);
	if (ret != 0)
		goto out;

	udev_event.e = EVENT_ON_STACK(monitor_handle_uevents,
				      udev_monitor_get_fd(monitor), EPOLLIN);
	if (udev_event.e.fd == -1)
		goto out;
	udev_event.e.cleanup = cleanup_udev_event;
	udev_event.monitor = monitor;
	monitor = NULL;

	if ((ret = event_add(mon_dsp, &udev_event.e)) != 0) {
		msg(LOG_ERR, "failed to register udev monitor event: %s\n",
		    strerror(-ret));
		goto out;
	}

	ret = event_loop(mon_dsp, &wait_mask, NULL);

out:
	free_dispatcher(mon_dsp);
	return nvme_status_to_errno(ret, true);
}
