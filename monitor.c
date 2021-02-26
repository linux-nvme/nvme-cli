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
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <libudev.h>
#include <signal.h>
#include <time.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/inotify.h>

#include "nvme-status.h"
#include "nvme.h"
#include "util/argconfig.h"
#include "util/cleanup.h"
#include "common.h"
#include "fabrics.h"
#include "monitor.h"
#include "conn-db.h"
#define LOG_FUNCNAME 1
#include "util/log.h"
#include "event/event.h"

static struct monitor_config {
	bool autoconnect;
	bool keep_ctrls;
} mon_cfg = {
	.autoconnect = true,
	.keep_ctrls = true,
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
static sig_atomic_t got_sigchld;
static sigset_t orig_sigmask;

static void monitor_int_handler(int sig)
{
	must_exit = 1;
}

static void monitor_chld_handler(int sig)
{
	got_sigchld = 1;
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
	if (sigprocmask(SIG_BLOCK, &mask, &orig_sigmask) == -1)
		return -errno;
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		return -errno;
	if (sigaction(SIGINT, &sa, NULL) == -1)
		return -errno;

	sa.sa_handler = monitor_chld_handler;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		return -errno;

	/* signal mask to be used in epoll_pwait() */
	sigfillset(wait_mask);
	sigdelset(wait_mask, SIGTERM);
	sigdelset(wait_mask, SIGINT);
	sigdelset(wait_mask, SIGCHLD);

	return 0;
}

static int child_reset_signals(void)
{
	int err = 0;
	struct sigaction sa = { .sa_handler = SIG_DFL, };

	if (sigaction(SIGTERM, &sa, NULL) == -1)
		err = errno;
	if (sigaction(SIGINT, &sa, NULL) == -1 && !err)
		err = errno;
	if (sigaction(SIGCHLD, &sa, NULL) == -1 && !err)
		err = errno;

	if (sigprocmask(SIG_SETMASK, &orig_sigmask, NULL) == -1 && !err)
		err = errno;

	if (err)
		msg(LOG_ERR, "error resetting signal handlers and mask\n");
	return -err;
}

static void monitor_handle_nvme_add(struct udev_device *ud)
{
	const char *syspath = udev_device_get_syspath(ud);
	char *subsysnqn __cleanup__(cleanup_charp) = NULL;
	char *state __cleanup__(cleanup_charp) = NULL;

	if (!syspath)
		return;
	subsysnqn = nvme_get_ctrl_attr(syspath, "subsysnqn");
	state = nvme_get_ctrl_attr(syspath, "state");
	msg(LOG_DEBUG, "add %s => %s [%s]\n", syspath, subsysnqn, state);
}

static void monitor_handle_nvme_remove(struct udev_device *ud)
{
	const char *sysname = udev_device_get_sysname(ud);
	struct nvme_connection *co;

	if (!sysname)
		return;

	co = conndb_find_by_ctrl(sysname);
	if (co) {
		msg(LOG_DEBUG, "%s: connection discovery controller removed\n",
		    sysname);
		co->discovery_instance = -1;
	}
	return;
}

static int monitor_get_fc_uev_props(struct udev_device *ud,
				    char *traddr, size_t tra_sz,
				    char *host_traddr, size_t htra_sz)
{
	const char *sysname = udev_device_get_sysname(ud);
	const char *tra = NULL, *host_tra = NULL;
	bool fc_event_seen = false;
	struct udev_list_entry *entry;

	entry = udev_device_get_properties_list_entry(ud);
	if (!entry) {
		msg(LOG_NOTICE, "%s: emtpy properties list\n", sysname);
		return -ENOENT;
	}

	for (; entry; entry = udev_list_entry_get_next(entry)) {
		const char *name = udev_list_entry_get_name(entry);

		if (!strcmp(name, "FC_EVENT") &&
		    !strcmp(udev_list_entry_get_value(entry), "nvmediscovery"))
				fc_event_seen = true;
		else if (!strcmp(name, "NVMEFC_HOST_TRADDR"))
			host_tra = udev_list_entry_get_value(entry);
		else if (!strcmp(name, "NVMEFC_TRADDR"))
			tra = udev_list_entry_get_value(entry);
	}
	if (!fc_event_seen) {
		msg(LOG_DEBUG, "%s: FC_EVENT property missing or unsupported\n",
		    sysname);
		return -EINVAL;
	}
	if (!tra || !host_tra) {
		msg(LOG_WARNING, "%s: transport properties missing\n", sysname);
		return -EINVAL;
	}

	if (!memccpy(traddr, tra, '\0', tra_sz) ||
	    !memccpy(host_traddr, host_tra, '\0', htra_sz)) {
		msg(LOG_ERR, "traddr (%zu) or host_traddr (%zu) overflow\n",
		    strlen(traddr), strlen(host_traddr));
		return -ENAMETOOLONG;
	}

	return 0;
}

static int monitor_discovery(const char *transport, const char *traddr,
			     const char *trsvcid, const char *host_traddr,
			     const char *devname)
{
	char argstr[BUF_SIZE];
	pid_t pid;
	int rc, db_rc;
	struct nvme_connection *co = NULL;
	char *device = NULL;

	db_rc = conndb_add(transport, traddr, trsvcid, host_traddr, &co);
	if (db_rc != 0 && db_rc != -EEXIST)
		return db_rc;

	if (co->status == CS_DISC_RUNNING) {
		co->discovery_pending = 1;
		return -EAGAIN;
	}

	pid = fork();
	if (pid == -1) {
		msg(LOG_ERR, "failed to fork discovery task: %m");
		return -errno;
	} else if (pid > 0) {
		msg(LOG_DEBUG, "started discovery task %ld\n", (long)pid);

		co->discovery_pending = 0;
		co->status = CS_DISC_RUNNING;
		co->discovery_task = pid;
		if (devname) {
			int instance = ctrl_instance(devname);

			if (instance < 0) {
				msg(LOG_ERR, "unexpected devname: %s\n",
				    devname);
			} else
				co->discovery_instance = instance;
		}
		return 0;
	}

	child_reset_signals();
	free_dispatcher(mon_dsp);
	conndb_free();

	conn_msg(LOG_NOTICE, co, "starting discovery in state %s\n",
		 conn_status_str(co->status));

	/*
	 * Try to re-use existing controller. do_discovery() will check
	 * if it matches the connection parameters.
	 * fabrics_cfg.device must be allocated on the heap!
	 */
	if (devname)
		device = strdup(devname);
	else if (co->discovery_instance >= 0 &&
		 asprintf(&device, "nvme%d", co->discovery_instance) == -1)
		device = NULL;

	if (device)
		msg(LOG_INFO, "using discovery controller %s\n", device);

	fabrics_cfg.nqn = NVME_DISC_SUBSYS_NAME;
	fabrics_cfg.transport = transport;
	fabrics_cfg.traddr = traddr;
	fabrics_cfg.trsvcid = trsvcid && *trsvcid ? trsvcid : NULL;
	fabrics_cfg.host_traddr = host_traddr && *host_traddr ? host_traddr : NULL;
	fabrics_cfg.device = device;
	/* Without the following, the kernel returns EINVAL */
	fabrics_cfg.tos = -1;
	fabrics_cfg.persistent = true;

	rc = build_options(argstr, sizeof(argstr), true);
	msg(LOG_DEBUG, "%s\n", argstr);
	rc = do_discover(argstr, mon_cfg.autoconnect, NORMAL);

	free(device);
	exit(-rc);
	/* not reached */
	return rc;
}

static void monitor_handle_fc_uev(struct udev_device *ud)
{
	const char *action = udev_device_get_action(ud);
	const char *sysname = udev_device_get_sysname(ud);
	char traddr[NVMF_TRADDR_SIZE], host_traddr[NVMF_TRADDR_SIZE];

	if (strcmp(action, "change") || strcmp(sysname, "fc_udev_device"))
		return;

	if (monitor_get_fc_uev_props(ud, traddr, sizeof(traddr),
				     host_traddr, sizeof(host_traddr)))
		return;

	monitor_discovery("fc", traddr, NULL, host_traddr, NULL);
}

static int monitor_get_nvme_uev_props(struct udev_device *ud,
				      char *transport, size_t tr_sz,
				      char *traddr, size_t tra_sz,
				      char *trsvcid, size_t trs_sz,
				      char *host_traddr, size_t htra_sz)
{
	const char *sysname = udev_device_get_sysname(ud);
	bool aen_disc = false;
	struct udev_list_entry *entry;

	entry = udev_device_get_properties_list_entry(ud);
	if (!entry) {
		msg(LOG_NOTICE, "%s: emtpy properties list\n", sysname);
		return -ENOENT;
	}

	*transport = *traddr = *trsvcid = *host_traddr = '\0';
	for (; entry; entry = udev_list_entry_get_next(entry)) {
		const char *name = udev_list_entry_get_name(entry);

		if (!strcmp(name, "NVME_AEN") &&
		    !strcmp(udev_list_entry_get_value(entry), "0x70f002"))
				aen_disc = true;
		else if (!strcmp(name, "NVME_TRTYPE"))
			memccpy(transport, udev_list_entry_get_value(entry),
				'\0', tr_sz);
		else if (!strcmp(name, "NVME_TRADDR"))
			memccpy(traddr, udev_list_entry_get_value(entry),
				'\0', htra_sz);
		else if (!strcmp(name, "NVME_TRSVCID"))
			memccpy(trsvcid, udev_list_entry_get_value(entry),
				'\0', trs_sz);
		else if (!strcmp(name, "NVME_HOST_TRADDR"))
			memccpy(host_traddr, udev_list_entry_get_value(entry),
				'\0', tra_sz);
	}
	if (!aen_disc) {
		msg(LOG_DEBUG, "%s: not a \"discovery log changed\" AEN, ignoring event\n",
		    sysname);
		return -EINVAL;
	}

	if (!*traddr || !*transport) {
		msg(LOG_WARNING, "%s: transport properties missing\n", sysname);
		return -EINVAL;
	}

	return 0;
}

static void monitor_handle_nvme_uev(struct udev_device *ud)
{
	char traddr[NVMF_TRADDR_SIZE], host_traddr[NVMF_TRADDR_SIZE];
	char trsvcid[NVMF_TRSVCID_SIZE], transport[5];

	if (!strcmp(udev_device_get_action(ud), "remove")) {
		monitor_handle_nvme_remove(ud);
		return;
	}
	if (!strcmp(udev_device_get_action(ud), "add")) {
		monitor_handle_nvme_add(ud);
		return;
	}
	if (strcmp(udev_device_get_action(ud), "change"))
		return;

	if (monitor_get_nvme_uev_props(ud, transport, sizeof(transport),
				       traddr, sizeof(traddr),
				       trsvcid, sizeof(trsvcid),
				       host_traddr, sizeof(host_traddr)))
		return;

	monitor_discovery(transport, traddr,
			  strcmp(trsvcid, "none") ? trsvcid : NULL, host_traddr,
			  udev_device_get_sysname(ud));
}

static void monitor_handle_udevice(struct udev_device *ud)
{
	const char *subsys  = udev_device_get_subsystem(ud);

	if (log_level >= LOG_INFO) {
		const char *action = udev_device_get_action(ud);
		const char *syspath = udev_device_get_syspath(ud);

		msg(LOG_INFO, "%s %s\n", action, syspath);
	}
	if (!strcmp(subsys, "fc"))
		monitor_handle_fc_uev(ud);
	else if (!strcmp(subsys, "nvme"))
		monitor_handle_nvme_uev(ud);
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

static struct {
	bool running;
	bool pending;
	pid_t pid;
} discovery_conf_task;

static int monitor_discover_from_conf_file(void);

static int handle_epoll_err(int errcode)
{
	if (errcode != -EINTR)
		return errcode;
	else if (must_exit) {
		msg(LOG_NOTICE, "monitor: exit signal received\n");
		return ELOOP_QUIT;
	} else if (!got_sigchld) {
		msg(LOG_WARNING, "monitor: unexpected interruption, ignoring\n");
		return ELOOP_CONTINUE;
	}

	got_sigchld = 0;
	while (true) {
	struct nvme_connection *co;
		int wstatus;
		pid_t pid;

		pid = waitpid(-1, &wstatus, WNOHANG);
		switch(pid) {
		case -1:
			if (errno != ECHILD)
				msg(LOG_ERR, "error in waitpid: %m\n");
			goto out;
		case 0:
			goto out;
		default:
			break;
		}

		co = conndb_find_by_pid(pid);
		if (!co) {
			if (!WIFEXITED(wstatus))
				msg(LOG_WARNING, "child %ld didn't exit normally\n",
				    (long)pid);
			else if (WEXITSTATUS(wstatus) != 0)
				msg(LOG_NOTICE, "child %ld exited with status \"%s\"\n",
				    (long)pid, strerror(WEXITSTATUS(wstatus)));
			else
				msg(LOG_DEBUG, "child %ld exited normally\n", (long)pid);
			if (discovery_conf_task.running &&
			    discovery_conf_task.pid == pid) {
				discovery_conf_task.running = false;
				if (discovery_conf_task.pending) {
					msg(LOG_NOTICE,
					    "discovery from conf file pending - restarting\n");
					monitor_discover_from_conf_file();
				}
			}
			continue;
		}

		if (!WIFEXITED(wstatus)) {
			msg(LOG_WARNING, "child %ld didn't exit normally\n",
			    (long)pid);
			co->status = CS_FAILED;
		} else if (WEXITSTATUS(wstatus) != 0) {
			msg(LOG_NOTICE, "child %ld exited with status \"%s\"\n",
			    (long)pid, strerror(WEXITSTATUS(wstatus)));
			co->status = CS_FAILED;
			co->did_discovery = 1;
			co->discovery_result = WEXITSTATUS(wstatus);
		} else {
			msg(LOG_DEBUG, "child %ld exited normally\n", (long)pid);
			co->status = CS_ONLINE;
			co->successful_discovery = co->did_discovery = 1;
			co->discovery_result = 0;
		}
		if (co->discovery_pending) {
			msg(LOG_NOTICE, "new discovery pending - restarting\n");
			monitor_discovery(co->transport, co->traddr,
					  co->trsvcid, co->host_traddr, NULL);
		}
	};

out:
	/* tell event_loop() to continue */
	return ELOOP_CONTINUE;
}

static int monitor_kill_discovery_task(struct nvme_connection *co,
				       void *arg __attribute__((unused)))
{
	int wstatus;
	pid_t pid, wpid = -1;

	if (co->status != CS_DISC_RUNNING)
		return CD_CB_OK;

	pid = co->discovery_task;
	co->status = CS_FAILED;
	if (kill(co->discovery_task, SIGTERM) == -1) {
		msg(LOG_ERR, "failed to send SIGTERM to pid %ld: %m\n",
		    (long)pid);
		wpid = waitpid(pid, &wstatus, WNOHANG);
	} else {
		msg(LOG_DEBUG, "sent SIGTERM to pid %ld, waiting\n", (long)pid);
		wpid = waitpid(pid, &wstatus, 0);
	}
	if (wpid != pid) {
		msg(LOG_ERR, "failed to wait for %ld: %m\n", (long)pid);
		return CD_CB_ERR;
	} else {
		msg(LOG_DEBUG, "child %ld terminated\n", (long)pid);
		return CD_CB_OK;
	}
}

static int monitor_remove_discovery_ctrl(struct nvme_connection *co,
					void *arg __attribute__((unused)))
{
	char syspath[PATH_MAX];
	int len;
	char *subsysnqn __cleanup__(cleanup_charp) = NULL;

	if (co->discovery_instance == -1 || co->discovery_ctrl_existed)
		return CD_CB_OK;

	len = snprintf(syspath, sizeof(syspath), SYS_NVME "/nvme%d",
		       co->discovery_instance);
	if (len < 0 || len >= sizeof(syspath))
		return CD_CB_ERR;

	subsysnqn = nvme_get_ctrl_attr(syspath, "subsysnqn");
	if (subsysnqn && !strcmp(subsysnqn, NVME_DISC_SUBSYS_NAME)) {
		if (remove_ctrl(co->discovery_instance)) {
			msg(LOG_ERR,
			    "failed to remove discovery controller /dev/nvme%d: %m\n",
			    co->discovery_instance);
			return CD_CB_ERR;
		} else
			msg(LOG_INFO,
			    "removed discovery controller /dev/nvme%d\n",
			    co->discovery_instance);
	} else
		msg(LOG_WARNING,
		    "unexpected NQN %s on /dev/nvme%d, not removing controller\n",
		    subsysnqn ? subsysnqn : "(NULL)", co->discovery_instance);
	return CD_CB_OK;
}

static int monitor_discover_from_conf_file(void)
{
	char argstr[BUF_SIZE];
	pid_t pid;
	int rc;

	if (discovery_conf_task.running) {
		msg(LOG_NOTICE, "discovery from conf file already running (%ld)\n",
		    (long)discovery_conf_task.pid);
		discovery_conf_task.pending = true;
		return 0;
	}

	pid = fork();
	if (pid == -1) {
		msg(LOG_ERR, "failed to fork discovery task: %m");
		return -errno;
	} else if (pid > 0) {
		msg(LOG_DEBUG, "started discovery task %ld from conf file\n",
		    (long)pid);
		discovery_conf_task.pending = false;
		discovery_conf_task.running = true;
		discovery_conf_task.pid = pid;
		return 0;
	}

	child_reset_signals();

	msg(LOG_NOTICE, "starting discovery from conf file\n");

	fabrics_cfg.nqn = NVME_DISC_SUBSYS_NAME;
	fabrics_cfg.tos = -1;
	fabrics_cfg.persistent = true;

	rc = discover_from_conf_file("Discover NVMeoF subsystems from " PATH_NVMF_DISC,
				     argstr, mon_cfg.autoconnect);

	exit(-rc);
	/* not reached */
	return rc;
}

static int discovery_from_conf_file_cb(struct event *ev __attribute__((unused)),
					unsigned int __attribute__((unused)) ep_events)
{
	monitor_discover_from_conf_file();
	return EVENTCB_CLEANUP;
}

static void handle_inotify_event(struct inotify_event *iev)
{
	if ((iev->mask & (IN_CLOSE_WRITE|IN_MOVED_TO)) == 0) {
		msg(LOG_DEBUG, "ignoring event mask 0x%"PRIx32"\n", iev->mask);
		return;
	}

	if (!iev->name || strcmp(iev->name, FILE_NVMF_DISC)) {
		msg(LOG_DEBUG, "ignoring event mask 0x%"PRIx32" for %s\n",
		    iev->mask, iev->name ? iev->name : "(null)");
		return;
	}

	msg(LOG_INFO, "discovery.conf changed, re-reading\n");
	monitor_discover_from_conf_file();
}

static int inotify_cb(struct event *ev, unsigned int ep_events)
{
	char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
	int rc;

	if (ev->reason != REASON_EVENT_OCCURED || (ep_events & EPOLLIN) == 0)
		return EVENTCB_CONTINUE;

	while (true) {
		struct inotify_event *iev;

		rc = read(ev->fd, buf, sizeof(buf));
		if (rc == -1) {
			if (errno != EAGAIN)
				msg(LOG_ERR, "error reading from inotify fd: %m\n");
			return EVENTCB_CONTINUE;
		}

		iev = (struct inotify_event *)buf;
		if (iev->mask & (IN_DELETE_SELF|IN_MOVE_SELF)) {
			if (inotify_rm_watch(ev->fd, iev->wd) == -1)
				msg(LOG_ERR, "failed to remove watch %d: %m\n",
				    iev->wd);
			msg(LOG_WARNING, "inotify watch %d removed\n", iev->wd);
			return EVENTCB_CLEANUP;
		}
		handle_inotify_event(iev);
	}
	return EVENTCB_CONTINUE;
}

static DEFINE_CLEANUP_FUNC(cleanup_event, struct event *, free);

static void add_inotify_event(struct dispatcher *dsp)
{
	struct event *inotify_event __cleanup__(cleanup_event) = NULL;
	int fd __cleanup__(cleanup_fd) = -1;
	int rc;

	inotify_event = calloc(1, sizeof *inotify_event);
	if (!inotify_event)
		return;

	fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
	if (fd == -1) {
		msg(LOG_ERR, "failed to init inotify: %m\n");
		return;
	}

	*inotify_event = EVENT_ON_HEAP(inotify_cb, fd, EPOLLIN);
	rc = inotify_add_watch(inotify_event->fd, PATH_NVMF_CFG_DIR,
			       IN_CLOSE_WRITE|IN_MOVED_TO|
			       IN_DELETE_SELF|IN_MOVE_SELF);
	if (rc == -1)
		msg(LOG_ERR, "failed to add inotify watch for %s: %m\n",
		    PATH_NVMF_CFG_DIR);

	if ((rc = event_add(dsp, inotify_event)) < 0) {
		msg(LOG_ERR, "failed to add inotify event: %s\n",
		    strerror(-rc));
		return;
	}
	fd = -1;
	inotify_event = NULL;
}

static int monitor_parse_opts(const char *desc, int argc, char **argv)
{
	bool quiet = false;
	bool verbose = false;
	bool debug = false;
	bool noauto = false;
	bool cleanup = false;
	int ret;
	OPT_ARGS(opts) = {
		OPT_FLAG("no-connect",     'N', &noauto,              "dry run, do not autoconnect to discovered controllers"),
		OPT_FLAG("cleanup",        'C', &cleanup,                     "remove created discovery controllers on exit"),
		OPT_LIST("hostnqn",        'q', &fabrics_cfg.hostnqn,         "user-defined hostnqn (if default not used)"),
		OPT_LIST("hostid",         'I', &fabrics_cfg.hostid,          "user-defined hostid (if default not used)"),
		OPT_INT("keep-alive-tmo",  'k', &fabrics_cfg.keep_alive_tmo,  "keep alive timeout period in seconds"),
		OPT_INT("reconnect-delay", 'c', &fabrics_cfg.reconnect_delay, "reconnect timeout period in seconds"),
		OPT_INT("ctrl-loss-tmo",   'l', &fabrics_cfg.ctrl_loss_tmo,   "controller loss timeout period in seconds"),
		OPT_INT("tos",             'T', &fabrics_cfg.tos,             "type of service"),
		OPT_FLAG("hdr_digest",     'g', &fabrics_cfg.hdr_digest,      "enable transport protocol header digest (TCP transport)"),
		OPT_FLAG("data_digest",    'G', &fabrics_cfg.data_digest,     "enable transport protocol data digest (TCP transport)"),
		OPT_INT("nr-io-queues",    'i', &fabrics_cfg.nr_io_queues,    "number of io queues to use (default is core count)"),
		OPT_INT("nr-write-queues", 'W', &fabrics_cfg.nr_write_queues, "number of write queues to use (default 0)"),
		OPT_INT("nr-poll-queues",  'P', &fabrics_cfg.nr_poll_queues,  "number of poll queues to use (default 0)"),
		OPT_INT("queue-size",      'Q', &fabrics_cfg.queue_size,      "number of io queue elements to use (default 128)"),
		OPT_FLAG("matching",       'm', &fabrics_cfg.matching_only,   "connect only records matching the traddr"),
		OPT_FLAG("silent",         'S', &quiet,               "log level: silent"),
		OPT_FLAG("verbose",        'v', &verbose,             "log level: verbose"),
		OPT_FLAG("debug",          'D', &debug,               "log level: debug"),
		OPT_FLAG("timestamps",     't', &log_timestamp,       "print log timestamps"),
		OPT_END()
	};

	log_pid = true;
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
	if (cleanup)
		mon_cfg.keep_ctrls = false;

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
	struct event startup_discovery_event = { .fd = -1, };
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

	startup_discovery_event =
		TIMER_EVENT_ON_STACK(discovery_from_conf_file_cb, 0);
	if ((ret = event_add(mon_dsp, &startup_discovery_event)) != 0)
		msg(LOG_ERR, "failed to register initial discovery timer: %s\n",
		    strerror(-ret));

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

	add_inotify_event(mon_dsp);
	conndb_init_from_sysfs();

	ret = event_loop(mon_dsp, &wait_mask, handle_epoll_err);

	conndb_for_each(monitor_kill_discovery_task, NULL);
	if (mon_cfg.autoconnect && !mon_cfg.keep_ctrls)
		conndb_for_each(monitor_remove_discovery_ctrl, NULL);
	conndb_free();
out:
	free_dispatcher(mon_dsp);
	return nvme_status_to_errno(ret, true);
}
