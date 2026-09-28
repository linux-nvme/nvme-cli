// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <systemd/sd-daemon.h>

#include "log.h"
#include "signals.h"

// Signal dispositions are per process, so one instance is enough.
static struct {
	dmn_reload_callback reload;
	void *user_data;
} reload_ctx;

static int on_sighup(sd_event_source *src,
		     const struct signalfd_siginfo *si __attribute__((unused)),
		     void *user_data __attribute__((unused)))
{
	uint64_t now = 0;

	/*
	 * Type=notify-reload: systemd ignores RELOADING=1 without
	 * MONOTONIC_USEC=, and the reload job times out.
	 */
	sd_event_now(sd_event_source_get_event(src), CLOCK_MONOTONIC, &now);
	sd_notifyf(0, "RELOADING=1\n"
		      "MONOTONIC_USEC=%" PRIu64 "\n"
		      "STATUS=Reloading configuration...", now);

	reload_ctx.reload(reload_ctx.user_data);

	// An empty STATUS= clears the text shown by systemctl status.
	sd_notify(0, "READY=1\nSTATUS=");

	return 0;
}

static int on_exit_signal(sd_event_source *src,
			  const struct signalfd_siginfo *si
				  __attribute__((unused)),
			  void *user_data __attribute__((unused)))
{
	sd_event_exit(sd_event_source_get_event(src), 0);

	return 0;
}

static int add_signal(sd_event *event, int signo, const char *name,
		      sd_event_signal_handler_t cback)
{
	int r;

	r = sd_event_add_signal(event, NULL, signo, cback, NULL);
	if (r < 0)
		log_err("sd_event_add_signal(%s): %s", name, strerror(-r));

	return r;
}

int dmn_add_signal_handlers(sd_event *event, dmn_reload_callback reload,
			    void *user_data)
{
	sigset_t mask;
	int r;

	reload_ctx.reload = reload;
	reload_ctx.user_data = user_data;

	// Block these from normal delivery; handle them via sd_event.
	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	r = add_signal(event, SIGHUP, "SIGHUP", on_sighup);
	if (r < 0)
		return r;

	// SIGTERM (systemctl stop) and SIGINT (Ctrl-C) exit the loop.
	r = add_signal(event, SIGTERM, "SIGTERM", on_exit_signal);
	if (r < 0)
		return r;

	return add_signal(event, SIGINT, "SIGINT", on_exit_signal);
}
