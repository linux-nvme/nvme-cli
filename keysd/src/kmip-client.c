// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

#include <daemon-util/log.h>

#include "config.h"
#include "import.h"
#include "kmip-client.h"
#include "kmip-varlink.h"

// Margin over the time the helper may take, for its start and DNS.
#define CALL_MARGIN_USEC	(5 * 1000000ULL)

struct kmip_call {
	const struct kmip_job *job;
	uint64_t next_try;	// CLOCK_MONOTONIC, in usec
	uint64_t delay;		// before the next retry
	bool done;
};

/* The calls to one KMS. Only one is active at a time. */
struct kms_queue {
	struct kmip_client *c;
	const struct keysd_kmip *kms;
	size_t server;		// the last server that answered
	struct kmip_call **calls;
	size_t nr_calls;
	struct kmip_call *active;
	sd_varlink *link;
	sd_event_source *timer;
};

struct kmip_client {
	sd_event *event;
	const struct kmip_client_cfg *cfg;
	struct kmip_call *calls;
	size_t nr_calls;
	struct kms_queue *queues;
	size_t nr_queues;
	size_t pending;
};

static void queue_next(struct kms_queue *q);

static void notify_status(struct kmip_client *c)
{
	if (c->pending)
		sd_notifyf(0, "STATUS=%zu KMIP key(s) not imported yet",
			   c->pending);
	else
		sd_notify(0, "STATUS=All KMIP keys imported");
}

static void call_done(struct kms_queue *q, struct kmip_call *call)
{
	call->done = true;
	q->c->pending--;
	notify_status(q->c);
}

static void call_failed(struct kms_queue *q, struct kmip_call *call,
			const char *why)
{
	const struct kmip_job *job = call->job;
	uint64_t now = 0;

	sd_event_now(q->c->event, CLOCK_MONOTONIC, &now);
	call->next_try = now + call->delay;

	log_err("%s: %s: KMS '%s', key '%s': %s, retry in %llu s",
		job->source, job->subsysnqn, q->kms->name, job->name, why,
		(unsigned long long)(call->delay / 1000000));

	call->delay *= 2;
	if (call->delay > q->c->cfg->retry_max_usec)
		call->delay = q->c->cfg->retry_max_usec;
}

static void end_call(struct kms_queue *q)
{
	q->link = sd_varlink_close_unref(q->link);
	q->active = NULL;
}

static int on_reply(sd_varlink *link, sd_json_variant *params,
		    const char *error_id, sd_varlink_reply_flags_t flags,
		    void *userdata)
{
	struct kms_queue *q = userdata;
	struct kmip_call *call = q->active;
	sd_json_variant *key, *server;
	int r;

	if (error_id) {
		call_failed(q, call, error_id);
		goto out;
	}

	key = sd_json_variant_by_key(params, "key");
	if (!key || !sd_json_variant_is_string(key)) {
		call_failed(q, call, "no key in the reply");
		goto out;
	}

	server = sd_json_variant_by_key(params, "server");
	if (server && sd_json_variant_is_unsigned(server) &&
	    sd_json_variant_unsigned(server) < q->kms->nr_servers)
		q->server = sd_json_variant_unsigned(server);

	r = q->c->cfg->import(call->job, sd_json_variant_string(key),
			      q->c->cfg->arg);
	if (r < 0)
		call_failed(q, call, strerror(-r));
	else
		call_done(q, call);

out:
	end_call(q);
	queue_next(q);

	return 0;
}

static int start_call(struct kms_queue *q, struct kmip_call *call)
{
	const struct kmip_job *job = call->job;
	uint64_t timeout;
	int r;

	r = sd_varlink_connect_address(&q->link, q->c->cfg->address);
	if (r < 0)
		return r;

	// The helper may try every server of the KMS.
	timeout = (uint64_t)q->kms->timeout_ms * 1000 * q->kms->nr_servers +
		  CALL_MARGIN_USEC;

	sd_varlink_set_userdata(q->link, q);
	r = sd_varlink_attach_event(q->link, q->c->event, 0);
	if (r >= 0)
		r = sd_varlink_set_input_sensitive(q->link);
	if (r >= 0)
		r = sd_varlink_bind_reply(q->link, on_reply);
	if (r >= 0)
		r = sd_varlink_set_relative_timeout(q->link, timeout);
	if (r >= 0)
		r = sd_varlink_invokebo(q->link, KMIP_VARLINK_GET_KEY,
				SD_JSON_BUILD_PAIR_STRING("kms", q->kms->name),
				SD_JSON_BUILD_PAIR_STRING("name", job->name),
				SD_JSON_BUILD_PAIR_UNSIGNED("server",
							    q->server));
	if (r < 0) {
		q->link = sd_varlink_close_unref(q->link);
		return r;
	}
	q->active = call;

	return 0;
}

static int on_timer(sd_event_source *s, uint64_t usec, void *userdata)
{
	queue_next(userdata);

	return 0;
}

static void arm_timer(struct kms_queue *q, uint64_t when)
{
	int r;

	if (!q->timer) {
		r = sd_event_add_time(q->c->event, &q->timer, CLOCK_MONOTONIC,
				      when, 0, on_timer, q);
		if (r < 0)
			log_err("KMS '%s': cannot add a timer: %s",
				q->kms->name, strerror(-r));
		return;
	}

	sd_event_source_set_time(q->timer, when);
	sd_event_source_set_enabled(q->timer, SD_EVENT_ONESHOT);
}

/* Start the next call that is due, or wait for the first one. */
static void queue_next(struct kms_queue *q)
{
	struct kmip_call *call, *next = NULL;
	uint64_t now = 0;
	char why[96];
	size_t i;
	int r;

	while (!q->active) {
		sd_event_now(q->c->event, CLOCK_MONOTONIC, &now);

		call = NULL;
		next = NULL;
		for (i = 0; i < q->nr_calls; i++) {
			if (q->calls[i]->done)
				continue;
			if (q->calls[i]->next_try <= now) {
				call = q->calls[i];
				break;
			}
			if (!next || q->calls[i]->next_try < next->next_try)
				next = q->calls[i];
		}

		if (!call) {
			if (next)
				arm_timer(q, next->next_try);
			return;
		}

		r = start_call(q, call);
		if (r < 0) {
			snprintf(why, sizeof(why),
				 "cannot reach nvme-keysd-kmip: %s",
				 strerror(-r));
			call_failed(q, call, why);
		}
	}
}

static struct kms_queue *find_queue(struct kmip_client *c,
				    const struct keysd_kmip *kms)
{
	size_t i;

	for (i = 0; i < c->nr_queues; i++)
		if (c->queues[i].kms == kms)
			return &c->queues[i];

	return NULL;
}

static int add_to_queue(struct kmip_client *c, struct kmip_call *call)
{
	struct kms_queue *q = find_queue(c, call->job->kms);
	struct kmip_call **calls;

	if (!q) {
		q = &c->queues[c->nr_queues++];
		q->c = c;
		q->kms = call->job->kms;
	}

	calls = realloc(q->calls, (q->nr_calls + 1) * sizeof(*calls));
	if (!calls)
		return -ENOMEM;
	q->calls = calls;
	q->calls[q->nr_calls++] = call;

	return 0;
}

int kmip_client_new(sd_event *event, const struct kmip_client_cfg *cfg,
		const struct kmip_job *jobs, size_t nr_jobs,
		struct kmip_client **out)
{
	struct kmip_client *c;
	size_t i;
	int r;

	c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;
	c->event = event;
	c->cfg = cfg;

	// At most one queue per job.
	c->calls = calloc(nr_jobs, sizeof(*c->calls));
	c->queues = calloc(nr_jobs, sizeof(*c->queues));
	if (nr_jobs && (!c->calls || !c->queues)) {
		r = -ENOMEM;
		goto err;
	}

	for (i = 0; i < nr_jobs; i++) {
		c->calls[i].job = &jobs[i];
		c->calls[i].delay = cfg->retry_usec;
		r = add_to_queue(c, &c->calls[i]);
		if (r < 0)
			goto err;
	}
	c->nr_calls = nr_jobs;
	c->pending = nr_jobs;
	notify_status(c);

	for (i = 0; i < c->nr_queues; i++)
		queue_next(&c->queues[i]);

	*out = c;

	return 0;

err:
	kmip_client_free(c);

	return r;
}

size_t kmip_client_pending(const struct kmip_client *c)
{
	return c->pending;
}

void kmip_client_free(struct kmip_client *c)
{
	struct kms_queue *q;
	size_t i;

	if (!c)
		return;

	for (i = 0; i < c->nr_queues; i++) {
		q = &c->queues[i];
		sd_varlink_close_unref(q->link);
		sd_event_source_disable_unref(q->timer);
		free(q->calls);
	}
	free(c->queues);
	free(c->calls);
	free(c);
}
