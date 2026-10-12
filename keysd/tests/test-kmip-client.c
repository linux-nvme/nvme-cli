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
#include <unistd.h>

#include <systemd/sd-event.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

#include <shared/io-util.h>

#include "config.h"
#include "import.h"
#include "kmip-client.h"
#include "kmip-varlink.h"

#define MAX_CALLS 16

/*
 * A fake nvme-keysd-kmip. It answers GetKey after a short delay, so that
 * calls overlap. The key of "name" is "PSK-name". It answers from server
 * 1 when the KMS has two servers.
 *
 * "fail-once" fails the first call with KmsFailed.
 */
struct fake_call {
	char kms[32];
	char name[32];
	uint64_t server;
};

static struct fake {
	sd_event *event;
	struct fake_call calls[MAX_CALLS];
	int nr_calls;
	int in_flight;
	int max_in_flight;
	int in_flight_kms[2];	// for KMS "a" and "b"
	int max_in_flight_kms;
} fake;

// Imports, done by the client.
static struct {
	int nr;
	int expected;		// stop the loop after this many imports
	int fail_left;		// imports to fail before one succeeds
	bool bad_key;
} imports;

static struct kmip_client *client;
static sd_varlink_server *server;

static bool check(bool cond, const char *what)
{
	printf(" - %s [%s]\n", what, cond ? "PASS" : "FAIL");
	return cond;
}

struct pending_reply {
	sd_varlink *link;
	struct fake_call *call;
};

static int kms_index(const char *kms)
{
	return strcmp(kms, "a") ? 1 : 0;
}

static int send_reply(sd_event_source *s, uint64_t usec, void *userdata)
{
	struct pending_reply *pr = userdata;
	struct fake_call *call = pr->call;
	char key[48];

	fake.in_flight--;
	fake.in_flight_kms[kms_index(call->kms)]--;

	if (!strcmp(call->name, "fail-once") &&
	    call == &fake.calls[0])
		sd_varlink_error(pr->link, KMIP_VARLINK_KMS_FAILED, NULL);
	else {
		snprintf(key, sizeof(key), "PSK-%s", call->name);
		sd_varlink_replybo(pr->link,
				   SD_JSON_BUILD_PAIR_STRING("key", key),
				   SD_JSON_BUILD_PAIR_UNSIGNED("server",
					kms_index(call->kms)));
	}

	sd_varlink_unref(pr->link);
	free(pr);
	sd_event_source_disable_unref(s);

	return 0;
}

static int fake_get_key(sd_varlink *link, sd_json_variant *params,
		sd_varlink_method_flags_t flags, void *userdata)
{
	struct pending_reply *pr;
	struct fake_call *call;
	sd_json_variant *v;
	uint64_t now;
	int i;

	if (fake.nr_calls == MAX_CALLS)
		return sd_varlink_error(link, KMIP_VARLINK_KMS_FAILED, NULL);
	call = &fake.calls[fake.nr_calls++];

	v = sd_json_variant_by_key(params, "kms");
	snprintf(call->kms, sizeof(call->kms), "%s",
		 v ? sd_json_variant_string(v) : "");
	v = sd_json_variant_by_key(params, "name");
	snprintf(call->name, sizeof(call->name), "%s",
		 v ? sd_json_variant_string(v) : "");
	v = sd_json_variant_by_key(params, "server");
	call->server = v ? sd_json_variant_unsigned(v) : 99;

	fake.in_flight++;
	if (fake.in_flight > fake.max_in_flight)
		fake.max_in_flight = fake.in_flight;
	i = kms_index(call->kms);
	fake.in_flight_kms[i]++;
	if (fake.in_flight_kms[i] > fake.max_in_flight_kms)
		fake.max_in_flight_kms = fake.in_flight_kms[i];

	pr = calloc(1, sizeof(*pr));
	if (!pr)
		return -ENOMEM;
	pr->link = sd_varlink_ref(link);
	pr->call = call;

	sd_event_now(fake.event, CLOCK_MONOTONIC, &now);

	return sd_event_add_time(fake.event, NULL, CLOCK_MONOTONIC,
				 now + 20000, 0, send_reply, pr);
}

static int test_import(const struct kmip_job *job, const char *encoded,
		void *arg)
{
	char key[48];

	snprintf(key, sizeof(key), "PSK-%s", job->name);
	if (strcmp(encoded, key))
		imports.bad_key = true;

	if (imports.fail_left) {
		imports.fail_left--;
		return -EIO;
	}
	imports.nr++;

	if (imports.nr == imports.expected)
		sd_event_exit(fake.event, 0);

	return 0;
}

/* Load nvme-keysd.conf with KMS "a" (one server) and "b" (two servers). */
static struct keysd_config *load_cfg(void)
{
	static const char text[] =
		"[kmip:a]\nserver = 192.0.2.1\n"
		"[kmip:b]\nserver = 192.0.2.2\nserver = 192.0.2.3\n";
	char path[] = "/tmp/nvme-keysd-client-XXXXXX";
	struct keysd_config *cfg;
	int fd;

	fd = mkstemp(path);
	if (fd < 0 || shr_write_all(fd, text, sizeof(text) - 1)) {
		fprintf(stderr, "cannot write the config\n");
		exit(EXIT_FAILURE);
	}
	close(fd);
	cfg = config_load(path);
	unlink(path);

	return cfg;
}

static void set_job(struct kmip_job *job, const struct keysd_config *cfg,
		const char *kms, const char *name)
{
	memset(job, 0, sizeof(*job));
	job->kms = config_find_kmip(cfg, kms);
	job->source = strdup("test.conf");
	job->subsysnqn = strdup("nqn.test");
	job->name = strdup(name);
}

static void free_jobs(struct kmip_job *jobs, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		free(jobs[i].source);
		free(jobs[i].subsysnqn);
		free(jobs[i].name);
	}
}

/*
 * Run the client on @jobs against the fake helper, until every key is
 * imported or @limit_usec passes.
 */
static void run(const char *address, const struct kmip_job *jobs, size_t n,
		uint64_t limit_usec)
{
	const struct kmip_client_cfg cfg = {
		.address = address,
		.retry_usec = 10000,
		.retry_max_usec = 40000,
		.import = test_import,
	};
	sd_event_source *limit;
	uint64_t now;

	memset(&fake.calls, 0, sizeof(fake.calls));
	fake.nr_calls = 0;
	fake.max_in_flight = 0;
	fake.max_in_flight_kms = 0;
	imports.nr = 0;
	imports.expected = n;
	imports.bad_key = false;

	// A loop cannot run again after it ends: use a new one.
	if (sd_event_new(&fake.event) < 0 ||
	    sd_varlink_server_attach_event(server, fake.event, 0) < 0) {
		fprintf(stderr, "event loop setup failed\n");
		exit(EXIT_FAILURE);
	}

	// A NULL callback ends the loop.
	sd_event_now(fake.event, CLOCK_MONOTONIC, &now);
	if (sd_event_add_time(fake.event, &limit, CLOCK_MONOTONIC,
			      now + limit_usec, 0, NULL, NULL) < 0) {
		fprintf(stderr, "sd_event_add_time failed\n");
		exit(EXIT_FAILURE);
	}

	if (kmip_client_new(fake.event, &cfg, jobs, n, &client) < 0) {
		fprintf(stderr, "kmip_client_new failed\n");
		exit(EXIT_FAILURE);
	}
	sd_event_loop(fake.event);
	kmip_client_free(client);
	client = NULL;
	sd_event_source_disable_unref(limit);
	sd_varlink_server_detach_event(server);
	fake.event = sd_event_unref(fake.event);
}

static bool test_parallel(const char *address,
		const struct keysd_config *cfg)
{
	struct kmip_job jobs[4];
	bool pass = true;
	int i, b_calls = 0;

	printf("test_parallel:\n");

	set_job(&jobs[0], cfg, "a", "k1");
	set_job(&jobs[1], cfg, "a", "k2");
	set_job(&jobs[2], cfg, "b", "k3");
	set_job(&jobs[3], cfg, "b", "k4");
	run(address, jobs, 4, 2000000);

	pass &= check(imports.nr == 4 && !imports.bad_key,
		      "all keys imported");
	pass &= check(fake.max_in_flight_kms == 1,
		      "one call at a time per KMS");
	pass &= check(fake.max_in_flight == 2, "KMSes asked in parallel");

	for (i = 0; i < fake.nr_calls; i++) {
		if (strcmp(fake.calls[i].kms, "b"))
			continue;
		if (b_calls)
			pass &= check(fake.calls[i].server == 1,
				      "next call asks the last server first");
		else
			pass &= check(fake.calls[i].server == 0,
				      "first call asks server 0 first");
		b_calls++;
	}
	free_jobs(jobs, 4);

	return pass;
}

static bool test_retry(const char *address, const struct keysd_config *cfg)
{
	struct kmip_job job;
	bool pass = true;

	printf("test_retry:\n");

	set_job(&job, cfg, "a", "fail-once");
	run(address, &job, 1, 2000000);
	pass &= check(imports.nr == 1 && fake.nr_calls == 2,
		      "KMS error retried");
	free_jobs(&job, 1);

	set_job(&job, cfg, "a", "k1");
	imports.fail_left = 2;
	run(address, &job, 1, 2000000);
	pass &= check(imports.nr == 1 && fake.nr_calls == 3,
		      "import error retried");
	free_jobs(&job, 1);

	set_job(&job, cfg, "a", "k1");
	run("/nonexistent/kmip", &job, 1, 100000);
	pass &= check(imports.nr == 0, "no helper: key stays pending");
	free_jobs(&job, 1);

	return pass;
}

int main(void)
{
	char dir[] = "/tmp/test-kmip-client-XXXXXX", address[108], *abs;
	struct keysd_config *cfg;
	bool pass = true;

	cfg = load_cfg();
	if (!cfg || cfg->nr_kmip != 2 || !mkdtemp(dir) ||
	    sd_varlink_server_new(&server, 0) < 0) {
		fprintf(stderr, "test setup failed\n");
		exit(EXIT_FAILURE);
	}
	// A socket address must be absolute.
	abs = realpath(dir, NULL);
	if (!abs || snprintf(address, sizeof(address), "%s/kmip", abs) >=
	    (int)sizeof(address)) {
		fprintf(stderr, "socket path too long\n");
		exit(EXIT_FAILURE);
	}
	free(abs);

	if (sd_varlink_server_bind_method(server, KMIP_VARLINK_GET_KEY,
					  fake_get_key) < 0 ||
	    sd_varlink_server_listen_address(server, address, 0600) < 0) {
		fprintf(stderr, "fake helper setup failed\n");
		exit(EXIT_FAILURE);
	}

	pass &= test_parallel(address, cfg);
	pass &= test_retry(address, cfg);

	sd_varlink_server_unref(server);
	unlink(address);
	rmdir(dir);
	config_free(cfg);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
