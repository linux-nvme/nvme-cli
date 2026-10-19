// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * Fuzz what nvme-cli does with the data a device returns: run a command
 * which reads and prints something against a mocked controller whose
 * every answer comes from the fuzz input. The device mock is
 * tests/cli/libmock_nvme.c built with MOCK_FUZZ, linked into this
 * program, so its open()/ioctl() replace the libc ones.
 *
 * The input is the command (one byte, an index into the table below),
 * the variant (one byte: output format, verbose, controller or namespace
 * device, whether to pass the argument), the argument (one byte, the
 * value of the option the command names) and then the answers of the
 * device, see ipc_call() in the mock.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include <ccan/array_size/array_size.h>

#include "args.h"
#include "fuzz.h"
#include "plugin.h"

/* the fuzz backend of libmock_nvme.c */
void mock_fuzz_input(const uint8_t *data, size_t size);

#define MAX_ARGS 12

/*
 * Commands which read from the device and print what they got. Nothing
 * which writes a file but /dev/null, waits or loops on the device, or
 * needs a value which can't have a default. The seeds select a command
 * by its index: add new commands at the end.
 *
 * A command may name an option which takes the argument byte of the
 * input as its value, 0xff meaning 0xffffffff (all namespaces).
 */
static const struct {
	const char *argv[4];
	const char *arg;
} commands[] = {
	{ { "id", "ctrl" } },
	{ { "id", "ns" }, "--namespace-id" },
	{ { "id", "ns-granularity" } },
	{ { "id", "ns-list" } },
	{ { "id", "ctrl-list" } },
	{ { "id", "nvm-ctrl" } },
	{ { "id", "nvm-ns" }, "--namespace-id" },
	{ { "id", "primary-ctrl-caps" } },
	{ { "id", "secondary-ctrl-list" } },
	{ { "id", "ns-ind" } },
	{ { "id", "ns-descs" }, "--namespace-id" },
	{ { "id", "nvmset" } },
	{ { "id", "uuid" } },
	{ { "id", "iocs" } },
	{ { "id", "domain" } },
	{ { "id", "endgrp-list" } },
	{ { "log", "supported-pages" } },
	{ { "log", "smart" }, "--namespace-id" },
	{ { "log", "ana" } },
	{ { "log", "fw" } },
	{ { "log", "endurance" } },
	{ { "log", "effects" } },
	{ { "log", "error" }, "--log-entries" },
	{ { "log", "changed-ns-list" } },
	{ { "log", "changed-alloc-ns-list" } },
	{ { "log", "predictable-lat" } },
	{ { "log", "pred-lat-event-agg" } },
	{ { "log", "persistent-event" }, "--action" },
	{ { "log", "endurance-event-agg" } },
	{ { "log", "lba-status" } },
	{ { "log", "resv-notif" } },
	{ { "log", "phy-rx-eom" } },
	{ { "log", "self-test" }, "--dst-entries" },
	{ { "log", "fid-support-effects" } },
	{ { "log", "mi-cmd-support-effects" } },
	{ { "log", "media-unit-stat" } },
	{ { "log", "supported-cap-config" } },
	{ { "log", "mgmt-addr-list" } },
	{ { "log", "rotational-media-info" } },
	{ { "log", "dispersed-ns-participating-nss" } },
	{ { "log", "reachability-groups" } },
	{ { "log", "reachability-associations" } },
	{ { "log", "host-discovery" } },
	{ { "log", "ave-discovery" } },
	{ { "log", "pull-model-ddc-req" } },
	{ { "log", "power-measurement" } },
	{ { "log", "sanitize" } },
	{ { "get-feature" }, "--feature-id" },
	{ { "zns", "id-ctrl" } },
	{ { "zns", "id-ns" } },
	{ { "zns", "changed-zone-list" } },
	{ { "fdp", "configs" }, "--endgrp-id" },
	{ { "fdp", "usage" } },
	{ { "fdp", "stats" } },
	{ { "fdp", "events" } },
	{ { "fdp", "status" } },
	{ { "ocp", "smart-add-log" } },
	{ { "ocp", "latency-monitor-log" } },
	{ { "ocp", "fw-activate-history" } },
	{ { "ocp", "unsupported-reqs-log" } },
	{ { "ocp", "error-recovery-log" } },
	{ { "ocp", "device-capability-log" } },
	{ { "ocp", "tcg-configuration-log" } },
	{ { "ocp", "hardware-component-log" } },
	{ { "ocp", "persistent-event-log" } },
	{ { "solidigm", "smart-log-add" } },
	{ { "solidigm", "vs-smart-add-log" } },
	{ { "solidigm", "garbage-collect-log" } },
	{ { "solidigm", "market-log" } },
	{ { "solidigm", "latency-tracking-log" } },
	{ { "solidigm", "vs-fw-activate-history" } },
	{ { "solidigm", "log-page-directory" } },
	{ { "solidigm", "temp-stats" } },
	{ { "solidigm", "vs-drive-info" } },
	{ { "wdc", "vs-smart-add-log" } },
	{ { "wdc", "vs-nand-stats" } },
	{ { "wdc", "vs-fw-activate-history" } },
	{ { "wdc", "log-page-directory" } },
	{ { "wdc", "vs-drive-info" } },
	{ { "wdc", "vs-temperature-stats" } },
	{ { "wdc", "capabilities" } },
	{ { "wdc", "vs-pcie-stats" } },
	{ { "wdc", "get-latency-monitor-log" } },
	{ { "wdc", "get-error-recovery-log" } },
	{ { "wdc", "get-dev-capabilities-log" } },
	{ { "wdc", "get-unsupported-reqs-log" } },
	{ { "wdc", "vs-cloud-log" } },
	{ { "wdc", "vs-hw-rev-log" } },
	{ { "wdc", "vs-device-waf" } },
	{ { "wdc", "cu-smart-log" } },
	{ { "micron", "vs-temperature-stats" } },
	{ { "micron", "vs-pcie-stats" } },
	{ { "micron", "vs-nand-stats" } },
	{ { "micron", "vs-smart-ext-log" } },
	{ { "micron", "vs-drive-info" } },
	{ { "micron", "log-page-directory" } },
	{ { "micron", "vs-fw-activate-history" } },
	{ { "micron", "vs-smart-add-log" } },
	{ { "micron", "vs-device-waf" } },
	{ { "micron", "smart-log" } },
	{ { "intel", "id-ctrl" } },
	{ { "intel", "lat-stats" } },
	{ { "intel", "market-name" } },
	{ { "intel", "smart-log-add" } },
	{ { "intel", "temp-stats" } },
	{ { "seagate", "vs-temperature-stats" } },
	{ { "seagate", "vs-log-page-sup" } },
	{ { "seagate", "vs-smart-add-log" } },
	{ { "seagate", "vs-pcie-stats" } },
	{ { "seagate", "vs-fw-activate-history" } },
	{ { "memblaze", "smart-log-add" } },
	{ { "memblaze", "get-pm-status" } },
	{ { "sfx", "smart-log-add" } },
	{ { "sfx", "lat-stats" } },
	{ { "sfx", "query-cap" } },
	{ { "ibm", "crit-log" } },
	{ { "ibm", "vpd" } },
	{ { "ibm", "persist-event-log" } },
	{ { "amzn", "stats" } },
	{ { "dapustor", "smart-log-add" } },
	{ { "dera", "smart-log-add" } },
	{ { "huawei", "id-ctrl" } },
	{ { "shannon", "smart-log-add" } },
	{ { "ssstc", "smart-log-add" } },
	{ { "toshiba", "vs-smart-add-log" } },
	{ { "transcend", "healthvalue" } },
	{ { "virtium", "show-identify" } },
	{ { "ymtc", "smart-log-add" } },
	{ { "resv", "report" } },
	{ { "id", "ns-lba-format" }, "--lba-format-index" },
	{ { "id", "nvm-ns-lba-format" }, "--lba-format-index" },
	{ { "log", "telemetry", "--output-file=/dev/null" }, "--data-area" },
	{ { "log", "boot-part", "--output-file=/dev/null" }, "--lsp" },
	{ { "get-log", "--log-len=4096" }, "--log-id" },
	{ { "get-feature", "--sel=3" }, "--feature-id" },
	{ { "get-lba-status", "--max-dw=1024" }, "--action" },
	{ { "get-reg" }, "--offset" },
	{ { "get-property" }, "--offset" },
	{ { "show-regs" } },
	{ { "feat", "arbitration" }, "--sel" },
	{ { "feat", "power-mgmt" }, "--sel" },
	{ { "feat", "temp-thresh" }, "--sel" },
	{ { "feat", "volatile-wc" }, "--sel" },
	{ { "feat", "num-queues" }, "--sel" },
	{ { "feat", "timestamp" }, "--sel" },
	{ { "feat", "hctm" }, "--sel" },
	{ { "feat", "host-behavior-support" }, "--sel" },
	{ { "feat", "perf-characteristics" }, "--sel" },
	{ { "feat", "power-limit" }, "--sel" },
	{ { "feat", "power-thresh" }, "--sel" },
	{ { "feat", "power-meas" }, "--sel" },
	{ { "feat", "err-recovery" }, "--sel" },
	{ { "feat", "lba-range-type" }, "--sel" },
	{ { "feat", "int-coalesce" }, "--sel" },
	{ { "feat", "int-vector-config" }, "--sel" },
	{ { "feat", "write-atom-normal" }, "--sel" },
	{ { "feat", "async-event-conf" }, "--sel" },
	{ { "feat", "keep-alive-timer" }, "--sel" },
	{ { "fdp", "feature" }, "--endgrp-id" },
	{ { "zns", "report-zones" }, "--descs" },
	{ { "zns", "report-zones", "--extended" }, "--descs" },
	{ { "zns", "zone-mgmt-recv", "--data-len=4096" }, "--zra" },
	{ { "sed", "discover" } },
	{ { "rpmb", "info" } },
	{ { "rpmb", "read-counter" }, "--target" },
	{ { "rpmb", "read-config", "--msgfile=/dev/null" } },
	{ { "lm", "get-cdq" }, "--cdqid" },
	{ { "lm", "migration-recv", "--output-file=/dev/null" }, "--sel" },
	{ { "dir", "receive", "--dir-type=0" }, "--dir-oper" },
	{ { "dir", "receive", "--dir-type=1" }, "--dir-oper" },
	{ { "io-mgmt", "recv", "--data-len=4096" }, "--mo" },
	{ { "nvme-mi", "recv", "--data-len=4096" }, "--opcode" },
	{ { "security", "recv", "--size=4096" }, "--secp" },
	{ { "fw", "commit" }, "--action" },
	{ { "ns", "get-id" } },
};

#define NR_COMMANDS ARRAY_SIZE(commands)

static struct nvme_args defaults;

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__ 1
#endif
#endif

#ifdef __SANITIZE_ADDRESS__
const char *__asan_default_options(void);

/*
 * nvme-cli allocates what a log length from the device says. Have ASan
 * fail a gigabyte allocation rather than abort, whichever driver runs
 * the target. ASAN_OPTIONS overrides it.
 */
const char *__asan_default_options(void)
{
	return "allocator_may_return_null=1:max_allocation_size_mb=1024";
}
#endif

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
#ifndef __SANITIZE_ADDRESS__
	/*
	 * nvme-cli allocates what a log length from the device says. Let a
	 * gigabyte allocation fail instead of spending the time on clearing
	 * it. ASan reserves terabytes of address space, so not with ASan.
	 */
	struct rlimit rl = { 1024UL << 20, 1024UL << 20 };

	setrlimit(RLIMIT_AS, &rl);
#endif
	(void)argc;
	(void)argv;
	defaults = nvme_args;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *argv[MAX_ARGS + 1];
	char arg[64];
	uint8_t variant;
	int argc = 0, i;

	/* No modulo: a new command must not change what an input does */
	if (size < 3 || data[0] >= NR_COMMANDS)
		return 0;

	argv[argc++] = "nvme";
	for (i = 0; i < 4 && commands[data[0]].argv[i]; i++)
		argv[argc++] = (char *)commands[data[0]].argv[i];

	variant = data[1];
	argv[argc++] = variant & 4 ? "/dev/nvme0n1" : "/dev/nvme0";
	if (variant & 1)
		argv[argc++] = "--output-format=json";
	if (variant & 2)
		argv[argc++] = "--verbose";
	if (variant & 8 && commands[data[0]].arg) {
		snprintf(arg, sizeof(arg), "%s=%u", commands[data[0]].arg,
			 data[2] == 0xff ? 0xffffffffU : data[2]);
		argv[argc++] = arg;
	}
	argv[argc] = NULL;

	nvme_args = defaults;
	mock_fuzz_input(data + 3, size - 3);
	nvme_main(argc, argv);
	mock_fuzz_input(NULL, 0);

	return 0;
}
