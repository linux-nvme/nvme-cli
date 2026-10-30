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
 * The input is the command (one byte, an index into the table below,
 * or 0xff and a second byte for the commands from index 255 on), the
 * variant (one byte: output format, verbose, controller or namespace
 * device, whether to pass the argument, which option set), the argument
 * (one byte, the value of the option the command names) and then the
 * answers of the device, see ipc_call() in the mock.
 *
 * FUZZ_PLUGINS, a comma-separated list of the first words of commands of
 * the table, e.g. "ocp,micron", has only those commands run: an input of
 * another one is rejected, libFuzzer adds it to no corpus.
 */
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <ccan/array_size/array_size.h>

#include <libnvme.h>

#include "args.h"
#include "fuzz.h"
#include "plugin.h"

/* the fuzz backend of libmock_nvme.c */
void mock_fuzz_input(const uint8_t *data, size_t size);

#define MAX_ARGS 14

/*
 * Commands which do something with what the device returns: print it,
 * size a buffer by it, wait for it. Nothing which writes a file but
 * /dev/null, reads one but /dev/zero, needs a terminal or a value which
 * can't have a default. The seeds select a command by its index: add new
 * commands at the end.
 *
 * A command may name an option which takes the argument byte of the
 * input as its value, 0xff meaning 0xffffffff (all namespaces).
 *
 * A command may have up to four option sets, of which bits 5:4 of the
 * variant select one: fixed values of the options which decide how much
 * data the command transfers, or what it does, rather than fuzzed ones.
 * A set it doesn't have adds no option.
 *
 * A command with pci set sees a controller whose PCI vendor and device ID
 * are the next four bytes of the input, little endian, ahead of the
 * answers of the device: plugins which check them to decide what a drive
 * supports do nothing on any other controller.
 */
/* --fw= the firmware image fw_setup() writes into the test root */
#define FW_IMAGE "fw.img"
#define FW_IMAGE_SIZE (64 * 1024)
static char fw_option[sizeof("--fw=/" FW_IMAGE) + PATH_MAX];

static const struct {
	const char *argv[4];
	const char *arg;
	bool pci;
	const char *opts[4][3];
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
	{ { "inspur", "nvme-vendor-log" } },
	{ { "memblaze", "smart-log-add-x" } },
	{ { "memblaze", "lat-get-feature-x" } },
	{ { "memblaze", "lat-stats-print-x" } },
	{ { "memblaze", "lat-log-print-x" } },
	{ { "micron", "latency-tracking" }, .pci = true },
	{ { "micron", "latency-stats" }, .pci = true },
	{ { "micron", "latency-logs" }, .pci = true },
	{ { "micron", "id-ctrl" }, .pci = true },
	{ { "micron", "cloud-boot-SSD-version" }, .pci = true },
	{ { "ocp", "get-error-injection" }, "--sel" },
	{ { "ocp", "get-latency-monitor" }, "--sel" },
	{ { "ocp", "get-latency-monitor", "--no-uuid" }, "--sel" },
	{ { "ocp", "get-idle-wakeup-time" }, "--sel" },
	{ { "ocp", "get-idle-wakeup-time", "--no-uuid" }, "--sel" },
	{ { "ocp", "get-dssd-power-state-feature", "--all" } },
	{ { "ocp", "get-plp-health-check-interval" }, "--sel" },
	{ { "ocp", "get-dssd-async-event-config" }, "--sel" },
	{ { "ocp", "get-enable-ieee1667-silo" }, "--sel" },
	{ { "ocp", "get-clear-pcie-correctable-errors" }, "--sel" },
	{ { "ocp", "get-telemetry-profile" }, "--sel" },
	{ { "ocp", "eol-plp-failure-mode" }, "--sel" },
	{ { "sndk", "vs-fw-activate-history" }, .pci = true },
	{ { "sndk", "capabilities" }, .pci = true },
	{ { "sfx", "get-bad-block" } },
	{ { "sfx", "get-feature" }, "--feature-id" },
	{ { "transcend", "badblock" } },
	{ { "wdc", "id-ctrl" }, .pci = true },
	{ { "wdc", "get-drive-status" }, .pci = true },
	{ { "wdc", "purge-monitor" }, .pci = true },
	{ { "wdc", "cloud-boot-SSD-version" }, .pci = true },
	{ { "wdc", "cloud-SSD-plugin-version" }, .pci = true },
	{ { "amzn", "id-ctrl" } },
	{ { "dell", "id-ctrl" } },
	{ { "mangoboost", "id-ctrl" } },
	{ { "nvidia", "id-ctrl" } },
	{ { "solidigm", "id-ctrl" } },
	{ { "read", "--data-size=4096" }, "--block-count" },
	{ { "wdc", "vs-smart-add-log" }, .pci = true },
	{ { "wdc", "vs-nand-stats" }, .pci = true },
	{ { "wdc", "vs-fw-activate-history" }, .pci = true },
	{ { "wdc", "log-page-directory" }, .pci = true },
	{ { "wdc", "vs-drive-info" }, .pci = true },
	{ { "wdc", "vs-temperature-stats" }, .pci = true },
	{ { "wdc", "capabilities" }, .pci = true },
	{ { "wdc", "vs-pcie-stats" }, .pci = true },
	{ { "wdc", "get-latency-monitor-log" }, .pci = true },
	{ { "wdc", "get-error-recovery-log" }, .pci = true },
	{ { "wdc", "get-dev-capabilities-log" }, .pci = true },
	{ { "wdc", "get-unsupported-reqs-log" }, .pci = true },
	{ { "wdc", "vs-cloud-log" }, .pci = true },
	{ { "wdc", "vs-hw-rev-log" }, .pci = true },
	{ { "wdc", "vs-device-waf" }, .pci = true },
	{ { "wdc", "cu-smart-log" }, .pci = true },
	{ { "micron", "vs-temperature-stats" }, .pci = true },
	{ { "micron", "vs-pcie-stats" }, .pci = true },
	{ { "micron", "vs-nand-stats" }, .pci = true },
	{ { "micron", "vs-smart-ext-log" }, .pci = true },
	{ { "micron", "vs-drive-info" }, .pci = true },
	{ { "micron", "log-page-directory" }, .pci = true },
	{ { "micron", "vs-fw-activate-history" }, .pci = true },
	{ { "micron", "vs-smart-add-log" }, .pci = true },
	{ { "micron", "vs-device-waf" }, .pci = true },
	{ { "micron", "smart-log" }, .pci = true },
	{ { "ymtc", "smart-log-add" }, .pci = true },
	{ { "sfx", "status" }, .pci = true },
	{ { "read", "--data=/dev/null", "--data-size=65536" }, "--block-count",
	  .opts = { {}, { "--metadata-size=4096", "--metadata=/dev/null" },
		    { "--block-size=4096" } } },
	{ { "write", "--data=/dev/zero", "--data-size=65536" }, "--block-count",
	  .opts = { {}, { "--metadata-size=4096", "--metadata=/dev/zero" },
		    { "--block-size=4096" } } },
	{ { "compare", "--data=/dev/zero", "--data-size=65536" },
	  "--block-count",
	  .opts = { {}, { "--metadata-size=4096", "--metadata=/dev/zero" },
		    { "--block-size=4096" } } },
	{ { "admin-passthru", "--data-len=4096", "--input-file=/dev/null",
	    "--metadata=/dev/null" }, "--opcode",
	  .opts = { {}, { "--read", "--metadata-len=64" }, { "--raw-binary" },
		    { "--write", "--metadata-len=64" } } },
	{ { "io-passthru", "--data-len=4096", "--input-file=/dev/null",
	    "--metadata=/dev/null" }, "--opcode",
	  .opts = { {}, { "--read", "--metadata-len=64" }, { "--raw-binary" },
		    { "--write", "--metadata-len=64" } } },
	{ { "format", "--force" }, "--lbaf",
	  .opts = { { "--namespace-id=1" },
		    { "--namespace-id=1", "--block-size=4096" },
		    { "--namespace-id=1", "--pi=1", "--ms=1" },
		    { "--namespace-id=1", "--reset" } } },
	{ { "sanitize", "--wait" }, "--sanact",
	  .opts = { { "--sanact=start-block-erase" },
		    { "--sanact=start-crypto-erase" },
		    { "--sanact=start-overwrite" },
		    { "--sanact=exit-media-verification" } } },
	{ { "sanitize-ns" }, "--namespace-id",
	  .opts = { { "--sanact=start-crypto-erase" },
		    { "--sanact=exit-media-verification" },
		    { "--sanact=exit-failure" } } },
	{ { "device-self-test", "--wait" }, "--self-test-code",
	  .opts = { { "--self-test-code=1" }, { "--self-test-code=2" } } },
	{ { "fw", "download", fw_option }, "--offset",
	  .opts = { {}, { "--xfer=4096" }, { "--stream", "--progress" },
		    { "--xfer=16384", "--ignore-ovr" } } },
	{ { "rpmb", "read-data", "--msgfile=/dev/null" }, "--blocks",
	  .opts = { {}, { "--address=8", "--target=1" } } },
	{ { "rpmb", "write-data", "--msg=fuzz", "--key=fuzz" }, "--blocks",
	  .opts = { {}, { "--address=8", "--target=1" } } },
	{ { "rpmb", "write-config", "--msg=fuzz", "--key=fuzz" } },
	{ { "rpmb", "program-key", "--key=fuzz" }, "--target" },
	/* from index 255 on, an input starts with 0xff and the index - 255 */
	{ { "dsm", "--ad", "--slbs=0,8", "--blocks=8,8" }, "--namespace-id",
	  .opts = { {}, { "--idw", "--idr" } } },
	{ { "copy", "--sdlba=0", "--slbs=0,8", "--blocks=7,7" }, "--format",
	  .opts = { {}, { "--snsids=1,1" },
		    { "--prinfow=8", "--ref-tag=1",
		      "--expected-ref-tags=1,2" } } },
	{ { "flush" }, "--namespace-id" },
	{ { "write-zeroes", "--start-block=0", "--block-count=7" }, "--prinfo",
	  .opts = { {}, { "--deac" }, { "--namespace-zeroes" } } },
	{ { "write-uncor", "--block-count=7" }, "--dir-type" },
	{ { "verify", "--block-count=7" }, "--prinfo" },
	{ { "capacity-mgmt" }, "--operation",
	  .opts = { {}, { "--element-id=1", "--cap-lower=1" } } },
	{ { "virt-mgmt", "--cntlid=1", "--nr=2" }, "--act",
	  .opts = { {}, { "--rt=1" } } },
	{ { "set-feature", "--value=1" }, "--feature-id",
	  .opts = { {}, { "--data-len=4096", "--data=/dev/zero" },
		    { "--save" } } },
	{ { "lockdown", "--ofi=6" }, "--scp",
	  .opts = { {}, { "--prhbt=1" }, { "--ifc=1" } } },
	{ { "security", "send", "--file=/dev/zero", "--tl=512" }, "--secp" },
	{ { "dir", "send", "--input-file=/dev/zero" }, "--dir-oper",
	  .opts = { { "--dir-type=0", "--target-dir=1", "--endir=1" },
		    { "--dir-type=1", "--data-len=4096" } } },
	{ { "io-mgmt", "send", "--data=/dev/zero", "--data-len=4096" },
	  "--mo" },
	{ { "ns", "create", "--nsze=0x100000", "--ncap=0x100000" }, "--flbas",
	  .opts = { {}, { "--block-size=4096" }, { "--csi=2", "--azr" },
		    { "--nphndls=2", "--phndls=1,2" } } },
	{ { "ns", "delete" }, "--namespace-id" },
	{ { "ns", "attach", "--controllers=1,2" }, "--namespace-id" },
	{ { "ns", "detach", "--controllers=1,2" }, "--namespace-id" },
	{ { "resv", "acquire", "--crkey=1" }, "--rtype",
	  .opts = { {}, { "--racqa=1", "--prkey=2" } } },
	{ { "resv", "register", "--nrkey=1" }, "--rrega",
	  .opts = { {}, { "--cptpl=2" } } },
	{ { "resv", "release", "--crkey=1" }, "--rtype",
	  .opts = { {}, { "--rrela=1" } } },
	{ { "lm", "create-cdq", "--size=1024", "--consent" }, "--queue-type" },
	{ { "lm", "delete-cdq" }, "--cdqid" },
	{ { "lm", "set-cdq", "--hp=1", "--tpt=2" }, "--cdqid" },
	{ { "lm", "track-send" }, "--cdqid",
	  .opts = { { "--start" }, { "--stop" }, { "--sel=1", "--mos=1" } } },
	{ { "lm", "migration-send", "--input-file=/dev/zero", "--numd=1023" },
	  "--sel" },
	{ { "fdp", "update", "--pids=1,2" }, "--namespace-id" },
	{ { "fdp", "set-events", "--event-types=0,1", "--enable" },
	  "--placement-handle" },
	{ { "zns", "reset-zone" }, "--start-lba",
	  .opts = { {}, { "--select-all" } } },
	{ { "zns", "close-zone" }, "--start-lba",
	  .opts = { {}, { "--select-all" } } },
	{ { "zns", "finish-zone" }, "--start-lba",
	  .opts = { {}, { "--select-all" } } },
	{ { "zns", "open-zone" }, "--start-lba",
	  .opts = { {}, { "--zrwaa" }, { "--select-all" } } },
	{ { "zns", "offline-zone" }, "--start-lba",
	  .opts = { {}, { "--select-all" } } },
	{ { "zns", "set-zone-desc", "--data=/dev/zero" }, "--start-lba",
	  .opts = { {}, { "--zrwaa" } } },
	{ { "zns", "zrwa-flush-zone" }, "--lba" },
	{ { "zns", "zone-mgmt-send", "--data=/dev/zero" }, "--zsa",
	  .opts = { {}, { "--data-len=4096" }, { "--select-all" },
		    { "--zsaso" } } },
	{ { "zns", "zone-append", "--data=/dev/zero", "--data-size=16384" },
	  "--zslba",
	  .opts = { {}, { "--metadata-size=64", "--metadata=/dev/zero" },
		    { "--prinfo=8", "--piremap" } } },
};

#define NR_COMMANDS ARRAY_SIZE(commands)

/* The first byte of an input of a command from index 255 on */
#define EXTENDED_INDEX 0xff

static struct nvme_args defaults;

/* The commands an input may run, see FUZZ_PLUGINS */
static bool selected[NR_COMMANDS];

static void select_commands(void)
{
	const char *env = getenv("FUZZ_PLUGINS");
	char *list, *name, *save;
	size_t i, names = 0;
	bool found;

	if (!env) {
		for (i = 0; i < NR_COMMANDS; i++)
			selected[i] = true;
		return;
	}
	list = strdup(env);
	if (!list)
		abort();
	for (name = strtok_r(list, ",", &save); name;
	     name = strtok_r(NULL, ",", &save)) {
		names++;
		found = false;
		for (i = 0; i < NR_COMMANDS; i++) {
			if (!strcmp(commands[i].argv[0], name))
				selected[i] = found = true;
		}
		if (!found) {
			fprintf(stderr, "FUZZ_PLUGINS=%s: no command of %s\n",
				env, name);
			exit(EXIT_FAILURE);
		}
	}
	if (!names) {
		fprintf(stderr, "FUZZ_PLUGINS=%s: names no command\n", env);
		exit(EXIT_FAILURE);
	}
	free(list);
}

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

/*
 * The mock answers a run with 1 MiB of data at most, so a larger buffer
 * only ever holds zeros. Fail the allocations of a length the device
 * claims early, as nvme-cli allocates its buffers with libnvme: clearing
 * gigabytes takes long, and under valgrind its shadow memory of them
 * exceeds the address space limit below. The executable's definitions
 * take the place of the libnvme ones.
 */
#define FUZZ_MAX_ALLOC	(64UL << 20)

static void *real(const char *name)
{
	void *fn = dlsym(RTLD_NEXT, name);

	if (!fn)
		abort();
	return fn;
}

void *libnvme_alloc(size_t len)
{
	static void *(*fn)(size_t);

	if (len > FUZZ_MAX_ALLOC) {
		errno = ENOMEM;
		return NULL;
	}
	if (!fn)
		fn = real("libnvme_alloc");
	return fn(len);
}

void *libnvme_realloc(void *p, size_t len)
{
	static void *(*fn)(void *, size_t);

	if (len > FUZZ_MAX_ALLOC) {
		errno = ENOMEM;
		return NULL;
	}
	if (!fn)
		fn = real("libnvme_realloc");
	return fn(p, len);
}

void *libnvme_alloc_huge(size_t len, struct libnvme_mem_huge *mh)
{
	static void *(*fn)(size_t, struct libnvme_mem_huge *);

	if (len > FUZZ_MAX_ALLOC) {
		memset(mh, 0, sizeof(*mh));
		errno = ENOMEM;
		return NULL;
	}
	if (!fn)
		fn = real("libnvme_alloc_huge");
	return fn(len, mh);
}

/*
 * The test root of a command with pci set: a sysfs with the controller
 * nvme0, whose PCI IDs pci_sysfs() writes. It is in the current
 * directory: a job which crashes leaves it behind, and scripts/build.sh
 * removes them from the directory it runs the jobs in.
 */
#define PCI_ROOT_TEMPLATE "fuzz-device-XXXXXX"
static char pci_root[PATH_MAX];
static char pci_dir[sizeof(pci_root) + 64];
static char pci_option[sizeof(pci_root) + 32];
static const char *const pci_attrs[] = {
	"vendor", "device", "subsystem_vendor", "subsystem_device",
};

/* Other attributes of the PCI device which commands read */
#define AER_COUNTERS(n) n " 0\n"
static const struct {
	const char *name;
	const char *value;
} pci_fixed_attrs[] = {
	{ "current_link_speed", "16.0 GT/s PCIe\n" },
	{ "current_link_width", "4\n" },
	{ "numa_node", "0\n" },
	{ "aer_dev_correctable",
	  AER_COUNTERS("RxErr") AER_COUNTERS("BadTLP")
	  AER_COUNTERS("BadDLLP") AER_COUNTERS("Rollover")
	  AER_COUNTERS("Timeout") AER_COUNTERS("NonFatalErr")
	  AER_COUNTERS("CorrIntErr") AER_COUNTERS("HeaderOF")
	  "TOTAL_ERR_COR 0\n" },
	{ "aer_dev_nonfatal",
	  AER_COUNTERS("Undefined") AER_COUNTERS("DLP")
	  AER_COUNTERS("SDES") AER_COUNTERS("TLP") AER_COUNTERS("FCP")
	  AER_COUNTERS("CmpltTO") AER_COUNTERS("CmpltAbrt")
	  AER_COUNTERS("UnxCmplt") AER_COUNTERS("RxOF")
	  AER_COUNTERS("MalfTLP") AER_COUNTERS("ECRC")
	  AER_COUNTERS("UnsupReq") AER_COUNTERS("ACSViol")
	  AER_COUNTERS("UncorrIntErr") AER_COUNTERS("BlockedTLP")
	  AER_COUNTERS("AtomicOpBlocked") AER_COUNTERS("TLPBlockedErr")
	  AER_COUNTERS("PoisonTLPBlocked")
	  "TOTAL_ERR_NONFATAL 0\n" },
	{ "aer_dev_fatal",
	  AER_COUNTERS("Undefined") AER_COUNTERS("DLP")
	  AER_COUNTERS("SDES") AER_COUNTERS("TLP") AER_COUNTERS("FCP")
	  AER_COUNTERS("CmpltTO") AER_COUNTERS("CmpltAbrt")
	  AER_COUNTERS("UnxCmplt") AER_COUNTERS("RxOF")
	  AER_COUNTERS("MalfTLP") AER_COUNTERS("ECRC")
	  AER_COUNTERS("UnsupReq") AER_COUNTERS("ACSViol")
	  AER_COUNTERS("UncorrIntErr") AER_COUNTERS("BlockedTLP")
	  AER_COUNTERS("AtomicOpBlocked") AER_COUNTERS("TLPBlockedErr")
	  AER_COUNTERS("PoisonTLPBlocked")
	  "TOTAL_ERR_FATAL 0\n" },
};

static void pci_cleanup(void)
{
	char path[sizeof(pci_dir) + 32];
	static const char *const dirs[] = { "/sys/class/nvme/nvme0/device",
		"/sys/class/nvme/nvme0", "/sys/class/nvme",
		"/sys/class/nvme-subsystem", "/sys/class", "/sys", "" };
	size_t i;

	for (i = 0; i < ARRAY_SIZE(pci_attrs); i++) {
		snprintf(path, sizeof(path), "%s/%s", pci_dir, pci_attrs[i]);
		unlink(path);
	}
	for (i = 0; i < ARRAY_SIZE(pci_fixed_attrs); i++) {
		snprintf(path, sizeof(path), "%s/%s", pci_dir,
			 pci_fixed_attrs[i].name);
		unlink(path);
	}
	snprintf(path, sizeof(path), "%s/" FW_IMAGE, pci_root);
	unlink(path);
	for (i = 0; i < ARRAY_SIZE(dirs); i++) {
		snprintf(path, sizeof(path), "%s%s", pci_root, dirs[i]);
		rmdir(path);
	}
}

static void pci_setup(void)
{
	/* without nvme-subsystem, a topology scan fails */
	static const char *const dirs[] = { "/sys", "/sys/class",
		"/sys/class/nvme-subsystem", "/sys/class/nvme",
		"/sys/class/nvme/nvme0", "/sys/class/nvme/nvme0/device" };
	char path[sizeof(pci_dir)];
	size_t i;

	if (!getcwd(pci_root, sizeof(pci_root) - sizeof(PCI_ROOT_TEMPLATE) - 1))
		abort();
	strcat(pci_root, "/" PCI_ROOT_TEMPLATE);
	if (!mkdtemp(pci_root))
		abort();
	atexit(pci_cleanup);
	for (i = 0; i < ARRAY_SIZE(dirs); i++) {
		snprintf(path, sizeof(path), "%s%s", pci_root, dirs[i]);
		if (mkdir(path, 0700))
			abort();
	}
	snprintf(pci_dir, sizeof(pci_dir), "%s", path);
	snprintf(pci_option, sizeof(pci_option), "test-sysfs-dir=%s",
		 pci_root);
	for (i = 0; i < ARRAY_SIZE(pci_fixed_attrs); i++) {
		char attr[sizeof(pci_dir) + 32];
		FILE *f;

		snprintf(attr, sizeof(attr), "%s/%s", pci_dir,
			 pci_fixed_attrs[i].name);
		f = fopen(attr, "w");
		if (!f)
			abort();
		fputs(pci_fixed_attrs[i].value, f);
		fclose(f);
	}
}

/*
 * The firmware image fw download sends, in the test root: of a size
 * which takes several transfers. What it holds doesn't matter, the mock
 * answers a write without looking at its data.
 */
static void fw_setup(void)
{
	static const char chunk[4096];
	FILE *f;
	size_t i;

	snprintf(fw_option, sizeof(fw_option), "--fw=%s/" FW_IMAGE,
		 pci_root);
	f = fopen(fw_option + strlen("--fw="), "w");
	if (!f)
		abort();
	for (i = 0; i < FW_IMAGE_SIZE / sizeof(chunk); i++)
		if (fwrite(chunk, sizeof(chunk), 1, f) != 1)
			abort();
	if (fclose(f))
		abort();
}

/* Give nvme0 of the test root the PCI IDs at @data, vendor and device */
static void pci_sysfs(const uint8_t *data)
{
	char path[sizeof(pci_dir) + 32];
	size_t i;

	for (i = 0; i < ARRAY_SIZE(pci_attrs); i++) {
		/* the subsystem IDs are the same as the device's */
		unsigned int id = data[i % 2 * 2] | data[i % 2 * 2 + 1] << 8;
		FILE *f;

		snprintf(path, sizeof(path), "%s/%s", pci_dir, pci_attrs[i]);
		f = fopen(path, "w");
		if (!f)
			abort();
		fprintf(f, "0x%04x\n", id);
		fclose(f);
	}
}

static bool running;

/*
 * nvme-cli waits a second between the polls of a device which sanitizes
 * or tests itself, and the mock answers them right away: don't wait. The
 * polls end when the device says so, or the data limit of the mock is
 * reached. libFuzzer's own sleep() calls still sleep.
 */
unsigned int sleep(unsigned int seconds)
{
	static unsigned int (*fn)(unsigned int);

	if (running)
		return 0;
	if (!fn)
		fn = real("sleep");
	return fn(seconds);
}

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
	select_commands();
	pci_setup();
	fw_setup();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static char args[MAX_ARGS][PATH_MAX + 64];
	const char *const *opts;
	char *argv[MAX_ARGS + 1];
	unsigned int idx;
	char arg[64];
	uint8_t variant;
	int argc = 0, i;
	bool pci;

	if (size && data[0] == EXTENDED_INDEX) {
		if (size < 2)
			return 0;
		idx = EXTENDED_INDEX + data[1];
		data++;
		size--;
	} else {
		idx = size ? data[0] : 0;
	}
	/* No modulo: a new command must not change what an input does */
	if (size < 3 || idx >= NR_COMMANDS)
		return 0;
	if (!selected[idx])
		return -1;
	pci = commands[idx].pci;
	if (pci && size < 7)
		return 0;

	argv[argc++] = "nvme";
	/*
	 * Not the sysfs, /proc and /etc of the host: run as root, nvme-cli
	 * would map the registers of a real controller, and an input would
	 * do something else on a machine with one.
	 */
	argv[argc++] = "--set-options";
	if (pci) {
		pci_sysfs(data + 3);
		argv[argc++] = pci_option;
	} else {
		argv[argc++] = "test-sysfs-dir=/nonexistent/fuzz-device";
	}
	for (i = 0; i < 4 && commands[idx].argv[i]; i++)
		argv[argc++] = (char *)commands[idx].argv[i];

	variant = data[1];
	argv[argc++] = variant & 4 ? "/dev/nvme0n1" : "/dev/nvme0";
	if (variant & 1)
		argv[argc++] = "--output-format=json";
	if (variant & 2)
		argv[argc++] = "--verbose";
	if (variant & 8 && commands[idx].arg) {
		snprintf(arg, sizeof(arg), "%s=%u", commands[idx].arg,
			 data[2] == 0xff ? 0xffffffffU : data[2]);
		argv[argc++] = arg;
	}
	opts = commands[idx].opts[variant >> 4 & 3];
	for (i = 0; i < 3 && opts[i]; i++)
		argv[argc++] = (char *)opts[i];
	argv[argc] = NULL;

	/* nvme-cli splits list values in place, as argv is writable */
	for (i = 0; i < argc; i++) {
		snprintf(args[i], sizeof(args[i]), "%s", argv[i]);
		argv[i] = args[i];
	}

	nvme_args = defaults;
	if (pci)
		mock_fuzz_input(data + 7, size - 7);
	else
		mock_fuzz_input(data + 3, size - 3);
	running = true;
	nvme_main(argc, argv);
	running = false;
	mock_fuzz_input(NULL, 0);

	return 0;
}
