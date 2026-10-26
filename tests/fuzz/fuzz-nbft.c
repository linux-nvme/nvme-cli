// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * Fuzz what nvme nbft show does with an NVMe Boot Firmware Table, the
 * ACPI table the firmware of a host which boots over NVMe-oF leaves in
 * /sys/firmware/acpi/tables: libnvme parses it, nvme-cli prints it.
 *
 * The input is the variant (one byte, see below) and then the table,
 * which the target writes as the only NBFT file of a directory of its
 * own, which --nbft-path names. libnvme refuses a table whose bytes
 * don't sum to 0: unless the variant says otherwise, the target sets the
 * checksum byte of the header so that they do, as nearly every mutation
 * would fail the check else.
 */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>

#include "args.h"
#include "fuzz.h"
#include "plugin.h"

/* The bits of the variant byte */
#define VARIANT_JSON		0x01
#define VARIANT_VERBOSE		0x02
#define VARIANT_SUBSYSTEM	0x04
#define VARIANT_DISCOVERY	0x08
#define VARIANT_HFI		0x10
#define VARIANT_RAW_CHECKSUM	0x80

/* The offset of the checksum in the header of an ACPI table */
#define NBFT_CHECKSUM_OFFSET	9

#define NBFT_DIR_TEMPLATE "fuzz-nbft-XXXXXX"

static struct nvme_args defaults;
static char dir[PATH_MAX];
static char file[sizeof(dir) + 8];
static char path_option[sizeof(dir) + 16];

static void cleanup(void)
{
	unlink(file);
	rmdir(dir);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	defaults = nvme_args;
	if (!getcwd(dir, sizeof(dir) - sizeof(NBFT_DIR_TEMPLATE) - 1))
		abort();
	strcat(dir, "/" NBFT_DIR_TEMPLATE);
	if (!mkdtemp(dir))
		abort();
	atexit(cleanup);
	snprintf(file, sizeof(file), "%s/NBFT", dir);
	snprintf(path_option, sizeof(path_option), "--nbft-path=%s", dir);
	return 0;
}

static bool write_table(const uint8_t *data, size_t size, bool fix_checksum)
{
	uint8_t sum = 0;
	uint8_t *table;
	size_t i;
	FILE *f;

	table = malloc(size ? size : 1);
	if (!table)
		return false;
	memcpy(table, data, size);
	if (fix_checksum && size > NBFT_CHECKSUM_OFFSET) {
		table[NBFT_CHECKSUM_OFFSET] = 0;
		for (i = 0; i < size; i++)
			sum += table[i];
		table[NBFT_CHECKSUM_OFFSET] = -sum;
	}

	f = fopen(file, "wb");
	if (f) {
		if (size)
			fwrite(table, 1, size, f);
		fclose(f);
	}
	free(table);
	return f != NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static char args[12][sizeof(path_option)];
	char *argv[ARRAY_SIZE(args) + 1];
	const char *arg[ARRAY_SIZE(args)];
	uint8_t variant;
	int argc = 0, i;

	if (!size)
		return 0;
	variant = data[0];
	if (!write_table(data + 1, size - 1,
			 !(variant & VARIANT_RAW_CHECKSUM)))
		return 0;

	arg[argc++] = "nvme";
	/* nothing of the host but the table */
	arg[argc++] = "--set-options";
	arg[argc++] = "test-sysfs-dir=/nonexistent/fuzz-nbft";
	arg[argc++] = "nbft";
	arg[argc++] = "show";
	arg[argc++] = path_option;
	if (variant & VARIANT_JSON)
		arg[argc++] = "--output-format=json";
	if (variant & VARIANT_VERBOSE)
		arg[argc++] = "--verbose";
	if (variant & VARIANT_SUBSYSTEM)
		arg[argc++] = "--subsystem";
	if (variant & VARIANT_DISCOVERY)
		arg[argc++] = "--discovery";
	if (variant & VARIANT_HFI)
		arg[argc++] = "--hfi";

	/* argv is writable for nvme-cli */
	for (i = 0; i < argc; i++) {
		snprintf(args[i], sizeof(args[i]), "%s", arg[i]);
		argv[i] = args[i];
	}
	argv[argc] = NULL;

	nvme_args = defaults;
	nvme_main(argc, argv);

	return 0;
}
