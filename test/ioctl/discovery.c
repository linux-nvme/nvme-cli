// SPDX-License-Identifier: LGPL-2.1-or-later

#include <libnvme.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>

#include "../../src/nvme/private.h"
#include "mock.h"
#include "util.h"

#define TEST_FD 0xFD

static void test_no_entries(nvme_ctrl_t c)
{
	struct nvmf_discovery_log header = {};
	/* No entries to fetch after fetching the header */
	struct mock_cmd mock_admin_cmds[] = {
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header),
			.cdw10 = (sizeof(header) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header,
		},
	};
	struct nvmf_discovery_log *log = NULL;

	set_mock_admin_cmds(mock_admin_cmds, ARRAY_SIZE(mock_admin_cmds));
	check(nvmf_get_discovery_log(c, &log, 1) == 0, "discovery failed: %m");
	end_mock_cmds();
	cmp(log, &header, sizeof(header), "incorrect header");
	free(log);
}

static void test_four_entries(nvme_ctrl_t c)
{
	struct nvmf_disc_log_entry entries[4];
	struct nvmf_discovery_log header = {
		.numrec = cpu_to_le64(ARRAY_SIZE(entries)),
	};
	/*
	 * All 4 entries should be fetched at once
	 * followed by the header again (to ensure genctr hasn't changed)
	 */
	struct mock_cmd mock_admin_cmds[] = {
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header),
			.cdw10 = (sizeof(header) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(entries),
			.cdw10 = (sizeof(entries) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.cdw12 = sizeof(header), /* LPOL */
			.out_data = entries,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header),
			.cdw10 = (sizeof(header) / 4 - 1) << 16 /* NUMDL */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header,
		},
	};
	struct nvmf_discovery_log *log = NULL;

	arbitrary(entries, sizeof(entries));
	set_mock_admin_cmds(mock_admin_cmds, ARRAY_SIZE(mock_admin_cmds));
	check(nvmf_get_discovery_log(c, &log, 1) == 0, "discovery failed: %m");
	end_mock_cmds();
	cmp(log, &header, sizeof(header), "incorrect header");
	cmp(log->entries, entries, sizeof(entries), "incorrect entries");
	free(log);
}

static void test_five_entries(nvme_ctrl_t c)
{
	struct nvmf_disc_log_entry entries[5];
	size_t first_entries = 4;
	size_t first_data_len = first_entries * sizeof(*entries);
	size_t second_entries = ARRAY_SIZE(entries) - first_entries;
	size_t second_data_len = second_entries * sizeof(*entries);
	struct nvmf_discovery_log header = {
		.numrec = cpu_to_le64(ARRAY_SIZE(entries)),
	};
	/*
	 * The first 4 entries (4 KB) are fetched together,
	 * followed by last entry separately.
	 * Finally, the header is fetched again to check genctr.
	 */
	struct mock_cmd mock_admin_cmds[] = {
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header),
			.cdw10 = (sizeof(header) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = first_data_len,
			.cdw10 = (first_data_len / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.cdw12 = sizeof(header), /* LPOL */
			.out_data = entries,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = second_data_len,
			.cdw10 = (second_data_len / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.cdw12 = sizeof(header) + first_data_len, /* LPOL */
			.out_data = entries + first_entries,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header),
			.cdw10 = (sizeof(header) / 4 - 1) << 16 /* NUMDL */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header,
		},
	};
	struct nvmf_discovery_log *log = NULL;

	arbitrary(entries, sizeof(entries));
	set_mock_admin_cmds(mock_admin_cmds, ARRAY_SIZE(mock_admin_cmds));
	check(nvmf_get_discovery_log(c, &log, 1) == 0, "discovery failed: %m");
	end_mock_cmds();
	cmp(log, &header, sizeof(header), "incorrect header");
	cmp(log->entries, entries, sizeof(entries), "incorrect entries");
	free(log);
}

static void test_genctr_change(nvme_ctrl_t c)
{
	struct nvmf_disc_log_entry entries1[1];
	struct nvmf_discovery_log header1 = {
		.numrec = cpu_to_le64(ARRAY_SIZE(entries1)),
	};
	struct nvmf_disc_log_entry entries2[2];
	struct nvmf_discovery_log header2 = {
		.genctr = cpu_to_le64(1),
		.numrec = cpu_to_le64(ARRAY_SIZE(entries2)),
	};
	/*
	 * genctr changes after the entries are fetched the first time,
	 * so the log page fetch is retried
	 */
	struct mock_cmd mock_admin_cmds[] = {
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header1),
			.cdw10 = (sizeof(header1) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header1,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(entries1),
			.cdw10 = (sizeof(entries1) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* NUMDL */
			.cdw12 = sizeof(header1), /* LPOL */
			.out_data = entries1,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header2),
			.cdw10 = (sizeof(header2) / 4 - 1) << 16 /* NUMDL */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header2,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header2),
			.cdw10 = (sizeof(header2) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header2,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(entries2),
			.cdw10 = (sizeof(entries2) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.cdw12 = sizeof(header2), /* LPOL */
			.out_data = entries2,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header2),
			.cdw10 = (sizeof(header2) / 4 - 1) << 16 /* NUMDL */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header2,
		},
	};
	struct nvmf_discovery_log *log = NULL;

	arbitrary(entries1, sizeof(entries1));
	arbitrary(entries2, sizeof(entries2));
	set_mock_admin_cmds(mock_admin_cmds, ARRAY_SIZE(mock_admin_cmds));
	check(nvmf_get_discovery_log(c, &log, 2) == 0, "discovery failed: %m");
	end_mock_cmds();
	cmp(log, &header2, sizeof(header2), "incorrect header");
	cmp(log->entries, entries2, sizeof(entries2), "incorrect entries");
	free(log);
}

static void test_max_retries(nvme_ctrl_t c)
{
	struct nvmf_disc_log_entry entry;
	struct nvmf_discovery_log header1 = {.numrec = cpu_to_le64(1)};
	struct nvmf_discovery_log header2 = {
		.genctr = cpu_to_le64(1),
		.numrec = cpu_to_le64(1),
	};
	struct nvmf_discovery_log header3 = {
		.genctr = cpu_to_le64(2),
		.numrec = cpu_to_le64(1),
	};
	/* genctr changes in both attempts, hitting the max retries (2) */
	struct mock_cmd mock_admin_cmds[] = {
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header1),
			.cdw10 = (sizeof(header1) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header1,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(entry),
			.cdw10 = (sizeof(entry) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.cdw12 = sizeof(header1), /* LPOL */
			.out_data = &entry,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header2),
			.cdw10 = (sizeof(header2) / 4 - 1) << 16 /* NUMDL */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header2,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header2),
			.cdw10 = (sizeof(header2) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header2,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(entry),
			.cdw10 = (sizeof(entry) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.cdw12 = sizeof(header2), /* LPOL */
			.out_data = &entry,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header3),
			.cdw10 = (sizeof(header3) / 4 - 1) << 16 /* NUMDL */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header3,
		},
	};
	struct nvmf_discovery_log *log = NULL;

	arbitrary(&entry, sizeof(entry));
	set_mock_admin_cmds(mock_admin_cmds, ARRAY_SIZE(mock_admin_cmds));
	check(nvmf_get_discovery_log(c, &log, 2) == -1, "discovery succeeded");
	end_mock_cmds();
	check(errno == EAGAIN, "discovery failed: %m");
	check(!log, "unexpected log page returned");
}

static void test_header_error(nvme_ctrl_t c)
{
	size_t header_size = sizeof(struct nvmf_discovery_log);
	/* Stop after an error in fetching the header the first time */
	struct mock_cmd mock_admin_cmds[] = {
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = header_size,
			.cdw10 = (header_size / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.err = NVME_SC_INVALID_OPCODE,
		},
	};
	struct nvmf_discovery_log *log = NULL;

	set_mock_admin_cmds(mock_admin_cmds, ARRAY_SIZE(mock_admin_cmds));
	check(nvmf_get_discovery_log(c, &log, 1) == -1, "discovery succeeded");
	end_mock_cmds();
	check(!log, "unexpected log page returned");
}

static void test_entries_error(nvme_ctrl_t c)
{
	struct nvmf_discovery_log header = {.numrec = cpu_to_le64(1)};
	size_t entry_size = sizeof(struct nvmf_disc_log_entry);
	/* Stop after an error in fetching the entries */
	struct mock_cmd mock_admin_cmds[] = {
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header),
			.cdw10 = (sizeof(header) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = entry_size,
			.cdw10 = (entry_size / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.cdw12 = sizeof(header), /* LPOL */
			.err = -EIO,
		},
	};
	struct nvmf_discovery_log *log = NULL;

	set_mock_admin_cmds(mock_admin_cmds, ARRAY_SIZE(mock_admin_cmds));
	check(nvmf_get_discovery_log(c, &log, 1) == -1, "discovery succeeded");
	end_mock_cmds();
	check(errno == EIO, "discovery failed: %m");
	check(!log, "unexpected log page returned");
}

static void test_genctr_error(nvme_ctrl_t c)
{
	struct nvmf_disc_log_entry entry;
	struct nvmf_discovery_log header = {.numrec = cpu_to_le64(1)};
	/* Stop after an error in refetching the header */
	struct mock_cmd mock_admin_cmds[] = {
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header),
			.cdw10 = (sizeof(header) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.out_data = &header,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(entry),
			.cdw10 = (sizeof(entry) / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.cdw12 = sizeof(header), /* LPOL */
			.out_data = &entry,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = sizeof(header),
			.cdw10 = (sizeof(header) / 4 - 1) << 16 /* NUMDL */
			       | NVME_LOG_LID_DISCOVER, /* LID */
			.err = NVME_SC_INTERNAL,
		},
	};
	struct nvmf_discovery_log *log = NULL;

	arbitrary(&entry, sizeof(entry));
	set_mock_admin_cmds(mock_admin_cmds, ARRAY_SIZE(mock_admin_cmds));
	check(nvmf_get_discovery_log(c, &log, 1) == -1, "discovery succeeded");
	end_mock_cmds();
	check(!log, "unexpected log page returned");
}

static void run_test(const char *test_name, void (*test_fn)(nvme_ctrl_t))
{
	struct nvme_ctrl c = {.fd = TEST_FD};

	printf("Running test %s...", test_name);
	fflush(stdout);
	check(asprintf(&c.name, "%s_ctrl", test_name) >= 0, "asprintf() failed");
	test_fn(&c);
	free(c.name);
	puts(" OK");
}

#define RUN_TEST(name) run_test(#name, test_ ## name)

int main(void)
{
	set_mock_fd(TEST_FD);
	RUN_TEST(no_entries);
	RUN_TEST(four_entries);
	RUN_TEST(five_entries);
	RUN_TEST(genctr_change);
	RUN_TEST(max_retries);
	RUN_TEST(header_error);
	RUN_TEST(entries_error);
	RUN_TEST(genctr_error);
}
