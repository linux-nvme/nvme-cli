// SPDX-License-Identifier: LGPL-2.1-or-later

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>

#include <libnvme.h>

#include "mock.h"
#include "util.h"

#define TEST_FD 0xFD
#define PDU_SIZE NVME_LOG_PAGE_PDU_SIZE

static void test_no_retries(void)
{
	struct nvme_ana_log log;
	__u32 len = sizeof(log);

	/* max_retries = 0 is nonsensical */
	check(nvme_get_ana_log_atomic(TEST_FD, false, false, 0, &log, &len),
	      "get log page succeeded");
	check(errno == EINVAL, "unexpected error: %m");
}

static void test_len_too_short(void)
{
	struct nvme_ana_log log;
	__u32 len = sizeof(log) - 1;

	/* Provided buffer doesn't have enough space to read the header */
	check(nvme_get_ana_log_atomic(TEST_FD, false, false, 1, &log, &len),
	      "get log page succeeded");
	check(errno == ENOSPC, "unexpected error: %m");
}

static void test_no_groups(void)
{
	struct nvme_ana_log header;
	/* The header reports no ANA groups. No additional commands needed. */
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.data_len = sizeof(header),
		.cdw10 = (sizeof(header) / 4 - 1) << 16 /* NUMDL */
		       | NVME_LOG_LID_ANA, /* LID */
		.out_data = &header,
	};
	struct nvme_ana_log log;
	__u32 len = sizeof(log);

	arbitrary(&log, sizeof(log));
	arbitrary(&header, sizeof(header));
	header.ngrps = cpu_to_le16(0);
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	check(!nvme_get_ana_log_atomic(TEST_FD, false, false, 1, &log, &len),
	      "get log page failed: %m");
	end_mock_cmds();
	cmp(&log, &header, sizeof(header), "incorrect header");
	check(len == sizeof(header),
	      "got len %" PRIu32 ", expected %zu", len, sizeof(header));
}

static void test_one_group_rgo(void)
{
	struct nvme_ana_log header;
	struct nvme_ana_group_desc group;
	__u8 log_page[sizeof(header) + sizeof(group)];
	__u32 len = 123;
	size_t len_dwords = len / 4;
	/*
	 * Header and group fetched in a single Get Log Page command.
	 * Since only one command was issued, chgcnt doesn't need to be checked.
	 */
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.data_len = len_dwords * 4,
		.cdw10 = (len_dwords - 1) << 16 /* NUMDL */
		       | NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY << 8 /* LSP */
		       | NVME_LOG_LID_ANA, /* LID */
		.out_data = log_page,
		.out_data_len = sizeof(log_page),
	};
	struct nvme_ana_log *log = malloc(len);

	arbitrary(log, len);
	arbitrary(&header, sizeof(header));
	header.ngrps = cpu_to_le16(1);
	arbitrary(&group, sizeof(group));
	group.nnsids = cpu_to_le32(0);
	memcpy(log_page, &header, sizeof(header));
	memcpy(log_page + sizeof(header), &group, sizeof(group));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	check(!nvme_get_ana_log_atomic(TEST_FD, true, false, 1, log, &len),
	      "get log page failed: %m");
	end_mock_cmds();
	cmp(log, log_page, sizeof(log_page), "incorrect log page");
	check(len == sizeof(log_page),
	      "got len %" PRIu32 ", expected %zu", len, sizeof(log_page));
	free(log);
}

static void test_one_group_nsids(void)
{
	struct nvme_ana_log header;
	struct nvme_ana_group_desc group;
	__le32 nsids[3];
	__u8 log_page[sizeof(header) + sizeof(group) + sizeof(nsids)];
	__u32 len = 124;
	size_t len_dwords = len / 4;
	/*
	 * Header, group, and NSIDs fetched in a single Get Log Page command.
	 * Since only one command was issued, chgcnt doesn't need to be checked.
	 */
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.data_len = len_dwords * 4,
		.cdw10 = (len_dwords - 1) << 16 /* NUMDL */
		       | NVME_LOG_LID_ANA, /* LID */
		.out_data = log_page,
		.out_data_len = sizeof(log_page),
	};
	struct nvme_ana_log *log = malloc(len);

	arbitrary(log, len);
	arbitrary(&header, sizeof(header));
	header.ngrps = cpu_to_le16(1);
	arbitrary(&group, sizeof(group));
	group.nnsids = cpu_to_le32(ARRAY_SIZE(nsids));
	arbitrary(nsids, sizeof(nsids));
	memcpy(log_page, &header, sizeof(header));
	memcpy(log_page + sizeof(header), &group, sizeof(group));
	memcpy(log_page + sizeof(header) + sizeof(group), nsids, sizeof(nsids));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	check(!nvme_get_ana_log_atomic(TEST_FD, false, false, 1, log, &len),
	      "get log page failed: %m");
	end_mock_cmds();
	cmp(log, log_page, sizeof(log_page), "incorrect log page");
	check(len == sizeof(log_page),
	      "got len %" PRIu32 ", expected %zu", len, sizeof(log_page));
	free(log);
}

static void test_multiple_groups_rgo(void)
{
	struct nvme_ana_log header;
	struct nvme_ana_group_desc groups[3];
	__u8 log_page[sizeof(header) + sizeof(groups)];
	__u32 len = 125;
	size_t len_dwords = len / 4;
	/*
	 * Header and groups fetched in a single Get Log Page command.
	 * Since only one command was issued, chgcnt doesn't need to be checked.
	 */
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.data_len = len_dwords * 4,
		.cdw10 = (len_dwords - 1) << 16 /* NUMDL */
		       | 1 << 15 /* RAE */
		       | NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY << 8 /* LSP */
		       | NVME_LOG_LID_ANA, /* LID */
		.out_data = log_page,
		.out_data_len = sizeof(log_page),
	};
	struct nvme_ana_log *log = malloc(len);

	arbitrary(log, len);
	arbitrary(&header, sizeof(header));
	header.ngrps = cpu_to_le16(ARRAY_SIZE(groups));
	arbitrary(groups, sizeof(groups));
	for (size_t i = 0; i < ARRAY_SIZE(groups); i++)
		groups[i].nnsids = cpu_to_le32(0);
	memcpy(log_page, &header, sizeof(header));
	memcpy(log_page + sizeof(header), groups, sizeof(groups));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	check(!nvme_get_ana_log_atomic(TEST_FD, true, true, 1, log, &len),
	      "get log page failed: %m");
	end_mock_cmds();
	cmp(log, log_page, sizeof(log_page), "incorrect log page");
	check(len == sizeof(log_page),
	      "got len %" PRIu32 ", expected %zu", len, sizeof(log_page));
	free(log);
}

static void test_multiple_groups_nsids(void)
{
	struct nvme_ana_log header;
	struct nvme_ana_group_desc group1;
	__le32 nsids1[3];
	struct nvme_ana_group_desc group2;
	__le32 nsids2[2];
	struct nvme_ana_group_desc group3;
	__le32 nsids3[1];
	__u8 log_page[sizeof(header) +
		      sizeof(group1) + sizeof(nsids1) +
		      sizeof(group2) + sizeof(nsids2) +
		      sizeof(group3) + sizeof(nsids3)];
	__u32 len = 456;
	size_t len_dwords = len / 4;
	/*
	 * Header, group, and NSIDs fetched in a single Get Log Page command.
	 * Since only one command was issued, chgcnt doesn't need to be checked.
	 */
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.data_len = len_dwords * 4,
		.cdw10 = (len_dwords - 1) << 16 /* NUMDL */
		       | NVME_LOG_LID_ANA, /* LID */
		.out_data = log_page,
		.out_data_len = sizeof(log_page),
	};
	struct nvme_ana_log *log = malloc(len);

	arbitrary(log, len);
	arbitrary(&header, sizeof(header));
	header.ngrps = cpu_to_le16(3);
	arbitrary(&group1, sizeof(group1));
	group1.nnsids = cpu_to_le32(ARRAY_SIZE(nsids1));
	arbitrary(nsids1, sizeof(nsids1));
	arbitrary(&group2, sizeof(group2));
	group2.nnsids = cpu_to_le32(ARRAY_SIZE(nsids2));
	arbitrary(nsids2, sizeof(nsids2));
	arbitrary(&group3, sizeof(group3));
	group3.nnsids = cpu_to_le32(ARRAY_SIZE(nsids3));
	arbitrary(nsids3, sizeof(nsids3));
	memcpy(log_page, &header, sizeof(header));
	memcpy(log_page + sizeof(header), &group1, sizeof(group1));
	memcpy(log_page + sizeof(header) + sizeof(group1),
	       nsids1, sizeof(nsids1));
	memcpy(log_page + sizeof(header) + sizeof(group1) + sizeof(nsids1),
	       &group2, sizeof(group2));
	memcpy(log_page + sizeof(header) + sizeof(group1) + sizeof(nsids1) +
			  sizeof(group2),
	       nsids2, sizeof(nsids2));
	memcpy(log_page + sizeof(header) + sizeof(group1) + sizeof(nsids1) +
			  sizeof(group2) + sizeof(nsids2),
	       &group3, sizeof(group3));
	memcpy(log_page + sizeof(header) + sizeof(group1) + sizeof(nsids1) +
			  sizeof(group2) + sizeof(nsids2) + sizeof(group3),
	       nsids3, sizeof(nsids3));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	check(!nvme_get_ana_log_atomic(TEST_FD, false, false, 1, log, &len),
	      "get log page failed: %m");
	end_mock_cmds();
	cmp(log, log_page, sizeof(log_page), "incorrect log page");
	check(len == sizeof(log_page),
	      "got len %" PRIu32 ", expected %zu", len, sizeof(log_page));
	free(log);
}

static void test_long_log(void)
{
	struct nvme_ana_log header;
	struct nvme_ana_group_desc group;
	__le32 nsids[PDU_SIZE * 2 / sizeof(*group.nsids)];
	__u8 log_page[sizeof(header) + sizeof(group) + sizeof(nsids)];
	__u32 len = PDU_SIZE * 4;
	/*
	 * Get Log Page is issued for 4 KB, returning the header (with 1 group),
	 * the group (with 2048 NSIDs) and the start of its NSIDs.
	 * Another Get Log page command is issued for the next 1024 NSIDs.
	 * Another Get Log page command is issued for the last NSIDs.
	 * Header is fetched again to verify chgcnt hasn't changed.
	 */
	struct mock_cmd mock_admin_cmds[] = {
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = PDU_SIZE,
			.cdw10 = (PDU_SIZE / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_ANA, /* LID */
			.out_data = log_page,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = PDU_SIZE,
			.cdw10 = (PDU_SIZE / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_ANA, /* LID */
			.cdw12 = PDU_SIZE, /* LPOL */
			.out_data = log_page + PDU_SIZE,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = PDU_SIZE,
			.cdw10 = (PDU_SIZE / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_ANA, /* LID */
			.cdw12 = PDU_SIZE * 2, /* LPOL */
			.out_data = log_page + PDU_SIZE * 2,
			.out_data_len = sizeof(log_page) - PDU_SIZE * 2,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = PDU_SIZE,
			.cdw10 = (PDU_SIZE / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_ANA, /* LID */
			.out_data = log_page,
		},
	};
	struct nvme_ana_log *log = malloc(len);

	arbitrary(log, len);
	arbitrary(&header, sizeof(header));
	header.ngrps = cpu_to_le16(1);
	arbitrary(&group, sizeof(group));
	group.nnsids = cpu_to_le32(ARRAY_SIZE(nsids));
	arbitrary(nsids, sizeof(nsids));
	memcpy(log_page, &header, sizeof(header));
	memcpy(log_page + sizeof(header), &group, sizeof(group));
	memcpy(log_page + sizeof(header) + sizeof(group), nsids, sizeof(nsids));
	set_mock_admin_cmds(mock_admin_cmds, ARRAY_SIZE(mock_admin_cmds));
	check(!nvme_get_ana_log_atomic(TEST_FD, false, true, 1, log, &len),
	      "get log page failed: %m");
	end_mock_cmds();
	cmp(log, log_page, sizeof(log_page), "incorrect log page");
	check(len == sizeof(log_page),
	      "got len %" PRIu32 ", expected %zu", len, sizeof(log_page));
	free(log);
}

static void test_chgcnt_change(void)
{
	struct nvme_ana_log header1;
	struct nvme_ana_group_desc groups1[PDU_SIZE / sizeof(*header1.descs)];
	__u8 log_page1[sizeof(header1) + sizeof(groups1)];
	struct nvme_ana_log header2;
	struct nvme_ana_group_desc group2;
	__u8 log_page2[sizeof(header2) + sizeof(group2)];
	__u32 len = PDU_SIZE + 126;
	size_t remainder_len_dwords = (len - PDU_SIZE) / 4;
	/*
	 * Get Log Page is issued for 4 KB,
	 * returning the header (with 128 groups), and the start of the groups.
	 * Get Log Page is issued for the rest of the groups.
	 * Get Log Page is issued for the first 4 KB again to check chgcnt.
	 * chgcnt has changed, but there is only 1 group now,
	 * which was already fetched with the header.
	 */
	struct mock_cmd mock_admin_cmds[] = {
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = PDU_SIZE,
			.cdw10 = (PDU_SIZE / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY << 8 /* LSP */
			       | NVME_LOG_LID_ANA, /* LID */
			.out_data = log_page1,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = remainder_len_dwords * 4,
			.cdw10 = (remainder_len_dwords - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY << 8 /* LSP */
			       | NVME_LOG_LID_ANA, /* LID */
			.cdw12 = PDU_SIZE, /* LPOL */
			.out_data = log_page1 + PDU_SIZE,
			.out_data_len = sizeof(log_page1) - PDU_SIZE,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = PDU_SIZE,
			.cdw10 = (PDU_SIZE / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY << 8 /* LSP */
			       | NVME_LOG_LID_ANA, /* LID */
			.out_data = log_page2,
			.out_data_len = sizeof(log_page2),
		},
	};
	struct nvme_ana_log *log = malloc(len);

	arbitrary(log, len);
	arbitrary(&header1, sizeof(header1));
	header1.ngrps = cpu_to_le16(ARRAY_SIZE(groups1));
	arbitrary(&groups1, sizeof(groups1));
	for (size_t i = 0; i < ARRAY_SIZE(groups1); i++)
		groups1[i].nnsids = cpu_to_le32(0);
	memcpy(log_page1, &header1, sizeof(header1));
	memcpy(log_page1 + sizeof(header1), groups1, sizeof(groups1));
	arbitrary(&header2, sizeof(header2));
	header2.ngrps = cpu_to_le16(1);
	arbitrary(&group2, sizeof(group2));
	group2.nnsids = cpu_to_le32(0);
	memcpy(log_page2, &header2, sizeof(header2));
	memcpy(log_page2 + sizeof(header2), &group2, sizeof(group2));
	set_mock_admin_cmds(mock_admin_cmds, ARRAY_SIZE(mock_admin_cmds));
	check(!nvme_get_ana_log_atomic(TEST_FD, true, true, 2, log, &len),
	      "get log page failed: %m");
	end_mock_cmds();
	cmp(log, log_page2, sizeof(log_page2), "incorrect log page");
	check(len == sizeof(log_page2),
	      "got len %" PRIu32 ", expected %zu", len, sizeof(log_page2));
	free(log);
}

static void test_buffer_too_short_chgcnt_change(void)
{
	struct nvme_ana_log header1;
	struct nvme_ana_group_desc group1_1;
	__le32 nsids1[PDU_SIZE / sizeof(*group1_1.nsids)];
	struct nvme_ana_group_desc group1_2;
	__u8 log_page1[sizeof(header1) +
		       sizeof(group1_1) + sizeof(nsids1) + sizeof(group1_2)];
	struct nvme_ana_log header2;
	struct nvme_ana_group_desc group2;
	__le32 nsid2;
	uint8_t log_page2[sizeof(header2) + sizeof(group2) + sizeof(nsid2)];
	__u32 len = PDU_SIZE + 123;
	size_t remainder_len_dwords = (len - PDU_SIZE) / 4;
	/*
	 * Get Log Page issued for 4 KB, returning the header (with 2 groups),
	 * the first group (with 1024 NSIDs), and the start of the NSIDs.
	 * Get Log Page is issued for the rest of the NSIDs and the second group.
	 * The second group contains garbage, making the log exceed the buffer.
	 * The first 4 KB is fetched again, returning a header with a new chgcnt
	 * and a group with one NSID.
	 */
	struct mock_cmd mock_admin_cmds[] = {
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = PDU_SIZE,
			.cdw10 = (PDU_SIZE / 4 - 1) << 16 /* NUMDL */
			       | NVME_LOG_LID_ANA, /* LID */
			.out_data = log_page1,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = remainder_len_dwords * 4,
			.cdw10 = (remainder_len_dwords - 1) << 16 /* NUMDL */
			       | NVME_LOG_LID_ANA, /* LID */
			.cdw12 = PDU_SIZE, /* LPOL */
			.out_data = log_page1 + PDU_SIZE,
			.out_data_len = sizeof(log_page1) - PDU_SIZE,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = PDU_SIZE,
			.cdw10 = (PDU_SIZE / 4 - 1) << 16 /* NUMDL */
			       | NVME_LOG_LID_ANA, /* LID */
			.out_data = log_page2,
			.out_data_len = sizeof(log_page2),
		},
	};
	struct nvme_ana_log *log = malloc(len);

	arbitrary(log, len);
	arbitrary(&header1, sizeof(header1));
	header1.ngrps = cpu_to_le16(2);
	arbitrary(&group1_1, sizeof(group1_1));
	group1_1.nnsids = cpu_to_le32(ARRAY_SIZE(nsids1));
	arbitrary(nsids1, sizeof(nsids1));
	memset(&group1_2, -1, sizeof(group1_2));
	memcpy(log_page1, &header1, sizeof(header1));
	memcpy(log_page1 + sizeof(header1), &group1_1, sizeof(group1_1));
	memcpy(log_page1 + sizeof(header1) + sizeof(group1_1),
	       nsids1, sizeof(nsids1));
	memcpy(log_page1 + sizeof(header1) + sizeof(group1_1) + sizeof(nsids1),
	       &group1_2, sizeof(group1_2));
	arbitrary(&header2, sizeof(header2));
	header2.ngrps = cpu_to_le16(1);
	arbitrary(&group2, sizeof(group2));
	group2.nnsids = cpu_to_le32(1);
	arbitrary(&nsid2, sizeof(nsid2));
	memcpy(log_page2, &header2, sizeof(header2));
	memcpy(log_page2 + sizeof(header2), &group2, sizeof(group2));
	memcpy(log_page2 + sizeof(header2) + sizeof(group2),
	       &nsid2, sizeof(nsid2));
	set_mock_admin_cmds(mock_admin_cmds, ARRAY_SIZE(mock_admin_cmds));
	check(!nvme_get_ana_log_atomic(TEST_FD, false, false, 2, log, &len),
	      "get log page failed: %m");
	end_mock_cmds();
	cmp(log, log_page2, sizeof(log_page2), "incorrect log page");
	check(len == sizeof(log_page2),
	      "got len %" PRIu32 ", expected %zu", len, sizeof(log_page2));
	free(log);
}

static void test_chgcnt_max_retries(void)
{
	struct nvme_ana_log header1, header2, header3;
	struct nvme_ana_group_desc group;
	__le32 nsids[PDU_SIZE / sizeof(*group.nsids)];
	__u8 log_page1[sizeof(header1) + sizeof(group) + sizeof(nsids)],
	     log_page2[sizeof(header2) + sizeof(group) + sizeof(nsids)];
	__u32 len = PDU_SIZE * 2;
	/*
	 * Get Log Page is issued for 4 KB, returning the header (with 1 group),
	 * the group (with 1024 NSIDs), and the start of the NSIDs.
	 * Get Log Page is issued for the rest of the NSIDs.
	 * Get Log Page is issued for the first 4 KB again to check chgcnt.
	 * chgcnt has changed and there is still 1 group with 1024 NSIDs.
	 * Get Log Page is issued for the rest of the NSIDs.
	 * Get Log Page is issued for the first 4 KB again to check chgcnt.
	 * chgcnt has changed again.
	 * This exceeds max_retries = 2 so nvme_get_ana_log() exits with EAGAIN.
	 */
	struct mock_cmd mock_admin_cmds[] = {
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = PDU_SIZE,
			.cdw10 = (PDU_SIZE / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_ANA, /* LID */
			.out_data = log_page1,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = PDU_SIZE,
			.cdw10 = (PDU_SIZE / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_ANA, /* LID */
			.cdw12 = PDU_SIZE, /* LPOL */
			.out_data = log_page1 + PDU_SIZE,
			.out_data_len = sizeof(log_page1) - PDU_SIZE,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = PDU_SIZE,
			.cdw10 = (PDU_SIZE / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_ANA, /* LID */
			.out_data = log_page2,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = PDU_SIZE,
			.cdw10 = (PDU_SIZE / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_ANA, /* LID */
			.cdw12 = PDU_SIZE, /* LPOL */
			.out_data = log_page2 + PDU_SIZE,
			.out_data_len = sizeof(log_page2) - PDU_SIZE,
		},
		{
			.opcode = nvme_admin_get_log_page,
			.data_len = PDU_SIZE,
			.cdw10 = (PDU_SIZE / 4 - 1) << 16 /* NUMDL */
			       | 1 << 15 /* RAE */
			       | NVME_LOG_LID_ANA, /* LID */
			.out_data = &header3,
			.out_data_len = sizeof(header3),
		},
	};
	struct nvme_ana_log *log = malloc(len);

	arbitrary(log, len);
	arbitrary(&header1, sizeof(header1));
	header1.ngrps = cpu_to_le16(1);
	arbitrary(&header2, sizeof(header2));
	header2.ngrps = cpu_to_le16(1);
	arbitrary(&header3, sizeof(header3));
	header3.ngrps = cpu_to_le16(0);
	arbitrary(&group, sizeof(group));
	group.nnsids = cpu_to_le32(ARRAY_SIZE(nsids));
	arbitrary(nsids, sizeof(nsids));
	memcpy(log_page1, &header1, sizeof(header1));
	memcpy(log_page1 + sizeof(header1), &group, sizeof(group));
	memcpy(log_page1 + sizeof(header1) + sizeof(group),
	       nsids, sizeof(nsids));
	memcpy(log_page2, &header2, sizeof(header2));
	memcpy(log_page2 + sizeof(header2), &group, sizeof(group));
	memcpy(log_page2 + sizeof(header2) + sizeof(group),
	       nsids, sizeof(nsids));
	set_mock_admin_cmds(mock_admin_cmds, ARRAY_SIZE(mock_admin_cmds));
	check(nvme_get_ana_log_atomic(TEST_FD, false, true, 2, log, &len) == -1,
	      "get log page succeeded");
	end_mock_cmds();
	check(errno == EAGAIN, "unexpected error: %m");
	free(log);
}

static void test_buffer_too_short(void)
{
	struct nvme_ana_log header;
	struct nvme_ana_group_desc group;
	__le32 nsids[20];
	__u8 log_page[sizeof(header) + sizeof(group) + sizeof(nsids)];
	__u32 len = 123;
	__u32 len_dwords = len / 4;
	/*
	 * Header, group, and NSIDs fetched in a single Get Log Page command.
	 * This length exceeds the provided buffer.
	 * Only one command was issued, so the log page couldn't have changed.
	 * nvme_get_ana_log() returns ENOSPC because the buffer is too small.
	 */
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.data_len = len_dwords * 4,
		.cdw10 = (len_dwords - 1) << 16 /* NUMDL */
		       | 1 << 15 /* RAE */
		       | NVME_LOG_LID_ANA, /* LID */
		.out_data = log_page,
	};
	struct nvme_ana_log *log = malloc(len);

	arbitrary(log, len);
	arbitrary(&header, sizeof(header));
	header.ngrps = cpu_to_le16(1);
	arbitrary(&group, sizeof(group));
	group.nnsids = cpu_to_le32(ARRAY_SIZE(nsids));
	arbitrary(nsids, sizeof(nsids));
	memcpy(log_page, &header, sizeof(header));
	memcpy(log_page + sizeof(header), &group, sizeof(group));
	memcpy(log_page + sizeof(header) + sizeof(group), nsids, sizeof(nsids));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	check(nvme_get_ana_log_atomic(TEST_FD, false, true, 2, log, &len) == -1,
	      "get log page succeeded");
	end_mock_cmds();
	check(errno == ENOSPC, "unexpected error: %m");
	free(log);
}

static void run_test(const char *test_name, void (*test_fn)(void))
{
	printf("Running test %s...", test_name);
	fflush(stdout);
	test_fn();
	puts(" OK");
}

#define RUN_TEST(name) run_test(#name, test_ ## name)

int main(void)
{
	set_mock_fd(TEST_FD);
	RUN_TEST(no_retries);
	RUN_TEST(len_too_short);
	RUN_TEST(no_groups);
	RUN_TEST(one_group_rgo);
	RUN_TEST(one_group_nsids);
	RUN_TEST(multiple_groups_rgo);
	RUN_TEST(multiple_groups_nsids);
	RUN_TEST(long_log);
	RUN_TEST(chgcnt_change);
	RUN_TEST(buffer_too_short_chgcnt_change);
	RUN_TEST(chgcnt_max_retries);
	RUN_TEST(buffer_too_short);
}
