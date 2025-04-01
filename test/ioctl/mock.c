// SPDX-License-Identifier: LGPL-2.1-or-later

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <string.h>
#include <sys/ioctl.h>
#include <dlfcn.h>

#include <nvme/ioctl.h>

#include "mock.h"
#include "util.h"

struct mock_cmds {
	const char *name;
	const struct mock_cmd *cmds;
	size_t remaining_cmds;
};

static int mock_fd = -1;
static struct mock_cmds mock_admin_cmds = {.name = "admin"};
static struct mock_cmds mock_io_cmds = {.name = "IO"};

static void set_mock_cmds(
	struct mock_cmds *mock_cmds, const struct mock_cmd *cmds, size_t len)
{
	mock_cmds->cmds = cmds;
	mock_cmds->remaining_cmds = len;
}

static void mock_cmds_done(const struct mock_cmds *mock_cmds)
{
	check(!mock_cmds->remaining_cmds,
	      "%zu %s commands not executed",
	      mock_cmds->remaining_cmds, mock_cmds->name);
}

void set_mock_fd(int fd)
{
	mock_fd = fd;
}

void set_mock_admin_cmds(const struct mock_cmd *cmds, size_t len)
{
	set_mock_cmds(&mock_admin_cmds, cmds, len);
}

void set_mock_io_cmds(const struct mock_cmd *cmds, size_t len)
{
	set_mock_cmds(&mock_io_cmds, cmds, len);
}

void end_mock_cmds(void)
{
	mock_cmds_done(&mock_admin_cmds);
	mock_cmds_done(&mock_io_cmds);
}

#define execute_ioctl(cmd, mock_cmd) ({ \
	check((cmd)->opcode == (mock_cmd)->opcode, \
	      "got opcode 0x%" PRIx8 ", expected 0x%" PRIx8, \
	      (cmd)->opcode, (mock_cmd)->opcode); \
	check((cmd)->flags == (mock_cmd)->flags, \
	      "got flags 0x%" PRIx8 ", expected 0x%" PRIx8, \
	      (cmd)->flags, (mock_cmd)->flags); \
	check((cmd)->nsid == (mock_cmd)->nsid, \
	      "got nsid 0x%" PRIx32 ", expected 0x%" PRIx32, \
	      (cmd)->nsid, (mock_cmd)->nsid); \
	check((cmd)->cdw2 == (mock_cmd)->cdw2, \
	      "got cdw2 0x%" PRIx32 ", expected 0x%" PRIx32, \
	      (cmd)->cdw2, (mock_cmd)->cdw2); \
	check((cmd)->cdw3 == (mock_cmd)->cdw3, \
	      "got cdw3 0x%" PRIx32 ", expected 0x%" PRIx32, \
	      (cmd)->cdw3, (mock_cmd)->cdw3); \
	check((cmd)->metadata_len == (mock_cmd)->metadata_len, \
	      "got metadata_len %" PRIu32 ", expected %" PRIu32, \
	      (cmd)->metadata_len, (mock_cmd)->metadata_len); \
	if ((cmd)->metadata_len) { \
		cmp((void const *)(uintptr_t)(cmd)->metadata, \
		    (mock_cmd)->metadata, \
		    (cmd)->metadata_len, \
		    "incorrect metadata"); \
	} \
	__u32 data_len = (cmd)->data_len; \
	check(data_len == (mock_cmd)->data_len, \
	      "got data_len %" PRIu32 ", expected %" PRIu32, \
	      data_len, (mock_cmd)->data_len); \
	void *data = (void *)(uintptr_t)(cmd)->addr; \
	if ((mock_cmd)->in_data) { \
		cmp(data, (mock_cmd)->in_data, data_len, "incorrect data"); \
	} \
	check((cmd)->cdw10 == (mock_cmd)->cdw10, \
	      "got cdw10 0x%" PRIx32 ", expected 0x%" PRIx32, \
	      (cmd)->cdw10, (mock_cmd)->cdw10); \
	check((cmd)->cdw11 == (mock_cmd)->cdw11, \
	      "got cdw11 0x%" PRIx32 ", expected 0x%" PRIx32, \
	      (cmd)->cdw11, (mock_cmd)->cdw11); \
	check((cmd)->cdw12 == (mock_cmd)->cdw12, \
	      "got cdw12 0x%" PRIx32 ", expected 0x%" PRIx32, \
	      (cmd)->cdw12, (mock_cmd)->cdw12); \
	check((cmd)->cdw13 == (mock_cmd)->cdw13, \
	      "got cdw13 0x%" PRIx32 ", expected 0x%" PRIx32, \
	      (cmd)->cdw13, (mock_cmd)->cdw13); \
	check((cmd)->cdw14 == (mock_cmd)->cdw14, \
	      "got cdw14 0x%" PRIx32 ", expected 0x%" PRIx32, \
	      (cmd)->cdw14, (mock_cmd)->cdw14); \
	check((cmd)->cdw15 == (mock_cmd)->cdw15, \
	      "got cdw15 0x%" PRIx32 ", expected 0x%" PRIx32, \
	      (cmd)->cdw15, (mock_cmd)->cdw15); \
	check((cmd)->timeout_ms == (mock_cmd)->timeout_ms, \
	      "got timeout_ms %" PRIu32 ", expected %" PRIu32, \
	      (cmd)->timeout_ms, (mock_cmd)->timeout_ms); \
	(cmd)->result = (mock_cmd)->result; \
	const void *out_data = (mock_cmd)->out_data; \
	if (out_data) { \
		memcpy(data, out_data, (mock_cmd)->out_data_len ?: data_len); \
	} \
})

#ifdef HAVE_GLIBC_IOCTL
typedef int (*ioctl_func_t)(int, unsigned long, void *);
int ioctl(int fd, unsigned long request, ...)
#else
typedef int (*ioctl_func_t)(int, int, void *);
int ioctl(int fd, int request, ...)
#endif
{
	ioctl_func_t real_ioctl = NULL;
	struct mock_cmds *mock_cmds;
	bool result64;
	const struct mock_cmd *mock_cmd;
	va_list args;
	void *cmd;

	switch (request) {
	case NVME_IOCTL_ADMIN_CMD:
		mock_cmds = &mock_admin_cmds;
		result64 = false;
		break;
	case NVME_IOCTL_ADMIN64_CMD:
		mock_cmds = &mock_admin_cmds;
		result64 = true;
		break;
	case NVME_IOCTL_IO_CMD:
		mock_cmds = &mock_io_cmds;
		result64 = false;
		break;
	case NVME_IOCTL_IO64_CMD:
		mock_cmds = &mock_io_cmds;
		result64 = true;
		break;
	default:
#if HAVE_LIBC_LDSYM
		real_ioctl = dlsym(RTLD_NEXT, "ioctl");
		if (!real_ioctl)
			fail("Error: dlsym failed to find original ioctl\n");
#else
		fail("Error: unhandled ioctl\n");
#endif
	}

	va_start(args, request);
	cmd = va_arg(args, void *);
	va_end(args);

	if (real_ioctl)
		return real_ioctl(fd, request, cmd);

	check(fd == mock_fd, "got fd %d, expected %d", fd, mock_fd);
	check(mock_cmds->remaining_cmds,
	      "unexpected %s command", mock_cmds->name);
	mock_cmd = mock_cmds->cmds++;
	mock_cmds->remaining_cmds--;

	if (result64) {
		execute_ioctl((struct nvme_passthru_cmd64 *)cmd, mock_cmd);
	} else {
		check((uint32_t)mock_cmd->result == mock_cmd->result,
		      "expected 64-bit %s for result %" PRIu64,
		      __func__, mock_cmd->result);
		execute_ioctl((struct nvme_passthru_cmd *)cmd, mock_cmd);
	}
	if (mock_cmd->err < 0) {
		errno = -mock_cmd->err;
		return -1;
	}

	return mock_cmd->err;
}

/* mock io_uring_get_probe, just fail */
struct io_uring_probe *io_uring_get_probe(void)
{
	return 0;
}
