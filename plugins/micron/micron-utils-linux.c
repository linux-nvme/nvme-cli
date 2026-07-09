// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libnvme.h>

#include "common.h"
#include "nvme-print.h"
#include "micron-utils.h"
#include "util/cleanup.h"

extern char **environ;

/*
 * Validates that a string is a canonical PCI address in the
 * "DDDD:BB:DD.F" form (domain:bus:device.function), e.g. "0000:03:00.0".
 *
 * Return: true if valid, false otherwise.
 */
static bool pcie_bdf_is_valid(const char *bdf)
{
	int i;

	if (!bdf)
		return false;

	/* DDDD:BB:DD.F — exactly 12 characters */
	if (strlen(bdf) != 12)
		return false;

	for (i = 0; i < 4; i++)
		if (!isxdigit((unsigned char)bdf[i]))
			return false;
	if (bdf[4] != ':')
		return false;
	for (i = 5; i < 7; i++)
		if (!isxdigit((unsigned char)bdf[i]))
			return false;
	if (bdf[7] != ':')
		return false;
	for (i = 8; i < 10; i++)
		if (!isxdigit((unsigned char)bdf[i]))
			return false;
	if (bdf[10] != '.')
		return false;
	/* PCI function is a single digit 0-7 */
	if (bdf[11] < '0' || bdf[11] > '7')
		return false;

	return true;
}

/*
 * Retrieves the PCI BDF string (e.g. "0000:03:00.0") for the NVMe controller.
 * Tries /sys/class/nvme/<ctrl>/address first (kernel >= 4.13), then falls back
 * to resolving the /sys/class/nvme/<ctrl>/device symlink.
 */
static int get_pcie_bdf(struct libnvme_transport_handle *hdl,
	char *bdf, size_t bdf_len)
{
	__cleanup_free char *ctrl_name = micron_get_ctrl_name(hdl);
	char path[512];
	char target[512];
	ssize_t n;
	int fd;
	int err;
	char *slash;

	if (!ctrl_name)
		return -EINVAL;

	/*
	 * If possible, use /sys/class/nvme/<ctrl>/address (kernel >= 4.13).
	 * On failure, fall back to using the /device symlink.
	 */
	snprintf(path, sizeof(path), "/sys/class/nvme/%s/address", ctrl_name);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		n = read(fd, target, sizeof(target) - 1);
		close(fd);
		if (n > 0) {
			size_t len;

			target[n] = '\0';
			len = strcspn(target, "\n");

			if (len > 0 && len < bdf_len) {
				snprintf(bdf, bdf_len, "%.*s", (int)len, target);
				if (pcie_bdf_is_valid(bdf))
					return 0;
			}
		}
	}

	/*
	 * If unable to use the address file, use the last component of the
	 * /sys/class/nvme/<ctrl>/device symlink.
	 */
	snprintf(path, sizeof(path), "/sys/class/nvme/%s/device", ctrl_name);
	n = readlink(path, target, sizeof(target) - 1);
	if (n < 0) {
		err = -errno;
		nvme_show_perror("%s", path);
		return err;
	}
	target[n] = '\0';

	slash = strrchr(target, '/');
	if (!slash) {
		nvme_show_error("Unexpected sysfs path: %s", target);
		return -EINVAL;
	}

	slash++;
	if (strlen(slash) >= bdf_len) {
		nvme_show_error("PCI address too long: %s", slash);
		return -EINVAL;
	}

	memcpy(bdf, slash, strlen(slash) + 1);
	if (!pcie_bdf_is_valid(bdf)) {
		nvme_show_error("Invalid PCI address: %s", bdf);
		return -EINVAL;
	}

	return 0;
}

/*
 * Waits for a spawned child, retrying across signal interruptions, and maps its
 * termination to a return code.
 *
 * @pid: PID of the child to wait for.
 *
 * Return: 0 if the child exited with status 0, negative errno on a wait
 * failure, or -EIO if the child did not exit cleanly with status 0.
 */
static int wait_for_child(pid_t pid)
{
	int status;

	while (waitpid(pid, &status, 0) == -1) {
		if (errno != EINTR)
			return -errno;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -EIO;

	return 0;
}

/*
 * Reads all data from @fd into @out (NUL-terminated), keeping at most
 * @out_len - 1 bytes and discarding any excess. Always reads to EOF so the
 * writer never blocks on a full pipe, which would otherwise hang.
 *
 * @fd:      File descriptor to read from.
 * @out:     Buffer to receive up to @out_len - 1 bytes (NUL-terminated).
 * @out_len: Size of @out; must be at least 1.
 *
 * Return: 0 on success, negative errno on a read failure.
 */
static int read_to_eof(int fd, char *out, size_t out_len)
{
	size_t total = 0;
	ssize_t n = 1; /* non-zero to ensure drain loop runs */
	char discard[512];

	out[0] = '\0';

	/* Fill the output buffer with up to out_len - 1 bytes. */
	while (total < out_len - 1) {
		n = read(fd, out + total, out_len - 1 - total);

		if (n == -1) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			break;
		total += (size_t)n;
	}
	out[total] = '\0';

	/* Drain any remaining output so the writer never blocks on a full pipe. */
	while (n > 0) {
		n = read(fd, discard, sizeof(discard));
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			break;
	}

	return 0;
}

/*
 * Runs a command (given as an argv vector) without a shell and captures its
 * standard output into @out.
 *
 * @argv:    NULL-terminated argument vector; argv[0] is the program name.
 * @out:     Buffer to receive up to @out_len - 1 bytes of stdout (NUL-terminated).
 * @out_len: Size of @out; must be at least 1.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int spawn_and_capture(char *const argv[], char *out, size_t out_len)
{
	posix_spawn_file_actions_t actions;
	int pipefd[2];
	pid_t pid;
	int ret;
	int err = 0;

	if (!out || out_len == 0)
		return -EINVAL;

	out[0] = '\0';

	if (pipe(pipefd) == -1)
		return -errno;

	err = posix_spawn_file_actions_init(&actions);
	if (err) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -err;
	}

	/* Child: redirect stdout to the pipe write end, close both raw fds. */
	err = posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
	if (!err)
		err = posix_spawn_file_actions_addclose(&actions, pipefd[0]);
	if (!err)
		err = posix_spawn_file_actions_addclose(&actions, pipefd[1]);
	if (err) {
		posix_spawn_file_actions_destroy(&actions);
		close(pipefd[0]);
		close(pipefd[1]);
		return -err;
	}

	err = posix_spawnp(&pid, argv[0], &actions, NULL, argv, environ);
	posix_spawn_file_actions_destroy(&actions);
	close(pipefd[1]);
	if (err) {
		close(pipefd[0]);
		return -err;
	}

	/* Parent: read the child's output, always draining to EOF. */
	err = read_to_eof(pipefd[0], out, out_len);
	close(pipefd[0]);

	ret = wait_for_child(pid);
	return err ? err : ret;
}

int micron_get_pcie_aer_errors(struct libnvme_transport_handle *hdl,
	__u32 *correctable_errors, __u32 *uncorrectable_errors)
{
	char bdf[64], buf[16] = { 0 };
	int ret;

	ret = get_pcie_bdf(hdl, bdf, sizeof(bdf));
	if (ret) {
		nvme_show_error("Failed to get PCI address");
		return ret;
	}

	ret = spawn_and_capture(
		(char *const []){"setpci", "-s", bdf, "ECAP_AER+0x10.L", NULL},
		buf, sizeof(buf));
	if (ret) {
		nvme_show_error("Failed to retrieve error count");
		return ret;
	}
	*correctable_errors = (__u32)strtoul(buf, NULL, 16);

	ret = spawn_and_capture(
		(char *const []){"setpci", "-s", bdf, "ECAP_AER+0x4.L", NULL},
		buf, sizeof(buf));
	if (ret) {
		nvme_show_error("Failed to retrieve error count");
		return ret;
	}
	*uncorrectable_errors = (__u32)strtoul(buf, NULL, 16);

	return 0;
}

int micron_clear_pcie_aer_correctable_errors(
	struct libnvme_transport_handle *hdl)
{
	char bdf[64], correctable[16] = { 0 };
	int ret;

	ret = get_pcie_bdf(hdl, bdf, sizeof(bdf));
	if (ret) {
		nvme_show_error("Failed to get PCI address");
		return ret;
	}

	/* Writing all 1s clears the errors. */
	ret = spawn_and_capture(
		(char *const []){"setpci", "-s", bdf,
			"ECAP_AER+0x10.L=0xffffffff", NULL},
		correctable, sizeof(correctable));
	if (ret) {
		nvme_show_error("Failed to clear error count");
		return ret;
	}

	ret = spawn_and_capture(
		(char *const []){"setpci", "-s", bdf, "ECAP_AER+0x10.L", NULL},
		correctable, sizeof(correctable));
	if (ret) {
		nvme_show_error("Failed to retrieve error count");
		return ret;
	}
	nvme_show_verbose_result("Device correctable errors cleared!");
	nvme_show_result("Device correctable errors detected: %s", correctable);
	return 0;
}

int micron_run_spawn(char *const argv[], const char *outfile, bool append)
{
	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_t *actionsp = NULL;
	pid_t pid;
	int ret;
	int oflags = O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC);

	if (outfile) {
		ret = posix_spawn_file_actions_init(&actions);
		if (ret)
			return -ret;
		actionsp = &actions;

		ret = posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO,
						       outfile, oflags, 0644);
		if (ret)
			goto out_destroy;

		ret = posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO,
						       STDERR_FILENO);
		if (ret)
			goto out_destroy;
	}

	ret = posix_spawnp(&pid, argv[0], actionsp, NULL, argv, environ);

	if (actionsp)
		posix_spawn_file_actions_destroy(actionsp);

	if (ret)
		return -ret;

	return wait_for_child(pid);

out_destroy:
	posix_spawn_file_actions_destroy(actionsp);
	return -ret;
}

void micron_write_os_config_to_file(const char *file_name)
{
	FILE *fpOSConfig = NULL;
	int ret;
	int i;

	struct {
		const char *header;
		char *const *argv;
	} cmds[] = {
		{ "SYSTEM INFORMATION",
			(char *const []){"uname", "-a", NULL} },
		{ "LINUX KERNEL MODULE INFORMATION",
			(char *const []){"lsmod", NULL} },
		{ "LINUX SYSTEM MEMORY INFORMATION",
			(char *const []){"cat", "/proc/meminfo", NULL} },
		{ "SYSTEM INTERRUPT INFORMATION",
			(char *const []){"cat", "/proc/interrupts", NULL} },
		{ "CPU INFORMATION",
			(char *const []){"cat", "/proc/cpuinfo", NULL} },
		{ "IO MEMORY MAP INFORMATION",
			(char *const []){"cat", "/proc/iomem", NULL} },
		{ "MAJOR NUMBER AND DEVICE GROUP",
			(char *const []){"cat", "/proc/devices", NULL} },
		{ "KERNEL DMESG",
			(char *const []){"dmesg", NULL} },
		{ "/VAR/LOG/MESSAGES",
			(char *const []){"cat", "/var/log/messages", NULL} },
	};

	for (i = 0; i < (int)(ARRAY_SIZE(cmds)); i++) {
		fpOSConfig = fopen(file_name, "a+");
		if (fpOSConfig) {
			fprintf(fpOSConfig,
				"\n\n\n\n%s\n-----------------------------------------------\n",
				cmds[i].header);
			fclose(fpOSConfig);
			fpOSConfig = NULL;
		}
		ret = micron_run_spawn(cmds[i].argv, file_name, true);
		if (ret) {
			char cmdline[512] = "";
			int pos = 0;

			for (int j = 0; cmds[i].argv[j] && pos < (int)sizeof(cmdline); j++) {
				int n = snprintf(cmdline + pos,
						 sizeof(cmdline) - pos, "%s%s",
						 j ? " " : "", cmds[i].argv[j]);

				if (n < 0 || n >= (int)(sizeof(cmdline) - pos))
					break;
				pos += n;
			}
			nvme_show_error("Failed to run \"%s\": %s",
				cmdline, strerror(-ret));
		}
	}
}
