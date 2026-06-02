// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>

#include <libnvme.h>

#include "common.h"
#include "nvme-print.h"
#include "micron-utils.h"
#include "util/cleanup.h"

static int ReadSysFile(const char *file, unsigned short *id)
{
	int ret = 0;
	char idstr[32] = { '\0' };
	int fd = open(file, O_RDONLY);

	if (fd < 0) {
		nvme_show_perror("%s", file);
		return fd;
	}

	ret = read(fd, idstr, sizeof(idstr) - 1);
	close(fd);
	if (ret < 0)
		nvme_show_perror("read");
	else
		*id = strtol(idstr, NULL, 16);

	return ret;
}

int micron_get_pci_ids(
	struct libnvme_global_ctx *ctx, struct libnvme_transport_handle *hdl,
	unsigned short *vid, unsigned short *did)
{
	char id_path[512];
	__cleanup_free char *ctrl_sysfs_dir = micron_get_ctrl_sysfs_dir(ctx, hdl);

	if (ctrl_sysfs_dir) {
		snprintf(id_path, sizeof(id_path), "%s/device/vendor",
			ctrl_sysfs_dir);
		ReadSysFile(id_path, vid);

		snprintf(id_path, sizeof(id_path), "%s/device/device",
			ctrl_sysfs_dir);
		ReadSysFile(id_path, did);
	} else {
		nvme_show_error("Unable to find sysfs dir for %s",
			libnvme_transport_handle_get_name(hdl));
		return -EINVAL;
	}

	return 0;
}

int micron_get_pcie_aer_errors(struct libnvme_transport_handle *hdl,
	__u32 *correctable_errors, __u32 *uncorrectable_errors)
{
	int bus = 0, domain = 0, device = 0, function = 0;
	char strTempFile[1024], strTempFile2[1024], cmdbuf[1024];
	char buf[8] = { 0 };
	char *businfo = NULL;
	__cleanup_free char *devicename = NULL;
	ssize_t sLinkSize = 0;
	FILE *fp;
	char *res;

	devicename = micron_get_ns_name(hdl);
	if (!devicename || !strstr(devicename, "nvme")) {
		nvme_show_error("Invalid device specified!");
		return -EINVAL;
	}
	snprintf(strTempFile, sizeof(strTempFile), "/sys/block/%s/device", devicename);
	sLinkSize = readlink(strTempFile, strTempFile2, sizeof(strTempFile2) - 1);
	if (sLinkSize < 0) {
		nvme_show_error("Failed to read device");
		return -errno;
	}
	strTempFile2[sLinkSize] = '\0';
	if (strstr(strTempFile2, "../../nvme")) {
		snprintf(strTempFile, sizeof(strTempFile), "/sys/block/%s/device/device", devicename);
		sLinkSize = readlink(strTempFile, strTempFile2, sizeof(strTempFile2) - 1);
		if (sLinkSize < 0) {
			nvme_show_error("Failed to read device");
			return -errno;
		}
		strTempFile2[sLinkSize] = '\0';
	}
	businfo = strrchr(strTempFile2, '/');
	if (!businfo || sscanf(businfo, "/%x:%x:%x.%x", &domain, &bus, &device, &function) != 4)
		domain = bus = device = function = 0;
	snprintf(cmdbuf, sizeof(cmdbuf), "setpci -s %x:%x.%x ECAP_AER+10.L", bus, device,
		function);
	fp = popen(cmdbuf, "r");
	if (!fp) {
		nvme_show_error("Failed to retrieve error count");
		return -EIO;
	}
	res = fgets(buf, sizeof(buf), fp);
	if (!res) {
		nvme_show_error("Failed to retrieve error count");
		pclose(fp);
		return -EIO;
	}
	pclose(fp);
	*correctable_errors = (__u32)strtol(buf, NULL, 16);

	snprintf(cmdbuf, sizeof(cmdbuf), "setpci -s %x:%x.%x ECAP_AER+0x4.L", bus, device,
		function);
	fp = popen(cmdbuf, "r");
	if (!fp) {
		nvme_show_error("Failed to retrieve error count");
		return -EIO;
	}
	res = fgets(buf, sizeof(buf), fp);
	if (!res) {
		nvme_show_error("Failed to retrieve error count");
		pclose(fp);
		return -EIO;
	}
	pclose(fp);
	*uncorrectable_errors = (__u32)strtol(buf, NULL, 16);

	return 0;
}

int micron_clear_pcie_aer_correctable_errors(
	struct libnvme_transport_handle *hdl)
{
	int err, bus = 0, domain = 0, device = 0, function = 0;
	char strTempFile[1024], strTempFile2[1024], cmdbuf[1024];
	char *businfo = NULL;
	__cleanup_free char *devicename = NULL;
	ssize_t sLinkSize = 0;
	char correctable[8] = { 0 };
	FILE *fp;
	char *res;

	devicename = micron_get_ns_name(hdl);
	if (!devicename || !strstr(devicename, "nvme")) {
		nvme_show_error("Invalid device specified!");
		return -EINVAL;
	}
	err = snprintf(strTempFile, sizeof(strTempFile),
				   "/sys/block/%s/device", devicename);
	if (err < 0)
		return err;

	sLinkSize = readlink(strTempFile, strTempFile2, sizeof(strTempFile2) - 1);
	if (sLinkSize < 0) {
		nvme_show_error("Failed to read device");
		return -errno;
	}
	strTempFile2[sLinkSize] = '\0';
	if (strstr(strTempFile2, "../../nvme")) {
		err = snprintf(strTempFile, sizeof(strTempFile),
					   "/sys/block/%s/device/device", devicename);
		if (err < 0)
			return err;
		sLinkSize = readlink(strTempFile, strTempFile2, sizeof(strTempFile2) - 1);
		if (sLinkSize < 0) {
			nvme_show_error("Failed to read device");
			return -errno;
		}
		strTempFile2[sLinkSize] = '\0';
	}
	businfo = strrchr(strTempFile2, '/');
	if (!businfo || sscanf(businfo, "/%x:%x:%x.%x", &domain, &bus, &device, &function) != 4)
		domain = bus = device = function = 0;
	snprintf(cmdbuf, sizeof(cmdbuf), "setpci -s %x:%x.%x ECAP_AER+0x10.L=0xffffffff", bus,
			device, function);
	fp = popen(cmdbuf, "r");
	if (!fp) {
		nvme_show_error("Failed to clear error count");
		return -1;
	}
	pclose(fp);

	snprintf(cmdbuf, sizeof(cmdbuf), "setpci -s %x:%x.%x ECAP_AER+0x10.L", bus, device,
			function);
	fp = popen(cmdbuf, "r");
	if (!fp) {
		nvme_show_error("Failed to retrieve error count");
		return -1;
	}
	res = fgets(correctable, sizeof(correctable), fp);
	if (!res) {
		nvme_show_error("Failed to retrieve error count");
		pclose(fp);
		return -1;
	}
	pclose(fp);
	nvme_show_verbose_result("Device correctable errors cleared!");
	nvme_show_result("Device correctable errors detected: %s", correctable);
	return 0;
}

extern char **environ;

int micron_run_spawn(char *const argv[], const char *outfile, bool append)
{
	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_t *actionsp = NULL;
	pid_t pid;
	int status, ret;
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
	while (waitpid(pid, &status, 0) == -1) {
		if (errno != EINTR)
			return -errno;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -EIO;
	return 0;

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
