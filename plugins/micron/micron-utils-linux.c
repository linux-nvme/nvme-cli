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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/klog.h>
#include <sys/utsname.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>

#include <shared/fs-util.h>
#include <shared/io-util.h>
#include <shared/proc-util.h>

#include "micron-utils.h"
#include "nvme-print.h"
#include "src/cleanup.h"
#include "src/global-ctx.h"

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
	__cleanup_free char *ctrl_dir = NULL;
	__cleanup_free char *addr_path = NULL;
	__cleanup_free char *dev_path = NULL;
	char target[512];
	ssize_t n;
	int fd;
	int err;
	char *slash;

	if (!ctrl_name)
		return -EINVAL;

	err = nvme_sysfs_ctrl_path(ctrl_name, &ctrl_dir);
	if (err)
		return err;

	/*
	 * If possible, use /sys/class/nvme/<ctrl>/address (kernel >= 4.13).
	 * On failure, fall back to using the /device symlink.
	 */
	if (asprintf(&addr_path, "%s/address", ctrl_dir) < 0)
		return -ENOMEM;

	fd = open(addr_path, O_RDONLY);
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
	if (asprintf(&dev_path, "%s/device", ctrl_dir) < 0)
		return -ENOMEM;

	n = readlink(dev_path, target, sizeof(target) - 1);
	if (n < 0) {
		err = -errno;
		nvme_show_perror("%s", dev_path);
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
	shr_proc_t proc;
	int fds[2];
	bool exited;
	int code;
	int ret;
	int err;

	if (!out || out_len == 0)
		return -EINVAL;

	out[0] = '\0';

	ret = shr_pipe(fds);
	if (ret)
		return ret;

	/* Child: stdout to the pipe write end; stderr inherited. */
	ret = shr_spawnp((const char *const *)argv, fds[1], -1, &proc);
	close(fds[1]); /* only the child holds a writer now */
	if (ret) {
		close(fds[0]);
		return ret;
	}

	/* Parent: read the child's output, always draining to EOF. */
	err = shr_read_all(fds[0], out, out_len);
	close(fds[0]);

	ret = shr_wait_proc(proc, &exited, &code);
	if (ret)
		return err ? err : ret;

	if (err)
		return err;

	return (exited && code == 0) ? 0 : -EIO;
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

/* Generous but bounded: this is a human-readable support dump, not a
 * guarantee of capturing every byte of a possibly huge /proc file or log.
 */
#define OS_CONFIG_CAPTURE_MAX (1 << 20)

static int append_file_contents(int out_fd, const char *path)
{
	__cleanup_fd int fd = open(path, O_RDONLY);
	__cleanup_free char *buf = NULL;
	int ret;

	if (fd < 0)
		return -errno;

	buf = malloc(OS_CONFIG_CAPTURE_MAX);
	if (!buf)
		return -ENOMEM;

	ret = shr_read_all(fd, buf, OS_CONFIG_CAPTURE_MAX);
	if (ret)
		return ret;

	return shr_write_all(out_fd, buf, strlen(buf));
}

static int append_uname(int out_fd)
{
	struct utsname uts;
	char line[512];
	int n;

	if (uname(&uts))
		return -errno;

	n = snprintf(line, sizeof(line), "%s %s %s %s %s\n",
		     uts.sysname, uts.nodename, uts.release, uts.version,
		     uts.machine);
	if (n < 0)
		return -errno;
	if ((size_t)n >= sizeof(line))
		n = sizeof(line) - 1;

	return shr_write_all(out_fd, line, (size_t)n);
}

/*
 * man 2 syslog documents these action numbers; <sys/klog.h> declares
 * klogctl() but, oddly, not the actions it takes.
 */
#define SYSLOG_ACTION_READ_ALL     3
#define SYSLOG_ACTION_SIZE_BUFFER 10

static int append_dmesg(int out_fd)
{
	__cleanup_free char *buf = NULL;
	int len;

	len = klogctl(SYSLOG_ACTION_SIZE_BUFFER, NULL, 0);
	if (len <= 0 || len > OS_CONFIG_CAPTURE_MAX)
		len = OS_CONFIG_CAPTURE_MAX;

	buf = malloc(len);
	if (!buf)
		return -ENOMEM;

	len = klogctl(SYSLOG_ACTION_READ_ALL, buf, len);
	if (len < 0)
		return -errno;

	return shr_write_all(out_fd, buf, (size_t)len);
}

enum os_config_kind {
	OS_CONFIG_FILE,
	OS_CONFIG_UNAME,
	OS_CONFIG_DMESG,
};

struct os_config_item {
	const char *header;
	enum os_config_kind kind;
	const char *path;
};

static const struct os_config_item os_config_items[] = {
	{ "SYSTEM INFORMATION", OS_CONFIG_UNAME, NULL },
	{ "LINUX KERNEL MODULE INFORMATION", OS_CONFIG_FILE, "/proc/modules" },
	{ "LINUX SYSTEM MEMORY INFORMATION", OS_CONFIG_FILE, "/proc/meminfo" },
	{ "SYSTEM INTERRUPT INFORMATION", OS_CONFIG_FILE, "/proc/interrupts" },
	{ "CPU INFORMATION", OS_CONFIG_FILE, "/proc/cpuinfo" },
	{ "IO MEMORY MAP INFORMATION", OS_CONFIG_FILE, "/proc/iomem" },
	{ "MAJOR NUMBER AND DEVICE GROUP", OS_CONFIG_FILE, "/proc/devices" },
	{ "KERNEL DMESG", OS_CONFIG_DMESG, NULL },
	{ "/VAR/LOG/MESSAGES", OS_CONFIG_FILE, "/var/log/messages" },
};

void micron_write_os_config_to_file(const char *file_name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(os_config_items); i++) {
		const struct os_config_item *item = &os_config_items[i];
		__cleanup_fd int out_fd = -1;
		FILE *header_file;
		int ret;

		header_file = fopen(file_name, "a+");
		if (header_file) {
			fprintf(header_file,
				"\n\n\n\n%s\n-----------------------------------------------\n",
				item->header);
			fclose(header_file);
		}

		out_fd = shr_open_rawdata(file_name,
					   O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (out_fd < 0) {
			nvme_show_error("Failed to open \"%s\": %s",
				file_name, strerror(errno));
			continue;
		}

		switch (item->kind) {
		case OS_CONFIG_UNAME:
			ret = append_uname(out_fd);
			break;
		case OS_CONFIG_DMESG:
			ret = append_dmesg(out_fd);
			break;
		case OS_CONFIG_FILE:
		default:
			ret = append_file_contents(out_fd, item->path);
			break;
		}
		if (ret)
			nvme_show_error("Failed to capture \"%s\": %s",
				item->header, strerror(-ret));
	}
}

void micron_get_os_string(char *buf, size_t len)
{
	struct utsname un;

	if (!buf || !len)
		return;
	buf[0] = '\0';

	if (uname(&un))
		return;

	snprintf(buf, len, "%s %s %s", un.sysname, un.release, un.machine);
}
