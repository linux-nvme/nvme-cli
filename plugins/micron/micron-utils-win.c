// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */

#include <errno.h>
#include <stdio.h>
#include <windows.h>

#include <libnvme.h>

#include "micron-utils.h"
#include "util/cleanup.h"

int micron_get_pci_ids(struct libnvme_global_ctx *ctx,
			struct libnvme_transport_handle *hdl,
			unsigned short *vid, unsigned short *did)
{
	const char *p;
	unsigned int val;

	/* Windows sysfs dir for controller contains VID and DID */
	__cleanup_free char *ctrl_sysfs_dir = micron_get_ctrl_sysfs_dir(ctx, hdl);

	*vid = 0;
	*did = 0;

	if (!ctrl_sysfs_dir)
		return -EINVAL;

	p = strstr(ctrl_sysfs_dir, "ven_");
	if (p && sscanf(p, "ven_%x", &val) == 1)
		*vid = (unsigned short)val;
	else
		return -EINVAL;

	p = strstr(ctrl_sysfs_dir, "dev_");
	if (p && sscanf(p, "dev_%x", &val) == 1)
		*did = (unsigned short)val;
	else
		return -EINVAL;

	return 0;
}

int micron_get_pcie_aer_errors(struct libnvme_transport_handle *hdl,
	__u32 *correctable_errors, __u32 *uncorrectable_errors)
{
	*correctable_errors = 0;
	*uncorrectable_errors = 0;
	printf("register reads not supported on the current platform\n");
	return -ENOTSUP;
}

int micron_clear_pcie_aer_correctable_errors(
	struct libnvme_transport_handle *hdl)
{
	printf("register writes not supported on the current platform\n");
	return -ENOTSUP;
}

static void write_section_header(FILE *fp, const char *header)
{
	fprintf(fp, "\n\n\n\n%s\n-----------------------------------------------\n",
		header);
}

void micron_write_os_config_to_file(const char *file_name)
{
	FILE *fp = NULL;
	OSVERSIONINFOEXA osvi;
	SYSTEM_INFO si;
	MEMORYSTATUSEX memstat;
	DWORD bufSize;
	char compName[256] = { 0 };
	HKEY hKey;
	LONG rc;

	fp = fopen(file_name, "w+");
	if (!fp) {
		fprintf(stderr, "Failed to create %s\n", file_name);
		return;
	}

	/* System Information */
	write_section_header(fp, "SYSTEM INFORMATION");

	memset(&osvi, 0, sizeof(osvi));
	osvi.dwOSVersionInfoSize = sizeof(osvi);
	/*
	 * GetVersionExA is deprecated but available everywhere.
	 * It returns capped values on newer Windows unless the
	 * application is manifested, which is acceptable here.
	 */
	if (GetVersionExA((OSVERSIONINFOA *)&osvi)) {
		fprintf(fp, "Windows Version   : %lu.%lu Build %lu",
			osvi.dwMajorVersion, osvi.dwMinorVersion,
			osvi.dwBuildNumber);
		if (osvi.szCSDVersion[0])
			fprintf(fp, " %s", osvi.szCSDVersion);
		fprintf(fp, "\n");
	}

	bufSize = sizeof(compName);
	if (GetComputerNameExA(ComputerNameDnsFullyQualified,
			       compName, &bufSize))
		fprintf(fp, "Computer Name     : %s\n", compName);

	GetNativeSystemInfo(&si);
	fprintf(fp, "Processor Arch    : ");
	switch (si.wProcessorArchitecture) {
	case PROCESSOR_ARCHITECTURE_AMD64:
		fprintf(fp, "x64 (AMD64)\n");
		break;
	case PROCESSOR_ARCHITECTURE_ARM64:
		fprintf(fp, "ARM64\n");
		break;
	case PROCESSOR_ARCHITECTURE_INTEL:
		fprintf(fp, "x86\n");
		break;
	default:
		fprintf(fp, "Unknown (%u)\n", si.wProcessorArchitecture);
		break;
	}
	fprintf(fp, "Number of Processors : %lu\n", si.dwNumberOfProcessors);
	fprintf(fp, "Page Size         : %lu\n", si.dwPageSize);

	/* Memory Information */
	write_section_header(fp, "SYSTEM MEMORY INFORMATION");

	memstat.dwLength = sizeof(memstat);
	if (GlobalMemoryStatusEx(&memstat)) {
		fprintf(fp, "Memory Load       : %lu%%\n", memstat.dwMemoryLoad);
		fprintf(fp, "Total Physical    : %llu MB\n",
			memstat.ullTotalPhys / (1024 * 1024));
		fprintf(fp, "Available Physical: %llu MB\n",
			memstat.ullAvailPhys / (1024 * 1024));
		fprintf(fp, "Total Page File   : %llu MB\n",
			memstat.ullTotalPageFile / (1024 * 1024));
		fprintf(fp, "Available Page File: %llu MB\n",
			memstat.ullAvailPageFile / (1024 * 1024));
		fprintf(fp, "Total Virtual     : %llu MB\n",
			memstat.ullTotalVirtual / (1024 * 1024));
		fprintf(fp, "Available Virtual : %llu MB\n",
			memstat.ullAvailVirtual / (1024 * 1024));
	}

	/* CPU Information from registry */
	write_section_header(fp, "CPU INFORMATION");

	rc = RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
		0, KEY_READ, &hKey);
	if (rc == ERROR_SUCCESS) {
		char cpuName[256] = { 0 };
		char cpuVendor[64] = { 0 };
		DWORD cpuMHz = 0;
		DWORD dataSize;

		dataSize = sizeof(cpuName);
		if (RegQueryValueExA(hKey, "ProcessorNameString", NULL,
				     NULL, (LPBYTE)cpuName,
				     &dataSize) == ERROR_SUCCESS)
			fprintf(fp, "Processor         : %s\n", cpuName);

		dataSize = sizeof(cpuVendor);
		if (RegQueryValueExA(hKey, "VendorIdentifier", NULL,
				     NULL, (LPBYTE)cpuVendor,
				     &dataSize) == ERROR_SUCCESS)
			fprintf(fp, "Vendor            : %s\n", cpuVendor);

		dataSize = sizeof(cpuMHz);
		if (RegQueryValueExA(hKey, "~MHz", NULL, NULL,
				     (LPBYTE)&cpuMHz,
				     &dataSize) == ERROR_SUCCESS)
			fprintf(fp, "Speed             : %lu MHz\n", cpuMHz);

		RegCloseKey(hKey);
	}
	fprintf(fp, "Logical Processors: %lu\n", si.dwNumberOfProcessors);

	fclose(fp);
}
