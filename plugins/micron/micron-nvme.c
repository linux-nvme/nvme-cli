// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) Micron, Inc 2024.
 *
 * @file: micron-nvme.c
 * @brief: This module contains all the constructs needed for micron nvme-cli plugin.
 * @authors:Hanumanthu H <hanumanthuh@micron.com>
 *			Chaithanya Shoba <ashoba@micron.com>
 *			Sivaprasad Gutha <sivaprasadg@micron.com>
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#include <libnvme.h>

#include "common.h"
#include "nvme-cmds.h"
#include "nvme-print.h"
#include "nvme.h"
#include "util/cleanup.h"
#include "util/types.h"
#include "util/utils.h"

#define CREATE_CMD
#include "micron-nvme.h"
#include "micron-utils.h"

/* Supported Vendor specific feature ids */
#define MICRON_FEATURE_CLEAR_PCI_CORRECTABLE_ERRORS    0xC3
#define MICRON_FEATURE_CLEAR_FW_ACTIVATION_HISTORY     0xC1
#define MICRON_FEATURE_TELEMETRY_CONTROL_OPTION        0xCF
#define MICRON_FEATURE_SMBUS_OPTION                    0xD5
#define MICRON_FEATURE_OCP_ENHANCED_TELEMETRY          0x16

/* Micron Supported Customer ID*/
#define MICRON_CUST_ID_GENERAL 0x10
#define MICRON_CUST_ID_GG  0x16

/* Supported Vendor specific log page sizes */
#define C5_log_size (((452 + 16 * 1024) / 4) * 4096)
#define C0_log_size 512
#define C2_log_size 4096
#define D0_log_size 512
#define FB_log_size 512
#define E1_log_size 256
#define MaxLogChunk (16 * 1024)
#define CommonChunkSize (16 * 4096)
#define C6_log_size 512
#define C5_MicronWorkLoad_log_size 256

#define SensorCount 8

/* Plugin version major_number.minor_number.patch */
static const char *__version_major = "2";
static const char *__version_minor = "1";
static const char *__version_patch = "0";

/*
 * supported models of micron plugin; new models should be added at the end
 * before UNKNOWN_MODEL. Make sure M5410 is first in the list !
 */
enum eDriveModel {
	M5410 = 0,
	M51AX,
	M51BX,
	M51BY,
	M51CY,
	M51CX,
	M5407,
	M5411,
	M6001,
	M6003,
	M6004,
	UNKNOWN_MODEL
};

#define MICRON_VENDOR_ID 0x1344

static unsigned short vendor_id;
static unsigned short device_id;

/* Additional log page IDs */
#define NVME_LOG_PERSISTENT_EVENT 0xD

struct LogPageHeader_t {
	unsigned char numDwordsInLogPageHeaderLo;
	unsigned char logPageHeaderFormatVersion;
	unsigned char logPageId;
	unsigned char numDwordsInLogPageHeaderHi;
	unsigned int numValidDwordsInPayload;
	unsigned int numDwordsInEntireLogPage;
};

struct MICRON_WORKLOAD_LOG_HDR {
	unsigned short usNumEntries;
	unsigned short usVersion;
	unsigned int uiLength;
};

static void WriteData(__u8 *data, __u32 len, const char *dir, const char *file, const char *msg)
{
	__cleanup_free char *tempFolder = NULL;
	FILE *fpOutFile = NULL;

	if (asprintf(&tempFolder, "%s/%s", dir, file) < 0) {
		nvme_show_error("Failed to allocate memory for temp folder path");
		return;
	}
	fpOutFile = fopen(tempFolder, "ab+");
	if (fpOutFile) {
		if (fwrite(data, 1, len,  fpOutFile) != len)
			nvme_show_error("Failed to write %s data to %s", msg, tempFolder);
		fclose(fpOutFile);
	} else	{
		nvme_show_error("Failed to open %s file to write %s", tempFolder, msg);
	}
}

static enum eDriveModel GetDriveModel(
	struct libnvme_global_ctx *ctx,
	struct libnvme_transport_handle *hdl)
{
	enum eDriveModel eModel = UNKNOWN_MODEL;

	micron_get_pci_ids(ctx, hdl, &vendor_id, &device_id);

	if (vendor_id == MICRON_VENDOR_ID) {
		switch (device_id) {
		case 0x5196:
		case 0x51A0:
		case 0x51A1:
		case 0x51A2:
			eModel = M51AX;
			break;
		case 0x51B0:
		case 0x51B1:
		case 0x51B2:
			eModel = M51BX;
			break;
		case 0x51B7:
		case 0x51B8:
		case 0x51B9:
			eModel = M51BY;
			break;
		case 0x51BB:
		case 0x51BD:
		case 0x51BC:
		case 0x51BE:
		case 0x51BF:
		case 0x51C8:
		case 0x51C9:
		case 0x51CA:
		case 0x51CB:
		case 0x51CC:
		case 0x51CD:
		case 0x51CE:
			eModel = M51CY;
			break;
		case 0x51C0:
		case 0x51C1:
		case 0x51C2:
		case 0x51C3:
		case 0x51C4:
			eModel = M51CX;
			break;
		case 0x5405:
		case 0x5406:
		case 0x5407:
			eModel = M5407;
			break;
		case 0x5410:
			eModel = M5410;
			break;
		case 0x5411:
			eModel = M5411;
			break;
		case 0x6001:
			eModel = M6001;
			break;
		case 0x6004:
			eModel = M6004;
			break;
		case 0x6003:
			eModel = M6003;
			break;
		default:
			break;
		}
	}
	return eModel;
}

/*
 * sanitize_serial - trim trailing spaces, null-terminate, and replace any
 * characters that are not alphanumeric, hyphen, or underscore with underscores.
 */
static void sanitize_serial(char *sn, size_t len)
{
	size_t i;
	size_t end;

	if (!sn || len == 0)
		return;

	end = len - 1;
	while (end > 0 && isblank((unsigned char)sn[end - 1]))
		end--;
	sn[end] = '\0';

	for (i = 0; i < end; i++) {
		if (!((sn[i] >= 'A' && sn[i] <= 'Z') ||
		      (sn[i] >= 'a' && sn[i] <= 'z') ||
		      (sn[i] >= '0' && sn[i] <= '9') ||
		      sn[i] == '-' || sn[i] == '_'))
			sn[i] = '_';
	}
}

/*
 * is_safe_path - validate that a path string is safe for use as a filename.
 *
 * Rejects control characters (0x00-0x1F), characters invalid on Windows
 * filesystems (<>"|?*), paths starting with '-' which could be
 * misinterpreted as flags by tar/zip, and trailing backslashes which
 * would escape the closing quote in Windows command-line argument parsing.
 */
static bool is_safe_path(const char *path)
{
	/* Lookup table: 1 = rejected character */
	static const unsigned char rejected[256] = {
		[0x01 ... 0x1F] = 1,	/* control characters */
		['<']  = 1,
		['>']  = 1,
		['"']  = 1,
		['|']  = 1,
		['?']  = 1,
		['*']  = 1,
	};
	const unsigned char *p = (const unsigned char *)path;

	if (!path || !*path)
		return false;

	if (path[0] == '-')
		return false;

	for (; *p; p++) {
		if (rejected[*p])
			return false;
	}

	if (p > (const unsigned char *)path && p[-1] == '\\')
		return false;

	return true;
}

/*
 * Recursively remove a directory and its contents.
 * Since this is only used for temporary directories that we create that
 * have no symlinks, it is safe to not check for and handle symlinks here.
 */
static int RemoveDirRecursive(const char *path)
{
	DIR *dir = NULL;
	struct dirent *entry;
	char child[PATH_MAX];

	dir = opendir(path);
	if (!dir) {
		if (errno == ENOENT)
			return 0;
		return -1;
	}

	while ((entry = readdir(dir))) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;

		if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >=
		    (int)sizeof(child)) {
			errno = ENAMETOOLONG;
			closedir(dir);
			return -1;
		}

		if (unlink(child) == 0 || errno == ENOENT)
			continue;

		/*
		 * On Linux, unlinking a directory fails with EISDIR or EPERM.
		 * On Windows, it fails with EACCES. In all cases, fall through
		 * to attempt recursive removal.
		 */
		if (errno != EISDIR && errno != EPERM && errno != EACCES) {
			closedir(dir);
			return -1;
		}

		if (RemoveDirRecursive(child) < 0) {
			if (errno == ENOENT)
				continue;
			closedir(dir);
			return -1;
		}
	}

	closedir(dir);

	if (rmdir(path) < 0 && errno != ENOENT)
		return -1;

	return 0;
}

/*
 * bsdtar-based versions of tar support creating zip archives when -a is used
 * with a .zip extension. Check if bsdtar is available and use it to create the
 * requested zip archive.
 *
 * Returns 0 on success, or a negative errno value if tar is not bsdtar
 * or if the command fails.
 */
static int ZipWithBsdTar(char *strDirName, char *strFileName)
{
	FILE *fpVersion = NULL;
	char version_buf[256] = { 0 };
	bool is_bsdtar = false;

	fpVersion = popen("tar --version 2>&1", "r");
	if (!fpVersion)
		return -EINVAL;

	while (fgets(version_buf, sizeof(version_buf), fpVersion)) {
		if (strstr(version_buf, "bsdtar")) {
			is_bsdtar = true;
			break;
		}
	}

	if (pclose(fpVersion))
		return -EINVAL;
	fpVersion = NULL;

	if (!is_bsdtar)
		return -EINVAL;

	char *argv[] = {"tar", "-caf", strFileName, "--", strDirName, NULL};

	return micron_run_spawn(argv, NULL, false);
}

static int ZipAndRemoveDir(char *strDirName, char *strFileName)
{
	int  err = 0;
	int  nRet;
	bool is_tgz = false;
	struct stat sb;

	if (strstr(strFileName, ".tar.gz") || strstr(strFileName, ".tgz")) {
		char *argv[] = {"tar", "-zcf", strFileName, "--", strDirName, NULL};

		is_tgz = true;
		nRet = micron_run_spawn(argv, NULL, false);
	} else {
		char *argv[] = {"zip", "-r", strFileName, "--", strDirName, NULL};

		nRet = micron_run_spawn(argv, NULL, false);
	}

	if (nRet && !is_tgz)
		/* if zip is not available, see if tar can be used instead */
		nRet = ZipWithBsdTar(strDirName, strFileName);

	/* check if log file is created, if not print error message */
	if (nRet || (stat(strFileName, &sb) == -1)) {
		err = -EINVAL;
		if (is_tgz)
			nvme_show_error("Failed to create log data package, "
				"check if tar and gzip commands are installed!\n");
		else
			nvme_show_error("Failed to create log data package, "
				"check if zip command is installed!\n");
	}

	if (RemoveDirRecursive(strDirName) < 0)
		nvme_show_error("Failed to remove temporary files!");

	return err;
}

static int SetupDebugDataDirectories(char *strSN, char *strFilePath,
					 char *strMainDirName, size_t mainDirSize,
					 char *strOSDirName, size_t osDirSize,
					 char *strCtrlDirName, size_t ctrlDirSize)
{
	int err = 0;
	struct stat st;
	char *fileLocation = NULL;
	char *fileName;
	int length = 0;
	int nIndex = 0;
	char *strTemp = NULL;
	int j;
	int k = 0;

	if (strchr(strFilePath, '/')) {
		fileName = strrchr(strFilePath, '\\');
		if (!fileName)
			fileName = strrchr(strFilePath, '/');

		if (fileName) {
			if (!strcmp(fileName, "/"))
				goto exit_status;

			while (strFilePath[nIndex] != '\0') {
				if ('\\' == strFilePath[nIndex] && '\\' == strFilePath[nIndex + 1])
					goto exit_status;
				nIndex++;
			}

			length = (int)strlen(strFilePath) - (int)strlen(fileName);

			if (fileName == strFilePath)
				length = 1;

			fileLocation = (char *)malloc(length + 1);
			if (!fileLocation)
				goto exit_status;
			strncpy(fileLocation, strFilePath, length);
			fileLocation[length] = '\0';

			while (fileLocation[k] != '\0') {
				if (fileLocation[k] == '\\')
					fileLocation[k] = '/';
				k++;
			}

			length = (int)strlen(fileLocation);

			if (':' == fileLocation[length - 1]) {
				strTemp = realloc(fileLocation, length + 2);

				if (!strTemp) {
					free(fileLocation);
					goto exit_status;
				}
				fileLocation = strTemp;
				fileLocation[length] = '/';
				fileLocation[length + 1] = '\0';
				length++;
			}

			if (stat(fileLocation, &st)) {
				free(fileLocation);
				goto exit_status;
			}
			free(fileLocation);
		} else {
			goto exit_status;
		}
	}

	snprintf(strMainDirName, mainDirSize, "%s", strSN);
	nIndex = strlen(strMainDirName);

	j = 1;
	while (mkdir(strMainDirName, 0700) < 0) {
		if (errno != EEXIST) {
			err = -1;
			goto exit_status;
		}
		strMainDirName[nIndex] = '\0';
		snprintf(strMainDirName + nIndex, mainDirSize - nIndex, "-%d", j);
		j++;
	}

	if (strOSDirName) {
		snprintf(strOSDirName, osDirSize, "%s/%s", strMainDirName, "OS");
		if (mkdir(strOSDirName, 0700) < 0) {
			rmdir(strMainDirName);
			err = -1;
			goto exit_status;
		}
	}
	if (strCtrlDirName) {
		snprintf(strCtrlDirName, ctrlDirSize, "%s/%s", strMainDirName, "Controller");
		if (mkdir(strCtrlDirName, 0700) < 0) {
			if (strOSDirName)
				rmdir(strOSDirName);
			rmdir(strMainDirName);
			err = -1;
		}
	}

exit_status:
	return err;
}

static int GetLogPageSize(struct libnvme_transport_handle *hdl, unsigned char ucLogID, int *nLogSize)
{
	int err = 0;
	unsigned char pTmpBuf[CommonChunkSize] = { 0 };
	struct LogPageHeader_t *pLogHeader = NULL;

	if (ucLogID == 0xC1 || ucLogID == 0xC2 || ucLogID == 0xC4) {
		err = nvme_get_log_simple(hdl, ucLogID, pTmpBuf, CommonChunkSize);
		if (!err) {
			pLogHeader = (struct LogPageHeader_t *) pTmpBuf;
			struct LogPageHeader_t *pLogHeader1 = (struct LogPageHeader_t *) pLogHeader;
			*nLogSize = (int)(pLogHeader1->numDwordsInEntireLogPage) * 4;
			if (!pLogHeader1->logPageHeaderFormatVersion) {
				nvme_show_error("Unsupported log page format version %d of log page : 0x%X",
					   ucLogID, err);
				*nLogSize = 0;
				err = -1;
			}
		} else {
			nvme_show_error("Getting size of log page : 0x%X failed with %d (ignored)!",
					 ucLogID, err);
			*nLogSize = 0;
		}
	}
	return err;
}

static int NVMEGetLogPage(struct libnvme_transport_handle *hdl, unsigned char ucLogID, unsigned char *pBuffer, int nBuffSize,
			  int offset)
{
	int err = 0;
	struct libnvme_passthru_cmd cmd = { 0 };
	unsigned int uiNumDwords = (unsigned int)nBuffSize / sizeof(unsigned int);
	unsigned int uiMaxChunk = uiNumDwords;
	unsigned int uiNumChunks = 1;
	unsigned int uiXferDwords = 0;
	unsigned long long ullBytesRead = offset;
	unsigned char *pTempPtr = pBuffer;
	unsigned char ucOpCode = 0x02;

	if (!ullBytesRead && (ucLogID == 0xE6 || ucLogID == 0xE7))
		uiMaxChunk = 4096;
	else if (uiMaxChunk > 16 * 1024)
		uiMaxChunk = 16 * 1024;

	if (ucLogID == 0xE9) {
		uiMaxChunk = 0x1D8C;
		ullBytesRead = offset;
	}

	uiNumChunks = uiNumDwords / uiMaxChunk;
	if (uiNumDwords % uiMaxChunk > 0)
		uiNumChunks += 1;

	for (unsigned int i = 0; i < uiNumChunks; i++) {
		memset(&cmd, 0, sizeof(cmd));
		uiXferDwords = uiMaxChunk;
		if (i == uiNumChunks - 1 && uiNumDwords % uiMaxChunk > 0)
			uiXferDwords = uiNumDwords % uiMaxChunk;

		cmd.opcode = ucOpCode;
		cmd.cdw10 |= ucLogID;
		cmd.cdw10 |= ((uiXferDwords - 1) & 0x0000FFFF) << 16;

		if (ucLogID == 0x7 && offset == 0)
			cmd.cdw10 |= 0x100;

		if (!ullBytesRead && (ucLogID == 0xE6 || ucLogID == 0xE7))
			cmd.cdw11 = 1;
		if (ullBytesRead > 0 && !(ucLogID == 0xE6 || ucLogID == 0xE7)) {
			unsigned long long ullOffset = ullBytesRead;

			cmd.cdw12 = ullOffset & 0xFFFFFFFF;
			cmd.cdw13 = (ullOffset >> 32) & 0xFFFFFFFF;
		}

		cmd.addr = (__u64) (uintptr_t) pTempPtr;
		cmd.nsid = 0xFFFFFFFF;
		cmd.data_len = uiXferDwords * 4;
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		ullBytesRead += uiXferDwords * 4;
		if (ucLogID == 0x07 || ucLogID == 0x08 || ucLogID == 0xE9)
			pTempPtr = pBuffer + (ullBytesRead - offset);
		else
			pTempPtr = pBuffer + ullBytesRead;
	}

	return err;
}

static int NVMEResetLog(struct libnvme_transport_handle *hdl, unsigned char ucLogID, int nBufferSize,
			long long llMaxSize)
{
	__cleanup_libnvme_free unsigned int *pBuffer = NULL;
	int err = 0;

	pBuffer = (unsigned int *)libnvme_alloc(nBufferSize);
	if (!pBuffer)
		return err;

	while (!err && llMaxSize > 0) {
		err = NVMEGetLogPage(hdl, ucLogID, (unsigned char *)pBuffer, nBufferSize, 0);
		if (err)
			return err;

		if (pBuffer[0] == 0xdeadbeef)
			break;

		llMaxSize = llMaxSize - nBufferSize;
	}

	return err;
}

static int GetCommonLogPage(struct libnvme_transport_handle *hdl, unsigned char ucLogID,
			    unsigned char **pBuffer, int nBuffSize)
{
	unsigned char *pTempPtr = NULL;
	int err = 0;

	pTempPtr = (unsigned char *)libnvme_alloc(nBuffSize);
	if (!pTempPtr) {
		err = -ENOMEM;
		goto exit_status;
	}
	err = nvme_get_log_simple(hdl, ucLogID, pTempPtr, nBuffSize);
	*pBuffer = pTempPtr;

exit_status:
	return err;
}

/*
 * Plugin Commands
 */
static int micron_parse_options(struct libnvme_global_ctx **ctx,
				struct libnvme_transport_handle **hdl, int argc,
				char **argv, const char *desc,
				struct argconfig_commandline_options *opts,
				enum eDriveModel *modelp)
{
	int err = parse_and_open(ctx, hdl, argc, argv, desc, opts);

	if (err) {
		nvme_show_err(err, "open");
		return -1;
	}

	if (modelp)
		*modelp = GetDriveModel(*ctx, *hdl);

	return 0;
}

static int micron_fw_commit(struct libnvme_transport_handle *hdl, int select)
{
	struct libnvme_passthru_cmd cmd = {
		.opcode = nvme_admin_fw_commit,
		.cdw10 = 8,
		.cdw12 = select,
	};

	return libnvme_exec_admin_passthru(hdl, &cmd);
}

static int micron_selective_download(int argc, char **argv,
					 struct command *command, struct plugin *plugin)
{
	const char *desc =
		"This performs a selective firmware download, which allows the user to\n"
		"select which firmware binary to update for 9200 devices. This requires\n"
		"a power cycle once the update completes. The options available are:\n\n"
		"OOB - This updates the OOB and main firmware\n"
		"EEP - This updates the eeprom and main firmware\n"
		"ALL - This updates the eeprom, OOB, and main firmware";
	const char *fw = "firmware file (required)";
	const char *select = "FW Select (e.g., --select=ALL)";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;

	int selectNo, fw_fd, fw_size, err, offset = 0;
	struct libnvme_passthru_cmd cmd;
	int xfer = 4096;
	struct stat sb;
	__cleanup_libnvme_free void *fw_buf = NULL;
	unsigned char *fw_ptr;

	struct config {
		char *fw;
		char *select;
	};

	struct config cfg = {
		.fw = "",
		.select = "\0",
	};

	NVME_ARGS(opts,
		OPT_STRING("fw", 'f', "FILE", &cfg.fw, fw),
		OPT_STRING("select", 's', "flag", &cfg.select, select));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (strlen(cfg.select) != 3) {
		nvme_show_error("Invalid select flag");
		return -EINVAL;
	}

	for (int i = 0; i < 3; i++)
		cfg.select[i] = toupper(cfg.select[i]);

	if (!strncmp(cfg.select, "OOB", 3)) {
		selectNo = 18;
	} else if (!strncmp(cfg.select, "EEP", 3)) {
		selectNo = 10;
	} else if (!strncmp(cfg.select, "ALL", 3)) {
		selectNo = 26;
	} else {
		nvme_show_error("Invalid select flag");
		return -EINVAL;
	}

	fw_fd = open(cfg.fw, O_RDONLY);
	if (fw_fd < 0) {
		nvme_show_error("no firmware file provided");
		return -EINVAL;
	}

	err = fstat(fw_fd, &sb);
	if (err < 0) {
		nvme_show_perror("fstat");
		err = errno;
		goto out;
	}

	fw_size = sb.st_size;
	if (fw_size & 0x3) {
		nvme_show_error("Invalid size:%d for f/w image", fw_size);
		err = EINVAL;
		goto out;
	}

	fw_buf = libnvme_alloc(fw_size);
	if (!fw_buf) {
		nvme_show_error("No memory for f/w size:%d", fw_size);
		err = ENOMEM;
		goto out;
	}
	fw_ptr = fw_buf;

	if (read(fw_fd, fw_buf, fw_size) != ((ssize_t) (fw_size))) {
		err = errno;
		goto out;
	}

	while (fw_size > 0) {
		xfer = min(xfer, fw_size);

		err = nvme_init_fw_download(&cmd, fw_ptr, xfer, offset);
		if (err) {
			nvme_show_err(err, "fw-download");
			goto out;
		}
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		if (err) {
			nvme_show_err(err, "fw-download");
			goto out;
		}
		fw_ptr += xfer;
		fw_size -= xfer;
		offset += xfer;
	}

	err = micron_fw_commit(hdl, selectNo);

	if (err == 0x10B || err == 0x20B) {
		err = 0;
		nvme_show_error(
			"Update successful! Power cycle for changes to take effect\n");
	}

out:
	close(fw_fd);
	return err;
}

static int micron_smbus_option(int argc, char **argv,
				   struct command *command, struct plugin *plugin)
{
	__u64 result = 0;
	__u32 cdw11 = 0;
	const char *desc = "Enable/Disable/Get status of SMBUS option on controller";
	const char *option = "enable or disable or status";
	const char *value =
		"1 - hottest component temperature, 0 - composite temperature (default) for enable option, 0 (current), 1 (default), 2 (saved) for status options";

	const char *save = "1 - persistent, 0 - non-persistent (default)";
	int fid = MICRON_FEATURE_SMBUS_OPTION;
	enum eDriveModel model = UNKNOWN_MODEL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err = 0;

	struct {
		char *option;
		int  value;
		int  save;
		int  status;
	} opt = {
		.option = "disable",
		.value = 0,
		.save = 0,
		.status = 0,
	};

	NVME_ARGS(opts,
		OPT_STRING("option", 'O', "option", &opt.option, option),
		OPT_UINT("value", 'V',	&opt.value, value),
		OPT_UINT("save", 's', &opt.save, save));

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &model);
	if (err < 0)
		return err;

	if (model != M5407 && model != M5411 && model != M6003 && model != M6004) {
		nvme_show_error("This option is not supported for specified drive");
		return err;
	}

	if (!strcmp(opt.option, "enable")) {
		cdw11 = opt.value << 1 | 1;
		err = nvme_set_features_simple(hdl, 1, fid, opt.save, cdw11,
				&result);
		if (!err)
			nvme_show_verbose_result("successfully enabled SMBus on drive");
		else
			nvme_show_error("Failed to enabled SMBus on drive");
	} else if (!strcmp(opt.option, "status")) {
		err = nvme_get_features(hdl, 1, fid, opt.value, 0, 0, NULL, 0, &result);
		if (!err)
			printf("SMBus status on the drive: %s (returns %s temperature)\n",
				   (result & 1) ? "enabled" : "disabled",
				   (result & 2) ? "hottest component" : "composite");
		else
			nvme_show_error("Failed to retrieve SMBus status on the drive");
	} else if (!strcmp(opt.option, "disable")) {
		cdw11 = opt.value << 1 | 0;
		err = nvme_set_features_simple(hdl, 1, fid, opt.save, cdw11,
				&result);
		if (!err)
			nvme_show_verbose_result("Successfully disabled SMBus on drive");
		else
			nvme_show_error("Failed to disable SMBus on drive");
	} else {
		nvme_show_error("Invalid option %s, valid values are enable, disable or status",
			   opt.option);
		return -1;
	}

	return err;
}

static int micron_temp_stats(int argc, char **argv, struct command *acmd,
				 struct plugin *plugin)
{

	struct nvme_smart_log smart_log;
	unsigned int temperature = 0, i = 0, err = 0;
	unsigned int tempSensors[SensorCount] = { 0 };
	const char *desc = "Retrieve Micron temperature info for the given device ";
	const char *fmt = "output format normal|json";
	nvme_print_flags_t flags;
	struct format {
		char *fmt;
	};
	struct format cfg = {
		.fmt = "normal",
	};
	bool is_json = false;
	struct json_object *root;
	struct json_object *logPages;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	NVME_ARGS(opts,
		OPT_FMT("format", 'f', &cfg.fmt, fmt));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err) {
		nvme_show_error("Device not found");
		return -1;
	}

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!strcmp(cfg.fmt, "json") || flags & JSON)
		is_json = true;

	err = nvme_get_log_smart(hdl, NVME_NSID_ALL, &smart_log);
	if (!err) {
		temperature = ((smart_log.temperature[1] << 8) | smart_log.temperature[0]);
		temperature = temperature ? temperature - 273 : 0;
		for (i = 0; i < SensorCount && tempSensors[i]; i++) {
			tempSensors[i] = le16_to_cpu(smart_log.temp_sensor[i]);
			tempSensors[i] = tempSensors[i] ? tempSensors[i] - 273 : 0;
		}
		if (is_json) {
			struct json_object *stats = json_create_object();
			char tempstr[64] = { 0 };

			root = json_create_object();
			logPages = json_create_array();
			json_object_add_value_array(root, "Micron temperature information", logPages);
			sprintf(tempstr, "%u C", temperature);
			json_object_add_value_string(stats, "Current Composite Temperature", tempstr);
			for (i = 0; i < SensorCount && tempSensors[i]; i++) {
				char sensor_str[256] = { 0 };
				char datastr[64] = { 0 };

				sprintf(sensor_str, "Temperature Sensor #%d", (i + 1));
				sprintf(datastr, "%u C", tempSensors[i]);
				json_object_add_value_string(stats, sensor_str, datastr);
			}
			json_array_add_value_object(logPages, stats);
			json_print_object(root, NULL);
			printf("\n");
			json_free_object(root);
		} else {
			printf("Micron temperature information:\n");
			printf("%-10s : %u C\n", "Current Composite Temperature", temperature);
			for (i = 0; i < SensorCount && tempSensors[i]; i++)
				printf("%-10s%d : %u C\n", "Temperature Sensor #", i + 1, tempSensors[i]);
		}
	}
	return err;
}

struct pcie_error_counters {
	__u16 receiver_error;
	__u16 bad_tlp;
	__u16 bad_dllp;
	__u16 replay_num_rollover;
	__u16 replay_timer_timeout;
	__u16 advisory_non_fatal_error;
	__u16 DLPES;
	__u16 poisoned_tlp;
	__u16 FCPC;
	__u16 completion_timeout;
	__u16 completion_abort;
	__u16 unexpected_completion;
	__u16 receiver_overflow;
	__u16 malformed_tlp;
	__u16 ecrc_error;
	__u16 unsupported_request_error;
} pcie_error_counters = { 0 };

struct {
	const char *err;
	int  bit;
	int  val;
} pcie_correctable_errors[] = {
		{ (char *)"Unsupported Request Error Status (URES)", 20,
		offsetof(struct pcie_error_counters, unsupported_request_error)},
		{ (char *)"ECRC Error Status (ECRCES)", 19,
		offsetof(struct pcie_error_counters, ecrc_error)},
		{ (char *)"Malformed TLP Status (MTS)", 18,
		offsetof(struct pcie_error_counters, malformed_tlp)},
		{ (char *)"Receiver Overflow Status (ROS)", 17,
		offsetof(struct pcie_error_counters, receiver_overflow)},
		{ (char *)"Unexpected Completion Status (UCS)", 16,
		offsetof(struct pcie_error_counters, unexpected_completion)},
		{ (char *)"Completer Abort Status (CAS)", 15,
		offsetof(struct pcie_error_counters, completion_abort)},
		{ (char *)"Completion Timeout Status (CTS)", 14,
		offsetof(struct pcie_error_counters, completion_timeout)},
		{ (char *)"Flow Control Protocol Error Status (FCPES)", 13,
		offsetof(struct pcie_error_counters, FCPC)},
		{ (char *)"Poisoned TLP Status (PTS)", 12,
		offsetof(struct pcie_error_counters, poisoned_tlp)},
		{ (char *)"Data Link Protocol Error Status (DLPES)", 4,
		offsetof(struct pcie_error_counters, DLPES)},
	},
	pcie_uncorrectable_errors[] = {
		{ (char *)"Advisory Non-Fatal Error Status (ANFES)", 13,
		offsetof(struct pcie_error_counters, advisory_non_fatal_error)},
		{ (char *)"Replay Timer Timeout Status (RTS)",	12,
		offsetof(struct pcie_error_counters, replay_timer_timeout)},
		{ (char *)"REPLAY_NUM Rollover Status (RRS)", 8,
		offsetof(struct pcie_error_counters, replay_num_rollover)},
		{ (char *)"Bad DLLP Status (BDS)", 7,
		offsetof(struct pcie_error_counters, bad_dllp)},
		{ (char *)"Bad TLP Status (BTS)", 6,
		offsetof(struct pcie_error_counters, bad_tlp)},
		{ (char *)"Receiver Error Status (RES)", 0,
		offsetof(struct pcie_error_counters, receiver_error)},
	};


static int micron_pcie_stats(int argc, char **argv,
				 struct command *command, struct plugin *plugin)
{
	int  i, err = 0;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	struct libnvme_passthru_cmd admin_cmd = { 0 };
	enum eDriveModel eModel = UNKNOWN_MODEL;
	bool is_json = true;
	bool counters = false;
	struct format {
		char *fmt;
	};
	const char *desc = "Retrieve PCIe event counters";
	const char *fmt = "output format json|normal";
	struct format cfg = {
		.fmt = "json",
	};

	__u32 correctable_errors = 0;
	__u32 uncorrectable_errors = 0;

	NVME_ARGS(opts,
		OPT_FMT("format", 'f', &cfg.fmt, fmt));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err) {
		nvme_show_error("Device not found");
		return -1;
	}

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	/* pull log details based on the model name */
	eModel = GetDriveModel(ctx, hdl);
	if (eModel == UNKNOWN_MODEL) {
		nvme_show_error("Unsupported drive model for vs-pcie-stats command");
		goto out;
	}

	if (!strcmp(cfg.fmt, "normal") || flags & NORMAL)
		is_json = false;

	if (eModel == M5407) {
		admin_cmd.opcode = 0xD6;
		admin_cmd.addr = (__u64)(uintptr_t)&pcie_error_counters;
		admin_cmd.data_len = sizeof(pcie_error_counters);
		admin_cmd.cdw10 = 1;
		err = libnvme_exec_admin_passthru(hdl, &admin_cmd);
		if (!err) {
			counters = true;
			correctable_errors = 10;
			uncorrectable_errors = 6;
			goto print_stats;
		}
	}

	err = micron_get_pcie_aer_errors(hdl, &correctable_errors,
					&uncorrectable_errors);
	if (err)
		goto out;
print_stats:
	if (is_json) {
		struct json_object *root = json_create_object();
		struct json_object *pcieErrors = json_create_array();
		struct json_object *stats = json_create_object();
		__u8 *pcounter = (__u8 *)&pcie_error_counters;

		json_object_add_value_array(root, "PCIE Stats", pcieErrors);
		for (i = 0; i < ARRAY_SIZE(pcie_correctable_errors); i++) {
			__u16 val = counters ? *(__u16 *)(pcounter + pcie_correctable_errors[i].val) :
					(correctable_errors >> pcie_correctable_errors[i].bit) & 1;
			json_object_add_value_int(stats, pcie_correctable_errors[i].err, val);
		}
		for (i = 0; i < ARRAY_SIZE(pcie_uncorrectable_errors); i++) {
			__u16 val = counters ? *(__u16 *)(pcounter + pcie_uncorrectable_errors[i].val) :
					(uncorrectable_errors >>
					pcie_uncorrectable_errors[i].bit) & 1;
			json_object_add_value_int(stats, pcie_uncorrectable_errors[i].err, val);
		}
		json_array_add_value_object(pcieErrors, stats);
		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
	} else if (counters == true) {
		__u8 *pcounter = (__u8 *)&pcie_error_counters;

		for (i = 0; i < ARRAY_SIZE(pcie_correctable_errors); i++)
			printf("%-42s : %-1hu\n", pcie_correctable_errors[i].err,
				   *(__u16 *)(pcounter + pcie_correctable_errors[i].val));
		for (i = 0; i < ARRAY_SIZE(pcie_uncorrectable_errors); i++)
			printf("%-42s : %-1hu\n", pcie_uncorrectable_errors[i].err,
				   *(__u16 *)(pcounter + pcie_uncorrectable_errors[i].val));
	} else if (eModel == M5407 || eModel == M5410) {
		for (i = 0; i < ARRAY_SIZE(pcie_correctable_errors); i++)
			printf("%-42s : %-1d\n", pcie_correctable_errors[i].err,
				   ((correctable_errors >>
				   pcie_correctable_errors[i].bit) & 1));
		for (i = 0; i < ARRAY_SIZE(pcie_uncorrectable_errors); i++)
			printf("%-42s : %-1d\n", pcie_uncorrectable_errors[i].err,
				   ((uncorrectable_errors >>
				   pcie_uncorrectable_errors[i].bit) & 1));
	} else {
		printf("PCIE Stats:\n");
		printf("Device correctable errors detected: 0x%x\n",
		       correctable_errors);
		printf("Device uncorrectable errors detected: 0x%x\n",
		       uncorrectable_errors);
	}

out:
	return err;
}

static int micron_clear_pcie_correctable_errors(int argc, char **argv,
		struct command *command,
		struct plugin *plugin)
{
	int err = -EINVAL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	enum eDriveModel model = UNKNOWN_MODEL;
	struct libnvme_passthru_cmd admin_cmd = { 0 };
	const char *desc = "Clear PCIe Device Correctable Errors";
	__u64 result = 0;
	__u8 fid = MICRON_FEATURE_CLEAR_PCI_CORRECTABLE_ERRORS;

	NVME_ARGS(opts);

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &model);
	if (err < 0)
		return err;

	/* For M51CX models, PCIe errors are cleared using 0xC3 feature
	 * and for M5407 models, PCIe errors are cleared using 0xD6 command
	 * If these fail, proceed with sysfs interface to set/clear bits
	 */
	if (model == M51CX || model == M51BY || model == M51CY) {
		err = nvme_set_features_simple(hdl, 0, fid, false, (1 << 31),
				&result);
		if (!err)
			err = (int)result;
		if (!err) {
			nvme_show_verbose_result("Device correctable errors are cleared!");
			return 0;
		}
	} else if (model == M5407) {
		admin_cmd.opcode = 0xD6;
		admin_cmd.addr = 0;
		admin_cmd.cdw10 = 0;
		err = libnvme_exec_admin_passthru(hdl, &admin_cmd);
		if (!err) {
			nvme_show_verbose_result("Device correctable error counters are cleared!");
			return 0;
		}
	}

	/* clear status bits using system commands */
	err = micron_clear_pcie_aer_correctable_errors(hdl);

	return err;
}

static struct logpage {
	const char *field;
	char	   datastr[128];
} d0_log_page[] = {
	{ "NAND Writes (Bytes Written)", { 0 }},
	{ "Program Failure Count", { 0 }},
	{ "Erase Failures", { 0 }},
	{ "Bad Block Count", { 0 }},
	{ "NAND XOR/RAID Recovery Trigger Events", { 0 }},
	{ "NSZE Change Supported", { 0 }},
	{ "Number of NSZE Modifications", { 0 }}
};

static void init_d0_log_page(__u8 *buf, __u8 nsze)
{
	unsigned int logD0[D0_log_size/sizeof(int)] = { 0 };
	__u64 count_lo, count_hi, count;

	memcpy(logD0, buf, sizeof(logD0));


	count = ((__u64)logD0[45] << 32) | logD0[44];
	sprintf(d0_log_page[0].datastr, "0x%"PRIx64, le64_to_cpu(count));

	count_hi = ((__u64)logD0[39] << 32) | logD0[38];
	count_lo = ((__u64)logD0[37] << 32) | logD0[36];
	if (count_hi)
		sprintf(d0_log_page[1].datastr, "0x%"PRIx64"%016"PRIx64,
			le64_to_cpu(count_hi), le64_to_cpu(count_lo));
	else
		sprintf(d0_log_page[1].datastr, "0x%"PRIx64, le64_to_cpu(count_lo));

	count = ((__u64)logD0[25] << 32) | logD0[24];
	sprintf(d0_log_page[2].datastr, "0x%"PRIx64, le64_to_cpu(count));

	sprintf(d0_log_page[3].datastr, "0x%x", logD0[3]);

	count_lo = ((__u64)logD0[37] << 32) | logD0[36];
	count = ((__u64)logD0[25] << 32) | logD0[24];
	count = (__u64)logD0[3] - (count_lo + count);
	sprintf(d0_log_page[4].datastr, "0x%"PRIx64, le64_to_cpu(count));

	sprintf(d0_log_page[5].datastr, "0x%x", nsze);
	sprintf(d0_log_page[6].datastr, "0x%x", logD0[1]);
}

static struct nand_stats {
	const char *field;
	char       datastr[128];
} hyperscale_BSSD_nand_stats[] = {
		{"Physical Media Units Written - TLC", {0}},
		{"Physical Media Units Written - SLC", {0}},
		{"Bad User NAND Block Count (Normalized)", {0}},
		{"Bad User NAND Block Count (Raw)", {0}},
		{"XOR Recovery count", {0}},
		{"Uncorrectable read error count", {0}},
		{ "User Data Erase Counts (Minimum TLC)", {0}},
		{ "User Data Erase Counts (Maximum TLC)", {0}},
		{ "User Data Erase Counts (Average TLC)", {0}},
		{ "User Data Erase Counts (Minimum SLC)", {0}},
		{ "User Data Erase Counts (Maximum SLC)", {0}},
		{ "User Data Erase Counts (Average SLC)", {0}},
		{ "Program Fail Count (Normalized)", {0}},
		{ "Program Fail Count (Raw)", {0}},
		{ "Erase Fail Count (Normalized)", {0}},
		{ "Erase Fail Count (Raw)", {0}},
		{ "Total # of Soft ECC Error Count", {0}},
		{ "Bad System NAND Block Count (Normalized)", {0}},
		{ "Bad System NAND Block Count (Raw)", {0}},
		{"Endurance Estimate", {0}},
		{"Physical Media Units Read", {0}},
		{"Boot SSD Spec Version", {0}},
};

static void micron_readFixedBytesFromBuffer(__u8 *buf, int offset, int numBytes, char *datastr)
{
	__u16 u16Val;
	__u32 u32Val;
	__u64 count_lo, count_hi, count;

	switch (numBytes) {
	case 16:
	{
		count_lo = *((__u64 *)(&buf[offset]));
		count_hi = *((__u64 *)(&buf[offset + 8]));
		if (count_hi)
			sprintf(datastr, "0x%"PRIx64"%016"PRIx64"",
				le64_to_cpu(count_hi),
				le64_to_cpu(count_lo));
		else
			sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(count_lo));

	}
	break;
	case 8:
	{
		count = *((__u64 *)(&buf[offset]));
		sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(count));
	}
	break;
	case 6:
	{
		u32Val    = *((__u32 *)(&buf[offset]));
		u16Val    = *((__u16 *)(&buf[offset + 4]));
		count = (((__u64)u32Val << 32) | u16Val);
		sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(count));
	}
	break;
	case 2:
	{
		u16Val = *((__u16 *)(&buf[offset]));
		sprintf(datastr, "0x%04x", le16_to_cpu(u16Val));
	}
	break;
	}
}

static void init_hyperscale_BSSD_nand_stats(__u8 *buf)
{

	__u16 majorVer, minorVer, pointVer, errataVer;

	micron_readFixedBytesFromBuffer(buf, 0, 16, hyperscale_BSSD_nand_stats[0].datastr);
	micron_readFixedBytesFromBuffer(buf, 16, 16, hyperscale_BSSD_nand_stats[1].datastr);
	micron_readFixedBytesFromBuffer(buf, 32, 2, hyperscale_BSSD_nand_stats[2].datastr);
	micron_readFixedBytesFromBuffer(buf, 34, 6, hyperscale_BSSD_nand_stats[3].datastr);
	micron_readFixedBytesFromBuffer(buf, 40, 8, hyperscale_BSSD_nand_stats[4].datastr);
	micron_readFixedBytesFromBuffer(buf, 48, 8, hyperscale_BSSD_nand_stats[5].datastr);
	micron_readFixedBytesFromBuffer(buf, 84, 8, hyperscale_BSSD_nand_stats[6].datastr);
	micron_readFixedBytesFromBuffer(buf, 92, 8, hyperscale_BSSD_nand_stats[7].datastr);
	micron_readFixedBytesFromBuffer(buf, 100, 8, hyperscale_BSSD_nand_stats[8].datastr);
	micron_readFixedBytesFromBuffer(buf, 108, 8, hyperscale_BSSD_nand_stats[9].datastr);
	micron_readFixedBytesFromBuffer(buf, 116, 8, hyperscale_BSSD_nand_stats[10].datastr);
	micron_readFixedBytesFromBuffer(buf, 124, 8, hyperscale_BSSD_nand_stats[11].datastr);
	micron_readFixedBytesFromBuffer(buf, 132, 2, hyperscale_BSSD_nand_stats[12].datastr);
	micron_readFixedBytesFromBuffer(buf, 134, 6, hyperscale_BSSD_nand_stats[13].datastr);
	micron_readFixedBytesFromBuffer(buf, 140, 2, hyperscale_BSSD_nand_stats[14].datastr);
	micron_readFixedBytesFromBuffer(buf, 142, 6, hyperscale_BSSD_nand_stats[15].datastr);
	micron_readFixedBytesFromBuffer(buf, 202, 8, hyperscale_BSSD_nand_stats[16].datastr);
	micron_readFixedBytesFromBuffer(buf, 218, 2, hyperscale_BSSD_nand_stats[17].datastr);
	micron_readFixedBytesFromBuffer(buf, 220, 6, hyperscale_BSSD_nand_stats[18].datastr);
	micron_readFixedBytesFromBuffer(buf, 226, 16, hyperscale_BSSD_nand_stats[19].datastr);
	micron_readFixedBytesFromBuffer(buf, 252, 16, hyperscale_BSSD_nand_stats[20].datastr);

	majorVer = *((__u16 *)(&buf[300]));
	minorVer = *((__u16 *)(&buf[302]));
	pointVer = *((__u16 *)(&buf[304]));
	errataVer = *((__u16 *)(&buf[306]));
	sprintf(hyperscale_BSSD_nand_stats[21].datastr,
					"%x.%x.%x.%x",
					le16_to_cpu(majorVer),
					le16_to_cpu(minorVer),
					le16_to_cpu(pointVer),
					le16_to_cpu(errataVer));
}


/* Smart Health Log information as per OCP spec M51CX models */
struct request_data ocp_c0_log_page[] = {
	{ "Physical Media Units Written", 16},
	{ "Physical Media Units Read", 16 },
	{ "Raw Bad User NAND Block Count", 6},
	{ "Normalized Bad User NAND Block Count", 2},
	{ "Raw Bad System NAND Block Count", 6},
	{ "Normalized Bad System NAND Block Count", 2},
	{ "XOR Recovery Count", 8},
	{ "Uncorrectable Read Error Count", 8},
	{ "Soft ECC Error Count", 8},
	{ "SSD End to End Detected Counts", 4},
	{ "SSD End to End Corrected Errors", 4},
	{ "System data % life-used", 1},
	{ "Refresh Count", 7},
	{ "Maximum User Data Erase Count", 4},
	{ "Minimum User Data Erase Count", 4},
	{ "Thermal Throttling Count", 1},
	{ "Thermal Throttling Status", 1},
	{ "Reserved", 6},
	{ "PCIe Correctable Error count", 8},
	{ "Incomplete Shutdowns", 4},
	{ "Reserved", 4},
	{ "% Free Blocks", 1},
	{ "Reserved", 7},
	{ "Capacitor Health", 2},
	{ "Reserved", 6},
	{ "Unaligned I/O", 8},
	{ "Security Version Number", 8},
	{ "NUSE", 8},
	{ "PLP Start Count", 16},
	{ "Endurance Estimate", 16},
	{ "Reserved", 302},
	{ "Log Page Version", 2},
	{ "Log Page GUID", 16},
},

/* Smart Health Log information Extended as per Hyperscale NVME Boot SSD spec M51CX models */
hyperscale_c0_log_page[] = {
		{ "Physical Media Units Written - TLC",  16},
		{ "Physical Media Units Written - SLC",  16},
		{ "Bad User NAND Block Count (Normalized)", 2},
		{ "Bad User NAND Block Count (Raw)", 6},
		{ "XOR Recovery Count", 8},
		{ "Uncorrectable Read Error Count", 8},
		{ "SSD End to End correction counts (Corrected Errors)", 8},
		{ "SSD End to End correction counts (Detected Counts)", 8},
		{ "SSD End to End correction counts (Uncorrected Counts)", 8},
		{ "System data % life-used", 1},
		{ "Reserved", 3},
		{ "User Data Erase Counts (Minimum TLC)", 8},
		{ "User Data Erase Counts (Maximum TLC)", 8},
		{ "User Data Erase Counts (Average TLC)", 8},
		{ "User Data Erase Counts (Minimum SLC)", 8},
		{ "User Data Erase Counts (Maximum SLC)", 8},
		{ "User Data Erase Counts (Average SLC)", 8},
		{ "Program Fail Count (Normalized)", 2},
		{ "Program Fail Count (Raw)", 6},
		{ "Erase Fail Count (Normalized)", 2},
		{ "Erase Fail Count (Raw)", 6},
		{ "Pcie Correctable Error Count", 8},
		{ "% Free Blocks (User)", 1},
		{ "Reserved", 3},
		{ "Security Version Number", 8},
		{ "% Free Blocks (System)", 1},
		{ "Reserved", 3},
		{ "NVMe Stats (# Data set Management/TRIM Commands Completed", 16},
		{ "Total Namespace Utilization (nvme0n1 NUSE)", 8},
		{ "NVMe Stats (#NVMe Format Commands Completed)", 2},
		{ "Background Back-Pressure Gauge(%)", 1},
		{ "Reserved", 3},
		{ "Total # of Soft ECC Error Count", 8},
		{ "Total # of Read Refresh Count", 8},
		{ "Bad System NAND Block Count (Normalized)", 2},
		{ "Bad System NAND Block Count (Raw)", 6},
		{ "Endurance Estimate (Total Writable Lifetime Bytes)", 16},
		{ "Thermal Throttling Status & Count (Number of thermal throttling events)", 2},
		{ "Total # Unaligned I/O", 8},
		{ "Total Physical Media Units Read (Bytes)", 16},
		{ "Command Timeout (# of READ CMDs exceeding threshold)", 4},
		{ "Command Timeout (# of WRITE CMDs exceeding threshold)", 4},
		{ "Command Timeout (# of TRIMs CMDs exceeding threshold)", 4},
		{ "Reserved", 4},
		{ "Total PCIe Link Retraining Count", 8},
		{ "Active Power State Change Count", 8},
		{ "Boot SSD Spec Version", 8},
		{ "FTL Unit Size", 4},
		{ "TCG Ownership Status", 4},
		{ "Reserved", 178},
		{ "Log Page Version", 2},
		{ "Log Page GUID", 16},
},

/* Smart Health Log information as per datacenter-nvme-ssd-specification-v2 M51BY models */
datacenter_c0_log_page[] = {
	{"Physical Media Units Written", 16},
	{"Physical Media Units Read", 16 },
	{"Raw Bad User NAND Block Count", 6},
	{"Normalized Bad User NAND Block Count", 2},
	{"Raw Bad System NAND Block Count", 6},
	{"Normalized Bad System NAND Block Count", 2},
	{"XOR Recovery Count", 8},
	{"Uncorrectable Read Error Count", 8},
	{"Soft ECC Error Count", 8},
	{"SSD End to End Detected Counts", 4},
	{"SSD End to End Corrected Errors", 4},
	{"System data % life-used", 1},
	{"Refresh Count", 7},
	{"Maximum User Data Erase Count", 4},
	{"Minimum User Data Erase Count", 4},
	{"Thermal Throttling Count", 1},
	{"Thermal Throttling Status", 1},
	{"DSSD Spec Version", 6},
	{"PCIe Correctable Error count", 8},
	{"Incomplete Shutdowns", 4},
	{"Reserved", 4},
	{"% Free Blocks", 1},
	{"Reserved", 7},
	{"Capacitor Health", 2},
	{"NVMe Errata Version", 1},
	{"Reserved", 5},
	{"Unaligned I/O", 8},
	{"Security Version Number", 8},
	{"Total NUSE", 8},
	{"PLP Start Count", 16},
	{"Endurance Estimate", 16},
	{"PCIe Link Retraining Count", 8},
	{"Power State Change Count", 8},
	{"Reserved", 286},
	{"Log Page Version", 2},
	{"Log Page GUID", 16},
},

/* Extended SMART log information */
e1_log_page[] = {
	{"Reserved", 12},
	{"Grown Bad Block Count", 4},
	{"Per Block Max Erase Count", 4},
	{"Power On Minutes", 4},
	{"Reserved", 24},
	{"Write Protect Reason", 4},
	{"Reserved", 12},
	{"Drive Capacity", 8},
	{"Reserved", 8},
	{"Total Erase Count", 8},
	{"Lifetime Use Rate", 8},
	{"Erase Fail Count", 8},
	{"Reserved", 8},
	{"Reported UC Errors", 8},
	{"Reserved", 24},
	{"Program Fail Count", 16},
	{"Total Bytes Read", 16},
	{"Total Bytes Written", 16},
	{"Reserved", 16},
	{"TU Size", 4},
	{"Total Block Stripe Count", 4},
	{"Free Block Stripe Count", 4},
	{"Block Stripe Size", 8},
	{"Reserved", 16},
	{"User Block Min Erase Count", 4},
	{"User Block Avg Erase Count", 4},
	{"User Block Max Erase Count", 4},
},
/* Vendor Specific Health Log information */
fb_log_page[] = {
	{"Physical Media Units Written - TLC",  16, 16 },
	{"Physical Media Units Written - SLC",  16, 16 },
	{"Normalized Bad User NAND Block Count", 2, 2},
	{"Raw Bad User NAND Block Count", 6, 6},
	{"XOR Recovery Count", 8, 8},
	{"Uncorrectable Read Error Count", 8, 8},
	{"SSD End to End Corrected Errors", 8, 8},
	{"SSD End to End Detected Counts", 4, 8},
	{"SSD End to End Uncorrected Counts", 4, 8},
	{"System data % life-used", 1, 1},
	{"Reserved", 0, 3},
	{"Minimum User Data Erase Count - TLC", 8, 8},
	{"Maximum User Data Erase Count - TLC", 8, 8},
	{"Average User Data Erase Count - TLC", 0, 8},
	{"Minimum User Data Erase Count - SLC", 8, 8},
	{"Maximum User Data Erase Count - SLC", 8, 8},
	{"Average User Data Erase Count - SLC", 0, 8},
	{"Normalized Program Fail Count", 2, 2},
	{"Raw Program Fail Count", 6, 6},
	{"Normalized Erase Fail Count", 2, 2},
	{"Raw Erase Fail Count", 6, 6},
	{"Pcie Correctable Error Count", 8, 8},
	{"% Free Blocks (User)", 1, 1},
	{"Reserved", 0, 3},
	{"Security Version Number", 8, 8},
	{"% Free Blocks (System)", 1, 1},
	{"Reserved", 0, 3},
	{"Dataset Management (Deallocate) Commands", 16, 16},
	{"Incomplete TRIM Data", 8, 8},
	{"% Age of Completed TRIM", 1, 2},
	{"Background Back-Pressure Gauge", 1, 1},
	{"Reserved", 0, 3},
	{"Soft ECC Error Count", 8, 8},
	{"Refresh Count", 8, 8},
	{"Normalized Bad System NAND Block Count", 2, 2},
	{"Raw Bad System NAND Block Count", 6, 6},
	{"Endurance Estimate", 16, 16},
	{"Thermal Throttling Status", 1, 1},
	{"Thermal Throttling Count", 1, 1},
	{"Unaligned I/O", 8, 8},
	{"Physical Media Units Read", 16, 16},
	{"Reserved", 279, 0},
	{"Log Page Version", 2, 0},
	{"READ CMDs exceeding threshold", 0, 4},
	{"WRITE CMDs exceeding threshold", 0, 4},
	{"TRIMs CMDs exceeding threshold", 0, 4},
	{"Reserved", 0, 4},
	{"Reserved", 0, 210},
	{"Log Page Version", 0, 2},
	{"Log Page GUID", 0, 16},
},

/* SMARTS for 0x6001 Nitro model */
//Extended Health Information (Log Identifier D0h)
D0_log_page[] = {
	{"Reserved", 2},//1:0
	{"Version", 2},//3:2
	{"Grown Bad Block Count", 4},//7:4
	{"Total SRAM SBE Count", 4},//11:8
	{"Total SRAM DBE Count", 4},//15:12
	{"Write Protect Reason", 4},//19:16
	{"Total Erase Count", 4},//23:20
	{"Erase Fail Count", 4},//27:24
	{"Program Fail Counts", 4},//31:28
	{"Reserved", 40},//71:32
	{"Completed PLN PLA Cycles", 4},//75:72
	{"PLN Assert Count", 4},//79:76
	{"PLN Deassert Count", 4},//83:80
	{"PLA Assert Count", 4},//87:84
	{"PLA Deassert Count", 4},//91:88
	{"Correctable NAND UECCs", 4},//95:92
	{"Reported Uncorrectable Errors UECCCs", 4},//99:96
	{"TLC Super Block Min Erase Count", 4},//103:100
	{"TLC Super Block Avg Erase Count", 4},//107:104
	{"TLC Super Block Max Erase Count", 4},//111:108
	{"Min ASIC Temp Recorded", 2},//113:112
	{"Max ASIC Temp Recorded", 2},//115:114
	{"Min NAND Temp Recorded", 2},//171:116
	{"Max NAND Temp Recorded", 2},//119:118
	{"SLC Super Block Min Erase Count", 4},//123:120
	{"SLC Super Block Avg Erase Count", 4},//127:124
	{"SLC Super Block Max Erase Count", 4},//131:128
	{"SLC Lifetime Used", 2},//133:132
	{"TLC Lifetime Used", 2},//135:134
	{"Unmapped LBA Count", 8},//143:136
	{"PWR1 Voltage Detection Threshold #1", 4},//147:144
	{"PWR1 Voltage Detection Threshold #2", 4},//151:148
},
//Micron Workload Log (Log Identifier C5h)
C5_log_page[] = {
	{"Reserved", 4},//3:0
	{"Number of Downshifts", 1},//4
	{"Reserved", 71},//75:5
	{"Number of LBAs Deallocated Trimmed", 4},//79:76
	{"Reserved", 41},//120:80
	{"Number of Security Send Commands", 4},//124:121
	{"Number of Security Receive Commands", 4},//128:125
	{"Total Sanitize Events", 4},//132:129
},
//Vendor Telemetry Log (Log Identifier C6h))
C6_log_page[] = {
	{"Reserved", 240},//239:0
	{"Total TLC NAND Write Count", 8},//247:240
	{"Total SLC NAND Write Count", 8},//255:248
	{"Total SLC Host Write Count", 8},//263:256
	{"Total TLC Host Write Count", 8},//272:264
};

static void print_smart_cloud_health_log(__u8 *buf, bool is_json, enum eDriveModel eModel)
{
	struct json_object *root = NULL;
	struct json_object *logPages = NULL;
	struct json_object *stats = NULL;
	int field_count = 0;

	if (eModel == M51CX)
		field_count = ARRAY_SIZE(ocp_c0_log_page);
	else if (eModel == M51BY || eModel == M51CY)
		field_count = ARRAY_SIZE(datacenter_c0_log_page);

	if (is_json) {
		root = json_create_object();
		stats = json_create_object();
		logPages = json_create_array();
		if (eModel == M51BY || eModel == M51CY)
			json_object_add_value_array(root, "OCP DataCenter SMART Health Log: 0xC0",
						logPages);
		else if (eModel == M51CX)
			json_object_add_value_array(root, "OCP SMART Cloud Health Log: 0xC0",
						logPages);
	}

	if (eModel == M51BY || eModel == M51CY)
		generic_structure_parser(buf, datacenter_c0_log_page, field_count, stats, 0, NULL);
	else if (eModel == M51CX)
		generic_structure_parser(buf, ocp_c0_log_page, field_count, stats, 0, NULL);

	if (is_json) {
		json_array_add_value_object(logPages, stats);
		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
	}
}

static void print_hyperscale_cloud_health_log(__u8 *buf, bool is_json)
{
	struct json_object *root;
	struct json_object  *logPages;
	struct json_object *stats = NULL;
	int field_count = ARRAY_SIZE(hyperscale_c0_log_page);

	if (is_json) {
		root = json_create_object();
		stats = json_create_object();
		logPages = json_create_array();
		json_object_add_value_array(root, "OCP Hyperscale Cloud Health Log: 0xC0",
									logPages);
	}

	generic_structure_parser(buf, hyperscale_c0_log_page, field_count, stats, 0, NULL);

	if (is_json) {
		json_array_add_value_object(logPages, stats);
		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
	}
}

static void print_nand_stats_fb(__u8 *buf, __u8 *buf2, __u8 nsze, bool is_json, __u8 spec)
{
	struct json_object *root;
	struct json_object  *logPages;
	struct json_object *stats = NULL;
	int field_count = ARRAY_SIZE(fb_log_page);

	if (is_json) {
		root = json_create_object();
		stats = json_create_object();
		logPages = json_create_array();
		json_object_add_value_array(root, "Extended Smart Log Page : 0xFB",
						logPages);
	}

	generic_structure_parser(buf, fb_log_page, field_count, stats, spec, NULL);

	/* print last three entries from D0 log page */
	if (buf2) {
		init_d0_log_page(buf2, nsze);

		if (is_json) {
			for (int i = 0; i < 7; i++)
				json_object_add_value_string(stats,
						 d0_log_page[i].field,
						 d0_log_page[i].datastr);
		} else {
			for (int i = 0; i < 7; i++)
				printf("%-40s : %s\n", d0_log_page[i].field, d0_log_page[i].datastr);
		}
	}

	if (is_json) {
		json_array_add_value_object(logPages, stats);
		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
	}
}

static void print_nand_stats_d0(__u8 *buf, __u8 oacs, bool is_json)
{
	init_d0_log_page(buf, oacs);

	if (is_json) {
		struct json_object *root = json_create_object();
		struct json_object *stats = json_create_object();
		struct json_object *logPages = json_create_array();

		json_object_add_value_array(root, "Extended Smart Log Page : 0xD0", logPages);

		for (int i = 0; i < 7; i++)
			json_object_add_value_string(stats,	d0_log_page[i].field,
				d0_log_page[i].datastr);

		json_array_add_value_object(logPages, stats);
		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
	} else {
		for (int i = 0; i < 7; i++)
			printf("%-40s : %s\n", d0_log_page[i].field, d0_log_page[i].datastr);
	}
}

static void print_hyperscale_nand_stats(__u8 *buf, bool is_json)
{
	init_hyperscale_BSSD_nand_stats(buf);

	if (is_json) {
		struct json_object *root = json_create_object();
		struct json_object *stats = json_create_object();
		struct json_object *logPages = json_create_array();

		json_object_add_value_array(root, "Extended Smart Log Page : 0xC0", logPages);

		for (int i = 0; i < 22; i++)
			json_object_add_value_string(stats,
			hyperscale_BSSD_nand_stats[i].field,
			hyperscale_BSSD_nand_stats[i].datastr);

		json_array_add_value_object(logPages, stats);
		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
	} else {
		for (int i = 0; i < 22; i++)
			printf("%-40s : %s\n", hyperscale_BSSD_nand_stats[i].field,
						hyperscale_BSSD_nand_stats[i].datastr);
	}
}

static bool nsze_from_oacs;/* read nsze for now from idd[4059]  */

static int micron_nand_stats(int argc, char **argv,
				struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve Micron NAND stats for the given device ";
	unsigned int extSmartLog[D0_log_size/sizeof(int)] = { 0 };
	unsigned int logFB[FB_log_size/sizeof(int)] = { 0 };
	unsigned char logC0[C0_log_size] = { 0 };
	enum eDriveModel eModel = UNKNOWN_MODEL;
	struct nvme_id_ctrl ctrl;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err;
	__u8 nsze;
	bool has_d0_log = true;
	bool has_fb_log = false;
	bool is_json = true;
	nsze_from_oacs = false;
	struct format {
		char *fmt;
	};
	const char *fmt = "output format json|normal";
	struct format cfg = {
		.fmt = "json",
	};

	NVME_ARGS(opts,
		OPT_FMT("format", 'f', &cfg.fmt, fmt));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err) {
		nvme_show_error("Device not found");
		return -1;
	}

	if (!strcmp(cfg.fmt, "normal"))
		is_json = false;

	/* pull log details based on the model name */
	eModel = GetDriveModel(ctx, hdl);
	if (eModel == UNKNOWN_MODEL) {
		nvme_show_error("Unsupported drive model for vs-nand-stats command");
		return -1;
	}

	err = nvme_identify_ctrl(hdl, &ctrl);
	if (err) {
		nvme_show_err(err, "ERROR : identify_ctrl() failed");
		return -1;
	}

	if ((ctrl.vs[536] == MICRON_CUST_ID_GG) && (eModel == M51CX)) {
		err = nvme_get_log_simple(hdl, 0xC0, logC0, C0_log_size);
		if (err == 0) {
			print_hyperscale_nand_stats((__u8 *)logC0, is_json);
			goto out;
		} else if (err < 0) {
			nvme_show_err(err, "Unable to retrieve extended smart log 0xC0 for the drive");
			return -1;
		}
	}

	err = nvme_get_log_simple(hdl, 0xD0, extSmartLog, D0_log_size);
	has_d0_log = !err;

	/* should check for firmware version if this log is supported or not */
	if (eModel != M5407 && eModel != M5410) {
		err = nvme_get_log_simple(hdl, 0xFB, logFB, FB_log_size);
		has_fb_log = !err;
	}

	nsze = (ctrl.vs[987] == 0x12);
	if (!nsze && nsze_from_oacs)
		nsze = ((ctrl.oacs >> 3) & 0x1);

	if (has_fb_log) {
		__u8 spec = (eModel == M5410) ? 0 : 1;	/* FB spec version */

		print_nand_stats_fb((__u8 *)logFB, (__u8 *)extSmartLog, nsze, is_json, spec);
		err = 0;
	} else if (has_d0_log) {
		print_nand_stats_d0((__u8 *)extSmartLog, nsze, is_json);
		err = 0;
	}
out:
	if (err)
		nvme_show_err(err, "Unable to retrieve extended smart log for the drive");

	return err;
}

static void print_log(__u8 *buf, bool is_json, unsigned char ucLogID)
{
	struct json_object *root;
	struct json_object *logPages;
	struct json_object *stats = NULL;
	int    field_count = 0;
	struct request_data *log_pageID;
	char tempStr[256] = { 0 };

	if (ucLogID == 0xE1) {
		log_pageID = e1_log_page;
		field_count = ARRAY_SIZE(e1_log_page);
		sprintf(tempStr, "SMART Extended Log:0x%X", ucLogID);
	} else if (ucLogID == 0xD0) {
		log_pageID = D0_log_page;
		field_count = ARRAY_SIZE(D0_log_page);
		sprintf(tempStr, "SMART Extended Log:0x%X", ucLogID);
	} else if (ucLogID == 0xC5) {
		log_pageID = C5_log_page;
		field_count = ARRAY_SIZE(C5_log_page);
		sprintf(tempStr, "Micron Workload Log:0x%X", ucLogID);
	} else if (ucLogID == 0xC6)	{
		log_pageID = C6_log_page;
		field_count = ARRAY_SIZE(C6_log_page);
		sprintf(tempStr, "Vendor Telemetry Log:0x%X", ucLogID);
	} else {
		log_pageID = NULL;
	}

	if (is_json) {
		root = json_create_object();
		stats = json_create_object();
		logPages = json_create_array();
		json_object_add_value_array(root, tempStr, logPages);
	} else {
		printf("%s\n", tempStr);
	}

	if (log_pageID != NULL)
		generic_structure_parser(buf, log_pageID, field_count, stats, 0, NULL);

	if (is_json) {
		json_array_add_value_object(logPages, stats);
		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
	}
}

static int micron_smart_ext_log(int argc, char **argv,
				struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve extended SMART logs for the given device ";
	unsigned int extSmartLog[E1_log_size/sizeof(int)] = { 0 };
	enum eDriveModel eModel = UNKNOWN_MODEL;
	int err = 0;
	__u8 log_id;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	bool is_json = true;
	struct format {
		char *fmt;
	};
	const char *fmt = "output format json|normal";
	struct format cfg = {
		.fmt = "json",
	};
	NVME_ARGS(opts,
		OPT_FMT("format", 'f', &cfg.fmt, fmt));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err) {
		nvme_show_error("Device not found");
		return -1;
	}
	if (!strcmp(cfg.fmt, "normal"))
		is_json = false;

	eModel = GetDriveModel(ctx, hdl);
	if (eModel == M51CX || eModel == M51BY || eModel == M51CY || eModel == M6003 ||
								eModel == M6004) {
		log_id = 0xE1;
	} else if (eModel == M6001) {
		log_id = 0xD0;
	} else {
		nvme_show_error("Unsupported drive model for vs-smart-ext-log command");
		err = -1;
		goto out;
	}
	err = nvme_get_log_simple(hdl, log_id, extSmartLog, E1_log_size);
	if (!err)
		print_log((__u8 *)extSmartLog, is_json, log_id);

out:
	if (err > 0)
		nvme_show_status(err);
	return err;
}

static int micron_work_load_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Micron Workload logs for the given device ";
	unsigned int micronWorkLoadLog[C5_MicronWorkLoad_log_size/sizeof(int)] = { 0 };
	enum eDriveModel eModel = UNKNOWN_MODEL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;

	int err = 0;
	bool is_json = true;
	struct format {
		char *fmt;
	};
	const char *fmt = "output format json|normal";
	struct format cfg = {
		.fmt = "json",
	};
	NVME_ARGS(opts,
		OPT_FMT("format", 'f', &cfg.fmt, fmt));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err) {
		nvme_show_error("Device not found");
		return -1;
	}
	if (strcmp(cfg.fmt, "normal") == 0)
		is_json = false;

	eModel = GetDriveModel(ctx, hdl);
	if (eModel == M6001 || eModel == M6004 || eModel == M6003) {
		err =  nvme_get_log_simple(hdl, 0xC5,
		micronWorkLoadLog, C5_MicronWorkLoad_log_size);
		if (!err)
			print_log((__u8 *)micronWorkLoadLog, is_json, 0xC5);
	} else {
		nvme_show_error("Unsupported drive model for vs-work-load-log command");
		err = -1;
		goto out;
	}

out:
	if (err > 0)
		nvme_show_status(err);
	return err;
}

static int micron_vendor_telemetry_log(int argc, char **argv,
				struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve Vendor Telemetry logs for the given device ";
	unsigned int vendorTelemetryLog[C6_log_size/sizeof(int)] = { 0 };
	enum eDriveModel eModel = UNKNOWN_MODEL;
	int err = 0;
	bool is_json = true;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;

	struct format {
		char *fmt;
	};
	const char *fmt = "output format json|normal";
	struct format cfg = {
		.fmt = "json",
	};
	NVME_ARGS(opts,
		OPT_FMT("format", 'f', &cfg.fmt, fmt));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err) {
		nvme_show_error("Device not found");
		return -1;
	}
	if (strcmp(cfg.fmt, "normal") == 0)
		is_json = false;

	eModel = GetDriveModel(ctx, hdl);
	if (eModel == M6001 || eModel == M6004 || eModel == M6003) {
		err =  nvme_get_log_simple(hdl, 0xC6, vendorTelemetryLog, C6_log_size);
		if (!err)
			print_log((__u8 *)vendorTelemetryLog, is_json, 0xC6);
	} else {
		nvme_show_error("Unsupported drive model for vs-vendor-telemetry-log command");
		err = -1;
		goto out;
	}

out:
	if (err > 0)
		nvme_show_status(err);
	return err;
}

static void GetDriveInfo(const char *strOSDirName, int nFD,
						 struct nvme_id_ctrl *ctrlp)
{
	FILE *fpOutFile = NULL;
	__cleanup_free char *tempFile = NULL;
	char strBuffer[1024] = { 0 };
	char model[41] = { 0 };
	char serial[21] = { 0 };
	char fwrev[9] = { 0 };
	__cleanup_free char *strPDir = NULL;
	char *strDest = NULL;

	strPDir = strdup(strOSDirName);
	if (!strPDir) {
		nvme_show_error("Failed to allocate memory for directory name");
		return;
	}
	strDest = dirname(strPDir);

	if (asprintf(&tempFile, "%s/%s", strDest, "drive-info.txt") < 0) {
		nvme_show_error("Failed to allocate memory for temp file name");
		return;
	}
	fpOutFile = fopen(tempFile, "w+");
	if (!fpOutFile) {
		nvme_show_error("Failed to create %s", tempFile);
		return;
	}

	strncpy(model, ctrlp->mn, 40);
	strncpy(serial, ctrlp->sn, 20);
	strncpy(fwrev, ctrlp->fr, 8);

	snprintf(strBuffer, sizeof(strBuffer),
			"********************\nDrive Info\n********************\n");

	fprintf(fpOutFile, "%s", strBuffer);
	snprintf(strBuffer, sizeof(strBuffer),
			"%-20s : /dev/nvme%d\n%-20s : %s\n%-20s : %-20s\n%-20s : %-20s\n",
			"Device Name", nFD,
			"Model No", (char *)model,
			"Serial No", (char *)serial, "FW-Rev", (char *)fwrev);

	fprintf(fpOutFile, "%s", strBuffer);

	snprintf(strBuffer, sizeof(strBuffer),
			"\n********************\nPCI Info\n********************\n");

	fprintf(fpOutFile, "%s", strBuffer);

	snprintf(strBuffer, sizeof(strBuffer),
			"%-22s : %04X\n%-22s : %04X\n",
			"VendorId", vendor_id, "DeviceId", device_id);
	fprintf(fpOutFile, "%s", strBuffer);
	fclose(fpOutFile);
}

static void GetTimestampInfo(const char *strOSDirName)
{
	__u8 outstr[1024];
	time_t t;
	struct tm *tmp;
	size_t num;
	size_t remaining;
	int n;
	__cleanup_free char *strPDir = NULL;
	char *strDest = NULL;

	t = time(NULL);
	tmp = localtime(&t);
	if (!tmp)
		return;

	num = strftime((char *)outstr, sizeof(outstr),
			"Timestamp (UTC): %a, %d %b %Y %H:%M:%S %z", tmp);
	remaining = sizeof(outstr) - num;
	n = snprintf((char *)(outstr + num), remaining, "\nPackage Version: 1.4");
	if (n > 0)
		num += (size_t)n < remaining ? (size_t)n : remaining - 1;
	if (num) {
		strPDir = strdup(strOSDirName);
		if (!strPDir)
			return;
		strDest = dirname(strPDir);
		WriteData(outstr, num, strDest, "timestamp_info.txt", "timestamp");
	}
}

static void GetCtrlIDDInfo(const char *dir, struct nvme_id_ctrl *ctrlp)
{
	WriteData((__u8 *)ctrlp, sizeof(*ctrlp), dir,
			  "nvme_controller_identify_data.bin", "id-ctrl");
}

static void GetSmartlogData(struct libnvme_transport_handle *hdl, const char *dir)
{
	struct nvme_smart_log smart_log;

	if (!nvme_get_log_smart(hdl, NVME_NSID_ALL, &smart_log))
		WriteData((__u8 *)&smart_log, sizeof(smart_log), dir,
			  "smart_data.bin", "smart log");
}

static void GetErrorlogData(struct libnvme_transport_handle *hdl, int entries, const char *dir)
{
	int logSize = entries * sizeof(struct nvme_error_log_page);
	__cleanup_libnvme_free struct nvme_error_log_page *error_log =
				(struct nvme_error_log_page *)libnvme_alloc(logSize);

	if (!error_log)
		return;

	if (!nvme_get_log_error(hdl, NVME_NSID_ALL, entries, error_log))
		WriteData((__u8 *)error_log, logSize, dir,
			  "error_information_log.bin", "error log");
}

static void GetGenericLogs(struct libnvme_transport_handle *hdl, const char *dir)
{
	struct nvme_self_test_log self_test_log;
	struct nvme_firmware_slot fw_log;
	struct nvme_cmd_effects_log effects;
	struct nvme_persistent_event_log pevent_log;
	__cleanup_huge struct libnvme_mem_huge mh = { 0, };
	void *pevent_log_info = NULL;
	__u32 log_len = 0;
	int err = 0;

	/* get self test log */
	if (!nvme_get_log_device_self_test(hdl, &self_test_log))
		WriteData((__u8 *)&self_test_log, sizeof(self_test_log), dir,
			  "drive_self_test.bin", "self test log");

	/* get fw slot info log */
	if (!nvme_get_log_fw_slot(hdl, false, &fw_log))
		WriteData((__u8 *)&fw_log, sizeof(fw_log), dir,
			  "firmware_slot_info_log.bin", "firmware log");

	/* get effects log */
	if (!nvme_get_log_cmd_effects(hdl, NVME_CSI_NVM, &effects))
		WriteData((__u8 *)&effects, sizeof(effects), dir,
			  "command_effects_log.bin", "effects log");

	/* get persistent event log */
	(void)nvme_get_log_persistent_event(hdl, NVME_PEVENT_LOG_RELEASE_CTX,
						&pevent_log, sizeof(pevent_log));
	memset(&pevent_log, 0, sizeof(pevent_log));
	err = nvme_get_log_persistent_event(hdl, NVME_PEVENT_LOG_EST_CTX_AND_READ,
						&pevent_log, sizeof(pevent_log));
	if (err) {
		nvme_show_error("Setting persistent event log read ctx failed (ignored)!");
		return;
	}

	log_len = le64_to_cpu(pevent_log.tll);
	pevent_log_info = libnvme_alloc_huge(log_len, &mh);
	if (!pevent_log_info) {
		nvme_show_perror("could not alloc buffer for persistent event log page (ignored)!\n");
		return;
	}

	err = nvme_get_log_persistent_event(hdl, NVME_PEVENT_LOG_READ,
						pevent_log_info, log_len);
	if (!err)
		WriteData((__u8 *)pevent_log_info, log_len, dir,
			  "persistent_event_log.bin", "persistent event log");
}

static void GetNSIDDInfo(struct libnvme_transport_handle *hdl, const char *dir, int nsid)
{
	char file[PATH_MAX] = { 0 };
	struct nvme_id_ns ns;

	if (!nvme_identify_ns(hdl, nsid, &ns)) {
		snprintf(file, sizeof(file), "identify_namespace_%d_data.bin", nsid);
		WriteData((__u8 *)&ns, sizeof(ns), dir, file, "id-ns");
	}
}

static void GetOSConfig(const char *strOSDirName)
{
	__cleanup_free char *strFileName = NULL;

	if (asprintf(&strFileName, "%s/%s", strOSDirName, "os_config.txt") < 0)
		return;
	micron_write_os_config_to_file(strFileName);
}

static int micron_telemetry_log(struct libnvme_transport_handle *hdl, __u8 type, __u8 **data,
				int *logSize, int da)
{
	int err, bs = 512, offset = bs;
	unsigned short data_area[5] = { 0 };
	unsigned char  ctrl_init = (type == 0x8);

	__u8 *buffer = (unsigned char *)libnvme_alloc(bs);

	if (!buffer)
		return -1;
	if (ctrl_init)
		err = nvme_get_log_telemetry_ctrl(hdl, true, 0, buffer, bs);
	else
		err = nvme_get_log_telemetry_host(hdl, 0, buffer, bs);
	if (err) {
		nvme_show_error("Failed to get telemetry log header for 0x%X", type);
		libnvme_free(buffer);
		return err;
	}

	/* compute size of the log */
	data_area[1] = buffer[9]  << 8 | buffer[8];
	data_area[2] = buffer[11] << 8 | buffer[10];
	data_area[3] = buffer[13] << 8 | buffer[12];
	data_area[4] = buffer[15] << 8 | buffer[14];
	data_area[0] = data_area[1] > data_area[2] ? data_area[1] : data_area[2];
	data_area[0] = data_area[3] > data_area[0] ? data_area[3] : data_area[0];
	data_area[0] = data_area[4] > data_area[0] ? data_area[4] : data_area[0];

	if (!data_area[da]) {
		nvme_show_error("Requested telemetry data for 0x%X is empty", type);
		libnvme_free(buffer);
		buffer = NULL;
		return -1;
	}

	*logSize = data_area[da] * bs;
	offset = bs;
	err = 0;
	buffer = (unsigned char *)libnvme_realloc(buffer, (size_t)(*logSize));
	if (buffer) {
		while (!err && offset != *logSize) {
			if (ctrl_init)
				err = nvme_get_log_telemetry_ctrl(hdl, true, offset, buffer + offset, bs);
			else
				err = nvme_get_log_telemetry_host(hdl, offset, buffer + offset, bs);
			offset += bs;
		}
	}

	if (!err && buffer) {
		*data = buffer;
	} else {
		nvme_show_err(err, "Failed to get telemetry data for 0x%x\n", type);
		libnvme_free(buffer);
	}

	return err;
}

static int GetTelemetryData(struct libnvme_transport_handle *hdl, const char *dir)
{
	unsigned char *buffer = NULL;
	int i, err, logSize = 0;
	char msg[256] = { 0 };
	struct {
		__u8 log;
		char *file;
	} tmap[] = {
		{0x07, "nvmetelemetrylog.bin"},
		{0x08, "nvmetelemetrylog.bin"},
	};

	for (i = 0; i < (int)(ARRAY_SIZE(tmap)); i++) {
		err = micron_telemetry_log(hdl, tmap[i].log, &buffer, &logSize, 0);
		if (!err && logSize > 0 && buffer) {
			snprintf(msg, sizeof(msg), "telemetry log: 0x%X", tmap[i].log);
			WriteData(buffer, logSize, dir, tmap[i].file, msg);
		}
		libnvme_free(buffer);
		buffer = NULL;
		logSize = 0;
	}
	return err;
}

static int GetFeatureSettings(struct libnvme_transport_handle *hdl, const char *dir)
{
	unsigned char *bufp, buf[4096] = { 0 };
	int i, err, len, errcnt = 0;
	__u64 attrVal = 0;
	char msg[256] = { 0 };

	struct features {
		int id;
		char *file;
	} fmap[] = {
		{0x01, "nvme_feature_setting_arbitration.bin"},
		{0x02, "nvme_feature_setting_pm.bin"},
		{0x03, "nvme_feature_setting_lba_range_namespace_1.bin"},
		{0x04, "nvme_feature_setting_temp_threshold.bin"},
		{0x05, "nvme_feature_setting_error_recovery.bin"},
		{0x06, "nvme_feature_setting_volatile_write_cache.bin"},
		{0x07, "nvme_feature_setting_num_queues.bin"},
		{0x08, "nvme_feature_setting_interrupt_coalescing.bin"},
		{0x09, "nvme_feature_setting_interrupt_vec_config.bin"},
		{0x0A, "nvme_feature_setting_write_atomicity.bin"},
		{0x0B, "nvme_feature_setting_async_event_config.bin"},
		{0x80, "nvme_feature_setting_sw_progress_marker.bin"},
	};

	for (i = 0; i < (int)(ARRAY_SIZE(fmap)); i++) {
		if (fmap[i].id == 0x03) {
			len = 4096;
			bufp = (unsigned char *)(&buf[0]);
		} else	{
			len = 0;
			bufp = NULL;
		}
		err = nvme_get_features(hdl, 1, fmap[i].id, 0, 0x0, 0, bufp, len,
				&attrVal);
		if (!err) {
			snprintf(msg, sizeof(msg), "feature: 0x%X", fmap[i].id);
			WriteData((__u8 *)&attrVal, sizeof(attrVal), dir, fmap[i].file, msg);
			if (bufp)
				WriteData(bufp, len, dir, fmap[i].file, msg);
		} else {
			nvme_show_error("Feature 0x%x data not retrieved, error %d (ignored)!",
					fmap[i].id, err);
			errcnt++;
		}
	}
	return (int)(errcnt == ARRAY_SIZE(fmap));
}

static int micron_drive_info(int argc, char **argv, struct command *acmd,
				 struct plugin *plugin)
{
	const char *desc = "Get drive HW information";
	struct nvme_id_ctrl ctrl =	{ 0 };
	struct libnvme_passthru_cmd admin_cmd = { 0 };
	unsigned char logC0[C0_log_size] = { 0 };
	struct fb_drive_info {
		unsigned char hw_ver_major;
		unsigned char hw_ver_minor;
		unsigned char ftl_unit_size;
		unsigned short bs_ver_major;
		unsigned short bs_ver_minor;
		unsigned int ownership_status;
	} dinfo = { 0 };
	enum eDriveModel model = UNKNOWN_MODEL;
	__u8 custId = 0x10;  /* default Micron generic */
	bool is_json = false;
	struct json_object *root;
	struct json_object *driveInfo;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct format {
		char *fmt;
	};
	int err = 0;

	const char *fmt = "output format normal|json";
	struct format cfg = {
		.fmt = "normal",
	};

	NVME_ARGS(opts,
		OPT_FMT("format", 'f', &cfg.fmt, fmt));

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &model);
	if (err < 0)
		return err;

	if (model == UNKNOWN_MODEL) {
		nvme_show_error("ERROR : Unsupported drive for vs-drive-info cmd");
		return -1;
	}

	if (strcmp(cfg.fmt, "normal") && strcmp(cfg.fmt, "json")) {
		nvme_show_error("Invalid output format");
		return -1;
	}

	if (!strcmp(cfg.fmt, "json"))
		is_json = true;

	if (model == M5407) {
		admin_cmd.opcode = 0xDA;
		admin_cmd.addr = (__u64) (uintptr_t) &dinfo;
		admin_cmd.data_len = (__u32)sizeof(dinfo);
		admin_cmd.cdw12 = 3;
		err = libnvme_exec_admin_passthru(hdl, &admin_cmd);
		if (err) {
			nvme_show_error("ERROR : drive-info opcode failed with 0x%x", err);
			return -1;
		}
	} else {
		err = nvme_identify_ctrl(hdl, &ctrl);
		if (err) {
			nvme_show_error("ERROR : identify_ctrl() failed with 0x%x", err);
			return -1;
		}
		dinfo.hw_ver_major = ctrl.vs[820];
		dinfo.hw_ver_minor = ctrl.vs[821];
		dinfo.ftl_unit_size = ctrl.vs[822];
		custId = ctrl.vs[536];
	}

	if ((custId == MICRON_CUST_ID_GG) && (model == M51CX)) {
		err = nvme_get_log_simple(hdl, 0xC0, logC0, C0_log_size);
		if (err == 0) {
			dinfo.bs_ver_major  = *((__u16 *)(logC0+300));
			dinfo.bs_ver_minor  = *((__u16 *)(logC0+302));
			dinfo.ownership_status = *((__u32 *)(logC0+312));
		} else {
			nvme_show_err(err, "Unable to retrieve extended smart log 0xC0 for the drive");
			return -1;
		}
	}

	if (is_json) {
		struct json_object *pinfo = json_create_object();
		char tempstr[64] = { 0 };
		root = json_create_object();
		driveInfo = json_create_array();
		json_object_add_value_array(root, "Micron Drive HW Information", driveInfo);

		sprintf(tempstr, "%hhu.%hhu", dinfo.hw_ver_major, dinfo.hw_ver_minor);
		json_object_add_value_string(pinfo, "Drive Hardware Version", tempstr);

		if (custId == MICRON_CUST_ID_GG) {
			if (dinfo.ftl_unit_size) {
				sprintf(tempstr, "%u B",
					(unsigned int)(dinfo.ftl_unit_size * 1024));
				json_object_add_value_string(pinfo, "FTL_unit_size", tempstr);
			}

			if (dinfo.bs_ver_major != 0 || dinfo.bs_ver_minor != 0) {
				sprintf(tempstr,
					"HyperScale Boot Version Spec.%hhu.%hhu"
					, (unsigned char)dinfo.bs_ver_major,
					(unsigned char)dinfo.bs_ver_minor);
				json_object_add_value_string(pinfo, "Boot Spec.Version", tempstr);
			}

			if (dinfo.ownership_status == 0)
				sprintf(tempstr, "N/A");
			else if (dinfo.ownership_status == 1)
				sprintf(tempstr, "UNSET");
			else if (dinfo.ownership_status == 2)
				sprintf(tempstr, "SET");
			else if (dinfo.ownership_status == 3)
				sprintf(tempstr, "BLOCKED");
			json_object_add_value_string(pinfo, "Drive Ownership Status", tempstr);

		} else {
			if (dinfo.ftl_unit_size) {
				sprintf(tempstr, "%hhu KB", dinfo.ftl_unit_size);
				json_object_add_value_string(pinfo, "FTL_unit_size", tempstr);
			}
			if (dinfo.bs_ver_major != 0 || dinfo.bs_ver_minor != 0) {
				sprintf(tempstr, "%hhu.%hhu", (unsigned char)dinfo.bs_ver_major,
							(unsigned char)dinfo.bs_ver_minor);
				json_object_add_value_string(pinfo, "Boot Spec.Version", tempstr);
			}
		}
		json_array_add_value_object(driveInfo, pinfo);
		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
	} else {
		printf("Drive Hardware Version: %hhu.%hhu\n",
				dinfo.hw_ver_major, dinfo.hw_ver_minor);

		if (custId == MICRON_CUST_ID_GG) {
			if (dinfo.ftl_unit_size)
				printf("FTL_unit_size: %u B\n",
					(unsigned int)(dinfo.ftl_unit_size * 1024));

			if (dinfo.bs_ver_major != 0 || dinfo.bs_ver_minor != 0) {
				printf(
					"Boot Spec.Version: HyperScale Boot Version Spec.%hhu.%hhu\n"
					, (unsigned char)dinfo.bs_ver_major,
					(unsigned char)dinfo.bs_ver_minor);
			}

			if (dinfo.ownership_status == 0)
				printf("Drive Ownership Status: N/A\n");
			else if (dinfo.ownership_status == 1)
				printf("Drive Ownership Status: UNSET\n");
			else if (dinfo.ownership_status == 2)
				printf("Drive Ownership Status: SET\n");
			else if (dinfo.ownership_status == 3)
				printf("Drive Ownership Status: BLOCKED\n");

		} else {
			if (dinfo.ftl_unit_size)
				printf("FTL_unit_size: %hhu KB\n", dinfo.ftl_unit_size);
			if (dinfo.bs_ver_major != 0 || dinfo.bs_ver_minor != 0)
				printf(
					"Boot Spec.Version: %hhu.%hhu\n"
					, (unsigned char)dinfo.bs_ver_major,
					(unsigned char)dinfo.bs_ver_minor);
		}

	}

	return 0;
}

static int micron_cloud_ssd_plugin_version(int argc, char **argv,
					   struct command *command, struct plugin *plugin)
{
	printf("nvme-cli Micron cloud SSD plugin version: %s.%s\n",
		   __version_major, __version_minor);
	return 0;
}

static int micron_plugin_version(int argc, char **argv, struct command *acmd,
				 struct plugin *plugin)
{
	printf("nvme-cli Micron plugin version: %s.%s.%s\n",
		   __version_major, __version_minor, __version_patch);
	return 0;
}

/* Binary format of firmware activation history entry */
struct __packed fw_activation_history_entry {
	__u8                               version;
	__u8                               length;
	__u16                              rsvd1;
	__le16                             valid;
	__le64                             power_on_hour;
	__le64                             rsvd2;
	__le64                             power_cycle_count;
	__u8                               previous_fw[8];
	__u8                               activated_fw[8];
	__u8                               slot;
	__u8                               commit_action_type;
	__le16                             result;
	__u8                               rsvd3[14];
};

/* Binary format for firmware activation history table */
struct __packed micron_fw_activation_history_table {
	__u8                               log_page;
	__u8                               rsvd1[3];
	__le32                             num_entries;
	struct fw_activation_history_entry entries[20];
	__u8                               rsvd2[2790];
	__u16                              version;
	__u8                               GUID[16];
};

static int display_fw_activate_entry(int entry_count, struct fw_activation_history_entry *entry,
					 char *formatted_entry, size_t buf_size,
					 struct json_object *stats)
{
	time_t timestamp, hours;
	char buffer[32];
	__u8 minutes, seconds;
	static const char * const ca[] = {"000b", "001b", "010b", "011b"};
	char *ptr = formatted_entry;
	int index = 0, entry_size = 82;
	int remaining;
	bool      is_json = false;

	if ((entry->version != 1 && entry->version != 2) || entry->length != 64)
		return -EINVAL;

	if (stats)
		is_json = true;

	remaining = buf_size - (ptr - formatted_entry);
	snprintf(ptr, remaining, "%d", entry_count);
	if (is_json)
		json_object_add_value_int(stats, "Entry Number", le32_to_cpu(entry_count));

	ptr += 10;

	timestamp = (le64_to_cpu(entry->power_on_hour) & 0x0000FFFFFFFFFFFFUL) / 1000;
	hours = timestamp / 3600;
	minutes = (timestamp % 3600) / 60;
	seconds = (timestamp % 3600) % 60;
	remaining = buf_size - (ptr - formatted_entry);
	snprintf(ptr, remaining, "|%"PRIu64":%hhu:%hhu", (uint64_t)hours, minutes, seconds);
	if (is_json)
		json_object_add_value_string(stats, "Power On Hour", ptr+1);

	ptr += 16;

	remaining = buf_size - (ptr - formatted_entry);
	snprintf(ptr, remaining, "| %"PRIu64, le64_to_cpu(entry->power_cycle_count));
	if (is_json)
		json_object_add_value_int(stats, "Power cycle count",
			le32_to_cpu(entry->power_cycle_count));

	ptr += 10;

	/* firmware details */
	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer, entry->previous_fw, sizeof(entry->previous_fw));
	remaining = buf_size - (ptr - formatted_entry);
	snprintf(ptr, remaining, "| %s", buffer);
	if (is_json)
		json_object_add_value_string(stats, "Previous firmware", buffer);

	ptr += 11;

	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer, entry->activated_fw, sizeof(entry->activated_fw));
	remaining = buf_size - (ptr - formatted_entry);
	snprintf(ptr, remaining, "| %s", buffer);
	if (is_json)
		json_object_add_value_string(stats, "New FW activated", buffer);

	ptr += 12;

	/* firmware slot and commit action*/
	remaining = buf_size - (ptr - formatted_entry);
	snprintf(ptr, remaining, "| %d", entry->slot);
	if (is_json)
		json_object_add_value_int(stats, "Slot number", entry->slot);

	ptr += 9;

	remaining = buf_size - (ptr - formatted_entry);
	if (entry->commit_action_type <= 3)
		snprintf(ptr, remaining, "| %s", ca[entry->commit_action_type]);
	else
		snprintf(ptr, remaining, "| xxxb");

	if (is_json)
		json_object_add_value_string(stats, "Commit Action Type", ptr+2);

	ptr += 9;

	/* result */
	remaining = buf_size - (ptr - formatted_entry);
	if (entry->result)
		snprintf(ptr, remaining, "| Fail #%d", entry->result);
	else
		snprintf(ptr, remaining, "| pass");

	if (is_json) {
		json_object_add_value_string(stats, "Result", ptr+2);
		return 0;
	}

	/* replace all null characters with spaces */
	ptr = formatted_entry;
	while (index < entry_size) {
		if (ptr[index] == '\0')
			ptr[index] = ' ';
		index++;
	}
	return 0;
}

static void micron_fw_activation_history_header_print(void)
{
	/* header to be printed  field widths = 10 | 12 | 10 | 11 | 12 | 9 | 9 | 9 */
	printf("__________________________________________________________________________________\n");
	printf("          |           |         |          |           |        |        |\n");
	printf("Firmware  | Power On  | Power   | Previous | New FW    | Slot   | Commit | Result\n");
	printf("Activation|   Hour    | cycle   | firmware | activated | number | Action |\n");
	printf("Counter   |           | count   |          |           |        | Type   |\n");
	printf("__________|___________|_________|__________|___________|________|________|________\n");
}

static int micron_fw_activation_history(int argc, char **argv, struct command *acmd,
					struct plugin *plugin)
{
	const char *desc = "Retrieve Firmware Activation history of the given drive";
	char formatted_output[100];
	int count = 0;
	unsigned int logC2[C2_log_size/sizeof(int)] = { 0 };
	enum eDriveModel eModel = UNKNOWN_MODEL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err;
	bool is_json = false;
	struct json_object *root, *fw_act, *element;
	struct json_object *entry;
	struct format {
		char *fmt;
	};

	const char *fmt = "output format normal|json";
	struct format cfg = {
		.fmt = "normal",
	};

	NVME_ARGS(opts,
		OPT_FMT("format", 'f', &cfg.fmt, fmt));

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &eModel);
	if (err < 0)
		return -1;


	if (!strcmp(cfg.fmt, "json"))
		is_json = true;

	/* check if product supports fw_history log */
	err = -EINVAL;
	if ((eModel != M51CX) && (eModel != M51BY) && (eModel != M51CY)
				&& (eModel != M6003) && (eModel != M6004)) {
		nvme_show_error("Unsupported drive model for vs-fw-activate-history command");
		goto out;
	}

	err = nvme_get_log_simple(hdl, 0xC2, logC2, C2_log_size);
	if (err) {
		nvme_show_err(err, "Failed to retrieve fw activation history log");
		goto out;
	}

	/* check if we have at least one entry to print */
	struct micron_fw_activation_history_table *table =
			   (struct micron_fw_activation_history_table *)logC2;

	/* check version and log page */
	if (table->log_page != 0xC2 || (table->version != 2 && table->version != 1)) {
		nvme_show_error("Unsupported fw activation history page: %x, version: %x",
				table->log_page, table->version);
		goto out;
	}

	if (!table->num_entries) {
		nvme_show_error("No entries were found in fw activation history log");
		goto out;
	}

	if (is_json) {
		root = json_create_object();
			fw_act = json_create_object();
			json_object_add_value_object(root, "vs-fw-activation-history", fw_act);
			json_object_add_value_int(fw_act, "Total Entry Num",
					le32_to_cpu(table->num_entries));
			entry = json_create_array();
			json_object_add_value_array(fw_act, "Entry", entry);
			for (count = 0; count < table->num_entries; count++) {
				element = json_create_object();
				if (!display_fw_activate_entry(count, &table->entries[count],
						formatted_output, sizeof(formatted_output),
						element))
					json_array_add_value_object(entry, element);
			}
			json_print_object(root, NULL);
			printf("\n");
			json_free_object(root);
	} else {
		micron_fw_activation_history_header_print();
		for (count = 0; count < table->num_entries; count++) {
			memset(formatted_output, '\0', 100);
			if (!display_fw_activate_entry(count, &table->entries[count],
						formatted_output,
						sizeof(formatted_output), NULL))
				printf("%s\n", formatted_output);
		}
	}
out:
	return err;
}

#define MICRON_FID_LATENCY_MONITOR 0xD0
#define MICRON_LOG_LATENCY_MONITOR 0xD1

static int micron_latency_stats_track(int argc, char **argv, struct command *acmd,
					  struct plugin *plugin)
{
	int err = 0;
	__u64 result = 0;
	const char *desc = "Enable, Disable or Get cmd latency monitoring stats";
	const char *option = "enable or disable or status, default is status";
	const char *cmdstr =
			"commands to monitor for - all|read|write|trim, default is all i.e, enabled for all commands"
			;
	const char *thrtime =
			"The threshold value to use for latency monitoring in milliseconds, default is 800ms"
			;

	int fid = MICRON_FID_LATENCY_MONITOR;
	enum eDriveModel model = UNKNOWN_MODEL;
	uint32_t command_mask = 0x7;	   /* 1:read 2:write 4:trim 7:all */
	uint32_t timing_mask = 0x08080800; /* R[31-24]:W[23:16]:T[15:8]:0 */
	uint32_t enable = 2;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct {
		char *option;
		char *command;
		uint32_t threshold;
	} opt = {
		.option = "status",
		.command = "all",
		.threshold = 0
	};

	NVME_ARGS(opts,
		OPT_STRING("option", 'O', "option", &opt.option, option),
		OPT_STRING("command", 'c', "command", &opt.command, cmdstr),
		OPT_UINT("threshold", 't', &opt.threshold, thrtime));


	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &model);
	if (err < 0)
		return -1;

	if (!strcmp(opt.option, "enable")) {
		enable = 1;
	} else if (!strcmp(opt.option, "disable")) {
		enable = 0;
	} else if (strcmp(opt.option, "status")) {
		nvme_show_error("Invalid control option %s specified", opt.option);
		return -1;
	}

	err = nvme_get_features(hdl, 0, fid, 0, 0, 0, NULL, 0, &result);
	if (err) {
		nvme_show_error("Failed to retrieve latency monitoring feature status");
		return err;
	}

	/* If it is to retrieve the status only */
	if (enable == 2) {
		printf("Latency Tracking Statistics is currently %s",
			   (result & 0xFFFF0000) ? "enabled" : "disabled");
		if ((result & 7) == 7) {
			printf(" for All commands\n");
		} else if ((result & 7) > 0) {
			printf(" for");
			if (result & 1)
				printf(" Read");
			if (result & 2)
				printf(" Write");
			if (result & 4)
				printf(" Trim");
			printf(" commands\n");
		} else if (!result) {
			printf("\n");
		}
		return err;
	}

	/* read and validate threshold values if enable option is specified */
	if (enable == 1) {
		if (opt.threshold > 2550) {
			nvme_show_error("The maximum threshold value cannot be more than 2550 ms");
			return -1;
		} else if (opt.threshold % 10) {
			/* timing mask is in terms of 10ms units, so min allowed is 10ms */
			nvme_show_error("The threshold value should be multiple of 10 ms");
			return -1;
		}
		opt.threshold /= 10;
	}

	/* read-in command(s) to be monitored */
	if (!strcmp(opt.command, "read")) {
		command_mask = 0x1;
		timing_mask = (opt.threshold << 24);
	} else if (!strcmp(opt.command, "write")) {
		command_mask = 0x2;
		timing_mask = (opt.threshold << 16);
	} else if (!strcmp(opt.command, "trim")) {
		command_mask = 0x4;
		timing_mask = (opt.threshold << 8);
	} else if (strcmp(opt.command, "all")) {
		nvme_show_error("Invalid command %s specified for option %s",
		opt.command, opt.option);
		return -1;
	}

	err = nvme_set_features(hdl, 0, MICRON_FID_LATENCY_MONITOR, 1, enable,
			command_mask, timing_mask, 0, 0, NULL, 0, &result);
	if (!err) {
		nvme_show_verbose_result("Successfully %sd latency monitoring for %s commands with %dms threshold",
				opt.option, opt.command, !opt.threshold ? 800 : opt.threshold * 10);
	} else {
		nvme_show_error("Failed to %s latency monitoring for %s commands with %dms threshold",
				opt.option, opt.command, !opt.threshold ? 800 : opt.threshold * 10);
	}

	return err;
}


static int micron_latency_stats_logs(int argc, char **argv, struct command *acmd,
					 struct plugin *plugin)
{
#define  LATENCY_LOG_ENTRIES 16
	struct latency_log_entry {
		uint64_t   timestamp;
		uint32_t   latency;
		uint32_t   cmdtag;
	union {
		struct {
				uint32_t opcode:8;
		uint32_t fuse:2;
		uint32_t rsvd1:4;
		uint32_t psdt:2;
		uint32_t cid:16;
		};
			uint32_t   dw0;
	};
	uint32_t nsid;
	uint32_t slba_low;
	uint32_t slba_high;
	union {
			struct {
			uint32_t nlb:16;
			uint32_t rsvd2:9;
			uint32_t deac:1;
			uint32_t prinfo:4;
			uint32_t fua:1;
			uint32_t lr:1;
		};
			uint32_t   dw12;
	};
		uint32_t   dsm;
		uint32_t   rfu[6];
	} log[LATENCY_LOG_ENTRIES];
	enum eDriveModel model = UNKNOWN_MODEL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err = -1;
	const char *desc = "Display Latency tracking log information";

	NVME_ARGS(opts);

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &model);
	if (err)
		return err;
	memset(&log, 0, sizeof(log));
	err = nvme_get_log_simple(hdl, 0xD1, &log, sizeof(log));
	if (err) {
		nvme_show_err(err, "Unable to retrieve the latency stats log");
		return err;
	}
	/* print header and each log entry */
	printf("Timestamp, Latency, CmdTag, Opcode, Fuse, Psdt, Cid, Nsid, Slba_L, Slba_H, Nlb, ");
	printf("DEAC, PRINFO, FUA, LR\n");
	for (int i = 0; i < LATENCY_LOG_ENTRIES; i++)
		printf("%"PRIu64",%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
			   log[i].timestamp, log[i].latency, log[i].cmdtag, log[i].opcode,
			   log[i].fuse, log[i].psdt, log[i].cid, log[i].nsid,
			   log[i].slba_low, log[i].slba_high, log[i].nlb,
			   log[i].deac, log[i].prinfo, log[i].fua, log[i].lr);
	printf("\n");
	return err;
}

static int micron_latency_stats_info(int argc, char **argv, struct command *acmd,
					 struct plugin *plugin)
{
	const char *desc = "display command latency statistics";
	const char *cmdstr = "command to display stats - all|read|write|trim, default is all";
	int err = 0;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	enum eDriveModel model = UNKNOWN_MODEL;
	#define LATENCY_BUCKET_COUNT 32
	#define LATENCY_BUCKET_RSVD  32
	struct micron_latency_stats {
		uint64_t version; /* major << 32 | minior */
		uint64_t all_cmds[LATENCY_BUCKET_COUNT + LATENCY_BUCKET_RSVD];
		uint64_t read_cmds[LATENCY_BUCKET_COUNT + LATENCY_BUCKET_RSVD];
		uint64_t write_cmds[LATENCY_BUCKET_COUNT + LATENCY_BUCKET_RSVD];
		uint64_t trim_cmds[LATENCY_BUCKET_COUNT + LATENCY_BUCKET_RSVD];
		uint32_t reserved[255]; /* round up to 4K */
	} log;

	struct latency_thresholds {
		uint32_t start;
		uint32_t end;
		char *unit;
	} thresholds[LATENCY_BUCKET_COUNT] = {
		{0, 50, "us"}, {50, 100, "us"}, {100, 150, "us"}, {150, 200, "us"},
		{200, 300, "us"}, {300, 400, "us"}, {400, 500, "us"}, {500, 600, "us"},
		{600, 700, "us"}, {700, 800, "us"}, {800, 900, "us"}, {900, 1000, "us"},
		{1, 5, "ms"}, {5, 10, "ms"}, {10, 20, "ms"}, {20, 50, "ms"}, {50, 100, "ms"},
		{100, 200, "ms"}, {200, 300, "ms"}, {300, 400, "ms"}, {400, 500, "ms"},
		{500, 600, "ms"}, {600, 700, "ms"}, {700, 800, "ms"}, {800, 900, "ms"},
		{900, 1000, "ms"}, {1, 2, "s"}, {2, 3, "s"}, {3, 4, "s"}, {4, 5, "s"},
		{5, 8, "s"},
		{8, INT_MAX, "s"},
	};

	struct {
		char *command;
	} opt = {
		.command = "all"
	};

	uint64_t *cmd_stats = &log.all_cmds[0];
	char *cmd_str = "All";

	NVME_ARGS(opts,
		OPT_STRING("command", 'c', "command", &opt.command, cmdstr));

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &model);
	if (err < 0)
		return err;
	if (!strcmp(opt.command, "read")) {
		cmd_stats = &log.read_cmds[0];
	cmd_str = "Read";
	} else if (!strcmp(opt.command, "write")) {
		cmd_stats = &log.write_cmds[0];
	cmd_str = "Write";
	} else if (!strcmp(opt.command, "trim")) {
		cmd_stats = &log.trim_cmds[0];
	cmd_str = "Trim";
	} else if (strcmp(opt.command, "all")) {
		nvme_show_error("Invalid command option %s to display latency stats", opt.command);
		return -1;
	}

	memset(&log, 0, sizeof(log));
	err = nvme_get_log_simple(hdl, 0xD0, &log, sizeof(log));
	if (err) {
		nvme_show_err(err, "Unable to retrieve latency stats log for the drive");
		return err;
	}
	printf("Micron IO %s Command Latency Statistics\n"
	   "Major Revision : %d\nMinor Revision : %d\n",
	   cmd_str, (int)(log.version >> 32), (int)(log.version & 0xFFFFFFFF));
	printf("=============================================\n");
	printf("Bucket    Start     End        Command Count\n");
	printf("=============================================\n");

	for (int b = 0; b < LATENCY_BUCKET_COUNT; b++) {
		int bucket = b + 1;
		char start[32] = { 0 };
		char end[32] = { 0 };

		sprintf(start, "%u%s", thresholds[b].start, thresholds[b].unit);
		if (thresholds[b].end == INT_MAX)
			sprintf(end, "INF");
		else
			sprintf(end, "%u%s", thresholds[b].end, thresholds[b].unit);
		printf("%2d   %8s    %8s    %8"PRIu64"\n", bucket, start, end, cmd_stats[b]);
	}
	return err;
}

static int micron_ocp_smart_health_logs(int argc, char **argv, struct command *acmd,
					struct plugin *plugin)
{
	const char *desc = "Retrieve Smart or Extended Smart Health log for the given device ";
	unsigned int logC0[C0_log_size/sizeof(int)] = { 0 };
	unsigned int logFB[FB_log_size/sizeof(int)] = { 0 };
	struct nvme_id_ctrl ctrl;
	enum eDriveModel eModel = UNKNOWN_MODEL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	bool is_json = true;
	nsze_from_oacs = false;
	struct format {
		char *fmt;
	};
	const char *fmt = "output format normal|json";
	struct format cfg = {
		.fmt = "json",
	};
	int err = 0;

	NVME_ARGS(opts,
		OPT_FMT("format", 'f', &cfg.fmt, fmt));

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &eModel);
	if (err < 0)
		return -1;

	if (!strcmp(cfg.fmt, "normal"))
		is_json = false;

	/* For M5410 and M5407, this option prints 0xFB log page */
	if (eModel == M5410 || eModel == M5407) {
		__u8 spec = (eModel == M5410) ? 0 : 1;
		__u8 nsze;

		err = nvme_identify_ctrl(hdl, &ctrl);
		if (!err)
			err = nvme_get_log_simple(hdl, 0xFB, logFB, FB_log_size);
		if (err) {
			nvme_show_err(err, "Unable to retrieve smart log 0xFB for the drive");
			goto out;
		}

		nsze = (ctrl.vs[987] == 0x12);
		if (!nsze && nsze_from_oacs)
			nsze = ((ctrl.oacs >> 3) & 0x1);
		print_nand_stats_fb((__u8 *)logFB, NULL, nsze, is_json, spec);
		goto out;
	}

	/* check for models that support 0xC0 log */
	if ((eModel != M51CX) && (eModel != M51BY) && (eModel != M51CY)
				&& (eModel != M6003) && (eModel != M6004)) {
		nvme_show_error("Unsupported drive model for vs-smart-add-log command");
		err = -1;
		goto out;
	}

	err = nvme_get_log_simple(hdl, 0xC0, logC0, C0_log_size);
	if (!err)
		print_smart_cloud_health_log((__u8 *)logC0, is_json, eModel);
	else
		nvme_show_err(err, "Unable to retrieve extended smart log 0xC0 for the drive");
out:
	return err;
}

static int micron_clr_fw_activation_history(int argc, char **argv,
						struct command *command, struct plugin *plugin)
{
	const char *desc = "Clear FW activation history";
	__u64 result = 0;
	__u8 fid = MICRON_FEATURE_CLEAR_FW_ACTIVATION_HISTORY;
	enum eDriveModel model = UNKNOWN_MODEL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;

	NVME_ARGS(opts);
	int err = 0;

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &model);
	if (err < 0)
		return err;

	if ((model != M51CX) && (model != M51BY) && (model != M51CY)
				&& (model != M6003) && (model != M6004)) {
		nvme_show_error("This option is not supported for specified drive");
		return err;
	}

	err = nvme_set_features_simple(hdl, 1 << 31, fid, 0, 0, &result);
	if (!err)
		err = (int)result;
	else
		nvme_show_err(err, "Failed to clear fw activation history");

	return err;
}

static int micron_telemetry_cntrl_option(int argc, char **argv,
					 struct command *command, struct plugin *plugin)
{
	int err = 0;
	__u64 result = 0;
	const char *desc = "Enable or Disable Controller telemetry log generation";
	const char *option = "enable or disable or status";
	const char *select =
		"select/save values: enable/disable options1 - save (persistent), 0 - non-persistent and for status options: 0 - current, 1 - default, 2-saved"
		;

	int fid = MICRON_FEATURE_TELEMETRY_CONTROL_OPTION;
	enum eDriveModel model = UNKNOWN_MODEL;
	struct nvme_id_ctrl ctrl = { 0 };
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;

	struct {
		char *option;
		int  select;
	} opt = {
		.option = "disable",
		.select = 0,
	};

	NVME_ARGS(opts,
		OPT_STRING("option", 'O', "option", &opt.option, option),
		OPT_UINT("select", 's', &opt.select, select));

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &model);
	if (err < 0)
		return -1;

	err = nvme_identify_ctrl(hdl, &ctrl);
	if ((ctrl.lpa & 0x8) != 0x8) {
		printf("drive doesn't support host/controller generated telemetry logs\n");
		return err;
	}

	if (!strcmp(opt.option, "enable")) {
		err = nvme_set_features(hdl, 1, fid, (opt.select & 0x1), 1, 0, 0, 0, 0,
				NULL, 0, &result);
		if (!err)
			nvme_show_verbose_result("successfully set controller telemetry option");
		else
			nvme_show_error("Failed to set controller telemetry option");
	} else if (!strcmp(opt.option, "disable")) {
		err = nvme_set_features(hdl, 1, fid, (opt.select & 0x1), 0, 0, 0, 0, 0,
				NULL, 0, &result);
		if (!err)
			nvme_show_verbose_result("successfully disabled controller telemetry option");
		else
			nvme_show_error("Failed to disable controller telemetry option");
	} else if (!strcmp(opt.option, "status")) {
		err = nvme_get_features(hdl, 1, fid, opt.select & 0x3, 0, 0, NULL, 0,
				&result);
		if (!err)
			printf("Controller telemetry option : %s\n",
				   (result) ? "enabled" : "disabled");
		else
			nvme_show_error("Failed to retrieve controller telemetry option");
	} else {
		nvme_show_error("invalid option %s, valid values are enable,disable or status",
			   opt.option);
		return -1;
	}

	return err;
}

/* M51XX models log page header */
struct micron_common_log_header  {
	uint8_t  id;
	uint8_t  version;
	uint16_t pn;
	uint32_t log_size;
	uint32_t max_size;
	uint32_t write_pointer;
	uint32_t next_pointer;
	uint32_t overwritten_bytes;
	uint8_t  flags;
	uint8_t  reserved[7];
};

/* helper function to retrieve logs with specific offset and max chunk size */
int nvme_get_log_lpo(struct libnvme_transport_handle *hdl, __u8 log_id, __u32 lpo, __u32 chunk,
		     __u32 data_len, void *data)
{
	__u32 offset = lpo, xfer_len = data_len;
	struct libnvme_passthru_cmd cmd;
	void *ptr = data;
	int ret = 0;

	/* divide data into multiple chunks */
	do {
		xfer_len = data_len - offset;
		if (xfer_len > chunk)
			xfer_len = chunk;

		nvme_init_get_log(&cmd, NVME_NSID_ALL, log_id, NVME_CSI_NVM,
				  ptr, xfer_len);
		nvme_init_get_log_lpo(&cmd, lpo);
		ret = libnvme_get_log(hdl, &cmd, false, xfer_len);
		if (ret)
			return ret;
		offset += xfer_len;
		ptr += xfer_len;
	} while (offset < data_len);
	return ret;
}

/* retrieves logs with common log format */
static int get_common_log(struct libnvme_transport_handle *hdl, uint8_t id, uint8_t **buf, int *size)
{
	struct micron_common_log_header hdr = { 0 };
	int log_size = sizeof(hdr), first = 0, second = 0;
	uint8_t *buffer = NULL;
	int ret = -1;
	int chunk = 0x4000; /* max chunk size to be used for these logs */

	ret = nvme_get_log_simple(hdl, id, &hdr, sizeof(hdr));
	if (ret) {
		nvme_show_error("pull hdr failed for  %u with error: 0x%x", id, ret);
		return ret;
	}

	if (hdr.id != id || !hdr.log_size || !hdr.max_size ||
		hdr.write_pointer < sizeof(hdr)) {
		nvme_show_error(
			"invalid log data for LOG: 0x%X, id: 0x%X, size: %u, max: %u, wp: %u, flags: %u, np: %u\n"
			, id, hdr.id, hdr.log_size, hdr.max_size, hdr.write_pointer, hdr.flags,
			hdr.next_pointer);
		return 1;
	}

	/*
	 * we may have just 32-bytes for some models; write to wfile if log hasn't
	 * yet reached its max size
	 */
	if (hdr.log_size == sizeof(hdr)) {
		buffer = (uint8_t *)libnvme_alloc(sizeof(hdr));
		if (!buffer) {
			nvme_show_error("malloc of %zu bytes failed for log: 0x%X",
				sizeof(hdr), id);
			return -ENOMEM;
		}
		memcpy(buffer, (uint8_t *)&hdr, sizeof(hdr));
	} else if (hdr.log_size < hdr.max_size) {
		buffer = (uint8_t *)libnvme_alloc(sizeof(hdr) + hdr.log_size);
		if (!buffer) {
			nvme_show_error("malloc of %zu bytes failed for log: 0x%X",
				hdr.log_size + sizeof(hdr), id);
			return -ENOMEM;
		}
		memcpy(buffer, &hdr, sizeof(hdr));
		ret = nvme_get_log_lpo(hdl, id, sizeof(hdr), chunk, hdr.log_size,
					   buffer + sizeof(hdr));
		if (!ret)
			log_size += hdr.log_size;
	} else if (hdr.log_size >= hdr.max_size) {
		/*
		 * reached maximum, to maintain, sequence we need to depend on write
		 * pointer to detect wrap-overs. FW doesn't yet implement the condition
		 * hdr.log_size > hdr.max_size; also ignore over-written log data; we
		 * also ignore collisions for now
		 */
		buffer = (uint8_t *)libnvme_alloc(hdr.max_size + sizeof(hdr));
		if (!buffer) {
			nvme_show_error("malloc of %zu bytes failed for log: 0x%X",
				hdr.max_size + sizeof(hdr), id);
			return -ENOMEM;
		}
		memcpy(buffer, &hdr, sizeof(hdr));

		first = hdr.max_size - hdr.write_pointer;
		second = hdr.write_pointer - sizeof(hdr);

		if (first) {
			ret = nvme_get_log_lpo(hdl, id, hdr.write_pointer, chunk, first,
						   buffer + sizeof(hdr));
			if (ret) {
				libnvme_free(buffer);
				nvme_show_error("failed to get log: 0x%X", id);
				return ret;
			}
			log_size += first;
		}
		if (second) {
			ret = nvme_get_log_lpo(hdl, id, sizeof(hdr), chunk, second,
						   buffer + sizeof(hdr) + first);
			if (ret) {
				nvme_show_error("failed to get log: 0x%X", id);
				libnvme_free(buffer);
				return ret;
			}
			log_size += second;
		}
	}
	*buf = buffer;
	*size = log_size;
	return ret;
}

static int GetOcpEnhancedTelemetryLog(struct libnvme_transport_handle *hdl, const char *dir, int nLogID)
{
	int err = 0;
	__cleanup_libnvme_free unsigned char *pTelemetryDataHeader = NULL;
	unsigned int nallocSize = 0;
	unsigned int nOffset = 0;
	unsigned char *pTelemetryBuffer = NULL;
	unsigned int usAreaLastBlock[4] = {0};
	bool bTeleheaderWrite = true;
	/* Enable ETDAS */
	unsigned int uiBufferSize = 512;
	unsigned char pBuffer[512] = { 0 };
	__u64 result = 0;

	pBuffer[1] = 1;

	err = nvme_set_features(hdl, NVME_NSID_ALL,
			MICRON_FEATURE_OCP_ENHANCED_TELEMETRY, 1, 0, 0, 0,
			0, 0, pBuffer, uiBufferSize, &result);

	if (err != 0)
		nvme_show_error("Failed to set ETDAS, Data Area 4 won't be avialable");

	/* Read Telemetry header information */
	pTelemetryDataHeader = (unsigned char *)libnvme_alloc(512);

	if (!pTelemetryDataHeader) {
		nvme_show_error("Unable to allocate buffer of size 0x%X bytes for telemetry header", 512);
		return -1;
	}
	err = NVMEGetLogPage(hdl, nLogID, pTelemetryDataHeader, 512, 0);

	if (err != 0)
		return err;

	nOffset += 512;
	int n = 8;
	/* Get size of log page */
	for (int i = 0; i < 3; i++) {
		usAreaLastBlock[i] = (pTelemetryDataHeader[n + 1] << 8) | pTelemetryDataHeader[n];
		n += 2;
	}
	n += 2;
	usAreaLastBlock[3] = (pTelemetryDataHeader[n + 3] << 24) |
						(pTelemetryDataHeader[n + 2] << 16) |
						(pTelemetryDataHeader[n + 1] << 8) |
						pTelemetryDataHeader[n];

	for (int nArea = 0; nArea <= 3; nArea++) {
		if (nArea != 0)
			nallocSize = (usAreaLastBlock[nArea] - usAreaLastBlock[nArea - 1]) * 512;
		else
			nallocSize = usAreaLastBlock[nArea] * 512;

		if (nallocSize == 0) {
			printf(
				"Enhanced Telemetry log Data Area %d Size is zero, continuing with next available Data Area\n"
				, (nArea + 1));
			continue;
		}

		pTelemetryBuffer = (unsigned char *)libnvme_alloc(nallocSize);
		if (!pTelemetryBuffer) {
			printf(
				"Unable to allocate buffer of size 0x%X bytes for Data Area %d"
				, nallocSize, (nArea + 1)
			);
			nOffset += nallocSize;
			continue;
		}
		/* Fetch the Data */
		err = NVMEGetLogPage(hdl, nLogID, pTelemetryBuffer, nallocSize, nOffset);

		if (err != 0) {
			printf(
				"Failed to fetch telemetry data of size : %u from offset : %u!\n"
				, nallocSize, nOffset
			);
			libnvme_free(pTelemetryBuffer);
			pTelemetryBuffer = NULL;
			nOffset += nallocSize;
			continue;
		}

		/* Increment the Offset value */
		nOffset += nallocSize;

		if ((nArea + 1) <= 4) {
			char strBuffer[256] = { 0 };

			if (nLogID == NVME_LOG_LID_TELEMETRY_HOST) {
				snprintf(strBuffer, sizeof(strBuffer), "%s", "nvme_host_telemetry_log.bin");
				if (bTeleheaderWrite) {
					WriteData(pTelemetryDataHeader, 512, dir,
						"nvme_host_telemetry_log.bin", strBuffer);
					bTeleheaderWrite = false;
				}
				WriteData(pTelemetryBuffer, nallocSize, dir,
					"nvme_host_telemetry_log.bin", strBuffer);
			} else if (nLogID == NVME_LOG_LID_TELEMETRY_CTRL) {
				snprintf(strBuffer, sizeof(strBuffer), "%s", "nvme_controller_telemetry_log.bin");
				if (bTeleheaderWrite) {
					WriteData(pTelemetryDataHeader, 512, dir,
						"nvme_controller_telemetry_log.bin", strBuffer);
					bTeleheaderWrite = false;
				}
				WriteData(pTelemetryBuffer, nallocSize, dir,
					"nvme_controller_telemetry_log.bin", strBuffer);
			}
		}

		libnvme_free(pTelemetryBuffer);
		pTelemetryBuffer = NULL;
	}

	return err;
}


static int micron_internal_logs(int argc, char **argv, struct command *acmd,
				struct plugin *plugin)
{
	int err = -EINVAL;
	int ctrlIdx, telemetry_option = 0;
	char strOSDirName[1024];
	char strCtrlDirName[1024];
	char strMainDirName[256];
	unsigned int *puiIDDBuf;
	unsigned int uiMask;
	struct nvme_id_ctrl ctrl;
	char safe_sn[sizeof(ctrl.sn) + 1] = { 0 };
	char msg[256] = { 0 };
	int  c_logs_index = 8; /* should be current size of aVendorLogs */
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct {
		unsigned char ucLogPage;
		const char *strFileName;
		int nLogSize;
		int nMaxSize;
	} aVendorLogs[32] = {
		{ 0x03, "firmware_slot_info_log.bin", 512, 0 },
		{ 0xC1, "nvmelog_C1.bin", 0, 0 },
		{ 0xC2, "nvmelog_C2.bin", 0, 0 },
		{ 0xC4, "nvmelog_C4.bin", 0, 0 },
		{ 0xC5, "nvmelog_C5.bin", C5_log_size, 0 },
		{ 0xD0, "nvmelog_D0.bin", D0_log_size, 0 },
		{ 0xE6, "nvmelog_E6.bin", 0, 0 },
		{ 0xE7, "nvmelog_E7.bin", 0, 0 }
	},
	aM51XXLogs[] = {
		{ 0xFB, "nvmelog_FB.bin", 4096, 0 },  /* this should be collected first for M51AX */
		{ 0xD0, "nvmelog_D0.bin", 512, 0 },
		{ 0x03, "firmware_slot_info_log.bin", 512, 0},
		{ 0xF7, "nvmelog_F7.bin", 4096, 512 * 1024 },
		{ 0xF8, "nvmelog_F8.bin", 4096, 512 * 1024 },
		{ 0xF9, "nvmelog_F9.bin", 4096, 200 * 1024 * 1024 },
		{ 0xFC, "nvmelog_FC.bin", 4096, 200 * 1024 * 1024 },
		{ 0xFD, "nvmelog_FD.bin", 4096, 80 * 1024 * 1024 }
	},
	aM51AXLogs[] = {
		{ 0xCA, "nvmelog_CA.bin", 512, 0 },
		{ 0xFA, "nvmelog_FA.bin", 4096, 15232 },
		{ 0xF6, "nvmelog_F6.bin", 4096, 512 * 1024 },
		{ 0xFE, "nvmelog_FE.bin", 4096, 512 * 1024 },
		{ 0xFF, "nvmelog_FF.bin", 4096, 162 * 1024 },
		{ 0x04, "changed_namespace_log.bin", 4096, 0 },
		{ 0x05, "command_effects_log.bin", 4096, 0 },
		{ 0x06, "drive_self_test.bin", 4096, 0 }
	},
	aM51BXLogs[] = {
		{ 0xFA, "nvmelog_FA.bin", 4096, 16376 },
		{ 0xFE, "nvmelog_FE.bin", 4096, 256 * 1024 },
		{ 0xFF, "nvmelog_FF.bin", 4096, 64 * 1024 },
		{ 0xCA, "nvmelog_CA.bin", 512, 1024 }
	},
	aM51CXLogs[] = {
		{ 0xE1, "nvmelog_E1.bin", 0, 0 },
		{ 0xE2, "nvmelog_E2.bin", 0, 0 },
		{ 0xE3, "nvmelog_E3.bin", 0, 0 },
		{ 0xE4, "nvmelog_E4.bin", 0, 0 },
		{ 0xE5, "nvmelog_E5.bin", 0, 0 },
		{ 0xE8, "nvmelog_E8.bin", 0, 0 },
		{ 0xE9, "nvmelog_E9.bin", 0, 0 },
		{ 0xEA, "nvmelog_EA.bin", 0, 0 }
	};

	enum eDriveModel eModel;

	const char *desc = "This retrieves the micron debug log package";
	const char *package = "Log output data file name (required)";
	const char *type = "telemetry log type - host or controller";
	const char *data_area = "telemetry log data area 1, 2, 3 or 4";
	unsigned char *dataBuffer = NULL;
	int bSize = 0;
	int maxSize = 0;
	struct MICRON_WORKLOAD_LOG_HDR stWllHdr = { 0 };

	struct config {
		char *type;
		char *package;
		int  data_area;
		int  log;
	};

	struct config cfg = {
		.type = "",
		.package = "",
		.data_area = -1,
		.log = 0x07,
	};

	NVME_ARGS(opts,
		OPT_STRING("type", 't', "log type", &cfg.type, type),
		OPT_STRING("package", 'p', "FILE", &cfg.package, package),
		OPT_UINT("data_area", 'd', &cfg.data_area, data_area));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	/* if telemetry type is specified, check for data area */
	if (strlen(cfg.type)) {
		if (!strcmp(cfg.type, "controller")) {
			cfg.log = 0x08;
		} else if (strcmp(cfg.type, "host")) {
			nvme_show_error("telemetry type (host or controller) should be specified i.e. -t=host");
			goto out;
		}

		if (cfg.data_area <= 0 || cfg.data_area > 4) {
			nvme_show_error("data area must be selected using -d option ie --d=1,2,3,4");
			goto out;
		}
		telemetry_option = 1;
	} else if (cfg.data_area > 0) {
		nvme_show_error(
			"data area option is valid only for telemetry option (i.e --type=host|controller)");
		goto out;
	}

	if (!strlen(cfg.package)) {
		if (telemetry_option)
			nvme_show_error("Log data file must be specified. ie -p=logfile.bin");
		else
			nvme_show_error(
				"Log data file must be specified. ie -p=logfile.zip or -p=logfile.tgz|logfile.tar.gz");
		goto out;
	}

	if (!is_safe_path(cfg.package)) {
		nvme_show_error(
			"Invalid package path: contains unsafe characters\n");
		goto out;
	}

	/* pull log details based on the model name */
	eModel = GetDriveModel(ctx, hdl);
	if (eModel == UNKNOWN_MODEL) {
		nvme_show_error("Unsupported drive model for vs-internal-log collection");
		goto out;
	}

	if (sscanf(libnvme_transport_handle_get_name(hdl), "nvme%d", &ctrlIdx) != 1)
		ctrlIdx = 0;

	err = nvme_identify_ctrl(hdl, &ctrl);
	if (err)
		goto out;

	err = -EINVAL;
	if (telemetry_option) {
		if ((ctrl.lpa & 0x8) != 0x8) {
			nvme_show_error("telemetry option is not supported for specified drive");
			goto out;
		}
		int logSize = 0; __u8 *buffer = NULL; const char *dir = ".";

		err = micron_telemetry_log(hdl, cfg.log,  &buffer, &logSize,
				   cfg.data_area);
		if (!err && logSize > 0 && buffer) {
			snprintf(msg, sizeof(msg), "telemetry log: 0x%X", cfg.log);
			WriteData(buffer, logSize, dir, cfg.package, msg);
			libnvme_free(buffer);
		}
		goto out;
	}

	printf("Preparing log package. This will take a few seconds...\n");

	strncpy(safe_sn, ctrl.sn, sizeof(safe_sn) - 1);
	sanitize_serial(safe_sn, sizeof(safe_sn));
	err = SetupDebugDataDirectories(safe_sn, cfg.package,
			strMainDirName, sizeof(strMainDirName),
			strOSDirName, sizeof(strOSDirName),
			strCtrlDirName, sizeof(strCtrlDirName));
	if (err) {
		nvme_show_error("Failed to create debug data directories");
		goto out;
	}

	GetTimestampInfo(strOSDirName);
	GetCtrlIDDInfo(strCtrlDirName, &ctrl);
	GetOSConfig(strOSDirName);
	GetDriveInfo(strOSDirName, ctrlIdx, &ctrl);

	for (int i = 1; i <= ctrl.nn; i++)
		GetNSIDDInfo(hdl, strCtrlDirName, i);

	GetSmartlogData(hdl, strCtrlDirName);
	GetErrorlogData(hdl, ctrl.elpe, strCtrlDirName);
	GetGenericLogs(hdl, strCtrlDirName);
	/* pull if telemetry log data is supported */
	if ((ctrl.lpa & 0x8) == 0x8) {
		if (eModel == M51BY) {
			err = GetOcpEnhancedTelemetryLog(hdl, strCtrlDirName,
								NVME_LOG_LID_TELEMETRY_HOST);
			if (err != 0)
				nvme_show_error("Failed to fetch the host telemetry log");

			err = GetOcpEnhancedTelemetryLog(hdl, strCtrlDirName,
								NVME_LOG_LID_TELEMETRY_CTRL);
			if (err != 0)
				nvme_show_error("Failed to fetch the controller telemetry log");
		} else {
			GetTelemetryData(hdl, strCtrlDirName);
		}
	}
	GetFeatureSettings(hdl, strCtrlDirName);

	if (eModel != M5410 && eModel != M5407) {
		memcpy(&aVendorLogs[c_logs_index], aM51XXLogs, sizeof(aM51XXLogs));
		c_logs_index += ARRAY_SIZE(aM51XXLogs);
		if (eModel == M51AX)
			memcpy((char *)&aVendorLogs[c_logs_index], aM51AXLogs, sizeof(aM51AXLogs));
		else if (eModel == M51BX)
			memcpy((char *)&aVendorLogs[c_logs_index], aM51BXLogs, sizeof(aM51BXLogs));
		else if (eModel == M51CX || eModel == M51BY || eModel == M51CY)
			memcpy((char *)&aVendorLogs[c_logs_index], aM51CXLogs, sizeof(aM51CXLogs));
	}

	for (int i = 0; i < (int)(ARRAY_SIZE(aVendorLogs)) && aVendorLogs[i].ucLogPage; i++) {
		err = -1;
		switch (aVendorLogs[i].ucLogPage) {
		case 0xE1:
		case 0xE5:
			err = 1;
			break;
		case 0xE9:
		if (eModel == M51CX || eModel == M51BY) {
			err = NVMEGetLogPage(hdl, aVendorLogs[i].ucLogPage,
					(unsigned char *)&stWllHdr,
					sizeof(struct MICRON_WORKLOAD_LOG_HDR), 0);
			if (err == 0) {
				bSize =  stWllHdr.uiLength;
				if (bSize < (int)sizeof(struct MICRON_WORKLOAD_LOG_HDR)) {
					nvme_show_error("Invalid log size for log id : 0x%02X",
						aVendorLogs[i].ucLogPage);
					err = -1;
					break;
				}
				dataBuffer = (unsigned char *)libnvme_alloc(bSize);
				if (!dataBuffer) {
					nvme_show_error("Memory allocation failed for log id : 0x%02X",
						aVendorLogs[i].ucLogPage);
					continue;
				}
				memcpy(dataBuffer, &stWllHdr,
					sizeof(struct MICRON_WORKLOAD_LOG_HDR));
				err = NVMEGetLogPage(hdl,
					aVendorLogs[i].ucLogPage,
					(dataBuffer +
					sizeof(struct MICRON_WORKLOAD_LOG_HDR)),
					(bSize -
					sizeof(struct MICRON_WORKLOAD_LOG_HDR)),
					sizeof(struct MICRON_WORKLOAD_LOG_HDR));
				if (err != 0)
					nvme_show_error("Failed to fetch the E9 logs");

			}
		} else {
			err = 1;
		}
			break;
		case 0xE2:
			if (eModel == M51CX || eModel == M51BY || eModel == M51CY)
				continue;

			err = get_common_log(hdl, aVendorLogs[i].ucLogPage,
			&dataBuffer, &bSize);
			break;
		case 0xE3:
		case 0xE4:
		case 0xE8:
		case 0xEA:
			err = get_common_log(hdl, aVendorLogs[i].ucLogPage,
				 &dataBuffer, &bSize);
			break;
		case 0xC1:
		case 0xC2:
			if (eModel == M51CX || eModel == M51BY || eModel == M51CY)
				continue;

			err = GetLogPageSize(hdl, aVendorLogs[i].ucLogPage, &bSize);
			if (err == 0 && bSize > 0)
				err = GetCommonLogPage(hdl,
				aVendorLogs[i].ucLogPage,
				&dataBuffer, bSize);
			break;
		case 0xC4:
			if (eModel == M51BY || eModel == M51CY)
				continue;

			err = GetLogPageSize(hdl, aVendorLogs[i].ucLogPage,
						 &bSize);
			if (!err && bSize > 0)
				err = GetCommonLogPage(hdl, aVendorLogs[i].ucLogPage,
							   &dataBuffer, bSize);
			break;
		case 0xE6:
		case 0xE7:
			puiIDDBuf = (unsigned int *)&ctrl;
			uiMask = puiIDDBuf[1015];
			if (!uiMask || (aVendorLogs[i].ucLogPage == 0xE6 && uiMask == 2) ||
				(aVendorLogs[i].ucLogPage == 0xE7 && uiMask == 1)) {
				bSize = 0;
			} else {
				bSize = (int)puiIDDBuf[1023];
				if (bSize % (16 * 1024))
					bSize += (16 * 1024) - (bSize % (16 * 1024));
			}
			dataBuffer = (unsigned char *)libnvme_alloc(bSize);
			if (bSize && dataBuffer) {
				memset(dataBuffer, 0, bSize);
				if (eModel == M5410 || eModel == M5407)
					err = NVMEGetLogPage(hdl,
					aVendorLogs[i].ucLogPage,
					dataBuffer, bSize, 0);
				else
					err = nvme_get_log_simple(hdl,
								  aVendorLogs[i].ucLogPage,
								  dataBuffer, bSize);
			}
			break;
		case 0xF7:
		case 0xF9:
		case 0xFC:
		case 0xFD:
			if (eModel == M51BX)
				(void)NVMEResetLog(hdl, aVendorLogs[i].ucLogPage,
						   aVendorLogs[i].nLogSize, aVendorLogs[i].nMaxSize);

		default:
			bSize = aVendorLogs[i].nLogSize;
			dataBuffer = (unsigned char *)libnvme_alloc(bSize);
			if (!dataBuffer)
				break;
			memset(dataBuffer, 0, bSize);
			err = nvme_get_log_simple(hdl, aVendorLogs[i].ucLogPage,
					  dataBuffer, bSize);
			maxSize = aVendorLogs[i].nMaxSize - bSize;
			while (!err && maxSize > 0 && ((unsigned int *)dataBuffer)[0] != 0xdeadbeef) {
				snprintf(msg, sizeof(msg), "log 0x%x", aVendorLogs[i].ucLogPage);
				WriteData(dataBuffer, bSize, strCtrlDirName, aVendorLogs[i].strFileName, msg);
				err = nvme_get_log_simple(hdl,
					  aVendorLogs[i].ucLogPage,
					  dataBuffer, bSize);
				if (err || (((unsigned int *)dataBuffer)[0] == 0xdeadbeef))
					break;
				maxSize -= bSize;
			}
			break;
		}

		if (!err && dataBuffer && ((unsigned int *)dataBuffer)[0] != 0xdeadbeef) {
			snprintf(msg, sizeof(msg), "log 0x%x", aVendorLogs[i].ucLogPage);
			WriteData(dataBuffer, bSize, strCtrlDirName, aVendorLogs[i].strFileName, msg);
		}

		libnvme_free(dataBuffer);
		dataBuffer = NULL;
	}

	err = ZipAndRemoveDir(strMainDirName, cfg.package);
out:
	return err;
}

#define MIN_LOG_SIZE 512
static int micron_logpage_dir(int argc, char **argv, struct command *acmd,
				  struct plugin *plugin)
{
	int err = -1;
	const char *desc = "List the supported log pages";
	enum eDriveModel model = UNKNOWN_MODEL;
	char logbuf[MIN_LOG_SIZE];
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int i;

	NVME_ARGS(opts);

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &model);
	if (err < 0)
		return err;

	struct nvme_supported_logs {
		uint8_t log_id;
		uint8_t supported;
		char	*desc;
	} log_list[] = {
		{0x00, 0, "Support Log Pages"},
		{0x01, 0, "Error Information"},
		{0x02, 0, "SMART / Health Information"},
		{0x03, 0, "Firmware Slot Information"},
		{0x04, 0, "Changed Namespace List"},
		{0x05, 0, "Commands Supported and Effects"},
		{0x06, 0, "Device Self Test"},
		{0x07, 0, "Telemetry Host-Initiated"},
		{0x08, 0, "Telemetry Controller-Initiated"},
		{0x09, 0, "Endurance Group Information"},
		{0x0A, 0, "Predictable Latency Per NVM Set"},
		{0x0B, 0, "Predictable Latency Event Aggregate"},
		{0x0C, 0, "Asymmetric Namespace Access"},
		{0x0D, 0, "Persistent Event Log"},
		{0x0E, 0, "Predictable Latency Event Aggregate"},
		{0x0F, 0, "Endurance Group Event Aggregate"},
		{0x10, 0, "Media Unit Status"},
		{0x11, 0, "Supported Capacity Configuration List"},
		{0x12, 0, "Feature Identifiers Supported and Effects"},
		{0x13, 0, "NVMe-MI Commands Supported and Effects"},
		{0x14, 0, "Command and Feature lockdown"},
		{0x15, 0, "Boot Partition"},
		{0x16, 0, "Rotational Media Information"},
		{0x70, 0, "Discovery"},
		{0x80, 0, "Reservation Notification"},
		{0x81, 0, "Sanitize Status"},
		{0xC0, 0, "SMART Cloud Health Log"},
		{0xC2, 0, "Firmware Activation History"},
		{0xC3, 0, "Latency Monitor Log"},
	};

	printf("Supported log page list\nLog ID : Description\n");
	for (i = 0; i < ARRAY_SIZE(log_list); i++) {
		err = nvme_get_log_simple(hdl, log_list[i].log_id,
					  &logbuf[0], MIN_LOG_SIZE);
		if (err)
			continue;
		printf("%02Xh    : %s\n", log_list[i].log_id, log_list[i].desc);
	}

	return err;
}

static int micron_cloud_boot_SSD_version(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	const char *desc = "Prints HyperScale Boot Version";
	unsigned char logC0[C0_log_size] = { 0 };
	struct nvme_id_ctrl ctrl;
	enum eDriveModel eModel = UNKNOWN_MODEL;
	int err = 0;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct format {
	char *fmt;
	};
	const char *fmt = "output format normal";
	struct format cfg = {
		.fmt = "normal",
	};

	NVME_ARGS(opts,
		OPT_FMT("format", 'f', &cfg.fmt, fmt));

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &eModel);
	if (err < 0)
		return -1;

	err = nvme_identify_ctrl(hdl, &ctrl);
	if (err == 0) {
		if (ctrl.vs[536] != MICRON_CUST_ID_GG) {
			nvme_show_error("cloud-boot-SSD-version option is not supported for specified drive");
			goto out;
		}
	} else {
		nvme_show_error("Error %d retrieving controller identification data", err);
		goto out;
	}

	err = nvme_get_log_simple(hdl, 0xC0, logC0, C0_log_size);
	if (err == 0) {
		__u16 major, minor;

		major  = *((__u16 *)(logC0+300));
		minor  = *((__u16 *)(logC0+302));

		printf("HyperScale Boot Version Spec.%x.%x\n", le16_to_cpu(major)
				, le16_to_cpu(minor));
	} else {
		nvme_show_err(err, "Error retrieving extended smart log 0xC0 for the drive");
		goto out;
	}
out:
	return err;
}

static int micron_device_waf(int argc, char **argv, struct command *acmd,
							  struct plugin *plugin)
{
	const char *desc = "Prints device Write Amplification Factor(WAF)";
	unsigned char logC0[C0_log_size] = { 0 };
	struct nvme_id_ctrl ctrl;
	struct nvme_smart_log smart_log;
	enum eDriveModel eModel = UNKNOWN_MODEL;
	int err = 0;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;

	long double tlc_units_written, slc_units_written;
	long double data_units_written, write_amplification_factor;

	struct format {
		char *fmt;
	};

	const char *fmt = "output format normal";

	struct format cfg = {
			.fmt = "normal",
	};

	NVME_ARGS(opts,
			OPT_FMT("format", 'f', &cfg.fmt, fmt));

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &eModel);
	if (err < 0)
		return -1;

	err = nvme_identify_ctrl(hdl, &ctrl);
	if (err == 0) {
		if (ctrl.vs[536] != MICRON_CUST_ID_GG) {
			nvme_show_error("vs-device-waf option is not supported for specified drive");
			goto out;
		}
	} else {
		nvme_show_error("Error %d retrieving controller identification data", err);
		goto out;
	}

	err = nvme_get_log_smart(hdl, NVME_NSID_ALL, &smart_log);
	if (err != 0) {
		nvme_show_error("nvme_smart_log() failed, err = %d", err);
		goto out;
	}

	err = nvme_get_log_simple(hdl, 0xC0, logC0, C0_log_size);
	if (err != 0) {
		nvme_show_error("Failed to get extended smart log, err = %d", err);
		goto out;
	}

	data_units_written = int128_to_double(smart_log.data_units_written);
	tlc_units_written = int128_to_double((__u8 *)logC0);
	slc_units_written = int128_to_double((__u8 *)(logC0+16));
	write_amplification_factor = (data_units_written/(tlc_units_written + slc_units_written));
	printf("Write Amplification Factor %.0Lf\n", write_amplification_factor);

out:
	return err;
}

static int micron_cloud_log(int argc, char **argv, struct command *acmd,
								struct plugin *plugin)
{
	const char *desc = "Retrieve Smart or Extended Smart Health log for the given device ";
	unsigned int logC0[C0_log_size/sizeof(int)] = { 0 };
	struct nvme_id_ctrl ctrl;
	enum eDriveModel eModel = UNKNOWN_MODEL;
	int err = 0;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	bool is_json = true;
	struct format {
		char *fmt;
	};
	const char *fmt = "output format normal|json";
	struct format cfg = {
		.fmt = "json",
	};

	NVME_ARGS(opts,
		OPT_FMT("format", 'f', &cfg.fmt, fmt));

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &eModel);
	if (err < 0)
		return -1;

	if (strcmp(cfg.fmt, "normal") == 0)
		is_json = false;

	/* check for models that support 0xC0 log */
	if (eModel != M51CX) {
		nvme_show_error("Unsupported drive model for vs-cloud-log commmand");
		err = -1;
		goto out;
	}

	err = nvme_identify_ctrl(hdl, &ctrl);
	if (err == 0) {
		if (ctrl.vs[536] != MICRON_CUST_ID_GG) {
			nvme_show_error("vs-cloud-log option is not supported for specified drive");
			goto out;
		}
	} else {
		nvme_show_error("Error %d retrieving controller identification data", err);
		goto out;
	}

	err = nvme_get_log_simple(hdl, 0xC0, logC0, C0_log_size);
	if (err == 0)
		print_hyperscale_cloud_health_log((__u8 *)logC0, is_json);
	else
		nvme_show_error("Unable to retrieve extended smart log 0xC0 for the drive");

out:
	if (err > 0)
		nvme_show_status(err);
	return err;
}

/* Extended SMART log structure with Micron-specific fields in reserved area */
struct micron_smart_log_ext {
	struct nvme_smart_log base;
	/* Access vendor-specific fields via rsvd232 overlay */
};

static inline __u64 get_smart_olec(struct nvme_smart_log *smart)
{
	return le64_to_cpu(smart->op_lifetime_energy_consumed);
}

static inline __u32 get_smart_ipm(struct nvme_smart_log *smart)
{
	return le32_to_cpu(smart->interval_power_measurement);
}

static void print_micron_health_log_normal(struct nvme_smart_log *smart,
					   const char *devname)
{
	__u16 temp = smart->temperature[1] << 8 | smart->temperature[0];
	__u64 olec = get_smart_olec(smart);
	__u32 ipm = get_smart_ipm(smart);
	int i;

	printf("SMART/Health Information Log for %s\n", devname);
	printf("========================================\n");

	printf("Critical Warning             : 0x%02x\n",
	       smart->critical_warning);
	if (smart->critical_warning) {
		if (smart->critical_warning & 0x01)
			printf("  - Available spare below threshold\n");
		if (smart->critical_warning & 0x02)
			printf("  - Temperature threshold exceeded\n");
		if (smart->critical_warning & 0x04)
			printf("  - NVM subsystem reliability degraded\n");
		if (smart->critical_warning & 0x08)
			printf("  - Media placed in read-only mode\n");
		if (smart->critical_warning & 0x10)
			printf("  - Volatile memory backup failed\n");
		if (smart->critical_warning & 0x20)
			printf("  - PMR read-only or unreliable\n");
	}

	printf("Composite Temperature        : %u K (%d C)\n",
	       temp, temp ? temp - 273 : 0);
	printf("Available Spare              : %u%%\n", smart->avail_spare);
	printf("Available Spare Threshold    : %u%%\n", smart->spare_thresh);
	printf("Percentage Used              : %u%%\n", smart->percent_used);
	printf("Endurance Grp Critical Warn  : 0x%02x\n",
	       smart->endu_grp_crit_warn_sumry);

	printf("Data Units Read              : %s\n",
	       uint128_t_to_string(le128_to_cpu(smart->data_units_read)));
	printf("Data Units Written           : %s\n",
	       uint128_t_to_string(le128_to_cpu(smart->data_units_written)));
	printf("Host Read Commands           : %s\n",
	       uint128_t_to_string(le128_to_cpu(smart->host_reads)));
	printf("Host Write Commands          : %s\n",
	       uint128_t_to_string(le128_to_cpu(smart->host_writes)));
	printf("Controller Busy Time         : %s min\n",
	       uint128_t_to_string(le128_to_cpu(smart->ctrl_busy_time)));
	printf("Power Cycles                 : %s\n",
	       uint128_t_to_string(le128_to_cpu(smart->power_cycles)));
	printf("Power On Hours               : %s\n",
	       uint128_t_to_string(le128_to_cpu(smart->power_on_hours)));
	printf("Unsafe Shutdowns             : %s\n",
	       uint128_t_to_string(le128_to_cpu(smart->unsafe_shutdowns)));
	printf("Media Errors                 : %s\n",
	       uint128_t_to_string(le128_to_cpu(smart->media_errors)));
	printf("Num Error Log Entries        : %s\n",
	       uint128_t_to_string(le128_to_cpu(smart->num_err_log_entries)));

	printf("Warning Comp Temp Time       : %u min\n",
	       le32_to_cpu(smart->warning_temp_time));
	printf("Critical Comp Temp Time      : %u min\n",
	       le32_to_cpu(smart->critical_comp_time));

	for (i = 0; i < 8; i++) {
		__u16 ts = le16_to_cpu(smart->temp_sensor[i]);

		if (ts)
			printf("Temperature Sensor %d         : %u K (%d C)\n",
			       i + 1, ts, ts - 273);
	}

	printf("Thm Temp 1 Trans Count       : %u\n",
	       le32_to_cpu(smart->thm_temp1_trans_count));
	printf("Thm Temp 2 Trans Count       : %u\n",
	       le32_to_cpu(smart->thm_temp2_trans_count));
	printf("Thm Temp 1 Total Time        : %u sec\n",
	       le32_to_cpu(smart->thm_temp1_total_time));
	printf("Thm Temp 2 Total Time        : %u sec\n",
	       le32_to_cpu(smart->thm_temp2_total_time));

	/* Micron-specific extended fields */
	printf("OLEC (Energy)                : %llu\n",
	       (unsigned long long)olec);
	printf("Interval Power Measurement   : %u\n", ipm);
}

static void print_micron_health_log_json(struct nvme_smart_log *smart,
					 const char *devname)
{
	__u16 temp = smart->temperature[1] << 8 | smart->temperature[0];
	__u64 olec = get_smart_olec(smart);
	__u32 ipm = get_smart_ipm(smart);
	struct json_object *root;
	int i;

	root = json_create_object();

	json_object_add_value_string(root, "device", devname);
	json_object_add_value_int(root, "critical_warning",
				  smart->critical_warning);
	json_object_add_value_int(root, "temperature_kelvin", temp);
	json_object_add_value_int(root, "temperature_celsius",
				  temp ? temp - 273 : 0);
	json_object_add_value_int(root, "avail_spare", smart->avail_spare);
	json_object_add_value_int(root, "spare_thresh", smart->spare_thresh);
	json_object_add_value_int(root, "percent_used", smart->percent_used);
	json_object_add_value_int(root, "endurance_grp_crit_warn",
				  smart->endu_grp_crit_warn_sumry);

	json_object_add_value_string(root, "data_units_read",
		uint128_t_to_string(le128_to_cpu(smart->data_units_read)));
	json_object_add_value_string(root, "data_units_written",
		uint128_t_to_string(le128_to_cpu(smart->data_units_written)));
	json_object_add_value_string(root, "host_reads",
		uint128_t_to_string(le128_to_cpu(smart->host_reads)));
	json_object_add_value_string(root, "host_writes",
		uint128_t_to_string(le128_to_cpu(smart->host_writes)));
	json_object_add_value_string(root, "ctrl_busy_time",
		uint128_t_to_string(le128_to_cpu(smart->ctrl_busy_time)));
	json_object_add_value_string(root, "power_cycles",
		uint128_t_to_string(le128_to_cpu(smart->power_cycles)));
	json_object_add_value_string(root, "power_on_hours",
		uint128_t_to_string(le128_to_cpu(smart->power_on_hours)));
	json_object_add_value_string(root, "unsafe_shutdowns",
		uint128_t_to_string(le128_to_cpu(smart->unsafe_shutdowns)));
	json_object_add_value_string(root, "media_errors",
		uint128_t_to_string(le128_to_cpu(smart->media_errors)));
	json_object_add_value_string(root, "num_err_log_entries",
		uint128_t_to_string(le128_to_cpu(smart->num_err_log_entries)));

	json_object_add_value_uint(root, "warning_temp_time",
				   le32_to_cpu(smart->warning_temp_time));
	json_object_add_value_uint(root, "critical_comp_time",
				   le32_to_cpu(smart->critical_comp_time));

	for (i = 0; i < 8; i++) {
		__u16 ts = le16_to_cpu(smart->temp_sensor[i]);
		char key[32];

		if (ts) {
			sprintf(key, "temp_sensor_%d", i + 1);
			json_object_add_value_int(root, key, ts - 273);
		}
	}

	json_object_add_value_uint(root, "thm_temp1_trans_count",
				   le32_to_cpu(smart->thm_temp1_trans_count));
	json_object_add_value_uint(root, "thm_temp2_trans_count",
				   le32_to_cpu(smart->thm_temp2_trans_count));
	json_object_add_value_uint(root, "thm_temp1_total_time",
				   le32_to_cpu(smart->thm_temp1_total_time));
	json_object_add_value_uint(root, "thm_temp2_total_time",
				   le32_to_cpu(smart->thm_temp2_total_time));

	/* Micron-specific extended fields */
	json_object_add_value_uint64(root, "olec", olec);
	json_object_add_value_uint(root, "ipm", ipm);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int micron_health_info(int argc, char **argv, struct command *acmd,
			      struct plugin *plugin)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	const char *desc = "Retrieve SMART/Health log for Micron drives";
	const char *fmt = "output format normal|json";
	enum eDriveModel eModel = UNKNOWN_MODEL;
	struct nvme_smart_log smart_log = { 0 };
	bool is_json = false;
	int err = 0;
	struct format {
		char *fmt;
	};
	struct format cfg = {
		.fmt = "normal",
	};

	NVME_ARGS(opts,
		OPT_FMT("format", 'f', &cfg.fmt, fmt));

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &eModel);
	if (err < 0)
		return err;

	if (eModel == UNKNOWN_MODEL)
		nvme_show_error("WARNING: Unknown drive model");

	if (!strcmp(cfg.fmt, "json"))
		is_json = true;

	err = nvme_get_log_smart(hdl, NVME_NSID_ALL, &smart_log);
	if (err) {
		nvme_show_error("Failed to get SMART log: %s",
			libnvme_strerror(err));
		return err;
	}

	if (is_json)
		print_micron_health_log_json(&smart_log, argv[optind]);
	else
		print_micron_health_log_normal(&smart_log, argv[optind]);

	return 0;
}

/*
 * Identify Controller field offsets for Micron-specific fields
 * PMS:   Power Measurement Support - bit 21 of CTRATT
 */
#define CTRATT_PMS_BIT           21

static inline __u16 get_id_ctrl_ipmsr(struct nvme_id_ctrl *ctrl)
{
	__le16 *p = (__le16 *)&ctrl->ipmsr;

	return le16_to_cpu(*p);
}

static inline __u16 get_id_ctrl_msmt(struct nvme_id_ctrl *ctrl)
{
	__le16 *p = (__le16 *)&ctrl->msmt;

	return le16_to_cpu(*p);
}

static inline bool get_id_ctrl_pms(struct nvme_id_ctrl *ctrl)
{
	return (le32_to_cpu(ctrl->ctratt) >> CTRATT_PMS_BIT) & 0x1;
}

/* Micron vendor-specific id-ctrl fields display */
static void micron_id_ctrl_vs(__u8 *vs, struct json_object *root)
{
	/* Cast back to get full ctrl structure for our extended fields */
	struct nvme_id_ctrl *ctrl =
		(struct nvme_id_ctrl *)(vs - offsetof(struct nvme_id_ctrl, vs));
	__u16 ipmsr = get_id_ctrl_ipmsr(ctrl);
	__u16 msmt = get_id_ctrl_msmt(ctrl);
	bool pms = get_id_ctrl_pms(ctrl);

	if (root) {
		/* JSON output */
		json_object_add_value_int(root, "pms", pms ? 1 : 0);
		json_object_add_value_uint(root, "ipmsr", ipmsr);
		json_object_add_value_uint(root, "msmt", msmt);
	} else {
		/* Normal output */
		printf("pms       : %u\n", pms ? 1 : 0);
		printf("ipmsr     : %u\n", ipmsr);
		printf("msmt      : %u\n", msmt);
	}
}

static int micron_id_ctrl(int argc, char **argv, struct command *acmd,
			  struct plugin *plugin)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	const char *desc = "Identify Controller with Micron vendor fields";
	enum eDriveModel eModel = UNKNOWN_MODEL;
	struct nvme_id_ctrl ctrl = { 0 };
	nvme_print_flags_t flags;
	int err = 0;

	NVME_ARGS(opts);

	err = micron_parse_options(&ctx, &hdl, argc, argv, desc, opts, &eModel);
	if (err < 0)
		return err;

	if (eModel == UNKNOWN_MODEL) {
		nvme_show_error(
			"WARNING: Drive not recognized as Micron, proceeding anyway\n");
	}

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = nvme_identify_ctrl(hdl, &ctrl);
	if (err) {
		nvme_show_error("identify controller failed: %s",
			libnvme_strerror(err));
		return err;
	}

	nvme_show_id_ctrl(&ctrl, libnvme_transport_handle_get_name(hdl),
			  flags, micron_id_ctrl_vs);

	return 0;
}
