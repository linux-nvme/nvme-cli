#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <libgen.h>
#include <sys/stat.h>
#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include <sys/ioctl.h>
#include <limits.h>

#define CREATE_CMD
#include "micron-nvme.h"
#define min(x, y) ((x) > (y) ? (y) : (x))
#define SensorCount 2
#define C5_log_size (((452 + 16 * 1024) / 4) * 4096)
#define D0_log_size 256
#define MaxLogChunk 16 * 1024
#define CommonChunkSize 16 * 4096

typedef struct _LogPageHeader_t {
	unsigned char numDwordsInLogPageHeaderLo;
	unsigned char logPageHeaderFormatVersion;
	unsigned char logPageId;
	unsigned char numDwordsInLogPageHeaderHi;
	unsigned int numValidDwordsInPayload;
	unsigned int numDwordsInEntireLogPage;
} LogPageHeader_t;

/*
 * Useful Helper functions
 */

static int micron_fw_commit(int fd, int select)
{
	struct nvme_admin_cmd cmd = {
		.opcode = nvme_admin_activate_fw,
		.cdw10 = 8,
		.cdw12 = select,
	};
	return ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);

}

static int ZipAndRemoveDir(char *strDirName, char *strFileName)
{
	int err = 0;
	char strBuffer[PATH_MAX];
	int nRet;

	sprintf(strBuffer, "zip -r \"%s\" \"%s\" >temp.txt 2>&1", strFileName,
		strDirName);

	nRet = system(strBuffer);

	if (nRet < 0) {
		printf("Unable to create zip package!\n");
		err = EINVAL;
		goto exit_status;
	}

	sprintf(strBuffer, "rm -f -R \"%s\" >temp.txt 2>&1", strDirName);
	nRet = system(strBuffer);
	if (nRet < 0) {
		printf("Unable to remove temporary files!\n");
		err = EINVAL;
		goto exit_status;
	}

 exit_status:
	err = system("rm -f temp.txt");
	return err;
}

static int SetupDebugDataDirectories(char *strSN, char *strFilePath,
				     char *strMainDirName, char *strOSDirName,
				     char *strCtrlDirName)
{
	int err = 0;
	char strAppend[250];
	struct stat st;
	char *fileLocation = NULL;
	char *fileName;
	int length = 0;
	int nIndex = 0;
	char *strTemp = NULL;
	struct stat dirStat;
	int j;
	int k = 0;
	int i = 0;

	if (strchr(strFilePath, '/') != NULL) {
		fileName = strrchr(strFilePath, '\\');
		if (fileName == NULL) {
			fileName = strrchr(strFilePath, '/');
		}

		if (fileName != NULL) {
			if (!strcmp(fileName, "/")) {
				goto exit_status;
			}

			while (strFilePath[nIndex] != '\0') {
				if ('\\' == strFilePath[nIndex] && '\\' == strFilePath[nIndex + 1]) {
					goto exit_status;
				}
				nIndex++;
			}

			length = (int)strlen(strFilePath) - (int)strlen(fileName);

			if (fileName == strFilePath) {
				length = 1;
			}

			fileLocation = (char *)malloc(length + 1);
			strncpy(fileLocation, strFilePath, length);
			fileLocation[length] = '\0';

			while (fileLocation[k] != '\0') {
				if (fileLocation[k] == '\\') {
					fileLocation[k] = '/';
				}
			}

			length = (int)strlen(fileLocation);

			if (':' == fileLocation[length - 1]) {
				strTemp = (char *)malloc(length + 2);
				strcpy(strTemp, fileLocation);
				strcat(strTemp, "/");
				free(fileLocation);

				length = (int)strlen(strTemp);
				fileLocation = (char *)malloc(length + 1);
				memcpy(fileLocation, strTemp, length + 1);
				free(strTemp);
			}

			if (stat(fileLocation, &st) != 0) {
				free(fileLocation);
				goto exit_status;
			}
			free(fileLocation);
		} else {
			goto exit_status;
		}
	}

	nIndex = 0;
	for (i = 0; i < (int)strlen(strSN); i++) {
		if (strSN[i] != ' ' && strSN[i] != '\n' && strSN[i] != '\t' && strSN[i] != '\r') {
			strMainDirName[nIndex++] = strSN[i];
		}
	}
	strMainDirName[nIndex] = '\0';

	j = 1;
	while (stat(strMainDirName, &dirStat) == 0) {
		strMainDirName[nIndex] = '\0';
		sprintf(strAppend, "-%d", j);
		strcat(strMainDirName, strAppend);
		j++;
	}

	mkdir(strMainDirName, 0777);

	if (strOSDirName != NULL) {
		sprintf(strOSDirName, "%s/%s", strMainDirName, "OS");
		mkdir(strOSDirName, 0777);

	}
	if (strCtrlDirName != NULL) {
		sprintf(strCtrlDirName, "%s/%s", strMainDirName, "Controller");
		mkdir(strCtrlDirName, 0777);

	}

 exit_status:
	return err;
}

static int GetLogPageSize(int nFD, unsigned char ucLogID, int *nLogSize)
{
	int err = 0;
	struct nvme_admin_cmd cmd;
	unsigned int uiXferDwords = 0;
	unsigned char pTmpBuf[CommonChunkSize] = { 0 };
	LogPageHeader_t *pLogHeader = NULL;

	if (ucLogID == 0xC1 || ucLogID == 0xC2 || ucLogID == 0xC4) {
		cmd.opcode = 0x02;
		cmd.cdw10 = ucLogID;
		uiXferDwords = (unsigned int)(CommonChunkSize / 4);
		cmd.nsid = 0xFFFFFFFF;
		cmd.cdw10 |= ((uiXferDwords - 1) & 0x0000FFFF) << 16;
		cmd.data_len = CommonChunkSize;
		cmd.addr = (__u64) (uintptr_t) & pTmpBuf;
		err = nvme_submit_passthru(nFD, NVME_IOCTL_ADMIN_CMD, &cmd);
		if (err == 0) {
			pLogHeader = (LogPageHeader_t *) pTmpBuf;
			LogPageHeader_t *pLogHeader1 = (LogPageHeader_t *) pLogHeader;
			*nLogSize = (int)(pLogHeader1->numDwordsInEntireLogPage) * 4;
		} else {
			printf ("Getting size of log page : 0x%X failed with %d\n", ucLogID, err);
			*nLogSize = 0;
		}
	}
	return err;
}

static int NVMEGetLogPage(int nFD, unsigned char ucLogID, unsigned char *pBuffer, int nBuffSize)
{
	int err = 0;
	struct nvme_admin_cmd cmd = { 0 };
	unsigned int uiNumDwords = (unsigned int)nBuffSize / sizeof(unsigned int);
	unsigned int uiMaxChunk = uiNumDwords;
	unsigned int uiNumChunks = 1;
	unsigned int uiXferDwords = 0;
	unsigned long long ullBytesRead = 0;
	unsigned char *pTempPtr = pBuffer;
	unsigned char ucOpCode = 0x02;

	if (ullBytesRead == 0 && (ucLogID == 0xE6 || ucLogID == 0xE7)) {
		uiMaxChunk = 4096;
	} else if (uiMaxChunk > 16 * 1024) {
		uiMaxChunk = 16 * 1024;
	}

	uiNumChunks = uiNumDwords / uiMaxChunk;
	if (uiNumDwords % uiMaxChunk > 0) {
		uiNumChunks += 1;
	}

	for (unsigned int i = 0; i < uiNumChunks; i++) {
		memset(&cmd, 0, sizeof(cmd));
		uiXferDwords = uiMaxChunk;
		if (i == uiNumChunks - 1 && uiNumDwords % uiMaxChunk > 0) {
			uiXferDwords = uiNumDwords % uiMaxChunk;
		}

		cmd.opcode = ucOpCode;
		cmd.cdw10 |= ucLogID;
		cmd.cdw10 |= ((uiXferDwords - 1) & 0x0000FFFF) << 16;

		if (ucLogID == 0x7) {
			cmd.cdw10 |= 0x80;
		}
		if (ullBytesRead == 0 && (ucLogID == 0xE6 || ucLogID == 0xE7)) {
			cmd.cdw11 = 1;
		}
		if (ullBytesRead > 0 && !(ucLogID == 0xE6 || ucLogID == 0xE7)) {
			unsigned long long ullOffset = ullBytesRead;
			cmd.cdw12 = ullOffset & 0xFFFFFFFF;
			cmd.cdw13 = (ullOffset >> 32) & 0xFFFFFFFF;
		}

		cmd.addr = (__u64) (uintptr_t) pTempPtr;
		cmd.nsid = 0xFFFFFFFF;
		cmd.data_len = uiXferDwords * 4;
		err = nvme_submit_passthru(nFD, NVME_IOCTL_ADMIN_CMD, &cmd);
		ullBytesRead += uiXferDwords * 4;
		pTempPtr = pBuffer + ullBytesRead;
	}

	return err;
}

static int NVMEResetLog(int nFD, unsigned char ucLogID, int nBufferSize,
			long long llMaxSize)
{
	unsigned int *pBuffer = NULL;
	int err = 0;

	if ((pBuffer = (unsigned int *)calloc(1, nBufferSize)) == NULL)
		return err;

	while (err == 0 && llMaxSize > 0) {
		err = NVMEGetLogPage(nFD, ucLogID, (unsigned char *)pBuffer, nBufferSize);
		if (err)
			return err;

		if (pBuffer[0] == 0xdeadbeef)
			break;

		llMaxSize = llMaxSize - nBufferSize;
	}

	free(pBuffer);
	return err;
}

static int GetCommonLogPage(int nFD, unsigned char ucLogID, unsigned char **pBuffer, int nBuffSize)
{
	struct nvme_admin_cmd cmd;
	int err = 0;
	unsigned char pTmpBuf[CommonChunkSize] = { 0 };
	unsigned int uiMaxChunk = 0;
	unsigned int uiXferDwords = 0;
	int nBytesRead = 0;
	unsigned char *pTempPtr = NULL;

	uiMaxChunk = CommonChunkSize / 4;
	pTempPtr = (unsigned char *)malloc(nBuffSize);
	if (!pTempPtr) {
		goto exit_status;
	}
	memset(pTempPtr, 0, nBuffSize);

	while (nBytesRead < nBuffSize) {
		int nBytesRemaining = nBuffSize - nBytesRead;

		memset(pTmpBuf, 0, CommonChunkSize);

		uiXferDwords = uiMaxChunk;
		memset(&cmd, 0, sizeof(cmd));
		cmd.opcode = 0x02;
		cmd.cdw10 |= ucLogID;
		cmd.cdw10 |= ((uiXferDwords - 1) & 0x0000FFFF) << 16;

		if (nBytesRead > 0) {
			unsigned long long ullOffset = (unsigned long long)nBytesRead;
			cmd.cdw12 = ullOffset & 0xFFFFFFFF;
			cmd.cdw13 = (ullOffset >> 32) & 0xFFFFFFFF;
		}
		cmd.nsid = 0xFFFFFFFF;
		cmd.data_len = uiXferDwords * 4;
		cmd.addr = (__u64) (uintptr_t) pTmpBuf;

		err = nvme_submit_passthru(nFD, NVME_IOCTL_ADMIN_CMD, &cmd);

		if (nBytesRemaining >= (int)(uiMaxChunk * 4)) {
			memcpy(&pTempPtr[nBytesRead], pTmpBuf, uiMaxChunk * 4);
		} else {
			memcpy(&pTempPtr[nBytesRead], pTmpBuf, nBytesRemaining);
		}

		nBytesRead += (int)uiXferDwords *4;
	}
	*pBuffer = pTempPtr;

 exit_status:
	return err;
}

/*
 * Plugin Commands
 */

static int micron_selective_download(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc =
		"This performs a selective firmware download, which allows the user to "
		"select which firmware binary to update for 9200 devices. This requires a power cycle once the "
		"update completes. The options available are: \n\n"
		"OOB - This updates the OOB and main firmware\n"
		"EEP - This updates the eeprom and main firmware\n"
		"ALL - This updates the eeprom, OOB, and main firmware";
	const char *fw = "firmware file (required)";
	const char *select = "FW Select (e.g., --select=ALL)";
	int xfer = 4096;
	void *fw_buf;
	int fd, selectNo, fw_fd, fw_size, err, offset = 0;
	struct stat sb;

	struct config {
		char *fw;
		char *select;
	};

	struct config cfg = {
		.fw = "",
		.select = "\0",
	};

	OPT_ARGS(opts) = {
		OPT_STRING("fw", 'f', "FILE", &cfg.fw, fw),
		OPT_STRING("select", 's', "flag", &cfg.select, select),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);

	if (fd < 0)
		return fd;

	if (strlen(cfg.select) != 3) {
		fprintf(stderr, "Invalid select flag\n");
		err = EINVAL;
		goto out;
	}

	for (int i = 0; i < 3; i++) {
		cfg.select[i] = toupper(cfg.select[i]);
	}

	if (strncmp(cfg.select, "OOB", 3) == 0) {
		selectNo = 18;
	} else if (strncmp(cfg.select, "EEP", 3) == 0) {
		selectNo = 10;
	} else if (strncmp(cfg.select, "ALL", 3) == 0) {
		selectNo = 26;
	} else {
		fprintf(stderr, "Invalid select flag\n");
		err = EINVAL;
		goto out;
	}

	fw_fd = open(cfg.fw, O_RDONLY);
	if (fw_fd < 0) {
		fprintf(stderr, "no firmware file provided\n");
		err = EINVAL;
		goto out;
	}

	err = fstat(fw_fd, &sb);
	if (err < 0) {
		perror("fstat");
		err = errno;
	}

	fw_size = sb.st_size;
	if (fw_size & 0x3) {
		fprintf(stderr, "Invalid size:%d for f/w image\n", fw_size);
		err = EINVAL;
		goto out;
	}

	if (posix_memalign(&fw_buf, getpagesize(), fw_size)) {
		fprintf(stderr, "No memory for f/w size:%d\n", fw_size);
		err = ENOMEM;
		goto out;
	}

	if (read(fw_fd, fw_buf, fw_size) != ((ssize_t) (fw_size)))
		return EIO;

	while (fw_size > 0) {
		xfer = min(xfer, fw_size);

		err = nvme_fw_download(fd, offset, xfer, fw_buf);
		if (err < 0) {
			perror("fw-download");
			goto out;
		} else if (err != 0) {
			fprintf(stderr, "NVME Admin command error:%s(%x)\n",
				nvme_status_to_string(err), err);
			goto out;
		}
		fw_buf += xfer;
		fw_size -= xfer;
		offset += xfer;
	}

	err = micron_fw_commit(fd, selectNo);

	if (err == 0x10B || err == 0x20B) {
		err = 0;
		fprintf(stderr,
			"Update successful! Please power cycle for changes to take effect\n");
	}

 out:
	return err;
}

static int micron_temp_stats(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{

	struct nvme_smart_log smart_log;
	unsigned int temperature = 0, i = 0, fd = 0, err = 0;
	unsigned int tempSensors[SensorCount] = { 0 };
	const char *desc = "Retrieve Micron temperature info for the given device ";

	OPT_ARGS(opts) = {
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0) {
		printf("\nDevice not found \n");;
		return -1;
	}

	err = nvme_smart_log(fd, 0xffffffff, &smart_log);
	if (!err) {
		printf("Micron temperature information:\n");
		temperature = ((smart_log.temperature[1] << 8) | smart_log.temperature[0]);
		temperature = temperature ? temperature - 273 : 0;
		for (i = 0; i < SensorCount; i++) {
			tempSensors[i] = le16_to_cpu(smart_log.temp_sensor[i]);
			tempSensors[i] = tempSensors[i] ? tempSensors[i] - 273 : 0;
		}
		printf("%-10s : %u C\n", "Current Composite Temperature", temperature);
		for (i = 0; i < SensorCount; i++) {
			printf("%-10s%d : %u C\n", "Temperature Sensor #", i + 1, tempSensors[i]);
		}
	}
	return err;
}

static int micron_pcie_stats(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = 0, bus = 0, domain = 0, device = 0, function = 0;
	char strTempFile[1024], strTempFile2[1024], command[1024];
	char *businfo = NULL;
	char *devicename = NULL;
	char tdevice[NAME_MAX] = { 0 };
	ssize_t sLinkSize = 0;
	FILE *fp;
	char correctable[8] = { 0 };
	char uncorrectable[8] = { 0 };
	char *res;

	if (argc != 2) {
		printf("vs-pcie-stats: Invalid argument\n");
		printf("Usage: nvme micron vs-pcie-stats <device>\n\n");
		goto out;
	}
	if (strstr(argv[optind], "/dev/nvme") && strstr(argv[optind], "n1")) {
		devicename = strrchr(argv[optind], '/');
	} else if (strstr(argv[optind], "/dev/nvme")) {
		devicename = strrchr(argv[optind], '/');
		sprintf(tdevice, "%s%s", devicename, "n1");
		devicename = tdevice;
	} else {
		printf("Invalid device specified!\n");
		goto out;
	}
	sprintf(strTempFile, "/sys/block/%s/device", devicename);
	sLinkSize = readlink(strTempFile, strTempFile2, 1024);
	if (sLinkSize < 0) {
		printf("Unable to read device\n");
		goto out;
	}
	if (strstr(strTempFile2, "../../nvme")) {
		sprintf(strTempFile, "/sys/block/%s/device/device", devicename);
		sLinkSize = readlink(strTempFile, strTempFile2, 1024);
		if (sLinkSize < 0) {
			printf("Unable to read device\n");
			goto out;
		}
	}
	businfo = strrchr(strTempFile2, '/');
	sscanf(businfo, "/%x:%x:%x.%x", &domain, &bus, &device, &function);
	sprintf(command, "setpci -s %x:%x.%x ECAP_AER+10.L", bus, device,
		function);
	fp = popen(command, "r");
	if (fp == NULL) {
		printf("Unable to retrieve error count\n");
		goto out;
	}
	res = fgets(correctable, sizeof(correctable), fp);
	if (res == NULL) {
		printf("Unable to retrieve error count\n");
		goto out;
	}
	pclose(fp);

	sprintf(command, "setpci -s %x:%x.%x ECAP_AER+0x4.L", bus, device,
		function);
	fp = popen(command, "r");
	if (fp == NULL) {
		printf("Unable to retrieve error count\n");
		goto out;
	}
	res = fgets(uncorrectable, sizeof(uncorrectable), fp);
	if (res == NULL) {
		printf("Unable to retrieve error count\n");
		goto out;
	}
	pclose(fp);
	printf("PCIE Stats:\n");
	printf("Device correctable errors detected: %s\n", correctable);
	printf("Device uncorrectable errors detected: %s\n", uncorrectable);

 out:
	return err;
}

static int micron_clear_pcie_correctable_errors(int argc, char **argv,
						struct command *cmd,
						struct plugin *plugin)
{
	int err = 0, bus = 0, domain = 0, device = 0, function = 0;
	char strTempFile[1024], strTempFile2[1024], command[1024];
	char *businfo = NULL;
	char *devicename = NULL;
	char tdevice[PATH_MAX] = { 0 };
	ssize_t sLinkSize = 0;
	FILE *fp;
	char correctable[8] = { 0 };
	char *res;

	if (argc != 2) {
		printf("clear-pcie-correctable-errors: Invalid argument\n");
		printf ("Usage: nvme micron clear-pcie-correctable-errors <device>\n\n");
		goto out;
	}
	if (strstr(argv[optind], "/dev/nvme") && strstr(argv[optind], "n1")) {
		devicename = strrchr(argv[optind], '/');
	} else if (strstr(argv[optind], "/dev/nvme")) {
		devicename = strrchr(argv[optind], '/');
		sprintf(tdevice, "%s%s", devicename, "n1");
		devicename = tdevice;
	} else {
		printf("Invalid device specified!\n");
		goto out;
	}
	err = snprintf(strTempFile, sizeof(strTempFile),
			"/sys/block/%s/device", devicename);
	if (err < 0)
		goto out;
	sLinkSize = readlink(strTempFile, strTempFile2, 1024);
	if (sLinkSize < 0) {
		printf("Unable to read device\n");
		goto out;
	}
	if (strstr(strTempFile2, "../../nvme")) {
		err = snprintf(strTempFile, sizeof(strTempFile),
				"/sys/block/%s/device/device", devicename);
		if (err < 0)
			goto out;
		sLinkSize = readlink(strTempFile, strTempFile2, 1024);
		if (sLinkSize < 0) {
			printf("Unable to read device\n");
			goto out;
		}
	}
	businfo = strrchr(strTempFile2, '/');
	sscanf(businfo, "/%x:%x:%x.%x", &domain, &bus, &device, &function);
	sprintf(command, "setpci -s %x:%x.%x ECAP_AER+0x10.L=0xffffffff", bus,
		device, function);

	fp = popen(command, "r");
	if (fp == NULL) {
		printf("Unable to clear error count\n");
		goto out;
	}
	pclose(fp);

	sprintf(command, "setpci -s %x:%x.%x ECAP_AER+0x10.L", bus, device,
		function);
	fp = popen(command, "r");
	if (fp == NULL) {
		printf("Unable to retrieve error count\n");
		goto out;
	}
	res = fgets(correctable, sizeof(correctable), fp);
	if (res == NULL) {
		printf("Unable to retrieve error count\n");
		goto out;
	}
	pclose(fp);
	printf("Device correctable errors cleared!\n");
	printf("Device correctable errors detected: %s\n", correctable);

 out:
	return err;
}

static int micron_nand_stats(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Micron NAND stats for the given device ";
	unsigned int extSmartLog[64] = { 0 };
	struct nvme_id_ctrl ctrl;
	int fd, err;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0) {
		printf("\nDevice not found \n");;
		return -1;
	}

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err)
		goto out;

	err = NVMEGetLogPage(fd, 0xD0, (unsigned char *)extSmartLog, D0_log_size);
	if (err)
		goto out;

	unsigned long long count = ((unsigned long long)extSmartLog[45] << 32) | extSmartLog[44];
	printf("%-40s : 0x%llx\n", "NAND Writes (Bytes Written)", count);
	printf("%-40s : ", "Program Failure Count");

	unsigned long long count_hi = ((unsigned long long)extSmartLog[39] << 32) | extSmartLog[38];
	unsigned long long count_lo = ((unsigned long long)extSmartLog[37] << 32) | extSmartLog[36];
	if (count_hi != 0)
		printf("0x%llx%016llx", count_hi, count_lo);
	else
		printf("0x%llx\n", count_lo);

	count = ((unsigned long long)extSmartLog[25] << 32) | extSmartLog[24];
	printf("%-40s : 0x%llx\n", "Erase Failures", count);
	printf("%-40s : 0x%x\n", "Bad Block Count", extSmartLog[3]);

	count = (unsigned long long)extSmartLog[3] - (count_lo + count);
	printf("%-40s : 0x%llx\n", "NAND XOR/RAID Recovery Trigger Events", count);
	printf("%-40s : 0x%x\n", "NSZE Change Supported", (ctrl.oacs >> 3) & 0x1);
	printf("%-40s : 0x%x\n", "Number of NSZE Modifications", extSmartLog[1]);
 out:
	close(fd);
	return err;
}

typedef enum { M5410 = 0, M51AX, M51BX, UNKNOWN_MODEL } eDriveModel;

static char *fvendorid1 = "/sys/class/nvme/nvme%d/device/vendor";
static char *fvendorid2 = "/sys/class/misc/nvme%d/device/vendor";
static char *fdeviceid1 = "/sys/class/nvme/nvme%d/device/device";
static char *fdeviceid2 = "/sys/class/misc/nvme%d/device/device";
static unsigned short vendor_id;
static unsigned short device_id;

static int ReadSysFile(const char *file, unsigned short *id)
{
	int ret = 0;
	char idstr[32] = { '\0' };
	int fd = open(file, O_RDONLY);

	if (fd > 0) {
		ret = read(fd, idstr, sizeof(idstr));
		close(fd);
	}

	if (fd < 0 || ret < 0)
		perror(file);
	else
		*id = strtol(idstr, NULL, 16);

	return ret;
}

static eDriveModel GetDriveModel(int idx)
{
	eDriveModel eModel = UNKNOWN_MODEL;
	char path[512];

	sprintf(path, fvendorid1, idx);
	if (ReadSysFile(path, &vendor_id) < 0) {
		sprintf(path, fvendorid2, idx);
		ReadSysFile(path, &vendor_id);
	}
	sprintf(path, fdeviceid1, idx);
	if (ReadSysFile(path, &device_id) < 0) {
		sprintf(path, fdeviceid2, idx);
		ReadSysFile(path, &device_id);
	}

	if (vendor_id == 0x1344) {
		switch (device_id) {
		case 0x5410:
			eModel = M5410;
			break;
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
		default:
			break;
		}
	}
	return eModel;
}

static void GetDriveInfo(const char *strOSDirName, int nFD,
			 struct nvme_id_ctrl *ctrlp)
{
	FILE *fpOutFile = NULL;
	char tempFile[256] = { 0 };
	char strBuffer[1024] = { 0 };
	char model[41] = { 0 };
	char serial[21] = { 0 };
	char fwrev[9] = { 0 };
	char *strPDir = strdup(strOSDirName);
	char *strDest = dirname(strPDir);

	sprintf(tempFile, "%s/%s", strDest, "drive-info.txt");
	fpOutFile = fopen(tempFile, "w+");
	if (!fpOutFile) {
		printf("Unable to create %s\n", tempFile);
		free(strPDir);
		return;
	}

	strncpy(model, ctrlp->mn, 40);
	strncpy(serial, ctrlp->sn, 20);
	strncpy(fwrev, ctrlp->fr, 8);

	sprintf(strBuffer,
		"********************\nDrive Info\n********************\n");

	fprintf(fpOutFile, "%s", strBuffer);
	sprintf(strBuffer,
		"%-20s : /dev/nvme%d\n%-20s : %s\n%-20s : %-20s\n%-20s : %-20s\n",
		"Device Name", nFD,
		"Model No", (char *)model,
		"Serial No", (char *)serial, "FW-Rev", (char *)fwrev);

	fprintf(fpOutFile, "%s", strBuffer);

	sprintf(strBuffer,
		"\n********************\nPCI Info\n********************\n");

	fprintf(fpOutFile, "%s", strBuffer);

	sprintf(strBuffer,
		"%-22s : %04X\n%-22s : %04X\n",
		"VendorId", vendor_id, "DeviceId", device_id);
	fprintf(fpOutFile, "%s", strBuffer);
	fclose(fpOutFile);
	free(strPDir);
}

static void GetTimestampInfo(const char *strOSDirName)
{
	char outstr[200];
	time_t t;
	struct tm *tmp;
	FILE *fpOutFile = NULL;
	size_t num;
	char tempFolder[256] = { 0 };
	char *strPDir;
	char *strDest;

	t = time(NULL);
	tmp = localtime(&t);
	if (tmp == NULL)
		return;

	num = strftime(outstr, sizeof(outstr), "Timestamp (UTC): %a, %d %b %Y %T %z", tmp);
	if (num) {
		strPDir = strdup(strOSDirName);
		strDest = dirname(strPDir);
		sprintf(tempFolder, "%s/%s", strDest, "timestamp_info.txt");
		fpOutFile = fopen(tempFolder, "wb");
		if (fwrite(outstr, 1, num, fpOutFile) != num)
			printf("Unable to write to %s file!", tempFolder);
		if (fpOutFile)
			fclose(fpOutFile);
		free(strPDir);
	}
}

static void GetCtrlIDDInfo(const char *strCtrlDirName, struct nvme_id_ctrl *ctrlp)
{
	char tempFolder[PATH_MAX] = { 0 };
	FILE *fpOutFile;
	sprintf(tempFolder, "%s/%s", strCtrlDirName,
		"nvme_controller_identify_data.bin");
	fpOutFile = fopen(tempFolder, "wb");
	if (fwrite(ctrlp, 1, sizeof(*ctrlp), fpOutFile) != sizeof(*ctrlp))
		printf("Unable to write controller data to %s file!", tempFolder);
	if (fpOutFile)
		fclose(fpOutFile);
}

static void GetSmartlogData(int fd, const char *strCtrlDirName)
{
	char tempFolder[PATH_MAX] = { 0 };
	FILE *fpOutFile = NULL;
	struct nvme_smart_log smart_log;
	if (nvme_smart_log(fd, -1, &smart_log) == 0) {
		sprintf(tempFolder, "%s/%s", strCtrlDirName, "smart_data.bin");
		fpOutFile = fopen(tempFolder, "wb");
		if (fwrite(&smart_log, 1, sizeof(smart_log), fpOutFile) != sizeof(smart_log))
			printf("Unable to write smart log data to %s file!", tempFolder);
		if (fpOutFile)
			fclose(fpOutFile);
	}
}

static void GetErrorlogData(int fd, int entries, const char *strCtrlDirName)
{
	char tempFolder[PATH_MAX] = { 0 };
	FILE *fpOutFile = NULL;
	int logSize = entries * sizeof(struct nvme_error_log_page);
	struct nvme_error_log_page *error_log = (struct nvme_error_log_page *)calloc(1, logSize);

	if (error_log == NULL)
		return;

	if (nvme_error_log(fd, entries, error_log) == 0) {
		sprintf(tempFolder, "%s/%s", strCtrlDirName,
			"error_information_log.bin");
		fpOutFile = fopen(tempFolder, "wb");
		if (fwrite(error_log, 1, logSize, fpOutFile) != logSize)
			printf("Unable to write error log to %s file!", tempFolder);
		if (fpOutFile)
			fclose(fpOutFile);
	}
	free(error_log);
}

static void GetNSIDDInfo(int fd, const char *strCtrlDirName, int nsid)
{
	char tempFolder[256] = { 0 };
	char strFileName[PATH_MAX] = { 0 };
	FILE *fpOutFile = NULL;
	struct nvme_id_ns ns;
	if (nvme_identify_ns(fd, nsid, 0, &ns) == 0) {
		sprintf(tempFolder, "identify_namespace_%d_data.bin.bin", nsid);
		sprintf(strFileName, "%s/%s", strCtrlDirName, tempFolder);
		fpOutFile = fopen(strFileName, "wb");
		if (fwrite(&ns, 1, sizeof(ns), fpOutFile) != sizeof(ns))
			printf("Unable to write controller data to %s file!", tempFolder);
		if (fpOutFile)
			fclose(fpOutFile);
	}
}

static void GetOSConfig(const char *strOSDirName)
{
	FILE *fpOSConfig = NULL;
	char strBuffer[1024], strTemp[1024];
	char strFileName[PATH_MAX];
	int i;

	struct {
		char *strcmdHeader;
		char *strCommand;
	} cmdArray[] = {
		{ (char *)"SYSTEM INFORMATION", (char *)"uname -a >> %s" },
		{ (char *)"LINUX KERNEL MODULE INFORMATION", (char *)"lsmod >> %s" },
		{ (char *)"LINUX SYSTEM MEMORY INFORMATION", (char *)"cat /proc/meminfo >> %s" },
		{ (char *)"SYSTEM INTERRUPT INFORMATION", (char *)"cat /proc/interrupts >> %s" },
		{ (char *)"CPU INFORMATION", (char *)"cat /proc/cpuinfo >> %s" },
		{ (char *)"IO MEMORY MAP INFORMATION", (char *)"cat /proc/iomem >> %s" },
		{ (char *)"MAJOR NUMBER AND DEVICE GROUP", (char *)"cat /proc/devices >> %s" },
		{ (char *)"KERNEL DMESG", (char *)"dmesg >> %s" },
		{ (char *)"/VAR/LOG/MESSAGES", (char *)"cat /var/log/messages >> %s" }
	};

	sprintf(strFileName, "%s/%s", strOSDirName, "os_config.txt");

	for (i = 0; i < 7; i++) {
		fpOSConfig = fopen(strFileName, "a+");
		fprintf(fpOSConfig,
			"\n\n\n\n%s\n-----------------------------------------------\n",
			cmdArray[i].strcmdHeader);
		if (NULL != fpOSConfig) {
			fclose(fpOSConfig);
			fpOSConfig = NULL;
		}
		strcpy(strTemp, cmdArray[i].strCommand);
		sprintf(strBuffer, strTemp, strFileName);
		if (system(strBuffer))
			fprintf(stderr, "Failed to send \"%s\"\n", strBuffer);
	}
}

static int micron_internal_logs(int argc, char **argv, struct command *cmd,
				struct plugin *plugin)
{

	int err = 0;
	int fd;
	int ctrlIdx;
	FILE *fpOutFile = NULL;
	char strOSDirName[1024];
	char strCtrlDirName[1024];
	char strMainDirName[256];
	char tempFolder[PATH_MAX] = { 0 };
	unsigned int *puiIDDBuf;
	unsigned int uiMask;
	struct nvme_id_ctrl ctrl;
	char sn[20] = { 0 };

	struct {
		unsigned char ucLogPage;
		const char *strFileName;
		int nLogSize;
		int nMaxSize;
	} aVendorLogs[32] = {
		{ 0xC1, "nvmelog_C1.bin", 0, 0 },
		{ 0xC2, "nvmelog_C2.bin", 0, 0 },
		{ 0xC4, "nvmelog_C4.bin", 0, 0 },
		{ 0xC5, "nvmelog_C5.bin", C5_log_size, 0 },
		{ 0xD0, "nvmelog_D0.bin", D0_log_size, 0 },
		{ 0xE6, "nvmelog_E6.bin", 0, 0 },
		{ 0xE7, "nvmelog_E7.bin", 0, 0 }
	},
	aM51XXLogs[] = {
		{ 0xFB, "nvmelog_FB.bin", 4096, 0 },	/* this should be collected first for M51AX */
		{ 0xF7, "nvmelog_F7.bin", 4096, 512 * 1024 },
		{ 0xF8, "nvmelog_F8.bin", 4096, 512 * 1024 },
		{ 0xF9, "nvmelog_F9.bin", 4096, 200 * 1024 * 1024 },
		{ 0xFC, "nvmelog_FC.bin", 4096, 200 * 1024 * 1024 },
		{ 0xFD, "nvmelog_FD.bin", 4096, 80 * 1024 * 1024 }
	},
	aM51AXLogs[] = {
		{ 0xD0, "nvmelog_D0.bin", 512, 0 },
		{ 0xCA, "nvmelog_CA.bin", 512, 0 },
		{ 0xFA, "nvmelog_FA.bin", 4096, 15232 },
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
	};

	eDriveModel eModel;

	const char *desc = "This retrieves the micron debug log package";
	const char *package = "Log output package name (required)";
	unsigned char *dataBuffer = NULL;
	int bSize = 0;
	int maxSize = 0;

	struct config {
		char *package;
	};

	struct config cfg = {
		.package = ""
	};

	OPT_ARGS(opts) = {
		OPT_STRING("package", 'p', "FILE", &cfg.package, package),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);

	if (strlen(cfg.package) == 0) {
		printf ("You must specify an output name for the log package. ie --p=logfiles.zip\n");
		goto out;
	}

	if (fd < 0)
		goto out;

	/* pull log details based on the model name */
	sscanf(argv[optind], "/dev/nvme%d", &ctrlIdx);
	if ((eModel = GetDriveModel(ctrlIdx)) == UNKNOWN_MODEL) {
		printf ("Unsupported drive model for vs-internal-log collection\n");
		close(fd);
		goto out;
	}

	printf("Preparing log package. This will take a few seconds...\n");
	err = nvme_identify_ctrl(fd, &ctrl);
	if (err)
		goto out;

	// trim spaces out of serial number string */
	int i, j = 0;
	for (i = 0; i < sizeof(ctrl.sn); i++) {
		if (isblank(ctrl.sn[i]))
			continue;
		sn[j++] = ctrl.sn[i];
	}
	sn[j] = '\0';
	strcpy(ctrl.sn, sn);

	SetupDebugDataDirectories(ctrl.sn, cfg.package, strMainDirName, strOSDirName, strCtrlDirName);

	GetTimestampInfo(strOSDirName);
	GetCtrlIDDInfo(strCtrlDirName, &ctrl);
	GetOSConfig(strOSDirName);
	GetDriveInfo(strOSDirName, ctrlIdx, &ctrl);

	for (int i = 1; i <= ctrl.nn; i++)
		GetNSIDDInfo(fd, strCtrlDirName, i);

	GetSmartlogData(fd, strCtrlDirName);
	GetErrorlogData(fd, ctrl.elpe, strCtrlDirName);

	if (eModel != M5410) {
		memcpy(aVendorLogs, aM51XXLogs, sizeof(aM51XXLogs));
		if (eModel == M51AX)
			memcpy((char *)aVendorLogs + sizeof(aM51XXLogs), aM51AXLogs, sizeof(aM51AXLogs));
		else
			memcpy((char *)aVendorLogs + sizeof(aM51XXLogs), aM51BXLogs, sizeof(aM51BXLogs));
	}

	for (int i = 0; i < (int)(sizeof(aVendorLogs) / sizeof(aVendorLogs[0])) && aVendorLogs[i].ucLogPage != 0; i++) {
		err = -1;
		switch (aVendorLogs[i].ucLogPage) {
		case 0xC1:
		case 0xC2:
		case 0xC4:
			err = GetLogPageSize(fd, aVendorLogs[i].ucLogPage, &bSize);
			if (err == 0 && bSize > 0)
				err = GetCommonLogPage(fd, aVendorLogs[i].ucLogPage, &dataBuffer, bSize);
			break;

		case 0xE6:
		case 0xE7:
			puiIDDBuf = (unsigned int *)&ctrl;
			uiMask = puiIDDBuf[1015];
			if (uiMask == 0 || (aVendorLogs[i].ucLogPage == 0xE6 && uiMask == 2) || (aVendorLogs[i].ucLogPage == 0xE7
				&& uiMask == 1)) {
				bSize = 0;
			} else {
				bSize = (int)puiIDDBuf[1015];
				if (bSize % (16 * 1024)) {
					bSize += (16 * 1024) - (bSize % (16 * 1024));
				}
			}
			if (bSize != 0) {
				dataBuffer = (unsigned char *)malloc(bSize);
				memset(dataBuffer, 0, bSize);
				err = NVMEGetLogPage(fd, aVendorLogs[i].ucLogPage, dataBuffer, bSize);
			}
			break;

		case 0xF7:
		case 0xF9:
		case 0xFC:
		case 0xFD:
			if (eModel == M51BX)
				(void)NVMEResetLog(fd, aVendorLogs[i].ucLogPage, aVendorLogs[i].nLogSize, aVendorLogs[i].nMaxSize);
		default:
			bSize = aVendorLogs[i].nLogSize;
			dataBuffer = (unsigned char *)malloc(bSize);
			memset(dataBuffer, 0, bSize);
			err = NVMEGetLogPage(fd, aVendorLogs[i].ucLogPage, dataBuffer, bSize);
			maxSize = aVendorLogs[i].nMaxSize - bSize;
			while (err == 0 && maxSize > 0 && ((unsigned int *)dataBuffer)[0] != 0xdeadbeef) {
				sprintf(tempFolder, "%s/%s", strCtrlDirName,
					aVendorLogs[i].strFileName);
				fpOutFile = fopen(tempFolder, "ab+");
				if (fwrite(dataBuffer, 1, bSize, fpOutFile) != bSize) {
					printf ("Unable to write log to file %s\n!", aVendorLogs[i].strFileName);
				}
				if (fpOutFile)
					fclose(fpOutFile);
				err = NVMEGetLogPage(fd, aVendorLogs[i].ucLogPage, dataBuffer, bSize);
				if (err || (((unsigned int *)dataBuffer)[0] == 0xdeadbeef))
					break;
				maxSize -= bSize;
			}
			break;
		}

		if (err == 0 && dataBuffer != NULL && ((unsigned int *)dataBuffer)[0] != 0xdeadbeef) {
			sprintf(tempFolder, "%s/%s", strCtrlDirName,
				aVendorLogs[i].strFileName);
			fpOutFile = fopen(tempFolder, "ab+");
			if (fwrite(dataBuffer, 1, bSize, fpOutFile) != bSize) {
				printf("Unable to write log to file %s\n!", aVendorLogs[i].strFileName);
			}
			if (fpOutFile)
				fclose(fpOutFile);
		}

		if (dataBuffer != NULL) {
			free(dataBuffer);
			dataBuffer = NULL;
		}
	}

	ZipAndRemoveDir(strMainDirName, cfg.package);
 out:
	return err;
}
