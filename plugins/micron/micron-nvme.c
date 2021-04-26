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

/* Supported Vendor specific feature ids */
#define MICRON_FEATURE_CLEAR_PCI_CORRECTABLE_ERRORS 0xC3
#define MICRON_FEATURE_CLEAR_FW_ACTIVATION_HISTORY  0xCE
#define MICRON_FEATURE_TELEMETRY_CONTROL_OPTION     0xCF
#define MICRON_FEATURE_SMBUS_OPTION                 0xD5

/* Supported Vendor specific log page sizes */
#define C5_log_size (((452 + 16 * 1024) / 4) * 4096)
#define C0_log_size 512
#define C2_log_size 4096
#define D0_log_size 512
#define FB_log_size 512
#define MaxLogChunk 16 * 1024
#define CommonChunkSize 16 * 4096

#define min(x, y) ((x) > (y) ? (y) : (x))
#define SensorCount 2

/* Plugin version major_number.minor_number.patch */
static const char *__version_major = "1";
static const char *__version_minor = "0";
static const char *__version_patch = "5";

/* supported models of micron plugin; new models should be added at the end
 * before UNKNOWN_MODEL. Make sure M5410 is first in the list !
 */
typedef enum { M5410 = 0, M51AX, M51BX, M51CX, M5407, M5411, UNKNOWN_MODEL } eDriveModel;

#define MICRON_VENDOR_ID 0x1344

static char *fvendorid1 = "/sys/class/nvme/nvme%d/device/vendor";
static char *fvendorid2 = "/sys/class/misc/nvme%d/device/vendor";
static char *fdeviceid1 = "/sys/class/nvme/nvme%d/device/device";
static char *fdeviceid2 = "/sys/class/misc/nvme%d/device/device";
static unsigned short vendor_id;
static unsigned short device_id;

typedef struct _LogPageHeader_t {
    unsigned char numDwordsInLogPageHeaderLo;
    unsigned char logPageHeaderFormatVersion;
    unsigned char logPageId;
    unsigned char numDwordsInLogPageHeaderHi;
    unsigned int numValidDwordsInPayload;
    unsigned int numDwordsInEntireLogPage;
} LogPageHeader_t;

static void WriteData(__u8 *data, __u32 len, const char *dir, const char *file, const char *msg)
{
    char tempFolder[PATH_MAX] = { 0 };
    FILE *fpOutFile = NULL;
    sprintf(tempFolder, "%s/%s", dir, file);
    if ((fpOutFile = fopen(tempFolder, "ab+")) != NULL) {
        if (fwrite(data, 1, len,  fpOutFile) != len) {
            printf("Failed to write %s data to %s\n", msg, tempFolder);
        }
        fclose(fpOutFile);
    } else  {
        printf("Failed to open %s file to write %s\n", tempFolder, msg);
    }
}

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
    if (vendor_id == MICRON_VENDOR_ID) {
        switch (device_id) {
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
        case 0x51C0:
        case 0x51C1:
        case 0x51C2:
        case 0x51C3:
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
        default:
            break;
        }
    }
    return eModel;
}

static int ZipAndRemoveDir(char *strDirName, char *strFileName)
{
    int  err = 0;
    char strBuffer[PATH_MAX];
    int  nRet;
    bool is_tgz = false;
    struct stat sb;

    if (strstr(strFileName, ".tar.gz") || strstr(strFileName, ".tgz")) {
        sprintf(strBuffer, "tar -zcf \"%s\" \"%s\"", strFileName,
                strDirName);
        is_tgz = true;
    } else {
        sprintf(strBuffer, "zip -r \"%s\" \"%s\" >temp.txt 2>&1", strFileName,
                strDirName);
    }

    err = EINVAL;
    nRet = system(strBuffer);

    /* check if log file is created, if not print error message */
    if (nRet < 0 || (stat(strFileName, &sb) == -1)) {
        if (is_tgz)
            sprintf(strBuffer, "check if tar and gzip commands are installed");
        else
            sprintf(strBuffer, "check if zip command is installed");

        fprintf(stderr, "Failed to create log data package, %s!\n", strBuffer);
    }

    sprintf(strBuffer, "rm -f -R \"%s\" >temp.txt 2>&1", strDirName);
    nRet = system(strBuffer);
    if (nRet < 0)
        printf("Failed to remove temporary files!\n");

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

            if ((fileLocation = (char *)malloc(length + 1)) == NULL) {
                goto exit_status;
            }
            strncpy(fileLocation, strFilePath, length);
            fileLocation[length] = '\0';

            while (fileLocation[k] != '\0') {
                if (fileLocation[k] == '\\') {
                    fileLocation[k] = '/';
                }
                k++;
            }

            length = (int)strlen(fileLocation);

            if (':' == fileLocation[length - 1]) {
                if ((strTemp = (char *)malloc(length + 2)) == NULL) {
                    goto exit_status;
                }
                strcpy(strTemp, fileLocation);
                strcat(strTemp, "/");
                free(fileLocation);

                length = (int)strlen(strTemp);
                if ((fileLocation = (char *)malloc(length + 1)) == NULL) {
                    goto exit_status;
                }

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
    unsigned char pTmpBuf[CommonChunkSize] = { 0 };
    LogPageHeader_t *pLogHeader = NULL;

    if (ucLogID == 0xC1 || ucLogID == 0xC2 || ucLogID == 0xC4) {
        err = nvme_get_log(nFD, NVME_NSID_ALL, ucLogID, false, NVME_NO_LOG_LSP,
                           CommonChunkSize, pTmpBuf);
        if (err == 0) {
            pLogHeader = (LogPageHeader_t *) pTmpBuf;
            LogPageHeader_t *pLogHeader1 = (LogPageHeader_t *) pLogHeader;
            *nLogSize = (int)(pLogHeader1->numDwordsInEntireLogPage) * 4;
            if (pLogHeader1->logPageHeaderFormatVersion == 0) {
                printf ("Unsupported log page format version %d of log page : 0x%X\n",
                         ucLogID, err);
                *nLogSize = 0;
                err = -1;
            }
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

static int GetCommonLogPage(int nFD, unsigned char ucLogID,
                            unsigned char **pBuffer, int nBuffSize)
{
    unsigned char *pTempPtr = NULL;
    int err = 0;
    pTempPtr = (unsigned char *)malloc(nBuffSize);
    if (!pTempPtr) {
        goto exit_status;
    }
    memset(pTempPtr, 0, nBuffSize);
    err = nvme_get_log(nFD, NVME_NSID_ALL, ucLogID, false, NVME_NO_LOG_LSP,
                       nBuffSize, pTempPtr);
    *pBuffer = pTempPtr;

exit_status:
    return err;
}

/*
 * Plugin Commands
 */
static int micron_parse_options(int argc, char **argv, const char *desc,
    const struct argconfig_commandline_options *opts, eDriveModel *modelp)
{
    int idx = 0;
    int fd = parse_and_open(argc, argv, desc, opts);

    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (modelp) {
        sscanf(argv[optind], "/dev/nvme%d", &idx);
        *modelp = GetDriveModel(idx);
    }

    return fd;
}

static int micron_fw_commit(int fd, int select)
{
    struct nvme_admin_cmd cmd = {
        .opcode = nvme_admin_activate_fw,
        .cdw10 = 8,
        .cdw12 = select,
    };
    return ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
}

static int micron_selective_download(int argc, char **argv,
                                     struct command *cmd, struct plugin *plugin)
{
    const char *desc =
        "This performs a selective firmware download, which allows the user to "
        "select which firmware binary to update for 9200 devices. This requires "
        "a power cycle once the update completes. The options available are: \n\n"
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
                "Update successful! Power cycle for changes to take effect\n");
    }

out:
    return err;
}

static int micron_smbus_option(int argc, char **argv,
                               struct command *cmd, struct plugin *plugin)
{
    __u32 result = 0;
    __u32 cdw10 = 0;
    __u32 cdw11 = 0;
    const char *desc = "Enable/Disable/Get status of SMBUS option on controller";
    const char *option = "enable or disable or status";
    const char *value = "1 - hottest component temperature, 0 - composite "
                        "temperature (default) for enable option, 0 (current), "
                        "1 (default), 2 (saved) for status options";
    const char *save = "1 - persistent, 0 - non-persistent (default)";
    int err = 0;
    int fd = 0;
    int fid = MICRON_FEATURE_SMBUS_OPTION;
    eDriveModel model = UNKNOWN_MODEL;

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

    OPT_ARGS(opts) = {
        OPT_STRING("option", 'o', "option", &opt.option, option),
        OPT_UINT("value", 'v',  &opt.value, value),
        OPT_UINT("save", 's', &opt.save, save),
        OPT_END()
    };

    if ((fd = micron_parse_options(argc, argv, desc, opts, &model)) < 0)
        return err;

    if (model != M5407 && model != M5411) {
        printf ("This option is not supported for specified drive\n");
        close(fd);
        return err;
    }

    if (!strcmp(opt.option, "enable")) {
        cdw11 = opt.value << 1 | 1;
        err = nvme_set_feature(fd, 1, fid, cdw11, 0, opt.save, 0, 0, &result);
        if (err == 0) {
            printf("successfully enabled SMBus on drive\n");
        } else {
            printf("Failed to enabled SMBus on drive\n");
        }
    }
    else if (!strcmp(opt.option, "status")) {
        cdw10 = opt.value;
        err = nvme_get_feature(fd, 1, fid, cdw10, 0, 0, 0, &result);
        if (err == 0) {
            printf("SMBus status on the drive: %s (returns %s temperature) \n",
                    (result & 1) ? "enabled" : "disabled",
                    (result & 2) ? "hottest component" : "composite");
        } else {
            printf("Failed to retrieve SMBus status on the drive\n");
        }
    }
    else if (!strcmp(opt.option, "disable")) {
        cdw11 = opt.value << 1 | 0;
        err = nvme_set_feature(fd, 1, fid, cdw11, 0, opt.save, 0, 0, &result);
        if (err == 0) {
            printf("Successfully disabled SMBus on drive\n");
        } else {
            printf("Failed to disable SMBus on drive\n");
        }
    } else {
        printf("Invalid option %s, valid values are enable, disable or status\n",
                opt.option);
        close(fd);
        return -1;
    }

    close(fd);
    return err;
}

static int micron_temp_stats(int argc, char **argv, struct command *cmd,
                             struct plugin *plugin)
{

    struct nvme_smart_log smart_log;
    unsigned int temperature = 0, i = 0, err = 0;
    unsigned int tempSensors[SensorCount] = { 0 };
    const char *desc = "Retrieve Micron temperature info for the given device ";
    const char *fmt = "output format normal|json";
    struct format {
        char *fmt;
    };
    struct format cfg = {
        .fmt = "normal",
    };
    bool is_json = false;
    struct json_object *root;
    struct json_object *logPages;
    int fd;

    OPT_ARGS(opts) = {
        OPT_FMT("format", 'f', &cfg.fmt, fmt),
        OPT_END()
    };

    fd = parse_and_open(argc, argv, desc, opts);
    if (fd < 0) {
        printf("\nDevice not found \n");;
        return -1;
    }

    if (strcmp(cfg.fmt, "json") == 0)
        is_json = true;

    err = nvme_smart_log(fd, 0xffffffff, &smart_log);
    if (!err) {
        temperature = ((smart_log.temperature[1] << 8) | smart_log.temperature[0]);
        temperature = temperature ? temperature - 273 : 0;
        for (i = 0; i < SensorCount; i++) {
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
            for (i = 0; i < SensorCount; i++) {
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
            for (i = 0; i < SensorCount; i++) {
                printf("%-10s%d : %u C\n", "Temperature Sensor #", i + 1, tempSensors[i]);
            }
        }
    }
    return err;
}

static int micron_pcie_stats(int argc, char **argv,
                             struct command *cmd, struct plugin *plugin)
{
    int  i, fd, err = 0, bus = 0, domain = 0, device = 0, function = 0, ctrlIdx;
    char strTempFile[1024], strTempFile2[1024], command[1024];
    char *businfo = NULL;
    char *devicename = NULL;
    char tdevice[NAME_MAX] = { 0 };
    ssize_t sLinkSize = 0;
    FILE *fp;
    char correctable[8] = { 0 };
    char uncorrectable[8] = { 0 };
    eDriveModel eModel = UNKNOWN_MODEL;
    char *res;
    bool is_json = true;
    struct format {
        char *fmt;
    };
    const char *desc = "Retrieve PCIe event counters";
    const char *fmt = "output format json|normal";
    struct format cfg = {
        .fmt = "json",
    };
    struct {
        char *err;
        int  bit;
        int  val;
    } pcie_correctable_errors[] = {
        { "Unsupported Request Error Status (URES)", 20},
        { "ECRC Error Status (ECRCES)", 19},
        { "Malformed TLP Status (MTS)", 18},
        { "Receiver Overflow Status (ROS)", 17},
        { "Unexpected Completion Status (UCS)", 16},
        { "Completer Abort Status (CAS)", 15},
        { "Completion Timeout Stats (CTS)", 14},
        { "Flow Control Protocol Error Status (FCPES)", 13},
        { "Poisoned TLP Status (PTS)", 12},
        { "Data Link Protocol Error Status (DLPES)", 4},
    },
    pcie_uncorrectable_errors[] = {
        { "Advisory Non-Fatal Error Status (ANFES)", 13},
        { "Replay Timer Timeout Status (RTS)",  12},
        { "REPLY NUM Rollover Status (RRS)", 8},
        { "Bad DLLP Status (BDS)", 7},
        { "Bad TLP Status (BTS)", 6},
        { "Receiver Error Status (RES)", 0},
    };

    __u32 correctable_errors;
    __u32 uncorrectable_errors;

    OPT_ARGS(opts) = {
        OPT_FMT("format", 'f', &cfg.fmt, fmt),
        OPT_END()
    };

    fd = parse_and_open(argc, argv, desc, opts);
    if (fd < 0) {
        printf("\nDevice not found \n");;
        return -1;
    }

    /* pull log details based on the model name */
    sscanf(argv[optind], "/dev/nvme%d", &ctrlIdx);
    if ((eModel = GetDriveModel(ctrlIdx)) == UNKNOWN_MODEL) {
        printf ("Unsupported drive model for vs-pcie-stats command\n");
        close(fd);
        goto out;
    }

    if (strcmp(cfg.fmt, "normal") == 0)
        is_json = false;

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
        err = -errno;
        printf("Failed to read device\n");
        goto out;
    }
    if (strstr(strTempFile2, "../../nvme")) {
        sprintf(strTempFile, "/sys/block/%s/device/device", devicename);
        sLinkSize = readlink(strTempFile, strTempFile2, 1024);
        if (sLinkSize < 0) {
            err = -errno;
            printf("Failed to read device\n");
            goto out;
        }
    }
    businfo = strrchr(strTempFile2, '/');
    sscanf(businfo, "/%x:%x:%x.%x", &domain, &bus, &device, &function);
    sprintf(command, "setpci -s %x:%x.%x ECAP_AER+10.L", bus, device,
            function);
    fp = popen(command, "r");
    if (fp == NULL) {
        printf("Failed to retrieve error count\n");
        goto out;
    }
    res = fgets(correctable, sizeof(correctable), fp);
    if (res == NULL) {
        printf("Failed to retrieve error count\n");
        goto out;
    }
    pclose(fp);

    sprintf(command, "setpci -s %x:%x.%x ECAP_AER+0x4.L", bus, device,
            function);
    fp = popen(command, "r");
    if (fp == NULL) {
        printf("Failed to retrieve error count\n");
        goto out;
    }
    res = fgets(uncorrectable, sizeof(uncorrectable), fp);
    if (res == NULL) {
        printf("Failed to retrieve error count\n");
        goto out;
    }
    pclose(fp);

    correctable_errors = (__u32)strtol(correctable, NULL, 16);
    uncorrectable_errors = (__u32)strtol(uncorrectable, NULL, 16);

    if (is_json) {

        struct json_object *root = json_create_object();
        struct json_object *pcieErrors = json_create_array();
        struct json_object *stats = json_create_object();

        json_object_add_value_array(root, "PCIE Stats", pcieErrors);
        for (i = 0; i < sizeof(pcie_correctable_errors) / sizeof(pcie_correctable_errors[0]); i++) {
            json_object_add_value_int(stats, pcie_correctable_errors[i].err,
                                      ((correctable_errors >> pcie_correctable_errors[i].bit) & 1));
        }
        for (i = 0; i < sizeof(pcie_uncorrectable_errors) / sizeof(pcie_uncorrectable_errors[0]); i++) {
            json_object_add_value_int(stats, pcie_uncorrectable_errors[i].err,
                                      ((uncorrectable_errors >> pcie_uncorrectable_errors[i].bit) & 1));
        }
        json_array_add_value_object(pcieErrors, stats);
        json_print_object(root, NULL);
        printf("\n");
        json_free_object(root);
    } else if (eModel == M5407 || eModel == M5410) {
        for (i = 0; i < sizeof(pcie_correctable_errors) / sizeof(pcie_correctable_errors[0]); i++) {
            printf("%-40s : %-1d\n", pcie_correctable_errors[i].err,
                                      ((correctable_errors >> pcie_correctable_errors[i].bit) & 1));
        }
        for (i = 0; i < sizeof(pcie_uncorrectable_errors) / sizeof(pcie_uncorrectable_errors[0]); i++) {
            printf("%-40s : %-1d\n", pcie_uncorrectable_errors[i].err,
                                      ((uncorrectable_errors >> pcie_uncorrectable_errors[i].bit) & 1));
        }
    } else {
        printf("PCIE Stats:\n");
        printf("Device correctable errors detected: %s\n", correctable);
        printf("Device uncorrectable errors detected: %s\n", uncorrectable);
    }

out:
    return err;
}

static int micron_clear_pcie_correctable_errors(int argc, char **argv,
        struct command *cmd,
        struct plugin *plugin)
{
    int err = -EINVAL, bus = 0, domain = 0, device = 0, function = 0;
    char strTempFile[1024], strTempFile2[1024], command[1024];
    char *businfo = NULL;
    char *devicename = NULL;
    char tdevice[PATH_MAX] = { 0 };
    ssize_t sLinkSize = 0;
    eDriveModel model = UNKNOWN_MODEL;
    char correctable[8] = { 0 };
    int  fd = -1;
    FILE *fp;
    char *res;
    const char *desc = "Clear PCIe Device Correctable Errors";
    __u32 result = 0;
    __u8 fid = MICRON_FEATURE_CLEAR_PCI_CORRECTABLE_ERRORS;
    OPT_ARGS(opts) = {
        OPT_END()
    };

    if ((fd = micron_parse_options(argc, argv, desc, opts, &model)) < 0)
        return err;

    /* For M51CX models, PCIe errors are cleared using 0xC3 feature */
    if (model == M51CX) {
        err = nvme_set_feature(fd, 0, fid, (1 << 31), 0, 0, 0, 0, &result);
        if (err == 0 && (err = (int)result) == 0)
            printf("Device correctable errors cleared!\n");
        else
            printf("Error clearing Device correctable errors = 0x%x\n", err);
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
        err = -errno;
        printf("Failed to read device\n");
        goto out;
    }
    if (strstr(strTempFile2, "../../nvme")) {
        err = snprintf(strTempFile, sizeof(strTempFile),
                       "/sys/block/%s/device/device", devicename);
        if (err < 0)
            goto out;
        sLinkSize = readlink(strTempFile, strTempFile2, 1024);
        if (sLinkSize < 0) {
            err = -errno;
            printf("Failed to read device\n");
            goto out;
        }
    }
    businfo = strrchr(strTempFile2, '/');
    sscanf(businfo, "/%x:%x:%x.%x", &domain, &bus, &device, &function);
    sprintf(command, "setpci -s %x:%x.%x ECAP_AER+0x10.L=0xffffffff", bus,
            device, function);
    err = -1;
    fp = popen(command, "r");
    if (fp == NULL) {
        printf("Failed to clear error count\n");
        goto out;
    }
    pclose(fp);

    sprintf(command, "setpci -s %x:%x.%x ECAP_AER+0x10.L", bus, device,
            function);
    fp = popen(command, "r");
    if (fp == NULL) {
        printf("Failed to retrieve error count\n");
        goto out;
    }
    res = fgets(correctable, sizeof(correctable), fp);
    if (res == NULL) {
        printf("Failed to retrieve error count\n");
        goto out;
    }
    pclose(fp);
    printf("Device correctable errors cleared!\n");
    printf("Device correctable errors detected: %s\n", correctable);
    err = 0;
out:
    if (fd > 0)
        close(fd);
    return err;
}

static struct logpage {
    const char *field;
    char       datastr[128];
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
    if (count_hi != 0)
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

/* OCP and Vendor specific log data format */
struct micron_vs_logpage {
    char *field;
    int  size;
}
/* Smart Health Log information as per OCP spec */
ocp_c0_log_page[] = {
    { "Physical Media Units Written", 16 },
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
/* Vendor Specific Health Log information */
fb_log_page[] = {
    { "Physical Media Units Written - TLC", 16 },
    { "Physical Media Units Written - SLC", 16 },
    { "Normalized Bad User NAND Block Count", 2},
    { "Raw Bad User NAND Block Count", 6},
    { "XOR Recovery Count", 8},
    { "Uncorrectable Read Error Count", 8},
    { "SSD End to End Corrected Errors", 8},
    { "SSD End to End Detected Counts", 4},
    { "SSD End to End Uncorrected Counts", 4},
    { "System data % life-used", 1},
    { "Minimum User Data Erase Count - TLC", 8},
    { "Maximum User Data Erase Count - TLC", 8},
    { "Minimum User Data Erase Count - SLC", 8},
    { "Maximum User Data Erase Count - SLC", 8},
    { "Normalized Program Fail Count", 2},
    { "Raw Program Fail Count", 6},
    { "Normalized Erase Fail Count", 2},
    { "Raw Erase Fail Count", 6},
    { "Pcie Correctable Error Count", 8},
    { "% Free Blocks (User)", 1},
    { "Security Version Number", 8},
    { "% Free Blocks (System)", 1},
    { "Dataset Management (Deallocate) Commands", 16},
    { "Incomplete TRIM Data", 8},
    { "% Age of Completed TRIM", 1},
    { "Background Back-Pressure Gauge", 1},
    { "Soft ECC Error Count", 8},
    { "Refresh Count", 8},
    { "Normalized Bad System NAND Block Count", 2},
    { "Raw Bad System NAND Block Count", 6},
    { "Endurance Estimate", 16},
    { "Thermal Throttling Count", 1},
    { "Thermal Throttling Status", 1},
    { "Unaligned I/O", 8},
    { "Physical Media Units Read", 16},
    { "Reserved", 279},
    { "Log Page Version", 2}
};

/* Common function to print Micron VS log pages */
static void print_micron_vs_logs(
    __u8                     *buf,             /* raw log data */
    struct micron_vs_logpage *log_page,        /* format of the data */
    int                      field_count,      /* log field count */
    struct json_object       *stats            /* json object to add fields */
)
{
    __u64 lval_lo, lval_hi;
    __u32 ival;
    __u16 sval;
    __u8  cval, lval[8] = { 0 };
    int field, guid_index;
    int offset = 0;

    for (field = 0; field < field_count; field++) {
        char datastr[1024] = { 0 };
        if (log_page[field].size == 16) {
            if (strstr(log_page[field].field, "GUID")) {
                char *tmpstr = datastr;
                tmpstr += sprintf(datastr, "0x");
                for(guid_index = 0; guid_index < 16; guid_index++)
                    tmpstr += sprintf(tmpstr, "%01X", buf[offset + guid_index]);
            } else {
                lval_lo = *((__u64 *)(&buf[offset]));
                lval_hi = *((__u64 *)(&buf[offset + 8]));
                if (lval_hi)
                    sprintf(datastr, "0x%"PRIx64"_%"PRIx64"",
                            le64_to_cpu(lval_hi), le64_to_cpu(lval_lo));
                else
                    sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo));
            }
        } else if (log_page[field].size == 8) {
            lval_lo = *((__u64 *)(&buf[offset]));
            sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo));
        } else if (log_page[field].size == 7) {
            /* 7 bytes will be in little-endian format, with last byte as MSB */
            memcpy(&lval[0], &buf[offset], 7);
            memcpy((void *)&lval_lo, lval, 8);
            sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo));
        } else if (log_page[field].size == 6) {
            ival    = *((__u32 *)(&buf[offset]));
            sval    = *((__u16 *)(&buf[offset + 4]));
            lval_lo = (((__u64)sval << 32) | ival);
            sprintf(datastr, "0x%"PRIx64"", le64_to_cpu(lval_lo));
        } else if (log_page[field].size == 4) {
            ival    = *((__u32 *)(&buf[offset]));
            sprintf(datastr, "0x%x", le32_to_cpu(ival));
        } else if (log_page[field].size == 2) {
            sval = *((__u16 *)(&buf[offset]));
            sprintf(datastr, "0x%04x", le16_to_cpu(sval));
        } else if (log_page[field].size == 1) {
            cval = buf[offset];
            sprintf(datastr, "0x%02x", cval);
        } else {
            sprintf(datastr, "0");
        }
        offset += log_page[field].size;
        /* do not print reserved values */
        if (strstr(log_page[field].field, "Reserved"))
            continue;
        if (stats != NULL) {
            json_object_add_value_string(stats, log_page[field].field, datastr);
        } else {
            printf("%-40s : %-4s\n", log_page[field].field, datastr);
        }
    }
}

static void print_smart_cloud_health_log(__u8 *buf, bool is_json)
{
    struct json_object *root;
    struct json_object *logPages;
    struct json_object *stats = NULL;
    int    field_count = sizeof(ocp_c0_log_page)/sizeof(ocp_c0_log_page[0]);

    if (is_json) {
        root = json_create_object();
        stats = json_create_object();
        logPages = json_create_array();
        json_object_add_value_array(root, "OCP SMART Cloud Health Log: 0xC0",
                                    logPages);
    }

    print_micron_vs_logs(buf, ocp_c0_log_page, field_count, stats);

    if (is_json) {
        json_array_add_value_object(logPages, stats);
        json_print_object(root, NULL);
        printf("\n");
        json_free_object(root);
    }
}

static void print_nand_stats_fb(__u8 *buf, __u8 *buf2, __u8 nsze, bool is_json)
{
    struct json_object *root;
    struct json_object *logPages;
    struct json_object *stats = NULL;
    int    field_count = sizeof(fb_log_page)/sizeof(fb_log_page[0]);

    if (is_json) {
        root = json_create_object();
        stats = json_create_object();
        logPages = json_create_array();
        json_object_add_value_array(root, "Extended Smart Log Page : 0xFB",
                                    logPages);
    }

    print_micron_vs_logs(buf, fb_log_page, field_count, stats);

    /* print last three entries from D0 log page */
    init_d0_log_page(buf2, nsze);

    if (is_json) {
        for (int i = 4; i < 7; i++) {
            json_object_add_value_string(stats,
                                         d0_log_page[i].field,
                                         d0_log_page[i].datastr);
        }
    } else {
        for (int i = 4; i < 7; i++) {
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

        json_object_add_value_array(root,
                                    "Extended Smart Log Page : 0xD0",
                                    logPages);

        for (int i = 0; i < 7; i++) {
            json_object_add_value_string(stats,
                                         d0_log_page[i].field,
                                         d0_log_page[i].datastr);
        }

        json_array_add_value_object(logPages, stats);
        json_print_object(root, NULL);
        printf("\n");
        json_free_object(root);
    } else {
        for (int i = 0; i < 7; i++) {
            printf("%-40s : %s\n", d0_log_page[i].field, d0_log_page[i].datastr);
        }
    }
}

static bool nsze_from_oacs = false; /* read nsze for now from idd[4059]  */

static int micron_nand_stats(int argc, char **argv,
                             struct command *cmd, struct plugin *plugin)
{
    const char *desc = "Retrieve Micron NAND stats for the given device ";
    unsigned int extSmartLog[D0_log_size/sizeof(int)] = { 0 };
    unsigned int logFB[FB_log_size/sizeof(int)] = { 0 };
    eDriveModel eModel = UNKNOWN_MODEL;
    struct nvme_id_ctrl ctrl;
    int fd, err, ctrlIdx;
    __u8 nsze;
    bool has_d0_log = true;
    bool has_fb_log = false;
    bool is_json = true;
    struct format {
        char *fmt;
    };
    const char *fmt = "output format json|normal";
    struct format cfg = {
        .fmt = "json",
    };

    OPT_ARGS(opts) = {
        OPT_FMT("format", 'f', &cfg.fmt, fmt),
        OPT_END()
    };

    fd = parse_and_open(argc, argv, desc, opts);
    if (fd < 0) {
        printf("\nDevice not found \n");;
        return -1;
    }

    if (strcmp(cfg.fmt, "normal") == 0)
        is_json = false;

    err = nvme_identify_ctrl(fd, &ctrl);
    if (err)
        goto out;

    /* pull log details based on the model name */
    sscanf(argv[optind], "/dev/nvme%d", &ctrlIdx);
    if ((eModel = GetDriveModel(ctrlIdx)) == UNKNOWN_MODEL) {
        printf ("Unsupported drive model for vs-nand-stats command\n");
        close(fd);
        goto out;
    }

    err = nvme_get_log(fd, NVME_NSID_ALL, 0xD0, false, NVME_NO_LOG_LSP,
                       D0_log_size, extSmartLog);
    has_d0_log = (0 == err);

    /* should check for firmware version if this log is supported or not */
    if (eModel == M5407 || eModel == M5410) {
        err = nvme_get_log(fd, NVME_NSID_ALL, 0xFB, false, NVME_NO_LOG_LSP,
                           FB_log_size, logFB);
        has_fb_log = (0 == err);
    }

    nsze = (ctrl.vs[987] == 0x12);
    if (nsze == 0 && nsze_from_oacs)
        nsze = ((ctrl.oacs >> 3) & 0x1);
    err = 0;
    if (has_fb_log)
        print_nand_stats_fb((__u8 *)logFB, (__u8 *)extSmartLog, nsze, is_json);
    else if (has_d0_log)
        print_nand_stats_d0((__u8 *)extSmartLog, nsze, is_json);
    else {
        printf("Unable to retrieve extended smart log for the drive\n");
        err = -ENOTTY;
    }
out:
    close(fd);
    return err;
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
        printf("Failed to create %s\n", tempFile);
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
    __u8 outstr[1024];
    time_t t;
    struct tm *tmp;
    size_t num;
    char *strPDir;
    char *strDest;

    t = time(NULL);
    tmp = localtime(&t);
    if (tmp == NULL)
        return;

    num = strftime((char *)outstr, sizeof(outstr),
                   "Timestamp (UTC): %a, %d %b %Y %T %z", tmp);
    num += sprintf((char *)(outstr + num), "\nPackage Version: 1.4");
    if (num) {
        strPDir = strdup(strOSDirName);
        strDest = dirname(strPDir);
        WriteData(outstr, num, strDest, "timestamp_info.txt", "timestamp");
        free(strPDir);
    }
}

static void GetCtrlIDDInfo(const char *dir, struct nvme_id_ctrl *ctrlp)
{
    WriteData((__u8*)ctrlp, sizeof(*ctrlp), dir,
              "nvme_controller_identify_data.bin", "id-ctrl");
}

static void GetSmartlogData(int fd, const char *dir)
{
    struct nvme_smart_log smart_log;
    if (nvme_smart_log(fd, -1, &smart_log) == 0) {
        WriteData((__u8*)&smart_log, sizeof(smart_log), dir,
                  "smart_data.bin", "smart log");
    }
}

static void GetErrorlogData(int fd, int entries, const char *dir)
{
    int logSize = entries * sizeof(struct nvme_error_log_page);
    struct nvme_error_log_page *error_log =
                (struct nvme_error_log_page *)calloc(1, logSize);

    if (error_log == NULL)
        return;

    if (nvme_error_log(fd, entries, error_log) == 0) {
        WriteData((__u8*)error_log, logSize, dir,
                  "error_information_log.bin", "error log");
    }

    free(error_log);
}

static void GetNSIDDInfo(int fd, const char *dir, int nsid)
{
    char file[PATH_MAX] = { 0 };
    struct nvme_id_ns ns;

    if (nvme_identify_ns(fd, nsid, 0, &ns) == 0) {
        sprintf(file, "identify_namespace_%d_data.bin", nsid);
        WriteData((__u8*)&ns, sizeof(ns), dir, file, "id-ns");
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

static int micron_telemetry_log(int fd, __u8 gen, __u8 type, __u8 **data,
                                int *logSize, int da)
{
    int err;
    unsigned short data_area[4];
    unsigned char  ctrl_init = (type == 0x8);

    __u8 *buffer = (unsigned char *)calloc(512, 1);
    if (buffer == NULL)
        return -1;
    err = nvme_get_telemetry_log(fd, buffer, gen, ctrl_init, 512, 0);
    if (err != 0) {
        fprintf(stderr, "Failed to get telemetry log header for 0x%X\n", type);
        if (buffer != NULL) {
            free(buffer);
        }
        return err;
    }

    // compute size of the log
    data_area[1] = buffer[9] << 16 | buffer[8];
    data_area[2] = buffer[11] << 16 | buffer[10];
    data_area[3] = buffer[13] << 16 | buffer[12];
    data_area[0] = data_area[1] > data_area[2] ? data_area[1] : data_area[2];
    data_area[0] = data_area[3] > data_area[0] ? data_area[3] : data_area[0];

    if (data_area[da] == 0) {
        fprintf(stderr, "Requested telemetry data for 0x%X is empty\n", type);
        if (buffer != NULL) {
            free(buffer);
            buffer = NULL;
        }
        return -1;
    }

    *logSize = data_area[da] * 512;
    if ((buffer = (unsigned char *)realloc(buffer, (size_t)(*logSize))) != NULL) {
        err = nvme_get_telemetry_log(fd, buffer, gen, ctrl_init, *logSize, 0);
    }

    if (err == 0 && buffer != NULL) {
        *data = buffer;
    } else {
        fprintf(stderr, "Failed to get telemetry data for 0x%x\n", type);
        if (buffer != NULL)
            free(buffer);
    }

    return err;
}

static int GetTelemetryData(int fd, const char *dir)
{
    unsigned char *buffer = NULL;
    int i, err, logSize = 0;
    char msg[256] = {0};
    struct {
        __u8 log;
        char *file;
    } tmap[] = {
        {0x07, "nvme_host_telemetry.bin"},
        {0x08, "nvme_cntrl_telemetry.bin"},
    };

    for(i = 0; i < (int)(sizeof(tmap)/sizeof(tmap[0])); i++) {
        err = micron_telemetry_log(fd, 0, tmap[i].log, &buffer, &logSize, 0);
        if (err == 0 && logSize > 0 && buffer != NULL) {
            sprintf(msg, "telemetry log: 0x%X", tmap[i].log);
            WriteData(buffer, logSize, dir, tmap[i].file, msg);
            if (buffer != NULL)
                free(buffer);
        }
        buffer = NULL;
        logSize = 0;
    }
    return err;
}

static int GetFeatureSettings(int fd, const char *dir)
{
    unsigned char *bufp, buf[4096] = { 0 };
    int i, err, len, errcnt = 0;
    __u32 attrVal = 0;
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

    for (i = 0; i < (int)(sizeof(fmap)/sizeof(fmap[0])); i++) {
        if (fmap[i].id == 0x03) {
            len = 4096;
            bufp = (unsigned char *)(&buf[0]);
        } else  {
            len = 0;
            bufp = NULL;
        }

        err = nvme_get_feature(fd, 1, fmap[i].id, 0, 0x0, len, bufp, &attrVal);
        if (err == 0) {
            sprintf(msg, "feature: 0x%X", fmap[i].id);
            WriteData((__u8*)&attrVal, sizeof(attrVal), dir, fmap[i].file, msg);
            if (bufp != NULL) {
                WriteData(bufp, len, dir, fmap[i].file, msg);
            }
        } else {
            printf("Failed to retrieve feature 0x%x data !\n", fmap[i].id);
            errcnt++;
        }
    }
    return (int)(errcnt == sizeof(fmap)/sizeof(fmap[0]));
}

static int micron_drive_info(int argc, char **argv, struct command *cmd,
                                struct plugin *plugin)
{
    const char *desc = "Get drive HW information";
    int fd, err = 0;
    struct nvme_id_ctrl ctrl =  { 0 };
    OPT_ARGS(opts) = {
        OPT_END()
    };

    if ((fd = micron_parse_options(argc, argv, desc, opts, NULL)) < 0)
        return err;

    err = nvme_identify_ctrl(fd, &ctrl);
    if (err) {
        fprintf(stderr, "ERROR : nvme_identify_ctrl() failed with 0x%x\n", err);
        return -1;
    }

    printf("%u.%u\n", ctrl.vs[820], ctrl.vs[821]);
    return 0;
}

static int micron_cloud_ssd_plugin_version(int argc, char **argv,
                                struct command *cmd, struct plugin *plugin)
{
    printf("nvme-cli Micron cloud SSD plugin version: %s.%s\n",
           __version_major, __version_minor);
    return 0;
}

static int micron_plugin_version(int argc, char **argv, struct command *cmd,
                                struct plugin *plugin)
{
    printf("nvme-cli Micron plugin version: %s.%s.%s\n",
           __version_major, __version_minor, __version_patch);
    return 0;
}

static int micron_logpage_dir(int argc, char **argv, struct command *cmd,
                                struct plugin *plugin)
{
    printf("This command is not implemented for the drive\n");
    return 0;
}
/* Binary format of firmware activation history entry */
struct __attribute__((__packed__)) fw_activation_history_entry {
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
struct __attribute__((__packed__)) micron_fw_activation_history_table {
    __u8                               log_page;
    __u8                               rsvd1[3];
    __le32                             num_entries;
    struct fw_activation_history_entry entries[20];
    __u8                               rsvd2[2790];
    __u16                              version;
    __u8                               GUID[16];
};

/* header to be printed  field widths = 10 | 12 | 10 | 11 | 12 | 9 | 9 | 9 */

const char *fw_activation_history_table_header = "\
__________________________________________________________________________________\n\
          |           |         |          |           |        |        |        \n\
Firmware  |  Power    | Power   | Previous | New FW    | Slot   | Commit | Result \n\
Activation|  On Hour  | cycle   | firmware | activated | number | Action |        \n\
Counter   |           | count   |          |           |        | Type   |        \n\
__________|___________|_________|__________|___________|________|________|________\n";

static int display_fw_activate_entry (
    int                                entry_count,
    struct fw_activation_history_entry *entry,
    char                               *formatted_entry,
    struct json_object                 *stats
)
{
    time_t    timestamp, hours;
    char      buffer[32];
    __u8      minutes, seconds;
    char      *ca[] = {"000b", "001b", "010b", "011b"};
    char      *ptr = formatted_entry;
    int       index = 0, entry_size = 82;

    if (entry->version != 1 || entry->length != 64) {
        fprintf(stderr, "unsupported entry ! version: %x with length: %d\n",
                entry->version, entry->length);
        return -EINVAL;
    }

    sprintf(ptr, "%d", entry_count);
    ptr += 10;

    timestamp = (le64_to_cpu(entry->power_on_hour) & 0x0000FFFFFFFFFFFFUL) / 1000;
    hours = timestamp / 3600;
    minutes = (timestamp % 3600) / 60;
    seconds = (timestamp % 3600) % 60;
    sprintf(ptr, "|%"PRIu64":%hhu:%hhu", (uint64_t)hours, minutes, seconds);
    ptr += 12;

    sprintf(ptr, "| %"PRIu64, le64_to_cpu(entry->power_cycle_count));
    ptr += 10;

    /* firmware details */
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, entry->previous_fw, sizeof(entry->previous_fw));
    sprintf(ptr, "| %s", buffer);
    ptr += 11;

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, entry->activated_fw, sizeof(entry->activated_fw));
    sprintf(ptr, "| %s", buffer);
    ptr += 12;

    /* firmware slot and commit action*/
    sprintf(ptr, "| %d", entry->slot);
    ptr += 9;

    if (entry->commit_action_type <= 3)
        sprintf(ptr, "| %s", ca[entry->commit_action_type]);
    else
        sprintf(ptr, "| xxxb");
    ptr += 9;

    /* result */
    if (entry->result) {
        sprintf(ptr, "| Fail #%d", entry->result);
    } else {
        sprintf(ptr, "| pass");
    }

    /* replace all null charecters with spaces */
    ptr = formatted_entry;
    while (index < entry_size) {
        if (ptr[index] == '\0')
            ptr[index] = ' ';
        index++;
    }
    return 0;
}


static int micron_fw_activation_history(int argc, char **argv, struct command *cmd,
                                struct plugin *plugin)
{
    const char *desc = "Retrieve Firmware Activation history of the given drive";
    char formatted_output[100];
    int count = 0;
    unsigned int logC2[C2_log_size/sizeof(int)] = { 0 };
    eDriveModel eModel = UNKNOWN_MODEL;
    struct nvme_id_ctrl ctrl;
    int fd, err, ctrlIdx;
    struct format {
        char *fmt;
    };

    const char *fmt = "output format normal";
    struct format cfg = {
        .fmt = "normal",
    };

    OPT_ARGS(opts) = {
        OPT_FMT("format", 'f', &cfg.fmt, fmt),
        OPT_END()
    };

    fd = parse_and_open(argc, argv, desc, opts);
    if (fd < 0) {
        printf("\nDevice not found \n");;
        return -1;
    }

    if (strcmp(cfg.fmt, "normal") != 0) {
        fprintf (stderr, "only normal format is supported currently\n");
        close(fd);
        return -1;
    }

    err = nvme_identify_ctrl(fd, &ctrl);
    if (err) {
        fprintf(stderr, "failed get device identification data, error: %x\n", err);
        goto out;
    }

    /* check if product supports fw_history log */
    err = -EINVAL;
    sscanf(argv[optind], "/dev/nvme%d", &ctrlIdx);
    eModel = GetDriveModel(ctrlIdx);
    if (eModel != M51CX) {
        fprintf(stderr, "Unsupported drive model for vs-fw-activate-history command\n");
        goto out;
    }

    err = nvme_get_log(fd, NVME_NSID_ALL, 0xC2, false, NVME_NO_LOG_LSP, C2_log_size, logC2);
    if (err)  {
        fprintf(stderr, "Failed to retrieve fw activation history log, error: %x\n", err);
        goto out;
    }

    /* check if we have atleast one entry to print */
    struct micron_fw_activation_history_table *table =
               (struct micron_fw_activation_history_table *)logC2;

    /* check version and log page */
    if (table->version != 2 || table->log_page != 0xC2) {
        fprintf(stderr, "Unsupported fw activation history page: %x, version: %x\n",
                table->log_page, table->version);
        goto out;
    }

    if (table->num_entries == 0) {
        fprintf(stderr, "No entries were found in fw activation history log\n");
        goto out;
    }

    printf("%s", fw_activation_history_table_header);
    for(count = 0; count < table->num_entries; count++) {
        memset(formatted_output, '\0', 100);
        if (display_fw_activate_entry(count,
                                      &table->entries[count],
                                      formatted_output, NULL) == 0)
        {
            printf("%s\n", formatted_output);
        }
    }
out:
    if (fd > 0)
        close(fd);
    return err;
}

static int micron_error_reason(int argc, char **argv, struct command *cmd,
                                struct plugin *plugin)
{
    printf("This command is not implemented for the drive\n");
    return 0;
}

static int micron_ocp_smart_health_logs(int argc, char **argv, struct command *cmd,
                                struct plugin *plugin)
{
    const char *desc = "Retrieve Micron OCP Smart Health log for the given device ";
    unsigned int logC0[C0_log_size/sizeof(int)] = { 0 };
    eDriveModel eModel = UNKNOWN_MODEL;
    struct nvme_id_ctrl ctrl;
    int fd, err, ctrlIdx;
    bool is_json = false;
    struct format {
        char *fmt;
    };
    const char *fmt = "output format normal|json";
    struct format cfg = {
        .fmt = "normal",
    };

    OPT_ARGS(opts) = {
        OPT_FMT("format", 'f', &cfg.fmt, fmt),
        OPT_END()
    };

    fd = parse_and_open(argc, argv, desc, opts);
    if (fd < 0) {
        printf("\nDevice not found \n");;
        return -1;
    }

    if (strcmp(cfg.fmt, "json") == 0)
        is_json = true;

    err = nvme_identify_ctrl(fd, &ctrl);
    if (err)
        goto out;

    /* pull log details based on the model name */
    sscanf(argv[optind], "/dev/nvme%d", &ctrlIdx);
    if ((eModel = GetDriveModel(ctrlIdx)) == UNKNOWN_MODEL) {
        printf ("Unsupported drive model for vs-smart-add-log commmand\n");
        close(fd);
        goto out;
    }

    /* should check for firmware version if this log is supported or not */
    if (eModel == M5407 || eModel == M5410) {
        err = nvme_get_log(fd, NVME_NSID_ALL, 0xC0, false, NVME_NO_LOG_LSP,
                           C0_log_size, logC0);
    }
    if (err < 0) {
        printf("Unable to retrieve extended smart log for the drive\n");
        err = -ENOTTY;
    } else {
        print_smart_cloud_health_log((__u8 *)logC0, is_json);
    }
out:
    close(fd);
    return err;
}

static int micron_clr_fw_activation_history(int argc, char **argv,
                                struct command *cmd, struct plugin *plugin)
{
    const char *desc = "Clear FW activation history";
    int fd, err = 0;
    __u32 result = 0;
    __u8 fid = MICRON_FEATURE_CLEAR_FW_ACTIVATION_HISTORY;
    eDriveModel model = UNKNOWN_MODEL;
    OPT_ARGS(opts) = {
        OPT_END()
    };

    if ((fd = micron_parse_options(argc, argv, desc, opts, &model)) < 0)
        return err;

    if (model != M51CX) {
        printf ("This option is not supported for specified drive\n");
        close(fd);
        return err;
    }

    //err = nvme_set_feature(fd, 1, fid, cdw11, 0, opt.save, 0, 0, &result);
    err = nvme_set_feature(fd, 1, fid, 0, 0, 0, 0, 0, &result);
    if (err == 0) err = (int)result;
    return err;
}

static int micron_telemetry_cntrl_option(int argc, char **argv,
                                struct command *cmd, struct plugin *plugin)
{
    int err = 0;
    __u32 result = 0;
    const char *desc = "Enable or Disable Controller telemetry log generation";
    const char *option = "enable or disable or status";
    const char *select = "select/save values: enable/disable options"
                         "1 - save (persistent), 0 - non-persistent and for "
                         "status options: 0 - current, 1 - default, 2-saved";
    int fd = 0;
    int fid = MICRON_FEATURE_TELEMETRY_CONTROL_OPTION;
    eDriveModel model = UNKNOWN_MODEL;
    struct nvme_id_ctrl ctrl =  { 0 };

    struct {
        char *option;
        int  select;
    } opt = {
        .option = "disable",
        .select= 0,
    };

    OPT_ARGS(opts) = {
        OPT_STRING("option", 'o', "option", &opt.option, option),
        OPT_UINT("select", 's', &opt.select, select),
        OPT_END()
    };

    if ((fd = micron_parse_options(argc, argv, desc, opts, &model)) < 0) {
        return -1;
    }

    err = nvme_identify_ctrl(fd, &ctrl);
    if ((ctrl.lpa & 0x8) != 0x8) {
           printf("drive doesn't support host/controller generated telemetry logs\n");
           close(fd);
           return err;
    }

    if (!strcmp(opt.option, "enable")) {
        err = nvme_set_feature(fd, 1, fid, 1, 0, (opt.select & 0x1), 0, 0, &result);
        if (err == 0) {
            printf("successfully set controller telemetry option\n");
        } else {
            printf("Failed to set controller telemetry option\n");
        }
    } else if (!strcmp(opt.option, "disable")) {
        err = nvme_set_feature(fd, 1, fid, 0, 0, (opt.select & 0x1), 0, 0, &result);
        if (err == 0) {
            printf("successfully disabled controller telemetry option\n");
        } else {
            printf("Failed to disable controller telemetry option\n");
        }
    } else if (!strcmp(opt.option, "status")) {
        opt.select &= 0x3;
        err = nvme_get_feature(fd, 1, fid, opt.select, 0, 0, 0, &result);
        if (err == 0) {
            printf("Controller telemetry option : %s\n",
                    (result) ? "enabled" : "disabled");
        } else {
            printf("Failed to retrieve controller telemetry option\n");
        }
    } else {
        printf("invalid option %s, valid values are enable,disable or status\n", opt.option);
        close(fd);
        return -1;
    }

    close(fd);
    return err;
}

static int micron_internal_logs(int argc, char **argv, struct command *cmd,
                                struct plugin *plugin)
{
    int err = -EINVAL;
    int fd = 0;
    int ctrlIdx, telemetry_option = 0;
    char strOSDirName[1024];
    char strCtrlDirName[1024];
    char strMainDirName[256];
    unsigned int *puiIDDBuf;
    unsigned int uiMask;
    struct nvme_id_ctrl ctrl;
    char sn[20] = { 0 };
    char msg[256] = { 0 };

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
    };

    eDriveModel eModel;

    const char *desc = "This retrieves the micron debug log package";
    const char *package = "Log output data file name (required)";
    const char *type = "telemetry log type - host or controller";
    const char *data_area = "telemetry log data area 1, 2 or 3";
    unsigned char *dataBuffer = NULL;
    int bSize = 0;
    int maxSize = 0;

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

    OPT_ARGS(opts) = {
        OPT_STRING("type", 't', "log type", &cfg.type, type),
        OPT_STRING("package", 'p', "FILE", &cfg.package, package),
        OPT_UINT("data_area", 'd', &cfg.data_area, data_area),
        OPT_END()
    };

    fd = parse_and_open(argc, argv, desc, opts);

    if (fd < 0)
        goto out;

    /* if telemetry type is specified, check for data area */
    if (strlen(cfg.type) != 0) {
        if (!strcmp(cfg.type, "controller")) {
            cfg.log = 0x08;
        } else if (strcmp(cfg.type, "host")) {
            printf ("telemetry type (host or controller) should be specified i.e. -t=host\n");
            close(fd);
            goto out;
        }

        if (cfg.data_area <= 0 || cfg.data_area > 3) {
            printf ("data area must be selected using -d option ie --d=1,2,3\n");
            close(fd);
            goto out;
        }
        telemetry_option = 1;
    } else if (cfg.data_area > 0) {
        printf ("data area option is valid only for telemetry option (i.e --type=host|controller)\n");
        close(fd);
        goto out;
    }

    if (strlen(cfg.package) == 0) {
        if (telemetry_option)
            printf ("Log data file must be specified. ie -p=logfile.bin\n");
        else
            printf ("Log data file must be specified. ie -p=logfile.zip or -p=logfile.tgz|logfile.tar.gz\n");
        goto out;
    }

    /* pull log details based on the model name */
    sscanf(argv[optind], "/dev/nvme%d", &ctrlIdx);
    if ((eModel = GetDriveModel(ctrlIdx)) == UNKNOWN_MODEL) {
        printf ("Unsupported drive model for vs-internal-log collection\n");
        close(fd);
        goto out;
    }

    err = nvme_identify_ctrl(fd, &ctrl);
    if (err)
        goto out;

    err = -EINVAL;
    if (telemetry_option) {
        if ((ctrl.lpa & 0x8) != 0x8) {
           printf("telemetry option is not supported for specified drive\n");
           close(fd);
           goto out;
        }
        int logSize = 0; __u8 *buffer = NULL; const char *dir = ".";
        err = micron_telemetry_log(fd, 0, cfg.log,  &buffer, &logSize, cfg.data_area);
        if (err == 0 && logSize > 0 && buffer != NULL) {
            sprintf(msg, "telemetry log: 0x%X", cfg.log);
            WriteData(buffer, logSize, dir, cfg.package, msg);
            free(buffer);
        }
        close(fd);
        goto out;
    }

    printf("Preparing log package. This will take a few seconds...\n");

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

    // pull if telemetry log data is supported
    if ((ctrl.lpa & 0x8) == 0x8)
        GetTelemetryData(fd, strCtrlDirName);

    GetFeatureSettings(fd, strCtrlDirName);

    if (eModel != M5410) {
        memcpy(aVendorLogs, aM51XXLogs, sizeof(aM51XXLogs));
        if (eModel == M51AX)
            memcpy((char *)aVendorLogs + sizeof(aM51XXLogs), aM51AXLogs, sizeof(aM51AXLogs));
        else
            memcpy((char *)aVendorLogs + sizeof(aM51XXLogs), aM51BXLogs, sizeof(aM51BXLogs));
    }

    for (int i = 0; i < (int)(sizeof(aVendorLogs) / sizeof(aVendorLogs[0])) &&
                        aVendorLogs[i].ucLogPage != 0; i++) {
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
            if (uiMask == 0 || (aVendorLogs[i].ucLogPage == 0xE6 && uiMask == 2) ||
               (aVendorLogs[i].ucLogPage == 0xE7 && uiMask == 1)) {
                bSize = 0;
            } else {
                bSize = (int)puiIDDBuf[1023];
                if (bSize % (16 * 1024)) {
                    bSize += (16 * 1024) - (bSize % (16 * 1024));
                }
            }
            if (bSize != 0 && (dataBuffer = (unsigned char *)malloc(bSize)) != NULL) {
                memset(dataBuffer, 0, bSize);
                if (eModel == M5410 || eModel == M5407)
                    err = NVMEGetLogPage(fd, aVendorLogs[i].ucLogPage, dataBuffer, bSize);
                else
                    err = nvme_get_log(fd, NVME_NSID_ALL, aVendorLogs[i].ucLogPage,
                                       false, NVME_NO_LOG_LSP, bSize, dataBuffer);
            }
            break;

        case 0xF7:
        case 0xF9:
        case 0xFC:
        case 0xFD:
            if (eModel == M51BX)
                (void)NVMEResetLog(fd, aVendorLogs[i].ucLogPage,
                                   aVendorLogs[i].nLogSize, aVendorLogs[i].nMaxSize);
        default:
            bSize = aVendorLogs[i].nLogSize;
            dataBuffer = (unsigned char *)malloc(bSize);
            if (dataBuffer == NULL) {
               break;
            }
            memset(dataBuffer, 0, bSize);
            err = nvme_get_log(fd, NVME_NSID_ALL, aVendorLogs[i].ucLogPage,
                               false, NVME_NO_LOG_LSP, bSize, dataBuffer);
            maxSize = aVendorLogs[i].nMaxSize - bSize;
            while (err == 0 && maxSize > 0 && ((unsigned int *)dataBuffer)[0] != 0xdeadbeef) {
                sprintf(msg, "log 0x%x", aVendorLogs[i].ucLogPage);
                WriteData(dataBuffer, bSize, strCtrlDirName, aVendorLogs[i].strFileName, msg);
                err = nvme_get_log(fd, NVME_NSID_ALL, aVendorLogs[i].ucLogPage,
                                   false, NVME_NO_LOG_LSP, bSize, dataBuffer);
                if (err || (((unsigned int *)dataBuffer)[0] == 0xdeadbeef))
                    break;
                maxSize -= bSize;
            }
            break;
        }

        if (err == 0 && dataBuffer != NULL && ((unsigned int *)dataBuffer)[0] != 0xdeadbeef) {
            sprintf(msg, "log 0x%x", aVendorLogs[i].ucLogPage);
            WriteData(dataBuffer, bSize, strCtrlDirName, aVendorLogs[i].strFileName, msg);
        }

        if (dataBuffer != NULL) {
            free(dataBuffer);
            dataBuffer = NULL;
        }
    }

    err = ZipAndRemoveDir(strMainDirName, cfg.package);
out:
    return err;
}
