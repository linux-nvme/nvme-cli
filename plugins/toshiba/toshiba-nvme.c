#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>

#include "linux/nvme_ioctl.h"
#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "plugin.h"
#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "toshiba-nvme.h"

static const __u32 OP_SCT_STATUS = 0xE0;
static const __u32 OP_SCT_COMMAND_TRANSFER = 0xE0;
static const __u32 OP_SCT_DATA_TRANSFER = 0xE1;

static const __u32 DW10_SCT_STATUS_COMMAND = 0x0;
static const __u32 DW10_SCT_COMMAND_TRANSFER = 0x1;

static const __u32 DW11_SCT_STATUS_COMMAND = 0x0;
static const __u32 DW11_SCT_COMMAND_TRANSFER = 0x0;

static const __u16 INTERNAL_LOG_ACTION_CODE = 0xFFFB;
static const __u16 CURRENT_LOG_FUNCTION_CODE = 0x0001;
static const __u16 SAVED_LOG_FUNCTION_CODE = 0x0002;

// A bitmask field for supported devices
typedef enum {
	MASK_0    = 1 << 0,
	MASK_1    = 1 << 1,
	// Future devices can use the remaining 31 bits from this field
	// and should use 1 << 2, 1 << 3, etc.
	MASK_IGNORE = 0
} DeviceMask;

// Internal device codes
typedef enum {
	CODE_0 = 0x0D,
	CODE_1 = 0x10
} DeviceCode;


static int nvme_sct_op(int fd,  __u32 opcode, __u32 cdw10, __u32 cdw11, void* data, __u32 data_len )
{
	void  *metadata = NULL;
	const __u32 cdw2 = 0;
	const __u32 cdw3 = 0;
	const __u32 cdw12 = 0;
	const __u32 cdw13 = 0;
	const __u32 cdw14 = 0;
	const __u32 cdw15 = 0;
	const __u32 timeout = 0;
	const __u32 metadata_len = 0;
	const __u32 namespace_id = 0x0;
	const __u32 flags = 0;
	const __u32 rsvd = 0;
	int err = 0;
	__u32 result;
	err = nvme_passthru(fd, NVME_IOCTL_ADMIN_CMD, opcode, flags, rsvd,
				namespace_id, cdw2, cdw3, cdw10,
				cdw11, cdw12, cdw13, cdw14, cdw15,
				data_len, data, metadata_len, metadata,
				timeout, &result);
	return err;
}

static int nvme_get_sct_status(int fd, __u32 device_mask)
{
	int err;
	void* data = NULL;
	size_t data_len = 512;
	if (posix_memalign(&data, getpagesize(), data_len)) {
		err = ENOMEM;
		goto end;
	}
	memset(data, 0, data_len);
	err = nvme_sct_op(fd, OP_SCT_STATUS, DW10_SCT_STATUS_COMMAND, DW11_SCT_STATUS_COMMAND, data, data_len);
	if (err) {
		fprintf(stderr, "%s: SCT status failed :%d\n", __func__, err);
		goto end;
	}
	const unsigned char* status = data;
	if (status[0] != 1U) {
		// Eek, wrong version in status header
		fprintf(stderr, "%s: unexpected value in SCT status[0]:(%x)\n", __func__, status[0]);
		err = -1;
		errno = EINVAL;
		goto end;
	}

	// Check if device is supported
	if (device_mask != MASK_IGNORE) {
		__u32 supported = 0;
		switch (status[1]) {
		case CODE_0:
			supported = (device_mask & MASK_0);
			break;

		case CODE_1:
			supported = (device_mask & MASK_1);
			break;

		default:
			break;
		};
		if (0 == supported) {
			fprintf(stderr, "%s: command unsupported on this device: (0x%x)\n",__func__, status[1]);
			err = -1;
			errno = EINVAL;
			goto end;
		}
	}
end:
	if (data) {
		free(data);
	}
	return err;
}

static int nvme_sct_command_transfer_log(int fd, bool current)
{
	__u16 action_code = INTERNAL_LOG_ACTION_CODE;
	__u16 function_code;
	if (current) {
		function_code = CURRENT_LOG_FUNCTION_CODE;
	} else {
		function_code = SAVED_LOG_FUNCTION_CODE;
	}
	int err;
	void* data = NULL;
	size_t data_len = 512;
	if (posix_memalign(&data, getpagesize(), data_len)) {
		err = ENOMEM;
		goto end;
	}
	memset(data, 0, data_len);
	memcpy(data, &action_code, sizeof(action_code));
	memcpy(data + 2, &function_code, sizeof(function_code));

	err = nvme_sct_op(fd, OP_SCT_COMMAND_TRANSFER, DW10_SCT_COMMAND_TRANSFER, DW11_SCT_COMMAND_TRANSFER, data, data_len);
	return err;
end:
	if (data) {
		free(data);
	}
	return err;
}

static int nvme_sct_data_transfer(int fd, void* data, size_t data_len, size_t offset)
{
	__u32 lba_count = (data_len) / 512;
	if (lba_count) {
		// the count is a 0-based value, which seems to mean
		// that it's actually last lba
		--lba_count;
	}

	__u32 dw10 = (offset << 16) | lba_count;
	__u32 dw11 = (offset >> 16);
	return nvme_sct_op(fd, OP_SCT_DATA_TRANSFER, dw10, dw11, data, data_len);
}

static int d_raw_to_fd(const unsigned char *buf, unsigned len, int fd)
{
	int written = 0;
	int remaining = len;
	while (remaining) {
		written = write(fd, buf, remaining);
		if (written < 0) {
			remaining = written;
			break;
		} else if (written <= remaining) {
			remaining -= written;
		} else {
			// Unexpected overwrite
			break;
		}
	}
	// return 0 on success or remaining/error
	return remaining;
}

// Display progress (incoming 0->1.0)
static void progress_runner(float progress)
{
    const size_t barWidth = 70;

    fprintf(stdout, "[");
    size_t pos = barWidth * progress;
    for (size_t i = 0; i < barWidth; ++i) {
        if (i <= pos) {
        	fprintf(stdout, "=");
        } else {
        	fprintf(stdout, " ");
        }
    }
	fprintf(stdout, "] %d %%\r",(int)(progress * 100.0));
	fflush(stdout);
}

static int nvme_get_internal_log(int fd, const char* const filename, bool current)
{
	int err;
	int o_fd = -1;
	void* page_data = NULL;
	const size_t page_sector_len = 32;
	const size_t page_data_len = page_sector_len * 512;// 32 sectors per page
	// By trial and error it seems that the largest transfer chunk size
	// is 128 * 32 =  4k sectors = 2MB
	const __u32 max_pages = 128;
	err = nvme_sct_command_transfer_log(fd, current);
	if (err) {
		fprintf(stderr, "%s: SCT command transfer failed\n", __func__);
		goto end;
	}
	if (posix_memalign(&page_data, getpagesize(), max_pages * page_data_len)) {
		err = ENOMEM;
		goto end;
	}
	memset(page_data, 0, max_pages * page_data_len);
	// Read the header to get the last log page - offsets 8->11, 12->15, 16->19
	err = nvme_sct_data_transfer(fd, page_data, page_data_len, 0);
	if (err) {
		fprintf(stderr, "%s: SCT data transfer failed, page 0\n",__func__);
		goto end;
	}
	const uint32_t* area1_last_page = (const uint32_t*) (page_data + 8);
	const uint32_t* area2_last_page = (const uint32_t*) (page_data + 12);
	const uint32_t* area3_last_page = (const uint32_t*) (page_data + 16);
	uint32_t log_sectors = 0;
	// The number of total log sectors is the maximum + 1;
	if (*area1_last_page > log_sectors) {
		log_sectors = *area1_last_page;
	}
	if (*area2_last_page > log_sectors) {
		log_sectors = *area2_last_page;
	}
	if (*area3_last_page > log_sectors) {
		log_sectors = *area3_last_page;
	}
	++log_sectors;
	const size_t pages = log_sectors / page_sector_len;
	float progress = 0.0;
	if (filename == NULL) {
		fprintf(stdout, "Page: %u of %zu\n", 0u, pages);
		d(page_data, page_data_len, 16, 1);
	} else {
		progress_runner(progress);
		o_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (o_fd < 0) {
			fprintf(stderr, "%s: couldn't output file %s\n", __func__, filename);
			err = EINVAL;
			goto end;
		}
		err = d_raw_to_fd(page_data, page_data_len, o_fd);
		if (err) {
			fprintf(stderr, "%s: couldn't write all data to output file\n", __func__);
			goto end;
		}
	}
	// Now read the rest
	for (size_t i = 1; i < pages;) {
		__u32 pages_chunk = max_pages;
		if (pages_chunk + i >= pages) {
			pages_chunk = pages - i;
		}
		err = nvme_sct_data_transfer(fd, page_data, pages_chunk * page_data_len, i * page_sector_len);
		if (err) {
			fprintf(stderr, "%s: SCT data transfer command failed\n", __func__);
			goto end;
		}
		progress = (float) (i) / (float) (pages);
		progress_runner(progress);
		if (filename == NULL) {
			for (unsigned j = 0; j < pages_chunk; ++j) {
				fprintf(stdout, "Page: %zu of %zu\n", i + j, pages);
				d(page_data + (j * page_data_len), page_data_len, 16, 1);
			}
		} else {
			progress_runner(progress);
			err = d_raw_to_fd(page_data, pages_chunk * page_data_len, o_fd);
			if (err) {
				fprintf(stderr, "%s: couldn't write all data to output file\n", __func__);
				goto end;
			}
		}
		i += pages_chunk;
	}
	progress = 1.0f;
	progress_runner(progress);
	fprintf(stdout,"\n");
	err = nvme_get_sct_status(fd, MASK_IGNORE);
	if (err) {
		fprintf(stderr, "%s: bad SCT status\n", __func__);
		goto end;
	}
end:
	if (o_fd >= 0) {
		close(o_fd);
	}
	if (page_data) {
		free(page_data);
	}
	return err;
}

static int nvme_get_internal_log_file(int fd, const char* const filename, bool current)
{
	int err;
	// Check device supported
	err = nvme_get_sct_status(fd, MASK_0 | MASK_1);
	if (!err) {
		err = nvme_get_internal_log(fd, filename, current);
	}
	return err;
}

enum LOG_PAGE_C0 {
	ERROR_LOG_C0 = 0,
	SMART_HEALTH_LOG_C0,
	FIRMWARE_SLOT_INFO_C0,
	COMMAND_EFFECTS_C0,
	DEVICE_SELF_TEST_C0,
	LOG_PAGE_DIRECTORY_C0,
	SMART_ATTRIBUTES_C0,
	NR_SMART_ITEMS_C0,
};

struct nvme_xdn_smart_log_c0 {
	__u8 items[NR_SMART_ITEMS_C0];
	__u8 resv[512 - NR_SMART_ITEMS_C0];
};

static void default_show_vendor_log_c0(int fd, __u32 nsid, const char *devname,
		struct nvme_xdn_smart_log_c0 *smart)
{
	printf("Vendor Log Page Directory 0xC0 for NVME device:%s namespace-id:%x\n", devname, nsid);
	printf("Error Log          : %u \n", smart->items[ERROR_LOG_C0]);
	printf("SMART Health Log   : %u \n", smart->items[SMART_HEALTH_LOG_C0]);
	printf("Firmware Slot Info : %u \n", smart->items[FIRMWARE_SLOT_INFO_C0]);
	printf("Command Effects    : %u \n", smart->items[COMMAND_EFFECTS_C0]);
	printf("Device Self Test   : %u \n", smart->items[DEVICE_SELF_TEST_C0]);
	printf("Log Page Directory : %u \n", smart->items[LOG_PAGE_DIRECTORY_C0]);
	printf("SMART Attributes   : %u \n", smart->items[SMART_ATTRIBUTES_C0]);
}

static int nvme_get_vendor_log(int fd, __u32 namespace_id, int log_page, const char* const filename)
{
	int err;
	void* log = NULL;
	size_t log_len = 512;
	if (posix_memalign(&log, getpagesize(), log_len)) {
		err = ENOMEM;
		goto end;
	}
	// Check device supported
	err = nvme_get_sct_status(fd, MASK_0 | MASK_1);
	if (err) {
		goto end;
	}
	err = nvme_get_log(fd, namespace_id, log_page, false,
		    log_len, log);
	if (err) {
		fprintf(stderr, "%s: couldn't get log 0x%x\n", __func__, log_page);
		goto end;
	}
	if (filename) {
		int o_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);

		if (o_fd < 0) {
			fprintf(stderr, "%s: couldn't output file %s\n", __func__, filename);
			err = EINVAL;
			goto end;
		}
		err = d_raw_to_fd(log, log_len, o_fd);
		if (err) {
			fprintf(stderr, "%s: couldn't write all data to output file %s\n", __func__, filename);
			// Attempt following close
		}
		if (close(o_fd)) {
			err = errno;
			goto end;
		}
	} else {
		if (log_page == 0xc0) {
			default_show_vendor_log_c0(fd, namespace_id, devicename, (struct nvme_xdn_smart_log_c0 *)log);
		} else {
			d(log, log_len,16,1);
		}
	}
end:
	if (log) {
		free(log);
	}
	return err;
}

static int vendor_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err;
	int fd;
	char *desc = "Get extended SMART information and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *output_file = "(optional) binary output filename";
	const char *log = "(optional) log ID (0xC0, or 0xCA), default 0xCA";
	struct config {
		__u32 namespace_id;
		const char* output_file;
		int log;
	};
	struct config cfg = {
		.namespace_id = 0xffffffff,
		.output_file = NULL,
		.log = 0xca
	};
	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace},
		{"output-file",  'o', "FILE", CFG_STRING,   &cfg.output_file,  required_argument, output_file},
		{"log",          'l', "NUM",  CFG_POSITIVE, &cfg.log,          required_argument, log},
		{NULL}
	};
	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		fprintf(stderr,"%s: failed to parse arguments\n", __func__);
		err = EINVAL;
		goto end;
	}
	if ((cfg.log != 0xC0) && (cfg.log != 0xCA)) {
		fprintf(stderr, "%s: invalid log page 0x%x - should be 0xC0 or 0xCA\n", __func__, cfg.log);
		err = EINVAL;
		goto end;
	}
	err = nvme_get_vendor_log(fd, cfg.namespace_id, cfg.log, cfg.output_file);
	if (err) {
		fprintf(stderr, "%s: couldn't get vendor log 0x%x\n", __func__, cfg.log);
		goto end;
	}
end:
	if (err > 0) {
		fprintf(stderr, "%s: NVMe Status:%s(%x)\n", __func__, nvme_status_to_string(err), err);
	}
	return err;
}

static int internal_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err;
	int fd;
	char *desc = "Get internal status log and show it.";
	const char *output_file = "(optional) binary output filename";
	const char *prev_log = "(optional) use previous log. Otherwise uses current log.";
	struct config {
		const char* output_file;
		bool prev_log;
	};
	struct config cfg = {
		.output_file = NULL,
		.prev_log = false
	};
	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file",  'o', "FILE", CFG_STRING,   &cfg.output_file, required_argument, output_file},
		{"prev-log", 'p', "", CFG_NONE, &cfg.prev_log, no_argument, prev_log},
		{NULL}
	};
	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		fprintf(stderr,"%s: failed to parse arguments\n", __func__);
		err = EINVAL;
		goto end;
	}
	if (cfg.prev_log) {
		printf("Getting previous log\n");
	} else {
		printf("Getting current log\n");
	}
	err = nvme_get_internal_log_file(fd, cfg.output_file, !cfg.prev_log);
	if (err) {
		fprintf(stderr, "%s: couldn't get fw log \n", __func__);
	}
end:
	if (err > 0) {
		fprintf(stderr, "%s: NVMe Status:%s(%x)\n", __func__, nvme_status_to_string(err), err);
	}
	return err;
}

static int clear_correctable_errors(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err;
	int fd;
	char *desc = "Clear PCIe correctable error count.";
	const struct argconfig_commandline_options command_line_options[] = {
		{NULL}
	};
	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0) {
		fprintf(stderr,"%s: failed to parse arguments\n", __func__);
		err = EINVAL;
		goto end;
	}
	// Check device supported
	err = nvme_get_sct_status(fd, MASK_0 | MASK_1);
	if (err) {
		goto end;
	}
	const __u32 namespace_id = 0xFFFFFFFF;
	const __u32 feature_id = 0xCA;
	const __u32 value = 1; // Bit0 - reset clear PCIe correctable count
	const __u32 cdw12 = 0;
	const bool save = false;
	__u32 result;
	err = nvme_set_feature(fd, namespace_id, feature_id, value, cdw12, save,
				0, NULL, &result);
	if (err) {
		fprintf(stderr, "%s: couldn't clear PCIe correctable errors \n", __func__);
	}
end:
	if (err > 0) {
		fprintf(stderr, "%s: NVMe Status:%s(%x)\n", __func__, nvme_status_to_string(err), err);
	}
	return err;
}
