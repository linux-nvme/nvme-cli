#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include <sys/ioctl.h>

#define CREATE_CMD
#include "common.h"
#include "micron-nvme.h"

static int micron_fw_commit(int fd, int select)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_activate_fw,
		.cdw10		= 8,
        .cdw12      = select,
	};
    return nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &cmd);

}

static int micron_selective_download(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "This performs a selective firmware download, which allows the user to " \
                       "select which firmware binary to update. This requires a power cycle once the " \
                       "update completes. The options available are: \n\n" \
                       "OOB - This updates the OOB and main firmware\n" \
                       "EEP - This updates the eeprom and main firmware\n" \
                       "ALL - This updates the eeprom, OOB, and main firmware";
	const char *fw = "firmware file (required)";
	const char *select = "FW Select (e.g., --select=ALL)";
    int xfer = 4096;
	void *fw_buf;
    int fd, selectNo,fw_fd,fw_size,err,offset = 0;
    struct stat sb;

	struct config {
		char  *fw;
		char  *select;
	};

	struct config cfg = {
		.fw     = "",
		.select = "\0",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"fw",     'f', "FILE", CFG_STRING,   &cfg.fw,     required_argument, fw},
		{"select",   's', "flag", CFG_STRING, &cfg.select,   required_argument, select},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

    if (fd < 0)
		return fd;
    
    if(strlen(cfg.select) != 3) {
        fprintf(stderr, "Invalid select flag\n");
        err = EINVAL;
        goto out;
    }

    for(int i=0;i<3;i++) 
    {
        cfg.select[i] = toupper(cfg.select[i]);
    }

    if(strncmp(cfg.select,"OOB", 3) == 0) {
        selectNo = 18;
    }
    else if(strncmp(cfg.select,"EEP", 3) == 0) {
        selectNo = 10;
    }
    else if(strncmp(cfg.select,"ALL", 3) == 0) {
        selectNo = 26;
    }
    else {
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

	if (read(fw_fd, fw_buf, fw_size) != ((ssize_t)(fw_size)))
		return EIO;

    while (fw_size > 0) 
    {
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
		fw_buf     += xfer;
		fw_size    -= xfer;
		offset += xfer;
	}

    err = micron_fw_commit(fd,selectNo);

    if(err == 0x10B || err == 0x20B) {
        err = 0;
        fprintf(stderr, "Update successful! Please power cycle for changes to take effect\n");
    }

out:
    return err;
}






