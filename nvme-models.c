/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include "nvme-models.h"
#include "nvme.h"

static char *_fmt1 = "/sys/class/nvme/nvme%d/device/subsystem_vendor";
static char *_fmt2 = "/sys/class/nvme/nvme%d/device/subsystem_device";
static char *_fmt3 = "/sys/class/nvme/nvme%d/device/vendor";
static char *_fmt4 = "/sys/class/nvme/nvme%d/device/device";
static char *_fmt5 = "/sys/class/nvme/nvme%d/device/class";

#define LINE_BUF_SIZE 1024

static char fmt1[78];
static char fmt2[78];
static char fmt3[78];
static char fmt4[78];
static char fmt5[78];

static char *device_top;
static char *device_mid;
static char *device_final;
static char *class_top;
static char *class_mid;
static char *class_final;



static void free_all(void)
{
	free(device_top);
	device_top = NULL;
	free(device_mid);
	device_mid = NULL;
	free(device_final);
	device_final = NULL;
	free(class_top);
	class_top = NULL;
	free(class_mid);
	class_mid = NULL;
	free(class_final);
	class_final = NULL;
}

static char *find_data(char *data)
{
	while (*data != '\0') {
		if (*data >= '0' && *data <= '9')
			return data;
		data++;
	}
	return NULL;
}

static char *locate_info(char *data, bool is_inner, bool is_class)
{
	char *orig = data;
	char *locate;
	if (!data)
		return orig;

	locate = find_data(data);
	if (!locate)
		return orig;
	if (is_class)
		return locate + 4;
	if (!is_inner)
		/* 4 to get over the number, 2 for spaces */
		return locate + 4 + 2;

	/* Inner data, has "sub_ven(space)sub_dev(space)(space)string */
	return locate + 4 + 1 + 4 + 2;
}

static void format_and_print(char *save)
{

	if (!class_mid) {
		if (device_final)
			snprintf(save, LINE_BUF_SIZE, "%s %s %s",
				 locate_info(device_top, false, false),
				 locate_info(device_mid, false, false),
				 locate_info(device_final, true, false));
		else
			snprintf(save, LINE_BUF_SIZE, "%s %s",
				 locate_info(device_top, false, false),
				 locate_info(device_mid, false, false));
	} else {
		if (device_final)
			snprintf(save, LINE_BUF_SIZE, "%s: %s %s %s",
				 locate_info(class_mid, false, true),
				 locate_info(device_top, false, false),
				 locate_info(device_mid, false, false),
				 locate_info(device_final, true, false));
		else
			snprintf(save, LINE_BUF_SIZE, "%s: %s %s",
				 locate_info(class_mid, false, true),
				 locate_info(device_top, false, false),
				 locate_info(device_mid, false, false));
	}
}

static void format_all(char *save, char *vendor, char *device)
{
	if (device_top && device_mid)
		format_and_print(save);

	else if (device_top && !device_mid && class_mid)
		snprintf(save, LINE_BUF_SIZE, "%s: %s Device %s",
			 locate_info(class_mid, false, true),
			 locate_info(device_top, false, false),
			 device);

	else if (!device_top && class_mid)
		snprintf(save, LINE_BUF_SIZE, "%s: Vendor %s Device %s",
			 locate_info(class_mid, false, true),
			 vendor,
			 device);
	else
		snprintf(save, LINE_BUF_SIZE, "Unknown device");
}

static int is_final_match(char *line, char *search)
{
	return !memcmp(&line[2], search, 2);
}

static int is_inner_sub_vendev(char *line, char *search, char *search2)
{
	char combine[10];
	snprintf(combine, sizeof(combine), "%s %s", &search[2], &search2[2]);
       	if (line[0] != '\t' && line[1] != '\t')
		return 0;

	return !memcmp(combine, &line[2], 9);
}

static int is_mid_level_match(char *line, char *device, bool class)
{
	if (!class)
		return !memcmp(&line[1], &device[2], 4);

	return !memcmp(&line[1], device, 2);
}

static inline bool is_comment(char *line)
{
	return line[0] == '#';
}

static int is_top_level_match(char *line, const char* device, bool class)
{
	if (line[0] == '\t')
		return false;
	if (line[0] == '#')
		return false;
	if (!class)
		return !memcmp(line, &device[2], 4);
	if (line[0] != 'C')
		return false;
	/* Skipping    C(SPACE)  0x */
	return !memcmp(&line[2], &device[2], 2);
}

static inline int is_tab(char *line)
{
	return line[0] == '\t';
}

static inline int is_class_info(char *line)
{
	return !memcmp(line, "# C class", 9);
}

static void parse_vendor_device(char *line, FILE *file,
			       char *device, char *subdev,
			       char *subven)
{
	bool device_single_found = false;
	size_t len;

	while (fgets(line, LINE_BUF_SIZE, file) != NULL) {
		len = strlen(line);
		if (len > 0 && line[len - 1] == '\n')
			line[len - 1] = '\0';
		if (is_comment(line))
			continue;
		if (!is_tab(line))
			return;

		if (!device_single_found && is_mid_level_match(line, device, false)) {
			device_single_found = true;
			device_mid = strdup(line);
			continue;
		}

		if (device_single_found && is_inner_sub_vendev(line, subven, subdev)) {
			device_final = strdup(line);
			break;
		}
	}
}

static void pull_class_info(char *line, FILE *file, char *class)
{
	bool top_found = false;
	bool mid_found = false;
	size_t len;

	while (fgets(line, LINE_BUF_SIZE, file) != NULL) {
		len = strlen(line);
		if (len > 0 && line[len - 1] == '\n')
			line[len - 1] = '\0';
		if (!top_found && is_top_level_match(line, class, true)) {
			class_top = strdup(line);
			top_found = true;
			continue;
		}
		if (!mid_found && top_found &&
		    is_mid_level_match(line, &class[4], true)) {
			class_mid = strdup(line);
			mid_found = true;
			continue;
		}
		if (top_found && mid_found &&
		    is_final_match(line, &class[6])) {
			class_final = strdup(line);
			break;
		}
	}
}

static int read_sys_node(char *where, char *save, size_t savesz)
{
	char *new;
	int fd, ret = 0, len;
	fd = open(where, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s with errno %s\n",
			where, libnvme_strerror(errno));
		return 1;
	}
	/* -1 so we can safely use strstr below */
	len = read(fd, save, savesz - 1);
	if (!len)
		ret = 1;
	else {
		save[len] = '\0';
		new = strstr(save, "\n");
		if (new)
			new[0] = '\0';
	}
	close(fd);
	return ret;
}

static FILE *open_pci_ids(void)
{
	int i;
	char *pci_ids_path;
	FILE *fp;

	const char* pci_ids[] = {
		"/usr/share/hwdata/pci.ids",  /* RHEL */
		"/usr/share/pci.ids",		  /* SLES */
		"/usr/share/misc/pci.ids",	  /* Ubuntu */
		NULL
	};

	/* First check if user gave pci ids in environment */
	if ((pci_ids_path = getenv("PCI_IDS_PATH")) != NULL) {
		if ((fp = fopen(pci_ids_path, "r")) != NULL) {
			return fp;
		} else {
			/* fail if user provided environment variable but could not open */
			perror(pci_ids_path);
			return NULL;
		}
	}

	/* NO environment, check in predefined places */
	for (i = 0; pci_ids[i] != NULL; i++) {
		if ((fp = fopen(pci_ids[i], "r")) != NULL)
			return fp;
	}

	fprintf(stderr, "Could not find pci.ids file\n");
	return NULL;
}

static char *__nvme_product_name(int id)
{
	char readbuf[LINE_BUF_SIZE];
	char vendor[7] = { 0 };
	char device[7] = { 0 };
	char sub_device[7] = { 0 };
	char sub_vendor[7] = { 0 };
	char class[13] = { 0 };
	size_t len;
	int ret = 0;
	char *result;
	FILE *file = open_pci_ids();

	if (!file)
		goto error1;

	snprintf(fmt1, 78, _fmt1, id);
	snprintf(fmt2, 78, _fmt2, id);
	snprintf(fmt3, 78, _fmt3, id);
	snprintf(fmt4, 78, _fmt4, id);
	snprintf(fmt5, 78, _fmt5, id);

	ret = read_sys_node(fmt1, sub_vendor, 7);
	ret |= read_sys_node(fmt2, sub_device, 7);
	ret |= read_sys_node(fmt3, vendor, 7);
	ret |= read_sys_node(fmt4, device, 7);
	ret |= read_sys_node(fmt5, class, 13);
	if (ret)
		goto error0;

	while (fgets(readbuf, sizeof(readbuf), file) != NULL) {
		len = strlen(readbuf);
		if (len > 0 && readbuf[len - 1] == '\n')
			readbuf[len - 1] = '\0';
		if (is_comment(readbuf) && !is_class_info(readbuf))
			continue;
		if (is_top_level_match(readbuf, vendor, false)) {
			free(device_top);
			device_top = strdup(readbuf);
			parse_vendor_device(readbuf, file,
						device,
						sub_device,
						sub_vendor);
		}
		if (is_class_info(readbuf))
			pull_class_info(readbuf, file, class);
	}
	fclose(file);

	result = malloc(LINE_BUF_SIZE);
	if (!result) {
		fprintf(stderr, "malloc: %s\n", libnvme_strerror(errno));
		free_all();
		return NULL;
	}
	format_all(result, vendor, device);
	free_all();
	return result;
error0:
	fclose(file);
error1:
	return NULL;
}

char *nvme_product_name(const char *devname)
{
	const char *base;
	int id;

	if (!devname)
		return NULL;

	base = strrchr(devname, '/');
	if (base) {
		if (!base[1])
			return NULL;
		devname = base + 1;
	}

	if (sscanf(devname, "nvme%d", &id) != 1)
		return NULL;

	return __nvme_product_name(id);
}
