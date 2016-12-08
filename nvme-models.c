#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static char *_fmt1 = "/sys/class/nvme/nvme%d/device/subsystem_vendor";
static char *_fmt2 = "/sys/class/nvme/nvme%d/device/subsystem_device";
static char *_fmt3 = "/sys/class/nvme/nvme%d/device/vendor";
static char *_fmt4 = "/sys/class/nvme/nvme%d/device/device";
static char *_fmt5 = "/sys/class/nvme/nvme%d/device/class";

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
	free(device_mid);
	free(device_final);
	free(class_top);
	free(class_mid);
	free(class_final);
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
	char *locate = find_data(data);
	if (!data)
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

	if (!class_mid)
		snprintf(save, 1024, "%s %s %s",
		       locate_info(device_top, false, false),
		       locate_info(device_mid, false, false),
		       locate_info(device_final, true, false));
	else
		snprintf(save, 1024, "%s: %s %s %s",
			 locate_info(class_mid, false, true),
			 locate_info(device_top, false, false),
			 locate_info(device_mid, false, false),
			 locate_info(device_final, true, false));
}

static void format_all(char *save, char *vendor, char *device)
{
	if (device_top && device_mid && device_final)
		format_and_print(save);

	else if (device_top && !device_mid && class_mid)
		snprintf(save, 1024, "%s: %s Device %s",
			 locate_info(class_mid, false, true),
			 locate_info(device_top, false, false),
			 device);

	else if (!device_top && class_mid)
		snprintf(save, 1024, "%s: Vendor %s Device %s",
			 locate_info(class_mid, false, true),
			 vendor,
			 device);
	else
		snprintf(save, 1024, "Unknown device");
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

static void parse_vendor_device(char **line, FILE *file,
			       char *device, char *subdev,
			       char *subven)
{
	bool device_single_found = false;
	size_t amnt = 1024;
	size_t found = 0;
	char *newline;

	while ((found = getline(line, &amnt, file)) != -1) {
		newline = *line;
		if (is_comment(newline))
			continue;
		if (!is_tab(newline))
			return;

		newline[found - 1] = '\0';
		if (!device_single_found && is_mid_level_match(newline, device, false)) {
			device_single_found = true;
			device_mid = strdup(newline);
			continue;
		}

		if (device_single_found && is_inner_sub_vendev(newline, subven, subdev)) {
			device_final = strdup(newline);
			break;
		}
	}
}

static void pull_class_info(char **_newline, FILE *file, char *class)
{
	size_t amnt;
	size_t size = 1024;
	bool top_found = false;
	bool mid_found = false;
	char *newline;

	while ((amnt = getline(_newline, &size, file)) != -1) {
		newline = *_newline;
		newline[amnt - 1] = '\0';
		if (!top_found && is_top_level_match(newline, class, true)) {
			class_top = strdup(newline);
			top_found = true;
			continue;
		}
		if (!mid_found && top_found &&
		    is_mid_level_match(newline,  &class[4], true)) {
			class_mid = strdup(newline);
			mid_found = true;
			continue;
		}
		if (top_found && mid_found &&
		    is_final_match(newline, &class[6])) {
			class_final = strdup(newline);
			break;
		}
	}
}

static int read_sys_node(char *where, char *save, size_t savesz)
{
	char *new;
	int fd, ret = 0;
	fd = open(where, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s with errno %s\n",
			where, strerror(errno));
		return 1;
	}
	/* -1 so we can safely use strstr below */
	if(!read(fd, save, savesz - 1))
		ret = 1;

	new = strstr(save, "\n");
	if (new)
		new[0] = '\0';

	close(fd);
	return ret;
}

char *nvme_product_name(int id)
{
	char *line;
	ssize_t amnt;
	FILE *file = fopen("/usr/share/hwdata/pci.ids", "r");
	char vendor[7] = { 0 };
	char device[7] = { 0 };
	char sub_device[7] = { 0 };
	char sub_vendor[7] = { 0 };
	char class[13] = { 0 };
	size_t size = 1024;
	char ret;

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
		goto error1;


	line = malloc(1024);
	if (!line)
		goto error1;

	while ((amnt = getline(&line, &size, file)) != -1) {
		if (is_comment(line) && !is_class_info(line))
			continue;
		if (is_top_level_match(line, vendor, false)) {
			line[amnt - 1] = '\0';
			device_top = strdup(line);
			parse_vendor_device(&line, file,
					    device,
					    sub_device,
					    sub_vendor);
		}
		if (is_class_info(line))
			pull_class_info(&line, file, class);
	}
	format_all(line, vendor, device);
	free_all();
	return line;
 error1:
	return strdup("Unknown Device");
}
