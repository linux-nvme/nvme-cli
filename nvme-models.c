#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

static const char *fmt1 = "/sys/class/nvme/nvme%d/device/subsystem_vendor";
static const char *fmt2 = "/sys/class/nvme/nvme%d/device/subsystem_device";

static int read_sys_node(char *where, char *save, size_t savesz)
{
	char *new;
	int fd, ret = 0;
	fd = open(where, O_RDONLY);
	if (fd < 0)
		return 1;
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
	struct stat f;
	char pname[128];
	char class_path[50];
	char ident[8] = { 0 };
	char ident2[8] = { 0 };
	char lookup[16];
	unsigned long amnt, tot;
	int fd;
	FILE *file = fopen("/usr/share/hwdata/pci.ids", "r");
	char *content, *where, *eol, *ret;
	if (!file)
		goto error1;

	fd = fileno(file);
	if (fd < 0)
		goto error1;

	if (fstat(fd, &f) < 0)
		goto error1;

	content = malloc(f.st_size);
	if (!content)
		goto error1;

	if (fread(content, 1, f.st_size, file) == 0
	    && !feof(file))
		goto error;

	snprintf(class_path, sizeof(class_path), fmt1, id);
	if (read_sys_node(class_path, ident, sizeof(ident)))
		goto error;

	snprintf(class_path, sizeof(class_path), fmt2, id);
	if (read_sys_node(class_path, ident2, sizeof(ident2)))
		goto error;

	/* The sys nodes return 0xABCD and the pci.ids file has no 0x
	 * so we'll skip the 0x.
	 */
	tot = snprintf(lookup, sizeof(lookup), "%s %s", &ident[2], &ident2[2]);
	where = strstr(content, lookup);
	if (!where)
		goto error;
	eol = strstr(where, "\n");
	if (!eol)
		goto error;

	amnt = (unsigned long) eol - (unsigned long) where;
	amnt -= tot;
	snprintf(pname, sizeof(pname), "PCIe NVMe%.*s", (int) amnt, &where[tot]);
	ret = strdup(pname);
	if (!ret)
		goto error;

	fclose(file);
	free(content);
	return ret;
 error:
	fclose(file);
	free(content);
 error1:
	return strdup("Unknown");

}
