#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "nvme.h"
#include "nvme-ioctl.h"

#ifdef HAVE_SYSTEMD
#include <systemd/sd-id128.h>
#define NVME_HOSTNQN_ID SD_ID128_MAKE(c7,f4,61,81,12,be,49,32,8c,83,10,6f,9d,dd,d8,6b)
#endif

static const char *dev = "/dev/";
static const char *subsys_dir = "/sys/class/nvme-subsystem/";
static void free_ctrl(struct nvme_ctrl *c);

char *get_nvme_subsnqn(char *path)
{
	char sspath[320], *subsysnqn;
	int fd, ret;

	snprintf(sspath, sizeof(sspath), "%s/subsysnqn", path);

	fd = open(sspath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n",
				sspath, strerror(errno));
		return NULL;
	}

	subsysnqn = calloc(1, 256);
	if (!subsysnqn)
		goto close_fd;

	ret = read(fd, subsysnqn, 256);
	if (ret < 0) {
		fprintf(stderr, "Failed to read %s: %s\n", sspath,
				strerror(errno));
		free(subsysnqn);
		subsysnqn = NULL;
	} else if (subsysnqn[strlen(subsysnqn) - 1] == '\n') {
		subsysnqn[strlen(subsysnqn) - 1] = '\0';
	}

close_fd:
	close(fd);
	return subsysnqn;
}

char *nvme_get_ctrl_attr(const char *path, const char *attr)
{
	char *attrpath, *value;
	ssize_t ret;
	int fd, i;

	ret = asprintf(&attrpath, "%s/%s", path, attr);
	if (ret < 0)
		return NULL;

	value = calloc(1, 1024);
	if (!value)
		goto err_free_path;

	fd = open(attrpath, O_RDONLY);
	if (fd < 0)
		goto err_free_value;

	ret = read(fd, value, 1024);
	if (ret < 0) {
		fprintf(stderr, "read :%s :%s\n", attrpath, strerror(errno));
		goto err_close_fd;
	}

	if (value[strlen(value) - 1] == '\n')
		value[strlen(value) - 1] = '\0';

	for (i = 0; i < strlen(value); i++) {
		if (value[i] == ',' )
			value[i] = ' ';
	}

	close(fd);
	free(attrpath);
	return value;
err_close_fd:
	close(fd);
err_free_value:
	free(value);
err_free_path:
	free(attrpath);
	return NULL;
}

static char *path_trim_last(char *path, char needle)
{
	int i;
	i = strlen(path);
	if (i>0 && path[i-1] == needle)		// remove trailing slash
		path[--i] = 0;
	for (; i>0; i--)
		if (path[i] == needle) {
			path[i] = 0;
			return path+i+1;
	}
	return NULL;
}

static void legacy_get_pci_bdf(char *node, char *bdf)
{
	int ret;
	char path[264], nodetmp[264];
	struct stat st;
	char *p, *__path = path;

	bdf[0] = 0;
	strcpy(nodetmp, node);
	p = path_trim_last(nodetmp, '/');
	sprintf(path, "/sys/block/%s/device", p);
	ret = readlink(path, nodetmp, sizeof(nodetmp));
	if (ret <= 0)
		return;
	nodetmp[ret] = 0;
	/* The link value is either "device -> ../../../0000:86:00.0" or "device -> ../../nvme0" */
	(void) path_trim_last(path, '/');
	sprintf(path+strlen(path), "/%s/device", nodetmp);
	ret = stat(path, &st);
	if (ret < 0)
		return;
	if ((st.st_mode & S_IFLNK) == 0) {
		/* follow the second link to get the PCI address */
		ret = readlink(path, __path, sizeof(path));
		if (ret <= 0)
			return;
		path[ret] = 0;
	}
	else
		(void) path_trim_last(path, '/');

	p = path_trim_last(path, '/');
	if (p && strlen(p) == 12)
		strcpy(bdf, p);
}

static int scan_namespace(struct nvme_namespace *n)
{
	int ret, fd;
	char *path;

	ret = asprintf(&path, "%s%s", n->ctrl->path, n->name);
	if (ret < 0)
		return ret;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto free;

	if (!n->nsid) {
		n->nsid = nvme_get_nsid(fd);
		if (n->nsid < 0)
			goto close_fd;
	}

	ret = nvme_identify_ns(fd, n->nsid, 0, &n->ns);
	if (ret < 0)
		goto close_fd;
close_fd:
	close(fd);
free:
	free(path);
	return 0;
}

static char *get_nvme_ctrl_path_ana_state(char *path, int nsid)
{
	struct dirent **paths;
	char *ana_state;
	int i, n;

	ana_state = calloc(1, 16);
	if (!ana_state)
		return NULL;

	n = scandir(path, &paths, scan_ctrl_paths_filter, alphasort);
	if (n <= 0) {
		free(ana_state);
		return NULL;
	}
	for (i = 0; i < n; i++) {
		int id, cntlid, ns, fd;
		char *ctrl_path;
		ssize_t ret;

		if (sscanf(paths[i]->d_name, "nvme%dc%dn%d",
			   &id, &cntlid, &ns) != 3) {
			if (sscanf(paths[i]->d_name, "nvme%dn%d",
				   &id, &ns) != 2) {
				continue;
			}
		}
		if (ns != nsid)
			continue;

		ret = asprintf(&ctrl_path, "%s/%s/ana_state",
			       path, paths[i]->d_name);
		if (ret < 0) {
			free(ana_state);
			ana_state = NULL;
			break;
		}
		fd = open(ctrl_path, O_RDONLY);
		if (fd < 0) {
			free(ctrl_path);
			free(ana_state);
			ana_state = NULL;
			break;
		}
		ret = read(fd, ana_state, 16);
		if (ret < 0) {
			fprintf(stderr, "Failed to read ANA state from %s\n",
				ctrl_path);
			free(ana_state);
			ana_state = NULL;
		} else if (ana_state[strlen(ana_state) - 1] == '\n')
			ana_state[strlen(ana_state) - 1] = '\0';
		close(fd);
		free(ctrl_path);
		break;
	}
	for (i = 0; i < n; i++)
		free(paths[i]);
	free(paths);
	return ana_state;
}

static bool ns_attached_to_ctrl(int nsid, struct nvme_ctrl *ctrl)
{
	struct nvme_namespace *n;
	int i;

	for (i = 0; i < ctrl->nr_namespaces; i++) {
		n = &ctrl->namespaces[i];
		if (nsid == n->nsid)
			return true;
	}
	return false;
}

static int scan_ctrl(struct nvme_ctrl *c, char *p, __u32 ns_instance)
{
	struct nvme_namespace *n;
	struct dirent **ns;
	char *path;
	int i, fd, ret;

	ret = asprintf(&path, "%s/%s", p, c->name);
	if (ret < 0)
		return ret;

	c->address = nvme_get_ctrl_attr(path, "address");
	c->transport = nvme_get_ctrl_attr(path, "transport");
	c->state = nvme_get_ctrl_attr(path, "state");
	c->hostnqn = nvme_get_ctrl_attr(path, "hostnqn");
	c->hostid = nvme_get_ctrl_attr(path, "hostid");

	if (ns_instance)
		c->ana_state = get_nvme_ctrl_path_ana_state(path, ns_instance);

	ret = scandir(path, &ns, scan_ctrl_namespace_filter, alphasort);
	if (ret == -1) {
		fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
		return errno;
	}

	c->nr_namespaces = ret;
	c->namespaces = calloc(c->nr_namespaces, sizeof(*n));
	if (c->namespaces) {
		for (i = 0; i < c->nr_namespaces; i++) {
			char *ns_path, nsid[16];
			int ns_fd;

			n = &c->namespaces[i];
			n->name = strdup(ns[i]->d_name);
			n->ctrl = c;
			ret = asprintf(&ns_path, "%s/%s/nsid", path, n->name);
			if (ret < 0)
				continue;
			ns_fd = open(ns_path, O_RDONLY);
			if (ns_fd < 0) {
				free(ns_path);
				continue;
			}
			ret = read(ns_fd, nsid, 16);
			if (ret < 0) {
				close(ns_fd);
				free(ns_path);
				continue;
			}
			n->nsid = (unsigned)strtol(nsid, NULL, 10);
			scan_namespace(n);
			close(ns_fd);
			free(ns_path);
		}
	} else {
		i = c->nr_namespaces;
		c->nr_namespaces = 0;
	}

	while (i--)
		free(ns[i]);
	free(ns);
	free(path);

	ret = asprintf(&path, "%s%s", c->path, c->name);
	if (ret < 0)
		return ret;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s\n", path);
		goto free;
	}

	ret = nvme_identify_ctrl(fd, &c->id);
	if (ret < 0)
		goto close_fd;
close_fd:
	close(fd);
free:
	free(path);
	return 0;
}

static int scan_subsystem(struct nvme_subsystem *s, __u32 ns_instance, int nsid)
{
	struct dirent **ctrls, **ns;
	struct nvme_namespace *n;
	struct nvme_ctrl *c;
	int i, j = 0, ret;
	char *path;

	ret = asprintf(&path, "%s%s", subsys_dir, s->name);
	if (ret < 0)
		return ret;

	s->subsysnqn = get_nvme_subsnqn(path);
	ret = scandir(path, &ctrls, scan_ctrls_filter, alphasort);
	if (ret == -1) {
		fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
		return errno;
	}
	s->nr_ctrls = ret;
	s->ctrls = calloc(s->nr_ctrls, sizeof(*c));
	for (i = 0; i < s->nr_ctrls; i++) {
		c = &s->ctrls[j];
		c->name = strdup(ctrls[i]->d_name);
		c->path = strdup(dev);
		c->subsys = s;
		scan_ctrl(c, path, ns_instance);

		if (!ns_instance || ns_attached_to_ctrl(nsid, c))
			j++;
		else
			free_ctrl(c);
	}
	s->nr_ctrls = j;

	while (i--)
		free(ctrls[i]);
	free(ctrls);

	ret = scandir(path, &ns, scan_namespace_filter, alphasort);
	if (ret == -1) {
		fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
		return errno;
	}

	s->nr_namespaces = ret;
	s->namespaces = calloc(s->nr_namespaces, sizeof(*n));
	if (s->namespaces) {
		for (i = 0; i < s->nr_namespaces; i++) {
			n = &s->namespaces[i];
			n->name = strdup(ns[i]->d_name);
			n->ctrl = &s->ctrls[0];
			scan_namespace(n);
		}
	} else {
		i = s->nr_namespaces;
		s->nr_namespaces = 0;
	}

	while (i--)
		free(ns[i]);
	free(ns);

	free(path);
	return 0;
}

static int verify_legacy_ns(struct nvme_namespace *n)
{
	struct nvme_ctrl *c = n->ctrl;
	struct nvme_id_ctrl id;
	char *path;
	int ret, fd;

	ret = asprintf(&path, "%s%s", n->ctrl->path, n->name);
	if (ret < 0)
		return ret;

	if (!n->ctrl->transport && !n->ctrl->address) {
		char tmp_address[64] = "";
		legacy_get_pci_bdf(path, tmp_address);
		if (tmp_address[0]) {
			if (asprintf(&n->ctrl->transport, "pcie") < 0)
				return -1;
			if (asprintf(&n->ctrl->address, "%s", tmp_address) < 0)
				return -1;
		}
	}

	fd = open(path, O_RDONLY);
	free (path);

	if (fd < 0)
		return fd;

	ret = nvme_identify_ctrl(fd, &id);
	close(fd);

	if (ret)
		return ret;

	if (memcmp(id.mn, c->id.mn, sizeof(id.mn)) ||
	    memcmp(id.sn, c->id.sn, sizeof(id.sn)))
		return -ENODEV;
	return 0;
}

/*
 * For pre-subsystem enabled kernel. Topology information is limited, but we can
 * assume controller names are always a prefix to their namespaces, i.e. nvme0
 * is the controller to nvme0n1 for such older kernels. We will also assume
 * every controller is its own subsystem.
 */
static int legacy_list(struct nvme_topology *t, char *dev_dir)
{
	struct nvme_ctrl *c;
	struct nvme_subsystem *s;
	struct nvme_namespace *n;
	struct dirent **devices, **namespaces;
	int ret = 0, fd, i;
	char *path;

	t->nr_subsystems = scandir(dev_dir, &devices, scan_ctrls_filter, alphasort);
	if (t->nr_subsystems == -1) {
		fprintf(stderr, "Failed to open %s: %s\n", dev_dir, strerror(errno));
		return errno;
	}

	t->subsystems = calloc(t->nr_subsystems, sizeof(*s));
	for (i = 0; i < t->nr_subsystems; i++) {
		int j;

		s = &t->subsystems[i];
		s->nr_ctrls = 1;
		s->ctrls = calloc(s->nr_ctrls, sizeof(*c));
		s->name = strdup(devices[i]->d_name);
		s->subsysnqn = strdup(s->name);
		s->nr_namespaces = 0;

		c = s->ctrls;
		c->name = strdup(s->name);
		sscanf(c->name, "nvme%d", &current_index);
		c->path = strdup(dev_dir);
		c->nr_namespaces = scandir(c->path, &namespaces, scan_dev_filter,
					   alphasort);
		c->namespaces = calloc(c->nr_namespaces, sizeof(*n));
		if (!c->namespaces) {
			while (c->nr_namespaces--)
				free(namespaces[c->nr_namespaces]);
			free(namespaces);
			continue;
		}

		ret = asprintf(&path, "%s%s", c->path, c->name);
		if (ret < 0)
			continue;
		ret = 0;

		fd = open(path, O_RDONLY);
		if (fd > 0) {
			nvme_identify_ctrl(fd, &c->id);
			close(fd);
		}
		free(path);

		for (j = 0; j < c->nr_namespaces; j++) {
			n = &c->namespaces[j];
			n->name = strdup(namespaces[j]->d_name);
			n->ctrl = c;
			scan_namespace(n);
			ret = verify_legacy_ns(n);
			if (ret)
				goto free;
		}
		while (j--)
			free(namespaces[j]);
		free(namespaces);
	}

free:
	while (i--)
		free(devices[i]);
	free(devices);
	return ret;
}

static void free_ctrl(struct nvme_ctrl *c)
{
	int i;

	for (i = 0; i < c->nr_namespaces; i++) {
		struct nvme_namespace *n = &c->namespaces[i];
		free(n->name);
	}
	free(c->name);
	free(c->path);
	free(c->transport);
	free(c->address);
	free(c->state);
	free(c->hostnqn);
	free(c->hostid);
	free(c->ana_state);
	free(c->namespaces);
}

static void free_subsystem(struct nvme_subsystem *s)
{
	int i;

	for (i = 0; i < s->nr_ctrls; i++)
		free_ctrl(&s->ctrls[i]);
	for (i = 0; i < s->nr_namespaces; i++) {
		struct nvme_namespace *n = &s->namespaces[i];
		free(n->name);
	}
	free(s->name);
	free(s->subsysnqn);
	free(s->ctrls);
	free(s->namespaces);
}

static int scan_subsystem_dir(struct nvme_topology *t, char *dev_dir)
{
	struct nvme_topology dev_dir_t = { };
	int ret, i, total_nr_subsystems;

	ret = legacy_list(&dev_dir_t, dev_dir);
	if (ret != 0)
		return ret;

	total_nr_subsystems = t->nr_subsystems + dev_dir_t.nr_subsystems;
	t->subsystems = realloc(t->subsystems,
				total_nr_subsystems * sizeof(struct nvme_subsystem));
	for (i = 0; i < dev_dir_t.nr_subsystems; i++){
		t->subsystems[i+t->nr_subsystems] = dev_dir_t.subsystems[i];
	}
	t->nr_subsystems = total_nr_subsystems;

	return 0;
}

int scan_subsystems(struct nvme_topology *t, const char *subsysnqn,
		    __u32 ns_instance, int nsid, char *dev_dir)
{
	struct nvme_subsystem *s;
	struct dirent **subsys;
	int ret = 0, i, j = 0;

	t->nr_subsystems = scandir(subsys_dir, &subsys, scan_subsys_filter,
				   alphasort);
	if (t->nr_subsystems < 0) {
		ret = legacy_list(t, (char *)dev);
		if (ret != 0)
			return ret;
	} else {

		t->subsystems = calloc(t->nr_subsystems, sizeof(*s));
		for (i = 0; i < t->nr_subsystems; i++) {
			s = &t->subsystems[j];
			s->name = strdup(subsys[i]->d_name);
			scan_subsystem(s, ns_instance, nsid);

			if (!subsysnqn || !strcmp(s->subsysnqn, subsysnqn))
				j++;
			else
				free_subsystem(s);
		}
		t->nr_subsystems = j;

		while (i--)
			free(subsys[i]);
		free(subsys);
	}

	if (dev_dir != NULL && strcmp(dev_dir, "/dev/")) {
		ret = scan_subsystem_dir(t, dev_dir);
	}

	return ret;
}

void free_topology(struct nvme_topology *t)
{
	int i;

	for (i = 0; i < t->nr_subsystems; i++)
		free_subsystem(&t->subsystems[i]);
	free(t->subsystems);
}

char *nvme_char_from_block(char *dev)
{
	char *path = NULL;
	char buf[256] = {0};
	int ret, id, nsid;

	ret = sscanf(dev, "nvme%dn%d", &id, &nsid);
	switch (ret) {
	case 1:
		return strdup(dev);
		break;
	case 2:
		if (asprintf(&path, "/sys/block/%s/device", dev) < 0)
			path = NULL;
		break;
	default:
		fprintf(stderr, "%s is not an nvme device\n", dev);
		return NULL;
	}

	if (!path)
		return NULL;

	ret = readlink(path, buf, sizeof(buf));
	if (ret > 0) {
		char *r = strdup(basename(buf));

		free(path);
		if (sscanf(r, "nvme%d", &id) != 1) {
			fprintf(stderr, "%s is not a physical nvme controller\n", r);
			free(r);
			r = NULL;
		}
		return r;
	}

	free(path);
	ret = asprintf(&path, "nvme%d", id);
	if (ret < 0)
		return NULL;
	return path;
}

void *mmap_registers(const char *dev)
{
	int fd;
	char *base, path[512];
	void *membase;

	base = nvme_char_from_block((char *)dev);
	if (!base)
		return NULL;

	sprintf(path, "/sys/class/nvme/%s/device/resource0", base);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		sprintf(path, "/sys/class/misc/%s/device/resource0", base);
		fd = open(path, O_RDONLY);
	}
	if (fd < 0) {
		fprintf(stderr, "%s did not find a pci resource, open failed %s\n",
				base, strerror(errno));
		free(base);
		return NULL;
	}

	membase = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, fd, 0);
	if (membase == MAP_FAILED) {
		fprintf(stderr, "%s failed to map. ", base);
		fprintf(stderr, "Did your kernel enable CONFIG_IO_STRICT_DEVMEM?\n");
		membase = NULL;
	}

	free(base);
	close(fd);
	return membase;
}

#define PATH_DMI_ENTRIES	"/sys/firmware/dmi/entries"

int uuid_from_dmi(char *system_uuid)
{
	int f;
	DIR *d;
	struct dirent *de;
	char buf[512];

	system_uuid[0] = '\0';
	d = opendir(PATH_DMI_ENTRIES);
	if (!d)
		return -ENXIO;
	while ((de = readdir(d))) {
		char filename[PATH_MAX];
		int len, type;

		if (de->d_name[0] == '.')
			continue;
		sprintf(filename, "%s/%s/type", PATH_DMI_ENTRIES, de->d_name);
		f = open(filename, O_RDONLY);
		if (f < 0)
			continue;
		len = read(f, buf, 512);
		close(f);
		if (len < 0)
			continue;
		if (sscanf(buf, "%d", &type) != 1)
			continue;
		if (type != 1)
			continue;
		sprintf(filename, "%s/%s/raw", PATH_DMI_ENTRIES, de->d_name);
		f = open(filename, O_RDONLY);
		if (f < 0)
			continue;
		len = read(f, buf, 512);
		close(f);
		if (len < 0)
			continue;
		/* Sigh. https://en.wikipedia.org/wiki/Overengineering */
		/* DMTF SMBIOS 3.0 Section 7.2.1 System UUID */
		sprintf(system_uuid,
			"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
			"%02x%02x%02x%02x%02x%02x",
			(uint8_t)buf[8 + 3], (uint8_t)buf[8 + 2],
			(uint8_t)buf[8 + 1], (uint8_t)buf[8 + 0],
			(uint8_t)buf[8 + 5], (uint8_t)buf[8 + 4],
			(uint8_t)buf[8 + 7], (uint8_t)buf[8 + 6],
			(uint8_t)buf[8 + 8], (uint8_t)buf[8 + 9],
			(uint8_t)buf[8 + 10], (uint8_t)buf[8 + 11],
			(uint8_t)buf[8 + 12], (uint8_t)buf[8 + 13],
			(uint8_t)buf[8 + 14], (uint8_t)buf[8 + 15]);
		break;
	}
	closedir(d);
	return strlen(system_uuid) ? 0 : -ENXIO;
}

int uuid_from_systemd(char *systemd_uuid)
{
#ifdef HAVE_SYSTEMD
	sd_id128_t id;

	if (sd_id128_get_machine_app_specific(NVME_HOSTNQN_ID, &id) < 0)
		return -ENXIO;

	sprintf(systemd_uuid, SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(id));
	return 0;
#else
	return -ENOTSUP;
#endif
}
