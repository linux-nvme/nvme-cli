#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "nvme.h"
#include "nvme-ioctl.h"

static const char delim_space  = ' ';

int get_nsid(int fd)
{
	int nsid = nvme_get_nsid(fd);

	if (nsid <= 0) {
		fprintf(stderr,
			"%s: failed to return namespace id\n",
			devicename);
	}
	return nsid < 0 ? 0 : nsid;
}

char *get_nvme_subsnqn(char *path)
{
	char sspath[320];
	char *subsysnqn;
	int fd;
	int ret;

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

char *get_nvme_ctrl_attr(char *path, const char *attr)
{
	char *attrpath;
	char *value;
	int fd;
	ssize_t ret;
	int i;

	ret = asprintf(&attrpath, "%s/%s", path, attr);
	if (ret < 0)
		return NULL;

	value = calloc(1, 1024);
	if (!value)
		goto err_free_path;

	fd = open(attrpath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n",
				attrpath, strerror(errno));
		goto err_free_value;
	}

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

static int scan_namespace(struct nvme_namespace *n)
{
	int ret, fd;
	char *path;

	ret = asprintf(&path, "%s%s", dev, n->name);
	if (ret < 0)
		return ret;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto free;

	n->nsid = get_nsid(fd);
	ret = nvme_identify_ns(fd, n->nsid, 0, &n->ns);
	if (ret < 0)
		goto close_fd;
close_fd:
	close(fd);
free:
	free(path);
	return 0;
}

static int scan_ctrl(struct nvme_ctrl *c, char *p)
{
	struct nvme_namespace *n;
	struct dirent **ns;
	char *path;
	int i, fd, ret;

	ret = asprintf(&path, "%s/%s", p, c->name);
	if (ret < 0)
		return ret;

	c->address = get_nvme_ctrl_attr(path, "address");
	c->transport = get_nvme_ctrl_attr(path, "transport");
	c->state = get_nvme_ctrl_attr(path, "state");

	ret = scandir(path, &ns, scan_namespace_filter, alphasort);
	if (ret == -1) {
		fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
		return errno;
	}
	c->nr_namespaces = ret;
	c->namespaces = calloc(c->nr_namespaces, sizeof(*n));
	for (i = 0; i < c->nr_namespaces; i++) {
		n = &c->namespaces[i];
		n->name = strdup(ns[i]->d_name);
		n->ctrl = c;
		scan_namespace(n);
	}

	while (i--)
		free(ns[i]);
	free(ns);
	free(path);

	ret = asprintf(&path, "%s%s", dev, c->name);
	if (ret < 0)
		return ret;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto free;

	ret = nvme_identify_ctrl(fd, &c->id);
	if (ret < 0)
		goto close_fd;
close_fd:
	close(fd);
free:
	free(path);
	return 0;
}

static int scan_subsystem(struct nvme_subsystem *s)
{
	struct dirent **ctrls, **ns;
	struct nvme_namespace *n;
	struct nvme_ctrl *c;
	int i, ret;
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
		c = &s->ctrls[i];
		c->name = strdup(ctrls[i]->d_name);
		c->subsys = s;
		scan_ctrl(c, path);
	}

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
	for (i = 0; i < s->nr_namespaces; i++) {
		n = &s->namespaces[i];
		n->name = strdup(ns[i]->d_name);
		n->ctrl = &s->ctrls[0];
		scan_namespace(n);
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

	ret = asprintf(&path, "%s%s", dev, n->name);
	if (ret < 0)
		return ret;

	fd = open(path, O_RDONLY);
	free (path);

	if (fd < 0)
		return fd;

	ret = nvme_identify_ctrl(fd, &id);
	close(fd);

	if (ret)
		return ret;

	if (memcmp(id.mn, c->id.mn, sizeof(id.mn)) ||
	    memcmp(id.sn, c->id.mn, sizeof(id.sn)))
		return -ENODEV;
	return 0;
}

/*
 * For pre-subsystem enabled kernel. Topology information is limited, but we can
 * assume controller names are always a prefix to their namespaces, i.e. nvme0
 * is the controller to nvme0n1 for such older kernels. We will also assume
 * every controller is its own subsystem.
 */
static int legacy_list(struct nvme_topology *t)
{
	struct nvme_ctrl *c;
	struct nvme_subsystem *s;
	struct nvme_namespace *n;
	struct dirent **devices, **namespaces;
	int ret = 0, fd, i;
	char *path;

	t->nr_subsystems = scandir(dev, &devices, scan_ctrls_filter, alphasort);
	if (t->nr_subsystems < 0) {
		fprintf(stderr, "no NVMe device(s) detected.\n");
		return t->nr_subsystems;
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
		c->nr_namespaces = scandir(dev, &namespaces, scan_dev_filter,
					   alphasort);
		c->namespaces = calloc(c->nr_namespaces, sizeof(*n));

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

		ret = asprintf(&path, "%s%s", dev, c->name);
		if (ret < 0)
			continue;
		ret = 0;

		fd = open(path, O_RDONLY);
		if (fd > 0) {
			nvme_identify_ctrl(fd, &c->id);
			close(fd);
		}
		free(path);
	}

free:
	while (i--)
		free(devices[i]);
	free(devices);
	return ret;
}

int scan_subsystems(struct nvme_topology *t)
{
	struct nvme_subsystem *s;
	struct dirent **subsys;
	int i;

	t->nr_subsystems = scandir(subsys_dir, &subsys, scan_subsys_filter, alphasort);
	if (t->nr_subsystems < 0)
		return legacy_list(t);

	t->subsystems = calloc(t->nr_subsystems, sizeof(*s));
	for (i = 0; i < t->nr_subsystems; i++) {
		s = &t->subsystems[i];
		s->name = strdup(subsys[i]->d_name);
		scan_subsystem(s);
	}

	while (i--)
		free(subsys[i]);
	free(subsys);
	return 0;
}

void free_topology(struct nvme_topology *t)
{
	int i, j, k;

	for (i = 0; i < t->nr_subsystems; i++) {
		struct nvme_subsystem *s = &t->subsystems[i];

		for (j = 0; j < s->nr_ctrls; j++) {
			struct nvme_ctrl *c = &s->ctrls[j];

			for (k = 0; k < c->nr_namespaces; k++) {
				struct nvme_namespace *n = &c->namespaces[k];
				free(n->name);
			}
			free(c->name);
			if (c->transport)
				free(c->transport);
			if (c->address)
				free(c->address);
			if (c->state)
				free(c->state);
			if (c->namespaces)
				free(c->namespaces);
		}
		free(s->name);
		free(s->subsysnqn);
		free(s->ctrls);
		free(s->namespaces);
	}
	free(t->subsystems);
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
		ssize_t ret;
		char *ctrl_path;

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

void free_ctrl_list_item(struct ctrl_list_item *ctrls)
{
	free(ctrls->name);
	free(ctrls->transport);
	free(ctrls->address);
	free(ctrls->state);
	free(ctrls->ana_state);
	free(ctrls->subsysnqn);
	free(ctrls->traddr);
	free(ctrls->trsvcid);
	free(ctrls->host_traddr);
}

int get_nvme_ctrl_info(char *name, char *path, struct ctrl_list_item *ctrl,
			__u32 nsid)
{
	char ctrl_path[512];

	ctrl->name = strdup(name);

	snprintf(ctrl_path, sizeof(ctrl_path), "%s/%s", path, ctrl->name);

	ctrl->address = get_nvme_ctrl_attr(ctrl_path, "address");
	if (!ctrl->address) {
		fprintf(stderr, "%s: failed to get controller address.\n",
			ctrl->name);
		goto free_ctrl_items;
	}

	ctrl->transport = get_nvme_ctrl_attr(ctrl_path, "transport");
	if (!ctrl->transport) {
		fprintf(stderr, "%s: failed to get controller transport.\n",
			ctrl->name);
		goto free_ctrl_items;
	}

	ctrl->state = get_nvme_ctrl_attr(ctrl_path, "state");
	if (!ctrl->state) {
		fprintf(stderr, "%s: failed to get controller state.\n",
			ctrl->name);
		goto free_ctrl_items;
	}

	if (nsid != NVME_NSID_ALL)
		ctrl->ana_state = get_nvme_ctrl_path_ana_state(ctrl_path, nsid);

	ctrl->subsysnqn = get_nvme_ctrl_attr(ctrl_path, "subsysnqn");
	if (!ctrl->subsysnqn) {
		fprintf(stderr, "%s: failed to get controller subsysnqn.\n",
			ctrl->name);
		goto free_ctrl_items;
	}

	ctrl->traddr = __parse_connect_arg(ctrl->address, delim_space,
					conarg_traddr);
	ctrl->trsvcid = __parse_connect_arg(ctrl->address, delim_space,
					conarg_trsvcid);
	ctrl->host_traddr = __parse_connect_arg(ctrl->address, delim_space,
					conarg_host_traddr);

	return 0;	/* success */

free_ctrl_items:
	free_ctrl_list_item(ctrl);

	return 1;	/* failure */
}

static int get_nvme_subsystem_info(char *name, char *path,
				struct subsys_list_item *item, __u32 nsid)
{
	struct dirent **ctrls;
	int n, i, ret = 1, ccnt = 0;

	item->subsysnqn = get_nvme_subsnqn(path);
	if (!item->subsysnqn) {
		fprintf(stderr, "failed to get subsystem nqn.\n");
		return ret;
	}

	item->name = strdup(name);

	n = scandir(path, &ctrls, scan_ctrls_filter, alphasort);
	if (n < 0) {
		fprintf(stderr, "failed to scan controller(s).\n");
		return ret;
	}

	item->ctrls = calloc(n, sizeof(struct ctrl_list_item));
	if (!item->ctrls) {
		fprintf(stderr, "failed to allocate subsystem controller(s)\n");
		goto free_ctrls;
	}

	item->nctrls = n;

	for (i = 0; i < n; i++) {
		if (get_nvme_ctrl_info(ctrls[i]->d_name, path,
				&item->ctrls[ccnt], nsid)) {
			fprintf(stderr, "failed to get controller[%d] info.\n",
					i);
		}
		ccnt++;
	}

	item->nctrls = ccnt;

	ret = 0;

free_ctrls:
	for (i = 0; i < n; i++)
		free(ctrls[i]);
	free(ctrls);

	return ret;

}

static void free_subsys_list_item(struct subsys_list_item *item)
{
	int i;

	for (i = 0; i < item->nctrls; i++)
		free_ctrl_list_item(&item->ctrls[i]);

	free(item->ctrls);
	free(item->subsysnqn);
	free(item->name);
}

void free_subsys_list(struct subsys_list_item *slist, int n)
{
	int i;

	for (i = 0; i < n; i++)
		free_subsys_list_item(&slist[i]);

	free(slist);
}

struct subsys_list_item *get_subsys_list(int *subcnt, char *subsysnqn,
					 __u32 nsid)
{
	char path[310];
	struct dirent **subsys;
	struct subsys_list_item *slist;
	int n, i, ret = 0;

	n = scandir(subsys_dir, &subsys, scan_subsys_filter, alphasort);
	if (n < 0) {
		fprintf(stderr, "no NVMe subsystem(s) detected.\n");
		return NULL;
	}

	slist = calloc(n, sizeof(struct subsys_list_item));
	if (!slist)
		goto free_subsys;

	for (i = 0; i < n; i++) {
		snprintf(path, sizeof(path), "%s%s", subsys_dir,
			subsys[i]->d_name);
		ret = get_nvme_subsystem_info(subsys[i]->d_name, path,
				&slist[*subcnt], nsid);
		if (ret) {
			fprintf(stderr,
				"%s: failed to get subsystem info: %s\n",
				path, strerror(errno));
			free_subsys_list_item(&slist[*subcnt]);
		} else if (subsysnqn &&
			   strncmp(slist[*subcnt].subsysnqn, subsysnqn, 255))
			free_subsys_list_item(&slist[*subcnt]);
		else
			(*subcnt)++;
	}

free_subsys:
	for (i = 0; i < n; i++)
		free(subsys[i]);
	free(subsys);

	return slist;
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

