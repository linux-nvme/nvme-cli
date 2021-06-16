#ifndef _NVME_PRIVATE_H
#define _NVME_PRIVATE_H

struct nvme_subsystem;
struct nvme_ctrl;

struct nvme_namespace {
	char *name;
	struct nvme_ctrl *ctrl;

	unsigned nsid;
	struct nvme_id_ns ns;
};

struct nvme_ctrl {
	char *name;
	char *path;
	struct nvme_subsystem *subsys;

	char *address;
	char *transport;
	char *state;
	char *ana_state;
	char *traddr;
	char *trsvcid;
	char *host_traddr;
	char *host_iface;
	char *hostnqn;
	char *hostid;

	struct nvme_id_ctrl id;

	int    nr_namespaces;
	struct nvme_namespace *namespaces;
};

struct nvme_subsystem {
	char *name;
	char *subsysnqn;

	int    nr_ctrls;
	struct nvme_ctrl *ctrls;

	int    nr_namespaces;
	struct nvme_namespace *namespaces;
};

struct nvme_topology {
	int    nr_subsystems;
	struct nvme_subsystem *subsystems;
};

void *mmap_registers(const char *dev);

int scan_ctrl_namespace_filter(const struct dirent *d);
int scan_namespace_filter(const struct dirent *d);
int scan_ctrl_paths_filter(const struct dirent *d);
int scan_ctrls_filter(const struct dirent *d);
int scan_subsys_filter(const struct dirent *d);
int scan_dev_filter(const struct dirent *d);

int scan_subsystems(struct nvme_topology *t, const char *subsysnqn,
		    __u32 ns_instance, int nsid, char *dev_dir);
void free_topology(struct nvme_topology *t);
char *get_nvme_subsnqn(char *path);
char *nvme_get_ctrl_attr(const char *path, const char *attr);

int uuid_from_dmi(char *uuid);
int uuid_from_systemd(char *uuid);

#endif /* _NVME_PRIVATE_H */
