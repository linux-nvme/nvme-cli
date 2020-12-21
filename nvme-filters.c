#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "nvme.h"

/* global, used for controller specific namespace filter */
int current_index;

int scan_ctrl_namespace_filter(const struct dirent *d)
{
	int c, i, n;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme")) {
		if (sscanf(d->d_name, "nvme%dc%dn%d", &i, &c, &n) == 3)
			return 1;
		if (sscanf(d->d_name, "nvme%dn%d", &i, &n) == 2)
			return 1;
	}
	return 0;
}

int scan_namespace_filter(const struct dirent *d)
{
	int i, n;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme"))
		if (sscanf(d->d_name, "nvme%dn%d", &i, &n) == 2)
			return 1;
	return 0;
}

int scan_ctrl_paths_filter(const struct dirent *d)
{
	int id, cntlid, nsid;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme")) {
		if (sscanf(d->d_name, "nvme%dc%dn%d", &id, &cntlid, &nsid) == 3)
			return 1;
		if (sscanf(d->d_name, "nvme%dn%d", &id, &nsid) == 2)
			return 1;
	}

	return 0;
}

int scan_ctrls_filter(const struct dirent *d)
{
	int id, nsid;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme")) {
		if (sscanf(d->d_name, "nvme%dn%d", &id, &nsid) == 2)
			return 0;
		if (sscanf(d->d_name, "nvme%dn", &id) == 1)
			return 1;
		return 0;
	}

	return 0;
}

int scan_subsys_filter(const struct dirent *d)
{
	int id;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme-subsys")) {
		if (sscanf(d->d_name, "nvme-subsys%d", &id) != 1)
			return 0;
		return 1;
	}

	return 0;
}

int scan_dev_filter(const struct dirent *d)
{
	int ctrl, ns, part;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme")) {
		if (sscanf(d->d_name, "nvme%dn%dp%d", &ctrl, &ns, &part) == 3)
			return 0;
		if (sscanf(d->d_name, "nvme%dn%d", &ctrl, &ns) == 2)
			return ctrl == current_index;
	}
	return 0;
}
