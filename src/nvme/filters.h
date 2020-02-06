#ifndef _LIBNVME_FILTERS_H
#define _LIBNVME_FILTERS_H

#include <dirent.h>
#include "tree.h"

/**
 * nvme_namespace_filter() -
 */
int nvme_namespace_filter(const struct dirent *d);

/**
 * nvme_paths_filter() -
 */
int nvme_paths_filter(const struct dirent *d);

/**
 * nvme_ctrls_filter() -
 */
int nvme_ctrls_filter(const struct dirent *d);

/**
 * nvme_subsys_filter() -
 */
int nvme_subsys_filter(const struct dirent *d);

/**
 * nvme_scan_subsystems() -
 */
int nvme_scan_subsystems(struct dirent ***subsys);

/**
 * nvme_scan_subsystem_ctrls() -
 */
int nvme_scan_subsystem_ctrls(nvme_subsystem_t s, struct dirent ***ctrls);

/**
 * nvme_scan_subsystem_namespaces() -
 */
int nvme_scan_subsystem_namespaces(nvme_subsystem_t s, struct dirent ***namespaces);

/**
 * nvme_scan_ctrl_namespace_paths() -
 */
int nvme_scan_ctrl_namespace_paths(nvme_ctrl_t c, struct dirent ***namespaces);

/**
 * nvme_scan_ctrl_namespaces() -
 */
int nvme_scan_ctrl_namespaces(nvme_ctrl_t c, struct dirent ***namespaces);

#endif /* _LIBNVME_FILTERS_H */
