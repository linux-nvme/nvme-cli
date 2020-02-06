#ifndef _LIBNVME_TREE_H
#define _LIBNVME_TREE_H

#include <stdbool.h>
#include <stddef.h>

#include <sys/types.h>

#include "ioctl.h"
#include "util.h"

typedef struct nvme_ns *nvme_ns_t;
typedef struct nvme_path *nvme_path_t;
typedef struct nvme_ctrl *nvme_ctrl_t;
typedef struct nvme_subsystem *nvme_subsystem_t;
typedef struct nvme_root *nvme_root_t;

/**
 * nvme_first_subsystem() -
 */
nvme_subsystem_t nvme_first_subsystem(nvme_root_t r);

/**
 * nvme_next_subsystem() -
 */
nvme_subsystem_t nvme_next_subsystem(nvme_root_t r, nvme_subsystem_t s);

/**
 * nvme_ctrl_first_ns() -
 */
nvme_ns_t nvme_ctrl_first_ns(nvme_ctrl_t c);

/**
 * nvme_ctrl_next_ns() -
 */
nvme_ns_t nvme_ctrl_next_ns(nvme_ctrl_t c, nvme_ns_t n);

/**
 * nvme_ctrl_first_path() -
 */
nvme_path_t nvme_ctrl_first_path(nvme_ctrl_t c);

/**
 * nvme_ctrl_next_path() -
 */
nvme_path_t nvme_ctrl_next_path(nvme_ctrl_t c, nvme_path_t p);

/**
 * nvme_subsystem_first_ctrl() -
 */
nvme_ctrl_t nvme_subsystem_first_ctrl(nvme_subsystem_t s);

/**
 * nvme_subsystem_next_ctrl() -
 */
nvme_ctrl_t nvme_subsystem_next_ctrl(nvme_subsystem_t s, nvme_ctrl_t c);

/**
 * nvme_subsystem_first_ns() -
 */
nvme_ns_t nvme_subsystem_first_ns(nvme_subsystem_t s);

/**
 * nvme_subsystem_next_ns() -
 */
nvme_ns_t nvme_subsystem_next_ns(nvme_subsystem_t s, nvme_ns_t n);

/**
 * ()
 */
#define nvme_for_each_subsystem_safe(r, s, _s)			\
	for (s = nvme_first_subsystem(r), 			\
             _s = nvme_next_subsystem(r, s); 			\
             s != NULL; 					\
	     s = _s, _s = nvme_next_subsystem(r, s))

/**
 * ()
 */
#define nvme_for_each_subsystem(r, s)				\
	for (s = nvme_first_subsystem(r); s != NULL; 		\
		s = nvme_next_subsystem(r, s))

/**
 * ()
 */
#define nvme_subsystem_for_each_ctrl_safe(s, c, _c)		\
	for (c = nvme_subsystem_first_ctrl(s), 			\
             _c = nvme_subsystem_next_ctrl(s, c); 		\
             c != NULL; 					\
	     c = _c, _c = nvme_subsystem_next_ctrl(s, c))

/**
 * ()
 */
#define nvme_subsystem_for_each_ctrl(s, c)			\
	for (c = nvme_subsystem_first_ctrl(s); c != NULL; 	\
		c = nvme_subsystem_next_ctrl(s, c))

/**
 * ()
 */
#define nvme_ctrl_for_each_ns_safe(c, n, _n)			\
	for (n = nvme_ctrl_first_ns(c), 			\
             _n = nvme_ctrl_next_ns(c, n); 			\
             n != NULL; 					\
	     n = _n, _n = nvme_ctrl_next_ns(c, n))

/**
 * ()
 */
#define nvme_ctrl_for_each_ns(c, n)				\
	for (n = nvme_ctrl_first_ns(c); n != NULL; 		\
		n = nvme_ctrl_next_ns(c, n))

/**
 * ()
 */
#define nvme_ctrl_for_each_path_safe(c, p, _p)			\
	for (p = nvme_ctrl_first_path(c), 			\
             _p = nvme_ctrl_next_path(c, p); 			\
             p != NULL; 					\
	     p = _p, _p = nvme_ctrl_next_path(c, p))

/**
 * ()
 */
#define nvme_ctrl_for_each_path(c, p)				\
	for (p = nvme_ctrl_first_path(c); p != NULL; 		\
		p = nvme_ctrl_next_path(c, p))

/**
 * ()
 */
#define nvme_subsystem_for_each_ns_safe(s, n, _n)		\
	for (n = nvme_subsystem_first_ns(s), 			\
             _n = nvme_subsystem_next_ns(s, n); 		\
             n != NULL; 					\
	     n = _n, _n = nvme_subsystem_next_ns(s, n))

/**
 * ()
 */
#define nvme_subsystem_for_each_ns(s, n)			\
	for (n = nvme_subsystem_first_ns(s); n != NULL; 	\
		n = nvme_subsystem_next_ns(s, n))

/**
 * nvme_ns_get_fd() -
 */
int nvme_ns_get_fd(nvme_ns_t n);

/**
 * nvme_ns_get_nsid() -
 */
int nvme_ns_get_nsid(nvme_ns_t n);

/**
 * nvme_ns_get_lba_size() -
 */
int nvme_ns_get_lba_size(nvme_ns_t n);

/**
 * nvme_ns_get_lba_count() -
 */
uint64_t nvme_ns_get_lba_count(nvme_ns_t n);

/**
 * nvme_ns_get_lba_util() -
 */
uint64_t nvme_ns_get_lba_util(nvme_ns_t n);

/**
 * char () -
 */
const char *nvme_ns_get_sysfs_dir(nvme_ns_t n);

/**
 * char () -
 */
const char *nvme_ns_get_name(nvme_ns_t n);

/**
 * nvme_ns_get_subsystem() -
 */
nvme_subsystem_t nvme_ns_get_subsystem(nvme_ns_t n);

/**
 * nvme_ns_get_ctrl() -
 */
nvme_ctrl_t nvme_ns_get_ctrl(nvme_ns_t n);

/**
 * nvme_ns_read() -
 */
int nvme_ns_read(nvme_ns_t n, void *buf, off_t offset, size_t count);

/**
 * nvme_ns_write() -
 */
int nvme_ns_write(nvme_ns_t n, void *buf, off_t offset, size_t count);

/**
 * nvme_ns_verify() -
 */
int nvme_ns_verify(nvme_ns_t n, off_t offset, size_t count);

/**
 * nvme_ns_compare() -
 */
int nvme_ns_compare(nvme_ns_t n, void *buf, off_t offset, size_t count);

/**
 * nvme_ns_write_zeros() -
 */
int nvme_ns_write_zeros(nvme_ns_t n, off_t offset, size_t count);

/**
 * nvme_ns_write_uncorrectable() -
 */
int nvme_ns_write_uncorrectable(nvme_ns_t n, off_t offset, size_t count);

/**
 * nvme_ns_flush() -
 */
int nvme_ns_flush(nvme_ns_t n);

/**
 * nvme_ns_identify() -
 */
int nvme_ns_identify(nvme_ns_t n, struct nvme_id_ns *ns);

/**
 * char () -
 */
const char *nvme_path_get_name(nvme_path_t p);

/**
 * char () -
 */
const char *nvme_path_get_sysfs_dir(nvme_path_t p);

/**
 * char () -
 */
const char *nvme_path_get_ana_state(nvme_path_t p);

/**
 * nvme_path_get_subsystem() -
 */
nvme_ctrl_t nvme_path_get_subsystem(nvme_path_t p);

/**
 * nvme_path_get_ns() -
 */
nvme_ns_t nvme_path_get_ns(nvme_path_t p);

int nvme_ctrl_get_fd(nvme_ctrl_t c);
/**
 * char () -
 */
const char *nvme_ctrl_get_name(nvme_ctrl_t c);
/**
 * char () -
 */
const char *nvme_ctrl_get_sysfs_dir(nvme_ctrl_t c);
/**
 * char () -
 */
const char *nvme_ctrl_get_address(nvme_ctrl_t c);
/**
 * char () -
 */
const char *nvme_ctrl_get_firmware(nvme_ctrl_t c);
/**
 * char () -
 */
const char *nvme_ctrl_get_model(nvme_ctrl_t c);
/**
 * char () -
 */
const char *nvme_ctrl_get_state(nvme_ctrl_t c);
/**
 * char () -
 */
const char *nvme_ctrl_get_numa_node(nvme_ctrl_t c);
/**
 * char () -
 */
const char *nvme_ctrl_get_queue_count(nvme_ctrl_t c);
/**
 * char () -
 */
const char *nvme_ctrl_get_serial(nvme_ctrl_t c);
/**
 * char () -
 */
const char *nvme_ctrl_get_sqsize(nvme_ctrl_t c);
/**
 * char () -
 */
const char *nvme_ctrl_get_transport(nvme_ctrl_t c);
/**
 * char () -
 */
const char *nvme_ctrl_get_nqn(nvme_ctrl_t c);
/**
 * char () -
 */
const char *nvme_ctrl_get_subsysnqn(nvme_ctrl_t c);
/**
 * nvme_ctrl_get_subsystem() -
 */
nvme_subsystem_t nvme_ctrl_get_subsystem(nvme_ctrl_t c);

/**
 * nvme_ctrl_identify() -
 */
int nvme_ctrl_identify(nvme_ctrl_t c, struct nvme_id_ctrl *id);
/**
 * nvme_ctrl_disconnect() -
 */
int nvme_ctrl_disconnect(nvme_ctrl_t c);
/**
 * nvme_scan_ctrl() -
 */
nvme_ctrl_t nvme_scan_ctrl(const char *name);

/**
 * nvme_free_ctrl() -
 */
void nvme_free_ctrl(struct nvme_ctrl *c);
/**
 * nvme_unlink_ctrl() -
 */
void nvme_unlink_ctrl(struct nvme_ctrl *c);

/**
 * char () -
 */
const char *nvme_subsystem_get_nqn(nvme_subsystem_t s);
/**
 * char () -
 */
const char *nvme_subsystem_get_sysfs_dir(nvme_subsystem_t s);
/**
 * char () -
 */
const char *nvme_subsystem_get_name(nvme_subsystem_t s);

typedef bool (*nvme_scan_filter_t)(nvme_subsystem_t);

/**
 * nvme_scan_filter() -
 */
nvme_root_t nvme_scan_filter(nvme_scan_filter_t f);

/**
 * nvme_scan() -
 */
nvme_root_t nvme_scan();

/**
 * nvme_refresh_topology() -
 */
void nvme_refresh_topology(nvme_root_t r);

/**
 * nvme_reset_topology() -
 */
void nvme_reset_topology(nvme_root_t r);

/**
 * nvme_free_tree() -
 */
void nvme_free_tree(nvme_root_t r);

/**
 * *() -
 */
char *nvme_get_subsys_attr(nvme_subsystem_t s, const char *attr);

/**
 * *() -
 */
char *nvme_get_ctrl_attr(nvme_ctrl_t c, const char *attr);

/**
 * *() -
 */
char *nvme_get_ns_attr(nvme_ns_t n, const char *attr);

/**
 * *() -
 */
char *nvme_get_path_attr(nvme_path_t p, const char *attr);

extern const char *nvme_ctrl_sysfs_dir;
extern const char *nvme_subsys_sysfs_dir;
#endif /* _LIBNVME_TREE_H */
