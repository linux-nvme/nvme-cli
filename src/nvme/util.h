#ifndef _LIBNVME_UTIL_H
#define _LIBNVME_UTIL_H

#include <stdbool.h>
#include <linux/types.h>

#include "types.h"

/**
 * nvme_status_type() - Returns SCT(Status Code Type) in status field of
 *			the completion queue entry.
 * @status: return value from nvme passthrough commands, which is the nvme
 * 	    status field, located at DW3 in completion queue entry
 */
static inline __u8 nvme_status_type(__u16 status)
{
	return (status & NVME_SCT_MASK) >> 8;
}

/**
 * nvme_status_to_string() -
 */
const char *nvme_status_to_string(int status, bool fabrics);

/*
 * nvme_status_to_errno() - Converts nvme return status to errno
 * @status: >= 0 for nvme status field in completion queue entry,
 *          < 0 for linux internal errors
 * @fabrics: true if given status is for fabrics
 *
 * Notes: This function will convert a given status to an errno
 */
__u8 nvme_status_to_errno(int status, bool fabrics);

/**
 * nvme_fw_download_seq() -
 */
int nvme_fw_download_seq(int fd, __u32 size, __u32 xfer, __u32 offset,
			 void *buf);

/**
 * nvme_get_telemetry_log() -
 */
int nvme_get_telemetry_log(int fd, bool create, bool ctrl, int data_area,
			   void **buf, __u32 *log_size);

/**
 * nvme_setup_id_ns() -
 */
void nvme_setup_id_ns(struct nvme_id_ns *ns, __u64 nsze, __u64 ncap, __u8 flbas,
		__u8 dps, __u8 nmic, __u32 anagrpid, __u16 nvmsetid);

/**
 * nvme_setup_ctrl_list() -
 */
void nvme_setup_ctrl_list(struct nvme_ctrl_list *cntlist, __u16 num_ctrls,
			  __u16 *ctrlist);

/**
 * nvme_dsm_range() - Constructs a data set range structure
 * @dsm:	DSM range array
 * @ctx_attrs:	Array of context attributes
 * @llbas:	Array of length in logical blocks
 * @slbas:	Array of starting logical blocks
 * @nr_ranges:	The size of the dsm arrays
 *
 * Each array must be the same size of size 'nr_ranges'.
 *
 * Return: The nvme command status if a response was received or -errno
 * 	   otherwise.
 */
void nvme_setup_dsm_range(struct nvme_dsm_range *dsm, __u32 *ctx_attrs,
			  __u32 *llbas, __u64 *slbas, __u16 nr_ranges);

/**
 * nvme_get_log_page() -
 */
int nvme_get_log_page(int fd, __u32 nsid, __u8 log_id, bool rae,
		__u32 data_len, void *data);

/**
 * nvme_get_ana_log_len() -
 */
int nvme_get_ana_log_len(int fd, size_t *analen);

/**
 * nvme_namespace_attach_ctrls() - Attach namespace to controller(s)
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to attach
 * @num_ctrls:	Number of controllers in ctrlist
 * @ctrlist:	List of controller IDs to perform the attach action
 *
 * Return: The nvme command status if a response was received or -errno
 * 	   otherwise.
 */
int nvme_namespace_attach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

/**
 * nvme_namespace_detach_ctrls() - Detach namespace from controller(s)
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to detach
 * @num_ctrls:	Number of controllers in ctrlist
 * @ctrlist:	List of controller IDs to perform the detach action
 *
 * Return: The nvme command status if a response was received or -errno
 * 	   otherwise.
 */
int nvme_namespace_detach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

/**
 * nvme_get_feature_length() -
 */
int nvme_get_feature_length(int fid, __u32 cdw11, __u32 *len);

/**
 * nvme_get_directive_receive_length() -
 */
int nvme_get_directive_receive_length(__u8 dtype, __u8 doper, __u32 *len);

/**
 * nvme_open() - Open an nvme controller or namespace device
 * @name:	The basename of the device to open
 *
 * This will look for the handle in /dev/ and validate the name and filetype
 * match linux conventions.
 *
 * Return: A file descriptor for the device on a successful open, or -1 with
 * 	   errno set otherwise.
 */
int nvme_open(const char *name);

int nvme_set_attr(const char *dir, const char *attr, const char *value);
#endif /* _LIBNVME_UTIL_H */
