#include <linux/types.h>
#include <stdbool.h>

/*
 * nvme_status_type - It gives SCT(Status Code Type) in status field in
 *                    completion queue entry.
 * @status: status field located at DW3 in completion queue entry
 */
static inline __u8 nvme_status_type(__u16 status)
{
	return (status & 0x700) >> 8;
}

__u8 nvme_status_to_errno(int status, bool fabrics);
