#include <linux/types.h>
#include <stdbool.h>
#include <errno.h>

#include "nvme.h"
#include "nvme-status.h"

static inline __u8 nvme_generic_status_to_errno(__u16 status)
{
	switch (status) {
	case NVME_SC_INVALID_OPCODE:
	case NVME_SC_INVALID_FIELD:
	case NVME_SC_INVALID_NS:
	case NVME_SC_SGL_INVALID_LAST:
	case NVME_SC_SGL_INVALID_COUNT:
	case NVME_SC_SGL_INVALID_DATA:
	case NVME_SC_SGL_INVALID_METADATA:
	case NVME_SC_SGL_INVALID_TYPE:
	case NVME_SC_SGL_INVALID_OFFSET:
	case NVME_SC_CMB_INVALID_USE:
	case NVME_SC_PRP_INVALID_OFFSET:
		return EINVAL;
	case NVME_SC_CMDID_CONFLICT:
		return EADDRINUSE;
	case NVME_SC_DATA_XFER_ERROR:
	case NVME_SC_INTERNAL:
	case NVME_SC_SANITIZE_FAILED:
		return EIO;
	case NVME_SC_POWER_LOSS:
	case NVME_SC_ABORT_REQ:
	case NVME_SC_ABORT_QUEUE:
	case NVME_SC_FUSED_FAIL:
	case NVME_SC_FUSED_MISSING:
		return EWOULDBLOCK;
	case NVME_SC_CMD_SEQ_ERROR:
		return EILSEQ;
	case NVME_SC_SANITIZE_IN_PROGRESS:
	case NVME_SC_FORMAT_IN_PROGRESS:
		return EINPROGRESS;
	case NVME_SC_NS_WRITE_PROTECTED:
	case NVME_SC_NS_NOT_READY:
	case NVME_SC_RESERVATION_CONFLICT:
		return EACCES;
	case NVME_SC_LBA_RANGE:
		return EREMOTEIO;
	case NVME_SC_CAP_EXCEEDED:
		return ENOSPC;
	case NVME_SC_OPERATION_DENIED:
		return EPERM;
	}

	return EIO;
}

static inline __u8 nvme_cmd_specific_status_to_errno(__u16 status)
{
	switch (status) {
	case NVME_SC_CQ_INVALID:
	case NVME_SC_QID_INVALID:
	case NVME_SC_QUEUE_SIZE:
	case NVME_SC_FIRMWARE_SLOT:
	case NVME_SC_FIRMWARE_IMAGE:
	case NVME_SC_INVALID_VECTOR:
	case NVME_SC_INVALID_LOG_PAGE:
	case NVME_SC_INVALID_FORMAT:
	case NVME_SC_INVALID_QUEUE:
	case NVME_SC_NS_INSUFFICIENT_CAP:
	case NVME_SC_NS_ID_UNAVAILABLE:
	case NVME_SC_CTRL_LIST_INVALID:
	case NVME_SC_BAD_ATTRIBUTES:
	case NVME_SC_INVALID_PI:
	case NVME_SC_INVALID_CTRL_ID:
	case NVME_SC_INVALID_SECONDARY_CTRL_STATE:
	case NVME_SC_INVALID_NUM_CTRL_RESOURCE:
	case NVME_SC_INVALID_RESOURCE_ID:
	case NVME_SC_ANA_INVALID_GROUP_ID:
		return EINVAL;
	case NVME_SC_ABORT_LIMIT:
	case NVME_SC_ASYNC_LIMIT:
		return EDQUOT;
	case NVME_SC_FW_NEEDS_CONV_RESET:
	case NVME_SC_FW_NEEDS_SUBSYS_RESET:
	case NVME_SC_FW_NEEDS_MAX_TIME:
		return ERESTART;
	case NVME_SC_FEATURE_NOT_SAVEABLE:
	case NVME_SC_FEATURE_NOT_CHANGEABLE:
	case NVME_SC_FEATURE_NOT_PER_NS:
	case NVME_SC_FW_ACTIVATE_PROHIBITED:
	case NVME_SC_NS_IS_PRIVATE:
	case NVME_SC_BP_WRITE_PROHIBITED:
	case NVME_SC_READ_ONLY:
	case NVME_SC_PMR_SAN_PROHIBITED:
		return EPERM;
	case NVME_SC_OVERLAPPING_RANGE:
	case NVME_SC_NS_NOT_ATTACHED:
		return ENOSPC;
	case NVME_SC_NS_ALREADY_ATTACHED:
		return EALREADY;
	case NVME_SC_THIN_PROV_NOT_SUPP:
		return EOPNOTSUPP;
	case NVME_SC_DEVICE_SELF_TEST_IN_PROGRESS:
		return EINPROGRESS;
	}

	return EIO;
}

static inline __u8 nvme_fabrics_status_to_errno(__u16 status)
{
	switch (status) {
	case NVME_SC_CONNECT_FORMAT:
	case NVME_SC_CONNECT_INVALID_PARAM:
		return EINVAL;
	case NVME_SC_CONNECT_CTRL_BUSY:
		return EBUSY;
	case NVME_SC_CONNECT_RESTART_DISC:
		return ERESTART;
	case NVME_SC_CONNECT_INVALID_HOST:
		return ECONNREFUSED;
	case NVME_SC_DISCOVERY_RESTART:
		return EAGAIN;
	case NVME_SC_AUTH_REQUIRED:
		return EPERM;
	}

	return EIO;
}

static inline __u8 nvme_path_status_to_errno(__u16 status)
{
	switch (status) {
	case NVME_SC_INTERNAL_PATH_ERROR:
	case NVME_SC_ANA_PERSISTENT_LOSS:
	case NVME_SC_ANA_INACCESSIBLE:
	case NVME_SC_ANA_TRANSITION:
	case NVME_SC_CTRL_PATHING_ERROR:
	case NVME_SC_HOST_PATHING_ERROR:
	case NVME_SC_HOST_CMD_ABORT:
		return EACCES;
	}

	return EIO;
}

/*
 * nvme_status_to_errno - It converts given status to errno mapped
 * @status: >= 0 for nvme status field in completion queue entry,
 *          < 0 for linux internal errors
 * @fabrics: true if given status is for fabrics
 *
 * Notes: This function will convert a given status to an errno mapped
 */
__u8 nvme_status_to_errno(int status, bool fabrics)
{
	__u8 sct;

	if (!status)
		return 0;

	if (status < 0) {
		if (errno)
			return errno;
		return status;
	}

	/*
	 * The actual status code is enough with masking 0xff, but we need to
	 * cover status code type which is 3bits with 0x7ff.
	 */
	status &= 0x7ff;

	sct = nvme_status_type(status);
	switch (sct) {
	case NVME_SCT_GENERIC:
		return nvme_generic_status_to_errno(status);
	case NVME_SCT_CMD_SPECIFIC:
		if (!fabrics) {
			return nvme_cmd_specific_status_to_errno(status);
		}
		return nvme_fabrics_status_to_errno(status);
	case NVME_SCT_PATH:
		return nvme_path_status_to_errno(status);
	}

	/*
	 * Media, integrity related status, and the others will be mapped to
	 * EIO.
	 */
	return EIO;
}
