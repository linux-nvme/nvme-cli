// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "filters.h"
#include "util.h"
#include "tree.h"
#include "log.h"

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
		return EINPROGRESS;
	case NVME_SC_NS_WRITE_PROTECTED:
	case NVME_SC_NS_NOT_READY:
	case NVME_SC_RESERVATION_CONFLICT:
		return EACCES;
	case NVME_SC_LBA_RANGE:
		return EREMOTEIO;
	case NVME_SC_CAP_EXCEEDED:
		return ENOSPC;
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

__u8 nvme_status_to_errno(int status, bool fabrics)
{
	__u16 sc;

	if (!status)
		return 0;
	if (status < 0)
		return errno;

	sc = nvme_status_code(status);
	switch (nvme_status_code_type(status)) {
	case NVME_SCT_GENERIC:
		return nvme_generic_status_to_errno(sc);
	case NVME_SCT_CMD_SPECIFIC:
		if  (fabrics)
			return nvme_fabrics_status_to_errno(sc);
		return nvme_cmd_specific_status_to_errno(sc);
	default:
		return EIO;
	}
}

static const char * const generic_status[] = {
	[NVME_SC_SUCCESS]			  = "Successful Completion: The command completed without error",
	[NVME_SC_INVALID_OPCODE]		  = "Invalid Command Opcode: A reserved coded value or an unsupported value in the command opcode field",
	[NVME_SC_INVALID_FIELD]			  = "Invalid Field in Command: A reserved coded value or an unsupported value in a defined field",
	[NVME_SC_CMDID_CONFLICT]		  = "Command ID Conflict: The command identifier is already in use",
	[NVME_SC_DATA_XFER_ERROR]		  = "Data Transfer Error: Transferring the data or metadata associated with a command experienced an error",
	[NVME_SC_POWER_LOSS]			  = "Commands Aborted due to Power Loss Notification: Indicates that the command was aborted due to a power loss notification",
	[NVME_SC_INTERNAL]			  = "Internal Error: The command was not completed successfully due to an internal error",
	[NVME_SC_ABORT_REQ]			  = "Command Abort Requested: The command was aborted due to an Abort command",
	[NVME_SC_ABORT_QUEUE]			  = "Command Aborted due to SQ Deletion: The command was aborted due to a Delete I/O Submission Queue",
	[NVME_SC_FUSED_FAIL]			  = "Command Aborted due to Failed Fused Command: The command was aborted due to the other command in a fused operation failing",
	[NVME_SC_FUSED_MISSING]			  = "Command Aborted due to Missing Fused Command: The fused command was aborted due to the adjacent submission queue entry not containing a fused command",
	[NVME_SC_INVALID_NS]			  = "Invalid Namespace or Format: The namespace or the format of that namespace is invalid",
	[NVME_SC_CMD_SEQ_ERROR]			  = "Command Sequence Error: The command was aborted due to a protocol violation in a multi- command sequence",
	[NVME_SC_SGL_INVALID_LAST]		  = "Invalid SGL Segment Descriptor: The command includes an invalid SGL Last Segment or SGL Segment descriptor",
	[NVME_SC_SGL_INVALID_COUNT]		  = "Invalid Number of SGL Descriptors: There is an SGL Last Segment descriptor or an SGL Segment descriptor in a location other than the last descriptor of a segment based on the length indicated",
	[NVME_SC_SGL_INVALID_DATA]		  = "Data SGL Length Invalid: The length of a Data SGL is too short or too long and the controller does not support SGL transfers longer than the amount of data to be transferred",
	[NVME_SC_SGL_INVALID_METADATA]		  = "Metadata SGL Length Invalid: The length of a Metadata SGL is too short or too long and the controller does not support SGL transfers longer than the amount of data to be transferred",
	[NVME_SC_SGL_INVALID_TYPE]		  = "SGL Descriptor Type Invalid: The type of an SGL Descriptor is a type that is not supported by the controller",
	[NVME_SC_CMB_INVALID_USE]		  = "Invalid Use of Controller Memory Buffer: The attempted use of the Controller Memory Buffer is not supported by the controller",
	[NVME_SC_PRP_INVALID_OFFSET]		  = "PRP Offset Invalid: The Offset field for a PRP entry is invalid",
	[NVME_SC_AWU_EXCEEDED]			  = "Atomic Write Unit Exceeded: The length specified exceeds the atomic write unit size",
	[NVME_SC_OP_DENIED]			  = "Operation Denied: The command was denied due to lack of access rights",
	[NVME_SC_SGL_INVALID_OFFSET]		  = "SGL Offset Invalid: The offset specified in a descriptor is invalid",
	[NVME_SC_HOSTID_FORMAT]			  = "Host Identifier Inconsistent Format: The NVM subsystem detected the simultaneous use of 64- bit and 128-bit Host Identifier values on different controllers",
	[NVME_SC_KAT_EXPIRED]			  = "Keep Alive Timer Expired: The Keep Alive Timer expired",
	[NVME_SC_KAT_INVALID]			  = "Keep Alive Timeout Invalid: The Keep Alive Timeout value specified is invalid",
	[NVME_SC_CMD_ABORTED_PREMEPT]		  = "Command Aborted due to Preempt and Abort: The command was aborted due to a Reservation Acquire command",
	[NVME_SC_SANITIZE_FAILED]		  = "Sanitize Failed: The most recent sanitize operation failed and no recovery action has been successfully completed",
	[NVME_SC_SANITIZE_IN_PROGRESS]		  = "Sanitize In Progress: The requested function is prohibited while a sanitize operation is in progress",
	[NVME_SC_SGL_INVALID_GRANULARITY]	  = "SGL Data Block Granularity Invalid: The Address alignment or Length granularity for an SGL Data Block descriptor is invalid",
	[NVME_SC_CMD_IN_CMBQ_NOT_SUPP]		  = "Command Not Supported for Queue in CMB: The controller does not support Submission Queue in the Controller Memory Buffer or Completion Queue in the Controller Memory Buffer",
	[NVME_SC_NS_WRITE_PROTECTED]		  = "Namespace is Write Protected: The command is prohibited while the namespace is write protected",
	[NVME_SC_CMD_INTERRUPTED]		  = "Command Interrupted: Command processing was interrupted and the controller is unable to successfully complete the command",
	[NVME_SC_TRAN_TPORT_ERROR]		  = "Transient Transport Error: A transient transport error was detected",
	[NVME_SC_PROHIBITED_BY_CMD_AND_FEAT]	  = "Command Prohibited by Command and Feature Lockdown: The command was aborted due to command execution being prohibited by the Command and Feature Lockdown",
	[NVME_SC_ADMIN_CMD_MEDIA_NOT_READY]	  = "Admin Command Media Not Ready: The Admin command requires access to media and the media is not ready",
	[NVME_SC_LBA_RANGE]			  = "LBA Out of Range: The command references an LBA that exceeds the size of the namespace",
	[NVME_SC_CAP_EXCEEDED]			  = "Capacity Exceeded: Execution of the command has caused the capacity of the namespace to be exceeded",
	[NVME_SC_NS_NOT_READY]			  = "Namespace Not Ready: The namespace is not ready to be accessed",
	[NVME_SC_RESERVATION_CONFLICT]		  = "Reservation Conflict: The command was aborted due to a conflict with a reservation held on the accessed namespace",
	[NVME_SC_FORMAT_IN_PROGRESS]		  = "Format In Progress: A Format NVM command is in progress on the namespace",
};

static const char * const cmd_spec_status[] = {
	[NVME_SC_CQ_INVALID]			  = "Completion Queue Invalid: The Completion Queue identifier specified in the command does not exist",
	[NVME_SC_QID_INVALID]			  = "Invalid Queue Identifier: The creation of the I/O Completion Queue failed due to an invalid queue identifier specified as part of the command",
	[NVME_SC_QUEUE_SIZE]			  = "Invalid Queue Size: The host attempted to create an I/O Completion Queue with an invalid number of entries",
	[NVME_SC_ABORT_LIMIT]			  = "Abort Command Limit Exceeded: The number of concurrently outstanding Abort commands has exceeded the limit indicated in the Identify Controller data structure",
	[NVME_SC_ABORT_MISSING]			  = "Abort Command Is Missing: The abort command is missing",
	[NVME_SC_ASYNC_LIMIT]			  = "Asynchronous Event Request Limit Exceeded: The number of concurrently outstanding Asynchronous Event Request commands has been exceeded",
	[NVME_SC_FIRMWARE_SLOT]			  = "Invalid Firmware Slot: The firmware slot indicated is invalid or read only",
	[NVME_SC_FIRMWARE_IMAGE]		  = "Invalid Firmware Image: The firmware image specified for activation is invalid and not loaded by the controller",
	[NVME_SC_INVALID_VECTOR]		  = "Invalid Interrupt Vector: The creation of the I/O Completion Queue failed due to an invalid interrupt vector specified as part of the command",
	[NVME_SC_INVALID_LOG_PAGE]		  = "Invalid Log Page: The log page indicated is invalid",
	[NVME_SC_INVALID_FORMAT]		  = "Invalid Format: The LBA Format specified is not supported",
	[NVME_SC_FW_NEEDS_CONV_RESET]		  = "Firmware Activation Requires Conventional Reset: The firmware commit was successful, however, activation of the firmware image requires a conventional reset",
	[NVME_SC_INVALID_QUEUE]			  = "Invalid Queue Deletion: Invalid I/O Completion Queue specified to delete",
	[NVME_SC_FEATURE_NOT_SAVEABLE]		  = "Feature Identifier Not Saveable: The Feature Identifier specified does not support a saveable value",
	[NVME_SC_FEATURE_NOT_CHANGEABLE]	  = "Feature Not Changeable: The Feature Identifier is not able to be changed",
	[NVME_SC_FEATURE_NOT_PER_NS]		  = "Feature Not Namespace Specific: The Feature Identifier specified is not namespace specific",
	[NVME_SC_FW_NEEDS_SUBSYS_RESET]		  = "Firmware Activation Requires NVM Subsystem Reset: The firmware commit was successful, however, activation of the firmware image requires an NVM Subsystem",
	[NVME_SC_FW_NEEDS_RESET]		  = "Firmware Activation Requires Controller Level Reset: The firmware commit was successful; however, the image specified does not support being activated without a reset",
	[NVME_SC_FW_NEEDS_MAX_TIME]		  = "Firmware Activation Requires Maximum Time Violation: The image specified if activated immediately would exceed the Maximum Time for Firmware Activation (MTFA) value reported in Identify Controller",
	[NVME_SC_FW_ACTIVATE_PROHIBITED]	  = "Firmware Activation Prohibited: The image specified is being prohibited from activation by the controller for vendor specific reasons",
	[NVME_SC_OVERLAPPING_RANGE]		  = "Overlapping Range: The downloaded firmware image has overlapping ranges",
	[NVME_SC_NS_INSUFFICIENT_CAP]		  = "Namespace Insufficient Capacity: Creating the namespace requires more free space than is currently available",
	[NVME_SC_NS_ID_UNAVAILABLE]		  = "Namespace Identifier Unavailable: The number of namespaces supported has been exceeded",
	[NVME_SC_NS_ALREADY_ATTACHED]		  = "Namespace Already Attached: The controller is already attached to the namespace specified",
	[NVME_SC_NS_IS_PRIVATE]			  = "Namespace Is Private: The namespace is private and is already attached to one controller",
	[NVME_SC_NS_NOT_ATTACHED]		  = "Namespace Not Attached: The request to detach the controller could not be completed because the controller is not attached to the namespace",
	[NVME_SC_THIN_PROV_NOT_SUPP]		  = "Thin Provisioning Not Supported: Thin provisioning is not supported by the controller",
	[NVME_SC_CTRL_LIST_INVALID]		  = "Controller List Invalid: The controller list provided contains invalid controller ids",
	[NVME_SC_SELF_TEST_IN_PROGRESS]		  = "Device Self-test In Progress: The controller or NVM subsystem already has a device self-test operation in process",
	[NVME_SC_BP_WRITE_PROHIBITED]		  = "Boot Partition Write Prohibited: The command tried to modify a locked Boot Partition",
	[NVME_SC_INVALID_CTRL_ID]		  = "Invalid Controller Identifier: An invalid controller id was specified",
	[NVME_SC_INVALID_SEC_CTRL_STATE]	  = "Invalid Secondary Controller State: The requested secondary controller action is invalid based on the secondary and primary controllers current states",
	[NVME_SC_INVALID_CTRL_RESOURCES]	  = "Invalid Number of Controller Resources: The specified number of Flexible Resources is invalid",
	[NVME_SC_INVALID_RESOURCE_ID]		  = "Invalid Resource Identifier: At least one of the specified resource identifiers was invalid",
	[NVME_SC_PMR_SAN_PROHIBITED]		  = "Sanitize Prohibited While Persistent Memory Region is Enabled",
	[NVME_SC_ANA_GROUP_ID_INVALID]		  = "ANA Group Identifier Invalid: The specified ANA Group Identifier (ANAGRPID) is not supported in the submitted command",
	[NVME_SC_ANA_ATTACH_FAILED]		  = "ANA Attach Failed: The controller is not attached to the namespace as a result of an ANA condition",
	[NVME_SC_INSUFFICIENT_CAP]		  = "Insufficient Capacity: Requested operation requires more free space than is currently available",
	[NVME_SC_NS_ATTACHMENT_LIMIT_EXCEEDED]	  = "Namespace Attachment Limit Exceeded: Attaching the ns to a controller causes max number of ns attachments allowed to be exceeded",
	[NVME_SC_PROHIBIT_CMD_EXEC_NOT_SUPPORTED] = "Prohibition of Command Execution Not Supported",
	[NVME_SC_IOCS_NOT_SUPPORTED]		  = "The I/O command set is not supported",
	[NVME_SC_IOCS_NOT_ENABLED]		  = "The I/O command set is not enabled",
	[NVME_SC_IOCS_COMBINATION_REJECTED]	  = "The I/O command set combination is rejected",
	[NVME_SC_INVALID_IOCS]			  = "The I/O command set is invalid",
	[NVME_SC_ID_UNAVAILABLE]		  = "Identifier Unavailable: The number of Endurance Groups or NVM Sets supported has been exceeded",
};

static const char * const nvm_status[] = {
	[NVME_SC_BAD_ATTRIBUTES]		 = "Conflicting Attributes: The attributes specified in the command are conflicting",
	[NVME_SC_INVALID_PI]			 = "Invalid Protection Information: The command's Protection Information Field settings are invalid for the namespace's Protection Information format",
	[NVME_SC_READ_ONLY]			 = "Attempted Write to Read Only Range: The LBA range specified contains read-only blocks",
	[NVME_SC_CMD_SIZE_LIMIT_EXCEEDED]	 = "Command Size Limit Exceeded",
	[NVME_SC_ZNS_BOUNDARY_ERROR]		 = "Zoned Boundary Error: Invalid Zone Boundary crossing",
	[NVME_SC_ZNS_FULL]			 = "Zone Is Full: The accessed zone is in ZSF:Full state",
	[NVME_SC_ZNS_READ_ONLY]			 = "Zone Is Read Only: The accessed zone is in ZSRO:Read Only state",
	[NVME_SC_ZNS_OFFLINE]			 = "Zone Is Offline: The access zone is in ZSO:Offline state",
	[NVME_SC_ZNS_INVALID_WRITE]		 = "Zone Invalid Write: The write to zone was not at the write pointer offset",
	[NVME_SC_ZNS_TOO_MANY_ACTIVE]		 = "Too Many Active Zones: The controller does not allow additional active zones",
	[NVME_SC_ZNS_TOO_MANY_OPENS]		 = "Too Many Open Zones: The controller does not allow additional open zones",
	[NVME_SC_ZNS_INVAL_TRANSITION]		 = "Invalid Zone State Transition: The request is not a valid zone state transition",
};

static const char * const nvmf_status[] = {
	[NVME_SC_CONNECT_FORMAT]	   = "Incompatible Format: The NVM subsystem does not support the record format specified by the host",
	[NVME_SC_CONNECT_CTRL_BUSY]	   = "Controller Busy: The controller is already associated with a host",
	[NVME_SC_CONNECT_INVALID_PARAM]    = "Connect Invalid Parameters: One or more of the command parameters",
	[NVME_SC_CONNECT_RESTART_DISC]	   = "Connect Restart Discovery: The NVM subsystem requested is not available",
	[NVME_SC_CONNECT_INVALID_HOST]	   = "Connect Invalid Host: The host is not allowed to establish an association to either any controller in the NVM subsystem or the specified controller",
	[NVME_SC_DISCONNECT_INVALID_QTYPE] = "Invalid Queue Type: The command was sent on the wrong queue type",
	[NVME_SC_DISCOVERY_RESTART]	   = "Discover Restart: The snapshot of the records is now invalid or out of date",
	[NVME_SC_AUTH_REQUIRED]		   = "Authentication Required: NVMe in-band authentication is required and the queue has not yet been authenticated",
};

static const char * const media_status[] = {
	[NVME_SC_WRITE_FAULT]		 = "Write Fault: The write data could not be committed to the media",
	[NVME_SC_READ_ERROR]		 = "Unrecovered Read Error: The read data could not be recovered from the media",
	[NVME_SC_GUARD_CHECK]		 = "End-to-end Guard Check Error: The command was aborted due to an end-to-end guard check failure",
	[NVME_SC_APPTAG_CHECK]		 = "End-to-end Application Tag Check Error: The command was aborted due to an end-to-end application tag check failure",
	[NVME_SC_REFTAG_CHECK]		 = "End-to-end Reference Tag Check Error: The command was aborted due to an end-to-end reference tag check failure",
	[NVME_SC_COMPARE_FAILED]	 = "Compare Failure: The command failed due to a miscompare during a Compare command",
	[NVME_SC_ACCESS_DENIED]		 = "Access Denied: Access to the namespace and/or LBA range is denied due to lack of access rights",
	[NVME_SC_UNWRITTEN_BLOCK]	 = "Deallocated or Unwritten Logical Block: The command failed due to an attempt to read from or verify an LBA range containing a deallocated or unwritten logical block",
	[NVME_SC_STORAGE_TAG_CHECK]	 = "End-to-End Storage Tag Check Error: The command was aborted due to an end-to-end storage tag check failure",
};

static const char * const path_status[] = {
	[NVME_SC_ANA_INTERNAL_PATH_ERROR] = "Internal Path Error: An internal error specific to the controller processing the commmand prevented completion",
	[NVME_SC_ANA_PERSISTENT_LOSS]	  = "Asymmetric Access Persistent Loss: The controller is in a persistent loss state with the requested namespace",
	[NVME_SC_ANA_INACCESSIBLE]	  = "Asymmetric Access Inaccessible: The controller is in an inaccessible state with the requested namespace",
	[NVME_SC_ANA_TRANSITION]	  = "Asymmetric Access Transition: The controller is currently transitioning states with the requested namespace",
	[NVME_SC_CTRL_PATH_ERROR]	  = "Controller Pathing Error: A pathing error was detected by the controller",
	[NVME_SC_HOST_PATH_ERROR]	  = "Host Pathing Error: A pathing error was detected by the host",
	[NVME_SC_CMD_ABORTED_BY_HOST]	  = "Command Aborted By Host: The command was aborted as a result of host action",
};

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define ARGSTR(s, i) arg_str(s, ARRAY_SIZE(s), i)

static const char *arg_str(const char * const *strings,
		size_t array_size, size_t idx)
{
	if (idx < array_size && strings[idx])
		return strings[idx];
	return "unrecognized";
}

const char *nvme_status_to_string(int status, bool fabrics)
{
	const char *s = "Unknown status";
	__u16 sc, sct;

	if (status < 0)
		return strerror(errno);

	sc = nvme_status_code(status);
	sct = nvme_status_code_type(status);

	switch (sct) {
	case NVME_SCT_GENERIC:
		s = ARGSTR(generic_status, sc);
		break;
	case NVME_SCT_CMD_SPECIFIC:
		if (sc < ARRAY_SIZE(cmd_spec_status))
			s = ARGSTR(cmd_spec_status, sc);
		else if (fabrics)
			s = ARGSTR(nvmf_status, sc);
		else
			s = ARGSTR(nvm_status, sc);
		break;
	case NVME_SCT_MEDIA:
		s = ARGSTR(media_status, sc);
		break;
	case NVME_SCT_PATH:
		s = ARGSTR(path_status, sc);
		break;
	case NVME_SCT_VS:
		s = "Vendor Specific Status";
		break;
	default:
		break;
	}

	return s;
}

static int __nvme_open(const char *name)
{
	char *path;
	int fd, ret;

	ret = asprintf(&path, "%s/%s", "/dev", name);
	if (ret < 0) {
		errno = ENOMEM;
		return -1;
	}

	fd = open(path, O_RDONLY);
	free(path);
	return fd;
}

int nvme_open(const char *name)
{
	int ret, fd, id, ns;
	struct stat stat;
	bool c;

	ret = sscanf(name, "nvme%dn%d", &id, &ns);
	if (ret != 1 && ret != 2) {
		errno = EINVAL;
		return -1;
	}
	c = ret == 1;

	fd = __nvme_open(name);
	if (fd < 0)
		return fd;

	ret = fstat(fd, &stat);
	if (ret < 0)
		goto close_fd;

	if (c) {
		if (!S_ISCHR(stat.st_mode)) {
			errno = EINVAL;
			goto close_fd;
		}
	} else if (!S_ISBLK(stat.st_mode)) {
		errno = EINVAL;
		goto close_fd;
	}

	return fd;

close_fd:
	close(fd);
	return -1;
}

int nvme_fw_download_seq(int fd, __u32 size, __u32 xfer, __u32 offset,
			 void *buf)
{
	int err = 0;

	while (size > 0) {
		xfer = MIN(xfer, size);
		err = nvme_fw_download(fd, offset, xfer, buf);
		if (err)
			break;

		buf += xfer;
		size -= xfer;
		offset += xfer;
	}

	return err;
}

int __nvme_get_log_page(int fd, __u32 nsid, __u8 log_id, bool rae,
			__u32 xfer_len, __u32 data_len, void *data)
{
	__u64 offset = 0, xfer;
	bool retain = true;
	void *ptr = data;
	int ret;

	/*
	 * 4k is the smallest possible transfer unit, so restricting to 4k
	 * avoids having to check the MDTS value of the controller.
	 */
	do {
		xfer = data_len - offset;
		if (xfer > xfer_len)
			xfer  = xfer_len;

		/*
		 * Always retain regardless of the RAE parameter until the very
		 * last portion of this log page so the data remains latched
		 * during the fetch sequence.
		 */
		if (offset + xfer == data_len)
			retain = rae;

		ret = nvme_get_log(fd, log_id, nsid, offset, NVME_LOG_LSP_NONE,
				   NVME_LOG_LSI_NONE, retain, NVME_UUID_NONE,
				   NVME_CSI_NVM, xfer, ptr);
		if (ret)
			return ret;

		offset += xfer;
		ptr += xfer;
	} while (offset < data_len);

	return 0;
}

int nvme_get_log_page(int fd, __u32 nsid, __u8 log_id, bool rae,
		      __u32 data_len, void *data)
{
	return __nvme_get_log_page(fd, nsid, log_id, rae, 4096, data_len, data);
}

static int nvme_get_telemetry_log(int fd, bool create, bool ctrl, bool rae,
				  struct nvme_telemetry_log **buf)
{
	static const __u32 xfer = NVME_LOG_TELEM_BLOCK_SIZE;

	struct nvme_telemetry_log *telem;
	enum nvme_cmd_get_log_lid lid;
	void *log, *tmp;
	__u32 size;
	int err;

	log = malloc(xfer);
	if (!log) {
		errno = ENOMEM;
		return -1;
	}

	if (ctrl) {
		err = nvme_get_log_telemetry_ctrl(fd, true, 0, xfer, log);
		lid = NVME_LOG_LID_TELEMETRY_CTRL;
	} else {
		lid = NVME_LOG_LID_TELEMETRY_HOST;
		if (create)
			err = nvme_get_log_create_telemetry_host(fd, log);
		else
			err = nvme_get_log_telemetry_host(fd, 0, xfer, log);
	}

	if (err)
		goto free;

	telem = log;
	if (ctrl && !telem->ctrlavail) {
		*buf = log;
		return 0;
	}

	/* dalb3 >= dalb2 >= dalb1 */
	size = (le16_to_cpu(telem->dalb3) + 1) * xfer;
	tmp = realloc(log, size);
	if (!tmp) {
		errno = ENOMEM;
		err = -1;
		goto free;
	}
	log = tmp;

	err = nvme_get_log_page(fd, NVME_NSID_NONE, lid, rae, size, (void *)log);
	if (!err) {
		*buf = log;
		return 0;
	}
free:
	free(log);
	return err;
}

int nvme_get_ctrl_telemetry(int fd, bool rae, struct nvme_telemetry_log **log)
{
	return nvme_get_telemetry_log(fd, false, true, rae, log);
}

int nvme_get_host_telemetry(int fd, struct nvme_telemetry_log **log)
{
	return nvme_get_telemetry_log(fd, false, false, false, log);
}

int nvme_get_new_host_telemetry(int fd, struct nvme_telemetry_log **log)
{
	return nvme_get_telemetry_log(fd, true, false, false, log);
}

int nvme_get_lba_status_log(int fd, bool rae, struct nvme_lba_status_log **log)
{
	__u32 size = sizeof(struct nvme_lba_status_log);
	void *buf, *tmp;
	int err;

	buf = malloc(size);
	if (!buf)
		return -1;

	*log = buf;
	err = nvme_get_log_lba_status(fd, true, 0, size, buf);
	if (err)
		goto free;

	size = le32_to_cpu((*log)->lslplen);
	if (!size)
		return 0;

	tmp = realloc(buf, size);
	if (!tmp) {
		err = -1;
		goto free;
	}
	buf = tmp;
	*log = buf;

	err = nvme_get_log_page(fd, NVME_NSID_NONE, NVME_LOG_LID_LBA_STATUS,
				rae, size, buf);
	if (!err)
		return 0;

free:
	*log = NULL;
	free(buf);
	return err;
}

void nvme_init_copy_range(struct nvme_copy_range *copy, __u16 *nlbs,
			  __u64 *slbas, __u32 *eilbrts, __u32 *elbatms,
			  __u32 *elbats, __u16 nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		copy[i].nlb = cpu_to_le16(nlbs[i]);
		copy[i].slba = cpu_to_le64(slbas[i]);
		copy[i].eilbrt = cpu_to_le32(eilbrts[i]);
		copy[i].elbatm = cpu_to_le16(elbatms[i]);
		copy[i].elbat = cpu_to_le16(elbats[i]);
	}
}

void nvme_init_dsm_range(struct nvme_dsm_range *dsm, __u32 *ctx_attrs,
			 __u32 *llbas, __u64 *slbas, __u16 nr_ranges)
{
	int i;

	for (i = 0; i < nr_ranges; i++) {
		dsm[i].cattr = cpu_to_le32(ctx_attrs[i]);
		dsm[i].nlb = cpu_to_le32(llbas[i]);
		dsm[i].slba = cpu_to_le64(slbas[i]);
	}
}

void nvme_init_id_ns(struct nvme_id_ns *ns, __u64 nsze, __u64 ncap, __u8 flbas,
		__u8 dps, __u8 nmic, __u32 anagrpid, __u16 nvmsetid)
{
	memset(ns, 0, sizeof(*ns));
	ns->nsze = cpu_to_le64(nsze);
	ns->ncap = cpu_to_le64(ncap);
	ns->flbas = flbas;
	ns->dps = dps;
	ns->nmic = nmic;
	ns->anagrpid = cpu_to_le32(anagrpid);
	ns->nvmsetid = cpu_to_le16(nvmsetid);
}

void nvme_init_ctrl_list(struct nvme_ctrl_list *cntlist, __u16 num_ctrls,
			  __u16 *ctrlist)
{
	int i;

	cntlist->num = cpu_to_le16(num_ctrls);
	for (i = 0; i < num_ctrls; i++)
		cntlist->identifier[i] = cpu_to_le16(ctrlist[i]);
}

static int nvme_ns_attachment(int fd, __u32 nsid, __u16 num_ctrls,
			      __u16 *ctrlist, bool attach)
{
	enum nvme_ns_attach_sel sel = NVME_NS_ATTACH_SEL_CTRL_DEATTACH;
	struct nvme_ctrl_list cntlist = { 0 };

	if (attach)
		sel = NVME_NS_ATTACH_SEL_CTRL_ATTACH;

	nvme_init_ctrl_list(&cntlist, num_ctrls, ctrlist);
	return nvme_ns_attach(fd, nsid, sel, &cntlist);
}

int nvme_namespace_attach_ctrls(int fd, __u32 nsid, __u16 num_ctrls,
				__u16 *ctrlist)
{
	return nvme_ns_attachment(fd, nsid, num_ctrls, ctrlist, true);
}

int nvme_namespace_detach_ctrls(int fd, __u32 nsid, __u16 num_ctrls,
				__u16 *ctrlist)
{
	return nvme_ns_attachment(fd, nsid, num_ctrls, ctrlist, false);
}

int nvme_get_ana_log_len(int fd, size_t *analen)
{
	struct nvme_id_ctrl ctrl;
	int ret;

	ret = nvme_identify_ctrl(fd, &ctrl);
	if (ret)
		return ret;

	*analen = sizeof(struct nvme_ana_log) +
		le32_to_cpu(ctrl.nanagrpid) * sizeof(struct nvme_ana_group_desc) +
		le32_to_cpu(ctrl.mnan) * sizeof(__le32);
	return 0;
}

int nvme_get_feature_length(int fid, __u32 cdw11, __u32 *len)
{
	switch (fid) {
	case NVME_FEAT_FID_LBA_RANGE:
		*len = sizeof(struct nvme_lba_range_type);
		break;
	case NVME_FEAT_FID_AUTO_PST:
		*len = sizeof(struct nvme_feat_auto_pst);
		break;
	case NVME_FEAT_FID_PLM_CONFIG:
		*len = sizeof(struct nvme_plm_config);
		break;
	case NVME_FEAT_FID_TIMESTAMP:
		*len = sizeof(struct nvme_timestamp);
		break;
	case NVME_FEAT_FID_HOST_BEHAVIOR:
		*len = sizeof(struct nvme_feat_host_behavior);
		break;
	case NVME_FEAT_FID_HOST_ID:
		*len = (cdw11 & 0x1) ? 16 : 8;
		break;
	case NVME_FEAT_FID_ARBITRATION:
	case NVME_FEAT_FID_POWER_MGMT:
	case NVME_FEAT_FID_TEMP_THRESH:
	case NVME_FEAT_FID_ERR_RECOVERY:
	case NVME_FEAT_FID_VOLATILE_WC:
	case NVME_FEAT_FID_NUM_QUEUES:
	case NVME_FEAT_FID_IRQ_COALESCE:
	case NVME_FEAT_FID_IRQ_CONFIG:
	case NVME_FEAT_FID_WRITE_ATOMIC:
	case NVME_FEAT_FID_ASYNC_EVENT:
	case NVME_FEAT_FID_HOST_MEM_BUF:
	case NVME_FEAT_FID_KATO:
	case NVME_FEAT_FID_HCTM:
	case NVME_FEAT_FID_NOPSC:
	case NVME_FEAT_FID_RRL:
	case NVME_FEAT_FID_PLM_WINDOW:
	case NVME_FEAT_FID_LBA_STS_INTERVAL:
	case NVME_FEAT_FID_SANITIZE:
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:
	case NVME_FEAT_FID_SW_PROGRESS:
	case NVME_FEAT_FID_RESV_MASK:
	case NVME_FEAT_FID_RESV_PERSIST:
	case NVME_FEAT_FID_WRITE_PROTECT:
		*len = 0;
		break;
	default:
		errno = EINVAL;
		return -1;
	}
	return 0;
}

int nvme_get_directive_receive_length(enum nvme_directive_dtype dtype,
		enum nvme_directive_receive_doper doper, __u32 *len)
{
	switch (dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
			*len = sizeof(struct nvme_id_directives);
			return 0;
		default:
			errno = EINVAL;
			return -1;
		}
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
			*len = sizeof(struct nvme_streams_directive_params);
			return 0;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
			*len = (128 * 1024) * sizeof(__le16);
			return 0;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
			*len = 0;
			return 0;
		default:
			return -EINVAL;
		}
	default:
		return -EINVAL;
	}
}

static int __nvme_set_attr(const char *path, const char *value)
{
	int ret, fd;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		nvme_msg(LOG_DEBUG, "Failed to open %s: %s\n", path,
			 strerror(errno));
		return -1;
	}
	ret = write(fd, value, strlen(value));
	close(fd);
	return ret;
}

int nvme_set_attr(const char *dir, const char *attr, const char *value)
{
	char *path;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return -1;

	ret = __nvme_set_attr(path, value);
	free(path);
	return ret;
}

static char *__nvme_get_attr(const char *path)
{
	char value[4096] = { 0 };
	int ret, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		nvme_msg(LOG_DEBUG, "Failed to open %s: %s\n", path,
			 strerror(errno));
		return NULL;
	}

	ret = read(fd, value, sizeof(value) - 1);
	close(fd);
	if (ret < 0 || !strlen(value)) {
		return NULL;
	}

	if (value[strlen(value) - 1] == '\n')
		value[strlen(value) - 1] = '\0';
	while (strlen(value) > 0 && value[strlen(value) - 1] == ' ')
		value[strlen(value) - 1] = '\0';

	return strlen(value) ? strdup(value) : NULL;
}

char *nvme_get_attr(const char *dir, const char *attr)
{
	char *path, *value;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return NULL;

	value = __nvme_get_attr(path);
	free(path);
	return value;
}

char *nvme_get_subsys_attr(nvme_subsystem_t s, const char *attr)
{
	return nvme_get_attr(nvme_subsystem_get_sysfs_dir(s), attr);
}

char *nvme_get_ctrl_attr(nvme_ctrl_t c, const char *attr)
{
	return nvme_get_attr(nvme_ctrl_get_sysfs_dir(c), attr);
}

char *nvme_get_ns_attr(nvme_ns_t n, const char *attr)
{
	return nvme_get_attr(nvme_ns_get_sysfs_dir(n), attr);
}

char *nvme_get_path_attr(nvme_path_t p, const char *attr)
{
	return nvme_get_attr(nvme_path_get_sysfs_dir(p), attr);
}
