// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Windows implementation of the ioctl mock.
 *
 * The Linux mock intercepts ioctl() and reads a struct that is already an
 * NVMe passthru command, so checking it against a struct mock_cmd is a plain
 * field comparison. Windows has no passthru ioctl: ioctl-win.c translates
 * each command family into a different Windows structure
 * (STORAGE_PROPERTY_QUERY for identify/get-log/get-features,
 * STORAGE_PROPERTY_SET for set-features, STORAGE_PROTOCOL_COMMAND for
 * vendor-specific passthru, and dedicated firmware/format/sanitize IOCTLs
 * elsewhere).
 *
 * So this mock intercepts DeviceIoControl and translates *back*: it decodes
 * the Windows request into the NVMe fields that request actually carries,
 * then reuses the same struct mock_cmd expectations the Linux tests declare.
 *
 * The reverse mapping is deliberately partial, because the forward mapping is
 * lossy. submit_admin_identify(), for example, forwards only CNS and NSID, so
 * cdw12/cdw13/cdw15 are not present in the Windows request at all and cannot
 * be asserted. Each decoder therefore records which fields it recovered, and
 * check_cmd() compares only those -- a field Windows discards is skipped
 * rather than silently compared against zero, which would turn a real
 * mismatch into a false pass.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <winioctl.h>

#include <libnvme.h>

#include "nvme/private.h"

#include "iat-hook.h"
#include "mock.h"
#include "util.h"

/*
 * Width of STORAGE_PROTOCOL_DATA_SUBVALUE_GET_LOG_PAGE.LogSpecificField, which
 * is narrower than the NVMe LSP field it carries.
 */
#define WIN_LOG_LSP_MASK	0xf

/*
 * Which NVMe fields a given Windows request carries. Anything not flagged
 * was dropped by the forward translation in ioctl-win.c.
 */
enum cmd_field {
	FIELD_OPCODE	= 1 << 0,
	FIELD_NSID	= 1 << 1,
	FIELD_CDW10	= 1 << 2,
	FIELD_CDW11	= 1 << 3,
	FIELD_CDW12	= 1 << 4,
	FIELD_CDW13	= 1 << 5,
	FIELD_CDW14	= 1 << 6,
	FIELD_CDW15	= 1 << 7,
	FIELD_DATA_LEN	= 1 << 8,
	FIELD_IN_DATA	= 1 << 9,
};

/* An NVMe command as recovered from a Windows IOCTL request. */
struct decoded_cmd {
	unsigned int present;	/* bitmask of enum cmd_field */
	uint8_t opcode;
	uint32_t nsid;
	uint32_t cdw10;
	uint32_t cdw11;
	uint32_t cdw12;
	uint32_t cdw13;
	uint32_t cdw14;
	uint32_t cdw15;
	uint32_t data_len;
	const void *in_data;	/* host-to-device payload, if any */

	/*
	 * Which bits of a recovered dword the Windows request really carried.
	 * A dword can be partly present: the Windows field it travels in may be
	 * narrower than the NVMe one, or only some subfields are forwarded at
	 * all. Zero means every bit of the dword survived.
	 */
	uint32_t cdw10_mask;
	uint32_t cdw11_mask;

	/* Where the mock writes device-to-host data and the CQE result. */
	void *out_buf;
	uint32_t out_buf_len;
	DWORD *result;
	bool result_is_64bit;
};

struct mock_cmds {
	const char *name;
	const struct mock_cmd *cmds;
	size_t remaining_cmds;
};

static libnvme_fd_t mock_fd = LIBNVME_INVALID_FD;
static struct mock_cmds mock_admin_cmds = {.name = "admin"};
static struct mock_cmds mock_io_cmds = {.name = "IO"};

/*
 * A typedef rather than a bare function pointer: checkpatch cannot parse the
 * WINAPI calling-convention macro ahead of the '*' and reports inconsistent
 * spacing around it.
 */
typedef BOOL WINAPI device_io_control_fn(HANDLE, DWORD, LPVOID, DWORD, LPVOID,
					 DWORD, LPDWORD, LPOVERLAPPED);

static device_io_control_fn *real_device_io_control;

static void set_mock_cmds(
	struct mock_cmds *mock_cmds, const struct mock_cmd *cmds, size_t len)
{
	mock_cmds->cmds = cmds;
	mock_cmds->remaining_cmds = len;
}

static void mock_cmds_done(const struct mock_cmds *mock_cmds)
{
	size_t unexecuted = 0;

	/*
	 * A command flagged win_no_ioctl is rejected by ioctl-win.c before any
	 * IOCTL is issued, so it legitimately leaves its mock unconsumed. Tests
	 * still declare those mocks, and still assert the resulting error via
	 * mock_err(); only the "was it executed" accounting differs.
	 */
	for (size_t i = 0; i < mock_cmds->remaining_cmds; i++) {
		if (!mock_cmds->cmds[i].win_no_ioctl)
			unexecuted++;
	}

	/* UCRT's printf has no %zu, so widen to a type it does understand. */
	check(!unexecuted, "%lu %s commands not executed",
	      (unsigned long)unexecuted, mock_cmds->name);
}

static void mock_win_install(void);

void set_mock_fd(libnvme_fd_t fd)
{
	static bool installed;

	/*
	 * Hook on first use rather than at static-init time: the IAT slot can
	 * only be rewritten once the loader has bound it. Every test calls
	 * set_mock_fd() before touching libnvme, so this needs no change to
	 * the test bodies shared with Linux.
	 */
	if (!installed) {
		mock_win_install();
		installed = true;
	}

	mock_fd = fd;
}

void set_mock_admin_cmds(const struct mock_cmd *cmds, size_t len)
{
	set_mock_cmds(&mock_admin_cmds, cmds, len);
}

void set_mock_io_cmds(const struct mock_cmd *cmds, size_t len)
{
	set_mock_cmds(&mock_io_cmds, cmds, len);
}

void end_mock_cmds(void)
{
	mock_cmds_done(&mock_admin_cmds);
	mock_cmds_done(&mock_io_cmds);
}

#define check_field(dec, mock, flag, name, fmt) do { \
	if ((dec)->present & FIELD_ ## flag) \
		check((dec)->name == (mock)->name, \
		      "got " #name " " fmt ", expected " fmt, \
		      (dec)->name, (mock)->name); \
} while (0)

/*
 * Like check_field(), but for a dword the Windows request carries only part of.
 * Compares the surviving bits and ignores the rest, so a field the forward
 * translation truncated or dropped is not asserted against a value it could
 * never have held.
 */
#define check_masked_field(dec, mock, flag, name, fmt) do { \
	if ((dec)->present & FIELD_ ## flag) { \
		uint32_t _mask = (dec)->name ## _mask ?: ~0u; \
		check(((dec)->name & _mask) == ((mock)->name & _mask), \
		      "got " #name " " fmt " (mask " fmt "), expected " fmt, \
		      (dec)->name, _mask, (mock)->name & _mask); \
	} \
} while (0)

static void check_cmd(const struct decoded_cmd *dec,
		      const struct mock_cmd *mock)
{
	check_field(dec, mock, OPCODE, opcode, "0x%" PRIx8);
	check_field(dec, mock, NSID, nsid, "0x%" PRIx32);
	check_masked_field(dec, mock, CDW10, cdw10, "0x%" PRIx32);
	check_masked_field(dec, mock, CDW11, cdw11, "0x%" PRIx32);
	check_field(dec, mock, CDW12, cdw12, "0x%" PRIx32);
	check_field(dec, mock, CDW13, cdw13, "0x%" PRIx32);
	check_field(dec, mock, CDW14, cdw14, "0x%" PRIx32);
	check_field(dec, mock, CDW15, cdw15, "0x%" PRIx32);
	check_field(dec, mock, DATA_LEN, data_len, "%" PRIu32);

	if ((dec->present & FIELD_IN_DATA) && mock->in_data)
		cmp(dec->in_data, mock->in_data, dec->data_len,
		    "incorrect data");
}

/*
 * Hand the mock's canned response back the way the Windows request expects
 * it: payload into the request's own buffer, CQE DW0 into the fixed return
 * field.
 */
static void complete_cmd(const struct decoded_cmd *dec,
			 const struct mock_cmd *mock)
{
	if (mock->out_data) {
		uint32_t len = mock->out_data_len ?: dec->out_buf_len;

		check(dec->out_buf,
		      "mock returns data but the request has no output buffer");
		check(len <= dec->out_buf_len,
		      "mock returns %" PRIu32 " bytes into a %" PRIu32
		      " byte buffer", len, dec->out_buf_len);
		memcpy(dec->out_buf, mock->out_data, len);
	}

	if (!dec->result)
		return;

	/*
	 * Only STORAGE_PROTOCOL_COMMAND supports 64 bits of result data. Other
	 * structures use a single DWORD FixedProtocolReturnData field.
	 */
	if (dec->result_is_64bit) {
		/*
		 * The result is carried in two DWORD fields,
		 * FixedProtocolReturnData and FixedProtocolReturnData2, so
		 * write the halves separately rather than with a memcpy the
		 * compiler would flag as overflowing the first field. UCRT64's
		 * winioctl.h predates the second field and still declares it
		 * reserved.
		 */
		dec->result[0] = (DWORD)mock->result;
		dec->result[1] = (DWORD)(mock->result >> 32);
	} else {
		check((uint32_t)mock->result == mock->result,
		      "result %" PRIu64 " does not fit in the 32-bit "
		      "FixedProtocolReturnData field", mock->result);
		*dec->result = (DWORD)mock->result;
	}
}

static void decode_protocol_specific_data(
		struct decoded_cmd *dec,
		PSTORAGE_PROTOCOL_SPECIFIC_DATA data,
		DWORD in_len)
{
	dec->data_len = data->ProtocolDataLength;
	dec->present |= FIELD_DATA_LEN;

	if (data->ProtocolDataOffset && data->ProtocolDataLength) {
		check((BYTE *)data + data->ProtocolDataOffset +
			      data->ProtocolDataLength <= (BYTE *)data + in_len,
		      "protocol data runs past the request buffer");
		dec->out_buf = (BYTE *)data + data->ProtocolDataOffset;
		dec->out_buf_len = data->ProtocolDataLength;
	}

	dec->result = &data->FixedProtocolReturnData;
}

/*
 * IOCTL_STORAGE_QUERY_PROPERTY carries identify, get-log-page and
 * get-features. DataType tells them apart, and each packs its NVMe fields
 * into the ProtocolDataRequest* slots differently -- see the matching
 * submit_admin_* function in ioctl-win.c.
 */
static void decode_query_property(struct decoded_cmd *dec, void *in,
				  DWORD in_len)
{
	PSTORAGE_PROPERTY_QUERY query = (PSTORAGE_PROPERTY_QUERY)in;
	PSTORAGE_PROTOCOL_SPECIFIC_DATA data;

	check(in_len >= FIELD_OFFSET(STORAGE_PROPERTY_QUERY,
				     AdditionalParameters) +
			sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA),
	      "STORAGE_PROPERTY_QUERY buffer too small: %lu", in_len);
	check(query->PropertyId == StorageAdapterProtocolSpecificProperty,
	      "got PropertyId %d, expected AdapterProtocolSpecific",
	      (int)query->PropertyId);

	data = (PSTORAGE_PROTOCOL_SPECIFIC_DATA)query->AdditionalParameters;
	check(data->ProtocolType == ProtocolTypeNvme,
	      "got ProtocolType %d, expected NVMe", (int)data->ProtocolType);

	decode_protocol_specific_data(dec, data, in_len);

	switch (data->DataType) {
	case NVMeDataTypeIdentify:
		/*
		 * submit_admin_identify() forwards CNS (cdw10[7:0]) and the
		 * NSID. CNTID in cdw10[31:16] is dropped, CSI is validated but
		 * never transmitted, and cdw12-15 are dropped entirely.
		 */
		dec->opcode = nvme_admin_identify;
		dec->cdw10 = data->ProtocolDataRequestValue;
		dec->cdw10_mask = NVME_IDENTIFY_CDW10_CNS_MASK <<
					NVME_IDENTIFY_CDW10_CNS_SHIFT;
		dec->nsid = data->ProtocolDataRequestSubValue;
		dec->present |= FIELD_OPCODE | FIELD_NSID | FIELD_CDW10;
		break;

	case NVMeDataTypeLogPage: {
		STORAGE_PROTOCOL_DATA_SUBVALUE_GET_LOG_PAGE sub;
		uint32_t numd;

		/*
		 * submit_admin_get_log_page() scatters cdw10 across three
		 * places: LID goes in the request value, RAE and LSP are
		 * packed into a subvalue, and NUMD is expressed as the
		 * transfer length rather than sent as a field. Reassemble all
		 * of it so the shared expectations still apply.
		 *
		 * NUMD is a zero-based dword count, so a length of 512 bytes
		 * means NUMD == 127.
		 *
		 * LSP does not survive intact: STORAGE_PROTOCOL_DATA_SUBVALUE_
		 * GET_LOG_PAGE.LogSpecificField is 4 bits wide, while the NVMe
		 * field is 7, so its top 3 bits are lost in transit.
		 */
		sub.AsUlong = data->ProtocolDataRequestSubValue4;
		numd = data->ProtocolDataLength / 4;
		numd = numd ? numd - 1 : 0;

		dec->opcode = nvme_admin_get_log_page;
		dec->cdw10 = (data->ProtocolDataRequestValue &
				NVME_LOG_CDW10_LID_MASK) |
			((uint32_t)sub.LogSpecificField <<
				NVME_LOG_CDW10_LSP_SHIFT) |
			((uint32_t)sub.RetainAsynEvent <<
				NVME_LOG_CDW10_RAE_SHIFT) |
			((numd & NVME_LOG_CDW10_NUMDL_MASK) <<
				NVME_LOG_CDW10_NUMDL_SHIFT);
		dec->cdw10_mask = ~(uint32_t)((NVME_LOG_CDW10_LSP_MASK &
						~WIN_LOG_LSP_MASK) <<
					      NVME_LOG_CDW10_LSP_SHIFT);
		dec->cdw11 = (data->ProtocolDataRequestSubValue3 <<
				NVME_LOG_CDW11_LSI_SHIFT) |
			((numd >> 16) & NVME_LOG_CDW11_NUMDU_MASK);
		dec->cdw12 = data->ProtocolDataRequestSubValue;
		dec->cdw13 = data->ProtocolDataRequestSubValue2;
		dec->present |= FIELD_OPCODE | FIELD_CDW10 | FIELD_CDW11 |
				FIELD_CDW12 | FIELD_CDW13;
		break;
	}

	case NVMeDataTypeFeature:
		/* submit_admin_get_features() forwards cdw10 through cdw14. */
		dec->opcode = nvme_admin_get_features;
		dec->cdw10 = data->ProtocolDataRequestValue;
		dec->cdw11 = data->ProtocolDataRequestSubValue;
		dec->cdw12 = data->ProtocolDataRequestSubValue2;
		dec->cdw13 = data->ProtocolDataRequestSubValue3;
		dec->cdw14 = data->ProtocolDataRequestSubValue4;
		dec->present |= FIELD_OPCODE | FIELD_CDW10 | FIELD_CDW11 |
				FIELD_CDW12 | FIELD_CDW13 | FIELD_CDW14;
		/*
		 * Get Features pads a zero-length request up to
		 * GET_FEATURES_DEF_DATA_LEN, so the length seen here is the
		 * driver's choice rather than the caller's.
		 */
		dec->present &= ~FIELD_DATA_LEN;
		break;

	default:
		fail("unexpected STORAGE_QUERY_PROPERTY DataType %d",
		     (int)data->DataType);
	}
}

/* IOCTL_STORAGE_SET_PROPERTY carries set-features. */
static void decode_set_property(struct decoded_cmd *dec, void *in,
				DWORD in_len)
{
	PSTORAGE_PROPERTY_SET set = (PSTORAGE_PROPERTY_SET)in;
	PSTORAGE_PROTOCOL_SPECIFIC_DATA_EXT data;

	check(in_len >= FIELD_OFFSET(STORAGE_PROPERTY_SET,
				     AdditionalParameters) +
			sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA_EXT),
	      "STORAGE_PROPERTY_SET buffer too small: %lu", in_len);

	data = (PSTORAGE_PROTOCOL_SPECIFIC_DATA_EXT)set->AdditionalParameters;
	check(data->ProtocolType == ProtocolTypeNvme,
	      "got ProtocolType %d, expected NVMe", (int)data->ProtocolType);
	check(data->DataType == NVMeDataTypeFeature,
	      "got SET_PROPERTY DataType %d, expected Feature",
	      (int)data->DataType);

	dec->opcode = nvme_admin_set_features;
	dec->cdw10 = data->ProtocolDataValue;
	dec->cdw11 = data->ProtocolDataSubValue;
	dec->cdw12 = data->ProtocolDataSubValue2;
	dec->cdw13 = data->ProtocolDataSubValue3;
	dec->cdw14 = data->ProtocolDataSubValue4;
	dec->cdw15 = data->ProtocolDataSubValue5;
	dec->data_len = data->ProtocolDataLength;
	dec->present |= FIELD_OPCODE | FIELD_CDW10 | FIELD_CDW11 |
			FIELD_CDW12 | FIELD_CDW13 | FIELD_CDW14 |
			FIELD_CDW15 | FIELD_DATA_LEN;

	if (data->ProtocolDataOffset && data->ProtocolDataLength) {
		check((ULONG)data->ProtocolDataOffset +
			      data->ProtocolDataLength <= in_len,
		      "protocol data runs past the request buffer");
		dec->in_data = (BYTE *)data + data->ProtocolDataOffset;
		dec->present |= FIELD_IN_DATA;
	}

	dec->result = &data->FixedProtocolReturnData;
}

/*
 * IOCTL_STORAGE_PROTOCOL_COMMAND is the closest thing Windows has to a
 * passthru: the 64-byte NVMe SQE is forwarded verbatim, so every command
 * field is recoverable here.
 */
static void decode_protocol_command(struct decoded_cmd *dec, void *in,
				    DWORD in_len)
{
	PSTORAGE_PROTOCOL_COMMAND pc = (PSTORAGE_PROTOCOL_COMMAND)in;
	const struct libnvme_passthru_cmd *sqe;

	check(in_len >= FIELD_OFFSET(STORAGE_PROTOCOL_COMMAND, Command) +
			STORAGE_PROTOCOL_COMMAND_LENGTH_NVME,
	      "STORAGE_PROTOCOL_COMMAND buffer too small: %lu", in_len);
	check(pc->ProtocolType == ProtocolTypeNvme,
	      "got ProtocolType %d, expected NVMe", (int)pc->ProtocolType);

	sqe = (const struct libnvme_passthru_cmd *)pc->Command;

	dec->opcode = sqe->opcode;
	dec->nsid = sqe->nsid;
	dec->cdw10 = sqe->cdw10;
	dec->cdw11 = sqe->cdw11;
	dec->cdw12 = sqe->cdw12;
	dec->cdw13 = sqe->cdw13;
	dec->cdw14 = sqe->cdw14;
	dec->cdw15 = sqe->cdw15;
	dec->present |= FIELD_OPCODE | FIELD_NSID | FIELD_CDW10 |
			FIELD_CDW11 | FIELD_CDW12 | FIELD_CDW13 |
			FIELD_CDW14 | FIELD_CDW15;

	if (pc->DataToDeviceTransferLength) {
		dec->data_len = pc->DataToDeviceTransferLength;
		dec->in_data = (BYTE *)in + pc->DataToDeviceBufferOffset;
		dec->present |= FIELD_DATA_LEN | FIELD_IN_DATA;
	} else if (pc->DataFromDeviceTransferLength) {
		dec->data_len = pc->DataFromDeviceTransferLength;
		dec->out_buf = (BYTE *)in + pc->DataFromDeviceBufferOffset;
		dec->out_buf_len = pc->DataFromDeviceTransferLength;
		dec->present |= FIELD_DATA_LEN;
	} else {
		dec->data_len = 0;
		dec->present |= FIELD_DATA_LEN;
	}

	/*
	 * submit_storage_protocol_command() copies sizeof(cmd->result) bytes
	 * out of FixedProtocolReturnData, reading the FixedProtocolReturnData2
	 * that follows it as well, so a full 64-bit result does survive this
	 * path.
	 */
	dec->result = &pc->FixedProtocolReturnData;
	dec->result_is_64bit = true;

	pc->ReturnStatus = STORAGE_PROTOCOL_STATUS_SUCCESS;
}

/*
 * Turn the mock's expected failure into the Windows error that ioctl-win.c
 * maps back to it. get_errno_from_error() is the function being inverted here,
 * along with the two command families that additionally recover an NVMe status
 * from a Win32 error: get_features_status() and get_log_page_status().
 *
 * Anything those functions cannot produce is rejected rather than
 * approximated, because a mistranslated status would make the test assert the
 * wrong thing.
 */
static DWORD win_error_for(int err)
{
	/*
	 * A positive expectation is an NVMe status code, which only reaches
	 * libnvme through the one Win32 error its family special-cases.
	 */
	if (err > 0) {
		/*
		 * Both families build the status with create_nvme_status_code()
		 * and retry=false, which sets DNR.
		 */
		if (err == ((NVME_SCT_GENERIC << NVME_SCT_SHIFT) |
			    NVME_SC_INVALID_FIELD | NVME_SC_DNR))
			return ERROR_IO_DEVICE;
		if (err == ((NVME_SCT_CMD_SPECIFIC << NVME_SCT_SHIFT) |
			    NVME_SC_INVALID_LOG_PAGE | NVME_SC_DNR))
			return ERROR_INVALID_FUNCTION;
		fail("NVMe status 0x%x is not recoverable from any Windows "
		     "error; set .win_err to declare what libnvme returns "
		     "instead", err);
	}

	switch (err) {
	case -EINVAL:
		return ERROR_INVALID_PARAMETER;
	case -ENOSYS:
		return ERROR_CALL_NOT_IMPLEMENTED;
	case -ENOTSUP:
		return ERROR_NOT_SUPPORTED;
	case -ENOMEM:
		return ERROR_INSUFFICIENT_BUFFER;
	case -EIO:
		/*
		 * Not ERROR_IO_DEVICE: get_features_status() converts that one
		 * into an NVMe status instead of an errno. Any error none of
		 * the mappings recognise falls through to EIO in every family,
		 * which is what this needs to mean.
		 */
		return ERROR_GEN_FAILURE;
	default:
		fail("mock error %d has no Windows equivalent; ioctl-win.c "
		     "cannot report it, so set .win_err to declare what "
		     "libnvme returns instead", err);
	}
}

static BOOL WINAPI mock_device_io_control(HANDLE fd, DWORD code,
					  LPVOID in, DWORD in_len,
					  LPVOID out, DWORD out_len,
					  LPDWORD returned,
					  LPOVERLAPPED overlapped)
{
	struct decoded_cmd dec = {};
	struct mock_cmds *mock_cmds;
	const struct mock_cmd *mock_cmd;

	/*
	 * Anything on a handle we weren't told about is real work by another
	 * part of the process -- pass it straight through. This is what keeps
	 * the hook from breaking libnvme's own device enumeration.
	 */
	if (fd != mock_fd)
		return real_device_io_control(fd, code, in, in_len, out,
					      out_len, returned, overlapped);

	switch (code) {
	case IOCTL_STORAGE_QUERY_PROPERTY:
		decode_query_property(&dec, in, in_len);
		break;
	case IOCTL_STORAGE_SET_PROPERTY:
		decode_set_property(&dec, in, in_len);
		break;
	case IOCTL_STORAGE_PROTOCOL_COMMAND:
		decode_protocol_command(&dec, in, in_len);
		break;
	default:
		/*
		 * Read/write/flush reach the driver as SCSI CDBs through
		 * IOCTL_SCSI_PASS_THROUGH_DIRECT, and firmware, format and
		 * sanitize each have their own IOCTL. Decoding those is not
		 * implemented yet, so say so instead of guessing.
		 */
		fail("IOCTL 0x%lX on the mock handle is not decoded yet", code);
	}

	/*
	 * Every family decoded above is an admin command. Windows maps NVMe
	 * IO commands onto SCSI IOCTLs, which land in the default case, so
	 * the IO queue can only be reached by a vendor-specific opcode in the
	 * IO range going through the passthru IOCTL.
	 */
	if (code == IOCTL_STORAGE_PROTOCOL_COMMAND &&
	    dec.opcode >= 0x80 && dec.opcode < 0xC0)
		mock_cmds = &mock_io_cmds;
	else
		mock_cmds = &mock_admin_cmds;

	check(mock_cmds->remaining_cmds, "unexpected %s command",
	      mock_cmds->name);
	mock_cmd = mock_cmds->cmds++;
	mock_cmds->remaining_cmds--;

	check_cmd(&dec, mock_cmd);

	if (mock_cmd->win_no_ioctl)
		fail("unexpected IOCTL for a command expected to be rejected "
		     "before reaching one");

	if (mock_err(mock_cmd)) {
		/*
		 * Report the error the test expects to observe on this
		 * platform, which mock_err() resolves. Where that differs from
		 * mock_cmd->err the difference is real: Windows carries NVMe
		 * status only as a Win32 error, and get_errno_from_error()
		 * recognises just a handful of errnos, so anything else is
		 * flattened. win_error_for() rejects an expectation libnvme
		 * could not have produced, so a missing .win_err is caught here
		 * rather than silently approximated.
		 */
		SetLastError(win_error_for(mock_err(mock_cmd)));
		return FALSE;
	}

	complete_cmd(&dec, mock_cmd);
	if (returned)
		*returned = in_len;

	return TRUE;
}

static void mock_win_install(void)
{
	void *saved = NULL;

	/*
	 * Patch whichever module holds the import thunk. With a shared build
	 * that is libnvme's own DLL; with default_library=static libnvme is
	 * linked into the test executable and the thunk lives there instead.
	 * Try the DLL first and fall back to the executable.
	 */
	HMODULE lib = GetModuleHandleA(LIBNVME_DLL_NAME);

	if (lib && iat_patch(lib, "DeviceIoControl",
			     (void *)mock_device_io_control, &saved))
		goto patched;

	lib = GetModuleHandleA(NULL);
	check(lib, "cannot get a handle to the test executable: %lu",
	      GetLastError());
	check(iat_patch(lib, "DeviceIoControl",
			(void *)mock_device_io_control, &saved),
	      "DeviceIoControl is not imported by " LIBNVME_DLL_NAME
	      " or by the test executable");

patched:
	real_device_io_control = saved;
	check(real_device_io_control, "no original DeviceIoControl saved");
}
