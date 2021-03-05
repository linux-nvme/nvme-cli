#include <assert.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>

#include <getopt.h>
#include <fcntl.h>
#include <inttypes.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

#include "nvme-ioctl.h"

static int nvme_verify_chr(int fd)
{
	static struct stat nvme_stat;
	int err = fstat(fd, &nvme_stat);

	if (err < 0) {
		perror("fstat");
		return errno;
	}
	if (!S_ISCHR(nvme_stat.st_mode)) {
		fprintf(stderr,
			"Error: requesting reset on non-controller handle\n");
		return ENOTBLK;
	}
	return 0;
}

int nvme_subsystem_reset(int fd)
{
	int ret;

	ret = nvme_verify_chr(fd);
	if (ret)
		return ret;
	return ioctl(fd, NVME_IOCTL_SUBSYS_RESET);
}

int nvme_reset_controller(int fd)
{
	int ret;

	ret = nvme_verify_chr(fd);
	if (ret)
		return ret;
	return ioctl(fd, NVME_IOCTL_RESET);
}

int nvme_ns_rescan(int fd)
{
	int ret;

	ret = nvme_verify_chr(fd);
	if (ret)
		return ret;
	return ioctl(fd, NVME_IOCTL_RESCAN);
}

int nvme_get_nsid(int fd)
{
	static struct stat nvme_stat;
	int err = fstat(fd, &nvme_stat);

	if (err < 0)
		return -errno;

	return ioctl(fd, NVME_IOCTL_ID);
}

int nvme_submit_passthru(int fd, unsigned long ioctl_cmd,
			 struct nvme_passthru_cmd *cmd)
{
	return ioctl(fd, ioctl_cmd, cmd);
}

int nvme_submit_admin_passthru(int fd, struct nvme_passthru_cmd *cmd)
{
	return ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd);
}

int nvme_submit_io_passthru(int fd, struct nvme_passthru_cmd *cmd)
{
	return ioctl(fd, NVME_IOCTL_IO_CMD, cmd);
}

int nvme_passthru(int fd, unsigned long ioctl_cmd, __u8 opcode,
		  __u8 flags, __u16 rsvd,
		  __u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11,
		  __u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15,
		  __u32 data_len, void *data, __u32 metadata_len,
		  void *metadata, __u32 timeout_ms, __u32 *result)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= opcode,
		.flags		= flags,
		.rsvd1		= rsvd,
		.nsid		= nsid,
		.cdw2		= cdw2,
		.cdw3		= cdw3,
		.metadata	= (__u64)(uintptr_t) metadata,
		.addr		= (__u64)(uintptr_t) data,
		.metadata_len	= metadata_len,
		.data_len	= data_len,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw13		= cdw13,
		.cdw14		= cdw14,
		.cdw15		= cdw15,
		.timeout_ms	= timeout_ms,
		.result		= 0,
	};
	int err;

	err = nvme_submit_passthru(fd, ioctl_cmd, &cmd);
	if (!err && result)
		*result = cmd.result;
	return err;
}

int nvme_io(int fd, __u8 opcode, __u64 slba, __u16 nblocks, __u16 control,
	    __u32 dsmgmt, __u32 reftag, __u16 apptag, __u16 appmask, void *data,
	    void *metadata)
{
	struct nvme_user_io io = {
		.opcode		= opcode,
		.flags		= 0,
		.control	= control,
		.nblocks	= nblocks,
		.rsvd		= 0,
		.metadata	= (__u64)(uintptr_t) metadata,
		.addr		= (__u64)(uintptr_t) data,
		.slba		= slba,
		.dsmgmt		= dsmgmt,
		.reftag		= reftag,
		.appmask	= appmask,
		.apptag		= apptag,
	};
	return ioctl(fd, NVME_IOCTL_SUBMIT_IO, &io);
}

int nvme_verify(int fd, __u32 nsid, __u64 slba, __u16 nblocks,
		__u16 control, __u32 reftag, __u16 apptag, __u16 appmask)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_verify,
		.nsid		= nsid,
		.cdw10		= slba & 0xffffffff,
		.cdw11		= slba >> 32,
		.cdw12		= nblocks | (control << 16),
		.cdw14		= reftag,
		.cdw15		= apptag | (appmask << 16),
	};

	return nvme_submit_io_passthru(fd, &cmd);
}

int nvme_passthru_io(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
		     __u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10,
		     __u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14,
		     __u32 cdw15, __u32 data_len, void *data,
		     __u32 metadata_len, void *metadata, __u32 timeout_ms)
{
	return nvme_passthru(fd, NVME_IOCTL_IO_CMD, opcode, flags, rsvd, nsid,
			     cdw2, cdw3, cdw10, cdw11, cdw12, cdw13, cdw14,
			     cdw15, data_len, data, metadata_len, metadata,
			     timeout_ms, NULL);
}

int nvme_write_zeros(int fd, __u32 nsid, __u64 slba, __u16 nlb,
		     __u16 control, __u32 reftag, __u16 apptag, __u16 appmask)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_write_zeroes,
		.nsid		= nsid,
		.cdw10		= slba & 0xffffffff,
		.cdw11		= slba >> 32,
		.cdw12		= nlb | (control << 16),
		.cdw14		= reftag,
		.cdw15		= apptag | (appmask << 16),
	};

	return nvme_submit_io_passthru(fd, &cmd);
}

int nvme_write_uncorrectable(int fd, __u32 nsid, __u64 slba, __u16 nlb)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_write_uncor,
		.nsid		= nsid,
		.cdw10		= slba & 0xffffffff,
		.cdw11		= slba >> 32,
		.cdw12		= nlb,
	};

	return nvme_submit_io_passthru(fd, &cmd);
}

int nvme_flush(int fd, __u32 nsid)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_flush,
		.nsid		= nsid,
	};

	return nvme_submit_io_passthru(fd, &cmd);
}

int nvme_dsm(int fd, __u32 nsid, __u32 cdw11, struct nvme_dsm_range *dsm,
	     __u16 nr_ranges)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_dsm,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t) dsm,
		.data_len	= nr_ranges * sizeof(*dsm),
		.cdw10		= nr_ranges - 1,
		.cdw11		= cdw11,
	};

	return nvme_submit_io_passthru(fd, &cmd);
}

struct nvme_dsm_range *nvme_setup_dsm_range(int *ctx_attrs, int *llbas,
					    unsigned long long *slbas,
					    __u16 nr_ranges)
{
	int i;
	struct nvme_dsm_range *dsm = malloc(nr_ranges * sizeof(*dsm));

	if (!dsm) {
		fprintf(stderr, "malloc: %s\n", strerror(errno));
		return NULL;
	}
	for (i = 0; i < nr_ranges; i++) {
		dsm[i].cattr = cpu_to_le32(ctx_attrs[i]);
		dsm[i].nlb = cpu_to_le32(llbas[i]);
		dsm[i].slba = cpu_to_le64(slbas[i]);
	}
	return dsm;
}

int nvme_copy(int fd, __u32 nsid, struct nvme_copy_range *copy, __u64 sdlba,
		__u16 nr, __u8 prinfor, __u8 prinfow, __u8 dtype, __u16 dspec,
		__u8 format, int lr, int fua, __u32 ilbrt, __u16 lbatm,
		__u16 lbat)
{
	__u32 cdw12 = ((nr - 1) & 0xff) | ((format & 0xf) <<  8) |
		((prinfor & 0xf) << 12) | ((dtype & 0xf) << 20) |
		((prinfow & 0xf) << 26) | ((fua & 0x1) << 30) |
		((lr & 0x1) << 31);

	struct nvme_passthru_cmd cmd = {
		.opcode         = nvme_cmd_copy,
		.nsid           = nsid,
		.addr           = (__u64)(uintptr_t)copy,
		.data_len       = nr * sizeof(*copy),
		.cdw10          = sdlba & 0xffffffff,
		.cdw11          = sdlba >> 32,
		.cdw12          = cdw12,
		.cdw13		= (dspec & 0xffff) << 16,
		.cdw14		= ilbrt,
		.cdw15		= (lbatm << 16) | lbat,
	};

	return nvme_submit_io_passthru(fd, &cmd);
}

struct nvme_copy_range *nvme_setup_copy_range(int *nlbs, unsigned long long *slbas,
		int *eilbrts, int *elbatms, int *elbats, __u16 nr)
{
	struct nvme_copy_range *copy = malloc(nr * sizeof(*copy));
	if (!copy) {
		fprintf(stderr, "malloc: %s\n", strerror(errno));
		return NULL;
	}

	for (int i = 0; i < nr; i++) {
		copy[i].nlb = cpu_to_le16(nlbs[i]);
		copy[i].slba = cpu_to_le64(slbas[i]);
		copy[i].eilbrt = cpu_to_le32(eilbrts[i]);
		copy[i].elbatm = cpu_to_le16(elbatms[i]);
		copy[i].elbat = cpu_to_le16(elbats[i]);
	}

	return copy;
}

int nvme_resv_acquire(int fd, __u32 nsid, __u8 rtype, __u8 racqa,
		      bool iekey, __u64 crkey, __u64 nrkey)
{
	__le64 payload[2] = { cpu_to_le64(crkey), cpu_to_le64(nrkey) };
	__u32 cdw10 = (racqa & 0x7) | (iekey ? 1 << 3 : 0) | rtype << 8;
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_resv_acquire,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.addr		= (__u64)(uintptr_t) (payload),
		.data_len	= sizeof(payload),
	};

	return nvme_submit_io_passthru(fd, &cmd);
}

int nvme_resv_register(int fd, __u32 nsid, __u8 rrega, __u8 cptpl,
		       bool iekey, __u64 crkey, __u64 nrkey)
{
	__le64 payload[2] = { cpu_to_le64(crkey), cpu_to_le64(nrkey) };
	__u32 cdw10 = (rrega & 0x7) | (iekey ? 1 << 3 : 0) | cptpl << 30;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_resv_register,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.addr		= (__u64)(uintptr_t) (payload),
		.data_len	= sizeof(payload),
	};

	return nvme_submit_io_passthru(fd, &cmd);
}

int nvme_resv_release(int fd, __u32 nsid, __u8 rtype, __u8 rrela,
		      bool iekey, __u64 crkey)
{
	__le64 payload[1] = { cpu_to_le64(crkey) };
	__u32 cdw10 = (rrela & 0x7) | (iekey ? 1 << 3 : 0) | rtype << 8;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_resv_release,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.addr		= (__u64)(uintptr_t) (payload),
		.data_len	= sizeof(payload),
	};

	return nvme_submit_io_passthru(fd, &cmd);
}

int nvme_resv_report(int fd, __u32 nsid, __u32 numd, __u32 cdw11, void *data)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_resv_report,
		.nsid		= nsid,
		.cdw10		= numd,
		.cdw11		= cdw11,
		.addr		= (__u64)(uintptr_t) data,
		.data_len	= (numd + 1) << 2,
	};

	return nvme_submit_io_passthru(fd, &cmd);
}

int nvme_identify13(int fd, __u32 nsid, __u32 cdw10, __u32 cdw11, void *data)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_identify,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t) data,
		.data_len	= NVME_IDENTIFY_DATA_SIZE,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_identify(int fd, __u32 nsid, __u32 cdw10, void *data)
{
	return nvme_identify13(fd, nsid, cdw10, 0, data);
}

int nvme_identify_ctrl(int fd, void *data)
{
	memset(data, 0, sizeof(struct nvme_id_ctrl));
	return nvme_identify(fd, 0, 1, data);
}

int nvme_identify_ns(int fd, __u32 nsid, bool present, void *data)
{
	int cns = present ? NVME_ID_CNS_NS_PRESENT : NVME_ID_CNS_NS;

	return nvme_identify(fd, nsid, cns, data);
}

int nvme_identify_ns_list_csi(int fd, __u32 nsid, __u8 csi, bool all, void *data)
{
	int cns;

	if (csi) {
		cns = all ? NVME_ID_CNS_CSI_NS_PRESENT_LIST : NVME_ID_CNS_CSI_NS_ACTIVE_LIST;
	} else {
		cns = all ? NVME_ID_CNS_NS_PRESENT_LIST : NVME_ID_CNS_NS_ACTIVE_LIST;
	}

	return nvme_identify13(fd, nsid, cns, csi << 24, data);
}

int nvme_identify_ns_list(int fd, __u32 nsid, bool all, void *data)
{
	return nvme_identify_ns_list_csi(fd, nsid, 0x0, all, data);
}

int nvme_identify_ctrl_list(int fd, __u32 nsid, __u16 cntid, void *data)
{
	int cns = nsid ? NVME_ID_CNS_CTRL_NS_LIST : NVME_ID_CNS_CTRL_LIST;

	return nvme_identify(fd, nsid, (cntid << 16) | cns, data);
}

int nvme_identify_secondary_ctrl_list(int fd, __u32 nsid, __u16 cntid, void *data)
{
	return nvme_identify(fd, nsid, (cntid << 16) | NVME_ID_CNS_SCNDRY_CTRL_LIST, data);
}

int nvme_identify_ns_descs(int fd, __u32 nsid, void *data)
{

	return nvme_identify(fd, nsid, NVME_ID_CNS_NS_DESC_LIST, data);
}

int nvme_identify_nvmset(int fd, __u16 nvmset_id, void *data)
{
	return nvme_identify13(fd, 0, NVME_ID_CNS_NVMSET_LIST, nvmset_id, data);
}

int nvme_identify_ns_granularity(int fd, void *data)
{
	return nvme_identify13(fd, 0, NVME_ID_CNS_NS_GRANULARITY, 0, data);
}

int nvme_identify_uuid(int fd, void *data)
{
	return nvme_identify(fd, 0, NVME_ID_CNS_UUID_LIST, data);
}

int nvme_identify_ctrl_nvm(int fd, void *data)
{
	return nvme_identify13(fd, 0, NVME_ID_CNS_CSI_ID_CTRL, 0, data);
}

int nvme_zns_identify_ns(int fd, __u32 nsid, void *data)
{
	return nvme_identify13(fd, nsid, NVME_ID_CNS_CSI_ID_NS, 2 << 24, data);
}

int nvme_zns_identify_ctrl(int fd, void *data)
{
	return nvme_identify13(fd, 0, NVME_ID_CNS_CSI_ID_CTRL, 2 << 24, data);
}

int nvme_identify_iocs(int fd, __u16 cntid, void *data)
{
	return nvme_identify(fd, 0, (cntid << 16) | NVME_ID_CNS_CSI, data);
}

int nvme_get_log14(int fd, __u32 nsid, __u8 log_id, __u8 lsp, __u64 lpo,
                 __u16 lsi, bool rae, __u8 uuid_ix, __u32 data_len, void *data)
{
	__u32 numd = (data_len >> 2) - 1;
	__u16 numdu = numd >> 16, numdl = numd & 0xffff;
	__u32 cdw10 = log_id | (numdl << 16) | (rae ? 1 << 15 : 0) | lsp << 8;

	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_get_log_page,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t) data,
		.data_len	= data_len,
		.cdw10		= cdw10,
		.cdw11		= numdu | (lsi << 16),
		.cdw12		= lpo & 0xffffffff,
		.cdw13		= lpo >> 32,
		.cdw14		= uuid_ix,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_get_log13(int fd, __u32 nsid, __u8 log_id, __u8 lsp,
		 __u64 lpo, __u16 lsi, bool rae, __u32 data_len,
		 void *data)
{
	return nvme_get_log14(fd, nsid, log_id, lsp, lpo, lsi, rae, 0,
			      data_len, data);
}

int nvme_get_log(int fd, __u32 nsid, __u8 log_id, bool rae,
		 __u8 lsp, __u32 data_len, void *data)
{
	__u32 offset = 0, xfer_len = data_len;
	void *ptr = data;
	int ret;

	/*
	 * 4k is the smallest possible transfer unit, so by
	 * restricting ourselves for 4k transfers we avoid having
	 * to check the MDTS value of the controller.
	 */
	do {
		xfer_len = data_len - offset;
		if (xfer_len > 4096)
			xfer_len = 4096;

		ret = nvme_get_log13(fd, nsid, log_id, lsp,
				     offset, 0, rae, xfer_len, ptr);
		if (ret)
			return ret;

		offset += xfer_len;
		ptr += xfer_len;
	} while (offset < data_len);

	return 0;
}

int nvme_get_telemetry_log(int fd, void *lp, int generate_report,
			   int ctrl_init, size_t log_page_size, __u64 offset)
{
	if (ctrl_init)
		return nvme_get_log13(fd, NVME_NSID_ALL, NVME_LOG_TELEMETRY_CTRL,
				      NVME_NO_LOG_LSP, offset,
				      0, 1, log_page_size, lp);
	if (generate_report)
		return nvme_get_log13(fd, NVME_NSID_ALL, NVME_LOG_TELEMETRY_HOST,
				      NVME_TELEM_LSP_CREATE, offset,
				      0, 1, log_page_size, lp);
	else
		return nvme_get_log13(fd, NVME_NSID_ALL, NVME_LOG_TELEMETRY_HOST,
				      NVME_NO_LOG_LSP, offset,
				      0, 1, log_page_size, lp);
}

int nvme_fw_log(int fd, struct nvme_firmware_log_page *fw_log)
{
	return nvme_get_log(fd, NVME_NSID_ALL, NVME_LOG_FW_SLOT, true,
			NVME_NO_LOG_LSP, sizeof(*fw_log), fw_log);
}

int nvme_changed_ns_list_log(int fd, struct nvme_changed_ns_list_log *changed_ns_list_log)
{
	return nvme_get_log(fd, 0, NVME_LOG_CHANGED_NS, true,
			NVME_NO_LOG_LSP, sizeof(changed_ns_list_log->log),
			changed_ns_list_log->log);
}

int nvme_error_log(int fd, int entries, struct nvme_error_log_page *err_log)
{
	return nvme_get_log(fd, NVME_NSID_ALL, NVME_LOG_ERROR, false,
			NVME_NO_LOG_LSP, entries * sizeof(*err_log), err_log);
}

int nvme_endurance_log(int fd, __u16 group_id, struct nvme_endurance_group_log *endurance_log)
{
	return nvme_get_log13(fd, 0, NVME_LOG_ENDURANCE_GROUP, 0, 0, group_id, 0,
			sizeof(*endurance_log), endurance_log);
}

int nvme_smart_log(int fd, __u32 nsid, struct nvme_smart_log *smart_log)
{
	return nvme_get_log(fd, nsid, NVME_LOG_SMART, false,
			NVME_NO_LOG_LSP, sizeof(*smart_log), smart_log);
}

int nvme_ana_log(int fd, void *ana_log, size_t ana_log_len, int rgo)
{
	return nvme_get_log13(fd, NVME_NSID_ALL, NVME_LOG_ANA, rgo, 0, 0,
			true, ana_log_len, ana_log);
}

int nvme_self_test_log(int fd, __u32 size, struct nvme_self_test_log *self_test_log)
{
	return nvme_get_log(fd, NVME_NSID_ALL, NVME_LOG_DEVICE_SELF_TEST, false,
		NVME_NO_LOG_LSP, size, self_test_log);
}

int nvme_effects_log(int fd, struct nvme_effects_log_page *effects_log)
{
	return nvme_get_log(fd, NVME_NSID_ALL, NVME_LOG_CMD_EFFECTS, false,
			NVME_NO_LOG_LSP, sizeof(*effects_log), effects_log);
}

int nvme_discovery_log(int fd, struct nvmf_disc_rsp_page_hdr *log, __u32 size)
{
	return nvme_get_log(fd, 0, NVME_LOG_DISC, false, NVME_NO_LOG_LSP, size, log);
}

int nvme_sanitize_log(int fd, struct nvme_sanitize_log_page *sanitize_log)
{
	return nvme_get_log(fd, 0, NVME_LOG_SANITIZE, false,
			NVME_NO_LOG_LSP, sizeof(*sanitize_log), sanitize_log);
}

int nvme_predictable_latency_per_nvmset_log(int fd,
		__u16 nvmset_id,
		struct nvme_predlat_per_nvmset_log_page *plpns_log)
{
	return nvme_get_log13(fd, NVME_NSID_ALL,
			NVME_LOG_PRELAT_PER_NVMSET, 0, 0, nvmset_id,
			false, sizeof(*plpns_log), plpns_log);
}

int nvme_predictable_latency_event_agg_log(int fd,
		void *pea_log, bool rae, __u32 size)
{
	return nvme_get_log(fd, NVME_NSID_ALL,
			NVME_LOG_PRELAT_EVENT_AGG, rae, NVME_NO_LOG_LSP,
			size, pea_log);
}

int nvme_persistent_event_log(int fd, __u8 action, __u32 size,
	void *pevent_log_info)
{
	return nvme_get_log(fd, NVME_NSID_ALL, NVME_LOG_PERSISTENT_EVENT,
			false, action, size, pevent_log_info);
}

int nvme_endurance_group_event_agg_log(int fd,
		void *endurance_log, bool rae, __u32 size)
{
	return nvme_get_log(fd, NVME_NSID_ALL,
			NVME_LOG_ENDURANCE_GROUP_EVENT_AGG, rae, NVME_NO_LOG_LSP,
			size, endurance_log);
}

int nvme_lba_status_log(int fd, void *lba_status, bool rae,
		__u32 size)
{
	return nvme_get_log(fd, NVME_NSID_ALL, NVME_LOG_LBA_STATUS,
		rae, NVME_NO_LOG_LSP, size, lba_status);
}

int nvme_resv_notif_log(int fd, struct nvme_resv_notif_log *resv)
{
	return nvme_get_log(fd, 0, NVME_LOG_RESERVATION, false,
		NVME_NO_LOG_LSP, sizeof(*resv), resv);
}

int nvme_feature(int fd, __u8 opcode, __u32 nsid, __u32 cdw10, __u32 cdw11,
		 __u32 cdw12, __u32 data_len, void *data, __u32 *result)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= opcode,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.addr		= (__u64)(uintptr_t) data,
		.data_len	= data_len,
	};
	int err;

	err = nvme_submit_admin_passthru(fd, &cmd);
	if (!err && result)
		*result = cmd.result;
	return err;
}

int nvme_set_feature(int fd, __u32 nsid, __u8 fid, __u32 value, __u32 cdw12,
		     bool save, __u32 data_len, void *data, __u32 *result)
{
	__u32 cdw10 = fid | (save ? 1 << 31 : 0);

	return nvme_feature(fd, nvme_admin_set_features, nsid, cdw10, value,
			    cdw12, data_len, data, result);
}


int nvme_get_property(int fd, int offset, uint64_t *value)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_fabrics_command,
		.nsid		= nvme_fabrics_type_property_get,
		.cdw10		= is_64bit_reg(offset),
		.cdw11		= offset,
	};
	int err;

	err = nvme_submit_admin_passthru(fd, &cmd);
	if (!err && value)
		*value = cmd.result;
	return err;
}

int nvme_get_properties(int fd, void **pbar)
{
	int offset;
	uint64_t value;
	int err, size = getpagesize();

	*pbar = malloc(size);
	if (!*pbar) {
		fprintf(stderr, "malloc: %s\n", strerror(errno));
		return -ENOMEM;
	}

	memset(*pbar, 0xff, size);
	for (offset = NVME_REG_CAP; offset <= NVME_REG_CMBSZ;) {
		err = nvme_get_property(fd, offset, &value);
		if (err > 0 && (err & 0xff) == NVME_SC_INVALID_FIELD) {
			err = 0;
			value = -1;
		} else if (err) {
			free(*pbar);
			break;
		}
		if (is_64bit_reg(offset)) {
			*(uint64_t *)(*pbar + offset) = value;
			offset += 8;
		} else {
			*(uint32_t *)(*pbar + offset) = value;
			offset += 4;
		}
	}

	return err;
}

int nvme_set_property(int fd, int offset, uint64_t value)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_fabrics_command,
		.nsid		= nvme_fabrics_type_property_set,
		.cdw10		= is_64bit_reg(offset),
		.cdw11		= offset,
		.cdw12		= value & 0xffffffff,
		.cdw13		= value >> 32,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_get_feature(int fd, __u32 nsid, __u8 fid, __u8 sel, __u32 cdw11,
		     __u32 data_len, void *data, __u32 *result)
{
	__u32 cdw10 = fid | sel << 8;

	return nvme_feature(fd, nvme_admin_get_features, nsid, cdw10, cdw11,
			    0, data_len, data, result);
}

int nvme_format(int fd, __u32 nsid, __u8 lbaf, __u8 ses, __u8 pi,
		__u8 pil, __u8 ms, __u32 timeout)
{
	__u32 cdw10 = lbaf | ms << 4 | pi << 5 | pil << 8 | ses << 9;
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_format_nvm,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_ns_create(int fd, __u64 nsze, __u64 ncap, __u8 flbas, __u8 dps,
		__u8 nmic, __u32 anagrpid, __u16 nvmsetid, __u8 csi,
		__u32 timeout, __u32 *result)
{
	struct nvme_id_ns ns = {
		.nsze		= cpu_to_le64(nsze),
		.ncap		= cpu_to_le64(ncap),
		.flbas		= flbas,
		.dps		= dps,
		.nmic		= nmic,
		.anagrpid	= anagrpid,
		.nvmsetid	= nvmsetid,
	};

	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_ns_mgmt,
		.addr		= (__u64)(uintptr_t) ((void *)&ns),
		.cdw10		= 0,
		.cdw11		= csi << 24,
		.data_len	= 0x1000,
		.timeout_ms	= timeout,
	};
	int err;

	err = nvme_submit_admin_passthru(fd, &cmd);
	if (!err && result)
		*result = cmd.result;
	return err;
}

int nvme_ns_delete(int fd, __u32 nsid, __u32 timeout)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_ns_mgmt,
		.nsid		= nsid,
		.cdw10		= 1,
		.timeout_ms	= timeout,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_ns_attachment(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist,
		       bool attach)
{
	struct nvme_controller_list cntlist = {
		.num = cpu_to_le16(num_ctrls),
	};

	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_ns_attach,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t)&cntlist,
		.cdw10		= attach ? 0 : 1,
		.data_len	= 0x1000,
	};
	int i;

	for (i = 0; i < num_ctrls; i++)
		cntlist.identifier[i] = cpu_to_le16(ctrlist[i]);

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_fw_download(int fd, __u32 offset, __u32 data_len, void *data)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_download_fw,
		.addr		= (__u64)(uintptr_t) data,
		.data_len	= data_len,
		.cdw10		= (data_len >> 2) - 1,
		.cdw11		= offset >> 2,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_fw_commit(int fd, __u8 slot, __u8 action, __u8 bpid)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_activate_fw,
		.cdw10		= (bpid << 31) | (action << 3) | slot,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_sec_send(int fd, __u32 nsid, __u8 nssf, __u16 spsp,
		  __u8 secp, __u32 tl, __u32 data_len, void *data)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_security_send,
		.addr		= (__u64)(uintptr_t) data,
		.data_len	= data_len,
		.nsid		= nsid,
		.cdw10		= secp << 24 | spsp << 8 | nssf,
		.cdw11		= tl,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_sec_recv(int fd, __u32 nsid, __u8 nssf, __u16 spsp,
		  __u8 secp, __u32 al, __u32 data_len, void *data)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_security_recv,
		.nsid		= nsid,
		.cdw10		= secp << 24 | spsp << 8 | nssf,
		.cdw11		= al,
		.addr		= (__u64)(uintptr_t) data,
		.data_len	= data_len,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_get_lba_status(int fd, __u32 namespace_id, __u64 slba, __u32 mndw,
		__u8 atype, __u16 rl, void *data)
{
	struct nvme_admin_cmd cmd = {
		.opcode =  nvme_admin_get_lba_status,
		.nsid = namespace_id,
		.addr = (__u64)(uintptr_t) data,
		.data_len = (mndw + 1) * 4,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = mndw,
		.cdw13 = (atype << 24) | rl,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_dir_send(int fd, __u32 nsid, __u16 dspec, __u8 dtype, __u8 doper,
                  __u32 data_len, __u32 dw12, void *data, __u32 *result)
{
        struct nvme_admin_cmd cmd = {
                .opcode         = nvme_admin_directive_send,
                .addr           = (__u64)(uintptr_t) data,
                .data_len       = data_len,
                .nsid           = nsid,
                .cdw10          = data_len? (data_len >> 2) - 1 : 0,
                .cdw11          = dspec << 16 | dtype << 8 | doper,
                .cdw12          = dw12,
        };
        int err;

        err = nvme_submit_admin_passthru(fd, &cmd);
        if (!err && result)
                *result = cmd.result;
        return err;
}

int nvme_dir_recv(int fd, __u32 nsid, __u16 dspec, __u8 dtype, __u8 doper,
                  __u32 data_len, __u32 dw12, void *data, __u32 *result)
{
        struct nvme_admin_cmd cmd = {
                .opcode         = nvme_admin_directive_recv,
                .addr           = (__u64)(uintptr_t) data,
                .data_len       = data_len,
                .nsid           = nsid,
                .cdw10          = data_len? (data_len >> 2) - 1 : 0,
                .cdw11          = dspec << 16 | dtype << 8 | doper,
                .cdw12          = dw12,
        };
        int err;

        err = nvme_submit_admin_passthru(fd, &cmd);
        if (!err && result)
                *result = cmd.result;
        return err;
}

int nvme_sanitize(int fd, __u8 sanact, __u8 ause, __u8 owpass, __u8 oipbp,
		  __u8 no_dealloc, __u32 ovrpat)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_sanitize_nvm,
		.cdw10		= no_dealloc << 9 | oipbp << 8 |
				  owpass << NVME_SANITIZE_OWPASS_SHIFT |
				  ause << 3 | sanact,
		.cdw11		= ovrpat,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_self_test_start(int fd, __u32 nsid, __u8 stc)
{
	struct nvme_admin_cmd cmd = {
		.opcode = nvme_admin_dev_self_test,
		.nsid = nsid,
		.cdw10 = stc,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_virtual_mgmt(int fd, __u32 cdw10, __u32 cdw11, __u32 *result)
{
	struct nvme_admin_cmd cmd = {
		.opcode = nvme_admin_virtual_mgmt,
		.cdw10  = cdw10,
		.cdw11  = cdw11,
	};
	int err;

	err = nvme_submit_admin_passthru(fd, &cmd);
	if (!err && result)
		*result = cmd.result;

	return err;
}

int nvme_zns_mgmt_send(int fd, __u32 nsid, __u64 slba, bool select_all,
		       enum nvme_zns_send_action zsa, __u32 data_len,
		       void *data)
{
	__u32 cdw10 = slba & 0xffffffff;
	__u32 cdw11 = slba >> 32;
	__u32 cdw13 = zsa | (!!select_all) << 8;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_zns_cmd_mgmt_send,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw13		= cdw13,
		.addr		= (__u64)(uintptr_t)data,
		.data_len	= data_len,
	};

	return nvme_submit_io_passthru(fd, &cmd);
}

int nvme_zns_mgmt_recv(int fd, __u32 nsid, __u64 slba,
		       enum nvme_zns_recv_action zra, __u8 zrasf,
		       bool zras_feat, __u32 data_len, void *data)
{
	__u32 cdw10 = slba & 0xffffffff;
	__u32 cdw11 = slba >> 32;
	__u32 cdw12 = (data_len >> 2) - 1;
	__u32 cdw13 = zra | zrasf << 8 | zras_feat << 16;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_zns_cmd_mgmt_recv,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw13		= cdw13,
		.addr		= (__u64)(uintptr_t)data,
		.data_len	= data_len,
	};

	return nvme_submit_io_passthru(fd, &cmd);
}

int nvme_zns_report_zones(int fd, __u32 nsid, __u64 slba, bool extended,
			  enum nvme_zns_report_options opts, bool partial,
			  __u32 data_len, void *data)
{
	enum nvme_zns_recv_action zra;

	if (extended)
		zra = NVME_ZNS_ZRA_EXTENDED_REPORT_ZONES;
	else
		zra = NVME_ZNS_ZRA_REPORT_ZONES;

	return nvme_zns_mgmt_recv(fd, nsid, slba, zra, opts, partial,
		data_len, data);
}

int nvme_zns_append(int fd, __u32 nsid, __u64 zslba, __u16 nlb, __u16 control,
		    __u32 ilbrt, __u16 lbat, __u16 lbatm, __u32 data_len,
		    void *data, __u32 metadata_len, void *metadata,
		    __u64 *result)
{
	__u32 cdw10 = zslba & 0xffffffff;
	__u32 cdw11 = zslba >> 32;
	__u32 cdw12 = nlb | (control << 16);
	__u32 cdw14 = ilbrt;
	__u32 cdw15 = lbat | (lbatm << 16);

	struct nvme_passthru_cmd64 cmd = {
		.opcode		= nvme_zns_cmd_append,
		.nsid		= nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw14		= cdw14,
		.cdw15		= cdw15,
		.metadata	= (__u64)(uintptr_t)metadata,
		.addr		= (__u64)(uintptr_t)data,
		.metadata_len	= metadata_len,
		.data_len	= data_len,
	};

	int err;

	err = ioctl(fd, NVME_IOCTL_IO64_CMD, &cmd);
	if (!err && result)
		*result = cmd.result;
	return err;
}
