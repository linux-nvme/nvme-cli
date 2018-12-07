#include <sys/ioctl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

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

	if (!S_ISBLK(nvme_stat.st_mode)) {
		fprintf(stderr,
			"Error: requesting namespace-id from non-block device\n");
		errno = ENOTBLK;
		return -errno;
	}
	return ioctl(fd, NVME_IOCTL_ID);
}

int nvme_submit_passthru(int fd, unsigned long ioctl_cmd,
			 struct nvme_passthru_cmd *cmd)
{
	return ioctl(fd, ioctl_cmd, cmd);
}

static int nvme_submit_admin_passthru(int fd, struct nvme_passthru_cmd *cmd)
{
	return ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd);
}

static int nvme_submit_io_passthru(int fd, struct nvme_passthru_cmd *cmd)
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

int nvme_read(int fd, __u64 slba, __u16 nblocks, __u16 control, __u32 dsmgmt,
	      __u32 reftag, __u16 apptag, __u16 appmask, void *data,
	      void *metadata)
{
	return nvme_io(fd, nvme_cmd_read, slba, nblocks, control, dsmgmt,
		       reftag, apptag, appmask, data, metadata);
}

int nvme_write(int fd, __u64 slba, __u16 nblocks, __u16 control, __u32 dsmgmt,
	       __u32 reftag, __u16 apptag, __u16 appmask, void *data,
	       void *metadata)
{
	return nvme_io(fd, nvme_cmd_write, slba, nblocks, control, dsmgmt,
		       reftag, apptag, appmask, data, metadata);
}

int nvme_compare(int fd, __u64 slba, __u16 nblocks, __u16 control, __u32 dsmgmt,
		 __u32 reftag, __u16 apptag, __u16 appmask, void *data,
		 void *metadata)
{
	return nvme_io(fd, nvme_cmd_compare, slba, nblocks, control, dsmgmt,
		       reftag, apptag, appmask, data, metadata);
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

struct nvme_dsm_range *nvme_setup_dsm_range(__u32 *ctx_attrs, __u32 *llbas,
					    __u64 *slbas, __u16 nr_ranges)
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
	return nvme_identify(fd, 0, 1, data);
}

int nvme_identify_ns(int fd, __u32 nsid, bool present, void *data)
{
	int cns = present ? NVME_ID_CNS_NS_PRESENT : NVME_ID_CNS_NS;

	return nvme_identify(fd, nsid, cns, data);
}

int nvme_identify_ns_list(int fd, __u32 nsid, bool all, void *data)
{
	int cns = all ? NVME_ID_CNS_NS_PRESENT_LIST : NVME_ID_CNS_NS_ACTIVE_LIST;

	return nvme_identify(fd, nsid, cns, data);
}

int nvme_identify_ctrl_list(int fd, __u32 nsid, __u16 cntid, void *data)
{
	int cns = nsid ? NVME_ID_CNS_CTRL_NS_LIST : NVME_ID_CNS_CTRL_LIST;

	return nvme_identify(fd, nsid, (cntid << 16) | cns, data);
}

int nvme_identify_ns_descs(int fd, __u32 nsid, void *data)
{

	return nvme_identify(fd, nsid, NVME_ID_CNS_NS_DESC_LIST, data);
}

int nvme_identify_nvmset(int fd, __u16 nvmset_id, void *data)
{
	return nvme_identify13(fd, 0, NVME_ID_CNS_NVMSET_LIST, nvmset_id, data);
}

int nvme_get_log13(int fd, __u32 nsid, __u8 log_id, __u8 lsp, __u64 lpo,
                 __u16 lsi, bool rae, __u32 data_len, void *data)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_get_log_page,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t) data,
		.data_len	= data_len,
	};
	__u32 numd = (data_len >> 2) - 1;
	__u16 numdu = numd >> 16, numdl = numd & 0xffff;

	cmd.cdw10 = log_id | (numdl << 16) | (rae ? 1 << 15 : 0);
	if (lsp)
                cmd.cdw10 |= lsp << 8;

	cmd.cdw11 = numdu | (lsi << 16);
	cmd.cdw12 = lpo;
	cmd.cdw13 = (lpo >> 32);

	return nvme_submit_admin_passthru(fd, &cmd);

}

int nvme_get_log(int fd, __u32 nsid, __u8 log_id, bool rae,
		 __u32 data_len, void *data)
{
	void *ptr = data;
	__u32 offset = 0, xfer_len = data_len;
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

		ret = nvme_get_log13(fd, nsid, log_id, NVME_NO_LOG_LSP,
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
			sizeof(*fw_log), fw_log);
}

int nvme_changed_ns_list_log(int fd, struct nvme_changed_ns_list_log *changed_ns_list_log)
{
	return nvme_get_log(fd, 0, NVME_LOG_CHANGED_NS, true,
			sizeof(changed_ns_list_log->log),
			changed_ns_list_log->log);
}

int nvme_error_log(int fd, int entries, struct nvme_error_log_page *err_log)
{
	return nvme_get_log(fd, NVME_NSID_ALL, NVME_LOG_ERROR, false,
			entries * sizeof(*err_log), err_log);
}

int nvme_endurance_log(int fd, __u16 group_id, struct nvme_endurance_group_log *endurance_log)
{
	return nvme_get_log13(fd, 0, NVME_LOG_ENDURANCE_GROUP, 0, 0, group_id, 0,
			sizeof(*endurance_log), endurance_log);
}

int nvme_smart_log(int fd, __u32 nsid, struct nvme_smart_log *smart_log)
{
	return nvme_get_log(fd, nsid, NVME_LOG_SMART, false,
			sizeof(*smart_log), smart_log);
}

int nvme_ana_log(int fd, void *ana_log, size_t ana_log_len, int rgo)
{
	__u64 lpo = 0;

	return nvme_get_log13(fd, NVME_NSID_ALL, NVME_LOG_ANA, rgo, lpo, 0,
			true, ana_log_len, ana_log);
}

int nvme_self_test_log(int fd, struct nvme_self_test_log *self_test_log)
{
	return nvme_get_log(fd, NVME_NSID_ALL, NVME_LOG_DEVICE_SELF_TEST, false,
		sizeof(*self_test_log), self_test_log);
}

int nvme_effects_log(int fd, struct nvme_effects_log_page *effects_log)
{
	return nvme_get_log(fd, 0, NVME_LOG_CMD_EFFECTS, false,
			sizeof(*effects_log), effects_log);
}

int nvme_discovery_log(int fd, struct nvmf_disc_rsp_page_hdr *log, __u32 size)
{
	return nvme_get_log(fd, 0, NVME_LOG_DISC, false, size, log);
}

int nvme_sanitize_log(int fd, struct nvme_sanitize_log_page *sanitize_log)
{
	return nvme_get_log(fd, 0, NVME_LOG_SANITIZE, false,
			sizeof(*sanitize_log), sanitize_log);
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

static int nvme_property(int fd, __u8 fctype, __le32 off, __le64 *value, __u8 attrib)
{
	int err;
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_fabrics_command,
		.cdw10		= attrib,
		.cdw11		= off,
	};

	if (!value) {
		errno = EINVAL;
		return -errno;
	}

	if (fctype == nvme_fabrics_type_property_get){
		cmd.nsid = nvme_fabrics_type_property_get;
	} else if(fctype == nvme_fabrics_type_property_set) {
		cmd.nsid = nvme_fabrics_type_property_set;
		cmd.cdw12 = *value;
	} else {
		errno = EINVAL;
		return -errno;
	}

	err = nvme_submit_admin_passthru(fd, &cmd);
	if (!err && fctype == nvme_fabrics_type_property_get)
		*value = cpu_to_le64(cmd.result);
	return err;
}

static int get_property_helper(int fd, int offset, void *value, int *advance)
{
	__le64 value64;
	int err = -EINVAL;

	switch (offset) {
	case NVME_REG_CAP:
	case NVME_REG_ASQ:
	case NVME_REG_ACQ:
		*advance = 8;
		break;
	default:
		*advance = 4;
	}

	if (!value)
		return err;

	err = nvme_property(fd, nvme_fabrics_type_property_get,
			cpu_to_le32(offset), &value64, (*advance == 8));

	if (!err) {
		if (*advance == 8)
			*((uint64_t *)value) = le64_to_cpu(value64);
		else
			*((uint32_t *)value) = le32_to_cpu(value64);
	}

	return err;
}

int nvme_get_property(int fd, int offset, uint64_t *value)
{
	int advance;
	return get_property_helper(fd, offset, value, &advance);
}

int nvme_get_properties(int fd, void **pbar)
{
	int offset, advance;
	int err, ret = -EINVAL;
	int size = getpagesize();

	*pbar = malloc(size);
	if (!*pbar) {
		fprintf(stderr, "malloc: %s\n", strerror(errno));
		return -ENOMEM;
	}

	memset(*pbar, 0xff, size);
	for (offset = NVME_REG_CAP; offset <= NVME_REG_CMBSZ; offset += advance) {
		err = get_property_helper(fd, offset, *pbar + offset, &advance);
		if (!err)
			ret = 0;
	}

	return ret;
}

int nvme_set_property(int fd, int offset, int value)
{
	__le64 val = cpu_to_le64(value);
	__le32 off = cpu_to_le32(offset);
	bool is64bit;

	switch (off) {
	case NVME_REG_CAP:
	case NVME_REG_ASQ:
	case NVME_REG_ACQ:
		is64bit = true;
		break;
	default:
		is64bit = false;
	}

	return nvme_property(fd, nvme_fabrics_type_property_set,
			off, &val, is64bit ? 1: 0);
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

int nvme_ns_create(int fd, __u64 nsze, __u64 ncap, __u8 flbas,
		   __u8 dps, __u8 nmic, __u32 *result)
{
	struct nvme_id_ns ns = {
		.nsze		= cpu_to_le64(nsze),
		.ncap		= cpu_to_le64(ncap),
		.flbas		= flbas,
		.dps		= dps,
		.nmic		= nmic,
	};
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_ns_mgmt,
		.addr		= (__u64)(uintptr_t) ((void *)&ns),
		.cdw10		= 0,
		.data_len	= 0x1000,
	};
	int err;

	err = nvme_submit_admin_passthru(fd, &cmd);
	if (!err && result)
		*result = cmd.result;
	return err;
}

int nvme_ns_delete(int fd, __u32 nsid)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_ns_mgmt,
		.nsid		= nsid,
		.cdw10		= 1,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_ns_attachment(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist,
		       bool attach)
{
	int i;
	__u8 buf[0x1000];
	struct nvme_controller_list *cntlist =
					(struct nvme_controller_list *)buf;
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_ns_attach,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t) cntlist,
		.cdw10		= attach ? 0 : 1,
		.data_len	= 0x1000,
	};

	memset(buf, 0, sizeof(buf));
	cntlist->num = cpu_to_le16(num_ctrls);
	for (i = 0; i < num_ctrls; i++)
		cntlist->identifier[i] = cpu_to_le16(ctrlist[i]);

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_ns_attach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist)
{
	return nvme_ns_attachment(fd, nsid, num_ctrls, ctrlist, true);
}

int nvme_ns_detach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist)
{
	return nvme_ns_attachment(fd, nsid, num_ctrls, ctrlist, false);
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
		  __u8 secp, __u32 tl, __u32 data_len, void *data, __u32 *result)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_security_send,
		.addr		= (__u64)(uintptr_t) data,
		.data_len	= data_len,
		.nsid		= nsid,
		.cdw10		= secp << 24 | spsp << 8 | nssf,
		.cdw11		= tl,
	};
	int err;

	err = nvme_submit_admin_passthru(fd, &cmd);
	if (!err && result)
		*result = cmd.result;
	return err;
}

int nvme_sec_recv(int fd, __u32 nsid, __u8 nssf, __u16 spsp,
		  __u8 secp, __u32 al, __u32 data_len, void *data, __u32 *result)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_security_recv,
		.nsid		= nsid,
		.cdw10		= secp << 24 | spsp << 8 | nssf,
		.cdw11		= al,
		.addr		= (__u64)(uintptr_t) data,
		.data_len	= data_len,
	};
	int err;

	err = nvme_submit_admin_passthru(fd, &cmd);
	if (!err && result)
		*result = cmd.result;
	return err;
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

int nvme_self_test_start(int fd, __u32 nsid, __u32 cdw10)
{
	struct nvme_admin_cmd cmd = {
		.opcode = nvme_admin_dev_self_test,
		.nsid = nsid,
		.cdw10 = cdw10,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}
