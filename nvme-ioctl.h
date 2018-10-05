#ifndef _NVME_LIB_H
#define _NVME_LIB_H

#include <linux/types.h>
#include <stdbool.h>
#include "linux/nvme_ioctl.h"
#include "nvme.h"

int nvme_get_nsid(int fd);

/* Generic passthrough */
int nvme_submit_passthru(int fd, unsigned long ioctl_cmd,
			 struct nvme_passthru_cmd *cmd);

int nvme_passthru(int fd, unsigned long ioctl_cmd, __u8 opcode, __u8 flags,
		  __u16 rsvd, __u32 nsid, __u32 cdw2, __u32 cdw3,
		  __u32 cdw10, __u32 cdw11, __u32 cdw12,
		  __u32 cdw13, __u32 cdw14, __u32 cdw15,
		  __u32 data_len, void *data, __u32 metadata_len,
		  void *metadata, __u32 timeout_ms, __u32 *result);

/* NVME_SUBMIT_IO */
int nvme_io(int fd, __u8 opcode, __u64 slba, __u16 nblocks, __u16 control,
	      __u32 dsmgmt, __u32 reftag, __u16 apptag,
	      __u16 appmask, void *data, void *metadata);

int nvme_read(int fd, __u64 slba, __u16 nblocks, __u16 control,
	      __u32 dsmgmt, __u32 reftag, __u16 apptag,
	      __u16 appmask, void *data, void *metadata);

int nvme_write(int fd, __u64 slba, __u16 nblocks, __u16 control,
	       __u32 dsmgmt, __u32 reftag, __u16 apptag,
	       __u16 appmask, void *data, void *metadata);

int nvme_compare(int fd, __u64 slba, __u16 nblocks, __u16 control,
		 __u32 dsmgmt, __u32 reftag, __u16 apptag,
		 __u16 appmask, void *data, void *metadata);

/* NVME_IO_CMD */
int nvme_passthru_io(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
		     __u32 nsid, __u32 cdw2, __u32 cdw3,
		     __u32 cdw10, __u32 cdw11, __u32 cdw12,
		     __u32 cdw13, __u32 cdw14, __u32 cdw15,
		     __u32 data_len, void *data, __u32 metadata_len,
		     void *metadata, __u32 timeout);

int nvme_write_zeros(int fd, __u32 nsid, __u64 slba, __u16 nlb,
		     __u16 control, __u32 reftag, __u16 apptag, __u16 appmask);

int nvme_write_uncorrectable(int fd, __u32 nsid, __u64 slba, __u16 nlb);

int nvme_flush(int fd, __u32 nsid);

int nvme_dsm(int fd, __u32 nsid, __u32 cdw11, struct nvme_dsm_range *dsm,
	     __u16 nr_ranges);
struct nvme_dsm_range *nvme_setup_dsm_range(__u32 *ctx_attrs,
					    __u32 *llbas, __u64 *slbas,
					    __u16 nr_ranges);

int nvme_resv_acquire(int fd, __u32 nsid, __u8 rtype, __u8 racqa,
		      bool iekey, __u64 crkey, __u64 nrkey);
int nvme_resv_register(int fd, __u32 nsid, __u8 rrega, __u8 cptpl,
		       bool iekey, __u64 crkey, __u64 nrkey);
int nvme_resv_release(int fd, __u32 nsid, __u8 rtype, __u8 rrela,
		      bool iekey, __u64 crkey);
int nvme_resv_report(int fd, __u32 nsid, __u32 numd, __u32 cdw11, void *data);

int nvme_identify13(int fd, __u32 nsid, __u32 cdw10, __u32 cdw11, void *data);
int nvme_identify(int fd, __u32 nsid, __u32 cdw10, void *data);
int nvme_identify_ctrl(int fd, void *data);
int nvme_identify_ns(int fd, __u32 nsid, bool present, void *data);
int nvme_identify_ns_list(int fd, __u32 nsid, bool all, void *data);
int nvme_identify_ctrl_list(int fd, __u32 nsid, __u16 cntid, void *data);
int nvme_identify_ns_descs(int fd, __u32 nsid, void *data);
int nvme_identify_nvmset(int fd, __u16 nvmset_id, void *data);
int nvme_get_log13(int fd, __u32 nsid, __u8 log_id, __u8 lsp, __u64 lpo,
		   __u16 group_id, bool rae, __u32 data_len, void *data);
int nvme_get_log(int fd, __u32 nsid, __u8 log_id, bool rae,
		 __u32 data_len, void *data);


int nvme_get_telemetry_log(int fd, void *lp, int generate_report,
			   int ctrl_gen, size_t log_page_size, __u64 offset);
int nvme_fw_log(int fd, struct nvme_firmware_log_page *fw_log);
int nvme_changed_ns_list_log(int fd,
		struct nvme_changed_ns_list_log *changed_ns_list_log);
int nvme_error_log(int fd, int entries, struct nvme_error_log_page *err_log);
int nvme_smart_log(int fd, __u32 nsid, struct nvme_smart_log *smart_log);
int nvme_ana_log(int fd, void *ana_log, size_t ana_log_len, int rgo);
int nvme_effects_log(int fd, struct nvme_effects_log_page *effects_log);
int nvme_discovery_log(int fd, struct nvmf_disc_rsp_page_hdr *log, __u32 size);
int nvme_sanitize_log(int fd, struct nvme_sanitize_log_page *sanitize_log);
int nvme_endurance_log(int fd, __u16 group_id,
		       struct nvme_endurance_group_log *endurance_log);

int nvme_feature(int fd, __u8 opcode, __u32 nsid, __u32 cdw10,
		 __u32 cdw11, __u32 cdw12, __u32 data_len, void *data,
		 __u32 *result);
int nvme_set_feature(int fd, __u32 nsid, __u8 fid, __u32 value, __u32 cdw12,
		     bool save, __u32 data_len, void *data, __u32 *result);
int nvme_get_feature(int fd, __u32 nsid, __u8 fid, __u8 sel,
		     __u32 cdw11, __u32 data_len, void *data, __u32 *result);

int nvme_format(int fd, __u32 nsid, __u8 lbaf, __u8 ses, __u8 pi,
		__u8 pil, __u8 ms, __u32 timeout);

int nvme_ns_create(int fd, __u64 nsze, __u64 ncap, __u8 flbas,
		   __u8 dps, __u8 nmic, __u32 *result);
int nvme_ns_delete(int fd, __u32 nsid);

int nvme_ns_attachment(int fd, __u32 nsid, __u16 num_ctrls,
		       __u16 *ctrlist, bool attach);
int nvme_ns_attach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist);
int nvme_ns_detach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

int nvme_fw_download(int fd, __u32 offset, __u32 data_len, void *data);
int nvme_fw_commit(int fd, __u8 slot, __u8 action, __u8 bpid);

int nvme_sec_send(int fd, __u32 nsid, __u8 nssf, __u16 spsp,
		  __u8 secp, __u32 tl, __u32 data_len, void *data, __u32 *result);
int nvme_sec_recv(int fd, __u32 nsid, __u8 nssf, __u16 spsp,
		  __u8 secp, __u32 al, __u32 data_len, void *data, __u32 *result);

int nvme_subsystem_reset(int fd);
int nvme_reset_controller(int fd);
int nvme_ns_rescan(int fd);

int nvme_dir_send(int fd, __u32 nsid, __u16 dspec, __u8 dtype, __u8 doper,
		  __u32 data_len, __u32 dw12, void *data, __u32 *result);
int nvme_dir_recv(int fd, __u32 nsid, __u16 dspec, __u8 dtype, __u8 doper,
		  __u32 data_len, __u32 dw12, void *data, __u32 *result);
int nvme_get_properties(int fd, void **pbar);
int nvme_set_property(int fd, int offset, int value);
int nvme_get_property(int fd, int offset, uint64_t *value);
int nvme_sanitize(int fd, __u8 sanact, __u8 ause, __u8 owpass, __u8 oipbp,
		  __u8 no_dealloc, __u32 ovrpat);
int nvme_self_test_start(int fd, __u32 nsid, __u32 cdw10);
int nvme_self_test_log(int fd, struct nvme_self_test_log *self_test_log);
#endif				/* _NVME_LIB_H */
