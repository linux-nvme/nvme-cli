.. _nvme-csi-cmds.h:

**nvme-csi-cmds.h**


NVM Command Set I/O Commands

.. c:function:: void nvme_init_flush (struct libnvme_passthru_cmd *cmd, __u32 nsid)

   Initialize passthru command for Flush command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

**Description**

The Flush command requests that the contents of volatile write cache be made
non-volatile.

Initializes the passthru command buffer for the Flush command.


.. c:function:: void nvme_init_cancel (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u16 sqid, __u16 cid, enum nvme_cancel_acode acode)

   Initialize passthru command for Cancel command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier, or ``NVME_NSID_ALL``

``__u16 sqid``
  Submission Queue Identifier (SQID) that the Cancel command is
  associated with

``__u16 cid``
  Command Identifier (CID) of the command to abort. Ignored if
  **acode** is ``NVME_CANCEL_ACODE_MULTIPLE_CMD``.

``enum nvme_cancel_acode acode``
  Action Code (ACODE), see :c:type:`enum nvme_cancel_acode <nvme_cancel_acode>`

**Description**

The Cancel command requests an abort for specified commands submitted on
the same I/O Submission Queue to which the Cancel command is submitted.
The number of commands eligible for a deferred abort and the number of
commands aborted are returned in the CQE result, see :c:type:`enum
nvme_cancel_cqe_dw0 <nvme_cancel_cqe_dw0>`.

Initializes the passthru command buffer for the Cancel command.


.. c:function:: void nvme_init_io (struct libnvme_passthru_cmd *cmd, __u8 opcode, __u32 nsid, __u64 slba, void *data, __u32 data_len, void *metadata, __u32 metadata_len)

   Initialize passthru command for a generic user I/O command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 opcode``
  Opcode to execute

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``void *data``
  Pointer to user address of the data buffer

``__u32 data_len``
  Length of user buffer, **data**, in bytes

``void *metadata``
  Pointer to user address of the metadata buffer

``__u32 metadata_len``
  Length of user buffer, **metadata**, in bytes

**Description**

Initializes the passthru command buffer for a generic NVM I/O command.

**Note**

If **elbas** is true, the caller must ensure the definition/logic for
nvme_init_set_var_size_tags is available and that the return value from
that function is checked for error.


.. c:function:: void nvme_init_write (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u16 dspec, __u8 dsm, __u8 cev, void *data, __u32 data_len, void *metadata, __u32 metadata_len)

   Initialize passthru command for a user write command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks (0-based)

``__u16 control``
  Upper 16 bits of cdw12

``__u16 dspec``
  Directive specific value

``__u8 dsm``
  Data set management attributes (CETYPE is zero),
  see :c:type:`enum nvme_io_dsm_flags <nvme_io_dsm_flags>`

``__u8 cev``
  Command Extension Value (CETYPE is non-zero)

``void *data``
  Pointer to user address of the data buffer

``__u32 data_len``
  Length of user buffer, **data**, in bytes

``void *metadata``
  Pointer to user address of the metadata buffer

``__u32 metadata_len``
  Length of user buffer, **metadata**, in bytes

**Description**

Initializes the passthru command buffer for the Write command.


.. c:function:: void nvme_init_read (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u8 dsm, __u16 cev, void *data, __u32 data_len, void *metadata, __u32 metadata_len)

   Initialize passthru command for a user read command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks (0-based)

``__u16 control``
  Upper 16 bits of cdw12

``__u8 dsm``
  Data set management attributes (CETYPE is zero),
  see :c:type:`enum nvme_io_dsm_flags <nvme_io_dsm_flags>`

``__u16 cev``
  Command Extension Value (CETYPE is non-zero)

``void *data``
  Pointer to user address of the data buffer

``__u32 data_len``
  Length of user buffer, **data**, in bytes

``void *metadata``
  Pointer to user address of the metadata buffer

``__u32 metadata_len``
  Length of user buffer, **metadata**, in bytes

**Description**

Initializes the passthru command buffer for the Read command.

**Note**

Assumes a macro or separate function exists to translate the combined
NLB/control/prinfo fields into cdw12/cdw13. This transformation assumes
the parameters are used for a generic nvme_init_io wrapper.


.. c:function:: void nvme_init_write_uncorrectable (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u16 dspec)

   Initialize passthru command for a write uncorrectable command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks (0-based)

``__u16 control``
  Upper 16 bits of cdw12

``__u16 dspec``
  Directive specific value

**Description**

Initializes the passthru command buffer for the Write Uncorrectable command.

**Note**

This command transfers no data or metadata.


.. c:function:: void nvme_init_compare (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u8 cev, void *data, __u32 data_len, void *metadata, __u32 metadata_len)

   Initialize passthru command for a user compare command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks (0-based)

``__u16 control``
  Command control flags, see :c:type:`enum nvme_io_control_flags <nvme_io_control_flags>`.

``__u8 cev``
  Command Extension Value (CETYPE is non-zero)

``void *data``
  Pointer to user address of the data buffer

``__u32 data_len``
  Length of user buffer, **data**, in bytes

``void *metadata``
  Pointer to user address of the metadata buffer

``__u32 metadata_len``
  Length of user buffer, **metadata**, in bytes

**Description**

Initializes the passthru command buffer for the Compare command.


.. c:function:: void nvme_init_write_zeros (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u16 dspec, __u8 dsm, __u8 cev)

   Initialize passthru command for a write zeroes command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks (0-based)

``__u16 control``
  Upper 16 bits of cdw12

``__u16 dspec``
  Directive specific value

``__u8 dsm``
  Data set management attributes (CETYPE is zero),
  see :c:type:`enum nvme_io_dsm_flags <nvme_io_dsm_flags>`

``__u8 cev``
  Command Extension Value (CETYPE is non-zero)

**Description**

Initializes the passthru command buffer for the Write Zeroes command.

**Note**

Write Zeroes command does not transfer data or metadata.


.. c:function:: void nvme_init_dsm (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u16 nr, __u8 idr, __u8 idw, __u8 ad, void *data, __u32 len)

   Initialize passthru command for NVMe I/O Data Set Management

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``__u16 nr``
  Number of block ranges in the data set management attributes

``__u8 idr``
  DSM Integral Dataset for Read attribute

``__u8 idw``
  DSM Integral Dataset for Write attribute

``__u8 ad``
  DSM Deallocate attribute

``void *data``
  User space destination address to transfer the data

``__u32 len``
  Length of provided user buffer to hold the log data in bytes


.. c:function:: void nvme_init_verify (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u8 cev, void *data, __u32 data_len, void *metadata, __u32 metadata_len)

   Initialize passthru command for a verify command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks (0-based)

``__u16 control``
  Upper 16 bits of cdw12

``__u8 cev``
  Command Extension Value (CETYPE is non-zero)

``void *data``
  Pointer to user address of the data buffer

``__u32 data_len``
  Length of user buffer, **data**, in bytes

``void *metadata``
  Pointer to user address of the metadata buffer

``__u32 metadata_len``
  Length of user buffer, **metadata**, in bytes

**Description**

Initializes the passthru command buffer for the Verify command.

**Note**

Verify command transfers data or metadata to the controller to perform
the verification but not back to the host.


.. c:function:: void nvme_init_resv_register (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_resv_rrega rrega, bool iekey, bool disnsrs, enum nvme_resv_cptpl cptpl, __u64 crkey, __u64 nrkey, __le64 *payload)

   Initialize passthru command for Reservation Register

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``enum nvme_resv_rrega rrega``
  The registration action, see :c:type:`enum nvme_resv_rrega <nvme_resv_rrega>`

``bool iekey``
  Set to ignore the existing key

``bool disnsrs``
  Disperse Namespace Reservation Support

``enum nvme_resv_cptpl cptpl``
  Change persist through power loss, see :c:type:`enum nvme_resv_cptpl <nvme_resv_cptpl>`

``__u64 crkey``
  The current reservation key associated with the host

``__u64 nrkey``
  The new reservation key to be register if action is register or
  replace

``__le64 *payload``
  Data payload buffer to hold crkey and nrkey

**Description**

Initializes the passthru command buffer for the Reservation Register command.


.. c:function:: void nvme_init_resv_report (struct libnvme_passthru_cmd *cmd, __u32 nsid, bool eds, bool disnsrs, struct nvme_resv_status *report, __u32 len)

   Initialize passthru command for Reservation Report

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``bool eds``
  Request extended Data Structure

``bool disnsrs``
  Disperse Namespace Reservation Support

``struct nvme_resv_status *report``
  The user space destination address to store the reservation
  report buffer

``__u32 len``
  Number of bytes to request transferred with this command

**Description**

Initializes the passthru command buffer for the Reservation Report command.


.. c:function:: void nvme_init_resv_acquire (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_resv_racqa racqa, bool iekey, bool disnsrs, enum nvme_resv_rtype rtype, __u64 crkey, __u64 prkey, __le64 *payload)

   Initialize passthru command for Reservation Acquire

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``enum nvme_resv_racqa racqa``
  The action that is performed by the command,
  see :c:type:`enum nvme_resv_racqa <nvme_resv_racqa>`

``bool iekey``
  Set to ignore the existing key

``bool disnsrs``
  Disperse Namespace Reservation Support

``enum nvme_resv_rtype rtype``
  The type of reservation to be create, see :c:type:`enum nvme_resv_rtype <nvme_resv_rtype>`

``__u64 crkey``
  The current reservation key associated with the host

``__u64 prkey``
  Preempt Reservation Key

``__le64 *payload``
  Data payload buffer to hold crkey and prkey

**Description**

Initializes the passthru command buffer for the Reservation Acquire command.


.. c:function:: void nvme_init_io_mgmt_recv (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u8 mo, __u16 mos, void *data, __u32 len)

   Initialize passthru command for I/O Management Receive command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``__u8 mo``
  Management Operation

``__u16 mos``
  Management Operation Specific

``void *data``
  Userspace address of the data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the I/O Management
Receive command.


.. c:function:: void nvme_init_fdp_reclaim_unit_handle_status (struct libnvme_passthru_cmd *cmd, __u32 nsid, void *data, __u32 len)

   Initialize passthru command to get reclaim unit handle status

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``void *data``
  Response buffer

``__u32 len``
  Length of response buffer

**Description**

Initializes the passthru command buffer for the I/O Management Receive -
Reclaim Unit Handle Status command.


.. c:function:: void nvme_init_resv_release (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_resv_rrela rrela, bool iekey, bool disnsrs, enum nvme_resv_rtype rtype, __u64 crkey, __le64 *payload)

   Initialize passthru command for Reservation Release

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``enum nvme_resv_rrela rrela``
  Reservation release action, see :c:type:`enum nvme_resv_rrela <nvme_resv_rrela>`

``bool iekey``
  Set to ignore the existing key

``bool disnsrs``
  Disperse Namespace Reservation Support

``enum nvme_resv_rtype rtype``
  The type of reservation to be create, see :c:type:`enum nvme_resv_rtype <nvme_resv_rtype>`

``__u64 crkey``
  The current reservation key to release

``__le64 *payload``
  Data payload buffer to hold crkey

**Description**

Initializes the passthru command buffer for the Reservation Release command.


.. c:function:: void nvme_init_copy (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 sdlba, __u16 nr, __u8 desfmt, __u8 prinfor, __u8 prinfow, __u8 cetype, __u8 dtype, bool stcw, bool stcr, bool fua, bool lr, __u16 cev, __u16 dspec, void *cpydsc)

   Initialize passthru command for Copy command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``__u64 sdlba``
  Start destination LBA

``__u16 nr``
  Number of ranges (1-based, 0-based in command)

``__u8 desfmt``
  Descriptor format

``__u8 prinfor``
  Protection information field for read

``__u8 prinfow``
  Protection information field for write

``__u8 cetype``
  Command Extension Type

``__u8 dtype``
  Directive Type

``bool stcw``
  Storage Tag Check Write

``bool stcr``
  Storage Tag Check Read

``bool fua``
  Force unit access

``bool lr``
  Limited retry

``__u16 cev``
  Command Extension Value

``__u16 dspec``
  Directive specific value

``void *cpydsc``
  Range description buffer

**Description**

Initializes the passthru command buffer for the Copy command by calculating
the data length and calling the generic I/O initializer.


.. c:function:: void nvme_init_io_mgmt_send (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u8 mo, __u16 mos, void *data, __u32 len)

   Initialize passthru command for I/O Management Send command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``__u8 mo``
  Management Operation

``__u16 mos``
  Management Operation Specific

``void *data``
  Userspace address of the data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the I/O Management Send command.


.. c:function:: void nvme_init_fdp_reclaim_unit_handle_update (struct libnvme_passthru_cmd *cmd, __u32 nsid, void *pids, unsigned int npids)

   Initialize passthru command to update a list of reclaim unit handles

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``void *pids``
  List of placement identifiers buffer

``unsigned int npids``
  Number of placement identifiers

**Description**

Initializes the passthru command buffer for the I/O Management Send -
Reclaim Unit Handle Update command.


.. c:function:: void nvme_init_app_tag (struct libnvme_passthru_cmd *cmd, __u16 lbat, __u16 lbatm)

   Initialize Command Dword fields for Logical Block Application Tag/Mask

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 lbat``
  Logical block application tag

``__u16 lbatm``
  Logical block application tag mask


.. c:function:: void nvme_init_dsm_range (struct nvme_dsm_range *dsm, __u32 *ctx_attrs, __u32 *llbas, __u64 *slbas, __u16 nr_ranges)

   Constructs a data set range structure

**Parameters**

``struct nvme_dsm_range *dsm``
  DSM range array

``__u32 *ctx_attrs``
  Array of context attributes

``__u32 *llbas``
  Array of length in logical blocks

``__u64 *slbas``
  Array of starting logical blocks

``__u16 nr_ranges``
  The size of the dsm arrays

**Description**

Each array must be the same size of size 'nr_ranges'. This is intended to be
used with constructing a payload for nvme_dsm().


.. c:function:: void nvme_init_copy_range_f0 (struct nvme_copy_range_f0 *copy, __u16 *nlbs, __u64 *slbas, __u32 *elbts, __u16 *elbatms, __u16 *elbats, __u16 nr)

   Constructs a copy range structure

**Parameters**

``struct nvme_copy_range_f0 *copy``
  Copy range array

``__u16 *nlbs``
  Number of logical blocks

``__u64 *slbas``
  Starting LBA

``__u32 *elbts``
  Expected initial logical block reference tag

``__u16 *elbatms``
  Expected logical block application tag mask

``__u16 *elbats``
  Expected logical block application tag

``__u16 nr``
  Number of descriptors to construct


.. c:function:: void nvme_init_copy_range_f1 (struct nvme_copy_range_f1 *copy, __u16 *nlbs, __u64 *slbas, __u64 *eilbrts, __u16 *elbatms, __u16 *elbats, __u16 nr)

   Constructs a copy range f1 structure

**Parameters**

``struct nvme_copy_range_f1 *copy``
  Copy range array

``__u16 *nlbs``
  Number of logical blocks

``__u64 *slbas``
  Starting LBA

``__u64 *eilbrts``
  Expected initial logical block reference tag

``__u16 *elbatms``
  Expected logical block application tag mask

``__u16 *elbats``
  Expected logical block application tag

``__u16 nr``
  Number of descriptors to construct


.. c:function:: void nvme_init_copy_range_f2 (struct nvme_copy_range_f2 *copy, __u32 *snsids, __u16 *nlbs, __u64 *slbas, __u16 *sopts, __u32 *elbts, __u16 *elbatms, __u16 *elbats, __u16 nr)

   Constructs a copy range f2 structure

**Parameters**

``struct nvme_copy_range_f2 *copy``
  Copy range array

``__u32 *snsids``
  Source namespace identifier

``__u16 *nlbs``
  Number of logical blocks

``__u64 *slbas``
  Starting LBA

``__u16 *sopts``
  Source options

``__u32 *elbts``
  Expected initial logical block reference tag

``__u16 *elbatms``
  Expected logical block application tag mask

``__u16 *elbats``
  Expected logical block application tag

``__u16 nr``
  Number of descriptors to construct


.. c:function:: void nvme_init_copy_range_f3 (struct nvme_copy_range_f3 *copy, __u32 *snsids, __u16 *nlbs, __u64 *slbas, __u16 *sopts, __u64 *eilbrts, __u16 *elbatms, __u16 *elbats, __u16 nr)

   Constructs a copy range f3 structure

**Parameters**

``struct nvme_copy_range_f3 *copy``
  Copy range array

``__u32 *snsids``
  Source namespace identifier

``__u16 *nlbs``
  Number of logical blocks

``__u64 *slbas``
  Starting LBA

``__u16 *sopts``
  Source options

``__u64 *eilbrts``
  Expected initial logical block reference tag

``__u16 *elbatms``
  Expected logical block application tag mask

``__u16 *elbats``
  Expected logical block application tag

``__u16 nr``
  Number of descriptors to construct


.. c:function:: int nvme_init_var_size_tags (struct libnvme_passthru_cmd *cmd, __u8 pif, __u8 sts, __u64 reftag, __u64 storage_tag)

   Initialize Command Dword fields for Extended LBA based on Variable Sized Tags

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 pif``
  Protection information format, determines tag placement

``__u8 sts``
  Storage tag size in bits

``__u64 reftag``
  Expected Initial Logical Block Reference Tag (EILBRT)

``__u64 storage_tag``
  Expected Logical Block Storage Tag (ELBST)

**Description**

Initializes the passthru command buffer fields cdw2, cdw3, and cdw14
for commands supporting Extended LBA. This logic is usually called from
the command-specific init function (like nvme_init_zns_append).

**sts** must be within the range the NVM Command Set spec (Figure 119,
STS field) allows for **pif**: [0, 32] for 16b Guard, [16, 64] for 32b
Guard, [0, 48] for 64b Guard. A **sts** outside that range is rejected
rather than encoded: for 32b Guard in particular, **storage_tag** and
**reftag** are only 64 bits wide each, so a **sts** outside [16, 64] would
require one of them to be wider than this interface can represent.

**Return**

0 on success, -EINVAL otherwise.


