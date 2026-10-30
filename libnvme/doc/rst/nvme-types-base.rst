.. _nvme-types-base.h:

**nvme-types-base.h**


NVMe Base Specification type definitions

Based on NVM Express Base Specification,
Revision 2.4, July 31, 2026 (Ratified)

This file contains core NVMe types organized by functional area:
- Helper Macros: NVME_GET, NVME_SET, NVME_CHECK, NVME_VAL
- Controller Registers: CAP, CC, CSTS, and other BAR0 registers
- Identify Structures: Controller, Namespace, and related data
- Log Pages: SMART, Error, Firmware, and other log structures
- Features: Feature identifiers and feature-specific data
- Commands: Admin and I/O command structures
- Namespace Management: Namespace descriptors and attributes
- Status & Errors: Status codes and error information

.. c:macro:: NVME_GET

``NVME_GET (value, name)``

   extract field from complex value

**Parameters**

``value``
  The original value of a complex field

``name``
  The name of the sub-field within an nvme value

**Description**

By convention, this library defines _SHIFT and _MASK such that mask can be
applied after the shift to isolate a specific set of bits that decode to a
sub-field.

**Return**

The 'name' field from 'value'


.. c:macro:: NVME_SET

``NVME_SET (value, name)``

   set field into complex value

**Parameters**

``value``
  The value to be set in its completed position

``name``
  The name of the sub-field within an nvme value

**Return**

The 'name' field from 'value'


.. c:macro:: NVMF_GET

``NVMF_GET (value, name)``

   extract field from complex value

**Parameters**

``value``
  The original value of a complex field

``name``
  The name of the sub-field within an nvme value

**Description**

By convention, this library defines _SHIFT and _MASK such that mask can be
applied after the shift to isolate a specific set of bits that decode to a
sub-field.

**Return**

The 'name' field from 'value'


.. c:macro:: NVMF_SET

``NVMF_SET (value, name)``

   set field into complex value

**Parameters**

``value``
  The value to be set in its completed position

``name``
  The name of the sub-field within an nvme value

**Return**

The 'name' field from 'value'


.. c:macro:: NVME_CHECK

``NVME_CHECK (value, name, check)``

   check value to compare field value

**Parameters**

``value``
  The value to be checked

``name``
  The name of the sub-field within an nvme value

``check``
  The sub-field value to check

**Return**

The result of compare the value and the sub-field value


.. c:macro:: NVME_VAL

``NVME_VAL (name)``

   get mask value shifted

**Parameters**

``name``
  The name of the sub-field within an nvme value

**Return**

The mask value shifted




.. c:enum:: nvme_constants

   A place to stash various constant nvme values

**Constants**

``NVME_NSID_ALL``
  A broadcast value that is used to specify all
  namespaces

``NVME_NSID_NONE``
  The invalid namespace id, for when the nsid
  parameter is not used in a command

``NVME_UUID_NONE``
  Use to omit a uuid command parameter

``NVME_CNTLID_NONE``
  Use to omit a cntlid command parameter

``NVME_CNSSPECID_NONE``
  Use to omit a cns_specific_id command parameter

``NVME_LOG_LSP_NONE``
  Use to omit a log lsp command parameter

``NVME_LOG_LSI_NONE``
  Use to omit a log lsi command parameter

``NVME_LOG_LPO_NONE``
  Use to omit a log lpo command parameter

``NVME_IDENTIFY_DATA_SIZE``
  The transfer size for nvme identify commands

``NVME_LOG_SUPPORTED_LOG_PAGES_MAX``
  The largest possible index in the supported
  log pages log.

``NVME_ID_NVMSET_LIST_MAX``
  The largest possible nvmset index in identify
  nvmeset

``NVME_ID_UUID_LIST_MAX``
  The largest possible uuid index in identify
  uuid list

``NVME_ID_CTRL_LIST_MAX``
  The largest possible controller index in
  identify controller list

``NVME_ID_NS_LIST_MAX``
  The largest possible namespace index in
  identify namespace list

``NVME_ID_SECONDARY_CTRL_MAX``
  The largest possible secondary controller index
  in identify secondary controller

``NVME_ID_DOMAIN_LIST_MAX``
  The largest possible domain index in the
  in domain list

``NVME_ID_ENDURANCE_GROUP_LIST_MAX``
  The largest possible endurance group
  index in the endurance group list

``NVME_ID_ND_DESCRIPTOR_MAX``
  The largest possible namespace granularity
  index in the namespace granularity descriptor
  list (i.e. with the LBA Format Extension
  Enable field set to 1h in the Host Behavior
  Support feature)

``NVME_FEAT_LBA_RANGE_MAX``
  The largest possible LBA range index in feature
  lba range type

``NVME_LOG_ST_MAX_RESULTS``
  The largest possible self test result index in the
  device self test log

``NVME_LOG_TELEM_BLOCK_SIZE``
  Specification defined size of Telemetry Data Blocks

``NVME_LOG_FID_SUPPORTED_EFFECTS_MAX``
  The largest possible FID index in the
  feature identifiers effects log.

``NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_MAX``
  The largest possible MI Command index
  in the MI Command effects log.

``NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_RESERVED``
  The reserved space in the MI Command
  effects log.

``NVME_DSM_MAX_RANGES``
  The largest possible range index in a data-set
  management command

``NVME_NQN_LENGTH``
  Max length for NVMe Qualified Name

``NVMF_TRADDR_SIZE``
  Max Transport Address size

``NVMF_TSAS_SIZE``
  Max Transport Specific Address Subtype size

``NVME_ZNS_CHANGED_ZONES_MAX``
  Max number of zones in the changed zones log
  page

``NVME_STREAM_ID_MAX``
  Max number of stream IDs

``NVME_UNDERLYING_NS_LIST_MAX``
  The maximum number of Underlying Namespace
  Entry data structures reportable in the Get
  Underlying Namespace List Identify data
  structure




.. c:enum:: nvme_csi

   Defined command set indicators

**Constants**

``NVME_CSI_NVM``
  NVM Command Set Indicator

``NVME_CSI_KV``
  Key Value Command Set

``NVME_CSI_ZNS``
  Zoned Namespace Command Set

``NVME_CSI_SLM``
  Subsystem Local Memory Command Set

``NVME_CSI_CP``
  Computational Programs Command Set




.. c:enum:: nvme_register_offsets

   controller registers for all transports. This is the layout of BAR0/1 for PCIe, and properties for fabrics.

**Constants**

``NVME_REG_CAP``
  Controller Capabilities

``NVME_REG_VS``
  Version

``NVME_REG_INTMS``
  Interrupt Mask Set

``NVME_REG_INTMC``
  Interrupt Mask Clear

``NVME_REG_CC``
  Controller Configuration

``NVME_REG_CSTS``
  Controller Status

``NVME_REG_NSSR``
  NVM Subsystem Reset

``NVME_REG_AQA``
  Admin Queue Attributes

``NVME_REG_ASQ``
  Admin SQ Base Address

``NVME_REG_ACQ``
  Admin CQ Base Address

``NVME_REG_CMBLOC``
  Controller Memory Buffer Location

``NVME_REG_CMBSZ``
  Controller Memory Buffer Size

``NVME_REG_BPINFO``
  Boot Partition Information

``NVME_REG_BPRSEL``
  Boot Partition Read Select

``NVME_REG_BPMBL``
  Boot Partition Memory Buffer Location

``NVME_REG_CMBMSC``
  Controller Memory Buffer Memory Space Control

``NVME_REG_CMBSTS``
  Controller Memory Buffer Status

``NVME_REG_CMBEBS``
  Controller Memory Buffer Elasticity Buffer Size

``NVME_REG_CMBSWTP``
  Controller Memory Buffer Sustained Write Throughput

``NVME_REG_NSSD``
  NVM Subsystem Shutdown

``NVME_REG_CRTO``
  Controller Ready Timeouts

``NVME_REG_PMRCAP``
  Persistent Memory Capabilities

``NVME_REG_PMRCTL``
  Persistent Memory Region Control

``NVME_REG_PMRSTS``
  Persistent Memory Region Status

``NVME_REG_PMREBS``
  Persistent Memory Region Elasticity Buffer Size

``NVME_REG_PMRSWTP``
  Memory Region Sustained Write Throughput

``NVME_REG_PMRMSCL``
  Persistent Memory Region Controller Memory Space Control Lower

``NVME_REG_PMRMSCU``
  Persistent Memory Region Controller Memory Space Control Upper


.. c:function:: bool nvme_is_64bit_reg (__u32 offset)

   Checks if offset of the controller register is a know 64bit value.

**Parameters**

``__u32 offset``
  Offset of controller register field in bytes

**Description**

This function does not care about transport so that the offset is not going
to be checked inside of this function for the unsupported fields in a
specific transport. For example, BPMBL(Boot Partition Memory Buffer
Location) register is not supported by fabrics, but it can be checked here.

**Return**

true if given offset is 64bit register, otherwise it returns false.




.. c:enum:: nvme_cap

   This field indicates the controller capabilities register

**Constants**

``NVME_CAP_MQES_SHIFT``
  Shift amount to get the maximum queue entries supported

``NVME_CAP_CQR_SHIFT``
  Shift amount to get the contiguous queues required

``NVME_CAP_AMS_SHIFT``
  Shift amount to get the arbitration mechanism supported

``NVME_CAP_TO_SHIFT``
  Shift amount to get the timeout

``NVME_CAP_DSTRD_SHIFT``
  Shift amount to get the doorbell stride

``NVME_CAP_NSSRS_SHIFT``
  Shift amount to get the NVM subsystem reset supported

``NVME_CAP_CSS_SHIFT``
  Shift amount to get the command sets supported

``NVME_CAP_BPS_SHIFT``
  Shift amount to get the boot partition support

``NVME_CAP_CPS_SHIFT``
  Shift amount to get the controller power scope

``NVME_CAP_MPSMIN_SHIFT``
  Shift amount to get the memory page size minimum

``NVME_CAP_MPSMAX_SHIFT``
  Shift amount to get the memory page size maximum

``NVME_CAP_PMRS_SHIFT``
  Shift amount to get the persistent memory region supported

``NVME_CAP_CMBS_SHIFT``
  Shift amount to get the controller memory buffer supported

``NVME_CAP_NSSS_SHIFT``
  Shift amount to get the NVM subsystem shutdown supported

``NVME_CAP_CRMS_SHIFT``
  Shift amount to get the controller ready modes supported

``NVME_CAP_NSSES_SHIFT``
  Shift amount to get the NVM subsystem shutdown enhancements supported

``NVME_CAP_MQES_MASK``
  Mask to get the maximum queue entries supported

``NVME_CAP_CQR_MASK``
  Mask to get the contiguous queues required

``NVME_CAP_AMS_MASK``
  Mask to get the arbitration mechanism supported

``NVME_CAP_TO_MASK``
  Mask to get the timeout

``NVME_CAP_DSTRD_MASK``
  Mask to get the doorbell stride

``NVME_CAP_NSSRS_MASK``
  Mask to get the NVM subsystem reset supported

``NVME_CAP_CSS_MASK``
  Mask to get the command sets supported

``NVME_CAP_BPS_MASK``
  Mask to get the boot partition support

``NVME_CAP_CPS_MASK``
  Mask to get the controller power scope

``NVME_CAP_MPSMIN_MASK``
  Mask to get the memory page size minimum

``NVME_CAP_MPSMAX_MASK``
  Mask to get the memory page size maximum

``NVME_CAP_PMRS_MASK``
  Mask to get the persistent memory region supported

``NVME_CAP_CMBS_MASK``
  Mask to get the controller memory buffer supported

``NVME_CAP_NSSS_MASK``
  Mask to get the NVM subsystem shutdown supported

``NVME_CAP_CRMS_MASK``
  Mask to get the controller ready modes supported

``NVME_CAP_NSSES_MASK``
  Mask to get the NVM subsystem shutdown enhancements supported

``NVME_CAP_AMS_WRR``
  Weighted round robin with urgent priority class

``NVME_CAP_AMS_VS``
  Vendor specific

``NVME_CAP_CSS_NVM``
  NVM command set or a discovery controller

``NVME_CAP_CSS_CSI``
  Controller supports one or more I/O command sets

``NVME_CAP_CSS_ADMIN``
  No I/O command set is supported

``NVME_CAP_CPS_NONE``
  Not reported

``NVME_CAP_CPS_CTRL``
  Controller scope

``NVME_CAP_CPS_DOMAIN``
  Domain scope

``NVME_CAP_CPS_NVMS``
  NVM subsystem scope

``NVME_CAP_CRWMS``
  Controller ready with media support

``NVME_CAP_CRIMS``
  Controller ready independent of media support




.. c:enum:: nvme_vs

   This field indicates the version

**Constants**

``NVME_VS_TER_SHIFT``
  Shift amount to get the tertiary version

``NVME_VS_MNR_SHIFT``
  Shift amount to get the minor version

``NVME_VS_MJR_SHIFT``
  Shift amount to get the major version

``NVME_VS_TER_MASK``
  Mask to get the tertiary version

``NVME_VS_MNR_MASK``
  Mask to get the minor version

``NVME_VS_MJR_MASK``
  Mask to get the major version




.. c:enum:: nvme_cc

   This field indicates the controller configuration

**Constants**

``NVME_CC_EN_SHIFT``
  Shift amount to get the enable

``NVME_CC_CSS_SHIFT``
  Shift amount to get the I/O command set selected

``NVME_CC_MPS_SHIFT``
  Shift amount to get the memory page size

``NVME_CC_AMS_SHIFT``
  Shift amount to get the arbitration mechanism selected

``NVME_CC_SHN_SHIFT``
  Shift amount to get the shutdown notification

``NVME_CC_IOSQES_SHIFT``
  Shift amount to get the I/O submission queue entry size

``NVME_CC_IOCQES_SHIFT``
  Shift amount to get the I/O completion queue entry size

``NVME_CC_CRIME_SHIFT``
  Shift amount to get the controller ready independent of media enable

``NVME_CC_EN_MASK``
  Mask to get the enable

``NVME_CC_CSS_MASK``
  Mask to get the I/O command set selected

``NVME_CC_MPS_MASK``
  Mask to get the memory page size

``NVME_CC_AMS_MASK``
  Mask to get the arbitration mechanism selected

``NVME_CC_SHN_MASK``
  Mask to get the shutdown notification

``NVME_CC_CRIME_MASK``
  Mask to get the I/O submission queue entry size

``NVME_CC_IOSQES_MASK``
  Mask to get the I/O completion queue entry size

``NVME_CC_IOCQES_MASK``
  Mask to get the controller ready independent of media enable

``NVME_CC_CSS_NVM``
  NVM command set

``NVME_CC_CSS_CSI``
  All supported I/O command sets

``NVME_CC_CSS_ADMIN``
  Admin command set only

``NVME_CC_AMS_RR``
  Round robin

``NVME_CC_AMS_WRRU``
  Weighted round robin with urgent priority class

``NVME_CC_AMS_VS``
  Vendor specific

``NVME_CC_SHN_NONE``
  No notification; no effect

``NVME_CC_SHN_NORMAL``
  Normal shutdown notification

``NVME_CC_SHN_ABRUPT``
  Abrupt shutdown notification

``NVME_CC_CRWME``
  Controller ready with media enable

``NVME_CC_CRIME``
  Controller ready independent of media enable




.. c:enum:: nvme_csts

   This field indicates the controller status register

**Constants**

``NVME_CSTS_RDY_SHIFT``
  Shift amount to get the ready

``NVME_CSTS_CFS_SHIFT``
  Shift amount to get the controller fatal status

``NVME_CSTS_SHST_SHIFT``
  Shift amount to get the shutdown status

``NVME_CSTS_NSSRO_SHIFT``
  Shift amount to get the NVM subsystem reset occurred

``NVME_CSTS_PP_SHIFT``
  Shift amount to get the processing paused

``NVME_CSTS_ST_SHIFT``
  Shift amount to get the shutdown type

``NVME_CSTS_RDY_MASK``
  Mask to get the ready

``NVME_CSTS_CFS_MASK``
  Mask to get the controller fatal status

``NVME_CSTS_SHST_MASK``
  Mask to get the shutdown status

``NVME_CSTS_NSSRO_MASK``
  Mask to get the NVM subsystem reset occurred

``NVME_CSTS_PP_MASK``
  Mask to get the processing paused

``NVME_CSTS_ST_MASK``
  Mask to get the shutdown type

``NVME_CSTS_SHST_NORMAL``
  Normal operation

``NVME_CSTS_SHST_OCCUR``
  Shutdown processing occurring

``NVME_CSTS_SHST_CMPLT``
  Shutdown processing complete




.. c:enum:: nvme_aqa

   This field indicates the admin queue attributes

**Constants**

``NVME_AQA_ASQS_SHIFT``
  Shift amount to get the admin submission queue size

``NVME_AQA_ACQS_SHIFT``
  Shift amount to get the admin completion queue size

``NVME_AQA_ASQS_MASK``
  Mask to get the admin submission queue size

``NVME_AQA_ACQS_MASK``
  Mask to get the admin completion queue size




.. c:enum:: nvme_asq

   This field indicates the admin submission queue base address

**Constants**

``NVME_ASQ_ASQB_SHIFT``
  Shift amount to get the admin submission queue base




.. c:enum:: nvme_acq

   This field indicates the admin completion queue base address

**Constants**

``NVME_ACQ_ACQB_SHIFT``
  Shift amount to get the admin completion queue base




.. c:enum:: nvme_cmbloc

   This field indicates the controller memory buffer location

**Constants**

``NVME_CMBLOC_BIR_SHIFT``
  Shift amount to get the base indicator register

``NVME_CMBLOC_CQMMS_SHIFT``
  Shift amount to get the CMB queue mixed memory support

``NVME_CMBLOC_CQPDS_SHIFT``
  Shift amount to get the CMB queue physically discontiguous support

``NVME_CMBLOC_CDPLMS_SHIFT``
  Shift amount to get the CMB data pointer mixed locations support

``NVME_CMBLOC_CDPCILS_SHIFT``
  Shift amount to get the CMB data pointer and command independent locations support

``NVME_CMBLOC_CDMMMS_SHIFT``
  Shift amount to get the CMB data metadata mixed memory support

``NVME_CMBLOC_CQDA_SHIFT``
  Shift amount to get the CMB queue dword alignment

``NVME_CMBLOC_OFST_SHIFT``
  Shift amount to get the offset

``NVME_CMBLOC_BIR_MASK``
  Mask to get the base indicator register

``NVME_CMBLOC_CQMMS_MASK``
  Mask to get the CMB queue mixed memory support

``NVME_CMBLOC_CQPDS_MASK``
  Mask to get the CMB queue physically discontiguous support

``NVME_CMBLOC_CDPLMS_MASK``
  Mask to get the CMB data pointer mixed locations support

``NVME_CMBLOC_CDPCILS_MASK``
  Mask to get the CMB data pointer and command independent locations support

``NVME_CMBLOC_CDMMMS_MASK``
  Mask to get the CMB data metadata mixed memory support

``NVME_CMBLOC_CQDA_MASK``
  Mask to get the CMB queue dword alignment

``NVME_CMBLOC_OFST_MASK``
  Mask to get the offset




.. c:enum:: nvme_cmbsz

   This field indicates the controller memory buffer size

**Constants**

``NVME_CMBSZ_SQS_SHIFT``
  Shift amount to get the submission queue support

``NVME_CMBSZ_CQS_SHIFT``
  Shift amount to get the completion queue support

``NVME_CMBSZ_LISTS_SHIFT``
  Shift amount to get the PLP SGL list support

``NVME_CMBSZ_RDS_SHIFT``
  Shift amount to get the read data support

``NVME_CMBSZ_WDS_SHIFT``
  Shift amount to get the write data support

``NVME_CMBSZ_SZU_SHIFT``
  Shift amount to get the size units

``NVME_CMBSZ_SZ_SHIFT``
  Shift amount to get the size

``NVME_CMBSZ_SQS_MASK``
  Mask to get the submission queue support

``NVME_CMBSZ_CQS_MASK``
  Mask to get the completion queue support

``NVME_CMBSZ_LISTS_MASK``
  Mask to get the PLP SGL list support

``NVME_CMBSZ_RDS_MASK``
  Mask to get the read data support

``NVME_CMBSZ_WDS_MASK``
  Mask to get the write data support

``NVME_CMBSZ_SZU_MASK``
  Mask to get the size units

``NVME_CMBSZ_SZ_MASK``
  Mask to get the size

``NVME_CMBSZ_SZU_4K``
  4 KiB

``NVME_CMBSZ_SZU_64K``
  64 KiB

``NVME_CMBSZ_SZU_1M``
  1 MiB

``NVME_CMBSZ_SZU_16M``
  16 MiB

``NVME_CMBSZ_SZU_256M``
  256 MiB

``NVME_CMBSZ_SZU_4G``
  4 GiB

``NVME_CMBSZ_SZU_64G``
  64 GiB


.. c:function:: __u64 nvme_cmb_size (__u32 cmbsz)

   Calculate size of the controller memory buffer

**Parameters**

``__u32 cmbsz``
  Value from controller register ``NVME_REG_CMBSZ``

**Return**

size of controller memory buffer in bytes




.. c:enum:: nvme_bpinfo

   This field indicates the boot partition information

**Constants**

``NVME_BPINFO_BPSZ_SHIFT``
  Shift amount to get the boot partition size

``NVME_BPINFO_BRS_SHIFT``
  Shift amount to get the boot read status

``NVME_BPINFO_ABPID_SHIFT``
  Shift amount to get the active boot partition ID

``NVME_BPINFO_BPSZ_MASK``
  Mask to get the boot partition size

``NVME_BPINFO_BRS_MASK``
  Mask to get the boot read status

``NVME_BPINFO_ABPID_MASK``
  Mask to get the active boot partition ID

``NVME_BPINFO_BRS_NONE``
  No boot partition read operation requested

``NVME_BPINFO_BRS_READ_IN_PROGRESS``
  Boot partition read in progress

``NVME_BPINFO_BRS_READ_SUCCESS``
  Boot partition read completed successfully

``NVME_BPINFO_BRS_READ_ERROR``
  Error completing boot partition read




.. c:enum:: nvme_bprsel

   This field indicates the boot partition read select

**Constants**

``NVME_BPRSEL_BPRSZ_SHIFT``
  Shift amount to get the boot partition read size

``NVME_BPRSEL_BPROF_SHIFT``
  Shift amount to get the boot partition read offset

``NVME_BPRSEL_BPID_SHIFT``
  Shift amount to get the boot partition identifier

``NVME_BPRSEL_BPRSZ_MASK``
  Mask to get the boot partition read size

``NVME_BPRSEL_BPROF_MASK``
  Mask to get the boot partition read offset

``NVME_BPRSEL_BPID_MASK``
  Mask to get the boot partition identifier




.. c:enum:: nvme_bpmbl

   This field indicates the boot partition memory buffer location

**Constants**

``NVME_BPMBL_BMBBA_SHIFT``
  Shift amount to get the boot partition memory buffer base address




.. c:enum:: nvme_cmbmsc

   This field indicates the controller memory buffer memory space control

**Constants**

``NVME_CMBMSC_CRE_SHIFT``
  Shift amount to get the capabilities registers enabled

``NVME_CMBMSC_CMSE_SHIFT``
  Shift amount to get the controller memory space enable

``NVME_CMBMSC_CBA_SHIFT``
  Shift amount to get the controller base address

``NVME_CMBMSC_CRE_MASK``
  Mask to get the capabilities registers enabled

``NVME_CMBMSC_CMSE_MASK``
  Mask to get the controller memory space enable




.. c:enum:: nvme_cmbsts

   This field indicates the controller memory buffer status

**Constants**

``NVME_CMBSTS_CBAI_SHIFT``
  Shift amount to get the controller base address invalid

``NVME_CMBSTS_CBAI_MASK``
  Mask to get the controller base address invalid




.. c:enum:: nvme_unit

   Defined buffer size and write throughput granularity units

**Constants**

``NVME_UNIT_B``
  Bytes or Bytes/second

``NVME_UNIT_1K``
  1 KiB or 1 KiB/second

``NVME_UNIT_1M``
  1 MiB or 1 MiB/second

``NVME_UNIT_1G``
  1 GiB or 1 GiB/second




.. c:enum:: nvme_cmbebs

   This field indicates the controller memory buffer elasticity buffer size

**Constants**

``NVME_CMBEBS_CMBSZU_SHIFT``
  Shift amount to get the CMB elasticity buffer size units

``NVME_CMBEBS_RBB_SHIFT``
  Shift amount to get the read bypass behavior

``NVME_CMBEBS_CMBWBZ_SHIFT``
  Shift amount to get the CMB elasiticity buffer size base

``NVME_CMBEBS_CMBSZU_MASK``
  Mask to get the CMB elasticity buffer size units

``NVME_CMBEBS_RBB_MASK``
  Mask to get the read bypass behavior

``NVME_CMBEBS_CMBWBZ_MASK``
  Mask to get the CMB elasiticity buffer size base

``NVME_CMBEBS_CMBSZU_B``
  Bytes granularity

``NVME_CMBEBS_CMBSZU_1K``
  1 KiB granularity

``NVME_CMBEBS_CMBSZU_1M``
  1 MiB granularity

``NVME_CMBEBS_CMBSZU_1G``
  1 GiB granularity




.. c:enum:: nvme_cmbswtp

   This field indicates the controller memory buffer sustained write throughput

**Constants**

``NVME_CMBSWTP_CMBSWTU_SHIFT``
  Shift amount to get the CMB sustained write throughput units

``NVME_CMBSWTP_CMBSWTV_SHIFT``
  Shift amount to get the CMB sustained write throughput

``NVME_CMBSWTP_CMBSWTU_MASK``
  Mask to get the CMB sustained write throughput units

``NVME_CMBSWTP_CMBSWTV_MASK``
  Mask to get the CMB sustained write throughput

``NVME_CMBSWTP_CMBSWTU_B``
  Bytes/second granularity

``NVME_CMBSWTP_CMBSWTU_1K``
  1 KiB/second granularity

``NVME_CMBSWTP_CMBSWTU_1M``
  1 MiB/second granularity

``NVME_CMBSWTP_CMBSWTU_1G``
  1 GiB/second granularity




.. c:enum:: nvme_crto

   This field indicates the controller ready timeouts

**Constants**

``NVME_CRTO_CRWMT_SHIFT``
  Shift amount to get the  controller ready with media timeout

``NVME_CRTO_CRIMT_SHIFT``
  Shift amount to get the controller ready independent of media timeout

``NVME_CRTO_CRWMT_MASK``
  Mask to get the controller ready with media timeout

``NVME_CRTO_CRIMT_MASK``
  Mask to get the controller ready independent of media timeout




.. c:enum:: nvme_pmrcap

   This field indicates the persistent memory region capabilities

**Constants**

``NVME_PMRCAP_RDS_SHIFT``
  Shift amount to get the read data support

``NVME_PMRCAP_WDS_SHIFT``
  Shift amount to get the write data support

``NVME_PMRCAP_BIR_SHIFT``
  Shift amount to get the base indicator register

``NVME_PMRCAP_PMRTU_SHIFT``
  Shift amount to get the persistent memory region time units

``NVME_PMRCAP_PMRWBM_SHIFT``
  Shift amount to get the persistent memory region write barrier mechanisms

``NVME_PMRCAP_PMRTO_SHIFT``
  Shift amount to get the persistent memory region timeout

``NVME_PMRCAP_CMSS_SHIFT``
  Shift amount to get the controller memory space supported

``NVME_PMRCAP_PMRWMB_SHIFT``
  Deprecated shift amount to get the persistent memory region write barrier mechanisms

``NVME_PMRCAP_RDS_MASK``
  Mask to get the read data support

``NVME_PMRCAP_WDS_MASK``
  Mask to get the write data support

``NVME_PMRCAP_BIR_MASK``
  Mask to get the base indicator register

``NVME_PMRCAP_PMRTU_MASK``
  Mask to get the persistent memory region time units

``NVME_PMRCAP_PMRWBM_MASK``
  Mask to get the persistent memory region write barrier mechanisms

``NVME_PMRCAP_PMRTO_MASK``
  Mask to get the persistent memory region timeout

``NVME_PMRCAP_CMSS_MASK``
  Mask to get the controller memory space supported

``NVME_PMRCAP_PMRWMB_MASK``
  Deprecated mask to get the persistent memory region write barrier mechanisms

``NVME_PMRCAP_PMRTU_500MS``
  500 milliseconds

``NVME_PMRCAP_PMRTU_60S``
  minutes




.. c:enum:: nvme_pmrctl

   This field indicates the persistent memory region control

**Constants**

``NVME_PMRCTL_EN_SHIFT``
  Shift amount to get the enable

``NVME_PMRCTL_EN_MASK``
  Mask to get the enable




.. c:enum:: nvme_pmrsts

   This field indicates the persistent memory region status

**Constants**

``NVME_PMRSTS_ERR_SHIFT``
  Shift amount to get the error

``NVME_PMRSTS_NRDY_SHIFT``
  Shift amount to get the not ready

``NVME_PMRSTS_HSTS_SHIFT``
  Shift amount to get the health status

``NVME_PMRSTS_CBAI_SHIFT``
  Shift amount to get the controller base address invalid

``NVME_PMRSTS_ERR_MASK``
  Mask to get the error

``NVME_PMRSTS_NRDY_MASK``
  Mask to get the not ready

``NVME_PMRSTS_HSTS_MASK``
  Mask to get the health status

``NVME_PMRSTS_CBAI_MASK``
  Mask to get the controller base address invalid




.. c:enum:: nvme_pmrebs

   This field indicates the persistent memory region elasticity buffer size

**Constants**

``NVME_PMREBS_PMRSZU_SHIFT``
  Shift amount to get the PMR elasticity buffer size units

``NVME_PMREBS_RBB_SHIFT``
  Shift amount to get the read bypass behavior

``NVME_PMREBS_PMRWBZ_SHIFT``
  Shift amount to get the PMR elasticity buffer size base

``NVME_PMREBS_PMRSZU_MASK``
  Mask to get the PMR elasticity buffer size units

``NVME_PMREBS_RBB_MASK``
  Mask to get the read bypass behavior

``NVME_PMREBS_PMRWBZ_MASK``
  Mask to get the PMR elasticity buffer size base

``NVME_PMREBS_PMRSZU_B``
  Bytes

``NVME_PMREBS_PMRSZU_1K``
  1 KiB

``NVME_PMREBS_PMRSZU_1M``
  1 MiB

``NVME_PMREBS_PMRSZU_1G``
  1 GiB


.. c:function:: __u64 nvme_pmr_size (__u32 pmrebs)

   Calculate size of persistent memory region elasticity buffer

**Parameters**

``__u32 pmrebs``
  Value from controller register ``NVME_REG_PMREBS``

**Return**

size of controller persistent memory buffer in bytes




.. c:enum:: nvme_pmrswtp

   This field indicates the persistent memory region sustained write throughput

**Constants**

``NVME_PMRSWTP_PMRSWTU_SHIFT``
  Shift amount to get the PMR sustained write throughput units

``NVME_PMRSWTP_PMRSWTV_SHIFT``
  Shift amount to get the PMR sustained write throughput

``NVME_PMRSWTP_PMRSWTU_MASK``
  Mask to get the PMR sustained write throughput units

``NVME_PMRSWTP_PMRSWTV_MASK``
  Mask to get the PMR sustained write throughput

``NVME_PMRSWTP_PMRSWTU_BPS``
  Bytes per second

``NVME_PMRSWTP_PMRSWTU_KBPS``
  1 KiB / s

``NVME_PMRSWTP_PMRSWTU_MBPS``
  1 MiB / s

``NVME_PMRSWTP_PMRSWTU_GBPS``
  1 GiB / s


.. c:function:: __u64 nvme_pmr_throughput (__u32 pmrswtp)

   Calculate throughput of persistent memory buffer

**Parameters**

``__u32 pmrswtp``
  Value from controller register ``NVME_REG_PMRSWTP``

**Return**

throughput of controller persistent memory buffer in bytes/second




.. c:enum:: nvme_pmrmsc

   This field indicates the persistent memory region memory space control

**Constants**

``NVME_PMRMSC_CMSE_SHIFT``
  Shift amount to get the controller memory space enable

``NVME_PMRMSC_CBA_SHIFT``
  Shift amount to get the controller base address

``NVME_PMRMSC_CMSE_MASK``
  Mask to get the controller memory space enable




.. c:enum:: nvme_flbas

   This field indicates the formatted LBA size

**Constants**

``NVME_FLBAS_LOWER_SHIFT``
  Shift amount to get the format index least significant 4 bits

``NVME_FLBAS_META_EXT_SHIFT``
  Shift amount to get the metadata transferred

``NVME_FLBAS_HIGHER_SHIFT``
  Shift amount to get the format index most significant 2 bits

``NVME_FLBAS_LOWER_MASK``
  Mask to get the format index least significant 4 bits

``NVME_FLBAS_META_EXT_MASK``
  Mask to get the metadata transferred

``NVME_FLBAS_HIGHER_MASK``
  Mask to get the format index most significant 2 bits




.. c:enum:: nvme_psd_flags

   Possible flag values in nvme power state descriptor

**Constants**

``NVME_PSD_FLAGS_MXPS``
  Indicates the scale for the Maximum Power
  field. If this bit is cleared, then the scale of the
  Maximum Power field is in 0.01 Watts. If this bit is
  set, then the scale of the Maximum Power field is in
  0.0001 Watts.

``NVME_PSD_FLAGS_NOPS``
  Indicates whether the controller processes I/O
  commands in this power state. If this bit is cleared,
  then the controller processes I/O commands in this
  power state. If this bit is set, then the controller
  does not process I/O commands in this power state.




.. c:enum:: nvme_psd_ps

   Known values for :c:type:`struct nvme_psd <nvme_psd>` ``ips`` and ``aps``. Use with nvme_psd_power_scale() to extract the power scale field to match this enum.

**Constants**

``NVME_PSD_PS_NOT_REPORTED``
  Not reported

``NVME_PSD_PS_100_MICRO_WATT``
  0.0001 watt scale

``NVME_PSD_PS_10_MILLI_WATT``
  0.01 watt scale




.. c:enum:: nvme_psd_mbws

   Known values for :c:type:`struct nvme_id_psd <nvme_id_psd>` ``mbws``, the scale for :c:type:`struct nvme_id_psd <nvme_id_psd>`.mbw.

**Constants**

``NVME_PSD_MBWS_1_MIB_S``
  1 MiB/second scale

``NVME_PSD_MBWS_10_MIB_S``
  10 MiB/second scale

``NVME_PSD_MBWS_100_MIB_S``
  100 MiB/second scale

``NVME_PSD_MBWS_1_GIB_S``
  1 GiB/second scale

``NVME_PSD_MBWS_10_GIB_S``
  10 GiB/second scale

``NVME_PSD_MBWS_100_GIB_S``
  100 GiB/second scale




.. c:enum:: nvme_power_measurement_type

   Power measurement types.

**Constants**

``NVME_PMT_NSS_TOTAL_POWER``
  NVM subsystem total power

``NVME_PMT_RSVD_MIN``
  Reserved minimum value

``NVME_PMT_RSVD_MAX``
  Reserved maximum value

``NVME_PMT_VS_MIN``
  Vendor Specific minimum value

``NVME_PMT_VS_MAX``
  Vendor Specific maximum value




.. c:enum:: nvme_power_measurement_action

   Power measurement actions.

**Constants**

``NVME_PMA_STOP``
  Stop power measurement

``NVME_PMA_START``
  Start power measurement


.. c:function:: unsigned int nvme_psd_power_scale (__u8 ps)

   power scale occupies the upper 3 bits

**Parameters**

``__u8 ps``
  power scale value

**Return**

power scale value




.. c:enum:: nvme_psd_workload

   Specifies a workload hint in the Power Management Feature (see :c:type:`struct nvme_psd <nvme_psd>`.apw) to inform the NVM subsystem or indicate the conditions for the active power level.

**Constants**

``NVME_PSD_WORKLOAD_NP``
  The workload is unknown or not provided.

``NVME_PSD_WORKLOAD_1``
  Extended Idle Period with a Burst of Random Write
  consists of five minutes of idle followed by
  thirty-two random write commands of size 1 MiB
  submitted to a single controller while all other
  controllers in the NVM subsystem are idle, and then
  thirty (30) seconds of idle.

``NVME_PSD_WORKLOAD_2``
  Heavy Sequential Writes consists of 80,000
  sequential write commands of size 128 KiB submitted to
  a single controller while all other controllers in the
  NVM subsystem are idle.  The submission queue(s)
  should be sufficiently large allowing the host to
  ensure there are multiple commands pending at all
  times during the workload.




.. c:struct:: nvme_id_psd

   Power Management data structure

**Definition**

::

  struct nvme_id_psd {
    __le16 mp;
    __u8 rsvd2;
    __u8 flags;
    __le32 enlat;
    __le32 exlat;
    __u8 rrt;
    __u8 rrl;
    __u8 rwt;
    __u8 rwl;
    __le16 idlp;
    __u8 ips;
    __u8 rsvd19;
    __le16 actp;
    __u8 apws;
    __u8 epfrt;
    __u8 fqvt;
    __u8 epfvt;
    __u8 epfr_fqv_ts;
    __u8 epfvts;
    __u8 mbw;
    __u8 mbws;
    __le16 miiell;
  };

**Members**

``mp``
  Maximum Power indicates the sustained maximum power consumed by the
  NVM subsystem in this power state. The power in Watts is equal to
  the value in this field multiplied by the scale specified in the Max
  Power Scale bit (see :c:type:`enum nvme_psd_flags <nvme_psd_flags>`). A value of 0 indicates
  Maximum Power is not reported.

``rsvd2``
  Reserved

``flags``
  Additional decoding flags, see :c:type:`enum nvme_psd_flags <nvme_psd_flags>`.

``enlat``
  Entry Latency indicates the maximum latency in microseconds
  associated with entering this power state. A value of 0 indicates
  Entry Latency is not reported.

``exlat``
  Exit Latency indicates the maximum latency in microseconds
  associated with exiting this power state. A value of 0 indicates
  Exit Latency is not reported.

``rrt``
  Relative Read Throughput indicates the read throughput rank
  associated with this power state relative to others. The value in
  this is less than the number of supported power states.

``rrl``
  Relative Read Latency indicates the read latency rank associated
  with this power state relative to others. The value in this field is
  less than the number of supported power states.

``rwt``
  Relative Write Throughput indicates write throughput rank associated
  with this power state relative to others. The value in this field is
  less than the number of supported power states

``rwl``
  Relative Write Latency indicates the write latency rank associated
  with this power state relative to others. The value in this field is
  less than the number of supported power states

``idlp``
  Idle Power indicates the typical power consumed by the NVM
  subsystem over 30 seconds in this power state when idle.

``ips``
  Idle Power Scale indicates the scale for :c:type:`struct nvme_id_psd <nvme_id_psd>`.idlp,
  see :c:type:`enum nvme_psd_ps <nvme_psd_ps>` for decoding this field.

``rsvd19``
  Reserved

``actp``
  Active Power indicates the largest average power consumed by the
  NVM subsystem over a 10 second period in this power state with
  the workload indicated in the Active Power Workload field.

``apws``
  Bits 7-6: Active Power Scale(APS) indicates the scale for the :c:type:`struct
  nvme_id_psd <nvme_id_psd>`.actp, see :c:type:`enum nvme_psd_ps <nvme_psd_ps>` for decoding this value.
  Bits 2-0: Active Power Workload(APW) indicates the workload
  used to calculate maximum power for this power state.
  See :c:type:`enum nvme_psd_workload <nvme_psd_workload>` for decoding this field.

``epfrt``
  Emergency power fail recovery time

``fqvt``
  Forced quiescence vault time

``epfvt``
  Emergency power fail vault time

``epfr_fqv_ts``
  Bits 7-4: Forced quiescence vault time scale
  Bits 3-0: Emergency power fail recovery time scale

``epfvts``
  Bits 3-0: Emergency power fail vault time scale

``mbw``
  Max Bandwidth indicates the maximum bandwidth attainable in this
  power state when submitting MDTS-length sequential read commands
  at a queue depth of the Optimal Aggregated Queue Depth field. The
  bandwidth is equal to the value in this field multiplied by the
  scale indicated in the Max Bandwidth Scale field. A value of 0
  indicates no maximum bandwidth is reported.

``mbws``
  Bits 2-0: Max Bandwidth Scale (MBWS) indicates the scale for
  :c:type:`struct nvme_id_psd <nvme_id_psd>`.mbw, see :c:type:`enum nvme_psd_mbws <nvme_psd_mbws>` for decoding
  this field.

``miiell``
  Minimum Idle I/O Exit Latency Limit: if the Idle I/O Exit Latency
  Limit capability is supported (see :c:type:`enum
  nvme_id_ctrl_ctratt <nvme_id_ctrl_ctratt>`.NVME_CTRL_CTRATT_IIELLSS) for this operational
  power state, a non-zero value indicates the minimum supported
  Idle I/O Exit Latency Limit in units of 100 microseconds, and a
  value of 0h indicates there is no minimum. Cleared to 0h for a
  non-operational power state or if the capability is not
  supported.





.. c:struct:: nvme_id_ctrl

   Identify Controller data structure

**Definition**

::

  struct nvme_id_ctrl {
    __le16 vid;
    __le16 ssvid;
    char sn[20];
    char mn[40];
    char fr[8];
    __u8 rab;
    __u8 ieee[3];
    __u8 cmic;
    __u8 mdts;
    __le16 cntlid;
    __le32 ver;
    __le32 rtd3r;
    __le32 rtd3e;
    __le32 oaes;
    __le32 ctratt;
    __le16 rrls;
    __u8 bpcap;
    __u8 chsi;
    __le32 nssl;
    __u8 rsvd108[2];
    __u8 plsi;
    __u8 cntrltype;
    __u8 fguid[16];
    __le16 crdt1;
    __le16 crdt2;
    __le16 crdt3;
    __u8 crcap;
    __u8 ciu;
    __u8 cirn[8];
    __u8 rsvd144[96];
    __u8 rsvd240[13];
    __u8 nvmsr;
    __u8 vwci;
    __u8 mec;
    __le16 oacs;
    __u8 acl;
    __u8 aerl;
    __u8 frmw;
    __u8 lpa;
    __u8 elpe;
    __u8 npss;
    __u8 avscc;
    __u8 apsta;
    __le16 wctemp;
    __le16 cctemp;
    __le16 mtfa;
    __le32 hmpre;
    __le32 hmmin;
    __u8 tnvmcap[16];
    __u8 unvmcap[16];
    __le32 rpmbs;
    __le16 edstt;
    __u8 dsto;
    __u8 fwug;
    __le16 kas;
    __le16 hctma;
    __le16 mntmt;
    __le16 mxtmt;
    __le32 sanicap;
    __le32 hmminds;
    __le16 hmmaxd;
    __le16 nsetidmax;
    __le16 endgidmax;
    __u8 anatt;
    __u8 anacap;
    __le32 anagrpmax;
    __le32 nanagrpid;
    __le32 pels;
    __le16 domainid;
    __u8 kpioc;
    __u8 rsvd359;
    __le16 mptfawr;
    __u8 rmdca;
    __u8 rsvd363[5];
    __u8 megcap[16];
    __u8 tmpthha;
    __u8 mupa;
    __le16 cqt;
    __le16 cdpa;
    __le16 mup;
    __le16 ipmsr;
    __le16 msmt;
    __le16 mnens;
    __le16 mnecpens;
    __le32 mensnn;
    __u8 ensa;
    __u8 endsfs;
    __le32 vsen1 ;
    __le32 vsen2 ;
    __le32 vsen3 ;
    __le32 vsen4 ;
    __le16 msvmt;
    __u8 rsvd424[88];
    __u8 sqes;
    __u8 cqes;
    __le16 maxcmd;
    __le32 nn;
    __le16 oncs;
    __le16 fuses;
    __u8 fna;
    __u8 vwc;
    __le16 awun;
    __le16 awupf;
    __u8 icsvscc;
    __u8 nwpc;
    __le16 acwu;
    __le16 ocfs;
    __le32 sgls;
    __le32 mnan;
    __u8 maxdna[16];
    __le32 maxcna;
    __le32 oaqd;
    __u8 rhiri;
    __u8 hirt;
    __le16 cmmrtd;
    __le16 nmmrtd;
    __u8 minmrtg;
    __u8 maxmrtg;
    __u8 trattr;
    __u8 rsvd577;
    __le16 mcudmq;
    __le16 mnsudmq;
    __le16 mcmr;
    __le16 nmcmr;
    __le16 mcdqpc;
    __u8 rsvd588[180];
    char subnqn[NVME_NQN_LENGTH];
    __u8 rsvd1024[768];
    __le32 ioccsz;
    __le32 iorcsz;
    __le16 icdoff;
    __u8 fcatt;
    __u8 msdbd;
    __le16 ofcs;
    __u8 dctype;
    __u8 ccrl;
    __u8 rsvd1808[240];
    struct nvme_id_psd      psd[32];
    __u8 vs[1024];
  };

**Members**

``vid``
  PCI Vendor ID, the company vendor identifier that is assigned by
  the PCI SIG.

``ssvid``
  PCI Subsystem Vendor ID, the company vendor identifier that is
  assigned by the PCI SIG for the subsystem.

``sn``
  Serial Number in ASCII

``mn``
  Model Number in ASCII

``fr``
  Firmware Revision in ASCII, the currently active firmware
  revision for the NVM subsystem

``rab``
  Recommended Arbitration Burst, reported as a power of two

``ieee``
  IEEE assigned Organization Unique Identifier

``cmic``
  Controller Multipath IO and Namespace Sharing  Capabilities of
  the controller and NVM subsystem. See :c:type:`enum nvme_id_ctrl_cmic <nvme_id_ctrl_cmic>`.

``mdts``
  Max Data Transfer Size is the largest data transfer size. The
  host should not submit a command that exceeds this maximum data
  transfer size. The value is in units of the minimum memory page
  size (CAP.MPSMIN) and is reported as a power of two

``cntlid``
  Controller ID, the NVM subsystem unique controller identifier
  associated with the controller.

``ver``
  Version, this field contains the value reported in the Version
  register, or property (see :c:type:`enum nvme_registers <nvme_registers>` ``NVME_REG_VS``).

``rtd3r``
  RTD3 Resume Latency, the expected latency in microseconds to resume
  from Runtime D3

``rtd3e``
  RTD3 Exit Latency, the typical latency in microseconds to enter
  Runtime D3.

``oaes``
  Optional Async Events Supported, see **enum** nvme_id_ctrl_oaes.

``ctratt``
  Controller Attributes, see **enum** nvme_id_ctrl_ctratt.

``rrls``
  Read Recovery Levels. If a bit is set, then the corresponding
  Read Recovery Level is supported. If a bit is cleared, then the
  corresponding Read Recovery Level is not supported.

``bpcap``
  Boot Partition Capabilities, see :c:type:`enum nvme_id_ctrl_bpcap <nvme_id_ctrl_bpcap>`.

``chsi``
  CXL HDM Support Information, see :c:type:`enum nvme_id_ctrl_chsi <nvme_id_ctrl_chsi>`.

``nssl``
  NVM Subsystem Shutdown Latency (NSSL). This field indicates the
  typical latency in microseconds for an NVM Subsystem Shutdown to
  complete.

``rsvd108``
  Reserved

``plsi``
  Power Loss Signaling Information (PLSI), see :c:type:`enum nvme_id_ctrl_plsi <nvme_id_ctrl_plsi>`

``cntrltype``
  Controller Type, see :c:type:`enum nvme_id_ctrl_cntrltype <nvme_id_ctrl_cntrltype>`

``fguid``
  FRU GUID, a 128-bit value that is globally unique for a given
  Field Replaceable Unit

``crdt1``
  Controller Retry Delay time in 100 millisecond units if CQE CRD
  field is 1

``crdt2``
  Controller Retry Delay time in 100 millisecond units if CQE CRD
  field is 2

``crdt3``
  Controller Retry Delay time in 100 millisecond units if CQE CRD
  field is 3

``crcap``
  Controller Reachability Capabilities (CRCAP), see
  :c:type:`enum nvme_id_ctrl_crcap <nvme_id_ctrl_crcap>`

``ciu``
  Controller Instance Uniquifier (CIU)

``cirn``
  Controller Instance Random Number (CIRN)

``rsvd144``
  Reserved

``rsvd240``
  Reserved for the NVMe Management Interface specification

``nvmsr``
  NVM Subsystem Report, see :c:type:`enum nvme_id_ctrl_nvmsr <nvme_id_ctrl_nvmsr>`

``vwci``
  VPD Write Cycle Information, see :c:type:`enum nvme_id_ctrl_vwci <nvme_id_ctrl_vwci>`

``mec``
  Management Endpoint Capabilities, see :c:type:`enum nvme_id_ctrl_mec <nvme_id_ctrl_mec>`

``oacs``
  Optional Admin Command Support,the optional Admin commands and
  features supported by the controller, see :c:type:`enum nvme_id_ctrl_oacs <nvme_id_ctrl_oacs>`.

``acl``
  Abort Command Limit, the maximum number of concurrently
  executing Abort commands supported by the controller. This is a
  0's based value.

``aerl``
  Async Event Request Limit, the maximum number of concurrently
  outstanding Asynchronous Event Request commands supported by the
  controller This is a 0's based value.

``frmw``
  Firmware Updates indicates capabilities regarding firmware
  updates. See :c:type:`enum nvme_id_ctrl_frmw <nvme_id_ctrl_frmw>`.

``lpa``
  Log Page Attributes, see :c:type:`enum nvme_id_ctrl_lpa <nvme_id_ctrl_lpa>`.

``elpe``
  Error Log Page Entries, the maximum number of Error Information
  log entries that are stored by the controller. This field is a
  0's based value.

``npss``
  Number of Power States Supported, the number of NVM Express
  power states supported by the controller, indicating the number
  of valid entries in :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.psd. This is a 0's
  based value.

``avscc``
  Admin Vendor Specific Command Configuration, see
  :c:type:`enum nvme_id_ctrl_avscc <nvme_id_ctrl_avscc>`.

``apsta``
  Autonomous Power State Transition Attributes, see
  :c:type:`enum nvme_id_ctrl_apsta <nvme_id_ctrl_apsta>`.

``wctemp``
  Warning Composite Temperature Threshold indicates
  the minimum Composite Temperature field value (see :c:type:`struct
  nvme_smart_log <nvme_smart_log>`.critical_comp_time) that indicates an overheating
  condition during which controller operation continues.

``cctemp``
  Critical Composite Temperature Threshold, field indicates the
  minimum Composite Temperature field value (see :c:type:`struct
  nvme_smart_log <nvme_smart_log>`.critical_comp_time) that indicates a critical
  overheating condition.

``mtfa``
  Maximum Time for Firmware Activation indicates the maximum time
  the controller temporarily stops processing commands to activate
  the firmware image, specified in 100 millisecond units. This
  field is always valid if the controller supports firmware
  activation without a reset.

``hmpre``
  Host Memory Buffer Preferred Size indicates the preferred size
  that the host is requested to allocate for the Host Memory
  Buffer feature in 4 KiB units.

``hmmin``
  Host Memory Buffer Minimum Size indicates the minimum size that
  the host is requested to allocate for the Host Memory Buffer
  feature in 4 KiB units.

``tnvmcap``
  Total NVM Capacity, the total NVM capacity in the NVM subsystem.
  The value is in bytes.

``unvmcap``
  Unallocated NVM Capacity, the unallocated NVM capacity in the
  NVM subsystem. The value is in bytes.

``rpmbs``
  Replay Protected Memory Block Support, see
  :c:type:`enum nvme_id_ctrl_rpmbs <nvme_id_ctrl_rpmbs>`.

``edstt``
  Extended Device Self-test Time, if Device Self-test command is
  supported (see :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.oacs, ``NVME_CTRL_OACS_DSTS``),
  then this field indicates the nominal amount of time in one
  minute units that the controller takes to complete an extended
  device self-test operation when in power state 0.

``dsto``
  Device Self-test Options, see :c:type:`enum nvme_id_ctrl_dsto <nvme_id_ctrl_dsto>`.

``fwug``
  Firmware Update Granularity indicates the granularity and
  alignment requirement of the firmware image being updated by the
  Firmware Image Download command. The value is reported in 4 KiB
  units. A value of 0h indicates no information on granularity is
  provided. A value of FFh indicates no restriction

``kas``
  Keep Alive Support indicates the granularity of the Keep Alive
  Timer in 100 millisecond units.

``hctma``
  Host Controlled Thermal Management Attributes, see
  :c:type:`enum nvme_id_ctrl_hctm <nvme_id_ctrl_hctm>`.

``mntmt``
  Minimum Thermal Management Temperature indicates the minimum
  temperature, in degrees Kelvin, that the host may request in the
  Thermal Management Temperature 1 field and Thermal Management
  Temperature 2 field of a Set Features command with the Feature
  Identifier field set to ``NVME_FEAT_FID_HCTM``.

``mxtmt``
  Maximum Thermal Management Temperature indicates the maximum
  temperature, in degrees Kelvin, that the host may request in the
  Thermal Management Temperature 1 field and Thermal Management
  Temperature 2 field of the Set Features command with the Feature
  Identifier set to ``NVME_FEAT_FID_HCTM``.

``sanicap``
  Sanitize Capabilities, see :c:type:`enum nvme_id_ctrl_sanicap <nvme_id_ctrl_sanicap>`

``hmminds``
  Host Memory Buffer Minimum Descriptor Entry Size indicates the
  minimum usable size of a Host Memory Buffer Descriptor Entry in
  4 KiB units.

``hmmaxd``
  Host Memory Maximum Descriptors Entries indicates the number of
  usable Host Memory Buffer Descriptor Entries.

``nsetidmax``
  NVM Set Identifier Maximum, defines the maximum value of a valid
  NVM Set Identifier for any controller in the NVM subsystem.

``endgidmax``
  Endurance Group Identifier Maximum, defines the maximum value of
  a valid Endurance Group Identifier for any controller in the NVM
  subsystem.

``anatt``
  ANA Transition Time indicates the maximum amount of time, in
  seconds, for a transition between ANA states or the maximum
  amount of time, in seconds, that the controller reports the ANA
  change state.

``anacap``
  Asymmetric Namespace Access Capabilities, see
  :c:type:`enum nvme_id_ctrl_anacap <nvme_id_ctrl_anacap>`.

``anagrpmax``
  ANA Group Identifier Maximum indicates the maximum value of a
  valid ANA Group Identifier for any controller in the NVM
  subsystem.

``nanagrpid``
  Number of ANA Group Identifiers indicates the number of ANA
  groups supported by this controller.

``pels``
  Persistent Event Log Size indicates the maximum reportable size
  for the Persistent Event Log.

``domainid``
  Domain Identifier indicates the identifier of the domain
  that contains this controller.

``kpioc``
  Key Per I/O Capabilities (KPIOC), see :c:type:`enum nvme_id_ctrl_kpioc <nvme_id_ctrl_kpioc>`

``rsvd359``
  Reserved

``mptfawr``
  Maximum Processing Time for Firmware Activation Without Reset
  (MPTFAWR). This field shall indicate the estimated maximum time
  in 100 ms units required by the controller to process a Firmware
  Commit command that specifies a value of 011b in the Commit
  Action field

``rmdca``
  Restore Manufacturing Configuration Attributes, see :c:type:`enum
  nvme_id_ctrl_rmdca <nvme_id_ctrl_rmdca>`

``rsvd363``
  Reserved

``megcap``
  Max Endurance Group Capacity indicates the maximum capacity
  of a single Endurance Group.

``tmpthha``
  Temperature Threshold Hysteresis Attributes

``mupa``
  Maximum Unlimited Power Attributes

``cqt``
  Command Quiesce Time (CQT). This field indicates the expected
  worst-case time in 1 millisecond units for the controller to
  quiesce all outstanding commands after a Keep Alive Timeout or
  other communication loss.

``cdpa``
  Configurable Device Personality Attributes: This field
  indicates the Configurable Device Personality feature attributes
  the controller supports.

``mup``
  Maximum Unlimited Power: This field specifies the maximum
  power for power state 0 that results from removal of a power
  limit (i.e., the maximum power is not limited).

``ipmsr``
  Interval Power Measurement Sample Rate: This field
  indicates the maximum interval between power measurement
  samples used to collect interval power measurements.

``msmt``
  Maximum Stop Measurement Time: This field indicates the
  maximum stop measurement time allowed to be specified in the
  SMT field for a Set Features command specifying the Power
  Measurement feature.

``mnens``
  Maximum Number of Exported NVM Subsystems

``mnecpens``
  Maximum Number of Exported Controllers per Exported NVM
  Subsystem

``mensnn``
  Maximum Exported NVM Subsystem Number of Namespaces

``ensa``
  Exported NVM Subsystem Attributes

``endsfs``
  Exported Namespace Data Structure Formats Supported

``vsen1``
  Voltage Sensor 1: indicates the characteristics of Voltage
  Sensor 1, see :c:type:`struct nvme_id_ctrl_vsds <nvme_id_ctrl_vsds>`. A value of 0h indicates
  Voltage Sensor 1 is not supported.

``vsen2``
  Voltage Sensor 2, see :c:type:`struct nvme_id_ctrl_vsds <nvme_id_ctrl_vsds>`. A value of
  0h indicates Voltage Sensor 2 is not supported.

``vsen3``
  Voltage Sensor 3, see :c:type:`struct nvme_id_ctrl_vsds <nvme_id_ctrl_vsds>`. A value of
  0h indicates Voltage Sensor 3 is not supported.

``vsen4``
  Voltage Sensor 4, see :c:type:`struct nvme_id_ctrl_vsds <nvme_id_ctrl_vsds>`. A value of
  0h indicates Voltage Sensor 4 is not supported.

``msvmt``
  Maximum Stop Voltage Measurement Time: This field indicates
  the maximum stop measurement time in minutes allowed to be
  specified in the SVMT field for a Set Features command
  specifying the Voltage Measurement feature. A value of 0h
  indicates that a maximum stop measurement time is not reported.

``rsvd424``
  Reserved

``sqes``
  Submission Queue Entry Size, see :c:type:`enum nvme_id_ctrl_sqes <nvme_id_ctrl_sqes>`.

``cqes``
  Completion Queue Entry Size, see :c:type:`enum nvme_id_ctrl_cqes <nvme_id_ctrl_cqes>`.

``maxcmd``
  Maximum Outstanding Commands indicates the maximum number of
  commands that the controller processes at one time for a
  particular queue.

``nn``
  Number of Namespaces indicates the maximum value of a valid
  nsid for the NVM subsystem. If the MNAN (:c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.mnan
  field is cleared to 0h, then this field also indicates the
  maximum number of namespaces supported by the NVM subsystem.

``oncs``
  Optional NVM Command Support, see :c:type:`enum nvme_id_ctrl_oncs <nvme_id_ctrl_oncs>`.

``fuses``
  Fused Operation Support, see :c:type:`enum nvme_id_ctrl_fuses <nvme_id_ctrl_fuses>`.

``fna``
  Format NVM Attributes, see :c:type:`enum nvme_id_ctrl_fna <nvme_id_ctrl_fna>`.

``vwc``
  Volatile Write Cache, see :c:type:`enum nvme_id_ctrl_vwc <nvme_id_ctrl_vwc>`.

``awun``
  Atomic Write Unit Normal indicates the size of the write
  operation guaranteed to be written atomically to the NVM across
  all namespaces with any supported namespace format during normal
  operation. This field is specified in logical blocks and is a
  0's based value.

``awupf``
  Atomic Write Unit Power Fail indicates the size of the write
  operation guaranteed to be written atomically to the NVM across
  all namespaces with any supported namespace format during a
  power fail or error condition. This field is specified in
  logical blocks and is a 0’s based value.

``icsvscc``
  NVM Vendor Specific Command Configuration, see
  :c:type:`enum nvme_id_ctrl_nvscc <nvme_id_ctrl_nvscc>`.

``nwpc``
  Namespace Write Protection Capabilities, see
  :c:type:`enum nvme_id_ctrl_nwpc <nvme_id_ctrl_nwpc>`.

``acwu``
  Atomic Compare & Write Unit indicates the size of the write
  operation guaranteed to be written atomically to the NVM across
  all namespaces with any supported namespace format for a Compare
  and Write fused operation. This field is specified in logical
  blocks and is a 0’s based value.

``ocfs``
  Optional Copy Formats Supported, each bit n means controller
  supports Copy Format n.

``sgls``
  SGL Support, see :c:type:`enum nvme_id_ctrl_sgls <nvme_id_ctrl_sgls>`

``mnan``
  Maximum Number of Allowed Namespaces indicates the maximum
  number of namespaces supported by the NVM subsystem.

``maxdna``
  Maximum Domain Namespace Attachments indicates the maximum
  of the sum of the number of namespaces attached to each I/O
  controller in the Domain.

``maxcna``
  Maximum I/O Controller Namespace Attachments indicates the
  maximum number of namespaces that are allowed to be attached to
  this I/O controller.

``oaqd``
  Optimal Aggregated Queue Depth indicates the recommended maximum
  total number of outstanding I/O commands across all I/O queues
  on the controller for optimal operation.

``rhiri``
  Recommended Host-Initiated Refresh Interval (RHIRI). If the
  Host-Initiated Refresh capability is supported, then this field
  indicates the recommended time interval in days from last power
  down to the time at which the host should initiate the
  Host-Initiated Refresh operation. If this field is cleared to
  0h, then this field is not reported.

``hirt``
  Host-Initiated Refresh Time (HIRT). If the Host-Initiated
  Refresh capability is supported, then this field indicates the
  nominal amount of time in minutes that the controller takes to
  complete the Host-Initiated Refresh operation. If this field is
  cleared to 0h, then this field is not reported.

``cmmrtd``
  Controller Maximum Memory Range Tracking Descriptors indicates
  the maximum number of Memory Range Tracking Descriptors the
  controller supports.

``nmmrtd``
  NVM Subsystem Maximum Memory Range Tracking Descriptors
  indicates the maximum number of Memory Range Tracking Descriptors
  the NVM subsystem supports.

``minmrtg``
  Minimum Memory Range Tracking Granularity indicates the minimum
  value supported in the Requested Memory Range Tracking
  Granularity (RMRTG) field of the Track Memory Ranges data
  structure.

``maxmrtg``
  Maximum Memory Range Tracking Granularity indicates the maximum
  value supported in the Requested Memory Range Tracking
  Granularity (RMRTG) field of the Track Memory Ranges data
  structure.

``trattr``
  Tracking Attributes indicates supported attributes for the Track Send
  command and Track Receive command. see :c:type:`enum nvme_id_ctrl_trattr <nvme_id_ctrl_trattr>`

``rsvd577``
  Reserved

``mcudmq``
  Maximum Controller User Data Migration Queues indicates the
  maximum number of User Data Migration Queues supported by the
  controller.

``mnsudmq``
  Maximum NVM Subsystem User Data Migration Queues indicates the
  maximum number of User Data Migration Queues supported by the NVM
  subsystem.

``mcmr``
  Maximum CDQ Memory Ranges indicates the maximum number of
  memory ranges allowed to be specified by the PRP1 field of a
  Controller Data Queue command.

``nmcmr``
  NVM Subsystem Maximum CDQ Memory Ranges indicates the maximum
  number of memory ranges for all Controller Data Queues in the
  NVM subsystem.

``mcdqpc``
  Maximum Controller Data Queue PRP Count indicates the maximum
  number of PRPs allowed to be specified in the PRP list in the
  Controller Data Queue command.

``rsvd588``
  Reserved

``subnqn``
  NVM Subsystem NVMe Qualified Name, UTF-8 null terminated string

``rsvd1024``
  Reserved

``ioccsz``
  I/O Queue Command Capsule Supported Size, defines the maximum
  I/O command capsule size in 16 byte units.

``iorcsz``
  I/O Queue Response Capsule Supported Size, defines the maximum
  I/O response capsule size in 16 byte units.

``icdoff``
  In Capsule Data Offset, defines the offset where data starts
  within a capsule. This value is applicable to I/O Queues only.

``fcatt``
  Fabrics Controller Attributes, see :c:type:`enum nvme_id_ctrl_fcatt <nvme_id_ctrl_fcatt>`.

``msdbd``
  Maximum SGL Data Block Descriptors indicates the maximum
  number of SGL Data Block or Keyed SGL Data Block descriptors
  that a host is allowed to place in a capsule. A value of 0h
  indicates no limit.

``ofcs``
  Optional Fabric Commands Support, see :c:type:`enum nvme_id_ctrl_ofcs <nvme_id_ctrl_ofcs>`.

``dctype``
  Discovery Controller Type (DCTYPE). This field indicates what
  type of Discovery controller the controller is (see enum
  nvme_id_ctrl_dctype)

``ccrl``
  Cross-Controller Reset Limit: This field indicates the limit
  on the number of simultaneous in-progress Cross-Controller Reset
  operations this controller is able to cause to be initiated that
  are supported.

``rsvd1808``
  Reserved

``psd``
  Power State Descriptors, see :c:type:`struct nvme_id_psd <nvme_id_psd>`.

``vs``
  Vendor Specific





.. c:enum:: nvme_cmic

   This field indicates the controller multi-path I/O and NS sharing capabilities

**Constants**

``NVME_CMIC_MULTI_PORT_SHIFT``
  Shift amount to get the NVM subsystem port

``NVME_CMIC_MULTI_CTRL_SHIFT``
  Shift amount to get the controllers

``NVME_CMIC_MULTI_SRIOV_SHIFT``
  Shift amount to get the SR-IOV virtual function

``NVME_CMIC_MULTI_ANA_SHIFT``
  Shift amount to get the asymmetric namespace access reporting

``NVME_CMIC_MULTI_RSVD_SHIFT``
  Shift amount to get the reserved

``NVME_CMIC_MULTI_PORT_MASK``
  Mask to get the NVM subsystem port

``NVME_CMIC_MULTI_CTRL_MASK``
  Mask to get the controllers

``NVME_CMIC_MULTI_SRIOV_MASK``
  Mask to get the SR-IOV virtual function

``NVME_CMIC_MULTI_ANA_MASK``
  Mask to get the asymmetric namespace access reporting

``NVME_CMIC_MULTI_RSVD_MASK``
  Mask to get the reserved




.. c:enum:: nvme_id_ctrl_cmic

   Controller Multipath IO and Namespace Sharing Capabilities of the controller and NVM subsystem.

**Constants**

``NVME_CTRL_CMIC_MULTI_PORT``
  If set, then the NVM subsystem may contain
  more than one NVM subsystem port, otherwise
  the NVM subsystem contains only a single
  NVM subsystem port.

``NVME_CTRL_CMIC_MULTI_CTRL``
  If set, then the NVM subsystem may contain
  two or more controllers, otherwise the
  NVM subsystem contains only a single
  controller. An NVM subsystem that contains
  multiple controllers may be used by
  multiple hosts, or may provide multiple
  paths for a single host.

``NVME_CTRL_CMIC_MULTI_SRIOV``
  If set, then the controller is associated
  with an SR-IOV Virtual Function, otherwise
  it is associated with a PCI Function
  or a Fabrics connection.

``NVME_CTRL_CMIC_MULTI_ANA_REPORTING``
  If set, then the NVM subsystem supports
  Asymmetric Namespace Access Reporting.




.. c:enum:: nvme_id_ctrl_oaes

   Optional Asynchronous Events Supported

**Constants**

``NVME_CTRL_OAES_NSAN_SHIFT``
  Shift amount to get the Attached Namespace
  Attribute Notices event supported bit

``NVME_CTRL_OAES_FAN_SHIFT``
  Shift amount to get the Firmware Activation
  Notices event supported bit

``NVME_CTRL_OAES_ANACN_SHIFT``
  Shift amount to get the Asymmetric Namespace
  Access Change Notices event supported bit

``NVME_CTRL_OAES_PLEAN_SHIFT``
  Shift amount to get the Predictable Latency
  Event Aggregate Log Change Notices event
  supported bit

``NVME_CTRL_OAES_LSIAN_SHIFT``
  Shift amount to get the LBA Status Information
  Alert Notices event supported bit

``NVME_CTRL_OAES_EGEAN_SHIFT``
  Shift amount to get the Endurance Group Event
  Aggregate Log Page Change Notices event
  supported bit

``NVME_CTRL_OAES_NNSS_SHIFT``
  Shift amount to get the Normal NVM Subsystem
  Shutdown event supported bit

``NVME_CTRL_OAES_TTHR_SHIFT``
  Shift amount to get the Temperature Threshold
  Hysteresis Recovery event supported bit

``NVME_CTRL_OAES_RGCNS_SHIFT``
  Shift amount to get the Reachability Groups
  Change Notices event supported bit

``NVME_CTRL_OAES_ANSAN_SHIFT``
  Shift amount to get the Allocated Namespace
  Attribute Notices event supported bit

``NVME_CTRL_OAES_CCRCN_SHIFT``
  Shift amount to get the Cross-Controller Reset
  Completed Notices event supported bit

``NVME_CTRL_OAES_LHCN_SHIFT``
  Shift amount to get the Lost Host Communication
  Notices event supported bit

``NVME_CTRL_OAES_RLCC_SHIFT``
  Shift amount to get the Rate Limiting
  Configuration Change event supported bit

``NVME_CTRL_OAES_ZDCN_SHIFT``
  Shift amount to get the Zone Descriptor Changed
  Notices event supported bit

``NVME_CTRL_OAES_DLPCN_SHIFT``
  Shift amount to get the Discovery Log Page
  Change Notification event supported bit

``NVME_CTRL_OAES_NSAN_MASK``
  Mask to get the Attached Namespace Attribute
  Notices event supported bit

``NVME_CTRL_OAES_FAN_MASK``
  Mask to get the Firmware Activation Notices
  event supported bit

``NVME_CTRL_OAES_ANACN_MASK``
  Mask to get the Asymmetric Namespace Access
  Change Notices event supported bit

``NVME_CTRL_OAES_PLEAN_MASK``
  Mask to get the Predictable Latency Event
  Aggregate Log Change Notices event supported bit

``NVME_CTRL_OAES_LSIAN_MASK``
  Mask to get the LBA Status Information Alert
  Notices event supported bit

``NVME_CTRL_OAES_EGEAN_MASK``
  Mask to get the Endurance Group Event Aggregate
  Log Page Change Notices event supported bit

``NVME_CTRL_OAES_NNSS_MASK``
  Mask to get the Normal NVM Subsystem Shutdown
  event supported bit

``NVME_CTRL_OAES_TTHR_MASK``
  Mask to get the Temperature Threshold Hysteresis
  Recovery event supported bit

``NVME_CTRL_OAES_RGCNS_MASK``
  Mask to get the Reachability Groups Change
  Notices event supported bit

``NVME_CTRL_OAES_ANSAN_MASK``
  Mask to get the Allocated Namespace Attribute
  Notices event supported bit

``NVME_CTRL_OAES_CCRCN_MASK``
  Mask to get the Cross-Controller Reset Completed
  Notices event supported bit

``NVME_CTRL_OAES_LHCN_MASK``
  Mask to get the Lost Host Communication Notices
  event supported bit

``NVME_CTRL_OAES_RLCC_MASK``
  Mask to get the Rate Limiting Configuration
  Change event supported bit

``NVME_CTRL_OAES_ZDCN_MASK``
  Mask to get the Zone Descriptor Changed Notices
  event supported bit

``NVME_CTRL_OAES_DLPCN_MASK``
  Mask to get the Discovery Log Page Change
  Notification event supported bit

``NVME_CTRL_OAES_NSAN``
  If set, the controller supports the Attached
  Namespace Attribute Notices event.

``NVME_CTRL_OAES_FAN``
  If set, the controller supports the Firmware
  Activation Notices event.

``NVME_CTRL_OAES_ANACN``
  If set, the controller supports the Asymmetric
  Namespace Access Change Notices event.

``NVME_CTRL_OAES_PLEAN``
  If set, the controller supports the Predictable
  Latency Event Aggregate Log Change Notices
  event.

``NVME_CTRL_OAES_LSIAN``
  If set, the controller supports the LBA Status
  Information Alert Notices event.

``NVME_CTRL_OAES_EGEAN``
  If set, the controller supports the Endurance
  Group Event Aggregate Log Page Change Notices
  event.

``NVME_CTRL_OAES_NNSS``
  If set, the controller supports the Normal NVM
  Subsystem Shutdown event.

``NVME_CTRL_OAES_TTHR``
  If set, the controller supports the Temperature
  Threshold Hysteresis Recovery event.

``NVME_CTRL_OAES_RGCNS``
  If set, the controller supports the Reachability
  Groups Change Notices event.

``NVME_CTRL_OAES_ANSAN``
  If set, the controller supports the Allocated
  Namespace Attribute Notices event.

``NVME_CTRL_OAES_CCRCN``
  If set, the controller supports the
  Cross-Controller Reset Completed Notices event.

``NVME_CTRL_OAES_LHCN``
  If set, the controller supports the Lost Host
  Communication Notices event.

``NVME_CTRL_OAES_RLCC``
  If set, the controller supports the Rate
  Limiting Configuration Change event.

``NVME_CTRL_OAES_ZDCN``
  If set, the controller supports the Zone
  Descriptor Changed Notices event.

``NVME_CTRL_OAES_DLPCN``
  If set, the controller supports the Discovery
  Log Page Change Notification event.




.. c:enum:: nvme_id_ctrl_ctratt

   Controller attributes

**Constants**

``NVME_CTRL_CTRATT_HIDS_SHIFT``
  HIDS shift

``NVME_CTRL_CTRATT_NOPSPM_SHIFT``
  NOPSPM shift

``NVME_CTRL_CTRATT_NSETS_SHIFT``
  NSETS shift

``NVME_CTRL_CTRATT_RRLVLS_SHIFT``
  RRLVLS shift

``NVME_CTRL_CTRATT_EGS_SHIFT``
  EGS shift

``NVME_CTRL_CTRATT_PLM_SHIFT``
  PLM shift

``NVME_CTRL_CTRATT_TBKAS_SHIFT``
  TBKAS shift

``NVME_CTRL_CTRATT_NG_SHIFT``
  NG shift

``NVME_CTRL_CTRATT_SQA_SHIFT``
  SQA shift

``NVME_CTRL_CTRATT_ULIST_SHIFT``
  ULIST shift

``NVME_CTRL_CTRATT_MDS_SHIFT``
  MDS shift

``NVME_CTRL_CTRATT_FCM_SHIFT``
  FCM shift

``NVME_CTRL_CTRATT_VCM_SHIFT``
  VCM shift

``NVME_CTRL_CTRATT_DEG_SHIFT``
  DEG shift

``NVME_CTRL_CTRATT_DNVMS_SHIFT``
  DNVMS shift

``NVME_CTRL_CTRATT_ELBAS_SHIFT``
  ELBAS shift

``NVME_CTRL_CTRATT_MEM_SHIFT``
  MEM shift

``NVME_CTRL_CTRATT_HMBR_SHIFT``
  HMBR shift

``NVME_CTRL_CTRATT_RHII_SHIFT``
  RHII shift

``NVME_CTRL_CTRATT_FDPS_SHIFT``
  FDPS shift

``NVME_CTRL_CTRATT_PLS_SHIFT``
  PLS shift

``NVME_CTRL_CTRATT_PMS_SHIFT``
  PMS shift

``NVME_CTRL_CTRATT_VMS_SHIFT``
  VMS shift

``NVME_CTRL_CTRATT_IIELLSS_SHIFT``
  IIELLSS shift

``NVME_CTRL_CTRATT_HIDS_MASK``
  HIDS mask

``NVME_CTRL_CTRATT_NOPSPM_MASK``
  NOPSPM mask

``NVME_CTRL_CTRATT_NSETS_MASK``
  NSETS mask

``NVME_CTRL_CTRATT_RRLVLS_MASK``
  RRLVLS mask

``NVME_CTRL_CTRATT_EGS_MASK``
  EGS mask

``NVME_CTRL_CTRATT_PLM_MASK``
  PLM mask

``NVME_CTRL_CTRATT_TBKAS_MASK``
  TBKAS mask

``NVME_CTRL_CTRATT_NG_MASK``
  NG mask

``NVME_CTRL_CTRATT_SQA_MASK``
  SQA mask

``NVME_CTRL_CTRATT_ULIST_MASK``
  ULIST mask

``NVME_CTRL_CTRATT_MDS_MASK``
  MDS mask

``NVME_CTRL_CTRATT_FCM_MASK``
  FCM mask

``NVME_CTRL_CTRATT_VCM_MASK``
  VCM mask

``NVME_CTRL_CTRATT_DEG_MASK``
  DEG mask

``NVME_CTRL_CTRATT_DNVMS_MASK``
  DNVMS mask

``NVME_CTRL_CTRATT_ELBAS_MASK``
  ELBAS mask

``NVME_CTRL_CTRATT_MEM_MASK``
  MEM mask

``NVME_CTRL_CTRATT_HMBR_MASK``
  HMBR mask

``NVME_CTRL_CTRATT_RHII_MASK``
  RHII mask

``NVME_CTRL_CTRATT_FDPS_MASK``
  FDPS mask

``NVME_CTRL_CTRATT_PLS_MASK``
  PLS mask

``NVME_CTRL_CTRATT_PMS_MASK``
  PMS mask

``NVME_CTRL_CTRATT_VMS_MASK``
  VMS mask

``NVME_CTRL_CTRATT_IIELLSS_MASK``
  IIELLSS mask

``NVME_CTRL_CTRATT_128_ID``
  128-bit Host Identifier supported

``NVME_CTRL_CTRATT_NON_OP_PSP``
  Non-Operational Poser State Permissive Mode
  supported

``NVME_CTRL_CTRATT_NVM_SETS``
  NVM Sets supported

``NVME_CTRL_CTRATT_READ_RECV_LVLS``
  Read Recovery Levels supported

``NVME_CTRL_CTRATT_ENDURANCE_GROUPS``
  Endurance Groups supported

``NVME_CTRL_CTRATT_PREDICTABLE_LAT``
  Predictable Latency Mode supported

``NVME_CTRL_CTRATT_TBKAS``
  Traffic Based Keep Alive Support

``NVME_CTRL_CTRATT_NAMESPACE_GRANULARITY``
  Namespace Granularity reporting
  supported

``NVME_CTRL_CTRATT_SQ_ASSOCIATIONS``
  SQ Associations supported

``NVME_CTRL_CTRATT_UUID_LIST``
  UUID List reporting supported

``NVME_CTRL_CTRATT_MDS``
  Multi-Domain Subsystem supported

``NVME_CTRL_CTRATT_FIXED_CAP``
  Fixed Capacity Management  supported

``NVME_CTRL_CTRATT_VARIABLE_CAP``
  Variable Capacity Management supported

``NVME_CTRL_CTRATT_DEL_ENDURANCE_GROUPS``
  Delete Endurance Groups supported

``NVME_CTRL_CTRATT_DEL_NVM_SETS``
  Delete NVM Sets supported

``NVME_CTRL_CTRATT_ELBAS``
  Extended LBA Formats supported

``NVME_CTRL_CTRATT_MEM``
  MDTS and Size Limits Exclude Metadata supported

``NVME_CTRL_CTRATT_HMBR``
  HMB Restrict Non-Operational Power State Access

``NVME_CTRL_CTRATT_RHII``
  Reservations and Host Identifier Interaction

``NVME_CTRL_CTRATT_FDPS``
  Flexible Data Placement supported

``NVME_CTRL_CTRATT_PLS``
  Power Limit Support

``NVME_CTRL_CTRATT_PMS``
  Power Measurement Support

``NVME_CTRL_CTRATT_VMS``
  Voltage Measurement Support

``NVME_CTRL_CTRATT_IIELLSS``
  Idle I/O Exit Latency Limit Support and Scope

``NVME_CTRL_CTRATT_IIELLSS_POWER_STATE``
  Each operational power state scope

``NVME_CTRL_CTRATT_IIELLSS_GLOBAL``
  All operational power states scope




.. c:enum:: nvme_id_ctrl_bpcap

   Boot Partition Capabilities

**Constants**

``NVME_CTRL_BPCAP_RPMBBPWPS_SHIFT``
  Shift amount to get the RPMB
  Boot Partition Write Protection
  Support from the :c:type:`struct
  nvme_id_ctrl <nvme_id_ctrl>`.bpcap field.

``NVME_CTRL_BPCAP_SFBPWPS_SHIFT``
  Shift amount to get the Set
  Features Boot Partition Write
  Protection Support from the
  :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.bpcap
  field.

``NVME_CTRL_BPCAP_RPMBBPWPS_MASK``
  Mask to get the RPMB Boot
  Partition Write Protection
  Support from the :c:type:`struct
  nvme_id_ctrl <nvme_id_ctrl>`.bpcap field.

``NVME_CTRL_BPCAP_SFBPWPS_MASK``
  Mask to get the Set Features
  Boot Partition Write Protection
  Support from the :c:type:`struct
  nvme_id_ctrl <nvme_id_ctrl>`.bpcap field.

``NVME_CTRL_BPCAP_RPMBBPWPS_NOT_SPECIFIED``
  Support for RPMB Boot Partition
  Write Protection is not
  specified.

``NVME_CTRL_BPCAP_RPMBBPWPS_NOT_SUPPORTED``
  RPMB Boot Partition Write
  Protection is not supported by
  this controller.

``NVME_CTRL_BPCAP_RPMBBPWPS_SUPPORTED``
  RPMB Boot Partition Write
  Protection is supported by this
  controller.




.. c:enum:: nvme_id_ctrl_chsi

   CXL HDM Support Information

**Constants**

``NVME_CTRL_CHSI_CHS_SHIFT``
  Shift amount to get the CXL HDM Support (CHS)
  from the :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.chsi field.

``NVME_CTRL_CHSI_CHS_MASK``
  Mask to get CHS




.. c:enum:: nvme_id_ctrl_rmdca

   Restore Manufacturing Configuration Attributes

**Constants**

``NVME_CTRL_RMDCA_RDSCS_SHIFT``
  Shift amount to get the Restore Default
  NVM Subsystem Configuration Supported
  (RDSCS) from the :c:type:`struct
  nvme_id_ctrl <nvme_id_ctrl>`.rmdca field.

``NVME_CTRL_RMDCA_RDSCS_MASK``
  Mask to get RDSCS

``NVME_CTRL_RMDCA_RDNCS_SHIFT``
  Shift amount to get the Restore Default
  Namespace Configuration Supported
  (RDNCS)

``NVME_CTRL_RMDCA_RDNCS_MASK``
  Mask to get RDNCS

``NVME_CTRL_RMDCA_RDCCS_SHIFT``
  Shift amount to get the Restore Default
  Capacity Management Configuration
  Supported (RDCCS)

``NVME_CTRL_RMDCA_RDCCS_MASK``
  Mask to get RDCCS




.. c:enum:: nvme_id_ctrl_plsi

   Power Loss Signaling Information

**Constants**

``NVME_CTRL_PLSI_PLSEPF_SHIFT``
  Shift amount to get the PLS Emergency Power Fail from the
  :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.plsi field.

``NVME_CTRL_PLSI_PLSFQ_SHIFT``
  Shift amount to get the PLS Forced Quiescence from the
  :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.plsi field.

``NVME_CTRL_PLSI_PLSEPF_MASK``
  Mask to get the PLS Emergency Power Fail from the
  :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.plsi field.

``NVME_CTRL_PLSI_PLSFQ_MASK``
  Mask to get the PLS Forced Quiescence from the
  :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.plsi field.




.. c:enum:: nvme_id_ctrl_crcap

   Power Loss Signaling Information

**Constants**

``NVME_CTRL_CRCAP_RRSUP_SHIFT``
  Shift amount to get the Reachability Reporting Supported
  from the :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.crcap field.

``NVME_CTRL_CRCAP_RGIDC_SHIFT``
  Shift amount to get the Reachability Group ID Changeable
  from the :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.crcap field.

``NVME_CTRL_CRCAP_RRSUP_MASK``
  Mask to get the Reachability Reporting Supported from the
  :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.crcap field.

``NVME_CTRL_CRCAP_RGIDC_MASK``
  Mask to get the Reachability Group ID Changeable from the
  :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.crcap field.




.. c:enum:: nvme_id_ctrl_cntrltype

   Controller types

**Constants**

``NVME_CTRL_CNTRLTYPE_IO``
  NVM I/O controller

``NVME_CTRL_CNTRLTYPE_DISCOVERY``
  Discovery controller

``NVME_CTRL_CNTRLTYPE_ADMIN``
  Admin controller




.. c:enum:: nvme_id_ctrl_dctype

   Discovery Controller types

**Constants**

``NVME_CTRL_DCTYPE_NOT_REPORTED``
  Not reported (I/O, Admin, and pre-TP8010)

``NVME_CTRL_DCTYPE_DDC``
  Direct Discovery controller

``NVME_CTRL_DCTYPE_CDC``
  Central Discovery controller




.. c:enum:: nvme_id_ctrl_nvmsr

   This field reports information associated with the NVM Subsystem, see :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.nvmsr.

**Constants**

``NVME_CTRL_NVMSR_NVMESD_SHIFT``
  NVMESD shift

``NVME_CTRL_NVMSR_NVMEE_SHIFT``
  NVMEE shift

``NVME_CTRL_NVMSR_NVMESD_MASK``
  NVMESD mask

``NVME_CTRL_NVMSR_NVMEE_MASK``
  NVMEE mask

``NVME_CTRL_NVMSR_NVMESD``
  If set, then the NVM Subsystem is part of an NVMe
  Storage Device; if cleared, then the NVM Subsystem
  is not part of an NVMe Storage Device.

``NVME_CTRL_NVMSR_NVMEE``
  If set, then the NVM Subsystem is part of an NVMe
  Enclosure; if cleared, then the NVM Subsystem is
  not part of an NVMe Enclosure.




.. c:enum:: nvme_id_ctrl_vwci

   This field indicates information about remaining number of times that VPD contents are able to be updated using the VPD Write command, see :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.vwci.

**Constants**

``NVME_CTRL_VWCI_VWCR_SHIFT``
  VWCR shift

``NVME_CTRL_VWCI_VWCRV_SHIFT``
  VWCRV shift

``NVME_CTRL_VWCI_VWCR_MASK``
  VWCR mask

``NVME_CTRL_VWCI_VWCRV_MASK``
  VWCRV mask

``NVME_CTRL_VWCI_VWCR``
  Mask to get value of VPD Write Cycles Remaining. If
  the VPD Write Cycle Remaining Valid bit is set, then
  this field contains a value indicating the remaining
  number of times that VPD contents are able to be
  updated using the VPD Write command. If this field is
  set to 7Fh, then the remaining number of times that
  VPD contents are able to be updated using the VPD
  Write command is greater than or equal to 7Fh.

``NVME_CTRL_VWCI_VWCRV``
  VPD Write Cycle Remaining Valid. If this bit is set,
  then the VPD Write Cycle Remaining field is valid. If
  this bit is cleared, then the VPD Write Cycles
  Remaining field is invalid and cleared to 0h.




.. c:enum:: nvme_id_ctrl_mec

   Flags indicating the capabilities of the Management Endpoint in the Controller, :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.mec.

**Constants**

``NVME_CTRL_MEC_TWPME_SHIFT``
  TWPME shift

``NVME_CTRL_MEC_PCIEME_SHIFT``
  PCIEME shift

``NVME_CTRL_MEC_TWPME_MASK``
  TWPME mask

``NVME_CTRL_MEC_PCIEME_MASK``
  PCIEME mask

``NVME_CTRL_MEC_TWPME``
  If set, then the NVM Subsystem contains one or more
  Management Endpoints on the 2-Wire port.

``NVME_CTRL_MEC_PCIEME``
  If set, then the NVM Subsystem contains one or more
  Management Endpoints on one or more PCIe ports.




.. c:enum:: nvme_id_ctrl_oacs

   Flags indicating the optional Admin commands and features supported by the controller, see :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.oacs.

**Constants**

``NVME_CTRL_OACS_SSRS_SHIFT``
  Shift amount to get the Security Send Receive supported

``NVME_CTRL_OACS_FNVMS_SHIFT``
  Shift amount to get the Format NVM supported

``NVME_CTRL_OACS_FWDS_SHIFT``
  Shift amount to get the Firmware Download supported

``NVME_CTRL_OACS_NMS_SHIFT``
  Shift amount to get the Namespace Management supported

``NVME_CTRL_OACS_DSTS_SHIFT``
  Shift amount to get the Device Self-test supported

``NVME_CTRL_OACS_DIRS_SHIFT``
  Shift amount to get the Directives supported

``NVME_CTRL_OACS_NSRS_SHIFT``
  Shift amount to get the NVMe-MI Send Receive supported

``NVME_CTRL_OACS_VMS_SHIFT``
  Shift amount to get the Virtualization Management supported

``NVME_CTRL_OACS_DBCS_SHIFT``
  Shift amount to get the Doorbell Buffer Config supported

``NVME_CTRL_OACS_GLSS_SHIFT``
  Shift amount to get the Get LBA Status supported

``NVME_CTRL_OACS_CFLS_SHIFT``
  Shift amount to get the Command and Feature Lockdown supported

``NVME_CTRL_OACS_HMLMS_SHIFT``
  Shift amount to get the Host Managed Live Migration support

``NVME_CTRL_OACS_ENSS_SHIFT``
  Shift amount to get the Exported NVM Subsystem
  Support

``NVME_CTRL_OACS_CCFLS_SHIFT``
  Shift amount to get the Controller-scoped
  Command and Feature Lockdown supported

``NVME_CTRL_OACS_SSRS_MASK``
  Mask to get the Security Send Receive supported

``NVME_CTRL_OACS_FNVMS_MASK``
  Mask to get the Format NVM supported

``NVME_CTRL_OACS_FWDS_MASK``
  Mask to get the Firmware Download supported

``NVME_CTRL_OACS_NMS_MASK``
  Mask to get the Namespace Management supported

``NVME_CTRL_OACS_DSTS_MASK``
  Mask to get the Device Self-test supported

``NVME_CTRL_OACS_DIRS_MASK``
  Mask to get the Directives supported

``NVME_CTRL_OACS_NSRS_MASK``
  Mask to get the NVMe-MI Send Receive supported

``NVME_CTRL_OACS_VMS_MASK``
  Mask to get the Virtualization Management supported

``NVME_CTRL_OACS_DBCS_MASK``
  Mask to get the Doorbell Buffer Config supported

``NVME_CTRL_OACS_GLSS_MASK``
  Mask to get the Get LBA Status supported

``NVME_CTRL_OACS_CFLS_MASK``
  Mask to get the Command and Feature Lockdown supported

``NVME_CTRL_OACS_HMLMS_MASK``
  Mask to get the Host Managed Live Migration support

``NVME_CTRL_OACS_ENSS_MASK``
  Mask to get the Exported NVM Subsystem Support

``NVME_CTRL_OACS_CCFLS_MASK``
  Mask to get the Controller-scoped Command and
  Feature Lockdown supported

``NVME_CTRL_OACS_SSRS``
  If set, then the controller supports the
  Security Send and Security Receive commands.

``NVME_CTRL_OACS_FNVMS``
  If set then the controller supports the Format
  NVM command.

``NVME_CTRL_OACS_FWDS``
  If set, then the controller supports the
  Firmware Commit and Firmware Image Download commands.

``NVME_CTRL_OACS_NMS``
  If set, then the controller supports the
  Namespace Management capability

``NVME_CTRL_OACS_DSTS``
  If set, then the controller supports the Device
  Self-test command.

``NVME_CTRL_OACS_DIRS``
  If set, then the controller supports Directives
  and the Directive Send and Directive Receive
  commands.

``NVME_CTRL_OACS_NSRS``
  If set, then the controller supports the NVMe-MI
  Send and NVMe-MI Receive commands.

``NVME_CTRL_OACS_VMS``
  If set, then the controller supports the
  Virtualization Management command.

``NVME_CTRL_OACS_DBCS``
  If set, then the controller supports the
  Doorbell Buffer Config command.

``NVME_CTRL_OACS_GLSS``
  If set, then the controller supports the Get LBA
  Status capability.

``NVME_CTRL_OACS_CFLS``
  If set, then the controller supports the command
  and feature lockdown capability.

``NVME_CTRL_OACS_HMLMS``
  If set, then the controller supports the
  Host Managed Live Migration capability.

``NVME_CTRL_OACS_ENSS``
  If set, then the controller supports the
  Exported Resource Management capability.

``NVME_CTRL_OACS_CCFLS``
  If set, then the controller supports the
  Controller-scoped Command and Feature Lockdown
  capability. Cleared to '0' if the Command and
  Feature Lockdown Supported (CFLS) bit is cleared
  to '0'.




.. c:enum:: nvme_id_ctrl_frmw

   Flags and values indicates capabilities regarding firmware updates from :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.frmw.

**Constants**

``NVME_CTRL_FRMW_FFSRO_SHIFT``
  FFSRO shift

``NVME_CTRL_FRMW_NOFS_SHIFT``
  NOFS shift

``NVME_CTRL_FRMW_FAWR_SHIFT``
  FAWR shift

``NVME_CTRL_FRMW_SMUD_SHIFT``
  SMUD shift

``NVME_CTRL_FRMW_FFSRO_MASK``
  FFSRO mask

``NVME_CTRL_FRMW_NOFS_MASK``
  NOFS mask

``NVME_CTRL_FRMW_FAWR_MASK``
  FAWR mask

``NVME_CTRL_FRMW_SMUD_MASK``
  SMUD mask

``NVME_CTRL_FRMW_FFSRO``
  If set, the first firmware slot is readonly

``NVME_CTRL_FRMW_NOFS``
  Mask to get the value of the number of
  firmware slots that the controller supports.

``NVME_CTRL_FRMW_FAWR``
  If set, the controller supports firmware
  activation without a reset.

``NVME_CTRL_FRMW_SMUD``
  If set, the controller is able to detect
  overlapping firmware/boot partition
  image update.




.. c:enum:: nvme_id_ctrl_lpa

   Flags indicating optional attributes for log pages that are accessed via the Get Log Page command.

**Constants**

``NVME_CTRL_LPA_SMARTS_SHIFT``
  SMARTS shift

``NVME_CTRL_LPA_CSES_SHIFT``
  CSES shift

``NVME_CTRL_LPA_LPEDS_SHIFT``
  LPEDS shift

``NVME_CTRL_LPA_TS_SHIFT``
  TS shift

``NVME_CTRL_LPA_PES_SHIFT``
  PES shift

``NVME_CTRL_LPA_MLPS_SHIFT``
  MLPS shift

``NVME_CTRL_LPA_DA4S_SHIFT``
  DA4S shift

``NVME_CTRL_LPA_SMARTS_MASK``
  SMARTS mask

``NVME_CTRL_LPA_CSES_MASK``
  CSES mask

``NVME_CTRL_LPA_LPEDS_MASK``
  LPEDS mask

``NVME_CTRL_LPA_TS_MASK``
  TS mask

``NVME_CTRL_LPA_PES_MASK``
  PES mask

``NVME_CTRL_LPA_MLPS_MASK``
  MLPS mask

``NVME_CTRL_LPA_DA4S_MASK``
  DA4S mask

``NVME_CTRL_LPA_SMARTS``
  If set, controller supports SMART/Health log
  page on a per namespace basis.

``NVME_CTRL_LPA_CSES``
  If Set, the controller supports the commands
  supported and effects log page.

``NVME_CTRL_LPA_LPEDS``
  If set, the controller supports extended data
  for log page command including extended number
  of dwords and log page offset fields.

``NVME_CTRL_LPA_TS``
  If set, the controller supports the telemetry
  host-initiated and telemetry controller-initiated
  log pages and sending telemetry log notices.

``NVME_CTRL_LPA_PES``
  If set, the controller supports
  persistent event log.

``NVME_CTRL_LPA_MLPS``
  If set, the controller supports
  the log pages log page, the scope of
  each command in the commands
  supported and effects log page, the
  feature identifiers supported and
  effects log page, and the NVMe-MI
  commands supported and effects log
  page.

``NVME_CTRL_LPA_DA4S``
  If set, the controller supports data
  area 4 for telemetry host-initiated and
  telemetry.




.. c:enum:: nvme_id_ctrl_avscc

   Flags indicating the configuration settings for Admin Vendor Specific command handling.

**Constants**

``NVME_CTRL_AVSCC_VSCF_SHIFT``
  VSCF shift

``NVME_CTRL_AVSCC_VSCF_MASK``
  VSCF mask

``NVME_CTRL_AVSCC_VSCF``
  If set, all Admin Vendor Specific Commands use
  the optional vendor specific command format with
  NDT and NDM fields.




.. c:enum:: nvme_id_ctrl_apsta

   Flags indicating the attributes of the autonomous power state transition feature.

**Constants**

``NVME_CTRL_APSTA_APST``
  If set, then the controller supports autonomous power
  state transitions.




.. c:enum:: nvme_id_ctrl_rpmbs

   This field indicates if the controller supports one or more Replay Protected Memory Blocks, from :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.rpmbs.

**Constants**

``NVME_CTRL_RPMBS_NR_UNITS``
  Mask to get the value of the Number of RPMB Units

``NVME_CTRL_RPMBS_AUTH_METHOD``
  Mask to get the value of the Authentication Method

``NVME_CTRL_RPMBS_TOTAL_SIZE``
  Mask to get the value of Total Size

``NVME_CTRL_RPMBS_ACCESS_SIZE``
  Mask to get the value of Access Size




.. c:enum:: nvme_id_ctrl_dsto

   Flags indicating the optional Device Self-test command or operation behaviors supported by the controller or NVM subsystem.

**Constants**

``NVME_CTRL_DSTO_SDSO_SHIFT``
  Shift amount to get the value of Single Device Self-test
  Operation from Device Self-test Options field.

``NVME_CTRL_DSTO_HIRS_SHIFT``
  Shift amount to get the value of  Host-Initiated Refresh
  Support from Device Self-test Options field.

``NVME_CTRL_DSTO_SDSO_MASK``
  Mask to get the value of Single Device Self-test Operation

``NVME_CTRL_DSTO_HIRS_MASK``
  Mask to get the value of Host-Initiated Refresh Support

``NVME_CTRL_DSTO_ONE_DST``
  If set, then the NVM subsystem supports only one device
  self-test operation in progress at a time. If cleared,
  then the NVM subsystem supports one device self-test
  operation per controller at a time.

``NVME_CTRL_DSTO_HIRS``
  If set, then the controller supports the Host-Initiated
  Refresh capability.




.. c:enum:: nvme_id_ctrl_hctm

   Flags indicate the attributes of the host controlled thermal management feature

**Constants**

``NVME_CTRL_HCTMA_HCTM``
  then the controller supports host controlled thermal
  management, and the Set Features command and Get
  Features command with the Feature Identifier field
  set to ``NVME_FEAT_FID_HCTM``.




.. c:enum:: nvme_id_ctrl_sanicap

   Indicates attributes for sanitize operations.

**Constants**

``NVME_CTRL_SANICAP_CES_SHIFT``
  Crypto erase support shift

``NVME_CTRL_SANICAP_BES_SHIFT``
  Block erase support shift

``NVME_CTRL_SANICAP_OWS_SHIFT``
  Overwrite support shift

``NVME_CTRL_SANICAP_VERS_SHIFT``
  Verification support shift

``NVME_CTRL_SANICAP_NVERS_SHIFT``
  Namespace verification support shift

``NVME_CTRL_SANICAP_SPRRS_SHIFT``
  Sanitize purge request and reporting
  supported shift

``NVME_CTRL_SANICAP_NDI_SHIFT``
  No-deallocate inhibited shift

``NVME_CTRL_SANICAP_NODMMAS_SHIFT``
  No-deallocate modifies media after sanitize
  shift

``NVME_CTRL_SANICAP_CES_MASK``
  Crypto erase support mask

``NVME_CTRL_SANICAP_BES_MASK``
  Block erase support mask

``NVME_CTRL_SANICAP_OWS_MASK``
  Overwrite support mask

``NVME_CTRL_SANICAP_VERS_MASK``
  Verification support mask

``NVME_CTRL_SANICAP_NVERS_MASK``
  Namespace verification support mask

``NVME_CTRL_SANICAP_SPRRS_MASK``
  Sanitize purge request and reporting
  supported mask

``NVME_CTRL_SANICAP_NDI_MASK``
  No-deallocate inhibited mask

``NVME_CTRL_SANICAP_NODMMAS_MASK``
  No-deallocate modifies media after sanitize
  mask

``NVME_CTRL_SANICAP_CES``
  Crypto Erase Support. If set, then the
  controller supports the Crypto Erase sanitize operation.

``NVME_CTRL_SANICAP_BES``
  Block Erase Support. If set, then the controller
  supports the Block Erase sanitize operation.

``NVME_CTRL_SANICAP_OWS``
  Overwrite Support. If set, then the controller
  supports the Overwrite sanitize operation.

``NVME_CTRL_SANICAP_VERS``
  Verification support

``NVME_CTRL_SANICAP_NVERS``
  Namespace verification support

``NVME_CTRL_SANICAP_SPRRS``
  Sanitize Purge Request and Reporting
  Supported. If set, then the controller supports
  the Purged (PRGD) field in the Sanitize Status
  log page and the Purge Required (PREQ) bit in
  the Sanitize command and the Sanitize Namespace
  command.

``NVME_CTRL_SANICAP_NDI``
  No-Deallocate Inhibited. If set and the No-
  Deallocate Response Mode bit is set, then the
  controller deallocates after the sanitize
  operation even if the No-Deallocate After
  Sanitize bit is set in a Sanitize command.

``NVME_CTRL_SANICAP_NODMMAS``
  No-Deallocate Modifies Media After Sanitize,
  mask to extract value.




.. c:enum:: nvme_id_ctrl_anacap

   This field indicates the capabilities associated with Asymmetric Namespace Access Reporting.

**Constants**

``NVME_CTRL_ANACAP_OPT``
  If set, then the controller is able to
  report ANA Optimized state.

``NVME_CTRL_ANACAP_NON_OPT``
  If set, then the controller is able to
  report ANA Non-Optimized state.

``NVME_CTRL_ANACAP_INACCESSIBLE``
  If set, then the controller is able to
  report ANA Inaccessible state.

``NVME_CTRL_ANACAP_PERSISTENT_LOSS``
  If set, then the controller is able to
  report ANA Persistent Loss state.

``NVME_CTRL_ANACAP_CHANGE``
  If set, then the controller is able to
  report ANA Change state.

``NVME_CTRL_ANACAP_GRPID_NO_CHG``
  If set, then the ANAGRPID field in the
  Identify Namespace data structure
  (:c:type:`struct nvme_id_ns <nvme_id_ns>`.anagrpid), does not
  change while the namespace is attached to
  any controller.

``NVME_CTRL_ANACAP_GRPID_MGMT``
  If set, then the controller supports a
  non-zero value in the ANAGRPID field of
  the Namespace Management command.




.. c:enum:: nvme_id_ctrl_kpioc

   Key Per I/O Capabilities

**Constants**

``NVME_CTRL_KPIOC_KPIOS_SHIFT``
  Shift amount to get the Key Per I/O Supported from the
  :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.kpioc field.

``NVME_CTRL_KPIOC_KPIOSC_SHIFT``
  Shift amount to get the Key Per I/O Scope from the
  :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.kpioc field.

``NVME_CTRL_KPIOC_KPIOS_MASK``
  Mask to get the Key Per I/O Supported from the
  :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.kpioc field.

``NVME_CTRL_KPIOC_KPIOSC_MASK``
  Mask to get the Key Per I/O Scope from the
  :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.kpioc field.




.. c:enum:: nvme_id_ctrl_mupa

   Maximum Unlimited Power Attributes

**Constants**

``NVME_CTRL_MUPA_MUPS_SHIFT``
  Shift amount to get the Maximum Unlimited Power
  Scale

``NVME_CTRL_MUPA_MUPS_MASK``
  Mask to get the Maximum Unlimited Power Scale




.. c:enum:: nvme_id_ctrl_cdpa

   Configurable Device Personality Attributes

**Constants**

``NVME_CTRL_CDPA_HMAC_SHA_384``
  If set, then the controller supports
  the HMAC-SHA-384 standard.




.. c:enum:: nvme_id_ctrl_ipmsr

   Interval Power Measurement Sample Rate

**Constants**

``NVME_CTRL_IPMSR_SRS_SHIFT``
  Shift amount to get the Sample Rate
  Scale from the :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.ipmsr field.

``NVME_CTRL_IPMSR_SRV_SHIFT``
  Shift amount to get the Sample Rate
  Value from the :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.ipmsr field.

``NVME_CTRL_IPMSR_SRS_MASK``
  Mask to get the Sample Rate Scale
  from the :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.ipmsr field.

``NVME_CTRL_IPMSR_SRV_MASK``
  Mask to get the Sample Rate Value
  from the :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.ipmsr field.




.. c:enum:: nvme_id_ctrl_ensa

   Exported NVM Subsystem Attributes

**Constants**

``NVME_CTRL_ENSA_ENSMS_SHIFT``
  Shift amount to get the Exported NVM Subsystem
  Support Migration Support

``NVME_CTRL_ENSA_ENSTS_SHIFT``
  Shift amount to get the Exported NVM Subsystem
  Template Support

``NVME_CTRL_ENSA_ENSMS_MASK``
  Mask to get the Exported NVM Subsystem Support
  Migration Support

``NVME_CTRL_ENSA_ENSTS_MASK``
  Mask to get the Exported NVM Subsystem Template
  Support




.. c:enum:: nvme_id_ctrl_endsfs

   Exported Namespace Data Structure Formats Supported

**Constants**

``NVME_CTRL_ENDSFS_ENF1_SHIFT``
  Shift amount to get the Exported Namespace
  Format 1

``NVME_CTRL_ENDSFS_ENF0_SHIFT``
  Shift amount to get the Exported Namespace
  Format 0
  Template Support

``NVME_CTRL_ENDSFS_ENF1_MASK``
  Mask to get the Exported Namespace Format 1

``NVME_CTRL_ENDSFS_ENF0_MASK``
  Mask to get the Exported Namespace Format 0




.. c:enum:: nvme_id_ctrl_sqes

   Defines the required and maximum Submission Queue entry size when using the NVM Command Set.

**Constants**

``NVME_CTRL_SQES_MIN``
  Mask to get the value of the required Submission Queue
  Entry size when using the NVM Command Set.

``NVME_CTRL_SQES_MAX``
  Mask to get the value of the maximum Submission Queue
  entry size when using the NVM Command Set.




.. c:enum:: nvme_id_ctrl_cqes

   Defines the required and maximum Completion Queue entry size when using the NVM Command Set.

**Constants**

``NVME_CTRL_CQES_MIN``
  Mask to get the value of the required Completion Queue
  Entry size when using the NVM Command Set.

``NVME_CTRL_CQES_MAX``
  Mask to get the value of the maximum Completion Queue
  entry size when using the NVM Command Set.




.. c:enum:: nvme_id_ctrl_oncs

   This field indicates the optional NVM commands and features supported by the controller.

**Constants**

``NVME_CTRL_ONCS_COMPARE``
  If set, then the controller supports
  the Compare command.

``NVME_CTRL_ONCS_WRITE_UNCORRECTABLE``
  If set, then the controller supports
  the Write Uncorrectable command.

``NVME_CTRL_ONCS_DSM``
  If set, then the controller supports
  the Dataset Management command.

``NVME_CTRL_ONCS_WRITE_ZEROES``
  If set, then the controller supports
  the Write Zeroes command.

``NVME_CTRL_ONCS_SAVE_FEATURES``
  If set, then the controller supports
  the Save field set to a non-zero value
  in the Set Features command and the
  Select field set to a non-zero value in
  the Get Features command.

``NVME_CTRL_ONCS_RESERVATIONS``
  If set, then the controller supports
  reservations.

``NVME_CTRL_ONCS_TIMESTAMP``
  If set, then the controller supports
  the Timestamp feature.

``NVME_CTRL_ONCS_VERIFY``
  If set, then the controller supports
  the Verify command.

``NVME_CTRL_ONCS_COPY``
  If set, then the controller supports
  the copy command.

``NVME_CTRL_ONCS_COPY_SINGLE_ATOMICITY``
  If set, then the write portion of a
  Copy command is performed as a single
  write command to which the same
  atomicity requirements that apply to
  a write command apply.

``NVME_CTRL_ONCS_ALL_FAST_COPY``
  If set, then all copy operations for
  the Copy command are fast copy
  operations.

``NVME_CTRL_ONCS_WRITE_ZEROES_DEALLOCATE``
  If MAXWZD bit set, then the maximum data
  size for Write Zeroes command depends on the
  value of the Deallocate bit in the Write Zeroes
  command and the value in the WZDSL field in the
  I/O Command Set specific Identify Controller
  data structure.

``NVME_CTRL_ONCS_NAMESPACE_ZEROES``
  If NSZS bit set, then the controller supports
  the Namespace Zeroes (NSZ) bit in the NVM
  Command Set Write Zeroes command.




.. c:enum:: nvme_id_ctrl_fuses

   This field indicates the fused operations that the controller supports.

**Constants**

``NVME_CTRL_FUSES_COMPARE_AND_WRITE``
  If set, then the controller supports the
  Compare and Write fused operation.




.. c:enum:: nvme_id_ctrl_fna

   This field indicates attributes for the Format NVM command.

**Constants**

``NVME_CTRL_FNA_FMT_ALL_NS_SHIFT``
  Shift amount to get the format applied to all namespaces

``NVME_CTRL_FNA_SEC_ALL_NS_SHIFT``
  Shift amount to get the secure erase applied to all namespaces

``NVME_CTRL_FNA_CES_SHIFT``
  Shift amount to get the cryptographic erase supported

``NVME_CTRL_FNA_NSID_ALL_F_SHIFT``
  Shift amount to get the format supported an NSID FFFFFFFFh

``NVME_CTRL_FNA_FMT_ALL_NS_MASK``
  Mask to get the format applied to all namespaces

``NVME_CTRL_FNA_SEC_ALL_NS_MASK``
  Mask to get the secure erase applied to all namespaces

``NVME_CTRL_FNA_CES_MASK``
  Mask to get the cryptographic erase supported

``NVME_CTRL_FNA_NSID_ALL_F_MASK``
  Mask to get the format supported an NSID FFFFFFFFh

``NVME_CTRL_FNA_FMT_ALL_NAMESPACES``
  If set, then all namespaces in an NVM
  subsystem shall be configured with the
  same attributes and a format (excluding
  secure erase) of any namespace results in
  a format of all namespaces in an NVM
  subsystem. If cleared, then the
  controller supports format on a per
  namespace basis.

``NVME_CTRL_FNA_SEC_ALL_NAMESPACES``
  If set, then any secure erase performed
  as part of a format operation results in
  a secure erase of all namespaces in the
  NVM subsystem. If cleared, then any
  secure erase performed as part of a
  format results in a secure erase of the
  particular namespace specified.

``NVME_CTRL_FNA_CRYPTO_ERASE``
  If set, then cryptographic erase is
  supported. If cleared, then cryptographic
  erase is not supported.

``NVME_CTRL_FNA_NSID_FFFFFFFF``
  If set, then format does not support
  nsid value set to FFFFFFFFh. If cleared,
  format supports nsid value set to
  FFFFFFFFh.




.. c:enum:: nvme_id_ctrl_vwc

   Volatile write cache

**Constants**

``NVME_CTRL_VWC_PRESENT``
  If set, indicates a volatile write cache is present.
  If a volatile write cache is present, then the host
  controls whether the volatile write cache is enabled
  with a Set Features command specifying the value
  ``NVME_FEAT_FID_VOLATILE_WC``.

``NVME_CTRL_VWC_FLUSH``
  Mask to get the value of the flush command behavior.




.. c:enum:: nvme_id_ctrl_nvscc

   This field indicates the configuration settings for NVM Vendor Specific command handling.

**Constants**

``NVME_CTRL_NVSCC_FMT``
  If set, all NVM Vendor Specific Commands use the
  format with NDT and NDM fields.




.. c:enum:: nvme_id_ctrl_nwpc

   This field indicates the optional namespace write protection capabilities supported by the controller.

**Constants**

``NVME_CTRL_NWPC_WRITE_PROTECT``
  If set, then the controller shall
  support the No Write Protect and
  Write Protect namespace write
  protection states and may support
  the Write Protect Until Power
  Cycle state and Permanent Write
  Protect namespace write
  protection states.

``NVME_CTRL_NWPC_WRITE_PROTECT_POWER_CYCLE``
  If set, then the controller
  supports the Write Protect Until
  Power Cycle state.

``NVME_CTRL_NWPC_WRITE_PROTECT_PERMANENT``
  If set, then the controller
  supports the Permanent Write
  Protect state.




.. c:enum:: nvme_id_ctrl_sgls

   This field indicates if SGLs are supported for the NVM Command Set and the particular SGL types supported.

**Constants**

``NVME_CTRL_SGLS_SUPPORTED``

``NVME_CTRL_SGLS_KEYED``

``NVME_CTRL_SGLS_BIT_BUCKET``

``NVME_CTRL_SGLS_MPTR_BYTE_ALIGNED``

``NVME_CTRL_SGLS_OVERSIZE``

``NVME_CTRL_SGLS_MPTR_SGL``

``NVME_CTRL_SGLS_OFFSET``

``NVME_CTRL_SGLS_TPORT``




.. c:enum:: nvme_id_ctrl_trattr

   Tracking Attributes

**Constants**

``NVME_CTRL_TRATTR_THMCS_SHIFT``
  Shift amount to get the Track Host Memory Changes Support
  from the :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.trattr field.

``NVME_CTRL_TRATTR_TUDCS_SHIFT``
  Shift amount to get the Track User Data Changes Support
  from the :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.trattr field.

``NVME_CTRL_TRATTR_MRTLL_SHIFT``
  Shift amount to get the Memory Range Tracking Length Limit
  from the :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.trattr field.

``NVME_CTRL_TRATTR_THMCS_MASK``
  Mask to get the Track Host Memory Changes Support
  from the :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.trattr field.

``NVME_CTRL_TRATTR_TUDCS_MASK``
  Mask to get the Track User Data Changes Support
  from the :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.trattr field.

``NVME_CTRL_TRATTR_MRTLL_MASK``
  Mask to get the Memory Range Tracking Length Limit
  from the :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.trattr field.




.. c:enum:: nvme_id_ctrl_fcatt

   This field indicates attributes of the controller that are specific to NVMe over Fabrics.

**Constants**

``NVME_CTRL_FCATT_DYNAMIC``
  If cleared, then the NVM subsystem uses a dynamic
  controller model. If set, then the NVM subsystem
  uses a static controller model.




.. c:enum:: nvme_id_ctrl_ofcs

   Indicate whether the controller supports optional fabric commands.

**Constants**

``NVME_CTRL_OFCS_DISCONNECT``
  If set, then the controller supports the
  Disconnect command and deletion of individual
  I/O Queues.




.. c:struct:: nvme_lbaf

   LBA Format Data Structure

**Definition**

::

  struct nvme_lbaf {
    __le16 ms;
    __u8 ds;
    __u8 rp;
  };

**Members**

``ms``
  Metadata Size indicates the number of metadata bytes provided per LBA
  based on the LBA Data Size indicated.

``ds``
  LBA Data Size indicates the LBA data size supported, reported as a
  power of two.

``rp``
  Relative Performance, see :c:type:`enum nvme_lbaf_rp <nvme_lbaf_rp>`.





.. c:enum:: nvme_lbaf_rp

   This field indicates the relative performance of the LBA format indicated relative to other LBA formats supported by the controller.

**Constants**

``NVME_LBAF_RP_BEST``
  Best performance

``NVME_LBAF_RP_BETTER``
  Better performance

``NVME_LBAF_RP_GOOD``
  Good performance

``NVME_LBAF_RP_DEGRADED``
  Degraded performance

``NVME_LBAF_RP_SHIFT``
  Relative performance shift

``NVME_LBAF_RP_MASK``
  Mask to get the relative performance value from the
  field




.. c:struct:: nvme_id_ns

   Identify Namespace data structure

**Definition**

::

  struct nvme_id_ns {
    __le64 nsze;
    __le64 ncap;
    __le64 nuse;
    __u8 nsfeat;
    __u8 nlbaf;
    __u8 flbas;
    __u8 mc;
    __u8 dpc;
    __u8 dps;
    __u8 nmic;
    __u8 rescap;
    __u8 fpi;
    __u8 dlfeat;
    __le16 nawun;
    __le16 nawupf;
    __le16 nacwu;
    __le16 nabsn;
    __le16 nabo;
    __le16 nabspf;
    __le16 noiob;
    __u8 nvmcap[16];
    __le16 npwg;
    __le16 npwa;
    __le16 npdg;
    __le16 npda;
    __le16 nows;
    __le16 mssrl;
    __le32 mcl;
    __u8 msrc;
    __u8 kpios;
    __u8 nulbaf;
    __u8 rsvd83;
    __le32 kpiodaag;
    __u8 rsvd88[4];
    __le32 anagrpid;
    __u8 rsvd96[3];
    __u8 nsattr;
    __le16 nvmsetid;
    __le16 endgid;
    __u8 nguid[16];
    __u8 eui64[8];
    struct nvme_lbaf        lbaf[64];
    __u8 vs[3712];
  };

**Members**

``nsze``
  Namespace Size indicates the total size of the namespace in
  logical blocks. The number of logical blocks is based on the
  formatted LBA size.

``ncap``
  Namespace Capacity indicates the maximum number of logical blocks
  that may be allocated in the namespace at any point in time. The
  number of logical blocks is based on the formatted LBA size.

``nuse``
  Namespace Utilization indicates the current number of logical
  blocks allocated in the namespace. This field is smaller than or
  equal to the Namespace Capacity. The number of logical blocks is
  based on the formatted LBA size.

``nsfeat``
  Namespace Features, see :c:type:`enum nvme_id_nsfeat <nvme_id_nsfeat>`.

``nlbaf``
  Number of LBA Formats defines the number of supported LBA data
  size and metadata size combinations supported by the namespace
  and the highest possible index to :c:type:`struct nvme_id_ns <nvme_id_ns>`.lbaf.

``flbas``
  Formatted LBA Size, see :c:type:`enum nvme_id_ns_flbas <nvme_id_ns_flbas>`.

``mc``
  Metadata Capabilities, see :c:type:`enum nvme_id_ns_mc <nvme_id_ns_mc>`.

``dpc``
  End-to-end Data Protection Capabilities, see
  :c:type:`enum nvme_id_ns_dpc <nvme_id_ns_dpc>`.

``dps``
  End-to-end Data Protection Type Settings, see
  :c:type:`enum nvme_id_ns_dps <nvme_id_ns_dps>`.

``nmic``
  Namespace Multi-path I/O and Namespace Sharing Capabilities, see
  :c:type:`enum nvme_id_ns_nmic <nvme_id_ns_nmic>`.

``rescap``
  Reservation Capabilities, see :c:type:`enum nvme_id_ns_rescap <nvme_id_ns_rescap>`.

``fpi``
  Format Progress Indicator, see :c:type:`enum nvme_nd_ns_fpi <nvme_nd_ns_fpi>`.

``dlfeat``
  Deallocate Logical Block Features, see :c:type:`enum nvme_id_ns_dlfeat <nvme_id_ns_dlfeat>`.

``nawun``
  Namespace Atomic Write Unit Normal indicates the
  namespace specific size of the write operation guaranteed to be
  written atomically to the NVM during normal operation.

``nawupf``
  Namespace Atomic Write Unit Power Fail indicates the
  namespace specific size of the write operation guaranteed to be
  written atomically to the NVM during a power fail or error
  condition.

``nacwu``
  Namespace Atomic Compare & Write Unit indicates the namespace
  specific size of the write operation guaranteed to be written
  atomically to the NVM for a Compare and Write fused command.

``nabsn``
  Namespace Atomic Boundary Size Normal indicates the atomic
  boundary size for this namespace for the NAWUN value. This field
  is specified in logical blocks.

``nabo``
  Namespace Atomic Boundary Offset indicates the LBA on this
  namespace where the first atomic boundary starts.

``nabspf``
  Namespace Atomic Boundary Size Power Fail indicates the atomic
  boundary size for this namespace specific to the Namespace Atomic
  Write Unit Power Fail value. This field is specified in logical
  blocks.

``noiob``
  Namespace Optimal I/O Boundary indicates the optimal I/O boundary
  for this namespace. This field is specified in logical blocks.
  The host should construct Read and Write commands that do not
  cross the I/O boundary to achieve optimal performance.

``nvmcap``
  NVM Capacity indicates the total size of the NVM allocated to
  this namespace. The value is in bytes.

``npwg``
  Namespace Preferred Write Granularity indicates the smallest
  recommended write granularity in logical blocks for this
  namespace. This is a 0's based value.

``npwa``
  Namespace Preferred Write Alignment indicates the recommended
  write alignment in logical blocks for this namespace. This is a
  0's based value.

``npdg``
  Namespace Preferred Deallocate Granularity indicates the
  recommended granularity in logical blocks for the Dataset
  Management command with the Attribute - Deallocate bit.

``npda``
  Namespace Preferred Deallocate Alignment indicates the
  recommended alignment in logical blocks for the Dataset
  Management command with the Attribute - Deallocate bit

``nows``
  Namespace Optimal Write Size indicates the size in logical blocks
  for optimal write performance for this namespace. This is a 0's
  based value.

``mssrl``
  Maximum Single Source Range Length indicates the maximum number
  of logical blocks that may be specified in each valid Source Range
  field of a Copy command.

``mcl``
  Maximum Copy Length indicates the maximum number of logical
  blocks that may be specified in a Copy command.

``msrc``
  Maximum Source Range Count indicates the maximum number of Source
  Range entries that may be used to specify source data in a Copy
  command. This is a 0’s based value.

``kpios``
  Key Per I/O Status indicates namespace Key Per I/O capability status.

``nulbaf``
  Number of Unique Capability LBA Formats defines the number of
  supported user data size and metadata size combinations supported
  by the namespace that may not share the same capabilities. LBA
  formats shall be allocated in order and packed sequentially.

``rsvd83``
  Reserved

``kpiodaag``
  Key Per I/O Data Access Alignment and Granularity indicates the
  alignment and granularity in logical blocks that is required
  for commands that support a KPIOTAG value in the CETYPE field.

``rsvd88``
  Reserved

``anagrpid``
  ANA Group Identifier indicates the ANA Group Identifier of the
  ANA group of which the namespace is a member.

``rsvd96``
  Reserved

``nsattr``
  Namespace Attributes, see :c:type:`enum nvme_id_ns_attr <nvme_id_ns_attr>`.

``nvmsetid``
  NVM Set Identifier indicates the NVM Set with which this
  namespace is associated.

``endgid``
  Endurance Group Identifier indicates the Endurance Group with
  which this namespace is associated.

``nguid``
  Namespace Globally Unique Identifier contains a 128-bit value
  that is globally unique and assigned to the namespace when the
  namespace is created. This field remains fixed throughout the
  life of the namespace and is preserved across namespace and
  controller operations

``eui64``
  IEEE Extended Unique Identifier contains a 64-bit IEEE Extended
  Unique Identifier (EUI-64) that is globally unique and assigned
  to the namespace when the namespace is created. This field
  remains fixed throughout the life of the namespace and is
  preserved across namespace and controller operations

``lbaf``
  LBA Format, see :c:type:`struct nvme_lbaf <nvme_lbaf>`.

``vs``
  Vendor Specific





.. c:enum:: nvme_id_nsfeat

   This field defines features of the namespace.

**Constants**

``NVME_NS_FEAT_THIN``
  If set, indicates that the namespace supports thin
  provisioning. Specifically, the Namespace Capacity
  reported may be less than the Namespace Size.

``NVME_NS_FEAT_NATOMIC``
  If set, indicates that the fields NAWUN, NAWUPF, and
  NACWU are defined for this namespace and should be
  used by the host for this namespace instead of the
  AWUN, AWUPF, and ACWU fields in the Identify
  Controller data structure.

``NVME_NS_FEAT_DULBE``
  If set, indicates that the controller supports the
  Deallocated or Unwritten Logical Block error for
  this namespace.

``NVME_NS_FEAT_ID_REUSE``
  If set, indicates that the value in the NGUID field
  for this namespace, if non- zero, is never reused by
  the controller and that the value in the EUI64 field
  for this namespace, if non-zero, is never reused by
  the controller.

``NVME_NS_FEAT_IO_OPT``
  If set, indicates that the fields NPWG, NPWA, NPDG,
  NPDA, and NOWS are defined for this namespace and
  should be used by the host for I/O optimization

``NVME_NS_FEAT_MAM``
  If set, indicates that Multiple Atomicity Mode
  applies to write operations to this namespace. If
  cleared, indicates that Single Atomicity Mode
  applies to write operations to this namespace.

``NVME_NS_FEAT_OPTRPERF``
  If set, indicates that the NPRG, NPRA, and NORS
  fields are defined for this namespace and should be
  used by the host for I/O optimization.




.. c:enum:: nvme_id_ns_flbas

   This field indicates the LBA data size & metadata size combination that the namespace has been formatted with

**Constants**

``NVME_NS_FLBAS_LOWER_SHIFT``
  Shift to get the lower 4 bits of LBA format index

``NVME_NS_FLBAS_LOWER_MASK``
  Mask to get the index of one of the supported
  LBA Formats's least significant
  4bits indicated in
  :c:type:`struct nvme_id_ns <nvme_id_ns>`.lbaf.

``NVME_NS_FLBAS_META_EXT``
  Applicable only if format contains metadata. If
  this bit is set, indicates that the metadata is
  transferred at the end of the data LBA, creating an
  extended data LBA. If cleared, indicates that all
  of the metadata for a command is transferred as a
  separate contiguous buffer of data.

``NVME_NS_FLBAS_HIGHER_SHIFT``
  Shift to get the higher 2 bits of LBA format index

``NVME_NS_FLBAS_HIGHER_MASK``
  Mask to get the index of one of
  the supported LBA Formats's most significant
  2bits indicated in
  :c:type:`struct nvme_id_ns <nvme_id_ns>`.lbaf.




.. c:enum:: nvme_id_ns_mc

   This field indicates the capabilities for metadata.

**Constants**

``NVME_NS_MC_EXTENDED``
  If set, indicates that the namespace supports the
  metadata being transferred as part of an extended data LBA.

``NVME_NS_MC_SEPARATE``
  If set, indicates the namespace supports the metadata
  being transferred as part of a separate buffer that is
  specified in the Metadata Pointer.




.. c:enum:: nvme_id_ns_dpc

   This field indicates the capabilities for the end-to-end data protection feature.

**Constants**

``NVME_NS_DPC_PI_TYPE1``
  If set, indicates that the namespace supports
  Protection Information Type 1.

``NVME_NS_DPC_PI_TYPE2``
  If set, indicates that the namespace supports
  Protection Information Type 2.

``NVME_NS_DPC_PI_TYPE3``
  If set, indicates that the namespace supports
  Protection Information Type 3.

``NVME_NS_DPC_PI_FIRST``
  If set, indicates that the namespace supports
  protection information transferred as the first eight
  bytes of metadata.

``NVME_NS_DPC_PI_LAST``
  If set, indicates that the namespace supports
  protection information transferred as the last eight
  bytes of metadata.




.. c:enum:: nvme_id_ns_dps

   This field indicates the Type settings for the end-to-end data protection feature.

**Constants**

``NVME_NS_DPS_PI_NONE``
  Protection information is not enabled

``NVME_NS_DPS_PI_TYPE1``
  Protection information is enabled, Type 1

``NVME_NS_DPS_PI_TYPE2``
  Protection information is enabled, Type 2

``NVME_NS_DPS_PI_TYPE3``
  Protection information is enabled, Type 3

``NVME_NS_DPS_PI_SHIFT``
  Protection information type shift

``NVME_NS_DPS_PI_MASK``
  Mask to get the value of the PI type

``NVME_NS_DPS_PI_FIRST_SHIFT``
  Protection information in first bytes shift

``NVME_NS_DPS_PI_FIRST_MASK``
  Protection information in first bytes mask

``NVME_NS_DPS_PI_FIRST``
  If set, indicates that the protection information, if
  enabled, is transferred as the first eight bytes of
  metadata.




.. c:enum:: nvme_id_ns_nmic

   This field specifies multi-path I/O and namespace sharing capabilities of the namespace.

**Constants**

``NVME_NS_NMIC_SHARED``
  If set, then the namespace may be attached to two or
  more controllers in the NVM subsystem concurrently




.. c:enum:: nvme_id_ns_rescap

   This field indicates the reservation capabilities of the namespace.

**Constants**

``NVME_NS_RESCAP_PTPL``
  If set, indicates that the namespace supports the
  Persist Through Power Loss capability.

``NVME_NS_RESCAP_WE``
  If set, indicates that the namespace supports the
  Write Exclusive reservation type.

``NVME_NS_RESCAP_EA``
  If set, indicates that the namespace supports the
  Exclusive Access reservation type.

``NVME_NS_RESCAP_WERO``
  If set, indicates that the namespace supports the
  Write Exclusive - Registrants Only reservation type.

``NVME_NS_RESCAP_EARO``
  If set, indicates that the namespace supports the
  Exclusive Access - Registrants Only reservation type.

``NVME_NS_RESCAP_WEAR``
  If set, indicates that the namespace supports the
  Write Exclusive - All Registrants reservation type.

``NVME_NS_RESCAP_EAAR``
  If set, indicates that the namespace supports the
  Exclusive Access - All Registrants reservation type.

``NVME_NS_RESCAP_IEK_13``
  If set, indicates that Ignore Existing Key is used
  as defined in revision 1.3 or later of this specification.




.. c:enum:: nvme_nd_ns_fpi

   If a format operation is in progress, this field indicates the percentage of the namespace that remains to be formatted.

**Constants**

``NVME_NS_FPI_REMAINING``
  Mask to get the format percent remaining value

``NVME_NS_FPI_SUPPORTED``
  If set, indicates that the namespace supports the
  Format Progress Indicator defined for the field.




.. c:enum:: nvme_id_ns_dlfeat

   This field indicates information about features that affect deallocating logical blocks for this namespace.

**Constants**

``NVME_NS_DLFEAT_RB``
  Mask to get the value of the read behavior

``NVME_NS_DLFEAT_RB_NR``
  Read behvaior is not reported

``NVME_NS_DLFEAT_RB_ALL_0S``
  A deallocated logical block returns all bytes
  cleared to 0h.

``NVME_NS_DLFEAT_RB_ALL_FS``
  A deallocated logical block returns all bytes
  set to FFh.

``NVME_NS_DLFEAT_WRITE_ZEROES``
  If set, indicates that the controller supports
  the Deallocate bit in the Write Zeroes command
  for this namespace.

``NVME_NS_DLFEAT_CRC_GUARD``
  If set, indicates that the Guard field for
  deallocated logical blocks that contain
  protection information is set to the CRC for
  the value read from the deallocated logical
  block and its metadata




.. c:enum:: nvme_id_ns_kpios

   Key Per I/O Status

**Constants**

``NVME_NS_KPIOS_KPIOENS_SHIFT``
  Shift amount to get Key Per I/O Enabled
  in Namespace from the :c:type:`struct nvme_id_ns <nvme_id_ns>`.kpios field.

``NVME_NS_KPIOS_KPIOENS_MASK``
  Mask to get Key Per I/O Enabled in Namespace
  from the :c:type:`struct nvme_id_ns <nvme_id_ns>`.kpios field.

``NVME_NS_KPIOS_KPIOSNS_SHIFT``
  Shift amount to get Key Per I/O Supported
  in Namespace from the :c:type:`struct nvme_id_ns <nvme_id_ns>`.kpios field.

``NVME_NS_KPIOS_KPIOSNS_MASK``
  Mask to get Key Per I/O Supported in Namespace
  from the :c:type:`struct nvme_id_ns <nvme_id_ns>`.kpios field.




.. c:enum:: nvme_id_ns_attr

   Specifies attributes of the namespace.

**Constants**

``NVME_NS_NSATTR_WRITE_PROTECTED``
  If set, then the namespace is currently
  write protected and all write access to the
  namespace shall fail.




.. c:struct:: nvme_ns_id_desc

   Namespace identifier type descriptor

**Definition**

::

  struct nvme_ns_id_desc {
    __u8 nidt;
    __u8 nidl;
    __le16 rsvd;
    __u8 nid[];
  };

**Members**

``nidt``
  Namespace Identifier Type, see :c:type:`enum nvme_ns_id_desc_nidt <nvme_ns_id_desc_nidt>`

``nidl``
  Namespace Identifier Length contains the length in bytes of the
  :c:type:`struct nvme_id_ns <nvme_id_ns>`.nid.

``rsvd``
  Reserved

``nid``
  Namespace Identifier contains a value that is globally unique and
  assigned to the namespace when the namespace is created. The length
  is defined in :c:type:`struct nvme_id_ns <nvme_id_ns>`.nidl.





.. c:enum:: nvme_ns_id_desc_nidt

   Known namespace identifier types

**Constants**

``NVME_NIDT_EUI64``
  IEEE Extended Unique Identifier, the NID field contains a
  copy of the EUI64 field in the struct nvme_id_ns.eui64.

``NVME_NIDT_NGUID``
  Namespace Globally Unique Identifier, the NID field
  contains a copy of the NGUID field in struct nvme_id_ns.nguid.

``NVME_NIDT_UUID``
  The NID field contains a 128-bit Universally Unique
  Identifier (UUID) as specified in RFC 4122.

``NVME_NIDT_CSI``
  The NID field contains the command set identifier.




.. c:enum:: nvme_ns_id_desc_nidt_lens

   Namespace Identifier Descriptor Type Lengths

**Constants**

``NVME_NIDT_EUI64_LEN``
  IEEE Extended Unique Identifier length (8 bytes)

``NVME_NIDT_NGUID_LEN``
  Namespace Globally Unique Identifier length (16 bytes)

``NVME_NIDT_UUID_LEN``
  Universally Unique Identifier length (16 bytes)

``NVME_NIDT_CSI_LEN``
  Command Set Identifier length (1 byte)




.. c:struct:: nvme_nvmset_attr

   NVM Set Attributes Entry

**Definition**

::

  struct nvme_nvmset_attr {
    __le16 nvmsetid;
    __le16 endgid;
    __u8 rsvd4[4];
    __le32 rr4kt;
    __le32 ows;
    __u8 tnvmsetcap[16];
    __u8 unvmsetcap[16];
    __u8 rsvd48[80];
  };

**Members**

``nvmsetid``
  NVM Set Identifier

``endgid``
  Endurance Group Identifier

``rsvd4``
  Reserved

``rr4kt``
  Random 4 KiB Read Typical indicates the typical
  time to complete a 4 KiB random read in 100 nanosecond units
  when the NVM Set is in a Predictable Latency Mode Deterministic
  Window and there is 1 outstanding command per NVM Set.

``ows``
  Optimal Write Size

``tnvmsetcap``
  Total NVM Set Capacity

``unvmsetcap``
  Unallocated NVM Set Capacity

``rsvd48``
  Reserved





.. c:struct:: nvme_id_nvmset_list

   NVM set list

**Definition**

::

  struct nvme_id_nvmset_list {
    __u8 nid;
    __u8 rsvd1[127];
    struct nvme_nvmset_attr ent[NVME_ID_NVMSET_LIST_MAX];
  };

**Members**

``nid``
  Nvmset id

``rsvd1``
  Reserved

``ent``
  nvmset id list





.. c:struct:: nvme_id_independent_id_ns

   Identify - I/O Command Set Independent Identify Namespace Data Structure

**Definition**

::

  struct nvme_id_independent_id_ns {
    __u8 nsfeat;
    __u8 nmic;
    __u8 rescap;
    __u8 fpi;
    __le32 anagrpid;
    __u8 nsattr;
    __u8 rsvd9;
    __le16 nvmsetid;
    __le16 endgid;
    __u8 nstat;
    __u8 kpios;
    __le16 maxkt;
    __u8 rsvd18[2];
    __le32 rgrpid;
    __u8 rsvd24[4072];
  };

**Members**

``nsfeat``
  common namespace features

``nmic``
  Namespace Multi-path I/O and Namespace
  Sharing Capabilities

``rescap``
  Reservation Capabilities

``fpi``
  Format Progress Indicator

``anagrpid``
  ANA Group Identifier

``nsattr``
  Namespace Attributes

``rsvd9``
  reserved

``nvmsetid``
  NVM Set Identifier

``endgid``
  Endurance Group Identifier

``nstat``
  Namespace Status

``kpios``
  Key Per I/O Status

``maxkt``
  Maximum Key Tag

``rsvd18``
  Reserved

``rgrpid``
  Reachability Group Identifier

``rsvd24``
  Reserved





.. c:struct:: nvme_id_ns_granularity_desc

   Namespace Granularity Descriptor

**Definition**

::

  struct nvme_id_ns_granularity_desc {
    __le64 nszegran;
    __le64 ncapgran;
  };

**Members**

``nszegran``
  Namespace Size Granularity

``ncapgran``
  Namespace Capacity Granularity





.. c:struct:: nvme_id_ns_granularity_list

   Namespace Granularity List

**Definition**

::

  struct nvme_id_ns_granularity_list {
    __le32 attributes;
    __u8 num_descriptors;
    __u8 rsvd5[27];
    struct nvme_id_ns_granularity_desc entry[NVME_ID_ND_DESCRIPTOR_MAX];
    __u8 rsvd1056[3040];
  };

**Members**

``attributes``
  Namespace Granularity Attributes

``num_descriptors``
  Number of Descriptors

``rsvd5``
  reserved

``entry``
  Namespace Granularity Descriptor

``rsvd1056``
  reserved





.. c:struct:: nvme_id_uuid_list_entry

   UUID List Entry

**Definition**

::

  struct nvme_id_uuid_list_entry {
    __u8 header;
    __u8 rsvd1[15];
    __u8 uuid[16];
  };

**Members**

``header``
  UUID Lists Entry Header

``rsvd1``
  reserved

``uuid``
  128-bit Universally Unique Identifier





.. c:enum:: nvme_id_uuid

   Identifier Association

**Constants**

``NVME_ID_UUID_HDR_ASSOCIATION_SHIFT``

``NVME_ID_UUID_HDR_ASSOCIATION_MASK``

``NVME_ID_UUID_ASSOCIATION_NONE``

``NVME_ID_UUID_ASSOCIATION_VENDOR``

``NVME_ID_UUID_ASSOCIATION_SUBSYSTEM_VENDOR``




.. c:struct:: nvme_id_uuid_list

   UUID list

**Definition**

::

  struct nvme_id_uuid_list {
    __u8 rsvd0[32];
    struct nvme_id_uuid_list_entry entry[NVME_ID_UUID_LIST_MAX];
  };

**Members**

``rsvd0``
  reserved

``entry``
  UUID list entry





.. c:struct:: nvme_underlying_ns_entry

   Underlying Namespace Entry Data Structure

**Definition**

::

  struct nvme_underlying_ns_entry {
    __u8 unsnqn[NVME_NQN_LENGTH];
    __le32 nsid;
    __le16 cntlid;
    __u8 rsvd58[56];
    __le16 idx;
  };

**Members**

``unsnqn``
  Underlying NVM Subsystem NQN (UNSNQN)

``nsid``
  Namespace Identifier (NSID) of the Underlying Namespace

``cntlid``
  Controller ID (CNTLID) of a controller able to attach **nsid**

``rsvd58``
  Reserved

``idx``
  Index (IDX) into the list of reportable Underlying Namespaces





.. c:struct:: nvme_underlying_ns_list

   Underlying Namespace List Data Structure (CNS 1Dh)

**Definition**

::

  struct nvme_underlying_ns_list {
    __le64 genctr;
    __le16 nument;
    __u8 rsvd10[6];
    struct nvme_underlying_ns_entry entries[NVME_UNDERLYING_NS_LIST_MAX];
  };

**Members**

``genctr``
  Generation Counter (GENCTR)

``nument``
  Number Entries (NUMENT)

``rsvd10``
  Reserved

``entries``
  Underlying Namespace list, see :c:type:`struct
  nvme_underlying_ns_entry <nvme_underlying_ns_entry>`. Reportable up to
  ``NVME_UNDERLYING_NS_LIST_MAX`` entries.





.. c:struct:: nvme_fabrics_transport_entry

   Underlying Fabrics Transport Entry Data Structure

**Definition**

::

  struct nvme_fabrics_transport_entry {
    __u8 traddr[NVMF_TRADDR_SIZE];
    __u8 tsas[NVMF_TSAS_SIZE];
    __le16 pidup;
    __u8 trtype;
    __u8 adrfam;
    __u8 treq;
    __u8 rsvd517[59];
  };

**Members**

``traddr``
  Transport Address (TRADDR)

``tsas``
  Transport Specific Address Subtype (TSAS)

``pidup``
  Port ID of the Underlying Port (PIDUP)

``trtype``
  Transport Type (TRTYPE), see :c:type:`enum nvmf_trtype <nvmf_trtype>`

``adrfam``
  Transport Address Family (ADRFAM), see :c:type:`enum nvmf_addr_family <nvmf_addr_family>`

``treq``
  Transport Requirements (TREQ), see :c:type:`enum nvmf_treq <nvmf_treq>`

``rsvd517``
  Reserved





.. c:struct:: nvme_ports_list

   Ports List Data Structure (CNS 1Eh)

**Definition**

::

  struct nvme_ports_list {
    __le64 genctr;
    __le16 nument;
    __u8 rsvd10[6];
    struct nvme_fabrics_transport_entry entries[];
  };

**Members**

``genctr``
  Generation Counter (GENCTR)

``nument``
  Number Entries (NUMENT)

``rsvd10``
  Reserved

``entries``
  Underlying Fabrics Transport Entry list, see :c:type:`struct
  nvme_fabrics_transport_entry <nvme_fabrics_transport_entry>`





.. c:struct:: nvme_supported_ctrl_state_formats

   Supported Controller State Formats Data Structure (CNS 20h)

**Definition**

::

  struct nvme_supported_ctrl_state_formats {
    __u8 nv;
    __u8 nuuid;
    __u8 data[4094];
  };

**Members**

``nv``
  Number of Versions (NV) in the NVMe Controller State Version
  list at the start of **data**

``nuuid``
  Number of UUIDs (NUUID) in the Vendor Specific Controller
  State UUID Supported list, immediately following the NVMe
  Controller State Version list in **data**

``data``
  NVMe Controller State Version list (**nv** :c:type:`__le16` entries)
  immediately followed by the Vendor Specific Controller State
  UUID Supported list (**nuuid** 128-bit UUID entries)





.. c:struct:: nvme_exported_nvm_subsys_template_uuid_list

   Exported NVM Subsystem Template UUID List data structure (CNS 22h)

**Definition**

::

  struct nvme_exported_nvm_subsys_template_uuid_list {
    __u8 rsvd0[16];
    __u8 enst[255][16];
  };

**Members**

``rsvd0``
  Reserved

``enst``
  Exported NVM Subsystem Template UUID list, up to 255 entries,
  listed in ascending order. An entry that is not reserved and
  is cleared to 0h indicates the end of the list.





.. c:struct:: nvme_ctrl_list

   Controller List

**Definition**

::

  struct nvme_ctrl_list {
    __le16 num;
    __le16 identifier[NVME_ID_CTRL_LIST_MAX];
  };

**Members**

``num``
  Number of Identifiers

``identifier``
  NVM subsystem unique controller identifier





.. c:struct:: nvme_ns_list

   Namespace List

**Definition**

::

  struct nvme_ns_list {
    __le32 ns[NVME_ID_NS_LIST_MAX];
  };

**Members**

``ns``
  Namespace Identifier





.. c:enum:: nvme_id_ctrl_nvm_lbamqf

   LBA Migration Queue Format

**Constants**

``NVME_ID_CTRL_NVM_LBAMQF_TYPE_0``

``NVME_ID_CTRL_NVM_LBAMQF_VENDOR_MIN``

``NVME_ID_CTRL_NVM_LBAMQF_VENDOR_MAX``




.. c:enum:: nvme_id_ctrl_nvm_rla

   Rate Limiting Attributes

**Constants**

``NVME_ID_CTRL_NVM_RLA_HLS_SHIFT``
  Shift amount to get Hard Limit Support (HLS)

``NVME_ID_CTRL_NVM_RLA_HLS_MASK``
  Mask to get HLS

``NVME_ID_CTRL_NVM_RLA_SLS_SHIFT``
  Shift amount to get Soft Limit Support (SLS)

``NVME_ID_CTRL_NVM_RLA_SLS_MASK``
  Mask to get SLS




.. c:enum:: nvme_id_ctrl_nvm_kpiocap

   Key Per I/O Capabilities

**Constants**

``NVME_ID_CTRL_NVM_KPIOCAP_KPIOS_SHIFT``
  Shift amount to get Key Per I/O
  Supported (KPIOS)

``NVME_ID_CTRL_NVM_KPIOCAP_KPIOS_MASK``
  Mask to get KPIOS

``NVME_ID_CTRL_NVM_KPIOCAP_KPIOSC_SHIFT``
  Shift amount to get Key Per I/O
  Scope (KPIOSC)

``NVME_ID_CTRL_NVM_KPIOCAP_KPIOSC_MASK``
  Mask to get KPIOSC




.. c:enum:: nvme_id_ctrl_nvm_aocs

   Admin Optional Command Support

**Constants**

``NVME_ID_CTRL_NVM_AOCS_RALBAS_SHIFT``
  Shift amount to get Reporting
  Allocated LBA Supported (RALBAS)

``NVME_ID_CTRL_NVM_AOCS_RALBAS_MASK``
  Mask to get RALBAS




.. c:struct:: nvme_id_ctrl_nvm

   I/O Command Set Specific Identify Controller data structure

**Definition**

::

  struct nvme_id_ctrl_nvm {
    __u8 vsl;
    __u8 wzsl;
    __u8 wusl;
    __u8 dmrl;
    __le32 dmrsl;
    __le64 dmsl;
    __u8 kpiocap;
    __u8 wzdsl;
    __le16 aocs;
    __le32 ver;
    __u8 lbamqf;
    __u8 rla;
    __le16 slmc;
    __u8 rsvd28[4068];
  };

**Members**

``vsl``
  Verify Size Limit

``wzsl``
  Write Zeroes Size Limit

``wusl``
  Write Uncorrectable Size Limit

``dmrl``
  Dataset Management Ranges Limit

``dmrsl``
  Dataset Management Range Size Limit

``dmsl``
  Dataset Management Size Limit

``kpiocap``
  Key Per I/O Capabilities

``wzdsl``
  Write Zeroes With Deallocate Size Limit

``aocs``
  Admin Optional Command Support

``ver``
  Version

``lbamqf``
  LBA Migration Queue Format

``rla``
  Rate Limiting Attributes, see :c:type:`enum nvme_id_ctrl_nvm_rla <nvme_id_ctrl_nvm_rla>`

``slmc``
  Soft Limit Maximum Controllers (0's based), valid only if SLS is set

``rsvd28``
  Reserved





.. c:enum:: nvme_primary_ctrl_cap_crt

   Controller Resource Types

**Constants**

``NVME_PRIMARY_CTRL_CAP_CRT_VQRS_SHIFT``
  Shift amount to get VQRS

``NVME_PRIMARY_CTRL_CAP_CRT_VQRS_MASK``
  Mask to get VQRS

``NVME_PRIMARY_CTRL_CAP_CRT_VIRS_SHIFT``
  Shift amount to get VIRS

``NVME_PRIMARY_CTRL_CAP_CRT_VIRS_MASK``
  Mask to get VIRS

``NVME_PRIMARY_CTRL_CAP_CRT_RSVD_SHIFT``
  Shift amount to get Reserved

``NVME_PRIMARY_CTRL_CAP_CRT_RSVD_MASK``
  Mask to get Reserved




.. c:struct:: nvme_primary_ctrl_cap

   Identify - Controller Capabilities Structure

**Definition**

::

  struct nvme_primary_ctrl_cap {
    __le16 cntlid;
    __le16 portid;
    __u8 crt;
    __u8 rsvd5[27];
    __le32 vqfrt;
    __le32 vqrfa;
    __le16 vqrfap;
    __le16 vqprt;
    __le16 vqfrsm;
    __le16 vqgran;
    __u8 rsvd48[16];
    __le32 vifrt;
    __le32 virfa;
    __le16 virfap;
    __le16 viprt;
    __le16 vifrsm;
    __le16 vigran;
    __u8 rsvd80[4016];
  };

**Members**

``cntlid``
  Controller Identifier

``portid``
  Port Identifier

``crt``
  Controller Resource Types

``rsvd5``
  reserved

``vqfrt``
  VQ Resources Flexible Total

``vqrfa``
  VQ Resources Flexible Assigned

``vqrfap``
  VQ Resources Flexible Allocated to Primary

``vqprt``
  VQ Resources Private Total

``vqfrsm``
  VQ Resources Flexible Secondary Maximum

``vqgran``
  VQ Flexible Resource Preferred Granularity

``rsvd48``
  reserved

``vifrt``
  VI Resources Flexible Total

``virfa``
  VI Resources Flexible Assigned

``virfap``
  VI Resources Flexible Allocated to Primary

``viprt``
  VI Resources Private Total

``vifrsm``
  VI Resources Flexible Secondary Maximum

``vigran``
  VI Flexible Resource Preferred Granularity

``rsvd80``
  reserved





.. c:struct:: nvme_secondary_ctrl

   Secondary Controller Entry

**Definition**

::

  struct nvme_secondary_ctrl {
    __le16 scid;
    __le16 pcid;
    __u8 scs;
    __u8 rsvd5[3];
    __le16 vfn;
    __le16 nvq;
    __le16 nvi;
    __u8 rsvd14[18];
  };

**Members**

``scid``
  Secondary Controller Identifier

``pcid``
  Primary Controller Identifier

``scs``
  Secondary Controller State

``rsvd5``
  Reserved

``vfn``
  Virtual Function Number

``nvq``
  Number of VQ Flexible Resources Assigned

``nvi``
  Number of VI Flexible Resources Assigned

``rsvd14``
  Reserved





.. c:struct:: nvme_secondary_ctrl_list

   Secondary Controller List

**Definition**

::

  struct nvme_secondary_ctrl_list {
    __u8 num;
    __u8 rsvd[31];
    struct nvme_secondary_ctrl sc_entry[NVME_ID_SECONDARY_CTRL_MAX];
  };

**Members**

``num``
  Number of Identifiers

``rsvd``
  Reserved

``sc_entry``
  Secondary Controller Entry





.. c:struct:: nvme_id_iocs

   NVMe Identify IO Command Set data structure

**Definition**

::

  struct nvme_id_iocs {
    __le64 iocsc[512];
  };

**Members**

``iocsc``
  List of supported IO Command Set Combination vectors





.. c:struct:: nvme_id_domain_attr

   Domain Attributes Entry

**Definition**

::

  struct nvme_id_domain_attr {
    __le16 dom_id;
    __u8 rsvd2[14];
    __u8 dom_cap[16];
    __u8 unalloc_dom_cap[16];
    __u8 max_egrp_dom_cap[16];
    __u8 rsvd64[64];
  };

**Members**

``dom_id``
  Domain Identifier

``rsvd2``
  Reserved

``dom_cap``
  Total Domain Capacity

``unalloc_dom_cap``
  Unallocated Domain Capacity

``max_egrp_dom_cap``
  Max Endurance Group Domain Capacity

``rsvd64``
  Reserved





.. c:struct:: nvme_id_domain_list

   Domain List

**Definition**

::

  struct nvme_id_domain_list {
    __u8 num;
    __u8 rsvd[127];
    struct nvme_id_domain_attr domain_attr[NVME_ID_DOMAIN_LIST_MAX];
  };

**Members**

``num``
  Number of domain attributes

``rsvd``
  Reserved

``domain_attr``
  List of domain attributes





.. c:struct:: nvme_id_endurance_group_list

   Endurance Group List

**Definition**

::

  struct nvme_id_endurance_group_list {
    __le16 num;
    __le16 identifier[NVME_ID_ENDURANCE_GROUP_LIST_MAX];
  };

**Members**

``num``
  Number of Identifiers

``identifier``
  Endurance Group Identifier





.. c:struct:: nvme_supported_log_pages

   Supported Log Pages - Log

**Definition**

::

  struct nvme_supported_log_pages {
    __le32 lid_support[NVME_LOG_SUPPORTED_LOG_PAGES_MAX];
  };

**Members**

``lid_support``
  Log Page Identifier Supported


**Description**

Supported Log Pages (Log Identifier 00h)




.. c:struct:: nvme_error_log_page

   Error Information Log Entry (Log Identifier 01h)

**Definition**

::

  struct nvme_error_log_page {
    __le64 error_count;
    __le16 sqid;
    __le16 cmdid;
    __le16 status_field;
    __le16 parm_error_location;
    __le64 lba;
    __le32 nsid;
    __u8 vs;
    __u8 trtype;
    __u8 csi;
    __u8 opcode;
    __le64 cs;
    __le16 trtype_spec_info;
    __u8 rsvd[21];
    __u8 log_page_version;
  };

**Members**

``error_count``
  Error Count: a 64-bit incrementing error count,
  indicating a unique identifier for this error. The error
  count starts at ``1h``, is incremented for each unique error
  log entry, and is retained across power off conditions.
  A value of ``0h`` indicates an invalid entry; this value
  is used when there are lost entries or when there are
  fewer errors than the maximum number of entries the
  controller supports. If the value of this field is
  ``FFFFFFFFh``, then the field shall be set to 1h when
  incremented (i.e., rolls over to ``1h``). Prior to NVMe
  1.4, processing of incrementing beyond ``FFFFFFFFh`` is
  unspecified.

``sqid``
  Submission Queue ID: indicates the Submission Queue
  Identifier of the command that the error information is
  associated with. If the error is not specific to
  a particular command, then this field shall be set to
  ``FFFFh``.

``cmdid``
  Command ID: indicates the Command Identifier of the
  command that the error is associated with. If the error
  is not specific to a particular command, then this field
  shall be set to ``FFFFh``.

``status_field``
  Bits 15-1: Status Field: indicates the Status Field for
  the command that completed. If the error is not specific
  to a particular command, then this field reports the most
  applicable status value.
  Bit 0: Phase Tag: may indicate the Phase Tag posted for
  the command.

``parm_error_location``
  Parameter Error Location: indicates the byte and bit of
  the command parameter that the error is associated with,
  if applicable. If the parameter spans multiple bytes or
  bits, then the location indicates the first byte and bit
  of the parameter.
  Bits 10-8: Bit in command that contained the error.
  Valid values are 0 to 7.
  Bits 7-0: Byte in command that contained the error.
  Valid values are 0 to 63.

``lba``
  LBA: This field indicates the first LBA that experienced
  the error condition, if applicable.

``nsid``
  Namespace: This field indicates the NSID of the namespace
  that the error is associated with, if applicable.

``vs``
  Vendor Specific Information Available: If there is
  additional vendor specific error information available,
  this field provides the log page identifier associated
  with that page. A value of ``0h`` indicates that no additional
  information is available. Valid values are in the range
  of ``80h`` to ``FFh``.

``trtype``
  Transport Type (TRTYPE): indicates the Transport Type of
  the transport associated with the error. The values in
  this field are the same as the TRTYPE values in the
  Discovery Log Page Entry. If the error is not transport
  related, this field shall be cleared to ``0h``. If the error
  is transport related, this field shall be set to the type
  of the transport - see :c:type:`enum nvme_trtype <nvme_trtype>`.

``csi``
  Command Set Indicator: This field contains command set
  indicator for the command that the error is associated
  with.

``opcode``
  Opcode: This field contains opcode for the command that
  the error is associated with.

``cs``
  Command Specific Information: This field contains command
  specific information. If used, the command definition
  specifies the information returned.

``trtype_spec_info``
  Transport Type Specific Information

``rsvd``
  Reserved: [62:42]

``log_page_version``
  This field shall be set to 1h. If set, **csi** and **opcode**
  will have valid values.





.. c:enum:: nvme_err_pel

   Parameter error location field

**Constants**

``NVME_ERR_PEL_BYTE_SHIFT``
  Byte location shift

``NVME_ERR_PEL_BYTE_MASK``
  Byte mask for error location

``NVME_ERR_PEL_BIT_SHIFT``
  Bit location shift

``NVME_ERR_PEL_BIT_MASK``
  Bit mask for error location




.. c:enum:: nvme_err_status_field

   This field indicates the error information log entry status field

**Constants**

``NVME_ERR_SF_PHASE_TAG_SHIFT``
  Shift amount to get the phase tag

``NVME_ERR_SF_STATUS_FIELD_SHIFT``
  Shift amount to get the status field

``NVME_ERR_SF_PHASE_TAG_MASK``
  Mask to get the phase tag

``NVME_ERR_SF_STATUS_FIELD_MASK``
  Mask to get the status field




.. c:struct:: nvme_smart_log

   SMART / Health Information Log (Log Identifier 02h)

**Definition**

::

  struct nvme_smart_log {
    __u8 critical_warning;
    __u8 temperature[2];
    __u8 avail_spare;
    __u8 spare_thresh;
    __u8 percent_used;
    __u8 endu_grp_crit_warn_sumry;
    __u8 informative_warning;
    __u8 rsvd8[24];
    __u8 data_units_read[16];
    __u8 data_units_written[16];
    __u8 host_reads[16];
    __u8 host_writes[16];
    __u8 ctrl_busy_time[16];
    __u8 power_cycles[16];
    __u8 power_on_hours[16];
    __u8 unsafe_shutdowns[16];
    __u8 media_errors[16];
    __u8 num_err_log_entries[16];
    __le32 warning_temp_time;
    __le32 critical_comp_time;
    __le16 temp_sensor[8];
    __le32 thm_temp1_trans_count;
    __le32 thm_temp2_trans_count;
    __le32 thm_temp1_total_time;
    __le32 thm_temp2_total_time;
    __le64 op_lifetime_energy_consumed;
    __le32 interval_power_measurement;
    __u8 rsvd244[268];
  };

**Members**

``critical_warning``
  This field indicates critical warnings for the state
  of the controller. Critical warnings may result in an
  asynchronous event notification to the host. Bits in
  this field represent the current associated state and
  are not persistent (see :c:type:`enum nvme_smart_crit <nvme_smart_crit>`).

``temperature``
  Composite Temperature: Contains a value corresponding
  to a temperature in Kelvins that represents the current
  composite temperature of the controller and namespace(s)
  associated with that controller. The manner in which
  this value is computed is implementation specific and
  may not represent the actual temperature of any physical
  point in the NVM subsystem. Warning and critical
  overheating composite temperature threshold values are
  reported by the WCTEMP and CCTEMP fields in the Identify
  Controller data structure.

``avail_spare``
  Available Spare: Contains a normalized percentage (0%
  to 100%) of the remaining spare capacity available.

``spare_thresh``
  Available Spare Threshold: When the Available Spare
  falls below the threshold indicated in this field, an
  asynchronous event completion may occur. The value is
  indicated as a normalized percentage (0% to 100%).
  The values 101 to 255 are reserved.

``percent_used``
  Percentage Used: Contains a vendor specific estimate
  of the percentage of NVM subsystem life used based on
  the actual usage and the manufacturer's prediction of
  NVM life. A value of 100 indicates that the estimated
  endurance of the NVM in the NVM subsystem has been
  consumed, but may not indicate an NVM subsystem failure.
  The value is allowed to exceed 100. Percentages greater
  than 254 shall be represented as 255. This value shall
  be updated once per power-on hour (when the controller
  is not in a sleep state).

``endu_grp_crit_warn_sumry``
  Endurance Group Critical Warning Summary: This field
  indicates critical warnings for the state of Endurance
  Groups. Bits in this field represent the current associated
  state and are not persistent (see :c:type:`enum nvme_smart_egcw <nvme_smart_egcw>`).

``informative_warning``
  Informative Warning: This field indicates warnings
  that the host may choose to act upon. Bits in this
  field are not persistent, see :c:type:`enum
  nvme_smart_infw <nvme_smart_infw>`.

``rsvd8``
  Reserved

``data_units_read``
  Data Units Read: Contains the number of 512 byte data
  units the host has read from the controller; this value
  does not include metadata. This value is reported in
  thousands (i.e., a value of 1 corresponds to 1000
  units of 512 bytes read) and is rounded up (e.g., one
  indicates the that number of 512 byte data units read
  is from 1 to 1000, three indicates that the number of
  512 byte data units read is from 2001 to 3000). When
  the LBA size is a value other than 512 bytes, the
  controller shall convert the amount of data read to
  512 byte units. For the NVM command set, logical blocks
  read as part of Compare, Read, and Verify operations
  shall be included in this value. A value of ``0h`` in
  this field indicates that the number of Data Units Read
  is not reported.

``data_units_written``
  Data Units Written: Contains the number of 512 byte
  data units the host has written to the controller;
  this value does not include metadata. This value is
  reported in thousands (i.e., a value of 1 corresponds
  to 1000 units of 512 bytes written) and is rounded up
  (e.g., one indicates that the number of 512 byte data
  units written is from 1 to 1,000, three indicates that
  the number of 512 byte data units written is from 2001
  to 3000). When the LBA size is a value other than 512
  bytes, the controller shall convert the amount of data
  written to 512 byte units. For the NVM command set,
  logical blocks written as part of Write operations shall
  be included in this value. Write Uncorrectable commands
  and Write Zeroes commands shall not impact this value.
  A value of ``0h`` in this field indicates that the number
  of Data Units Written is not reported.

``host_reads``
  Host Read Commands: Contains the number of read commands
  completed by the controller. For the NVM command set,
  this value is the sum of the number of Compare commands
  and the number of Read commands.

``host_writes``
  Host Write Commands: Contains the number of write
  commands completed by the controller. For the NVM
  command set, this is the number of Write commands.

``ctrl_busy_time``
  Controller Busy Time: Contains the amount of time the
  controller is busy with I/O commands. The controller
  is busy when there is a command outstanding to an I/O
  Queue (specifically, a command was issued via an I/O
  Submission Queue Tail doorbell write and the corresponding
  completion queue entry has not been posted yet to the
  associated I/O Completion Queue). This value is
  reported in minutes.

``power_cycles``
  Power Cycles: Contains the number of power cycles.

``power_on_hours``
  Power On Hours: Contains the number of power-on hours.
  This may not include time that the controller was
  powered and in a non-operational power state.

``unsafe_shutdowns``
  Unsafe Shutdowns: Contains the number of unsafe
  shutdowns. This count is incremented when a Shutdown
  Notification (CC.SHN) is not received prior to loss of power.

``media_errors``
  Media and Data Integrity Errors: Contains the number
  of occurrences where the controller detected an
  unrecovered data integrity error. Errors such as
  uncorrectable ECC, CRC checksum failure, or LBA tag
  mismatch are included in this field. Errors introduced
  as a result of a Write Uncorrectable command may or
  may not be included in this field.

``num_err_log_entries``
  Number of Error Information Log Entries: Contains the
  number of Error Information log entries over the life
  of the controller.

``warning_temp_time``
  Warning Composite Temperature Time: Contains the amount
  of time in minutes that the controller is operational
  and the Composite Temperature is greater than or equal
  to the Warning Composite Temperature Threshold (WCTEMP)
  field and less than the Critical Composite Temperature
  Threshold (CCTEMP) field in the Identify Controller
  data structure. If the value of the WCTEMP or CCTEMP
  field is ``0h``, then this field is always cleared to ``0h``
  regardless of the Composite Temperature value.

``critical_comp_time``
  Critical Composite Temperature Time: Contains the amount
  of time in minutes that the controller is operational
  and the Composite Temperature is greater than or equal
  to the Critical Composite Temperature Threshold (CCTEMP)
  field in the Identify Controller data structure. If
  the value of the CCTEMP field is ``0h``, then this field
  is always cleared to 0h regardless of the Composite
  Temperature value.

``temp_sensor``
  Temperature Sensor 1-8: Contains the current temperature
  in degrees Kelvin reported by temperature sensors 1-8.
  The physical point in the NVM subsystem whose temperature
  is reported by the temperature sensor and the temperature
  accuracy is implementation specific. An implementation
  that does not implement the temperature sensor reports
  a value of ``0h``.

``thm_temp1_trans_count``
  Thermal Management Temperature 1 Transition Count:
  Contains the number of times the controller transitioned
  to lower power active power states or performed vendor
  specific thermal management actions while minimizing
  the impact on performance in order to attempt to reduce
  the Composite Temperature because of the host controlled
  thermal management feature (i.e., the Composite
  Temperature rose above the Thermal Management
  Temperature 1). This counter shall not wrap once the
  value ``FFFFFFFFh`` is reached. A value of ``0h``, indicates
  that this transition has never occurred or this field
  is not implemented.

``thm_temp2_trans_count``
  Thermal Management Temperature 2 Transition Count

``thm_temp1_total_time``
  Total Time For Thermal Management Temperature 1:
  Contains the number of seconds that the controller
  had transitioned to lower power active power states or
  performed vendor specific thermal management actions
  while minimizing the impact on performance in order to
  attempt to reduce the Composite Temperature because of
  the host controlled thermal management feature. This
  counter shall not wrap once the value ``FFFFFFFFh`` is
  reached. A value of ``0h``, indicates that this transition
  has never occurred or this field is not implemented.

``thm_temp2_total_time``
  Total Time For Thermal Management Temperature 2

``op_lifetime_energy_consumed``
  Operational Lifetime Energy Consumed: Contains
  the cumulative operational energy consumed by the NVM
  subsystem in watt-hours calculated from all interval
  power measurements collected from the time of
  manufacture to the point that this log page is read.
  This value is rounded up (e.g., two indicates the
  number of watt-hours consumed is greater than 1 and
  less than or equal to 2). This field shall not wrap
  once the value ``FFFFFFFFFFFFFFFFh`` is reached. A value
  of ``0h`` indicates that the cumulative operational energy
  consumed is not reported.

``interval_power_measurement``
  Interval Power Measurement: Contains the average
  of power measurement samples over the most recent one
  second interval at the time of processing the Get Log
  Page command. The power in Watts is equal to the
  Interval Power Measurement Value (bits 15:0) multiplied
  by the scale indicated in the Interval Power Measurement
  Scale field (bits 17:16). A value of ``0h`` indicates that
  the interval power measurement is not reported.

``rsvd244``
  Reserved





.. c:enum:: nvme_smart_crit

   Critical Warning

**Constants**

``NVME_SMART_CW_ASCBT_SHIFT``
  Shift amount to get the available spare capacity has fallen
  below the threshold.

``NVME_SMART_CW_TTC_SHIFT``
  Shift amount to get the temperature is either greater
  than or equal to an over temperature threshold; or
  less than or equal to an under temperature threshold.

``NVME_SMART_CW_NDR_SHIFT``
  Shift amount to get the NVM subsystem reliability has
  been degraded due to significant media related errors
  or any internal error that degrades NVM subsystem
  reliability.

``NVME_SMART_CW_AMRO_SHIFT``
  Shift amount to get the all of the media has been placed in read
  only mode. The controller shall not set this bit if
  the read-only condition on the media is a result of
  a change in the write protection state of a namespace.

``NVME_SMART_CW_VMBF_SHIFT``
  Shift amount to get the  volatile memory backup
  device has failed. This field is only valid if the
  controller has a volatile memory backup solution.

``NVME_SMART_CW_PMRRO_SHIFT``
  Shift amount to get the Persistent Memory Region has become
  read-only or unreliable.

``NVME_SMART_CW_IPS_SHIFT``
  Shift amount to get the indeterminate Personality
  State.

``NVME_SMART_CW_ASCBT_MASK``
  If set, then the available spare capacity has fallen
  below the threshold.

``NVME_SMART_CW_TTC_MASK``
  Mask to get the temperature is either greater
  than or equal to an over temperature threshold; or
  less than or equal to an under temperature threshold.

``NVME_SMART_CW_NDR_MASK``
  Mask to get the NVM subsystem reliability has
  been degraded due to significant media related errors
  or any internal error that degrades NVM subsystem
  reliability.

``NVME_SMART_CW_AMRO_MASK``
  Mask to get the all of the media has been placed in read
  only mode. The controller shall not set this bit if
  the read-only condition on the media is a result of
  a change in the write protection state of a namespace.

``NVME_SMART_CW_VMBF_MASK``
  Mask to get the volatile memory backup
  device has failed. This field is only valid if the
  controller has a volatile memory backup solution.

``NVME_SMART_CW_PMRRO_MASK``
  Mask to get the Persistent Memory Region has become
  read-only or unreliable.

``NVME_SMART_CW_IPS_MASK``
  Mask to get the indeterminate Personality State.

``NVME_SMART_CRIT_SPARE``
  If set, then the available spare capacity has fallen
  below the threshold.

``NVME_SMART_CRIT_TEMPERATURE``
  If set, then a temperature is either greater
  than or equal to an over temperature threshold; or
  less than or equal to an under temperature threshold.

``NVME_SMART_CRIT_DEGRADED``
  If set, then the NVM subsystem reliability has
  been degraded due to significant media related errors
  or any internal error that degrades NVM subsystem
  reliability.

``NVME_SMART_CRIT_MEDIA``
  If set, then all of the media has been placed in read
  only mode. The controller shall not set this bit if
  the read-only condition on the media is a result of
  a change in the write protection state of a namespace.

``NVME_SMART_CRIT_VOLATILE_MEMORY``
  If set, then the volatile memory backup
  device has failed. This field is only valid if the
  controller has a volatile memory backup solution.

``NVME_SMART_CRIT_PMR_RO``
  If set, then the Persistent Memory Region has become
  read-only or unreliable.

``NVME_SMART_CRIT_INDETERMINATE_PERSONALITY``
  If set, then a requested change
  to the settings of a Configurable Device Personality
  did not complete successfully and the controller was
  not able to revert to the previous settings of that
  personality.




.. c:enum:: nvme_smart_egcw

   Endurance Group Critical Warning Summary

**Constants**

``NVME_SMART_EGCW_SPARE``
  If set, then the available spare capacity of one or
  more Endurance Groups has fallen below the threshold.

``NVME_SMART_EGCW_DEGRADED``
  If set, then the reliability of one or more
  Endurance Groups has been degraded due to significant
  media related errors or any internal error that
  degrades NVM subsystem reliability.

``NVME_SMART_EGCW_RO``
  If set, then the namespaces in one or more Endurance
  Groups have been placed in read only mode not as
  a result of a change in the write protection state
  of a namespace.




.. c:enum:: nvme_smart_infw

   Informative Warning

**Constants**

``NVME_SMART_INFW_VLTHW``
  Voltage Log Threshold Warning: if set, then the
  Overvoltage Valid (OVV) bit or the Undervoltage
  Valid (UVV) bit in the Voltage Measurement log
  page is set to '1'.




.. c:enum:: nvme_voltage_sensor

   Voltage Sensors

**Constants**

``NVME_VOLTAGE_SENSOR_1``
  Voltage Sensor 1 (VSEN1)

``NVME_VOLTAGE_SENSOR_2``
  Voltage Sensor 2 (VSEN2)

``NVME_VOLTAGE_SENSOR_3``
  Voltage Sensor 3 (VSEN3)

``NVME_VOLTAGE_SENSOR_4``
  Voltage Sensor 4 (VSEN4)




.. c:enum:: nvme_voltage_threshold_type

   Voltage Threshold Type

**Constants**

``NVME_VOLTAGE_THRESHOLD_TYPE_OVERVOLTAGE``
  Overvoltage Threshold

``NVME_VOLTAGE_THRESHOLD_TYPE_UNDERVOLTAGE``
  Undervoltage Threshold




.. c:enum:: nvme_id_ctrl_vsen

   Identify Controller Voltage Sensor data structure (VSEN1-VSEN4)

**Constants**

``NVME_CTRL_VSEN_VSRV_SHIFT``
  Shift amount to get the Voltage Sample Rate
  Value (VSRV)

``NVME_CTRL_VSEN_VSRV_MASK``
  Mask to get VSRV

``NVME_CTRL_VSEN_VSRS_SHIFT``
  Shift amount to get the Voltage Sample Rate
  Scale (VSRS)

``NVME_CTRL_VSEN_VSRS_MASK``
  Mask to get VSRS

``NVME_CTRL_VSEN_VOLSS_SHIFT``
  Shift amount to get the Voltage Sample Scale
  (VOLSS)

``NVME_CTRL_VSEN_VOLSS_MASK``
  Mask to get VOLSS

``NVME_CTRL_VSEN_PISL_SHIFT``
  Shift amount to get the Power Input Supply
  Label (PISL)

``NVME_CTRL_VSEN_PISL_MASK``
  Mask to get PISL

``NVME_CTRL_VSEN_PISV_SHIFT``
  Shift amount to get the Power Input Supply
  Value (PISV), in units of 0.05 V

``NVME_CTRL_VSEN_PISV_MASK``
  Mask to get PISV




.. c:enum:: nvme_voltage_measurement_vma

   Voltage Measurement log page - Voltage Measurement Attributes (VMA)

**Constants**

``NVME_VOLTAGE_MEASUREMENT_VMA_VME``
  Voltage Measurement Enable

``NVME_VOLTAGE_MEASUREMENT_VMA_IVOLTS``
  Interval Voltage Timestamp
  Support

``NVME_VOLTAGE_MEASUREMENT_VMA_VSM_SHIFT``
  Shift amount to get the
  Voltage Sensor Measured (VSM),
  see :c:type:`enum nvme_voltage_sensor <nvme_voltage_sensor>`

``NVME_VOLTAGE_MEASUREMENT_VMA_VSM_MASK``
  Mask to get VSM

``NVME_VOLTAGE_MEASUREMENT_VMA_VMC``
  Voltage Measurement Counted




.. c:enum:: nvme_voltage_measurement_vsi

   Voltage Measurement log page - Voltage Sensor Info (VSI)

**Constants**

``NVME_VOLTAGE_MEASUREMENT_VSI_VSSV_SHIFT``
  Shift amount to get the Voltage
  Sensor Supply Value (VSSV), in
  units of 0.05 V

``NVME_VOLTAGE_MEASUREMENT_VSI_VSSV_MASK``
  Mask to get VSSV

``NVME_VOLTAGE_MEASUREMENT_VSI_VSSL_SHIFT``
  Shift amount to get the Voltage
  Sensor Supply Label (VSSL)

``NVME_VOLTAGE_MEASUREMENT_VSI_VSSL_MASK``
  Mask to get VSSL

``NVME_VOLTAGE_MEASUREMENT_VSI_VSSS_SHIFT``
  Shift amount to get the Voltage
  Sensor Sample Scale (VSSS)

``NVME_VOLTAGE_MEASUREMENT_VSI_VSSS_MASK``
  Mask to get VSSS




.. c:enum:: nvme_voltage_measurement_ovol

   Voltage Measurement log page - Overvoltage (OVOL)

**Constants**

``NVME_VOLTAGE_MEASUREMENT_OVOL_MOVV_SHIFT``
  Shift amount to get the
  Maximum Overvoltage Value (MOVV)

``NVME_VOLTAGE_MEASUREMENT_OVOL_MOVV_MASK``
  Mask to get MOVV

``NVME_VOLTAGE_MEASUREMENT_OVOL_OVV``
  Overvoltage Valid




.. c:enum:: nvme_voltage_measurement_uvol

   Voltage Measurement log page - Undervoltage (UVOL)

**Constants**

``NVME_VOLTAGE_MEASUREMENT_UVOL_MUVV_SHIFT``
  Shift amount to get the
  Minimum Undervoltage Value
  (MUVV)

``NVME_VOLTAGE_MEASUREMENT_UVOL_MUVV_MASK``
  Mask to get MUVV

``NVME_VOLTAGE_MEASUREMENT_UVOL_UVV``
  Undervoltage Valid




.. c:enum:: nvme_voltage_measurement_ivmd

   Voltage Measurement log page - Interval Voltage Measurement Descriptor (IVMD)

**Constants**

``NVME_VOLTAGE_MEASUREMENT_IVMD_VOLV_SHIFT``
  Shift amount to get the Voltage
  Value (VOLV)

``NVME_VOLTAGE_MEASUREMENT_IVMD_VOLV_MASK``
  Mask to get VOLV

``NVME_VOLTAGE_MEASUREMENT_IVMD_NCVM``
  Non Contiguous Voltage
  Measurement




.. c:enum:: nvme_voltage_measurement_lvolta

   Start Voltage Measurements Data Structure - Log Voltage Threshold Attributes (LVOLTA)

**Constants**

``NVME_VOLTAGE_MEASUREMENT_LVOLTA_VSSEL_SHIFT``
  Shift amount to get the
  Voltage Sensor Selected
  (VSSEL), see :c:type:`enum
  nvme_voltage_sensor <nvme_voltage_sensor>`

``NVME_VOLTAGE_MEASUREMENT_LVOLTA_VSSEL_MASK``
  Mask to get VSSEL

``NVME_VOLTAGE_MEASUREMENT_LVOLTA_VMLT``
  Voltage Measurement Log
  Threshold




.. c:enum:: nvme_voltage_measurement_lvolt

   Start Voltage Measurements Data Structure - Log Voltage Threshold (LVOLT)

**Constants**

``NVME_VOLTAGE_MEASUREMENT_LVOLT_LUVT_SHIFT``
  Shift amount to get the Log
  Undervoltage Threshold (LUVT)

``NVME_VOLTAGE_MEASUREMENT_LVOLT_LUVT_MASK``
  Mask to get LUVT

``NVME_VOLTAGE_MEASUREMENT_LVOLT_LOVT_SHIFT``
  Shift amount to get the Log
  Overvoltage Threshold (LOVT)

``NVME_VOLTAGE_MEASUREMENT_LVOLT_LOVT_MASK``
  Mask to get LOVT




.. c:struct:: nvme_voltage_measurement_start_data

   Start Voltage Measurements Data Structure

**Definition**

::

  struct nvme_voltage_measurement_start_data {
    __le16 lvolta;
    __le16 svmt;
    __le32 lvolt;
    __u8 rsvd8[4088];
  };

**Members**

``lvolta``
  Log Voltage Threshold Attributes, see :c:type:`enum
  nvme_voltage_measurement_lvolta <nvme_voltage_measurement_lvolta>`.

``svmt``
  Stop Voltage Measurement Time, in minutes. A value of 0h
  specifies no stop measurement time value.

``lvolt``
  Log Voltage Threshold, see :c:type:`enum nvme_voltage_measurement_lvolt <nvme_voltage_measurement_lvolt>`.
  Ignored if the VMLT bit is cleared to '0' in **lvolta**.

``rsvd8``
  Reserved





.. c:enum:: nvme_aer_one_shot

   Asynchronous Event Information - One Shot

**Constants**

``NVME_AER_ONE_SHOT_VOLTAGE_THRESHOLD_EVENT``
  Voltage Threshold Event: the
  interval voltage measurement crossed one of the voltage thresholds
  configured by the Voltage Threshold feature, see :c:type:`enum
  nvme_aer_voltage_threshold_event <nvme_aer_voltage_threshold_event>` for the Event Specific Parameter
  field format.




.. c:enum:: nvme_aer_voltage_threshold_event

   Voltage Threshold Event - Event Specific Parameter

**Constants**

``NVME_AER_VOLTAGE_THRESHOLD_EVENT_IVM_SHIFT``
  Shift amount to get the
  Interval Voltage
  Measurement (IVM)

``NVME_AER_VOLTAGE_THRESHOLD_EVENT_IVM_MASK``
  Mask to get IVM

``NVME_AER_VOLTAGE_THRESHOLD_EVENT_VTHT_SHIFT``
  Shift amount to get the
  Voltage Threshold Type
  (VTHT), see :c:type:`enum
  nvme_voltage_threshold_type <nvme_voltage_threshold_type>`

``NVME_AER_VOLTAGE_THRESHOLD_EVENT_VTHT_MASK``
  Mask to get VTHT

``NVME_AER_VOLTAGE_THRESHOLD_EVENT_VSENT_SHIFT``
  Shift amount to get the
  Voltage Sensor Triggered
  (VSENT), see :c:type:`enum
  nvme_voltage_sensor <nvme_voltage_sensor>`

``NVME_AER_VOLTAGE_THRESHOLD_EVENT_VSENT_MASK``
  Mask to get VSENT




.. c:struct:: nvme_firmware_slot

   Firmware Slot Information Log

**Definition**

::

  struct nvme_firmware_slot {
    __u8 afi;
    __u8 rsvd1[7];
    char frs[7][8];
    __u8 rsvd2[448];
  };

**Members**

``afi``
  Active Firmware Info

``rsvd1``
  Reserved

``frs``
  Firmware Revision for Slot

``rsvd2``
  Reserved





.. c:struct:: nvme_cmd_effects_log

   Commands Supported and Effects Log

**Definition**

::

  struct nvme_cmd_effects_log {
    __le32 acs[256];
    __le32 iocs[256];
    __u8 rsvd[2048];
  };

**Members**

``acs``
  Admin Command Supported

``iocs``
  I/O Command Supported

``rsvd``
  Reserved





.. c:enum:: nvme_cmd_effects

   Commands Supported and Effects

**Constants**

``NVME_CMD_EFFECTS_CSUPP``
  Command Supported

``NVME_CMD_EFFECTS_LBCC``
  Logical Block Content Change

``NVME_CMD_EFFECTS_NCC``
  Namespace Capability Change

``NVME_CMD_EFFECTS_NIC``
  Namespace Inventory Change

``NVME_CMD_EFFECTS_CCC``
  Controller Capability Change

``NVME_CMD_EFFECTS_CSER_SHIFT``
  Command submission and execution relaxations
  shift

``NVME_CMD_EFFECTS_CSER_MASK``
  Command Submission and Execution Relaxations

``NVME_CMD_EFFECTS_CSE_SHIFT``
  Command submission and execution shift

``NVME_CMD_EFFECTS_CSE_MASK``
  Command Submission and Execution

``NVME_CMD_EFFECTS_UUID_SEL``
  UUID Selection Supported




.. c:struct:: nvme_st_result

   Self-test Result

**Definition**

::

  struct nvme_st_result {
    __u8 dsts;
    __u8 seg;
    __u8 vdi;
    __u8 rsvd;
    __le64 poh;
    __le32 nsid;
    __le64 flba;
    __u8 sct;
    __u8 sc;
    __u8 vs[2];
  };

**Members**

``dsts``
  Device Self-test Status: Indicates the device self-test code and the
  status of the operation (see :c:type:`enum nvme_status_result <nvme_status_result>` and :c:type:`enum nvme_st_code <nvme_st_code>`).

``seg``
  Segment Number: Iindicates the segment number where the first self-test
  failure occurred. If Device Self-test Status (**dsts**) is not set to
  #NVME_ST_RESULT_KNOWN_SEG_FAIL, then this field should be ignored.

``vdi``
  Valid Diagnostic Information: Indicates the diagnostic failure
  information that is reported. See :c:type:`enum nvme_st_valid_diag_info <nvme_st_valid_diag_info>`.

``rsvd``
  Reserved

``poh``
  Power On Hours (POH): Indicates the number of power-on hours at the
  time the device self-test operation was completed or aborted. This
  does not include time that the controller was powered and in a low
  power state condition.

``nsid``
  Namespace Identifier (NSID): Indicates the namespace that the Failing
  LBA occurred on. Valid only when the NSID Valid bit
  (#NVME_ST_VALID_DIAG_INFO_NSID) is set in the Valid Diagnostic
  Information (**vdi**) field.

``flba``
  Failing LBA: indicates the LBA of the logical block that caused the
  test to fail. If the device encountered more than one failed logical
  block during the test, then this field only indicates one of those
  failed logical blocks. Valid only when the NSID Valid bit
  (#NVME_ST_VALID_DIAG_INFO_FLBA) is set in the Valid Diagnostic
  Information (**vdi**) field.

``sct``
  Status Code Type: This field may contain additional information related
  to errors or conditions. Bits 2:0 may contain additional information
  relating to errors or conditions that occurred during the device
  self-test operation represented in the same format used in the Status
  Code Type field of the completion queue entry (refer to :c:type:`enum nvme_status_field <nvme_status_field>`).
  Valid only when the NSID Valid bit (#NVME_ST_VALID_DIAG_INFO_SCT) is
  set in the Valid Diagnostic Information (**vdi**) field.

``sc``
  Status Code: This field may contain additional information relating
  to errors or conditions that occurred during the device self-test
  operation represented in the same format used in the Status Code field
  of the completion queue entry. Valid only when the SCT Valid bit
  (#NVME_ST_VALID_DIAG_INFO_SC) is set in the Valid Diagnostic
  Information (**vdi**) field.

``vs``
  Vendor Specific.





.. c:enum:: nvme_status_result

   Result of the device self-test operation

**Constants**

``NVME_ST_RESULT_NO_ERR``
  Operation completed without error.

``NVME_ST_RESULT_ABORTED``
  Operation was aborted by a Device Self-test command.

``NVME_ST_RESULT_CLR``
  Operation was aborted by a Controller Level Reset.

``NVME_ST_RESULT_NS_REMOVED``
  Operation was aborted due to a removal of
  a namespace from the namespace inventory.

``NVME_ST_RESULT_ABORTED_FORMAT``
  Operation was aborted due to the processing
  of a Format NVM command.

``NVME_ST_RESULT_FATAL_ERR``
  A fatal error or unknown test error occurred
  while the controller was executing the device
  self-test operation and the operation did
  not complete.

``NVME_ST_RESULT_UNKNOWN_SEG_FAIL``
  Operation completed with a segment that failed
  and the segment that failed is not known.

``NVME_ST_RESULT_KNOWN_SEG_FAIL``
  Operation completed with one or more failed
  segments and the first segment that failed
  is indicated in the Segment Number field.

``NVME_ST_RESULT_ABORTED_UNKNOWN``
  Operation was aborted for unknown reason.

``NVME_ST_RESULT_ABORTED_SANITIZE``
  Operation was aborted due to a sanitize operation.

``NVME_ST_RESULT_NOT_USED``
  Entry not used (does not contain a test result).

``NVME_ST_RESULT_SHIFT``
  Device self-test result shift

``NVME_ST_RESULT_MASK``
  Mask to get the status result value from
  the :c:type:`struct nvme_st_result <nvme_st_result>`.dsts field.




.. c:enum:: nvme_st_code

   Self-test Code value

**Constants**

``NVME_ST_CODE_RESERVED``
  Reserved.

``NVME_ST_CODE_SHORT``
  Short device self-test operation.

``NVME_ST_CODE_EXTENDED``
  Extended device self-test operation.

``NVME_ST_CODE_HOST_INIT``
  Host-Initiated Refresh operation.

``NVME_ST_CODE_VS``
  Vendor specific.

``NVME_ST_CODE_ABORT``
  Abort device self-test operation.

``NVME_ST_CODE_SHIFT``
  Shift amount to get the code value from the
  :c:type:`struct nvme_st_result <nvme_st_result>`.dsts field.

``NVME_ST_CODE_MASK``
  Self-test code mask




.. c:enum:: nvme_st_curr_op

   Current Device Self-Test Operation

**Constants**

``NVME_ST_CURR_OP_NOT_RUNNING``
  No device self-test operation in progress.

``NVME_ST_CURR_OP_SHORT``
  Short device self-test operation in progress.

``NVME_ST_CURR_OP_EXTENDED``
  Extended device self-test operation in progress.

``NVME_ST_CURR_OP_VS``
  Vendor specific.

``NVME_ST_CURR_OP_RESERVED``
  Reserved.

``NVME_ST_CURR_OP_SHIFT``
  Device self-test operation status shift

``NVME_ST_CURR_OP_MASK``
  Mask to get the current operation value from the
  :c:type:`struct nvme_self_test_log <nvme_self_test_log>`.current_operation field.

``NVME_ST_CURR_OP_CMPL_SHIFT``
  Current device self-test completion shift

``NVME_ST_CURR_OP_CMPL_MASK``
  Mask to get the current operation completion value
  from the :c:type:`struct nvme_self_test_log <nvme_self_test_log>`.completion field.




.. c:enum:: nvme_st_valid_diag_info

   Valid Diagnostic Information

**Constants**

``NVME_ST_VALID_DIAG_INFO_NSID``
  NSID Valid: if set, then the contents of
  the Namespace Identifier field are valid.

``NVME_ST_VALID_DIAG_INFO_FLBA``
  FLBA Valid: if set, then the contents of
  the Failing LBA field are valid.

``NVME_ST_VALID_DIAG_INFO_SCT``
  SCT Valid: if set, then the contents of
  the Status Code Type field are valid.

``NVME_ST_VALID_DIAG_INFO_SC``
  SC Valid: if set, then the contents of
  the Status Code field are valid.




.. c:struct:: nvme_self_test_log

   Device Self-test (Log Identifier 06h)

**Definition**

::

  struct nvme_self_test_log {
    __u8 current_operation;
    __u8 completion;
    __u8 rsvd[2];
    struct nvme_st_result   result[NVME_LOG_ST_MAX_RESULTS];
  };

**Members**

``current_operation``
  Current Device Self-Test Operation: indicates the status
  of the current device self-test operation. If a device
  self-test operation is in process (i.e., this field is set
  to #NVME_ST_CURR_OP_SHORT or #NVME_ST_CURR_OP_EXTENDED),
  then the controller shall not set this field to
  #NVME_ST_CURR_OP_NOT_RUNNING until a new Self-test Result
  Data Structure is created (i.e., if a device self-test
  operation completes or is aborted, then the controller
  shall create a Self-test Result Data Structure prior to
  setting this field to #NVME_ST_CURR_OP_NOT_RUNNING).
  See :c:type:`enum nvme_st_curr_op <nvme_st_curr_op>`.

``completion``
  Current Device Self-Test Completion: indicates the percentage
  of the device self-test operation that is complete (e.g.,
  a value of 25 indicates that 25% of the device self-test
  operation is complete and 75% remains to be tested).
  If the **current_operation** field is cleared to
  #NVME_ST_CURR_OP_NOT_RUNNING (indicating there is no device
  self-test operation in progress), then this field is ignored.

``rsvd``
  Reserved

``result``
  Self-test Result Data Structures, see :c:type:`struct nvme_st_result <nvme_st_result>`.





.. c:enum:: nvme_log_telemetry_host_lsp

   Telemetry Host-Initiated log specific field

**Constants**

``NVME_LOG_TELEM_HOST_LSP_RETAIN``
  Get Telemetry Data Blocks

``NVME_LOG_TELEM_HOST_LSP_CREATE``
  Create Telemetry Data Blocks




.. c:enum:: nvme_telemetry_da

   Telemetry Log Data Area

**Constants**

``NVME_TELEMETRY_DA_CTRL_DETERMINE``
  The controller determines the data areas to be created

``NVME_TELEMETRY_DA_1``
  Data Area 1

``NVME_TELEMETRY_DA_2``
  Data Area 2

``NVME_TELEMETRY_DA_3``
  Data Area 3

``NVME_TELEMETRY_DA_4``
  Data Area 4




.. c:struct:: nvme_telemetry_log

   Retrieve internal data specific to the manufacturer.

**Definition**

::

  struct nvme_telemetry_log {
    __u8 lpi;
    __u8 rsvd1[4];
    __u8 ieee[3];
    __le16 dalb1;
    __le16 dalb2;
    __le16 dalb3;
    __u8 rsvd14[2];
    __le32 dalb4;
    __u8 rsvd20[360];
    __u8 ths;
    union {
      __u8 hostdgn;
      __u8 tcs;
    };
    __u8 ctrlavail;
    __u8 ctrldgn;
    __u8 rsnident[128];
    __u8 data_area[];
  };

**Members**

``lpi``
  Log Identifier, either ``NVME_LOG_LID_TELEMETRY_HOST`` or
  ``NVME_LOG_LID_TELEMETRY_CTRL``

``rsvd1``
  Reserved

``ieee``
  IEEE OUI Identifier is the Organization Unique Identifier (OUI)
  for the controller vendor that is able to interpret the data.

``dalb1``
  Telemetry Host/Controller Initiated Data Area 1 Last Block is
  the value of the last block in this area.

``dalb2``
  Telemetry Host/Controller Initiated Data Area 1 Last Block is
  the value of the last block in this area.

``dalb3``
  Telemetry Host/ControllerInitiated Data Area 1 Last Block is
  the value of the last block in this area.

``rsvd14``
  Reserved

``dalb4``
  Telemetry Host/Controller Initiated Data Area 4 Last Block is
  the value of the last block in this area.

``rsvd20``
  Reserved

``ths``
  Telemetry Host-Initiated Scope

``{unnamed_union}``
  anonymous

``hostdgn``
  Telemetry Host-Initiated Data Generation Number is a
  value that is incremented each time the host initiates a
  capture of its internal controller state in the controller.

``tcs``
  Telemetry Controller-Initiated Scope

``ctrlavail``
  Telemetry Controller-Initiated Data Available, if cleared,
  then the controller telemetry log does not contain saved
  internal controller state. If this field is set to 1h, the
  controller log contains saved internal controller state. If
  this field is set to 1h, the data will be latched until the
  host releases it by reading the log with RAE cleared.

``ctrldgn``
  Telemetry Controller-Initiated Data Generation Number is
  a value that is incremented each time the controller initiates a
  capture of its internal controller state in the controller .

``rsnident``
  Reason Identifiers a vendor specific identifier that describes
  the operating conditions of the controller at the time of
  capture.

``data_area``
  Telemetry data blocks, vendor specific information data.


**Description**

This log consists of a header describing the log and zero or more Telemetry
Data Blocks. All Telemetry Data Blocks are ``NVME_LOG_TELEM_BLOCK_SIZE``, 512
bytes, in size. This log captures the controller’s internal state.




.. c:struct:: nvme_endurance_group_log

   Endurance Group Information Log

**Definition**

::

  struct nvme_endurance_group_log {
    __u8 critical_warning;
    __u8 endurance_group_features;
    __u8 rsvd2;
    __u8 avl_spare;
    __u8 avl_spare_threshold;
    __u8 percent_used;
    __le16 domain_identifier;
    __u8 rsvd8[24];
    __u8 endurance_estimate[16];
    __u8 data_units_read[16];
    __u8 data_units_written[16];
    __u8 media_units_written[16];
    __u8 host_read_cmds[16];
    __u8 host_write_cmds[16];
    __u8 media_data_integrity_err[16];
    __u8 num_err_info_log_entries[16];
    __u8 total_end_grp_cap[16];
    __u8 unalloc_end_grp_cap[16];
    __u8 rsvd192[320];
  };

**Members**

``critical_warning``
  Critical Warning

``endurance_group_features``
  Endurance Group Features

``rsvd2``
  Reserved

``avl_spare``
  Available Spare

``avl_spare_threshold``
  Available Spare Threshold

``percent_used``
  Percentage Used

``domain_identifier``
  Domain Identifier

``rsvd8``
  Reserved

``endurance_estimate``
  Endurance Estimate

``data_units_read``
  Data Units Read

``data_units_written``
  Data Units Written

``media_units_written``
  Media Units Written

``host_read_cmds``
  Host Read Commands

``host_write_cmds``
  Host Write Commands

``media_data_integrity_err``
  Media and Data Integrity Errors

``num_err_info_log_entries``
  Number of Error Information Log Entries

``total_end_grp_cap``
  Total Endurance Group Capacity

``unalloc_end_grp_cap``
  Unallocated Endurance Group Capacity

``rsvd192``
  Reserved





.. c:enum:: nvme_eg_critical_warning_flags

   Endurance Group Information Log - Critical Warning

**Constants**

``NVME_EG_CRITICAL_WARNING_SPARE``
  Available spare capacity of the Endurance Group
  has fallen below the threshold

``NVME_EG_CRITICAL_WARNING_DEGRADED``
  Endurance Group reliability has been degraded

``NVME_EG_CRITICAL_WARNING_READ_ONLY``
  Endurance Group have been placed in read only
  mode




.. c:struct:: nvme_aggregate_endurance_group_event

   Endurance Group Event Aggregate

**Definition**

::

  struct nvme_aggregate_endurance_group_event {
    __le64 num_entries;
    __le16 entries[];
  };

**Members**

``num_entries``
  Number or entries

``entries``
  List of entries





.. c:struct:: nvme_nvmset_predictable_lat_log

   Predictable Latency Mode - Deterministic Threshold Configuration Data

**Definition**

::

  struct nvme_nvmset_predictable_lat_log {
    __u8 status;
    __u8 rsvd1;
    __le16 event_type;
    __u8 rsvd4[28];
    __le64 dtwin_rt;
    __le64 dtwin_wt;
    __le64 dtwin_tmax;
    __le64 ndwin_tmin_hi;
    __le64 ndwin_tmin_lo;
    __u8 rsvd72[56];
    __le64 dtwin_re;
    __le64 dtwin_we;
    __le64 dtwin_te;
    __u8 rsvd152[360];
  };

**Members**

``status``
  Status

``rsvd1``
  Reserved

``event_type``
  Event Type

``rsvd4``
  Reserved

``dtwin_rt``
  DTWIN Reads Typical

``dtwin_wt``
  DTWIN Writes Typical

``dtwin_tmax``
  DTWIN Time Maximum

``ndwin_tmin_hi``
  NDWIN Time Minimum High

``ndwin_tmin_lo``
  NDWIN Time Minimum Low

``rsvd72``
  Reserved

``dtwin_re``
  DTWIN Reads Estimate

``dtwin_we``
  DTWIN Writes Estimate

``dtwin_te``
  DTWIN Time Estimate

``rsvd152``
  Reserved





.. c:enum:: nvme_nvmeset_pl_status

   Predictable Latency Per NVM Set Log - Status

**Constants**

``NVME_NVMSET_PL_STATUS_DISABLED``
  Not used (Predictable Latency Mode not enabled)

``NVME_NVMSET_PL_STATUS_DTWIN``
  Deterministic Window (DTWIN)

``NVME_NVMSET_PL_STATUS_NDWIN``
  Non-Deterministic Window (NDWIN)




.. c:enum:: nvme_nvmset_pl_events

   Predictable Latency Per NVM Set Log - Event Type

**Constants**

``NVME_NVMSET_PL_EVENT_DTWIN_READ_WARN``
  DTWIN Reads Warning

``NVME_NVMSET_PL_EVENT_DTWIN_WRITE_WARN``
  DTWIN Writes Warning

``NVME_NVMSET_PL_EVENT_DTWIN_TIME_WARN``
  DTWIN Time Warning

``NVME_NVMSET_PL_EVENT_DTWIN_EXCEEDED``
  Autonomous transition from DTWIN
  to NDWIN due to typical or
  maximum value exceeded

``NVME_NVMSET_PL_EVENT_DTWIN_EXCURSION``
  Autonomous transition from DTWIN
  to NDWIN due to Deterministic
  Excursion




.. c:struct:: nvme_aggregate_predictable_lat_event

   Predictable Latency Event Aggregate Log Page

**Definition**

::

  struct nvme_aggregate_predictable_lat_event {
    __le64 num_entries;
    __le16 entries[];
  };

**Members**

``num_entries``
  Number of entries

``entries``
  Entry list





.. c:struct:: nvme_ana_group_desc

   ANA Group Descriptor

**Definition**

::

  struct nvme_ana_group_desc {
    __le32 grpid;
    __le32 nnsids;
    __le64 chgcnt;
    __u8 state;
    __u8 rsvd17[15];
    __le32 nsids[];
  };

**Members**

``grpid``
  ANA group id

``nnsids``
  Number of namespaces in **nsids**

``chgcnt``
  Change counter

``state``
  ANA state

``rsvd17``
  Reserved

``nsids``
  List of namespaces





.. c:enum:: nvme_ana_state

   ANA Group Descriptor - Asymmetric Namespace Access State

**Constants**

``NVME_ANA_STATE_OPTIMIZED``
  ANA Optimized state

``NVME_ANA_STATE_NONOPTIMIZED``
  ANA Non-Optimized state

``NVME_ANA_STATE_INACCESSIBLE``
  ANA Inaccessible state

``NVME_ANA_STATE_PERSISTENT_LOSS``
  ANA Persistent Loss state

``NVME_ANA_STATE_CHANGE``
  ANA Change state




.. c:struct:: nvme_ana_log

   Asymmetric Namespace Access Log

**Definition**

::

  struct nvme_ana_log {
    __le64 chgcnt;
    __le16 ngrps;
    __u8 rsvd10[6];
    struct nvme_ana_group_desc descs[];
  };

**Members**

``chgcnt``
  Change Count

``ngrps``
  Number of ANA Group Descriptors

``rsvd10``
  Reserved

``descs``
  ANA Group Descriptor





.. c:struct:: nvme_persistent_event_log

   Persistent Event Log

**Definition**

::

  struct nvme_persistent_event_log {
    __u8 lid;
    __u8 rsvd1[3];
    __le32 tnev;
    __le64 tll;
    __u8 rv;
    __u8 rsvd17;
    __le16 lhl;
    __le64 ts;
    __u8 poh[16];
    __le64 pcc;
    __le16 vid;
    __le16 ssvid;
    char sn[20];
    char mn[40];
    char subnqn[NVME_NQN_LENGTH];
    __le16 gen_number;
    __le32 rci;
    __u8 rsvd378[102];
    __u8 seb[32];
  };

**Members**

``lid``
  Log Identifier

``rsvd1``
  Reserved

``tnev``
  Total Number of Events

``tll``
  Total Log Length

``rv``
  Log Revision

``rsvd17``
  Reserved

``lhl``
  Log Header Length

``ts``
  Timestamp

``poh``
  Power on Hours

``pcc``
  Power Cycle Count

``vid``
  PCI Vendor ID

``ssvid``
  PCI Subsystem Vendor ID

``sn``
  Serial Number

``mn``
  Model Number

``subnqn``
  NVM Subsystem NVMe Qualified Name

``gen_number``
  Generation Number

``rci``
  Reporting Context Information

``rsvd378``
  Reserved

``seb``
  Supported Events Bitmap





.. c:enum:: nvme_pel_rci

   This field indicates the persistent event log reporting context

**Constants**

``NVME_PEL_RCI_RCPID_SHIFT``
  Shift amount to get the reporting context port identifier
  from the :c:type:`struct nvme_persistent_event_log <nvme_persistent_event_log>`.rci field.

``NVME_PEL_RCI_RCPIT_SHIFT``
  Shift amount to get the reporting context port identifier
  type from the :c:type:`struct nvme_persistent_event_log <nvme_persistent_event_log>`.rci field.

``NVME_PEL_RCI_RCE_SHIFT``
  Shift amount to get the reporting context exists
  from the :c:type:`struct nvme_persistent_event_log <nvme_persistent_event_log>`.rci field.

``NVME_PEL_RCI_RSVD_SHIFT``
  Shift amount to get the reserved reporting context
  from the :c:type:`struct nvme_persistent_event_log <nvme_persistent_event_log>`.rci field.

``NVME_PEL_RCI_RCPID_MASK``
  Mask to get the reporting context port identifier from
  the :c:type:`struct nvme_persistent_event_log <nvme_persistent_event_log>`.rci field.

``NVME_PEL_RCI_RCPIT_MASK``
  Mask to get the reporting context port identifier type from
  the :c:type:`struct nvme_persistent_event_log <nvme_persistent_event_log>`.rci field.

``NVME_PEL_RCI_RCE_MASK``
  Mask to get the reporting context exists from
  the :c:type:`struct nvme_persistent_event_log <nvme_persistent_event_log>`.rci field.

``NVME_PEL_RCI_RSVD_MASK``
  Mask to get the reserved reporting context from
  the :c:type:`struct nvme_persistent_event_log <nvme_persistent_event_log>`.rci field.




.. c:enum:: nvme_pel_rci_rcpit

   Persistent Event Log Reporting Context - Port Identifier Type

**Constants**

``NVME_PEL_RCI_RCPIT_NOT_EXIST``
  Does not already exist

``NVME_PEL_RCI_RCPIT_EST_PORT``
  Established by an NVM subsystem port

``NVME_PEL_RCI_RCPIT_EST_ME``
  Established by a Management Endpoint




.. c:struct:: nvme_persistent_event_entry

   Persistent Event

**Definition**

::

  struct nvme_persistent_event_entry {
    __u8 etype;
    __u8 etype_rev;
    __u8 ehl;
    __u8 ehai;
    __le16 cntlid;
    __le64 ets;
    __le16 pelpid;
    __u8 rsvd16[4];
    __le16 vsil;
    __le16 el;
  };

**Members**

``etype``
  Event Type

``etype_rev``
  Event Type Revision

``ehl``
  Event Header Length

``ehai``
  Event Header Additional Info

``cntlid``
  Controller Identifier

``ets``
  Event Timestamp

``pelpid``
  Port Identifier

``rsvd16``
  Reserved

``vsil``
  Vendor Specific Information Length

``el``
  Event Length





.. c:enum:: nvme_persistent_event_types

   Persistent event log events

**Constants**

``NVME_PEL_SMART_HEALTH_EVENT``
  SMART / Health Log Snapshot Event

``NVME_PEL_FW_COMMIT_EVENT``
  Firmware Commit Event

``NVME_PEL_TIMESTAMP_EVENT``
  Timestamp Change Event

``NVME_PEL_POWER_ON_RESET_EVENT``
  Power-on or Reset Event

``NVME_PEL_NSS_HW_ERROR_EVENT``
  NVM Subsystem Hardware Error Event

``NVME_PEL_CHANGE_NS_EVENT``
  Change Namespace Event

``NVME_PEL_FORMAT_START_EVENT``
  Format NVM Start Event

``NVME_PEL_FORMAT_COMPLETION_EVENT``
  Format NVM Completion Event

``NVME_PEL_SANITIZE_START_EVENT``
  Sanitize Start Event

``NVME_PEL_SANITIZE_COMPLETION_EVENT``
  Sanitize Completion Event

``NVME_PEL_SET_FEATURE_EVENT``
  Set Feature Event

``NVME_PEL_TELEMETRY_CRT``
  Telemetry Log Create Event

``NVME_PEL_THERMAL_EXCURSION_EVENT``
  Thermal Excursion Event

``NVME_PEL_SANITIZE_MEDIA_VERIF_EVENT``
  Sanitize Media Verification Event

``NVME_PEL_CONF_DEV_PERSONALITY_CHG_EVENT``
  Configurable Device Personality
  Change Event

``NVME_PEL_EXPORT_NVMS_CHG_EVENT``
  Exported NVM Subsystem Change Event

``NVME_PEL_VENDOR_SPECIFIC_EVENT``
  Vendor Specific Event

``NVME_PEL_TCG_DEFINED_EVENT``
  TCG Defined Event




.. c:enum:: nvme_pel_ehai

   This field indicates the persistent event header additional information

**Constants**

``NVME_PEL_EHAI_PIT_SHIFT``
  Shift amount to get the reporting context port identifier
  from the :c:type:`struct nvme_persistent_event_log <nvme_persistent_event_log>`.rci field.

``NVME_PEL_EHAI_RSVD_SHIFT``
  Shift amount to get the reserved reporting context
  from the :c:type:`struct nvme_persistent_event_log <nvme_persistent_event_log>`.rci field.

``NVME_PEL_EHAI_PIT_MASK``
  Mask to get the reporting context port identifier from
  the :c:type:`struct nvme_st_result <nvme_st_result>`.dsts field.

``NVME_PEL_EHAI_RSVD_MASK``
  Mask to get the reserved reporting context from
  the :c:type:`struct nvme_st_result <nvme_st_result>`.dsts field.




.. c:enum:: nvme_pel_ehai_pit

   Persistent Event Header Additional Information - Port Identifier Type

**Constants**

``NVME_PEL_EHAI_PIT_NOT_REPORTED``
  PIT not reported and PELPID does not apply

``NVME_PEL_EHAI_PIT_NSS_PORT``
  NVM subsystem port

``NVME_PEL_EHAI_PIT_NMI_PORT``
  NVMe-MI port

``NVME_PEL_EHAI_PIT_NOT_ASSOCIATED``
  Event not associated with any port and PELPID does not apply




.. c:enum:: nvme_pel_vsedt_code

   Persistent Event Log - Vendor Specific Event Data Type Code

**Constants**

``NVME_PEL_VSEDT_RSVD``
  Reserved

``NVME_PEL_VSEDT_EVENT_NAME``
  Event Name

``NVME_PEL_VSEDT_ASCII_STRING``
  ASCII String

``NVME_PEL_VSEDT_BINARY``
  Binary

``NVME_PEL_VSEDT_SIGNED_INT``
  Signed Integer




.. c:struct:: nvme_vs_event_desc

   Vendor Specific Event Descriptor

**Definition**

::

  struct nvme_vs_event_desc {
    __le16 vsec;
    __u8 vsedt;
    __u8 uidx;
    __le16 vsedl;
  };

**Members**

``vsec``
  Vendor Specific Event Code

``vsedt``
  Vendor Specific Event Data Type

``uidx``
  UUID Index

``vsedl``
  Vendor Specific Event Data Length





.. c:struct:: nvme_fw_commit_event

   Firmware Commit Event Data

**Definition**

::

  struct nvme_fw_commit_event {
    __le64 old_fw_rev;
    __le64 new_fw_rev;
    __u8 fw_commit_action;
    __u8 fw_slot;
    __u8 sct_fw;
    __u8 sc_fw;
    __le16 vndr_assign_fw_commit_rc;
  };

**Members**

``old_fw_rev``
  Old Firmware Revision

``new_fw_rev``
  New Firmware Revision

``fw_commit_action``
  Firmware Commit Action

``fw_slot``
  Firmware Slot

``sct_fw``
  Status Code Type for Firmware Commit Command

``sc_fw``
  Status Returned for Firmware Commit Command

``vndr_assign_fw_commit_rc``
  Vendor Assigned Firmware Commit Result Code





.. c:struct:: nvme_time_stamp_change_event

   Timestamp Change Event

**Definition**

::

  struct nvme_time_stamp_change_event {
    __le64 previous_timestamp;
    __le64 ml_secs_since_reset;
  };

**Members**

``previous_timestamp``
  Previous Timestamp

``ml_secs_since_reset``
  Milliseconds Since Reset





.. c:struct:: nvme_power_on_reset_info_list

   Controller Reset Information

**Definition**

::

  struct nvme_power_on_reset_info_list {
    __le16 cid;
    __u8 fw_act;
    __u8 op_in_prog;
    __u8 rsvd4[12];
    __le32 ctrl_power_cycle;
    __le64 power_on_ml_seconds;
    __le64 ctrl_time_stamp;
  };

**Members**

``cid``
  Controller ID

``fw_act``
  Firmware Activation

``op_in_prog``
  Operation in Progress

``rsvd4``
  Reserved

``ctrl_power_cycle``
  Controller Power Cycle

``power_on_ml_seconds``
  Power on milliseconds

``ctrl_time_stamp``
  Controller Timestamp





.. c:struct:: nvme_nss_hw_err_event

   NVM Subsystem Hardware Error Event

**Definition**

::

  struct nvme_nss_hw_err_event {
    __le16 nss_hw_err_event_code;
    __u8 rsvd2[2];
    __u8 *add_hw_err_info;
  };

**Members**

``nss_hw_err_event_code``
  NVM Subsystem Hardware Error Event Code

``rsvd2``
  Reserved

``add_hw_err_info``
  Additional Hardware Error Information





.. c:struct:: nvme_change_ns_event

   Change Namespace Event Data

**Definition**

::

  struct nvme_change_ns_event {
    __le32 nsmgt_cdw10;
    __u8 rsvd4[4];
    __le64 nsze;
    __u8 rsvd16[8];
    __le64 nscap;
    __u8 flbas;
    __u8 dps;
    __u8 nmic;
    __u8 rsvd35;
    __le32 ana_grp_id;
    __le16 nvmset_id;
    __le16 rsvd42;
    __le32 nsid;
  };

**Members**

``nsmgt_cdw10``
  Namespace Management CDW10

``rsvd4``
  Reserved

``nsze``
  Namespace Size

``rsvd16``
  Reserved

``nscap``
  Namespace Capacity

``flbas``
  Formatted LBA Size

``dps``
  End-to-end Data Protection Type Settings

``nmic``
  Namespace Multi-path I/O and Namespace Sharing Capabilities

``rsvd35``
  Reserved

``ana_grp_id``
  ANA Group Identifier

``nvmset_id``
  NVM Set Identifier

``rsvd42``
  Reserved

``nsid``
  Namespace ID





.. c:struct:: nvme_format_nvm_start_event

   Format NVM Start Event Data

**Definition**

::

  struct nvme_format_nvm_start_event {
    __le32 nsid;
    __u8 fna;
    __u8 rsvd5[3];
    __le32 format_nvm_cdw10;
  };

**Members**

``nsid``
  Namespace Identifier

``fna``
  Format NVM Attributes

``rsvd5``
  Reserved

``format_nvm_cdw10``
  Format NVM CDW10





.. c:struct:: nvme_format_nvm_compln_event

   Format NVM Completion Event Data

**Definition**

::

  struct nvme_format_nvm_compln_event {
    __le32 nsid;
    __u8 smallest_fpi;
    __u8 format_nvm_status;
    __le16 compln_info;
    __le32 status_field;
  };

**Members**

``nsid``
  Namespace Identifier

``smallest_fpi``
  Smallest Format Progress Indicator

``format_nvm_status``
  Format NVM Status

``compln_info``
  Completion Information

``status_field``
  Status Field





.. c:struct:: nvme_sanitize_start_event

   Sanitize Start Event Data

**Definition**

::

  struct nvme_sanitize_start_event {
    __le32 sani_cap;
    __le32 sani_cdw10;
    __le32 sani_cdw11;
  };

**Members**

``sani_cap``
  SANICAP

``sani_cdw10``
  Sanitize CDW10

``sani_cdw11``
  Sanitize CDW11





.. c:struct:: nvme_sanitize_compln_event

   Sanitize Completion Event Data

**Definition**

::

  struct nvme_sanitize_compln_event {
    __le16 sani_prog;
    __le16 sani_status;
    __le16 cmpln_info;
    __u8 rsvd6[2];
  };

**Members**

``sani_prog``
  Sanitize Progress

``sani_status``
  Sanitize Status

``cmpln_info``
  Completion Information

``rsvd6``
  Reserved





.. c:struct:: nvme_set_feature_event

   Set Feature Event Data

**Definition**

::

  struct nvme_set_feature_event {
    __le32 layout;
    __le32 cdw_mem[0];
  };

**Members**

``layout``
  Set Feature Event Layout

``cdw_mem``
  Command Dwords Memory buffer





.. c:enum:: nvme_set_feat_event_layout

   This field indicates the set feature event layout

**Constants**

``NVME_SET_FEAT_EVENT_DW_COUNT_SHIFT``
  Shift amount to get the Dword count from the
  :c:type:`struct nvme_set_feature_event <nvme_set_feature_event>`.layout field.

``NVME_SET_FEAT_EVENT_CC_DW0_SHIFT``
  Shift amount to get the logged command completion Dword 0
  from the :c:type:`struct nvme_set_feature_event <nvme_set_feature_event>`.layout field.

``NVME_SET_FEAT_EVENT_MB_COUNT_SHIFT``
  Shift amount to get the memory buffer count from
  the :c:type:`struct nvme_set_feature_event <nvme_set_feature_event>`.layout field.

``NVME_SET_FEAT_EVENT_DW_COUNT_MASK``
  Mask to get the Dword count from the :c:type:`struct
  nvme_set_feature_event <nvme_set_feature_event>`.layout field.

``NVME_SET_FEAT_EVENT_CC_DW0_MASK``
  Mask to get the logged command completion Dword 0 from
  the :c:type:`struct nvme_set_feature_event <nvme_set_feature_event>`.layout field.

``NVME_SET_FEAT_EVENT_MB_COUNT_MASK``
  Mask to get the memory buffer count from the :c:type:`struct
  nvme_set_feature_event <nvme_set_feature_event>`.layout field.




.. c:struct:: nvme_thermal_exc_event

   Thermal Excursion Event Data

**Definition**

::

  struct nvme_thermal_exc_event {
    __u8 over_temp;
    __u8 threshold;
  };

**Members**

``over_temp``
  Over Temperature

``threshold``
  temperature threshold





.. c:struct:: nvme_cdp_change_event

   CDP Change Event Data Format (Event Type 0Fh)

**Definition**

::

  struct nvme_cdp_change_event {
    __u8 ps;
    __u8 perid;
    __u8 rsvd2[10];
    __u8 ped[];
  };

**Members**

``ps``
  Personality Status, see :c:type:`enum nvme_cdp_change_event_ps <nvme_cdp_change_event_ps>`.

``perid``
  Personality Identifier of the personality whose settings a Set
  Features command requested to change, see :c:type:`enum
  nvme_personality_identifier <nvme_personality_identifier>`.

``rsvd2``
  Reserved

``ped``
  Personality Event Data: the data buffer of the Set Features
  command corresponding to **perid**, if any.





.. c:enum:: nvme_cdp_change_event_ps

   CDP Change Event - Personality Status

**Constants**

``NVME_CDP_CHANGE_EVENT_PS_CDPCE``
  CDP Change Error: If the change to the
  settings of the specified personality was
  successful, then this bit is cleared to
  '0'; otherwise, this bit is set to '1'.

``NVME_CDP_CHANGE_EVENT_PS_CDPRFS``
  CDP Requested Freeze State: If the
  personality was requested to be frozen,
  then this bit is set to '1'; otherwise,
  this bit is cleared to '0'.




.. c:enum:: nvme_personality_identifier

   Personality Identifier List

**Constants**

``NVME_PERID_MFG_DEFAULT``
  Manufacturing Default Personality

``NVME_PERID_SECURITY``
  Security Personality

``NVME_PERID_LOCKDOWN_PERSISTENCE``
  Lockdown Persistence Personality, see
  :c:type:`enum nvme_lockdown_persistence_cdw11 <nvme_lockdown_persistence_cdw11>`
  and :c:type:`enum
  nvme_lockdown_persistence_cqe_dw1 <nvme_lockdown_persistence_cqe_dw1>`

``NVME_PERID_REVERT_MFG_SETTINGS``
  Revert to Subsystem Manufacturing
  Settings Personality: reverts all
  supported Features (other than CDP
  itself), restorable log pages, and
  vendor specific settings to their
  manufacturing default content for the
  current active firmware image. Uses no
  data buffer; requires an NVM Subsystem
  Reset (see :c:type:`enum
  nvme_personality_mrstt <nvme_personality_mrstt>`) to take effect.

``NVME_PERID_ALL``
  All Personalities




.. c:enum:: nvme_lockdown_persistence_cdw11

   Lockdown Persistence Personality - Command Dword 11 (Set Features)

**Constants**

``NVME_LOCKDOWN_PERSISTENCE_LDPE``
  Lockdown Persistence Enable: If set to
  '1', then Lockdown Persistence is
  enabled and the prohibitions of the
  Lockdown command that affect all
  controllers in the NVM subsystem persist
  across power cycles of the NVM subsystem.
  If cleared to '0', then Lockdown
  Persistence is disabled.




.. c:enum:: nvme_lockdown_persistence_cqe_dw1

   Lockdown Persistence Personality - Get Features Completion Queue Entry Dword 1

**Constants**

``NVME_LOCKDOWN_PERSISTENCE_LDPS``
  Lockdown Persistence State: set to '1' if
  Lockdown Persistence is enabled; cleared
  to '0' if disabled.




.. c:enum:: nvme_personality_mrstt

   Personality Properties - Minimum Required Reset Type (MRSTT)

**Constants**

``NVME_PERSONALITY_MRSTT_NONE``
  No reset required

``NVME_PERSONALITY_MRSTT_CTRL_RESET``
  Controller Level Reset required

``NVME_PERSONALITY_MRSTT_LIMITED_CTRL_RESET``
  Controller Level Reset other
  than one initiated by a
  Controller Reset required

``NVME_PERSONALITY_MRSTT_NVM_SUBSYSTEM_RESET``
  NVM Subsystem Reset required

``NVME_PERSONALITY_MRSTT_POWER_CYCLE``
  Main power cycle required




.. c:enum:: nvme_personality_aus

   Personality Properties - Authenticated Unfreeze Support (AUS)

**Constants**

``NVME_PERSONALITY_AUS_PCAS``
  Physical Credential Authentication Support

``NVME_PERSONALITY_AUS_PKAS``
  Programmable Key Authentication Support




.. c:enum:: nvme_personality_attrs

   Personality Properties - Personality Attributes

**Constants**

``NVME_PERSONALITY_ATTRS_PSCUDE``
  Personality Settings Change User Data
  Effect




.. c:struct:: nvme_personality_properties

   Personality Properties data structure

**Definition**

::

  struct nvme_personality_properties {
    __u8 pps;
    __u8 perid;
    __u8 mrstt;
    __u8 aus;
    __u8 attrs;
  };

**Members**

``pps``
  Personality Properties Size: size in bytes of this data
  structure.

``perid``
  Personality Identifier, see :c:type:`enum nvme_personality_identifier <nvme_personality_identifier>`.

``mrstt``
  Minimum Required Reset Type, see :c:type:`enum nvme_personality_mrstt <nvme_personality_mrstt>`.

``aus``
  Authenticated Unfreeze Support, see :c:type:`enum
  nvme_personality_aus <nvme_personality_aus>`. Cleared to 0h if this personality does
  not support an authenticated unfreeze method, in which case a
  frozen instance of this personality is permanently frozen.

``attrs``
  Personality Attributes, see :c:type:`enum nvme_personality_attrs <nvme_personality_attrs>`.





.. c:struct:: nvme_dev_personalities_log

   Device Personalities Log Page (Log Identifier 1Dh)

**Definition**

::

  struct nvme_dev_personalities_log {
    __le16 nump;
    __u8 cdplpv;
    __u8 dplphl;
    __le16 cdplps;
    struct nvme_personality_properties perprops[];
  };

**Members**

``nump``
  Number of Personalities: number of :c:type:`struct
  nvme_personality_properties <nvme_personality_properties>` entries in **perprops**. This is a
  0's based value.

``cdplpv``
  CDP Log Page Version

``dplphl``
  Device Personalities Log Page Header Length

``cdplps``
  Device Personalities Log Page Size: size of this log page in
  bytes.

``perprops``
  CDP Personality list, listed in ascending order of
  Personality Identifier.





.. c:enum:: nvme_mfg_default_config_status_mdcs

   Manufacturer Default Configuration Status log page - Manufacturer Default Configuration Status (MDCS)

**Constants**

``NVME_MDCS_DSCS_SHIFT``
  Shift amount to get the Default NVM Subsystem
  Configuration Status (DSCS)

``NVME_MDCS_DSCS_MASK``
  Mask to get DSCS

``NVME_MDCS_DNCS_SHIFT``
  Shift amount to get the Default Namespace
  Configuration Status (DNCS)

``NVME_MDCS_DNCS_MASK``
  Mask to get DNCS

``NVME_MDCS_DCCS_SHIFT``
  Shift amount to get the Default Capacity
  Configuration Status (DCCS)

``NVME_MDCS_DCCS_MASK``
  Mask to get DCCS




.. c:struct:: nvme_mfg_default_config_status_log

   Manufacturer Default Configuration Status log page (Log Page Identifier 24h)

**Definition**

::

  struct nvme_mfg_default_config_status_log {
    __u8 mdcsv;
    __u8 mdcs;
  };

**Members**

``mdcsv``
  Manufacturer Default Configuration Status Version: version of
  this data structure, shall be cleared to 0h

``mdcs``
  Manufacturer Default Configuration Status, see :c:type:`enum
  nvme_mfg_default_config_status_mdcs <nvme_mfg_default_config_status_mdcs>`





.. c:enum:: nvme_security_personality_attrs

   Security Personality Attributes data structure

**Constants**

``NVME_SEC_PERSONALITY_ASP``
  Allow Security Protocol: If set, then the
  security protocols specified by this data
  structure shall be allowed; if cleared,
  then they shall be prohibited.

``NVME_SEC_PERSONALITY_TCGP``
  TCG Security Protocol: specifies the
  security protocol range 01h to 06h.

``NVME_SEC_PERSONALITY_AHATSDP``
  Authentication in Host Attachments of
  Transient Storage Devices Protocol:
  specifies the security protocol value EEh.

``NVME_SEC_PERSONALITY_VSP_SHIFT``
  Shift amount to get the Vendor Specific
  Protocol Fx bitmap (security protocols F0h
  to FFh) field.

``NVME_SEC_PERSONALITY_VSP_MASK``
  Mask to get the Vendor Specific Protocol
  Fx bitmap field.




.. c:struct:: nvme_lba_rd

   LBA Range Descriptor

**Definition**

::

  struct nvme_lba_rd {
    __le64 rslba;
    __le32 rnlb;
    __u8 rsvd12[4];
  };

**Members**

``rslba``
  Range Starting LBA

``rnlb``
  Range Number of Logical Blocks

``rsvd12``
  Reserved





.. c:struct:: nvme_lbas_ns_element

   LBA Status Log Namespace Element

**Definition**

::

  struct nvme_lbas_ns_element {
    __le32 neid;
    __le32 nlrd;
    __u8 ratype;
    __u8 rsvd8[7];
    struct nvme_lba_rd lba_rd[];
  };

**Members**

``neid``
  Namespace Element Identifier

``nlrd``
  Number of LBA Range Descriptors

``ratype``
  Recommended Action Type. see **enum** nvme_lba_status_atype

``rsvd8``
  Reserved

``lba_rd``
  LBA Range Descriptor





.. c:enum:: nvme_lba_status_atype

   Action type the controller uses to return LBA status

**Constants**

``NVME_LBA_STATUS_ATYPE_ALLOCATED``
  Return tracked allocated LBAs status

``NVME_LBA_STATUS_ATYPE_SCAN_UNTRACKED``
  Perform scan and return Untracked and
  Tracked Potentially Unrecoverable LBAs
  status

``NVME_LBA_STATUS_ATYPE_TRACKED``
  Return Tracked Potentially Unrecoverable
  LBAs associated with physical storage




.. c:struct:: nvme_lba_status_log

   LBA Status Information Log

**Definition**

::

  struct nvme_lba_status_log {
    __le32 lslplen;
    __le32 nlslne;
    __le32 estulb;
    __u8 rsvd12[2];
    __le16 lsgc;
    struct nvme_lbas_ns_element elements[];
  };

**Members**

``lslplen``
  LBA Status Log Page Length

``nlslne``
  Number of LBA Status Log Namespace Elements

``estulb``
  Estimate of Unrecoverable Logical Blocks

``rsvd12``
  Reserved

``lsgc``
  LBA Status Generation Counter

``elements``
  LBA Status Log Namespace Element List





.. c:struct:: nvme_eg_event_aggregate_log

   Endurance Group Event Aggregate

**Definition**

::

  struct nvme_eg_event_aggregate_log {
    __le64 nr_entries;
    __le16 egids[];
  };

**Members**

``nr_entries``
  Number of Entries

``egids``
  Endurance Group Identifier





.. c:enum:: nvme_fid_supported_effects

   FID Supported and Effects Data Structure definitions

**Constants**

``NVME_FID_SUPPORTED_EFFECTS_FSUPP``
  FID Supported

``NVME_FID_SUPPORTED_EFFECTS_UDCC``
  User Data Content Change

``NVME_FID_SUPPORTED_EFFECTS_NCC``
  Namespace Capability Change

``NVME_FID_SUPPORTED_EFFECTS_NIC``
  Namespace Inventory Change

``NVME_FID_SUPPORTED_EFFECTS_CCC``
  Controller Capability Change

``NVME_FID_SUPPORTED_EFFECTS_UUID_SEL``
  UUID Selection Supported

``NVME_FID_SUPPORTED_EFFECTS_SCOPE_SHIFT``
  FID Scope Shift

``NVME_FID_SUPPORTED_EFFECTS_SCOPE_MASK``
  FID Scope Mask

``NVME_FID_SUPPORTED_EFFECTS_SCOPE_NS``
  Namespace Scope

``NVME_FID_SUPPORTED_EFFECTS_SCOPE_CTRL``
  Controller Scope

``NVME_FID_SUPPORTED_EFFECTS_SCOPE_NVM_SET``
  NVM Set Scope

``NVME_FID_SUPPORTED_EFFECTS_SCOPE_ENDGRP``
  Endurance Group Scope

``NVME_FID_SUPPORTED_EFFECTS_SCOPE_DOMAIN``
  Domain Scope

``NVME_FID_SUPPORTED_EFFECTS_SCOPE_NSS``
  NVM Subsystem Scope

``NVME_FID_SUPPORTED_EFFECTS_CDQSCP``
  Controller Data Queue

``NVME_FID_SUPPORTED_EFFECTS_RUHS``
  Reclaim Unit Handle Scope: if
  set, then modifying the
  attributes of the feature may
  impact Reclaim Unit Handles




.. c:struct:: nvme_fid_supported_effects_log

   Feature Identifiers Supported and Effects

**Definition**

::

  struct nvme_fid_supported_effects_log {
    __le32 fid_support[NVME_LOG_FID_SUPPORTED_EFFECTS_MAX];
  };

**Members**

``fid_support``
  Feature Identifier Supported





.. c:struct:: nvme_boot_partition

   Boot Partition Log

**Definition**

::

  struct nvme_boot_partition {
    __u8 lid;
    __u8 rsvd1[3];
    __le32 bpinfo;
    __u8 rsvd8[8];
    __u8 boot_partition_data[];
  };

**Members**

``lid``
  Boot Partition Identifier

``rsvd1``
  Reserved

``bpinfo``
  Boot Partition Information

``rsvd8``
  Reserved

``boot_partition_data``
  Contains the contents of the
  specified Boot Partition





.. c:enum:: nvme_boot_partition_info

   This field indicates the boot partition information

**Constants**

``NVME_BOOT_PARTITION_INFO_BPSZ_SHIFT``
  Shift amount to get the boot partition size from
  the :c:type:`struct nvme_boot_partition <nvme_boot_partition>`.bpinfo field.

``NVME_BOOT_PARTITION_INFO_ABPID_SHIFT``
  Shift amount to get the active boot partition ID
  from the :c:type:`struct nvme_boot_partition <nvme_boot_partition>`.bpinfo field.

``NVME_BOOT_PARTITION_INFO_BPSZ_MASK``
  Mask to get the boot partition size from the
  :c:type:`struct nvme_boot_partition <nvme_boot_partition>`.bpinfo field.

``NVME_BOOT_PARTITION_INFO_ABPID_MASK``
  Mask to get the active boot partition ID from the
  :c:type:`struct nvme_boot_partition <nvme_boot_partition>`.bpinfo field.




.. c:struct:: nvme_rotational_media_info_log

   Rotational Media Information Log

**Definition**

::

  struct nvme_rotational_media_info_log {
    __le16 endgid;
    __le16 numa;
    __le16 nrs;
    __u8 rsvd6[2];
    __le32 spinc;
    __le32 fspinc;
    __le32 ldc;
    __le32 fldc;
    __u8 rsvd24[488];
  };

**Members**

``endgid``
  Endurance Group Identifier

``numa``
  Number of Actuators

``nrs``
  Nominal Rotational Speed

``rsvd6``
  Reserved

``spinc``
  Spinup Count

``fspinc``
  Failed Spinup Count

``ldc``
  Load Count

``fldc``
  Failed Load Count

``rsvd24``
  Reserved





.. c:struct:: nvme_dispersed_ns_participating_nss_log

   Dispersed Namespace Participating NVM Subsystems Log

**Definition**

::

  struct nvme_dispersed_ns_participating_nss_log {
    __le64 genctr;
    __le64 numpsub;
    __u8 rsvd16[240];
    __u8 participating_nss[];
  };

**Members**

``genctr``
  Generation Counter

``numpsub``
  Number of Participating NVM Subsystems

``rsvd16``
  Reserved

``participating_nss``
  Participating NVM Subsystem Entry





.. c:struct:: nvme_mgmt_addr_desc

   Management Address Descriptor

**Definition**

::

  struct nvme_mgmt_addr_desc {
    __u8 mat;
    __u8 rsvd1[3];
    __u8 madrs[508];
  };

**Members**

``mat``
  Management Address Type

``rsvd1``
  Reserved

``madrs``
  Management Address





.. c:struct:: nvme_mgmt_addr_list_log

   Management Address List Log

**Definition**

::

  struct nvme_mgmt_addr_list_log {
    struct nvme_mgmt_addr_desc      mad[8];
  };

**Members**

``mad``
  Management Address Descriptor





.. c:struct:: nvme_eom_lane_desc

   EOM Lane Descriptor

**Definition**

::

  struct nvme_eom_lane_desc {
    __u8 rsvd0;
    __u8 mstatus;
    __u8 lane;
    __u8 eye;
    __le16 top;
    __le16 bottom;
    __le16 left;
    __le16 right;
    __le16 nrows;
    __le16 ncols;
    __le16 edlen;
    __u8 rsvd18[14];
    __u8 eye_desc[];
  };

**Members**

``rsvd0``
  Reserved

``mstatus``
  Measurement Status

``lane``
  Lane number

``eye``
  Eye number

``top``
  Absolute number of rows from center to top edge of eye

``bottom``
  Absolute number of rows from center to bottom edge of eye

``left``
  Absolute number of rows from center to left edge of eye

``right``
  Absolute number of rows from center to right edge of eye

``nrows``
  Number of Rows

``ncols``
  Number of Columns

``edlen``
  Eye Data Length

``rsvd18``
  Reserved

``eye_desc``
  Printable Eye, Eye Data, and any Padding





.. c:struct:: nvme_phy_rx_eom_log

   Physical Interface Receiver Eye Opening Measurement Log

**Definition**

::

  struct nvme_phy_rx_eom_log {
    __u8 lid;
    __u8 eomip;
    __le16 hsize;
    __le32 rsize;
    __u8 eomdgn;
    __u8 lr;
    __u8 odp;
    __u8 lanes;
    __u8 epl;
    __u8 lspfc;
    __u8 li;
    __u8 rsvd15[3];
    __le16 lsic;
    __le32 dsize;
    __le16 nd;
    __le16 maxtb;
    __le16 maxlr;
    __le16 etgood;
    __le16 etbetter;
    __le16 etbest;
    __u8 rsvd36[28];
    struct nvme_eom_lane_desc descs[];
  };

**Members**

``lid``
  Log Identifier

``eomip``
  EOM In Progress

``hsize``
  Header Size

``rsize``
  Result Size

``eomdgn``
  EOM Data Generation Number

``lr``
  Log Revision

``odp``
  Optional Data Present

``lanes``
  Number of lanes configured for this port

``epl``
  Eyes Per Lane

``lspfc``
  Log Specific Parameter Field Copy

``li``
  Link Information

``rsvd15``
  Reserved

``lsic``
  Log Specific Identifier Copy

``dsize``
  Descriptor Size

``nd``
  Number of Descriptors

``maxtb``
  Maximum Top Bottom

``maxlr``
  Maximum Left Right

``etgood``
  Estimated Time for Good Quality

``etbetter``
  Estimated Time for Better Quality

``etbest``
  Estimated Time for Best Quality

``rsvd36``
  Reserved

``descs``
  EOM Lane Descriptors





.. c:enum:: nvme_eom_optional_data_present

   EOM Optional Data Present Fields

**Constants**

``NVME_EOM_ODP_PEFP_SHIFT``
  Shift amount to get the printable eye field present
  from the :c:type:`struct nvme_phy_rx_eom_log <nvme_phy_rx_eom_log>`.odp field.

``NVME_EOM_ODP_EDFP_SHIFT``
  Shift amount to get the eye data field present
  from the :c:type:`struct nvme_phy_rx_eom_log <nvme_phy_rx_eom_log>`.odp field.

``NVME_EOM_ODP_RSVD_SHIFT``
  Shift amount to get the reserved optional data present
  from the :c:type:`struct nvme_phy_rx_eom_log <nvme_phy_rx_eom_log>`.odp field.

``NVME_EOM_ODP_PEFP_MASK``
  Mask to get the printable eye field present
  from the :c:type:`struct nvme_phy_rx_eom_log <nvme_phy_rx_eom_log>`.odp field.

``NVME_EOM_ODP_EDFP_MASK``
  Mask to get the eye data field present
  from the :c:type:`struct nvme_phy_rx_eom_log <nvme_phy_rx_eom_log>`.odp field.

``NVME_EOM_ODP_RSVD_MASK``
  Mask to get the reserved data present
  from the :c:type:`struct nvme_phy_rx_eom_log <nvme_phy_rx_eom_log>`.odp field.




.. c:enum:: nvme_eom_optional_data

   EOM Optional Data Present Fields (Deprecated)

**Constants**

``NVME_EOM_PRINTABLE_EYE_PRESENT``
  Printable Eye Present

``NVME_EOM_EYE_DATA_PRESENT``
  Eye Data Present




.. c:enum:: nvme_phy_rx_eom_progress

   EOM In Progress Values

**Constants**

``NVME_PHY_RX_EOM_NOT_STARTED``
  EOM Not Started

``NVME_PHY_RX_EOM_IN_PROGRESS``
  EOM In Progress

``NVME_PHY_RX_EOM_COMPLETED``
  EOM Completed




.. c:struct:: nvme_reachability_group_desc

   Reachability Group Descriptor

**Definition**

::

  struct nvme_reachability_group_desc {
    __le32 rgid;
    __le32 nnid;
    __le64 chngc;
    __u8 rsvd16[16];
    __le32 nsid[];
  };

**Members**

``rgid``
  Reachability Group ID

``nnid``
  Number of NSID Values

``chngc``
  Change Count

``rsvd16``
  Reserved

``nsid``
  Namespace Identifier List





.. c:struct:: nvme_reachability_groups_log

   Reachability Groups Log

**Definition**

::

  struct nvme_reachability_groups_log {
    __le64 chngc;
    __le16 nrgd;
    __u8 rsvd10[6];
    struct nvme_reachability_group_desc     rgd[];
  };

**Members**

``chngc``
  Change Count

``nrgd``
  Number of Reachability Group Descriptors

``rsvd10``
  Reserved

``rgd``
  Reachability Group Descriptor List





.. c:struct:: nvme_reachability_association_desc

   Reachability Association Descriptor

**Definition**

::

  struct nvme_reachability_association_desc {
    __le32 rasid;
    __le32 nrid;
    __le64 chngc;
    __u8 rac;
    __u8 rsvd17[15];
    __le32 rgid[];
  };

**Members**

``rasid``
  Reachability Association ID

``nrid``
  Number of RGID Values

``chngc``
  Change Count

``rac``
  Reachability Association Characteristics

``rsvd17``
  Reserved

``rgid``
  Reachability Group Identifier List





.. c:struct:: nvme_reachability_associations_log

   Reachability Associations Log

**Definition**

::

  struct nvme_reachability_associations_log {
    __le64 chngc;
    __le16 nrad;
    __u8 rsvd10[6];
    struct nvme_reachability_association_desc       rad[];
  };

**Members**

``chngc``
  Change Count

``nrad``
  Number of Reachability Association Descriptors

``rsvd10``
  Reserved

``rad``
  Reachability Association Descriptor List





.. c:struct:: nvme_media_unit_stat_desc

   Media Unit Status Descriptor

**Definition**

::

  struct nvme_media_unit_stat_desc {
    __le16 muid;
    __le16 domainid;
    __le16 endgid;
    __le16 nvmsetid;
    __le16 cap_adj_fctr;
    __u8 avl_spare;
    __u8 percent_used;
    __u8 mucs;
    __u8 cio;
  };

**Members**

``muid``
  Media Unit Identifier

``domainid``
  Domain Identifier

``endgid``
  Endurance Group Identifier

``nvmsetid``
  NVM Set Identifier

``cap_adj_fctr``
  Capacity Adjustment Factor

``avl_spare``
  Available Spare

``percent_used``
  Percentage Used

``mucs``
  Number of Channels attached to media units

``cio``
  Channel Identifiers Offset





.. c:struct:: nvme_media_unit_stat_log

   Media Unit Status

**Definition**

::

  struct nvme_media_unit_stat_log {
    __le16 nmu;
    __le16 cchans;
    __le16 sel_config;
    __u8 rsvd6[10];
    struct nvme_media_unit_stat_desc mus_desc[];
  };

**Members**

``nmu``
  Number unit status descriptor

``cchans``
  Number of Channels

``sel_config``
  Selected Configuration

``rsvd6``
  Reserved

``mus_desc``
  Media unit statistic descriptors





.. c:struct:: nvme_media_unit_config_desc

   Media Unit Configuration Descriptor

**Definition**

::

  struct nvme_media_unit_config_desc {
    __le16 muid;
    __u8 rsvd2[4];
    __le16 mudl;
  };

**Members**

``muid``
  Media Unit Identifier

``rsvd2``
  Reserved

``mudl``
  Media Unit Descriptor Length





.. c:struct:: nvme_channel_config_desc

   Channel Configuration Descriptor

**Definition**

::

  struct nvme_channel_config_desc {
    __le16 chanid;
    __le16 chmus;
    struct nvme_media_unit_config_desc mu_config_desc[];
  };

**Members**

``chanid``
  Channel Identifier

``chmus``
  Number Channel Media Units

``mu_config_desc``
  Channel Unit config descriptors.
  See **struct** nvme_media_unit_config_desc





.. c:struct:: nvme_end_grp_chan_desc

   Endurance Group Channel Configuration Descriptor

**Definition**

::

  struct nvme_end_grp_chan_desc {
    __le16 egchans;
    struct nvme_channel_config_desc chan_config_desc[];
  };

**Members**

``egchans``
  Number of Channels

``chan_config_desc``
  Channel config descriptors.
  See **struct** nvme_channel_config_desc





.. c:struct:: nvme_end_grp_config_desc

   Endurance Group Configuration Descriptor

**Definition**

::

  struct nvme_end_grp_config_desc {
    __le16 endgid;
    __le16 cap_adj_factor;
    __u8 rsvd4[12];
    __u8 tegcap[16];
    __u8 segcap[16];
    __u8 end_est[16];
    __u8 rsvd64[16];
    __le16 egsets;
    __le16 nvmsetid[];
  };

**Members**

``endgid``
  Endurance Group Identifier

``cap_adj_factor``
  Capacity Adjustment Factor

``rsvd4``
  Reserved

``tegcap``
  Total Endurance Group Capacity

``segcap``
  Spare Endurance Group Capacity

``end_est``
  Endurance Estimate

``rsvd64``
  Reserved

``egsets``
  Number of NVM Sets

``nvmsetid``
  NVM Set Identifier





.. c:struct:: nvme_capacity_config_desc

   Capacity Configuration structure definitions

**Definition**

::

  struct nvme_capacity_config_desc {
    __le16 cap_config_id;
    __le16 domainid;
    __le16 egcn;
    __u8 rsvd6[26];
    struct nvme_end_grp_config_desc egcd[];
  };

**Members**

``cap_config_id``
  Capacity Configuration Identifier

``domainid``
  Domain Identifier

``egcn``
  Number Endurance Group Configuration
  Descriptors

``rsvd6``
  Reserved

``egcd``
  Endurance Group Config descriptors.
  See **struct** nvme_end_grp_config_desc





.. c:struct:: nvme_supported_cap_config_list_log

   Supported Capacity Configuration list log page

**Definition**

::

  struct nvme_supported_cap_config_list_log {
    __u8 sccn;
    __u8 rsvd1[15];
    struct nvme_capacity_config_desc cap_config_desc[];
  };

**Members**

``sccn``
  Number of capacity configuration

``rsvd1``
  Reserved

``cap_config_desc``
  Capacity configuration descriptor.
  See **struct** nvme_capacity_config_desc





.. c:struct:: nvme_lockdown_log

   Command and Feature Lockdown Log

**Definition**

::

  struct nvme_lockdown_log {
    __u8 cfila;
    __u8 rsvd1[2];
    __u8 lngth;
    __u8 cfil[508];
  };

**Members**

``cfila``
  Contents of the Command and Feature Identifier List field in the log page.

``rsvd1``
  Reserved

``lngth``
  Length of Command and Feature Identifier List field

``cfil``
  Command and Feature Identifier List





.. c:enum:: nvme_lockdown_csel

   Lockdown Command Dword 10 - Controller Select (CSEL)

**Constants**

``NVME_LOCKDOWN_CSEL_NVM_SUBSYSTEM``
  NVM Subsystem: this command affects
  all controllers in the NVM subsystem.

``NVME_LOCKDOWN_CSEL_SPECIFIC_CTRL``
  Specific Controller: this command
  affects the controller specified in
  the Controller Select Specific (CSS)
  field of Command Dword 14.

``NVME_LOCKDOWN_CSEL_SECONDARY_CTRLS``
  Secondary Controllers for a Specific
  Primary Controller: this command
  affects all secondary controllers
  associated with the primary
  controller specified in the CSS
  field of Command Dword 14.

``NVME_LOCKDOWN_CSEL_VENDOR_SPECIFIC``
  Vendor Specific




.. c:enum:: nvme_lockdown_log_lsp

   Command and Feature Lockdown Log Specific Parameter field (Get Log Page Command Dword 10 LSP field)

**Constants**

``NVME_LOCKDOWN_LOG_LSP_SCP_SHIFT``
  Shift amount to get the Scope (SCP)

``NVME_LOCKDOWN_LOG_LSP_SCP_MASK``
  Mask to get SCP

``NVME_LOCKDOWN_LOG_LSP_CNTTS_SHIFT``
  Shift amount to get the Contents
  (CNTTS)

``NVME_LOCKDOWN_LOG_LSP_CNTTS_MASK``
  Mask to get CNTTS

``NVME_LOCKDOWN_LOG_LSP_ELPF``
  Enhanced Log Page Format: if set,
  then the Controller-scoped Enhanced
  log page format (see :c:type:`struct
  nvme_lockdown_log_enhanced <nvme_lockdown_log_enhanced>`) is
  requested instead of :c:type:`struct
  nvme_lockdown_log <nvme_lockdown_log>`. The Controller
  Identifier is specified via the Log
  Specific Identifier field of Command
  Dword 11 (``NVME_LOG_CDW11_LSI_SHIFT``).




.. c:struct:: nvme_lockdown_cfi_desc

   Command and Feature Identifier Descriptor

**Definition**

::

  struct nvme_lockdown_cfi_desc {
    __u8 cfi;
    __u8 cfia;
  };

**Members**

``cfi``
  Command and Feature Identifier: contents depend on the Contents
  Selected (CS) and Scope Selected (SS) fields of **struct**
  nvme_lockdown_log_enhanced.cfia.

``cfia``
  Command and Feature Identifier Attributes, see :c:type:`enum
  nvme_lockdown_cfi_desc_cfia <nvme_lockdown_cfi_desc_cfia>`.





.. c:enum:: nvme_lockdown_cfi_desc_cfia

   Command and Feature Identifier Descriptor - Command and Feature Identifier Attributes (CFIA)

**Constants**

``NVME_LOCKDOWN_CFI_DESC_CFIA_ACNTL``
  All Controllers: if set, then **cfi** is
  reported by all controllers in the NVM
  subsystem; if cleared, then **cfi** is
  reported by at least one but not all
  controllers in the NVM subsystem.




.. c:enum:: nvme_lockdown_log_enhanced_cfia

   Command and Feature Lockdown Log Page - Enhanced - Command and Feature Identifier Attributes (CFIA)

**Constants**

``NVME_LOCKDOWN_LOG_ENHANCED_CFIA_SS_SHIFT``
  Shift amount to get the
  Scope Selected (SS)

``NVME_LOCKDOWN_LOG_ENHANCED_CFIA_SS_MASK``
  Mask to get SS

``NVME_LOCKDOWN_LOG_ENHANCED_CFIA_CS_SHIFT``
  Shift amount to get the
  Contents Selected (CS)

``NVME_LOCKDOWN_LOG_ENHANCED_CFIA_CS_MASK``
  Mask to get CS




.. c:struct:: nvme_lockdown_log_enhanced

   Command and Feature Lockdown Log Page - Enhanced

**Definition**

::

  struct nvme_lockdown_log_enhanced {
    __u8 ver;
    __u8 cfia;
    __le16 cntlid;
    __le32 sze;
    __le16 ncfid;
    __le16 cfids;
    __u8 rsvd12[4];
    struct nvme_lockdown_cfi_desc   cfid[];
  };

**Members**

``ver``
  Version: cleared to 0h.

``cfia``
  Command and Feature Identifier Attributes, see :c:type:`enum
  nvme_lockdown_log_enhanced_cfia <nvme_lockdown_log_enhanced_cfia>`.

``cntlid``
  Controller Identifier this log page applies to. FFFFh indicates
  the descriptor list entries are each reported by one or more
  controllers in the NVM subsystem, rather than a single
  controller.

``sze``
  Size of this log page in bytes.

``ncfid``
  Number of Command and Feature Identifier Descriptors in **cfid**.

``cfids``
  Command and Feature Identifier Descriptors Size: size in bytes
  of each entry in **cfid**.

``rsvd12``
  Reserved

``cfid``
  Command and Feature Identifier Descriptor list, see :c:type:`struct
  nvme_lockdown_cfi_desc <nvme_lockdown_cfi_desc>`.





.. c:struct:: nvme_sanitize_log_page

   Sanitize Status (Log Identifier 81h)

**Definition**

::

  struct nvme_sanitize_log_page {
    __le16 sprog;
    __le16 sstat;
    __le32 scdw10;
    __le32 eto;
    __le32 etbe;
    __le32 etce;
    __le32 etond;
    __le32 etbend;
    __le32 etcend;
    __le32 etpvds;
    __u8 ssi;
    __u8 rsvd37[475];
  };

**Members**

``sprog``
  Sanitize Progress (SPROG): indicates the fraction complete of the
  sanitize operation. The value is a numerator of the fraction
  complete that has 65,536 (10000h) as its denominator. This value
  shall be set to FFFFh if the **sstat** field is not set to
  ``NVME_SANITIZE_SSTAT_STATUS_IN_PROGRESS``.

``sstat``
  Sanitize Status (SSTAT): indicates the status associated with
  the most recent sanitize operation. See :c:type:`enum nvme_sanitize_sstat <nvme_sanitize_sstat>`.

``scdw10``
  Sanitize Command Dword 10 Information (SCDW10): contains the value
  of the Command Dword 10 field of the Sanitize command that started
  the sanitize operation.

``eto``
  Estimated Time For Overwrite: indicates the number of seconds required
  to complete an Overwrite sanitize operation with 16 passes in
  the background when the No-Deallocate Modifies Media After Sanitize
  field is not set to 10b. A value of 0h indicates that the sanitize
  operation is expected to be completed in the background when the
  Sanitize command that started that operation is completed. A value
  of FFFFFFFFh indicates that no time period is reported.

``etbe``
  Estimated Time For Block Erase: indicates the number of seconds
  required to complete a Block Erase sanitize operation in the
  background when the No-Deallocate Modifies Media After Sanitize
  field is not set to 10b. A value of 0h indicates that the sanitize
  operation is expected to be completed in the background when the
  Sanitize command that started that operation is completed.
  A value of FFFFFFFFh indicates that no time period is reported.

``etce``
  Estimated Time For Crypto Erase: indicates the number of seconds
  required to complete a Crypto Erase sanitize operation in the
  background when the No-Deallocate Modifies Media After Sanitize
  field is not set to 10b. A value of 0h indicates that the sanitize
  operation is expected to be completed in the background when the
  Sanitize command that started that operation is completed.
  A value of FFFFFFFFh indicates that no time period is reported.

``etond``
  Estimated Time For Overwrite With No-Deallocate Media Modification:
  indicates the number of seconds required to complete an Overwrite
  sanitize operation and the associated additional media modification
  after the Overwrite sanitize operation in the background when
  the No-Deallocate After Sanitize bit was set to 1 in the Sanitize
  command that requested the Overwrite sanitize operation; and
  the No-Deallocate Modifies Media After Sanitize field is set to 10b.
  A value of 0h indicates that the sanitize operation is expected
  to be completed in the background when the Sanitize command that
  started that operation is completed. A value of FFFFFFFFh indicates
  that no time period is reported.

``etbend``
  Estimated Time For Block Erase With No-Deallocate Media Modification:
  indicates the number of seconds required to complete a Block Erase
  sanitize operation and the associated additional media modification
  after the Block Erase sanitize operation in the background when
  the No-Deallocate After Sanitize bit was set to 1 in the Sanitize
  command that requested the Overwrite sanitize operation; and
  the No-Deallocate Modifies Media After Sanitize field is set to 10b.
  A value of 0h indicates that the sanitize operation is expected
  to be completed in the background when the Sanitize command that
  started that operation is completed. A value of FFFFFFFFh indicates
  that no time period is reported.

``etcend``
  Estimated Time For Crypto Erase With No-Deallocate Media Modification:
  indicates the number of seconds required to complete a Crypto Erase
  sanitize operation and the associated additional media modification
  after the Crypto Erase sanitize operation in the background when
  the No-Deallocate After Sanitize bit was set to 1 in the Sanitize
  command that requested the Overwrite sanitize operation; and
  the No-Deallocate Modifies Media After Sanitize field is set to 10b.
  A value of 0h indicates that the sanitize operation is expected
  to be completed in the background when the Sanitize command that
  started that operation is completed. A value of FFFFFFFFh indicates
  that no time period is reported.

``etpvds``
  Estimated Time For Post-Verification Deallocation State: indicates the
  number of seconds required to deallocate all media allocated for user data
  after exiting the Media Verification state (i.e., the time difference between
  entering and exiting the Post-Verification Deallocation state), if that state
  is entered as part of the sanitize operation. A value of FFFFFFFFh indicates
  that no time period is reported.

``ssi``
  Sanitize State Information: indicate the state of the Sanitize Operation
  State Machine.

``rsvd37``
  Reserved





.. c:enum:: nvme_sanitize_sstat

   Sanitize Status (SSTAT)

**Constants**

``NVME_SANITIZE_SSTAT_STATUS_SHIFT``
  Shift amount to get the status value of
  the most recent sanitize operation from
  the :c:type:`struct nvme_sanitize_log_page <nvme_sanitize_log_page>`.sstat
  field.

``NVME_SANITIZE_SSTAT_STATUS_MASK``
  Mask to get the status value of the most
  recent sanitize operation.

``NVME_SANITIZE_SSTAT_STATUS_NEVER_SANITIZED``
  The NVM subsystem has never been
  sanitized.

``NVME_SANITIZE_SSTAT_STATUS_COMPLETE_SUCCESS``
  The most recent sanitize operation
  completed successfully including any
  additional media modification.

``NVME_SANITIZE_SSTAT_STATUS_IN_PROGRESS``
  A sanitize operation is currently in
  progress.

``NVME_SANITIZE_SSTAT_STATUS_COMPLETED_FAILED``
  The most recent sanitize operation
  failed.

``NVME_SANITIZE_SSTAT_STATUS_ND_COMPLETE_SUCCESS``
  The most recent sanitize operation
  for which No-Deallocate After Sanitize was
  requested has completed successfully with
  deallocation of all user data.

``NVME_SANITIZE_SSTAT_COMPLETED_PASSES_SHIFT``
  Shift amount to get the number
  of completed passes if the most recent
  sanitize operation was an Overwrite. This
  value shall be cleared to 0h if the most
  recent sanitize operation was not
  an Overwrite.

``NVME_SANITIZE_SSTAT_COMPLETED_PASSES_MASK``
  Mask to get the number of completed
  passes.

``NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED_SHIFT``
  Shift amount to get the Global
  Data Erased value from the
  :c:type:`struct nvme_sanitize_log_page <nvme_sanitize_log_page>`.sstat field.

``NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED_MASK``
  Mask to get the Global Data Erased
  value.

``NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED``
  Global Data Erased: if set, then no
  namespace user data in the NVM subsystem
  has been written to and no Persistent
  Memory Region in the NVM subsystem has
  been enabled since being manufactured and
  the NVM subsystem has never been sanitized;
  or since the most recent successful sanitize
  operation.

``NVME_SANITIZE_SSTAT_MVCNCLD_SHIFT``
  Shift amount to get the value of Media Verification
  Canceled bit of Sanitize status field.

``NVME_SANITIZE_SSTAT_MVCNCLD_MASK``
  Mask to get the value of Media Verification Canceled
  bit of Sanitize status field.

``NVME_SANITIZE_SSTAT_PRGD_SHIFT``
  Shift amount to get the Purged (PRGD)
  bit of Sanitize status field.

``NVME_SANITIZE_SSTAT_PRGD_MASK``
  Mask to get the Purged (PRGD) bit of
  Sanitize status field.

``NVME_SANITIZE_SSTAT_PRGD``
  Purged: if set, then the most recent
  sanitize operation purged user data, as
  defined by IEEE Std 2883, because the
  Purge Required (PREQ) bit was set to
  '1' in the command that started that
  sanitize operation.




.. c:enum:: nvme_sanitize_ssi

   Sanitize State Information (SSI)

**Constants**

``NVME_SANITIZE_SSI_SANS_SHIFT``
  Shift amount to get the value of Sanitize State
  from Sanitize State Information (SSI) field.

``NVME_SANITIZE_SSI_SANS_MASK``
  Mask to get the value of Sanitize State from
  Sanitize State Information (SSI) field.

``NVME_SANITIZE_SSI_FAILS_SHIFT``
  Shift amount to get the value of Failure State
  from Sanitize State Information (SSI) field.

``NVME_SANITIZE_SSI_FAILS_MASK``
  Mask to get the value of Failure State from
  Sanitize State Information (SSI) field.

``NVME_SANITIZE_SSI_IDLE``
  No sanitize operation is in process.

``NVME_SANITIZE_SSI_RESTRICT_PROCESSING``
  The Sanitize operation is in Restricted Processing
  State.

``NVME_SANITIZE_SSI_RESTRICT_FAILURE``
  The Sanitize operation is in Restricted Failure
  State. This state is entered if sanitize processing
  was performed in the Restricted Processing state and
  sanitize processing failed or a failure occurred
  during deallocation of media allocated for user data
  in the Post-Verification Deallocation state.

``NVME_SANITIZE_SSI_UNRESTRICT_PROCESSING``
  The Sanitize operation is in Unrestricted Processing
  State.

``NVME_SANITIZE_SSI_UNRESTRICT_FAILURE``
  The Sanitize operation is in Unrestricted Failure
  State. This state is entered if sanitize processing
  was performed in the Unrestricted Processing state
  and sanitize processing failed or a failure occurred
  during deallocation of media allocated for user data
  in the Post-Verification.

``NVME_SANITIZE_SSI_MEDIA_VERIFICATION``
  The Sanitize operation is in Media Verification
  State. In this state, the sanitize processing
  completed successfully, and all media allocated for
  user data in the sanitization target is readable by
  the host for purposes of verifying sanitization.

``NVME_SANITIZE_SSI_POST_VERIF_DEALLOC``
  The Sanitize operation is in Post-Verification
  Deallocation State. In this state, the controller
  shall deallocate all media allocated for user data
  in the sanitization target.




.. c:enum:: nvme_lockdown_log_scope

   lockdown log page scope attributes

**Constants**

``NVME_LOCKDOWN_ADMIN_CMD``
  Scope value for Admin commandS

``NVME_LOCKDOWN_FEATURE_ID``
  Scope value for Feature ID

``NVME_LOCKDOWN_MI_CMD_SET``
  Scope value for Management Interface commands

``NVME_LOCKDOWN_PCI_CMD_SET``
  Scope value for PCI commands




.. c:enum:: nvme_lockdown_log_contents

   lockdown log page content attributes

**Constants**

``NVME_LOCKDOWN_SUPPORTED_CMD``
  Content value for Supported commands

``NVME_LOCKDOWN_PROHIBITED_CMD``
  Content value for prohibited commands

``NVME_LOCKDOWN_PROHIBITED_OUTOFBAND_CMD``
  Content value for prohibited side band commands




.. c:enum:: nvme_lockdown_scope_contents

   Lockdown Log shift and mask

**Constants**

``NVME_LOCKDOWN_SS_SHIFT``
  Lockdown log scope select Shift

``NVME_LOCKDOWN_SS_MASK``
  Lockdown log scope select Mask

``NVME_LOCKDOWN_CS_SHIFT``
  Lockdown log contents Shift

``NVME_LOCKDOWN_CS_MASK``
  Lockdown log contents Mask




.. c:enum:: nvme_pma

   Power Measurement Attributes (PMA) field

**Constants**

``NVME_PMA_PME_SHIFT``
  Shift amount to get the power measurement enable

``NVME_PMA_NCPDF_SHIFT``
  Shift amount to get the non-contiguous power data flag

``NVME_PMA_EPF_SHIFT``
  Shift amount to get the estimated power flag

``NVME_PMA_MIPWRTS_SHIFT``
  Shift amount to get the maximum interval power timestamp support

``NVME_PMA_PHDO_SHIFT``
  Shift amount to get the power histogram descriptor overflow

``NVME_PMA_PMT_SHIFT``
  Shift amount to get the power measurement type

``NVME_PMA_PME_MASK``
  Mask to get the power measurement enable

``NVME_PMA_NCPDF_MASK``
  Mask to get the non-contiguous power data flag

``NVME_PMA_EPF_MASK``
  Mask to get the estimated power flag

``NVME_PMA_MIPWRTS_MASK``
  Mask to get the maximum interval power timestamp support

``NVME_PMA_PHDO_MASK``
  Mask to get the power histogram descriptor overflow

``NVME_PMA_PMT_MASK``
  Mask to get the power measurement type




.. c:struct:: nvme_power_histogram_desc

   Power Histogram Descriptor

**Definition**

::

  struct nvme_power_histogram_desc {
    __le32 phbc;
    __le32 phblt;
  };

**Members**

``phbc``
  Power Histogram Bin Count. Does not wrap after ``FFFFFFFFh``.
  Cleared to ``0h`` if PMC is ``0h``.

``phblt``
  Power Histogram Bin Lower Threshold. Bits 17:16 are PWRS
  (see :c:type:`enum nvme_psd_ps <nvme_psd_ps>`), bits 15:0 are PWRV.





.. c:struct:: nvme_timestamp

   Timestamp - Data Structure for Get Features

**Definition**

::

  struct nvme_timestamp {
    __u8 timestamp[6];
    __u8 attr;
    __u8 rsvd;
  };

**Members**

``timestamp``
  Timestamp value based on origin and synch field

``attr``
  Attribute

``rsvd``
  Reserved





.. c:struct:: nvme_voltage_measurement_log

   Voltage Measurement Log Page (Log Identifier 27h)

**Definition**

::

  struct nvme_voltage_measurement_log {
    __u8 vmgn;
    __u8 vma;
    __le16 vsi;
    __le32 vmlsz;
    __le16 nvmds;
    __le16 nvmde;
    __le16 svmtr;
    struct nvme_timestamp   svmts;
    __le16 cntlid;
    __le16 vlvss;
    __u8 rsvd26[6];
    __le16 ovol;
    __le16 ovc;
    __le16 ovlt;
    struct nvme_timestamp   ovts;
    __u8 iovpe;
    __le16 uvol;
    __le16 uvc;
    __le16 uvlt;
    struct nvme_timestamp   uvts;
    __u8 iuvpe;
    __u8 rsvd62[2];
    __le16 ivmd[];
  };

**Members**

``vmgn``
  Voltage Measurement Generation Number: incremented each time a
  Set Features command starts Voltage Measurements.

``vma``
  Voltage Measurement Attributes, see :c:type:`enum
  nvme_voltage_measurement_vma <nvme_voltage_measurement_vma>`.

``vsi``
  Voltage Sensor Info, see :c:type:`enum nvme_voltage_measurement_vsi <nvme_voltage_measurement_vsi>`.
  Meaningless if the VMC bit is cleared to '0' in **vma**.

``vmlsz``
  Voltage Measurement Log Size: size of this log page in bytes.

``nvmds``
  Number of Voltage Measurement Descriptors Supported: maximum
  number of entries in the Interval Voltage Measurement Descriptor
  list.

``nvmde``
  Number of Voltage Measurement Descriptors Entries: number of
  entries in **ivmd**.

``svmtr``
  Stop Voltage Measurement Time Remaining, in minutes rounded up.

``svmts``
  Stop Voltage Measurement Timestamp: time at which interval
  voltage measurements stopped being collected. See :c:type:`struct
  nvme_timestamp <nvme_timestamp>`.

``cntlid``
  Controller Identifier associated with **vsi**, **svmts**, **ovts**, and
  **uvts**.

``vlvss``
  Voltage Log Vendor Specific Size: size in bytes of the Vendor
  Specific field following **ivmd**.

``rsvd26``
  Reserved

``ovol``
  Overvoltage, see :c:type:`enum nvme_voltage_measurement_ovol <nvme_voltage_measurement_ovol>`.

``ovc``
  Overvoltage Count.

``ovlt``
  Overvoltage Log Threshold, in units of the Voltage Sensor Sample
  Scale.

``ovts``
  Overvoltage Timestamp. See :c:type:`struct nvme_timestamp <nvme_timestamp>`.

``iovpe``
  Interval Overvoltage Percent Error (0 to 100). 255 indicates a
  value is not reported.

``uvol``
  Undervoltage, see :c:type:`enum nvme_voltage_measurement_uvol <nvme_voltage_measurement_uvol>`.

``uvc``
  Undervoltage Count.

``uvlt``
  Undervoltage Log Threshold, in units of the Voltage Sensor
  Sample Scale.

``uvts``
  Undervoltage Timestamp. See :c:type:`struct nvme_timestamp <nvme_timestamp>`.

``iuvpe``
  Interval Undervoltage Percent Error (0 to 100). 255 indicates a
  value is not reported.

``rsvd62``
  Reserved

``ivmd``
  Interval Voltage Measurement Descriptor list, see :c:type:`enum
  nvme_voltage_measurement_ivmd <nvme_voltage_measurement_ivmd>`. Followed by a Vendor Specific
  field of **vlvss** bytes, if non-zero.





.. c:enum:: nvme_timestamp_attr

   Timestamp Attribute field

**Constants**

``NVME_TIMESTAMP_ATTR_SYNC_SHIFT``
  Shift amount to get the timestamp synch

``NVME_TIMESTAMP_ATTR_TO_SHIFT``
  Shift amount to get the timestamp origin

``NVME_TIMESTAMP_ATTR_SYNC_MASK``
  Mask to get the timestamp synch

``NVME_TIMESTAMP_ATTR_TO_MASK``
  Mask to get the timestamp origin




.. c:struct:: nvme_power_meas_log

   Power Measurement Log Page (Log Identifier 25h)

**Definition**

::

  struct nvme_power_meas_log {
    __u8 ver;
    __u8 pmgn;
    __le16 pma;
    __le32 sze;
    __le32 pmc;
    __le16 nphd;
    __le16 smtr;
    struct nvme_timestamp   smts;
    __le16 phds;
    __le16 phbs;
    __le16 nphds;
    __le16 vss;
    __le32 phdoc;
    __u8 rsvd36[4];
    __le32 aipwr;
    __le32 mipwr;
    struct nvme_timestamp   mipwrt;
    __u8 ipwrpe;
    __u8 rsvd57[7];
    struct nvme_power_histogram_desc descs[];
  };

**Members**

``ver``
  Version. Shall be cleared to ``0h``.

``pmgn``
  Power Measurement Generation Number. Incremented each time a
  Set Features command with Action = ``1h`` (Start Power Measurements)
  is successfully completed. Rolls over from ``FFh`` to ``0h``.

``pma``
  Power Measurement Attributes. See :c:type:`enum nvme_pma <nvme_pma>`.

``sze``
  Size. Indicates the size of this log page in bytes.

``pmc``
  Power Measurement Count. Number of interval power measurements
  collected. Does not wrap after ``FFFFFFFFh``. Cleared to ``0h`` when
  Start Power Measurements succeeds or if no measurement has occurred.

``nphd``
  Number of Power Histogram Descriptors in this log page.

``smtr``
  Stop Measurement Time Remaining. Time remaining in minutes until
  controller stops collecting interval power measurements.
  ``0h`` means not specified.

``smts``
  Stop Measurement Timestamp. Timestamp of when interval power
  measurements stopped being collected. See :c:type:`struct nvme_timestamp <nvme_timestamp>`.

``phds``
  Power Histogram Descriptor Size. Size in bytes of each descriptor.

``phbs``
  Power Histogram Bin Size. Size in milliwatts of each bin.
  Shall be set to 250 milliwatts.

``nphds``
  Number of Power Histogram Descriptors Supported. Maximum number
  of descriptors that can be reported. If ``0h``, NPHD shall be
  cleared to ``0h`` and no descriptors are reported.

``vss``
  Vendor Specific Size. Size in bytes of the Vendor Specific field.

``phdoc``
  Power Histogram Descriptor Overflow Count. Number of interval
  power measurements greater than the maximum power indicated by
  the last Power Histogram Descriptor. Does not wrap after ``FFFFFFFFh``.

``rsvd36``
  Reserved.

``aipwr``
  Average Interval Power. Bits 31:18 are reserved. Bits 17:16
  contain the Power Scale (PWRS); see :c:type:`enum nvme_psd_ps <nvme_psd_ps>`. Bits 15:0
  contain the Power Value (PWRV).

``mipwr``
  Maximum Interval Power. Bits 31:18 are reserved. Bits 17:16
  contain the Power Scale (PWRS); see :c:type:`enum nvme_psd_ps <nvme_psd_ps>`. Bits 15:0
  contain the Power Value (PWRV).

``mipwrt``
  Maximum Interval Power Timestamp. Timestamp of when the maximum
  interval power was collected. See :c:type:`struct nvme_timestamp <nvme_timestamp>`.

``ipwrpe``
  Interval Power Percent Error. Maximum percent error (0-100%).
  Values 101-254 reserved. 255 indicates not reported.

``rsvd57``
  Reserved.

``descs``
  Power Histogram Descriptors (:c:type:`struct nvme_power_histogram_desc <nvme_power_histogram_desc>`).





.. c:enum:: nvme_lba_status_lbars

   LBA Range Status (LBARS), used with the :c:type:`struct nvme_lba_status_desc <nvme_lba_status_desc>`.status field.

**Constants**

``NVME_LBA_STATUS_LBARS_SHIFT``
  Shift amount to get the value of LBARS

``NVME_LBA_STATUS_LBARS_MASK``
  Mask to get the value of LBARS

``NVME_LBA_STATUS_LBARS_MAY_ERR``
  Each logical block may report Unrecovered
  Read Error status, be a logical block
  most recently written by a Write
  Uncorrectable command, or be read
  successfully. Used with ATYPE 10h/11h.

``NVME_LBA_STATUS_LBARS_ERR``
  Each logical block may report
  Unrecovered Read Error status or be a
  logical block most recently written by
  a Write Uncorrectable command. Used
  with ATYPE 10h/11h.

``NVME_LBA_STATUS_LBARS_ALLOCATED``
  One or more of the reported logical
  blocks are allocated. Used with
  ATYPE 02h.

``NVME_LBA_STATUS_LBARS_WRITE_UNC``
  Each logical block was most recently
  written by a Write Uncorrectable
  command. Used with ATYPE 10h/11h.




.. c:struct:: nvme_lba_status_desc

   LBA Status Descriptor Entry

**Definition**

::

  struct nvme_lba_status_desc {
    __le64 dslba;
    __le32 nlb;
    __u8 rsvd12;
    __u8 status;
    __u8 rsvd14[2];
  };

**Members**

``dslba``
  Descriptor Starting LBA

``nlb``
  Number of Logical Blocks

``rsvd12``
  Reserved

``status``
  Additional status about this LBA range, see
  :c:type:`enum nvme_lba_status_lbars <nvme_lba_status_lbars>`

``rsvd14``
  Reserved





.. c:struct:: nvme_lba_status

   LBA Status Descriptor List

**Definition**

::

  struct nvme_lba_status {
    __le32 nlsd;
    __u8 cmpc;
    __u8 rsvd5[3];
    struct nvme_lba_status_desc descs[];
  };

**Members**

``nlsd``
  Number of LBA Status Descriptors

``cmpc``
  Completion Condition

``rsvd5``
  Reserved

``descs``
  LBA status descriptor Entry





.. c:enum:: nvme_lba_status_cmpc

   Get LBA Status Command Completion Condition

**Constants**

``NVME_LBA_STATUS_CMPC_NO_CMPC``
  No indication of the completion condition

``NVME_LBA_STATUS_CMPC_INCOMPLETE``
  Command completed, but additional LBA Status
  Descriptor Entries are available to transfer
  or scan did not complete (if ATYPE = 10h)

``NVME_LBA_STATUS_CMPC_COMPLETE``
  Completed the specified action over the number
  of LBAs specified in the Range Length field and
  transferred all available LBA Status Descriptors




.. c:struct:: nvme_feat_auto_pst

   Autonomous Power State Transition

**Definition**

::

  struct nvme_feat_auto_pst {
    __le64 apst_entry[32];
  };

**Members**

``apst_entry``
  See :c:type:`enum nvme_apst_entry <nvme_apst_entry>`





.. c:enum:: nvme_apst_entry

   Autonomous Power State Transition

**Constants**

``NVME_APST_ENTRY_ITPS_SHIFT``
  Idle Transition Power State Shift

``NVME_APST_ENTRY_ITPT_SHIFT``
  Idle Time Prior to Transition Shift

``NVME_APST_ENTRY_ITPS_MASK``
  Idle Transition Power State Mask

``NVME_APST_ENTRY_ITPT_MASK``
  Idle Time Prior to Transition Mask




.. c:struct:: nvme_std_perf_attr

   Standard performance attribute structure

**Definition**

::

  struct nvme_std_perf_attr {
    __u8 rsvd0[4];
    __u8 r4karl;
    __u8 rsvd5[4091];
  };

**Members**

``rsvd0``
  Reserved

``r4karl``
  Random 4 KiB average read latency

``rsvd5``
  Reserved





.. c:struct:: nvme_perf_attr_id

   Performance attribute identifier structure

**Definition**

::

  struct nvme_perf_attr_id {
    __u8 id[NVME_UUID_LEN];
  };

**Members**

``id``
  Performance attribute identifier





.. c:struct:: nvme_perf_attr_id_list

   Performance attribute identifier list structure

**Definition**

::

  struct nvme_perf_attr_id_list {
    __u8 attrtyp;
    __u8 msvspa;
    __u8 usvspa;
    __u8 rsvd3[13];
    struct nvme_perf_attr_id id_list[63];
    __u8 rsvd1024[3072];
  };

**Members**

``attrtyp``
  Bits 7-3: Reserved
  Bits 2-0: Attribute type

``msvspa``
  Maximum saveable vendor specific performance attributes

``usvspa``
  Unused saveable vendor specific performance attributes

``rsvd3``
  Reserved

``id_list``
  Performance attribute identifier list

``rsvd1024``
  Reserved





.. c:struct:: nvme_vs_perf_attr

   Vendor specific performance attribute structure

**Definition**

::

  struct nvme_vs_perf_attr {
    __u8 paid[16];
    __u8 rsvd16[14];
    __le16 attrl;
    __u8 vs[4064];
  };

**Members**

``paid``
  Performance attribute identifier

``rsvd16``
  Reserved

``attrl``
  Attribute Length

``vs``
  Vendor specific





.. c:struct:: nvme_perf_characteristics

   Performance attribute structure

**Definition**

::

  struct nvme_perf_characteristics {
    union {
      struct nvme_std_perf_attr std_perf[0];
      struct nvme_perf_attr_id_list id_list[0];
      struct nvme_vs_perf_attr vs_perf[0];
      __u8 attr_buf[4096];
    };
  };

**Members**

``{unnamed_union}``
  anonymous

``std_perf``
  Standard performance attribute

``id_list``
  Performance attribute identifier list

``vs_perf``
  Vendor specific performance attribute

``attr_buf``
  Attribute buffer





.. c:struct:: nvme_metadata_element_desc

   Metadata Element Descriptor

**Definition**

::

  struct nvme_metadata_element_desc {
    __u8 type;
    __u8 rev;
    __le16 len;
    __u8 val[0];
  };

**Members**

``type``
  Element Type (ET)

``rev``
  Element Revision (ER)

``len``
  Element Length (ELEN)

``val``
  Element Value (EVAL), UTF-8 string





.. c:struct:: nvme_host_metadata

   Host Metadata Data Structure

**Definition**

::

  struct nvme_host_metadata {
    __u8 ndesc;
    __u8 rsvd1;
    union {
      struct nvme_metadata_element_desc descs[0];
      __u8 descs_buf[4094];
    };
  };

**Members**

``ndesc``
  Number of metadata element descriptors

``rsvd1``
  Reserved

``{unnamed_union}``
  anonymous

``descs``
  Metadata element descriptors

``descs_buf``
  Metadata element descriptor buffer





.. c:enum:: nvme_host_metadata_cdw11

   Host Metadata Features (7Dh/7Eh/7Fh) - Command Dword 11

**Constants**

``NVME_HOST_METADATA_GDHM``
  Generate Default Host Metadata (Get Features
  Command Dword 11 only)

``NVME_HOST_METADATA_EA_SHIFT``
  Shift amount to set the Element Action (EA)
  field (Set Features Command Dword 11 only)

``NVME_HOST_METADATA_EA_MASK``
  Mask to set EA




.. c:enum:: nvme_host_metadata_ea

   Host Metadata Features - Element Action (EA)

**Constants**

``NVME_HOST_METADATA_EA_ADD_REPLACE``
  Add or Replace Entry

``NVME_HOST_METADATA_EA_DELETE_MULTIPLE``
  Delete Entry Multiple

``NVME_HOST_METADATA_EA_ADD_MULTIPLE``
  Add Entry Multiple




.. c:enum:: nvme_ctrl_metadata_type

   Controller Metadata Element Types

**Constants**

``NVME_CTRL_METADATA_OS_CTRL_NAME``
  Name of the controller in
  the operating system.

``NVME_CTRL_METADATA_OS_DRIVER_NAME``
  Name of the driver in the
  operating system.

``NVME_CTRL_METADATA_OS_DRIVER_VER``
  Version of the driver in
  the operating system.

``NVME_CTRL_METADATA_PRE_BOOT_CTRL_NAME``
  Name of the controller in
  the pre-boot environment.

``NVME_CTRL_METADATA_PRE_BOOT_DRIVER_NAME``
  Name of the driver in the
  pre-boot environment.

``NVME_CTRL_METADATA_PRE_BOOT_DRIVER_VER``
  Version of the driver in the
  pre-boot environment.

``NVME_CTRL_METADATA_SYS_PROC_MODEL``
  Model of the processor.

``NVME_CTRL_METADATA_CHIPSET_DRV_NAME``
  Chipset driver name.

``NVME_CTRL_METADATA_CHIPSET_DRV_VERSION``
  Chipset driver version.

``NVME_CTRL_METADATA_OS_NAME_AND_BUILD``
  Operating system name and build.

``NVME_CTRL_METADATA_SYS_PROD_NAME``
  System product name.

``NVME_CTRL_METADATA_FIRMWARE_VERSION``
  Host firmware (e.g UEFI) version.

``NVME_CTRL_METADATA_OS_DRIVER_FILENAME``
  Operating system driver filename.

``NVME_CTRL_METADATA_DISPLAY_DRV_NAME``
  Display driver name.

``NVME_CTRL_METADATA_DISPLAY_DRV_VERSION``
  Display driver version.

``NVME_CTRL_METADATA_HOST_DET_FAIL_REC``
  Failure record.




.. c:enum:: nvme_ns_metadata_type

   Namespace Metadata Element Types

**Constants**

``NVME_NS_METADATA_OS_NS_NAME``
  Name of the namespace in the
  operating system

``NVME_NS_METADATA_PRE_BOOT_NS_NAME``
  Name of the namespace in the pre-boot
  environment.

``NVME_NS_METADATA_OS_NS_QUAL_1``
  First qualifier of the Operating System
  Namespace Name.

``NVME_NS_METADATA_OS_NS_QUAL_2``
  Second qualifier of the Operating System
  Namespace Name.




.. c:struct:: nvme_lba_range_type_entry

   LBA Range Type - Data Structure Entry

**Definition**

::

  struct nvme_lba_range_type_entry {
    __u8 type;
    __u8 attributes;
    __u8 rsvd2[14];
    __le64 slba;
    __le64 nlb;
    __u8 guid[16];
    __u8 rsvd48[16];
  };

**Members**

``type``
  Specifies the Type of the LBA range

``attributes``
  Specifies attributes of the LBA range

``rsvd2``
  Reserved

``slba``
  Starting LBA

``nlb``
  Number of Logical Blocks

``guid``
  Unique Identifier

``rsvd48``
  Reserved





.. c:enum:: nvme_lbart

   LBA Range Type - Data Structure Entry

**Constants**

``NVME_LBART_TYPE_GP``
  General Purpose

``NVME_LBART_TYPE_FS``
  Filesystem

``NVME_LBART_TYPE_RAID``
  RAID

``NVME_LBART_TYPE_CACHE``
  Cache

``NVME_LBART_TYPE_SWAP``
  Page / swap file

``NVME_LBART_ATTRB_LBARO_SHIFT``
  LBA range overwriteable shift

``NVME_LBART_ATTRB_HLBAR_SHIFT``
  Hide LBA range shift

``NVME_LBART_ATTRB_LBARO_MASK``
  LBA range overwriteable mask

``NVME_LBART_ATTRB_HLBAR_MASK``
  Hide LBA range mask

``NVME_LBART_ATTRIB_TEMP``
  Temp

``NVME_LBART_ATTRIB_HIDE``
  Hidden




.. c:struct:: nvme_lba_range_type

   LBA Range Type

**Definition**

::

  struct nvme_lba_range_type {
    struct nvme_lba_range_type_entry entry[NVME_FEAT_LBA_RANGE_MAX];
  };

**Members**

``entry``
  LBA range type entry. See **struct** nvme_lba_range_type_entry





.. c:struct:: nvme_plm_config

   Predictable Latency Mode - Deterministic Threshold Configuration Data Structure

**Definition**

::

  struct nvme_plm_config {
    __le16 ee;
    __u8 rsvd2[30];
    __le64 dtwinrt;
    __le64 dtwinwt;
    __le64 dtwintt;
    __u8 rsvd56[456];
  };

**Members**

``ee``
  Enable Event

``rsvd2``
  Reserved

``dtwinrt``
  DTWIN Reads Threshold

``dtwinwt``
  DTWIN Writes Threshold

``dtwintt``
  DTWIN Time Threshold

``rsvd56``
  Reserved





.. c:struct:: nvme_feat_host_behavior

   Host Behavior Support - Data Structure

**Definition**

::

  struct nvme_feat_host_behavior {
    __u8 acre;
    __u8 etdas;
    __u8 lbafee;
    __u8 hdisns;
    __le16 cdfe;
    __u8 rsvd6[506];
  };

**Members**

``acre``
  Advanced Command Retry Enable

``etdas``
  Extended Telemetry Data Area 4 Supported

``lbafee``
  LBA Format Extension Enable

``hdisns``
  Host Dispersed Namespace Support

``cdfe``
  Copy Descriptor Formats Enable

``rsvd6``
  Reserved





.. c:enum:: nvme_host_behavior_support

   Enable Advanced Command

**Constants**

``NVME_ENABLE_ACRE``
  Enable Advanced Command Retry Enable




.. c:struct:: nvme_streams_directive_params

   Streams Directive - Return Parameters Data Structure

**Definition**

::

  struct nvme_streams_directive_params {
    __le16 msl;
    __le16 nssa;
    __le16 nsso;
    __u8 nssc;
    __u8 rsvd[9];
    __le32 sws;
    __le16 sgs;
    __le16 nsa;
    __le16 nso;
    __u8 rsvd2[6];
  };

**Members**

``msl``
  Max Streams Limit

``nssa``
  NVM Subsystem Streams Available

``nsso``
  NVM Subsystem Streams Open

``nssc``
  NVM Subsystem Stream Capability

``rsvd``
  Reserved

``sws``
  Stream Write Size

``sgs``
  Stream Granularity Size

``nsa``
  Namespace Streams Allocated

``nso``
  Namespace Streams Open

``rsvd2``
  Reserved





.. c:struct:: nvme_streams_directive_status

   Streams Directive - Get Status Data Structure

**Definition**

::

  struct nvme_streams_directive_status {
    __le16 osc;
    __le16 sid[];
  };

**Members**

``osc``
  Open Stream Count

``sid``
  Stream Identifier





.. c:struct:: nvme_id_directives

   Identify Directive - Return Parameters Data Structure

**Definition**

::

  struct nvme_id_directives {
    __u8 supported[32];
    __u8 enabled[32];
    __u8 rsvd64[4032];
  };

**Members**

``supported``
  Identify directive is supported

``enabled``
  Identify directive is Enabled

``rsvd64``
  Reserved





.. c:enum:: nvme_directive_types

   Directives Supported or Enabled

**Constants**

``NVME_ID_DIR_ID_BIT``
  Identify directive is supported

``NVME_ID_DIR_SD_BIT``
  Streams directive is supported

``NVME_ID_DIR_DP_BIT``
  Direct Placement directive is supported




.. c:struct:: nvme_host_mem_buf_attrs

   Host Memory Buffer - Attributes Data Structure

**Definition**

::

  struct nvme_host_mem_buf_attrs {
    __le32 hsize;
    __le32 hmdlal;
    __le32 hmdlau;
    __le32 hmdlec;
    __u8 rsvd16[4080];
  };

**Members**

``hsize``
  Host Memory Buffer Size

``hmdlal``
  Host Memory Descriptor List Lower Address

``hmdlau``
  Host Memory Descriptor List Upper Address

``hmdlec``
  Host Memory Descriptor List Entry Count

``rsvd16``
  Reserved





.. c:enum:: nvme_ae_type

   Asynchronous Event Type

**Constants**

``NVME_AER_ERROR``
  Error event

``NVME_AER_SMART``
  SMART / Health Status event

``NVME_AER_NOTICE``
  Notice event

``NVME_AER_IMMEDIATE``
  Immediate

``NVME_AER_ONESHOT``
  One-Shot

``NVME_AER_CSS``
  NVM Command Set Specific events

``NVME_AER_VS``
  Vendor Specific event




.. c:enum:: nvme_ae_info_error

   Asynchronous Event Information - Error Status

**Constants**

``NVME_AER_ERROR_INVALID_DB_REG``
  Write to Invalid Doorbell Register

``NVME_AER_ERROR_INVALID_DB_VAL``
  Invalid Doorbell Write Value

``NVME_AER_ERROR_DIAG_FAILURE``
  Diagnostic Failure

``NVME_AER_ERROR_PERSISTENT_INTERNAL_ERROR``
  Persistent Internal Error

``NVME_AER_ERROR_TRANSIENT_INTERNAL_ERROR``
  Transient Internal Error

``NVME_AER_ERROR_FW_IMAGE_LOAD_ERROR``
  Firmware Image Load Error




.. c:enum:: nvme_ae_info_smart

   Asynchronous Event Information - SMART / Health Status

**Constants**

``NVME_AER_SMART_SUBSYSTEM_RELIABILITY``
  NVM subsystem Reliability

``NVME_AER_SMART_TEMPERATURE_THRESHOLD``
  Temperature Threshold

``NVME_AER_SMART_SPARE_THRESHOLD``
  Spare Below Threshold




.. c:enum:: nvme_ae_info_css_nvm

   Asynchronous Event Information - I/O Command Specific Status

**Constants**

``NVME_AER_CSS_NVM_RESERVATION``
  Reservation Log Page Available

``NVME_AER_CSS_NVM_SANITIZE_COMPLETED``
  Sanitize Operation Completed

``NVME_AER_CSS_NVM_UNEXPECTED_SANITIZE_DEALLOC``
  Sanitize Operation Completed
  With Unexpected Deallocation




.. c:enum:: nvme_ae_info_notice

   Asynchronous Event Information - Notice

**Constants**

``NVME_AER_NOTICE_ATTACHED_NS_CHANGED``
  Attached Namespace Attribute Changed

``NVME_AER_NOTICE_FW_ACT_STARTING``
  Firmware Activation Starting

``NVME_AER_NOTICE_TELEMETRY``
  Telemetry Log Changed

``NVME_AER_NOTICE_ANA``
  Asymmetric Namespace Access Change

``NVME_AER_NOTICE_PL_EVENT``
  Predictable Latency Event Aggregate Log Change

``NVME_AER_NOTICE_LBA_STATUS_ALERT``
  LBA Status Information Alert

``NVME_AER_NOTICE_EG_EVENT``
  Endurance Group Event Aggregate Log Page Change

``NVME_AER_NOTICE_RATE_LIMITING_CFG_CHANGE``
  Rate Limiting Configuration Change

``NVME_AER_NOTICE_ZONE_DESC_CHANGED``
  Zone Descriptor Changed (Zoned Namespace
  Command Set specific)

``NVME_AER_NOTICE_DISC_CHANGED``
  Discovery Log Page Change




.. c:enum:: nvme_cross_ctrl_reset_cdw10

   Cross-Controller Reset - Command Dword 10

**Constants**

``NVME_CROSS_CTRL_RESET_CDW10_ICID_SHIFT``
  Shift amount to set Impacted
  Controller ID (ICID)

``NVME_CROSS_CTRL_RESET_CDW10_ICID_MASK``
  Mask to set ICID

``NVME_CROSS_CTRL_RESET_CDW10_CIU_SHIFT``
  Shift amount to set Controller
  Instance Uniquifier (CIU)

``NVME_CROSS_CTRL_RESET_CDW10_CIU_MASK``
  Mask to set CIU




.. c:enum:: nvme_cross_ctrl_reset_cqe_dw0

   Cross-Controller Reset Command - Completion Queue Entry Dword 0

**Constants**

``NVME_CROSS_CTRL_RESET_CQE_IRS``
  Immediate Reset Successful (IRS)

``NVME_CROSS_CTRL_RESET_CQE_V``
  Validated (V). Undefined if IRS is
  cleared to '0'.

``NVME_CROSS_CTRL_RESET_CQE_CLRI``
  Controller Level Reset Initiated (CLRI).
  Undefined if IRS is cleared to '0'.




.. c:enum:: nvme_cross_ctrl_reset_lsp

   Cross-Controller Reset Log Specific Parameter Field

**Constants**

``NVME_CROSS_CTRL_RESET_LSP_RMC``
  Remove Completed (RMC)




.. c:enum:: nvme_fabric_zoning_recv_cdw12

   Fabric Zoning Receive - Command Dword 12

**Constants**

``NVME_FABRIC_ZONING_RECV_CDW12_NUMD_SHIFT``
  Shift amount to set Number of
  Dwords (NUMD)

``NVME_FABRIC_ZONING_RECV_CDW12_NUMD_MASK``
  Mask to set NUMD

``NVME_FABRIC_ZONING_RECV_CDW12_ZDKC``
  ZDK Context (ZDKC)




.. c:enum:: nvme_fabric_zoning_recv_cqe_dw0

   Fabric Zoning Receive - Completion Queue Entry Dword 0

**Constants**

``NVME_FABRIC_ZONING_RECV_CQE_LF``
  Last Fragment (LF)




.. c:enum:: nvme_fabric_zoning_send_cdw12

   Fabric Zoning Send - Command Dword 12

**Constants**

``NVME_FABRIC_ZONING_SEND_CDW12_NUMD_SHIFT``
  Shift amount to set Number of
  Dwords (NUMD)

``NVME_FABRIC_ZONING_SEND_CDW12_NUMD_MASK``
  Mask to set NUMD

``NVME_FABRIC_ZONING_SEND_CDW12_ZDKC``
  ZDK Context (ZDKC)

``NVME_FABRIC_ZONING_SEND_CDW12_LF``
  Last Fragment (LF)




.. c:enum:: nvme_manage_export_nvms_recv_sel

   Manage Exported NVM Subsystem Receive - Select (SEL)

**Constants**

``NVME_MANAGE_EXPORT_NVMS_RECV_SEL_CREATE``
  Create Exported NVM
  Subsystem

``NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_SUBSYSTEMS``
  List Exported NVM
  Subsystems

``NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_NAMESPACES``
  List Exported
  Namespaces

``NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_CONTROLLERS``
  List Exported
  Controllers (message-based
  transports only)

``NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_PORTS``
  List Exported Ports
  (memory-based transports
  only)

``NVME_MANAGE_EXPORT_NVMS_RECV_SEL_GET_CONFIG_STATE``
  Get Exported NVM
  Subsystem Configuration
  State




.. c:enum:: nvme_manage_export_nvms_recv_cdw10

   Manage Exported NVM Subsystem Receive - Command Dword 10

**Constants**

``NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_SEL_SHIFT``
  Shift amount to set Select
  (SEL), see :c:type:`enum
  nvme_manage_export_nvms_recv_sel <nvme_manage_export_nvms_recv_sel>`

``NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_SEL_MASK``
  Mask to set SEL

``NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_MOS_SHIFT``
  Shift amount to set
  Management Operation
  Specific (MOS)

``NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_MOS_MASK``
  Mask to set MOS

``NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_MOSE_SHIFT``
  Shift amount to set
  Management Operation
  Specific Extended (MOSE)

``NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_MOSE_MASK``
  Mask to set MOSE




.. c:enum:: nvme_manage_export_nvms_recv_cdw14

   Manage Exported NVM Subsystem Receive - Command Dword 14

**Constants**

``NVME_MANAGE_EXPORT_NVMS_RECV_CDW14_MOSI_SHIFT``
  Shift amount to set
  Management Operation
  Specific Identifier (MOSI)

``NVME_MANAGE_EXPORT_NVMS_RECV_CDW14_MOSI_MASK``
  Mask to set MOSI




.. c:enum:: nvme_export_nvms_create_cdw11

   Manage Exported NVM Subsystem Receive - Create Exported NVM Subsystem - Command Dword 11

**Constants**

``NVME_EXPORT_NVMS_CREATE_CDW11_ENSTI_SHIFT``
  Shift amount to set Exported
  NVM Subsystem Template Index (ENSTI), see the Identify
  CNS value ``NVME_IDENTIFY_CNS_EXPORTED_NVM_SUBSYS_TEMPLATE_UUID_LIST``

``NVME_EXPORT_NVMS_CREATE_CDW11_ENSTI_MASK``
  Mask to set ENSTI

``NVME_EXPORT_NVMS_CREATE_CDW11_TR``
  Template Required (TR)




.. c:enum:: nvme_export_nvms_create_mos

   Manage Exported NVM Subsystem Receive - Create Exported NVM Subsystem - Management Operation Specific (MOS) field, message-based transports only

**Constants**

``NVME_EXPORT_NVMS_CREATE_MOS_RA``
  Restricted Access (RA)




.. c:enum:: nvme_export_nvms_create_cqe_dw0

   Manage Exported NVM Subsystem Receive - Create Exported NVM Subsystem - Completion Queue Entry Dword 0

**Constants**

``NVME_EXPORT_NVMS_CREATE_CQE_ESUBID_SHIFT``
  Shift amount to get Exported
  NVM Subsystem Identifier (ESUBID)

``NVME_EXPORT_NVMS_CREATE_CQE_ESUBID_MASK``
  Mask to get ESUBID




.. c:struct:: nvme_exported_nvm_subsys_create_data

   Create Exported NVM Subsystem Data Buffer

**Definition**

::

  struct nvme_exported_nvm_subsys_create_data {
    __u8 esubnqn[256];
  };

**Members**

``esubnqn``
  Exported NVM Subsystem NQN (ESUBNQN): the host may leave this
  field cleared to request an NQN be assigned by the
  controller; the assigned/confirmed NQN is returned in this
  same buffer on successful completion.





.. c:struct:: nvme_exported_nvm_subsys_descriptor

   Exported NVM Subsystem Descriptor

**Definition**

::

  struct nvme_exported_nvm_subsys_descriptor {
    __u8 esubnqn[256];
    __u8 rsvd256[2];
    __le16 esubid;
  };

**Members**

``esubnqn``
  Exported NVM Subsystem NQN (ESUBNQN)

``rsvd256``
  Reserved

``esubid``
  Exported NVM Subsystem Identifier (ESUBID)





.. c:struct:: nvme_exported_nvm_subsys_list

   Exported NVM Subsystems List Data Structure, returned by the Manage Exported NVM Subsystem Receive command's List Exported NVM Subsystems management operation

**Definition**

::

  struct nvme_exported_nvm_subsys_list {
    __le16 n;
    __u8 rsvd2;
    __u8 gn;
    struct nvme_exported_nvm_subsys_descriptor entries[];
  };

**Members**

``n``
  Number of Exported NVM Subsystem Descriptors (N)

``rsvd2``
  Reserved

``gn``
  Generation Number (GN)

``entries``
  Exported NVM Subsystem Descriptor list, see :c:type:`struct
  nvme_exported_nvm_subsys_descriptor <nvme_exported_nvm_subsys_descriptor>`





.. c:struct:: nvme_exported_ns_descriptor

   Exported Namespace Descriptor

**Definition**

::

  struct nvme_exported_ns_descriptor {
    __le32 ensid;
    __le32 unsid;
  };

**Members**

``ensid``
  Exported Namespace ID (ENSID)

``unsid``
  Underlying Namespace ID (UNSID)





.. c:struct:: nvme_exported_ns_list

   Exported Namespace List Data Structure, returned by the Manage Exported NVM Subsystem Receive command's List Exported Namespaces management operation

**Definition**

::

  struct nvme_exported_ns_list {
    __le16 n;
    __u8 rsvd2;
    __u8 gn;
    __u8 rsvd4[4];
    struct nvme_exported_ns_descriptor entries[];
  };

**Members**

``n``
  Number of Exported Namespaces (N)

``rsvd2``
  Reserved

``gn``
  Generation Number (GN)

``rsvd4``
  Reserved

``entries``
  Exported Namespace Descriptor list, see :c:type:`struct
  nvme_exported_ns_descriptor <nvme_exported_ns_descriptor>`





.. c:struct:: nvme_exported_ctrl_descriptor

   Exported Controller Descriptor

**Definition**

::

  struct nvme_exported_ctrl_descriptor {
    __le16 ecntlid;
    __le16 cntlid;
  };

**Members**

``ecntlid``
  Exported Controller Identifier (ECNTLID)

``cntlid``
  Controller Identifier (CNTLID) of the associated Underlying
  Controller





.. c:struct:: nvme_exported_ctrl_list

   Exported Controller List Data Structure, returned by the Manage Exported NVM Subsystem Receive command's List Exported Controllers management operation (message-based transports only)

**Definition**

::

  struct nvme_exported_ctrl_list {
    __le16 n;
    __u8 rsvd2;
    __u8 gn;
    struct nvme_exported_ctrl_descriptor entries[];
  };

**Members**

``n``
  Number of Exported Controllers (N)

``rsvd2``
  Reserved

``gn``
  Generation Number (GN)

``entries``
  Exported Controller Descriptor list, see :c:type:`struct
  nvme_exported_ctrl_descriptor <nvme_exported_ctrl_descriptor>`





.. c:struct:: nvme_exported_port_descriptor

   Exported Port Descriptor

**Definition**

::

  struct nvme_exported_port_descriptor {
    __le16 epid;
    __le16 pidud;
    __u8 rsvd4[4];
    __u8 trsvcid[32];
  };

**Members**

``epid``
  Exported Port ID (EPID)

``pidud``
  Port ID of the Underlying Port (PIDUD)

``rsvd4``
  Reserved

``trsvcid``
  Transport Service ID (TRSVCID), ASCII string





.. c:struct:: nvme_exported_port_list

   Exported Ports List Data Structure, returned by the Manage Exported NVM Subsystem Receive command's List Exported Ports management operation (memory-based transports only)

**Definition**

::

  struct nvme_exported_port_list {
    __le16 n;
    __u8 rsvd2[6];
    struct nvme_exported_port_descriptor entries[];
  };

**Members**

``n``
  Number of Exported Ports (N)

``rsvd2``
  Reserved

``entries``
  Exported Port Descriptor list, see :c:type:`struct
  nvme_exported_port_descriptor <nvme_exported_port_descriptor>`





.. c:enum:: nvme_manage_export_ns_sel

   Manage Exported Namespace - Select (SEL)

**Constants**

``NVME_MANAGE_EXPORT_NS_SEL_ASSOCIATE``
  Associate Namespace

``NVME_MANAGE_EXPORT_NS_SEL_DISASSOCIATE``
  Disassociate Namespace




.. c:enum:: nvme_manage_export_ns_cdw10

   Manage Exported Namespace - Command Dword 10

**Constants**

``NVME_MANAGE_EXPORT_NS_CDW10_SEL_SHIFT``
  Shift amount to set Select (SEL),
  see :c:type:`enum nvme_manage_export_ns_sel <nvme_manage_export_ns_sel>`

``NVME_MANAGE_EXPORT_NS_CDW10_SEL_MASK``
  Mask to set SEL

``NVME_MANAGE_EXPORT_NS_CDW10_MOS_SHIFT``
  Shift amount to set Management
  Operation Specific (MOS)

``NVME_MANAGE_EXPORT_NS_CDW10_MOS_MASK``
  Mask to set MOS




.. c:enum:: nvme_manage_export_ns_cdw14

   Manage Exported Namespace - Command Dword 14

**Constants**

``NVME_MANAGE_EXPORT_NS_CDW14_ESUBIDV``
  Exported NVM Subsystem Identifier
  Valid (ESUBIDV)

``NVME_MANAGE_EXPORT_NS_CDW14_ESUBID_SHIFT``
  Shift amount to set Exported
  NVM Subsystem Identifier (ESUBID), used if ESUBIDV is
  set

``NVME_MANAGE_EXPORT_NS_CDW14_ESUBID_MASK``
  Mask to set ESUBID




.. c:struct:: nvme_associate_ns_data

   Associate Namespace Data Structure

**Definition**

::

  struct nvme_associate_ns_data {
    __u8 pad[32];
    __le32 ensid;
    __u8 ensnqn[256];
    __le32 unsid;
    __le16 uctrlid;
    __u8 unsnqn[256];
    __u8 rsvd554[22];
  };

**Members**

``pad``
  Padding (PAD), shall be cleared to 0h

``ensid``
  Exported Namespace ID (ENSID) to associate

``ensnqn``
  Exported NVM Subsystem NQN (ENSNQN). Ignored for a
  memory-based controller, or if ESUBIDV is set.

``unsid``
  Underlying Namespace ID (UNSID) to associate with **ensid**

``uctrlid``
  Underlying Controller ID (UCTRLID). Ignored for a
  memory-based controller.

``unsnqn``
  Underlying NVM Subsystem NQN (UNSNQN). Ignored for a
  memory-based controller.

``rsvd554``
  Reserved





.. c:struct:: nvme_disassociate_ns_data

   Disassociate Namespace Data Structure

**Definition**

::

  struct nvme_disassociate_ns_data {
    __u8 pad[32];
    __le32 ensid;
    __u8 ensnqn[256];
    __u8 rsvd292[28];
  };

**Members**

``pad``
  Padding (PAD), shall be cleared to 0h

``ensid``
  Exported Namespace ID (ENSID) to disassociate

``ensnqn``
  Exported NVM Subsystem NQN (ENSNQN). Ignored for a
  memory-based controller, or if ESUBIDV is set.

``rsvd292``
  Reserved





.. c:enum:: nvme_export_nvms_change_access_mode_mos

   Manage Exported NVM Subsystem Send - Change Access Mode - Management Operation Specific (MOS) field, message-based transports only

**Constants**

``NVME_EXPORT_NVMS_CHANGE_ACCESS_MODE_MOS_RA``
  Restricted Access (RA)




.. c:struct:: nvme_exported_subsys_mgmt_host_entry

   Host Entry Data Structure, used by the Manage Exported NVM Subsystem Send Grant Host Access and Revoke Host Access operations

**Definition**

::

  struct nvme_exported_subsys_mgmt_host_entry {
    __u8 rsvd0[8];
    __u8 hostid[16];
    __u8 hostnqn[256];
    __u8 rsvd280[40];
  };

**Members**

``rsvd0``
  Reserved

``hostid``
  Host Identifier (HOSTID)

``hostnqn``
  Host NVMe Qualified Name (HOSTNQN)

``rsvd280``
  Reserved





.. c:struct:: nvme_exported_subsys_mgmt_subsys_entry

   Exported NVM Subsystem Entry Data Structure, used by the Manage Exported NVM Subsystem Send Grant Host Access and Revoke Host Access operations

**Definition**

::

  struct nvme_exported_subsys_mgmt_subsys_entry {
    __u8 rsvd0[24];
    __u8 subnqn[256];
    __le16 pidup;
    __u8 rsvd282[38];
  };

**Members**

``rsvd0``
  Reserved

``subnqn``
  NVM Subsystem NVMe Qualified Name (SUBNQN) of an Exported NVM
  Subsystem

``pidup``
  Port ID of the Underlying Port (PIDUP)

``rsvd282``
  Reserved





.. c:struct:: nvme_exported_subsys_mgmt_data

   Subsystem Management Data Structure, used by the Manage Exported NVM Subsystem Send Grant Host Access and Revoke Host Access operations

**Definition**

::

  struct nvme_exported_subsys_mgmt_data {
    __u8 rsvd0[64];
    __le16 numhent;
    __le16 numense;
    __u8 rsvd68[188];
    __u8 entries[];
  };

**Members**

``rsvd0``
  Reserved

``numhent``
  Number of Host Entries (NUMHENT), shall be greater than 0h

``numense``
  Number of Exported NVM Subsystem Entries (NUMENSE), shall be
  greater than 0h

``rsvd68``
  Reserved

``entries``
  **numhent** entries of :c:type:`struct nvme_exported_subsys_mgmt_host_entry <nvme_exported_subsys_mgmt_host_entry>`
  followed by **numense** entries of :c:type:`struct
  nvme_exported_subsys_mgmt_subsys_entry <nvme_exported_subsys_mgmt_subsys_entry>`. Left as a raw byte
  buffer since the two variable-length lists have different
  element sizes and cannot both be expressed as fixed struct
  members - the caller walks **entries** using the sizes of those
  two struct types.





.. c:struct:: nvme_exported_ctrl_assoc_descriptor

   Exported Controller Association Descriptor

**Definition**

::

  struct nvme_exported_ctrl_assoc_descriptor {
    __le16 cntlid;
    __le16 ecntlid;
  };

**Members**

``cntlid``
  Controller Identifier (CNTLID) of the Underlying Controller

``ecntlid``
  Exported Controller Identifier (ECNTLID) to associate with
  **cntlid**





.. c:struct:: nvme_exported_ctrl_assoc_data

   Associate Controllers Management Operation Data Buffer

**Definition**

::

  struct nvme_exported_ctrl_assoc_data {
    __le16 n;
    __u8 rsvd2[2];
    struct nvme_exported_ctrl_assoc_descriptor entries[];
  };

**Members**

``n``
  Number of Associated Exported Controller Descriptors (N),
  0's based

``rsvd2``
  Reserved

``entries``
  Exported Controller Association Descriptor list, see :c:type:`struct
  nvme_exported_ctrl_assoc_descriptor <nvme_exported_ctrl_assoc_descriptor>`





.. c:enum:: nvme_export_nvms_set_config_state_cqe_dw0

   Manage Exported NVM Subsystem Send - Set Exported Configuration State - Completion Queue Entry Dword 0, valid when the command fails with ``NVME_SC_INVALID_EXPORTED_CONFIG_STATE``

**Constants**

``NVME_EXPORT_NVMS_SET_CONFIG_STATE_CQE_DWLOC_SHIFT``
  Shift amount to get
  Dword Location (DWLOC): offset in the data buffer to
  the Dword that contained an invalid bit

``NVME_EXPORT_NVMS_SET_CONFIG_STATE_CQE_DWLOC_MASK``
  Mask to get DWLOC

``NVME_EXPORT_NVMS_SET_CONFIG_STATE_CQE_BITLOC_SHIFT``
  Shift amount to get
  Bit Location (BITLOC): offset of the invalid bit
  within the Dword indicated by DWLOC

``NVME_EXPORT_NVMS_SET_CONFIG_STATE_CQE_BITLOC_MASK``
  Mask to get BITLOC




.. c:struct:: nvme_exported_nvm_subsys_nqn_data

   Exported NVM Subsystem NQN Data Buffer, used by Manage Exported NVM Subsystem Send operations that identify the target Exported NVM Subsystem by NQN instead of by Exported NVM Subsystem Identifier (ESUBID)

**Definition**

::

  struct nvme_exported_nvm_subsys_nqn_data {
    __u8 esubnqn[256];
  };

**Members**

``esubnqn``
  Exported NVM Subsystem NQN (ESUBNQN)





.. c:enum:: nvme_manage_export_nvms_send_sel

   Manage Exported NVM Subsystem Send - Select (SEL)

**Constants**

``NVME_MANAGE_EXPORT_NVMS_SEND_SEL_DELETE``
  Delete

``NVME_MANAGE_EXPORT_NVMS_SEND_SEL_CHANGE_ACCESS_MODE``
  Change Access Mode
  (message-based transports only)

``NVME_MANAGE_EXPORT_NVMS_SEND_SEL_GRANT_HOST_ACCESS``
  Grant Host Access
  (message-based transports only)

``NVME_MANAGE_EXPORT_NVMS_SEND_SEL_REVOKE_HOST_ACCESS``
  Revoke Host Access
  (message-based transports only)

``NVME_MANAGE_EXPORT_NVMS_SEND_SEL_ASSOCIATE_CONTROLLERS``
  Associate
  Controllers (memory-based transports only)

``NVME_MANAGE_EXPORT_NVMS_SEND_SEL_SET_CONFIG_STATE``
  Set Exported
  Configuration State




.. c:enum:: nvme_manage_export_nvms_send_cdw10

   Manage Exported NVM Subsystem Send - Command Dword 10

**Constants**

``NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_SEL_SHIFT``
  Shift amount to set Select
  (SEL), see :c:type:`enum nvme_manage_export_nvms_send_sel <nvme_manage_export_nvms_send_sel>`

``NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_SEL_MASK``
  Mask to set SEL

``NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_MOS_SHIFT``
  Shift amount to set
  Management Operation Specific (MOS)

``NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_MOS_MASK``
  Mask to set MOS

``NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_MOSE_SHIFT``
  Shift amount to set
  Management Operation Specific Extended (MOSE)

``NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_MOSE_MASK``
  Mask to set MOSE




.. c:enum:: nvme_manage_export_nvms_send_cdw14

   Manage Exported NVM Subsystem Send - Command Dword 14

**Constants**

``NVME_MANAGE_EXPORT_NVMS_SEND_CDW14_ESUBIDV``
  Exported NVM Subsystem
  Identifier Valid (ESUBIDV)

``NVME_MANAGE_EXPORT_NVMS_SEND_CDW14_ESUBID_SHIFT``
  Shift amount to set
  Exported NVM Subsystem Identifier (ESUBID), used if
  ESUBIDV is set

``NVME_MANAGE_EXPORT_NVMS_SEND_CDW14_ESUBID_MASK``
  Mask to set ESUBID




.. c:enum:: nvme_manage_export_port_sel

   Manage Exported Port - Select (SEL)

**Constants**

``NVME_MANAGE_EXPORT_PORT_SEL_CREATE``
  Create

``NVME_MANAGE_EXPORT_PORT_SEL_DELETE``
  Delete




.. c:enum:: nvme_manage_export_port_cdw10

   Manage Exported Port - Command Dword 10

**Constants**

``NVME_MANAGE_EXPORT_PORT_CDW10_SEL_SHIFT``
  Shift amount to set Select
  (SEL), see :c:type:`enum nvme_manage_export_port_sel <nvme_manage_export_port_sel>`

``NVME_MANAGE_EXPORT_PORT_CDW10_SEL_MASK``
  Mask to set SEL

``NVME_MANAGE_EXPORT_PORT_CDW10_MOS_SHIFT``
  Shift amount to set Management
  Operation Specific (MOS)

``NVME_MANAGE_EXPORT_PORT_CDW10_MOS_MASK``
  Mask to set MOS




.. c:enum:: nvme_export_port_create_mos

   Manage Exported Port - Create - Management Operation Specific (MOS) field

**Constants**

``NVME_EXPORT_PORT_CREATE_MOS_GEPID``
  Generate Exported Port ID (GEPID): if
  set, the controller generates the Exported Port ID
  instead of using the value in the data buffer




.. c:enum:: nvme_export_port_create_cqe_dw0

   Manage Exported Port - Create - Completion Queue Entry Dword 0

**Constants**

``NVME_EXPORT_PORT_CREATE_CQE_EPID_SHIFT``
  Shift amount to get Exported
  Port ID (EPID)

``NVME_EXPORT_PORT_CREATE_CQE_EPID_MASK``
  Mask to get EPID




.. c:struct:: nvme_exported_port_create_data

   Manage Exported Port - Create Data Structure

**Definition**

::

  struct nvme_exported_port_create_data {
    __u8 subnqn[256];
    __le16 epid;
    __le16 pidud;
    __u8 trsvcid[32];
    __u8 rsvd292[28];
  };

**Members**

``subnqn``
  Exported NVM Subsystem NQN (SUBNQN) to associate the created
  Exported Port with

``epid``
  Exported Port ID (EPID). Used unless GEPID is set in the MOS
  field, in which case this field is ignored and the assigned
  Exported Port ID is returned in the CQE result instead.

``pidud``
  Port ID of the Underlying Port (PIDUD)

``trsvcid``
  Transport Service ID (TRSVCID), ASCII string

``rsvd292``
  Reserved





.. c:struct:: nvme_exported_port_delete_data

   Manage Exported Port - Delete Data Structure

**Definition**

::

  struct nvme_exported_port_delete_data {
    __u8 subnqn[256];
    __le16 epid;
    __u8 rsvd258[62];
  };

**Members**

``subnqn``
  Exported NVM Subsystem NQN (SUBNQN) associated with the
  Exported Port to delete

``epid``
  Exported Port ID (EPID) of the Exported Port to delete

``rsvd258``
  Reserved





.. c:enum:: nvme_send_discovery_log_page_rlps

   Send Discovery Log Page (SDLP) - Requested Log Page Status (RLPS)

**Constants**

``NVME_SDLP_RLPS_VALID``
  Valid Log Page: the requested log page is
  carried in the command.

``NVME_SDLP_RLPS_INVALID``
  Invalid Log Page: the requested log page is
  invalid or not supported.

``NVME_SDLP_RLPS_NOT_ALLOWED``
  Not Allowed Log Page: the requested log page
  is not allowed to be transferred by an SDLP
  command.

``NVME_SDLP_RLPS_NOT_SUCCESSFUL``
  Not Successful: retrieving the requested
  log page failed. Further details are
  provided in the SCT and SC fields.




.. c:enum:: nvme_send_discovery_log_page_cdw10

   Send Discovery Log Page (SDLP) - Command Dword 10

**Constants**

``NVME_SDLP_CDW10_TLID_SHIFT``
  Shift amount to set Transferred Log Page
  Identifier (TLID)

``NVME_SDLP_CDW10_TLID_MASK``
  Mask to set TLID

``NVME_SDLP_CDW10_TLSP_SHIFT``
  Shift amount to set Transferred Log Specific
  Parameter (TLSP)

``NVME_SDLP_CDW10_TLSP_MASK``
  Mask to set TLSP

``NVME_SDLP_CDW10_SC_SHIFT``
  Shift amount to set Status Code (SC)

``NVME_SDLP_CDW10_SC_MASK``
  Mask to set SC

``NVME_SDLP_CDW10_SCT_SHIFT``
  Shift amount to set Status Code Type (SCT)

``NVME_SDLP_CDW10_SCT_MASK``
  Mask to set SCT

``NVME_SDLP_CDW10_RLPS_SHIFT``
  Shift amount to set Requested Log Page
  Status (RLPS), see :c:type:`enum
  nvme_send_discovery_log_page_rlps <nvme_send_discovery_log_page_rlps>`

``NVME_SDLP_CDW10_RLPS_MASK``
  Mask to set RLPS




.. c:enum:: nvme_send_discovery_log_page_cqe_dw0

   Send Discovery Log Page (SDLP) Completion Queue Entry Dword 0

**Constants**

``NVME_SDLP_CQE_LPUR``
  Log Page Update Registration (LPUR)




.. c:enum:: nvme_cross_ctrl_reset_ccrs

   Cross-Controller Reset Entry - Cross- Controller Reset Status (CCRS)

**Constants**

``NVME_CROSS_CTRL_RESET_CCRS_IN_PROGRESS``
  In Progress

``NVME_CROSS_CTRL_RESET_CCRS_SUCCESS``
  Success

``NVME_CROSS_CTRL_RESET_CCRS_FAILED``
  Failed




.. c:enum:: nvme_cross_ctrl_reset_ccrf

   Cross-Controller Reset Entry - Cross- Controller Reset Flags (CCRF)

**Constants**

``NVME_CROSS_CTRL_RESET_CCRF_V``
  Validated (V)

``NVME_CROSS_CTRL_RESET_CCRF_CLRI``
  Controller Level Reset Initiated
  (CLRI)

``NVME_CROSS_CTRL_RESET_CCRF_RETRY_SHIFT``
  Shift amount to get the Retry
  (RETRY) field

``NVME_CROSS_CTRL_RESET_CCRF_RETRY_MASK``
  Mask to get RETRY




.. c:struct:: nvme_cross_ctrl_reset_entry

   Cross-Controller Reset Entry Data Structure

**Definition**

::

  struct nvme_cross_ctrl_reset_entry {
    __le16 icid;
    __u8 ciu;
    __u8 rsvd3;
    __le16 acid;
    __u8 ccrs;
    __u8 ccrf;
  };

**Members**

``icid``
  Impacted Controller ID (ICID)

``ciu``
  Controller Instance Uniquifier (CIU)

``rsvd3``
  Reserved

``acid``
  Alternate Controller ID (ACID)

``ccrs``
  Cross-Controller Reset Status (CCRS), see :c:type:`enum
  nvme_cross_ctrl_reset_ccrs <nvme_cross_ctrl_reset_ccrs>`

``ccrf``
  Cross-Controller Reset Flags (CCRF), see :c:type:`enum
  nvme_cross_ctrl_reset_ccrf <nvme_cross_ctrl_reset_ccrf>`





.. c:struct:: nvme_cross_ctrl_reset_log

   Cross-Controller Reset Log Page (Log Identifier 1Eh)

**Definition**

::

  struct nvme_cross_ctrl_reset_log {
    __le16 ne;
    __u8 rsvd2[6];
    struct nvme_cross_ctrl_reset_entry entries[];
  };

**Members**

``ne``
  Number of Entries (NE)

``rsvd2``
  Reserved

``entries``
  Cross-Controller Reset Entry list, see :c:type:`struct
  nvme_cross_ctrl_reset_entry <nvme_cross_ctrl_reset_entry>`





.. c:struct:: nvme_lost_host_comm_entry

   Lost Host Communication Entry Data Structure

**Definition**

::

  struct nvme_lost_host_comm_entry {
    __le16 cntlid;
    __u8 lc;
    __u8 ciu;
    __u8 rsvd4[4];
  };

**Members**

``cntlid``
  Controller ID (CNTLID) of the LHC Controller

``lc``
  Loss Count (LC)

``ciu``
  Controller Instance Uniquifier (CIU)

``rsvd4``
  Reserved





.. c:struct:: nvme_lost_host_comm_log

   Lost Host Communication Log Page (Log Identifier 1Fh)

**Definition**

::

  struct nvme_lost_host_comm_log {
    __le16 ne;
    __u8 rsvd2[6];
    struct nvme_lost_host_comm_entry entries[];
  };

**Members**

``ne``
  Number of Entries (NE)

``rsvd2``
  Reserved

``entries``
  Lost Host Communication Entry list, see :c:type:`struct
  nvme_lost_host_comm_entry <nvme_lost_host_comm_entry>`





.. c:struct:: nvme_pull_model_ddc_req_log

   Pull Model DDC Request Log

**Definition**

::

  struct nvme_pull_model_ddc_req_log {
    __u8 ori;
    __u8 rsvd1[3];
    __le32 tpdrpl;
    __u8 osp[];
  };

**Members**

``ori``
  Operation Request Identifier

``rsvd1``
  Reserved

``tpdrpl``
  Total Pull Model DDC Request Log Page Length

``osp``
  Operation Specific Parameters





.. c:enum:: nvme_status_field

   Defines all parts of the nvme status field: status code, status code type, and additional flags.

**Constants**

``NVME_SCT_GENERIC``
  Generic errors applicable to multiple opcodes

``NVME_SCT_CMD_SPECIFIC``
  Errors associated to a specific opcode

``NVME_SCT_MEDIA``
  Errors associated with media and data integrity

``NVME_SCT_PATH``
  Errors associated with the paths connection

``NVME_SCT_VS``
  Vendor specific errors

``NVME_SCT_MASK``
  Mask to get the value of the Status Code Type

``NVME_SCT_SHIFT``
  Shift value to get the value of the Status
  Code Type

``NVME_SC_MASK``
  Mask to get the value of the status code.

``NVME_SC_SHIFT``
  Shift value to get the value of the status
  code.

``NVME_SC_SUCCESS``
  Successful Completion: The command
  completed without error.

``NVME_SC_INVALID_OPCODE``
  Invalid Command Opcode: A reserved coded
  value or an unsupported value in the
  command opcode field.

``NVME_SC_INVALID_FIELD``
  Invalid Field in Command: A reserved
  coded value or an unsupported value in a
  defined field.

``NVME_SC_CMDID_CONFLICT``
  Command ID Conflict: The command
  identifier is already in use.

``NVME_SC_DATA_XFER_ERROR``
  Data Transfer Error: Transferring the
  data or metadata associated with a
  command experienced an error.

``NVME_SC_POWER_LOSS``
  Commands Aborted due to Power Loss
  Notification: Indicates that the command
  was aborted due to a power loss
  notification.

``NVME_SC_INTERNAL``
  Internal Error: The command was not
  completed successfully due to an internal error.

``NVME_SC_ABORT_REQ``
  Command Abort Requested: The command was
  aborted due to an Abort command being
  received that specified the Submission
  Queue Identifier and Command Identifier
  of this command.

``NVME_SC_ABORT_QUEUE``
  Command Aborted due to SQ Deletion: The
  command was aborted due to a Delete I/O
  Submission Queue request received for the
  Submission Queue to which the command was
  submitted.

``NVME_SC_FUSED_FAIL``
  Command Aborted due to Failed Fused Command:
  The command was aborted due to the other
  command in a fused operation failing.

``NVME_SC_FUSED_MISSING``
  Aborted due to Missing Fused Command: The
  fused command was aborted due to the
  adjacent submission queue entry not
  containing a fused command that is the
  other command.

``NVME_SC_INVALID_NS``
  Invalid Namespace or Format: The
  namespace or the format of that namespace
  is invalid.

``NVME_SC_CMD_SEQ_ERROR``
  Command Sequence Error: The command was
  aborted due to a protocol violation in a
  multi-command sequence.

``NVME_SC_SGL_INVALID_LAST``
  Invalid SGL Segment Descriptor: The
  command includes an invalid SGL Last
  Segment or SGL Segment descriptor.

``NVME_SC_SGL_INVALID_COUNT``
  Invalid Number of SGL Descriptors: There
  is an SGL Last Segment descriptor or an
  SGL Segment descriptor in a location
  other than the last descriptor of a
  segment based on the length indicated.

``NVME_SC_SGL_INVALID_DATA``
  Data SGL Length Invalid: This may occur
  if the length of a Data SGL is too short.
  This may occur if the length of a Data
  SGL is too long and the controller does
  not support SGL transfers longer than the
  amount of data to be transferred as
  indicated in the SGL Support field of the
  Identify Controller data structure.

``NVME_SC_SGL_INVALID_METADATA``
  Metadata SGL Length Invalid: This may
  occur if the length of a Metadata SGL is
  too short. This may occur if the length
  of a Metadata SGL is too long and the
  controller does not support SGL transfers
  longer than the amount of data to be
  transferred as indicated in the SGL
  Support field of the Identify Controller
  data structure.

``NVME_SC_SGL_INVALID_TYPE``
  SGL Descriptor Type Invalid: The type of
  an SGL Descriptor is a type that is not
  supported by the controller.

``NVME_SC_CMB_INVALID_USE``
  Invalid Use of Controller Memory Buffer:
  The attempted use of the Controller
  Memory Buffer is not supported by the
  controller.

``NVME_SC_PRP_INVALID_OFFSET``
  PRP Offset Invalid: The Offset field for
  a PRP entry is invalid.

``NVME_SC_AWU_EXCEEDED``
  Atomic Write Unit Exceeded: The length
  specified exceeds the atomic write unit size.

``NVME_SC_OP_DENIED``
  Operation Denied: The command was denied
  due to lack of access rights. Refer to
  the appropriate security specification.

``NVME_SC_SGL_INVALID_OFFSET``
  SGL Offset Invalid: The offset specified
  in a descriptor is invalid. This may
  occur when using capsules for data
  transfers in NVMe over Fabrics
  implementations and an invalid offset in
  the capsule is specified.

``NVME_SC_HOSTID_FORMAT``
  Host Identifier Inconsistent Format: The
  NVM subsystem detected the simultaneous
  use of 64- bit and 128-bit Host
  Identifier values on different
  controllers.

``NVME_SC_KAT_EXPIRED``
  Keep Alive Timer Expired: The Keep Alive
  Timer expired.

``NVME_SC_KAT_INVALID``
  Keep Alive Timeout Invalid: The Keep
  Alive Timeout value specified is invalid.

``NVME_SC_CMD_ABORTED_PREMEPT``
  Command Aborted due to Preempt and Abort:
  The command was aborted due to a
  Reservation Acquire command.

``NVME_SC_SANITIZE_FAILED``
  Sanitize Failed: The most recent sanitize
  operation failed and no recovery action
  has been successfully completed.

``NVME_SC_SANITIZE_IN_PROGRESS``
  Sanitize In Progress: The requested
  function (e.g., command) is prohibited
  while a sanitize operation is in
  progress.

``NVME_SC_SGL_INVALID_GRANULARITY``
  SGL Data Block Granularity Invalid: The
  Address alignment or Length granularity
  for an SGL Data Block descriptor is
  invalid.

``NVME_SC_CMD_IN_CMBQ_NOT_SUPP``
  Command Not Supported for Queue in CMB:
  The implementation does not support
  submission of the command to a Submission
  Queue in the Controller Memory Buffer or
  command completion to a Completion Queue
  in the Controller Memory Buffer.

``NVME_SC_NS_WRITE_PROTECTED``
  Namespace is Write Protected: The command
  is prohibited while the namespace is
  write protected as a result of a change
  in the namespace write protection state
  as defined by the Namespace Write
  Protection State Machine.

``NVME_SC_CMD_INTERRUPTED``
  Command Interrupted: Command processing
  was interrupted and the controller is
  unable to successfully complete the
  command. The host should retry the
  command.

``NVME_SC_TRAN_TPORT_ERROR``
  Transient Transport Error: A transient
  transport error was detected. If the
  command is retried on the same
  controller, the command is likely to
  succeed. A command that fails with a
  transient transport error four or more
  times should be treated as a persistent
  transport error that is not likely to
  succeed if retried on the same
  controller.

``NVME_SC_PROHIBITED_BY_CMD_AND_FEAT``
  Command Prohibited by Command and Feature
  Lockdown: The command was aborted due to
  command execution being prohibited by
  the Command and Feature Lockdown.

``NVME_SC_ADMIN_CMD_MEDIA_NOT_READY``
  Admin Command Media Not Ready: The Admin
  command requires access to media and
  the media is not ready.

``NVME_SC_INVALID_KEY_TAG``
  The command was aborted due to an invalid KEYTAG
  field value.

``NVME_SC_HOST_DISPERSED_NS_NOT_ENABLED``
  The command is prohibited while the
  Host Disperesed Namespace Support (HDISNS) field is not
  set to 1h in the Host Behavior Support feature.

``NVME_SC_HOST_ID_NOT_INITIALIZED``
  Host Identifier Not Initialized.

``NVME_SC_INCORRECT_KEY``
  The command was aborted due to the key associated
  with the KEYTAG field being incorrect.

``NVME_SC_FDP_DISABLED``
  Command is not allowed when
  Flexible Data Placement is disabled.

``NVME_SC_INVALID_PLACEMENT_HANDLE_LIST``
  The Placement Handle List is invalid
  due to invalid Reclaim Unit Handle Identifier or
  valid Reclaim Unit Handle Identifier but restricted or
  the Placement Handle List number of entries exceeded the
  maximum number allowed.

``NVME_SC_SANITIZE_NS_FAILED``
  Sanitize Namespace Failed: The most
  recent namespace sanitize operation failed
  and no recovery action has been
  successfully completed.

``NVME_SC_SANITIZE_NS_IN_PROGRESS``
  Sanitize Namespace In Progress: The
  requested function (e.g., command) is
  prohibited while a namespace sanitize
  operation is in progress.

``NVME_SC_FAILED_TO_RESTORE_CONFIG``
  Failed to Restore Configuration: The
  command was aborted due to the command
  failing to restore configuration.

``NVME_SC_LBA_RANGE``
  LBA Out of Range: The command references
  an LBA that exceeds the size of the namespace.

``NVME_SC_CAP_EXCEEDED``
  Capacity Exceeded: Execution of the
  command has caused the capacity of the
  namespace to be exceeded.

``NVME_SC_NS_NOT_READY``
  Namespace Not Ready: The namespace is not
  ready to be accessed as a result of a
  condition other than a condition that is
  reported as an Asymmetric Namespace
  Access condition.

``NVME_SC_RESERVATION_CONFLICT``
  Reservation Conflict: The command was
  aborted due to a conflict with a
  reservation held on the accessed
  namespace.

``NVME_SC_FORMAT_IN_PROGRESS``
  Format In Progress: A Format NVM command
  is in progress on the namespace.

``NVME_SC_INVALID_VALUE_SIZE``
  The value size is not valid.

``NVME_SC_INVALID_KEY_SIZE``
  The KV key size is not valid.

``NVME_SC_KV_KEY_NOT_EXISTS``
  The Store If Key Exists (SIKE) bit is set to
  '1' in the Store Option field and the KV key does not
  exists.

``NVME_SC_UNRECOVERED_ERROR``
  There was an unrecovered error when reading
  from the meidum.

``NVME_SC_KEY_EXISTS``
  The Store If No Key Exists (SINKE) bit is set to '1'
  in the Store Option field and the KV key exists.

``NVME_SC_CQ_INVALID``
  Completion Queue Invalid: The Completion
  Queue identifier specified in the command
  does not exist.

``NVME_SC_QID_INVALID``
  Invalid Queue Identifier: The creation of
  the I/O Completion Queue failed due to an
  invalid queue identifier specified as
  part of the command. An invalid queue
  identifier is one that is currently in
  use or one that is outside the range
  supported by the controller.

``NVME_SC_QUEUE_SIZE``
  Invalid Queue Size: The host attempted to
  create an I/O Completion Queue with an
  invalid number of entries.

``NVME_SC_ABORT_LIMIT``
  Abort Command Limit Exceeded: The number
  of concurrently outstanding Abort commands
  has exceeded the limit indicated in the
  Identify Controller data structure.

``NVME_SC_ABORT_MISSING``
  Abort Command is missing: The abort
  command is missing.

``NVME_SC_ASYNC_LIMIT``
  Asynchronous Event Request Limit
  Exceeded: The number of concurrently
  outstanding Asynchronous Event Request
  commands has been exceeded.

``NVME_SC_FIRMWARE_SLOT``
  Invalid Firmware Slot: The firmware slot
  indicated is invalid or read only. This
  error is indicated if the firmware slot
  exceeds the number supported.

``NVME_SC_FIRMWARE_IMAGE``
  Invalid Firmware Image: The firmware
  image specified for activation is invalid
  and not loaded by the controller.

``NVME_SC_INVALID_VECTOR``
  Invalid Interrupt Vector: The creation of
  the I/O Completion Queue failed due to an
  invalid interrupt vector specified as
  part of the command.

``NVME_SC_INVALID_LOG_PAGE``
  Invalid Log Page: The log page indicated
  is invalid. This error condition is also
  returned if a reserved log page is
  requested.

``NVME_SC_INVALID_FORMAT``
  Invalid Format: The LBA Format specified
  is not supported.

``NVME_SC_FW_NEEDS_CONV_RESET``
  Firmware Activation Requires Conventional Reset:
  The firmware commit was successful,
  however, activation of the firmware image
  requires a conventional reset.

``NVME_SC_INVALID_QUEUE``
  Invalid Queue Deletion: Invalid I/O
  Completion Queue specified to delete.

``NVME_SC_FEATURE_NOT_SAVEABLE``
  Feature Identifier Not Saveable: The
  Feature Identifier specified does not
  support a saveable value.

``NVME_SC_FEATURE_NOT_CHANGEABLE``
  Feature Not Changeable: The Feature
  Identifier is not able to be changed.

``NVME_SC_FEATURE_NOT_PER_NS``
  Feature Not Namespace Specific: The
  Feature Identifier specified is not
  namespace specific. The Feature
  Identifier settings apply across all
  namespaces.

``NVME_SC_FW_NEEDS_SUBSYS_RESET``
  Firmware Activation Requires NVM
  Subsystem Reset: The firmware commit was
  successful, however, activation of the
  firmware image requires an NVM Subsystem.

``NVME_SC_FW_NEEDS_RESET``
  Firmware Activation Requires Controller
  Level Reset: The firmware commit was
  successful; however, the image specified
  does not support being activated without
  a reset.

``NVME_SC_FW_NEEDS_MAX_TIME``
  Firmware Activation Requires Maximum Time
  Violation: The image specified if
  activated immediately would exceed the
  Maximum Time for Firmware Activation
  (MTFA) value reported in Identify
  Controller.

``NVME_SC_FW_ACTIVATE_PROHIBITED``
  Firmware Activation Prohibited: The image
  specified is being prohibited from
  activation by the controller for vendor
  specific reasons.

``NVME_SC_OVERLAPPING_RANGE``
  Overlapping Range: The downloaded
  firmware image has overlapping ranges.

``NVME_SC_NS_INSUFFICIENT_CAP``
  Namespace Insufficient Capacity: Creating
  the namespace requires more free space
  than is currently available.

``NVME_SC_NS_ID_UNAVAILABLE``
  Namespace Identifier Unavailable: The
  number of namespaces supported has been
  exceeded.

``NVME_SC_NS_ALREADY_ATTACHED``
  Namespace Already Attached: The
  controller is already attached to the
  namespace specified.

``NVME_SC_NS_IS_PRIVATE``
  Namespace Is Private: The namespace is
  private and is already attached to one
  controller.

``NVME_SC_NS_NOT_ATTACHED``
  Namespace Not Attached: The request to
  detach the controller could not be
  completed because the controller is not
  attached to the namespace.

``NVME_SC_THIN_PROV_NOT_SUPP``
  Thin Provisioning Not Supported: Thin
  provisioning is not supported by the
  controller.

``NVME_SC_CTRL_LIST_INVALID``
  Controller List Invalid: The controller
  list provided contains invalid controller
  ids.

``NVME_SC_SELF_TEST_IN_PROGRESS``
  Device Self-test In Progress: The controller
  or NVM subsystem already has a device
  self-test operation in process.

``NVME_SC_BP_WRITE_PROHIBITED``
  Boot Partition Write Prohibited: The
  command is trying to modify a locked Boot
  Partition.

``NVME_SC_INVALID_CTRL_ID``
  Invalid Controller Identifier:

``NVME_SC_INVALID_SEC_CTRL_STATE``
  Invalid Secondary Controller State

``NVME_SC_INVALID_CTRL_RESOURCES``
  Invalid Number of Controller Resources

``NVME_SC_INVALID_RESOURCE_ID``
  Invalid Resource Identifier

``NVME_SC_PMR_SAN_PROHIBITED``
  Sanitize Prohibited While Persistent
  Memory Region is Enabled

``NVME_SC_ANA_GROUP_ID_INVALID``
  ANA Group Identifier Invalid: The specified
  ANA Group Identifier (ANAGRPID) is not
  supported in the submitted command.

``NVME_SC_ANA_ATTACH_FAILED``
  ANA Attach Failed: The controller is not
  attached to the namespace as a result
  of an ANA condition.

``NVME_SC_INSUFFICIENT_CAP``
  Insufficient Capacity: Requested operation
  requires more free space than is currently
  available.

``NVME_SC_NS_ATTACHMENT_LIMIT_EXCEEDED``
  Namespace Attachment Limit Exceeded:
  Attaching the ns to a controller causes
  max number of ns attachments allowed
  to be exceeded.

``NVME_SC_PROHIBIT_CMD_EXEC_NOT_SUPPORTED``
  Prohibition of Command Execution
  Not Supported

``NVME_SC_IOCS_NOT_SUPPORTED``
  I/O Command Set Not Supported

``NVME_SC_IOCS_NOT_ENABLED``
  I/O Command Set Not Enabled

``NVME_SC_IOCS_COMBINATION_REJECTED``
  I/O Command Set Combination Rejected

``NVME_SC_INVALID_IOCS``
  Invalid I/O Command Set

``NVME_SC_ID_UNAVAILABLE``
  Identifier Unavailable

``NVME_SC_INVALID_DISCOVERY_INFO``
  The discovery information provided in
  one or more extended discovery
  information entries is not applicable
  for the type of entity selected in
  the Entity Type (ETYPE) field of the
  Discovery Information Management
  command data portion’s header.

``NVME_SC_ZONING_DATA_STRUCT_LOCKED``
  The requested Zoning data structure
  is locked on the CDC.

``NVME_SC_ZONING_DATA_STRUCT_NOTFND``
  The requested Zoning data structure
  does not exist on the CDC.

``NVME_SC_INSUFFICIENT_DISC_RES``
  The number of discover information
  entries provided in the data portion
  of the Discovery Information
  Management command for a registration
  task (i.e., TAS field cleared to 0h)
  exceeds the available capacity for
  new discovery information entries on
  the CDC or DDC. This may be a
  transient condition.

``NVME_SC_REQSTD_FUNCTION_DISABLED``
  Fabric Zoning is not enabled on the
  CDC

``NVME_SC_ZONEGRP_ORIGINATOR_INVLD``
  The NQN contained in the ZoneGroup
  Originator field does not match the
  Host NQN used by the DDC to connect
  to the CDC.

``NVME_SC_INVALID_HOST``
  Invalid Host: the Manage Exported NVM
  Subsystem Send Grant/Revoke Host Access
  operation specified a host entry that
  could not be processed.

``NVME_SC_INVALID_NVM_SUBSYSTEM``
  Invalid NVM Subsystem: the Manage
  Exported NVM Subsystem Send Grant/Revoke
  Host Access operation specified an
  Exported NVM Subsystem entry that could
  not be processed.

``NVME_SC_INVALID_CONTROLER_DATA_QUEUE``
  This error indicates that the
  specified Controller Data Queue
  Identifier is invalid for the controller
  processing the command.

``NVME_SC_NOT_ENOUGH_RESOURCES``
  This error indicates that there is not
  enough resources in the controller to
  process the command.

``NVME_SC_CONTROLLER_SUSPENDED``
  The operation requested is not allowed if
  the specified controller is suspended.

``NVME_SC_CONTROLLER_NOT_SUSPENDED``
  The operation requested is not allowed if
  the specified controller is not
  suspended.

``NVME_SC_CONTROLLER_DATA_QUEUE_FULL``
  The controller detected that a
  Controller Data Queue became full.

``NVME_SC_EXCEEDS_MAX_NS_SANITIZE``
  Request Exceeds Maximum Namespace
  Sanitize Operations In Progress
  (Sanitize Namespace command specific
  status). Numerically identical to
  ``NVME_SC_FW_NEEDS_MAX_TIME`` (Firmware
  Commit) - command specific status is
  scoped per opcode, so this collision is
  expected; use only when decoding the
  completion of a Sanitize Namespace
  command.

``NVME_SC_MFG_DEFAULT_PERSONALITY_REQUIRED``
  Manufacturing Default Personality
  Required: The Firmware Commit command was
  aborted due to the firmware image being
  incompatible with the current personality
  settings; the settings of each affected
  personality are required to be compatible
  with the current personality settings for
  the firmware image to be committed.

``NVME_SC_INVALID_POWER_LIMIT``
  Invalid Power Limit: The power limit
  specified for the Power Limit feature is
  invalid because that power limit prohibits
  all operational power states.

``NVME_SC_CROSS_CTRL_RESET_IN_PROGRESS``
  Cross-Controller Reset in Progress:
  there is already an in-progress
  Cross-Controller Reset operation that
  this controller caused to be initiated
  for the Impacted Controller.

``NVME_SC_CROSS_CTRL_RESET_LOG_FULL``
  Cross-Controller Reset Log Page Full:
  the Cross-Controller Reset log page
  already contains the maximum number of
  entries.

``NVME_SC_CROSS_CTRL_RESET_LIMIT_EXCEEDED``
  Cross-Controller Reset Limit
  Exceeded: the number of simultaneous
  in-progress Cross-Controller Reset
  operations this controller caused to be
  initiated is greater than or equal to
  the Cross-Controller Reset Limit field
  in the Identify Controller data
  structure.

``NVME_SC_CONTROLLER_ACTIVE``
  Controller Active: for a Manage Exported
  NVM Subsystem Send Delete operation, an
  Underlying Controller in the specified
  Exported NVM Subsystem is able to
  process commands. For an Associate
  Controllers operation, an Underlying
  Controller being associated with an
  Exported NVM Subsystem was in a state
  that could process commands.

``NVME_SC_INVALID_EXPORTED_ASSOCIATION``
  Invalid Exported Association: an
  Underlying Controller being associated
  with an Exported NVM Subsystem has
  Underlying Namespaces attached that are
  not associated with that Exported NVM
  Subsystem, or the association otherwise
  conflicts with an existing one.

``NVME_SC_INVALID_EXPORTED_CONFIG_STATE``
  Invalid Exported Configuration
  State: invalid data was found in the
  Exported Configuration State provided
  with the Set Exported Configuration
  State management operation.

``NVME_SC_BAD_ATTRIBUTES``
  Conflicting Dataset Management Attributes

``NVME_SC_INVALID_PI``
  Invalid Protection Information

``NVME_SC_READ_ONLY``
  Attempted Write to Read Only Range

``NVME_SC_CMD_SIZE_LIMIT_EXCEEDED``
  Command Size Limit Exceeded

``NVME_SC_INVALID_CMD_ID``
  Invalid Command ID: for the Cancel
  command, the specified Command
  Identifier (CID) matched the CID of
  the Cancel command itself.

``NVME_SC_INCOMPATIBLE_NS``
  Incompatible Namespace or Format: At
  least one source namespace and the
  destination namespace have incompatible
  formats.

``NVME_SC_FAST_COPY_NOT_POSSIBLE``
  Fast Copy Not Possible: The Fast Copy
  Only (FCO) bit was set to ‘1’ in a Source
  Range entry and the controller was not
  able to use fast copy operations to copy
  the specified data.

``NVME_SC_OVERLAPPING_IO_RANGE``
  Overlapping I/O Range: A source logical
  block range overlaps the destination
  logical block range.

``NVME_SC_INSUFFICIENT_RESOURCES``
  Insufficient Resources: A resource
  shortage prevented the controller from
  performing the requested copy.

``NVME_SC_CONNECT_FORMAT``
  Incompatible Format: The NVM subsystem
  does not support the record format
  specified by the host.

``NVME_SC_CONNECT_CTRL_BUSY``
  Controller Busy: The controller is
  already associated with a host.

``NVME_SC_CONNECT_INVALID_PARAM``
  Connect Invalid Parameters: One or more
  of the command parameters.

``NVME_SC_CONNECT_RESTART_DISC``
  Connect Restart Discovery: The NVM
  subsystem requested is not available.

``NVME_SC_CONNECT_INVALID_HOST``
  Connect Invalid Host: The host is either
  not allowed to establish an association
  to any controller in the NVM subsystem or
  the host is not allowed to establish an
  association to the specified controller

``NVME_SC_DISCONNECT_INVALID_QTYPE``
  Invalid Queue Type: The command was sent
  on the wrong queue type.

``NVME_SC_DISCOVERY_RESTART``
  Discover Restart: The snapshot of the
  records is now invalid or out of date.

``NVME_SC_AUTH_REQUIRED``
  Authentication Required: NVMe in-band
  authentication is required and the queue
  has not yet been authenticated.

``NVME_SC_ZNS_INVALID_OP_REQUEST``
  Invalid Zone Operation Request:
  The operation requested is invalid. This may be due to
  various conditions, including: attempting to allocate a
  ZRWA when a zone is not in the ZSE:Empty state; or
  invalid Flush Explicit ZRWA Range Send Zone Action
  operation.

``NVME_SC_ZNS_ZRWA_RESOURCES_UNAVAILABLE``
  ZRWA Resources Unavailable:
  No ZRWAs are available.

``NVME_SC_ZNS_BOUNDARY_ERROR``
  Zone Boundary Error: The command specifies
  logical blocks in more than one zone.

``NVME_SC_ZNS_FULL``
  Zone Is Full: The accessed zone is in the
  ZSF:Full state.

``NVME_SC_ZNS_READ_ONLY``
  Zone Is Read Only: The accessed zone is
  in the ZSRO:Read Only state.

``NVME_SC_ZNS_OFFLINE``
  Zone Is Offline: The accessed zone is
  in the ZSO:Offline state.

``NVME_SC_ZNS_INVALID_WRITE``
  Zone Invalid Write: The write to a zone
  was not at the write pointer.

``NVME_SC_ZNS_TOO_MANY_ACTIVE``
  Too Many Active Zones: The controller
  does not allow additional active zones.

``NVME_SC_ZNS_TOO_MANY_OPENS``
  Too Many Open Zones: The controller does
  not allow additional open zones.

``NVME_SC_ZNS_INVAL_TRANSITION``
  Invalid Zone State Transition: The request
  is not a valid zone state transition.

``NVME_SC_WRITE_FAULT``
  Write Fault: The write data could not be
  committed to the media.

``NVME_SC_READ_ERROR``
  Unrecovered Read Error: The read data
  could not be recovered from the media.

``NVME_SC_GUARD_CHECK``
  End-to-end Guard Check Error: The command
  was aborted due to an end-to-end guard
  check failure.

``NVME_SC_APPTAG_CHECK``
  End-to-end Application Tag Check Error:
  The command was aborted due to an
  end-to-end application tag check failure.

``NVME_SC_REFTAG_CHECK``
  End-to-end Reference Tag Check Error: The
  command was aborted due to an end-to-end
  reference tag check failure.

``NVME_SC_COMPARE_FAILED``
  Compare Failure: The command failed due
  to a miscompare during a Compare command.

``NVME_SC_ACCESS_DENIED``
  Access Denied: Access to the namespace
  and/or LBA range is denied due to lack of
  access rights.

``NVME_SC_UNWRITTEN_BLOCK``
  Deallocated or Unwritten Logical Block:
  The command failed due to an attempt to
  read from or verify an LBA range
  containing a deallocated or unwritten
  logical block.

``NVME_SC_STORAGE_TAG_CHECK``
  End-to-End Storage Tag Check Error: The
  command was aborted due to an end-to-end
  storage tag check failure.

``NVME_SC_ANA_INTERNAL_PATH_ERROR``
  Internal Path Error: The command was not
  completed as the result of a controller
  internal error that is specific to the
  controller processing the command.

``NVME_SC_ANA_PERSISTENT_LOSS``
  Asymmetric Access Persistent Loss: The
  requested function (e.g., command) is not
  able to be performed as a result of the
  relationship between the controller and
  the namespace being in the ANA Persistent
  Loss state.

``NVME_SC_ANA_INACCESSIBLE``
  Asymmetric Access Inaccessible: The
  requested function (e.g., command) is not
  able to be performed as a result of the
  relationship between the controller and
  the namespace being in the ANA
  Inaccessible state.

``NVME_SC_ANA_TRANSITION``
  Asymmetric Access Transition: The
  requested function (e.g., command) is not
  able to be performed as a result of the
  relationship between the controller and
  the namespace transitioning between
  Asymmetric Namespace Access states.

``NVME_SC_CTRL_PATH_ERROR``
  Controller Pathing Error: A pathing error
  was detected by the controller.

``NVME_SC_HOST_PATH_ERROR``
  Host Pathing Error: A pathing error was
  detected by the host.

``NVME_SC_CMD_ABORTED_BY_HOST``
  Command Aborted By Host: The command was
  aborted as a result of host action.

``NVME_SC_CRD``
  Mask to get value of Command Retry Delay
  index

``NVME_SC_MORE``
  More bit. If set, more status information
  for this command as part of the Error
  Information log that may be retrieved with
  the Get Log Page command.

``NVME_SC_DNR``
  Do Not Retry bit. If set, if the same
  command is re-submitted to any controller
  in the NVM subsystem, then that
  re-submitted command is expected to fail.


.. c:function:: __u16 nvme_status_code_type (__u16 status_field)

   Returns the NVMe Status Code Type

**Parameters**

``__u16 status_field``
  The NVMe Completion Queue Entry's Status Field
  See :c:type:`enum nvme_status_field <nvme_status_field>`

**Return**

status code type


.. c:function:: __u16 nvme_status_code (__u16 status_field)

   Returns the NVMe Status Code

**Parameters**

``__u16 status_field``
  The NVMe Completion Queue Entry's Status Field
  See :c:type:`enum nvme_status_field <nvme_status_field>`

**Return**

status code




.. c:enum:: nvme_status_type

   type encoding for NVMe return values, when represented as an int.

**Constants**

``NVME_STATUS_TYPE_SHIFT``
  shift value for status bits

``NVME_STATUS_TYPE_MASK``
  mask value for status bits

``NVME_STATUS_TYPE_NVME``
  NVMe command status value, typically from CDW3

``NVME_STATUS_TYPE_MI``
  NVMe-MI header status

**Description**


The nvme_* api returns an int, with negative values indicating an internal
or syscall error, zero signifying success, positive values representing
the NVMe status.

That latter case (the NVMe status) may represent status values from
different parts of the transport/controller/etc, and are at most 16 bits of
data. So, we use the most-significant 3 bits of the signed int to indicate
which type of status this is.


.. c:function:: __u32 nvme_status_get_type (int status)

   extract the type from a nvme_* return value

**Parameters**

``int status``
  the (non-negative) return value from the NVMe API

**Return**

the type component of the status.


.. c:function:: __u32 nvme_status_get_value (int status)

   extract the status value from a nvme_* return value

**Parameters**

``int status``
  the (non-negative) return value from the NVMe API

**Return**

the value component of the status; the set of values will depend
on the status type.


.. c:function:: __u32 nvme_status_equals (int status, enum nvme_status_type type, unsigned int value)

   helper to check a status against a type and value

**Parameters**

``int status``
  the (non-negative) return value from the NVMe API

``enum nvme_status_type type``
  the status type

``unsigned int value``
  the status value

**Return**

true if **status** is of the specified type and value




.. c:enum:: nvme_admin_opcode

   Known NVMe admin opcodes

**Constants**

``nvme_admin_delete_sq``
  Delete I/O Submission Queue

``nvme_admin_create_sq``
  Create I/O Submission Queue

``nvme_admin_get_log_page``
  Get Log Page

``nvme_admin_delete_cq``
  Delete I/O Completion Queue

``nvme_admin_create_cq``
  Create I/O Completion Queue

``nvme_admin_identify``
  Identify

``nvme_admin_abort_cmd``
  Abort

``nvme_admin_set_features``
  Set Features

``nvme_admin_get_features``
  Get Features

``nvme_admin_async_event``
  Asynchronous Event Request

``nvme_admin_ns_mgmt``
  Namespace Management

``nvme_admin_fw_commit``
  Firmware Commit

``nvme_admin_fw_activate``
  Firmware Commit

``nvme_admin_fw_download``
  Firmware Image Download

``nvme_admin_dev_self_test``
  Device Self-test

``nvme_admin_ns_attach``
  Namespace Attachment

``nvme_admin_keep_alive``
  Keep Alive

``nvme_admin_directive_send``
  Directive Send

``nvme_admin_directive_recv``
  Directive Receive

``nvme_admin_virtual_mgmt``
  Virtualization Management

``nvme_admin_nvme_mi_send``
  NVMe-MI Send

``nvme_admin_nvme_mi_recv``
  NVMe-MI Receive

``nvme_admin_capacity_mgmt``
  Capacity Management

``nvme_admin_discovery_info_mgmt``
  Discovery Information Management (DIM)

``nvme_admin_fabric_zoning_recv``
  Fabric Zoning Receive

``nvme_admin_lockdown``
  Lockdown

``nvme_admin_fabric_zoning_lookup``
  Fabric Zoning Lookup

``nvme_admin_clear_export_nvm_res``
  Clear Exported NVM Resource Configuration

``nvme_admin_fabric_zoning_send``
  Fabric Zoning Send

``nvme_admin_manage_export_nvms_receive``
  Manage Exported NVM Subsystem Receive

``nvme_admin_manage_export_nvms_send``
  Manage Exported NVM Subsystem Send

``nvme_admin_manage_export_ns``
  Manage Exported Namespace

``nvme_admin_manage_export_port``
  Manage Exported Port

``nvme_admin_cross_ctrl_reset``
  Cross-Controller Reset

``nvme_admin_send_disc_log_page``
  Send Discovery Log Page

``nvme_admin_track_send``
  Track Send

``nvme_admin_track_receive``
  Track Receive

``nvme_admin_migration_send``
  Migration Send

``nvme_admin_migration_receive``
  Migration Receive

``nvme_admin_ctrl_data_queue``
  Controller Data Queue

``nvme_admin_dbbuf``
  Doorbell Buffer Config

``nvme_admin_fabrics``
  Fabrics Commands

``nvme_admin_format_nvm``
  Format NVM

``nvme_admin_security_send``
  Security Send

``nvme_admin_security_recv``
  Security Receive

``nvme_admin_sanitize_nvm``
  Sanitize

``nvme_admin_load_program``
  Load Program

``nvme_admin_get_lba_status``
  Get LBA Status

``nvme_admin_program_act_mgmt``
  Program Activation Management

``nvme_admin_mem_range_set_mgmt``
  Memory Range Set Management

``nvme_admin_sanitize_ns``
  Sanitize Namespace




.. c:enum:: nvme_abort_cqe_dw0

   Abort Command – Completion Queue Entry Dword 0

**Constants**

``NVME_ABORT_CQE_DW0_IANP``
  Immediate Abort Not Performed: if set to '1',
  then an immediate abort was not performed for
  any reason. If cleared to '0', then an
  immediate abort was performed.




.. c:enum:: nvme_identify_cns

   Identify - CNS Values

**Constants**

``NVME_IDENTIFY_CNS_NS``
  Identify Namespace data structure

``NVME_IDENTIFY_CNS_CTRL``
  Identify Controller data structure

``NVME_IDENTIFY_CNS_NS_ACTIVE_LIST``
  Active Namespace ID list

``NVME_IDENTIFY_CNS_NS_DESC_LIST``
  Namespace Identification Descriptor list

``NVME_IDENTIFY_CNS_NVMSET_LIST``
  NVM Set List

``NVME_IDENTIFY_CNS_CSI_NS``
  I/O Command Set specific Identify
  Namespace data structure

``NVME_IDENTIFY_CNS_CSI_CTRL``
  I/O Command Set specific Identify
  Controller data structure

``NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST``
  Active Namespace ID list associated
  with the specified I/O Command Set

``NVME_IDENTIFY_CNS_CSI_INDEPENDENT_ID_NS``
  I/O Command Set Independent Identify

``NVME_IDENTIFY_CNS_NS_USER_DATA_FORMAT``
  Namespace user data format

``NVME_IDENTIFY_CNS_CSI_NS_USER_DATA_FORMAT``
  I/O Command Set specific user data
  format
  Namespace data structure

``NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST``
  Allocated Namespace ID list

``NVME_IDENTIFY_CNS_ALLOCATED_NS``
  Identify Namespace data structure for
  the specified allocated NSID

``NVME_IDENTIFY_CNS_NS_CTRL_LIST``
  Controller List of controllers attached
  to the specified NSID

``NVME_IDENTIFY_CNS_CTRL_LIST``
  Controller List of controllers that exist
  in the NVM subsystem

``NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP``
  Primary Controller Capabilities data
  structure for the specified primary controller

``NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST``
  Secondary Controller list of controllers
  associated with the primary controller
  processing the command

``NVME_IDENTIFY_CNS_NS_GRANULARITY``
  A Namespace Granularity List

``NVME_IDENTIFY_CNS_UUID_LIST``
  A UUID List

``NVME_IDENTIFY_CNS_DOMAIN_LIST``
  Domain List

``NVME_IDENTIFY_CNS_ENDURANCE_GROUP_ID``
  Endurance Group List

``NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS_LIST``
  I/O Command Set specific Allocated Namespace
  ID list

``NVME_IDENTIFY_CNS_CSI_ID_NS_DATA_STRUCTURE``
  I/O Command Set specific ID Namespace
  Data Structure for Allocated Namespace ID

``NVME_IDENTIFY_CNS_COMMAND_SET_STRUCTURE``
  I/O Command Set data structure

``NVME_IDENTIFY_CNS_UNDERLYING_NS_LIST``
  Get Underlying Namespace List

``NVME_IDENTIFY_CNS_PORTS_LIST``
  Get Ports List

``NVME_IDENTIFY_CNS_IOCS_IND_ID_ALLOC_NS``
  I/O Command Set Independent Identify Namespace data
  structure for the specified allocated NSID

``NVME_IDENTIFY_CNS_SUPPORTED_CTRL_STATE_FORMATS``
  Supported Controller State Formats
  identifying the supported NVMe Controller
  State data structures

``NVME_IDENTIFY_CNS_UNDERLYING_CTRL_LIST``
  Get Underlying Controller List

``NVME_IDENTIFY_CNS_EXPORTED_NVM_SUBSYS_TEMPLATE_UUID_LIST``
  Exported NVM
  Subsystem Template UUID List




.. c:enum:: nvme_cmd_get_log_lid

   Get Log Page -Log Page Identifiers

**Constants**

``NVME_LOG_LID_SUPPORTED_LOG_PAGES``
  Supported Log Pages

``NVME_LOG_LID_ERROR``
  Error Information

``NVME_LOG_LID_SMART``
  SMART / Health Information

``NVME_LOG_LID_FW_SLOT``
  Firmware Slot Information

``NVME_LOG_LID_CHANGED_ATTACHED_NS``
  Changed Attached Namespace List

``NVME_LOG_LID_CMD_EFFECTS``
  Commands Supported and Effects

``NVME_LOG_LID_DEVICE_SELF_TEST``
  Device Self-test

``NVME_LOG_LID_TELEMETRY_HOST``
  Telemetry Host-Initiated

``NVME_LOG_LID_TELEMETRY_CTRL``
  Telemetry Controller-Initiated

``NVME_LOG_LID_ENDURANCE_GROUP``
  Endurance Group Information

``NVME_LOG_LID_PREDICTABLE_LAT_NVMSET``
  Predictable Latency Per NVM Set

``NVME_LOG_LID_PREDICTABLE_LAT_AGG``
  Predictable Latency Event Aggregate

``NVME_LOG_LID_ANA``
  Asymmetric Namespace Access

``NVME_LOG_LID_PERSISTENT_EVENT``
  Persistent Event Log

``NVME_LOG_LID_LBA_STATUS``
  LBA Status Information

``NVME_LOG_LID_ENDURANCE_GRP_EVT``
  Endurance Group Event Aggregate

``NVME_LOG_LID_MEDIA_UNIT_STATUS``
  Media Unit Status

``NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST``
  Supported Capacity Configuration Lis

``NVME_LOG_LID_FID_SUPPORTED_EFFECTS``
  Feature Identifiers Supported and Effects

``NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS``
  NVMe-MI Commands Supported and Effects

``NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN``
  Command and Feature Lockdown

``NVME_LOG_LID_BOOT_PARTITION``
  Boot Partition

``NVME_LOG_LID_ROTATIONAL_MEDIA_INFO``
  Rotational Media Information

``NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS``
  Dispersed Namespace Participating NVM Subsystems

``NVME_LOG_LID_MGMT_ADDR_LIST``
  Management Address List

``NVME_LOG_LID_PHY_RX_EOM``
  Physical Interface Receiver Eye Opening Measurement

``NVME_LOG_LID_REACHABILITY_GROUPS``
  Reachability Groups

``NVME_LOG_LID_REACHABILITY_ASSOCIATIONS``
  Reachability Associations

``NVME_LOG_LID_CHANGED_ALLOC_NS``
  Changed Allocated Namespace List

``NVME_LOG_LID_DEV_PERSONALITY``
  Device Personalities, see :c:type:`struct
  nvme_dev_personalities_log <nvme_dev_personalities_log>`

``NVME_LOG_LID_CROSS_CTRL_RESET``
  Cross-Controller Reset

``NVME_LOG_LID_LOST_HOST_COMMUNICATION``
  Lost Host Communication

``NVME_LOG_LID_FDP_CONFIGS``
  FDP Configurations

``NVME_LOG_LID_FDP_RUH_USAGE``
  Reclaim Unit Handle Usage

``NVME_LOG_LID_FDP_STATS``
  FDP Statistics

``NVME_LOG_LID_FDP_EVENTS``
  FDP Events

``NVME_LOG_LID_MFG_DEFAULT_CONFIG``
  Manufacturer Default Configuration
  Status, see :c:type:`struct
  nvme_mfg_default_config_status_log <nvme_mfg_default_config_status_log>`

``NVME_LOG_LID_POWER_MEASUREMENT``
  Power Measurement

``NVME_LOG_LID_VOLTAGE_MEASUREMENT``
  Voltage Measurement, see
  :c:type:`struct
  nvme_voltage_measurement_log <nvme_voltage_measurement_log>`

``NVME_LOG_LID_RATE_LIMITING``
  Rate Limiting

``NVME_LOG_LID_DISCOVERY``
  Discovery

``NVME_LOG_LID_HOST_DISCOVERY``
  Host Discovery

``NVME_LOG_LID_AVE_DISCOVERY``
  AVE Discovery

``NVME_LOG_LID_PULL_MODEL_DDC_REQ``
  Pull Model DDC Request

``NVME_LOG_LID_SANITIZE_NS_STATUS_LIST``
  Sanitize Namespace Status List

``NVME_LOG_LID_RESERVATION``
  Reservation Notification

``NVME_LOG_LID_SANITIZE``
  Sanitize Status

``NVME_LOG_LID_HOST_ADDRESSABLE_NS``
  Host Addressable Namespaces, see
  :c:type:`struct nvme_host_addressable_ns_log <nvme_host_addressable_ns_log>`

``NVME_LOG_LID_ZNS_CHANGED_ZONES``
  Changed Zone List




.. c:enum:: nvme_features_id

   Features - Feature Identifiers

**Constants**

``NVME_FEAT_FID_ARBITRATION``
  Arbitration

``NVME_FEAT_FID_POWER_MGMT``
  Power Management

``NVME_FEAT_FID_LBA_RANGE``
  LBA Range Type

``NVME_FEAT_FID_TEMP_THRESH``
  Temperature Threshold

``NVME_FEAT_FID_ERR_RECOVERY``
  Error Recovery

``NVME_FEAT_FID_VOLATILE_WC``
  Volatile Write Cache

``NVME_FEAT_FID_NUM_QUEUES``
  Number of Queues

``NVME_FEAT_FID_IRQ_COALESCE``
  Interrupt Coalescing

``NVME_FEAT_FID_IRQ_CONFIG``
  Interrupt Vector Configuration

``NVME_FEAT_FID_WRITE_ATOMIC``
  Write Atomicity Normal

``NVME_FEAT_FID_ASYNC_EVENT``
  Asynchronous Event Configuration

``NVME_FEAT_FID_AUTO_PST``
  Autonomous Power State Transition

``NVME_FEAT_FID_HOST_MEM_BUF``
  Host Memory Buffer

``NVME_FEAT_FID_TIMESTAMP``
  Timestamp

``NVME_FEAT_FID_KATO``
  Keep Alive Timer

``NVME_FEAT_FID_HCTM``
  Host Controlled Thermal Management

``NVME_FEAT_FID_NOPSC``
  Non-Operational Power State Config

``NVME_FEAT_FID_RRL``
  Read Recovery Level Config

``NVME_FEAT_FID_PLM_CONFIG``
  Predictable Latency Mode Config

``NVME_FEAT_FID_PLM_WINDOW``
  Predictable Latency Mode Window

``NVME_FEAT_FID_LBA_STS_INTERVAL``
  LBA Status Information Report Interval

``NVME_FEAT_FID_HOST_BEHAVIOR``
  Host Behavior Support

``NVME_FEAT_FID_SANITIZE``
  Sanitize Config

``NVME_FEAT_FID_ENDURANCE_EVT_CFG``
  Endurance Group Event Configuration

``NVME_FEAT_FID_IOCS_PROFILE``
  I/O Command Set Profile

``NVME_FEAT_FID_SPINUP_CONTROL``
  Spinup Control

``NVME_FEAT_FID_POWER_LOSS_SIGNAL``
  Power Loss Signaling Config

``NVME_FEAT_FID_PERF_CHARACTERISTICS``
  Performance Characteristics

``NVME_FEAT_FID_FDP``
  Flexible Data Placement

``NVME_FEAT_FID_FDP_EVENTS``
  FDP Events

``NVME_FEAT_FID_NS_ADMIN_LABEL``
  Namespace Admin Label

``NVME_FEAT_FID_KEY_VALUE``
  Key Value Configuration

``NVME_FEAT_FID_CTRL_DATA_QUEUE``
  Controller Data Queue

``NVME_FEAT_FID_CONF_DEV_PERSONALITY``
  Configurable Device Personality, see
  :c:type:`enum nvme_cdp_cdw13_fields <nvme_cdp_cdw13_fields>` (Set/Get
  Features Command Dword 13), :c:type:`enum
  nvme_cdp_cqe_dw0_fields <nvme_cdp_cqe_dw0_fields>` (Get Features
  Completion Queue Entry Dword 0), and
  :c:type:`enum nvme_personality_identifier <nvme_personality_identifier>`

``NVME_FEAT_FID_POWER_LIMIT``
  Power Limit

``NVME_FEAT_FID_POWER_THRESH``
  Power Threshold

``NVME_FEAT_FID_POWER_MEASUREMENT``
  Power Measurement

``NVME_FEAT_FID_VOLTAGE_THRESHOLD``
  Voltage Threshold, see :c:type:`enum
  nvme_voltage_sensor <nvme_voltage_sensor>`

``NVME_FEAT_FID_VOLTAGE_MEASUREMENT``
  Voltage Measurement, see :c:type:`enum
  nvme_voltage_measurement_act <nvme_voltage_measurement_act>` and
  :c:type:`struct
  nvme_voltage_measurement_start_data <nvme_voltage_measurement_start_data>`

``NVME_FEAT_FID_RATE_LIMITING``
  Rate Limiting

``NVME_FEAT_FID_EMB_MGMT_CTRL_ADDR``
  Embedded Management Controller Address

``NVME_FEAT_FID_HOST_MGMT_AGENT_ADDR``
  Host Management Agent Address

``NVME_FEAT_FID_ENH_CTRL_METADATA``
  Enhanced Controller Metadata

``NVME_FEAT_FID_CTRL_METADATA``
  Controller Metadata

``NVME_FEAT_FID_NS_METADATA``
  Namespace Metadata

``NVME_FEAT_FID_SW_PROGRESS``
  Software Progress Marker

``NVME_FEAT_FID_HOST_ID``
  Host Identifier

``NVME_FEAT_FID_RESV_NF_MASK``
  Reservation Notification Mask

``NVME_FEAT_FID_RESV_PERSIST``
  Reservation Persistence

``NVME_FEAT_FID_WRITE_PROTECT``
  Namespace Write Protection Config

``NVME_FEAT_FID_BP_WRITE_PROTECT``
  Boot Partition Write Protection Config




.. c:enum:: nvme_feat

   Features Access Shifts/Masks values

**Constants**

``NVME_FEAT_ARBITRATION_BURST_SHIFT``

``NVME_FEAT_ARBITRATION_BURST_MASK``

``NVME_FEAT_ARBITRATION_LPW_SHIFT``

``NVME_FEAT_ARBITRATION_LPW_MASK``

``NVME_FEAT_ARBITRATION_MPW_SHIFT``

``NVME_FEAT_ARBITRATION_MPW_MASK``

``NVME_FEAT_ARBITRATION_HPW_SHIFT``

``NVME_FEAT_ARBITRATION_HPW_MASK``

``NVME_FEAT_PWRMGMT_PS_SHIFT``

``NVME_FEAT_PWRMGMT_PS_MASK``

``NVME_FEAT_PWRMGMT_WH_SHIFT``

``NVME_FEAT_PWRMGMT_WH_MASK``

``NVME_FEAT_PWRMGMT_IIELL_SHIFT``
  Shift amount to set/get the Idle I/O Exit
  Latency Limit (IIELL), in units of 100
  microseconds

``NVME_FEAT_PWRMGMT_IIELL_MASK``
  Mask to set/get IIELL

``NVME_FEAT_LBAR_NR_SHIFT``

``NVME_FEAT_LBAR_NR_MASK``

``NVME_FEAT_TT_TMPTH_SHIFT``

``NVME_FEAT_TT_TMPTH_MASK``

``NVME_FEAT_TT_TMPSEL_SHIFT``

``NVME_FEAT_TT_TMPSEL_MASK``

``NVME_FEAT_TT_THSEL_SHIFT``

``NVME_FEAT_TT_THSEL_MASK``

``NVME_FEAT_TT_TMPTHH_SHIFT``

``NVME_FEAT_TT_TMPTHH_MASK``

``NVME_FEAT_ERROR_RECOVERY_TLER_SHIFT``

``NVME_FEAT_ERROR_RECOVERY_TLER_MASK``

``NVME_FEAT_ERROR_RECOVERY_DULBE_SHIFT``

``NVME_FEAT_ERROR_RECOVERY_DULBE_MASK``

``NVME_FEAT_VWC_WCE_SHIFT``

``NVME_FEAT_VWC_WCE_MASK``

``NVME_FEAT_NRQS_NSQR_SHIFT``

``NVME_FEAT_NRQS_NSQR_MASK``

``NVME_FEAT_NRQS_NCQR_SHIFT``

``NVME_FEAT_NRQS_NCQR_MASK``

``NVME_FEAT_IRQC_THR_SHIFT``

``NVME_FEAT_IRQC_THR_MASK``

``NVME_FEAT_IRQC_TIME_SHIFT``

``NVME_FEAT_IRQC_TIME_MASK``

``NVME_FEAT_ICFG_IV_SHIFT``

``NVME_FEAT_ICFG_IV_MASK``

``NVME_FEAT_ICFG_CD_SHIFT``

``NVME_FEAT_ICFG_CD_MASK``

``NVME_FEAT_WA_DN_SHIFT``

``NVME_FEAT_WA_DN_MASK``

``NVME_FEAT_AE_SMART_SHIFT``

``NVME_FEAT_AE_SMART_MASK``

``NVME_FEAT_AE_NAN_SHIFT``

``NVME_FEAT_AE_NAN_MASK``

``NVME_FEAT_AE_FW_SHIFT``

``NVME_FEAT_AE_FW_MASK``

``NVME_FEAT_AE_TELEM_SHIFT``

``NVME_FEAT_AE_TELEM_MASK``

``NVME_FEAT_AE_ANA_SHIFT``

``NVME_FEAT_AE_ANA_MASK``

``NVME_FEAT_AE_PLA_SHIFT``

``NVME_FEAT_AE_PLA_MASK``

``NVME_FEAT_AE_LBAS_SHIFT``

``NVME_FEAT_AE_LBAS_MASK``

``NVME_FEAT_AE_EGA_SHIFT``

``NVME_FEAT_AE_EGA_MASK``

``NVME_FEAT_AE_NNSSHDN_SHIFT``

``NVME_FEAT_AE_NNSSHDN_MASK``

``NVME_FEAT_AE_TTHRY_SHIFT``

``NVME_FEAT_AE_TTHRY_MASK``

``NVME_FEAT_AE_RASSN_SHIFT``

``NVME_FEAT_AE_RASSN_MASK``

``NVME_FEAT_AE_RGRP0_SHIFT``

``NVME_FEAT_AE_RGRP0_MASK``

``NVME_FEAT_AE_ANSAN_SHIFT``

``NVME_FEAT_AE_ANSAN_MASK``

``NVME_FEAT_AE_CCRCN_SHIFT``

``NVME_FEAT_AE_CCRCN_MASK``

``NVME_FEAT_AE_LHCN_SHIFT``

``NVME_FEAT_AE_LHCN_MASK``

``NVME_FEAT_AE_RLCCN_SHIFT``
  Shift amount to get/set the Rate Limiting
  Configuration Change Notices (RLCCN)

``NVME_FEAT_AE_RLCCN_MASK``
  Mask to get/set RLCCN

``NVME_FEAT_AE_ZDCN_SHIFT``

``NVME_FEAT_AE_ZDCN_MASK``

``NVME_FEAT_AE_PMDRLPCN_SHIFT``

``NVME_FEAT_AE_PMDRLPCN_MASK``

``NVME_FEAT_AE_ADLPCN_SHIFT``

``NVME_FEAT_AE_ADLPCN_MASK``

``NVME_FEAT_AE_HDLPCN_SHIFT``

``NVME_FEAT_AE_HDLPCN_MASK``

``NVME_FEAT_AE_DLPCN_SHIFT``

``NVME_FEAT_AE_DLPCN_MASK``

``NVME_FEAT_APST_APSTE_SHIFT``

``NVME_FEAT_APST_APSTE_MASK``

``NVME_FEAT_HMEM_EHM_SHIFT``

``NVME_FEAT_HMEM_EHM_MASK``

``NVME_FEAT_KATO_TIMEOUT_SHIFT``

``NVME_FEAT_KATO_TIMEOUT_MASK``

``NVME_FEAT_HCTM_TMT2_SHIFT``

``NVME_FEAT_HCTM_TMT2_MASK``

``NVME_FEAT_HCTM_TMT1_SHIFT``

``NVME_FEAT_HCTM_TMT1_MASK``

``NVME_FEAT_NOPS_NOPPME_SHIFT``

``NVME_FEAT_NOPS_NOPPME_MASK``

``NVME_FEAT_RRL_NVMSETID_SHIFT``

``NVME_FEAT_RRL_NVMSETID_MASK``

``NVME_FEAT_RRL_RRL_SHIFT``

``NVME_FEAT_RRL_RRL_MASK``

``NVME_FEAT_PLM_NVMSETID_SHIFT``

``NVME_FEAT_PLM_NVMSETID_MASK``

``NVME_FEAT_PLM_LPE_SHIFT``

``NVME_FEAT_PLM_LPE_MASK``

``NVME_FEAT_PLMW_WS_SHIFT``

``NVME_FEAT_PLMW_WS_MASK``

``NVME_FEAT_LBAS_LSIRI_SHIFT``

``NVME_FEAT_LBAS_LSIRI_MASK``

``NVME_FEAT_LBAS_LSIPI_SHIFT``

``NVME_FEAT_LBAS_LSIPI_MASK``

``NVME_FEAT_SC_NODRM_SHIFT``

``NVME_FEAT_SC_NODRM_MASK``

``NVME_FEAT_EG_ENDGID_SHIFT``

``NVME_FEAT_EG_ENDGID_MASK``

``NVME_FEAT_EG_EGCW_SHIFT``

``NVME_FEAT_EG_EGCW_MASK``

``NVME_FEAT_FDPE_PHNDL_SHIFT``

``NVME_FEAT_FDPE_PHNDL_MASK``

``NVME_FEAT_FDPE_NOET_SHIFT``

``NVME_FEAT_FDPE_NOET_MASK``

``NVME_FEAT_SPM_PBSLC_SHIFT``

``NVME_FEAT_SPM_PBSLC_MASK``

``NVME_FEAT_HOSTID_EXHID_SHIFT``

``NVME_FEAT_HOSTID_EXHID_MASK``

``NVME_FEAT_RM_REGPRE_SHIFT``

``NVME_FEAT_RM_REGPRE_MASK``

``NVME_FEAT_RM_RESREL_SHIFT``

``NVME_FEAT_RM_RESREL_MASK``

``NVME_FEAT_RM_RESPRE_SHIFT``

``NVME_FEAT_RM_RESPRE_MASK``

``NVME_FEAT_RP_PTPL_SHIFT``

``NVME_FEAT_RP_PTPL_MASK``

``NVME_FEAT_WP_WPS_SHIFT``

``NVME_FEAT_WP_WPS_MASK``

``NVME_FEAT_IOCSP_IOCSCI_SHIFT``

``NVME_FEAT_IOCSP_IOCSCI_MASK``

``NVME_FEAT_SPINUP_CONTROL_SHIFT``

``NVME_FEAT_SPINUP_CONTROL_MASK``

``NVME_FEAT_PLS_MODE_SHIFT``

``NVME_FEAT_PLS_MODE_MASK``

``NVME_FEAT_PERFC_ATTRI_SHIFT``

``NVME_FEAT_PERFC_ATTRI_MASK``

``NVME_FEAT_PERFC_RVSPA_SHIFT``

``NVME_FEAT_PERFC_RVSPA_MASK``

``NVME_FEAT_PERFC_ATTRTYP_SHIFT``

``NVME_FEAT_PERFC_ATTRTYP_MASK``

``NVME_FEAT_FDP_ENABLED_SHIFT``

``NVME_FEAT_FDP_ENABLED_MASK``

``NVME_FEAT_FDP_INDEX_SHIFT``

``NVME_FEAT_FDP_INDEX_MASK``

``NVME_FEAT_FDP_EVENTS_ENABLE_SHIFT``

``NVME_FEAT_FDP_EVENTS_ENABLE_MASK``

``NVME_FEAT_HOST_ID_EXHID_SHIFT``

``NVME_FEAT_HOST_ID_EXHID_MASK``

``NVME_FEAT_BPWPC_BP0WPS_SHIFT``

``NVME_FEAT_BPWPC_BP0WPS_MASK``

``NVME_FEAT_BPWPC_BP1WPS_SHIFT``

``NVME_FEAT_BPWPC_BP1WPS_MASK``

``NVME_FEAT_SANITIZE_NODRM_SHIFT``

``NVME_FEAT_SANITIZE_NODRM_MASK``

``NVME_FEAT_RESP_PTPL_SHIFT``

``NVME_FEAT_RESP_PTPL_MASK``

``NVME_FEAT_CDP_CHPS``
  Change Personality Settings (Set Features
  Command Dword 13 only)

``NVME_FEAT_CDP_PERFS``
  Personality Freeze State (Set Features
  Command Dword 13, and Get Features Completion
  Queue Entry Dword 0)

``NVME_FEAT_CDP_PERID_SHIFT``
  Shift amount to set/get the Personality
  Identifier (Set Features Command Dword 13, and
  Get Features Completion Queue Entry Dword 0)

``NVME_FEAT_CDP_PERID_MASK``
  Mask to set/get the Personality Identifier

``NVME_FEAT_CDP_PMDSS``
  Personality Manufacturing Default Settings
  State (Get Features Completion Queue Entry
  Dword 0 only)

``NVME_FEAT_CDP_PPSC``
  Pending Personality Settings Change (Get
  Features Completion Queue Entry Dword 0 only)

``NVME_FEAT_POWER_LIMIT_PLV_SHIFT``

``NVME_FEAT_POWER_LIMIT_PLV_MASK``

``NVME_FEAT_POWER_LIMIT_PLS_SHIFT``

``NVME_FEAT_POWER_LIMIT_PLS_MASK``

``NVME_FEAT_POWER_THRESH_PTV_SHIFT``

``NVME_FEAT_POWER_THRESH_PTV_MASK``

``NVME_FEAT_POWER_THRESH_PTS_SHIFT``

``NVME_FEAT_POWER_THRESH_PTS_MASK``

``NVME_FEAT_POWER_THRESH_PMTS_SHIFT``

``NVME_FEAT_POWER_THRESH_PMTS_MASK``

``NVME_FEAT_POWER_THRESH_EPT_SHIFT``

``NVME_FEAT_POWER_THRESH_EPT_MASK``

``NVME_FEAT_POWER_MEAS_ACT_SHIFT``

``NVME_FEAT_POWER_MEAS_ACT_MASK``

``NVME_FEAT_POWER_MEAS_PMTS_SHIFT``

``NVME_FEAT_POWER_MEAS_PMTS_MASK``

``NVME_FEAT_POWER_MEAS_SMT_SHIFT``

``NVME_FEAT_POWER_MEAS_SMT_MASK``

``NVME_FEAT_VOLTAGE_THRESHOLD_UVT_SHIFT``
  Shift amount to set/get the
  Undervoltage Threshold (UVT)

``NVME_FEAT_VOLTAGE_THRESHOLD_UVT_MASK``
  Mask to set/get UVT

``NVME_FEAT_VOLTAGE_THRESHOLD_OVT_SHIFT``
  Shift amount to set/get the
  Overvoltage Threshold (OVT)

``NVME_FEAT_VOLTAGE_THRESHOLD_OVT_MASK``
  Mask to set/get OVT

``NVME_FEAT_VOLTAGE_THRESHOLD_EVT``
  Enable Voltage Threshold

``NVME_FEAT_VOLTAGE_THRESHOLD_VSENS_SHIFT``
  Shift amount to set/get the
  Voltage Sensor Select (VSENS),
  see :c:type:`enum nvme_voltage_sensor <nvme_voltage_sensor>`

``NVME_FEAT_VOLTAGE_THRESHOLD_VSENS_MASK``
  Mask to set/get VSENS

``NVME_FEAT_VOLTAGE_MEASUREMENT_ACT_SHIFT``
  Shift amount to set the
  Action (ACT), see :c:type:`enum
  nvme_voltage_measurement_act <nvme_voltage_measurement_act>`

``NVME_FEAT_VOLTAGE_MEASUREMENT_ACT_MASK``
  Mask to set ACT

``NVME_FEAT_RATE_LIMITING_TID_SHIFT``
  Shift amount to set/get the Target
  Identifier (TID)

``NVME_FEAT_RATE_LIMITING_TID_MASK``
  Mask to set/get TID

``NVME_FEAT_RATE_LIMITING_TGT_SHIFT``
  Shift amount to set/get the Target
  (TGT), see :c:type:`enum nvme_rate_limiting_target <nvme_rate_limiting_target>`

``NVME_FEAT_RATE_LIMITING_TGT_MASK``
  Mask to set/get TGT




.. c:enum:: nvme_get_features_sel

   Get Features - Select

**Constants**

``NVME_GET_FEATURES_SEL_CURRENT``
  Current value

``NVME_GET_FEATURES_SEL_DEFAULT``
  Default value

``NVME_GET_FEATURES_SEL_SAVED``
  Saved value

``NVME_GET_FEATURES_SEL_SUPPORTED``
  Supported capabilities




.. c:enum:: nvme_get_features_supported_cqe_dw0

   Get Features Completion Queue Entry Dword 0 when the Select field is set to ``NVME_GET_FEATURES_SEL_SUPPORTED``

**Constants**

``NVME_GET_FEATURES_SUPPORTED_SVBL``
  Saveable: the feature values are
  saveable if set to '1'.

``NVME_GET_FEATURES_SUPPORTED_NSSPEC``
  NS Specific: the Feature Identifier
  has a namespace scope if set to '1'.

``NVME_GET_FEATURES_SUPPORTED_CHANG``
  Changeable: the feature values are
  changeable if set to '1'.




.. c:enum:: nvme_cmd_format_mset

   Format NVM - Metadata Settings

**Constants**

``NVME_FORMAT_MSET_SEPARATE``
  indicates that the metadata is transferred
  as part of a separate buffer.

``NVME_FORMAT_MSET_EXTENDED``
  indicates that the metadata is transferred
  as part of an extended data LBA.




.. c:enum:: nvme_cmd_format_pi

   Format NVM - Protection Information

**Constants**

``NVME_FORMAT_PI_DISABLE``
  Protection information is not enabled.

``NVME_FORMAT_PI_TYPE1``
  Protection information is enabled, Type 1.

``NVME_FORMAT_PI_TYPE2``
  Protection information is enabled, Type 2.

``NVME_FORMAT_PI_TYPE3``
  Protection information is enabled, Type 3.




.. c:enum:: nvme_cmd_format_pil

   Format NVM - Protection Information Location

**Constants**

``NVME_FORMAT_PIL_LAST``
  Protection information is transferred as the last
  bytes of metadata.

``NVME_FORMAT_PIL_FIRST``
  Protection information is transferred as the first
  bytes of metadata.




.. c:enum:: nvme_cmd_format_ses

   Format NVM - Secure Erase Settings

**Constants**

``NVME_FORMAT_SES_NONE``
  No secure erase operation requested.

``NVME_FORMAT_SES_USER_DATA_ERASE``
  User Data Erase: All user data shall be erased,
  contents of the user data after the erase is
  indeterminate (e.g. the user data may be zero
  filled, one filled, etc.). If a User Data Erase
  is requested and all affected user data is
  encrypted, then the controller is allowed
  to use a cryptographic erase to perform
  the requested User Data Erase.

``NVME_FORMAT_SES_CRYPTO_ERASE``
  Cryptographic Erase: All user data shall
  be erased cryptographically. This is
  accomplished by deleting the encryption key.




.. c:enum:: nvme_ns_mgmt_sel

   Namespace Management - Select

**Constants**

``NVME_NS_MGMT_SEL_CREATE``
  Namespace Create selection

``NVME_NS_MGMT_SEL_DELETE``
  Namespace Delete selection

``NVME_NS_MGMT_SEL_RESTORE_DEFAULT_CONFIG``
  Restore Default Namespace
  Configuration selection




.. c:enum:: nvme_ns_attach_sel

   Namespace Attachment - Select

**Constants**

``NVME_NS_ATTACH_SEL_CTRL_ATTACH``
  Namespace attach selection

``NVME_NS_ATTACH_SEL_CTRL_DEATTACH``
  Namespace detach selection




.. c:enum:: nvme_fw_commit_ca

   Firmware Commit - Commit Action

**Constants**

``NVME_FW_COMMIT_CA_REPLACE``
  Downloaded image replaces the existing
  image, if any, in the specified Firmware
  Slot. The newly placed image is not
  activated.

``NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE``
  Downloaded image replaces the existing
  image, if any, in the specified Firmware
  Slot. The newly placed image is activated
  at the next Controller Level Reset.

``NVME_FW_COMMIT_CA_SET_ACTIVE``
  The existing image in the specified
  Firmware Slot is activated at the
  next Controller Level Reset.

``NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE_IMMEDIATE``
  Downloaded image replaces the existing
  image, if any, in the specified Firmware
  Slot and is then activated immediately.
  If there is not a newly downloaded image,
  then the existing image in the specified
  firmware slot is activated immediately.

``NVME_FW_COMMIT_CA_REPLACE_BOOT_PARTITION``
  Downloaded image replaces the Boot
  Partition specified by the Boot
  Partition ID field.

``NVME_FW_COMMIT_CA_ACTIVATE_BOOT_PARTITION``
  Mark the Boot Partition specified in
  the BPID field as active and update
  BPINFO.ABPID.




.. c:enum:: nvme_directive_dtype

   Directive Types

**Constants**

``NVME_DIRECTIVE_DTYPE_IDENTIFY``
  Identify directive type

``NVME_DIRECTIVE_DTYPE_STREAMS``
  Streams directive type




.. c:enum:: nvme_directive_receive_doper

   Directive Receive Directive Operation

**Constants**

``NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM``

``NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM``

``NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS``

``NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE``




.. c:enum:: nvme_directive_send_doper

   Directive Send Directive Operation

**Constants**

``NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR``

``NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER``

``NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE``




.. c:enum:: nvme_directive_send_identify_endir

   Enable Directive

**Constants**

``NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_DISABLE``

``NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_ENABLE``




.. c:enum:: nvme_sanitize_sanact

   Sanitize Action

**Constants**

``NVME_SANITIZE_SANACT_EXIT_FAILURE``
  Exit Failure Mode.

``NVME_SANITIZE_SANACT_START_BLOCK_ERASE``
  Start a Block Erase sanitize operation.

``NVME_SANITIZE_SANACT_START_OVERWRITE``
  Start an Overwrite sanitize operation.

``NVME_SANITIZE_SANACT_START_CRYPTO_ERASE``
  Start a Crypto Erase sanitize operation.

``NVME_SANITIZE_SANACT_EXIT_MEDIA_VERIF``
  Exit Media Verification State




.. c:enum:: nvme_dst_stc

   Action taken by the Device Self-test command

**Constants**

``NVME_DST_STC_SHORT``
  Start a short device self-test operation

``NVME_DST_STC_LONG``
  Start an extended device self-test operation

``NVME_DST_STC_HOST_INIT``
  Start a Host-Initiated Refresh operation

``NVME_DST_STC_VS``
  Start a vendor specific device self-test operation

``NVME_DST_STC_ABORT``
  Abort device self-test operation




.. c:enum:: nvme_virt_mgmt_act

   Virtualization Management - Action

**Constants**

``NVME_VIRT_MGMT_ACT_PRIM_CTRL_FLEX_ALLOC``
  Primary Controller Flexible
  Allocation

``NVME_VIRT_MGMT_ACT_OFFLINE_SEC_CTRL``
  Secondary Controller Offline

``NVME_VIRT_MGMT_ACT_ASSIGN_SEC_CTRL``
  Secondary Controller Assign

``NVME_VIRT_MGMT_ACT_ONLINE_SEC_CTRL``
  Secondary Controller Online




.. c:enum:: nvme_capacity_mgmt_oper

   Capacity Management - Operation (OPER)

**Constants**

``NVME_CAPACITY_MGMT_OPER_RESTORE_DEFAULT_CONFIG``
  Restore Default
  Capacity Management Configuration: restores the default
  Endurance Groups and NVM Sets configuration in the NVM
  subsystem. The Element Identifier field should be set to
  0h and shall be ignored by the controller.




.. c:enum:: nvme_virt_mgmt_rt

   Virtualization Management - Resource Type

**Constants**

``NVME_VIRT_MGMT_RT_VQ_RESOURCE``
  VQ Resources

``NVME_VIRT_MGMT_RT_VI_RESOURCE``
  VI Resources




.. c:enum:: nvme_ns_write_protect_cfg

   Write Protection - Write Protection State

**Constants**

``NVME_NS_WP_CFG_NONE``
  No Write Protect

``NVME_NS_WP_CFG_PROTECT``
  Write Protect

``NVME_NS_WP_CFG_PROTECT_POWER_CYCLE``
  Write Protect Until Power Cycle

``NVME_NS_WP_CFG_PROTECT_PERMANENT``
  Permanent Write Protect




.. c:enum:: nvme_log_ana_lsp

   Asymmetric Namespace Access - Return Groups Only

**Constants**

``NVME_LOG_ANA_LSP_RGO_NAMESPACES``

``NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY``




.. c:enum:: nvme_log_phy_rx_eom_action

   Physical Interface Receiver Eye Opening Measurement Action

**Constants**

``NVME_LOG_PHY_RX_EOM_READ``
  Read Log Data

``NVME_LOG_PHY_RX_EOM_START_READ``
  Start Measurement and Read Log Data

``NVME_LOG_PHY_RX_EOM_ABORT_CLEAR``
  Abort Measurement and Clear Log Data




.. c:enum:: nvme_log_phy_rx_eom_quality

   Physical Interface Receiver Eye Opening Measurement Quality

**Constants**

``NVME_LOG_PHY_RX_EOM_GOOD``
  <= Better Quality

``NVME_LOG_PHY_RX_EOM_BETTER``
  <= Best Quality, >= Good Quality

``NVME_LOG_PHY_RX_EOM_BEST``
  >= Better Quality




.. c:enum:: nvme_pevent_log_action

   Persistent Event Log - Action

**Constants**

``NVME_PEVENT_LOG_READ``
  Read Log Data

``NVME_PEVENT_LOG_EST_CTX_AND_READ``
  Establish Context and Read Log Data

``NVME_PEVENT_LOG_RELEASE_CTX``
  Release Context




.. c:enum:: nvme_feat_tmpthresh_thsel

   Temperature Threshold - Threshold Type Select

**Constants**

``NVME_FEATURE_TEMPTHRESH_THSEL_OVER``
  Over temperature threshold select

``NVME_FEATURE_TEMPTHRESH_THSEL_UNDER``
  Under temperature threshold select




.. c:enum:: nvme_features_async_event_config_flags

   Asynchronous Event Configuration configuration flags

**Constants**

``NVME_FEATURE_AENCFG_SMART_CRIT_SPARE``

``NVME_FEATURE_AENCFG_SMART_CRIT_TEMPERATURE``

``NVME_FEATURE_AENCFG_SMART_CRIT_DEGRADED``

``NVME_FEATURE_AENCFG_SMART_CRIT_READ_ONLY``

``NVME_FEATURE_AENCFG_SMART_CRIT_VOLATILE_BACKUP``

``NVME_FEATURE_AENCFG_SMART_CRIT_READ_ONLY_PMR``

``NVME_FEATURE_AENCFG_NOTICE_NAMESPACE_ATTRIBUTES``

``NVME_FEATURE_AENCFG_NOTICE_FIRMWARE_ACTIVATION``

``NVME_FEATURE_AENCFG_NOTICE_TELEMETRY_LOG``

``NVME_FEATURE_AENCFG_NOTICE_ANA_CHANGE``

``NVME_FEATURE_AENCFG_NOTICE_PL_EVENT``

``NVME_FEATURE_AENCFG_NOTICE_LBA_STATUS``

``NVME_FEATURE_AENCFG_NOTICE_EG_EVENT``

``NVME_FEATURE_AENCFG_NOTICE_DISCOVERY_CHANGE``




.. c:enum:: nvme_feat_plm_window_select

   Predictable Latency Per NVM Set Log

**Constants**

``NVME_FEATURE_PLM_DTWIN``
  Deterministic Window select

``NVME_FEATURE_PLM_NDWIN``
  Non-Deterministic Window select




.. c:enum:: nvme_feat_nswpcfg_state

   Write Protection - Write Protection State

**Constants**

``NVME_FEAT_NS_NO_WRITE_PROTECT``
  No Write Protect

``NVME_FEAT_NS_WRITE_PROTECT``
  Write Protect

``NVME_FEAT_NS_WRITE_PROTECT_PWR_CYCLE``
  Write Protect Until Power Cycle

``NVME_FEAT_NS_WRITE_PROTECT_PERMANENT``
  Permanent Write Protect




.. c:enum:: nvme_feat_perfc_attri

   performance characteristics attribute index

**Constants**

``NVME_FEAT_PERFC_ATTRI_STD``
  standard performance attribute

``NVME_FEAT_PERFC_ATTRI_ID_LIST``
  performance attribute identifier list

``NVME_FEAT_PERFC_ATTRI_VS_MIN``
  vendor specific performance attribute minimum index

``NVME_FEAT_PERFC_ATTRI_VS_MAX``
  vendor specific performance attribute maximum index




.. c:enum:: nvme_feat_perfc_r4karl

   standard performance attribute random 4 kib average latency

**Constants**

``NVME_FEAT_PERFC_R4KARL_NO_REPORT``
  not reported

``NVME_FEAT_PERFC_R4KARL_GE_100_SEC``
  greater than or equal to 100 secs

``NVME_FEAT_PERFC_R4KARL_GE_50_SEC``
  greater than or equal to 50 secs and less than 100 secs

``NVME_FEAT_PERFC_R4KARL_GE_10_SEC``
  greater than or equal to 10 secs and less than 50 secs

``NVME_FEAT_PERFC_R4KARL_GE_5_SEC``
  greater than or equal to 5 secs and less than 10 secs

``NVME_FEAT_PERFC_R4KARL_GE_1_SEC``
  greater than or equal to 1 sec and less than 5 secs

``NVME_FEAT_PERFC_R4KARL_GE_500_MS``
  greater than or equal to 500 msecs and less than 1 sec

``NVME_FEAT_PERFC_R4KARL_GE_100_MS``
  greater than or equal to 100 msecs and less than 500 msecs

``NVME_FEAT_PERFC_R4KARL_GE_50_MS``
  greater than or equal to 50 msecs and less than 100 msecs

``NVME_FEAT_PERFC_R4KARL_GE_10_MS``
  greater than or equal to 10 msecs and less than 50 msecs

``NVME_FEAT_PERFC_R4KARL_GE_5_MS``
  greater than or equal to 5 msecs and less than 10 msecs

``NVME_FEAT_PERFC_R4KARL_GE_1_MS``
  greater than or equal to 1 msec and less than 5 msecs

``NVME_FEAT_PERFC_R4KARL_GE_500_US``
  greater than or equal to 500 usecs and less than 1 msec

``NVME_FEAT_PERFC_R4KARL_GE_100_US``
  greater than or equal to 100 usecs and less than 500 usecs

``NVME_FEAT_PERFC_R4KARL_GE_50_US``
  greater than or equal to 50 usecs and less than 100 usecs

``NVME_FEAT_PERFC_R4KARL_GE_10_US``
  greater than or equal to 10 usecs and less than 50 usecs

``NVME_FEAT_PERFC_R4KARL_GE_5_US``
  greater than or equal to 5 usecs and less than 10 usecs

``NVME_FEAT_PERFC_R4KARL_GE_1_US``
  greater than or equal to 1 usec and less than 5 usecs

``NVME_FEAT_PERFC_R4KARL_GE_500_NS``
  greater than or equal to 500 nsecs and less than 1 usec

``NVME_FEAT_PERFC_R4KARL_GE_100_NS``
  greater than or equal to 100 nsecs and less than 500 nsecs

``NVME_FEAT_PERFC_R4KARL_GE_50_NS``
  greater than or equal to 50 nsecs and less than 100 nsecs

``NVME_FEAT_PERFC_R4KARL_GE_10_NS``
  greater than or equal to 10 nsecs and less than 50 nsecs

``NVME_FEAT_PERFC_R4KARL_GE_5_NS``
  greater than or equal to 5 nsecs and less than 10 nsecs

``NVME_FEAT_PERFC_R4KARL_GE_1_NS``
  greater than or equal to 1 nsec and less than 5 nsecs




.. c:enum:: nvme_feat_bpwp_state

   Boot Partition Write Protection State

**Constants**

``NVME_FEAT_BPWPS_CHANGE_NOT_REQUESTED``
  Change in state not requested

``NVME_FEAT_BPWPS_WRITE_UNLOCKED``
  Write Unlocked

``NVME_FEAT_BPWPS_WRITE_LOCKED``
  Write Locked

``NVME_FEAT_BPWPS_WRITE_LOCKED_PWR_CYCLE``
  Write Locked Until Power Cycle

``NVME_FEAT_BPWPS_WRITE_PROTECTION_RPMB``
  Write Protection controlled by RPMB




.. c:enum:: nvme_fctype

   Fabrics Command Types

**Constants**

``nvme_fabrics_type_property_set``
  Property set

``nvme_fabrics_type_connect``
  Connect

``nvme_fabrics_type_property_get``
  Property Get

``nvme_fabrics_type_auth_send``
  Authentication Send

``nvme_fabrics_type_auth_receive``
  Authentication Receive

``nvme_fabrics_type_disconnect``
  Disconnect




.. c:enum:: nvme_data_tfr

   Data transfer direction of the command

**Constants**

``NVME_DATA_TFR_NO_DATA_TFR``
  No data transfer

``NVME_DATA_TFR_HOST_TO_CTRL``
  Host to controller

``NVME_DATA_TFR_CTRL_TO_HOST``
  Controller to host

``NVME_DATA_TFR_BIDIRECTIONAL``
  Bidirectional




.. c:enum:: nvme_io_opcode

   Opcodes for I/O Commands

**Constants**

``nvme_cmd_flush``
  Flush

``nvme_cmd_write``
  Write

``nvme_cmd_read``
  Read

``nvme_cmd_write_uncor``
  Write Uncorrectable

``nvme_cmd_compare``
  Compare

``nvme_cmd_write_zeroes``
  write Zeros

``nvme_cmd_dsm``
  Dataset Management

``nvme_cmd_verify``
  Verify

``nvme_cmd_resv_register``
  Reservation Register

``nvme_cmd_resv_report``
  Reservation Report

``nvme_cmd_resv_acquire``
  Reservation Acquire

``nvme_cmd_io_mgmt_recv``
  I/O Management Receive

``nvme_cmd_resv_release``
  Reservation Release

``nvme_cmd_cancel``
  Cancel

``nvme_cmd_copy``
  Copy

``nvme_cmd_io_mgmt_send``
  I/O Management Send

``nvme_zns_cmd_mgmt_send``
  Zone Management Send

``nvme_zns_cmd_mgmt_recv``
  Zone Management Receive

``nvme_zns_cmd_append``
  Zone Append

``nvme_cmd_fabric``
  Fabric Commands




.. c:enum:: nvme_kv_opcode

   Opcodes for KV Commands

**Constants**

``nvme_kv_cmd_flush``
  Flush

``nvme_kv_cmd_store``
  Store

``nvme_kv_cmd_retrieve``
  Retrieve

``nvme_kv_cmd_list``
  List

``nvme_kv_cmd_resv_register``
  Reservation Register

``nvme_kv_cmd_resv_report``
  Reservation Report

``nvme_kv_cmd_delete``
  Delete

``nvme_kv_cmd_resv_acquire``
  Reservation Acquire

``nvme_kv_cmd_exist``
  Exist

``nvme_kv_cmd_resv_release``
  Reservation Release




.. c:enum:: nvme_ns_mgmt_zns_znsco

   Zoned Namespace Create Options, see :c:type:`struct nvme_ns_mgmt_host_sw_specified <nvme_ns_mgmt_host_sw_specified>`.zns.znsco

**Constants**

``NVME_NS_MGMT_ZNSCO_AZR``
  Allocate ZRWA Resources (AZR)




.. c:struct:: nvme_ns_mgmt_host_sw_specified

   Namespace management Host Software Specified Fields.

**Definition**

::

  struct nvme_ns_mgmt_host_sw_specified {
    __le64 nsze;
    __le64 ncap;
    __u8 rsvd16[10];
    __u8 flbas;
    __u8 rsvd27[2];
    __u8 dps;
    __u8 nmic;
    __u8 rsvd31[61];
    __le32 anagrpid;
    __u8 rsvd96[4];
    __le16 nvmsetid;
    __le16 endgid;
    __u8 rsvd104[280];
    __le64 lbstm;
    __le16 nphndls;
    __u8 rsvd394[105];
    union {
      __u8 rsvd499[13];
      struct {
        __u8 znsco;
        __le32 rar;
        __le32 ror;
        __le32 rnumzrwa;
      } zns;
    };
    __le16 phndl[128];
    __u8 rsvd768[3328];
  };

**Members**

``nsze``
  Namespace Size indicates the total size of the namespace in
  logical blocks. The number of logical blocks is based on the
  formatted LBA size.

``ncap``
  Namespace Capacity indicates the maximum number of logical blocks
  that may be allocated in the namespace at any point in time. The
  number of logical blocks is based on the formatted LBA size.

``rsvd16``
  Reserved

``flbas``
  Formatted LBA Size, see :c:type:`enum nvme_id_ns_flbas <nvme_id_ns_flbas>`.

``rsvd27``
  Reserved

``dps``
  End-to-end Data Protection Type Settings, see
  :c:type:`enum nvme_id_ns_dps <nvme_id_ns_dps>`.

``nmic``
  Namespace Multi-path I/O and Namespace Sharing Capabilities, see
  :c:type:`enum nvme_id_ns_nmic <nvme_id_ns_nmic>`.

``rsvd31``
  Reserved

``anagrpid``
  ANA Group Identifier indicates the ANA Group Identifier of the
  ANA group of which the namespace is a member.

``rsvd96``
  Reserved

``nvmsetid``
  NVM Set Identifier indicates the NVM Set with which this
  namespace is associated.

``endgid``
  Endurance Group Identifier indicates the Endurance Group with
  which this namespace is associated.

``rsvd104``
  Reserved

``lbstm``
  Logical Block Storage Tag Mask Identifies the mask for the
  Storage Tag field for the protection information

``nphndls``
  Number of Placement Handles specifies the number of Placement
  Handles included in the Placement Handle List

``rsvd394``
  Reserved

``{unnamed_union}``
  anonymous

``rsvd499``
  Reserved for I/O Command Sets that extend this specification.

``zns``
  rsvd499( Zoned Namespace Command Set specific field )

``phndl``
  Placement Handle Associated RUH : This field specifies the Reclaim
  Unit Handle Identifier to be associated with the Placement Handle
  value. If the Flexible Data Placement capability is not supported or
  not enabled in specified Endurance Group, then the controller shall
  ignore this field.

``rsvd768``
  Reserved





.. c:enum:: nvme_lm_cdq_fields

   Controller Data Queue command fields

**Constants**

``NVME_LM_CDQ_MOS_SHIFT``
  Shift to set Management Operation Specific (MOS) field

``NVME_LM_CDQ_MOS_MASK``
  Mask to set MOS field

``NVME_LM_CDQ_SEL_SHIFT``
  Shift to set Select (SEL) field

``NVME_LM_CDQ_SEL_MASK``
  Mask to set SEL field

``NVME_LM_SEL_CREATE_CDQ``
  Create CDQ select option

``NVME_LM_SEL_DELETE_CDQ``
  Delete CDQ select option

``NVME_LM_QT_SHIFT``
  Shift amount to set Queue Type (QT) field relative to MOS

``NVME_LM_QT_MASK``
  Mask to set QT field relative to MOS

``NVME_LM_CQS_SHIFT``
  Shift amount for Create Queue Specific (CQS) field

``NVME_LM_CQS_MASK``
  Mask to set CQS field

``NVME_LM_QT_USER_DATA_MIGRATION_QUEUE``
  User Data Migration Queue type

``NVME_LM_CREATE_CDQ_PC``
  Physically Contiguous (PC)

``NVME_LM_CREATE_CDQ_PC_SHIFT``
  Shift amount to set the PC field

``NVME_LM_CREATE_CDQ_PC_MASK``
  Mask to set PC field

``NVME_LM_CREATE_CDQ_CNTLID_SHIFT``
  Shift amount to set CNTLID field relative to MOS

``NVME_LM_CREATE_CDQ_CNTLID_MASK``
  Mask to set CNTLID field relative to MOS

``NVME_LM_DELETE_CDQ_CDQID_SHIFT``
  Shift amount to set CDQID field for deletion

``NVME_LM_DELETE_CDQ_CDQID_MASK``
  Mask to set CDQID field for deletion

``NVME_LM_CREATE_CDQ_CDQID_SHIFT``
  Shift amount to get CDQID field from Create response in
  completion dword0

``NVME_LM_CREATE_CDQ_CDQID_MASK``
  Mask to get CNTLID field from Create response in
  completion dword0




.. c:enum:: nvme_lm_track_send_fields

   Track Send command fields

**Constants**

``NVME_LM_TRACK_SEND_MOS_SHIFT``
  Shift to set Management Operation Specific (MOS) field

``NVME_LM_TRACK_SEND_MOS_MASK``
  Mask to set MOS field

``NVME_LM_TRACK_SEND_SEL_SHIFT``
  Shift to set Select (SEL) field

``NVME_LM_TRACK_SEND_SEL_MASK``
  Mask to set SEL field

``NVME_LM_SEL_LOG_USER_DATA_CHANGES``
  Log User Data Changes select option

``NVME_LM_SEL_TRACK_MEMORY_CHANGES``
  Track Memory Changes select option

``NVME_LM_LACT_SHIFT``
  Shift to set Logging Action (LACT) relative to MOS

``NVME_LM_LACT_MASK``
  Mask to set LACT relative to MOS

``NVME_LM_LACT_STOP_LOGGING``
  The controller shall stop logging user data changes to
  namespaces attached to the controller associated with the
  User Data Migration Queue specified in the CDQ ID.

``NVME_LM_LACT_START_LOGGING``
  The controller shall start logging user data changes to
  namespaces attached to the controller associated with the
  User Data Migration Queue into that User Data Migration
  Queue where those user data changes are caused by the
  controller associated with that User Data Migration Queue
  processing commands.




.. c:enum:: nvme_lm_tact

   Track Send - Track Memory Changes - Management Operation Specific field - Tracking Action (TACT)

**Constants**

``NVME_LM_TACT_STOP_TRACKING``
  Stop tracking host memory changes

``NVME_LM_TACT_START_TRACKING``
  Start tracking host memory changes; the
  data buffer contains a Track Memory Changes data
  structure, see :c:type:`struct nvme_lm_track_memory_changes_data <nvme_lm_track_memory_changes_data>`




.. c:enum:: nvme_lm_track_memory_changes_cqe

   Track Send - Track Memory Changes - Completion Queue Entry Dword 0

**Constants**

``NVME_LM_TRACK_MEMORY_CHANGES_CQE_MRTG_SHIFT``
  Shift amount to get Memory
  Range Tracking Granularity (MRTG)

``NVME_LM_TRACK_MEMORY_CHANGES_CQE_MRTG_MASK``
  Mask to get MRTG




.. c:struct:: nvme_lm_memory_range_tracking_descriptor

   Memory Range Tracking Descriptor

**Definition**

::

  struct nvme_lm_memory_range_tracking_descriptor {
    __le64 saddr;
    __le32 len;
  };

**Members**

``saddr``
  Address (SADDR): starting host memory address of the range,
  aligned to the granularity specified by **rmrtg** in :c:type:`struct
  nvme_lm_track_memory_changes_data <nvme_lm_track_memory_changes_data>`

``len``
  Length (LEN), in units of the tracking granularity specified
  by **rmrtg**





.. c:struct:: nvme_lm_track_memory_changes_data

   Track Memory Changes Data Structure, supplied by the host in the data buffer of a Track Send command's Track Memory Changes management operation when starting tracking (TACT set to ``NVME_LM_TACT_START_TRACKING``)

**Definition**

::

  struct nvme_lm_track_memory_changes_data {
    __u8 ver;
    __u8 rsvd1[2];
    __u8 rmrtg;
    __le32 rnmrtd;
    struct nvme_lm_memory_range_tracking_descriptor desc[];
  };

**Members**

``ver``
  Version (VER), shall be cleared to 0h

``rsvd1``
  Reserved

``rmrtg``
  Requested Memory Range Tracking Granularity (RMRTG)

``rnmrtd``
  Number of Memory Range Tracking Descriptors (RNMRTD), a 1's
  based value

``desc``
  Memory Range Tracking Descriptor list, see :c:type:`struct
  nvme_lm_memory_range_tracking_descriptor <nvme_lm_memory_range_tracking_descriptor>`





.. c:enum:: nvme_lm_track_receive_fields

   Track Receive command fields

**Constants**

``NVME_LM_TRACK_RECV_SEL_SHIFT``
  Shift to set Select (SEL) field

``NVME_LM_TRACK_RECV_SEL_MASK``
  Mask to set SEL field

``NVME_LM_SEL_TRACKED_MEMORY_CHANGES``
  Tracked Memory Changes select option

``NVME_LM_TRACKED_MEMORY_CHANGES_CNTLID_SHIFT``
  Shift amount to set Controller
  Identifier (CNTLID)

``NVME_LM_TRACKED_MEMORY_CHANGES_CNTLID_MASK``
  Mask to set CNTLID




.. c:enum:: nvme_lm_tracked_memory_change_attrb

   Tracked Memory Change Data Structure Attributes (ATTRB) field

**Constants**

``NVME_LM_TMC_ATTRB_MTR_SHIFT``
  Shift to get More To Report (MTR)

``NVME_LM_TMC_ATTRB_MTR_MASK``
  Mask to get MTR

``NVME_LM_TMC_ATTRB_SUSP_SHIFT``
  Shift to get Suspended (SUSP)

``NVME_LM_TMC_ATTRB_SUSP_MASK``
  Mask to get SUSP




.. c:struct:: nvme_lm_tracked_memory_changed_descriptor

   Tracked Memory Changed Descriptor

**Definition**

::

  struct nvme_lm_tracked_memory_changed_descriptor {
    __le64 saddr;
    __le32 len;
    __u8 rsvd12[4];
  };

**Members**

``saddr``
  Start Address (SADDR)

``len``
  Length (LEN), in units of the tracking granularity indicated
  by **rpmpg** in :c:type:`struct nvme_lm_tracked_memory_change_data <nvme_lm_tracked_memory_change_data>`

``rsvd12``
  Reserved





.. c:struct:: nvme_lm_tracked_memory_change_data

   Tracked Memory Change Data Structure returned by the Track Receive command's Tracked Memory Changes management operation

**Definition**

::

  struct nvme_lm_tracked_memory_change_data {
    __u8 ver;
    __u8 attrb;
    __le16 cntlid;
    __le32 ntmcd;
    __le16 rpmpg;
    __u8 rsvd10[6];
    struct nvme_lm_tracked_memory_changed_descriptor desc[];
  };

**Members**

``ver``
  Version (VER)

``attrb``
  Attributes (ATTRB), see :c:type:`enum nvme_lm_tracked_memory_change_attrb <nvme_lm_tracked_memory_change_attrb>`

``cntlid``
  Controller Identifier (CNTLID) whose memory modifications are
  being tracked and reported

``ntmcd``
  Number of Tracked Memory Changed Descriptors (NTMCD)

``rpmpg``
  Reported Memory Range Granularity (RPMPG)

``rsvd10``
  Reserved

``desc``
  Tracked Memory Changed Descriptor list





.. c:enum:: nvme_lm_migration_send_fields

   Migration Send command fields

**Constants**

``NVME_LM_MIGRATION_SEND_MOS_SHIFT``
  Shift to set Management Operation Specific (MOS)
  field

``NVME_LM_MIGRATION_SEND_MOS_MASK``
  Mask to set MOS field

``NVME_LM_MIGRATION_SEND_SEL_SHIFT``
  Shift amount to set Select (SEL) field

``NVME_LM_MIGRATION_SEND_SEL_MASK``
  Mask to set SEL field

``NVME_LM_SEL_SUSPEND``
  Migration Send - Suspend

``NVME_LM_SEL_RESUME``
  Migration Send - Resume

``NVME_LM_SEL_SET_CONTROLLER_STATE``
  Migration Send - Set Controller State

``NVME_LM_MIGRATION_SEND_UIDX_SHIFT``
  Shift to set UUID Index (UIDX)

``NVME_LM_MIGRATION_SEND_UIDX_MASK``
  Mask to set UIDX

``NVME_LM_DUDMQ``
  Delete User Data Migration Queue

``NVME_LM_STYPE_SHIFT``
  Shift amount to set Suspend Type (STYPE)

``NVME_LM_STYPE_MASK``
  Mask to set STYPE

``NVME_LM_STYPE_SUSPEND_NOTIFICATION``
  Suspend Notification - The specified controller is
  going to be suspended in the future with a
  subsequent Migration Send command

``NVME_LM_STYPE_SUSPEND``
  Suspend - Suspend the controller

``NVME_LM_SUSPEND_CNTLID_SHIFT``
  Shift amount to set Controller ID (CNTLID) when SEL
  is Suspend

``NVME_LM_SUSPEND_CNTLID_MASK``
  Mask to set CNTLID with SEL Suspend

``NVME_LM_RESUME_CNTLID_SHIFT``
  Shift amount to set Controller ID (CNTLID) when SEL
  is Resume

``NVME_LM_RESUME_CNTLID_MASK``
  Mask to set CNTLID when SEL is Resume

``NVME_LM_SEQIND_SHIFT``
  Shift amount to set Sequence Indicator (SEQIND)
  field relative to MOS

``NVME_LM_SEQIND_MASK``
  Mask to set SEQIND field relative to MOS

``NVME_LM_SEQIND_NOT_FIRST_NOT_LAST``
  This command is not the first or last of a sequence
  of two or more Migration Send commands with this
  management operation used to transfer the controller
  state from host to controller

``NVME_LM_SEQIND_FIRST``
  This command is the first of a sequence of two or
  more Migration Send commands

``NVME_LM_SEQIND_LAST``
  This command is the last command of a sequence of
  two or more Migration Send commands

``NVME_LM_SEQIND_ENTIRE``
  This Migration Send command is the only command and
  contains the entire controller state for this
  management operation

``NVME_LM_SET_CONTROLLER_STATE_CSUUIDI_SHIFT``
  Shift amount to set Controller State UUID Index
  (CSUUIDI)

``NVME_LM_SET_CONTROLLER_STATE_CSUUIDI_MASK``
  Mask to set CSUUIDI

``NVME_LM_SET_CONTROLLER_STATE_CSVI_SHIFT``
  Shift amount to set Controller State Version Index
  (CSVI)

``NVME_LM_SET_CONTROLLER_STATE_CSVI_MASK``
  Mask to set CSVI

``NVME_LM_SET_CONTROLLER_STATE_CNTLID_SHIFT``
  Shift amount to set Controller ID (CNTLID) when SEL
  is Set Controller State

``NVME_LM_SET_CONTROLLER_STATE_CNTLID_MASK``
  Mask to set CNTLID when SEL is Set Controller State




.. c:enum:: nvme_lm_migration_recv_fields

   Migration Receive command fields

**Constants**

``NVME_LM_MIGRATION_RECV_MOS_SHIFT``
  Shift amount to set Management Specific Operation
  (MOS) field

``NVME_LM_MIGRATION_RECV_MOS_MASK``
  Mask to set MOS field

``NVME_LM_MIGRATION_RECV_SEL_SHIFT``
  Shift amount to set Select (SEL) field

``NVME_LM_MIGRATION_RECV_SEL_MASK``
  Mask to set SEL field

``NVME_LM_SEL_GET_CONTROLLER_STATE``
  Get Controller State select option

``NVME_LM_MIGRATION_RECV_UIDX_SHIFT``
  Shift to set UUID Index (UIDX)

``NVME_LM_MIGRATION_RECV_UIDX_MASK``
  Mask to set UIDX

``NVME_LM_GET_CONTROLLER_STATE_CSVI_SHIFT``
  Shift amount to set Controller State Version Index
  (CSVI) relative to MOS

``NVME_LM_GET_CONTROLLER_STATE_CSVI_MASK``
  Mask to set CSVI relative to MOS

``NVME_LM_GET_CONTROLLER_STATE_CSUIDXP_SHIFT``
  Shift amount to set Controller State UUID Index
  Parameter (CSUIDXP)

``NVME_LM_GET_CONTROLLER_STATE_CSUIDXP_MASK``
  Mask to set CSUIDXP

``NVME_LM_GET_CONTROLLER_STATE_CSUUIDI_SHIFT``
  Shift amount to set Controller State UUID Index
  (CSUUIDI)

``NVME_LM_GET_CONTROLLER_STATE_CSUUIDI_MASK``
  Mask to set CSUUIDI

``NVME_LM_GET_CONTROLLER_STATE_CNTLID_SHIFT``
  Shift amount to set Controller ID (CNTLID)

``NVME_LM_GET_CONTROLLER_STATE_CNTLID_MASK``
  Mask to set CNTLID

``NVME_LM_GET_CONTROLLER_STATE_CSUP``
  Controller Suspended




.. c:struct:: nvme_lm_io_submission_queue_data

   I/O Submission Queue data structure. Fields related to the contents of Create I/O Submission Queue command that created an I/O Submission Queue.

**Definition**

::

  struct nvme_lm_io_submission_queue_data {
    __le64 iosqprp1;
    __le16 iosqqsize;
    __le16 iosqqid;
    __le16 iosqcqid;
    __le16 iosqa;
    __le16 iosqhp;
    __le16 iosqtp;
    __u8 rsvd20[4];
  };

**Members**

``iosqprp1``
  I/O Submission PRP Entry 1 (IOSQPRP1)

``iosqqsize``
  I/O Submission Queue Size (IOSQQSIZE)

``iosqqid``
  I/O Submission Queue Identifier (IOSQQID)

``iosqcqid``
  I/O Completion Queue Identifier (IOSQCQID)

``iosqa``
  I/O Submission Queue Attributes (IOSQA)

``iosqhp``
  I/O Submission Queue Head Pointer (IOSQHP)

``iosqtp``
  I/O Submission Queue Tail Pointer (IOSQTP)

``rsvd20``
  Reserved





.. c:struct:: nvme_lm_io_completion_queue_data

   I/O Completion Queue data structure. Fields related to the contents of Create I/O Completion Queue command that created an I/O Completion Queue.

**Definition**

::

  struct nvme_lm_io_completion_queue_data {
    __le64 iocqprp1;
    __le16 iocqqsize;
    __le16 iocqqid;
    __le16 iocqhp;
    __le16 iocqtp;
    __le32 iocqa;
    __u8 rsvd20[4];
  };

**Members**

``iocqprp1``
  I/O Completion Queue PRP Entry 1 (IOCQPRP1)

``iocqqsize``
  I/O Completion Queue Size (IOCQQSIZE)

``iocqqid``
  I/O Completion Queue Identifier (IOCQQID)

``iocqhp``
  I/O Completion Queue Head Pointer (IOCQHP)

``iocqtp``
  I/O Completion Queue Tail Pointer (IOCQTP)

``iocqa``
  I/O Completion Queue Attributes (IOCQA)

``rsvd20``
  Reserved





.. c:struct:: nvme_lm_nvme_controller_state_data_header

   Controller State data structure header

**Definition**

::

  struct nvme_lm_nvme_controller_state_data_header {
    __le16 ver;
    __le16 niosq;
    __le16 niocq;
    __le16 rsvd6;
  };

**Members**

``ver``
  The version of this data structure.

``niosq``
  The number of I/O Submission Queues contained in this data structure.

``niocq``
  The number of I/O Completion Queues contained in this data structure.

``rsvd6``
  Reserved





.. c:struct:: nvme_lm_nvme_controller_state_data

   NVMe Controller State data structure describes the state of a NVMe Controller's I/O Submission and I/O Completion queues

**Definition**

::

  struct nvme_lm_nvme_controller_state_data {
    struct nvme_lm_nvme_controller_state_data_header hdr;
    union {
      struct nvme_lm_io_submission_queue_data sqs[0];
      struct nvme_lm_io_completion_queue_data cqs[0];
      __u8 queue_data_buf[4088];
    };
  };

**Members**

``hdr``
  Header

``{unnamed_union}``
  anonymous

``sqs``
  I/O Submission Queue list

``cqs``
  I/O Completion Queue list

``queue_data_buf``
  Queue data buffer





.. c:struct:: nvme_lm_controller_state_data_header

   Controller State data header structure describes the contents of the Controller State data

**Definition**

::

  struct nvme_lm_controller_state_data_header {
    __le16 ver;
    __u8 csattr;
    __u8 rsvd3[13];
    __u8 nvmecss[16];
    __u8 vss[16];
  };

**Members**

``ver``
  Version of this data structure

``csattr``
  Controller state attributes

``rsvd3``
  Reserved

``nvmecss``
  NVMe Controller state size in dwords

``vss``
  Vendor specific size in dowrds





.. c:struct:: nvme_lm_controller_state_data

   Controller State data structure contains data on the controller's state.

**Definition**

::

  struct nvme_lm_controller_state_data {
    struct nvme_lm_controller_state_data_header hdr;
    struct nvme_lm_nvme_controller_state_data   data;
  };

**Members**

``hdr``
  Header

``data``
  Data





.. c:enum:: nvme_tdisp_ti

   NVMe TDISP DEVICE_INTERFACE_REPORT - TDISP Information (TI)

**Constants**

``NVME_TDISP_TI_VER_SHIFT``
  Shift amount to get the Version (VER)

``NVME_TDISP_TI_VER_MASK``
  Mask to get VER

``NVME_TDISP_TI_ACPS_SHIFT``
  Shift amount to get the Admin Command Processing
  Status (ACPS)

``NVME_TDISP_TI_ACPS_MASK``
  Mask to get ACPS

``NVME_TDISP_TI_ENV_SHIFT``
  Shift amount to get the Enable Value (ENV)

``NVME_TDISP_TI_ENV_MASK``
  Mask to get ENV

``NVME_TDISP_TI_SHNV_SHIFT``
  Shift amount to get the Shutdown Notification
  Value (SHNV)

``NVME_TDISP_TI_SHNV_MASK``
  Mask to get SHNV

``NVME_TDISP_TI_SHSTV_SHIFT``
  Shift amount to get the Shutdown Status Value
  (SHSTV)

``NVME_TDISP_TI_SHSTV_MASK``
  Mask to get SHSTV

``NVME_TDISP_TI_STV_SHIFT``
  Shift amount to get the Shutdown Type Value (STV)

``NVME_TDISP_TI_STV_MASK``
  Mask to get STV

``NVME_TDISP_TI_CSSV_SHIFT``
  Shift amount to get the Command Sets Supported
  Value (CSSV)

``NVME_TDISP_TI_CSSV_MASK``
  Mask to get CSSV

``NVME_TDISP_TI_MPSV_SHIFT``
  Shift amount to get the Memory Page Size Value
  (MPSV)

``NVME_TDISP_TI_MPSV_MASK``
  Mask to get MPSV

``NVME_TDISP_TI_IOSQESV_SHIFT``
  Shift amount to get the I/O Submission Queue
  Entry Size Value (IOSQESV)

``NVME_TDISP_TI_IOSQESV_MASK``
  Mask to get IOSQESV

``NVME_TDISP_TI_IOCQESV_SHIFT``
  Shift amount to get the I/O Completion Queue
  Entry Size Value (IOCQESV)

``NVME_TDISP_TI_IOCQESV_MASK``
  Mask to get IOCQESV




.. c:struct:: nvme_tdisp_device_interface_report

   NVMe TDISP DEVICE_INTERFACE_REPORT Reporting Structure

**Definition**

::

  struct nvme_tdisp_device_interface_report {
    __le32 tni;
    __le32 ti;
    __u8 cu;
    __u8 vu;
    __u8 rsvd10[2];
    __le32 aqv;
    __le32 asv;
    __le32 acv;
    __le32 cv;
    __le32 pmv;
    __le32 pcv;
    __u8 qh[48];
    __u8 rsvd84[44];
  };

**Members**

``tni``
  TDISP NVMe Identifier, shall be ``NVME_TDISP_NVME_IDENTIFIER``

``ti``
  TDISP Information, see :c:type:`enum nvme_tdisp_ti <nvme_tdisp_ti>`

``cu``
  CSVL Used, the Controller State Version Index of the NVMe
  Controller State data structure used to generate **qh**

``vu``
  VER Used, the Version field in the NVMe Controller State data
  structure used to generate **qh**

``rsvd10``
  Reserved

``aqv``
  AQA Value

``asv``
  ASQ Value

``acv``
  ACQ Value

``cv``
  CMBMSC Value

``pmv``
  PMRMSC Value

``pcv``
  PMRCTL Value

``qh``
  Queue Hash, a SHA-384 hash of all the fields in the NVMe
  Controller State data structure, see
  :c:type:`struct nvme_lm_controller_state_data <nvme_lm_controller_state_data>`

``rsvd84``
  Reserved


**Description**


This is the NVMe class-specific DEVICE_SPECIFIC_INFO payload that a PCIe
Function returns in response to a PCIe TDISP GET_DEVICE_INTERFACE_REPORT
request (refer to the NVM Express over PCIe Transport Specification).
There is no NVMe Admin, I/O, or MI command that transfers this structure
-- it is produced by the device's Device Security Module and consumed by
a platform TEE Security Module entirely via the PCIe TDISP protocol,
outside of any NVMe command/response mechanism. This type is provided
purely so that software which has otherwise obtained a
DEVICE_INTERFACE_REPORT (e.g., from a TDISP/SPDM stack) can decode its
NVMe-specific portion.




.. c:enum:: nvme_lm_queue_attributes

   I/O Submission and I/O Completion Queue Attributes

**Constants**

``NVME_LM_IOSQPC_MASK``
  Mask to get the Physically Contiguous (PC) bit for this I/O
  submission queue.

``NVME_LM_IOSQPC_SHIFT``
  Shift to get the PC bit for this I/O submission queue

``NVME_LM_IOSQPRIO_MASK``
  Mask to get the Priority for this I/O submission queue.

``NVME_LM_IOSQPRIO_SHIFT``
  Shift to get the Priority for this I/O submission queue.

``NVME_LM_IOCQPC_MASK``
  Mask to get the Physicaly Contiguous (PC) bit for this I/O
  completion queue.

``NVME_LM_IOCQPC_SHIFT``
  Shift to get the PC bit for this I/O completion queue.

``NVME_LM_IOCQIEN_MASK``
  Mask to get the Interrupts Enabled bit for this I/O completion
  queue

``NVME_LM_IOCQIEN_SHIFT``
  Shift to get the Interrupts Enabled bit for this I/O completion

``NVME_LM_S0PT_MASK``
  Mask to get the value of the Phase Tag bit for Slot 0 of this I/O
  completion queue.

``NVME_LM_S0PT_SHIFT``
  Shift to get the value of the Phase Tag bit for Slot 0 of this I/O
  completion queue.

``NVME_LM_IOCQIV_MASK``
  Mask to get the Interrupt Vector (IV) for this I/O completion
  queue.

``NVME_LM_IOCQIV_SHIFT``
  Shift to get the IV for this I/O completion queue.




.. c:enum:: nvme_lm_ctrl_data_queue_fid

   Controller Data Queue - Set Feature

**Constants**

``NVME_LM_CTRL_DATA_QUEUE_ETPT_MASK``
  Mask to set Enable Tail Pointer Trigger (ETPT)

``NVME_LM_CTRL_DATA_QUEUE_ETPT_SHIFT``
  Shift to set ETPT




.. c:struct:: nvme_lm_ctrl_data_queue_fid_data

   Get Controller Data Queue feature data

**Definition**

::

  struct nvme_lm_ctrl_data_queue_fid_data {
    __le32 hp;
    __le32 tpt;
  };

**Members**

``hp``
  Head Pointer

``tpt``
  Tail Pointer Trigger





.. c:enum:: nvme_rate_limiting_target

   Rate Limiting Feature Command Dword 11 Target (TGT)

**Constants**

``NVME_RATE_LIMITING_TARGET_CONTROLLER``
  Target Identifier field specifies
  the controller identifier

``NVME_RATE_LIMITING_TARGET_VENDOR_MIN``
  Start of vendor specific range

``NVME_RATE_LIMITING_TARGET_VENDOR_MAX``
  End of vendor specific range




.. c:enum:: nvme_voltage_measurement_act

   Voltage Measurement Feature - Command Dword 11 Action (ACT)

**Constants**

``NVME_VOLTAGE_MEASUREMENT_ACT_STOP``
  Stop Voltage Measurements

``NVME_VOLTAGE_MEASUREMENT_ACT_START``
  Start Voltage Measurements

``NVME_VOLTAGE_MEASUREMENT_ACT_CLEAR``
  Clear Overvoltage Valid and
  Undervoltage Valid


