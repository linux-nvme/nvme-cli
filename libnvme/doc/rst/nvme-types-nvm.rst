.. _nvme-types-nvm.h:

**nvme-types-nvm.h**


NVM Command Set type definitions

Based on NVM Express NVM Command Set Specification,
Revision 1.3

This file is organized into functional groups:

- NVM Namespace Identification: Extended LBA formats and namespace-specific data
- I/O Command Set Support: Command set identification and capabilities
- Reservation Notifications: Log pages for reservation events
- Flexible Data Placement (FDP): Comprehensive FDP feature support including
  configuration, events, statistics, and status reporting
- Data Set Management & Copy: DSM ranges and copy operation formats
- Reservation Support: Controller registration and reservation management
- I/O Management: Control flags and management operations
- Rate Limiting: Bandwidth and IOPS limiting feature and log page



.. c:enum:: nvme_nvm_id_ns_elbaf

   This field indicates the extended LBA format

**Constants**

``NVME_NVM_ELBAF_STS_SHIFT``
  Shift to get the storage tag size

``NVME_NVM_ELBAF_STS_MASK``
  Mask to get the storage tag size used to determine
  the variable-sized storage tag/reference tag fields

``NVME_NVM_ELBAF_PIF_SHIFT``
  Shift to get the protection information format

``NVME_NVM_ELBAF_PIF_MASK``
  Mask to get the protection information format for
  the extended LBA format.

``NVME_NVM_ELBAF_QPIF_SHIFT``
  Shift to get the Qualified Protection Information Format

``NVME_NVM_ELBAF_QPIF_MASK``
  Mask to get the Qualified Protection Information
  Format.




.. c:enum:: nvme_nvm_id_ns_pif

   This field indicates the type of the Protection Information Format

**Constants**

``NVME_NVM_PIF_16B_GUARD``
  16-bit Guard Protection Information Format

``NVME_NVM_PIF_32B_GUARD``
  32-bit Guard Protection Information Format

``NVME_NVM_PIF_64B_GUARD``
  64-bit Guard Protection Information Format

``NVME_NVM_PIF_QTYPE``
  If Qualified Protection Information Format Supports
  and Protection Information Format is set to 3, then
  protection information format is taken from Qualified
  Protection Information Format field.




.. c:enum:: nvme_nvm_id_ns_lbstm

   Logical Block Storage Tag Mask

**Constants**

``NVME_NVM_LBSTM_DEALLOCATED_SHIFT``
  Shift amount to get Deallocated/Unwritten Logical Block error time

``NVME_NVM_LBSTM_DEALLOCATED_MASK``
  Mask to get Deallocated/Unwritten Logical Block error time

``NVME_NVM_LBSTM_WRITTEN_SHIFT``
  Shift amount to get Written Logical Block error time

``NVME_NVM_LBSTM_WRITTEN_MASK``
  Mask to get Written Logical Block error time




.. c:enum:: nvme_nvm_id_ns_pic

   Protection Information Capabilities

**Constants**

``NVME_NVM_PIC_PITPS16B_SHIFT``
  Shift amount to get 16b Guard Protection Information Storage Tag Support

``NVME_NVM_PIC_PITPS16B_MASK``
  Mask to get 16b Guard Protection Information Storage Tag Support

``NVME_NVM_PIC_PISTM16B_SHIFT``
  Shift amount to get 16b Guard Protection Information Storage Tag Mask

``NVME_NVM_PIC_PISTM16B_MASK``
  Mask to get 16b Guard Protection Information Storage Tag Mask

``NVME_NVM_PIC_STCRS_SHIFT``
  Shift amount to get Storage Tag Check Read Support

``NVME_NVM_PIC_STCRS_MASK``
  Mask to get Storage Tag Check Read Support

``NVME_NVM_PIC_QPIFS_SHIFT``
  Shift amount to get Qualified Protection Information Format Support

``NVME_NVM_PIC_QPIFS_MASK``
  Mask to get Qualified Protection Information Format Support




.. c:enum:: nvme_nvm_id_ns_pifa

   Protection Information Format Attribute

**Constants**

``NVME_NVM_PIFA_STMLA_SHIFT``
  Shift amount to get Storage Tag Masking Level Attribute

``NVME_NVM_PIFA_STMLA_MASK``
  Mask to get Storage Tag Masking Level Attribute

``NVME_NVM_PIFA_BIT_GRANULARITY_MASKING``
  Bit Granularity Masking

``NVME_NVM_PIFA_BYTE_GRANULARITY_MASKING``
  Byte Granularity Masking

``NVME_NVM_PIFA_MASKING_NOT_SUPPORTED``
  Masking Not Supported




.. c:struct:: nvme_nvm_id_ns

   NVME Command Set I/O Command Set Specific Identify Namespace Data Structure

**Definition**

::

  struct nvme_nvm_id_ns {
    __le64 lbstm;
    __u8 pic;
    __u8 pifa;
    __u8 rsvd10[2];
    __le32 elbaf[64];
    __le32 npdgl;
    __le32 nprg;
    __le32 npra;
    __le32 nors;
    __le32 npdal;
    __le32 lbapss;
    __le32 tlbaag;
    __u8 rsvd296[3800];
  };

**Members**

``lbstm``
  Logical Block Storage Tag Mask

``pic``
  Protection Information Capabilities

``pifa``
  Protection Information Format Attribute

``rsvd10``
  Reserved

``elbaf``
  List of Extended LBA Format Support

``npdgl``
  Namespace Preferred Deallocate Granularity Large

``nprg``
  Namespace Preferred Read Granularity

``npra``
  Namespace Preferred Read Alignment

``nors``
  Namespace Optimal Read Size

``npdal``
  Namespace Preferred Deallocate Alignment Large

``lbapss``
  LBA Format Placement Shard Size

``tlbaag``
  Tracked LBA Allocation Granularity

``rsvd296``
  Reserved





.. c:enum:: nvme_id_iocs_iocsc

   This field indicates the Identify I/O Command Set Data Structure

**Constants**

``NVME_IOCS_IOCSC_NVMCS_SHIFT``
  Shift amount to get the value of NVM Command Set

``NVME_IOCS_IOCSC_NVMCS_MASK``
  Mask to get the value of NVM Command Set

``NVME_IOCS_IOCSC_KVCS_SHIFT``
  Shift amount to get the value of Key Value Command Set

``NVME_IOCS_IOCSC_KVCS_MASK``
  Mask to get the value of Key Value Command Set

``NVME_IOCS_IOCSC_ZNSCS_SHIFT``
  Shift amount to get the value of Zoned Namespace Command
  Set

``NVME_IOCS_IOCSC_ZNSCS_MASK``
  Mask to get the value of Zoned Namespace Command Set

``NVME_IOCS_IOCSC_SLMCS_SHIFT``
  Shift amount to get the value of Subsystem Local Memory
  Command Set

``NVME_IOCS_IOCSC_SLMCS_MASK``
  Mask to get the value of Subsystem Local Memory Command Set

``NVME_IOCS_IOCSC_CPNCS_SHIFT``
  Shift amount to get the value of Computational Programs
  Namespace Command Set

``NVME_IOCS_IOCSC_CPNCS_MASK``
  Mask to get the value of Computational Programs Namespace
  Command Set




.. c:struct:: nvme_resv_notification_log

   Reservation Notification Log

**Definition**

::

  struct nvme_resv_notification_log {
    __le64 lpc;
    __u8 rnlpt;
    __u8 nalp;
    __u8 rsvd9[2];
    __le32 nsid;
    __u8 rsvd16[48];
  };

**Members**

``lpc``
  Log Page Count

``rnlpt``
  See :c:type:`enum nvme_resv_notify_rnlpt <nvme_resv_notify_rnlpt>`.

``nalp``
  Number of Available Log Pages

``rsvd9``
  Reserved

``nsid``
  Namespace ID

``rsvd16``
  Reserved





.. c:enum:: nvme_resv_notify_rnlpt

   Reservation Notification Log - Reservation Notification Log Page Type

**Constants**

``NVME_RESV_NOTIFY_RNLPT_EMPTY``
  Empty Log Page

``NVME_RESV_NOTIFY_RNLPT_REGISTRATION_PREEMPTED``
  Registration Preempted

``NVME_RESV_NOTIFY_RNLPT_RESERVATION_RELEASED``
  Reservation Released

``NVME_RESV_NOTIFY_RNLPT_RESERVATION_PREEMPTED``
  Reservation Preempted




.. c:enum:: nvme_fdp_ruh_type

   Reclaim Unit Handle Type

**Constants**

``NVME_FDP_RUHT_INITIALLY_ISOLATED``
  Initially Isolated

``NVME_FDP_RUHT_PERSISTENTLY_ISOLATED``
  Persistently Isolated




.. c:struct:: nvme_fdp_ruh_desc

   Reclaim Unit Handle Descriptor

**Definition**

::

  struct nvme_fdp_ruh_desc {
    __u8 ruht;
    __u8 rsvd1[3];
  };

**Members**

``ruht``
  Reclaim Unit Handle Type

``rsvd1``
  Reserved





.. c:enum:: nvme_fdp_config_fdpa

   FDP Attributes

**Constants**

``NVME_FDP_CONFIG_FDPA_RGIF_SHIFT``
  Reclaim Group Identifier Format Shift

``NVME_FDP_CONFIG_FDPA_RGIF_MASK``
  Reclaim Group Identifier Format Mask

``NVME_FDP_CONFIG_FDPA_FDPVWC_SHIFT``
  FDP Volatile Write Cache Shift

``NVME_FDP_CONFIG_FDPA_FDPVWC_MASK``
  FDP Volatile Write Cache Mask

``NVME_FDP_CONFIG_FDPA_VALID_SHIFT``
  FDP Configuration Valid Shift

``NVME_FDP_CONFIG_FDPA_VALID_MASK``
  FDP Configuration Valid Mask




.. c:struct:: nvme_fdp_config_desc

   FDP Configuration Descriptor

**Definition**

::

  struct nvme_fdp_config_desc {
    __le16 size;
    __u8 fdpa;
    __u8 vss;
    __le32 nrg;
    __le16 nruh;
    __le16 maxpids;
    __le32 nnss;
    __le64 runs;
    __le32 erutl;
    __u8 rsvd28[36];
    struct nvme_fdp_ruh_desc ruhs[];
  };

**Members**

``size``
  Descriptor size

``fdpa``
  FDP Attributes (:c:type:`enum nvme_fdp_config_fdpa <nvme_fdp_config_fdpa>`)

``vss``
  Vendor Specific Size

``nrg``
  Number of Reclaim Groups

``nruh``
  Number of Reclaim Unit Handles

``maxpids``
  Max Placement Identifiers

``nnss``
  Number of Namespaces Supported

``runs``
  Reclaim Unit Nominal Size

``erutl``
  Estimated Reclaim Unit Time Limit

``rsvd28``
  Reserved

``ruhs``
  Reclaim Unit Handle descriptors (:c:type:`struct nvme_fdp_ruh_desc <nvme_fdp_ruh_desc>`)





.. c:struct:: nvme_fdp_config_log

   FDP Configurations Log Page

**Definition**

::

  struct nvme_fdp_config_log {
    __le16 n;
    __u8 version;
    __u8 rsvd3;
    __le32 size;
    __u8 rsvd8[8];
    struct nvme_fdp_config_desc configs[];
  };

**Members**

``n``
  Number of FDP Configurations

``version``
  Log page version

``rsvd3``
  Reserved

``size``
  Log page size in bytes

``rsvd8``
  Reserved

``configs``
  FDP Configuration descriptors (:c:type:`struct nvme_fdp_config_desc <nvme_fdp_config_desc>`)





.. c:enum:: nvme_fdp_ruha

   Reclaim Unit Handle Attributes

**Constants**

``NVME_FDP_RUHA_HOST_SHIFT``
  Host Specified Reclaim Unit Handle Shift

``NVME_FDP_RUHA_HOST_MASK``
  Host Specified Reclaim Unit Handle Mask

``NVME_FDP_RUHA_CTRL_SHIFT``
  Controller Specified Reclaim Unit Handle Shift

``NVME_FDP_RUHA_CTRL_MASK``
  Controller Specified Reclaim Unit Handle Mask




.. c:struct:: nvme_fdp_ruhu_desc

   Reclaim Unit Handle Usage Descriptor

**Definition**

::

  struct nvme_fdp_ruhu_desc {
    __u8 ruha;
    __u8 rsvd1[7];
  };

**Members**

``ruha``
  Reclaim Unit Handle Attributes (:c:type:`enum nvme_fdp_ruha <nvme_fdp_ruha>`)

``rsvd1``
  Reserved





.. c:struct:: nvme_fdp_ruhu_log

   Reclaim Unit Handle Usage Log Page

**Definition**

::

  struct nvme_fdp_ruhu_log {
    __le16 nruh;
    __u8 rsvd2[6];
    struct nvme_fdp_ruhu_desc ruhus[];
  };

**Members**

``nruh``
  Number of Reclaim Unit Handles

``rsvd2``
  Reserved

``ruhus``
  Reclaim Unit Handle Usage descriptors





.. c:struct:: nvme_fdp_stats_log

   FDP Statistics Log Page

**Definition**

::

  struct nvme_fdp_stats_log {
    __u8 hbmw[16];
    __u8 mbmw[16];
    __u8 mbe[16];
    __u8 rsvd48[16];
  };

**Members**

``hbmw``
  Host Bytes with Metadata Written

``mbmw``
  Media Bytes with Metadata Written

``mbe``
  Media Bytes Erased

``rsvd48``
  Reserved





.. c:enum:: nvme_fdp_event_type

   FDP Event Types

**Constants**

``NVME_FDP_EVENT_RUNFW``
  Reclaim Unit Not Fully Written

``NVME_FDP_EVENT_RUTLE``
  Reclaim Unit Time Limit Exceeded

``NVME_FDP_EVENT_RESET``
  Controller Level Reset Modified Reclaim Unit Handles

``NVME_FDP_EVENT_PID``
  Invalid Placement Identifier

``NVME_FDP_EVENT_REALLOC``
  Media Reallocated

``NVME_FDP_EVENT_MODIFY``
  Implicitly Modified Reclaim Unit Handle




.. c:enum:: nvme_fdp_event_realloc_flags

   Media Reallocated Event Type Specific Flags

**Constants**

``NVME_FDP_EVENT_REALLOC_F_LBAV``
  LBA Valid




.. c:struct:: nvme_fdp_event_realloc

   Media Reallocated Event Type Specific Information

**Definition**

::

  struct nvme_fdp_event_realloc {
    __u8 flags;
    __u8 rsvd1;
    __le16 nlbam;
    __le64 lba;
    __u8 rsvd12[4];
  };

**Members**

``flags``
  Event Type Specific flags (:c:type:`enum nvme_fdp_event_realloc_flags <nvme_fdp_event_realloc_flags>`)

``rsvd1``
  Reserved

``nlbam``
  Number of LBAs Moved

``lba``
  Logical Block Address

``rsvd12``
  Reserved





.. c:enum:: nvme_fdp_event_flags

   FDP Event Flags

**Constants**

``NVME_FDP_EVENT_F_PIV``
  Placement Identifier Valid

``NVME_FDP_EVENT_F_NSIDV``
  Namespace Identifier Valid

``NVME_FDP_EVENT_F_LV``
  Location Valid




.. c:struct:: nvme_fdp_event

   FDP Event

**Definition**

::

  struct nvme_fdp_event {
    __u8 type;
    __u8 flags;
    __le16 pid;
    struct nvme_timestamp ts;
    __le32 nsid;
    __u8 type_specific[16];
    __le16 rgid;
    __u8 ruhid;
    __u8 rsvd35[5];
    __u8 vs[24];
  };

**Members**

``type``
  Event Type (:c:type:`enum nvme_fdp_event_type <nvme_fdp_event_type>`)

``flags``
  Event Flags (:c:type:`enum nvme_fdp_event_flags <nvme_fdp_event_flags>`)

``pid``
  Placement Identifier

``ts``
  Timestamp

``nsid``
  Namespace Identifier

``type_specific``
  Event Type Specific Information

``rgid``
  Reclaim Group Identifier

``ruhid``
  Reclaim Unit Handle Identifier

``rsvd35``
  Reserved

``vs``
  Vendor Specific





.. c:struct:: nvme_fdp_events_log

   FDP Events Log Page

**Definition**

::

  struct nvme_fdp_events_log {
    __le32 n;
    __u8 rsvd4[60];
    struct nvme_fdp_event events[63];
  };

**Members**

``n``
  Number of FDP Events

``rsvd4``
  Reserved

``events``
  FDP Events (:c:type:`struct nvme_fdp_event <nvme_fdp_event>`)





.. c:struct:: nvme_feat_fdp_events_cdw11

   FDP Events Feature Command Dword 11 Deprecated: doesn't support this struct. Use NVME_FEAT_FDPE_*** definitions instead.

**Definition**

::

  struct nvme_feat_fdp_events_cdw11 {
    __le16 phndl;
    __u8 noet;
    __u8 rsvd24;
  };

**Members**

``phndl``
  Placement Handle

``noet``
  Number of FDP Event Types

``rsvd24``
  Reserved





.. c:enum:: nvme_fdp_supported_event_attributes

   Supported FDP Event Attributes

**Constants**

``NVME_FDP_SUPP_EVENT_ENABLED_SHIFT``
  FDP Event Enable Shift

``NVME_FDP_SUPP_EVENT_ENABLED_MASK``
  FDP Event Enable Mask




.. c:struct:: nvme_fdp_supported_event_desc

   Supported FDP Event Descriptor

**Definition**

::

  struct nvme_fdp_supported_event_desc {
    __u8 evt;
    __u8 evta;
  };

**Members**

``evt``
  FDP Event Type

``evta``
  FDP Event Type Attributes (:c:type:`enum nvme_fdp_supported_event_attributes <nvme_fdp_supported_event_attributes>`)





.. c:struct:: nvme_fdp_ruh_status_desc

   Reclaim Unit Handle Status Descriptor

**Definition**

::

  struct nvme_fdp_ruh_status_desc {
    __le16 pid;
    __le16 ruhid;
    __le32 earutr;
    __le64 ruamw;
    __u8 rsvd16[16];
  };

**Members**

``pid``
  Placement Identifier

``ruhid``
  Reclaim Unit Handle Identifier

``earutr``
  Estimated Active Reclaim Unit Time Remaining

``ruamw``
  Reclaim Unit Available Media Writes

``rsvd16``
  Reserved





.. c:struct:: nvme_fdp_ruh_status

   Reclaim Unit Handle Status

**Definition**

::

  struct nvme_fdp_ruh_status {
    __u8 rsvd0[14];
    __le16 nruhsd;
    struct nvme_fdp_ruh_status_desc ruhss[];
  };

**Members**

``rsvd0``
  Reserved

``nruhsd``
  Number of Reclaim Unit Handle Status Descriptors

``ruhss``
  Reclaim Unit Handle Status descriptors





.. c:struct:: nvme_dsm_range

   Dataset Management - Range Definition

**Definition**

::

  struct nvme_dsm_range {
    __le32 cattr;
    __le32 nlb;
    __le64 slba;
  };

**Members**

``cattr``
  Context Attributes

``nlb``
  Length in logical blocks

``slba``
  Starting LBA





.. c:struct:: nvme_copy_range_f0

   Copy - Source Range Entries Descriptor Format 0h

**Definition**

::

  struct nvme_copy_range_f0 {
    __u8 rsvd0[8];
    __le64 slba;
    __le16 nlb;
    __u8 cetype;
    __u8 rsvd19;
    __le16 cev;
    __u8 rsvd22[2];
    __le32 elbt;
    __le16 elbat;
    __le16 elbatm;
  };

**Members**

``rsvd0``
  Reserved

``slba``
  Starting LBA

``nlb``
  Number of Logical Blocks

``cetype``
  Bits 3-0: Command Extension Type

``rsvd19``
  Reserved

``cev``
  Command Extension Value

``rsvd22``
  Reserved

``elbt``
  Expected Initial Logical Block Reference Tag /
  Expected Logical Block Storage Tag

``elbat``
  Expected Logical Block Application Tag

``elbatm``
  Expected Logical Block Application Tag Mask





.. c:struct:: nvme_copy_range_f1

   Copy - Source Range Entries Descriptor Format 1h

**Definition**

::

  struct nvme_copy_range_f1 {
    __u8 rsvd0[8];
    __le64 slba;
    __le16 nlb;
    __u8 cetype;
    __u8 rsvd19;
    __le16 cev;
    __u8 rsvd22[4];
    __u8 elbt[10];
    __le16 elbat;
    __le16 elbatm;
  };

**Members**

``rsvd0``
  Reserved

``slba``
  Starting LBA

``nlb``
  Number of Logical Blocks

``cetype``
  Bits 3-0: Command Extension Type

``rsvd19``
  Reserved

``cev``
  Command Extension Value

``rsvd22``
  Reserved

``elbt``
  Expected Initial Logical Block Reference Tag /
  Expected Logical Block Storage Tag

``elbat``
  Expected Logical Block Application Tag

``elbatm``
  Expected Logical Block Application Tag Mask





.. c:enum:: nvme_copy_range_sopt

   NVMe Copy Range Source Options

**Constants**

``NVME_COPY_SOPT_FCO``
  NVMe Copy Source Option Fast Copy Only




.. c:struct:: nvme_copy_range_f2

   Copy - Source Range Entries Descriptor Format 2h

**Definition**

::

  struct nvme_copy_range_f2 {
    __le32 snsid;
    __u8 rsvd4[4];
    __le64 slba;
    __le16 nlb;
    __u8 cetype;
    __u8 rsvd19;
    __le16 cev;
    __le16 sopt;
    __le32 elbt;
    __le16 elbat;
    __le16 elbatm;
  };

**Members**

``snsid``
  Source Namespace Identifier

``rsvd4``
  Reserved

``slba``
  Starting LBA

``nlb``
  Number of Logical Blocks

``cetype``
  Bits 3-0: Command Extension Type

``rsvd19``
  Reserved

``cev``
  Command Extension Value

``sopt``
  Source Options

``elbt``
  Expected Initial Logical Block Reference Tag /
  Expected Logical Block Storage Tag

``elbat``
  Expected Logical Block Application Tag

``elbatm``
  Expected Logical Block Application Tag Mask





.. c:struct:: nvme_copy_range_f3

   Copy - Source Range Entries Descriptor Format 3h

**Definition**

::

  struct nvme_copy_range_f3 {
    __le32 snsid;
    __u8 rsvd4[4];
    __le64 slba;
    __le16 nlb;
    __u8 cetype;
    __u8 rsvd19;
    __le16 cev;
    __le16 sopt;
    __u8 rsvd24[2];
    __u8 elbt[10];
    __le16 elbat;
    __le16 elbatm;
  };

**Members**

``snsid``
  Source Namespace Identifier

``rsvd4``
  Reserved

``slba``
  Starting LBA

``nlb``
  Number of Logical Blocks

``cetype``
  Bits 3-0: Command Extension Type

``rsvd19``
  Reserved

``cev``
  Command Extension Value

``sopt``
  Source Options

``rsvd24``
  Reserved

``elbt``
  Expected Initial Logical Block Reference Tag /
  Expected Logical Block Storage Tag

``elbat``
  Expected Logical Block Application Tag

``elbatm``
  Expected Logical Block Application Tag Mask





.. c:struct:: nvme_registrant

   Registrant Data Structure

**Definition**

::

  struct nvme_registrant {
    __le16 cntlid;
    __u8 rcsts;
    __u8 rsvd3[5];
    __le64 hostid;
    __le64 rkey;
  };

**Members**

``cntlid``
  Controller ID

``rcsts``
  Reservation Status

``rsvd3``
  Reserved

``hostid``
  Host Identifier

``rkey``
  Reservation Key





.. c:struct:: nvme_registrant_ext

   Registrant Extended Data Structure

**Definition**

::

  struct nvme_registrant_ext {
    __le16 cntlid;
    __u8 rcsts;
    __u8 rsvd3[5];
    __le64 rkey;
    __u8 hostid[16];
    __u8 rsvd32[32];
  };

**Members**

``cntlid``
  Controller ID

``rcsts``
  Reservation Status

``rsvd3``
  Reserved

``rkey``
  Reservation Key

``hostid``
  Host Identifier

``rsvd32``
  Reserved





.. c:struct:: nvme_resv_status

   Reservation Status Data Structure

**Definition**

::

  struct nvme_resv_status {
    __le32 gen;
    __u8 rtype;
    __u8 regstrnt[2];
    __u8 rsvd7[2];
    __u8 ptpls;
    __u8 rsvd10[14];
    union {
      struct {
        __u8 rsvd24[40];
        struct nvme_registrant_ext registrant_eds[0];
      };
      struct nvme_registrant registrant_ds[0];
    };
  };

**Members**

``gen``
  Generation

``rtype``
  Reservation Type

``regstrnt``
  Number of Registrants

``rsvd7``
  Reserved

``ptpls``
  Persist Through Power Loss State

``rsvd10``
  Reserved

``{unnamed_union}``
  anonymous

``{unnamed_struct}``
  anonymous

``rsvd24``
  Reserved

``registrant_eds``
  Registrant Extended Data Structure

``registrant_ds``
  Registrant Data Structure





.. c:enum:: nvme_feat_resv_notify_flags

   Reservation Notification Configuration

**Constants**

``NVME_FEAT_RESV_NOTIFY_REGPRE``
  Mask Registration Preempted Notification

``NVME_FEAT_RESV_NOTIFY_RESREL``
  Mask Reservation Released Notification

``NVME_FEAT_RESV_NOTIFY_RESPRE``
  Mask Reservation Preempted Notification




.. c:enum:: nvme_io_control_flags

   I/O control flags

**Constants**

``NVME_IO_DTYPE_STREAMS``
  Directive Type Streams

``NVME_IO_NSZ``
  Namespace Zeroes

``NVME_IO_STC``
  Storage Tag Check

``NVME_IO_DEAC``
  Deallocate

``NVME_IO_ZNS_APPEND_PIREMAP``
  Protection Information Remap

``NVME_IO_PRINFO_PRCHK_REF``
  Protection Information Check Reference Tag

``NVME_IO_PRINFO_PRCHK_APP``
  Protection Information Check Application Tag

``NVME_IO_PRINFO_PRCHK_GUARD``
  Protection Information Check Guard field

``NVME_IO_PRINFO_PRACT``
  Protection Information Action

``NVME_IO_FUA``
  Force Unit Access

``NVME_IO_LR``
  Limited Retry




.. c:enum:: nvme_io_dsm_flags

   Dataset Management flags

**Constants**

``NVME_IO_DSM_FREQ_UNSPEC``
  No frequency information provided

``NVME_IO_DSM_FREQ_TYPICAL``
  Typical number of reads and writes
  expected for this LBA range

``NVME_IO_DSM_FREQ_RARE``
  Infrequent writes and infrequent
  reads to the LBA range indicated

``NVME_IO_DSM_FREQ_READS``
  Infrequent writes and frequent
  reads to the LBA range indicated

``NVME_IO_DSM_FREQ_WRITES``
  Frequent writes and infrequent
  reads to the LBA range indicated

``NVME_IO_DSM_FREQ_RW``
  Frequent writes and frequent reads
  to the LBA range indicated

``NVME_IO_DSM_FREQ_ONCE``

``NVME_IO_DSM_FREQ_PREFETCH``

``NVME_IO_DSM_FREQ_TEMP``

``NVME_IO_DSM_LATENCY_NONE``
  No latency information provided

``NVME_IO_DSM_LATENCY_IDLE``
  Longer latency acceptable

``NVME_IO_DSM_LATENCY_NORM``
  Typical latency

``NVME_IO_DSM_LATENCY_LOW``
  Smallest possible latency

``NVME_IO_DSM_SEQ_REQ``

``NVME_IO_DSM_COMPRESSED``




.. c:enum:: nvme_dsm_attributes

   Dataset Management attributes

**Constants**

``NVME_DSMGMT_IDR``
  Attribute -Integral Dataset for Read

``NVME_DSMGMT_IDW``
  Attribute - Integral Dataset for Write

``NVME_DSMGMT_AD``
  Attribute - Deallocate




.. c:enum:: nvme_resv_rtype

   Reservation Type Encoding

**Constants**

``NVME_RESERVATION_RTYPE_WE``
  Write Exclusive Reservation

``NVME_RESERVATION_RTYPE_EA``
  Exclusive Access Reservation

``NVME_RESERVATION_RTYPE_WERO``
  Write Exclusive - Registrants Only Reservation

``NVME_RESERVATION_RTYPE_EARO``
  Exclusive Access - Registrants Only Reservation

``NVME_RESERVATION_RTYPE_WEAR``
  Write Exclusive - All Registrants Reservation

``NVME_RESERVATION_RTYPE_EAAR``
  Exclusive Access - All Registrants Reservation




.. c:enum:: nvme_resv_racqa

   Reservation Acquire - Reservation Acquire Action

**Constants**

``NVME_RESERVATION_RACQA_ACQUIRE``
  Acquire

``NVME_RESERVATION_RACQA_PREEMPT``
  Preempt

``NVME_RESERVATION_RACQA_PREEMPT_AND_ABORT``
  Preempt and Abort




.. c:enum:: nvme_resv_rrega

   Reservation Register - Reservation Register Action

**Constants**

``NVME_RESERVATION_RREGA_REGISTER_KEY``
  Register Reservation Key

``NVME_RESERVATION_RREGA_UNREGISTER_KEY``
  Unregister Reservation Key

``NVME_RESERVATION_RREGA_REPLACE_KEY``
  Replace Reservation Key




.. c:enum:: nvme_resv_cptpl

   Reservation Register - Change Persist Through Power Loss State

**Constants**

``NVME_RESERVATION_CPTPL_NO_CHANGE``
  No change to PTPL state

``NVME_RESERVATION_CPTPL_CLEAR``
  Reservations are released and
  registrants are cleared on a power on

``NVME_RESERVATION_CPTPL_PERSIST``
  Reservations and registrants persist
  across a power loss




.. c:enum:: nvme_resv_rrela

   Reservation Release - Reservation Release Action

**Constants**

``NVME_RESERVATION_RRELA_RELEASE``
  Release

``NVME_RESERVATION_RRELA_CLEAR``
  Clear




.. c:enum:: nvme_cancel_acode

   Cancel - Action Code (ACODE)

**Constants**

``NVME_CANCEL_ACODE_SINGLE_CMD``
  Single Command Cancel

``NVME_CANCEL_ACODE_MULTIPLE_CMD``
  Multiple Command Cancel




.. c:enum:: nvme_cancel_cqe_dw0

   Cancel - Completion Queue Entry Dword 0

**Constants**

``NVME_CANCEL_CQE_CMDA_SHIFT``
  Shift amount to get Commands Aborted (CMDA)

``NVME_CANCEL_CQE_CMDA_MASK``
  Mask to get CMDA

``NVME_CANCEL_CQE_CEDA_SHIFT``
  Shift amount to get Commands Eligible for
  Deferred Abort (CEDA)

``NVME_CANCEL_CQE_CEDA_MASK``
  Mask to get CEDA




.. c:enum:: nvme_io_mgmt_recv_mo

   I/O Management Receive - Management Operation

**Constants**

``NVME_IO_MGMT_RECV_RUH_STATUS``
  Reclaim Unit Handle Status




.. c:enum:: nvme_io_mgmt_send_mo

   I/O Management Send - Management Operation

**Constants**

``NVME_IO_MGMT_SEND_RUH_UPDATE``
  Reclaim Unit Handle Update




.. c:enum:: nvme_rate_limiting_bw_scale

   Rate Limiting Bandwidth Scale Factors (BWS)

**Constants**

``NVME_RATE_LIMITING_BW_SCALE_1MIB``
  1 MiB/second

``NVME_RATE_LIMITING_BW_SCALE_10MIB``
  10 MiB/second

``NVME_RATE_LIMITING_BW_SCALE_100MIB``
  100 MiB/second

``NVME_RATE_LIMITING_BW_SCALE_1GIB``
  1 GiB/second

``NVME_RATE_LIMITING_BW_SCALE_10GIB``
  10 GiB/second

``NVME_RATE_LIMITING_BW_SCALE_100GIB``
  100 GiB/second




.. c:enum:: nvme_rate_limiting_mode

   Rate Limiting Control - Rate Limiting Mode (RLM)

**Constants**

``NVME_RATE_LIMITING_MODE_HARD_LIMIT``
  Hard Limit mode

``NVME_RATE_LIMITING_MODE_SOFT_LIMIT``
  Soft Limit mode




.. c:enum:: nvme_rate_limiting_rlc

   Rate Limiting Data Buffer - Rate Limits Control (RLC)

**Constants**

``NVME_RATE_LIMITING_RLC_RLM_SHIFT``
  Shift amount to get/set the Rate
  Limiting Mode (RLM), see :c:type:`enum
  nvme_rate_limiting_mode <nvme_rate_limiting_mode>`

``NVME_RATE_LIMITING_RLC_RLM_MASK``
  Mask to get/set RLM

``NVME_RATE_LIMITING_RLC_RLE_SHIFT``
  Shift amount to get/set the Rate
  Limiting Enable (RLE)

``NVME_RATE_LIMITING_RLC_RLE_MASK``
  Mask to get/set RLE




.. c:struct:: nvme_rate_limiting_data

   Rate Limiting Feature - Data Buffer (RLDB)

**Definition**

::

  struct nvme_rate_limiting_data {
    __le16 rlc;
    __u8 rsvd2[5];
    __u8 bwsf;
    __le64 tbwv;
    __le64 wbwv;
    __le32 tiops;
    __le32 wiops;
    __u8 riopsr;
    __u8 wiopsr;
    __u8 rbwr;
    __u8 wbwr;
    __u8 rsvd36[476];
    __u8 vs[512];
  };

**Members**

``rlc``
  Rate Limits Control, see :c:type:`enum nvme_rate_limiting_rlc <nvme_rate_limiting_rlc>`

``rsvd2``
  Reserved

``bwsf``
  Bandwidth Scale Factor, see :c:type:`enum nvme_rate_limiting_bw_scale <nvme_rate_limiting_bw_scale>`

``tbwv``
  Total Bandwidth Value

``wbwv``
  Write Bandwidth Value

``tiops``
  Total IOPS

``wiops``
  Write IOPS

``riopsr``
  Read IOPS Ratio portion of the Write to Read IOPS Ratio, non-zero

``wiopsr``
  Write IOPS Ratio portion of the Write to Read IOPS Ratio, non-zero

``rbwr``
  Read Bandwidth Ratio portion of the Write to Read Bandwidth Ratio, non-zero

``wbwr``
  Write Bandwidth Ratio portion of the Write to Read Bandwidth Ratio, non-zero

``rsvd36``
  Reserved

``vs``
  Vendor Specific





.. c:struct:: nvme_rate_limiting_max_access_descriptor

   Rate Limiting Maximum Access Descriptor (QMAD)

**Definition**

::

  struct nvme_rate_limiting_max_access_descriptor {
    __u8 mbsf;
    __u8 rsvd1[7];
    __le64 mrbwv;
    __le64 mwbwv;
    __le32 mriops;
    __le32 mwiops;
  };

**Members**

``mbsf``
  Maximum Bandwidth Scale Factor, see :c:type:`enum nvme_rate_limiting_bw_scale <nvme_rate_limiting_bw_scale>`

``rsvd1``
  Reserved

``mrbwv``
  Maximum Read Bandwidth Value, shall not be cleared to 0h

``mwbwv``
  Maximum Write Bandwidth Value, shall not be cleared to 0h

``mriops``
  Maximum Random Read IOPS, shall not be cleared to 0h

``mwiops``
  Maximum Random Write IOPS, shall not be cleared to 0h





.. c:enum:: nvme_rate_limiting_scope

   Non-Volatile Storage Medium Access Descriptor - Scope (SC)

**Constants**

``NVME_RATE_LIMITING_SCOPE_NVM_SUBSYSTEM``
  NVM subsystem

``NVME_RATE_LIMITING_SCOPE_DOMAIN``
  Domain

``NVME_RATE_LIMITING_SCOPE_ENDURANCE_GROUP``
  Endurance Group

``NVME_RATE_LIMITING_SCOPE_NAMESPACE``
  Namespace




.. c:struct:: nvme_non_volatile_storage_medium_access_descriptor

   Non-Volatile Storage Medium Access Descriptor (QNSED)

**Definition**

::

  struct nvme_non_volatile_storage_medium_access_descriptor {
    __u8 sc;
    __u8 rsvd1;
    __le16 nnsmad;
    __le32 si;
    struct nvme_rate_limiting_max_access_descriptor rlma;
    __u8 rsvd40[24];
    __le32 nvsma_offset[];
  };

**Members**

``sc``
  Scope, see :c:type:`enum nvme_rate_limiting_scope <nvme_rate_limiting_scope>`

``rsvd1``
  Reserved

``nnsmad``
  Number of Non-Volatile Storage Medium Access Descriptors in
  **nvsma_offset**, cleared to 0h if **sc** is NVM subsystem or the
  NVM subsystem supports a single domain

``si``
  Scope Identifier for the scope indicated by **sc**

``rlma``
  Rate Limiting Maximum Access for the scope indicated by **sc**

``rsvd40``
  Reserved

``nvsma_offset``
  Dword offsets, relative to the start of the Rate Limiting
  log page, to the nested Non-Volatile Storage Medium Access
  Descriptors, **nnsmad** entries





.. c:struct:: nvme_rate_limiting_controller_descriptor

   Rate Limiting Controller Descriptor (QCD)

**Definition**

::

  struct nvme_rate_limiting_controller_descriptor {
    __le16 cntlid;
    __le16 nnsmad;
    __u8 rsvd4[4];
    struct nvme_rate_limiting_max_access_descriptor rlma;
    __u8 rsvd40[24];
    __u8 vs[256];
    __le32 nvsma_offset[];
  };

**Members**

``cntlid``
  Controller Identifier

``nnsmad``
  Number of Non-Volatile Storage Medium Access Descriptors in
  **nvsma_offset**, non-zero

``rsvd4``
  Reserved

``rlma``
  Rate Limiting Maximum Access of the controller to the NVM
  subsystem port

``rsvd40``
  Reserved

``vs``
  Vendor Specific

``nvsma_offset``
  Dword offsets, relative to the start of the Rate Limiting
  log page, to the Non-Volatile Storage Medium Access
  Descriptors, **nnsmad** entries





.. c:struct:: nvme_rate_limiting_port_descriptor

   Rate Limiting Port Descriptor (QPD)

**Definition**

::

  struct nvme_rate_limiting_port_descriptor {
    __le16 portid;
    __le16 nc;
    __u8 rsvd4[3];
    __u8 abwsf;
    struct nvme_rate_limiting_max_access_descriptor rlma;
    __le64 arbwv;
    __le64 awbwv;
    __le32 ariops;
    __le32 awiops;
    __u8 rsvd64[448];
    __u8 vs[512];
    __le32 rlc_offset[];
  };

**Members**

``portid``
  NVM subsystem Port Identifier

``nc``
  Number of Controllers in **rlc_offset** (0's based)

``rsvd4``
  Reserved

``abwsf``
  Available Bandwidth Scale Factor, see :c:type:`enum nvme_rate_limiting_bw_scale <nvme_rate_limiting_bw_scale>`

``rlma``
  Rate Limiting Maximum Access to the non-volatile storage
  medium of the port

``arbwv``
  Available Read Bandwidth Value of the NVM subsystem to the transport

``awbwv``
  Available Write Bandwidth Value of the NVM subsystem to the transport

``ariops``
  Available Read IOPS of the NVM subsystem to the transport

``awiops``
  Available Write IOPS of the NVM subsystem to the transport

``rsvd64``
  Reserved

``vs``
  Vendor Specific

``rlc_offset``
  Dword offsets, relative to the start of the Rate Limiting log
  page, to the Rate Limiting Controller Descriptors accessible
  by this port, **nc** + 1 entries





.. c:struct:: nvme_rate_limiting_log

   Rate Limiting log page (Log Page Identifier 28h)

**Definition**

::

  struct nvme_rate_limiting_log {
    __u8 rsvd0[2];
    __le16 np;
    __le32 lpl;
    __le32 gc;
    __le16 nst;
    __u8 rsvd14[2];
    __le32 port_offset[];
  };

**Members**

``rsvd0``
  Reserved

``np``
  Number of Ports in **port_offset** (0's based)

``lpl``
  Log Page Length, in dwords, of this log page

``gc``
  Generation Count, incremented each time the information in
  this log page changes since the last time the host read it

``nst``
  Number of Supported Targets (0's based)

``rsvd14``
  Reserved

``port_offset``
  Dword offsets, relative to the start of this log page, to
  the Rate Limiting Port Descriptors, **np** + 1 entries.
  The Rate Limiting Data (referenced by these and nested
  offsets), the Supported Target list, and trailing padding
  follow this array and are located using **lpl**, **np**, and **nst**.



