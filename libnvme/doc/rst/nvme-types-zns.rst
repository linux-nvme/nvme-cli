.. _nvme-types-zns.h:

**nvme-types-zns.h**


Zoned Namespace Command Set type definitions

Based on NVM Express Zoned Namespace Command Set Specification,
Revision 1.4, August 1, 2025 (Ratified)



.. c:struct:: nvme_zns_lbafe

   LBA Format Extension Data Structure

**Definition**

::

  struct nvme_zns_lbafe {
    __le64 zsze;
    __u8 zdes;
    __u8 rsvd9[7];
  };

**Members**

``zsze``
  Zone Size

``zdes``
  Zone Descriptor Extension Size

``rsvd9``
  reserved





.. c:enum:: nvme_zns_id_ns_zoc

   Zone Operation Characteristics

**Constants**

``NVME_ZNS_ID_NS_ZOC_VZC_SHIFT``
  Shift amount to get Variable Zone
  Capacity (VZC)

``NVME_ZNS_ID_NS_ZOC_VZC_MASK``
  Mask to get VZC

``NVME_ZNS_ID_NS_ZOC_ZAE_SHIFT``
  Shift amount to get Zone Active
  Excursions (ZAE)

``NVME_ZNS_ID_NS_ZOC_ZAE_MASK``
  Mask to get ZAE




.. c:enum:: nvme_zns_id_ns_ozcs

   Optional Zoned Command Support

**Constants**

``NVME_ZNS_ID_NS_OZCS_RAZB_SHIFT``
  Shift amount to get Read Across Zone
  Boundaries (RAZB)

``NVME_ZNS_ID_NS_OZCS_RAZB_MASK``
  Mask to get RAZB

``NVME_ZNS_ID_NS_OZCS_ZRWASUP_SHIFT``
  Shift amount to get ZRWA Supported
  (ZRWASUP)

``NVME_ZNS_ID_NS_OZCS_ZRWASUP_MASK``
  Mask to get ZRWASUP




.. c:enum:: nvme_zns_id_ns_zrwacap

   ZRWA Capability

**Constants**

``NVME_ZNS_ID_NS_ZRWACAP_EXPFLUSHSUP_SHIFT``
  Shift amount to get Explicit
  Flush Support (EXPFLUSHSUP)

``NVME_ZNS_ID_NS_ZRWACAP_EXPFLUSHSUP_MASK``
  Mask to get EXPFLUSHSUP




.. c:struct:: nvme_zns_id_ns

   Zoned Namespace Command Set Specific Identify Namespace Data Structure

**Definition**

::

  struct nvme_zns_id_ns {
    __le16 zoc;
    __le16 ozcs;
    __le32 mar;
    __le32 mor;
    __le32 rrl;
    __le32 frl;
    __le32 rrl1;
    __le32 rrl2;
    __le32 rrl3;
    __le32 frl1;
    __le32 frl2;
    __le32 frl3;
    __le32 numzrwa;
    __le16 zrwafg;
    __le16 zrwasz;
    __u8 zrwacap;
    __u8 rsvd53[2763];
    struct nvme_zns_lbafe   lbafe[64];
    __u8 vs[256];
  };

**Members**

``zoc``
  Zone Operation Characteristics, see :c:type:`enum nvme_zns_id_ns_zoc <nvme_zns_id_ns_zoc>`

``ozcs``
  Optional Zoned Command Support, see :c:type:`enum nvme_zns_id_ns_ozcs <nvme_zns_id_ns_ozcs>`

``mar``
  Maximum Active Resources

``mor``
  Maximum Open Resources

``rrl``
  Reset Recommended Limit

``frl``
  Finish Recommended Limit

``rrl1``
  Reset Recommended Limit 1

``rrl2``
  Reset Recommended Limit 2

``rrl3``
  Reset Recommended Limit 3

``frl1``
  Finish Recommended Limit 1

``frl2``
  Finish Recommended Limit 2

``frl3``
  Finish Recommended Limit 3

``numzrwa``
  Number of ZRWA Resources

``zrwafg``
  ZRWA Flush Granularity

``zrwasz``
  ZRWA Size

``zrwacap``
  ZRWA Capability, see :c:type:`enum nvme_zns_id_ns_zrwacap <nvme_zns_id_ns_zrwacap>`

``rsvd53``
  Reserved

``lbafe``
  LBA Format Extension

``vs``
  Vendor Specific





.. c:enum:: nvme_zns_id_ctrl_zctratt

   Zoned Controller Attributes

**Constants**

``NVME_ZNS_CTRL_ZCTRATT_ZNRM_SHIFT``
  Shift amount to get Zoned Namespace
  Resource Management (ZNRM)

``NVME_ZNS_CTRL_ZCTRATT_ZNRM_MASK``
  Mask to get ZNRM




.. c:struct:: nvme_zns_id_ctrl

   I/O Command Set Specific Identify Controller Data Structure for the Zoned Namespace Command Set

**Definition**

::

  struct nvme_zns_id_ctrl {
    __u8 zasl;
    __u8 rsvd1[3];
    __le32 zctratt;
    __le32 tar;
    __le32 uar;
    __le32 tor;
    __le32 uor;
    __le32 tzrwar;
    __le32 uzrwar;
    __le32 ver;
    __u8 rsvd36[4060];
  };

**Members**

``zasl``
  Zone Append Size Limit

``rsvd1``
  Reserved

``zctratt``
  Zoned Controller Attributes, see :c:type:`enum nvme_zns_id_ctrl_zctratt <nvme_zns_id_ctrl_zctratt>`

``tar``
  Total Active Resources

``uar``
  Unallocated Active Resources

``tor``
  Total Open Resources

``uor``
  Unallocated Open Resources

``tzrwar``
  Total ZRWA Resources

``uzrwar``
  Unallocated ZRWA Resources

``ver``
  Version, a Specification Version Descriptor, see
  ``NVME_MAJOR``, ``NVME_MINOR``, ``NVME_TERTIARY``

``rsvd36``
  Reserved





.. c:struct:: nvme_zns_changed_zone_log

   ZNS Changed Zone List log

**Definition**

::

  struct nvme_zns_changed_zone_log {
    __le16 nrzid;
    __u8 rsvd2[6];
    __le64 zid[NVME_ZNS_CHANGED_ZONES_MAX];
  };

**Members**

``nrzid``
  Number of Zone Identifiers

``rsvd2``
  Reserved

``zid``
  Zone Identifier





.. c:enum:: nvme_zns_zt

   Zone Descriptor Data Structure - Zone Type Attributes

**Constants**

``NVME_ZNS_DESC_ZT_SHIFT``
  Shift amount to get the Zone Type (ZT)
  from the :c:type:`struct nvme_zns_desc <nvme_zns_desc>`.zt field.

``NVME_ZNS_DESC_ZT_MASK``
  Mask to get ZT from the
  :c:type:`struct nvme_zns_desc <nvme_zns_desc>`.zt field.

``NVME_ZONE_TYPE_SEQWRITE_REQ``
  Sequential Write Required




.. c:enum:: nvme_zns_za

   Zone Descriptor Data Structure

**Constants**

``NVME_ZNS_ZA_ZFC``
  Zone Finished by Controller

``NVME_ZNS_ZA_FZR``
  Finish Zone Recommended

``NVME_ZNS_ZA_RZR``
  Reset Zone Recommended

``NVME_ZNS_ZA_ZRWAV``

``NVME_ZNS_ZA_ZDEV``
  Zone Descriptor Extension Valid




.. c:enum:: nvme_zns_zs

   Zone Descriptor Data Structure - Zone State Attributes

**Constants**

``NVME_ZNS_DESC_ZS_SHIFT``
  Shift amount to get the Zone State (ZS) from
  the :c:type:`struct nvme_zns_desc <nvme_zns_desc>`.zs field.

``NVME_ZNS_DESC_ZS_MASK``
  Mask to get ZS from the
  :c:type:`struct nvme_zns_desc <nvme_zns_desc>`.zs field.

``NVME_ZNS_ZS_EMPTY``
  Empty state

``NVME_ZNS_ZS_IMPL_OPEN``
  Implicitly open state

``NVME_ZNS_ZS_EXPL_OPEN``
  Explicitly open state

``NVME_ZNS_ZS_CLOSED``
  Closed state

``NVME_ZNS_ZS_READ_ONLY``
  Read only state

``NVME_ZNS_ZS_FULL``
  Full state

``NVME_ZNS_ZS_OFFLINE``
  Offline state




.. c:enum:: nvme_zns_zai

   Zone Descriptor Data Structure - Zone Attributes Information

**Constants**

``NVME_ZNS_ZAI_RZRTL_SHIFT``
  Shift amount to get the Reset Zone
  Recommended Time Limit (RZRTL) from the
  :c:type:`struct nvme_zns_desc <nvme_zns_desc>`.zai field.

``NVME_ZNS_ZAI_RZRTL_MASK``
  Mask to get RZRTL from the
  :c:type:`struct nvme_zns_desc <nvme_zns_desc>`.zai field.

``NVME_ZNS_ZAI_FZRTL_SHIFT``
  Shift amount to get the Finish Zone
  Recommended Time Limit (FZRTL) from the
  :c:type:`struct nvme_zns_desc <nvme_zns_desc>`.zai field.

``NVME_ZNS_ZAI_FZRTL_MASK``
  Mask to get FZRTL from the
  :c:type:`struct nvme_zns_desc <nvme_zns_desc>`.zai field.

``NVME_ZNS_ZAI_RTL_0``
  Reset/Finish Recommended Limit (RRL/FRL)

``NVME_ZNS_ZAI_RTL_1``
  Reset/Finish Recommended Limit 1 (RRL1/FRL1)

``NVME_ZNS_ZAI_RTL_2``
  Reset/Finish Recommended Limit 2 (RRL2/FRL2)

``NVME_ZNS_ZAI_RTL_3``
  Reset/Finish Recommended Limit 3 (RRL3/FRL3)




.. c:struct:: nvme_zns_desc

   Zone Descriptor Data Structure

**Definition**

::

  struct nvme_zns_desc {
    __u8 zt;
    __u8 zs;
    __u8 za;
    __u8 zai;
    __u8 rsvd4[4];
    __le64 zcap;
    __le64 zslba;
    __le64 wp;
    __u8 rsvd32[32];
  };

**Members**

``zt``
  Zone Type Attributes, ZT is bits 3:0, see :c:type:`enum nvme_zns_zt <nvme_zns_zt>`

``zs``
  Zone State Attributes, ZS is bits 7:4, see :c:type:`enum nvme_zns_zs <nvme_zns_zs>`

``za``
  Zone Attributes, see :c:type:`enum nvme_zns_za <nvme_zns_za>`

``zai``
  Zone Attributes Information, see :c:type:`enum nvme_zns_zai <nvme_zns_zai>`

``rsvd4``
  Reserved

``zcap``
  Zone Capacity

``zslba``
  Zone Start Logical Block Address

``wp``
  Write Pointer

``rsvd32``
  Reserved





.. c:struct:: nvme_zone_report

   Report Zones Data Structure

**Definition**

::

  struct nvme_zone_report {
    __le64 nr_zones;
    __u8 rsvd8[56];
    struct nvme_zns_desc    entries[];
  };

**Members**

``nr_zones``
  Number of descriptors in **entries**

``rsvd8``
  Reserved

``entries``
  Zoned namespace descriptors





.. c:enum:: nvme_zns_send_action

   Zone Management Send - Zone Send Action

**Constants**

``NVME_ZNS_ZSA_CLOSE``
  Close Zone

``NVME_ZNS_ZSA_FINISH``
  Finish Zone

``NVME_ZNS_ZSA_OPEN``
  Open Zone

``NVME_ZNS_ZSA_RESET``
  Reset Zone

``NVME_ZNS_ZSA_OFFLINE``
  Offline Zone

``NVME_ZNS_ZSA_SET_DESC_EXT``
  Set Zone Descriptor Extension

``NVME_ZNS_ZSA_ZRWA_FLUSH``
  Flush




.. c:enum:: nvme_zns_recv_action

   Zone Management Receive - Zone Receive Action Specific Features

**Constants**

``NVME_ZNS_ZRA_REPORT_ZONES``
  Report Zones

``NVME_ZNS_ZRA_EXTENDED_REPORT_ZONES``
  Extended Report Zones




.. c:enum:: nvme_zns_report_options

   Zone Management Receive - Zone Receive Action Specific Field

**Constants**

``NVME_ZNS_ZRAS_REPORT_ALL``
  List all zones

``NVME_ZNS_ZRAS_REPORT_EMPTY``
  List the zones in the ZSE:Empty state

``NVME_ZNS_ZRAS_REPORT_IMPL_OPENED``
  List the zones in the ZSIO:Implicitly Opened state

``NVME_ZNS_ZRAS_REPORT_EXPL_OPENED``
  List the zones in the ZSEO:Explicitly Opened state

``NVME_ZNS_ZRAS_REPORT_CLOSED``
  List the zones in the ZSC:Closed state

``NVME_ZNS_ZRAS_REPORT_FULL``
  List the zones in the ZSF:Full state

``NVME_ZNS_ZRAS_REPORT_READ_ONLY``
  List the zones in the ZSRO:Read Only state

``NVME_ZNS_ZRAS_REPORT_OFFLINE``
  List the zones in the ZSO:Offline state




.. c:enum:: nvme_zns_mgmt_send_cqe_dw0

   Zone Management Send - Completion Queue Entry Dword 0

**Constants**

``NVME_ZNS_MGMT_SEND_CQE_ZCC_SHIFT``
  Shift amount to get Zone Capacity
  Changed (ZCC)

``NVME_ZNS_MGMT_SEND_CQE_ZCC_MASK``
  Mask to get ZCC


