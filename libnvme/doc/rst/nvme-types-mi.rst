.. _nvme-types-mi.h - NVMe-MI data structure type definitions:

**nvme-types-mi.h - NVMe-MI data structure type definitions**


NVMe Management Interface type definitions

Based on NVM Express Management Interface Specification,
Revision 2.1, August 1, 2025 (Ratified)

This file contains core NVMe types organized by functional area:
- MI command data structures (controller info, port info, etc.)
- Health status structures (subsystem and controller health)
- VPD (Vital Product Data) structures
- MI log page structures
- Command effects and capabilities
- Spec-defined data payloads
- Response status values



.. c:enum:: nvme_mi_cmd_supported_effects

   MI Command Supported and Effects Data Structure

**Constants**

``NVME_MI_CMD_SUPPORTED_EFFECTS_CSUPP``
  Command Supported

``NVME_MI_CMD_SUPPORTED_EFFECTS_UDCC``
  User Data Content Change

``NVME_MI_CMD_SUPPORTED_EFFECTS_NCC``
  Namespace Capability Change

``NVME_MI_CMD_SUPPORTED_EFFECTS_NIC``
  Namespace Inventory Change

``NVME_MI_CMD_SUPPORTED_EFFECTS_CCC``
  Controller Capability Change

``NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_SHIFT``
  20 bit shift

``NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_MASK``
  12 bit mask - 0xfff

``NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NS``
  Namespace Scope

``NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_CTRL``
  Controller Scope

``NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NVM_SET``
  NVM Set Scope

``NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_ENDGRP``
  Endurance Group Scope

``NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_DOMAIN``
  Domain Scope

``NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NSS``
  NVM Subsystem Scope




.. c:struct:: nvme_mi_cmd_supported_effects_log

   NVMe-MI Commands Supported and Effects Log

**Definition**

::

  struct nvme_mi_cmd_supported_effects_log {
    __le32 mi_cmd_support[NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_MAX];
    __le32 rsvd128[NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_RESERVED];
  };

**Members**

``mi_cmd_support``
  NVMe-MI Commands Supported

``rsvd128``
  Reserved





.. c:struct:: nvme_mi_read_nvm_ss_info

   NVM Subsystem Information Data Structure

**Definition**

::

  struct nvme_mi_read_nvm_ss_info {
    __u8 nump;
    __u8 mjr;
    __u8 mnr;
    __u8 rsvd3[29];
  };

**Members**

``nump``
  Number of Ports

``mjr``
  NVMe-MI Major Version Number

``mnr``
  NVMe-MI Minor Version Number

``rsvd3``
  Reserved





.. c:struct:: nvme_mi_port_pcie

   PCIe Port Specific Data

**Definition**

::

  struct nvme_mi_port_pcie {
    __u8 mps;
    __u8 sls;
    __u8 cls;
    __u8 mlw;
    __u8 nlw;
    __u8 pn;
    __u8 rsvd14[18];
  };

**Members**

``mps``
  PCIe Maximum Payload Size

``sls``
  PCIe Supported Link Speeds Vector

``cls``
  PCIe Current Link Speed

``mlw``
  PCIe Maximum Link Width

``nlw``
  PCIe Negotiated Link Width

``pn``
  PCIe Port Number

``rsvd14``
  Reserved





.. c:enum:: nvme_mi_port_sdformat

   2-Wire Port Specific Data - Supported Data Format (SDFORMAT)

**Constants**

``NVME_MI_PORT_SDFORMAT_BYTE_LEVEL``
  Byte Level data format of the
  NVMe-MI Persistent Data Area is
  supported

``NVME_MI_PORT_SDFORMAT_512B``
  512B data format of the NVMe-MI
  Persistent Data Area is supported

``NVME_MI_PORT_SDFORMAT_4KIB``
  4KiB data format of the NVMe-MI
  Persistent Data Area is supported




.. c:struct:: nvme_mi_port_smb

   SMBus Port Specific Data

**Definition**

::

  struct nvme_mi_port_smb {
    __u8 vpd_addr;
    __u8 mvpd_freq;
    __u8 mme_addr;
    __u8 mme_freq;
    __u8 nvmebm;
    __le32 pdas ;
    __u8 sdformat;
    __u8 rsvd18[14];
  };

**Members**

``vpd_addr``
  Current VPD SMBus/I2C Address

``mvpd_freq``
  Maximum VPD Access SMBus/I2C Frequency

``mme_addr``
  Current Management Endpoint SMBus/I2C Address

``mme_freq``
  Maximum Management Endpoint SMBus/I2C Frequency

``nvmebm``
  NVMe Basic Management

``pdas``
  PDA Size, the size of the NVMe-MI Persistent Data Area (PDA)
  is 2^**pdas** bytes; 0h indicates there is no NVMe-MI PDA

``sdformat``
  Supported Data Format for the NVMe-MI PDA, see :c:type:`enum
  nvme_mi_port_sdformat <nvme_mi_port_sdformat>`

``rsvd18``
  Reserved





.. c:enum:: nvme_mi_port_prtcap

   Port Information Data Structure - Port Capabilities (PRTCAP)

**Constants**

``NVME_MI_PORT_PRTCAP_CIAPS``
  Command Initiated Auto Pause Supported:
  obsolete as of NVMe-MI 2.2 and later (the
  Command Initiated Auto Pause bit in Command
  Messages is always supported); this bit is
  set to '1'.

``NVME_MI_PORT_PRTCAP_AEMS``
  Asynchronous Event Messages Supported: if set,
  then all Management Endpoints on this port
  support AEMs and the Asynchronous Event
  configuration (Configuration Identifier 04h).




.. c:struct:: nvme_mi_read_port_info

   Port Information Data Structure

**Definition**

::

  struct nvme_mi_read_port_info {
    __u8 portt;
    __u8 prtcap;
    __le16 mmctptus;
    __le32 meb;
    union {
      struct nvme_mi_port_pcie pcie;
      struct nvme_mi_port_smb smb;
    };
  };

**Members**

``portt``
  Port Type

``prtcap``
  Port Capabilities, see :c:type:`enum nvme_mi_port_prtcap <nvme_mi_port_prtcap>`.

``mmctptus``
  Maximum MCTP Transmission Unit Size

``meb``
  Management Endpoint Buffer Size

``{unnamed_union}``
  anonymous

``pcie``
  PCIe Port Specific Data

``smb``
  SMBus Port Specific Data





.. c:struct:: nvme_mi_read_ctrl_info

   Controller Information Data Structure

**Definition**

::

  struct nvme_mi_read_ctrl_info {
    __u8 portid;
    __u8 rsvd1[4];
    __u8 prii;
    __le16 pri;
    __le16 vid;
    __le16 did;
    __le16 ssvid;
    __le16 ssid;
    __u8 rsvd16[16];
  };

**Members**

``portid``
  Port Identifier

``rsvd1``
  Reserved

``prii``
  PCIe Routing ID Information

``pri``
  PCIe Routing ID

``vid``
  PCI Vendor ID

``did``
  PCI Device ID

``ssvid``
  PCI Subsystem Vendor ID

``ssid``
  PCI Subsystem Device ID

``rsvd16``
  Reserved





.. c:struct:: nvme_mi_osc

   Optionally Supported Command Data Structure

**Definition**

::

  struct nvme_mi_osc {
    __u8 type;
    __u8 opc;
  };

**Members**

``type``
  Command Type

``opc``
  Opcode





.. c:struct:: nvme_mi_read_sc_list

   Management Endpoint Buffer Supported Command List Data Structure

**Definition**

::

  struct nvme_mi_read_sc_list {
    __le16 numcmd;
    struct nvme_mi_osc cmds[];
  };

**Members**

``numcmd``
  Number of Commands

``cmds``
  MEB supported Command Data Structure.
  See **struct** nvme_mi_osc





.. c:enum:: nvme_mi_nss

   NVM Subsystem Status

**Constants**

``NVME_MI_NSS_NRDY_SHIFT``
  Shift amount to get Not Ready

``NVME_MI_NSS_NRDY_MASK``
  Mask to get Not Ready

``NVME_MI_NSS_DRV_SHIFT``
  Shift amount to get Drive Ready

``NVME_MI_NSS_DRV_MASK``
  Mask to get Drive Ready




.. c:enum:: nvme_mi_sw

   Smart Warnings

**Constants**

``NVME_MI_SW_ST_SHIFT``
  Shift amount to get Spare Threshold

``NVME_MI_SW_ST_MASK``
  Mask to get Spare Threshold

``NVME_MI_SW_TAUT_SHIFT``
  Shift amount to get Temperature Above or Under Threshold

``NVME_MI_SW_TAUT_MASK``
  Mask to get Temperature Above or Under Threshold

``NVME_MI_SW_RD_SHIFT``
  Shift amount to get Reliability Degraded

``NVME_MI_SW_RD_MASK``
  Mask to get Reliability Degraded

``NVME_MI_SW_RO_SHIFT``
  Shift amount to get Read Only

``NVME_MI_SW_RO_MASK``
  Mask to get Read Only

``NVME_MI_SW_VMBF_SHIFT``
  Shift amount to get Volatile Memory Backup Failed

``NVME_MI_SW_VMBF_MASK``
  Mask to get Volatile Memory Backup Failed




.. c:struct:: nvme_mi_nvm_ss_health_status

   Subsystem Management Data Structure

**Definition**

::

  struct nvme_mi_nvm_ss_health_status {
    __u8 nss;
    __u8 sw;
    __u8 ctemp;
    __u8 pdlu;
    __le16 ccsf;
    __u8 rsvd8[2];
  };

**Members**

``nss``
  NVM Subsystem Status (see :c:type:`enum nvme_mi_nss <nvme_mi_nss>`)

``sw``
  Smart Warnings (see :c:type:`enum nvme_mi_sw <nvme_mi_sw>`)

``ctemp``
  Composite Temperature

``pdlu``
  Percentage Drive Life Used

``ccsf``
  Composite Controller Status Flags (see :c:type:`enum nvme_mi_ccsf <nvme_mi_ccsf>`)

``rsvd8``
  Reserved





.. c:enum:: nvme_mi_ccsf

   NVM Subsystem Health Data Structure (NSHDS) - Composite Controller Status Flags (CCSF)

**Constants**

``NVME_MI_CCSF_RDYF``
  Ready Flag

``NVME_MI_CCSF_CFSF``
  Controller Fatal Status Flag

``NVME_MI_CCSF_SHSTF``
  Shutdown Status Flag

``NVME_MI_CCSF_NSSROF``
  NVM Subsystem Reset Occurred Flag

``NVME_MI_CCSF_CECOF``
  Controller Enable Change Occurred Flag

``NVME_MI_CCSF_NACF``
  Namespace Attribute Changed Flag

``NVME_MI_CCSF_FAF``
  Firmware Activated Flag

``NVME_MI_CCSF_CSF``
  Controller Status Change Flag

``NVME_MI_CCSF_CTEMPF``
  Composite Temperature Change Flag

``NVME_MI_CCSF_PDLUF``
  Percentage Drive Life Used Flag

``NVME_MI_CCSF_SPAREF``
  Available Spare Flag

``NVME_MI_CCSF_CWARNF``
  Critical Warning Flag

``NVME_MI_CCSF_TCIDAF``
  Telemetry Controller-Initiated Data Available Flag




.. c:struct:: nvme_mi_ctrl_health_status

   Controller Health Data Structure (CHDS)

**Definition**

::

  struct nvme_mi_ctrl_health_status {
    __le16 ctlid;
    __le16 csts;
    __le16 ctemp;
    __u8 pdlu;
    __u8 spare;
    __u8 cwarn;
    __u8 chscf[2];
    __u8 rsvd11[5];
  };

**Members**

``ctlid``
  Controller Identifier

``csts``
  Controller Status

``ctemp``
  Composite Temperature

``pdlu``
  Percentage Used

``spare``
  Available Spare

``cwarn``
  Critical Warning

``chscf``
  Controller Health Status Changed Flags (see :c:type:`enum nvme_mi_chscf <nvme_mi_chscf>`)

``rsvd11``
  Reserved





.. c:enum:: nvme_mi_chscf

   Controller Health Data Structure (CHDS) - Controller Health Status Changed Flags (CHSCF)

**Constants**

``NVME_MI_CHSCF_RDYF``
  Ready Flag

``NVME_MI_CHSCF_CFSF``
  Controller Fatal Status Flag

``NVME_MI_CHSCF_SHSTF``
  Shutdown Status Flag

``NVME_MI_CHSCF_NSSROF``
  NVM Subsystem Reset Occurred Flag

``NVME_MI_CHSCF_CECOF``
  Controller Enable Change Occurred Flag

``NVME_MI_CHSCF_NACF``
  Namespace Attribute Changed Flag

``NVME_MI_CHSCF_FAF``
  Firmware Activated Flag

``NVME_MI_CHSCF_CSF``
  Controller Status Change Flag

``NVME_MI_CHSCF_CTEMPF``
  Composite Temperature Change Flag

``NVME_MI_CHSCF_PDLUF``
  Percentage Drive Life Used Flag

``NVME_MI_CHSCF_SPAREF``
  Available Spare Flag

``NVME_MI_CHSCF_CWARNF``
  Critical Warning Flag

``NVME_MI_CHSCF_TCIDAF``
  Telemetry Controller-Initiated Data Available Flag




.. c:enum:: nvme_mi_csts

   Controller Health Data Structure (CHDS) - Controller Status (CSTS)

**Constants**

``NVME_MI_CSTS_RDY``
  Ready

``NVME_MI_CSTS_CFS``
  Controller Fatal Status

``NVME_MI_CSTS_SHST``
  Shutdown Status

``NVME_MI_CSTS_NSSRO``
  NVM Subsystem Reset Occurred

``NVME_MI_CSTS_CECO``
  Controller Enable Change Occurred

``NVME_MI_CSTS_NAC``
  Namespace Attribute Changed

``NVME_MI_CSTS_FA``
  Firmware Activated




.. c:enum:: nvme_mi_cwarn

   Controller Health Data Structure (CHDS) - Critical Warning (CWARN)

**Constants**

``NVME_MI_CWARN_ST``
  Spare Threshold

``NVME_MI_CWARN_TAUT``
  Temperature Above or Under Threshold

``NVME_MI_CWARN_RD``
  Reliability Degraded

``NVME_MI_CWARN_RO``
  Read Only

``NVME_MI_CWARN_VMBF``
  Volatile Memory Backup Failed




.. c:struct:: nvme_mi_vpd_mra

   NVMe MultiRecord Area

**Definition**

::

  struct nvme_mi_vpd_mra {
    __u8 nmravn;
    __u8 ff;
    __u8 rsvd7[6];
    __u8 i18vpwr;
    __u8 m18vpwr;
    __u8 i33vpwr;
    __u8 m33vpwr;
    __u8 rsvd17;
    __u8 m33vapsr;
    __u8 i5vapsr;
    __u8 m5vapsr;
    __u8 i12vapsr;
    __u8 m12vapsr;
    __u8 mtl;
    __u8 tnvmcap[16];
    __u8 rsvd37[27];
  };

**Members**

``nmravn``
  NVMe MultiRecord Area Version Number

``ff``
  Form Factor

``rsvd7``
  Reserved

``i18vpwr``
  Initial 1.8 V Power Supply Requirements

``m18vpwr``
  Maximum 1.8 V Power Supply Requirements

``i33vpwr``
  Initial 3.3 V Power Supply Requirements

``m33vpwr``
  Maximum 3.3 V Power Supply Requirements

``rsvd17``
  Reserved

``m33vapsr``
  Maximum 3.3 Vi aux Power Supply Requirements

``i5vapsr``
  Initial 5 V Power Supply Requirements

``m5vapsr``
  Maximum 5 V Power Supply Requirements

``i12vapsr``
  Initial 12 V Power Supply Requirements

``m12vapsr``
  Maximum 12 V Power Supply Requirements

``mtl``
  Maximum Thermal Load

``tnvmcap``
  Total NVM Capacity

``rsvd37``
  Reserved





.. c:struct:: nvme_mi_vpd_ppmra

   NVMe PCIe Port MultiRecord Area

**Definition**

::

  struct nvme_mi_vpd_ppmra {
    __u8 nppmravn;
    __u8 pn;
    __u8 ppi;
    __u8 ls;
    __u8 mlw;
    __u8 mctp;
    __u8 refccap;
    __u8 pi;
    __u8 rsvd13[3];
  };

**Members**

``nppmravn``
  NVMe PCIe Port MultiRecord Area Version Number

``pn``
  PCIe Port Number

``ppi``
  Port Information

``ls``
  PCIe Link Speed

``mlw``
  PCIe Maximum Link Width

``mctp``
  MCTP Support

``refccap``
  Ref Clk Capability

``pi``
  Port Identifier

``rsvd13``
  Reserved





.. c:struct:: nvme_mi_vpd_telem

   Vital Product Data Element Descriptor

**Definition**

::

  struct nvme_mi_vpd_telem {
    __u8 type;
    __u8 rev;
    __u8 len;
    __u8 data[0];
  };

**Members**

``type``
  Type of the Element Descriptor

``rev``
  Revision of the Element Descriptor

``len``
  Number of bytes in the Element Descriptor

``data``
  Type-specific information associated with
  the Element Descriptor





.. c:enum:: nvme_mi_elem

   Element Descriptor Types

**Constants**

``NVME_MI_ELEM_EED``
  Extended Element Descriptor

``NVME_MI_ELEM_USCE``
  Upstream Connector Element Descriptor

``NVME_MI_ELEM_ECED``
  Expansion Connector Element Descriptor

``NVME_MI_ELEM_LED``
  Label Element Descriptor

``NVME_MI_ELEM_SMBMED``
  SMBus/I2C Mux Element Descriptor

``NVME_MI_ELEM_PCIESED``
  PCIe Switch Element Descriptor

``NVME_MI_ELEM_NVMED``
  NVM Subsystem Element Descriptor




.. c:enum:: nvme_mi_form_factor

   Upstream Connector Element Descriptor - Form Factor (FF) values

**Constants**

``NVME_MI_FF_UNKNOWN``
  Unspecified: Other - unknown

``NVME_MI_FF_PCIE_INTEGRATED``
  PCIe: Integrated

``NVME_MI_FF_PCIE_OTHER``
  PCIe: Other - unknown

``NVME_MI_FF_PCIE_2_5_UNKNOWN``
  PCIe: 2.5" Form Factor - unknown

``NVME_MI_FF_PCIE_2_5_U2_15MM``
  PCIe: 2.5" Form Factor - PCI Express
  SFF-8639 Module (U.2) 15 mm

``NVME_MI_FF_PCIE_2_5_U2_7MM``
  PCIe: 2.5" Form Factor - PCI Express
  SFF-8639 Module (U.2) 7 mm

``NVME_MI_FF_PCIE_2_5_SFF_TA_1001_15MM``
  PCIe: 2.5" Form Factor -
  (SFF-TA-1001) 15 mm

``NVME_MI_FF_PCIE_2_5_SFF_TA_1001_7MM``
  PCIe: 2.5" Form Factor -
  (SFF-TA-1001) 7 mm

``NVME_MI_FF_PCIE_CEM_UNKNOWN``
  PCIe: CEM add in card - unknown

``NVME_MI_FF_PCIE_CEM_HHHL``
  PCIe: CEM add in card - Low Profile
  (HHHL)

``NVME_MI_FF_PCIE_CEM_FHHL``
  PCIe: CEM add in card - Standard
  Height Half Length (FHHL)

``NVME_MI_FF_PCIE_CEM_FHFL``
  PCIe: CEM add in card - Standard
  Height Full Length (FHFL)

``NVME_MI_FF_PCIE_M2_UNKNOWN``
  PCIe: M.2 module - unknown

``NVME_MI_FF_PCIE_M2_2230``
  PCIe: M.2 module - 2230

``NVME_MI_FF_PCIE_M2_2242``
  PCIe: M.2 module - 2242

``NVME_MI_FF_PCIE_M2_2260``
  PCIe: M.2 module - 2260

``NVME_MI_FF_PCIE_M2_2280``
  PCIe: M.2 module - 2280

``NVME_MI_FF_PCIE_M2_22110``
  PCIe: M.2 module - 22110

``NVME_MI_FF_PCIE_BGA_UNKNOWN``
  PCIe: BGA SSD - unknown

``NVME_MI_FF_PCIE_BGA_M2_1620``
  PCIe: BGA SSD - 16 x 20 mm (M.2 Type
  1620)

``NVME_MI_FF_PCIE_BGA_M2_1113``
  PCIe: BGA SSD - 11.5 x 13 mm (M.2
  Type 1113)

``NVME_MI_FF_PCIE_EDSFF_UNKNOWN``
  PCIe: Enterprise & Datacenter SSD
  Form Factor - unknown

``NVME_MI_FF_PCIE_E1S_5_9MM``
  PCIe: E1.S - (SFF-TA-1006) 5.9 mm

``NVME_MI_FF_PCIE_E1S_8MM``
  PCIe: E1.S - (SFF-TA-1006) 8 mm

``NVME_MI_FF_PCIE_E1L_9_5MM``
  PCIe: E1.L - (SFF-TA-1007) 9.5 mm

``NVME_MI_FF_PCIE_E1L_18MM``
  PCIe: E1.L - (SFF-TA-1007) 18 mm

``NVME_MI_FF_PCIE_E3S_7_5MM``
  PCIe: E3.S - (SFF-TA-1008) 7.5 mm

``NVME_MI_FF_PCIE_E3S_16_8MM``
  PCIe: E3.S - (SFF-TA-1008) 16.8 mm

``NVME_MI_FF_PCIE_E3L_7_5MM``
  PCIe: E3.L - (SFF-TA-1008) 7.5 mm

``NVME_MI_FF_PCIE_E3L_16_8MM``
  PCIe: E3.L - (SFF-TA-1008) 16.8 mm

``NVME_MI_FF_PCIE_E1S_9_5MM``
  PCIe: E1.S - (SFF-TA-1006) 9.5 mm

``NVME_MI_FF_PCIE_E1S_15MM``
  PCIe: E1.S - (SFF-TA-1006) 15 mm

``NVME_MI_FF_PCIE_E1S_25MM``
  PCIe: E1.S - (SFF-TA-1006) 25 mm

``NVME_MI_FF_PCIE_E2_9_5MM``
  PCIe: E2 - (SFF-TA-1042) 9.5 mm

``NVME_MI_FF_ETHERNET_UNKNOWN``
  Ethernet: Other - unknown

``NVME_MI_FF_ETHERNET_2_5_15MM``
  Ethernet: 2.5" Form Factor (Native
  NVMe-oF Drive) 15 mm

``NVME_MI_FF_ETHERNET_2_5_7MM``
  Ethernet: 2.5" Form Factor (Native
  NVMe-oF Drive) 7 mm

``NVME_MI_FF_ETHERNET_E3S_7_5MM``
  Ethernet: E3.S (Native NVMe-oF Drive)
  7.5 mm

``NVME_MI_FF_ETHERNET_E3S_16_8MM``
  Ethernet: E3.S (Native NVMe-oF Drive)
  16.8 mm




.. c:struct:: nvme_mi_vpd_usce

   Upstream Connector Element Descriptor

**Definition**

::

  struct nvme_mi_vpd_usce {
    __u8 typ;
    __u8 rev;
    __u8 len;
    __u8 ff;
    __u8 lptr;
    __u8 rsvd6[2];
    __u8 maxapwr;
    __le16 maxpwr;
    __u8 updc;
    __u8 upd[];
  };

**Members**

``typ``
  Type: set to ``NVME_MI_ELEM_USCE``.

``rev``
  Revision: cleared to 0h.

``len``
  Length of this Upstream Connector Element Descriptor in
  bytes.

``ff``
  Form Factor of the NVMe Storage Device, see :c:type:`enum
  nvme_mi_form_factor <nvme_mi_form_factor>`.

``lptr``
  Label Pointer: index of the Label Element Descriptor
  containing this Upstream Connector's label, if any. A value
  of 0h indicates there is no associated label.

``rsvd6``
  Reserved

``maxapwr``
  Maximum Auxiliary Power in 10 mW increments consumed by the
  NVMe Storage Device from this Upstream Connector. A value
  of 0h indicates auxiliary power is not used.

``maxpwr``
  Maximum Power in Watts consumed by the NVMe Storage Device.

``updc``
  Upstream Port Descriptor Count: number of Upstream Port
  Descriptors in **upd**.

``upd``
  Upstream Port Descriptor list. Each entry's size is
  implementation specific; use **len** and **updc** to walk the
  list.





.. c:struct:: nvme_mi_vpd_tra

   Vital Product Data Topology MultiRecord

**Definition**

::

  struct nvme_mi_vpd_tra {
    __u8 vn;
    __u8 rsvd6;
    __u8 ec;
    struct nvme_mi_vpd_telem elems[0];
  };

**Members**

``vn``
  Version Number

``rsvd6``
  Reserved

``ec``
  Element Count

``elems``
  Element Descriptor





.. c:struct:: nvme_mi_vpd_mr_common

   NVMe MultiRecord Area

**Definition**

::

  struct nvme_mi_vpd_mr_common {
    __u8 type;
    __u8 rf;
    __u8 rlen;
    __u8 rchksum;
    __u8 hchksum;
    union {
      struct nvme_mi_vpd_mra nmra;
      struct nvme_mi_vpd_ppmra ppmra;
      struct nvme_mi_vpd_tra tmra;
    };
  };

**Members**

``type``
  NVMe Record Type ID

``rf``
  Record Format

``rlen``
  Record Length

``rchksum``
  Record Checksum

``hchksum``
  Header Checksum

``{unnamed_union}``
  anonymous

``nmra``
  NVMe MultiRecord Area

``ppmra``
  NVMe PCIe Port MultiRecord Area

``tmra``
  Topology MultiRecord Area





.. c:struct:: nvme_mi_vpd_hdr

   Vital Product Data Common Header

**Definition**

::

  struct nvme_mi_vpd_hdr {
    __u8 ipmiver;
    __u8 iuaoff;
    __u8 ciaoff;
    __u8 biaoff;
    __u8 piaoff;
    __u8 mrioff;
    __u8 rsvd6;
    __u8 chchk;
    __u8 vpd[];
  };

**Members**

``ipmiver``
  IPMI Format Version Number

``iuaoff``
  Internal Use Area Starting Offset

``ciaoff``
  Chassis Info Area Starting Offset

``biaoff``
  Board Info Area Starting Offset

``piaoff``
  Product Info Area Starting Offset

``mrioff``
  MultiRecord Info Area Starting Offset

``rsvd6``
  Reserved

``chchk``
  Common Header Checksum

``vpd``
  Vital Product Data





.. c:enum:: nvme_mi_resp_status

   values for the response status field

**Constants**

``NVME_MI_RESP_SUCCESS``
  success

``NVME_MI_RESP_MPR``
  More Processing Required

``NVME_MI_RESP_INTERNAL_ERR``
  Internal Error

``NVME_MI_RESP_INVALID_OPCODE``
  Invalid command opcode

``NVME_MI_RESP_INVALID_PARAM``
  Invalid command parameter

``NVME_MI_RESP_INVALID_CMD_SIZE``
  Invalid command size

``NVME_MI_RESP_INVALID_INPUT_SIZE``
  Invalid command input data size

``NVME_MI_RESP_ACCESS_DENIED``
  Access Denied

``NVME_MI_RESP_VPD_UPDATES_EXCEEDED``
  More VPD updates than allowed

``NVME_MI_RESP_PCIE_INACCESSIBLE``
  PCIe functionality currently unavailable

``NVME_MI_RESP_MEB_SANITIZED``
  MEB has been cleared due to sanitize

``NVME_MI_RESP_ENC_SERV_FAILURE``
  Enclosure services process failed

``NVME_MI_RESP_ENC_SERV_XFER_FAILURE``
  Transfer with enclosure services failed

``NVME_MI_RESP_ENC_FAILURE``
  Unreoverable enclosure failure

``NVME_MI_RESP_ENC_XFER_REFUSED``
  Enclosure services transfer refused

``NVME_MI_RESP_ENC_FUNC_UNSUP``
  Unsupported enclosure services function

``NVME_MI_RESP_ENC_SERV_UNAVAIL``
  Enclosure services unavailable

``NVME_MI_RESP_ENC_DEGRADED``
  Noncritical failure detected by enc. services

``NVME_MI_RESP_SANITIZE_IN_PROGRESS``
  Command prohibited during sanitize


