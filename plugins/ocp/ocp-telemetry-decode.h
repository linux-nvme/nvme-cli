/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2024 Western Digital Corporation or its affiliates.
 *
 * Authors: Jeff Lien <jeff.lien@wdc.com>,
 */
#ifndef OCP_TELEMETRY_DECODE_H
#define OCP_TELEMETRY_DECODE_H

#include "nvme.h"
#include "nvme-print.h"
#include "util/utils.h"
#include "common.h"
#include "ocp-nvme.h"

extern __u8 *ptelemetry_buffer;
extern __u8 *pstring_buffer;

/*****************************************************************************
 * Telemetry Statistics ID's and Strings
 *****************************************************************************/
enum TELEMETRY_STATISTIC_ID {
	TELEMETRY_STAT_ID_OAC		= 0x1,  /* Outstanding Admin Commands */
	TELEMETRY_STAT_ID_HWB		= 0x2,  /* Host Write Bandwidth       */
	TELEMETRY_STAT_ID_GCWB		= 0x3,  /* Garbage Collection Write Bandwidth */
	TELEMETRY_STAT_ID_AN		= 0x4,  /* Active Namespaces  */
	TELEMETRY_STAT_ID_IWW		= 0x5,  /* Internal Write Workload  */
	TELEMETRY_STAT_ID_IRW		= 0x6,  /* Internal Read Workload  */
	TELEMETRY_STAT_ID_IWQD		= 0x7,  /* Internal Write Queue Depth  */
	TELEMETRY_STAT_ID_IRQD		= 0x8,  /* Internal Read Queue Depth  */
	TELEMETRY_STAT_ID_PTC		= 0x9,  /* Pending Trim LBA Count  */
	TELEMETRY_STAT_ID_HTRC		= 0xA,  /* Host Trim LBA Request Count  */
	TELEMETRY_STAT_ID_CNPS		= 0xB,  /* Current NVMe Power State  */
	TELEMETRY_STAT_ID_CDPS		= 0xC,  /* Current DSSD Power State  */
	TELEMETRY_STAT_ID_PFC		= 0xD,  /* Program Fail Count  */
	TELEMETRY_STAT_ID_EFC		= 0xE,  /* Erase Fail Count  */
	TELEMETRY_STAT_ID_RDW		= 0xF,  /* Read Disturb Write  */
	TELEMETRY_STAT_ID_RW		= 0x10, /* Retention Writes  */
	TELEMETRY_STAT_ID_WLW		= 0x11, /* Wear Leveling Writes  */
	TELEMETRY_STAT_ID_RRW		= 0x12, /* Read Recovery Writes  */
	TELEMETRY_STAT_ID_GCW		= 0x13, /* Garbage Collection Writes  */
	TELEMETRY_STAT_ID_SCC		= 0x14, /* SRAM Correctable Count  */
	TELEMETRY_STAT_ID_DCC		= 0x15, /* DRAM Uncorrectable Count  */
	TELEMETRY_STAT_ID_SUC		= 0x16, /* SRAM Correctable Count  */
	TELEMETRY_STAT_ID_DUC		= 0x17, /* DRAM Uncorrectable Count  */
	TELEMETRY_STAT_ID_DIEC		= 0x18, /* Data Integrity Error Count  */
	TELEMETRY_STAT_ID_RREC		= 0x19, /* Read Retry Error Count  */
	TELEMETRY_STAT_ID_PEC		= 0x1A, /* PERST Events Count  */
	TELEMETRY_STAT_ID_MAXDBB	= 0x1B, /* Max Die Bad Block  */
	TELEMETRY_STAT_ID_MAXCBB	= 0x1C, /* Max NAND Channel Bad Block  */
	TELEMETRY_STAT_ID_MINCBB	= 0x1D, /* Min NAND Channel Bad Block  */
	TELEMETRY_STAT_ID_PMUW		= 0x1E, /* Physical Media Units Written  */
	TELEMETRY_STAT_ID_PMUR		= 0x1F, /* Physical Media Units Read  */
	TELEMETRY_STAT_ID_BUNB		= 0x20, /* Bad User NAND Blocks  */
	TELEMETRY_STAT_ID_BSNB		= 0x21, /* Bad System NAND Blocks  */
	TELEMETRY_STAT_ID_XORRC		= 0x22, /* XOR Recovery Count  */
	TELEMETRY_STAT_ID_UNREC		= 0x23, /* Uncorrectable Read Error Count  */
	TELEMETRY_STAT_ID_SECCEC	= 0x24, /* Soft ECC Error Count  */
	TELEMETRY_STAT_ID_ETOECC	= 0x25, /* End To End Correction Counts  */
	TELEMETRY_STAT_ID_SDU		= 0x26, /* System Data % Used  */
	TELEMETRY_STAT_ID_RC		= 0x27, /* Refresh Count  */
	TELEMETRY_STAT_ID_UDEC		= 0x28, /* User Data Erase Counts  */
	TELEMETRY_STAT_ID_TTSC		= 0x29, /* Thremal Throttling Status and Count  */
	TELEMETRY_STAT_ID_DSSDSV	= 0x2A, /* DSSD Specification Version  */
	TELEMETRY_STAT_ID_PCIECEC	= 0x2B, /* PCIe Correctable Error Count  */
	TELEMETRY_STAT_ID_IS		= 0x2C, /* Incomplete Shutdown  */
	TELEMETRY_STAT_ID_FB		= 0x2D, /* % Free Block  */
	TELEMETRY_STAT_ID_CH		= 0x2E, /* Capacitor Health  */
	TELEMETRY_STAT_ID_NVMEBEV	= 0x2F, /* NVM Express Base Errata Version  */
	TELEMETRY_STAT_ID_NVMCSEV	= 0x30, /* NVM Command Set Errata Version  */
	TELEMETRY_STAT_ID_NVMEMIEV	= 0x31, /* NVM Exp Mgmt Interface Err Version  */
	TELEMETRY_STAT_ID_UIO		= 0x32, /* Unaligned IO  */
	TELEMETRY_STAT_ID_SVN		= 0x33, /* Security Version Number  */
	TELEMETRY_STAT_ID_TNUSE		= 0x34, /* Total NUSE  */
	TELEMETRY_STAT_ID_PLPSC		= 0x35, /* PLP Start Count  */
	TELEMETRY_STAT_ID_EE		= 0x36, /* Endurance Estimate  */
	TELEMETRY_STAT_ID_PCIELRC	= 0x37, /* PCIe Link Retraining Count  */
	TELEMETRY_STAT_ID_PSCC		= 0x38, /* Power State Change Count  */
	TELEMETRY_STAT_ID_LPFR		= 0x39, /* Lowest Permitted Firmware Revision  */
	TELEMETRY_STAT_ID_LPV		= 0x3A, /* Log Page Version  */
	TELEMETRY_STAT_ID_MDO		= 0x3B, /* Media Dies Offline  */
	TELEMETRY_STAT_ID_MTR		= 0x3C, /* Max Temperature Recorded  */
	TELEMETRY_STAT_ID_NAEC		= 0x3D, /* Nand Avg Erase Count  */
	TELEMETRY_STAT_ID_CT		= 0x3E, /* Command Timeout  */
	TELEMETRY_STAT_ID_SAPFC		= 0x3F, /* System Area Program Fail Count  */
	TELEMETRY_STAT_ID_SARFC		= 0x40, /* System Area Read Fail Count  */
	TELEMETRY_STAT_ID_SAEFC		= 0x41, /* System Area Erase Fail Count  */
	TELEMETRY_STAT_ID_MPPC		= 0x42, /* Max Peak Power Capability  */
	TELEMETRY_STAT_ID_CMAP		= 0x43, /* Current Max Average Power  */
	TELEMETRY_STAT_ID_LPC		= 0x44, /* Lifetime Power Consumed  */
	TELEMETRY_STAT_ID_PAC		= 0x45, /* Panic Asset Count  */
	TELEMETRY_STAT_ID_DBT		= 0x46, /* Device Busy Time  */
	TELEMETRY_STAT_ID_CW		= 0x47, /* Critical Warning  */
	TELEMETRY_STAT_ID_COMTEMP	= 0x48, /* Composite Temperature  */
	TELEMETRY_STAT_ID_AS		= 0x49, /* Available Spare  */
	TELEMETRY_STAT_ID_AST		= 0x4A, /* Available Spare Threshold  */
	TELEMETRY_STAT_ID_PU		= 0x4B, /* Percentage Used  */
	TELEMETRY_STAT_ID_EGCWS		= 0x4C, /* Endurance Gp CW Summary  */
	TELEMETRY_STAT_ID_DUR		= 0x4D, /* Data Units Read  */
	TELEMETRY_STAT_ID_DUW		= 0x4E, /* Data Units Written  */
	TELEMETRY_STAT_ID_HRC		= 0x4F, /* Host Read Commands  */
	TELEMETRY_STAT_ID_HWC		= 0x50, /* Host Write Commands  */
	TELEMETRY_STAT_ID_CBT		= 0x51, /* Controller Busy Time  */
	TELEMETRY_STAT_ID_PC		= 0x52, /* Power Cycles  */
	TELEMETRY_STAT_ID_POH		= 0x53, /* Power On Hours  */
	TELEMETRY_STAT_ID_US		= 0x54, /* Unsafe Shutdowns  */
	TELEMETRY_STAT_ID_MDIE		= 0x55, /* Media and Data Integrity Er  */
	TELEMETRY_STAT_ID_NEILE		= 0x56, /* No of Error Info Entries  */
	TELEMETRY_STAT_ID_WCTT		= 0x57, /* Warning Composite Temp Time  */
	TELEMETRY_STAT_ID_CCTT		= 0x58, /* Critical Comp Temp Time  */
	TELEMETRY_STAT_ID_TS1		= 0x59, /* Temperature Sensor 1  */
	TELEMETRY_STAT_ID_TS2		= 0x5A, /* Temperature Sensor 2  */
	TELEMETRY_STAT_ID_TS3		= 0x5B, /* Temperature Sensor 3  */
	TELEMETRY_STAT_ID_TS4		= 0x5C, /* Temperature Sensor 4  */
	TELEMETRY_STAT_ID_TS5		= 0x5D, /* Temperature Sensor 5  */
	TELEMETRY_STAT_ID_TS6		= 0x5E, /* Temperature Sensor 6  */
	TELEMETRY_STAT_ID_TS7		= 0x5F, /* Temperature Sensor 7  */
	TELEMETRY_STAT_ID_TS8		= 0x60, /* Temperature Sensor 8  */
	TELEMETRY_STAT_ID_TMT1TC	= 0x61, /* Thermal Mgmt Temp1 TC  */
	TELEMETRY_STAT_ID_TMT2TC	= 0x62, /* Thermal Mgmt Temp2 TC  */
	TELEMETRY_STAT_ID_TTTMT1	= 0x63, /* Total Time TMT1  */
	TELEMETRY_STAT_ID_TTTMT2	= 0x64, /* Total Time TMT2  */
	TELEMETRY_STAT_ID_EEE		= 0x65, /* Endurance Estimate  */
	TELEMETRY_STAT_ID_EDUR		= 0x66, /* Endurance Data Units Read  */
	TELEMETRY_STAT_ID_EDUW		= 0x67, /* Endurance Data Units Written  */
	TELEMETRY_STAT_ID_EMUW		= 0x68, /* Endurance Media Units Written  */
	TELEMETRY_STAT_ID_ENEILE	= 0x69, /* Endurance No Of Err Info Log Entries  */

};

static const char * const telemetry_stat_id_str[] = {
	[TELEMETRY_STAT_ID_OAC]		= "Outstanding Admin Commands",
	[TELEMETRY_STAT_ID_HWB]		= "Host Write Bandwidth",
	[TELEMETRY_STAT_ID_GCWB]	= "Garbage Collection Write Bandwidth",
	[TELEMETRY_STAT_ID_AN]		= "Active Namespaces",
	[TELEMETRY_STAT_ID_IWW]		= "Internal Write Workload",
	[TELEMETRY_STAT_ID_IRW]		= "Internal Read Workload",
	[TELEMETRY_STAT_ID_IWQD]	= "Internal Write Queue Depth",
	[TELEMETRY_STAT_ID_IRQD]	= "Internal Read Queue Depth",
	[TELEMETRY_STAT_ID_PTC]		= "Pending Trim LBA Count",
	[TELEMETRY_STAT_ID_HTRC]	= "Host Trim LBA Request Count",
	[TELEMETRY_STAT_ID_CNPS]	= "Current NVMe Power State",
	[TELEMETRY_STAT_ID_CDPS]	= "Current DSSD Power State",
	[TELEMETRY_STAT_ID_PFC]		= "Program Fail Count",
	[TELEMETRY_STAT_ID_EFC]		= "Erase Fail Count",
	[TELEMETRY_STAT_ID_RDW]		= "Read Disturb Write",
	[TELEMETRY_STAT_ID_RW]		= "Retention Writes",
	[TELEMETRY_STAT_ID_WLW]		= "Wear Leveling Writes",
	[TELEMETRY_STAT_ID_RRW]		= "Read Recovery Writes",
	[TELEMETRY_STAT_ID_GCW]		= "Garbage Collection Writes",
	[TELEMETRY_STAT_ID_SCC]		= "SRAM Correctable Count",
	[TELEMETRY_STAT_ID_DCC]		= "DRAM Correctable Count",
	[TELEMETRY_STAT_ID_SUC]		= "SRAM Uncorrectable Count",
	[TELEMETRY_STAT_ID_DUC]		= "DRAM Uncorrectable Count",
	[TELEMETRY_STAT_ID_DIEC]	= "Data Integrity Error Count",
	[TELEMETRY_STAT_ID_RREC]	= "Read Retry Error Count",
	[TELEMETRY_STAT_ID_PEC]		= "PERST Events Count",
	[TELEMETRY_STAT_ID_MAXDBB]	= "Max Die Bad Block",
	[TELEMETRY_STAT_ID_MAXCBB]	= "Max NAND Channel Bad Block",
	[TELEMETRY_STAT_ID_MINCBB]	= "Min NAND Channel Bad Block",
	[TELEMETRY_STAT_ID_PMUW]	 = "Physical Media Units Written",
	[TELEMETRY_STAT_ID_PMUR]	 = "Physical Media Units Read",
	[TELEMETRY_STAT_ID_BUNB]	 = "Bad User NAND Blocks",
	[TELEMETRY_STAT_ID_BSNB]	 = "Bad System NAND Blocks",
	[TELEMETRY_STAT_ID_XORRC]	 = "XOR Recovery Count",
	[TELEMETRY_STAT_ID_UNREC]	 = "Uncorrectable Read Error Count",
	[TELEMETRY_STAT_ID_SECCEC]	 = "Soft ECC Error Count",
	[TELEMETRY_STAT_ID_ETOECC]	 = "End To End Correction Counts",
	[TELEMETRY_STAT_ID_SDU]		 = "System Data Used",
	[TELEMETRY_STAT_ID_RC]		 = "Refresh Count",
	[TELEMETRY_STAT_ID_UDEC]	 = "User Data Erase Counts",
	[TELEMETRY_STAT_ID_TTSC]	 = "Thremal Throttling Status and Count",
	[TELEMETRY_STAT_ID_DSSDSV]	 = "DSSD Specification Version",
	[TELEMETRY_STAT_ID_PCIECEC]	 = "PCIe Correctable Error Count",
	[TELEMETRY_STAT_ID_IS]		 = "Incomplete Shutdown",
	[TELEMETRY_STAT_ID_FB]		 = "Free Block",
	[TELEMETRY_STAT_ID_CH]		 = "Capacitor Health",
	[TELEMETRY_STAT_ID_NVMEBEV]	 = "NVM Express Base Errata Version",
	[TELEMETRY_STAT_ID_NVMCSEV]	 = "NVM Command Set Errata Version",
	[TELEMETRY_STAT_ID_NVMEMIEV] = "NVM Express Management Interface Errata Version",
	[TELEMETRY_STAT_ID_UIO]		 = "Unaligned IO",
	[TELEMETRY_STAT_ID_SVN]		 = "Security Version Number",
	[TELEMETRY_STAT_ID_TNUSE]	 = "Total NUSE",
	[TELEMETRY_STAT_ID_PLPSC]	 = "PLP Start Count",
	[TELEMETRY_STAT_ID_EE]		 = "Endurance Estimate",
	[TELEMETRY_STAT_ID_PCIELRC]	 = "PCIe Link Retraining Count",
	[TELEMETRY_STAT_ID_PSCC]	 = "Power State Change Count",
	[TELEMETRY_STAT_ID_LPFR]	 = "Lowest Permitted Firmware Revision",
	[TELEMETRY_STAT_ID_LPV]		 = "Log Page Version",
	[TELEMETRY_STAT_ID_MDO]		 = "Media Dies Offline",
	[TELEMETRY_STAT_ID_MTR]		 = "Max Temperature Recorded",
	[TELEMETRY_STAT_ID_NAEC]	 = "Nand Avg Erase Count",
	[TELEMETRY_STAT_ID_CT]		 = "Command Timeout",
	[TELEMETRY_STAT_ID_SAPFC]	 = "System Area Program Fail Count",
	[TELEMETRY_STAT_ID_SARFC]	 = "System Area Read Fail Count",
	[TELEMETRY_STAT_ID_SAEFC]	 = "System Area Erase Fail Count",
	[TELEMETRY_STAT_ID_MPPC]	 = "Max Peak Power Capability",
	[TELEMETRY_STAT_ID_CMAP]	 = "Current Max Average Power",
	[TELEMETRY_STAT_ID_LPC]		 = "Lifetime Power Consumed",
	[TELEMETRY_STAT_ID_PAC]		 = "Panic Asset Count",
	[TELEMETRY_STAT_ID_DBT]		 = "Device Busy Time",
	[TELEMETRY_STAT_ID_CW]		 = "Critical Warning",
	[TELEMETRY_STAT_ID_COMTEMP]	 = "Composite Temperature",
	[TELEMETRY_STAT_ID_AS]		 = "Available Spare",
	[TELEMETRY_STAT_ID_AST]		 = "Available Spare Threshold",
	[TELEMETRY_STAT_ID_PU]		 = "Percentage Used",
	[TELEMETRY_STAT_ID_EGCWS]	 = "Endurance Gp CW Summary",
	[TELEMETRY_STAT_ID_DUR]		 = "Data Units Read",
	[TELEMETRY_STAT_ID_DUW]		 = "Data Units Written",
	[TELEMETRY_STAT_ID_HRC]		 = "Host Read Commands",
	[TELEMETRY_STAT_ID_HWC]		 = "Host Write Commands",
	[TELEMETRY_STAT_ID_CBT]		 = "Controller Busy Time",
	[TELEMETRY_STAT_ID_PC]		 = "Power Cycles",
	[TELEMETRY_STAT_ID_POH]		 = "Power On Hours",
	[TELEMETRY_STAT_ID_US]		 = "Unsafe Shutdowns",
	[TELEMETRY_STAT_ID_MDIE]	 = "Media and Data Integrity Er",
	[TELEMETRY_STAT_ID_NEILE]	 = "No of Error Info Entries",
	[TELEMETRY_STAT_ID_WCTT]	 = "Warning Composite Temp Time",
	[TELEMETRY_STAT_ID_CCTT]	 = "Critical Comp Temp Time",
	[TELEMETRY_STAT_ID_TS1]		 = "Temperature Sensor 1",
	[TELEMETRY_STAT_ID_TS2]		 = "Temperature Sensor 2",
	[TELEMETRY_STAT_ID_TS3]		 = "Temperature Sensor 3",
	[TELEMETRY_STAT_ID_TS4]		 = "Temperature Sensor 4",
	[TELEMETRY_STAT_ID_TS5]		 = "Temperature Sensor 5",
	[TELEMETRY_STAT_ID_TS6]		 = "Temperature Sensor 6",
	[TELEMETRY_STAT_ID_TS7]		 = "Temperature Sensor 7",
	[TELEMETRY_STAT_ID_TS8]		 = "Temperature Sensor 8",
	[TELEMETRY_STAT_ID_TMT1TC]	 = "Thermal Mgmt Temp1 TC",
	[TELEMETRY_STAT_ID_TMT2TC]	 = "Thermal Mgmt Temp2 TC",
	[TELEMETRY_STAT_ID_TTTMT1]	 = "Total Time TMT1",
	[TELEMETRY_STAT_ID_TTTMT2]	 = "Total Time TMT2",
	[TELEMETRY_STAT_ID_EEE]		 = "Endurance Estimate",
	[TELEMETRY_STAT_ID_EDUR]	 = "Endurance Data Units Read",
	[TELEMETRY_STAT_ID_EDUW]	 = "Endurance Data Units Written",
	[TELEMETRY_STAT_ID_EMUW]	 = "Endurance Media Units Written",
	[TELEMETRY_STAT_ID_ENEILE]	 = "Endurance No Of Err Info Log Entries",
};

/*****************************************************************************
 * Telemetry FIFO Event Class ID's and Strings
 *****************************************************************************/
enum TELEMETRY_EVENT_CLASS_TYPE {
	TELEMETRY_TIMESTAMP_CLASS           = 0x1,
	TELEMETRY_PCIE_CLASS                = 0x2,
	TELEMETRY_NVME_CLASS                = 0x3,
	TELEMETRY_RESET_CLASS               = 0x4,
	TELEMETRY_BOOT_SEQ_CLASS            = 0x5,
	TELEMETRY_FW_ASSERT_CLASS           = 0x6,
	TELEMETRY_TEMPERATURE_CLASS         = 0x7,
	TELEMETRY_MEDIA_DBG_CLASS           = 0x8,
	TELEMETRY_MEDIA_WEAR_CLASS          = 0x9,
	TELEMETRY_STAT_SNAPSHOT_CLASS       = 0xA,
	TELEMETRY_VIRTUAL_FIFO_EVENT_CLASS  = 0xB,
};

static const char * const telemetry_event_class_str[] = {
	[TELEMETRY_TIMESTAMP_CLASS]          = "Timestamp Class",
	[TELEMETRY_PCIE_CLASS]               = "PCIe Class",
	[TELEMETRY_NVME_CLASS]               = "NVMe Class",
	[TELEMETRY_RESET_CLASS]              = "Reset Class",
	[TELEMETRY_BOOT_SEQ_CLASS]           = "Boot Sequence Class",
	[TELEMETRY_FW_ASSERT_CLASS]          = "FW Assert Class",
	[TELEMETRY_TEMPERATURE_CLASS]        = "Temperature Class",
	[TELEMETRY_MEDIA_DBG_CLASS]          = "Media Debug Class",
	[TELEMETRY_MEDIA_WEAR_CLASS]         = "Media Wear Class",
	[TELEMETRY_STAT_SNAPSHOT_CLASS]      = "Statistic Snapshot Class",
	[TELEMETRY_VIRTUAL_FIFO_EVENT_CLASS] = "Virtual FIFO Event Class",
};

/*****************************************************************************
 * Telemetry Timestamp Class (01h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_TIMESTAMP_EVENT_ID {
	TIMESTAMP_FEATURE_HOST_ISSUED    = 0x0000,
	TIMESTAMP_FW_INTIATED_SNAPSHOT   = 0x0001,
	TIMESTAMP_OBSOLETE               = 0x0002,
};

static const char * const telemetry_timestamp_event_id_str[] = {
	[TIMESTAMP_FEATURE_HOST_ISSUED]		= "Host Issued Timestamp Set Feature Cmd",
	[TIMESTAMP_FW_INTIATED_SNAPSHOT]	= "Fw Initiated Timestamp Snapshot",
	[TIMESTAMP_OBSOLETE]                = "TimeStamp Obsolete",
};

/*****************************************************************************
 * Telemetry PCIE Class (02h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_PCIE_EVENT_ID {
	PCIE_LINK_UP                   = 0x0000,
	PCIE_LINK_DOWN                 = 0x0001,
	PCIE_ERROR_DETECTED            = 0x0002,
	PCIE_PERST_ASSERTED            = 0x0003,
	PCIE_PERST_DEASSERTED          = 0x0004,
	PCIE_REFCLK_STABLE             = 0x0005,
	PCIE_VMAIN_STABLE              = 0x0006,
	PCIE_LINK_NEGOTIATED           = 0x0007,
};

static const char * const telemetry_pcie_event_id_str[] = {
	[PCIE_LINK_UP]				= "PCIe Link Up",
	[PCIE_LINK_DOWN]			= "PCIe Link Down",
	[PCIE_ERROR_DETECTED]		= "PCIe Error Detected",
	[PCIE_PERST_ASSERTED]		= "PCIe PERST Asserted",
	[PCIE_PERST_DEASSERTED]		= "PCIe PERST Deasserted",
	[PCIE_REFCLK_STABLE]		= "PCIe Refclk Stable",
	[PCIE_VMAIN_STABLE]			= "PCIe Vmain Stable",
	[PCIE_LINK_NEGOTIATED]		= "PCIe Link Negotiated",
};

enum TELEMETRY_PCIE_STATE_DATA {
	PCIE_STATE_UNCHANGED           = 0x00,
	PCIE_SPEED_CHANGED             = 0x01,
	PCIE_WIDTH_CHANGED             = 0x02,
};

static const char * const telemetry_pcie_state_data_str[] = {
	[PCIE_STATE_UNCHANGED]	= "PCIe State Unchained",
	[PCIE_SPEED_CHANGED]	= "PCIe Speed Changed",
	[PCIE_WIDTH_CHANGED]	= "PCIe Width Changed",
};

enum TELEMETRY_PCIE_SPEED_DATA {
	PCIE_LINK_GEN1			= 0x01,
	PCIE_LINK_GEN2			= 0x02,
	PCIE_LINK_GEN3			= 0x03,
	PCIE_LINK_GEN4			= 0x04,
	PCIE_LINK_GEN5			= 0x05,
	PCIE_LINK_GEN6			= 0x06,
	PCIE_LINK_GEN7			= 0x07,
};

static const char * const telemetry_pcie_speed_data_str[] = {
	[PCIE_LINK_GEN1]		= "PCIe Link Speed Gen1",
	[PCIE_LINK_GEN2]		= "PCIe Link Speed Gen2",
	[PCIE_LINK_GEN3]		= "PCIe Link Speed Gen3",
	[PCIE_LINK_GEN4]		= "PCIe Link Speed Gen4",
	[PCIE_LINK_GEN5]		= "PCIe Link Speed Gen5",
	[PCIE_LINK_GEN6]		= "PCIe Link Speed Gen6",
	[PCIE_LINK_GEN7]		= "PCIe Link Speed Gen7",
};

enum TELEMETRY_PCIE_WIDTH_DATA {
	PCIE_LINK_X1			= 0x01,
	PCIE_LINK_X2			= 0x02,
	PCIE_LINK_X4			= 0x03,
	PCIE_LINK_X8			= 0x04,
	PCIE_LINK_X16			= 0x05,
};

static const char * const telemetry_pcie_width_data_str[] = {
	[PCIE_LINK_X1]			= "PCIe Link Width x1",
	[PCIE_LINK_X2]			= "PCIe Link Width x2",
	[PCIE_LINK_X4]			= "PCIe Link Width x4",
	[PCIE_LINK_X8]			= "PCIe Link Width x8",
	[PCIE_LINK_X16]			= "PCIe Link Width x16",
};

/*****************************************************************************
 * Telemetry NVMe Class (03h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_NVME_EVENT_ID {
	CC_EN_0_TO_1					= 0x0000,
	CC_EN_1_TO_0					= 0x0001,
	CSTS_RDY_0_TO_1					= 0x0002,
	CSTS_RDY_1_TO_0					= 0x0003,
	NVME_EVENT_ID_RESERVED			= 0x0004,
	CREATE_IO_QUEUE_PROCESSED		= 0x0005,
	ADMIN_QUEUE_CMD_PROCESSED		= 0x0006,
	ADMIN_QUEUE_NONZERO_STATUS		= 0x0007,
	IO_QUEUE_NONZERO_STATUS			= 0x0008,
	CSTS_CFS_0_TO_1					= 0x0009,
	ADMIN_QUEUE_BASE_WRITTEN		= 0x000A,
	CC_REGISTER_CHANGED				= 0x000B,
	CSTS_REGISTER_CHANGED			= 0x000C,
	DELETE_IO_QUEUE_PROCESSED		= 0x000D,
	OOB_COMMAND	                    = 0x000E,
	OOB_AER_EVENT_MSG_TRANS			= 0x000F
};

static const char * const telemetry_nvme_event_id_str[] = {
	[CC_EN_0_TO_1]					= "CC.EN Transitions from 0 to 1",
	[CC_EN_1_TO_0]					= "CC.EN Transitions from 1 to 0",
	[CSTS_RDY_0_TO_1]				= "CSTS.RDY Transitions from 0 to 1",
	[CSTS_RDY_1_TO_0]				= "CSTS.RDY Transitions from 1 to 0",
	[NVME_EVENT_ID_RESERVED]		= "Reserved NVMe Event ID",
	[CREATE_IO_QUEUE_PROCESSED]		= "Create IO SQ or CQ Command Processed",
	[ADMIN_QUEUE_CMD_PROCESSED]		= "Inb-Admin Que Cmd Proc other than Cr IO SQ/CQ",
	[ADMIN_QUEUE_NONZERO_STATUS]	= "Admin Command Returned Non-zero Status",
	[IO_QUEUE_NONZERO_STATUS]		= "IO Command Returned Non-zero Status",
	[CSTS_CFS_0_TO_1]				= "CSTS.CFS Transitions from 0 to 1",
	[ADMIN_QUEUE_BASE_WRITTEN]		= "Admin SQ or CQ Base Address Written",
	[CC_REGISTER_CHANGED]			= "CC Register Changed",
	[CSTS_REGISTER_CHANGED]			= "CSTS Register Changed",
	[DELETE_IO_QUEUE_PROCESSED]		= "Delete IO SQ or CQ Command Processed",
	[OOB_COMMAND]			        = "Out of Band Command Process",
	[OOB_AER_EVENT_MSG_TRANS]		= "Out of Band AER Event Msg Transition"
};

/*****************************************************************************
 * Telemetry Reset Class (04h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_RESET_EVENT_ID {
	PCIE_CONVENTIONAL_HOT_RESET		= 0x0000,
	MAIN_POWER_CYCLE				= 0x0001,
	PERST							= 0x0002,
	PCIE_FUNCTION_LEVEL_RESET		= 0x0003,
	NVME_SUBSYSTEM_RESET			= 0x0004,
};

static const char * const telemetry_reset_event_id_str[] = {
	[PCIE_CONVENTIONAL_HOT_RESET]	= "PCIE Conventional Hot Reset",
	[MAIN_POWER_CYCLE]				= "Main Power_Cycle",
	[PERST]							= "PERST",
	[PCIE_FUNCTION_LEVEL_RESET]		= "PCIE Function Level Reset",
	[NVME_SUBSYSTEM_RESET]			= "NVMe Subsytem Reset",
};

/*****************************************************************************
 * Telemetry Boot Sequence Class (05h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_BOOT_SEQ_EVENT_ID {
	MAIN_FW_BOOT_COMPLETE			= 0x0000,
	FTL_LOAD_FROM_NVM_COMPLETE		= 0x0001,
	FTL_REBUILD_STARTED				= 0x0002,
	FTL_REBUILD_COMPLETE			= 0x0003,
};

static const char * const telemetry_boot_seq_event_id_str[] = {
	[MAIN_FW_BOOT_COMPLETE]			= "Main Firmware Boot Complete",
	[FTL_LOAD_FROM_NVM_COMPLETE]	= "FTL Load from NVM Complete",
	[FTL_REBUILD_STARTED]			= "FTL Rebuild Started",
	[FTL_REBUILD_COMPLETE]			= "FTL Rebuild Complete",
};

/*****************************************************************************
 * Telemetry Firmware Assert Class (06h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_FW_ASSERT_EVENT_ID {
	ASSERT_NVME_CODE				= 0x0000,
	ASSERT_MEDIA_CODE				= 0x0001,
	ASSERT_SECURITY_CODE			= 0x0002,
	ASSERT_BACKGROUND_CODE			= 0x0003,
	FTL_REBUILD_FAILED				= 0x0004,
	FTL_DATA_MISMATCH				= 0x0005,
	ASSERT_OTHER_CODE				= 0x0006,
};

static const char * const telemetry_fw_assert_event_id_str[] = {
	[ASSERT_NVME_CODE]				= "Assert in NVMe Processing Code",
	[ASSERT_MEDIA_CODE]				= "Assert in Media Code",
	[ASSERT_SECURITY_CODE]			= "Assert in Security Code",
	[ASSERT_BACKGROUND_CODE]		= "Assert in Background Services Code",
	[FTL_REBUILD_FAILED]			= "FTL Rebuild Failed",
	[FTL_DATA_MISMATCH]				= "FTL Data Mismatch",
	[ASSERT_OTHER_CODE]		        = "Assert in Other Code",
};

/*****************************************************************************
 * Telemetry Temperature Class (07h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_TEMPERATURE_EVENT_ID {
	COMPOSITE_TEMP_DECREASE			= 0x0000,
	COMPOSITE_TEMP_INCREASE_WCTEMP	= 0x0001,
	COMPOSITE_TEMP_INCREASE_CCTEMP	= 0x0002,
};

static const char * const telemetry_temperature_event_id_str[] = {
	[COMPOSITE_TEMP_DECREASE]			= "Composite Temp Decreases to (WCTEMP-2)",
	[COMPOSITE_TEMP_INCREASE_WCTEMP]	= "Composite Temp Increases to WCTEMP",
	[COMPOSITE_TEMP_INCREASE_CCTEMP]	= "Composite Temp Increases to CCTEMP",
};

/*****************************************************************************
 * Telemetry Media Debug Class (08h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_MEDIA_DEBUG_EVENT_ID {
	XOR_RECOVERY_INVOKED			= 0x0000,
	UNCORRECTABLE_MEDIA_ERROR		= 0x0001,
	BAD_BLOCK_PROGRAM_ERROR			= 0x0002,
	BAD_BLOCK_ERASE_ERROR			= 0x0003,
	BAD_BLOCK_READ_ERROR			= 0x0004,
	PLANE_FAILURE_EVENT				= 0x0005,
};

static const char * const telemetry_media_debug_event_id_str[] = {
	[XOR_RECOVERY_INVOKED]			= "XOR Recovery Invoked",
	[UNCORRECTABLE_MEDIA_ERROR]		= "Uncorrectable Media Error",
	[BAD_BLOCK_PROGRAM_ERROR]		= "Block Marked Bad Due to Program Error",
	[BAD_BLOCK_ERASE_ERROR]			= "Block Marked Bad Due to Erase Error",
	[BAD_BLOCK_READ_ERROR]			= "Block Marked Bad Due to Read Error",
	[PLANE_FAILURE_EVENT]			= "Plane Failure Event",
};

/*****************************************************************************
 * Telemetry Media Wear Class (09h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_MEDIA_WEAR_EVENT_ID {
	MEDIA_WEAR						= 0x0000,
};

static const char * const telemetry_media_wear_event_id_str[] = {
	[MEDIA_WEAR]					= "Media Wear",
};

/*****************************************************************************
 * Telemetry Virtual FIFO (0Bh) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_VIRTUAL_FIFO_EVENT_ID {
	VIRTUAL_FIFO_START			= 0x0000,
	VIRTUAL_FIFO_END			= 0x0002,
};

static const char * const telemetry_virtual_fifo_event_id_str[] = {
	[VIRTUAL_FIFO_START]			= "Virtual FIFO Start",
	[VIRTUAL_FIFO_END]				= "Virtual FIFO End",
};


/*****************************************************************************
 * Telemetry Data Structures
 *****************************************************************************/
#define TELEMETRY_HEADER_SIZE 512
#define TELEMETRY_DATA_SIZE 1536
#define TELEMETRY_BYTE_PER_BLOCK 512
#define TELEMETRY_TRANSFER_SIZE 1024
#define FILE_NAME_SIZE 2048

enum TELEMETRY_TYPE {
	TELEMETRY_TYPE_HOST       = 7,
	TELEMETRY_TYPE_CONTROLLER = 8,
	TELEMETRY_TYPE_HOST_0     = 9,
	TELEMETRY_TYPE_HOST_1     = 10,
};

struct telemetry_initiated_log {
	__u8  LogIdentifier;
	__u8  Reserved1[4];
	__u8  IEEE[3];
	__le16 DataArea1LastBlock;
	__le16 DataArea2LastBlock;
	__le16 DataArea3LastBlock;
	__u8  Reserved2[2];
	__le32 DataArea4LastBlock;
	__u8  Reserved3[361];
	__u8  DataHostGenerationNumber;
	__u8  CtlrDataAvailable;
	__u8  DataCtlrGenerationNumber;
	__u8  ReasonIdentifier[128];
};

struct telemetry_stats_desc {
	__le16 id;
	__u8 info;
	__u8 ns_info;
	__le16 size;
	__le16 nsid;
	__u8 data[];
};

struct __packed telemetry_event_desc {
	__u8 class;
	__le16 id;
	__u8 size;
	__u8 data[];
};

struct event_fifo {
	__le64	start;
	__le64	size;
};

struct telemetry_data_area_1 {
	__le16 major_version;
	__le16 minor_version;
	__u8   reserved1[4];
	__le64 timestamp;
	__u8   log_page_guid[GUID_LEN];
	__u8   no_of_tps_supp;
	__u8   tps;
	__u8   reserved2[6];
	__le64 sls;
	__u8   reserved3[8];
	__u8   fw_revision[8];
	__u8   reserved4[32];
	__le64 da1_stat_start;
	__le64 da1_stat_size;
	__le64 da2_stat_start;
	__le64 da2_stat_size;
	__u8   reserved5[32];
	__u8   event_fifo_da[16];
	struct event_fifo event_fifos[16];
	__u8   reserved6[80];
	__u8   smart_health_info[512];
	__u8   smart_health_info_extended[512];
};

#define DATA_SIZE_12   12
#define DATA_SIZE_8    8
#define DATA_SIZE_4    4
#define MAX_BUFFER_32_KB              0x8000
#define OCP_TELEMETRY_DATA_BLOCK_SIZE 512
#define SIZE_OF_DWORD                 4
#define MAX_NUM_FIFOS                 16
#define DA1_OFFSET                    512
#define DEFAULT_ASCII_STRING_SIZE     16
#define SIZE_OF_VU_EVENT_ID           2

#define DEFAULT_TELEMETRY_BIN "telemetry.bin"
#define DEFAULT_STRING_BIN "string.bin"
#define DEFAULT_OUTPUT_FORMAT_JSON "json"

/* C9 Telemetry String Log Format Log Page */
#define C9_TELEMETRY_STR_LOG_LEN                 432
#define C9_TELEMETRY_STR_LOG_SIST_OFST           431

#define STR_LOG_PAGE_HEADER "Log Page Header"
#define STR_REASON_IDENTIFIER "Reason Identifier"
#define STR_TELEMETRY_HOST_DATA_BLOCK_1 "Telemetry Host-Initiated Data Block 1"
#define STR_SMART_HEALTH_INFO "SMART / Health Information Log(LID-02h)"
#define STR_SMART_HEALTH_INTO_EXTENDED "SMART / Health Information Extended(LID-C0h)"
#define STR_DA_1_STATS "Data Area 1 Statistics"
#define STR_DA_2_STATS "Data Area 2 Statistics"
#define STR_DA_1_EVENT_FIFO_INFO "Data Area 1 Event FIFO info"
#define STR_DA_2_EVENT_FIFO_INFO "Data Area 2 Event FIFO info"
#define STR_STATISTICS_IDENTIFIER "Statistics Identifier"
#define STR_STATISTICS_IDENTIFIER_STR "Statistic Identifier String"
#define STR_STATISTICS_INFO_BEHAVIOUR_TYPE "Statistics Info Behavior Type"
#define STR_STATISTICS_INFO_RESERVED "Statistics Info Reserved"
#define STR_NAMESPACE_IDENTIFIER "Namespace Identifier"
#define STR_NAMESPACE_INFO_VALID "Namespace Information Valid"
#define STR_STATISTICS_DATA_SIZE "Statistic Data Size"
#define STR_RESERVED "Reserved"
#define STR_STATISTICS_SPECIFIC_DATA "Statistic Specific Data"
#define STR_STATISTICS_WORST_DIE_PERCENT "Worst die % of bad blocks"
#define STR_STATISTICS_WORST_DIE_RAW "Worst die raw number of bad blocks"
#define STR_STATISTICS_WORST_NAND_CHANNEL_PERCENT "Worst NAND channel % of bad blocks"
#define STR_STATISTICS_WORST_NAND_CHANNEL_RAW "Worst NAND channel number of bad blocks"
#define STR_STATISTICS_BEST_NAND_CHANNEL_PERCENT "Best NAND channel % of bad blocks"
#define STR_STATISTICS_BEST_NAND_CHANNEL_RAW "Best NAND channel number of bad blocks"
#define STR_CLASS_SPECIFIC_DATA "Class Specific Data"
#define STR_DBG_EVENT_CLASS_TYPE "Debug Event Class type"
#define STR_EVENT_IDENTIFIER "Event Identifier"
#define STR_EVENT_STRING "Event String"
#define STR_EVENT_DATA_SIZE "Event Data Size"
#define STR_VU_EVENT_STRING "VU Event String"
#define STR_VU_EVENT_ID_STRING "VU Event Identifier"
#define STR_VU_DATA "VU Data"
#define STR_LINE "==============================================================================\n"
#define STR_LINE2 "-----------------------------------------------------------------------------\n"

/**
 * enum ocp_telemetry_data_area - Telemetry Data Areas
 * @DATA_AREA_1:	Data Area 1
 * @DATA_AREA_2:	Data Area 2
 * @DATA_AREA_3:	Data Area 3
 * @DATA_AREA_4:	Data Area 4
 */
enum ocp_telemetry_data_area {
	DATA_AREA_1 = 0x01,
	DATA_AREA_2 = 0x02,
	DATA_AREA_3 = 0x03,
	DATA_AREA_4 = 0x04,
};

/**
 * enum ocp_telemetry_string_tables - OCP telemetry string tables
 * @STATISTICS_IDENTIFIER_STRING:	Statistic Identifier string
 * @EVENT_STRING:	Event String
 * @VU_EVENT_STRING:	VU Event String
 */
enum ocp_telemetry_string_tables {
	STATISTICS_IDENTIFIER_STRING = 0,
	EVENT_STRING,
	VU_EVENT_STRING
};

/**
 * enum ocp_telemetry_statistics_identifiers - OCP Statistics Identifiers
 */
enum ocp_telemetry_statistic_identifiers {
	STATISTICS_RESERVED_ID = 0x00,
	OUTSTANDING_ADMIN_CMDS_ID = 0x01,
	HOST_WRTIE_BANDWIDTH_ID = 0x02,
	GW_WRITE_BANDWITH_ID = 0x03,
	ACTIVE_NAMESPACES_ID = 0x04,
	INTERNAL_WRITE_WORKLOAD_ID = 0x05,
	INTERNAL_READ_WORKLOAD_ID = 0x06,
	INTERNAL_WRITE_QUEUE_DEPTH_ID = 0x07,
	INTERNAL_READ_QUEUE_DEPTH_ID = 0x08,
	PENDING_TRIM_LBA_COUNT_ID = 0x09,
	HOST_TRIM_LBA_REQUEST_COUNT_ID = 0x0A,
	CURRENT_NVME_POWER_STATE_ID = 0x0B,
	CURRENT_DSSD_POWER_STATE_ID = 0x0C,
	PROGRAM_FAIL_COUNT_ID = 0x0D,
	ERASE_FAIL_COUNT_ID = 0x0E,
	READ_DISTURB_WRITES_ID = 0x0F,

	RETENTION_WRITES_ID = 0x10,
	WEAR_LEVELING_WRITES_ID = 0x11,
	READ_RECOVERY_WRITES_ID = 0x12,
	GC_WRITES_ID = 0x13,
	SRAM_CORRECTABLE_COUNT_ID = 0x14,
	DRAM_CORRECTABLE_COUNT_ID = 0x15,
	SRAM_UNCORRECTABLE_COUNT_ID = 0x16,
	DRAM_UNCORRECTABLE_COUNT_ID = 0x17,
	DATA_INTEGRITY_ERROR_COUNT_ID = 0x18,
	READ_RETRY_ERROR_COUNT_ID = 0x19,
	PERST_EVENTS_COUNT_ID = 0x1A,
	MAX_DIE_BAD_BLOCK_ID = 0x1B,
	MAX_NAND_CHANNEL_BAD_BLOCK_ID = 0x1C,
	MIN_NAND_CHANNEL_BAD_BLOCK_ID = 0x1D,

	//RESERVED = 7FFFh-1Eh,
	//VENDOR_UNIQUE_CLASS_TYPE = FFFFh-8000h,
};


/**
 * enum ocp_telemetry_debug_event_class_types - OCP Debug Event Class types
 * @RESERVED_CLASS_TYPE:	       Reserved class
 * @TIME_STAMP_CLASS_TYPE:	       Time stamp class
 * @PCIE_CLASS_TYPE:	           PCIe class
 * @NVME_CLASS_TYPE:	           NVME class
 * @RESET_CLASS_TYPE:	           Reset class
 * @BOOT_SEQUENCE_CLASS_TYPE:	   Boot Sequence class
 * @FIRMWARE_ASSERT_CLASS_TYPE:	   Firmware Assert class
 * @TEMPERATURE_CLASS_TYPE:	       Temperature class
 * @MEDIA_CLASS_TYPE:	           Media class
 * @MEDIA_WEAR_CLASS_TYPE:	       Media wear class
 * @STATISTIC_SNAPSHOT_CLASS_TYPE: Statistic snapshot class
 * @RESERVED:	                   Reserved class
 * @VENDOR_UNIQUE_CLASS_TYPE:	   Vendor Unique class
 */
enum ocp_telemetry_debug_event_class_types {
	RESERVED_CLASS_TYPE = 0x00,
	TIME_STAMP_CLASS_TYPE = 0x01,
	PCIE_CLASS_TYPE = 0x02,
	NVME_CLASS_TYPE = 0x03,
	RESET_CLASS_TYPE = 0x04,
	BOOT_SEQUENCE_CLASS_TYPE = 0x05,
	FIRMWARE_ASSERT_CLASS_TYPE = 0x06,
	TEMPERATURE_CLASS_TYPE = 0x07,
	MEDIA_CLASS_TYPE = 0x08,
	MEDIA_WEAR_CLASS_TYPE = 0x09,
	STATISTIC_SNAPSHOT_CLASS_TYPE = 0x0A,
	//RESERVED = 7Fh-0Bh,
	//VENDOR_UNIQUE_CLASS_TYPE = FFh-80h,
};

/**
 * struct telemetry_str_log_format - Telemetry String Log Format
 * @log_page_version:          indicates the version of the mapping this log page uses
 *                             Shall be set to 01h.
 * @reserved1:                 Reserved.
 * @log_page_guid:             Shall be set to B13A83691A8F408B9EA495940057AA44h.
 * @sls:                       Shall be set to the number of DWORDS in the String Log.
 * @reserved2:                 reserved.
 * @sits:                      shall be set to the number of DWORDS in the Statistics
 *                             Identifier String Table
 * @ests:                      Shall be set to the number of DWORDS from byte 0 of this
 *                             log page to the start of the Event String Table
 * @estsz:                     shall be set to the number of DWORDS in the Event String Table
 * @vu_eve_sts:                Shall be set to the number of DWORDS from byte 0 of this
 *                             log page to the start of the VU Event String Table
 * @vu_eve_st_sz:              shall be set to the number of DWORDS in the VU Event String Table
 * @ascts:                     the number of DWORDS from byte 0 of this log page until the
 *                             ASCII Table Starts.
 * @asctsz:                    the number of DWORDS in the ASCII Table
 * @fifo1:                     FIFO 0 ASCII String
 * @fifo2:                     FIFO 1 ASCII String
 * @fifo3:                     FIFO 2 ASCII String
 * @fifo4:                     FIFO 3 ASCII String
 * @fif05:                     FIFO 4 ASCII String
 * @fifo6:                     FIFO 5 ASCII String
 * @fifo7:                     FIFO 6 ASCII String
 * @fifo8:                     FIFO 7 ASCII String
 * @fifo9:                     FIFO 8 ASCII String
 * @fifo10:                    FIFO 9 ASCII String
 * @fif011:                    FIFO 10 ASCII String
 * @fif012:                    FIFO 11 ASCII String
 * @fifo13:                    FIFO 12 ASCII String
 * @fif014:                    FIFO 13 ASCII String
 * @fif015:                    FIFO 14 ASCII String
 * @fif016:                    FIFO 15 ASCII String
 * @reserved3:                 reserved
 */
struct __packed telemetry_str_log_format {
	__u8    log_page_version;
	__u8    reserved1[15];
	__u8    log_page_guid[GUID_LEN];
	__le64  sls;
	__u8    reserved2[24];
	__le64  sits;
	__le64  sitsz;
	__le64  ests;
	__le64  estsz;
	__le64  vu_eve_sts;
	__le64  vu_eve_st_sz;
	__le64  ascts;
	__le64  asctsz;
	__u8    fifo1[16];
	__u8    fifo2[16];
	__u8    fifo3[16];
	__u8    fifo4[16];
	__u8    fifo5[16];
	__u8    fifo6[16];
	__u8    fifo7[16];
	__u8    fifo8[16];
	__u8    fifo9[16];
	__u8    fifo10[16];
	__u8    fifo11[16];
	__u8    fifo12[16];
	__u8    fifo13[16];
	__u8    fifo14[16];
	__u8    fifo15[16];
	__u8    fifo16[16];
	__u8    reserved3[48];
};

/*
 * struct statistics_id_str_table_entry - Statistics Identifier String Table Entry
 * @vs_si:                    Shall be set the Vendor Unique Statistic Identifier number.
 * @reserved1:                Reserved
 * @ascii_id_len:             Shall be set the number of ASCII Characters that are valid.
 * @ascii_id_ofst:            Shall be set to the offset from DWORD 0/Byte 0 of the Start
 *                            of the ASCII Table to the first character of the string for
 *                            this Statistic Identifier string..
 * @reserved2                 reserved
 */
struct __packed statistics_id_str_table_entry {
	__le16  vs_si;
	__u8    reserved1;
	__u8    ascii_id_len;
	__le64  ascii_id_ofst;
	__le32  reserved2;
};

/*
 * struct event_id_str_table_entry - Event Identifier String Table Entry
 * @deb_eve_class:            Shall be set the Debug Class.
 * @ei:                       Shall be set to the Event Identifier
 * @ascii_id_len:             Shall be set the number of ASCII Characters that are valid.
 * @ascii_id_ofst:            This is the offset from DWORD 0/ Byte 0 of the start of the
 *                            ASCII table to the ASCII data for this identifier
 * @reserved2                 reserved
 */
struct __packed event_id_str_table_entry {
	__u8      deb_eve_class;
	__le16    ei;
	__u8      ascii_id_len;
	__le64    ascii_id_ofst;
	__le32    reserved2;
};

/*
 * struct vu_event_id_str_table_entry - VU Event Identifier String Table Entry
 * @deb_eve_class:            Shall be set the Debug Class.
 * @vu_ei:                    Shall be set to the VU Event Identifier
 * @ascii_id_len:             Shall be set the number of ASCII Characters that are valid.
 * @ascii_id_ofst:            This is the offset from DWORD 0/ Byte 0 of the start of the
 *                            ASCII table to the ASCII data for this identifier
 * @reserved                  reserved
 */
struct __packed vu_event_id_str_table_entry {
	__u8      deb_eve_class;
	__le16    vu_ei;
	__u8      ascii_id_len;
	__le64    ascii_id_ofst;
	__le32    reserved;
};


struct __packed ocp_telemetry_parse_options {
	char *telemetry_log;
	char *string_log;
	char *output_file;
	char *output_format;
	int data_area;
	char *telemetry_type;
};

struct __packed nvme_ocp_telemetry_reason_id
{
	__u8 error_id[64];                // Bytes 63:00
	__u8 file_id[8];                  // Bytes 71:64
	__le16 line_number;               // Bytes 73:72
	__u8 valid_flags;                 // Bytes 74
	__u8 reserved[21];                // Bytes 95:75
	__u8 vu_reason_ext[32];           // Bytes 127:96
};

struct __packed nvme_ocp_telemetry_common_header
{
	__u8 log_id;                             // Byte 00
	__le32 reserved1;                        // Bytes 04:01
	__u8 ieee_oui_id[3];                     // Bytes 07:05
	__le16 da1_last_block;                   // Bytes 09:08
	__le16 da2_last_block;                   // Bytes 11:10
	__le16 da3_last_block;                   // Bytes 13:12
	__le16 reserved2;                        // Bytes 15:14
	__le32 da4_last_block;                   // Bytes 19:16
};

struct __packed nvme_ocp_telemetry_host_initiated_header
{
	struct nvme_ocp_telemetry_common_header commonHeader;    // Bytes 19:00
	__u8 reserved3[360];                                     // Bytes 379:20
	__u8 host_initiated_scope;                               // Byte 380
	__u8 host_initiated_gen_number;                          // Byte 381
	__u8 host_initiated_data_available;                      // Byte 382
	__u8 ctrl_initiated_gen_number;                          // Byte 383
	struct nvme_ocp_telemetry_reason_id reason_id;           // Bytes 511:384
};

struct __packed nvme_ocp_telemetry_controller_initiated_header
{
	struct nvme_ocp_telemetry_common_header commonHeader;   // Bytes 19:00
	__u8 reserved3[361];                                    // Bytes 380:20
	__u8 ctrl_initiated_scope;                              // Byte 381
	__u8 ctrl_initiated_data_available;                     // Byte 382
	__u8 ctrl_initiated_gen_number;                         // Byte 383
	struct nvme_ocp_telemetry_reason_id reason_id;          // Bytes 511:384
};

struct __packed nvme_ocp_telemetry_smart
{
	__u8 critical_warning;                                         // Byte 0
	__le16 composite_temperature;                                  // Bytes 2:1
	__u8 available_spare;                                          // Bytes 3
	__u8 available_spare_threshold;                                // Bytes 4
	__u8 percentage_used;                                          // Bytes 5
	__u8 reserved1[26];                                            // Bytes 31:6
	__u8 data_units_read[16];                                      // Bytes 47:32
	__u8 data_units_written[16];                                   // Bytes 63:48
	__u8 host_read_commands[16];                                   // Byte  79:64
	__u8 host_write_commands[16];                                  // Bytes 95:80
	__u8 controller_busy_time[16];                                 // Bytes 111:96
	__u8 power_cycles[16];                                         // Bytes 127:112
	__u8 power_on_hours[16];                                       // Bytes 143:128
	__u8 unsafe_shutdowns[16];                                     // Bytes 159:144
	__u8 media_and_data_integrity_errors[16];                      // Bytes 175:160
	__u8 number_of_error_information_log_entries[16];              // Bytes 191:176
	__le32 warning_composite_temperature_time;                     // Byte  195:192
	__le32 critical_composite_temperature_time;                    // Bytes 199:196
	__le16 temperature_sensor1;                                    // Bytes 201:200
	__le16 temperature_sensor2;                                    // Byte  203:202
	__le16 temperature_sensor3;                                    // Byte  205:204
	__le16 temperature_sensor4;                                    // Bytes 207:206
	__le16 temperature_sensor5;                                    // Bytes 209:208
	__le16 temperature_sensor6;                                    // Bytes 211:210
	__le16 temperature_sensor7;                                    // Bytes 213:212
	__le16 temperature_sensor8;                                    // Bytes 215:214
	__le32 thermal_management_temperature1_transition_count;       // Bytes 219:216
	__le32 thermal_management_temperature2_transition_count;       // Bytes 223:220
	__le32 total_time_for_thermal_management_temperature1;         // Bytes 227:224
	__le32 total_time_for_thermal_management_temperature2;         // Bytes 231:228
	__u8 reserved2[280];                                           // Bytes 511:232
};

struct __packed nvme_ocp_telemetry_smart_extended
{
	__u8 physical_media_units_written[16];                   // Bytes 15:0
	__u8 physical_media_units_read[16];                      // Bytes 31:16
	__u8 bad_user_nand_blocks_raw_count[6];                  // Bytes 37:32
	__le16 bad_user_nand_blocks_normalized_value;            // Bytes 39:38
	__u8 bad_system_nand_blocks_raw_count[6];                // Bytes 45:40
	__le16 bad_system_nand_blocks_normalized_value;          // Bytes 47:46
	__le64 xor_recovery_count;                               // Bytes 55:48
	__le64 uncorrectable_read_error_count;                   // Bytes 63:56
	__le64 soft_ecc_error_count;                             // Bytes 71:64
	__le32 end_to_end_correction_counts_detected_errors;     // Bytes 75:72
	__le32 end_to_end_correction_counts_corrected_errors;    // Bytes 79:76
	__u8 system_data_percent_used;                           // Byte  80
	__u8 refresh_counts[7];                                  // Bytes 87:81
	__le32 max_user_data_erase_count;                        // Bytes 91:88
	__le32 min_user_data_erase_count;                        // Bytes 95:92
	__u8 num_thermal_throttling_events;                      // Bytes 96
	__u8 current_throttling_status;                          // Bytes 97
	__u8  errata_version_field;                              // Byte 98
	__le16 point_version_field;                              // Byte 100:99
	__le16 minor_version_field;                              // Byte 102:101
	__u8  major_version_field;                               // Byte 103
	__le64 pcie_correctable_error_count;                     // Bytes 111:104
	__le32 incomplete_shutdowns;                             // Bytes 115:112
	__le32 reserved1;                                        // Bytes 119:116
	__u8 percent_free_blocks;                                // Byte  120
	__u8 reserved2[7];                                       // Bytes 127:121
	__le16 capacitor_health;                                 // Bytes 129:128
	__u8 nvme_base_errata_version;                           // Byte  130
	__u8 nvme_command_set_errata_version;                    // Byte  131
	__le32 reserved3;                                        // Bytes 135:132
	__le64 unaligned_io;                                     // Bytes 143:136
	__le64 security_version_number;                          // Bytes 151:144
	__le64 total_nuse;                                       // Bytes 159:152
	__u8 plp_start_count[16];                                // Bytes 175:160
	__u8 endurance_estimate[16];                             // Bytes 191:176
	__le64 pcie_link_retraining_count;                       // Bytes 199:192
	__le64 power_state_change_count;                         // Bytes 207:200
	__le64 lowest_permitted_firmware_revision;               // Bytes 215:208
	__u8 reserved4[278];                                     // Bytes 493:216
	__le16 log_page_version;                                 // Bytes 495:494
	__u8 log_page_guid[GUID_LEN];                            // Bytes 511:496
};

struct __packed nvme_ocp_event_fifo_data
{
	__le32 event_fifo_num;
	__u8 event_fifo_da;
	__le64 event_fifo_start;
	__le64 event_fifo_size;
};

struct __packed nvme_ocp_telemetry_offsets
{
	__le32 data_area;
	__le32 header_size;
	__le32 da1_start_offset;
	__le32 da1_size;
	__le32 da2_start_offset;
	__le32 da2_size;
	__le32 da3_start_offset;
	__le32 da3_size;
	__le32 da4_start_offset;
	__le32 da4_size;
};

struct __packed nvme_ocp_event_fifo_offsets
{
	__le64 event_fifo_start;
	__le64 event_fifo_size;
};

struct __packed nvme_ocp_header_in_da1
{
	__le16 major_version;                                                // Bytes 1:0
	__le16 minor_version;                                                // Bytes 3:2
	__le32 reserved1;                                                    // Bytes 7:4
	__le64 time_stamp;                                                   // Bytes 15:8
	__u8 log_page_guid[GUID_LEN];                                        // Bytes 31:16
	__u8 num_telemetry_profiles_supported;                               // Byte 32
	__u8 telemetry_profile_selected;                                     // Byte 33
	__u8 reserved2[6];                                                   // Bytes 39:34
	__le64 string_log_size;                                              // Bytes 47:40
	__le64 reserved3;                                                    // Bytes 55:48
	__le64 firmware_revision;                                            // Bytes 63:56
	__u8 reserved4[32];                                                  // Bytes 95:64
	__le64 da1_statistic_start;                                          // Bytes 103:96
	__le64 da1_statistic_size;                                           // Bytes 111:104
	__le64 da2_statistic_start;                                          // Bytes 119:112
	__le64 da2_statistic_size;                                           // Bytes 127:120
	__u8 reserved5[32];                                                  // Bytes 159:128
	__u8 event_fifo_da[16];                                              // Bytes 175:160
	struct nvme_ocp_event_fifo_offsets fifo_offsets[16];                 // Bytes 431:176
	__u8 reserved6[80];                                                  // Bytes 511:432
	struct nvme_ocp_telemetry_smart smart_health_info;                   // Bytes 1023:512
	struct nvme_ocp_telemetry_smart_extended smart_health_info_extended; // Bytes 1535:1024
};

struct __packed nvme_ocp_telemetry_statistic_descriptor
{
	__le16 statistic_id;                    // Bytes 1:0
	__u8 statistic_info_behaviour_type : 4; // Byte  2(3:0)
	__u8 statistic_info_reserved : 4;       // Byte  2(7:4)
	__u8 ns_info_nsid : 7;                  // Bytes 3(6:0)
	__u8 ns_info_ns_info_valid : 1;         // Bytes 3(7)
	__le16 statistic_data_size;             // Bytes 5:4
	__le16 reserved;                        // Bytes 7:6
};

struct __packed nvme_ocp_telemetry_event_descriptor
{
	__u8 debug_event_class_type;    // Byte 0
	__le16 event_id;                // Bytes 2:1
	__u8 event_data_size;           // Byte 3
};

struct __packed nvme_ocp_time_stamp_dbg_evt_class_format
{
	__u8 time_stamp[DATA_SIZE_8];             // Bytes 11:4
};

struct __packed nvme_ocp_pcie_dbg_evt_class_format
{
	__u8 pCIeDebugEventData[DATA_SIZE_4];     // Bytes 7:4
};

struct __packed nvme_ocp_nvme_dbg_evt_class_format
{
	__u8 nvmeDebugEventData[DATA_SIZE_8];     // Bytes 11:4
};

struct __packed nvme_ocp_media_wear_dbg_evt_class_format
{
	__u8 currentMediaWear[DATA_SIZE_12];         // Bytes 15:4

};

struct __packed nvme_ocp_common_dbg_evt_class_vu_data
{
	__le16 vu_event_identifier;         // Bytes 5:4
	__u8 data[];                        // Bytes N:6
};

struct __packed nvme_ocp_statistic_snapshot_evt_class_format
{
	__u8 debug_event_class_type;    // Byte  0
	__u8 reserved1[3];              // Bytes 3:1
	__le16 stat_id;                 // Bytes 5:4
	__u8 stat_info;                 // Byte  6
	__u8 namespace_info;            // Byte  7
	__le16 stat_data_size;          // Bytes 9:8
	__le16 nsid;                    // Bytes 11:10
};

struct __packed nvme_ocp_statistics_identifier_string_table
{
	__le16 vs_statistic_identifier;     //1:0
	__u8 reserved1;                     //2
	__u8 ascii_id_length;               //3
	__le64 ascii_id_offset;             //11:4
	__le32 reserved2;                   //15:12
};

struct __packed nvme_ocp_event_string_table
{
	__u8 debug_event_class;         //0
	__le16 event_identifier;        //2:1
	__u8 ascii_id_length;           //3
	__le64 ascii_id_offset;         //11:4
	__le32 reserved;                //15:12
};

struct __packed nvme_ocp_vu_event_string_table
{
	__u8 debug_event_class;        //0
	__le16 vu_event_identifier;    //2:1
	__u8 ascii_id_length;          //3
	__le64 ascii_id_offset;        //11:4
	__le32 reserved;               //15:12
};

struct __packed nvme_ocp_telemetry_string_header
{
	__u8 version;                   //0:0
	__u8 reserved1[15];             //15:1
	__u8 guid[GUID_LEN];            //32:16
	__le64 string_log_size;         //39:32
	__u8 reserved2[24];             //63:40
	__le64 sits;                    //71:64 Statistics Identifier String Table Start(SITS)
	__le64 sitsz;                   //79:72 Statistics Identifier String Table Size (SITSZ)
	__le64 ests;                    //87:80 Event String Table Start(ESTS)
	__le64 estsz;                   //95:88 Event String Table Size(ESTSZ)
	__le64 vu_ests;                 //103:96 VU Event String Table Start
	__le64 vu_estsz;                //111:104 VU Event String Table Size
	__le64 ascts;                   //119:112 ASCII Table start
	__le64 asctsz;                  //127:120 ASCII Table Size
	__u8 fifo_ascii_string[16][16]; //383:128
	__u8 reserved3[48];             //431:384
};

struct __packed statistic_entry {
	int identifier;
	char *description;
};

/************************************************************
 * Telemetry Parsing Function Prototypes
 ************************************************************/
void print_vu_event_data(__u32 size, __u8 *data);
void print_stats_desc(struct telemetry_stats_desc *stat_desc);
void print_telemetry_fifo_event(__u8 class_type,
		__u16 id, __u8 size, __u8 *data);


/************************************************************
 * Telemetry ID to String Conversion Functions
 ************************************************************/
static inline const char *arg_str(const char * const *strings,
		size_t array_size, size_t idx)
{
	if (idx < array_size && strings[idx])
		return strings[idx];
	return "unrecognized";
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define ARGSTR(s, i) arg_str(s, ARRAY_SIZE(s), i)

static inline const char *telemetry_stat_id_to_string(int stat_id)
{
	return ARGSTR(telemetry_stat_id_str, stat_id);
}
static inline const char *telemetry_event_class_to_string(int class)
{
	return ARGSTR(telemetry_event_class_str, class);
}
static inline const char *telemetry_ts_event_to_string(int event_id)
{
	return ARGSTR(telemetry_timestamp_event_id_str, event_id);
}
static inline const char *telemetry_pcie_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_pcie_event_id_str, event_id);
}
static inline const char *telemetry_pcie_state_data_to_string(int pcie_state)
{
	return ARGSTR(telemetry_pcie_state_data_str, pcie_state);
}
static inline const char *telemetry_pcie_speed_data_to_string(int pcie_speed)
{
	return ARGSTR(telemetry_pcie_speed_data_str, pcie_speed);
}
static inline const char *telemetry_pcie_width_data_to_string(int pcie_width)
{
	return ARGSTR(telemetry_pcie_width_data_str, pcie_width);
}
static inline const char *telemetry_nvme_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_nvme_event_id_str, event_id);
}
static inline const char *telemetry_reset_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_reset_event_id_str, event_id);
}
static inline const char *telemetry_boot_seq_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_boot_seq_event_id_str, event_id);
}
static inline const char *telemetry_fw_assert_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_fw_assert_event_id_str, event_id);
}
static inline const char *telemetry_temperature_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_temperature_event_id_str, event_id);
}
static inline const char *telemetry_media_debug_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_media_debug_event_id_str, event_id);
}
static inline const char *telemetry_media_wear_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_media_wear_event_id_str, event_id);
}
static inline const char *telemetry_virtual_fifo_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_virtual_fifo_event_id_str, event_id);
}

/**
 * @brief parse the ocp telemetry host or controller log binary file
 *        into json or text
 *
 * @param options, input pointer for inputs like telemetry log bin file,
 *        string log bin file and output file etc.
 *
 * @return 0 success
 */
int parse_ocp_telemetry_log(struct ocp_telemetry_parse_options *options);

/**
 * @brief parse the ocp telemetry string log binary file to json or text
 *
 * @param event_fifo_num, input event FIFO number
 * @param debug_event_class, input debug event class id
 * @param string_table, input string table
 * @param description, input description string
 *
 * @return 0 success
 */
int parse_ocp_telemetry_string_log(int event_fifo_num, int identifier, int debug_event_class,
	enum ocp_telemetry_string_tables string_table, char *description);

/**
 * @brief gets the telemetry datas areas, offsets and sizes information
 *
 * @param ptelemetry_common_header, input telemetry common header pointer
 * @param ptelemetry_das_offset, input telemetry offsets pointer
 *
 * @return 0 success
 */
int get_telemetry_das_offset_and_size(
	struct nvme_ocp_telemetry_common_header *ptelemetry_common_header,
	struct nvme_ocp_telemetry_offsets *ptelemetry_das_offset);

/**
 * @brief parses statistics data to text or json formats
 *
 * @param root, input time json root object pointer
 * @param ptelemetry_das_offset, input telemetry offsets pointer
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_statistics(struct json_object *root, struct nvme_ocp_telemetry_offsets *pOffsets,
	FILE *fp);

/**
 * @brief parses a single statistic data to text or json formats
 *
 * @param pstatistic_entry, statistic entry pointer
 * @param pstats_array, stats array pointer
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_statistic(struct nvme_ocp_telemetry_statistic_descriptor *pstatistic_entry,
	struct json_object *pstats_array, FILE *fp);

/**
 * @brief parses event fifos data to text or json formats
 *
 * @param root, input time json root object pointer
 * @param poffsets, input telemetry offsets pointer
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_event_fifos(struct json_object *root, struct nvme_ocp_telemetry_offsets *poffsets,
	FILE *fp);

/**
 * @brief parses a single event fifo data to text or json formats
 *
 * @param fifo_num, input event fifo number
 * @param pfifo_start, event fifo start pointer
 * @param pevent_fifos_object, event fifos json object pointer
 * @param ptelemetry_das_offset, input telemetry offsets pointer
 * @param fifo_size, input event fifo size
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_event_fifo(unsigned int fifo_num, unsigned char *pfifo_start,
	struct json_object *pevent_fifos_object, unsigned char *pstring_buffer,
	struct nvme_ocp_telemetry_offsets *poffsets, __u64 fifo_size, FILE *fp);

/**
 * @brief parses event fifos data to text or json formats
 *
 * @return 0 success
 */
int print_ocp_telemetry_normal(struct ocp_telemetry_parse_options *options);

/**
 * @brief parses event fifos data to text or json formats
 *
 * @return 0 success
 */
int print_ocp_telemetry_json(struct ocp_telemetry_parse_options *options);

/**
 * @brief gets statistic id ascii string
 *
 * @param identifier, string id
 * @param description, string description
 *
 * @return 0 success
 */
int get_statistic_id_ascii_string(int identifier, char *description);

/**
 * @brief gets event id ascii string
 *
 * @param identifier, string id
 * @param debug_event_class, debug event class
 * @param description, string description
 *
 * @return 0 success
 */
int get_event_id_ascii_string(int identifier, int debug_event_class, char *description);

/**
 * @brief gets vu event id ascii string
 *
 * @param identifier, string id
 * @param debug_event_class, debug event class
 * @param description, string description
 *
 * @return 0 success
 */
int get_vu_event_id_ascii_string(int identifier, int debug_event_class, char *description);

/**
 * @brief parses a time-stamp event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return
 */
void parse_time_stamp_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp);

/**
 * @brief parses a pcie event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return
 */
void parse_pcie_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp);

/**
 * @brief parses a nvme event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return
 */
void parse_nvme_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp);

/**
 * @brief parses common event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return
 */
void parse_common_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp);

/**
 * @brief parses a media-wear event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return
 */
void parse_media_wear_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp);
#endif /* OCP_TELEMETRY_DECODE_H */
