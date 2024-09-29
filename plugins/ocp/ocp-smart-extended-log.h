/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2022 Meta Platforms, Inc.
 *
 * Authors: Arthur Shau <arthurshau@fb.com>,
 *          Wei Zhang <wzhang@fb.com>,
 *          Venkat Ramesh <venkatraghavan@fb.com>
 */

#ifndef OCP_SMART_EXTENDED_LOG_H
#define OCP_SMART_EXTENDED_LOG_H

struct command;
struct plugin;

enum {
	SCAO_PMUW	= 0,	/* Physical media units written */
	SCAO_PMUR	= 16,	/* Physical media units read */
	SCAO_BUNBR	= 32,	/* Bad user nand blocks raw */
	SCAO_BUNBN	= 38,	/* Bad user nand blocks normalized */
	SCAO_BSNBR	= 40,	/* Bad system nand blocks raw */
	SCAO_BSNBN	= 46,	/* Bad system nand blocks normalized */
	SCAO_XRC	= 48,	/* XOR recovery count */
	SCAO_UREC	= 56,	/* Uncorrectable read error count */
	SCAO_SEEC	= 64,	/* Soft ecc error count */
	SCAO_EEDC	= 72,	/* End to end detected errors */
	SCAO_EECE	= 76,	/* End to end corrected errors */
	SCAO_SDPU	= 80,	/* System data percent used */
	SCAO_RFSC	= 81,	/* Refresh counts */
	SCAO_MXUDEC	= 88,	/* Max User data erase counts */
	SCAO_MNUDEC	= 92,	/* Min User data erase counts */
	SCAO_NTTE	= 96,	/* Number of Thermal throttling events */
	SCAO_CTS	= 97,	/* Current throttling status */
	SCAO_EVF	= 98,	/* Errata Version Field */
	SCAO_PVF	= 99,	/* Point Version Field */
	SCAO_MIVF	= 101,	/* Minor Version Field */
	SCAO_MAVF	= 103,	/* Major Version Field */
	SCAO_PCEC	= 104,	/* PCIe correctable error count */
	SCAO_ICS	= 112,	/* Incomplete shutdowns */
	SCAO_PFB	= 120,	/* Percent free blocks */
	SCAO_CPH	= 128,	/* Capacitor health */
	SCAO_NBEV	= 130,  /* NVMe Base Errata Version */
	SCAO_NCSEV	= 131,  /* NVMe Command Set Errata Version */
	SCAO_UIO	= 136,	/* Unaligned I/O */
	SCAO_SVN	= 144,	/* Security Version Number */
	SCAO_NUSE	= 152,	/* NUSE - Namespace utilization */
	SCAO_PSC	= 160,	/* PLP start count */
	SCAO_EEST	= 176,	/* Endurance estimate */
	SCAO_PLRC	= 192,	/* PCIe Link Retraining Count */
	SCAO_PSCC	= 200,	/* Power State Change Count */
	SCAO_LPFR	= 208,	/* Lowest Permitted Firmware Revision */
	SCAO_LPV	= 494,	/* Log page version */
	SCAO_LPG	= 496,	/* Log page GUID */
};

int ocp_smart_add_log(int argc, char **argv, struct command *cmd,
	struct plugin *plugin);

#endif
