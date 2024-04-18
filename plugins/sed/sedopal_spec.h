/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _SED_OPAL_SPEC_H
#define _SED_OPAL_SPEC_H

/*
 * TCP Storage Architecture Core Specification Version 2.01
 * section 5.1.5 Method Status Codes
 */
enum sed_status_codes {
	SED_STATUS_SUCCESS =			0x00,
	SED_STATUS_NOT_AUTHORIZED =		0x01,
	SED_STATUS_OBSOLETE_1 =			0x02,
	SED_STATUS_SP_BUSY =			0x03,
	SED_STATUS_SP_FAILED =			0x04,
	SED_STATUS_SP_DISABLED =		0x05,
	SED_STATUS_SP_FROZEN =			0x06,
	SED_STATUS_NO_SESSIONS_AVAILABLE =	0x07,
	SED_STATUS_UNIQUENESS_CONFLICT =	0x08,
	SED_STATUS_INSUFFICIENT_SPACE =		0x09,
	SED_STATUS_INSUFFICIENT_ROWS =		0x0A,
	SED_STATUS_OBSOLETE_2 =			0x0B,
	SED_STATUS_INVALID_PARAMETER =		0x0C,
	SED_STATUS_OBSOLETE_3 =			0x0D,
	SED_STATUS_OBSOLETE_4 =			0x0E,
	SED_STATUS_TPER_MALFUNCTION =		0x0F,
	SED_STATUS_TRANSACTION_FAILURE =	0x10,
	SED_STATUS_RESPONSE_OVERFLOW =		0x11,
	SED_STATUS_AUTHORITY_LOCKED_OUT =	0x12,
	SED_STATUS_FAIL =			0x3F,
	SED_STATUS_NO_METHOD_STATUS =		0x89,
};

/*
 * Definitions from TCG Opal Specification v2.0.2
 */

/*
 * level 0 feature codes - section 3.1.1
 */
#define	OPAL_FEATURE_CODE_LOCKING		0x0002
#define	OPAL_FEATURE_CODE_OPALV2		0x0203

/* locking features */
#define OPAL_FEATURE_LOCKING_SUPPORTED		0x01
#define OPAL_FEATURE_LOCKING_ENABLED		0x02
#define OPAL_FEATURE_LOCKED			0x04


/*
 * discovery header as specified in section 3.1.1.1
 */
struct level_0_discovery_header {
	uint32_t	parameter_length;
	uint32_t	revision;
	uint64_t	reserved;
	uint8_t		vendor_specific[32];
};

/*
 * level 0 features as specified in section 3.1.1.3
 */
struct level_0_discovery_features {
	uint16_t	code;
	uint8_t		version;
	uint8_t		length;
	uint8_t		feature;
	uint8_t		reserved[11];
};

#endif /* _SED_OPAL_SPEC_H */
