/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _SED_OPAL_SPEC_H
#define _SED_OPAL_SPEC_H

#include <common.h>

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
 * level 0 feature flags
 */
#define OPAL_FEATURE_TPER                       0x0001
#define OPAL_FEATURE_LOCKING                    0x0002
#define OPAL_FEATURE_GEOMETRY                   0x0004
#define OPAL_FEATURE_OPALV1                     0x0008
#define OPAL_FEATURE_SINGLE_USER_MODE           0x0010
#define OPAL_FEATURE_DATA_STORE                 0x0020
#define OPAL_FEATURE_OPALV2                     0x0040
#define OPAL_FEATURE_OPALITE                    0x0080
#define OPAL_FEATURE_PYRITE_V1                  0x0100
#define OPAL_FEATURE_PYRITE_V2                  0x0200
#define OPAL_FEATURE_RUBY                       0x0400
#define OPAL_FEATURE_LOCKING_LBA                0x0800
#define OPAL_FEATURE_BLOCK_SID_AUTH             0x1000
#define OPAL_FEATURE_CONFIG_NS_LOCKING          0x2000
#define OPAL_FEATURE_DATA_REMOVAL               0x4000
#define OPAL_FEATURE_NS_GEOMETRY                0x8000

#define OPAL_SED_LOCKING_SUPPORT \
		(OPAL_FEATURE_OPALV1 | OPAL_FEATURE_OPALV2 |  \
		OPAL_FEATURE_RUBY | OPAL_FEATURE_PYRITE_V1 | \
		OPAL_FEATURE_PYRITE_V2 | OPAL_FEATURE_LOCKING)

/*
 * Definitions from TCG Opal Specification v2.0.2
 */

/*
 * level 0 feature codes - section 3.1.1
 */
#define OPAL_FEATURE_CODE_TPER                  0x0001
#define OPAL_FEATURE_CODE_LOCKING               0x0002
#define OPAL_FEATURE_CODE_GEOMETRY              0x0003

#define OPAL_FEATURE_CODE_OPALV1                0x0200
#define OPAL_FEATURE_CODE_SINGLE_USER_MODE      0x0201
#define OPAL_FEATURE_CODE_DATA_STORE            0x0202
#define OPAL_FEATURE_CODE_OPALV2                0x0203

#define OPAL_FEATURE_CODE_OPALITE               0x0301
#define OPAL_FEATURE_CODE_PYRITE_V1             0x0302
#define OPAL_FEATURE_CODE_PYRITE_V2             0x0303
#define OPAL_FEATURE_CODE_RUBY                  0x0304

#define OPAL_FEATURE_CODE_LOCKING_LBA           0x0401
#define OPAL_FEATURE_CODE_BLOCK_SID_AUTH        0x0402
#define OPAL_FEATURE_CODE_CONFIG_NS_LOCKING     0x0403
#define OPAL_FEATURE_CODE_DATA_REMOVAL          0x0404
#define OPAL_FEATURE_CODE_NS_GEOMETRY           0x0405

/* locking features */
#define OPAL_FEATURE_LOCKING_SUPPORTED		0x01
#define OPAL_FEATURE_LOCKING_ENABLED		0x02
#define OPAL_FEATURE_LOCKED			0x04
#define OPAL_FEATURE_MEDIA_ENCRYPT              0x08
#define OPAL_FEATURE_MBR_ENABLED                0x10
#define OPAL_FEATURE_MBR_DONE                   0x20

/*
 * discovery header as specified in section 3.1.1
 */
struct level_0_discovery_header {
	__be32		parameter_length;
	__be32		revision;
	__be64		reserved;
	uint8_t		vendor_specific[32];
} __packed;

/*
 * level 0 features as specified in section 3.1.1.3
 */
struct level_0_discovery_features {
	__be16		code;
	uint8_t		version;
	uint8_t		length;
} __packed;

#define TPER_FEATURE_SYNC       0x0001
#define TPER_FEATURE_ASYNC      0x0002
#define TPER_FEATURE_ACKNAK     0x0004
#define TPER_FEATURE_BUF_MGMT   0x0008
#define TPER_FEATURE_STREAMING  0x0010
#define TPER_FEATURE_COMID_MGMT 0x0040

/*
 * 3.1.1.2
 *
 * feature code 0x0001
 */
struct tper_desc {
	uint8_t         feature;
	uint8_t         reserved[11];
} __packed;

/*
 * 3.1.1.3
 *
 * feature code 0x0002
 */
struct locking_desc {
	uint8_t         features;
	uint8_t         reserved[11];
} __packed;

/*
 * 3.1.1.4
 *
 * feature code 0x0003
 */
#define GEOMETRY_ALIGNMENT_REQUIRED    0x01

struct geometry_reporting_desc {
	uint8_t         align;
	uint8_t         reserved[7];
	__be32          logical_block_size;
	__be64          alignment_granularity;
	__be64          lowest_aligned_lba;
} __packed;

/*
 * 3.1.1.5
 *
 * feature code 0x0203
 */
#define OPAL_V2_RANGE_CROSSING 0x01

struct opalv2_desc {
	__be16          base_comid;
	__be16          num_comids;
	uint8_t         flags;
	__be16          num_locking_sp_admin_auth;
	__be16          num_locking_sp_user_auth;
	uint8_t         initial_cpin_sid_ind;
	uint8_t         initial_cpin_sid_revert;
	uint8_t         reserved_future[5];
} __packed;

/*
 * 3.1.1.5
 *
 * feature code 0x0200
 */
struct opalv1_desc {
	__be16          base_comid;
	__be16          num_comids;
} __packed;

/*
 * TCG Opal SSC Feature Set v1.00 : Single User Mode
 * section 4.2.1
 *
 * feature code 0x0201
 */
#define SUM_FEATURE_ANY         0x0001
#define SUM_FEATURE_ALL         0x0002
#define SUM_FEATURE_POLICY      0x0004

struct single_user_mode_desc {
	__be32          num_locking_objects;
	uint8_t         flags;
	uint8_t         reserved[7];
} __packed;

/*
 * TCG Opal SSC Feature Set v1.00 : Additional DataStore Tables
 * section 4.2.1
 *
 * feature code 0x0202
 */
struct datastore_desc {
	__be16          reserved;
	__be16          max_tables;
	__be32          max_table_size;
	__be32          table_alignment;
} __packed;

/*
 * TCG Storage Security Subsystem Class: Opalite
 * section 3.1.1.4
 *
 * feature code 0x0301
 */
struct opalite_desc {
	__be16          base_comid;
	__be16          num_comids;
	uint8_t         reserved[5];
	uint8_t         initial_cpin_sid_ind;
	uint8_t         initial_cpin_sid_revert;
	uint8_t         reserved_future[5];
} __packed;

/*
 * TCG Storage Security Subsystem Class: Pyrite version 1
 * section 3.1.1.4
 *
 * feature code 0x0302
 */
struct pyrite_v1_desc {
	__be16          base_comid;
	__be16          num_comids;
	uint8_t         reserved[5];
	uint8_t         initial_cpin_sid_ind;
	uint8_t         initial_cpin_sid_revert;
	uint8_t         reserved_future[5];
} __packed;

/*
 * TCG Storage Security Subsystem Class: Pyrite version 2
 * section 3.1.1.4
 *
 * feature code 0x0303
 */
struct pyrite_v2_desc {
	__be16          base_comid;
	__be16          num_comids;
	uint8_t         reserved[5];
	uint8_t         initial_cpin_sid_ind;
	uint8_t         initial_cpin_sid_revert;
	uint8_t         reserved_future[5];
} __packed;

/*
 * TCG Ruby SSC Feature Set v1.00
 * section 3.1.1.5
 *
 * feature code 0x0304
 */
#define RUBY_RANGE_CROSSING    0x01

struct ruby_desc {
	__be16          base_comid;
	__be16          num_comids;
	uint8_t         flags;
	__be16          num_locking_sp_admin_auth;
	__be16          num_locking_sp_user_auth;
	uint8_t         initial_cpin_sid_ind;
	uint8_t         initial_cpin_sid_revert;
	uint8_t         reserved_future[5];
} __packed;

/*
 * TCG Storage Enterprise SSC Feature Set Locking LBA Ranges Control
 * section 4.1.1
 *
 * feature code 0x0401
 */
struct locking_lba_desc {
	uint8_t         reserved;
	uint8_t         reserved_range_control[11];
} __packed;

/*
 * TCG Storage Feature Set: Block SID Authentication
 * section 4.1.1
 *
 * feature code 0x0402
 */
#define BLOCK_SID_VALUE_STATE           0x0001
#define BLOCK_SID_BLOCKED_STATE         0x0002
#define BLOCK_SID_HW_RESET              0x0001

struct block_sid_auth_desc {
	uint8_t         states;
	uint8_t         hw_reset;
} __packed;

/*
 * TCG Storage Opal SSC Feature Set: Configurable Namespace Locking
 * section 4.2.1
 *
 * feature code 0x0403
 */
#define CONFIG_NS_RANGE_C               0x0080
#define CONFIG_NS_RANGE_P               0x0040

struct config_ns_desc {
	uint8_t         flags;
	uint8_t         reserved[3];
	__be32          max_key_count;
	__be32          unused_key_count;
	__be32          max_ranges_per_ns;
} __packed;

/*
 * TCG Storage Security Subsystem Class: Opal version 2.02
 * section 3.1.1.6
 *
 * feature code 0x0404
 */
#define DATA_REMOVAL_OPER_PROCESSING                    0x01
#define DATA_REMOVAL_OPER_INTERRUPTED                   0x02
#define DATA_REMOVAL_TIME_BIT0                          0x01
#define DATA_REMOVAL_TIME_BIT1                          0x02
#define DATA_REMOVAL_TIME_BIT2                          0x04
#define DATA_REMOVAL_TIME_BIT5                          0x20

#define DATA_REMOVAL_MECHANISM_OVERWRITE                0x01
#define DATA_REMOVAL_MECHANISM_BLOCK_ERASE              0x02
#define DATA_REMOVAL_MECHANISM_CRYPTO_ERASE             0x04
#define DATA_REMOVAL_MECHANISM_VENDOR_ERASE             0x10

struct data_removal_desc {
	uint8_t         reserved;
	uint8_t         flags;
	uint8_t         removal_mechanism;
	uint8_t         format;
	__be16          time_mechanism_bit0;
	__be16          time_mechanism_bit1;
	__be16          time_mechanism_bit2;
	uint8_t         reserved_mech[4];
	__be16          time_mechanism_bit5;
	uint8_t         future_reserved[16];
} __packed;

/*
 * TCG Storage Opal SSC Feature Set: Configurable Namespace Locking
 * section 4.2.1
 *
 * feature code 0x0405
 */
#define NS_GEOMETRY_ALIGNMENT_REQUIRED 0x01

struct ns_geometry_desc {
	uint8_t         align;
	uint8_t         reserved[7];
	__be32          logical_block_size;
	__be64          alignment_granularity;
	__be64          lowest_aligned_lba;
} __packed;

#endif /* _SED_OPAL_SPEC_H */
