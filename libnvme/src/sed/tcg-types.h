/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 *
 * Authors: Greg Joyce <gjoyce@linux.ibm.com>
 */
#pragma once

#include <nvme/types.h>

/**
 * DOC: tcg-types.h - TCG Storage data structures
 *
 * Data structures and constants from the TCG Storage Architecture Core
 * Specification and the TCG Security Subsystem Classes (Opal, Opalite,
 * Pyrite, Ruby) and Feature Sets. All multi-byte fields are big-endian.
 */

/**
 * enum tcg_method_status - TCG method status codes
 * @TCG_METHOD_STATUS_SUCCESS:			Success
 * @TCG_METHOD_STATUS_NOT_AUTHORIZED:		Not authorized
 * @TCG_METHOD_STATUS_OBSOLETE_1:		Obsolete
 * @TCG_METHOD_STATUS_SP_BUSY:			SP busy
 * @TCG_METHOD_STATUS_SP_FAILED:		SP failed
 * @TCG_METHOD_STATUS_SP_DISABLED:		SP disabled
 * @TCG_METHOD_STATUS_SP_FROZEN:		SP frozen
 * @TCG_METHOD_STATUS_NO_SESSIONS_AVAILABLE:	No sessions available
 * @TCG_METHOD_STATUS_UNIQUENESS_CONFLICT:	Uniqueness conflict
 * @TCG_METHOD_STATUS_INSUFFICIENT_SPACE:	Insufficient space
 * @TCG_METHOD_STATUS_INSUFFICIENT_ROWS:	Insufficient rows
 * @TCG_METHOD_STATUS_OBSOLETE_2:		Obsolete
 * @TCG_METHOD_STATUS_INVALID_PARAMETER:	Invalid parameter
 * @TCG_METHOD_STATUS_OBSOLETE_3:		Obsolete
 * @TCG_METHOD_STATUS_OBSOLETE_4:		Obsolete
 * @TCG_METHOD_STATUS_TPER_MALFUNCTION:		TPer malfunction
 * @TCG_METHOD_STATUS_TRANSACTION_FAILURE:	Transaction failure
 * @TCG_METHOD_STATUS_RESPONSE_OVERFLOW:	Response overflow
 * @TCG_METHOD_STATUS_AUTHORITY_LOCKED_OUT:	Authority locked out
 * @TCG_METHOD_STATUS_FAIL:			Fail
 * @TCG_METHOD_STATUS_NO_METHOD_STATUS:		No method status
 *
 * TCG Storage Architecture Core Specification 2.01, section 5.1.5.
 */
enum tcg_method_status {
	TCG_METHOD_STATUS_SUCCESS			= 0x00,
	TCG_METHOD_STATUS_NOT_AUTHORIZED		= 0x01,
	TCG_METHOD_STATUS_OBSOLETE_1			= 0x02,
	TCG_METHOD_STATUS_SP_BUSY			= 0x03,
	TCG_METHOD_STATUS_SP_FAILED			= 0x04,
	TCG_METHOD_STATUS_SP_DISABLED			= 0x05,
	TCG_METHOD_STATUS_SP_FROZEN			= 0x06,
	TCG_METHOD_STATUS_NO_SESSIONS_AVAILABLE		= 0x07,
	TCG_METHOD_STATUS_UNIQUENESS_CONFLICT		= 0x08,
	TCG_METHOD_STATUS_INSUFFICIENT_SPACE		= 0x09,
	TCG_METHOD_STATUS_INSUFFICIENT_ROWS		= 0x0a,
	TCG_METHOD_STATUS_OBSOLETE_2			= 0x0b,
	TCG_METHOD_STATUS_INVALID_PARAMETER		= 0x0c,
	TCG_METHOD_STATUS_OBSOLETE_3			= 0x0d,
	TCG_METHOD_STATUS_OBSOLETE_4			= 0x0e,
	TCG_METHOD_STATUS_TPER_MALFUNCTION		= 0x0f,
	TCG_METHOD_STATUS_TRANSACTION_FAILURE		= 0x10,
	TCG_METHOD_STATUS_RESPONSE_OVERFLOW		= 0x11,
	TCG_METHOD_STATUS_AUTHORITY_LOCKED_OUT		= 0x12,
	TCG_METHOD_STATUS_FAIL				= 0x3f,
	TCG_METHOD_STATUS_NO_METHOD_STATUS		= 0x89,
};

/**
 * enum tcg_l0_discovery - Level 0 Discovery addressing
 * @TCG_L0_DISCOVERY_SECP:	Security Protocol for Level 0 Discovery
 * @TCG_L0_DISCOVERY_COMID:	ComID for Level 0 Discovery
 */
enum tcg_l0_discovery {
	TCG_L0_DISCOVERY_SECP		= 0x01,
	TCG_L0_DISCOVERY_COMID		= 0x0001,
};

/**
 * struct tcg_l0_header - Level 0 Discovery header
 * @length:	Length of the parameter data, excluding this field
 * @revision:	Data structure revision
 * @rsvd8:	Reserved
 * @vs:		Vendor specific
 *
 * TCG Opal SSC 2.02, section 3.1.1.1.
 */
struct tcg_l0_header {
	__be32	length;
	__be32	revision;
	__u8	rsvd8[8];
	__u8	vs[32];
} __attribute__((packed));

/**
 * struct tcg_l0_desc - Level 0 Discovery feature descriptor header
 * @code:	Feature code, see &enum tcg_l0_code
 * @version:	Feature descriptor version
 * @length:	Length of the feature data following this header
 *
 * TCG Opal SSC 2.02, section 3.1.1.3.
 */
struct tcg_l0_desc {
	__be16	code;
	__u8	version;
	__u8	length;
} __attribute__((packed));

/**
 * enum tcg_l0_code - Level 0 Discovery feature codes
 * @TCG_L0_CODE_TPER:		TPer feature
 * @TCG_L0_CODE_LOCKING:	Locking feature
 * @TCG_L0_CODE_GEOMETRY:	Geometry Reporting feature
 * @TCG_L0_CODE_OPAL_V1:	Opal SSC V1.00 feature
 * @TCG_L0_CODE_SUM:		Single User Mode feature
 * @TCG_L0_CODE_DATASTORE:	Additional DataStore Tables feature
 * @TCG_L0_CODE_OPAL_V2:	Opal SSC V2.00 feature
 * @TCG_L0_CODE_OPALITE:	Opalite SSC feature
 * @TCG_L0_CODE_PYRITE_V1:	Pyrite SSC V1.00 feature
 * @TCG_L0_CODE_PYRITE_V2:	Pyrite SSC V2.00 feature
 * @TCG_L0_CODE_RUBY:		Ruby SSC feature
 * @TCG_L0_CODE_LOCKING_LBA:	Locking LBA Ranges Control feature
 * @TCG_L0_CODE_BLOCK_SID_AUTH:	Block SID Authentication feature
 * @TCG_L0_CODE_CNL:		Configurable Namespace Locking feature
 * @TCG_L0_CODE_DATA_REMOVAL:	Data Removal Mechanism feature
 * @TCG_L0_CODE_NS_GEOMETRY:	Namespace Geometry Reporting feature
 */
enum tcg_l0_code {
	TCG_L0_CODE_TPER		= 0x0001,
	TCG_L0_CODE_LOCKING		= 0x0002,
	TCG_L0_CODE_GEOMETRY		= 0x0003,
	TCG_L0_CODE_OPAL_V1		= 0x0200,
	TCG_L0_CODE_SUM			= 0x0201,
	TCG_L0_CODE_DATASTORE		= 0x0202,
	TCG_L0_CODE_OPAL_V2		= 0x0203,
	TCG_L0_CODE_OPALITE		= 0x0301,
	TCG_L0_CODE_PYRITE_V1		= 0x0302,
	TCG_L0_CODE_PYRITE_V2		= 0x0303,
	TCG_L0_CODE_RUBY		= 0x0304,
	TCG_L0_CODE_LOCKING_LBA		= 0x0401,
	TCG_L0_CODE_BLOCK_SID_AUTH	= 0x0402,
	TCG_L0_CODE_CNL			= 0x0403,
	TCG_L0_CODE_DATA_REMOVAL	= 0x0404,
	TCG_L0_CODE_NS_GEOMETRY		= 0x0405,
};

/**
 * enum tcg_l0_tper_features - TPer feature flags
 * @TCG_L0_TPER_SYNC:		Synchronous protocol supported
 * @TCG_L0_TPER_ASYNC:		Asynchronous protocol supported
 * @TCG_L0_TPER_ACKNAK:		ACK/NAK supported
 * @TCG_L0_TPER_BUF_MGMT:	Buffer management supported
 * @TCG_L0_TPER_STREAMING:	Streaming supported
 * @TCG_L0_TPER_COMID_MGMT:	ComID management supported
 */
enum tcg_l0_tper_features {
	TCG_L0_TPER_SYNC		= 1 << 0,
	TCG_L0_TPER_ASYNC		= 1 << 1,
	TCG_L0_TPER_ACKNAK		= 1 << 2,
	TCG_L0_TPER_BUF_MGMT		= 1 << 3,
	TCG_L0_TPER_STREAMING		= 1 << 4,
	TCG_L0_TPER_COMID_MGMT		= 1 << 6,
};

/**
 * struct tcg_l0_tper - TPer feature (0x0001)
 * @features:	Feature flags, see &enum tcg_l0_tper_features
 * @rsvd1:	Reserved
 *
 * TCG Opal SSC 2.02, section 3.1.1.2.
 */
struct tcg_l0_tper {
	__u8	features;
	__u8	rsvd1[11];
} __attribute__((packed));

/**
 * enum tcg_l0_locking_features - Locking feature flags
 * @TCG_L0_LOCKING_SUPPORTED:		Locking supported
 * @TCG_L0_LOCKING_ENABLED:		Locking enabled
 * @TCG_L0_LOCKING_LOCKED:		Locked
 * @TCG_L0_LOCKING_MEDIA_ENCRYPT:	Media encryption
 * @TCG_L0_LOCKING_MBR_ENABLED:		MBR shadowing enabled
 * @TCG_L0_LOCKING_MBR_DONE:		MBR shadowing done
 */
enum tcg_l0_locking_features {
	TCG_L0_LOCKING_SUPPORTED	= 1 << 0,
	TCG_L0_LOCKING_ENABLED		= 1 << 1,
	TCG_L0_LOCKING_LOCKED		= 1 << 2,
	TCG_L0_LOCKING_MEDIA_ENCRYPT	= 1 << 3,
	TCG_L0_LOCKING_MBR_ENABLED	= 1 << 4,
	TCG_L0_LOCKING_MBR_DONE		= 1 << 5,
};

/**
 * struct tcg_l0_locking - Locking feature (0x0002)
 * @features:	Feature flags, see &enum tcg_l0_locking_features
 * @rsvd1:	Reserved
 *
 * TCG Opal SSC 2.02, section 3.1.1.3.
 */
struct tcg_l0_locking {
	__u8	features;
	__u8	rsvd1[11];
} __attribute__((packed));

/**
 * enum tcg_l0_geometry_flags - Geometry Reporting feature flags
 * @TCG_L0_GEOMETRY_ALIGN:	Alignment required
 */
enum tcg_l0_geometry_flags {
	TCG_L0_GEOMETRY_ALIGN		= 1 << 0,
};

/**
 * struct tcg_l0_geometry - Geometry Reporting feature (0x0003)
 * @align:			Flags, see &enum tcg_l0_geometry_flags
 * @rsvd1:			Reserved
 * @logical_block_size:		Logical block size
 * @alignment_granularity:	Alignment granularity
 * @lowest_aligned_lba:		Lowest aligned LBA
 *
 * TCG Opal SSC 2.02, section 3.1.1.4.
 */
struct tcg_l0_geometry {
	__u8	align;
	__u8	rsvd1[7];
	__be32	logical_block_size;
	__be64	alignment_granularity;
	__be64	lowest_aligned_lba;
} __attribute__((packed));

/**
 * struct tcg_l0_opal_v1 - Opal SSC V1.00 feature (0x0200)
 * @base_comid:	Base ComID
 * @num_comids:	Number of ComIDs
 */
struct tcg_l0_opal_v1 {
	__be16	base_comid;
	__be16	num_comids;
} __attribute__((packed));

/**
 * enum tcg_l0_sum_flags - Single User Mode feature flags
 * @TCG_L0_SUM_ANY:	Any locking object is in single user mode
 * @TCG_L0_SUM_ALL:	All locking objects are in single user mode
 * @TCG_L0_SUM_POLICY:	Administrator controls the locking ranges
 */
enum tcg_l0_sum_flags {
	TCG_L0_SUM_ANY			= 1 << 0,
	TCG_L0_SUM_ALL			= 1 << 1,
	TCG_L0_SUM_POLICY		= 1 << 2,
};

/**
 * struct tcg_l0_sum - Single User Mode feature (0x0201)
 * @num_locking_objects:	Number of locking objects supported
 * @flags:			Flags, see &enum tcg_l0_sum_flags
 * @rsvd5:			Reserved
 *
 * TCG Opal SSC Feature Set: Single User Mode 1.00, section 4.2.1.
 */
struct tcg_l0_sum {
	__be32	num_locking_objects;
	__u8	flags;
	__u8	rsvd5[7];
} __attribute__((packed));

/**
 * struct tcg_l0_datastore - Additional DataStore Tables feature (0x0202)
 * @rsvd0:		Reserved
 * @max_tables:		Maximum number of DataStore tables
 * @max_table_size:	Maximum total size of DataStore tables
 * @table_alignment:	DataStore table size alignment
 *
 * TCG Opal SSC Feature Set: Additional DataStore Tables 1.00,
 * section 4.2.1.
 */
struct tcg_l0_datastore {
	__be16	rsvd0;
	__be16	max_tables;
	__be32	max_table_size;
	__be32	table_alignment;
} __attribute__((packed));

/**
 * enum tcg_l0_opal_v2_flags - Opal SSC V2.00 feature flags
 * @TCG_L0_OPAL_V2_RANGE_CROSSING:	Range crossing behavior
 */
enum tcg_l0_opal_v2_flags {
	TCG_L0_OPAL_V2_RANGE_CROSSING	= 1 << 0,
};

/**
 * struct tcg_l0_opal_v2 - Opal SSC V2.00 feature (0x0203)
 * @base_comid:			Base ComID
 * @num_comids:			Number of ComIDs
 * @flags:			Flags, see &enum tcg_l0_opal_v2_flags
 * @num_locking_sp_admin_auth:	Number of Locking SP Admin authorities
 * @num_locking_sp_user_auth:	Number of Locking SP User authorities
 * @initial_cpin_sid_ind:	Initial C_PIN_SID PIN indicator
 * @initial_cpin_sid_revert:	Behavior of C_PIN_SID PIN upon TPer revert
 * @rsvd11:			Reserved
 *
 * TCG Opal SSC 2.02, section 3.1.1.5.
 */
struct tcg_l0_opal_v2 {
	__be16	base_comid;
	__be16	num_comids;
	__u8	flags;
	__be16	num_locking_sp_admin_auth;
	__be16	num_locking_sp_user_auth;
	__u8	initial_cpin_sid_ind;
	__u8	initial_cpin_sid_revert;
	__u8	rsvd11[5];
} __attribute__((packed));

/**
 * struct tcg_l0_opalite - Opalite SSC feature (0x0301)
 * @base_comid:			Base ComID
 * @num_comids:			Number of ComIDs
 * @rsvd4:			Reserved
 * @initial_cpin_sid_ind:	Initial C_PIN_SID PIN indicator
 * @initial_cpin_sid_revert:	Behavior of C_PIN_SID PIN upon TPer revert
 * @rsvd11:			Reserved
 *
 * TCG Storage Security Subsystem Class: Opalite, section 3.1.1.4.
 */
struct tcg_l0_opalite {
	__be16	base_comid;
	__be16	num_comids;
	__u8	rsvd4[5];
	__u8	initial_cpin_sid_ind;
	__u8	initial_cpin_sid_revert;
	__u8	rsvd11[5];
} __attribute__((packed));

/**
 * struct tcg_l0_pyrite_v1 - Pyrite SSC V1.00 feature (0x0302)
 * @base_comid:			Base ComID
 * @num_comids:			Number of ComIDs
 * @rsvd4:			Reserved
 * @initial_cpin_sid_ind:	Initial C_PIN_SID PIN indicator
 * @initial_cpin_sid_revert:	Behavior of C_PIN_SID PIN upon TPer revert
 * @rsvd11:			Reserved
 *
 * TCG Storage Security Subsystem Class: Pyrite 1.00, section 3.1.1.4.
 */
struct tcg_l0_pyrite_v1 {
	__be16	base_comid;
	__be16	num_comids;
	__u8	rsvd4[5];
	__u8	initial_cpin_sid_ind;
	__u8	initial_cpin_sid_revert;
	__u8	rsvd11[5];
} __attribute__((packed));

/**
 * struct tcg_l0_pyrite_v2 - Pyrite SSC V2.00 feature (0x0303)
 * @base_comid:			Base ComID
 * @num_comids:			Number of ComIDs
 * @rsvd4:			Reserved
 * @initial_cpin_sid_ind:	Initial C_PIN_SID PIN indicator
 * @initial_cpin_sid_revert:	Behavior of C_PIN_SID PIN upon TPer revert
 * @rsvd11:			Reserved
 *
 * TCG Storage Security Subsystem Class: Pyrite 2.00, section 3.1.1.4.
 */
struct tcg_l0_pyrite_v2 {
	__be16	base_comid;
	__be16	num_comids;
	__u8	rsvd4[5];
	__u8	initial_cpin_sid_ind;
	__u8	initial_cpin_sid_revert;
	__u8	rsvd11[5];
} __attribute__((packed));

/**
 * enum tcg_l0_ruby_flags - Ruby SSC feature flags
 * @TCG_L0_RUBY_RANGE_CROSSING:	Range crossing behavior
 */
enum tcg_l0_ruby_flags {
	TCG_L0_RUBY_RANGE_CROSSING	= 1 << 0,
};

/**
 * struct tcg_l0_ruby - Ruby SSC feature (0x0304)
 * @base_comid:			Base ComID
 * @num_comids:			Number of ComIDs
 * @flags:			Flags, see &enum tcg_l0_ruby_flags
 * @num_locking_sp_admin_auth:	Number of Locking SP Admin authorities
 * @num_locking_sp_user_auth:	Number of Locking SP User authorities
 * @initial_cpin_sid_ind:	Initial C_PIN_SID PIN indicator
 * @initial_cpin_sid_revert:	Behavior of C_PIN_SID PIN upon TPer revert
 * @rsvd11:			Reserved
 *
 * TCG Ruby SSC 1.00, section 3.1.1.5.
 */
struct tcg_l0_ruby {
	__be16	base_comid;
	__be16	num_comids;
	__u8	flags;
	__be16	num_locking_sp_admin_auth;
	__be16	num_locking_sp_user_auth;
	__u8	initial_cpin_sid_ind;
	__u8	initial_cpin_sid_revert;
	__u8	rsvd11[5];
} __attribute__((packed));

/**
 * struct tcg_l0_locking_lba - Locking LBA Ranges Control feature (0x0401)
 * @rsvd0:			Reserved
 * @reserved_range_control:	Reserved for range control
 *
 * TCG Storage Enterprise SSC Feature Set: Locking LBA Ranges Control,
 * section 4.1.1.
 */
struct tcg_l0_locking_lba {
	__u8	rsvd0;
	__u8	reserved_range_control[11];
} __attribute__((packed));

/**
 * enum tcg_l0_block_sid_states - Block SID Authentication states
 * @TCG_L0_BLOCK_SID_VALUE_STATE:	C_PIN_SID PIN differs from MSID
 * @TCG_L0_BLOCK_SID_BLOCKED_STATE:	SID authentication is blocked
 */
enum tcg_l0_block_sid_states {
	TCG_L0_BLOCK_SID_VALUE_STATE	= 1 << 0,
	TCG_L0_BLOCK_SID_BLOCKED_STATE	= 1 << 1,
};

/**
 * enum tcg_l0_block_sid_hw_reset - Block SID Authentication hardware reset
 * @TCG_L0_BLOCK_SID_HW_RESET:	Hardware reset clears the blocked state
 */
enum tcg_l0_block_sid_hw_reset {
	TCG_L0_BLOCK_SID_HW_RESET	= 1 << 0,
};

/**
 * struct tcg_l0_block_sid_auth - Block SID Authentication feature (0x0402)
 * @states:	States, see &enum tcg_l0_block_sid_states
 * @hw_reset:	Hardware reset, see &enum tcg_l0_block_sid_hw_reset
 *
 * TCG Storage Feature Set: Block SID Authentication, section 4.1.1.
 */
struct tcg_l0_block_sid_auth {
	__u8	states;
	__u8	hw_reset;
} __attribute__((packed));

/**
 * enum tcg_l0_cnl_flags - Configurable Namespace Locking feature flags
 * @TCG_L0_CNL_RANGE_P:	Non-global locking objects exist
 * @TCG_L0_CNL_RANGE_C:	Non-global locking objects are supported
 */
enum tcg_l0_cnl_flags {
	TCG_L0_CNL_RANGE_P		= 1 << 6,
	TCG_L0_CNL_RANGE_C		= 1 << 7,
};

/**
 * struct tcg_l0_cnl - Configurable Namespace Locking feature (0x0403)
 * @flags:		Flags, see &enum tcg_l0_cnl_flags
 * @rsvd1:		Reserved
 * @max_key_count:	Maximum key count
 * @unused_key_count:	Unused key count
 * @max_ranges_per_ns:	Maximum ranges per namespace
 *
 * TCG Storage Opal SSC Feature Set: Configurable Namespace Locking,
 * section 4.2.1.
 */
struct tcg_l0_cnl {
	__u8	flags;
	__u8	rsvd1[3];
	__be32	max_key_count;
	__be32	unused_key_count;
	__be32	max_ranges_per_ns;
} __attribute__((packed));

/**
 * enum tcg_l0_data_removal_flags - Data Removal Mechanism feature flags
 * @TCG_L0_DATA_REMOVAL_PROCESSING:	Data removal operation in progress
 * @TCG_L0_DATA_REMOVAL_INTERRUPTED:	Data removal operation interrupted
 */
enum tcg_l0_data_removal_flags {
	TCG_L0_DATA_REMOVAL_PROCESSING	= 1 << 0,
	TCG_L0_DATA_REMOVAL_INTERRUPTED	= 1 << 1,
};

/**
 * enum tcg_l0_data_removal_mechanism - Supported data removal mechanisms
 * @TCG_L0_DATA_REMOVAL_OVERWRITE:	Overwrite data erase
 * @TCG_L0_DATA_REMOVAL_BLOCK_ERASE:	Block erase
 * @TCG_L0_DATA_REMOVAL_CRYPTO_ERASE:	Cryptographic erase
 * @TCG_L0_DATA_REMOVAL_VENDOR_ERASE:	Vendor specific erase
 */
enum tcg_l0_data_removal_mechanism {
	TCG_L0_DATA_REMOVAL_OVERWRITE		= 1 << 0,
	TCG_L0_DATA_REMOVAL_BLOCK_ERASE		= 1 << 1,
	TCG_L0_DATA_REMOVAL_CRYPTO_ERASE	= 1 << 2,
	TCG_L0_DATA_REMOVAL_VENDOR_ERASE	= 1 << 4,
};

/**
 * struct tcg_l0_data_removal - Data Removal Mechanism feature (0x0404)
 * @rsvd0:		Reserved
 * @flags:		Flags, see &enum tcg_l0_data_removal_flags
 * @removal_mechanism:	Supported mechanisms, see
 *			&enum tcg_l0_data_removal_mechanism
 * @format:		Data removal time format
 * @time_mechanism_bit0: Data removal time for mechanism bit 0
 * @time_mechanism_bit1: Data removal time for mechanism bit 1
 * @time_mechanism_bit2: Data removal time for mechanism bit 2
 * @rsvd10:		Reserved
 * @time_mechanism_bit5: Data removal time for mechanism bit 5
 * @rsvd16:		Reserved
 *
 * TCG Storage Opal SSC 2.02, section 3.1.1.6.
 */
struct tcg_l0_data_removal {
	__u8	rsvd0;
	__u8	flags;
	__u8	removal_mechanism;
	__u8	format;
	__be16	time_mechanism_bit0;
	__be16	time_mechanism_bit1;
	__be16	time_mechanism_bit2;
	__u8	rsvd10[4];
	__be16	time_mechanism_bit5;
	__u8	rsvd16[16];
} __attribute__((packed));

/**
 * enum tcg_l0_ns_geometry_flags - Namespace Geometry Reporting flags
 * @TCG_L0_NS_GEOMETRY_ALIGN:	Alignment required
 */
enum tcg_l0_ns_geometry_flags {
	TCG_L0_NS_GEOMETRY_ALIGN	= 1 << 0,
};

/**
 * struct tcg_l0_ns_geometry - Namespace Geometry Reporting feature (0x0405)
 * @align:			Flags, see &enum tcg_l0_ns_geometry_flags
 * @rsvd1:			Reserved
 * @logical_block_size:		Logical block size
 * @alignment_granularity:	Alignment granularity
 * @lowest_aligned_lba:		Lowest aligned LBA
 *
 * TCG Storage Opal SSC Feature Set: Configurable Namespace Locking,
 * section 4.2.1.
 */
struct tcg_l0_ns_geometry {
	__u8	align;
	__u8	rsvd1[7];
	__be32	logical_block_size;
	__be64	alignment_granularity;
	__be64	lowest_aligned_lba;
} __attribute__((packed));
