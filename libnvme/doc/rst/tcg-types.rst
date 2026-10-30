.. _tcg-types.h - TCG Storage data structures:

**tcg-types.h - TCG Storage data structures**


Data structures and constants from the TCG Storage Architecture Core
Specification and the TCG Security Subsystem Classes (Opal, Opalite,
Pyrite, Ruby) and Feature Sets. All multi-byte fields are big-endian.



.. c:enum:: tcg_method_status

   TCG method status codes

**Constants**

``TCG_METHOD_STATUS_SUCCESS``
  Success

``TCG_METHOD_STATUS_NOT_AUTHORIZED``
  Not authorized

``TCG_METHOD_STATUS_OBSOLETE_1``
  Obsolete

``TCG_METHOD_STATUS_SP_BUSY``
  SP busy

``TCG_METHOD_STATUS_SP_FAILED``
  SP failed

``TCG_METHOD_STATUS_SP_DISABLED``
  SP disabled

``TCG_METHOD_STATUS_SP_FROZEN``
  SP frozen

``TCG_METHOD_STATUS_NO_SESSIONS_AVAILABLE``
  No sessions available

``TCG_METHOD_STATUS_UNIQUENESS_CONFLICT``
  Uniqueness conflict

``TCG_METHOD_STATUS_INSUFFICIENT_SPACE``
  Insufficient space

``TCG_METHOD_STATUS_INSUFFICIENT_ROWS``
  Insufficient rows

``TCG_METHOD_STATUS_OBSOLETE_2``
  Obsolete

``TCG_METHOD_STATUS_INVALID_PARAMETER``
  Invalid parameter

``TCG_METHOD_STATUS_OBSOLETE_3``
  Obsolete

``TCG_METHOD_STATUS_OBSOLETE_4``
  Obsolete

``TCG_METHOD_STATUS_TPER_MALFUNCTION``
  TPer malfunction

``TCG_METHOD_STATUS_TRANSACTION_FAILURE``
  Transaction failure

``TCG_METHOD_STATUS_RESPONSE_OVERFLOW``
  Response overflow

``TCG_METHOD_STATUS_AUTHORITY_LOCKED_OUT``
  Authority locked out

``TCG_METHOD_STATUS_FAIL``
  Fail

``TCG_METHOD_STATUS_NO_METHOD_STATUS``
  No method status

**Description**

TCG Storage Architecture Core Specification 2.01, section 5.1.5.




.. c:enum:: tcg_l0_discovery

   Level 0 Discovery addressing

**Constants**

``TCG_L0_DISCOVERY_SECP``
  Security Protocol for Level 0 Discovery

``TCG_L0_DISCOVERY_COMID``
  ComID for Level 0 Discovery




.. c:struct:: tcg_l0_header

   Level 0 Discovery header

**Definition**

::

  struct tcg_l0_header {
    __be32 length;
    __be32 revision;
    __u8 rsvd8[8];
    __u8 vs[32];
  };

**Members**

``length``
  Length of the parameter data, excluding this field

``revision``
  Data structure revision

``rsvd8``
  Reserved

``vs``
  Vendor specific


**Description**

TCG Opal SSC 2.02, section 3.1.1.1.




.. c:struct:: tcg_l0_desc

   Level 0 Discovery feature descriptor header

**Definition**

::

  struct tcg_l0_desc {
    __be16 code;
    __u8 version;
    __u8 length;
  };

**Members**

``code``
  Feature code, see :c:type:`enum tcg_l0_code <tcg_l0_code>`

``version``
  Feature descriptor version

``length``
  Length of the feature data following this header


**Description**

TCG Opal SSC 2.02, section 3.1.1.3.




.. c:enum:: tcg_l0_code

   Level 0 Discovery feature codes

**Constants**

``TCG_L0_CODE_TPER``
  TPer feature

``TCG_L0_CODE_LOCKING``
  Locking feature

``TCG_L0_CODE_GEOMETRY``
  Geometry Reporting feature

``TCG_L0_CODE_OPAL_V1``
  Opal SSC V1.00 feature

``TCG_L0_CODE_SUM``
  Single User Mode feature

``TCG_L0_CODE_DATASTORE``
  Additional DataStore Tables feature

``TCG_L0_CODE_OPAL_V2``
  Opal SSC V2.00 feature

``TCG_L0_CODE_OPALITE``
  Opalite SSC feature

``TCG_L0_CODE_PYRITE_V1``
  Pyrite SSC V1.00 feature

``TCG_L0_CODE_PYRITE_V2``
  Pyrite SSC V2.00 feature

``TCG_L0_CODE_RUBY``
  Ruby SSC feature

``TCG_L0_CODE_LOCKING_LBA``
  Locking LBA Ranges Control feature

``TCG_L0_CODE_BLOCK_SID_AUTH``
  Block SID Authentication feature

``TCG_L0_CODE_CNL``
  Configurable Namespace Locking feature

``TCG_L0_CODE_DATA_REMOVAL``
  Data Removal Mechanism feature

``TCG_L0_CODE_NS_GEOMETRY``
  Namespace Geometry Reporting feature




.. c:enum:: tcg_l0_tper_features

   TPer feature flags

**Constants**

``TCG_L0_TPER_SYNC``
  Synchronous protocol supported

``TCG_L0_TPER_ASYNC``
  Asynchronous protocol supported

``TCG_L0_TPER_ACKNAK``
  ACK/NAK supported

``TCG_L0_TPER_BUF_MGMT``
  Buffer management supported

``TCG_L0_TPER_STREAMING``
  Streaming supported

``TCG_L0_TPER_COMID_MGMT``
  ComID management supported




.. c:struct:: tcg_l0_tper

   TPer feature (0x0001)

**Definition**

::

  struct tcg_l0_tper {
    __u8 features;
    __u8 rsvd1[11];
  };

**Members**

``features``
  Feature flags, see :c:type:`enum tcg_l0_tper_features <tcg_l0_tper_features>`

``rsvd1``
  Reserved


**Description**

TCG Opal SSC 2.02, section 3.1.1.2.




.. c:enum:: tcg_l0_locking_features

   Locking feature flags

**Constants**

``TCG_L0_LOCKING_SUPPORTED``
  Locking supported

``TCG_L0_LOCKING_ENABLED``
  Locking enabled

``TCG_L0_LOCKING_LOCKED``
  Locked

``TCG_L0_LOCKING_MEDIA_ENCRYPT``
  Media encryption

``TCG_L0_LOCKING_MBR_ENABLED``
  MBR shadowing enabled

``TCG_L0_LOCKING_MBR_DONE``
  MBR shadowing done




.. c:struct:: tcg_l0_locking

   Locking feature (0x0002)

**Definition**

::

  struct tcg_l0_locking {
    __u8 features;
    __u8 rsvd1[11];
  };

**Members**

``features``
  Feature flags, see :c:type:`enum tcg_l0_locking_features <tcg_l0_locking_features>`

``rsvd1``
  Reserved


**Description**

TCG Opal SSC 2.02, section 3.1.1.3.




.. c:enum:: tcg_l0_geometry_flags

   Geometry Reporting feature flags

**Constants**

``TCG_L0_GEOMETRY_ALIGN``
  Alignment required




.. c:struct:: tcg_l0_geometry

   Geometry Reporting feature (0x0003)

**Definition**

::

  struct tcg_l0_geometry {
    __u8 align;
    __u8 rsvd1[7];
    __be32 logical_block_size;
    __be64 alignment_granularity;
    __be64 lowest_aligned_lba;
  };

**Members**

``align``
  Flags, see :c:type:`enum tcg_l0_geometry_flags <tcg_l0_geometry_flags>`

``rsvd1``
  Reserved

``logical_block_size``
  Logical block size

``alignment_granularity``
  Alignment granularity

``lowest_aligned_lba``
  Lowest aligned LBA


**Description**

TCG Opal SSC 2.02, section 3.1.1.4.




.. c:struct:: tcg_l0_opal_v1

   Opal SSC V1.00 feature (0x0200)

**Definition**

::

  struct tcg_l0_opal_v1 {
    __be16 base_comid;
    __be16 num_comids;
  };

**Members**

``base_comid``
  Base ComID

``num_comids``
  Number of ComIDs





.. c:enum:: tcg_l0_sum_flags

   Single User Mode feature flags

**Constants**

``TCG_L0_SUM_ANY``
  Any locking object is in single user mode

``TCG_L0_SUM_ALL``
  All locking objects are in single user mode

``TCG_L0_SUM_POLICY``
  Administrator controls the locking ranges




.. c:struct:: tcg_l0_sum

   Single User Mode feature (0x0201)

**Definition**

::

  struct tcg_l0_sum {
    __be32 num_locking_objects;
    __u8 flags;
    __u8 rsvd5[7];
  };

**Members**

``num_locking_objects``
  Number of locking objects supported

``flags``
  Flags, see :c:type:`enum tcg_l0_sum_flags <tcg_l0_sum_flags>`

``rsvd5``
  Reserved


**Description**

TCG Opal SSC Feature Set: Single User Mode 1.00, section 4.2.1.




.. c:struct:: tcg_l0_datastore

   Additional DataStore Tables feature (0x0202)

**Definition**

::

  struct tcg_l0_datastore {
    __be16 rsvd0;
    __be16 max_tables;
    __be32 max_table_size;
    __be32 table_alignment;
  };

**Members**

``rsvd0``
  Reserved

``max_tables``
  Maximum number of DataStore tables

``max_table_size``
  Maximum total size of DataStore tables

``table_alignment``
  DataStore table size alignment


**Description**

TCG Opal SSC Feature Set: Additional DataStore Tables 1.00,
section 4.2.1.




.. c:enum:: tcg_l0_opal_v2_flags

   Opal SSC V2.00 feature flags

**Constants**

``TCG_L0_OPAL_V2_RANGE_CROSSING``
  Range crossing behavior




.. c:struct:: tcg_l0_opal_v2

   Opal SSC V2.00 feature (0x0203)

**Definition**

::

  struct tcg_l0_opal_v2 {
    __be16 base_comid;
    __be16 num_comids;
    __u8 flags;
    __be16 num_locking_sp_admin_auth;
    __be16 num_locking_sp_user_auth;
    __u8 initial_cpin_sid_ind;
    __u8 initial_cpin_sid_revert;
    __u8 rsvd11[5];
  };

**Members**

``base_comid``
  Base ComID

``num_comids``
  Number of ComIDs

``flags``
  Flags, see :c:type:`enum tcg_l0_opal_v2_flags <tcg_l0_opal_v2_flags>`

``num_locking_sp_admin_auth``
  Number of Locking SP Admin authorities

``num_locking_sp_user_auth``
  Number of Locking SP User authorities

``initial_cpin_sid_ind``
  Initial C_PIN_SID PIN indicator

``initial_cpin_sid_revert``
  Behavior of C_PIN_SID PIN upon TPer revert

``rsvd11``
  Reserved


**Description**

TCG Opal SSC 2.02, section 3.1.1.5.




.. c:struct:: tcg_l0_opalite

   Opalite SSC feature (0x0301)

**Definition**

::

  struct tcg_l0_opalite {
    __be16 base_comid;
    __be16 num_comids;
    __u8 rsvd4[5];
    __u8 initial_cpin_sid_ind;
    __u8 initial_cpin_sid_revert;
    __u8 rsvd11[5];
  };

**Members**

``base_comid``
  Base ComID

``num_comids``
  Number of ComIDs

``rsvd4``
  Reserved

``initial_cpin_sid_ind``
  Initial C_PIN_SID PIN indicator

``initial_cpin_sid_revert``
  Behavior of C_PIN_SID PIN upon TPer revert

``rsvd11``
  Reserved


**Description**

TCG Storage Security Subsystem Class: Opalite, section 3.1.1.4.




.. c:struct:: tcg_l0_pyrite_v1

   Pyrite SSC V1.00 feature (0x0302)

**Definition**

::

  struct tcg_l0_pyrite_v1 {
    __be16 base_comid;
    __be16 num_comids;
    __u8 rsvd4[5];
    __u8 initial_cpin_sid_ind;
    __u8 initial_cpin_sid_revert;
    __u8 rsvd11[5];
  };

**Members**

``base_comid``
  Base ComID

``num_comids``
  Number of ComIDs

``rsvd4``
  Reserved

``initial_cpin_sid_ind``
  Initial C_PIN_SID PIN indicator

``initial_cpin_sid_revert``
  Behavior of C_PIN_SID PIN upon TPer revert

``rsvd11``
  Reserved


**Description**

TCG Storage Security Subsystem Class: Pyrite 1.00, section 3.1.1.4.




.. c:struct:: tcg_l0_pyrite_v2

   Pyrite SSC V2.00 feature (0x0303)

**Definition**

::

  struct tcg_l0_pyrite_v2 {
    __be16 base_comid;
    __be16 num_comids;
    __u8 rsvd4[5];
    __u8 initial_cpin_sid_ind;
    __u8 initial_cpin_sid_revert;
    __u8 rsvd11[5];
  };

**Members**

``base_comid``
  Base ComID

``num_comids``
  Number of ComIDs

``rsvd4``
  Reserved

``initial_cpin_sid_ind``
  Initial C_PIN_SID PIN indicator

``initial_cpin_sid_revert``
  Behavior of C_PIN_SID PIN upon TPer revert

``rsvd11``
  Reserved


**Description**

TCG Storage Security Subsystem Class: Pyrite 2.00, section 3.1.1.4.




.. c:enum:: tcg_l0_ruby_flags

   Ruby SSC feature flags

**Constants**

``TCG_L0_RUBY_RANGE_CROSSING``
  Range crossing behavior




.. c:struct:: tcg_l0_ruby

   Ruby SSC feature (0x0304)

**Definition**

::

  struct tcg_l0_ruby {
    __be16 base_comid;
    __be16 num_comids;
    __u8 flags;
    __be16 num_locking_sp_admin_auth;
    __be16 num_locking_sp_user_auth;
    __u8 initial_cpin_sid_ind;
    __u8 initial_cpin_sid_revert;
    __u8 rsvd11[5];
  };

**Members**

``base_comid``
  Base ComID

``num_comids``
  Number of ComIDs

``flags``
  Flags, see :c:type:`enum tcg_l0_ruby_flags <tcg_l0_ruby_flags>`

``num_locking_sp_admin_auth``
  Number of Locking SP Admin authorities

``num_locking_sp_user_auth``
  Number of Locking SP User authorities

``initial_cpin_sid_ind``
  Initial C_PIN_SID PIN indicator

``initial_cpin_sid_revert``
  Behavior of C_PIN_SID PIN upon TPer revert

``rsvd11``
  Reserved


**Description**

TCG Ruby SSC 1.00, section 3.1.1.5.




.. c:struct:: tcg_l0_locking_lba

   Locking LBA Ranges Control feature (0x0401)

**Definition**

::

  struct tcg_l0_locking_lba {
    __u8 rsvd0;
    __u8 reserved_range_control[11];
  };

**Members**

``rsvd0``
  Reserved

``reserved_range_control``
  Reserved for range control


**Description**

TCG Storage Enterprise SSC Feature Set: Locking LBA Ranges Control,
section 4.1.1.




.. c:enum:: tcg_l0_block_sid_states

   Block SID Authentication states

**Constants**

``TCG_L0_BLOCK_SID_VALUE_STATE``
  C_PIN_SID PIN differs from MSID

``TCG_L0_BLOCK_SID_BLOCKED_STATE``
  SID authentication is blocked




.. c:enum:: tcg_l0_block_sid_hw_reset

   Block SID Authentication hardware reset

**Constants**

``TCG_L0_BLOCK_SID_HW_RESET``
  Hardware reset clears the blocked state




.. c:struct:: tcg_l0_block_sid_auth

   Block SID Authentication feature (0x0402)

**Definition**

::

  struct tcg_l0_block_sid_auth {
    __u8 states;
    __u8 hw_reset;
  };

**Members**

``states``
  States, see :c:type:`enum tcg_l0_block_sid_states <tcg_l0_block_sid_states>`

``hw_reset``
  Hardware reset, see :c:type:`enum tcg_l0_block_sid_hw_reset <tcg_l0_block_sid_hw_reset>`


**Description**

TCG Storage Feature Set: Block SID Authentication, section 4.1.1.




.. c:enum:: tcg_l0_cnl_flags

   Configurable Namespace Locking feature flags

**Constants**

``TCG_L0_CNL_RANGE_P``
  Non-global locking objects exist

``TCG_L0_CNL_RANGE_C``
  Non-global locking objects are supported




.. c:struct:: tcg_l0_cnl

   Configurable Namespace Locking feature (0x0403)

**Definition**

::

  struct tcg_l0_cnl {
    __u8 flags;
    __u8 rsvd1[3];
    __be32 max_key_count;
    __be32 unused_key_count;
    __be32 max_ranges_per_ns;
  };

**Members**

``flags``
  Flags, see :c:type:`enum tcg_l0_cnl_flags <tcg_l0_cnl_flags>`

``rsvd1``
  Reserved

``max_key_count``
  Maximum key count

``unused_key_count``
  Unused key count

``max_ranges_per_ns``
  Maximum ranges per namespace


**Description**

TCG Storage Opal SSC Feature Set: Configurable Namespace Locking,
section 4.2.1.




.. c:enum:: tcg_l0_data_removal_flags

   Data Removal Mechanism feature flags

**Constants**

``TCG_L0_DATA_REMOVAL_PROCESSING``
  Data removal operation in progress

``TCG_L0_DATA_REMOVAL_INTERRUPTED``
  Data removal operation interrupted




.. c:enum:: tcg_l0_data_removal_mechanism

   Supported data removal mechanisms

**Constants**

``TCG_L0_DATA_REMOVAL_OVERWRITE``
  Overwrite data erase

``TCG_L0_DATA_REMOVAL_BLOCK_ERASE``
  Block erase

``TCG_L0_DATA_REMOVAL_CRYPTO_ERASE``
  Cryptographic erase

``TCG_L0_DATA_REMOVAL_VENDOR_ERASE``
  Vendor specific erase




.. c:struct:: tcg_l0_data_removal

   Data Removal Mechanism feature (0x0404)

**Definition**

::

  struct tcg_l0_data_removal {
    __u8 rsvd0;
    __u8 flags;
    __u8 removal_mechanism;
    __u8 format;
    __be16 time_mechanism_bit0;
    __be16 time_mechanism_bit1;
    __be16 time_mechanism_bit2;
    __u8 rsvd10[4];
    __be16 time_mechanism_bit5;
    __u8 rsvd16[16];
  };

**Members**

``rsvd0``
  Reserved

``flags``
  Flags, see :c:type:`enum tcg_l0_data_removal_flags <tcg_l0_data_removal_flags>`

``removal_mechanism``
  Supported mechanisms, see
  :c:type:`enum tcg_l0_data_removal_mechanism <tcg_l0_data_removal_mechanism>`

``format``
  Data removal time format

``time_mechanism_bit0``
  Data removal time for mechanism bit 0

``time_mechanism_bit1``
  Data removal time for mechanism bit 1

``time_mechanism_bit2``
  Data removal time for mechanism bit 2

``rsvd10``
  Reserved

``time_mechanism_bit5``
  Data removal time for mechanism bit 5

``rsvd16``
  Reserved


**Description**

TCG Storage Opal SSC 2.02, section 3.1.1.6.




.. c:enum:: tcg_l0_ns_geometry_flags

   Namespace Geometry Reporting flags

**Constants**

``TCG_L0_NS_GEOMETRY_ALIGN``
  Alignment required




.. c:struct:: tcg_l0_ns_geometry

   Namespace Geometry Reporting feature (0x0405)

**Definition**

::

  struct tcg_l0_ns_geometry {
    __u8 align;
    __u8 rsvd1[7];
    __be32 logical_block_size;
    __be64 alignment_granularity;
    __be64 lowest_aligned_lba;
  };

**Members**

``align``
  Flags, see :c:type:`enum tcg_l0_ns_geometry_flags <tcg_l0_ns_geometry_flags>`

``rsvd1``
  Reserved

``logical_block_size``
  Logical block size

``alignment_granularity``
  Alignment granularity

``lowest_aligned_lba``
  Lowest aligned LBA


**Description**

TCG Storage Opal SSC Feature Set: Configurable Namespace Locking,
section 4.2.1.


