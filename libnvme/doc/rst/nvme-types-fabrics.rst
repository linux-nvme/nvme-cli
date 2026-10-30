.. _nvme-types-fabrics.h:

**nvme-types-fabrics.h**


NVMe over Fabrics type definitions

Based on:

- NVM Express over RDMA Transport Specification, Revision 1.2,
  August 1, 2025 (Ratified)
- NVM Express over TCP Transport Specification, Revision 1.2,
  August 1, 2025 (Ratified)
- NVM Express Base Specification (Fabrics command set sections)

This file is organized by functional area:
- Discovery: Discovery log entries and log pages
- Transport Configuration: Transport types, addressing, requirements
- RDMA-Specific: RDMA queue pairs, providers, connection management
- TCP-Specific: TCP security types
- Discovery Information Model (DIM): Extended discovery attributes
- Connection: Connect command data structures
- Authentication: KX-HMAC-CHAP in-band authentication protocol



.. c:enum:: nvme_subsys_type

   Type of the NVM subsystem.

**Constants**

``NVME_NQN_DISC``
  Discovery type target subsystem. Describes a referral to another
  Discovery Service composed of Discovery controllers that provide
  additional discovery records. Multiple Referral entries may
  be reported for each Discovery Service (if that Discovery Service
  has multiple NVM subsystem ports or supports multiple protocols).

``NVME_NQN_NVME``
  NVME type target subsystem. Describes an NVM subsystem whose
  controllers may have attached namespaces (an NVM subsystem
  that is not composed of Discovery controllers). Multiple NVM
  Subsystem entries may be reported for each NVM subsystem if
  that NVM subsystem has multiple NVM subsystem ports.

``NVME_NQN_CURR``
  Current Discovery type target subsystem. Describes this Discovery
  subsystem (the Discovery Service that contains the controller
  processing the Get Log Page command). Multiple Current Discovery
  Subsystem entries may be reported for this Discovery subsystem
  if the current Discovery subsystem has multiple NVM subsystem
  ports.




.. c:enum:: nvmf_disc_eflags

   Discovery Log Page entry flags.

**Constants**

``NVMF_DISC_EFLAGS_NONE``
  Indicates that none of the DUPRETINFO or EPCSD
  features are supported.

``NVMF_DISC_EFLAGS_DUPRETINFO``
  Duplicate Returned Information (DUPRETINFO):
  Indicates that using the content of this entry
  to access this Discovery Service returns the same
  information that is returned by using the content
  of other entries in this log page that also have
  this flag set.

``NVMF_DISC_EFLAGS_EPCSD``
  Explicit Persistent Connection Support for Discovery (EPCSD):
  Indicates that Explicit Persistent Connections are
  supported for the Discovery controller.

``NVMF_DISC_EFLAGS_NCC``
  No CDC Connectivity (NCC): If set to
  '1', then no DDC that describes this entry
  is currently connected to the CDC. If
  cleared to '0', then at least one DDC that
  describes this entry is currently
  connected to the CDC. If the Discovery
  controller returning this log page is not
  a CDC, then this bit shall be cleared to
  '0' and should be ignored by the host.




.. c:union:: nvmf_tsas

   Transport Specific Address Subtype

**Definition**

::

  union nvmf_tsas {
    char common[NVMF_TSAS_SIZE];
    struct rdma {
      __u8 qptype;
      __u8 prtype;
      __u8 cms;
      __u8 rsvd3[5];
      __le16 pkey;
      __u8 rsvd10[246];
    } rdma;
    struct tcp {
      __u8 sectype;
    } tcp;
  };

**Members**

``common``
  Common transport specific attributes

``rdma``
  RDMA transport specific attribute settings

``tcp``
  TCP transport specific attribute settings





.. c:struct:: nvmf_disc_log_entry

   Discovery Log Page Entry

**Definition**

::

  struct nvmf_disc_log_entry {
    __u8 trtype;
    __u8 adrfam;
    __u8 subtype;
    __u8 treq;
    __le16 portid;
    __le16 cntlid;
    __le16 asqsz;
    __le16 eflags;
    __u8 rsvd12[20];
    char trsvcid[NVMF_TRSVCID_SIZE];
    __u8 rsvd64[192];
    char subnqn[NVME_NQN_LENGTH];
    char traddr[NVMF_TRADDR_SIZE];
    union nvmf_tsas tsas;
  };

**Members**

``trtype``
  Transport Type (see :c:type:`enum nvmf_trtype <nvmf_trtype>`)

``adrfam``
  Address Family (see :c:type:`enum nvmf_addr_family <nvmf_addr_family>`)

``subtype``
  Subsystem Type

``treq``
  Transport Requirements (see :c:type:`enum nvmf_treq <nvmf_treq>`)

``portid``
  Port ID

``cntlid``
  Controller ID

``asqsz``
  Admin Submission Queue Size

``eflags``
  Entry Flags (see :c:type:`enum nvmf_disc_eflags <nvmf_disc_eflags>`)

``rsvd12``
  Reserved

``trsvcid``
  Transport Service Identifier

``rsvd64``
  Reserved

``subnqn``
  NVM Subsystem Qualified Name

``traddr``
  Transport Address

``tsas``
  Transport Specific Address Subtype (see :c:type:`union nvmf_tsas <nvmf_tsas>`)





.. c:enum:: nvmf_trtype

   Transport Type codes for Discovery Log Page entry TRTYPE field

**Constants**

``NVMF_TRTYPE_UNSPECIFIED``
  Not indicated

``NVMF_TRTYPE_RDMA``
  RDMA

``NVMF_TRTYPE_FC``
  Fibre Channel

``NVMF_TRTYPE_TCP``
  TCP

``NVMF_TRTYPE_LOOP``
  Intra-host Transport (i.e., loopback), reserved
  for host usage.

``NVMF_TRTYPE_MAX``
  Maximum value for :c:type:`enum nvmf_trtype <nvmf_trtype>`




.. c:enum:: nvmf_addr_family

   Address Family codes for Discovery Log Page entry ADRFAM field

**Constants**

``NVMF_ADDR_FAMILY_PCI``
  PCIe

``NVMF_ADDR_FAMILY_IP4``
  AF_INET: IPv4 address family.

``NVMF_ADDR_FAMILY_IP6``
  AF_INET6: IPv6 address family.

``NVMF_ADDR_FAMILY_IB``
  AF_IB: InfiniBand address family.

``NVMF_ADDR_FAMILY_FC``
  Fibre Channel address family.

``NVMF_ADDR_FAMILY_LOOP``
  Intra-host Transport (i.e., loopback), reserved
  for host usage.




.. c:enum:: nvmf_treq

   Transport Requirements codes for Discovery Log Page entry TREQ field

**Constants**

``NVMF_TREQ_SECTYPE_SHIFT``
  Shift amount to get Secure Channel requirement

``NVMF_TREQ_SECTYPE_MASK``
  Mask to get Secure Channel requirement

``NVMF_TREQ_NOT_SPECIFIED``
  Not specified

``NVMF_TREQ_REQUIRED``
  Required

``NVMF_TREQ_NOT_REQUIRED``
  Not Required

``NVMF_TREQ_DISABLE_SQFLOW_SHIFT``
  Shift amount to get SQ flow control disable

``NVMF_TREQ_DISABLE_SQFLOW_MASK``
  Mask to get SQ flow control disable

``NVMF_TREQ_DISABLE_SQFLOW``
  SQ flow control disable supported




.. c:enum:: nvmf_rdma_qptype

   RDMA QP Service Type codes for Discovery Log Page entry TSAS RDMA_QPTYPE field

**Constants**

``NVMF_RDMA_QPTYPE_CONNECTED``
  Reliable Connected

``NVMF_RDMA_QPTYPE_DATAGRAM``
  Reliable Datagram




.. c:enum:: nvmf_rdma_prtype

   RDMA Provider Type codes for Discovery Log Page entry TSAS RDMA_PRTYPE field

**Constants**

``NVMF_RDMA_PRTYPE_NOT_SPECIFIED``
  No Provider Specified

``NVMF_RDMA_PRTYPE_IB``
  InfiniBand

``NVMF_RDMA_PRTYPE_ROCE``
  InfiniBand RoCE

``NVMF_RDMA_PRTYPE_ROCEV2``
  InfiniBand RoCEV2

``NVMF_RDMA_PRTYPE_IWARP``
  iWARP




.. c:enum:: nvmf_rdma_cms

   RDMA Connection Management Service Type codes for Discovery Log Page entry TSAS RDMA_CMS field

**Constants**

``NVMF_RDMA_CMS_RDMA_CM``
  Sockets based endpoint addressing




.. c:enum:: nvmf_tcp_sectype

   Transport Specific Address Subtype Definition for NVMe/TCP Transport

**Constants**

``NVMF_TCP_SECTYPE_NONE``
  No Security

``NVMF_TCP_SECTYPE_TLS``
  Transport Layer Security version 1.2

``NVMF_TCP_SECTYPE_TLS13``
  Transport Layer Security version 1.3 or a subsequent
  version. The TLS protocol negotiates the version and
  cipher suite for each TCP connection.




.. c:enum:: nvmf_log_discovery_lid_support

   Discovery log specific support

**Constants**

``NVMF_LOG_DISC_LID_NONE``
  None

``NVMF_LOG_DISC_LID_EXTDLPES``
  Extended Discovery Log Page Entries Supported

``NVMF_LOG_DISC_LID_PLEOS``
  Port Local Entries Only Supported

``NVMF_LOG_DISC_LID_ALLSUBES``
  All NVM Subsystem Entries Supported




.. c:enum:: nvmf_log_discovery_lsp

   Discovery log specific field

**Constants**

``NVMF_LOG_DISC_LSP_NONE``
  None

``NVMF_LOG_DISC_LSP_EXTDLPE``
  Extended Discovery Log Page Entries

``NVMF_LOG_DISC_LSP_PLEO``
  Port Local Entries Only

``NVMF_LOG_DISC_LSP_ALLSUBE``
  All NVM Subsystem Entries




.. c:struct:: nvmf_discovery_log

   Discovery Log Page (Log Identifier 70h)

**Definition**

::

  struct nvmf_discovery_log {
    __le64 genctr;
    __le64 numrec;
    __le16 recfmt;
    __u8 rsvd14[1006];
    struct nvmf_disc_log_entry entries[];
  };

**Members**

``genctr``
  Generation Counter (GENCTR): Indicates the version of the discovery
  information, starting at a value of 0h. For each change in the
  Discovery Log Page, this counter is incremented by one. If the value
  of this field is FFFFFFFF_FFFFFFFFh, then the field shall be cleared
  to 0h when incremented (i.e., rolls over to 0h).

``numrec``
  Number of Records (NUMREC): Indicates the number of records
  contained in the log.

``recfmt``
  Record Format (RECFMT): Specifies the format of the Discovery Log
  Page. If a new format is defined, this value is incremented by one.
  The format of the record specified in this definition shall be 0h.

``rsvd14``
  Reserved

``entries``
  Discovery Log Page Entries - see :c:type:`struct nvmf_disc_log_entry <nvmf_disc_log_entry>`.





.. c:enum:: nvmf_dim_tas

   Discovery Information Management Task

**Constants**

``NVMF_DIM_TAS_REGISTER``
  Register

``NVMF_DIM_TAS_DEREGISTER``
  Deregister

``NVMF_DIM_TAS_UPDATE``
  Update




.. c:enum:: nvmf_dim_entfmt

   Discovery Information Management Entry Format

**Constants**

``NVMF_DIM_ENTFMT_BASIC``
  Basic discovery information entry

``NVMF_DIM_ENTFMT_EXTENDED``
  Extended discovery information entry




.. c:enum:: nvmf_dim_etype

   Discovery Information Management Entity Type

**Constants**

``NVMF_DIM_ETYPE_HOST``
  Host

``NVMF_DIM_ETYPE_DDC``
  Direct Discovery controller

``NVMF_DIM_ETYPE_CDC``
  Centralized Discovery controller




.. c:enum:: nvmf_exattype

   Extended Attribute Type

**Constants**

``NVMF_EXATTYPE_HOSTID``
  Host Identifier

``NVMF_EXATTYPE_SYMNAME``
  Symblic Name




.. c:struct:: nvmf_ext_attr

   Extended Attribute (EXAT)

**Definition**

::

  struct nvmf_ext_attr {
    __le16 exattype;
    __le16 exatlen;
    __u8 exatval[];
  };

**Members**

``exattype``
  Extended Attribute Type (EXATTYPE) - see **enum** nvmf_exattype

``exatlen``
  Extended Attribute Length (EXATLEN)

``exatval``
  Extended Attribute Value (EXATVAL) - size allocated for array
  must be a multiple of 4 bytes





.. c:struct:: nvmf_ext_die

   Extended Discovery Information Entry (DIE)

**Definition**

::

  struct nvmf_ext_die {
    __u8 trtype;
    __u8 adrfam;
    __u8 subtype;
    __u8 treq;
    __le16 portid;
    __le16 cntlid;
    __le16 asqsz;
    __u8 rsvd10[22];
    char trsvcid[NVMF_TRSVCID_SIZE];
    __u8 resv64[192];
    char nqn[NVME_NQN_LENGTH];
    char traddr[NVMF_TRADDR_SIZE];
    union nvmf_tsas         tsas;
    __le32 tel;
    __le16 numexat;
    __u8 resv1030[2];
    struct nvmf_ext_attr    exat[];
  };

**Members**

``trtype``
  Transport Type (:c:type:`enum nvmf_trtype <nvmf_trtype>`)

``adrfam``
  Address Family (:c:type:`enum nvmf_addr_family <nvmf_addr_family>`)

``subtype``
  Subsystem Type (:c:type:`enum nvme_subsys_type <nvme_subsys_type>`)

``treq``
  Transport Requirements (:c:type:`enum nvmf_treq <nvmf_treq>`)

``portid``
  Port ID

``cntlid``
  Controller ID

``asqsz``
  Admin Max SQ Size

``rsvd10``
  Reserved

``trsvcid``
  Transport Service Identifier

``resv64``
  Reserved

``nqn``
  NVM Qualified Name

``traddr``
  Transport Address

``tsas``
  Transport Specific Address Subtype (:c:type:`union nvmf_tsas <nvmf_tsas>`)

``tel``
  Total Entry Length

``numexat``
  Number of Extended Attributes

``resv1030``
  Reserved

``exat``
  Extended Attributes 0 (:c:type:`struct nvmf_ext_attr <nvmf_ext_attr>`)





.. c:union:: nvmf_die

   Discovery Information Entry (DIE)

**Definition**

::

  union nvmf_die {
    struct nvmf_disc_log_entry      basic[0];
    struct nvmf_ext_die             extended;
  };

**Members**

``basic``
  Basic format (:c:type:`struct nvmf_disc_log_entry <nvmf_disc_log_entry>`)

``extended``
  Extended format (:c:type:`struct nvmf_ext_die <nvmf_ext_die>`)


**Description**

Depending on the ENTFMT specified in the DIM, DIEs can be entered
with the Basic or Extended formats. For Basic format, each entry
has a fixed length. Therefore, the "basic" field defined below can
be accessed as a C array. For the Extended format, however, each
entry is of variable length (TEL). Therefore, the "extended" field
defined below cannot be accessed as a C array. Instead, the
"extended" field is akin to a linked-list, where one can "walk"
through the list. To move to the next entry, one simply adds the
current entry's length (TEL) to the "walk" pointer. The number of
entries in the list is specified by NUMENT.  Although extended
entries are of a variable lengths (TEL), TEL is always a multiple of
4 bytes.




.. c:struct:: nvmf_dim_data

   Discovery Information Management (DIM) - Data

**Definition**

::

  struct nvmf_dim_data {
    __le32 tdl;
    __u8 rsvd4[4];
    __le64 nument;
    __le16 entfmt;
    __le16 etype;
    __u8 portlcl;
    __u8 rsvd21;
    __le16 ektype;
    char eid[NVME_NQN_LENGTH];
    char ename[NVMF_ENAME_LEN];
    char ever[NVMF_EVER_LEN];
    __u8 rsvd600[424];
    union nvmf_die  die[];
  };

**Members**

``tdl``
  Total Data Length

``rsvd4``
  Reserved

``nument``
  Number of entries

``entfmt``
  Entry Format (:c:type:`enum nvmf_dim_entfmt <nvmf_dim_entfmt>`)

``etype``
  Entity Type (:c:type:`enum nvmf_dim_etype <nvmf_dim_etype>`)

``portlcl``
  Port Local

``rsvd21``
  Reserved

``ektype``
  Entry Key Type

``eid``
  Entity Identifier (e.g. Host NQN)

``ename``
  Entity Name (e.g. hostname)

``ever``
  Entity Version (e.g. OS Name/Version)

``rsvd600``
  Reserved

``die``
  Discovery Information Entry (see **nument** above)





.. c:struct:: nvmf_connect_data

   Data payload for the 'connect' command

**Definition**

::

  struct nvmf_connect_data {
    __u8 hostid[16];
    __le16 cntlid;
    char rsvd4[238];
    char subsysnqn[NVME_NQN_LENGTH];
    char hostnqn[NVME_NQN_LENGTH];
    char rsvd5[256];
  };

**Members**

``hostid``
  Host ID of the connecting host

``cntlid``
  Requested controller ID

``rsvd4``
  Reserved

``subsysnqn``
  Subsystem NQN to connect to

``hostnqn``
  Host NQN of the connecting host

``rsvd5``
  Reserved





.. c:struct:: nvme_host_ext_discovery_log

   Host Extended Discovery Log

**Definition**

::

  struct nvme_host_ext_discovery_log {
    __u8 trtype;
    __u8 adrfam;
    __u8 rsvd2[8];
    __le16 eflags;
    __u8 rsvd12[244];
    char hostnqn[NVME_NQN_LENGTH];
    char traddr[NVMF_TRADDR_SIZE];
    union nvmf_tsas         tsas;
    __le32 tel;
    __le16 numexat;
    __u8 rsvd1030[2];
    struct nvmf_ext_attr    exat[];
  };

**Members**

``trtype``
  Transport Type

``adrfam``
  Address Family

``rsvd2``
  Reserved

``eflags``
  Entry Flags

``rsvd12``
  Reserved

``hostnqn``
  Host NVMe Qualified Name

``traddr``
  Transport Address

``tsas``
  Transport Specific Address Subtype

``tel``
  Total Entry Length

``numexat``
  Number of Extended Attributes

``rsvd1030``
  Reserved

``exat``
  Extended Attributes List





.. c:struct:: nvme_host_discovery_log

   Host Discovery Log

**Definition**

::

  struct nvme_host_discovery_log {
    __le64 genctr;
    __le64 numrec;
    __le16 recfmt;
    __u8 hdlpf;
    __u8 rsvd19;
    __le32 thdlpl;
    __u8 rsvd24[1000];
    struct nvme_host_ext_discovery_log      hedlpe[];
  };

**Members**

``genctr``
  Generation Counter

``numrec``
  Number of Records

``recfmt``
  Record Format

``hdlpf``
  Host Discovery Log Page Flags

``rsvd19``
  Reserved

``thdlpl``
  Total Host Discovery Log Page Length

``rsvd24``
  Reserved

``hedlpe``
  Host Extended Discovery Log Page Entry List





.. c:struct:: nvme_ave_tr_record

   AVE Transport Record

**Definition**

::

  struct nvme_ave_tr_record {
    __u8 aveadrfam;
    __u8 rsvd1;
    __le16 avetrsvcid;
    __u8 avetraddr[16];
  };

**Members**

``aveadrfam``
  AVE Address Family

``rsvd1``
  Reserved

``avetrsvcid``
  AVE Transport Service Identifier

``avetraddr``
  AVE Transport Address





.. c:struct:: nvme_ave_discovery_log_entry

   AVE Discovery Log Entry

**Definition**

::

  struct nvme_ave_discovery_log_entry {
    __le32 tel;
    char avenqn[224];
    __u8 numatr;
    __u8 rsvd229[3];
    struct nvme_ave_tr_record       atr[];
  };

**Members**

``tel``
  Total Entry Length

``avenqn``
  AVE NQN

``numatr``
  Number of AVE Transport Records

``rsvd229``
  Reserved

``atr``
  AVE Transport Record List





.. c:struct:: nvme_ave_discovery_log

   AVE Discovery Log

**Definition**

::

  struct nvme_ave_discovery_log {
    __le64 genctr;
    __le64 numrec;
    __le16 recfmt;
    __u8 rsvd18[2];
    __le32 tadlpl;
    __u8 rsvd24[1000];
    struct nvme_ave_discovery_log_entry     adlpe[];
  };

**Members**

``genctr``
  Generation Counter

``numrec``
  Number of Records

``recfmt``
  Record Format

``rsvd18``
  Reserved

``tadlpl``
  Total AVE Discovery Log Page Length

``rsvd24``
  Reserved

``adlpe``
  AVE Discovery Log Page Entry List





.. c:enum:: nvme_ave_pdu_type

   KX-HMAC-CHAP AVE Access Protocol PDU Types

**Constants**

``NVME_AVE_PDU_TYPE_ACCESS_REQUEST``
  KX-HMAC-CHAP_Access-Request

``NVME_AVE_PDU_TYPE_ACCESS_RESULT``
  KX-HMAC-CHAP_Access-Result




.. c:struct:: nvme_ave_access_request

   KX-HMAC-CHAP_Access-Request PDU, sent by an NVMe entity (host or controller) to an AVE over the AVE's TLS connection

**Definition**

::

  struct nvme_ave_access_request {
    __u8 pdu_type;
    __u8 flags;
    __u8 hlen;
    __u8 pdo;
    __le32 plen;
    __le64 id;
    __u8 hl;
    __u8 hashid;
    __le16 t_id;
    __u8 sc_c;
    __u8 respr;
    __u8 nqnrlen;
    __u8 rsvd23;
    __le32 seqnum;
    __u8 acv_respv_nqnr[];
  };

**Members**

``pdu_type``
  PDU Type, see :c:type:`enum nvme_ave_pdu_type <nvme_ave_pdu_type>`

``flags``
  Reserved

``hlen``
  Header Length: fixed length of 8 bytes (08h)

``pdo``
  PDU Data Offset, reserved

``plen``
  PDU Length: total length of the PDU in bytes

``id``
  Identifier used to match this PDU with the corresponding
  :c:type:`struct nvme_ave_access_result <nvme_ave_access_result>` PDU

``hl``
  Hash Length: length in bytes of the selected hash function

``hashid``
  Hash Identifier, see :c:type:`enum libnvmf_hmac_alg <libnvmf_hmac_alg>`

``t_id``
  Transaction Identifier

``sc_c``
  Secure Channel Concatenation, see :c:type:`enum nvmf_auth_sc_c <nvmf_auth_sc_c>`

``respr``
  Responder's Role: 'H' (48h) if host, 'C' (43h) if controller

``nqnrlen``
  NQN Responder Length: length in bytes of **acv_respv_nqnr**'s
  NQNR component

``rsvd23``
  Reserved

``seqnum``
  Sequence Number (S)

``acv_respv_nqnr``
  Augmented Challenge Value (Ca, **hl** bytes), followed by
  the Response Value (R, **hl** bytes), followed by the NQN of the
  Responder (NQNR, **nqnrlen** bytes)





.. c:enum:: nvme_ave_authres

   KX-HMAC-CHAP AVE Authentication Verification Result (AuthRes)

**Constants**

``NVME_AVE_AUTHRES_SUCCESS``
  Authentication Verification Successful

``NVME_AVE_AUTHRES_FAILED``
  Authentication Verification Failed




.. c:enum:: nvme_ave_rcode

   KX-HMAC-CHAP AVE Access-Result Reason Code (RCODE)

**Constants**

``NVME_AVE_RCODE_NONE``
  No additional explanation

``NVME_AVE_RCODE_AUTH_FAILURE``
  Authentication failure

``NVME_AVE_RCODE_HASH_UNUSABLE``
  Selected hash function unusable




.. c:struct:: nvme_ave_access_result

   KX-HMAC-CHAP_Access-Result PDU, sent by an AVE in response to a :c:type:`struct nvme_ave_access_request <nvme_ave_access_request>` PDU

**Definition**

::

  struct nvme_ave_access_result {
    __u8 pdu_type;
    __u8 flags;
    __u8 hlen;
    __u8 pdo;
    __le32 plen;
    __le64 id;
    __u8 authres;
    __u8 rcode;
    __u16 rsvd18;
  };

**Members**

``pdu_type``
  PDU Type, see :c:type:`enum nvme_ave_pdu_type <nvme_ave_pdu_type>`

``flags``
  Reserved

``hlen``
  Header Length: fixed length of 8 bytes (08h)

``pdo``
  PDU Data Offset, reserved

``plen``
  PDU Length: fixed length of 20 bytes (14h)

``id``
  Identifier matching the corresponding
  :c:type:`struct nvme_ave_access_request <nvme_ave_access_request>` PDU

``authres``
  Authentication Verification Result, see :c:type:`enum nvme_ave_authres <nvme_ave_authres>`

``rcode``
  Reason Code, see :c:type:`enum nvme_ave_rcode <nvme_ave_rcode>`

``rsvd18``
  Reserved





.. c:enum:: nvmf_auth_protocol_id

   Authentication Protocol Identifiers

**Constants**

``NVMF_AUTH_PROTOCOL_COMMON``
  Common messages

``NVMF_AUTH_PROTOCOL_KXCHAP``
  KX-HMAC-CHAP




.. c:enum:: nvmf_auth_id

   Common Authentication Identifiers (AUTH_ID)

**Constants**

``NVMF_AUTH_ID_NEGOTIATE``
  AUTH_Negotiate

``NVMF_AUTH_ID_FAILURE2``
  AUTH_Failure2

``NVMF_AUTH_ID_FAILURE1``
  AUTH_Failure1




.. c:enum:: nvmf_auth_sc_c

   Secure Channel Concatenation values (SC_C)

**Constants**

``NVMF_AUTH_SCC_NOSC``
  No secure channel concatenation. Allowed on
  any Admin or I/O Queue; does not generate a
  PSK.

``NVMF_AUTH_SCC_NEWTLSPSK``
  Generate a PSK and associated PSK identity on
  an Admin Queue over a TCP channel without TLS,
  for use setting up TLS secure channels for
  subsequent Admin and I/O queues. 0x01 is
  obsolete (refer to NVM Express Base
  Specification 2.0).

``NVMF_AUTH_SCC_REPLACETLSPSK``
  Generate a PSK and associated PSK identity
  on an Admin Queue over a TLS secure channel,
  replacing the PSK used to set up that secure
  channel.




.. c:struct:: nvmf_auth_negotiate

   AUTH_Negotiate message, host to controller

**Definition**

::

  struct nvmf_auth_negotiate {
    __u8 auth_type;
    __u8 auth_id;
    __u16 rsvd2;
    __le16 t_id;
    __u8 sc_c;
    __u8 napd;
    __u8 apd[];
  };

**Members**

``auth_type``
  Authentication Type, see :c:type:`enum nvmf_auth_protocol_id <nvmf_auth_protocol_id>`.
  Cleared to 0h (i.e., common messages).

``auth_id``
  Authentication Identifier, see :c:type:`enum nvmf_auth_id <nvmf_auth_id>`.
  Cleared to 0h (i.e., AUTH_Negotiate).

``rsvd2``
  Reserved

``t_id``
  Transaction Identifier

``sc_c``
  Secure Channel Concatenation, see :c:type:`enum nvmf_auth_sc_c <nvmf_auth_sc_c>`

``napd``
  Number of Authentication Protocol Descriptors

``apd``
  Authentication Protocol Descriptor list, **napd** entries of 64
  bytes each. Currently always a
  :c:type:`struct nvmf_auth_kxchap_protocol_descriptor <nvmf_auth_kxchap_protocol_descriptor>`, the only
  authentication protocol defined.





.. c:enum:: nvmf_auth_rcode

   AUTH_Failure Reason Codes (RCODE)

**Constants**

``NVMF_AUTH_RCODE_FAILURE``
  Authentication failure: the authentication
  transaction failed




.. c:enum:: nvmf_auth_rcodeex

   AUTH_Failure Reason Code Explanations (RCODEEX)

**Constants**

``NVMF_AUTH_RCODEEX_FAILED``
  Authentication failed:
  authentication of the involved host or NVM subsystem failed

``NVMF_AUTH_RCODEEX_PROTOCOL_NOT_USABLE``
  Authentication protocol not
  usable: the protocol descriptors proposed by the host do not
  satisfy the security requirements of the controller

``NVMF_AUTH_RCODEEX_SCC_MISMATCH``
  Secure channel concatenation
  mismatch: the SC_C value specified by the host does not
  satisfy the security requirements of the controller

``NVMF_AUTH_RCODEEX_HASH_NOT_USABLE``
  Hash function not usable: the
  HashIDList proposed by the host does not satisfy the security
  requirements of the controller

``NVMF_AUTH_RCODEEX_KXGROUP_NOT_USABLE``
  Key exchange group not usable:
  the KXgIDList proposed by the host does not satisfy the
  security requirements of the controller

``NVMF_AUTH_RCODEEX_INCORRECT_PAYLOAD``
  Incorrect payload: the payload
  of the received message is not correct

``NVMF_AUTH_RCODEEX_INCORRECT_MESSAGE``
  Incorrect protocol message: the
  received message is not the expected next message in the
  authentication protocol sequence




.. c:struct:: nvmf_auth_failure

   AUTH_Failure1 message, controller to host, or AUTH_Failure2 message, host to controller

**Definition**

::

  struct nvmf_auth_failure {
    __u8 auth_type;
    __u8 auth_id;
    __u16 rsvd2;
    __le16 t_id;
    __u8 rcode;
    __u8 rcodeex;
  };

**Members**

``auth_type``
  Authentication Type, see :c:type:`enum nvmf_auth_protocol_id <nvmf_auth_protocol_id>`.
  Cleared to 0h (i.e., common messages).

``auth_id``
  Authentication Identifier, see :c:type:`enum nvmf_auth_id <nvmf_auth_id>`.
  NVMF_AUTH_ID_FAILURE1 for AUTH_Failure1, NVMF_AUTH_ID_FAILURE2
  for AUTH_Failure2.

``rsvd2``
  Reserved

``t_id``
  Transaction Identifier

``rcode``
  Reason Code, see :c:type:`enum nvmf_auth_rcode <nvmf_auth_rcode>`

``rcodeex``
  Reason Code Explanation, see :c:type:`enum nvmf_auth_rcodeex <nvmf_auth_rcodeex>`





.. c:enum:: nvmf_auth_kxchap_id

   KX-HMAC-CHAP Authentication Identifiers (AUTH_ID)

**Constants**

``NVMF_AUTH_KXCHAP_ID_CHALLENGE``
  KX-HMAC-CHAP_Challenge

``NVMF_AUTH_KXCHAP_ID_REPLY``
  KX-HMAC-CHAP_Reply

``NVMF_AUTH_KXCHAP_ID_SUCCESS1``
  KX-HMAC-CHAP_Success1

``NVMF_AUTH_KXCHAP_ID_SUCCESS2``
  KX-HMAC-CHAP_Success2




.. c:enum:: nvmf_auth_kxgid

   KX-HMAC-CHAP Key Exchange Group Identifiers

**Constants**

``NVMF_AUTH_KXGID_NULL``
  No key exchange performed

``NVMF_AUTH_KXGID_FFDHE2048``
  Finite Field Diffie-Hellman Ephemeral,
  2048-bit group (refer to RFC 7919)

``NVMF_AUTH_KXGID_FFDHE3072``
  Finite Field Diffie-Hellman Ephemeral,
  3072-bit group (refer to RFC 7919)

``NVMF_AUTH_KXGID_FFDHE4096``
  Finite Field Diffie-Hellman Ephemeral,
  4096-bit group (refer to RFC 7919)

``NVMF_AUTH_KXGID_FFDHE6144``
  Finite Field Diffie-Hellman Ephemeral,
  6144-bit group (refer to RFC 7919)

``NVMF_AUTH_KXGID_FFDHE8192``
  Finite Field Diffie-Hellman Ephemeral,
  8192-bit group (refer to RFC 7919)

``NVMF_AUTH_KXGID_SECP256R1``
  Elliptic Curve Diffie-Hellman Ephemeral,
  curve secp256r1 (refer to RFC 8422,
  NIST SP 800-186)

``NVMF_AUTH_KXGID_SECP384R1``
  Elliptic Curve Diffie-Hellman Ephemeral,
  curve secp384r1 (refer to RFC 8422,
  NIST SP 800-186)

``NVMF_AUTH_KXGID_MLKEM768``
  Module-Lattice Key-Encapsulation Mechanism,
  security category 3 (refer to NIST FIPS 203)

``NVMF_AUTH_KXGID_MLKEM1024``
  Module-Lattice Key-Encapsulation Mechanism,
  security category 5 (refer to NIST FIPS 203)

``NVMF_AUTH_KXGID_SECP256R1MLKEM768``
  Hybrid key exchange using secp256r1 and
  ML-KEM-768 (refer to draft-ietf-tls-ecdhe-mlkem)

``NVMF_AUTH_KXGID_SECP384R1MLKEM1024``
  Hybrid key exchange using secp384r1 and
  ML-KEM-1024 (refer to draft-ietf-tls-ecdhe-mlkem)




.. c:struct:: nvmf_auth_kxchap_protocol_descriptor

   KX-HMAC-CHAP Authentication Protocol Descriptor

**Definition**

::

  struct nvmf_auth_kxchap_protocol_descriptor {
    __u8 authid;
    __u8 rsvd1;
    __u8 halen;
    __u8 kxlen;
    __u8 hashidlist[30];
    __u8 kxgidlist[30];
  };

**Members**

``authid``
  Authentication Protocol Identifier, see
  :c:type:`enum nvmf_auth_protocol_id <nvmf_auth_protocol_id>`

``rsvd1``
  Reserved

``halen``
  HashIDList Length: number of hash function identifiers (1 to 30)

``kxlen``
  KXgIDList Length: number of key exchange group identifiers (1 to 30)

``hashidlist``
  Hash Function Identifier List, one byte per identifier,
  see :c:type:`enum libnvmf_hmac_alg <libnvmf_hmac_alg>`. Unused trailing bytes are padding
  cleared to 0h.

``kxgidlist``
  Key Exchange Group Identifier List, one byte per identifier,
  see :c:type:`enum nvmf_auth_kxgid <nvmf_auth_kxgid>`. Unused trailing bytes are padding
  cleared to 0h.





.. c:struct:: nvmf_auth_kxchap_challenge

   KX-HMAC-CHAP_Challenge message, controller to host

**Definition**

::

  struct nvmf_auth_kxchap_challenge {
    __u8 auth_type;
    __u8 auth_id;
    __u16 rsvd2;
    __le16 t_id;
    __u8 hl;
    __u8 rsvd7;
    __u8 hashid;
    __u8 kxgid;
    __le16 kxvlen;
    __le32 seqnum;
    __u8 cval_kxv[];
  };

**Members**

``auth_type``
  Authentication Type, see :c:type:`enum nvmf_auth_protocol_id <nvmf_auth_protocol_id>`

``auth_id``
  Authentication Identifier, see :c:type:`enum nvmf_auth_kxchap_id <nvmf_auth_kxchap_id>`

``rsvd2``
  Reserved

``t_id``
  Transaction Identifier

``hl``
  Hash Length: length in bytes of the selected hash function

``rsvd7``
  Reserved

``hashid``
  Hash Identifier, see :c:type:`enum libnvmf_hmac_alg <libnvmf_hmac_alg>`

``kxgid``
  Key Exchange Group Identifier, see :c:type:`enum nvmf_auth_kxgid <nvmf_auth_kxgid>`.
  Cleared to 0h if no key exchange is performed.

``kxvlen``
  KX Value Length: length in bytes of the KX Value carried in
  **cval_kxv**, cleared to 0h if **kxgid** is cleared to 0h.

``seqnum``
  Sequence Number (S1)

``cval_kxv``
  Challenge Value (C1, **hl** bytes) followed by the KX Value
  (KXc, **kxvlen** bytes). The KX Value is absent if **kxvlen** is
  cleared to 0h.





.. c:struct:: nvmf_auth_kxchap_reply

   KX-HMAC-CHAP_Reply message, host to controller

**Definition**

::

  struct nvmf_auth_kxchap_reply {
    __u8 auth_type;
    __u8 auth_id;
    __u16 rsvd2;
    __le16 t_id;
    __u8 hl;
    __u8 rsvd7;
    __u8 cvalid;
    __u8 rsvd9;
    __le16 kxvlen;
    __le32 seqnum;
    __u8 rval_cval_kxv[];
  };

**Members**

``auth_type``
  Authentication Type, see :c:type:`enum nvmf_auth_protocol_id <nvmf_auth_protocol_id>`

``auth_id``
  Authentication Identifier, see :c:type:`enum nvmf_auth_kxchap_id <nvmf_auth_kxchap_id>`

``rsvd2``
  Reserved

``t_id``
  Transaction Identifier

``hl``
  Hash Length: length in bytes of the selected hash function

``rsvd7``
  Reserved

``cvalid``
  Challenge Valid: 01h if the Challenge Value in **rval_cval_kxv**
  is valid (bidirectional authentication requested), 00h otherwise.

``rsvd9``
  Reserved

``kxvlen``
  KX Value Length: length in bytes of the KX Value carried in
  **rval_cval_kxv**, cleared to 0h if no key exchange is performed.

``seqnum``
  Sequence Number (S2)

``rval_cval_kxv``
  Response Value (R1, **hl** bytes), followed by the Challenge
  Value (C2, **hl** bytes, cleared to 0h if **cvalid** is 00h),
  followed by the KX Value (KXh, **kxvlen** bytes). The KX Value
  is absent if **kxvlen** is cleared to 0h.





.. c:struct:: nvmf_auth_kxchap_success1

   KX-HMAC-CHAP_Success1 message, controller to host

**Definition**

::

  struct nvmf_auth_kxchap_success1 {
    __u8 auth_type;
    __u8 auth_id;
    __u16 rsvd2;
    __le16 t_id;
    __u8 hl;
    __u8 rsvd7;
    __u8 rvalid;
    __u8 rsvd9[7];
    __u8 rval[];
  };

**Members**

``auth_type``
  Authentication Type, see :c:type:`enum nvmf_auth_protocol_id <nvmf_auth_protocol_id>`

``auth_id``
  Authentication Identifier, see :c:type:`enum nvmf_auth_kxchap_id <nvmf_auth_kxchap_id>`

``rsvd2``
  Reserved

``t_id``
  Transaction Identifier

``hl``
  Hash Length: length in bytes of the selected hash function

``rsvd7``
  Reserved

``rvalid``
  Response Valid: 01h if **rval** carries a valid Response Value
  (bidirectional authentication was requested), 00h otherwise.

``rsvd9``
  Reserved

``rval``
  Response Value (R2, **hl** bytes), cleared to 0h if **rvalid** is 00h.





.. c:struct:: nvmf_auth_kxchap_success2

   KX-HMAC-CHAP_Success2 message, host to controller

**Definition**

::

  struct nvmf_auth_kxchap_success2 {
    __u8 auth_type;
    __u8 auth_id;
    __u16 rsvd2;
    __le16 t_id;
    __u8 rsvd6[10];
  };

**Members**

``auth_type``
  Authentication Type, see :c:type:`enum nvmf_auth_protocol_id <nvmf_auth_protocol_id>`

``auth_id``
  Authentication Identifier, see :c:type:`enum nvmf_auth_kxchap_id <nvmf_auth_kxchap_id>`

``rsvd2``
  Reserved

``t_id``
  Transaction Identifier

``rsvd6``
  Reserved



