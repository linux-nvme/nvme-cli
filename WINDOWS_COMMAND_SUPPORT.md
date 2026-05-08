# Windows Command Support Status

This document tracks the support status of nvme-cli commands on Windows.
Commands are categorized based on their current implementation and testing state.

## Supported and Confirmed Functional

These commands are fully implemented and verified working on Windows.

| Command | Description | Notes |
|---------|-------------|-------|
| `list` | List all NVMe devices and namespaces on machine | |
| `list-subsys` | List NVMe subsystems | |
| `id-ctrl` | Send NVMe Identify Controller | |
| `id-ns` | Send NVMe Identify Namespace, display structure | |
| `list-ns` | Send NVMe Identify List, display structure | |
| `list-ctrl` | Send NVMe Identify Controller List, display structure | |
| `nvm-id-ctrl` | Send NVMe Identify Controller NVM Command Set, display structure | |
| `nvm-id-ns` | Send NVMe Identify Namespace NVM Command Set, display structure | |
| `ns-descs` | Send NVMe Namespace Descriptor List, display structure | |
| `id-uuid` | Send NVMe Identify UUID List, display structure | |
| `get-ns-id` | Retrieve the namespace ID of opened block device | |
| `get-log` | Generic NVMe get log, returns log in raw format | |
| `telemetry-log` | Retrieve FW Telemetry log write to file | |
| `fw-log` | Retrieve FW Log, show it | |
| `changed-ns-list-log` | Retrieve Changed Attached Namespace List, show it | |
| `smart-log` | Retrieve SMART Log, show it | |
| `error-log` | Retrieve Error Log, show it | |
| `effects-log` | Retrieve Command Effects Log, show it | Usage: `--csi=0` |
| `endurance-log` | Retrieve Endurance Group Log, show it | |
| `persistent-event-log` | Retrieve Persistent Event Log, show it | `--action=[0,2,3]` |
| `endurance-event-agg-log` | Retrieve Endurance Group Event Aggregate Log, show it | |
| `lba-status-log` | Retrieve LBA Status Information Log, show it | |
| `phy-rx-eom-log` | Retrieve Physical Interface Receiver Eye Opening Measurement, show it | |
| `get-feature` | Get feature and show the resulting value | |
| `device-self-test` | Perform the necessary tests to observe the performance | |
| `self-test-log` | Retrieve the SELF-TEST Log, show it | |
| `supported-log-pages` | Retrieve the Supported Log pages details, show it | |
| `fid-support-effects-log` | Retrieve FID Support and Effects log and show it | |
| `mi-cmd-support-effects-log` | Retrieve MI Command Support and Effects log and show it | |
| `changed-alloc-ns-list-log` | Retrieve Changed Allocated Namespace List, show it | |
| `set-feature` | Set a feature and show the resulting value | |
| `format` | Format namespace with new block format | |
| `admin-passthru` | Submit an arbitrary admin command, return results | |
| `io-passthru` | Submit an arbitrary IO command, return results | |
| `flush` | Submit a Flush command, return results | |
| `read` | Submit a read command, return results | |
| `write` | Submit a write command, return results | |
| `sanitize-log` | Retrieve sanitize log, show it | |
| `ns-rescan` | Rescans the NVME namespaces | |
| `show-topology` | Show the topology | |

### Supported on Windows but Not Supported by Current Test Device (Log Pages)

These commands are implemented but return errors because the log pages are not
supported by the test drives. They may work on drives that support the
corresponding log page identifiers.

| Command | Description | Log ID |
|---------|-------------|--------|
| `ana-log` | Retrieve ANA Log, show it | LID 0x0C |
| `predictable-lat-log` | Retrieve Predictable Latency per NVM Set Log, show it | LID 0x0A |
| `pred-lat-event-agg-log` | Retrieve Predictable Latency Event Aggregate Log, show it | LID 0x0B |
| `resv-notif-log` | Retrieve Reservation Notification Log, show it | LID 0x80 |
| `boot-part-log` | Retrieve Boot Partition Log, show it | LID 0x15 |
| `media-unit-stat-log` | Retrieve the configuration and wear of media units, show it | LID 0x10 |
| `supported-cap-config-log` | Retrieve the list of Supported Capacity Configuration Descriptors | LID 0x11 |
| `mgmt-addr-list-log` | Retrieve Management Address List Log, show it | LID 0x18 |
| `rotational-media-info-log` | Retrieve Rotational Media Information Log, show it | LID 0x16 |
| `dispersed-ns-participating-nss-log` | Retrieve Dispersed Namespace Participating NVM Subsystems Log, show it | LID 0x17 |
| `reachability-groups-log` | Retrieve Reachability Groups Log, show it | LID 0x1a |
| `reachability-associations-log` | Retrieve Reachability Associations Log, show it | LID 0x1b |
| `host-discovery-log` | Retrieve Host Discovery Log, show it | LID 0x71 |
| `ave-discovery-log` | Retrieve AVE Discovery Log, show it | LID 0x72 |
| `pull-model-ddc-req-log` | Retrieve Pull Model DDC Request Log, show it | LID 0x73 |
| `power-measurement-log` | Retrieve Power Measurement Log, show it | LID 0x25 |

## Supported but with Known Issues or Needs Testing

These commands are implemented on Windows but have known issues or have not yet
been fully tested.

### Known Issues

| Command | Description | Issue |
|---------|-------------|-------|
| `sanitize` | Submit a sanitize command | Failing with `STORAGE_PROTOCOL_STATUS_PENDING` |

### Needs Testing

| Command | Description | Notes |
|---------|-------------|-------|
| `fw-commit` | Verify and commit firmware to a specific slot | Needs testing |
| `fw-download` | Download new firmware | Needs testing |
| `security-send` | Submit a Security Send command, return results | Needs testing |
| `security-recv` | Submit a Security Receive command, return results | Needs testing |
| `compare` | Submit a Compare command, return results | Only supported in WinPE |

## Supported by Windows but Not Implemented

| Command | Description | Notes |
|---------|-------------|-------|
| `dsm` | Submit a Data Set Management command, return results | Deallocate option is supported by Windows but not implemented |
| `rpmb` | Replay Protection Memory Block commands | Not implemented yet |


## Not Supported on Windows

These commands are not supported by Windows NVMe drivers or are Linux-specific.

### Identify Commands

| Command | Description |
|---------|-------------|
| `id-ns-granularity` | Send NVMe Identify Namespace Granularity List, display structure |
| `id-ns-lba-format` | Send NVMe Identify Namespace for the specified LBA Format index, display structure |
| `nvm-id-ns-lba-format` | Send NVMe Identify Namespace NVM Command Set for the specified LBA Format index, display structure |
| `primary-ctrl-caps` | Send NVMe Identify Primary Controller Capabilities |
| `list-secondary` | List Secondary Controllers associated with a Primary Controller |
| `cmdset-ind-id-ns` | I/O Command Set Independent Identify Namespace |
| `id-nvmset` | Send NVMe Identify NVM Set List, display structure |
| `id-iocs` | Send NVMe Identify I/O Command Set, display structure |
| `id-domain` | Send NVMe Identify Domain List, display structure |
| `list-endgrp` | Send NVMe Identify Endurance Group List, display structure |

### Namespace Management

| Command | Description |
|---------|-------------|
| `create-ns` | Creates a namespace with the provided parameters |
| `delete-ns` | Deletes a namespace from the controller |
| `attach-ns` | Attaches a namespace to requested controller(s) |
| `detach-ns` | Detaches a namespace from requested controller(s) |

### Properties and Registers

| Command | Description |
|---------|-------------|
| `set-property` | Set a property and show the resulting value |
| `get-property` | Get a property and show the resulting value |
| `show-regs` | Shows the controller registers or properties |
| `set-reg` | Set a register and show the resulting value |
| `get-reg` | Get a register and show the resulting value |

### Data Commands

| Command | Description |
|---------|-------------|
| `get-lba-status` | Submit a Get LBA Status command, return results |
| `capacity-mgmt` | Submit Capacity Management Command, return results |
| `copy` | Submit a Simple Copy command, return results |
| `write-zeroes` | Submit a write zeroes command, return results |
| `write-uncor` | Submit a write uncorrectable command, return results |
| `verify` | Submit a verify command, return results |

### Reservation Commands

| Command | Description |
|---------|-------------|
| `resv-acquire` | Submit a Reservation Acquire, return results |
| `resv-register` | Submit a Reservation Register, return results |
| `resv-release` | Submit a Reservation Release, return results |
| `resv-report` | Submit a Reservation Report, return results |

### Controller Management

| Command | Description |
|---------|-------------|
| `reset` | Resets the controller |
| `subsystem-reset` | Resets the subsystem |
| `lockdown` | Submit a Lockdown command, return result |
| `virt-mgmt` | Manage Flexible Resources between Primary and Secondary Controller |
| `sanitize-ns` | Submit a sanitize namespace command |

### Directive Commands

| Command | Description |
|---------|-------------|
| `dir-receive` | Submit a Directive Receive command, return results |
| `dir-send` | Submit a Directive Send command, return results |

### I/O Management

| Command | Description |
|---------|-------------|
| `io-mgmt-recv` | I/O Management Receive |
| `io-mgmt-send` | I/O Management Send |

### NVMe-MI Commands

| Command | Description |
|---------|-------------|
| `nvme-mi-recv` | Submit a NVMe-MI Receive command, return results |
| `nvme-mi-send` | Submit a NVMe-MI Send command, return results |

### NVMe-oF (Fabrics) Commands

`CONFIG_FABRICS` is not supported on Windows.

| Command | Description |
|---------|-------------|
| `discover` | Discover NVMeoF subsystems |
| `connect-all` | Discover and Connect to NVMeoF subsystems |
| `connect` | Connect to NVMeoF subsystem |
| `disconnect` | Disconnect from NVMeoF subsystem |
| `disconnect-all` | Disconnect from all connected NVMeoF subsystems |
| `config` | Configuration of NVMeoF subsystems |
| `dim` | Send Discovery Information Management command to a Discovery Controller |

### NVMe-oF Key Management

| Command | Description |
|---------|-------------|
| `gen-hostnqn` | Generate NVMeoF host NQN |
| `show-hostnqn` | Show NVMeoF host NQN |
| `gen-dhchap-key` | Generate NVMeoF DH-HMAC-CHAP host key |
| `check-dhchap-key` | Validate NVMeoF DH-HMAC-CHAP host key |
| `gen-tls-key` | Generate NVMeoF TLS PSK |
| `check-tls-key` | Validate NVMeoF TLS PSK |
| `tls-key` | Manipulate NVMeoF TLS PSK |
