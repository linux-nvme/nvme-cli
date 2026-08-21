<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
# libnvme Specification Coverage

Tracks which chapters of each NVMe specification have been verified
field-by-field against libnvme, and when. Update this table whenever a
verification pass covers new ground.

**Status:** ✅ synced · 🔍 skimmed, not verified · ❌ not implemented · ❔ not checked

## NVM Express Base Specification, Revision 2.4

| Chapter | Status | Last synced |
|---|---|---|
| 1-4 (Intro, Architecture, Registers/Properties, Base Model) | ❔ | — |
| 5 — Admin Command Set | ✅ | 2026-08-21 |
| 6 — Fabrics Command Set | ✅ | 2026-08-21 |
| 7 — I/O Commands | ✅ | 2026-08-21 |
| 8 — Extended Capabilities | ❔ | — |
| Annexes | ❔ | — |

## NVM Command Set Specification, Revision 1.3

| Chapter | Status | Last synced |
|---|---|---|
| 1-2 (Intro, Model) | n/a | — |
| 3 — I/O Commands | ✅ | 2026-08-21 |
| 4 — Admin Command behavior | ✅ | 2026-08-21 |
| 5 — Extended Capabilities | 🔍 | — |

## Zoned Namespace (ZNS) Command Set Specification, Revision 1.5

| Chapter | Status | Last synced |
|---|---|---|
| 1-2 (Intro, Model) | n/a | — |
| 3 — I/O Commands | ✅ | 2026-08-21 |
| 4 — Admin Commands | ✅ | 2026-08-21 |
| 5 — Extended Capabilities | ✅ | 2026-08-21 |
| Annex A — Host Considerations | ❔ | — |

## Other command sets

| Spec | Status | Last synced |
|---|---|---|
| Key Value Command Set, Rev 1.4 | ❌ not implemented | 2026-08-21 |
| Computational Programs Command Set, Rev 1.3 | ❌ not implemented | 2026-08-21 |
| Subsystem Local Memory Command Set, Rev 1.3 | ❌ mostly not implemented (one log page done) | 2026-08-21 |

## Not yet checked

NVMe Management Interface Specification, NVMe-oF Specification, PCIe/RDMA/TCP
Transport Specifications, NVMe Boot Specification.
