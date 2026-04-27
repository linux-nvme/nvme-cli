# License headers

This repository contains two components with different licenses. Every new
source file must carry the correct SPDX identifier as its first line.

| Directory / component | License | SPDX identifier |
|-----------------------|---------|-----------------|
| `libnvme/` (library) | GNU Lesser General Public License v2.1 or later | `LGPL-2.1-or-later` |
| `nvme.c`, `nvme.h`, plugins, CLI utilities | GNU General Public License v2.0 or later | `GPL-2.0-or-later` |

## Format

C source and header files:
```c
// SPDX-License-Identifier: LGPL-2.1-or-later
```
or the block-comment form used by some existing files:
```c
/* SPDX-License-Identifier: GPL-2.0-or-later */
```

Python, shell, and meson files:
```python
# SPDX-License-Identifier: LGPL-2.1-or-later
```

The SPDX line must be the very first line of the file (before any other
comment or include).
