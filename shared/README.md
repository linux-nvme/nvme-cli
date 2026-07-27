<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
# shared

A small static library for code with no natural home in any single one of nvme-cli, libnvme, nvme-discoverd, or the Python bindings -- split by topic, one concern per file (`string-util.h`, `array-util.h`, ...), not lumped into a single header. Modeled loosely on systemd's `src/basic/`.

Licensed LGPL-2.1-or-later, matching libnvme, so libnvme can link it too. Everything here must be free of dependencies specific to any one consumer (no NVMe spec types, no CLI print/display logic, no discoverd internals).

There is no umbrella header. Include the specific file you need, e.g. `#include <string-util.h>`, not `#include <shared.h>`. From outside this directory, `shared_dep` (declared in `meson.build`) puts this directory on the include path, so no `shared/` prefix is needed either. See each header's own comments for what it provides.

Every public function, type, and macro is prefixed `shr_` (e.g. `shr_ptrarray_append()`, `enum shr_ini_event`) -- C has one flat global symbol namespace, and this closes off collisions with everything else in the tree, including libc itself. A `static` symbol private to one file (e.g. a helper used only inside that file) does not need the prefix, since it already has no external linkage to collide with.
