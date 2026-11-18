// SPDX-License-Identifier: GPL-2.0-or-later
//
// Use shr_bin_to_hex() to write bytes as hexadecimal digits. Report
// only: the loops do not follow a fixed pattern.

@@
expression b, s, e;
@@
for (...;...;...) {
<+...
(
* sprintf(b, "%02x", e)
|
* sprintf(b, "%02X", e)
|
* snprintf(b, s, "%02x", e)
|
* snprintf(b, s, "%02X", e)
)
...+>
}
