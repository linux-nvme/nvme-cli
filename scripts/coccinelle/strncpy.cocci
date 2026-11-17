// SPDX-License-Identifier: GPL-2.0-or-later
//
// Report strncpy(). It does not terminate the copy if the source is too
// long, and it fills the rest of the buffer with zeros. Use shr_strscpy()
// to copy a string, memcpy() to copy a known number of bytes.

@@
@@
* strncpy(...)
