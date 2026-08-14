# ioctl mock tests

These tests exercise libnvme's command-building code without a device. Each
test declares the NVMe command it expects libnvme to issue, runs a libnvme
call, and checks that what reached the driver matches. The tests themselves
(`identify.c`, `features.c`, `logs.c`, ...) are shared across platforms; only
the interception layer differs.

## How the mock is injected

On Linux, `mock.c` is loaded with `LD_PRELOAD` so its `ioctl()` shadows libc's,
and it recovers the real one with `dlsym(RTLD_NEXT)`.

Windows has neither mechanism, so `mock-win.c` intercepts `DeviceIoControl`
by rewriting libnvme's Import Address Table entry for it (`iat-hook.c`). Every
PE image reaches an imported function through a slot in its IAT, so
overwriting libnvme's slot redirects the call without modifying libnvme's code.
The patch is per-module and touches only data, so other modules calling
`DeviceIoControl` are unaffected — which is what lets the mock pass unrelated
traffic straight through to the real function.

### Why not `ld --wrap`

`--wrap` operates at link time on symbols the *linker* resolves. libnvme is
built as a DLL, so its call to `DeviceIoControl` is bound through its own
import thunk when the DLL loads. No wrappable symbol reference ever appears in
the test executable's link, so `--wrap=DeviceIoControl` has nothing to
rename and the call reaches the real function regardless. Rewriting the thunk
at runtime is the only way to intercept it from outside libnvme.

The IAT approach was verified on both x86_64 and aarch64.

## Why the Windows mock decodes rather than compares

The Linux mock reads a struct that is already an NVMe passthru command, so
checking it against the expected `struct mock_cmd` is a field-by-field
comparison.

Windows has no passthru ioctl. `ioctl-win.c` translates each command family
into a different Windows structure — `STORAGE_PROPERTY_QUERY` for identify,
get-log-page and get-features, `STORAGE_PROPERTY_SET` for set-features,
`STORAGE_PROTOCOL_COMMAND` for vendor passthru, and dedicated IOCTLs for
firmware, format and sanitize. The Windows mock therefore translates *back*,
reconstructing the NVMe fields the request actually carries, and then reuses
the same expectations the shared tests declare.

That forward translation is lossy, and the decoder has to be honest about it.
Each decoder records which fields it recovered, and only those are compared; a
field Windows discards is skipped rather than compared against zero, which
would turn a real mismatch into a false pass. Where a field survives only
partly — Windows' `LogSpecificField` is 4 bits wide against NVMe's 7, and
identify forwards CNS but drops CNTID — the decoder also records a bit mask,
so the surviving bits are still asserted while the lost ones are not.

## Declaring behaviour that differs on Windows

Some commands cannot behave identically on Windows, and the tests state that
explicitly rather than being skipped. Two fields on `struct mock_cmd` cover it:

- `win_err` — what libnvme returns when Windows cannot carry the command's
  result faithfully. Windows reports NVMe status only as a Win32 error, and
  `get_errno_from_error()` recognises a handful of errnos, so most statuses and
  errnos are flattened. Two paths do recover a status from an error
  (`get_features_status()` and `get_log_page_status()`); everything else
  becomes `-EIO`.
- `win_no_ioctl` — set alongside `win_err` when Windows rejects the command
  before issuing any IOCTL, so no mock is consumed. This is what a Command Set
  other than NVM does: both `submit_admin_identify()` and
  `submit_admin_get_log_page()` check the CSI field themselves and return
  `-ENOTSUP` without touching the driver.

Tests read these through `mock_err()`, `mock_ok()` and `mock_result()`, which
resolve to the plain expectation everywhere except Windows. The mock rejects an
expectation libnvme could not have produced, so an undeclared divergence fails
loudly instead of being approximated.

## Which tests run on Windows

`meson.build` limits the Windows test list to the command families the mock
decodes. The rest reach the driver by routes with no decoder yet — SCSI CDBs
for read/write/flush, dedicated firmware/format/sanitize IOCTLs — or are not
implemented on Windows at all. Enabling one needs a decoder for its family, so
they stay off rather than reporting a pass they didn't earn.
