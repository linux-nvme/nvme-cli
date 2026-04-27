# Commit message format

Follow the Linux kernel mailing-list convention used by this project.

## Structure

```
<subject>: <short summary>

<body — wrap at 72 columns>

Signed-off-by: Full Name <email@example.com>
Assisted-by: Claude Model <noreply@anthropic.com>   # if AI-assisted
```

- **Subject prefix**: use the subsystem or file being changed
  (`libnvme`, `nvme`, `fabrics`, `plugins/ocp`, `doc`, `tests`, …).
- **Summary line**: imperative mood, lowercase after the colon, no trailing
  period, ≤ 72 characters total.
- **Body**: explain *why*, not just *what*. Omit if the summary is
  self-explanatory for a trivial fix.
- **Signed-off-by**: required on every commit (Developer Certificate of
  Origin). Use the author's real name and email.
- **Assisted-by**: required whenever an AI assistant contributed to the
  commit (wrote code, generated a patch, drafted the message, etc.).
  Use the model name and `noreply@anthropic.com` as the address.
  Examples:
  - `Assisted-by: Claude Sonnet 4.6 <noreply@anthropic.com>`
  - `Assisted-by: Claude Opus 4.7 <noreply@anthropic.com>`

## Example

```
libnvme: add libnvme_ctrl_get_address() accessor

The ctrl address field is built from multiple sysfs attributes and
requires custom formatting, so a hand-written getter is provided
instead of a generated one.

Signed-off-by: Jane Developer <jane@example.com>
Assisted-by: Claude Sonnet 4.6 <noreply@anthropic.com>
```

## What to avoid

- Merge commits in a PR branch — rebase instead.
- Vague summaries like "fix bug" or "update code".
- Committing generated files (accessors.{h,c}) without also committing
  the private.h change that triggered the regeneration.
