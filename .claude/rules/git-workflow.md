# Git workflow — commits and PRs

## Never commit or create PRs without explicit user approval

Claude must **never** run `git commit`, `git push`, or `gh pr create`
autonomously. Always stop and ask the user before taking any of these actions,
even if the user has said "go ahead" for earlier steps in the same session.

This applies to:
- `git commit` (any form, including `--amend`)
- `git push` (any form, including `--force`)
- `gh pr create` / `gh pr edit`
- Any other command that writes to the remote repository or creates/modifies
  a GitHub object (issues, PR comments, labels, etc.)

## Correct behaviour

When work is ready to commit or submit:
1. Show the user a `git diff --stat` or the proposed commit message.
2. **Ask explicitly**: "Shall I commit this?" or "Ready to open the PR —
   shall I proceed?"
3. Wait for the user to confirm before running the command.

## PR branch hygiene

When preparing a PR branch:
- No merge commits — rebase on `master` instead.
- Every individual commit in the series must build cleanly on its own.
- Run `meson compile -C .build` (or `./scripts/build.sh`) to verify before
  declaring the branch ready.
