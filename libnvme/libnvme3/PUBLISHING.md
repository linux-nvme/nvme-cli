<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
# Publishing the libnvme PyPI package

Publishing is handled automatically by GitHub Actions workflows — no manual `twine` or `pip` commands are needed.

## What gets published

A **source distribution** (sdist) is published — not a binary wheel. The package contains the full source tree and builds libnvme and the Python bindings on the target machine at install time (via `pyproject.toml`).

## Workflows

### Test PyPI — once a week

The `release-python.yml` workflow builds a dev sdist on every push to `master` (version derived from `git describe`, e.g. `3.0.dev123`). It publishes it to [TestPyPI](https://test.pypi.org/) only from the weekly schedule or a manual run of the workflow. A version that is already on TestPyPI is skipped.

To install from TestPyPI:

```bash
pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  libnvme3==<version>
```

### PyPI — on release tags

When a tag matching `vX.Y`, `vX.Y.Z` or a release candidate `vX.Y[.Z]-rcN` is pushed, the same workflow publishes the release sdist to the official [PyPI](https://pypi.org/) registry. Alpha and beta tags (`-a.N`, `-b.N`) are not published.

Publishing uses OIDC (`id-token: write`) — no API token is required.
The trusted publisher on PyPI and TestPyPI names the workflow file
`release-python.yml` and the environment `pypi`. Renaming the file
needs a new trusted publisher on both, or uploads fail.

## Removing old dev releases

PyPI has no API to delete releases, and the OIDC publishing cannot delete
either. Remove old dev releases from TestPyPI by hand with
[pypi-cleanup](https://github.com/arcivanov/pypi-cleanup). It logs in with
the password and the 2FA code of a TestPyPI owner of `libnvme3`:

```bash
pip install pypi-cleanup

# list what would be deleted, no login needed
pypi-cleanup -t https://test.pypi.org -p libnvme3 \
  --leave-most-recent-only --query-only

# delete all versions except the most recent one
pypi-cleanup -t https://test.pypi.org -p libnvme3 -u <username> \
  --leave-most-recent-only --do-it
```

`--leave-most-recent-only` deletes every version except the newest,
not only the dev versions. Do not run it against PyPI.
