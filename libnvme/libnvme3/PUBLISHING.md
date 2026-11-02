<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
# Publishing the libnvme PyPI package

Publishing is handled automatically by GitHub Actions workflows — no manual `twine` or `pip` commands are needed.

## What gets published

A **source distribution** (sdist) is published — not a binary wheel. The package contains the full source tree and builds libnvme and the Python bindings on the target machine at install time (via `pyproject.toml`).

## Workflows

### Test PyPI — once a week

The `libnvme-release-python.yml` workflow builds a dev sdist on every push to `master` (version derived from `git describe`, e.g. `3.0.dev123`). It publishes it to [TestPyPI](https://test.pypi.org/) only from the weekly schedule or a manual run of the workflow. A version that is already on TestPyPI is skipped.

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
