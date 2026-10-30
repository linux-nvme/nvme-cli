#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>

usage() {
    echo "Usage: release.sh [-d] [-f] [-r REMOTE] VERSION"
    echo ""
    echo "The script does all necessary steps to create a new release."
    echo ""
    echo " -d:  no documentation update"
    echo " -f:  disable all sanity checks and just do the release"
    echo " -r:  remote to push the release to (default: origin)"
    echo ""
    echo "Note: The version number needs to match"
    echo "      '^v[0-9]+.[0-9]+(.[0-9]+)?(-rc[0-9]+|-(a|b).[0-9]+)?$'"
    echo ""
    echo "example:"
    echo "  release.sh v3.2-rc1     # v3.2 release candidate 1"
    echo "  release.sh v3.2         # v3.2 release"
}

build_doc=true
force=false
remote=origin

while getopts "dfr:" o; do
    case "${o}" in
        d)
            build_doc=false
            ;;
        f)
            force=true
            ;;
        r)
            remote="${OPTARG}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

VERSION=${1:-}

if [ -z "$VERSION" ] ; then
    usage
    exit 1
fi

cleanup() {
    if [ -z "${OLD_HEAD}" ] ; then
        exit
    fi
    if [ -n "${BUILDDIR}" ] ; then
        rm -rf -- "${BUILDDIR}"
    fi
    if [ "${TAGGED}" = true ] ; then
        git tag -d "$VERSION"
    fi
    git reset --hard "${OLD_HEAD}"
    # The sanity checks ensured a clean tree, so the untracked
    # files are new pages from update-docs.sh.
    if [ "$force" = false ] ; then
        git clean -fdq -- Documentation libnvme/doc completions
    fi
}

register_cleanup() {
    OLD_HEAD="$(git rev-parse HEAD)"
}

unregister_cleanup() {
    OLD_HEAD=""
}

trap cleanup EXIT

# expected version regex
re='^v([0-9]+\.[0-9]+(\.[0-9]+)?)(-rc[0-9]+|-(a|b)\.[0-9]+)?$'

# use the version string provided from the command line
if [[ "$VERSION" =~ ${re} ]]; then
    echo "valid version $VERSION string"

    # remove the leading 'v'
    ver="${VERSION#v}"
else
    echo "invalid version string $VERSION"
    exit 1
fi

cd "$(git rev-parse --show-toplevel)" || exit 1

if [ "$force" = false ] ; then
    if [[ -n $(git status -s) ]]; then
        echo "tree is dirty."
        exit 1
    fi

    if [ "$(git rev-parse --abbrev-ref HEAD)" != "master" ] ; then
        echo "currently not on master branch. abort."
        exit 1
    fi
fi

register_cleanup

if [ "$build_doc" = true ]; then
    if ! ./scripts/update-docs.sh; then
        echo "release.sh: failed to regenerate the documentation" >&2
        exit 1
    fi
    git add Documentation libnvme/doc
    git commit -s -m "doc: Regenerate all docs for $VERSION"
fi

BUILDDIR="$(mktemp -d)"

if ! meson setup -Dlibnvme=enabled -Djson-c=enabled "${BUILDDIR}" > "${BUILDDIR}/setup.log" 2>&1; then
    echo "release.sh: failed to configure a build for completion generation:" >&2
    cat "${BUILDDIR}/setup.log" >&2
    rm -rf -- "${BUILDDIR}"
    exit 1
fi

if ! meson compile -C "${BUILDDIR}" > "${BUILDDIR}/compile.log" 2>&1; then
    echo "release.sh: failed to build nvme for completion generation:" >&2
    cat "${BUILDDIR}/compile.log" >&2
    rm -rf -- "${BUILDDIR}"
    exit 1
fi

if ! "${BUILDDIR}/nvme" utils dump-command-metadata > "${BUILDDIR}/metadata.json" 2> "${BUILDDIR}/metadata.err"; then
    echo "release.sh: 'nvme utils dump-command-metadata' failed; is nvme built with json-c support?" >&2
    cat "${BUILDDIR}/metadata.err" >&2
    rm -rf -- "${BUILDDIR}"
    exit 1
fi

if ! ./completions/generate-completions.py \
    --bash completions/bash-nvme-completion.sh \
    --zsh completions/_nvme \
    --powershell completions/nvme-completion.ps1 \
    < "${BUILDDIR}/metadata.json"; then
    echo "release.sh: failed to generate completions" >&2
    rm -rf -- "${BUILDDIR}"
    exit 1
fi
rm -rf -- "${BUILDDIR}"

if [[ -n $(git status -s -- completions/bash-nvme-completion.sh completions/_nvme completions/nvme-completion.ps1) ]]; then
    git add completions/bash-nvme-completion.sh completions/_nvme completions/nvme-completion.ps1
    git commit -s -m "completions: regenerate bash, zsh, and PowerShell completions for $VERSION"
fi

if [[ "$ver" != *-* ]]; then
    news_ver="$ver"
    news_heading="## Changes in $news_ver (unreleased)"
    if ! grep -qF "$news_heading" NEWS.md; then
        echo "release.sh: could not find '$news_heading' in NEWS.md" >&2
        exit 1
    fi
    sed -i "0,/^${news_heading//./\\.}$/s//## Changes in $news_ver ($(date +%Y-%m-%d))/" NEWS.md
    git add NEWS.md
fi

# update meson.build
sed -i -e "0,/[ \t]version: /s/\([ \t]version: \).*/\1\'$ver\',/" meson.build
git add meson.build
git commit -s -m "Release $VERSION"

git tag -s -m "Release $VERSION" "$VERSION" || exit 1
TAGGED=true
git push --dry-run "$remote" "$VERSION"^{}:master tag "$VERSION"

read -p "All good? Ready to push changes to remote? [Yy]" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git push "$remote" "$VERSION"^{}:master tag "$VERSION"
    unregister_cleanup
fi
