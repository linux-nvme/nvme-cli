#!/bin/bash

usage() {
    echo "release.sh: VERSION"
    echo ""
    echo "The script does all necessary steps to create a new release."
    echo ""
    echo "Note: The version number needs to be exactly"
    echo "      '^v[\d]+.[\d]+(-rc[0-9]+)?$'"
    echo ""
    echo "example:"
    echo "  release.sh v2.1-rc0     # v2.1 release candidate 0 -> sets the project "
    echo "                          # version to '1.1' and sets the tag"
    echo "  release.sh v2.1-rc1     # v2.1 release canditate 1 -> only sets the tag"
    echo "  release.sh v2.1         # v2.1 release -> sets the final tag"
}

VERSION=$1

if [ -z "$VERSION" ] ; then
    usage
    exit 1
fi

new_ver=""
rc=""

re='^v([0-9]+\.[0-9]+)(-rc[0-9]+)?$'
if [[ "$VERSION" =~ $re ]]; then
    echo "Valid version $VERSION string"
    new_ver=${BASH_REMATCH[1]}
    rc=${BASH_REMATCH[2]}
else
    echo "Invalid version string $VERSION"
    echo ""
    usage
    exit 1
fi

if [[ -n $(git status -s) ]]; then
    echo "tree is dirty. abort."
    exit 1
fi

if [ "$(git rev-parse --abbrev-ref HEAD)" != "master" ] ; then
    echo "currently not on master branch. abort."
    exit 1
fi

# update all docs
doc_dir=""
if [ -d "Documentation" ]; then
    doc_dir="Documentation"
elif [ -d "doc" ]; then
    doc_dir="doc"
else
    echo "documenation directory not found"
    exit 1
fi

./$doc_dir/update-docs.sh
git add $doc_dir
git commit -s -m "Regenerate all documentation" \
              -m "Regenerate documentation for $VERSION release"

# update meson.build
old_ver=$(sed -n "0,/[ \t]\+version: /s/[ \t]\+version: '\([0-9]\+.[0-9]\+\)',$/\1/p" meson.build)
if [ "$old_ver" != "$new_ver" ]; then
    # Only update project version once, that is either
    # - for the first RC phase or
    # - for the release when there was no RC
    sed -i -e "0,/[ \t]version: /s/\([ \t]version: \).*/\1\'$new_ver\',/" meson.build
    git add meson.build
fi

git commit -s -m "Release $VERSION"
git tag -s -m "Release $VERSION" "$VERSION"
git push --dry-run origin "$VERSION"^{}:master tag "$VERSION"

read -p "All good? Ready to push changes to remote? [Yy]" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git push origin "$VERSION"^{}:master tag "$VERSION"
fi
