#!/bin/bash

usage() {
    echo "Usage: release.sh [-d] VERSION"
    echo ""
    echo "The script does all necessary steps to create a new release."
    echo ""
    echo " -d:  no documentation update"
    echo ""
    echo "Note: The version number needs to be exactly"
    echo "      '^v[\d]+.[\d]+(.[\d\]+(-rc[0-9]+)?$'"
    echo ""
    echo "example:"
    echo "  release.sh v2.1-rc0     # v2.1 release candidate 0"
    echo "  release.sh v2.1         # v2.1 release"
}

build_doc=true

while getopts "d" o; do
    case "${o}" in
        d)
            build_doc=false
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

VERSION=${1:-}

if [ -z "$VERSION" ] ; then
    usage
    exit 1
fi

ver=""

re='^v([0-9]+\.[0-9]+(\.[0-9]+)?)(-rc[0-9]+)?$'
if [[ "$VERSION" =~ $re ]]; then
    echo "Valid version $VERSION string"
    # remove the leading 'v'
    ver=${VERSION#v}
else
    echo "Invalid version string $VERSION"
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

# update meson.build
sed -i -e "0,/[ \t]version: /s/\([ \t]version: \).*/\1\'$ver\',/" meson.build
git add meson.build
git commit -s -m "build: Update version to $VERSION"

if [ "$build_doc" = true ]; then
    # update documentation
    ./$doc_dir/update-docs.sh
    git add $doc_dir
    git commit -s -m "doc: Regenerate all docs for $VERSION"
fi

git tag -s -m "Release $VERSION" "$VERSION"
git push --dry-run origin "$VERSION"^{}:master tag "$VERSION"

read -p "All good? Ready to push changes to remote? [Yy]" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git push origin "$VERSION"^{}:master tag "$VERSION"
fi
