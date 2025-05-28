#!/bin/bash

usage() {
    echo "Usage: release.sh [-d] VERSION"
    echo ""
    echo "The script does all necessary steps to create a new release."
    echo ""
    echo " -d:  no documentation update"
    echo " -f:  disable all sanity checks and just do the release"
    echo " -l:  do not update library dependency"
    echo ""
    echo "Note: The version number needs to be exactly"
    echo "      '^v[\d]+.[\d]+(.[\d\]+(-rc[0-9]+)?$'"
    echo ""
    echo "example:"
    echo "  release.sh v2.1-rc0     # v2.1 release candidate 0"
    echo "  release.sh v2.1         # v2.1 release"
}

build_doc=true
update_lib_dep=true
force=false

while getopts "dfl" o; do
    case "${o}" in
        d)
            build_doc=false
            ;;
        f)
            force=true
            ;;
        l)
            update_lib_dep=false
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

cleanup() {
    if [ -z "${OLD_HEAD}" ] ; then
        exit
    fi
    git tag -d "Release $VERSION" "$VERSION"
    git reset --hard "${OLD_HEAD}"
}

register_cleanup() {
    OLD_HEAD="$(git rev-parse HEAD)"
}

unregister_cleanup() {
    OLD_HEAD=""
}

trap cleanup EXIT

register_cleanup

# expected version regex
re='^v([0-9]+\.[0-9]+(\.[0-9]+)?)(-rc[0-9]+)?$'

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

if [ "$update_lib_dep" = true ] && [[ -f subprojects/libnvme.wrap ]]; then
    git -C subprojects/libnvme fetch --all

    # extract the version string from libnvme by using the ref
    # defined in libnvme.wrap.
    libnvme_ref=$(sed -n "s/revision = \([0-9a-z]\+\)/\1/p" subprojects/libnvme.wrap)
    libnvme_VERSION=$(git -C subprojects/libnvme describe "${libnvme_ref}")
    if [[ "${libnvme_VERSION}" =~ ${re} ]]; then
        echo "libnvme: valid version ${libnvme_VERSION} string"

        # remove the leading 'v'
        libnvme_ver="${libnvme_VERSION#v}"
    else
        echo "libnvme: invalid version string ${libnvme_VERSION}"
        exit 1
    fi
fi

if [ "$force" = false ] ; then
    if [[ -n $(git status -s) ]]; then
        echo "tree is dirty."
        if [[ "${dry_run}" = false ]]; then
            exit 1
        fi
    fi

    if [ "$(git rev-parse --abbrev-ref HEAD)" != "master" ] ; then
        echo "currently not on master branch. abort."
        exit 1
    fi
fi

# update all docs
doc_dir=""
if [ -d "Documentation" ]; then
    doc_dir="Documentation"
elif [ -d "doc" ]; then
    doc_dir="doc"
else
    echo "documentation directory not found"
    exit 1
fi

if [ "$build_doc" = true ]; then
    # update documentation
    ./scripts/update-docs.sh
    git add $doc_dir
    git commit -s -m "doc: Regenerate all docs for $VERSION"
fi

declare -A maps
maps=(
    [src/libnvme.map]=LIBNVME
)

lib_ver="${ver//./_}"

for map_file in "${!maps[@]}"
do
    lib_name=${maps[$map_file]}

    if [ ! -f "${map_file}" ]; then
       continue
    fi

    lib_unreleased="${lib_name}_UNRELEASED"

    # Check if UNRELEASED has symbols
    if ! awk -v lib_unreleased="$lib_unreleased" '
        $0 ~ "^"lib_unreleased { in_section = 1; next }
        in_section && $0 ~ /\}/ { exit }
        in_section && $0 !~ /^[[:space:]]*($|\/|\/\*|\*|#)/ { found = 1; exit }
        END { exit !found }
    ' "${map_file}"; then
        continue
    fi

    sed -i \
        -e "s/^${lib_unreleased}\s*{/&\n};\n\n${lib_name}_${lib_ver} {/" \
        "$map_file"

    git add "${map_file}"
    echo "${map_file} updated."
done

# update meson.build
sed -i -e "0,/[ \t]version: /s/\([ \t]version: \).*/\1\'$ver\',/" meson.build
if [[ -n "$libnvme_VERSION" ]] && [[ -f subprojects/libnvme.wrap ]]; then
    sed -i -e "s/\(dependency('libnvme', version: '>=\)\([\.1-9]\+\)/\1$libnvme_ver/" meson.build
fi

git add meson.build
git commit -s -m "Release $VERSION"

git tag -s -m "Release $VERSION" "$VERSION"
git push --dry-run origin "$VERSION"^{}:master tag "$VERSION"

read -p "All good? Ready to push changes to remote? [Yy]" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git push origin "$VERSION"^{}:master tag "$VERSION"
    unregister_cleanup
fi
