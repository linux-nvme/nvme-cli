#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

filename=nvme-sysfs-$(hostname)-$(uname -r).tar.xz

declare -a dirs=(
    "/sys/class/nvme"
    "/sys/class/nvme-fabrics"
    "/sys/class/nvme-generic"
    "/sys/class/nvme-subsystem"
    "/sys/bus/pci/slots"
)

files=""
for d in "${dirs[@]}"; do
    files+="${d} "
    for l in "${d}"/*; do
        files+="$(readlink -f $l) "
    done
done

tar -c -J -p -f "${filename}" ${files} 2> /dev/null
