#!/bin/bash

API_FILES="src/nvme/filters.h src/nvme/ioctl.h src/nvme/linux.h src/nvme/log.h src/nvme/tree.h src/nvme/types.h src/nvme/fabrics.h src/nvme/util.h"
MAN=doc/man

for file in $API_FILES ; do
    for func in $(sed -n 's/ \* \([a-z_]*\)() -.*/\1/p' $file); do
	echo "Updating ${func}.2"
	./doc/kernel-doc -man -function $func $file > ${MAN}/${func}.2
    done
    for struct in $(sed -n 's/ \* struct \([a-z_]*\) -.*/\1/p' $file); do
	echo "Updating ${struct}.2"
	./doc/kernel-doc -man -function $struct $file > ${MAN}/${struct}.2
    done
    for enum in $(sed -n 's/ \* enum \([a-z_]*\) -.*/\1/p' $file); do
	echo "Updating ${enum}.2"
	./doc/kernel-doc -man -function $enum $file > ${MAN}/${enum}.2
    done
done
