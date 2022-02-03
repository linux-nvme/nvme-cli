#!/bin/bash

API_FILES="filters.h ioctl.h linux.h log.h tree.h types.h fabrics.h util.h"
DOC_ROOT=doc

rm ${DOC_ROOT}/libnvme.rst
for file in $API_FILES ; do
    ./doc/kernel-doc -rst src/nvme/$file >> ${DOC_ROOT}/libnvme.rst
done
