# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of nvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
NAME          := nvme
.DEFAULT_GOAL := ${NAME}
BUILD-DIR     := .build

${BUILD-DIR}:
	meson $@
	@echo "Configuration located in: $@"
	@echo "-------------------------------------------------------"

.PHONY: ${NAME}
${NAME}: ${BUILD-DIR}
	ninja -C ${BUILD-DIR}

.PHONY: clean
clean:
ifneq ("$(wildcard ${BUILD-DIR})","")
	ninja -C ${BUILD-DIR} -t $@
endif

.PHONY: purge
purge:
ifneq ("$(wildcard ${BUILD-DIR})","")
	rm -rf ${BUILD-DIR}
endif

.PHONY: install dist
install dist: ${BUILD-DIR}
	cd ${BUILD-DIR} && meson $@

.PHONY: test
test: ${BUILD-DIR}
	ninja -C ${BUILD-DIR} $@

.PHONY: rpm
rpm:
	meson ${BUILD-DIR} \
		-Dudevrulesdir=$(shell rpm --eval '%{_udevrulesdir}') \
		-Dsystemddir=$(shell rpm --eval '%{_unitdir}') \
		-Ddocs=man -Ddocs-build=true
	rpmbuild -ba ${BUILD-DIR}/nvme.spec --define "_builddir ${BUILD-DIR}" -v

.PHONY: debug
debug:
	meson ${BUILD-DIR} --buildtype=debug
	ninja -C ${BUILD-DIR}
