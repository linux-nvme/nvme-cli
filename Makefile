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

.PHONY: update-subprojects
update-subprojects:
	meson subprojects update

${BUILD-DIR}:
	meson setup $@
	@echo "Configuration located in: $@"
	@echo "-------------------------------------------------------"

.PHONY: ${NAME}
${NAME}: ${BUILD-DIR}
	meson compile -C ${BUILD-DIR}

.PHONY: clean
clean:
ifneq ("$(wildcard ${BUILD-DIR})","")
	meson compile --clean -C ${BUILD-DIR}
endif

.PHONY: purge
purge:
ifneq ("$(wildcard ${BUILD-DIR})","")
	rm -rf ${BUILD-DIR}
	meson subprojects purge --confirm
endif

.PHONY: install
install: ${NAME}
	meson install -C ${BUILD-DIR} --skip-subprojects

.PHONY: uninstall
uninstall:
	cd ${BUILD-DIR} && meson --internal uninstall

.PHONY: dist
dist: ${NAME}
	meson dist -C ${BUILD-DIR} --formats gztar

.PHONY: test
test: ${NAME}
	meson test -C ${BUILD-DIR}

# Test strictly nvme-cli (do not run tests on all the subprojects)
.PHONY: test-strict
test-strict: ${NAME}
	meson test -C ${BUILD-DIR} --suite nvme-cli

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

.PHONY: static
static:
	meson ${BUILD-DIR} --buildtype=release \
		--default-library=static -Dc_link_args="-static" \
		--wrap-mode=forcefallback \
		-Dlibnvme:tests=false -Dlibnvme:keyutils=disabled
	ninja -C ${BUILD-DIR}
