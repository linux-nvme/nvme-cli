# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libnvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
NAME          := libnvme
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

# Test strictly libnvme (do not run tests on all the subprojects)
.PHONY: test-strict
test-strict: ${NAME}
	meson test -C ${BUILD-DIR} --suite libnvme

.PHONY: rpm
rpm: ${BUILD-DIR}
	git archive --format=tar HEAD > libnvme.tar
	tar rf libnvme.tar ${BUILD-DIR}/libnvme.spec
	gzip -f -9 libnvme.tar
	rpmbuild -ta libnvme.tar.gz -v
