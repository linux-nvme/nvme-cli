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

.PHONY: uninstall
uninstall:
	cd ${BUILD-DIR} && meson --internal uninstall

.PHONY: test
test: ${BUILD-DIR}
	ninja -C ${BUILD-DIR} $@

.PHONY: rpm
rpm: ${BUILD-DIR}
	git archive --format=tar HEAD > libnvme.tar
	tar rf libnvme.tar ${BUILD-DIR}/libnvme.spec
	gzip -f -9 libnvme.tar
	rpmbuild -ta libnvme.tar.gz -v
