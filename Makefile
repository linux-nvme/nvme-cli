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

# Allow PLUGINS variable as a shorthand for MESON_ARGS
ifdef PLUGINS
	MESON_ARGS += -Dplugins=$(PLUGINS)
endif

.PHONY: update-subprojects
update-subprojects:
	meson subprojects update

${BUILD-DIR}:
	meson setup $@ ${MESON_ARGS}
	@echo "Configuration located in: $@"
	@echo "-------------------------------------------------------"

.PHONY: ${NAME}
${NAME}: ${BUILD-DIR}
	meson compile -C ${BUILD-DIR}

.PHONY: clean
clean:
ifneq ("$(wildcard ${BUILD-DIR})","")
	rm -rf ${BUILD-DIR}
	meson subprojects purge --confirm
endif

.PHONY: purge
purge: clean

.PHONY: install
install: ${NAME}
	meson install -C ${BUILD-DIR} --skip-subprojects

.PHONY: uninstall
uninstall:
	cd ${BUILD-DIR} && meson --internal uninstall

.PHONY: update-accessors
update-accessors: ${BUILD-DIR}
	meson compile -C ${BUILD-DIR} update-accessors

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
	meson setup ${BUILD-DIR} ${MESON_ARGS} \
		-Dudevrulesdir=$(shell rpm --eval '%{_udevrulesdir}') \
		-Dsystemddir=$(shell rpm --eval '%{_unitdir}') \
		-Ddocs=man -Ddocs-build=true
	rpmbuild -ba ${BUILD-DIR}/nvme.spec --define "_builddir ${BUILD-DIR}" -v

.PHONY: debug
debug:
	meson setup ${BUILD-DIR} ${MESON_ARGS} --buildtype=debug
	meson compile -C ${BUILD-DIR}

.PHONY: static
static:
	meson setup ${BUILD-DIR} ${MESON_ARGS}
		--buildtype=release \
		--wrap-mode=forcefallback \
		--default-library=static \
		--prefix=/usr \
		-Dc_link_args="-static" \
		-Dkeyutils=disabled \
		-Dliburing=disabled \
		-Dpython=disabled \
		-Dopenssl=disabled \
		-Dtests=false \
		-Dexamples=false

	meson compile -C ${BUILD-DIR}

CHECKPATCH     := /tmp/checkpatch.pl
CHECKPATCH_URL := https://raw.githubusercontent.com/torvalds/linux/master/scripts/checkpatch.pl
BASE ?= master

# make checkpatch              → check all commits on branch vs $(BASE)
# make checkpatch BASE=HEAD~3  → check last 3 commits only
.PHONY: checkpatch
checkpatch:
	@[ -f ${CHECKPATCH} ] || curl -sSf ${CHECKPATCH_URL} -o ${CHECKPATCH}
	git format-patch --stdout ${BASE}..HEAD | perl ${CHECKPATCH} -

# make checkpatch-diff  → check staged/unstaged changes + untracked files
.PHONY: checkpatch-diff
checkpatch-diff:
	@[ -f ${CHECKPATCH} ] || curl -sSf ${CHECKPATCH_URL} -o ${CHECKPATCH}
	git diff HEAD | perl ${CHECKPATCH} -
	@git ls-files --others --exclude-standard | xargs -r -I{} perl ${CHECKPATCH} --file {}
