# Makefile
#
# Copyright (C) 2017-2019 Red Hat, Inc.
# Gris Ge <fge@redhat.com>
#
include ../Makefile.inc

ifeq ($(TOPDIR),)
	TOPDIR	= ..
endif

LIBNVME_DIR=$(TOPDIR)/libnvme
LIBNVME_VERSION_MAJOR=0
LIBNVME_VERSION=0.1.0
SONAME=$(LIBNVME_VERSION)
DEVLIB = libnvme.so
LIBS = $(DEVLIB).$(SONAME)
LIBS_MAJOR = $(DEVLIB).$(LIBNVME_VERSION_MAJOR)
HEADERS = libnvme/libnvme.h
TESTS = test/ptr_array_test test/nvme_ctrls_test
PKGFILE = libnvme.pc

OBJS = libnvme.o ioctl.o ptr_array.o sysfs.o ctrl.o utils.o

override CFLAGS += -Wall -Werror -Wextra -fvisibility=hidden -fPIC -I.

all: $(LIBS) $(DEVLIB) $(LIBS_MAJOR) $(TESTS)

$(LIBS): $(OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname=$@ \
		-o $@ $(OBJS)

$(DEVLIB): $(LIBS)
	ln -sf $(LIBS) $@

$(LIBS_MAJOR): $(LIBS)
	ln -sf $(LIBS) $@

clean:
	$(RM) core *.a *.o *.gz *.so *.so.* $(TESTS) test/nvme_test_ns.o

test/ptr_array_test: ptr_array.o

test/nvme_ctrls_test: $(DEVLIB)
test/nvme_ctrls_test: CFLAGS = -Wall -Werror -Wextra -I$(TOPDIR)/libnvme -g
test/nvme_ctrls_test: LDFLAGS = -L$(TOPDIR)/libnvme -lnvme

check: $(TESTS)
	for unit_test in $(TESTS); do \
		echo "Running $$unit_test"; \
		sudo env LD_LIBRARY_PATH=$(LIBNVME_DIR) \
			valgrind --quiet --leak-check=full \
			--show-reachable=no --show-possibly-lost=no \
			--trace-children=yes --error-exitcode=1 \
			$$unit_test || exit 1; \
	done

install: $(LIBS) $(DEVLIB) $(LIBS_MAJOR)
	$(INSTALL) -d $(DESTDIR)$(LIB_DIR)/
	$(INSTALL) $(LIBS) $(DESTDIR)$(LIB_DIR)/
	$(INSTALL) $(DEVLIB) $(DESTDIR)$(LIB_DIR)/
	$(INSTALL) $(LIBS_MAJOR) $(DESTDIR)$(LIB_DIR)/
	$(INSTALL) $(HEADERS) $(DESTDIR)$(INCLUDE_DIR)/
	$(INSTALL) -m 644 -D $(PKGFILE).in $(DESTDIR)$(PKGCONF_DIR)/$(PKGFILE)
	perl -i -pe 's|__VERSION__|$(LIBNVME_VERSION)|g' \
		$(DESTDIR)$(PKGCONF_DIR)/$(PKGFILE)
	perl -i -pe 's|__LIB_DIR__|$(LIB_DIR)|g' \
		$(DESTDIR)$(PKGCONF_DIR)/$(PKGFILE)
	perl -i -pe 's|__INCLUDE_DIR__|$(INCLUDE_DIR)|g' \
		$(DESTDIR)$(PKGCONF_DIR)/$(PKGFILE)
