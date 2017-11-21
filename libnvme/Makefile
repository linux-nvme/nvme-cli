# Makefile
#
# Copyright (C) 2017 Red Hat, Inc.
# Gris Ge <fge@redhat.com>

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
HEADERS = libnvme.h
TESTS = test/ptr_array_test test/nvme_ctrls_test

OBJS = libnvme.o ioctl.o ptr_array.o sysfs.o ctrl.o utils.o

CFLAGS ?= -g
CFLAGS += -Wall -Werror -Wextra -fvisibility=hidden -fPIC -I.

#LIBADD =

all: $(LIBS) $(DEVLIB) $(LIBS_MAJOR)

$(LIBS): $(OBJS)
	$(CC) $(LDFLAGS) -shared -Wl,-soname=$@ -o $@ $(OBJS) $(LIBADD)

$(DEVLIB): $(LIBS)
	ln -sf $(LIBS) $@

$(LIBS_MAJOR): $(LIBS)
	ln -sf $(LIBS) $@

clean:
	$(RM) core *.a *.o *.gz *.so *.so.* $(TESTS)

test/ptr_array_test: ptr_array.o

test/nvme_ctrls_test: CFLAGS = -Wall -Werror -Wextra -I$(TOPDIR)/libnvme -g
test/nvme_ctrls_test: LDFLAGS = -L$(TOPDIR)/libnvme -lnvme
test/nvme_ctrls_test: $(DEVLIB)

check: $(TESTS)
	for unit_test in $(TESTS); do \
		echo "Running $$unit_test"; \
		sudo env LD_LIBRARY_PATH=$(LIBNVME_DIR) \
			valgrind --quiet --leak-check=full \
			--show-reachable=no --show-possibly-lost=no \
			--trace-children=yes --error-exitcode=1 \
			$$unit_test || exit 1; \
	done
