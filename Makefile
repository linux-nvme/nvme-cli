CFLAGS := -I $(SRC) $(CFLAGS) -m64 -std=gnu99 -O2 -g -pthread -D_GNU_SOURCE -D_REENTRANT -Wall -Werror
LDFLAGS := $(LDFLAGS) -lm
NVME = nvme
INSTALL ?= install
SRC = ./src
DESTDIR =
PREFIX := /usr/local
SBINDIR = $(PREFIX)/sbin
LIBUDEV:=$(shell ld -ludev > /dev/null 2>&1 ; echo $$?)
ifeq ($(LIBUDEV),0)
	LDFLAGS += -ludev
	CFLAGS  += -DLIBUDEV_EXISTS
endif

# For the uapi header file we priorize this way:
# 1. Use /usr/src/$(uname -r)/include/uapi/linux/nvme.h
# 2. Use ./linux/nvme.h

ifneq (,$(wildcard /usr/src/linux-headers-$(shell uname -r)/include/uapi/linux/nvme.h))
	NVME_HEADER = /usr/src/linux-headers-$(shell uname -r)/include/uapi/linux/nvme.h
else
	NVME_HEADER = ./linux/nvme.h
endif

default: $(NVME)

nvme: nvme.c $(NVME_HEADER) argconfig.o suffix.o
	$(CC) $(CFLAGS) nvme.c $(LDFLAGS) -o $(NVME) argconfig.o suffix.o

argconfig.o: $(SRC)/argconfig.c $(SRC)/argconfig.h $(SRC)/suffix.h
	$(CC) -c $(CFLAGS) $(SRC)/argconfig.c

suffix.o: $(SRC)/suffix.c $(SRC)/suffix.h
	$(CC) -c $(CFLAGS) $(SRC)/suffix.c

doc: $(NVME)
	$(MAKE) -C Documentation

all: doc

clean:
	rm -f $(NVME) *.o *~ a.out
	$(MAKE) -C Documentation clean

clobber: clean
	$(MAKE) -C Documentation clobber

install-man:
	$(MAKE) -C Documentation install-no-build

install-bin: default
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 755 nvme $(DESTDIR)$(SBINDIR)

install: install-bin install-man

.PHONY: default all doc clean clobber install install-bin install-man
