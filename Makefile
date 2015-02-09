CFLAGS := -m64 -O2 -g -pthread -D_GNU_SOURCE -D_REENTRANT -Wall -Werror
LDFLAGS := -m64 -lm
NVME = nvme
INSTALL ?= install

LIBUDEV:=$(shell ld -ludev > /dev/null 2>&1 ; echo $$?)
ifeq ($(LIBUDEV),0)
	LDFLAGS += -ludev
	CFLAGS  += -DLIBUDEV_EXISTS
endif

default: $(NVME)

doc: $(NVME)
	$(MAKE) -C Documentation

all: doc

clean:
	rm -f $(NVME) *.o *~
	$(MAKE) -C Documentation clean

clobber: clean

install: default
	$(MAKE) -C Documentation install
	$(INSTALL) -m 755 nvme /usr/local/bin

.PHONY: default all doc clean clobber install

test:
	@echo $(LIBUDEV)