CFLAGS := -m64 -O2 -g -pthread -D_GNU_SOURCE -D_REENTRANT -Wall
LDFLAGS := -m64 -lm
NVME = nvme
INSTALL ?= install

default: $(NVME)

doc: $(NVME)
	$(MAKE) -C Documentation

all: doc

clean:
	rm -f $(NVME) *.o
	$(MAKE) -C Documentation clean

clobber: clean

install: default
	$(MAKE) -C Documentation install
	$(INSTALL) -m 755 nvme /usr/local/bin

.PHONY: default all doc clean clobber install
