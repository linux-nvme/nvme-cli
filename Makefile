CFLAGS := -I $(SRC) -m64 -std=c99 -O2 -g -pthread -D_GNU_SOURCE -D_REENTRANT -Wall -Werror
LDFLAGS := -lm
NVME = nvme
INSTALL ?= install
SRC = ./src
LIBUDEV:=$(shell ld -ludev > /dev/null 2>&1 ; echo $$?)
ifeq ($(LIBUDEV),0)
	LDFLAGS += -ludev
	CFLAGS  += -DLIBUDEV_EXISTS
endif

default: $(NVME)

nvme: nvme.c ./linux/nvme.h argconfig.o suffix.o
	$(CC) $(CFLAGS) nvme.c $(LDFLAGS) -o $(NVME) argconfig.o suffix.o

argconfig.o: $(SRC)/argconfig.c $(SRC)/argconfig.h $(SRC)/suffix.h
	$(CC) -c $(CFLAGS) $(SRC)/argconfig.c

suffix.o: $(SRC)/suffix.c $(SRC)/suffix.h
	$(CC) -c $(CFLAGS) $(SRC)/suffix.c

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
