CFLAGS := -m64 -O2 -g -pthread -D_GNU_SOURCE -D_REENTRANT -Wall
LDFLAGS := -m64 -lm
NVME_PROGS = nvme
ALL_PROGS := $(NVME_PROGS)
default: $(ALL_PROGS)
	$(MAKE) -C Documentation
clean:
	rm -f $(ALL_PROGS) *.o
	$(MAKE) -C Documentation clean
clobber: clean
.PHONY: default clean clobber
