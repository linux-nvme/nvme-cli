CFLAGS ?= -g -O2
override CFLAGS += -Wall -D_GNU_SOURCE -L../src/ -I../src/ -lsystemd

include ../Makefile.quiet

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

all_targets += telemetry-listen display-tree display-columnar discover-loop

all: $(all_targets)

%: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ $< -lnvme

clean:
	rm -f $(all_targets)
