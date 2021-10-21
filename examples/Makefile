CFLAGS ?= -g -O2
override CFLAGS += -Wall -D_GNU_SOURCE -I .. -I ../src -L ../src -I../ccan --include "config.h"

include ../Makefile.quiet

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

all_targets += telemetry-listen display-tree display-columnar discover-loop

all: $(all_targets)

%: %.c ../src/libnvme.a
	$(QUIET_CC)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lnvme $(LIBS)

clean:
	rm -f $(all_targets)
