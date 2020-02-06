CFLAGS ?= -g -O2
override CFLAGS += -Wall -D_GNU_SOURCE -L../src/ -I../src/

include ../Makefile.quiet

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

all_targets += telemetry-listen display-tree

all: $(all_targets)

test_srcs := telemetry-listen.c display-tree.c

test_objs := $(patsubst %.c,%.ol,$(test_srcs))

%: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ $< -lnvme

clean:
	@rm -f $(all_targets) $(test_objs)
