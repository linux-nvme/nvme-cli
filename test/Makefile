CFLAGS ?= -g -O2
override CFLAGS += -Wall -D_GNU_SOURCE -L../src/ -I../src/

include ../Makefile.quiet

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

all_targets += test

all: $(all_targets)

%: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ $< -lnvme

test_srs := test.c

test_objs := $(patsubst %.c,%.ol,$(test_srcs))

clean:
	@rm -f $(all_targets) $(test_objs)
