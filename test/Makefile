CFLAGS ?= -g -O2
override CFLAGS += -Wall -D_GNU_SOURCE -L../src/ -I .. -I../src/ -I../ccan --include "config.h"

include ../Makefile.quiet

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
else
CONFIG_CPLUSPLUS=y
endif

c_targets += test register zns

ifdef CONFIG_CPLUSPLUS
cpp_targets += cpp
else
cpp_targets += 
endif

all_targets += $(c_targets) $(cpp_targets)
all: $(all_targets)

CXXFLAGS ?= -lstdc++

%: %.cc ../src/libnvme.a
	$(QUIET_CC)$(CXX) $(CFLAGS) $(LDFLAGS) $(CXXFLAGS) -o $@ $< -lnvme $(LIBS)

%: %.c ../src/libnvme.a
	$(QUIET_CC)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lnvme $(LIBS)

clean:
	rm -f $(all_targets)
