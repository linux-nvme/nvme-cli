NAME=libnvme
SPECFILE=$(NAME).spec
VERSION=$(shell awk '/Version:/ { print $$2 }' $(SPECFILE))

prefix ?= /usr
includedir ?= $(prefix)/include
libdir ?= $(prefix)/lib

CFLAGS ?= -g -fomit-frame-pointer -O2 -I/usr/include -Invme/
override CFLAGS += -Wall -fPIC
SO_CFLAGS=-shared $(CFLAGS)
L_CFLAGS=$(CFLAGS)
LINK_FLAGS= -L /usr/lib64 -lsystemd
LINK_FLAGS+=$(LDFLAGS)
ENABLE_SHARED ?= 1
SED ?= sed
INSTALL ?= install

soname=$(NAME).so.1
minor=0
micro=1
libname=$(soname).$(minor).$(micro)
all_targets += $(NAME).a

SED_PROCESS = \
	$(SED) -e "s%@prefix@%$(prefix)%g" \
               -e "s%@libdir@%$(libdir)%g" \
               -e "s%@includedir@%$(includedir)%g" \
               -e "s%@NAME@%$(NAME)%g" \
               -e "s%@VERSION@%$(VERSION)%g" \
               $< >$@

%.pc: %.pc.in Makefile
	$(SED_PROCESS)

ifeq ($(ENABLE_SHARED),1)
all_targets += $(libname)
endif

ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	QUIET_CC	= @echo '    '   CC $@;
	QUIET_LINK	= @echo '  '   LINK $@;
	QUIET_AR	= @echo '    '   AR $@;
	QUIET_RANLIB	= @echo ''   RANLIB $@;
endif
endif

all: $(all_targets)

libnvme_srcs := nvme/ioctl.c nvme/filters.c nvme/fabrics.c nvme/util.c nvme/tree.c
libnvme_objs := $(patsubst %.c,%.ol,$(libnvme_srcs))
libnvme_sobjs := $(patsubst %.c,%.os,$(libnvme_srcs))

$(libnvme_objs) $(libnvme_sobjs): libnvme.h nvme/types.h nvme/ioctl.h nvme/filters.h nvme/tree.h nvme/util.h nvme/cmd.h

%.os: %.c
	$(QUIET_CC)$(CC) $(SO_CFLAGS) -c -o $@ $<

%.ol: %.c
	$(QUIET_CC)$(CC) $(L_CFLAGS) -c -o $@ $<

AR ?= ar
RANLIB ?= ranlib
libnvme.a: $(libnvme_objs)
	@rm -f libnvme.a
	$(QUIET_AR)$(AR) r libnvme.a $^
	$(QUIET_RANLIB)$(RANLIB) libnvme.a

$(libname): $(libnvme_sobjs) libnvme.map
	$(QUIET_CC)$(CC) $(SO_CFLAGS) -Wl,--version-script=libnvme.map -Wl,-soname=$(soname) -o $@ $(libnvme_sobjs) $(LINK_FLAGS)

install: $(all_targets) $(NAME).pc
	$(INSTALL) -D -m 644 nvme/types.h $(includedir)/nvme/types.h
	$(INSTALL) -D -m 644 nvme/ioctl.h $(includedir)/nvme/ioctl.h
	$(INSTALL) -D -m 644 nvme/fabrics.h $(includedir)/nvme/fabrics.h
	$(INSTALL) -D -m 644 nvme/filters.h $(includedir)/nvme/filters.h
	$(INSTALL) -D -m 644 libnvme.h $(includedir)/libnvme.h
	$(INSTALL) -D -m 644 libnvme.a $(libdir)/libnvme.a
	$(INSTALL) -D -m 644 $(NAME).pc $(DESTDIR)$(libdir)/pkgconfig/$(NAME).pc
ifeq ($(ENABLE_SHARED),1)
	$(INSTALL) -D -m 755 $(libname) $(libdir)/$(libname)
	ln -sf $(libname) $(libdir)/$(soname)
	ln -sf $(libname) $(libdir)/libnvme.so
endif

$(libnvme_objs): libnvme.h

clean:
	rm -f $(all_targets) $(libnvme_objs) $(libnvme_sobjs) $(soname).new $(NAME).pc
	rm -f *.so* *.a *.o
