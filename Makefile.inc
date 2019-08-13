CFLAGS ?= -O2 -g -Wall -Werror
override CFLAGS += -std=gnu99
override CPPFLAGS += -D_GNU_SOURCE -D__CHECK_ENDIAN__

INSTALL ?= install
DESTDIR ?=
PREFIX ?= /usr/local
SYSCONFDIR = /etc
SBINDIR = $(PREFIX)/sbin
SYSTEMDDIR ?= $(PREFIX)/lib/systemd
UDEVDIR ?= $(PREFIX)/lib/udev
DRACUTDIR ?= $(PREFIX)/lib/dracut
LIB_DEPENDS =

ifndef LIB_DIR
	ifeq ($(shell test -d /lib64 && echo 1),1)
		LIB_DIR=$(PREFIX)/lib64
	else
		LIB_DIR=$(PREFIX)/lib
	endif
endif


PKGCONF_DIR ?= $(LIB_DIR)/pkgconfig
INCLUDE_DIR ?= $(PREFIX)/include

RPMBUILD = rpmbuild
TAR = tar
RM = rm -f
