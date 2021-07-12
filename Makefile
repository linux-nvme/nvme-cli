CFLAGS ?= -O2 -g -Wall -Werror
override CFLAGS += -std=gnu99
override CPPFLAGS += -D_GNU_SOURCE -D__CHECK_ENDIAN__
LIBUUID = $(shell $(LD) -o /dev/null -luuid >/dev/null 2>&1; echo $$?)
LIBHUGETLBFS = $(shell $(LD) -o /dev/null -lhugetlbfs >/dev/null 2>&1; echo $$?)
HAVE_SYSTEMD = $(shell pkg-config --exists libsystemd  --atleast-version=242; echo $$?)
LIBJSONC = $(shell $(LD) -o /dev/null -ljson-c >/dev/null 2>&1; echo $$?)
HAVE_LIBUDEV = $(shell pkg-config --exists libudev; echo $$?)
NVME = nvme
INSTALL ?= install
DESTDIR =
DESTDIROLD = /usr/local/sbin
PREFIX ?= /usr
SYSCONFDIR = /etc
SBINDIR = $(PREFIX)/sbin
LIBDIR ?= $(PREFIX)/lib
SYSTEMDDIR ?= $(LIBDIR)/systemd
UDEVDIR ?= $(SYSCONFDIR)/udev
UDEVRULESDIR ?= $(UDEVDIR)/rules.d
DRACUTDIR ?= $(LIBDIR)/dracut
LIB_DEPENDS =

ifeq ($(LIBUUID),0)
	override LDFLAGS += -luuid
	override CFLAGS += -DLIBUUID
	override LIB_DEPENDS += uuid
endif

ifeq ($(LIBHUGETLBFS),0)
	override LDFLAGS += -lhugetlbfs
	override CFLAGS += -DLIBHUGETLBFS
	override LIB_DEPENDS += hugetlbfs
endif

INC=-I. -Iutil

ifeq ($(HAVE_LIBUDEV),0)
	override LDFLAGS += -ludev
	override CFLAGS += -DHAVE_LIBUDEV
endif

ifeq ($(HAVE_SYSTEMD),0)
	override LDFLAGS += -lsystemd
	override CFLAGS += -DHAVE_SYSTEMD
endif

ifeq ($(LIBJSONC), 0)
	override LDFLAGS += -ljson-c
	override CFLAGS += -DLIBJSONC
endif

RPMBUILD = rpmbuild
TAR = tar
RM = rm -f

AUTHOR=Keith Busch <kbusch@kernel.org>

ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	QUIET_CC	= @echo '   ' CC $@;
endif
endif

default: $(NVME)

NVME-VERSION-FILE: FORCE
	@$(SHELL_PATH) ./NVME-VERSION-GEN
-include NVME-VERSION-FILE
override CFLAGS += -DNVME_VERSION='"$(NVME_VERSION)"'

NVME_DPKG_VERSION=1~`lsb_release -sc`

OBJS := nvme-print.o nvme-ioctl.o nvme-rpmb.o \
	nvme-lightnvm.o fabrics.o nvme-models.o plugin.o \
	nvme-status.o nvme-filters.o nvme-topology.o

ifeq ($(HAVE_LIBUDEV),0)
	OBJS += monitor.o conn-db.o
endif

UTIL_OBJS := util/argconfig.o util/suffix.o util/parser.o \
	util/cleanup.o util/log.o
ifneq ($(LIBJSONC), 0)
override UTIL_OBJS += util/json.o
endif
EVENT_LIB := event/libminivent.a

PLUGIN_OBJS :=					\
	plugins/intel/intel-nvme.o		\
	plugins/amzn/amzn-nvme.o		\
	plugins/lnvm/lnvm-nvme.o		\
	plugins/memblaze/memblaze-nvme.o	\
	plugins/wdc/wdc-nvme.o			\
	plugins/wdc/wdc-utils.o			\
	plugins/huawei/huawei-nvme.o		\
	plugins/netapp/netapp-nvme.o		\
	plugins/toshiba/toshiba-nvme.o		\
	plugins/micron/micron-nvme.o		\
	plugins/seagate/seagate-nvme.o 		\
	plugins/virtium/virtium-nvme.o		\
	plugins/shannon/shannon-nvme.o		\
	plugins/dera/dera-nvme.o 		\
	plugins/scaleflux/sfx-nvme.o		\
	plugins/transcend/transcend-nvme.o	\
	plugins/zns/zns.o	        		\
	plugins/nvidia/nvidia-nvme.o        \
	plugins/ymtc/ymtc-nvme.o

nvme: nvme.c nvme.h $(OBJS) $(PLUGIN_OBJS) $(UTIL_OBJS) $(EVENT_LIB) NVME-VERSION-FILE
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) $< -o $(NVME) \
		$(OBJS) $(PLUGIN_OBJS) $(UTIL_OBJS) $(EVENT_LIB) $(LDFLAGS)

verify-no-dep: nvme.c nvme.h $(OBJS) $(UTIL_OBJS) NVME-VERSION-FILE
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) $< -o $@ $(OBJS) $(UTIL_OBJS) $(LDFLAGS)

nvme.o: nvme.c nvme.h nvme-print.h nvme-ioctl.h util/argconfig.h util/suffix.h nvme-lightnvm.h fabrics.h
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) -c $<

%.o: %.c %.h nvme.h linux/nvme.h linux/nvme_ioctl.h nvme-ioctl.h nvme-print.h util/argconfig.h
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) -o $@ -c $<

%.o: %.c nvme.h linux/nvme.h linux/nvme_ioctl.h nvme-ioctl.h nvme-print.h util/argconfig.h
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) -o $@ -c $<

$(EVENT_LIB):	event/*.[hc]
	$(MAKE) -C event INCLUDE="$(patsubst -I%,-I../%,$(INC))" DISABLE_TV=yes static

event-test:
	$(MAKE) -C event INCLUDE="$(patsubst -I%,-I../%,$(INC))" \
		LOG_O=../../util/log.o CLEANUP_O=../../util/cleanup.o \
		DISABLE_TV=yes run-test

doc: $(NVME)
	$(MAKE) -C Documentation

test:
	$(MAKE) -C tests/ run

all: doc

clean:
	$(RM) $(NVME) $(OBJS) $(PLUGIN_OBJS) $(UTIL_OBJS) *~ a.out NVME-VERSION-FILE *.tar* nvme.spec version control nvme-*.deb 70-nvmf-autoconnect.conf
	$(MAKE) -C Documentation clean
	$(MAKE) -C event clean
	$(RM) tests/*.pyc
	$(RM) verify-no-dep

clobber: clean
	$(MAKE) -C Documentation clobber

install-man:
	$(MAKE) -C Documentation install-no-build

install-bin: default
	$(RM) $(DESTDIROLD)/nvme
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 755 nvme $(DESTDIR)$(SBINDIR)

install-bash-completion:
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/bash-completion/completions
	$(INSTALL) -m 644 -T ./completions/bash-nvme-completion.sh $(DESTDIR)$(PREFIX)/share/bash-completion/completions/nvme

install-systemd:
	$(INSTALL) -d $(DESTDIR)$(SYSTEMDDIR)/system
	$(INSTALL) -m 644 ./nvmf-autoconnect/systemd/* $(DESTDIR)$(SYSTEMDDIR)/system

install-udev:
	$(INSTALL) -d $(DESTDIR)$(UDEVRULESDIR)
	$(INSTALL) -m 644 ./nvmf-autoconnect/udev-rules/* $(DESTDIR)$(UDEVRULESDIR)

install-dracut: 70-nvmf-autoconnect.conf
	$(INSTALL) -d $(DESTDIR)$(DRACUTDIR)/dracut.conf.d
	$(INSTALL) -m 644 $< $(DESTDIR)$(DRACUTDIR)/dracut.conf.d

install-zsh-completion:
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/share/zsh/site-functions
	$(INSTALL) -m 644 -T ./completions/_nvme $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_nvme

install-hostparams: install-etc
	if [ ! -s $(DESTDIR)$(SYSCONFDIR)/nvme/hostnqn ]; then \
		echo `$(DESTDIR)$(SBINDIR)/nvme gen-hostnqn` > $(DESTDIR)$(SYSCONFDIR)/nvme/hostnqn; \
	fi
	if [ ! -s $(DESTDIR)$(SYSCONFDIR)/nvme/hostid ]; then \
		uuidgen > $(DESTDIR)$(SYSCONFDIR)/nvme/hostid; \
	fi

install-etc:
	$(INSTALL) -d $(DESTDIR)$(SYSCONFDIR)/nvme
	touch $(DESTDIR)$(SYSCONFDIR)/nvme/hostnqn
	touch $(DESTDIR)$(SYSCONFDIR)/nvme/hostid
	if [ ! -f $(DESTDIR)$(SYSCONFDIR)/nvme/discovery.conf ]; then \
		$(INSTALL) -m 644 -T ./etc/discovery.conf.in $(DESTDIR)$(SYSCONFDIR)/nvme/discovery.conf; \
	fi

install-spec: install-bin install-man install-bash-completion install-zsh-completion install-etc install-systemd install-udev install-dracut
install: install-spec install-hostparams

nvme.spec: nvme.spec.in NVME-VERSION-FILE
	sed -e 's/@@VERSION@@/$(NVME_VERSION)/g' < $< > $@+
	mv $@+ $@

70-nvmf-autoconnect.conf: nvmf-autoconnect/dracut-conf/70-nvmf-autoconnect.conf.in
	sed -e 's#@@UDEVRULESDIR@@#$(UDEVRULESDIR)#g' < $< > $@+
	mv $@+ $@

dist: nvme.spec
	git archive --format=tar --prefix=nvme-$(NVME_VERSION)/ HEAD > nvme-$(NVME_VERSION).tar
	@echo $(NVME_VERSION) > version
	$(TAR) rf  nvme-$(NVME_VERSION).tar nvme.spec version
	gzip -f -9 nvme-$(NVME_VERSION).tar

control: nvme.control.in NVME-VERSION-FILE
	sed -e 's/@@VERSION@@/$(NVME_VERSION)/g' < $< > $@+
	mv $@+ $@
	sed -e 's/@@DEPENDS@@/$(LIB_DEPENDS)/g' < $@ > $@+
	mv $@+ $@

pkg: control nvme.control.in
	mkdir -p nvme-$(NVME_VERSION)$(SBINDIR)
	mkdir -p nvme-$(NVME_VERSION)$(PREFIX)/share/man/man1
	mkdir -p nvme-$(NVME_VERSION)/DEBIAN/
	cp Documentation/*.1 nvme-$(NVME_VERSION)$(PREFIX)/share/man/man1
	cp nvme nvme-$(NVME_VERSION)$(SBINDIR)
	cp control nvme-$(NVME_VERSION)/DEBIAN/

# Make a reproducible tar.gz in the super-directory. Uses
# git-restore-mtime if available to adjust timestamps.
../nvme-cli_$(NVME_VERSION).orig.tar.gz:
	find . -type f -perm -u+rwx -exec chmod 0755 '{}' +
	find . -type f -perm -u+rw '!' -perm -u+x -exec chmod 0644 '{}' +
	if which git-restore-mtime >/dev/null; then git-restore-mtime; fi
	git ls-files | tar cf ../nvme-cli_$(NVME_VERSION).orig.tar \
	  --owner=root --group=root \
	  --transform='s#^#nvme-cli-$(NVME_VERSION)/#' --files-from -
	touch -d "`git log --format=%ci -1`" ../nvme-cli_$(NVME_VERSION).orig.tar
	gzip -f -9 ../nvme-cli_$(NVME_VERSION).orig.tar

dist-orig: ../nvme-cli_$(NVME_VERSION).orig.tar.gz

# Create a throw-away changelog, which dpkg-buildpackage uses to
# determine the package version.
deb-changelog:
	printf '%s\n\n  * Auto-release.\n\n %s\n' \
          "nvme-cli ($(NVME_VERSION)-$(NVME_DPKG_VERSION)) `lsb_release -sc`; urgency=low" \
          "-- $(AUTHOR)  `git log -1 --format=%cD`" \
	  > debian/changelog

deb: deb-changelog dist-orig
	dpkg-buildpackage -uc -us -sa

# After this target is build you need to do a debsign and dput on the
# ../<name>.changes file to upload onto the relevant PPA. For example:
#
#  > make AUTHOR='First Last <first.last@company.com>' \
#        NVME_DPKG_VERSION='0ubuntu1' deb-ppa
#  > debsign <name>.changes
#  > dput ppa:<lid>/ppa <name>.changes
#
# where lid is your launchpad.net ID.
deb-ppa: deb-changelog dist-orig
	debuild -uc -us -S

deb-light: $(NVME) pkg nvme.control.in
	dpkg-deb --build nvme-$(NVME_VERSION)

rpm: dist
	$(RPMBUILD) --define '_prefix $(DESTDIR)$(PREFIX)' \
	--define '_libdir $(DESTDIR)${LIBDIR}' \
	--define '_sysconfdir $(DESTDIR)$(SYSCONFDIR)' \
	-ta nvme-$(NVME_VERSION).tar.gz

.PHONY: default doc all clean clobber install-man install-bin install
.PHONY: dist pkg dist-orig deb deb-light rpm FORCE test
