CFLAGS += -std=gnu99 -O2 -g -Wall -Werror
CPPFLAGS += -I $(SRC) -D_GNU_SOURCE
NVME = nvme
INSTALL ?= install
SRC = ./src
DESTDIR =
PREFIX ?= /usr/local
SBINDIR = $(PREFIX)/sbin
LIBUDEV := $(shell ld -o /dev/null -ludev >/dev/null 2>&1; echo $$?)
LIB_DEPENDS =

RPMBUILD = rpmbuild
TAR = tar
RM = rm -f

ifeq ($(LIBUDEV),0)
	LDFLAGS += -ludev
	CFLAGS  += -DLIBUDEV_EXISTS
	LIB_DEPENDS += udev
endif

default: $(NVME)

NVME-VERSION-FILE: FORCE
	@$(SHELL_PATH) ./NVME-VERSION-GEN
-include NVME-VERSION-FILE
override CFLAGS += -DNVME_VERSION='"$(NVME_VERSION)"'

nvme: nvme.c ./linux/nvme.h argconfig.o suffix.o common.o NVME-VERSION-FILE
	$(CC) $(CPPFLAGS) $(CFLAGS) nvme.c $(LDFLAGS) -o $(NVME) argconfig.o suffix.o common.o

argconfig.o: $(SRC)/argconfig.c $(SRC)/argconfig.h $(SRC)/suffix.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $(SRC)/argconfig.c

suffix.o: $(SRC)/suffix.c $(SRC)/suffix.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $(SRC)/suffix.c

common.o: common.c

doc: $(NVME)
	$(MAKE) -C Documentation

all: doc

clean:
	$(RM) $(NVME) *.o *~ a.out NVME-VERSION-FILE *.tar* nvme.spec version control nvme-*.deb
	$(RM) -r nvme-*
	$(MAKE) -C Documentation clean

clobber: clean
	$(MAKE) -C Documentation clobber

install-man:
	$(MAKE) -C Documentation install-no-build

install-bin: default
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 755 nvme $(DESTDIR)$(SBINDIR)

install: install-bin install-man

nvme.spec: nvme.spec.in NVME-VERSION-FILE
	sed -e 's/@@VERSION@@/$(NVME_VERSION)/g' < $< > $@+
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

deb: dist-orig
	# Create a throw-away changelog, which dpkg-buildpackage uses to
	# determine the package version.
	printf '%s\n\n  * Auto-release.\n\n %s\n' \
          "nvme-cli ($(NVME_VERSION)-1~`lsb_release -sc`) `lsb_release -sc`; urgency=low" \
          "-- Keith Busch <keith.busch@intel.com>  `git log -1 --format=%cD`" \
	  > debian/changelog
	dpkg-buildpackage -uc -us -sa  # from dpkg-dev package

deb-light: $(NVME) pkg nvme.control.in
	dpkg-deb --build nvme-$(NVME_VERSION)

rpm: dist
	$(RPMBUILD) -ta nvme-$(NVME_VERSION).tar.gz

.PHONY: default doc all clean clobber install-man install-bin install
.PHONY: dist pkg dist-orig deb deb-light rpm FORCE
