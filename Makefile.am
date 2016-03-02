AM_CPPFLAGS = -D_GNU_SOURCE -I$(srcdir)/src/argconfig -I$(srcdir)
ACLOCAL_AMFLAGS = -I config

sbin_PROGRAMS = nvme

noinst_LTLIBRARIES = \
		libargconfig.la \
		libioctl.la \
		libprint.la

libargconfig_la_SOURCES = \
		src/argconfig.c \
		src/suffix.c

libioctl_la_SOURCES = \
		nvme-ioctl.c

libprint_la_SOURCES = \
		nvme-print.c

nvme_SOURCES = \
		nvme.c

nvme_LDADD = libargconfig.la libprint.la libioctl.la

man1_MANS = \
		Documentation/nvme.1 \
		Documentation/nvme-admin-passthru.1 \
		Documentation/nvme-attach-ns.1 \
		Documentation/nvme-compare.1 \
		Documentation/nvme-create-ns.1 \
		Documentation/nvme-delete-ns.1 \
		Documentation/nvme-detach-ns.1 \
		Documentation/nvme-dsm.1 \
		Documentation/nvme-error-log.1 \
		Documentation/nvme-flush.1 \
		Documentation/nvme-format.1 \
		Documentation/nvme-fw-activate.1 \
		Documentation/nvme-fw-download.1 \
		Documentation/nvme-fw-log.1 \
		Documentation/nvme-get-feature.1 \
		Documentation/nvme-get-log.1 \
		Documentation/nvme-get-ns-id.1 \
		Documentation/nvme-help.1 \
		Documentation/nvme-id-ctrl.1 \
		Documentation/nvme-id-ns.1 \
		Documentation/nvme-io-passthru.1 \
		Documentation/nvme-list.1 \
		Documentation/nvme-list-ctrl.1 \
		Documentation/nvme-list-ns.1 \
		Documentation/nvme-read.1 \
		Documentation/nvme-resv-acquire.1 \
		Documentation/nvme-resv-register.1 \
		Documentation/nvme-resv-release.1 \
		Documentation/nvme-resv-report.1 \
		Documentation/nvme-security-recv.1 \
		Documentation/nvme-security-send.1 \
		Documentation/nvme-set-feature.1 \
		Documentation/nvme-show-regs.1 \
		Documentation/nvme-smart-log.1 \
		Documentation/nvme-write.1 \
		Documentation/nvme-write-uncor.1 \
		Documentation/nvme-write-zeroes.1

EXTRA_DIST = $(man1_MANS) \
		nvme-cli.spec \
		nvme-print.h \
		nvme-ioctl.h \
		nvme-headers.h \
		src/suffix.h \
		src/argconfig.h \
		linux/nvme_ioctl.h \
		linux/nvme.h

# Put non automake convenience targets below here:

rpm: dist
	rpmbuild -ta nvme-cli-*.tar.bz2

# debian packaging stuff:
# TODO: unbreak this and adjust for autotools

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

