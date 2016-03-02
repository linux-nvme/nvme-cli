# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([nvme-cli], [0.3], [keith.busch@intel.com])
AC_CONFIG_SRCDIR([nvme.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([config])

AM_INIT_AUTOMAKE([1.11 dist-bzip2 foreign -Wall -Werror parallel-tests])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_ARG_ENABLE([debug],
			  [AS_HELP_STRING([--enable-debug], [Enable debugging @<:@default=no@:>@])],
			  [CFLAGS="$CFLAGS -g -Wall -DDEBUG"],
			  [CFLAGS="$CFLAGS -O2 -Wall"])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_LIBTOOL

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h locale.h stdlib.h string.h sys/ioctl.h sys/time.h unistd.h])

# Check for mandatory linux kernel includes.
AC_CHECK_HEADERS([uapi/linux/nvme_ioctl.h], [], [])

# Checks for optional libudev
AC_CHECK_LIB([udev], [udev_new])

AC_CONFIG_FILES([Makefile
				 nvme-cli.spec
				 nvme.control])
AC_OUTPUT
