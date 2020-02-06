Name: libnvme
Version: 0.1
Release: 1
Summary: Linux-native nvme device management library
License: LGPLv2+
Group:  System Environment/Libraries
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-root
URL: http://github.com/linux-nvme/nvme-cli

%description
Provides library functions for accessing and managing nvme devices.

%package devel
Summary: Development files for Linux-native nvme
Group: Development/System
Requires: libnvme
Provides: libnvme.so.1

%description devel
This package provides header files to include and libraries to link with
for the Linux-native nvme.

%prep
%setup

%build
./configure --prefix=/usr --libdir=/%{_libdir} --mandir=/usr/share/man
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

make install DESTDIR=$RPM_BUILD_ROOT

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/libnvme.so.*
%doc COPYING

%files devel
%defattr(-,root,root)
%attr(-,root,root) %{_includedir}/libnvme/
%attr(0644,root,root) %{_includedir}/libnvme.h
%attr(0755,root,root) %{_libdir}/libnvme.so
%attr(0644,root,root) %{_libdir}/libnvme.a
%attr(0644,root,root) %{_libdir}/pkgconfig/*
%attr(0644,root,root) %{_mandir}/man2/*

%changelog
* Thu Dec 12 2019 Keith Busch <kbusch@kernel.org> - 0.1
- Initial version
