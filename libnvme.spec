Name: libnvme
Version: 0.1
Release: 0
Summary: Linux-native nvme device management library
License: LGPLv2+
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-root
URL: http://github.com/linux-nvme/libnvme
BuildRequires: gcc

%description
Provides library functions for accessing and managing nvme devices on a Linux
system.

%package devel
Summary: Development files for Linux-native nvme
Requires: libnvme
Provides: libnvme.so.1

%description devel
This package provides header files to include and libraries to link with
for Linux-native nvme device maangement.

%prep
%setup

%build
./configure --prefix=/usr --libdir=/%{_libdir} --mandir=/usr/share/man

%make_build

%install
%make_install

%files
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/libnvme.so.*
%doc COPYING

%files devel
%defattr(-,root,root)
%attr(-,root,root) %{_includedir}/nvme/
%attr(0644,root,root) %{_includedir}/libnvme.h
%attr(0755,root,root) %{_libdir}/libnvme.so
%attr(0644,root,root) %{_libdir}/libnvme.a
%attr(0644,root,root) %{_libdir}/pkgconfig/*
%attr(0644,root,root) %{_mandir}/man2/*

%changelog
* Thu Dec 12 2019 Keith Busch <kbusch@kernel.org> - 0.1
- Initial version
