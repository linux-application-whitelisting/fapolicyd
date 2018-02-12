Summary: Application Whitelisting Daemon
Name: fapolicyd
Version: 0.8.5
Release: 1
License: GPLv2+
Group: System Environment/Daemons
URL: https://github.com/stevegrubb/fapolicyd
Source0: https://github.com/stevegrubb/fapolicyd/archive/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: kernel-headers
BuildRequires: systemd-devel libgcrypt-devel rpm-devel file-devel
BuildRequires: libcap-ng-devel libseccomp-devel
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units

%description
Fapolicyd (File Access Policy Daemon) implements application whitelisting to decide file access rights. Applications that are known via a reputation source is allowed access while unknown applications are not. The daemon makes use of the kernel's fanotify interface to determine file access rights.

%prep
%setup -q

%build
%configure --sbindir=/sbin --with-audit 
make CFLAGS="%{optflags}" %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR="${RPM_BUILD_ROOT}" INSTALL='install -p' install

%pre
getent passwd fapolicyd >/dev/null || useradd -r -M -s /sbin/nologin fapolicyd

%post
%systemd_post fapolicyd.service

%preun
%systemd_preun fapolicyd.service

%postun
%systemd_postun_with_restart fapolicyd.service

%files
%defattr(-,root,root,-)
%doc README COPYING
%attr(750,root,root) %dir /etc/fapolicyd
%config(noreplace) %attr(644,root,root) /etc/fapolicyd/fapolicyd.rules
%config(noreplace) %attr(644,root,root) /etc/fapolicyd/fapolicyd.mounts
%attr(644,root,root) %{_unitdir}/fapolicyd.service
%attr(755,root,root) /sbin/fapolicyd
%attr(644,root,root) %{_mandir}/man8/fapolicyd.8.gz
%attr(644,root,root) %{_mandir}/man5/fapolicyd.rules.5.gz
%ghost /var/log/fapolicyd-access.log

%changelog
* Wed Feb 07 2018 Steve Grubb <sgrubb@redhat.com> 0.8.5-1
- New release

