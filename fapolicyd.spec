Summary: Application Whitelisting Daemon
Name: fapolicyd
Version: 0.8.6
Release: 1
License: GPLv3+
URL: http://people.redhat.com/sgrubb/fapolicyd
Source0: https://people.redhat.com/sgrubb/fapolicyd/%{name}-%{version}.tar.gz
BuildRequires: kernel-headers
BuildRequires: systemd-devel libgcrypt-devel rpm-devel file-devel
BuildRequires: libcap-ng-devel libseccomp-devel lmdb-devel
Requires(pre): shadow-utils
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units

%description
Fapolicyd (File Access Policy Daemon) implements application whitelisting
to decide file access rights. Applications that are known via a reputation
source are allowed access while unknown applications are not. The daemon
makes use of the kernel's fanotify interface to determine file access rights.

%prep
%setup -q

%build
%configure --with-audit 
make CFLAGS="%{optflags}" %{?_smp_mflags}

%install
make DESTDIR="%{buildroot}" INSTALL='install -p' install
mkdir -p %{buildroot}/%{_localstatedir}/lib/%{name}

%pre
getent passwd fapolicyd >/dev/null || useradd -r -M -s /sbin/nologin -c "Application Whitelisting Daemon" fapolicyd

%post
%systemd_post fapolicyd.service

%preun
%systemd_preun fapolicyd.service

%postun
%systemd_postun_with_restart fapolicyd.service

%files
%doc README
%{!?_licensedir:%global license %%doc}
%license COPYING
%attr(750,root,fapolicyd) %dir %{_sysconfdir}/%{name}
%config(noreplace) %attr(644,root,fapolicyd) %{_sysconfdir}/%{name}/fapolicyd.rules
%config(noreplace) %attr(644,root,fapolicyd) %{_sysconfdir}/%{name}/fapolicyd.mounts
%attr(644,root,root) %{_unitdir}/fapolicyd.service
%attr(755,root,root) %{_sbindir}/fapolicyd
%attr(644,root,root) %{_mandir}/man8/*
%attr(644,root,root) %{_mandir}/man5/*
%ghost %{_localstatedir}/log/fapolicyd-access.log
%attr(770,root,fapolicyd) %dir %{_localstatedir}/lib/%{name}

%changelog
* Fri Feb 16 2018 Steve Grubb <sgrubb@redhat.com> 0.8.6-1
- New release

