Summary: Application Whitelisting Daemon
Name: fapolicyd
Version: 1.0.5
Release: 1
License: GPLv3+
URL: http://people.redhat.com/sgrubb/fapolicyd
Source0: https://people.redhat.com/sgrubb/fapolicyd/%{name}-%{version}.tar.gz
BuildRequires: gcc
BuildRequires: kernel-headers
BuildRequires: autoconf automake make gcc libtool
BuildRequires: systemd-devel libgcrypt-devel rpm-devel file-devel file
BuildRequires: libcap-ng-devel libseccomp-devel lmdb-devel
BuildRequires: python3-devel
BuildRequires: uthash-devel
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

# generate rules for python
sed -i "s/%python2_path%/`readlink -f %{__python2} | sed 's/\//\\\\\//g'`/g" init/%{name}.rules.*
sed -i "s/%python3_path%/`readlink -f %{__python3} | sed 's/\//\\\\\//g'`/g" init/%{name}.rules.*
sed -i "s/%ld_so_path%/`find /usr/lib64/ -type f -name 'ld-2\.*.so' | sed 's/\//\\\\\//g'`/g" init/%{name}.rules.*

%build
%configure \
    --with-audit \
    --disable-shared

%make_build

%install
%make_install
mkdir -p %{buildroot}/%{python3_sitelib}/dnf-plugins/
install -p -m 644 dnf/%{name}-dnf-plugin.py %{buildroot}/%{python3_sitelib}/dnf-plugins/
install -p -m 644 -D init/%{name}-tmpfiles.conf %{buildroot}/%{_tmpfilesdir}/%{name}.conf
install -p -m 644 init/%{name}.rules.known-libs %{buildroot}/%{_sysconfdir}/%{name}/%{name}.rules
mkdir -p %{buildroot}/%{_localstatedir}/lib/%{name}
mkdir -p %{buildroot}/run/%{name}
mkdir -p %{buildroot}%{_sysconfdir}/%{name}/trust.d
mkdir -p %{buildroot}%{_sysconfdir}/%{name}/rules.d

#cleanup
find %{buildroot} \( -name '*.la' -o -name '*.a' \) -exec rm -f {} ';'

%check
make check

%pre
getent passwd %{name} >/dev/null || useradd -r -M -d %{_localstatedir}/lib/%{name} -s /sbin/nologin -c "Application Whitelisting Daemon" %{name}

%post
# if no pre-existing rule file
if [ ! -e %{_sysconfdir}/%{name}/%{name}.rules ] ; then
	files=`ls %{_sysconfdir}/%{name}/rules.d/ 2>/dev/null | wc -w`
	# Only if no pre-existing component rules
	if [ "$files" -eq 0 ] ; then
		## cp % {_datadir}/%{name}/10-some.rule  %{_sysconfdir}/%{name}/rules.d/
		if [ -x /usr/sbin/restorecon ] ; then
			# restore correct label
			/usr/sbin/restorecon -F %{_sysconfdir}/%{name}/rules.d/*
		fi
		fagenrules --load
	fi
fi
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
%doc README.md
%{!?_licensedir:%global license %%doc}
%license COPYING
%attr(755,root,%{name}) %dir %{_datadir}/%{name}
%attr(644,root,%{name}) %{_datadir}/%{name}/*
%attr(750,root,%{name}) %dir %{_sysconfdir}/%{name}
%attr(750,root,%{name}) %dir %{_sysconfdir}/%{name}/trust.d
%attr(750,root,%{name}) %dir %{_sysconfdir}/%{name}/rules.d
%config(noreplace) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/%{name}.conf
%config(noreplace) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/%{name}.trust
%config(noreplace) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/%{name}.rules
%attr(644,root,root) %{_unitdir}/%{name}.service
%attr(644,root,root) %{_tmpfilesdir}/%{name}.conf
%attr(755,root,root) %{_sbindir}/%{name}
%attr(755,root,root) %{_sbindir}/%{name}-cli
%attr(755,root,root) %{_sbindir}/fagenrules
%attr(644,root,root) %{_mandir}/man8/*
%attr(644,root,root) %{_mandir}/man5/*
%attr(644,root,root) %{_mandir}/man1/*
%attr(644,root,root) %{_datadir}/%{name}/*
%ghost %attr(440,%{name},%{name}) %verify(not md5 size maj min mtime) %{_localstatedir}/log/%{name}-access.log
%attr(770,root,%{name}) %dir %{_localstatedir}/lib/%{name}
%attr(770,root,%{name}) %dir /run/%{name}
%ghost %attr(660,root,%{name}) /run/%{name}/%{name}.fifo
%ghost %attr(660,%{name},%{name}) %verify(not md5 size maj min mtime) %{_localstatedir}/lib/%{name}/data.mdb
%ghost %attr(660,%{name},%{name}) %verify(not md5 size maj min mtime) %{_localstatedir}/lib/%{name}/lock.mdb
%{python3_sitelib}/dnf-plugins/%{name}-dnf-plugin.py
%{python3_sitelib}/dnf-plugins/__pycache__/%{name}-dnf-plugin.*.pyc

%changelog
* Fri Nov 12 2021 Steve Grubb <sgrubb@redhat.com> 1.0.5-1
- New release
