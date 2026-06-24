BUILDING
========

Building fapolicyd is reasonably straightforward on Fedora and RedHat-based Linux distributions.
This document will guide in installing the build-time dependencies, configure and compile the code,
and finally build the RPMs for distribution on compatible non-production systems.

BUILD-TIME DEPENDENCIES (fedora and RHEL8)
------------------------------------------

* gcc
* autoconf
* automake
* libtool
* make
* libudev-devel
* kernel-headers
* systemd-devel
* libgcrypt-devel ( <= fapolicyd-1.1.3)
* openssl         ( >= fapolicyd-1.1.4)
* rpm-devel (optional)
* file
* file-devel
* libcap-ng-devel
* libseccomp-devel
* lmdb-devel
* uthash-devel
* python3-devel
* kernel >= 4.20 (Must support FANOTIFY_OPEN_EXEC_PERM. See [1] below.)

RHEL8: ENABLE CODEREADY AND INSTALL EPEL REPOS
----------------------------------------------

```bash
sudo subscription-manager repos --enable codeready-builder-for-rhel-8-$(arch)-rpms
sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
```

INSTALL BUILD DEPENDENCIES (fedora and RHEL8)
---------------------------------------------

```bash
sudo dnf install -y gcc autoconf automake libtool make libudev-devel kernel-headers systemd-devel libgcrypt-devel rpm-devel file file-devel libcap-ng-devel libseccomp-devel lmdb-devel uthash-devel python3-devel
```

CONFIGURING AND COMPILING
-------------------------

To build from the repo after cloning and installing dependencies:

```bash
cd fapolicyd
./autogen.sh
./configure --with-audit --disable-shared
make
make dist
```

This will create a tarball. You can use the new tarball with the spec file
and create your own rpm. If you want to experiment without installing, just
run make with no arguments. It should run fine from where it was built as
long as you put the configuration files in the configured sysconfdir
(default: /usr/local/etc/fapolicyd when no --prefix is given).
Note that --prefix=/usr alone sets sysconfdir to /usr/etc, not /etc.
To get standard FHS paths, pass --sysconfdir=/etc --localstatedir=/var
--runstatedir=/run explicitly (the RPM %configure macro does this
automatically).

Note that the shipped policy expects that auditing is enabled. This is done
by passing --with-audit to ./configure.

The use of rpm as a trust source is now optional. You can run ./configure
passing --without-rpm and it will not link against librpm. In this mode, it
purely uses the file database in fapolicyd.trust. If rpm is used, then the
file trust database can be used in addition to rpmdb.

BUILDING THE RPMS
-----------------

:exclamation: These unofficial RPMs should only be used for testing and
experimentation purposes and not for production systems. :exclamation:

To build the RPMs, first install the RPM development tools:

```bash
sudo dnf install -y rpmdevtools
```

Then in the root of the repository where fapolicyd was built, use `rpmbuild`
to build the RPMs:

```bash
rpmbuild -ta fapolicyd-*.tar.gz
```

By default, the RPMs will appear in `~/rpmbuild/RPMS/$(arch)`.

NOT BUILDING RPMS
-----------------
If you chose to do it yourself, you need to do a couple prep steps:

```
1) sed -i "s/%python2_path%/`readlink -f /bin/python2 | sed 's/\//\\\\\//g'`/g" rules.d/*.rules
2) sed -i "s/%python3_path%/`readlink -f /bin/python3 | sed 's/\//\\\\\//g'`/g" rules.d/*.rules
3) interpret=`readelf -e /usr/bin/bash \
                | grep Requesting \
                | sed 's/.$//' \
                | rev | cut -d" " -f1 \
                | rev`
4) sed -i "s|%ld_so_path%|`realpath $interpret`|g" rules.d/*.rules
```
This corrects the placeholders to match your current system. Then follow the
rules listed above for compiling except run make install instead of make dist.

INSTALLING WITHOUT RPMS
-----------------------
`make install` handles installing all binaries, configuration files, systemd
units, tmpfiles configuration, and the bash completion file. All paths
respect the configured --prefix (default: /usr/local).

After installing, create the fapolicyd user and set up the required
directories:

```bash
prefix=/usr/local  # adjust to match your --prefix

useradd -r -M -d ${prefix}/var/lib/fapolicyd -s /sbin/nologin -c "Application Whitelisting Daemon" fapolicyd

# Create directories with proper ownership
mkdir -p ${prefix}/etc/fapolicyd/{rules.d,trust.d}
chown root:fapolicyd ${prefix}/etc/fapolicyd/
chown root:fapolicyd ${prefix}/etc/fapolicyd/rules.d/
chown root:fapolicyd ${prefix}/etc/fapolicyd/trust.d/

# Copy sample rules
cp rules.d/*.rules ${prefix}/etc/fapolicyd/rules.d/

# Reload systemd and enable the tmpfiles configuration
systemctl daemon-reload
systemd-tmpfiles --create
```

The trust database directory is created automatically by the daemon on
first startup.

