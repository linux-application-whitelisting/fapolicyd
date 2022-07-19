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
long as you put the configuration files in /etc/fapolicyd (fapolicyd.rules,
fapolicyd.trust, fapolicyd.conf).

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
