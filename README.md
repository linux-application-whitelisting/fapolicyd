# fapolicyd
File Access Policy Daemon

This is an application whitelisting daemon for Linux.

# Dependencies
libgcrypt-devel
rpm-devel
file-devel

# Building
To build from the repo after cloning:

cd fapolicyd
./autogen.sh
./configure
make dist

Then use the new tarball with the spec file and create your own rpm.
Sample rules are included.

One thing to note, as of the 0.8 release you can deadlock your system
if you use rpm -i/U, yum update, or dnf update.

Its highly recommended to run in permissive mode while you are testing the
daemon's policy. To see access decision use the debug option.
