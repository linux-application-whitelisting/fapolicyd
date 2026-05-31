#! /bin/bash

set -e

cd .. || exit 1
make dist
cd deb || exit 1
cp ../fapolicyd-*.tar.gz .

tar zxvf fapolicyd-*.tar.gz

(
	cd fapolicyd-*/ || exit 1

	# Ugly work around for INSTALL.tmp
	# Need to figure out proper fix.
	mv INSTALL INSTALL.tmp
)

tar zcvf fapolicyd-*.tar.gz fapolicyd-*/
cd fapolicyd-*/ || exit 1

debmake

cp ../rules debian/
cp ../postinst debian/
cp ../README.Debian debian/

debuild
