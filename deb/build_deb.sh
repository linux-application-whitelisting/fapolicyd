#! /bin/bash

cd ..
make dist
cd deb
cp ../fapolicyd-*.tar.gz .

tar zxvf fapolicyd-*.tar.gz
cd fapolicyd-*/

# Ugly work around for INSTALL.tmp
# Need to figure out proper fix.
mv INSTALL INSTALL.tmp
cd ..
tar zcvf fapolicyd-*.tar.gz fapolicyd-*/
cd fapolicyd-*/

debmake

cp ../rules debian/
cp ../postinst debian/
cp ../README.Debian debian/

debuild

cd ..
