# Copyright 2020 Red Hat Inc.
# All Rights Reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Authors:
#   Steve Grubb <sgrubb@redhat.com>
#

CONFIG_CLEAN_FILES = *.orig *.cur
EXTRA_DIST = filter.conf
check_PROGRAMS = avl_test gid_proc_test filter_test

AM_CPPFLAGS = -I${top_srcdir}/src/library/

avl_test_SOURCES = avl_test.c ${top_srcdir}/src/library/avl.c
gid_proc_test_SOURCES = gid_proc_test.c
gid_proc_test_LDADD = ${top_builddir}/src/.libs/libfapolicyd.la

filter_test_SOURCES = filter_test.c
filter_test_LDADD = ${top_builddir}/src/.libs/libfapolicyd.la
filter_test_CPPFLAGS = -I${top_srcdir}/src/library/

TESTS_ENVIRONMENT = FILTER_CONF=$(abs_srcdir)/filter.conf

if WITH_DEB
check_PROGRAMS += deb_test
deb_test_CFLAGS = -fPIE -DPIE -pthread -g -W -Wall -Wshadow -Wundef -Wno-unused-result -Wno-unused-parameter -D_GNU_SOURCE -DLIBDPKG_VOLATILE_API
deb_test_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now,-ldpkg -lmd

deb_test_LDADD = ${top_builddir}/src/.libs/libfapolicyd.la
deb_test_SOURCES = \
  deb_test.c \
  ${top_srcdir}/src/library/file.c \
  ${top_srcdir}/src/library/backend-manager.c \
  ${top_srcdir}/src/library/deb-backend.c
endif

TESTS = $(check_PROGRAMS)
