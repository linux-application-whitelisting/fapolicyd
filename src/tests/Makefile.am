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
check_PROGRAMS = avl_test gid_proc_test uid_proc_test escape_test \
attr_sets_test elf_file_test fd_fgets_test rules_test event_test \
trustdb_format_test

AM_CPPFLAGS = -I${top_srcdir}/src/library/
AM_CFLAGS = -std=gnu11

avl_test_SOURCES = avl_test.c ${top_srcdir}/src/library/avl.c
gid_proc_test_SOURCES = gid_proc_test.c
gid_proc_test_LDADD = ${top_builddir}/src/.libs/libfapolicyd.la
uid_proc_test_SOURCES = uid_proc_test.c
uid_proc_test_LDADD = ${top_builddir}/src/.libs/libfapolicyd.la
escape_test_SOURCES = escape_test.c
escape_test_LDADD = ${top_builddir}/src/.libs/libfapolicyd.la
attr_sets_test_SOURCES = attr_sets_test.c
attr_sets_test_LDADD = ${top_builddir}/src/.libs/libfapolicyd.la
elf_file_test_SOURCES = elf_file_test.c
elf_file_test_LDADD = ${top_builddir}/src/.libs/libfapolicyd.la
fd_fgets_test_SOURCES = fd_fgets_test.c
fd_fgets_test_LDADD = ${top_builddir}/src/.libs/libfapolicyd.la
rules_test_SOURCES = rules_test.c
rules_test_LDADD = ${top_builddir}/src/.libs/libfapolicyd.la
rules_test_CPPFLAGS = -I${top_srcdir}/src/library/ -DTEST_BASE=\"${top_srcdir}\"
trustdb_format_test_SOURCES = trustdb_format_test.c
event_test_SOURCES = event_test.c
event_test_LDADD = \
	${top_builddir}/src/library/libfapolicyd_la-event.o \
	${top_builddir}/src/library/libfapolicyd_la-lru.o \
	${top_builddir}/src/library/libfapolicyd_la-subject.o \
	${top_builddir}/src/library/libfapolicyd_la-subject-attr.o \
	${top_builddir}/src/library/libfapolicyd_la-object.o \
	${top_builddir}/src/library/libfapolicyd_la-object-attr.o \
	${top_builddir}/src/library/libfapolicyd_la-attr-sets.o \
	${top_builddir}/src/library/libfapolicyd_la-avl.o
event_test_DEPENDENCIES = $(event_test_LDADD)

if WITH_RPM
check_PROGRAMS += filter_test
filter_test_SOURCES = filter_test.c
filter_test_LDADD = ${top_builddir}/src/.libs/libfapolicyd.la
filter_test_CPPFLAGS = -I${top_srcdir}/src/library/ -DTEST_BASE=\"${top_srcdir}\"
check_PROGRAMS += file_filter_test
file_filter_test_SOURCES = file_filter_test.c
file_filter_test_LDADD = ${top_builddir}/src/.libs/libfapolicyd.la
file_filter_test_CPPFLAGS = -I${top_srcdir}/src/library/ -DTEST_BASE=\"${top_srcdir}\"
endif

if WITH_DEB
check_PROGRAMS += deb_test
LIBS += -ldpkg -lmd
deb_test_CFLAGS = -std=gnu11 -fPIE -DPIE -pthread -g -W -Wall -Wshadow -Wundef -Wno-unused-result -Wno-unused-parameter -D_GNU_SOURCE -DLIBDPKG_VOLATILE_API
deb_test_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now
deb_test_LDADD = ${top_builddir}/src/.libs/libfapolicyd.la -ldpkg -lmd
deb_test_SOURCES = \
  deb_test.c \
  ${top_srcdir}/src/library/file.c \
  ${top_srcdir}/src/library/backend-manager.c \
  ${top_srcdir}/src/library/deb-backend.c
endif

TESTS = $(check_PROGRAMS)
