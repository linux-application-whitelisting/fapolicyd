# Copyright 2026 Red Hat Inc.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2, or
# (at your option) any later version.

if WITH_STRESS
noinst_PROGRAMS = fapolicyd-stress
endif

CLEANFILES = fapolicyd-stress

AM_CPPFLAGS = -I${top_builddir} \
	-I${top_srcdir}/src/library \
	-DSTRESS_SCRIPT_DIR=\"$(abs_srcdir)/scripts\"
AM_CFLAGS = -std=gnu11 -fPIE -DPIE -g -W -Wall -Wshadow -Wundef \
	-Wno-unused-result -Wno-unused-parameter -D_GNU_SOURCE

fapolicyd_stress_SOURCES = fapolicyd-stress.c
fapolicyd_stress_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now

EXTRA_DIST = README.md \
	scripts/with-shebang.sh \
	scripts/without-shebang
