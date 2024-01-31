# Makefile.am --
# Copyright 2022-24 Red Hat Inc.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
# Boston, MA 02110-1335, USA.
#
# Authors:
#   Steve Grubb <sgrubb@redhat.com>
#

CONFIG_CLEAN_FILES = *.rej *.orig

EXTRA_DIST = README-rules 10-languages.rules 20-dracut.rules \
	21-updaters.rules 22-buildroot.rules 30-patterns.rules \
	40-bad-elf.rules 41-shared-obj.rules 42-trusted-elf.rules \
	43-known-elf.rules \
	70-trusted-lang.rules 71-known-python.rules 72-shell.rules \
	73-known-perl.rules 74-known-ocaml.rules 75-known-php.rules \
	76-known-ruby.rules 77-known-lua.rules \
	90-deny-execute.rules 91-deny-lang.rules 95-allow-open.rules

rulesdir = $(datadir)/fapolicyd/sample-rules
dist_rules_DATA = $(EXTRA_DIST)

