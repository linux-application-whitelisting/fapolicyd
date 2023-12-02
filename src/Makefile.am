SUBDIRS = tests
CONFIG_CLEAN_FILES = *.loT *.rej *.orig

AM_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_srcdir}/src/library

sbin_PROGRAMS = fapolicyd fapolicyd-cli
lib_LTLIBRARIES= libfapolicyd.la

fapolicyd_CFLAGS = -fPIE -DPIE -pthread -g -W -Wall -Wshadow -Wundef -Wno-unused-result -Wno-unused-parameter -D_GNU_SOURCE
fapolicyd_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now

libfapolicyd_la_SOURCES = \
	library/avl.c \
	library/avl.h \
	library/attr-sets.c \
	library/attr-sets.h \
	library/backend-manager.c \
	library/backend-manager.h \
	library/conf.h \
	library/database.c \
	library/database.h \
	library/daemon-config.c \
	library/daemon-config.h \
	library/escape.c \
	library/escape.h \
	library/event.c \
	library/event.h \
	library/fapolicyd-defs.h \
	library/fapolicyd-backend.h \
	library/fd-fgets.c \
	library/fd-fgets.h \
	library/file.c \
	library/file.h \
	library/file-backend.c \
	library/gcc-attributes.h \
	library/llist.c \
	library/llist.h \
	library/lru.c \
	library/lru.h \
	library/message.c \
	library/message.h \
	library/nv.h \
	library/object-attr.c \
	library/object-attr.h \
	library/object.c \
	library/object.h \
	library/paths.h \
	library/policy.c \
	library/policy.h \
	library/process.c \
	library/process.h \
	library/queue.c \
	library/queue.h \
	library/rules.c \
	library/rules.h \
	library/subject-attr.c \
	library/subject-attr.h \
	library/subject.c \
	library/subject.h \
	library/stack.c \
	library/stack.h \
	library/string-util.c \
	library/string-util.h \
	library/trust-file.c \
	library/trust-file.h

if WITH_RPM
libfapolicyd_la_SOURCES += \
	library/rpm-backend.c
endif

if WITH_DEB
libfapolicyd_la_SOURCES += \
	library/deb-backend.c
fapolicyd_CFLAGS += -DLIBDPKG_VOLATILE_API
fapolicyd_LDFLAGS += -ldpkg
endif

if WITH_EBUILD
libfapolicyd_la_SOURCES += \
	library/ebuild-backend.c
endif

if NEED_FILTER
libfapolicyd_la_SOURCES += \
	library/filter.c \
	library/filter.h
endif

if NEED_MD5
libfapolicyd_la_SOURCES += \
	library/md5-backend.c \
	library/md5-backend.h
endif

fapolicyd_cli_CFLAGS = $(fapolicyd_CFLAGS)
fapolicyd_cli_LDFLAGS = $(fapolicyd_LDFLAGS)

libfapolicyd_la_CFLAGS = $(fapolicyd_CFLAGS)
libfapolicyd_la_LDFLAGS = $(fapolicyd_LDFLAGS) -lpthread

fapolicyd_SOURCES = \
	daemon/fapolicyd.c \
	daemon/mounts.c \
	daemon/mounts.h \
	daemon/notify.c \
	daemon/notify.h


fapolicyd_LDADD = libfapolicyd.la
fapolicyd_LDFLAGS += -static


fapolicyd_cli_SOURCES = \
	cli/fapolicyd-cli.c \
	cli/file-cli.c \
	cli/file-cli.h

fapolicyd_cli_LDADD = libfapolicyd.la
