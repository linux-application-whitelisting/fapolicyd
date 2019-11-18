AUTOMAKE_OPTIONS = subdir-objects

CONFIG_CLEAN_FILES = *.loT *.rej *.orig
AM_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_srcdir}/src/daemon \
	-I${top_srcdir}/src/library

sbin_PROGRAMS = fapolicyd fapolicyd-cli
lib_LTLIBRARIES= libfapolicyd.la

fapolicyd_CFLAGS = -fPIE -DPIE -pthread -g -W -Wall -Wshadow -Wundef -Wno-unused-result -Wno-unused-parameter -D_GNU_SOURCE
fapolicyd_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now

fapolicyd_cli_CFLAGS = $(fapolicyd_CFLAGS)
fapolicyd_cli_LDFLAGS = $(fapolicyd_LDFLAGS)

libfapolicyd_la_SOURCES = \
	library/avl.c \
	library/avl.h \
	library/database.c \
	library/database.h \
	library/event.c \
	library/event.h \
	library/fapolicyd-defs.h \
	library/file.c \
	library/file.h \
	library/lru.c \
	library/lru.h \
	library/message.c \
	library/message.h \
	library/nv.h \
	library/object-attr.c \
	library/object-attr.h \
	library/object.c \
	library/object.h \
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
	library/temporary_db.c \
	library/temporary_db.h

libfapolicyd_la_CFLAGS = $(fapolicyd_CFLAGS)
libfapolicyd_la_LDFLAGS = $(fapolicyd_LDFLAGS) -lpthread

fapolicyd_SOURCES = \
	daemon/fapolicyd.c \
	daemon/daemon-config.c \
	daemon/daemon-config.h \
	daemon/fd-fgets.c \
	daemon/fd-fgets.h \
	daemon/mounts.c \
	daemon/mounts.h \
	daemon/notify.c \
	daemon/notify.h


fapolicyd_LDADD = libfapolicyd.la
fapolicyd_LDFLAGS += -static


fapolicyd_cli_SOURCES = cli/fapolicyd-cli.c
