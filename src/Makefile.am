CONFIG_CLEAN_FILES = *.loT *.rej *.orig
AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/src
sbin_PROGRAMS = fapolicyd fapolicyd-cli
fapolicyd_CFLAGS = -fPIE -DPIE -pthread -g -W -Wall -Wshadow -Wundef -Wno-unused-result -Wno-unused-parameter -D_GNU_SOURCE
fapolicyd_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now
fapolicyd_LDADD = -lpthread

fapolicyd_cli_CFLAGS = $(fapolicyd_CFLAGS)
fapolicyd_cli_LDFLAGS = $(fapolicyd_LDFLAGS)

fapolicyd_SOURCES = avl.c database.c daemon-config.c event.c \
	fapolicyd.c fd-fgets.c file.c lru.c message.c \
	mounts.c notify.c object-attr.c object.c \
	policy.c process.c queue.c rules.c \
	subject-attr.c subject.c temporary_db.c

fapolicyd_cli_SOURCES = fapolicyd-cli.c

noinst_HEADERS = avl.h database.h daemon-config.h event.h \
	fd-fgets.h file.h lru.h message.h mounts.h notify.h \
	nv.h object-attr.h object.h policy.h \
	process.h queue.h rules.h subject-attr.h subject.h \
	temporary_db.h
