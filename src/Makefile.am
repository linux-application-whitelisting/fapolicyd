CONFIG_CLEAN_FILES = *.loT *.rej *.orig
AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/src
sbin_PROGRAMS = fapolicyd
fapolicyd_CFLAGS = -fPIE -DPIE -pthread -g -W -Wall -Wshadow -Wundef -Wno-unused-result -Wno-unused-parameter -D_GNU_SOURCE
fapolicyd_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now
fapolicyd_LDADD = -lpthread 

fapolicyd_SOURCES = event.c fapolicyd.c file.c lru.c message.c \
	mounts.c notify.c object-attr.c object.c \
	policy.c process.c queue.c rules.c \
	subject-attr.c subject.c

noinst_HEADERS = event.h file.h lru.h message.h mounts.h notify.h \
	nv.h object-attr.h object.h policy.h process.h \
	queue.h rules.h subject-attr.h subject.h
