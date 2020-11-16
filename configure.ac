AC_REVISION($Revision: 1.3 $)dnl
AC_INIT(fapolicyd,1.0.2)
AC_PREREQ(2.12)dnl
AM_CONFIG_HEADER(config.h)
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([foreign])
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

echo .
echo Checking for programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CC_C99
AC_PROG_INSTALL
AC_PROG_AWK
PKG_PROG_PKG_CONFIG
AC_CHECK_PROG([FILE_COMM], "file", "yes", "no")
if test "$FILE_COMM" = "no"; then
	AC_MSG_ERROR([Unable to find the file program need to build magic databases])
fi

echo .
echo Checking compiler options

AC_C_CONST
AC_C_INLINE

withval=""
AC_ARG_WITH(debug,
AS_HELP_STRING([--with-debug],[turn on debugging (default=no)]),
AC_DEFINE(DEBUG,1,[Define if you want to enable runtime debug checking.]),
[])

AC_ARG_WITH(audit,
AS_HELP_STRING([--with-audit],[turn on decision auditing (default=no)]),
AC_DEFINE(USE_AUDIT,1,[Define if you want to enable decision auditing.]),
[])
AC_CHECK_DECLS([FAN_AUDIT], [], [], [[#include <linux/fanotify.h>]])
AC_CHECK_DECLS([FAN_OPEN_EXEC_PERM], [perm=yes], [perm=no], [[#include <linux/fanotify.h>]])
if test $perm = "no"; then
	AC_MSG_ERROR([FAN_OPEN_EXEC_PERM is not defined in linux/fanotify.h. It is required for the kernel to support it])
fi

withval=""
AC_ARG_WITH(rpm,
AS_HELP_STRING([--with-rpm],[Use the rpm database as a trust source]),
use_rpm=$withval,use_rpm=yes)

if test x$use_rpm = xyes ; then
    AC_CHECK_LIB(rpm, rpmtsInitIterator, , [AC_MSG_ERROR([librpm not found])], -lrpm)
    AC_CHECK_LIB(rpmio, rpmFreeCrypto, , [AC_MSG_ERROR([librpmio not found])], -lrpmio)
    AC_DEFINE(USE_RPM,1,[Define if you want to use the rpm database as trust source.])
fi
AM_CONDITIONAL(WITH_RPM, test x$use_rpm = xyes)

dnl FIXME some day pass this on the command line
def_systemdsystemunitdir=${prefix}/lib/systemd/system
AC_SUBST([systemdsystemunitdir], [$def_systemdsystemunitdir])

echo .
echo Checking for required header files
AC_HEADER_STDC
AC_CHECK_HEADER(sys/fanotify.h, , [AC_MSG_ERROR(
["Couldn't find sys/fanotify.h...your kernel might not be new enough"] )])
AC_CHECK_FUNCS(fexecve, [], [])

AC_CHECK_HEADER(uthash.h, , [AC_MSG_ERROR(
["Couldn't find uthash.h...uthash-devel is missing"] )])


echo .
echo Checking for required libraries
AC_CHECK_LIB(udev, udev_device_get_devnode, , [AC_MSG_ERROR([libudev not found])], -ludev)
AC_CHECK_LIB(gcrypt, gcry_md_open, , [AC_MSG_ERROR([libgcrypt not found])], -lgcrypt)
AC_CHECK_LIB(magic, magic_descriptor, , [AC_MSG_ERROR([libmagic not found])], -lmagic)
AC_CHECK_LIB(cap-ng, capng_change_id, , [AC_MSG_ERROR([libcap-ng not found])], -lcap-ng)
AC_CHECK_LIB(seccomp, seccomp_rule_add, , [AC_MSG_ERROR([libseccomp not found])], -lseccomp)
AC_CHECK_LIB(lmdb, mdb_env_create, , [AC_MSG_ERROR([liblmdb not found])], -llmdb)

LD_SO_PATH

AC_OUTPUT(Makefile src/Makefile init/Makefile doc/Makefile)

echo .
echo "

  fapolicyd Version:      $VERSION
  Target:                 $target
  Installation prefix:    $prefix
  Compiler:               $CC
  Compiler flags:
`echo $CFLAGS | fmt -w 50 | sed 's,^,                          ,'`
"
 
